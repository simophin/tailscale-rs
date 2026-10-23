//! Outbound TCP through an HTTP proxy named in the environment, as Go's
//! `http.ProxyFromEnvironment` (and so `tailscaled` and `tsnet`) reach the control plane and DERP.
//!
//! `HTTPS_PROXY` (or `https_proxy`) applies to TLS destinations and `HTTP_PROXY` (or
//! `http_proxy`) to plain ones. `NO_PROXY` (or `no_proxy`) lists hosts to reach directly: a
//! name matches itself and its subdomains, a leading `.` or `*.` means the same, an IP matches
//! itself, and `*` alone turns the proxy off. Loopback destinations are never proxied. The proxy
//! is an `http://` URL, with an optional `user:password@` for Basic authentication; the tunnel
//! is an HTTP/1.1 `CONNECT`.

use std::{io, net::IpAddr};

use base64::Engine as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Most bytes of a proxy's reply headers read before giving up on it.
const MAX_REPLY: usize = 8192;

/// Connect to `host:port`, through the environment's proxy for that destination when there is
/// one, or directly. `tls` says whether the connection will carry TLS, which picks the variable.
pub async fn connect(host: &str, port: u16, tls: bool) -> io::Result<TcpStream> {
    match proxy_for(host, tls, |k| std::env::var(k).ok()) {
        Some(proxy) => connect_via(&proxy, host, port).await,
        None => TcpStream::connect((host, port)).await,
    }
}

/// The proxy to reach `host` through, read with `getenv`, or `None` to connect directly.
pub fn proxy_for(
    host: &str,
    tls: bool,
    getenv: impl Fn(&str) -> Option<String>,
) -> Option<url::Url> {
    let var = |name: &str| {
        getenv(name)
            .or_else(|| getenv(&name.to_ascii_lowercase()))
            .filter(|v| !v.trim().is_empty())
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if is_loopback(host) {
        return None;
    }
    if let Some(no_proxy) = var("NO_PROXY")
        && excluded(host, &no_proxy)
    {
        return None;
    }
    let raw = var(if tls { "HTTPS_PROXY" } else { "HTTP_PROXY" })?;
    let raw = raw.trim();
    // A bare host:port, as curl and Go accept, is an http:// proxy.
    let parsed = if raw.contains("://") {
        url::Url::parse(raw)
    } else {
        url::Url::parse(&format!("http://{raw}"))
    };
    match parsed {
        Ok(url) if url.scheme() == "http" && url.host_str().is_some() => Some(url),
        Ok(url) => {
            tracing::warn!(
                scheme = url.scheme(),
                "unsupported proxy scheme; connecting directly"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "invalid proxy URL; connecting directly");
            None
        }
    }
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether `NO_PROXY` exempts `host`.
fn excluded(host: &str, no_proxy: &str) -> bool {
    let host = host.to_ascii_lowercase();
    no_proxy
        .split(',')
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .any(|entry| {
            if entry == "*" {
                return true;
            }
            // An entry may carry a port, which applies to every port here.
            let entry = match entry.rsplit_once(':') {
                Some((name, port)) if !name.contains(':') && port.parse::<u16>().is_ok() => {
                    name.to_owned()
                }
                _ => entry,
            };
            let domain = entry.trim_start_matches("*.").trim_start_matches('.');
            host == domain || host.ends_with(&format!(".{domain}"))
        })
}

/// Open a `CONNECT` tunnel to `host:port` through `proxy`.
pub async fn connect_via(proxy: &url::Url, host: &str, port: u16) -> io::Result<TcpStream> {
    let proxy_host = proxy
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy URL has no host"))?;
    let proxy_port = proxy.port_or_known_default().unwrap_or(80);
    let mut stream = TcpStream::connect((
        proxy_host.trim_start_matches('[').trim_end_matches(']'),
        proxy_port,
    ))
    .await?;

    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if !proxy.username().is_empty() {
        let credentials = format!(
            "{}:{}",
            percent_decode(proxy.username()),
            percent_decode(proxy.password().unwrap_or(""))
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Read the reply headers a byte at a time, so nothing of the tunnel is consumed.
    let mut reply = Vec::with_capacity(256);
    while !reply.ends_with(b"\r\n\r\n") {
        if reply.len() >= MAX_REPLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy reply too long",
            ));
        }
        let byte = stream.read_u8().await?;
        reply.push(byte);
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(&reply) {
        Ok(httparse::Status::Complete(_))
            if response.code.is_some_and(|c| (200..300).contains(&c)) =>
        {
            Ok(stream)
        }
        Ok(httparse::Status::Complete(_)) => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "proxy refused CONNECT to {authority}: {} {}",
                response.code.unwrap_or(0),
                response.reason.unwrap_or("")
            ),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed proxy reply",
        )),
    }
}

/// Decodes `%XX` escapes, as URL userinfo carries them.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = s.get(i + 1..i + 3)
            && let Ok(b) = u8::from_str_radix(hex, 16)
        {
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncBufReadExt;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn picks_the_variable_for_the_destination() {
        let e = env(&[("HTTPS_PROXY", "http://p:3128"), ("http_proxy", "q:8080")]);
        assert_eq!(
            proxy_for("controlplane.tailscale.com", true, &e)
                .unwrap()
                .as_str(),
            "http://p:3128/"
        );
        assert_eq!(
            proxy_for("controlplane.tailscale.com", false, &e)
                .unwrap()
                .as_str(),
            "http://q:8080/"
        );
        assert!(proxy_for("x", true, env(&[])).is_none());
        assert!(proxy_for("x", true, env(&[("HTTPS_PROXY", " ")])).is_none());
    }

    #[test]
    fn loopback_and_no_proxy_go_direct() {
        let e = env(&[
            ("HTTPS_PROXY", "http://p:3128"),
            ("NO_PROXY", "corp.example, .lan,10.1.2.3,*.ts.net:443"),
        ]);
        for host in [
            "127.0.0.1",
            "localhost",
            "[::1]",
            "corp.example",
            "a.corp.example",
            "nas.lan",
            "10.1.2.3",
            "x.ts.net",
        ] {
            assert!(proxy_for(host, true, &e).is_none(), "{host}");
        }
        for host in ["notcorp.example", "derp1.tailscale.com", "10.1.2.4"] {
            assert!(proxy_for(host, true, &e).is_some(), "{host}");
        }
        assert!(
            proxy_for(
                "anything",
                true,
                env(&[("HTTPS_PROXY", "p:1"), ("no_proxy", "*")])
            )
            .is_none()
        );
    }

    #[test]
    fn only_http_proxies() {
        assert!(proxy_for("x", true, env(&[("HTTPS_PROXY", "socks5://p:1080")])).is_none());
    }

    #[test]
    fn userinfo_is_percent_decoded() {
        assert_eq!(percent_decode("a%40b%3Ac"), "a@b:c");
        assert_eq!(percent_decode("100%"), "100%");
    }

    /// A proxy that checks the CONNECT request, answers 200, then echoes the tunnel.
    #[tokio::test]
    async fn tunnels_through_connect_with_basic_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = tokio::io::BufReader::new(sock);
            let mut head = String::new();
            loop {
                let mut line = String::new();
                sock.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            sock.get_mut()
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 5];
            sock.read_exact(&mut buf).await.unwrap();
            sock.get_mut().write_all(&buf).await.unwrap();
            head
        });
        let proxy = url::Url::parse(&format!("http://us%40er:pa:ss@{addr}")).unwrap();
        let mut tunnel = connect_via(&proxy, "derp.example", 443).await.unwrap();
        tunnel.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        tunnel.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");
        let head = server.await.unwrap();
        assert!(
            head.starts_with("CONNECT derp.example:443 HTTP/1.1\r\n"),
            "{head}"
        );
        let expected = base64::engine::general_purpose::STANDARD.encode("us@er:pa:ss");
        assert!(
            head.contains(&format!("Proxy-Authorization: Basic {expected}")),
            "{head}"
        );
    }

    #[tokio::test]
    async fn a_refused_connect_is_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _request = sock.read(&mut buf).await;
            sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        });
        let proxy = url::Url::parse(&format!("http://{addr}")).unwrap();
        let err = connect_via(&proxy, "x", 443).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }
}
