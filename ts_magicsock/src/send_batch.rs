//! Batched sends to one destination on the shared (unconnected) UDP socket, on Linux.
//!
//! WireGuard hands magicsock a batch of datagrams for one peer at a time. Sent one `sendto` each,
//! the syscall and the kernel's per-datagram UDP and netfilter work dominate the data path. As
//! wireguard-go's `StdNetBind` does on Linux, a batch instead goes out in one `sendmmsg`, and each
//! run of consecutive datagrams of the same size as one message with UDP generic segmentation
//! offload (`UDP_SEGMENT`), which the kernel splits back into datagrams after its UDP and IP work.
//!
//! A kernel or device that rejects GSO turns it off for the process, and the batch is sent with
//! `sendmmsg` alone; a kernel without `sendmmsg` turns batching off and the caller sends the rest
//! one datagram at a time.

use std::{
    io,
    net::{SocketAddr, SocketAddrV6},
    os::fd::AsRawFd,
    sync::atomic::{AtomicBool, Ordering},
};

use tokio::{io::Interest, net::UdpSocket};

/// Most datagrams per `sendmmsg` call (wireguard-go's `IdealBatchSize`).
pub(crate) const MAX_BATCH: usize = 128;
/// Most segments in one GSO message (the kernel's `UDP_MAX_SEGMENTS`).
const MAX_SEGMENTS: usize = 64;
/// Most payload bytes in one GSO message: what fits in one IP datagram.
const MAX_GSO_BYTES: usize = 65_000;

/// Cleared once `sendmmsg` turns out to be unusable.
static USABLE: AtomicBool = AtomicBool::new(true);
/// Cleared once the kernel or the outgoing device rejects `UDP_SEGMENT`.
static GSO: AtomicBool = AtomicBool::new(true);

/// Whether batched sends may be attempted.
pub(crate) fn usable() -> bool {
    USABLE.load(Ordering::Relaxed) && !disabled_by_env()
}

/// `TS_DEBUG_DISABLE_SEND_BATCH=1` sends every datagram on its own, for comparison.
fn disabled_by_env() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| {
        std::env::var("TS_DEBUG_DISABLE_SEND_BATCH").is_ok_and(|v| v == "1" || v == "true")
    })
}

/// One `sendmmsg` message: `count` datagrams from `start`, each `segment` bytes but the last,
/// which may be shorter. With one datagram, or without GSO, it carries no `UDP_SEGMENT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    start: usize,
    count: usize,
    segment: usize,
}

/// Splits `lens` into messages: runs of equal lengths, where a run may end with one shorter
/// datagram, bounded by the kernel's segment and size limits. Without `gso`, one per datagram.
fn runs(lens: &[usize], gso: bool) -> Vec<Run> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lens.len() {
        let segment = lens[i];
        let mut count = 1;
        let mut bytes = segment;
        if gso {
            while i + count < lens.len() && count < MAX_SEGMENTS {
                let next = lens[i + count];
                if next > segment || bytes + next > MAX_GSO_BYTES {
                    break;
                }
                count += 1;
                bytes += next;
                if next < segment {
                    // A shorter datagram can only end a run.
                    break;
                }
            }
        }
        out.push(Run {
            start: i,
            count,
            segment,
        });
        i += count;
    }
    out
}

/// The destination as the socket's family expects it: a dual-stack IPv6 socket takes IPv4
/// destinations as v4-mapped addresses.
fn destination(sock: &UdpSocket, addr: SocketAddr) -> io::Result<socket2::SockAddr> {
    let local = sock.local_addr()?;
    Ok(match (local, addr) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => {
            SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0).into()
        }
        (SocketAddr::V4(_), SocketAddr::V6(_)) => {
            return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
        }
        _ => addr.into(),
    })
}

/// Send `pkts` to `addr` on `sock`, in batches of up to [`MAX_BATCH`]. Returns how many were
/// sent before an error that the caller should handle by sending the rest one at a time;
/// `pkts.len()` when all went out.
pub(crate) async fn send_to<P: AsRef<[u8]>>(
    sock: &UdpSocket,
    addr: SocketAddr,
    pkts: &[P],
) -> usize {
    let Ok(dest) = destination(sock, addr) else {
        return 0;
    };
    let mut sent = 0;
    while sent < pkts.len() {
        let chunk = &pkts[sent..pkts.len().min(sent + MAX_BATCH)];
        let gso = GSO.load(Ordering::Relaxed);
        match sock
            .async_io(Interest::WRITABLE, || send_chunk(sock, &dest, chunk, gso))
            .await
        {
            // The kernel may take fewer than offered; continue with the rest.
            Ok(n) if n > 0 => sent += n,
            Ok(_) => return sent,
            Err(e) => {
                let unsupported = matches!(
                    e.raw_os_error(),
                    Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL | libc::EIO)
                );
                if gso && unsupported {
                    // EIO: the device cannot checksum the segments; EINVAL: the kernel predates
                    // UDP_SEGMENT or refuses this segment size. Retry the chunk without GSO.
                    tracing::warn!(error = %e, "magicsock: UDP GSO unusable; sending without it");
                    GSO.store(false, Ordering::Relaxed);
                    continue;
                }
                if unsupported {
                    tracing::warn!(error = %e, "magicsock: sendmmsg unusable; batching disabled");
                    USABLE.store(false, Ordering::Relaxed);
                } else {
                    tracing::trace!(error = %e, "magicsock: batched send failed");
                }
                return sent;
            }
        }
    }
    sent
}

/// One `sendmmsg` of `chunk`, at most [`MAX_BATCH`] datagrams. Returns how many datagrams the
/// kernel took: whole messages only.
fn send_chunk<P: AsRef<[u8]>>(
    sock: &UdpSocket,
    dest: &socket2::SockAddr,
    chunk: &[P],
    gso: bool,
) -> io::Result<usize> {
    // SAFETY: CMSG_SPACE only computes a size.
    let cmsg_space = unsafe { libc::CMSG_SPACE(size_of::<u16>() as u32) } as usize;
    let control_words = cmsg_space.div_ceil(8);
    let lens: Vec<usize> = chunk.iter().map(|p| p.as_ref().len()).collect();
    let runs = runs(&lens, gso);
    let mut iovs: Vec<libc::iovec> = chunk
        .iter()
        .map(|p| libc::iovec {
            iov_base: p.as_ref().as_ptr() as *mut libc::c_void,
            iov_len: p.as_ref().len(),
        })
        .collect();
    // One control buffer per message, u64-aligned as cmsghdr needs.
    let mut control = vec![0u64; runs.len() * control_words];
    // SAFETY: an all-zero mmsghdr is a valid, empty message.
    let mut msgs: Vec<libc::mmsghdr> = vec![unsafe { std::mem::zeroed() }; runs.len()];
    for (i, run) in runs.iter().enumerate() {
        let hdr = &mut msgs[i].msg_hdr;
        hdr.msg_name = dest.as_ptr() as *mut libc::c_void;
        hdr.msg_namelen = dest.len();
        hdr.msg_iov = iovs[run.start..].as_mut_ptr();
        hdr.msg_iovlen = run.count as _;
        if run.count > 1 {
            let buf = &mut control[i * control_words..(i + 1) * control_words];
            hdr.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
            hdr.msg_controllen = cmsg_space as _;
            // SAFETY: the control buffer holds one cmsg of a u16, as CMSG_SPACE sized it.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(hdr);
                (*cmsg).cmsg_level = libc::SOL_UDP;
                (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<u16>() as u32) as _;
                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, run.segment as u16);
            }
        }
    }
    // SAFETY: every message points into `iovs`, `control` and `dest`, which outlive the call.
    let n = unsafe {
        libc::sendmmsg(
            sock.as_raw_fd(),
            msgs.as_mut_ptr(),
            msgs.len() as _,
            libc::MSG_DONTWAIT as _,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(runs[..n as usize].iter().map(|r| r.count).sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(start: usize, count: usize, segment: usize) -> Run {
        Run {
            start,
            count,
            segment,
        }
    }

    #[test]
    fn equal_datagrams_share_a_message_and_a_shorter_one_ends_it() {
        let lens = [1280, 1280, 1280, 100, 1280, 1280];
        assert_eq!(runs(&lens, true), vec![run(0, 4, 1280), run(4, 2, 1280)]);
    }

    #[test]
    fn a_longer_datagram_starts_a_new_message() {
        assert_eq!(
            runs(&[100, 1280, 1280], true),
            vec![run(0, 1, 100), run(1, 2, 1280)]
        );
    }

    #[test]
    fn messages_stay_within_the_kernel_limits() {
        let lens = vec![1000; 200];
        let r = runs(&lens, true);
        assert!(
            r.iter()
                .all(|r| r.count <= MAX_SEGMENTS && r.count * 1000 <= MAX_GSO_BYTES)
        );
        assert_eq!(r.iter().map(|r| r.count).sum::<usize>(), 200);
        assert_eq!(r[0].count, 64);
        let big = vec![1400; 60];
        assert!(
            runs(&big, true)
                .iter()
                .all(|r| r.count * 1400 <= MAX_GSO_BYTES)
        );
    }

    #[test]
    fn without_gso_every_datagram_is_its_own_message() {
        assert_eq!(
            runs(&[1280, 1280], false),
            vec![run(0, 1, 1280), run(1, 1, 1280)]
        );
    }

    #[tokio::test]
    async fn a_batch_arrives_as_the_datagrams_sent() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pkts: Vec<Vec<u8>> = (0..10u8)
            .map(|i| vec![i; if i == 6 { 50 } else { 1200 }])
            .collect();
        assert_eq!(
            send_to(&tx, rx.local_addr().unwrap(), &pkts).await,
            pkts.len()
        );
        let mut buf = [0u8; 2000];
        for want in &pkts {
            let n = rx.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], want.as_slice());
        }
    }

    #[tokio::test]
    async fn a_dual_stack_socket_sends_to_ipv4() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let Ok(tx) = UdpSocket::bind("[::]:0").await else {
            return; // no IPv6 on this host
        };
        let pkts = vec![vec![1u8; 300], vec![2u8; 300]];
        assert_eq!(send_to(&tx, rx.local_addr().unwrap(), &pkts).await, 2);
        let mut buf = [0u8; 400];
        assert_eq!(rx.recv(&mut buf).await.unwrap(), 300);
        assert_eq!(buf[0], 1);
    }
}
