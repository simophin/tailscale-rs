//! The raw packets of forwarded (subnet-route and exit-node) flows, for an embedder that forwards
//! them itself ([`ts_control::Config::external_forwarder`]).
//!
//! The runtime gives such flows their own overlay transport, and the route updater sends the
//! node's subnet and exit routes to it instead of the forwarder netstack. [`ForwardedPackets`] is
//! that transport's two queues: the packets peers sent to forwarded destinations, decrypted and
//! past the packet filter, and the way back, where each packet goes to the peer that owns its
//! destination address.

use ts_packet::PacketMut;

use crate::dataplane::{OverlayFromDataplane, OverlayToDataplane};

/// The dataplane is gone: the runtime has shut down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the dataplane is closed")]
pub struct DataplaneClosed;

/// Both directions of the forwarded traffic. Split it with [`ForwardedPackets::split`] to read
/// and write from different tasks.
pub struct ForwardedPackets {
    sender: ForwardedPacketSender,
    receiver: ForwardedPacketReceiver,
}

/// Sends packets back to peers. Cheap to clone.
#[derive(Clone)]
pub struct ForwardedPacketSender(OverlayToDataplane);

/// Receives the packets peers send to forwarded destinations.
pub struct ForwardedPacketReceiver(OverlayFromDataplane);

impl ForwardedPackets {
    pub(crate) fn new(to_dataplane: OverlayToDataplane, from_dataplane: OverlayFromDataplane) -> Self {
        Self {
            sender: ForwardedPacketSender(to_dataplane),
            receiver: ForwardedPacketReceiver(from_dataplane),
        }
    }

    /// The sending and receiving halves.
    pub fn split(self) -> (ForwardedPacketSender, ForwardedPacketReceiver) {
        (self.sender, self.receiver)
    }
}

impl ForwardedPacketSender {
    /// Hands a batch of IP packets to the dataplane, which encrypts each for the peer its
    /// destination belongs to. Packets for no peer are dropped. Never waits.
    pub fn send(&self, packets: Vec<PacketMut>) -> Result<(), DataplaneClosed> {
        self.0.send(packets).map_err(|_| DataplaneClosed)
    }
}

impl ForwardedPacketReceiver {
    /// The next batch of IP packets from peers, or `None` once the runtime has shut down.
    pub async fn recv(&mut self) -> Option<Vec<PacketMut>> {
        self.0.recv().await
    }

    /// Like [`recv`](Self::recv), but appends up to `limit` batches already queued to `out`
    /// without waiting for more; returns how many batches it took, `0` once shut down.
    pub async fn recv_many(&mut self, out: &mut Vec<Vec<PacketMut>>, limit: usize) -> usize {
        self.0.recv_many(out, limit).await
    }
}
