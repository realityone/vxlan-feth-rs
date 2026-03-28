use std::{io, net::SocketAddr};

use tokio::net::UdpSocket;

use crate::protocol::{self, EthernetHeader, VXLAN_HEADER_LEN, VxlanHdr};

/// Maximum UDP datagram we expect: VXLAN header + inner Ethernet frame (jumbo-safe).
const MAX_RECV_BUF: usize = 65535;

/// Configuration for a VXLAN server instance.
#[derive(Debug, Clone)]
pub struct VxlanServerConfig {
    /// Local address to bind the UDP socket (e.g. "0.0.0.0:4789").
    pub listen_addr: SocketAddr,
    /// The VNI this server handles. Packets with a different VNI are dropped.
    pub vni: u32,
    /// Name of the feth I/O-side interface to inject/capture frames.
    pub feth_ifname: String,
    /// Remote VTEP address to send encapsulated frames to.
    pub remote_vtep: SocketAddr,
}

/// A userspace VXLAN tunnel server.
///
/// Bridges between a tokio UDP socket (outer VXLAN transport) and a feth
/// interface (inner L2 domain).
///
/// ```text
///  Remote VTEP ──UDP──▶ VxlanServer ──feth──▶ macOS network stack
///                           ◀──feth──          ◀──UDP──
/// ```
///
/// RX path: UDP recv → parse VXLAN header → validate VNI → write inner frame to feth
/// TX path: feth recv → prepend VXLAN header → UDP send to remote VTEP
pub struct VxlanServer {
    config: VxlanServerConfig,
    socket: UdpSocket,
    feth_io: feth_rs::feth_tokio::AsyncFethIO,
}

impl VxlanServer {
    /// Create a new server, binding the UDP socket and opening the feth interface.
    pub async fn bind(config: VxlanServerConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(config.listen_addr).await?;
        tracing::info!(
            listen = %config.listen_addr,
            vni = config.vni,
            feth = %config.feth_ifname,
            remote = %config.remote_vtep,
            "vxlan server bound",
        );
        let feth_io = feth_rs::feth_tokio::AsyncFethIO::open(&config.feth_ifname)?;
        Ok(Self {
            config,
            socket,
            feth_io,
        })
    }

    /// Run the server, forwarding packets in both directions until cancelled.
    ///
    /// Uses `tokio::select!` to multiplex between the UDP socket and the feth
    /// interface in a single loop, avoiding ownership splitting.
    pub async fn run(mut self) -> io::Result<()> {
        let vxlan_hdr = VxlanHdr::new(self.config.vni);

        let mut udp_buf = vec![0u8; MAX_RECV_BUF];
        let mut feth_buf = vec![0u8; MAX_RECV_BUF];

        loop {
            tokio::select! {
                // RX path: UDP → feth (decapsulation)
                result = self.socket.recv_from(&mut udp_buf) => {
                    let (n, peer) = result?;
                    self.handle_rx(&udp_buf[..n], peer);
                }

                // TX path: feth → UDP (encapsulation)
                result = self.feth_io.recv(&mut feth_buf) => {
                    let n = result?;
                    let frame = &feth_buf[..n];
                    self.handle_tx(&vxlan_hdr, frame).await;
                }
            }
        }
    }

    /// Handle an incoming UDP datagram: parse VXLAN, validate VNI, inject inner frame.
    /// Returns the injected frame bytes (for BPF feedback detection).
    fn handle_rx(&self, data: &[u8], peer: SocketAddr) -> Option<Vec<u8>> {
        let (vxlan, inner_frame) = match VxlanHdr::from_bytes(data) {
            Ok(parsed) => parsed,
            Err(_) => return None,
        };

        if vxlan.vni() != self.config.vni {
            return None;
        }

        if inner_frame.len() < protocol::ETH_HEADER_LEN {
            return None;
        }

        if let Ok((eth, _)) = EthernetHeader::from_bytes(inner_frame) {
            tracing::trace!(
                dst = format_args!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.dst_mac[0], eth.dst_mac[1], eth.dst_mac[2],
                    eth.dst_mac[3], eth.dst_mac[4], eth.dst_mac[5]),
                src = format_args!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.src_mac[0], eth.src_mac[1], eth.src_mac[2],
                    eth.src_mac[3], eth.src_mac[4], eth.src_mac[5]),
                ethertype = format_args!("{:#06x}", eth.ethertype()),
                bytes = inner_frame.len(),
                %peer,
                "rx: decapsulated frame",
            );
        }

        match self.feth_io.send(inner_frame) {
            Ok(_) => Some(inner_frame.to_vec()),
            Err(e) => {
                tracing::warn!(error = %e, "failed to inject frame into feth");
                None
            }
        }
    }

    /// Handle an outgoing frame from feth: prepend VXLAN header, send via UDP.
    async fn handle_tx(&self, vxlan_hdr: &VxlanHdr, frame: &[u8]) {
        if frame.len() < protocol::ETH_HEADER_LEN {
            return;
        }

        if let Ok((eth, _)) = EthernetHeader::from_bytes(frame) {
            tracing::trace!(
                dst = format_args!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.dst_mac[0],
                    eth.dst_mac[1],
                    eth.dst_mac[2],
                    eth.dst_mac[3],
                    eth.dst_mac[4],
                    eth.dst_mac[5]
                ),
                src = format_args!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.src_mac[0],
                    eth.src_mac[1],
                    eth.src_mac[2],
                    eth.src_mac[3],
                    eth.src_mac[4],
                    eth.src_mac[5]
                ),
                ethertype = format_args!("{:#06x}", eth.ethertype()),
                bytes = frame.len(),
                "tx: encapsulating frame from feth",
            );
        }

        let total = VXLAN_HEADER_LEN + frame.len();
        let mut send_buf = Vec::with_capacity(total);
        send_buf.extend_from_slice(vxlan_hdr.as_bytes());
        send_buf.extend_from_slice(frame);

        match self
            .socket
            .send_to(&send_buf, self.config.remote_vtep)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "failed to send vxlan datagram");
            }
        }
    }
}
