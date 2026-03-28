use std::{io, net::SocketAddr, os::fd::AsRawFd};

use tokio::{io::Interest, net::UdpSocket};

use crate::protocol::{self, VxlanHdr};

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
    fn handle_rx(&self, data: &[u8], _: SocketAddr) -> Option<Vec<u8>> {
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

        match self.feth_io.send(inner_frame) {
            Ok(_) => Some(inner_frame.to_vec()),
            Err(e) => {
                tracing::warn!(error = %e, "failed to inject frame into feth");
                None
            }
        }
    }

    /// Handle an outgoing frame from feth: prepend VXLAN header, send via UDP.
    ///
    /// Uses `sendmsg` with `iovec` to scatter-gather the VXLAN header and
    /// inner frame, avoiding a copy into a contiguous buffer.
    async fn handle_tx(&self, vxlan_hdr: &VxlanHdr, frame: &[u8]) {
        if frame.len() < protocol::ETH_HEADER_LEN {
            return;
        }

        // Wait for the socket to be writable, then do the sendmsg syscall.
        self.socket.writable().await.ok();
        let result = self.socket.try_io(Interest::WRITABLE, || {
            sendmsg_udp(
                self.socket.as_raw_fd(),
                &[vxlan_hdr.as_bytes(), frame],
                self.config.remote_vtep,
            )
        });

        match result {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "failed to send vxlan datagram");
            }
        }
    }
}

/// Opaque storage large enough for either `sockaddr_in` or `sockaddr_in6`.
union SockAddrStorage {
    v4: libc::sockaddr_in,
    v6: libc::sockaddr_in6,
}

/// Send a UDP datagram assembled from multiple `iovec` slices via `sendmsg(2)`.
fn sendmsg_udp(fd: std::os::fd::RawFd, slices: &[&[u8]], dest: SocketAddr) -> io::Result<usize> {
    let iov: Vec<libc::iovec> = slices
        .iter()
        .map(|s| libc::iovec {
            iov_base: s.as_ptr() as *mut libc::c_void,
            iov_len: s.len(),
        })
        .collect();

    let mut storage: SockAddrStorage = unsafe { std::mem::zeroed() };
    let addr_len = match dest {
        SocketAddr::V4(v4) => {
            storage.v4 = libc::sockaddr_in {
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as u8,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            storage.v6 = libc::sockaddr_in6 {
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as u8,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::addr_of_mut!(storage).cast::<libc::c_void>();
    msg.msg_namelen = addr_len;
    msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
    msg.msg_iovlen = iov.len() as _;

    // Safety: all pointers (iov, storage) are valid stack references for the
    // duration of the sendmsg syscall.
    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}
