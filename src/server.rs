use std::{collections::HashMap, io, net::SocketAddr, os::fd::AsRawFd};

use tokio::{io::Interest, net::UdpSocket};

use crate::{
    config::{self, FdbEntry},
    protocol::{self, EthernetHeader, VxlanHdr},
};

/// Maximum UDP datagram we expect: VXLAN header + inner Ethernet frame (jumbo-safe).
const MAX_RECV_BUF: usize = 65535;

/// Socket receive buffer size (4 MiB).
const SO_RCVBUF_SIZE: libc::c_int = 4 * 1024 * 1024;
/// Socket send buffer size (4 MiB).
const SO_SNDBUF_SIZE: libc::c_int = 4 * 1024 * 1024;

/// Forwarding database: maps destination MAC to remote VTEP(s).
///
/// - Unicast entries (`mac != 00:00:00:00:00:00`) map to a single VTEP.
/// - BUM entries (`mac == 00:00:00:00:00:00`) are collected into a flood list;
///   frames with no unicast match are sent to all BUM destinations.
#[derive(Debug)]
struct Fdb {
    /// Exact MAC → VTEP mapping.
    unicast: HashMap<[u8; 6], SocketAddr>,
    /// Flood list for broadcast / unknown-unicast / multicast.
    bum: Vec<SocketAddr>,
}

impl Fdb {
    fn from_entries(entries: &[FdbEntry]) -> Self {
        let mut unicast = HashMap::new();
        let mut bum = Vec::new();
        for entry in entries {
            if entry.is_bum() {
                bum.push(entry.dst);
            } else {
                unicast.insert(entry.mac, entry.dst);
            }
        }
        Self { unicast, bum }
    }

    /// Look up destinations for a given destination MAC.
    ///
    /// Returns a single VTEP for known unicast, or the full BUM flood list
    /// for broadcast/multicast/unknown destinations.
    fn lookup(&self, dst_mac: &[u8; 6]) -> &[SocketAddr] {
        // Broadcast / multicast — always flood.
        if dst_mac[0] & 0x01 != 0 {
            return &self.bum;
        }
        // Known unicast.
        if let Some(addr) = self.unicast.get(dst_mac) {
            return std::slice::from_ref(addr);
        }
        // Unknown unicast — flood.
        &self.bum
    }
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
/// TX path: feth recv → FDB lookup → VXLAN encap → UDP sendmsg to VTEP(s)
pub struct VxlanServer {
    vni: u32,
    socket: UdpSocket,
    feth_io: feth_rs::feth_tokio::AsyncFethIO,
    fdb: Fdb,
}

impl VxlanServer {
    /// Create a new server from the parsed config.
    pub async fn bind(config: &config::Config) -> io::Result<Self> {
        let socket = UdpSocket::bind(config.server.listen).await?;
        set_sock_buf_size(socket.as_raw_fd())?;

        let fdb = Fdb::from_entries(&config.fdb);

        tracing::info!(
            listen = %config.server.listen,
            vni = config.server.vni,
            feth = %config.interface.io_name(),
            bum_peers = fdb.bum.len(),
            unicast_entries = fdb.unicast.len(),
            "vxlan server bound",
        );

        let feth_io = feth_rs::feth_tokio::AsyncFethIO::open(&config.interface.io_name())?;
        Ok(Self {
            vni: config.server.vni,
            socket,
            feth_io,
            fdb,
        })
    }

    /// Run the server, forwarding packets in both directions until cancelled.
    ///
    /// After each readiness notification, drains all available packets before
    /// re-entering the event loop to reduce epoll overhead.
    pub async fn run(mut self) -> io::Result<()> {
        let vxlan_hdr = VxlanHdr::new(self.vni);

        let mut udp_buf = vec![0u8; MAX_RECV_BUF];
        let mut feth_buf = vec![0u8; MAX_RECV_BUF];

        loop {
            tokio::select! {
                // RX path: UDP → feth (decapsulation)
                result = self.socket.readable() => {
                    result?;
                    // Drain all queued datagrams before re-polling.
                    loop {
                        match self.socket.try_recv_from(&mut udp_buf) {
                            Ok((n, peer)) => self.handle_rx(&udp_buf[..n], peer),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(e),
                        }
                    }
                }

                // TX path: feth → UDP (encapsulation)
                result = self.feth_io.recv(&mut feth_buf) => {
                    let n = result?;
                    self.handle_tx(&vxlan_hdr, &feth_buf[..n]).await;
                }
            }
        }
    }

    /// Handle an incoming UDP datagram: parse VXLAN, validate VNI, inject inner frame.
    fn handle_rx(&self, data: &[u8], _: SocketAddr) {
        let (vxlan, inner_frame) = match VxlanHdr::from_bytes(data) {
            Ok(parsed) => parsed,
            Err(_) => return,
        };

        if vxlan.vni() != self.vni {
            return;
        }

        if inner_frame.len() < protocol::ETH_HEADER_LEN {
            return;
        }

        if let Err(e) = self.feth_io.send(inner_frame) {
            tracing::warn!(error = %e, "failed to inject frame into feth");
        }
    }

    /// Handle an outgoing frame from feth: FDB lookup → VXLAN encap → sendmsg.
    ///
    /// Uses `sendmsg` with `iovec` to scatter-gather the VXLAN header and
    /// inner frame, avoiding a copy into a contiguous buffer.
    async fn handle_tx(&self, vxlan_hdr: &VxlanHdr, frame: &[u8]) {
        if frame.len() < protocol::ETH_HEADER_LEN {
            return;
        }

        let dst_mac = match EthernetHeader::from_bytes(frame) {
            Ok((eth, _)) => eth.dst_mac,
            Err(_) => return,
        };

        let destinations = self.fdb.lookup(&dst_mac);
        if destinations.is_empty() {
            return;
        }

        let hdr_bytes = vxlan_hdr.as_bytes();
        self.socket.writable().await.ok();

        for &remote in destinations {
            let result = self.socket.try_io(Interest::WRITABLE, || {
                sendmsg_udp(self.socket.as_raw_fd(), &[hdr_bytes, frame], remote)
            });

            if let Err(e) = result {
                tracing::warn!(
                    error = %e,
                    dst = %config::format_mac(&dst_mac),
                    remote = %remote,
                    "failed to send vxlan datagram",
                );
            }
        }
    }
}

/// Opaque storage large enough for either `sockaddr_in` or `sockaddr_in6`.
union SockAddrStorage {
    v4: libc::sockaddr_in,
    v6: libc::sockaddr_in6,
}

/// Send a UDP datagram from exactly two buffers (header + payload) via `sendmsg(2)`.
fn sendmsg_udp(fd: std::os::fd::RawFd, slices: &[&[u8]; 2], dest: SocketAddr) -> io::Result<usize> {
    let iov = [
        libc::iovec {
            iov_base: slices[0].as_ptr() as *mut libc::c_void,
            iov_len: slices[0].len(),
        },
        libc::iovec {
            iov_base: slices[1].as_ptr() as *mut libc::c_void,
            iov_len: slices[1].len(),
        },
    ];

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

/// Enlarge the kernel socket buffers to reduce packet drops under load.
fn set_sock_buf_size(fd: std::os::fd::RawFd) -> io::Result<()> {
    for (opt, size) in [
        (libc::SO_RCVBUF, SO_RCVBUF_SIZE),
        (libc::SO_SNDBUF, SO_SNDBUF_SIZE),
    ] {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                std::ptr::addr_of!(size).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            tracing::warn!(
                opt = if opt == libc::SO_RCVBUF { "SO_RCVBUF" } else { "SO_SNDBUF" },
                size,
                error = %e,
                "failed to set socket buffer size, using default",
            );
        }
    }
    Ok(())
}
