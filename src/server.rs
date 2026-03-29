use std::{
    cell::RefCell,
    collections::HashMap,
    io,
    net::SocketAddr,
    os::fd::AsRawFd,
    time::Instant,
};

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

/// Learned MAC entries expire after this duration.
const LEARNED_MAC_TTL: std::time::Duration = std::time::Duration::from_secs(300);

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
    /// Source MAC → (remote VTEP IP, last seen time) learned from incoming
    /// VXLAN packets.  Used for split-horizon: don't flood a frame back to
    /// the VTEP that originated it.  Entries expire after `LEARNED_MAC_TTL`.
    learned: RefCell<HashMap<[u8; 6], (std::net::IpAddr, Instant)>>,
    /// Maximum number of learned MAC entries.
    max_learned: usize,
}

impl Fdb {
    fn new(entries: &[FdbEntry], max_learned: usize) -> Self {
        let mut unicast = HashMap::new();
        let mut bum = Vec::new();
        for entry in entries {
            if entry.is_bum() {
                bum.push(entry.dst);
            } else {
                unicast.insert(entry.mac, entry.dst);
            }
        }
        Self {
            unicast,
            bum,
            learned: RefCell::new(HashMap::new()),
            max_learned,
        }
    }

    /// Record the source MAC → remote VTEP IP from an incoming frame.
    fn learn(&self, src_mac: [u8; 6], peer: SocketAddr) {
        let mut table = self.learned.borrow_mut();
        let is_new = !table.contains_key(&src_mac);
        if table.len() >= self.max_learned && is_new {
            tracing::trace!(
                mac = %config::format_mac(&src_mac),
                peer = %peer,
                table_size = table.len(),
                max = self.max_learned,
                "learned table full, dropping new entry",
            );
            return;
        }
        table.insert(src_mac, (peer.ip(), Instant::now()));
        if is_new {
            tracing::trace!(
                mac = %config::format_mac(&src_mac),
                peer_ip = %peer.ip(),
                table_size = table.len(),
                "learned new MAC",
            );
        }
    }

    /// Evict all expired entries.  Called periodically from the event loop.
    fn gc_learned(&self) {
        let mut table = self.learned.borrow_mut();
        let before = table.len();
        table.retain(|_, (_, ts)| ts.elapsed() < LEARNED_MAC_TTL);
        let evicted = before - table.len();
        if evicted > 0 {
            tracing::debug!(evicted, remaining = table.len(), "learned MAC GC");
        }
    }

    /// Return the VTEP IP a source MAC was learned from, if not expired.
    fn learned_peer_ip(&self, src_mac: &[u8; 6]) -> Option<std::net::IpAddr> {
        let table = self.learned.borrow();
        match table.get(src_mac) {
            Some(&(ip, ts)) if ts.elapsed() < LEARNED_MAC_TTL => Some(ip),
            Some(&(ip, ts)) => {
                tracing::trace!(
                    mac = %config::format_mac(src_mac),
                    peer_ip = %ip,
                    age_secs = ts.elapsed().as_secs(),
                    "learned entry expired",
                );
                None
            }
            _ => None,
        }
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

        let max_learned = config.interface.subnet_host_count();
        let fdb = Fdb::new(&config.fdb, max_learned);

        tracing::info!(
            listen = %config.server.listen,
            vni = config.server.vni,
            feth = %config.interface.io.name(),
            bum_peers = fdb.bum.len(),
            unicast_entries = fdb.unicast.len(),
            max_learned,
            "vxlan server bound",
        );

        let feth_io = feth_rs::feth_tokio::AsyncFethIO::open(&config.interface.io.name())?;
        Ok(Self {
            vni: config.server.vni,
            socket,
            feth_io,
            fdb,
        })
    }

    /// Send a raw Ethernet frame to all BUM peers via VXLAN encapsulation.
    pub async fn flood_frame(&self, frame: &[u8]) {
        let vxlan_hdr = VxlanHdr::new(self.vni);
        let hdr_bytes = vxlan_hdr.as_bytes();
        self.socket.writable().await.ok();

        for &remote in &self.fdb.bum {
            let result = self.socket.try_io(Interest::WRITABLE, || {
                sendmsg_udp(self.socket.as_raw_fd(), &[hdr_bytes, frame], remote)
            });
            if let Err(e) = result {
                tracing::warn!(remote = %remote, error = %e, "failed to flood frame");
            }
        }
    }

    /// Run the server, forwarding packets in both directions until cancelled.
    ///
    /// The `on_ready` callback is invoked with a reference to the server after
    /// binding but before entering the main loop, giving the caller a chance to
    /// send initial packets (e.g. gratuitous ARP).
    ///
    /// After each readiness notification, drains all available packets before
    /// re-entering the event loop to reduce epoll overhead.
    pub async fn run<F>(mut self, on_ready: F) -> io::Result<()>
    where
        F: for<'a> FnOnce(&'a Self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>,
    {
        on_ready(&self).await;

        let vxlan_hdr = VxlanHdr::new(self.vni);
        let mut udp_buf = vec![0u8; MAX_RECV_BUF];
        let mut feth_buf = vec![0u8; MAX_RECV_BUF];
        let mut gc_interval = tokio::time::interval(LEARNED_MAC_TTL / 2);

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

                // Periodic GC of expired learned MAC entries.
                _ = gc_interval.tick() => {
                    self.fdb.gc_learned();
                }
            }
        }
    }

    /// Handle an incoming UDP datagram: parse VXLAN, validate VNI, learn source
    /// MAC for split-horizon, inject inner frame.
    fn handle_rx(&self, data: &[u8], peer: SocketAddr) {
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

        // Learn source MAC → remote VTEP for split-horizon filtering.
        if let Ok((eth, _)) = EthernetHeader::from_bytes(inner_frame) {
            self.fdb.learn(eth.src_mac, peer);
        }

        if let Err(e) = self.feth_io.send(inner_frame) {
            tracing::warn!(error = %e, "failed to inject frame into feth");
        }
    }

    /// Handle an outgoing frame from feth: FDB lookup → VXLAN encap → sendmsg.
    ///
    /// Uses `sendmsg` with `iovec` to scatter-gather the VXLAN header and
    /// inner frame, avoiding a copy into a contiguous buffer.
    ///
    /// Split-horizon: if the frame's source MAC was learned from a remote VTEP,
    /// that VTEP is excluded from the flood list to prevent loops.
    async fn handle_tx(&self, vxlan_hdr: &VxlanHdr, frame: &[u8]) {
        if frame.len() < protocol::ETH_HEADER_LEN {
            return;
        }

        let (dst_mac, src_mac) = match EthernetHeader::from_bytes(frame) {
            Ok((eth, _)) => (eth.dst_mac, eth.src_mac),
            Err(_) => return,
        };

        let destinations = self.fdb.lookup(&dst_mac);
        if destinations.is_empty() {
            return;
        }

        // Split-horizon: skip the VTEP this source MAC was learned from.
        let exclude_ip = self.fdb.learned_peer_ip(&src_mac);

        let hdr_bytes = vxlan_hdr.as_bytes();
        self.socket.writable().await.ok();

        for &remote in destinations {
            if exclude_ip == Some(remote.ip()) {
                tracing::trace!(
                    src = %config::format_mac(&src_mac),
                    dst = %config::format_mac(&dst_mac),
                    remote = %remote,
                    "split-horizon: skipping originating VTEP",
                );
                continue;
            }

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
