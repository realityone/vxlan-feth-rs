use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Instant,
};

use tokio::{io::Interest, net::UdpSocket};

use crate::{
    config::{self, FdbEntry},
    protocol::{self, EthernetHeader, VxlanHdr},
};

/// Tunnel traffic statistics, similar to `ip -s link show` on Linux.
#[derive(Debug, Default)]
pub struct TunnelStats {
    /// RX: packets received from remote VTEPs (UDP → feth).
    pub rx_packets: AtomicU64,
    /// RX: bytes received (inner frame bytes, excluding VXLAN header).
    pub rx_bytes: AtomicU64,
    /// RX: packets dropped (invalid VXLAN header, wrong VNI, too short).
    pub rx_drops: AtomicU64,
    /// RX: packets with invalid VXLAN header.
    pub rx_invalid: AtomicU64,

    /// TX: packets sent to remote VTEPs (feth → UDP).
    pub tx_packets: AtomicU64,
    /// TX: bytes sent (inner frame bytes, excluding VXLAN header).
    pub tx_bytes: AtomicU64,
    /// TX: send errors.
    pub tx_errors: AtomicU64,
    /// TX: packets dropped due to empty FDB lookup.
    pub tx_no_route: AtomicU64,
}

/// Maximum UDP datagram size: full 16-bit UDP length field.
/// Avoids truncation on `recvfrom` regardless of inner MTU.
const MAX_UDP_BUF: usize = 65535;

/// Maximum single ethernet frame from BPF.
/// Covers jumbo frames (9000) + ethernet header (14) + VLAN tags (4) + margin.
const MAX_ETHER_BUF: usize = 9216;

/// Socket receive buffer size (4 MiB).
const SO_RCVBUF_SIZE: libc::c_int = 4 * 1024 * 1024;
/// Socket send buffer size (4 MiB).
const SO_SNDBUF_SIZE: libc::c_int = 4 * 1024 * 1024;

/// Learned MAC entries expire after this duration.
const LEARNED_MAC_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Result of an FDB lookup — either a borrowed slice (static/BUM) or an
/// owned single address (learned).
enum FdbLookup<'a> {
    /// One or more static destinations (unicast hit or BUM flood list).
    Static(&'a [SocketAddr]),
    /// A single destination resolved from the learned MAC table.
    Learned(SocketAddr),
}

impl FdbLookup<'_> {
    fn as_slice(&self) -> &[SocketAddr] {
        match self {
            Self::Static(s) => s,
            Self::Learned(addr) => std::slice::from_ref(addr),
        }
    }
}

/// Forwarding database: maps destination MAC to remote VTEP(s).
///
/// - Unicast entries (`mac != 00:00:00:00:00:00`) map to a single VTEP.
/// - BUM entries (`mac == 00:00:00:00:00:00`) are collected into a flood list;
///   frames with no unicast match are sent to all BUM destinations.
#[derive(Debug)]
pub struct Fdb {
    /// Exact MAC → VTEP mapping.
    pub unicast: HashMap<[u8; 6], SocketAddr>,
    /// Flood list for broadcast / unknown-unicast / multicast.
    pub bum: Vec<SocketAddr>,
    /// Source MAC → (remote VTEP IP, last seen time) learned from incoming
    /// VXLAN packets.  Used for unicast forwarding (avoiding floods) and
    /// split-horizon filtering (don't send a frame back to the VTEP that
    /// originated it).  Entries expire after `LEARNED_MAC_TTL`.
    pub learned: RwLock<HashMap<[u8; 6], (std::net::IpAddr, Instant)>>,
    /// Maximum number of learned MAC entries.
    max_learned: usize,
    /// VXLAN destination port used when forwarding to learned peers.
    vxlan_port: u16,
}

impl Fdb {
    fn new(entries: &[FdbEntry], max_learned: usize, vxlan_port: u16) -> Self {
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
            learned: RwLock::new(HashMap::new()),
            max_learned,
            vxlan_port,
        }
    }

    /// Record the source MAC → remote VTEP IP from an incoming frame.
    fn learn(&self, src_mac: [u8; 6], peer: SocketAddr) {
        let mut table = self.learned.write().unwrap();
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
        let mut table = self.learned.write().unwrap();
        let before = table.len();
        table.retain(|_, (_, ts)| ts.elapsed() < LEARNED_MAC_TTL);
        let evicted = before - table.len();
        if evicted > 0 {
            tracing::debug!(evicted, remaining = table.len(), "learned MAC GC");
        }
    }

    /// Look up destinations for a destination MAC.
    ///
    /// Resolution order (mirrors Linux `vxlan_xmit`):
    /// 1. Broadcast/multicast → BUM flood list.
    /// 2. Static unicast FDB entry → single VTEP.
    /// 3. Learned MAC → single VTEP (IP from learned table + configured port).
    /// 4. Unknown unicast → BUM flood list.
    fn lookup(&self, dst_mac: [u8; 6]) -> FdbLookup<'_> {
        // Broadcast / multicast — always flood.
        if dst_mac[0] & 0x01 != 0 {
            return FdbLookup::Static(&self.bum);
        }
        // Static unicast.
        if let Some(addr) = self.unicast.get(&dst_mac) {
            return FdbLookup::Static(std::slice::from_ref(addr));
        }
        // Learned unicast.
        let table = self.learned.read().unwrap();
        if let Some(&(ip, ts)) = table.get(&dst_mac) {
            if ts.elapsed() < LEARNED_MAC_TTL {
                return FdbLookup::Learned(SocketAddr::new(ip, self.vxlan_port));
            }
        }
        // Unknown unicast — flood.
        FdbLookup::Static(&self.bum)
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
    fdb: Arc<Fdb>,
    stats: Arc<TunnelStats>,
}

impl VxlanServer {
    /// Create a new server from the parsed config.
    pub async fn bind(config: &config::Config) -> io::Result<Self> {
        let socket = UdpSocket::bind(config.server.listen).await?;
        set_sock_buf_size(socket.as_raw_fd());

        let max_learned = config.interface.subnet_host_count();
        let fdb = Fdb::new(&config.fdb, max_learned, config.server.listen.port());

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
            fdb: Arc::new(fdb),
            stats: Arc::new(TunnelStats::default()),
        })
    }

    /// Get a shared reference to the FDB for use by the inspect API.
    pub fn fdb(&self) -> &Arc<Fdb> {
        &self.fdb
    }

    /// Get a shared reference to the tunnel stats for use by the inspect API.
    pub fn stats(&self) -> &Arc<TunnelStats> {
        &self.stats
    }

    /// Run the server, forwarding packets in both directions until cancelled.
    ///
    /// After each readiness notification, drains all available packets before
    /// re-entering the event loop to reduce epoll overhead.
    pub async fn run(mut self) -> io::Result<()> {
        let vxlan_hdr = VxlanHdr::new(self.vni);
        let mut udp_buf = vec![0u8; MAX_UDP_BUF];
        let mut feth_buf = vec![0u8; MAX_ETHER_BUF];
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
                    // Drain remaining buffered BPF frames without waiting for I/O.
                    while let Some(n) = self.feth_io.try_next_frame(&mut feth_buf)? {
                        self.handle_tx(&vxlan_hdr, &feth_buf[..n]).await;
                    }
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
        let Ok((vxlan, inner_frame)) = VxlanHdr::from_bytes(data) else {
            self.stats.rx_invalid.fetch_add(1, Relaxed);
            return;
        };

        if vxlan.vni() != self.vni {
            self.stats.rx_drops.fetch_add(1, Relaxed);
            return;
        }

        if inner_frame.len() < protocol::ETH_HEADER_LEN {
            self.stats.rx_drops.fetch_add(1, Relaxed);
            return;
        }

        // Learn source MAC → remote VTEP for split-horizon filtering.
        if let Ok((eth, _)) = EthernetHeader::from_bytes(inner_frame) {
            self.fdb.learn(eth.src_mac, peer);
        }

        if let Err(e) = self.feth_io.send(inner_frame) {
            tracing::warn!(error = %e, "failed to inject frame into feth");
            self.stats.rx_drops.fetch_add(1, Relaxed);
            return;
        }

        self.stats.rx_packets.fetch_add(1, Relaxed);
        self.stats
            .rx_bytes
            .fetch_add(inner_frame.len() as u64, Relaxed);
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

        let result = self.fdb.lookup(dst_mac);
        let destinations = result.as_slice();
        if destinations.is_empty() {
            self.stats.tx_no_route.fetch_add(1, Relaxed);
            return;
        }

        let hdr_bytes = vxlan_hdr.as_bytes();
        self.socket.writable().await.ok();

        for &remote in destinations {
            let result = self.socket.try_io(Interest::WRITABLE, || {
                sendmsg_udp(self.socket.as_raw_fd(), &[hdr_bytes, frame], remote)
            });

            match result {
                Ok(n) => {
                    self.stats.tx_packets.fetch_add(1, Relaxed);
                    self.stats.tx_bytes.fetch_add(n as u64, Relaxed);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        dst = %config::format_mac(&dst_mac),
                        remote = %remote,
                        "failed to send vxlan datagram",
                    );
                    self.stats.tx_errors.fetch_add(1, Relaxed);
                }
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
    msg.msg_iov = iov.as_ptr().cast_mut();
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
fn set_sock_buf_size(fd: std::os::fd::RawFd) {
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
}
