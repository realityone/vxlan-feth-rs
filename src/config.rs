use std::{fmt, io, net::SocketAddr, path::Path};

use feth_rs::feth::MacAddr;
use serde::Deserialize;

/// Top-level configuration loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub interface: InterfaceConfig,
    pub fdb: Vec<FdbEntry>,
}

/// VXLAN server settings.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Local bind address (e.g. "0.0.0.0:4789").
    pub listen: SocketAddr,
    /// 24-bit VXLAN Network Identifier.
    pub vni: u32,
    /// Inspect API unix socket path (e.g. "/tmp/vxlan-feth.sock").
    /// Defaults to "/tmp/vxlan-feth.sock".
    pub api: Option<String>,
    /// BPF→TX channel capacity. Defaults to 2048.
    pub bpf_channel_cap: Option<usize>,
}

/// feth interface pair settings.
#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceConfig {
    /// I/O-side feth — raw frames, no IP.
    pub io: FethSideConfig,
    /// IP-side feth — carries the overlay address.
    pub ip: FethSideConfig,
}

/// Per-side feth interface settings.
#[derive(Debug, Clone, Deserialize)]
pub struct FethSideConfig {
    /// Unit number (e.g. 101 → feth101).
    pub unit: u32,
    /// IP address with prefix length (e.g. "10.0.0.2/24"). Only meaningful for the IP side.
    pub address: Option<String>,
    /// MTU for this interface.
    pub mtu: u32,
    /// MAC address (e.g. "02:aa:bb:cc:dd:ee"). Random if omitted.
    #[serde(default, deserialize_with = "deserialize_optional_mac")]
    pub mac: Option<MacAddr>,
}

/// A forwarding database entry mapping a MAC address to a remote VTEP.
///
/// `00:00:00:00:00:00` is the BUM (broadcast, unknown-unicast, multicast)
/// wildcard — packets with no specific FDB match are flooded to all BUM
/// entries.
#[derive(Debug, Clone, Deserialize)]
pub struct FdbEntry {
    /// Destination MAC address. Use `00:00:00:00:00:00` for BUM flooding.
    #[serde(deserialize_with = "deserialize_mac")]
    pub mac: [u8; 6],
    /// Remote VTEP socket address (ip:port).
    pub dst: SocketAddr,
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        serde_yaml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl InterfaceConfig {
    /// Compute the number of host addresses in the IP-side CIDR subnet.
    /// E.g. /24 → 254, /16 → 65534.  Returns 254 as fallback.
    pub fn subnet_host_count(&self) -> usize {
        let prefix_len = self.ip.parse_address().map(|(_, p)| p).unwrap_or(24);
        if prefix_len >= 31 {
            return 2usize.saturating_pow(32 - u32::from(prefix_len));
        }
        // 2^(32 - prefix) - 2  (exclude network + broadcast)
        (1usize << (32 - prefix_len)) - 2
    }
}

impl FethSideConfig {
    pub fn name(&self) -> String {
        format!("feth{}", self.unit)
    }

    /// Parse `address` field into (`ip_str`, `prefix_len`).
    pub fn parse_address(&self) -> io::Result<(&str, u8)> {
        let addr = self
            .address
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "address is required"))?;
        let (ip, prefix) = addr.split_once('/').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected CIDR notation (e.g. 10.0.0.2/24), got: {addr}"),
            )
        })?;
        let prefix_len: u8 = prefix.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid prefix length: {e}"),
            )
        })?;
        Ok((ip, prefix_len))
    }
}

impl FdbEntry {
    /// Returns `true` if this is a BUM wildcard entry (all-zeros MAC).
    pub fn is_bum(&self) -> bool {
        self.mac == [0; 6]
    }
}

/// Display a MAC address in colon-separated hex.
pub fn format_mac(mac: &[u8; 6]) -> impl fmt::Display + '_ {
    struct MacFmt<'a>(&'a [u8; 6]);
    impl fmt::Display for MacFmt<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let m = self.0;
            write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        }
    }
    MacFmt(mac)
}

fn deserialize_mac<'de, D>(deserializer: D) -> Result<[u8; 6], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let mac: MacAddr = s.parse().map_err(serde::de::Error::custom)?;
    Ok(mac.0)
}

fn deserialize_optional_mac<'de, D>(deserializer: D) -> Result<Option<MacAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(s) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let mac: MacAddr = s.parse().map_err(serde::de::Error::custom)?;
    Ok(Some(mac))
}
