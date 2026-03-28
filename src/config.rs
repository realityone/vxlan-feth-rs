use std::{fmt, io, net::SocketAddr, path::Path};

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
}

/// feth interface pair settings.
#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceConfig {
    /// Unit number for the I/O-side feth (e.g. 101 → feth101).
    pub io_unit: u32,
    /// Unit number for the IP-side feth (e.g. 100 → feth100).
    pub ip_unit: u32,
    /// Inner IP address with prefix length (e.g. "10.0.0.2/24").
    pub address: String,
    /// MTU for both interfaces.
    pub mtu: u32,
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
    pub fn io_name(&self) -> String {
        format!("feth{}", self.io_unit)
    }

    pub fn ip_name(&self) -> String {
        format!("feth{}", self.ip_unit)
    }

    /// Parse `address` field into (ip_str, prefix_len).
    pub fn parse_address(&self) -> io::Result<(&str, u8)> {
        let (ip, prefix) = self.address.split_once('/').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected CIDR notation (e.g. 10.0.0.2/24), got: {}",
                    self.address
                ),
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
    parse_mac(&s).map_err(serde::de::Error::custom)
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("expected 6 colon-separated octets, got: {s}"));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("invalid hex octet '{part}' in MAC: {s}"))?;
    }
    Ok(mac)
}
