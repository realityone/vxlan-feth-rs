use std::{
    fmt,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
};

/// Errors that can occur during packet parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer is too short for the expected header.
    TooShort { expected: usize, actual: usize },
    /// Invalid VXLAN flags (I bit not set).
    InvalidVxlanFlags(u8),
    /// Unsupported IP version.
    UnsupportedIpVersion(u8),
    /// Unsupported `EtherType`.
    UnsupportedEtherType(u16),
    /// Invalid IP header length.
    InvalidIpHeaderLen(u8),
    /// Not a UDP packet.
    NotUdp { protocol: u8 },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { expected, actual } => {
                write!(f, "buffer too short: need {expected}, got {actual}")
            }
            Self::InvalidVxlanFlags(flags) => {
                write!(f, "invalid VXLAN flags: {flags:#04x} (I bit not set)")
            }
            Self::UnsupportedIpVersion(v) => write!(f, "unsupported IP version: {v}"),
            Self::UnsupportedEtherType(et) => write!(f, "unsupported EtherType: {et:#06x}"),
            Self::InvalidIpHeaderLen(ihl) => write!(f, "invalid IP header length: {ihl}"),
            Self::NotUdp { protocol } => write!(f, "not UDP: protocol {protocol}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Cast `&[u8]` to `&T` where `T` is a `#[repr(C)]` struct with alignment 1.
///
/// # Safety
///
/// `T` must be `#[repr(C)]` with all fields being `u8` or `[u8; N]`
/// (alignment 1, no padding). The caller must ensure valid data for `T`.
unsafe fn cast_ref<T>(buf: &[u8]) -> Result<&T, ParseError> {
    if buf.len() < size_of::<T>() {
        return Err(ParseError::TooShort {
            expected: size_of::<T>(),
            actual: buf.len(),
        });
    }
    Ok(unsafe { &*buf.as_ptr().cast::<T>() })
}

/// Cast and split: returns `(&T, &[u8])` where the second element is the
/// remaining bytes after the struct.
///
/// # Safety
///
/// Same requirements as [`cast_ref`].
unsafe fn cast_ref_with_payload<T>(buf: &[u8]) -> Result<(&T, &[u8]), ParseError> {
    let hdr = unsafe { cast_ref::<T>(buf)? };
    let payload = &buf[size_of::<T>()..];
    Ok((hdr, payload))
}

// ── Ethernet ────────────────────────────────────────────────────────────────

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN: u16 = 0x8100;

/// Ethernet frame header (14 bytes).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Destination MAC (bytes 0-3)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Dest MAC (4-5)  |         Source MAC (bytes 0-1)            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Source MAC (bytes 2-5)                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         EtherType             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: [u8; 2],
}

const _: () = assert!(size_of::<EthernetHeader>() == 14);

impl EthernetHeader {
    pub fn from_bytes(buf: &[u8]) -> Result<(&Self, &[u8]), ParseError> {
        // Safety: all fields are [u8; N], alignment is 1.
        unsafe { cast_ref_with_payload(buf) }
    }

    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes(self.ether_type)
    }
}

impl fmt::Debug for EthernetHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &self.dst_mac;
        let s = &self.src_mac;
        f.debug_struct("EthernetHeader")
            .field(
                "dst",
                &format_args!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    d[0], d[1], d[2], d[3], d[4], d[5]
                ),
            )
            .field(
                "src",
                &format_args!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    s[0], s[1], s[2], s[3], s[4], s[5]
                ),
            )
            .field("ethertype", &format_args!("{:#06x}", self.ethertype()))
            .finish_non_exhaustive()
    }
}

// ── IPv4 ────────────────────────────────────────────────────────────────────

pub const IP_PROTO_UDP: u8 = 17;

/// IPv4 header, fixed 20-byte portion.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |    DSCP/ECN   |         Total Length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|     Fragment Offset     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |        Header Checksum        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: [u8; 2],
    pub identification: [u8; 2],
    pub flags_fragment: [u8; 2],
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: [u8; 2],
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

const _: () = assert!(size_of::<Ipv4Header>() == 20);

impl Ipv4Header {
    /// Parse the fixed IPv4 header and return it with the payload.
    ///
    /// The payload starts at the IHL offset (which may be > 20 if options
    /// are present), and its length is bounded by the `total_length` field.
    pub fn from_bytes(buf: &[u8]) -> Result<(&Self, &[u8]), ParseError> {
        // Safety: all fields are u8 or [u8; N], alignment is 1.
        let (hdr, _) = unsafe { cast_ref_with_payload::<Self>(buf)? };

        let ihl = hdr.version_ihl & 0x0F;
        if ihl < 5 {
            return Err(ParseError::InvalidIpHeaderLen(ihl));
        }
        let hdr_len = usize::from(ihl) * 4;
        let total = hdr.total_length() as usize;
        if buf.len() < hdr_len {
            return Err(ParseError::TooShort {
                expected: hdr_len,
                actual: buf.len(),
            });
        }
        let end = total.min(buf.len());
        Ok((hdr, &buf[hdr_len..end]))
    }

    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    pub fn header_len(&self) -> usize {
        usize::from(self.ihl()) * 4
    }

    pub fn ecn(&self) -> u8 {
        self.dscp_ecn & 0x03
    }

    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.total_length)
    }

    pub fn identification(&self) -> u16 {
        u16::from_be_bytes(self.identification)
    }

    pub fn flags(&self) -> u8 {
        self.flags_fragment[0] >> 5
    }

    pub fn dont_fragment(&self) -> bool {
        self.flags() & 0x02 != 0
    }

    pub fn more_fragments(&self) -> bool {
        self.flags() & 0x01 != 0
    }

    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.flags_fragment[0] & 0x1F, self.flags_fragment[1]])
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.src_addr)
    }

    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.dst_addr)
    }
}

impl fmt::Debug for Ipv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv4Header")
            .field("src", &self.src_addr())
            .field("dst", &self.dst_addr())
            .field("protocol", &self.protocol)
            .field("ttl", &self.ttl)
            .field("total_length", &self.total_length())
            .finish_non_exhaustive()
    }
}

// ── IPv6 ────────────────────────────────────────────────────────────────────

/// IPv6 header (40 bytes, fixed).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version| Traffic Class |           Flow Label                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Payload Length        |  Next Header  |   Hop Limit   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Source Address                        |
/// |                         (128 bits)                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Destination Address                      |
/// |                         (128 bits)                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
pub struct Ipv6Header {
    pub version_tc_flow: [u8; 4],
    pub payload_length: [u8; 2],
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

const _: () = assert!(size_of::<Ipv6Header>() == 40);

impl Ipv6Header {
    /// Parse the fixed IPv6 header and return it with the payload.
    ///
    /// The payload length is bounded by the `payload_length` field.
    pub fn from_bytes(buf: &[u8]) -> Result<(&Self, &[u8]), ParseError> {
        // Safety: all fields are u8 or [u8; N], alignment is 1.
        let (hdr, _) = unsafe { cast_ref_with_payload::<Self>(buf)? };
        let len = hdr.payload_length() as usize;
        let end = (size_of::<Self>() + len).min(buf.len());
        Ok((hdr, &buf[size_of::<Self>()..end]))
    }

    pub fn version(&self) -> u8 {
        self.version_tc_flow[0] >> 4
    }

    pub fn traffic_class(&self) -> u8 {
        ((self.version_tc_flow[0] & 0x0F) << 4) | (self.version_tc_flow[1] >> 4)
    }

    pub fn ecn(&self) -> u8 {
        self.traffic_class() & 0x03
    }

    pub fn flow_label(&self) -> u32 {
        (u32::from(self.version_tc_flow[1]) & 0x0F) << 16
            | u32::from(self.version_tc_flow[2]) << 8
            | u32::from(self.version_tc_flow[3])
    }

    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes(self.payload_length)
    }

    pub fn src_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.src_addr)
    }

    pub fn dst_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.dst_addr)
    }
}

impl fmt::Debug for Ipv6Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv6Header")
            .field("src", &self.src_addr())
            .field("dst", &self.dst_addr())
            .field("next_header", &self.next_header)
            .field("hop_limit", &self.hop_limit)
            .field("payload_length", &self.payload_length())
            .finish_non_exhaustive()
    }
}

// ── UDP ─────────────────────────────────────────────────────────────────────

/// UDP header (8 bytes).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Length             |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
pub struct UdpHeader {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub length: [u8; 2],
    pub checksum: [u8; 2],
}

const _: () = assert!(size_of::<UdpHeader>() == 8);

impl UdpHeader {
    /// Parse the UDP header and return it with the payload.
    ///
    /// The payload length is bounded by the `length` field.
    pub fn from_bytes(buf: &[u8]) -> Result<(&Self, &[u8]), ParseError> {
        // Safety: all fields are [u8; 2], alignment is 1.
        let (hdr, _) = unsafe { cast_ref_with_payload::<Self>(buf)? };
        let len = hdr.length() as usize;
        let end = len.min(buf.len());
        Ok((hdr, &buf[size_of::<Self>()..end]))
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }

    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }
}

impl fmt::Debug for UdpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpHeader")
            .field("src_port", &self.src_port())
            .field("dst_port", &self.dst_port())
            .field("length", &self.length())
            .field("checksum", &format_args!("{:#06x}", self.checksum()))
            .finish()
    }
}

// ── VXLAN ───────────────────────────────────────────────────────────────────
//
// Matches Linux kernel `include/net/vxlan.h`.

pub const IANA_VXLAN_UDP_PORT: u16 = 4789;
/// `VXLAN_HF_VNI` = `cpu_to_be32(BIT(27))` = `0x0800_0000` in network order.
pub const VXLAN_HF_VNI: u32 = 0x0800_0000;

pub const VXLAN_N_VID: u32 = 1 << 24;
pub const VXLAN_VID_MASK: u32 = VXLAN_N_VID - 1;
/// VNI mask in network order: upper 24 bits of `vx_vni`.
pub const VXLAN_VNI_MASK: u32 = VXLAN_VID_MASK << 8;

/// `VXLAN_HF_RCO` = `cpu_to_be32(BIT(21))`.
pub const VXLAN_HF_RCO: u32 = 0x0020_0000;
pub const VXLAN_RCO_MASK: u32 = 0x7f;
pub const VXLAN_RCO_UDP: u32 = 0x80;
pub const VXLAN_RCO_SHIFT: u32 = 1;

/// `VXLAN_HF_GBP` = `cpu_to_be32(BIT(31))`.
pub const VXLAN_HF_GBP: u32 = 0x8000_0000;

pub const VXLAN_GBP_DONT_LEARN: u32 = 0x0040_0000;
pub const VXLAN_GBP_POLICY_APPLIED: u32 = 0x0008_0000;
pub const VXLAN_GBP_ID_MASK: u16 = 0xFFFF;

// VXLAN device flags (from `vxlan.h` `VXLAN_F_*`).
pub const VXLAN_F_LEARN: u32 = 0x01;
pub const VXLAN_F_PROXY: u32 = 0x02;
pub const VXLAN_F_RSC: u32 = 0x04;
pub const VXLAN_F_L2MISS: u32 = 0x08;
pub const VXLAN_F_L3MISS: u32 = 0x10;
pub const VXLAN_F_IPV6: u32 = 0x20;
pub const VXLAN_F_UDP_ZERO_CSUM_TX: u32 = 0x40;
pub const VXLAN_F_UDP_ZERO_CSUM6_TX: u32 = 0x80;
pub const VXLAN_F_UDP_ZERO_CSUM6_RX: u32 = 0x100;
pub const VXLAN_F_REMCSUM_TX: u32 = 0x200;
pub const VXLAN_F_REMCSUM_RX: u32 = 0x400;
pub const VXLAN_F_GBP: u32 = 0x800;
pub const VXLAN_F_REMCSUM_NOPARTIAL: u32 = 0x1000;
pub const VXLAN_F_COLLECT_METADATA: u32 = 0x2000;
pub const VXLAN_F_TTL_INHERIT: u32 = 0x1_0000;
pub const VXLAN_F_VNIFILTER: u32 = 0x2_0000;

/// VXLAN protocol header (RFC 7348) — matches `struct vxlanhdr` from `vxlan.h`.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R|R|R|R|I|R|R|R|               Reserved                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                VXLAN Network Identifier (VNI) |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Both fields are `__be32` in the kernel. The I flag is bit 27 of
/// `vx_flags`. The VNI occupies bits [31:8] of `vx_vni`.
#[repr(C)]
pub struct VxlanHdr {
    pub vx_flags: [u8; 4],
    pub vx_vni: [u8; 4],
}

const _: () = assert!(size_of::<VxlanHdr>() == 8);

impl VxlanHdr {
    /// Parse and validate a VXLAN header from a byte slice.
    pub fn from_bytes(buf: &[u8]) -> Result<(&Self, &[u8]), ParseError> {
        // Safety: all fields are [u8; 4], alignment is 1.
        let (hdr, payload) = unsafe { cast_ref_with_payload::<Self>(buf)? };
        if hdr.flags() & VXLAN_HF_VNI == 0 {
            return Err(ParseError::InvalidVxlanFlags(hdr.vx_flags[0]));
        }
        Ok((hdr, payload))
    }

    /// Parse without validating the I flag (for `VXLAN_F_COLLECT_METADATA` mode).
    pub fn from_bytes_unchecked(buf: &[u8]) -> Result<(&Self, &[u8]), ParseError> {
        // Safety: all fields are [u8; 4], alignment is 1.
        unsafe { cast_ref_with_payload(buf) }
    }

    /// Read `vx_flags` as a big-endian u32.
    pub fn flags(&self) -> u32 {
        u32::from_be_bytes(self.vx_flags)
    }

    /// Read `vx_vni` as a big-endian u32 (includes VNI + reserved byte).
    pub fn vni_field(&self) -> u32 {
        u32::from_be_bytes(self.vx_vni)
    }

    /// Extract the 24-bit VNI from `vx_vni`.
    ///
    /// Equivalent to the kernel's `vxlan_vni()`:
    /// `(__force u32)vni_field >> 8` (big-endian).
    pub fn vni(&self) -> u32 {
        self.vni_field() >> 8
    }

    /// Encode a 24-bit VNI into `vx_vni`.
    ///
    /// Equivalent to the kernel's `vxlan_vni_field()`:
    /// `(__force __be32)((__force u32)vni << 8)`.
    pub fn set_vni(&mut self, vni: u32) {
        self.vx_vni = (vni << 8).to_be_bytes();
    }

    /// Create a new VXLAN header with `VXLAN_HF_VNI` set and the given VNI.
    pub fn new(vni: u32) -> Self {
        Self {
            vx_flags: VXLAN_HF_VNI.to_be_bytes(),
            vx_vni: (vni << 8).to_be_bytes(),
        }
    }

    /// Return the header as a byte slice.
    pub fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
        // Safety: #[repr(C)] with alignment 1, no padding.
        unsafe { &*std::ptr::from_ref(self).cast::<[u8; size_of::<Self>()]>() }
    }

    /// Reinterpret as GBP header.
    ///
    /// # Safety
    ///
    /// Caller must ensure `VXLAN_HF_GBP` is set in `vx_flags`.
    pub unsafe fn as_gbp(&self) -> &VxlanHdrGbp {
        unsafe { &*std::ptr::from_ref(self).cast::<VxlanHdrGbp>() }
    }

}

impl fmt::Debug for VxlanHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VxlanHdr")
            .field("vx_flags", &format_args!("{:#010x}", self.flags()))
            .field("vni", &self.vni())
            .finish()
    }
}

/// VXLAN Group Based Policy Extension — matches `struct vxlanhdr_gbp`.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |G|R|R|R|I|R|R|R|R|D|R|R|A|R|R|R|        Group Policy ID        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                VXLAN Network Identifier (VNI) |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
pub struct VxlanHdrGbp {
    pub vx_flags: u8,
    pub flags_byte: u8,
    pub policy_id: [u8; 2],
    pub vx_vni: [u8; 4],
}

const _: () = assert!(size_of::<VxlanHdrGbp>() == 8);

impl VxlanHdrGbp {
    /// D bit — Don't Learn.
    pub fn dont_learn(&self) -> bool {
        // Big-endian bit layout: bit 6 of flags_byte.
        self.flags_byte & 0x40 != 0
    }

    /// A bit — Policy Applied.
    pub fn policy_applied(&self) -> bool {
        // Big-endian bit layout: bit 3 of flags_byte.
        self.flags_byte & 0x08 != 0
    }

    pub fn policy_id(&self) -> u16 {
        u16::from_be_bytes(self.policy_id)
    }
}

impl fmt::Debug for VxlanHdrGbp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VxlanHdrGbp")
            .field("dont_learn", &self.dont_learn())
            .field("policy_applied", &self.policy_applied())
            .field("policy_id", &self.policy_id())
            .finish_non_exhaustive()
    }
}

/// Metadata carried alongside a VXLAN packet — matches `struct vxlan_metadata`.
#[derive(Debug, Clone, Copy, Default)]
pub struct VxlanMetadata {
    pub gbp: u32,
}

// ── Outer IP layer (enum over v4/v6) ───────────────────────────────────────

/// The outer IP header, either IPv4 or IPv6.
#[derive(Debug)]
pub enum IpHeader<'a> {
    V4(&'a Ipv4Header),
    V6(&'a Ipv6Header),
}

impl<'a> IpHeader<'a> {
    /// Parse an IP header by inspecting the version nibble.
    /// Returns the header and the transport-layer payload.
    pub fn from_bytes(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        if buf.is_empty() {
            return Err(ParseError::TooShort {
                expected: 1,
                actual: 0,
            });
        }
        match buf[0] >> 4 {
            4 => {
                let (hdr, payload) = Ipv4Header::from_bytes(buf)?;
                Ok((Self::V4(hdr), payload))
            }
            6 => {
                let (hdr, payload) = Ipv6Header::from_bytes(buf)?;
                Ok((Self::V6(hdr), payload))
            }
            v => Err(ParseError::UnsupportedIpVersion(v)),
        }
    }

    /// The transport-layer protocol number (IPv4 protocol / IPv6 next header).
    pub fn protocol(&self) -> u8 {
        match self {
            Self::V4(h) => h.protocol,
            Self::V6(h) => h.next_header,
        }
    }
}

// ── Full VXLAN packet ───────────────────────────────────────────────────────

/// A fully-parsed VXLAN-encapsulated packet.
///
/// Packet layout:
/// ```text
/// [Outer Ethernet] [Outer IP] [Outer UDP] [VXLAN Header] [Inner Ethernet Frame...]
/// ```
///
/// All header references point directly into the original buffer — no copies.
#[derive(Debug)]
pub struct VxlanPacket<'a> {
    pub outer_eth: &'a EthernetHeader,
    pub outer_ip: IpHeader<'a>,
    pub outer_udp: &'a UdpHeader,
    pub vxlan: &'a VxlanHdr,
    pub inner_eth: &'a EthernetHeader,
    /// The inner payload after the inner Ethernet header (e.g. inner IP packet).
    pub inner_payload: &'a [u8],
}

impl<'a> VxlanPacket<'a> {
    /// Parse a complete VXLAN packet from a raw Ethernet frame.
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        Self::parse_with_port(buf, IANA_VXLAN_UDP_PORT)
    }

    /// Parse a complete VXLAN packet, accepting a custom destination port.
    ///
    /// Linux kernel default is 8472; IANA standard is 4789.
    pub fn parse_with_port(buf: &'a [u8], _expected_port: u16) -> Result<Self, ParseError> {
        // Layer 2: Outer Ethernet
        let (outer_eth, ip_buf) = EthernetHeader::from_bytes(buf)?;

        // Layer 3: Outer IP
        match outer_eth.ethertype() {
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {}
            other => return Err(ParseError::UnsupportedEtherType(other)),
        }
        let (outer_ip, udp_buf) = IpHeader::from_bytes(ip_buf)?;
        if outer_ip.protocol() != IP_PROTO_UDP {
            return Err(ParseError::NotUdp {
                protocol: outer_ip.protocol(),
            });
        }

        // Layer 4: Outer UDP
        let (outer_udp, vxlan_buf) = UdpHeader::from_bytes(udp_buf)?;

        // VXLAN header
        let (vxlan, inner_buf) = VxlanHdr::from_bytes(vxlan_buf)?;

        // Inner Ethernet frame
        let (inner_eth, inner_payload) = EthernetHeader::from_bytes(inner_buf)?;

        Ok(Self {
            outer_eth,
            outer_ip,
            outer_udp,
            vxlan,
            inner_eth,
            inner_payload,
        })
    }

    /// The 24-bit VNI of this packet.
    pub fn vni(&self) -> u32 {
        self.vxlan.vni()
    }
}

// ── ARP ─────────────────────────────────────────────────────────────────────

pub const ARP_HW_ETHERNET: u16 = 1;
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// ARP packet for Ethernet/IPv4 (28 bytes).
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Hardware Type          |         Protocol Type         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  HW Len | Proto Len |           Operation           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Sender Hardware Address                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Sender HW (cont) |         Sender Protocol Address          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Sender Proto (c)  |       Target Hardware Address           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                Target HW (cont)       |  Target Proto Addr   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Target Proto (cont)  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
pub struct ArpPacket {
    pub hw_type: [u8; 2],
    pub proto_type: [u8; 2],
    pub hw_len: u8,
    pub proto_len: u8,
    pub operation: [u8; 2],
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

const _: () = assert!(size_of::<ArpPacket>() == 28);

impl ArpPacket {
    pub fn from_bytes(buf: &[u8]) -> Result<(&Self, &[u8]), ParseError> {
        // Safety: all fields are u8 or [u8; N], alignment is 1.
        unsafe { cast_ref_with_payload(buf) }
    }

    pub fn hw_type(&self) -> u16 {
        u16::from_be_bytes(self.hw_type)
    }

    pub fn proto_type(&self) -> u16 {
        u16::from_be_bytes(self.proto_type)
    }

    pub fn operation(&self) -> u16 {
        u16::from_be_bytes(self.operation)
    }

    pub fn sender_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.sender_ip)
    }

    pub fn target_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.target_ip)
    }
}

impl fmt::Debug for ArpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_mac = |m: &[u8; 6]| {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        };
        f.debug_struct("ArpPacket")
            .field("operation", &self.operation())
            .field("sender_mac", &fmt_mac(&self.sender_mac))
            .field("sender_ip", &self.sender_ip())
            .field("target_mac", &fmt_mac(&self.target_mac))
            .field("target_ip", &self.target_ip())
            .finish_non_exhaustive()
    }
}

/// Combined Ethernet + ARP frame (42 bytes), for zero-copy construction
/// and parsing.
#[repr(C)]
pub struct ArpFrame {
    pub eth: EthernetHeader,
    pub arp: ArpPacket,
}

const _: () = assert!(size_of::<ArpFrame>() == 42);

impl ArpFrame {
    /// Parse an ARP frame from a byte slice.
    pub fn from_bytes(buf: &[u8]) -> Result<&Self, ParseError> {
        // Safety: all fields are u8 or [u8; N], alignment is 1.
        unsafe { cast_ref(buf) }
    }

    /// View the frame as a raw byte slice, suitable for sending on the wire.
    pub fn as_bytes(&self) -> &[u8; size_of::<Self>()] {
        // Safety: #[repr(C)] with alignment 1, no padding.
        unsafe { &*std::ptr::from_ref(self).cast::<[u8; size_of::<Self>()]>() }
    }

    /// Build a gratuitous ARP reply frame.
    ///
    /// A gratuitous ARP announces a MAC→IP binding to all hosts on the L2
    /// segment, causing them to update their ARP caches immediately.
    pub fn gratuitous(sender_mac: &[u8; 6], sender_ip: Ipv4Addr) -> Self {
        Self {
            eth: EthernetHeader {
                dst_mac: BROADCAST_MAC,
                src_mac: *sender_mac,
                ether_type: ETHERTYPE_ARP.to_be_bytes(),
            },
            arp: ArpPacket {
                hw_type: ARP_HW_ETHERNET.to_be_bytes(),
                proto_type: ETHERTYPE_IPV4.to_be_bytes(),
                hw_len: 6,
                proto_len: 4,
                operation: ARP_OP_REPLY.to_be_bytes(),
                sender_mac: *sender_mac,
                sender_ip: sender_ip.octets(),
                target_mac: BROADCAST_MAC,
                target_ip: sender_ip.octets(),
            },
        }
    }
}

// ── Convenience constant ────────────────────────────────────────────────────

pub const ETH_HEADER_LEN: usize = size_of::<EthernetHeader>();
pub const VXLAN_HEADER_LEN: usize = size_of::<VxlanHdr>();

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_header_roundtrip() {
        for vni in [0, 1, 100, 0xFFFFFF, 0x123456] {
            let hdr = VxlanHdr::new(vni);
            assert_eq!(hdr.vni(), vni);
            assert_eq!(hdr.flags() & VXLAN_HF_VNI, VXLAN_HF_VNI);

            // Also round-trip through bytes.
            let bytes = hdr.as_bytes();
            let (parsed, _) = VxlanHdr::from_bytes(bytes).unwrap();
            assert_eq!(parsed.vni(), vni);
        }
    }

    #[test]
    fn test_vxlan_header_missing_i_flag() {
        let buf = [0x00, 0, 0, 0, 0, 0, 0x01, 0];
        let err = VxlanHdr::from_bytes(&buf).unwrap_err();
        assert_eq!(err, ParseError::InvalidVxlanFlags(0x00));
    }

    #[test]
    fn test_vxlan_header_too_short() {
        let buf = [0x08, 0, 0];
        let err = VxlanHdr::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, ParseError::TooShort { expected: 8, .. }));
    }

    #[test]
    fn test_ethernet_header() {
        let mut buf = [0u8; 20];
        buf[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        buf[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        buf[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        let (eth, payload) = EthernetHeader::from_bytes(&buf).unwrap();
        assert_eq!(eth.dst_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(eth.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(eth.ethertype(), ETHERTYPE_IPV4);
        assert_eq!(payload.len(), 6);
    }

    #[test]
    fn test_udp_header() {
        let mut buf = [0u8; 16];
        buf[0..2].copy_from_slice(&4789u16.to_be_bytes());
        buf[2..4].copy_from_slice(&4789u16.to_be_bytes());
        buf[4..6].copy_from_slice(&16u16.to_be_bytes());
        buf[6..8].copy_from_slice(&0u16.to_be_bytes());

        let (udp, payload) = UdpHeader::from_bytes(&buf).unwrap();
        assert_eq!(udp.src_port(), 4789);
        assert_eq!(udp.dst_port(), 4789);
        assert_eq!(udp.length(), 16);
        assert_eq!(payload.len(), 8);
    }

    #[test]
    fn test_ipv4_header() {
        #[rustfmt::skip]
        let buf: [u8; 30] = [
            0x45, 0x00, 0x00, 0x1e, // version=4, ihl=5, total_length=30
            0x00, 0x00, 0x40, 0x00, // id=0, flags=DF, frag_offset=0
            0x40, 0x11, 0x00, 0x00, // ttl=64, protocol=17(UDP), checksum=0
            0x0a, 0x00, 0x00, 0x01, // src=10.0.0.1
            0x0a, 0x00, 0x00, 0x02, // dst=10.0.0.2
            // 10 bytes of payload
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let (ip, payload) = Ipv4Header::from_bytes(&buf).unwrap();
        assert_eq!(ip.version(), 4);
        assert_eq!(ip.ihl(), 5);
        assert_eq!(ip.header_len(), 20);
        assert_eq!(ip.total_length(), 30);
        assert_eq!(ip.ttl, 64);
        assert_eq!(ip.protocol, IP_PROTO_UDP);
        assert_eq!(ip.src_addr(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.dst_addr(), Ipv4Addr::new(10, 0, 0, 2));
        assert!(ip.dont_fragment());
        assert_eq!(payload.len(), 10);
    }

    /// Build a minimal complete VXLAN packet and parse it.
    #[test]
    fn test_full_vxlan_packet_parse() {
        let mut pkt = Vec::new();

        // Outer Ethernet: dst + src + ethertype(IPv4)
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&[0x01; 6]);
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        // Outer IPv4 header (20 bytes)
        let ip_start = pkt.len();
        #[rustfmt::skip]
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x00, // version=4, ihl=5, total_length (filled later)
            0x00, 0x00, 0x40, 0x00, // id, flags=DF
            0x40, 0x11, 0x00, 0x00, // ttl=64, proto=UDP
            0x0a, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x0a, 0x00, 0x00, 0x02, // dst 10.0.0.2
        ]);

        // Outer UDP header (8 bytes)
        let udp_start = pkt.len();
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&IANA_VXLAN_UDP_PORT.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // length (filled later)
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum

        // VXLAN header (8 bytes)
        let vxlan_hdr = VxlanHdr::new(42);
        pkt.extend_from_slice(vxlan_hdr.as_bytes());

        // Inner Ethernet (14 bytes) + some payload
        pkt.extend_from_slice(&[0xaa; 6]);
        pkt.extend_from_slice(&[0xbb; 6]);
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        pkt.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        // Patch lengths
        let ip_total = (pkt.len() - ip_start) as u16;
        pkt[ip_start + 2..ip_start + 4].copy_from_slice(&ip_total.to_be_bytes());
        let udp_len = (pkt.len() - udp_start) as u16;
        pkt[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());

        let parsed = VxlanPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.vni(), 42);
        assert_eq!(parsed.inner_eth.dst_mac, [0xaa; 6]);
        assert_eq!(parsed.inner_eth.src_mac, [0xbb; 6]);
        assert_eq!(parsed.inner_eth.ethertype(), ETHERTYPE_IPV4);
        assert_eq!(parsed.inner_payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_arp_frame_roundtrip() {
        let mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let ip = Ipv4Addr::new(10, 0, 0, 2);

        let frame = ArpFrame::gratuitous(&mac, ip);
        let bytes = frame.as_bytes();
        assert_eq!(bytes.len(), 42);

        // Parse it back.
        let parsed = ArpFrame::from_bytes(bytes).unwrap();
        assert_eq!(parsed.eth.dst_mac, BROADCAST_MAC);
        assert_eq!(parsed.eth.src_mac, mac);
        assert_eq!(parsed.eth.ethertype(), ETHERTYPE_ARP);
        assert_eq!(parsed.arp.hw_type(), ARP_HW_ETHERNET);
        assert_eq!(parsed.arp.proto_type(), ETHERTYPE_IPV4);
        assert_eq!(parsed.arp.hw_len, 6);
        assert_eq!(parsed.arp.proto_len, 4);
        assert_eq!(parsed.arp.operation(), ARP_OP_REPLY);
        assert_eq!(parsed.arp.sender_mac, mac);
        assert_eq!(parsed.arp.sender_ip(), ip);
        assert_eq!(parsed.arp.target_mac, BROADCAST_MAC);
        assert_eq!(parsed.arp.target_ip(), ip);
    }
}
