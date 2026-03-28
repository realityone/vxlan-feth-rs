pub mod protocol;
pub mod server;

use std::net::SocketAddr;

use feth_rs::feth::Feth;
use server::VxlanServerConfig;

const FETH_IO_UNIT: u32 = 101;
const FETH_IP_UNIT: u32 = 100;
const INNER_ADDR: &str = "10.0.0.2";
const INNER_PREFIX: u8 = 24;
const MTU: u32 = 1450;

/// Create and configure the feth pair using feth-rs.
fn setup_interfaces() -> Result<(Feth, Feth), feth_rs::feth::Error> {
    // Clean up any leftover interfaces first.
    if let Ok(old) = Feth::from_existing(format!("feth{FETH_IO_UNIT}")) {
        let _ = old.destroy();
    }
    if let Ok(old) = Feth::from_existing(format!("feth{FETH_IP_UNIT}")) {
        let _ = old.destroy();
    }

    tracing::info!(
        io = format_args!("feth{FETH_IO_UNIT}"),
        ip = format_args!("feth{FETH_IP_UNIT}"),
        "creating feth pair",
    );

    // Create both interfaces first, then set peer relationship.
    let feth_io = Feth::create(FETH_IO_UNIT)?;
    let feth_ip = Feth::create(FETH_IP_UNIT)?;

    feth_io.set_peer(feth_ip.name())?;

    // Configure I/O side (no IP — raw frames only).
    feth_io.set_mtu(MTU)?;
    feth_io.up()?;

    // Configure IP side.
    feth_ip.set_inet(INNER_ADDR, INNER_PREFIX)?;
    feth_ip.set_mtu(MTU)?;
    feth_ip.up()?;

    tracing::info!(
        ip_iface = feth_ip.name(),
        addr = format_args!("{INNER_ADDR}/{INNER_PREFIX}"),
        mtu = MTU,
        "feth pair ready",
    );

    Ok((feth_io, feth_ip))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let (feth_io, feth_ip) = setup_interfaces().map_err(|e| std::io::Error::other(e))?;

    let config = VxlanServerConfig {
        listen_addr: SocketAddr::from(([0, 0, 0, 0], protocol::IANA_VXLAN_UDP_PORT)),
        vni: 100,
        feth_ifname: "feth101".to_owned(),
        remote_vtep: SocketAddr::from(([192, 168, 50, 212], protocol::IANA_VXLAN_UDP_PORT)),
    };

    let server = server::VxlanServer::bind(config).await?;

    let result = tokio::select! {
        result = server.run() => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    };

    tracing::info!("tearing down feth interfaces");
    let _ = feth_io.destroy();
    let _ = feth_ip.destroy();

    result
}
