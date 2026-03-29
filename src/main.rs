pub mod config;
pub mod inspect;
pub mod protocol;
pub mod server;

use std::{net::Ipv4Addr, path::PathBuf};

use clap::{Parser, Subcommand};
use feth_rs::feth::{Feth, MacAddr};

#[derive(Parser)]
#[command(name = "vxlan-feth", about = "Userspace VXLAN tunnel over feth")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage the VXLAN server.
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Inspect the running server via the API.
    Inspect {
        /// Unix socket path of the inspect API server.
        #[arg(short, long, default_value = inspect::DEFAULT_SOCK_PATH)]
        server: PathBuf,
        #[command(subcommand)]
        query: InspectQuery,
    },
}

#[derive(Subcommand)]
enum ServerAction {
    /// Start the VXLAN server.
    Up {
        /// Path to the YAML config file [default: vxlan-feth.yaml].
        #[arg(default_value = "vxlan-feth.yaml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum InspectQuery {
    /// Show forwarding database entries.
    Fdb,
    /// Show learned MAC addresses.
    Learned,
    /// Show tunnel statistics.
    Stats,
}

/// Result of setting up the feth interface pair.
struct InterfaceSetup {
    feth_io: Feth,
    feth_ip: Feth,
    /// MAC address assigned to the IP-side interface.
    ip_mac: MacAddr,
    /// Overlay IPv4 address.
    ip_addr: Ipv4Addr,
}

/// Create and configure the feth pair from config.
fn setup_interfaces(
    iface: &config::InterfaceConfig,
) -> Result<InterfaceSetup, feth_rs::feth::Error> {
    let io_cfg = &iface.io;
    let ip_cfg = &iface.ip;
    let io_name = io_cfg.name();
    let ip_name = ip_cfg.name();

    // Clean up any leftover interfaces first.
    if let Ok(old) = Feth::from_existing(&io_name) {
        let _ = old.destroy();
    }
    if let Ok(old) = Feth::from_existing(&ip_name) {
        let _ = old.destroy();
    }

    tracing::info!(io = %io_name, ip = %ip_name, "creating feth pair");

    let feth_io = Feth::create(io_cfg.unit)?;
    let feth_ip = Feth::create(ip_cfg.unit)?;

    feth_io.set_peer(feth_ip.name())?;

    // Set MAC addresses (random if not configured).
    let io_mac = io_cfg.mac.unwrap_or_else(MacAddr::random);
    let ip_mac = ip_cfg.mac.unwrap_or_else(MacAddr::random);
    feth_io.set_mac(&io_mac)?;
    feth_ip.set_mac(&ip_mac)?;

    // I/O side: no IP — raw frames only.
    feth_io.set_mtu(io_cfg.mtu)?;
    feth_io.up()?;

    // IP side.
    let (addr, prefix) = ip_cfg
        .parse_address()
        .map_err(|e| feth_rs::feth::Error::InvalidName(e.to_string()))?;
    let ip_addr: Ipv4Addr = addr
        .parse()
        .map_err(|e: std::net::AddrParseError| feth_rs::feth::Error::InvalidName(e.to_string()))?;
    feth_ip.set_inet(addr, prefix)?;
    feth_ip.set_mtu(ip_cfg.mtu)?;
    feth_ip.up()?;

    tracing::info!(
        ip_iface = %ip_name,
        addr = %ip_cfg.address.as_deref().unwrap_or("none"),
        io_mac = %io_mac,
        ip_mac = %ip_mac,
        "feth pair ready",
    );

    Ok(InterfaceSetup {
        feth_io,
        feth_ip,
        ip_mac,
        ip_addr,
    })
}

async fn cmd_server_up(config_path: PathBuf) -> std::io::Result<()> {
    let config = config::Config::from_file(&config_path)?;
    tracing::info!(path = %config_path.display(), "loaded config");

    let iface_setup = setup_interfaces(&config.interface).map_err(std::io::Error::other)?;

    let garp = protocol::ArpFrame::gratuitous(&iface_setup.ip_mac.0, iface_setup.ip_addr);

    let server = server::VxlanServer::bind(&config).await?;

    // Start the inspect API.
    let api_path = PathBuf::from(
        config
            .server
            .api
            .as_deref()
            .unwrap_or(inspect::DEFAULT_SOCK_PATH),
    );
    {
        let fdb = server.fdb().clone();
        let stats = server.stats().clone();
        tokio::spawn(async move {
            if let Err(e) = inspect::serve(&api_path, fdb, stats).await {
                tracing::error!(error = %e, "inspect API failed");
            }
        });
    }

    let result = tokio::select! {
        result = server.run(|srv| Box::pin(async move {
            tracing::info!("sending gratuitous ARP to BUM peers");
            srv.flood_frame(garp.as_bytes()).await;
        })) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    };

    tracing::info!("tearing down feth interfaces");
    let _ = iface_setup.feth_io.destroy();
    let _ = iface_setup.feth_ip.destroy();

    result
}

async fn cmd_inspect(server: PathBuf, query: InspectQuery) -> std::io::Result<()> {
    let client = inspect::connect(&server).await?;

    match query {
        InspectQuery::Fdb => {
            let fdb = client
                .get_fdb(tarpc::context::current())
                .await
                .map_err(std::io::Error::other)?;
            println!("BUM flood list:");
            for entry in &fdb.bum {
                println!("  {}", entry.dst);
            }
            println!("\nUnicast entries:");
            for entry in &fdb.unicast {
                println!("  {} -> {}", entry.mac, entry.dst);
            }
        }
        InspectQuery::Learned => {
            let learned = client
                .get_learned(tarpc::context::current())
                .await
                .map_err(std::io::Error::other)?;
            if learned.is_empty() {
                println!("No learned MAC entries.");
            } else {
                println!("{:<20} {:<20} Age (s)", "MAC", "Peer IP");
                for entry in &learned {
                    println!("{:<20} {:<20} {}", entry.mac, entry.peer_ip, entry.age_secs);
                }
            }
        }
        InspectQuery::Stats => {
            let stats = client
                .get_stats(tarpc::context::current())
                .await
                .map_err(std::io::Error::other)?;
            println!(
                "RX: {} packets, {} bytes, {} drops, {} invalid",
                stats.rx_packets, stats.rx_bytes, stats.rx_drops, stats.rx_invalid
            );
            println!(
                "TX: {} packets, {} bytes, {} errors",
                stats.tx_packets, stats.tx_bytes, stats.tx_errors
            );
            println!(
                "    split-horizon: {}, no-route: {}",
                stats.tx_split_horizon, stats.tx_no_route
            );
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,tarpc=warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Server { action } => match action {
            ServerAction::Up { config } => cmd_server_up(config).await,
        },
        Command::Inspect { server, query } => cmd_inspect(server, query).await,
    }
}
