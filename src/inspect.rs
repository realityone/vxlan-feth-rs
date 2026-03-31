use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use futures::{StreamExt, future};
use serde::{Deserialize, Serialize};
use tarpc::{context::Context, server::Channel};

use crate::{
    config,
    server::{Fdb, TunnelStats},
};

pub const DEFAULT_SOCK_PATH: &str = "/tmp/vxlan-feth.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdbUnicastEntry {
    pub mac: String,
    pub dst: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdbBumEntry {
    pub dst: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdbInfo {
    pub unicast: Vec<FdbUnicastEntry>,
    pub bum: Vec<FdbBumEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedEntry {
    pub mac: String,
    pub peer_ip: String,
    pub age_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsInfo {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_drops: u64,
    pub rx_invalid: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_errors: u64,
    pub tx_no_route: u64,
}

#[tarpc::service]
pub trait Inspect {
    async fn get_fdb() -> FdbInfo;
    async fn get_learned() -> Vec<LearnedEntry>;
    async fn get_stats() -> StatsInfo;
}

#[derive(Clone)]
struct InspectServer {
    fdb: Arc<Fdb>,
    stats: Arc<TunnelStats>,
}

impl Inspect for InspectServer {
    async fn get_fdb(self, _: Context) -> FdbInfo {
        let unicast = self
            .fdb
            .unicast
            .iter()
            .map(|(mac, dst)| FdbUnicastEntry {
                mac: config::format_mac(mac).to_string(),
                dst: dst.to_string(),
            })
            .collect();
        let bum = self
            .fdb
            .bum
            .iter()
            .map(|dst| FdbBumEntry {
                dst: dst.to_string(),
            })
            .collect();
        FdbInfo { unicast, bum }
    }

    async fn get_learned(self, _: Context) -> Vec<LearnedEntry> {
        let table = self.fdb.learned.read().unwrap();
        table
            .iter()
            .map(|(mac, (ip, ts))| LearnedEntry {
                mac: config::format_mac(mac).to_string(),
                peer_ip: ip.to_string(),
                age_secs: ts.elapsed().as_secs(),
            })
            .collect()
    }

    async fn get_stats(self, _: Context) -> StatsInfo {
        use std::sync::atomic::Ordering::Relaxed;
        StatsInfo {
            rx_packets: self.stats.rx_packets.load(Relaxed),
            rx_bytes: self.stats.rx_bytes.load(Relaxed),
            rx_drops: self.stats.rx_drops.load(Relaxed),
            rx_invalid: self.stats.rx_invalid.load(Relaxed),
            tx_packets: self.stats.tx_packets.load(Relaxed),
            tx_bytes: self.stats.tx_bytes.load(Relaxed),
            tx_errors: self.stats.tx_errors.load(Relaxed),
            tx_no_route: self.stats.tx_no_route.load(Relaxed),
        }
    }
}

pub async fn serve(path: &Path, fdb: Arc<Fdb>, stats: Arc<TunnelStats>) -> std::io::Result<()> {
    // Clean up stale socket file.
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let mut incoming =
        tarpc::serde_transport::unix::listen(path, tarpc::tokio_serde::formats::Json::default)
            .await?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    tracing::info!(path = %path.display(), "inspect API listening");

    while let Some(result) = incoming.next().await {
        match result {
            Ok(transport) => {
                tracing::debug!("inspect client connected");

                let server = InspectServer {
                    fdb: Arc::clone(&fdb),
                    stats: Arc::clone(&stats),
                };
                let channel = tarpc::server::BaseChannel::with_defaults(transport);
                tokio::spawn(channel.execute(server.serve()).for_each(|resp| {
                    tokio::spawn(resp);
                    future::ready(())
                }));
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to accept inspect connection");
            }
        }
    }
    Ok(())
}

pub async fn connect(path: &Path) -> std::io::Result<InspectClient> {
    let transport =
        tarpc::serde_transport::unix::connect(path, tarpc::tokio_serde::formats::Json::default)
            .await?;
    Ok(InspectClient::new(tarpc::client::Config::default(), transport).spawn())
}
