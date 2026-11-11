//! Probe-Betrieb (`netpulse probe`): läuft in einem entfernten Sektor, braucht keine Datenbank.
//!
//! Umgebungsvariablen:
//! - `NETPULSE_SERVER`: Adresse des NetPulse-Servers, z. B. `https://monitoring.example.org`
//! - `PROBE_TOKEN`: Schlüssel der Probe (`npp_…`, unter Netzwerke → Probes angelegt)
//!
//! Ablauf: Aufgaben holen → Geräte prüfen → Ergebnisse senden; im Such-Takt zusätzlich die Netze des
//! Sektors durchsuchen und gefundene Geräte melden. Fehler werden protokolliert und beim nächsten
//! Durchlauf mitgeschickt; die Probe läuft weiter.

use std::{net::IpAddr, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use futures::{stream, StreamExt};
use serde::Deserialize;
use serde_json::json;

use crate::scanner::{discovery, monitor, net, net::Pinger};

#[derive(Deserialize)]
struct Task {
    monitor_interval_s: u64,
    discovery_interval_s: u64,
    networks: Vec<Network>,
    devices: Vec<Device>,
}

#[derive(Deserialize)]
struct Network {
    id: i64,
    cidr: String,
}

#[derive(Deserialize)]
struct Device {
    id: i64,
    ip: String,
    open_ports: Vec<i32>,
}

struct Client {
    http: reqwest::Client,
    server: String,
    token: String,
}

impl Client {
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let r = self.http.get(format!("{}/api/probe/v1/{path}", self.server)).bearer_auth(&self.token).send().await?;
        if !r.status().is_success() {
            bail!("Server antwortete {} auf {path}", r.status());
        }
        Ok(r.json().await?)
    }
    async fn post(&self, path: &str, body: &serde_json::Value) -> Result<()> {
        let r = self.http.post(format!("{}/api/probe/v1/{path}", self.server)).bearer_auth(&self.token).json(body).send().await?;
        if !r.status().is_success() {
            bail!("Server antwortete {} auf {path}", r.status());
        }
        Ok(())
    }
}

pub async fn run() -> Result<()> {
    let server = std::env::var("NETPULSE_SERVER").context("NETPULSE_SERVER fehlt (z. B. https://monitoring.example.org)")?;
    let token = std::env::var("PROBE_TOKEN").context("PROBE_TOKEN fehlt (unter Netzwerke → Probes anlegen)")?;
    let server = server.trim().trim_end_matches('/').to_string();
    if !server.starts_with("https://") && std::env::var("PROBE_ALLOW_HTTP").as_deref() != Ok("true") {
        bail!("NETPULSE_SERVER muss mit https:// beginnen (zum Testen im LAN: PROBE_ALLOW_HTTP=true)");
    }
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-probe-version", env!("CARGO_PKG_VERSION").parse()?);
    let http = reqwest::Client::builder().timeout(Duration::from_secs(60)).default_headers(headers).build()?;
    let client = Client { http, server, token: token.trim().to_string() };
    let pinger = Arc::new(Pinger::new());
    tracing::info!("NetPulse-Probe startet – Server {}", client.server);

    let mut last_error: Option<String> = None;
    let mut next_discovery = std::time::Instant::now();
    loop {
        let task: Task = match client.get("config").await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Aufgaben nicht abrufbar: {e:#}");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        let started = std::time::Instant::now();

        // Statusprüfung (wie beim Server: Ping, sonst bekannte Ports per TCP)
        let results: Vec<serde_json::Value> = stream::iter(task.devices)
            .map(|d| {
                let pinger = pinger.clone();
                async move {
                    let rtt = match d.ip.parse::<IpAddr>() {
                        Ok(ip) => monitor::check_device(&pinger, ip, &d.open_ports).await,
                        Err(_) => None,
                    };
                    json!({ "id": d.id, "up": rtt.is_some(), "rtt_ms": rtt.map(|r| r.as_secs_f32() * 1000.0) })
                }
            })
            .buffer_unordered(64)
            .collect()
            .await;
        // Eigene Netze mitschicken – der Server schlägt sie unter „Netze erkennen“ für den Sektor vor
        let local = crate::scanner::local::detect();
        match client.post("results", &json!({ "results": results, "error": last_error.take(), "local_networks": local })).await {
            Ok(()) => tracing::debug!("{} Prüfergebnisse gemeldet", results.len()),
            Err(e) => tracing::warn!("Ergebnisse nicht gesendet: {e:#}"),
        }

        // Netzsuche im eigenen Takt
        if std::time::Instant::now() >= next_discovery {
            next_discovery = std::time::Instant::now() + Duration::from_secs(task.discovery_interval_s.max(300));
            for network in &task.networks {
                if let Err(e) = scan(&client, &pinger, network).await {
                    tracing::warn!("Suche in {} fehlgeschlagen: {e:#}", network.cidr);
                    last_error = Some(format!("Suche in {}: {e:#}", network.cidr));
                }
            }
        }

        let wait = Duration::from_secs(task.monitor_interval_s.max(10)).saturating_sub(started.elapsed());
        tokio::time::sleep(wait).await;
    }
}

async fn scan(client: &Client, pinger: &Arc<Pinger>, network: &Network) -> Result<()> {
    let started = std::time::Instant::now();
    let (addr, prefix) = net::parse_cidr(&network.cidr)?;
    let targets = net::hosts(addr, prefix);
    tracing::info!("Suche in {} ({} Adressen)", network.cidr, targets.len());
    let found = discovery::sweep(pinger, &targets, None).await;
    let hosts: Vec<discovery::HostFacts> = stream::iter(found)
        .map(|(ip, rtt, mac)| discovery::gather(ip, rtt, mac))
        .buffer_unordered(16)
        .collect()
        .await;
    tracing::info!("{}: {} Geräte gefunden", network.cidr, hosts.len());
    client
        .post("discovery", &json!({ "network_id": network.id, "hosts": hosts, "duration_s": started.elapsed().as_secs() }))
        .await
}
