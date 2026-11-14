//! Zugangsdaten prüfen: einzeln („Testen“) oder als Suchlauf über viele Geräte.
//!
//! Ein Suchlauf ordnet die Zugangsdaten jedem Gerät zu, bei dem die Anmeldung klappt,
//! und stößt dort sofort eine tiefe Abfrage an. Fortschritt und Ergebnis je Gerät
//! liegen im Speicher und werden von der Oberfläche abgefragt.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use futures::{stream, StreamExt};
use serde::Serialize;
use serde_json::Value;

use super::{shelly, snmp, ssh, Credential};
use crate::AppState;

#[derive(Clone, Serialize)]
pub struct CheckResult {
    pub device_id: i64,
    pub label: String,
    pub ip: String,
    pub ok: bool,
    pub message: String,
}

#[derive(Clone, Serialize, Default)]
pub struct Job {
    pub running: bool,
    pub total: usize,
    pub done: usize,
    pub found: usize,
    pub started_at: Option<DateTime<Utc>>,
    pub results: Vec<CheckResult>,
}

#[derive(Default)]
pub struct Jobs {
    jobs: Mutex<HashMap<i64, Job>>,
}

impl Jobs {
    pub fn get(&self, credential_id: i64) -> Job {
        self.jobs.lock().unwrap().get(&credential_id).cloned().unwrap_or_default()
    }
}

#[derive(sqlx::FromRow)]
struct Target {
    id: i64,
    ip: String,
    label: String,
    open_ports: Vec<i32>,
    ssh_host_key: Option<String>,
    integration: Option<String>,
    tls_pin: Option<String>,
}

const TARGET_SELECT: &str = "SELECT id, host(ip) AS ip, COALESCE(name, reported_name, hostname, host(ip)) AS label,
                                    open_ports, ssh_host_key, integration, tls_pin FROM devices";

/// Eine Zugangsangabe gegen ein Gerät prüfen; liefert eine verständliche Meldung
async fn check(cred: &Credential, t: &Target) -> Result<String> {
    let ip: Ipv4Addr = t.ip.parse().map_err(|_| anyhow!("nur IPv4 wird unterstützt"))?;
    match cred.kind.as_str() {
        "snmp_v2c" | "snmp_v3" => {
            let mut session = snmp::open(ip, cred).await?;
            let sys = snmp::get(&mut session, &[&[1, 3, 6, 1, 2, 1, 1, 5, 0], &[1, 3, 6, 1, 2, 1, 1, 1, 0]]).await?;
            let name = sys.first().and_then(|(_, v)| v.text());
            let descr = sys.get(1).and_then(|(_, v)| v.text());
            if name.is_none() && descr.is_none() {
                bail!("Gerät antwortet, liefert aber keine Systemdaten (Zugriffsrechte der Community/des Benutzers prüfen)");
            }
            let descr: String = descr.unwrap_or_default().lines().next().unwrap_or_default().chars().take(80).collect();
            Ok(format!("SNMP ok – {}{}", name.unwrap_or_else(|| "(ohne Namen)".into()), if descr.is_empty() { String::new() } else { format!(" · {descr}") }))
        }
        "ssh_password" | "ssh_key" => {
            let port = cred.port.unwrap_or(22);
            if !t.open_ports.is_empty() && !t.open_ports.contains(&port) && port == 22 {
                bail!("Port 22 ist beim letzten Scan nicht offen gewesen – SSH am Gerät aktiviert?");
            }
            let out = ssh::run_command(ip, cred, t.ssh_host_key.as_deref(), "hostname")
                .await
                .map_err(|e| match e {
                    ssh::SshError::HostKeyChanged { .. } => anyhow!("SSH-Host-Schlüssel hat sich geändert – beim Gerät zurücksetzen"),
                    ssh::SshError::Failed(msg) => anyhow!(msg),
                })?;
            Ok(format!("SSH-Anmeldung ok – Hostname {}", out.trim()))
        }
        "http" => {
            // Passwörter nur an Geräte, die sich als Shelly ausgewiesen haben
            if t.integration.as_deref() != Some("shelly") {
                bail!("kein Shelly – HTTP-Zugangsdaten gelten derzeit für Shelly-Geräte");
            }
            let info = shelly::probe(ip).await.ok_or_else(|| anyhow!("kein Shelly erkannt (HTTP-Zugangsdaten gelten derzeit für Shelly-Geräte)"))?;
            let data = shelly::collect(ip, &info, Some(cred)).await?;
            let power = data["power_w"].as_f64().map(|w| format!(" · {w} W")).unwrap_or_default();
            Ok(format!("Shelly ok – {}{power}", data["name"].as_str().or(info.model.as_deref()).unwrap_or("Shelly")))
        }
        "http_basic" | "http_token" => {
            let path = cred.options["test_path"].as_str().filter(|p| !p.trim().is_empty()).unwrap_or("/");
            let reply = super::custom::http_request(ip, cred, t.tls_pin.as_deref(), "GET", path, None).await?;
            if !reply.status.is_success() {
                bail!("{} antwortete mit {}", reply.url, reply.status);
            }
            let size = reply.body.len();
            Ok(format!("HTTP-Anmeldung ok – {} antwortete mit {} ({size} Zeichen)", reply.url, reply.status))
        }
        "unifi" => {
            let (data, _) = super::unifi::collect(ip, cred, t.tls_pin.as_deref()).await?;
            Ok(format!(
                "UniFi ok – Version {}, {} Geräte ({} online), {} Clients",
                data["version"].as_str().unwrap_or("?"),
                data["devices_total"],
                data["devices_online"],
                data["clients_total"]
            ))
        }
        "fritzbox" | "opnsense" | "mikrotik" => {
            let (data, _) = super::collect_api(&cred.kind, ip, cred, t.tls_pin.as_deref()).await?;
            let what = [data["model"].as_str(), data["board"].as_str(), data["version"].as_str()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            Ok(format!("{} ok{} – {} verbundene Geräte", super::api_label(&cred.kind), if what.is_empty() { String::new() } else { format!(" ({what})") }, data["clients_total"]))
        }
        other => bail!("unbekannte Zugangsart {other}"),
    }
}

pub(crate) async fn load_credential(state: &AppState, credential_id: i64) -> Result<Credential> {
    let (name, kind, username, port, sealed, options): (String, String, Option<String>, Option<i32>, String, Value) =
        sqlx::query_as("SELECT name, kind, username, port, secret, options FROM credentials WHERE id = $1")
            .bind(credential_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| anyhow!("Zugangsdaten nicht gefunden"))?;
    Ok(Credential { id: credential_id, name, kind, username, port, secret: state.vault.open_value(&sealed)?, linked: true, options })
}

/// Einzeltest gegen ein Gerät (ohne Zuordnung)
pub async fn test_one(state: &AppState, credential_id: i64, device_id: i64) -> Result<CheckResult> {
    let cred = load_credential(state, credential_id).await?;
    let target: Target = sqlx::query_as(&format!("{TARGET_SELECT} WHERE id = $1"))
        .bind(device_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| anyhow!("Gerät nicht gefunden"))?;
    let result = check(&cred, &target).await;
    Ok(CheckResult {
        device_id,
        label: target.label,
        ip: target.ip,
        ok: result.is_ok(),
        message: result.unwrap_or_else(|e| format!("{e:#}")),
    })
}

/// Suchlauf starten. Ohne Geräteauswahl werden alle passenden Geräte geprüft:
/// SNMP → alle erreichbaren, SSH-Schlüssel → offener SSH-Port, HTTP → erkannte Shellys.
/// SSH-Passwörter nur für ausdrücklich ausgewählte Geräte.
pub async fn start_scan(state: &AppState, credential_id: i64, device_ids: Option<Vec<i64>>) -> Result<Job> {
    let cred = load_credential(state, credential_id).await?;
    if state.cred_jobs.get(credential_id).running {
        bail!("Für diese Zugangsdaten läuft bereits ein Suchlauf");
    }
    let targets: Vec<Target> = match &device_ids {
        Some(ids) => sqlx::query_as(&format!("{TARGET_SELECT} WHERE id = ANY($1) ORDER BY ip"))
            .bind(ids)
            .fetch_all(&state.db)
            .await?,
        None => {
            let filter = match cred.kind.as_str() {
                "snmp_v2c" | "snmp_v3" => "status = 'up'".to_string(),
                "ssh_key" => format!("status = 'up' AND {} = ANY(open_ports)", cred.port.unwrap_or(22)),
                "http" => "status = 'up' AND integration = 'shelly'".to_string(),
                "unifi" => bail!("UniFi-Zugangsdaten bitte gezielt dem Controller zuordnen (Gerät auswählen)"),
                "http_basic" | "http_token" => bail!("HTTP-Zugangsdaten werden nur an ausgewählte Geräte gesendet – bitte Geräte auswählen"),
                "fritzbox" | "opnsense" | "mikrotik" => bail!("Diese Zugangsdaten bitte gezielt dem Router zuordnen (Gerät auswählen)"),
                _ => bail!("SSH-Passwörter werden nur an ausgewählte Geräte gesendet – bitte Geräte auswählen"),
            };
            sqlx::query_as(&format!("{TARGET_SELECT} WHERE {filter} ORDER BY ip")).fetch_all(&state.db).await?
        }
    };
    let job = Job { running: true, total: targets.len(), started_at: Some(Utc::now()), ..Default::default() };
    state.cred_jobs.jobs.lock().unwrap().insert(credential_id, job.clone());

    let state = state.clone();
    let cred = Arc::new(cred);
    tokio::spawn(async move {
        stream::iter(targets)
            .for_each_concurrent(16, |target| {
                let state = state.clone();
                let cred = cred.clone();
                async move {
                    let result = check(&cred, &target).await;
                    if result.is_ok() {
                        let linked = sqlx::query(
                            "INSERT INTO device_credentials (device_id, credential_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        )
                        .bind(target.id)
                        .bind(cred.id)
                        .execute(&state.db)
                        .await;
                        if linked.is_ok() {
                            let _ = state.poll_tx.send(target.id);
                        }
                    }
                    let mut jobs = state.cred_jobs.jobs.lock().unwrap();
                    if let Some(job) = jobs.get_mut(&cred.id) {
                        job.done += 1;
                        job.found += usize::from(result.is_ok());
                        job.results.push(CheckResult {
                            device_id: target.id,
                            label: target.label,
                            ip: target.ip,
                            ok: result.is_ok(),
                            message: result.unwrap_or_else(|e| format!("{e:#}")),
                        });
                    }
                }
            })
            .await;
        if let Some(job) = state.cred_jobs.jobs.lock().unwrap().get_mut(&cred.id) {
            job.running = false;
        }
    });
    Ok(job)
}
