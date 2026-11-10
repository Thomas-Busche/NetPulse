//! Tiefe Abfragen („Inventar“) über SNMP und SSH.
//!
//! Alle `INVENTORY_INTERVAL_MIN` Minuten werden Geräte mit zugeordneten Zugangsdaten abgefragt.
//! Zugangsdaten mit „automatisch ausprobieren“ werden bei Geräten ohne Zuordnung getestet
//! (SNMP immer, SSH nur mit Schlüssel und nur bei offenem Port) und bei Erfolg fest zugeordnet.

pub mod check;
pub mod fast;
pub mod fritzbox;
pub mod live;
pub mod mikrotik;
pub mod netclients;
pub mod opnsense;
pub mod shelly;
pub mod snmp;
pub mod ssh;
pub mod tls;
pub mod unifi;

use std::{net::Ipv4Addr, time::Duration};

use anyhow::Result;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{scanner, AppState};

/// Geheimer Teil einer Zugangsangabe (liegt verschlüsselt in der Datenbank)
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priv_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priv_password: Option<String>,
}

#[derive(Clone)]
pub struct Credential {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub username: Option<String>,
    pub port: Option<i32>,
    pub secret: Secret,
    pub linked: bool,
}

impl Credential {
    fn is_snmp(&self) -> bool {
        self.kind.starts_with("snmp")
    }
}

/// Wie oft Geräte ohne passende Zugangsdaten erneut automatisch probiert werden
const AUTO_RETRY: &str = "6 hours";

pub async fn run(state: AppState, mut requests: UnboundedReceiver<i64>) {
    tokio::time::sleep(Duration::from_secs(20)).await;
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let ids: Vec<i64> = tokio::select! {
            _ = tick.tick() => match due_devices(&state).await {
                Ok(ids) => ids,
                Err(e) => { tracing::error!("Inventar: Geräteliste nicht ladbar: {e:#}"); continue; }
            },
            Some(id) = requests.recv() => {
                let mut ids = vec![id];
                while let Ok(id) = requests.try_recv() { ids.push(id); }
                ids
            }
        };
        stream::iter(ids)
            .for_each_concurrent(8, |id| {
                let state = state.clone();
                async move {
                    match tokio::spawn(async move { poll_device(&state, id).await }).await {
                        Ok(Err(e)) => tracing::warn!("Inventar für Gerät {id} fehlgeschlagen: {e:#}"),
                        Err(e) => tracing::error!("Inventar für Gerät {id} abgebrochen: {e}"),
                        Ok(Ok(())) => {}
                    }
                }
            })
            .await;
    }
}

async fn due_devices(state: &AppState) -> sqlx::Result<Vec<i64>> {
    let rows: Vec<(i64,)> = sqlx::query_as(&format!(
        "SELECT d.id FROM devices d
          WHERE d.status = 'up' AND (
                ((d.integration IS NOT NULL OR EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = d.id))
                 AND (d.inventory_at IS NULL OR d.inventory_at < now() - make_interval(secs => $1)))
             OR (d.integration IS NULL AND NOT EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = d.id)
                 AND EXISTS (SELECT 1 FROM credentials c WHERE c.auto)
                 AND (d.inventory_at IS NULL OR d.inventory_at < now() - interval '{AUTO_RETRY}')))
          ORDER BY d.inventory_at NULLS FIRST
          LIMIT 200"
    ))
    .bind(state.config.inventory_interval.as_secs_f64())
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

#[derive(sqlx::FromRow)]
struct CredentialRow {
    id: i64,
    name: String,
    kind: String,
    username: Option<String>,
    port: Option<i32>,
    secret: String,
    linked: bool,
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    ip: String,
    open_ports: Vec<i32>,
    ssh_host_key: Option<String>,
    inventory: Option<Value>,
    inventory_error: Option<String>,
    label: String,
    device_type: Option<String>,
    wan_interface: Option<String>,
    wan_interface_manual: bool,
    integration: Option<String>,
    tls_pin: Option<String>,
}

pub(crate) async fn load_credentials(state: &AppState, device_id: i64) -> Result<Vec<Credential>> {
    let rows: Vec<CredentialRow> = sqlx::query_as(
        "SELECT c.id, c.name, c.kind, c.username, c.port, c.secret,
                EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = $1 AND dc.credential_id = c.id) AS linked
           FROM credentials c
          WHERE c.auto OR c.id IN (SELECT credential_id FROM device_credentials WHERE device_id = $1)
          ORDER BY linked DESC, c.id",
    )
    .bind(device_id)
    .fetch_all(&state.db)
    .await?;
    let mut creds = Vec::new();
    for row in rows {
        match state.vault.open_value::<Secret>(&row.secret) {
            Ok(secret) => creds.push(Credential {
                id: row.id,
                name: row.name,
                kind: row.kind,
                username: row.username,
                port: row.port,
                secret,
                linked: row.linked,
            }),
            Err(e) => tracing::error!("Zugangsdaten {}: {e:#}", row.id),
        }
    }
    Ok(creds)
}

/// Schrittweises Protokoll einer Abfrage (Reiter „Diagnose“ und System-Log)
struct Trace {
    label: String,
    steps: Vec<Value>,
}

impl Trace {
    fn add(&mut self, ok: Option<bool>, text: impl Into<String>) {
        let text = text.into();
        match ok {
            Some(false) => tracing::warn!(target: "netpulse::inventar", "{}: {text}", self.label),
            _ => tracing::debug!(target: "netpulse::inventar", "{}: {text}", self.label),
        }
        self.steps.push(json!({ "time": chrono::Utc::now(), "ok": ok, "text": text }));
    }
    fn to_json(&self) -> Value {
        json!({ "time": chrono::Utc::now(), "steps": self.steps })
    }
}

/// Fragt ein Gerät ab und speichert Inventar, Messwerte und abgeleitete Angaben.
pub async fn poll_device(state: &AppState, device_id: i64) -> Result<()> {
    let _perf = crate::perf::Timer::new("Inventar-Abfrage (je Gerät)");
    let row: Option<DeviceRow> = sqlx::query_as(
        "SELECT host(ip) AS ip, open_ports, ssh_host_key, inventory, inventory_error,
                COALESCE(name, reported_name, hostname, host(ip)) AS label, device_type, wan_interface, wan_interface_manual,
                integration, tls_pin
           FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(DeviceRow {
        ip,
        open_ports,
        ssh_host_key: host_key,
        inventory: previous,
        inventory_error: previous_error,
        label,
        device_type,
        wan_interface,
        wan_interface_manual,
        integration,
        tls_pin,
    }) = row
    else {
        return Ok(());
    };
    let Ok(addr) = ip.parse::<Ipv4Addr>() else { return Ok(()) };

    let credentials = load_credentials(state, device_id).await?;
    let has_linked = credentials.iter().any(|c| c.linked);
    let mut errors: Vec<String> = Vec::new();
    let mut inventory = Map::new();
    let mut trace = Trace { label: format!("{label} ({ip})"), steps: vec![] };
    let linked_count = credentials.iter().filter(|c| c.linked).count();
    trace.add(
        None,
        format!(
            "Abfrage gestartet – {linked_count} zugeordnete, {} automatische Zugangsdaten{}",
            credentials.len() - linked_count,
            integration.as_deref().map(|i| format!(", Geräte-Schnittstelle: {i}")).unwrap_or_default()
        ),
    );

    // SNMP: zugeordnete zuerst, dann automatische
    for cred in credentials.iter().filter(|c| c.is_snmp()) {
        match snmp::collect(addr, cred).await {
            Ok(data) => {
                trace.add(Some(true), format!("SNMP mit „{}“: Daten gelesen", cred.name));
                inventory.insert("snmp".into(), data);
                link(state, device_id, cred).await?;
                break;
            }
            Err(e) if cred.linked => {
                trace.add(Some(false), format!("SNMP mit „{}“: {e:#}", cred.name));
                errors.push(format!("SNMP: {e:#}"));
            }
            // automatischer Versuch – Fehlschlag ist normal
            Err(e) => trace.add(None, format!("SNMP mit „{}“ (automatisch) passt nicht: {e:#}", cred.name)),
        }
    }

    // SSH: Passwort-Zugänge nur bei fester Zuordnung (sonst würde das Passwort an fremde Geräte gehen)
    for cred in credentials.iter().filter(|c| c.kind.starts_with("ssh")) {
        let port = cred.port.unwrap_or(22);
        if !cred.linked && (cred.kind != "ssh_key" || !open_ports.contains(&port)) {
            trace.add(None, format!("SSH mit „{}“ übersprungen (automatisch nur mit Schlüssel und offenem Port {port})", cred.name));
            continue;
        }
        match ssh::collect(addr, cred, host_key.as_deref()).await {
            Ok(result) => {
                trace.add(
                    Some(true),
                    format!("SSH mit „{}“: Daten gelesen ({})", cred.name, result.data["os"].as_str().unwrap_or("System")),
                );
                if host_key.is_none() {
                    sqlx::query("UPDATE devices SET ssh_host_key = $2 WHERE id = $1")
                        .bind(device_id)
                        .bind(&result.host_key)
                        .execute(&state.db)
                        .await?;
                }
                inventory.insert("ssh".into(), result.data);
                link(state, device_id, cred).await?;
                break;
            }
            Err(ssh::SshError::HostKeyChanged { expected, seen }) => {
                let message = format!(
                    "SSH-Host-Schlüssel von {label} hat sich geändert ({expected} → {seen}). Abfrage gestoppt – \
                     bei Neuinstallation in der Geräteansicht zurücksetzen, sonst möglicher Angriff prüfen."
                );
                if !previous_error.as_deref().unwrap_or_default().contains("Host-Schlüssel") {
                    scanner::add_event(&state.db, device_id, "ssh_key_changed", &message).await?;
                }
                trace.add(Some(false), "SSH: Host-Schlüssel hat sich geändert – Abfrage gestoppt");
                errors.push("SSH: Host-Schlüssel hat sich geändert".into());
                break;
            }
            Err(ssh::SshError::Failed(e)) if cred.linked => {
                trace.add(Some(false), format!("SSH mit „{}“: {e}", cred.name));
                errors.push(format!("SSH: {e}"));
            }
            Err(ssh::SshError::Failed(e)) => trace.add(None, format!("SSH mit „{}“ (automatisch) passt nicht: {e}", cred.name)),
        }
    }

    // Shelly: Daten über die lokale HTTP-API; Passwort nur, falls am Gerät eines gesetzt ist.
    // HTTP-Zugangsdaten gehen ausschließlich an Geräte, die sich vorher als Shelly ausgewiesen haben.
    if integration.as_deref() == Some("shelly") {
        match shelly::probe(addr).await {
            None => {
                trace.add(Some(false), "Shelly antwortet nicht auf http://…/shelly (Gerät aus, WLAN schwach oder Webserver blockiert?)");
                errors.push("Shelly: keine Antwort auf /shelly".into());
            }
            Some(info) => {
                trace.add(
                    Some(true),
                    format!(
                        "Shelly Gen{} erkannt ({}), Passwortschutz {}",
                        info.generation,
                        info.model.as_deref().unwrap_or("Modell unbekannt"),
                        if info.auth { "aktiv" } else { "aus" }
                    ),
                );
                // Gen1 überträgt das Passwort per Basic-Auth unverschlüsselt → nur fest zugeordnete Zugangsdaten
                let http_creds: Vec<&Credential> =
                    credentials.iter().filter(|c| c.kind == "http" && (c.linked || info.generation >= 2)).collect();
                if info.generation == 1 && info.auth && http_creds.is_empty() && credentials.iter().any(|c| c.kind == "http") {
                    trace.add(None, "Shelly Gen1 überträgt Passwörter unverschlüsselt – automatische HTTP-Zugangsdaten werden hier nicht gesendet, bitte gezielt zuordnen");
                }
                let result = if info.auth && http_creds.is_empty() {
                    Err(anyhow::anyhow!(
                        "Passwortschutz aktiv, aber keine HTTP-Zugangsdaten vorhanden – unter Zugangsdaten „HTTP / Web-Anmeldung“ anlegen"
                    ))
                } else if info.auth {
                    let mut last = Err(anyhow::anyhow!("Anmeldung fehlgeschlagen"));
                    for cred in http_creds {
                        last = shelly::collect(addr, &info, Some(cred)).await;
                        match &last {
                            Ok(_) => {
                                trace.add(Some(true), format!("Anmeldung mit „{}“ erfolgreich", cred.name));
                                link(state, device_id, cred).await?;
                                break;
                            }
                            Err(e) => trace.add(Some(false), format!("Anmeldung mit „{}“: {e:#}", cred.name)),
                        }
                    }
                    last
                } else {
                    shelly::collect(addr, &info, None).await
                };
                match result {
                    Ok(data) => {
                        let channels = data["channels"].as_array().map_or(0, Vec::len);
                        let power = data["power_w"].as_f64().map(|w| format!(", {w} W")).unwrap_or_default();
                        trace.add(Some(true), format!("Shelly-Daten gelesen: {channels} Kanäle{power}"));
                        inventory.insert("shelly".into(), data);
                    }
                    Err(e) => {
                        if !info.auth || trace.steps.last().is_none_or(|s| s["ok"] != false) {
                            trace.add(Some(false), format!("Shelly: {e:#}"));
                        }
                        errors.push(format!("Shelly: {e:#}"));
                    }
                }
            }
        }
    }

    // UniFi-Controller: nur mit fest zugeordneten Zugangsdaten – API-Schlüssel und Passwort gehen nie an fremde Geräte
    for cred in credentials.iter().filter(|c| c.kind == "unifi") {
        if !cred.linked {
            trace.add(None, format!("UniFi „{}“ übersprungen – wird nur bei fester Zuordnung zum Controller genutzt", cred.name));
            continue;
        }
        let how = if cred.username.as_deref().is_some_and(|u| !u.trim().is_empty()) { "lokales Konto" } else { "API-Schlüssel" };
        match unifi::collect(addr, cred, tls_pin.as_deref()).await {
            Ok((data, pin)) => {
                if tls_pin.is_none() {
                    if let Some(pin) = pin {
                        sqlx::query("UPDATE devices SET tls_pin = $2 WHERE id = $1").bind(device_id).bind(pin).execute(&state.db).await?;
                        trace.add(Some(true), "Zertifikat des Controllers gemerkt – eine spätere Änderung wird als möglicher Angriff gemeldet");
                    }
                }
                trace.add(
                    Some(true),
                    format!(
                        "UniFi-Controller mit „{}“ ({how}, Port {}, Version {}): {} Geräte ({} online), {} Clients",
                        cred.name,
                        data["port"],
                        data["version"].as_str().unwrap_or("?"),
                        data["devices_total"],
                        data["devices_online"],
                        data["clients_total"]
                    ),
                );
                inventory.insert("unifi".into(), data);
                break;
            }
            Err(e) => {
                trace.add(Some(false), format!("UniFi mit „{}“ ({how}): {e:#}", cred.name));
                errors.push(format!("UniFi: {e:#}"));
            }
        }
    }

    // Router/Firewalls mit eigener Schnittstelle (FRITZ!Box, OPNsense, MikroTik) – ebenfalls nur fest zugeordnet
    for cred in credentials.iter().filter(|c| API_KINDS.contains(&c.kind.as_str())) {
        if !cred.linked {
            continue;
        }
        let label = api_label(&cred.kind);
        match collect_api(&cred.kind, addr, cred, tls_pin.as_deref()).await {
            Ok((data, pin)) => {
                if tls_pin.is_none() {
                    if let Some(pin) = pin {
                        sqlx::query("UPDATE devices SET tls_pin = $2 WHERE id = $1").bind(device_id).bind(pin).execute(&state.db).await?;
                    }
                }
                trace.add(Some(true), format!("{label} mit „{}“: {} verbundene Geräte gelesen", cred.name, data["clients_total"]));
                inventory.insert(cred.kind.clone(), data);
            }
            Err(e) => {
                trace.add(Some(false), format!("{label} mit „{}“: {e:#}", cred.name));
                errors.push(format!("{label}: {e:#}"));
            }
        }
    }
    if let Some(n) = rebuild_netclients(&mut inventory, device_id) {
        trace.add(Some(true), format!("Verbundene Geräte: {n} (für Geräteliste, Clients und Netzwerkkarte)"));
    }

    // HTTP-Zugangsdaten gelten nur für erkannte Shellys – sagen, warum sie hier nicht versucht wurden
    if integration.as_deref() != Some("shelly") {
        for cred in credentials.iter().filter(|c| c.kind == "http") {
            trace.add(None, format!("„{}“ (HTTP) nicht versucht – gilt nur für Geräte, die sich als Shelly ausgewiesen haben", cred.name));
        }
    }

    if inventory.is_empty() {
        // Nur bei fest zugeordneten Zugangsdaten ist ein Fehlschlag eine Meldung wert;
        // dass automatische Versuche nicht passen, ist der Normalfall.
        let error = if has_linked || integration.is_some() { errors.join(" · ") } else { String::new() };
        trace.add((!error.is_empty()).then_some(false), "Ergebnis: keine Detaildaten (Erreichbarkeit wird trotzdem überwacht)");
        trace.add(None, advice(&open_ports, has_linked));
        sqlx::query(
            "UPDATE devices SET inventory_at = now(), inventory_error = NULLIF($2, ''), inventory_log = $3 WHERE id = $1",
        )
        .bind(device_id)
        .bind(error)
        .bind(trace.to_json())
        .execute(&state.db)
        .await?;
        return Ok(());
    }

    let now = chrono::Utc::now();
    inventory.insert("collected_at".into(), json!(now));
    let inventory = Value::Object(inventory);
    let wan = if wan_interface_manual {
        wan_interface
    } else {
        detect_wan(&inventory, device_type.as_deref())
    };
    let rates = interface_rates(&inventory, previous.as_ref());
    let stats = derive_stats(&inventory, &rates, wan.as_deref());
    let derived = derive_fields(&inventory);

    sqlx::query(
        "UPDATE devices SET
             inventory = $2, inventory_at = now(), inventory_error = NULLIF($3, ''),
             os = COALESCE($4, os), model = COALESCE($5, model),
             hostname = COALESCE(hostname, $6), vendor = COALESCE($7, vendor),
             wan_interface = $8, reported_name = COALESCE($9, reported_name), inventory_log = $10
         WHERE id = $1",
    )
    .bind(device_id)
    .bind(&inventory)
    .bind(errors.join(" · "))
    .bind(derived.os)
    .bind(derived.model)
    .bind(derived.hostname)
    .bind(derived.vendor)
    .bind(&wan)
    .bind(derived.reported_name)
    .bind({
        let sources: Vec<&str> = ["snmp", "ssh", "shelly", "unifi"].into_iter().filter(|k| inventory.get(*k).is_some()).collect();
        trace.add(Some(true), format!("Gespeichert ({})", sources.join(" + ").to_uppercase()));
        trace.to_json()
    })
    .execute(&state.db)
    .await?;

    if stats.iter().any(Option::is_some) {
        sqlx::query(
            "INSERT INTO device_stats (time, device_id, cpu_pct, mem_pct, disk_pct, temp_c, rx_bps, tx_bps, clients, power_w)
             VALUES (now(), $1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(device_id)
        .bind(stats[0].map(|v| v as f32))
        .bind(stats[1].map(|v| v as f32))
        .bind(stats[2].map(|v| v as f32))
        .bind(stats[3].map(|v| v as f32))
        .bind(stats[4])
        .bind(stats[5])
        .bind(stats[6].map(|v| v as f32))
        .bind(stats[7].map(|v| v as f32))
        .execute(&state.db)
        .await?;
    }
    // Verlauf je Schnittstelle (höchstens 64, nur mit Messwert)
    let rates: Vec<&InterfaceRate> = rates.iter().filter(|r| r.rx.is_some() || r.tx.is_some()).take(64).collect();
    if !rates.is_empty() {
        sqlx::query(
            "INSERT INTO interface_stats (time, device_id, name, rx_bps, tx_bps)
             SELECT now(), $1, u.name, u.rx, u.tx FROM UNNEST($2::text[], $3::float8[], $4::float8[]) AS u(name, rx, tx)",
        )
        .bind(device_id)
        .bind(rates.iter().map(|r| r.name.clone()).collect::<Vec<_>>())
        .bind(rates.iter().map(|r| r.rx).collect::<Vec<_>>())
        .bind(rates.iter().map(|r| r.tx).collect::<Vec<_>>())
        .execute(&state.db)
        .await?;
    }
    if let Some(unifi) = inventory.get("unifi") {
        if let Err(e) = apply_unifi(state, unifi).await {
            tracing::warn!("UniFi-Daten konnten nicht übernommen werden: {e:#}");
        }
    }
    if let Some(clients) = inventory["netclients"]["clients"].as_array() {
        if let Err(e) = apply_clients(state, device_id, clients).await {
            tracing::warn!("Verbundene Geräte konnten nicht übernommen werden: {e:#}");
        }
    }
    scanner::reclassify(&state.db, device_id).await?;
    Ok(())
}

/// Verständlicher Hinweis, warum keine Detaildaten kamen und was man tun kann
fn advice(open_ports: &[i32], has_linked: bool) -> String {
    let has = |p: i32| open_ports.contains(&p);
    let ports = if open_ports.is_empty() {
        "keine offenen Dienste gefunden".to_string()
    } else {
        format!("offene Ports: {}", open_ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
    };
    let mut tips = Vec::new();
    if has(22) {
        tips.push("SSH ist offen → SSH-Zugangsdaten (am besten mit Schlüssel) zuordnen");
    }
    if has(11443) || has(8443) {
        tips.push("sieht nach UniFi-Controller aus → Zugangsart „UniFi-Controller“ mit API-Schlüssel zuordnen");
    }
    if has(5985) || has(5986) || has(3389) {
        tips.push("Windows → OpenSSH-Server aktivieren oder SNMP-Dienst einrichten");
    }
    if tips.is_empty() && (has(80) || has(443)) {
        tips.push("nur eine Weboberfläche – falls das Gerät SNMP kann, dort aktivieren und SNMP-Zugangsdaten zuordnen");
    }
    if tips.is_empty() {
        tips.push("typisch für Handys, TVs und viele IoT-Geräte: sie bieten keine Abfrage an – das ist normal, Online-Status und Antwortzeit werden trotzdem überwacht");
    }
    format!(
        "Bedeutung: {}. {ports}. Tipp: {}",
        if has_linked { "die zugeordneten Zugangsdaten haben nicht funktioniert (siehe oben)" } else { "es gibt für dieses Gerät keine passende Abfragemöglichkeit" },
        tips.join("; ")
    )
}

/// UniFi-Controller-Daten auf die Geräte in NetPulse übertragen (Zuordnung über die MAC-Adresse):
/// Namen und Modelle der UniFi-Geräte, Auslastung als Messwerte, Client-Namen als Gerätenamen.
async fn apply_unifi(state: &AppState, unifi: &Value) -> Result<()> {
    let devices = unifi["devices"].as_array().cloned().unwrap_or_default();
    let mut macs = Vec::new();
    let mut names = Vec::new();
    let mut models = Vec::new();
    let mut types = Vec::new();
    let (mut cpu, mut mem, mut rx, mut tx, mut clients) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for d in &devices {
        let Some(mac) = d["mac"].as_str() else { continue };
        macs.push(mac.to_lowercase());
        names.push(d["name"].as_str().map(str::to_string));
        let model = d["model"].as_str().map(str::to_string);
        types.push(model.as_deref().and_then(unifi::device_type).map(str::to_string));
        models.push(model);
        cpu.push(d["cpu_pct"].as_f64().map(|v| v as f32));
        mem.push(d["mem_pct"].as_f64().map(|v| v as f32));
        rx.push(d["rx_bps"].as_f64());
        tx.push(d["tx_bps"].as_f64());
        clients.push(d["clients"].as_f64().map(|v| v as f32));
    }
    if !macs.is_empty() {
        sqlx::query(
            "UPDATE devices d SET reported_name = COALESCE(u.name, d.reported_name), model = COALESCE(u.model, d.model),
                    device_type = CASE WHEN d.device_type_manual OR u.kind IS NULL THEN d.device_type ELSE u.kind END,
                    vendor = COALESCE(d.vendor, 'Ubiquiti')
               FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[]) AS u(mac, name, model, kind)
              WHERE lower(d.mac) = u.mac",
        )
        .bind(&macs)
        .bind(&names)
        .bind(&models)
        .bind(&types)
        .execute(&state.db)
        .await?;
        sqlx::query(
            "INSERT INTO device_stats (time, device_id, cpu_pct, mem_pct, rx_bps, tx_bps, clients)
             SELECT now(), d.id, u.cpu, u.mem, u.rx, u.tx, u.clients
               FROM UNNEST($1::text[], $2::real[], $3::real[], $4::float8[], $5::float8[], $6::real[]) AS u(mac, cpu, mem, rx, tx, clients)
               JOIN devices d ON lower(d.mac) = u.mac
              WHERE u.cpu IS NOT NULL OR u.mem IS NOT NULL OR u.rx IS NOT NULL OR u.clients IS NOT NULL",
        )
        .bind(&macs)
        .bind(&cpu)
        .bind(&mem)
        .bind(&rx)
        .bind(&tx)
        .bind(&clients)
        .execute(&state.db)
        .await?;
    }
    // Abhängigkeiten: Client hängt an Access Point/Switch (nur, wenn nicht von Hand gesetzt)
    let (child_macs, parent_macs): (Vec<String>, Vec<String>) = unifi["clients"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| Some((c["mac"].as_str()?.to_lowercase(), c["uplink_mac"].as_str()?.to_lowercase())))
        .unzip();
    if !child_macs.is_empty() {
        sqlx::query(
            "UPDATE devices d SET parent_id = p.id
               FROM UNNEST($1::text[], $2::text[]) AS u(mac, up) JOIN devices p ON lower(p.mac) = u.up
              WHERE lower(d.mac) = u.mac AND NOT d.parent_manual AND d.id <> p.id AND d.parent_id IS DISTINCT FROM p.id",
        )
        .bind(&child_macs)
        .bind(&parent_macs)
        .execute(&state.db)
        .await?;
    }
    // Datenraten und WLAN-Signal je Client in den Verlauf des passenden Geräts
    // (aus Sicht des Geräts: empfangen = Download, gesendet = Upload)
    let mut c_macs = Vec::new();
    let (mut c_rx, mut c_tx, mut c_sig) = (Vec::new(), Vec::new(), Vec::new());
    for c in unifi["clients"].as_array().into_iter().flatten() {
        let Some(mac) = c["mac"].as_str() else { continue };
        let (down, up, sig) = (c["down_bps"].as_f64(), c["up_bps"].as_f64(), c["signal_dbm"].as_f64());
        if down.is_none() && up.is_none() && sig.is_none() {
            continue;
        }
        c_macs.push(mac.to_lowercase());
        c_rx.push(down);
        c_tx.push(up);
        c_sig.push(sig.map(|v| v as f32));
    }
    if !c_macs.is_empty() {
        sqlx::query(
            "INSERT INTO device_stats (time, device_id, rx_bps, tx_bps, wifi_signal)
             SELECT now(), d.id, u.rx, u.tx, u.sig
               FROM UNNEST($1::text[], $2::float8[], $3::float8[], $4::real[]) AS u(mac, rx, tx, sig)
               JOIN devices d ON lower(d.mac) = u.mac",
        )
        .bind(&c_macs)
        .bind(&c_rx)
        .bind(&c_tx)
        .bind(&c_sig)
        .execute(&state.db)
        .await?;
    }
    // Client-Namen aus dem Controller für Geräte ohne eigenen Namen
    let (client_macs, client_names): (Vec<String>, Vec<String>) = unifi["clients"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| Some((c["mac"].as_str()?.to_lowercase(), c["name"].as_str().filter(|n| !n.trim().is_empty())?.to_string())))
        .unzip();
    if !client_macs.is_empty() {
        sqlx::query(
            "UPDATE devices d SET reported_name = u.name
               FROM UNNEST($1::text[], $2::text[]) AS u(mac, name)
              WHERE lower(d.mac) = u.mac AND d.reported_name IS NULL",
        )
        .bind(&client_macs)
        .bind(&client_names)
        .execute(&state.db)
        .await?;
    }
    Ok(())
}

/// UniFi-Controller jede Minute abfragen (Client-Datenraten, Auslastung der Access Points),
/// unabhängig vom 5-Minuten-Takt der übrigen Inventar-Abfragen.
pub async fn unifi_loop(state: AppState) {
    tokio::time::sleep(Duration::from_secs(45)).await;
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let controllers: Vec<(i64, String, Option<String>)> = match sqlx::query_as(
            "SELECT d.id, host(d.ip), d.tls_pin FROM devices d
              WHERE d.status = 'up' AND d.inventory ? 'unifi'
                AND d.inventory_at < now() - interval '50 seconds'
                AND EXISTS (SELECT 1 FROM device_credentials dc JOIN credentials c ON c.id = dc.credential_id
                             WHERE dc.device_id = d.id AND c.kind = 'unifi')",
        )
        .fetch_all(&state.db)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!("UniFi: Controller-Liste nicht ladbar: {e}");
                continue;
            }
        };
        for (id, ip, pin) in controllers {
            let Ok(addr) = ip.parse::<Ipv4Addr>() else { continue };
            let _perf = crate::perf::Timer::new("UniFi-Abfrage (je Minute)");
            let Ok(creds) = load_credentials(&state, id).await else { continue };
            let Some(cred) = creds.iter().find(|c| c.kind == "unifi" && c.linked) else { continue };
            match unifi::collect(addr, cred, pin.as_deref()).await {
                Ok((data, _)) => {
                    // Nur den UniFi-Teil ersetzen – SNMP/SSH-Daten des Controllers bleiben; inventory_at bleibt,
                    // damit die vollständige Abfrage im normalen Takt weiterläuft
                    let saved = sqlx::query(
                        "UPDATE devices SET inventory = jsonb_set(COALESCE(inventory, '{}'), '{unifi}', $2)
                          WHERE id = $1",
                    )
                    .bind(id)
                    .bind(&data)
                    .execute(&state.db)
                    .await;
                    if let Err(e) = saved {
                        tracing::warn!("UniFi-Daten von {ip} nicht gespeichert: {e}");
                        continue;
                    }
                    if let Err(e) = apply_unifi(&state, &data).await {
                        tracing::warn!("UniFi-Daten konnten nicht übernommen werden: {e:#}");
                    }
                    state.hub.publish(&serde_json::json!({ "type": "unifi", "controller": id, "time": chrono::Utc::now() }));
                }
                // Fehler meldet die reguläre Abfrage im Reiter „Diagnose“ – hier nur protokollieren
                Err(e) => tracing::debug!("UniFi-Minutenabfrage {ip}: {e:#}"),
            }
        }
        api_minute(&state).await;
    }
}

/// FRITZ!Box, OPNsense, MikroTik: verbundene Geräte jede Minute auffrischen
async fn api_minute(state: &AppState) {
    let rows: Vec<(i64, String, Option<String>, String)> = sqlx::query_as(
        "SELECT DISTINCT d.id, host(d.ip), d.tls_pin, c.kind FROM devices d
           JOIN device_credentials dc ON dc.device_id = d.id JOIN credentials c ON c.id = dc.credential_id
          WHERE d.status = 'up' AND c.kind = ANY($1) AND d.inventory ? c.kind
            AND d.inventory_at < now() - interval '50 seconds'",
    )
    .bind(API_KINDS)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for (id, ip, pin, kind) in rows {
        let Ok(addr) = ip.parse::<Ipv4Addr>() else { continue };
        let _perf = crate::perf::Timer::new("Router-Abfrage (je Minute)");
        let Ok(creds) = load_credentials(state, id).await else { continue };
        let Some(cred) = creds.iter().find(|c| c.kind == kind && c.linked) else { continue };
        let Ok((mut data, _)) = collect_api(&kind, addr, cred, pin.as_deref()).await else { continue };
        let fresh = data.as_object_mut().and_then(|d| d.remove("clients")).unwrap_or(json!([]));
        // Bisherige Clients dieser Quelle durch die neuen ersetzen, die anderer Quellen behalten
        let current: Option<Value> = sqlx::query_scalar("SELECT inventory->'netclients' FROM devices WHERE id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await
            .ok()
            .flatten();
        let mut clients: Vec<Value> = current
            .as_ref()
            .and_then(|c| c["clients"].as_array())
            .map(|list| list.iter().filter(|c| c["source"] != kind.as_str()).cloned().collect())
            .unwrap_or_default();
        for mut c in fresh.as_array().cloned().unwrap_or_default() {
            c["source_id"] = json!(id);
            clients.push(c);
        }
        let mut sources: Vec<Value> = current.as_ref().and_then(|c| c["sources"].as_array().cloned()).unwrap_or_default();
        if !sources.contains(&json!(kind)) {
            sources.push(json!(kind));
        }
        let netclients = json!({ "sources": sources, "clients": clients, "time": chrono::Utc::now() });
        let saved = sqlx::query(
            "UPDATE devices SET inventory = jsonb_set(jsonb_set(inventory, ARRAY[$2::text], $3), '{netclients}', $4) WHERE id = $1",
        )
        .bind(id)
        .bind(&kind)
        .bind(&data)
        .bind(&netclients)
        .execute(&state.db)
        .await;
        if saved.is_err() {
            continue;
        }
        if let Err(e) = apply_clients(state, id, netclients["clients"].as_array().map(Vec::as_slice).unwrap_or_default()).await {
            tracing::warn!("Verbundene Geräte von {ip} nicht übernommen: {e:#}");
        }
        state.hub.publish(&json!({ "type": "unifi", "controller": id, "time": chrono::Utc::now() }));
    }
}

// ---------------------------------------------------------------------------
// Verbundene Geräte aus Routern, Switches und Access Points (herstellerübergreifend)
// ---------------------------------------------------------------------------

/// Zugangsarten mit eigener Schnittstelle, die verbundene Geräte liefern
pub const API_KINDS: &[&str] = &["fritzbox", "opnsense", "mikrotik"];

pub fn api_label(kind: &str) -> &'static str {
    match kind {
        "fritzbox" => "FRITZ!Box",
        "opnsense" => "OPNsense",
        "mikrotik" => "MikroTik",
        _ => "Schnittstelle",
    }
}

/// Eine der Hersteller-Schnittstellen abfragen → (Daten, gesehenes Zertifikat)
pub async fn collect_api(kind: &str, ip: Ipv4Addr, cred: &Credential, pin: Option<&str>) -> Result<(Value, Option<String>)> {
    match kind {
        "fritzbox" => Ok((fritzbox::collect(ip, cred).await?, None)),
        "opnsense" => opnsense::collect(ip, cred, pin).await,
        "mikrotik" => mikrotik::collect(ip, cred, pin).await,
        other => anyhow::bail!("{other} ist keine Router-Schnittstelle"),
    }
}

/// Client-Listen aller Quellen dieses Geräts einsammeln → `inventory.netclients`
/// (die großen Listen werden aus den Einzelteilen entfernt, damit sie nicht doppelt gespeichert werden)
fn rebuild_netclients(inventory: &mut Map<String, Value>, device_id: i64) -> Option<usize> {
    let mut all: Vec<Value> = Vec::new();
    let mut sources: Vec<&str> = Vec::new();
    for (part, key) in [("ssh", "net_clients"), ("snmp", "net_clients"), ("fritzbox", "clients"), ("opnsense", "clients"), ("mikrotik", "clients")] {
        let Some(list) = inventory.get_mut(part).and_then(|p| p.as_object_mut()).and_then(|p| p.remove(key)) else { continue };
        for mut c in list.as_array().cloned().unwrap_or_default() {
            c["source_id"] = json!(device_id);
            all.push(c);
        }
        sources.push(part);
    }
    if all.is_empty() {
        inventory.remove("netclients");
        return None;
    }
    let n = all.len();
    inventory.insert("netclients".into(), json!({ "sources": sources, "clients": all, "time": chrono::Utc::now() }));
    Some(n)
}

/// Verbundene Geräte übernehmen: Datenraten/Signal in den Verlauf, „hängt an“, Namen, fehlende MAC-Adressen
async fn apply_clients(state: &AppState, device_id: i64, clients: &[Value]) -> Result<()> {
    let mut macs = Vec::new();
    let (mut rx, mut tx, mut sig) = (Vec::new(), Vec::new(), Vec::new());
    let (mut child, mut names, mut name_macs) = (Vec::new(), Vec::new(), Vec::new());
    let (mut ips, mut ip_macs) = (Vec::new(), Vec::new());
    for c in clients {
        let Some(mac) = c["mac"].as_str().map(str::to_lowercase) else { continue };
        let (down, up, s) = (c["down_bps"].as_f64(), c["up_bps"].as_f64(), c["signal_dbm"].as_f64());
        if down.is_some() || up.is_some() || s.is_some() {
            macs.push(mac.clone());
            rx.push(down);
            tx.push(up);
            sig.push(s.map(|v| v as f32));
        }
        // Direkt an diesem Gerät angeschlossen (WLAN-Station oder Switch-/LAN-Port)?
        let direct = matches!(c["source"].as_str(), Some("wifi" | "switch" | "fritzbox" | "mikrotik"))
            && (c["type"] == "wireless" || c.get("port").is_some_and(|p| !p.is_null()));
        if direct {
            child.push(mac.clone());
        }
        if let Some(name) = c["name"].as_str().filter(|n| !n.trim().is_empty()) {
            name_macs.push(mac.clone());
            names.push(name.to_string());
        }
        if let Some(ip) = c["ip"].as_str().filter(|i| i.parse::<Ipv4Addr>().is_ok()) {
            ip_macs.push(mac.clone());
            ips.push(ip.to_string());
        }
    }
    if !macs.is_empty() {
        sqlx::query(
            "INSERT INTO device_stats (time, device_id, rx_bps, tx_bps, wifi_signal)
             SELECT now(), d.id, u.rx, u.tx, u.sig
               FROM UNNEST($1::text[], $2::float8[], $3::float8[], $4::real[]) AS u(mac, rx, tx, sig)
               JOIN devices d ON lower(d.mac) = u.mac
              WHERE NOT EXISTS (SELECT 1 FROM devices c WHERE c.inventory ? 'unifi'
                                  AND c.inventory->'unifi'->'clients' @> jsonb_build_array(jsonb_build_object('mac', u.mac)))",
        )
        .bind(&macs)
        .bind(&rx)
        .bind(&tx)
        .bind(&sig)
        .execute(&state.db)
        .await?;
    }
    if !child.is_empty() {
        // Nur setzen, wenn noch nichts bekannt ist – UniFi oder eine Angabe von Hand haben Vorrang
        sqlx::query(
            "UPDATE devices SET parent_id = $2
              WHERE lower(mac) = ANY($1) AND parent_id IS NULL AND NOT parent_manual AND id <> $2",
        )
        .bind(&child)
        .bind(device_id)
        .execute(&state.db)
        .await?;
    }
    if !names.is_empty() {
        sqlx::query(
            "UPDATE devices d SET reported_name = u.name
               FROM UNNEST($1::text[], $2::text[]) AS u(mac, name)
              WHERE lower(d.mac) = u.mac AND d.reported_name IS NULL AND d.name IS NULL",
        )
        .bind(&name_macs)
        .bind(&names)
        .execute(&state.db)
        .await?;
    }
    if !ips.is_empty() {
        // Von Hand angelegte Geräte ohne MAC-Adresse bekommen sie über die IP
        sqlx::query(
            "UPDATE devices d SET mac = u.mac
               FROM UNNEST($1::text[], $2::text[]) AS u(mac, ip)
              WHERE d.mac IS NULL AND d.ip = u.ip::inet
                AND d.site_id = (SELECT site_id FROM devices WHERE id = $3)
                AND NOT EXISTS (SELECT 1 FROM devices x WHERE lower(x.mac) = u.mac AND x.site_id = d.site_id)",
        )
        .bind(&ip_macs)
        .bind(&ips)
        .bind(device_id)
        .execute(&state.db)
        .await?;
    }
    Ok(())
}

/// Erfolgreiche automatische Zugangsdaten fest zuordnen
async fn link(state: &AppState, device_id: i64, cred: &Credential) -> sqlx::Result<()> {
    if !cred.linked {
        sqlx::query("INSERT INTO device_credentials (device_id, credential_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(device_id)
            .bind(cred.id)
            .execute(&state.db)
            .await?;
    }
    Ok(())
}

struct Derived {
    reported_name: Option<String>,
    os: Option<String>,
    model: Option<String>,
    hostname: Option<String>,
    vendor: Option<String>,
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn derive_fields(inv: &Value) -> Derived {
    let ssh = &inv["ssh"];
    let snmp = &inv["snmp"];
    let shelly = &inv["shelly"];
    let snmp_os = text(&snmp["sys_descr"]).map(|d| d.lines().next().unwrap_or_default().chars().take(120).collect());
    let shelly_os = shelly["generation"].as_u64().map(|g| format!("Shelly Gen{g}"));
    Derived {
        reported_name: text(&shelly["name"]),
        os: text(&ssh["os"]).or(snmp_os).or(shelly_os),
        model: text(&ssh["model"])
            .or_else(|| text(&shelly["model"]))
            .or_else(|| text(&snmp["synology"]["model"]))
            .or_else(|| text(&snmp["ups"]["model"]))
            .or_else(|| text(&snmp["model"])),
        hostname: text(&ssh["hostname"]).or_else(|| text(&snmp["sys_name"])).map(|h| h.to_lowercase()),
        vendor: text(&ssh["vendor"]).filter(|v| !v.eq_ignore_ascii_case("To Be Filled By O.E.M.")),
    }
}

pub(crate) struct InterfaceRate {
    name: String,
    rx: Option<f64>,
    tx: Option<f64>,
}

/// Datenrate je Schnittstelle aus der Differenz der Byte-Zähler zur vorherigen Abfrage
fn interface_rates(inv: &Value, previous: Option<&Value>) -> Vec<InterfaceRate> {
    let Some(prev) = previous else { return vec![] };
    let seconds = match (inv["collected_at"].as_str(), prev["collected_at"].as_str()) {
        (Some(a), Some(b)) => chrono::DateTime::parse_from_rfc3339(a)
            .ok()
            .zip(chrono::DateTime::parse_from_rfc3339(b).ok())
            .map(|(a, b)| (a - b).num_milliseconds() as f64 / 1000.0),
        _ => None,
    };
    let Some(seconds) = seconds.filter(|s| *s > 10.0 && *s < 7200.0) else { return vec![] };
    let source = if inv["ssh"]["interfaces"].is_array() { "ssh" } else { "snmp" };
    let (Some(now), Some(before)) = (inv[source]["interfaces"].as_array(), prev[source]["interfaces"].as_array()) else {
        return vec![];
    };
    now.iter()
        // Loopback (Typ 24) nicht mitzählen
        .filter(|iface| iface["type"].as_f64() != Some(24.0))
        .filter_map(|iface| {
            let name = iface["name"].as_str()?.to_string();
            let old = before.iter().find(|b| b["name"] == iface["name"])?;
            let rate = |field: &str| {
                let (n, o) = (iface[field].as_f64()?, old[field].as_f64()?);
                (n >= o).then(|| (n - o) * 8.0 / seconds)
            };
            Some(InterfaceRate { name, rx: rate("rx_bytes"), tx: rate("tx_bytes") })
        })
        .collect()
}

/// Internet-Anschluss erkennen: Schnittstelle der Standardroute (bei Routern/Firewalls)
/// oder eine Schnittstelle mit sprechendem Namen („WAN“, „Internet“, „PPPoE“ …)
fn detect_wan(inv: &Value, device_type: Option<&str>) -> Option<String> {
    let is_gateway = matches!(device_type, Some("router" | "firewall" | "network"));
    let route = text(&inv["snmp"]["default_route_if"]).or_else(|| text(&inv["ssh"]["default_route_if"]));
    if is_gateway {
        if let Some(route) = route {
            return Some(route);
        }
    }
    let interfaces = inv["snmp"]["interfaces"].as_array().or_else(|| inv["ssh"]["interfaces"].as_array())?;
    const HINTS: &[&str] = &["wan", "internet", "pppoe", "dsl", "wwan", "lte", "uplink"];
    interfaces
        .iter()
        .find(|i| {
            let label = format!("{} {}", i["name"].as_str().unwrap_or(""), i["alias"].as_str().unwrap_or("")).to_lowercase();
            label.split(|c: char| !c.is_alphanumeric()).any(|word| HINTS.iter().any(|h| word.starts_with(h)))
        })
        .and_then(|i| text(&i["name"]))
}

/// Messwerte: [CPU %, RAM %, höchste Datenträger-Belegung %, Temperatur °C, Empfang bit/s, Senden bit/s,
/// WLAN-Clients, Leistung W]
/// Bei Geräten mit Internet-Anschluss zählt dessen Datenrate, sonst die Summe aller Schnittstellen.
fn derive_stats(inv: &Value, rates: &[InterfaceRate], wan: Option<&str>) -> [Option<f64>; 8] {
    let ssh = &inv["ssh"];
    let snmp = &inv["snmp"];
    let cpu = ssh["cpu_pct"].as_f64().or_else(|| snmp["cpu_pct"].as_f64());
    let storage = snmp["storage"].as_array();
    let mem = ssh["mem_pct"].as_f64().or_else(|| {
        storage?.iter().find(|s| s["kind"] == "ram").and_then(|s| s["pct"].as_f64())
    });
    let disk = ssh["disks"]
        .as_array()
        .and_then(|d| d.iter().filter_map(|x| x["pct"].as_f64()).reduce(f64::max))
        .or_else(|| {
            storage?.iter().filter(|s| s["kind"] == "disk").filter_map(|s| s["pct"].as_f64()).reduce(f64::max)
        });
    let temp = [
        ssh["temp_c"].as_f64(),
        snmp["temp_c"].as_f64(),
        snmp["synology"]["temp_c"].as_f64(),
        snmp["mikrotik"]["temp_c"].as_f64(),
        inv["shelly"]["temp_c"].as_f64(),
    ]
    .into_iter()
    .flatten()
    .reduce(f64::max);
    let clients = snmp["unifi"]["clients"].as_f64().or_else(|| snmp["mikrotik"]["clients"].as_f64());

    let (rx, tx) = match wan.and_then(|w| rates.iter().find(|r| r.name == w)) {
        Some(r) => (r.rx, r.tx),
        None if rates.is_empty() => (None, None),
        None => (Some(rates.iter().filter_map(|r| r.rx).sum()), Some(rates.iter().filter_map(|r| r.tx).sum())),
    };
    [cpu, mem, disk, temp, rx, tx, clients, inv["shelly"]["power_w"].as_f64()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datenrate_aus_zaehlerdifferenz() {
        let prev = json!({ "collected_at": "2026-01-01T10:00:00Z",
            "ssh": { "interfaces": [{ "name": "eth0", "rx_bytes": 1000.0, "tx_bytes": 500.0 }] } });
        let now = json!({ "collected_at": "2026-01-01T10:05:00Z",
            "ssh": { "cpu_pct": 12.5, "mem_pct": 40.0,
                     "disks": [{ "pct": 10.0 }, { "pct": 80.0 }],
                     "interfaces": [{ "name": "eth0", "rx_bytes": 301000.0, "tx_bytes": 500.0 }] } });
        let rates = interface_rates(&now, Some(&prev));
        let s = derive_stats(&now, &rates, None);
        assert_eq!(s[0], Some(12.5));
        assert_eq!(s[2], Some(80.0));
        assert_eq!(s[4], Some(8000.0)); // 300.000 Byte in 300 s = 8.000 bit/s
        assert_eq!(s[5], Some(0.0));
    }
}
