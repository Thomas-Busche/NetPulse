//! Agentenlose Datenerfassung.
//!
//! - `discovery`: findet Geräte in den freigegebenen Netzen (Ping, TCP, ARP, DNS, Port-Scan)
//! - `monitor`  : prüft bekannte Geräte regelmäßig auf Erreichbarkeit und speichert Messwerte
//! - `net`      : Netzwerk-Hilfsfunktionen

pub mod discovery;
pub mod local;
pub mod monitor;
pub mod names;
pub mod net;
pub mod schedule;

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::{classify, oui};

pub async fn add_event(db: &PgPool, device_id: i64, kind: &str, message: &str) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO events (device_id, kind, message) VALUES ($1, $2, $3)")
        .bind(device_id)
        .bind(kind)
        .bind(message)
        .execute(db)
        .await?;
    Ok(())
}

/// Auftrag an die Discovery: alle Netze oder ein bestimmtes (z. B. gerade hinzugefügtes) Netz
#[derive(Debug, Clone, Copy)]
pub enum ScanRequest {
    All,
    Network(i64),
}

/// Fortschritt des laufenden Scans – wird von der Oberfläche abgefragt
#[derive(Default)]
pub struct ScanProgress {
    current: Mutex<Option<CurrentScan>>,
    queued: AtomicUsize,
    pub done: AtomicUsize,
    pub found: AtomicUsize,
}

#[derive(Clone)]
struct CurrentScan {
    network: String,
    total: usize,
    started_at: DateTime<Utc>,
}

impl ScanProgress {
    pub fn start(&self, network: &str, total: usize, queued: usize) {
        self.done.store(0, Ordering::Relaxed);
        self.found.store(0, Ordering::Relaxed);
        self.queued.store(queued, Ordering::Relaxed);
        *self.current.lock().unwrap() =
            Some(CurrentScan { network: network.to_string(), total, started_at: Utc::now() });
    }

    pub fn finish(&self) {
        *self.current.lock().unwrap() = None;
    }

    pub fn snapshot(&self) -> Value {
        match self.current.lock().unwrap().clone() {
            Some(scan) => json!({
                "running": true,
                "network": scan.network,
                "total": scan.total,
                "done": self.done.load(Ordering::Relaxed),
                "found": self.found.load(Ordering::Relaxed),
                "started_at": scan.started_at,
                "queued": self.queued.load(Ordering::Relaxed),
            }),
            None => json!({ "running": false }),
        }
    }
}

#[derive(sqlx::FromRow)]
struct ClassifyRow {
    ip: String,
    open_ports: Vec<i32>,
    hostname: Option<String>,
    vendor: Option<String>,
    mac: Option<String>,
    inventory: Option<Value>,
    model: Option<String>,
    device_type_manual: bool,
    site_id: i64,
    is_gateway: bool,
}

/// Gerätetyp neu bestimmen (außer er wurde von Hand gesetzt)
pub async fn reclassify(db: &PgPool, device_id: i64) -> sqlx::Result<()> {
    let row: Option<ClassifyRow> = sqlx::query_as(
        "SELECT host(d.ip) AS ip, d.open_ports, d.hostname, d.vendor, d.mac, d.inventory, d.model, d.device_type_manual, d.site_id,
                EXISTS (SELECT 1 FROM networks n WHERE n.site_id = d.site_id AND n.gateway = d.ip) AS is_gateway
           FROM devices d WHERE d.id = $1",
    )
    .bind(device_id)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else { return Ok(()) };
    if row.device_type_manual {
        return Ok(());
    }
    let kind = classify::classify(&classify::Hints {
        ip: &row.ip,
        open_ports: &row.open_ports,
        hostname: row.hostname.as_deref(),
        vendor: row.vendor.as_deref(),
        random_mac: row.mac.as_deref().is_some_and(oui::is_random),
        inventory: row.inventory.as_ref(),
        model: row.model.as_deref(),
        // Eingetragenes Gateway oder – im Hauptstandort – ein Gateway aus der Routing-Tabelle des Servers
        gateway: row.is_gateway
            || (row.site_id == crate::sites::DEFAULT_SITE
                && local::gateways().iter().any(|(_, gw)| gw.to_string() == row.ip)),
    });
    sqlx::query("UPDATE devices SET device_type = $2 WHERE id = $1 AND device_type IS DISTINCT FROM $2")
        .bind(device_id)
        .bind(kind)
        .execute(db)
        .await?;
    Ok(())
}
