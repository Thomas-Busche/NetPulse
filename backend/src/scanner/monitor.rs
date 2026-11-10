//! Statusprüfung: prüft alle überwachten Geräte im festen Takt (Standard: jede Minute)
//! und speichert Erreichbarkeit und Antwortzeit als Zeitreihe.

use std::{net::IpAddr, sync::Arc, time::Duration};

use anyhow::Result;
use futures::{stream, StreamExt};

use crate::{
    scanner::net::{self, Pinger},
    AppState,
};

/// Ein zu prüfendes Gerät, wie es aus der Datenbank kommt
#[derive(sqlx::FromRow)]
struct Target {
    id: i64,
    ip: String,
    open_ports: Vec<i32>,
}

/// Rohergebnis einer Prüfung (vom Server selbst oder von einer Probe gemeldet)
pub struct Reading {
    pub id: i64,
    pub up: bool,
    pub rtt_ms: Option<f32>,
}

/// Bewertetes Ergebnis: Status erst nach `MONITOR_FAIL_THRESHOLD` Fehlversuchen in Folge auf „down“
struct Check {
    id: i64,
    up: bool,
    rtt_ms: Option<f32>,
    previous_status: String,
    status: &'static str,
    fail_count: i32,
    label: String,
}

/// Neuen Status bestimmen: Antwort = „up“; keine Antwort erst ab der Schwelle „down“, davor bleibt der alte Status.
fn next_status(previous: &str, up: bool, fail_count: i32, threshold: i32) -> &'static str {
    if up {
        "up"
    } else if fail_count >= threshold || previous == "down" {
        "down"
    } else if previous == "up" {
        "up"
    } else {
        "unknown"
    }
}

pub async fn run(state: AppState, pinger: Arc<Pinger>) {
    let mut ticker = tokio::time::interval(state.config.monitor_interval);
    // Dauert eine Runde länger als das Intervall, wird die nächste nicht doppelt gestartet
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Err(e) = check_all(&state, &pinger).await {
            tracing::error!("Statusprüfung fehlgeschlagen: {e:#}");
        }
    }
}

async fn check_all(state: &AppState, pinger: &Arc<Pinger>) -> Result<()> {
    let _perf = crate::perf::Timer::new("Erreichbarkeit (Runde über alle Geräte)");
    // Von verbundenen Programmen pausierte Geräte (z. B. Container im Backup) gar nicht prüfen
    let targets: Vec<Target> = sqlx::query_as(&format!(
        "SELECT id, host(ip) AS ip, open_ports
           FROM devices WHERE monitored AND {} AND {}",
        crate::integration::DEVICE_NOT_PAUSED,
        crate::sites::SITE_LOCAL
    ))
    .fetch_all(&state.db)
    .await?;
    if targets.is_empty() {
        return Ok(());
    }

    let results: Vec<Reading> = stream::iter(targets)
        .map(|target| {
            let pinger = pinger.clone();
            async move {
                let rtt = match target.ip.parse::<IpAddr>() {
                    Ok(addr) => check_device(&pinger, addr, &target.open_ports).await,
                    Err(_) => None,
                };
                Reading { id: target.id, up: rtt.is_some(), rtt_ms: rtt.map(|d| d.as_secs_f32() * 1000.0) }
            }
        })
        .buffer_unordered(64)
        .collect()
        .await;
    apply_results(state, &results).await
}

/// Ergebnisse speichern, Status (mit Dämpfung) setzen, Ereignisse schreiben und an die Browser melden.
/// Wird auch für die Meldungen der Probes in entfernten Sektoren benutzt.
pub async fn apply_results(state: &AppState, results: &[Reading]) -> Result<()> {
    if results.is_empty() {
        return Ok(());
    }
    let ids: Vec<i64> = results.iter().map(|c| c.id).collect();
    let current: Vec<(i64, String, i32, String)> = sqlx::query_as(
        "SELECT id, status, fail_count, COALESCE(name, hostname, host(ip)) || ' (' || host(ip) || ')' FROM devices WHERE id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(&state.db)
    .await?;
    let current: std::collections::HashMap<i64, (String, i32, String)> =
        current.into_iter().map(|(id, status, fails, label)| (id, (status, fails, label))).collect();
    let threshold = state.config.monitor_fail_threshold;
    let checks: Vec<Check> = results
        .iter()
        .filter_map(|r| {
            let (previous, fails, label) = current.get(&r.id)?;
            let fail_count = if r.up { 0 } else { fails.saturating_add(1) };
            Some(Check {
                id: r.id,
                up: r.up,
                rtt_ms: r.rtt_ms,
                status: next_status(previous, r.up, fail_count, threshold),
                previous_status: previous.clone(),
                fail_count,
                label: label.clone(),
            })
        })
        .collect();

    // Alle Ergebnisse mit wenigen Datenbankbefehlen schreiben (UNNEST = Listen als Tabelle)
    let ids: Vec<i64> = checks.iter().map(|c| c.id).collect();
    let ups: Vec<bool> = checks.iter().map(|c| c.up).collect();
    let rtts: Vec<Option<f32>> = checks.iter().map(|c| c.rtt_ms).collect();
    let statuses: Vec<&str> = checks.iter().map(|c| c.status).collect();
    let fails: Vec<i32> = checks.iter().map(|c| c.fail_count).collect();

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO device_metrics (time, device_id, up, rtt_ms)
         SELECT now(), u.id, u.up, u.rtt FROM UNNEST($1::bigint[], $2::boolean[], $3::real[]) AS u(id, up, rtt)",
    )
    .bind(&ids)
    .bind(&ups)
    .bind(&rtts)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE devices d SET
             status_since = CASE WHEN d.status = u.status THEN COALESCE(d.status_since, now()) ELSE now() END,
             status      = u.status,
             fail_count  = u.fails,
             last_rtt_ms = u.rtt,
             last_check  = now(),
             last_seen   = CASE WHEN u.up THEN now() ELSE d.last_seen END
           FROM UNNEST($1::bigint[], $2::boolean[], $3::real[], $4::text[], $5::int[]) AS u(id, up, rtt, status, fails)
          WHERE d.id = u.id",
    )
    .bind(&ids)
    .bind(&ups)
    .bind(&rtts)
    .bind(&statuses)
    .bind(&fails)
    .execute(&mut *tx)
    .await?;

    // Statuswechsel als Ereignis festhalten
    for check in &checks {
        let status = check.status;
        let first_check_ok = check.previous_status == "unknown" && status == "up";
        if check.previous_status != status && !first_check_ok && status != "unknown" {
            let message = if status == "up" {
                format!("{} ist wieder erreichbar", check.label)
            } else {
                format!("{} ist nicht erreichbar", check.label)
            };
            sqlx::query("INSERT INTO events (device_id, kind, message) VALUES ($1, $2, $3)")
                .bind(check.id)
                .bind(status)
                .bind(message)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;

    // Statuswechsel sofort an offene Browser melden
    let changes: Vec<_> = checks
        .iter()
        .filter(|c| c.previous_status != c.status)
        .map(|c| serde_json::json!({ "id": c.id, "status": c.status, "label": c.label }))
        .collect();
    if !changes.is_empty() {
        state.hub.publish(&serde_json::json!({ "type": "status", "devices": changes }));
    }

    let down = checks.iter().filter(|c| c.status == "down").count();
    tracing::debug!("Statusprüfung: {} Geräte, {down} nicht erreichbar", checks.len());
    Ok(())
}

/// Erst Ping; antwortet das Gerät nicht, werden bekannte offene Ports per TCP geprüft.
async fn check_device(pinger: &Pinger, ip: IpAddr, open_ports: &[i32]) -> Option<Duration> {
    if let Some(rtt) = pinger.ping_ip(ip, Duration::from_secs(1), 2).await {
        return Some(rtt);
    }
    let known: Vec<u16> = open_ports.iter().filter_map(|&p| u16::try_from(p).ok()).take(3).collect();
    let ports = if known.is_empty() { net::LIVENESS_PORTS } else { &known[..] };
    net::tcp_alive(ip, ports, Duration::from_secs(1)).await
}

#[cfg(test)]
mod tests {
    use super::next_status;

    #[test]
    fn flattern_gedaempft() {
        // Einzelner Aussetzer: bleibt „up“
        assert_eq!(next_status("up", false, 1, 2), "up");
        // Zweiter Fehlversuch in Folge: „down“
        assert_eq!(next_status("up", false, 2, 2), "down");
        assert_eq!(next_status("down", false, 1, 2), "down");
        assert_eq!(next_status("down", true, 0, 2), "up");
        assert_eq!(next_status("unknown", false, 1, 2), "unknown");
        assert_eq!(next_status("up", false, 1, 1), "down");
    }
}
