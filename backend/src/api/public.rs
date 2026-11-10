//! Öffentliche Statusseite und Netzwerkkarte.
//!
//! Die Statusseite ist ohne Anmeldung über einen geheimen Link erreichbar (`/status.html#<token>`).
//! Sie zeigt nur, was ausdrücklich freigegeben wurde – Anzeigename, Status und Verfügbarkeit,
//! keine IP-Adressen oder sonstigen Details.

use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{self, perm, Need},
    error::{ApiError, ApiResult},
    AppState,
};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct StatusItem {
    /// `device` oder `check`
    kind: String,
    id: i64,
    /// Anzeigename auf der Statusseite (sonst ein neutraler Name wie „Router“ – nie der interne Hostname)
    #[serde(default)]
    label: Option<String>,
    /// Abschnitt, z. B. „Internet“ oder „Smart Home“
    #[serde(default)]
    group: Option<String>,
    /// 24-h-Verlauf zeigen (Antwortzeit, Datenverkehr)
    #[serde(default)]
    details: bool,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct StatusPage {
    enabled: bool,
    title: String,
    #[serde(default)]
    description: String,
    token: String,
    items: Vec<StatusItem>,
}

async fn load(st: &AppState) -> StatusPage {
    let row: Option<(Value,)> =
        sqlx::query_as("SELECT value FROM settings WHERE key = 'status_page'").fetch_optional(&st.db).await.ok().flatten();
    row.and_then(|(v,)| serde_json::from_value(v).ok()).unwrap_or_else(|| StatusPage {
        enabled: false,
        title: "Status".into(),
        description: String::new(),
        token: auth::random_token(24),
        items: vec![],
    })
}

async fn save(st: &AppState, page: &StatusPage) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES ('status_page', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(json!(page))
        .execute(&st.db)
        .await?;
    Ok(())
}

pub async fn get_config(State(st): State<AppState>, _admin: Need<perm::SettingsManage>) -> Json<StatusPage> {
    Json(load(&st).await)
}

#[derive(Deserialize)]
pub struct StatusInput {
    enabled: bool,
    title: String,
    #[serde(default)]
    description: String,
    items: Vec<StatusItem>,
    /// Neuen geheimen Link erzeugen (alter Link funktioniert dann nicht mehr)
    #[serde(default)]
    new_token: bool,
}

pub async fn set_config(State(st): State<AppState>, Need(user, _): Need<perm::SettingsManage>, Json(req): Json<StatusInput>) -> ApiResult<Json<StatusPage>> {
    if req.items.len() > 100 || req.items.iter().any(|i| !matches!(i.kind.as_str(), "device" | "check")) {
        return Err(ApiError::BadRequest("Ungültige Einträge".into()));
    }
    let mut page = load(&st).await;
    page.enabled = req.enabled;
    page.title = req.title.trim().chars().take(80).collect();
    page.description = req.description.trim().chars().take(500).collect();
    page.items = req
        .items
        .into_iter()
        .map(|mut i| {
            i.label = i.label.map(|l| l.trim().chars().take(80).collect::<String>()).filter(|l| !l.is_empty());
            i.group = i.group.map(|g| g.trim().chars().take(60).collect::<String>()).filter(|g| !g.is_empty());
            i
        })
        .collect();
    if req.new_token || page.token.len() < 20 {
        page.token = auth::random_token(24);
    }
    save(&st, &page).await?;
    *cache().lock().unwrap() = None;
    audit::by(&st.db, &user, "status_page", json!({ "enabled": page.enabled, "items": page.items.len() })).await;
    Ok(Json(page))
}

fn cache() -> &'static std::sync::Mutex<Option<(std::time::Instant, Value)>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Option<(std::time::Instant, Value)>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Vergleich in konstanter Zeit (verrät nicht, wie viele Zeichen stimmen)
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Neutraler Name, falls kein Anzeigename gesetzt ist – interne Hostnamen bleiben intern
fn generic_name(kind: &str, device_type: &str) -> &'static str {
    match (kind, device_type) {
        ("check", _) => "Dienst",
        (_, "router") => "Router",
        (_, "firewall") => "Firewall",
        (_, "switch") => "Switch",
        (_, "access_point") => "WLAN",
        (_, "nas") => "Speicher (NAS)",
        (_, "server" | "hypervisor" | "linux" | "windows") => "Server",
        (_, "printer") => "Drucker",
        (_, "camera") => "Kamera",
        _ => "Gerät",
    }
}

/// Öffentlich (ohne Anmeldung): Status der freigegebenen Einträge.
/// Der geheime Schlüssel kommt im Header `X-Status-Token` (nicht in der Adresse → nicht in Proxy-Logs).
pub async fn public_status(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let token = headers.get("x-status-token").and_then(|v| v.to_str().ok()).unwrap_or_default();
    let page = load(&st).await;
    if !page.enabled || token.len() < 20 || !same(token, &page.token) {
        return Err(ApiError::NotFound);
    }
    // 15 s zwischenspeichern: schützt Datenbank und Geräte vor vielen Aufrufen
    if let Some((at, value)) = cache().lock().unwrap().as_ref() {
        if at.elapsed() < std::time::Duration::from_secs(15) {
            return Ok(Json(value.clone()));
        }
    }
    let mut items = Vec::new();
    for (index, item) in page.items.iter().enumerate() {
        type Row = (String, String, Option<f64>, Option<Vec<Option<f64>>>, bool, Option<f64>);
        let row: Option<Row> = if item.kind == "device" {
            sqlx::query_as(
                "SELECT COALESCE(d.device_type, 'unknown'),
                        CASE WHEN NOT d.monitored THEN 'unknown' ELSE d.status END,
                        (SELECT round(100.0 * avg(CASE WHEN up THEN 1 ELSE 0 END), 2)::float8 FROM device_metrics
                          WHERE device_id = d.id AND time > now() - interval '30 days'),
                        (SELECT array_agg(a ORDER BY day) FROM (
                           SELECT g.day, (SELECT round(100.0 * avg(CASE WHEN up THEN 1 ELSE 0 END), 2)::float8 FROM device_metrics m
                                            WHERE m.device_id = d.id AND m.time >= g.day AND m.time < g.day + interval '1 day') AS a
                             FROM generate_series(date_trunc('day', now()) - interval '29 days', date_trunc('day', now()), interval '1 day') AS g(day)) x),
                        d.wan_interface IS NOT NULL, d.last_rtt_ms::float8
                   FROM devices d WHERE d.id = $1",
            )
        } else {
            sqlx::query_as(
                "SELECT 'check', CASE WHEN NOT c.enabled THEN 'unknown' ELSE c.status END,
                        (SELECT round(100.0 * avg(CASE WHEN ok THEN 1 ELSE 0 END), 2)::float8 FROM check_results
                          WHERE check_id = c.id AND time > now() - interval '30 days'),
                        (SELECT array_agg(a ORDER BY day) FROM (
                           SELECT g.day, (SELECT round(100.0 * avg(CASE WHEN ok THEN 1 ELSE 0 END), 2)::float8 FROM check_results r
                                            WHERE r.check_id = c.id AND r.time >= g.day AND r.time < g.day + interval '1 day') AS a
                             FROM generate_series(date_trunc('day', now()) - interval '29 days', date_trunc('day', now()), interval '1 day') AS g(day)) x),
                        false, c.last_ms::float8
                   FROM checks c WHERE c.id = $1",
            )
        }
        .bind(item.id)
        .fetch_optional(&st.db)
        .await?;
        let Some((device_type, status, uptime, days, wan, latency)) = row else { continue };
        let status = match status.as_str() {
            "up" => "ok",
            "warn" => "degraded",
            "down" => "down",
            _ => "unknown",
        };
        let name = item.label.clone().unwrap_or_else(|| format!("{} {}", generic_name(&item.kind, &device_type), index + 1));
        let mut entry = json!({
            "name": name,
            "group": item.group,
            "kind": item.kind,
            "status": status,
            "uptime_30d": uptime,
            "days": days,
            "latency_ms": latency,
        });
        if item.details {
            // 24 h in Halbstunden-Schritten: Antwortzeit + Datenverkehr (beim Router = Internet)
            type Point = (chrono::DateTime<chrono::Utc>, Option<f64>, Option<f64>, Option<f64>);
            let points: Vec<Point> = if item.kind == "device" {
                sqlx::query_as(
                    "SELECT g.t,
                            (SELECT avg(rtt_ms)::float8 FROM device_metrics m WHERE m.device_id = $1 AND m.time >= g.t AND m.time < g.t + interval '30 minutes'),
                            (SELECT avg(rx_bps) FROM device_stats s WHERE s.device_id = $1 AND s.time >= g.t AND s.time < g.t + interval '30 minutes'),
                            (SELECT avg(tx_bps) FROM device_stats s WHERE s.device_id = $1 AND s.time >= g.t AND s.time < g.t + interval '30 minutes')
                       FROM generate_series(date_trunc('hour', now()) - interval '23 hours 30 minutes', date_trunc('hour', now()) + interval '30 minutes', interval '30 minutes') AS g(t)
                      ORDER BY g.t",
                )
            } else {
                sqlx::query_as(
                    "SELECT g.t,
                            (SELECT avg(ms)::float8 FROM check_results r WHERE r.check_id = $1 AND r.time >= g.t AND r.time < g.t + interval '30 minutes'),
                            NULL::float8, NULL::float8
                       FROM generate_series(date_trunc('hour', now()) - interval '23 hours 30 minutes', date_trunc('hour', now()) + interval '30 minutes', interval '30 minutes') AS g(t)
                      ORDER BY g.t",
                )
            }
            .bind(item.id)
            .fetch_all(&st.db)
            .await?;
            let latest = |pick: fn(&Point) -> Option<f64>| points.iter().rev().find_map(pick);
            // Aktuelle Datenrate live vom Gerät (dieselbe Abfrage wie im Dashboard; wegen des Zwischenspeichers
            // höchstens alle 15 s, und nur für freigegebene Geräte mit Details)
            let (mut rx_now, mut tx_now, mut is_live) = (latest(|p| p.2), latest(|p| p.3), false);
            if item.kind == "device" {
                // Box::pin: die Live-Abfrage (SNMP/SSH) ist ein großer Future – auf den Heap statt auf den Stack
                let live = Box::pin(crate::collect::live::live(&st, item.id));
                if let Ok(Ok(v)) = tokio::time::timeout(std::time::Duration::from_secs(4), live).await {
                    let ifs = v["interfaces"].as_array().cloned().unwrap_or_default();
                    let pick = |i: &Value| (i["rx_bps"].as_f64(), i["tx_bps"].as_f64());
                    let rates = match v["wan"].as_str() {
                        Some(w) => ifs.iter().find(|i| i["name"] == w).map(pick).unwrap_or((None, None)),
                        None => {
                            let rx: Vec<f64> = ifs.iter().filter_map(|i| i["rx_bps"].as_f64()).collect();
                            let tx: Vec<f64> = ifs.iter().filter_map(|i| i["tx_bps"].as_f64()).collect();
                            ((!rx.is_empty()).then(|| rx.iter().sum()), (!tx.is_empty()).then(|| tx.iter().sum()))
                        }
                    };
                    if rates.0.is_some() || rates.1.is_some() {
                        (rx_now, tx_now, is_live) = (rates.0.map(f64::round), rates.1.map(f64::round), true);
                    }
                }
            }
            entry["details"] = json!({
                "traffic_label": if wan { "Internet" } else { "Netzwerk" },
                "rtt": points.iter().map(|p| p.1.map(|v| (v * 10.0).round() / 10.0)).collect::<Vec<_>>(),
                "rx": points.iter().map(|p| p.2.map(f64::round)).collect::<Vec<_>>(),
                "tx": points.iter().map(|p| p.3.map(f64::round)).collect::<Vec<_>>(),
                "rx_now": rx_now,
                "tx_now": tx_now,
                "live": is_live,
            });
        }
        items.push(entry);
    }
    let down = items.iter().filter(|i| i["status"] == "down").count();
    let degraded = items.iter().filter(|i| i["status"] == "degraded").count();
    let overall = if down > 0 { "down" } else if degraded > 0 { "degraded" } else { "ok" };
    let value = json!({
        "title": page.title,
        "description": page.description,
        "overall": overall,
        "items": items,
        "updated": chrono::Utc::now(),
    });
    *cache().lock().unwrap() = Some((std::time::Instant::now(), value.clone()));
    Ok(Json(value))
}

// ---------------------------------------------------------------------------
// Netzwerkkarte
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct Node {
    id: i64,
    label: String,
    ip: String,
    device_type: String,
    status: String,
    monitored: bool,
    parent_id: Option<i64>,
    parent_manual: bool,
    wan: bool,
    site_id: i64,
}

#[derive(Deserialize)]
pub struct TopologyQuery {
    site: Option<i64>,
}

/// Netzwerkkarte – optional nur ein Sektor (inkl. Unter-Sektoren)
pub async fn topology(State(st): State<AppState>, user: Need<perm::View>, axum::extract::Query(q): axum::extract::Query<TopologyQuery>) -> ApiResult<Json<Vec<Node>>> {
    let sites = crate::sites::filter(&st.db, &user, "view", q.site).await?;
    let nodes = sqlx::query_as::<_, Node>(
        "SELECT id, COALESCE(name, reported_name, hostname, host(ip)) AS label, host(ip) AS ip,
                COALESCE(device_type, 'unknown') AS device_type, status, monitored, parent_id, parent_manual,
                wan_interface IS NOT NULL AS wan, site_id
           FROM devices WHERE ($1::bigint[] IS NULL OR site_id = ANY($1)) ORDER BY site_id, ip",
    )
    .bind(&sites)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(nodes))
}
