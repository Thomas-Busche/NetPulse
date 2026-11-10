//! Probes: kleine NetPulse-Ableger in entfernten Sektoren (Filialen, abgeschottete Netze).
//!
//! Eine Probe läuft vor Ort (`netpulse probe`), holt sich hier ihre Aufgaben (Netze und Geräte ihres
//! Sektors), sucht und prüft lokal und meldet die Ergebnisse zurück. Sie braucht nur ausgehend HTTPS
//! zum Server – keine Portfreigabe und keinen VPN-Tunnel in die Filiale.
//!
//! Anmeldung mit einem eigenen Schlüssel (`npp_…`) im Authorization-Header; er gilt nur für den einen
//! Sektor der Probe und nur für diese Schnittstelle.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{self, perm, Need},
    error::{ApiError, ApiResult},
    scanner::{discovery::HostFacts, monitor::Reading},
    AppState,
};

// ---------------------------------------------------------------------------
// Verwaltung
// ---------------------------------------------------------------------------

const PERM: &str = "networks.manage";

/// Sektor einer Probe; nur wenn der Benutzer dort Netzwerke verwalten darf
async fn own_probe(st: &AppState, user: &auth::CurrentUser, id: i64) -> ApiResult<()> {
    let site: Option<(i64,)> = sqlx::query_as("SELECT site_id FROM probes WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let (site_id,) = site.ok_or(ApiError::NotFound)?;
    user.require_site(PERM, site_id)
}

pub async fn list(State(st): State<AppState>, Need(user, _): Need<perm::NetworksManage>) -> ApiResult<Json<Value>> {
    type Row = (i64, String, i64, String, bool, Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<String>, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT p.id, p.name, p.site_id, s.name, p.enabled, p.last_seen, p.version, p.address, p.last_error
           FROM probes p JOIN sites s ON s.id = p.site_id
          WHERE ($1::bigint[] IS NULL OR p.site_id = ANY($1)) ORDER BY s.name",
    )
    .bind(user.site_filter(PERM))
    .fetch_all(&st.db)
    .await?;
    let now = chrono::Utc::now();
    Ok(Json(json!(rows
        .into_iter()
        .map(|(id, name, site_id, site, enabled, last_seen, version, address, last_error)| json!({
            "id": id, "name": name, "site_id": site_id, "site": site, "enabled": enabled, "last_seen": last_seen,
            "online": enabled && last_seen.is_some_and(|t| (now - t).num_seconds() < 300),
            "version": version, "address": address, "last_error": last_error,
        }))
        .collect::<Vec<_>>())))
}

#[derive(Deserialize)]
pub struct NewProbe {
    name: String,
    site_id: i64,
}

fn new_token() -> (String, Vec<u8>) {
    let token = format!("npp_{}", auth::random_token(24));
    let hash = auth::token_hash(&token);
    (token, hash)
}

pub async fn create(State(st): State<AppState>, Need(user, _): Need<perm::NetworksManage>, Json(req): Json<NewProbe>) -> ApiResult<Json<Value>> {
    user.require_site(PERM, req.site_id)?;
    user.require_recent_auth(&st.db).await?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 80 Zeichen) angeben".into()));
    }
    if req.site_id == crate::sites::DEFAULT_SITE {
        return Err(ApiError::BadRequest("Der Hauptstandort wird vom Server selbst geprüft – bitte einen anderen Sektor wählen".into()));
    }
    let (token, hash) = new_token();
    let id: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO probes (name, site_id, token_hash) SELECT $1, $2, $3 WHERE EXISTS (SELECT 1 FROM sites WHERE id = $2)
         ON CONFLICT (site_id) DO NOTHING RETURNING id",
    )
    .bind(name)
    .bind(req.site_id)
    .bind(&hash)
    .fetch_optional(&st.db)
    .await?;
    let Some((id,)) = id else {
        return Err(ApiError::BadRequest("Für diesen Sektor gibt es schon eine Probe (oder den Sektor gibt es nicht)".into()));
    };
    audit::by(&st.db, &user, "probe_add", json!({ "id": id, "name": name, "site_id": req.site_id })).await;
    Ok(Json(json!({ "id": id, "token": token })))
}

pub async fn new_key(State(st): State<AppState>, Need(user, _): Need<perm::NetworksManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    own_probe(&st, &user, id).await?;
    user.require_recent_auth(&st.db).await?;
    let (token, hash) = new_token();
    let done = sqlx::query("UPDATE probes SET token_hash = $2 WHERE id = $1").bind(id).bind(&hash).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "probe_token", json!({ "id": id })).await;
    Ok(Json(json!({ "token": token })))
}

#[derive(Deserialize)]
pub struct ProbeUpdate {
    enabled: bool,
}

pub async fn update(
    State(st): State<AppState>,
    Need(user, _): Need<perm::NetworksManage>,
    Path(id): Path<i64>,
    Json(req): Json<ProbeUpdate>,
) -> ApiResult<Json<Value>> {
    own_probe(&st, &user, id).await?;
    sqlx::query("UPDATE probes SET enabled = $2 WHERE id = $1").bind(id).bind(req.enabled).execute(&st.db).await?;
    audit::by(&st.db, &user, "probe_update", json!({ "id": id, "enabled": req.enabled })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove(State(st): State<AppState>, Need(user, _): Need<perm::NetworksManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    own_probe(&st, &user, id).await?;
    user.require_recent_auth(&st.db).await?;
    sqlx::query("DELETE FROM probes WHERE id = $1").bind(id).execute(&st.db).await?;
    audit::by(&st.db, &user, "probe_delete", json!({ "id": id })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Schnittstelle für die Probe
// ---------------------------------------------------------------------------

/// Probe anhand ihres Schlüssels erkennen; merkt sich Lebenszeichen, Version und Absender
async fn probe_from(st: &AppState, headers: &HeaderMap) -> ApiResult<(i64, i64)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| t.starts_with("npp_"))
        .ok_or(ApiError::Unauthorized)?;
    let version = headers.get("x-probe-version").and_then(|v| v.to_str().ok()).map(|v| v.chars().take(40).collect::<String>());
    let row: Option<(i64, i64)> = sqlx::query_as(
        "UPDATE probes SET last_seen = now(), version = COALESCE($2, version), address = $3
          WHERE token_hash = $1 AND enabled RETURNING id, site_id",
    )
    .bind(auth::token_hash(token))
    .bind(version)
    .bind(auth::client_ip(headers))
    .fetch_optional(&st.db)
    .await?;
    row.ok_or(ApiError::Unauthorized)
}

/// Aufgaben: Netze (zum Suchen) und Geräte (zum Prüfen) des Sektors
pub async fn config(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let (_, site_id) = probe_from(&st, &headers).await?;
    let networks: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, cidr::text FROM networks WHERE site_id = $1 AND enabled AND family(cidr) = 4 ORDER BY id",
    )
    .bind(site_id)
    .fetch_all(&st.db)
    .await?;
    let devices: Vec<(i64, String, Vec<i32>)> = sqlx::query_as(&format!(
        "SELECT id, host(ip), open_ports FROM devices WHERE site_id = $1 AND monitored AND {}",
        crate::integration::DEVICE_NOT_PAUSED
    ))
    .bind(site_id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({
        "site_id": site_id,
        "monitor_interval_s": st.config.monitor_interval.as_secs(),
        "discovery_interval_s": st.config.discovery_interval.as_secs(),
        "networks": networks.into_iter().map(|(id, cidr)| json!({ "id": id, "cidr": cidr })).collect::<Vec<_>>(),
        "devices": devices.into_iter().map(|(id, ip, ports)| json!({ "id": id, "ip": ip, "open_ports": ports })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
pub struct ResultRow {
    id: i64,
    up: bool,
    rtt_ms: Option<f32>,
}

#[derive(Deserialize)]
pub struct Results {
    results: Vec<ResultRow>,
    #[serde(default)]
    error: Option<String>,
}

/// Ergebnisse der Statusprüfung – nur für Geräte des eigenen Sektors
pub async fn results(State(st): State<AppState>, headers: HeaderMap, Json(req): Json<Results>) -> ApiResult<Json<Value>> {
    let (probe_id, site_id) = probe_from(&st, &headers).await?;
    sqlx::query("UPDATE probes SET last_error = $2 WHERE id = $1")
        .bind(probe_id)
        .bind(req.error.map(|e| e.chars().take(500).collect::<String>()))
        .execute(&st.db)
        .await?;
    let ids: Vec<i64> = req.results.iter().map(|r| r.id).collect();
    let own: Vec<(i64,)> = sqlx::query_as("SELECT id FROM devices WHERE id = ANY($1) AND site_id = $2").bind(&ids).bind(site_id).fetch_all(&st.db).await?;
    let own: std::collections::HashSet<i64> = own.into_iter().map(|r| r.0).collect();
    let readings: Vec<Reading> = req
        .results
        .into_iter()
        .filter(|r| own.contains(&r.id))
        .map(|r| Reading { id: r.id, up: r.up, rtt_ms: r.rtt_ms.filter(|v| v.is_finite() && *v >= 0.0) })
        .collect();
    let count = readings.len();
    crate::scanner::monitor::apply_results(&st, &readings).await.map_err(ApiError::Internal)?;
    Ok(Json(json!({ "accepted": count })))
}

#[derive(Deserialize)]
pub struct Discovery {
    network_id: i64,
    hosts: Vec<HostFacts>,
    #[serde(default)]
    duration_s: i32,
}

/// Ergebnis einer Netzsuche der Probe
pub async fn discovery(State(st): State<AppState>, headers: HeaderMap, Json(req): Json<Discovery>) -> ApiResult<Json<Value>> {
    let (_, site_id) = probe_from(&st, &headers).await?;
    let Some((cidr,)): Option<(String,)> = sqlx::query_as("SELECT cidr::text FROM networks WHERE id = $1 AND site_id = $2")
        .bind(req.network_id)
        .bind(site_id)
        .fetch_optional(&st.db)
        .await?
    else {
        return Err(ApiError::NotFound);
    };
    let (net, prefix) = crate::scanner::net::parse_cidr(&cidr).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let mut stored = 0;
    for host in req.hosts.iter().take(70_000) {
        // Nur Adressen aus dem eigenen Netz annehmen
        if u32::from(host.ip) & mask != u32::from(net) & mask {
            continue;
        }
        match crate::scanner::discovery::save_host(&st, site_id, host).await {
            Ok(()) => stored += 1,
            Err(e) => tracing::warn!("Probe-Ergebnis {} nicht gespeichert: {e:#}", host.ip),
        }
    }
    sqlx::query("UPDATE networks SET last_scan_at = now(), last_scan_found = $2, last_scan_duration_s = $3 WHERE id = $1")
        .bind(req.network_id)
        .bind(stored)
        .bind(req.duration_s.max(0))
        .execute(&st.db)
        .await?;
    tracing::info!("Probe-Scan von {cidr} (Sektor {site_id}): {stored} Geräte");
    Ok(Json(json!({ "stored": stored })))
}
