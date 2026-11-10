//! Verwaltung: Netze, Scans, Audit-Log, Wartung, Protokolle, Sicherheit. Rechte je Handler (`Need<perm::…>`).

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::{
    audit,
    auth::{perm, CurrentUser, Need},
    error::{ApiError, ApiResult},
    scanner::{self, ScanRequest},
    AppState,
};

// ---------------------------------------------------------------------------
// Netze
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct Network {
    id: i64,
    cidr: String,
    name: String,
    enabled: bool,
    created_at: DateTime<Utc>,
    last_scan_at: Option<DateTime<Utc>>,
    last_scan_found: Option<i32>,
    last_scan_duration_s: Option<i32>,
    device_count: i64,
    site_id: i64,
    site_name: String,
    vlan_id: Option<i32>,
    gateway: Option<String>,
    description: String,
    schedule: Option<Value>,
    /// Wird von einer Probe im Sektor gescannt
    probe: Option<String>,
}

const NETWORK_SELECT: &str = "SELECT n.id, n.cidr::text AS cidr, n.name, n.enabled, n.created_at,
                                     n.last_scan_at, n.last_scan_found, n.last_scan_duration_s,
                                     (SELECT count(*) FROM devices d WHERE d.ip << n.cidr AND d.site_id = n.site_id) AS device_count,
                                     n.site_id, s.name AS site_name, n.vlan_id, host(n.gateway) AS gateway, n.description, n.schedule,
                                     (SELECT p.name FROM probes p WHERE p.site_id = n.site_id AND p.enabled) AS probe
                                FROM networks n JOIN sites s ON s.id = n.site_id";

pub async fn list_networks(State(st): State<AppState>, _admin: Need<perm::NetworksManage>) -> ApiResult<Json<Vec<Network>>> {
    let sql = format!("{NETWORK_SELECT} ORDER BY s.name, n.cidr");
    Ok(Json(sqlx::query_as::<_, Network>(&sql).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct NewNetwork {
    cidr: String,
    name: String,
    #[serde(default)]
    site_id: Option<i64>,
    #[serde(default)]
    vlan_id: Option<i32>,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    description: Option<String>,
    /// Eigener Such-Zeitplan; `null` = globaler Zeitplan
    #[serde(default)]
    schedule: Option<scanner::schedule::Schedule>,
}

fn validate_network_fields(req: &NewNetwork) -> ApiResult<()> {
    if req.vlan_id.is_some_and(|v| !(1..=4094).contains(&v)) {
        return Err(ApiError::BadRequest("VLAN-ID muss zwischen 1 und 4094 liegen".into()));
    }
    if let Some(gw) = req.gateway.as_deref().map(str::trim).filter(|g| !g.is_empty()) {
        gw.parse::<std::net::IpAddr>().map_err(|_| ApiError::BadRequest("Gateway ist keine gültige IP-Adresse".into()))?;
    }
    if req.description.as_deref().is_some_and(|d| d.chars().count() > 500) {
        return Err(ApiError::BadRequest("Beschreibung darf höchstens 500 Zeichen haben".into()));
    }
    if let Some(plan) = &req.schedule {
        plan.validate().map_err(ApiError::BadRequest)?;
    }
    Ok(())
}

pub async fn add_network(
    State(st): State<AppState>,
    Need(user, _): Need<perm::NetworksManage>,
    Json(req): Json<NewNetwork>,
) -> ApiResult<Json<Network>> {
    let (addr, prefix) =
        scanner::net::parse_cidr(&req.cidr).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 100 Zeichen) angeben".into()));
    }
    validate_network_fields(&req)?;
    let site_id = req.site_id.unwrap_or(crate::sites::DEFAULT_SITE);
    let cidr = format!("{addr}/{prefix}");
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO networks (cidr, name, site_id, vlan_id, gateway, description, schedule)
         SELECT $1::cidr, $2, s.id, $4, NULLIF(trim($5), '')::inet, COALESCE($6, ''), $7 FROM sites s WHERE s.id = $3
         ON CONFLICT (site_id, cidr) DO NOTHING RETURNING id",
    )
    .bind(&cidr)
    .bind(name)
    .bind(site_id)
    .bind(req.vlan_id)
    .bind(req.gateway.as_deref().unwrap_or(""))
    .bind(req.description.as_deref().map(str::trim))
    .bind(req.schedule.as_ref().map(|s| json!(s)))
    .fetch_optional(&st.db)
    .await?
    .ok_or_else(|| ApiError::BadRequest(format!("Netz {cidr} ist in diesem Sektor bereits eingetragen (oder der Sektor fehlt)")))?;

    audit::by(&st.db, &user, "network_add", json!({ "cidr": cidr, "name": name, "site_id": site_id })).await;
    // Neues Netz sofort scannen – hat Vorrang vor einem laufenden Durchlauf
    let _ = st.scan_tx.send(ScanRequest::Network(id));
    let sql = format!("{NETWORK_SELECT} WHERE n.id = $1");
    Ok(Json(sqlx::query_as::<_, Network>(&sql).bind(id).fetch_one(&st.db).await?))
}

/// Name, Sektor, VLAN, Gateway, Beschreibung, Zeitplan und „aktiv“ ändern (die Adresse selbst bleibt)
#[derive(Deserialize)]
pub struct NetworkUpdate {
    name: Option<String>,
    enabled: Option<bool>,
    site_id: Option<i64>,
    vlan_id: Option<i32>,
    gateway: Option<String>,
    description: Option<String>,
    /// `true` = Zeitplan auf global zurücksetzen
    #[serde(default)]
    schedule_global: bool,
    schedule: Option<scanner::schedule::Schedule>,
}

pub async fn update_network(
    State(st): State<AppState>,
    Need(user, _): Need<perm::NetworksManage>,
    Path(id): Path<i64>,
    Json(req): Json<NetworkUpdate>,
) -> ApiResult<Json<Network>> {
    if req.name.as_deref().is_some_and(|n| n.trim().is_empty() || n.chars().count() > 100) {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 100 Zeichen) angeben".into()));
    }
    validate_network_fields(&NewNetwork {
        cidr: String::new(),
        name: String::new(),
        site_id: None,
        vlan_id: req.vlan_id.filter(|v| *v != 0),
        gateway: req.gateway.clone(),
        description: req.description.clone(),
        schedule: req.schedule.clone(),
    })?;
    let done = sqlx::query(
        "UPDATE networks SET
             name        = COALESCE(NULLIF(trim($2), ''), name),
             enabled     = COALESCE($3, enabled),
             site_id     = COALESCE((SELECT id FROM sites WHERE id = $4), site_id),
             vlan_id     = CASE WHEN $5::int IS NULL THEN vlan_id WHEN $5 = 0 THEN NULL ELSE $5 END,
             gateway     = CASE WHEN $6::text IS NULL THEN gateway ELSE NULLIF(trim($6), '')::inet END,
             description = COALESCE(trim($7), description),
             schedule    = CASE WHEN $8 THEN NULL WHEN $9::jsonb IS NULL THEN schedule ELSE $9 END
          WHERE id = $1",
    )
    .bind(id)
    .bind(&req.name)
    .bind(req.enabled)
    .bind(req.site_id)
    .bind(req.vlan_id)
    .bind(&req.gateway)
    .bind(&req.description)
    .bind(req.schedule_global)
    .bind(req.schedule.as_ref().map(|s| json!(s)))
    .execute(&st.db)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::BadRequest("Dieses Netz gibt es im Ziel-Sektor schon".into()),
        _ => e.into(),
    })?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "network_update", json!({ "network_id": id, "site_id": req.site_id, "enabled": req.enabled })).await;
    let sql = format!("{NETWORK_SELECT} WHERE n.id = $1");
    Ok(Json(sqlx::query_as::<_, Network>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn delete_network(
    State(st): State<AppState>,
    Need(user, _): Need<perm::NetworksManage>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let (cidr,): (String,) = sqlx::query_as("DELETE FROM networks WHERE id = $1 RETURNING cidr::text")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "network_delete", json!({ "cidr": cidr })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn trigger_scan(State(st): State<AppState>, Need(user, _): Need<perm::NetworksManage>) -> ApiResult<Json<Value>> {
    let _ = st.scan_tx.send(ScanRequest::All);
    audit::by(&st.db, &user, "scan_trigger", json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn scan_network(
    State(st): State<AppState>,
    Need(user, _): Need<perm::NetworksManage>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let _ = st.scan_tx.send(ScanRequest::Network(id));
    audit::by(&st.db, &user, "scan_trigger", json!({ "network_id": id })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn scan_status(State(st): State<AppState>, _user: CurrentUser) -> Json<Value> {
    Json(st.scan_progress.snapshot())
}

// ---------------------------------------------------------------------------
// Audit-Log
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct AuditEntry {
    id: i64,
    time: DateTime<Utc>,
    username: Option<String>,
    action: String,
    detail: Value,
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<i64>,
    /// Benutzername (genau)
    user: Option<String>,
    /// Aktion beginnt mit … (z. B. „login“, „device_“)
    action: Option<String>,
    /// Suchtext in den Details
    q: Option<String>,
    /// Nur Einträge zu Geräten/Netzen dieses Sektors
    site: Option<i64>,
}

pub async fn audit_log(
    State(st): State<AppState>,
    _admin: Need<perm::AuditView>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let like = |v: &Option<String>| {
        v.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(|t| t.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"))
    };
    let entries = sqlx::query_as::<_, AuditEntry>(
        "SELECT a.id, a.time, a.username, a.action, a.detail FROM audit_log a
          WHERE ($2::text IS NULL OR a.username = lower($2))
            AND ($3::text IS NULL OR a.action LIKE $3 || '%')
            AND ($4::text IS NULL OR a.detail::text ILIKE '%' || $4 || '%')
            AND ($5::bigint IS NULL OR (a.detail->>'site_id')::bigint = $5
                 OR (a.detail->>'device_id')::bigint IN (SELECT id FROM devices WHERE site_id = $5))
          ORDER BY a.time DESC LIMIT $1",
    )
    .bind(limit)
    .bind(q.user.as_deref().map(str::trim).filter(|t| !t.is_empty()))
    .bind(like(&q.action))
    .bind(like(&q.q))
    .bind(q.site)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(entries))
}

// ---------------------------------------------------------------------------
// Zeitplan der Geräte-Suche
// ---------------------------------------------------------------------------

async fn discovery_view(st: &AppState) -> Value {
    use scanner::schedule;
    let plan = schedule::load(&st.db, &st.config).await;
    let last = schedule::last_full_scan(&st.db).await;
    let tz = schedule::timezone();
    let next = schedule::next_due(&plan, last, Utc::now(), tz);
    json!({ "schedule": plan, "last_run": last, "next_run": next, "timezone": tz.name() })
}

pub async fn get_discovery(State(st): State<AppState>, _admin: Need<perm::NetworksManage>) -> Json<Value> {
    Json(discovery_view(&st).await)
}

pub async fn set_discovery(
    State(st): State<AppState>,
    Need(user, _): Need<perm::NetworksManage>,
    Json(mut plan): Json<scanner::schedule::Schedule>,
) -> ApiResult<Json<Value>> {
    plan.times = plan.times.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
    plan.times.sort();
    plan.times.dedup();
    plan.validate().map_err(ApiError::BadRequest)?;
    scanner::schedule::save(&st.db, &plan).await?;
    audit::by(&st.db, &user, "discovery_schedule", json!(plan)).await;
    Ok(Json(discovery_view(&st).await))
}

// ---------------------------------------------------------------------------
// System-Log (die letzten Meldungen aus dem Speicher)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LogQuery {
    level: Option<String>,
    q: Option<String>,
    limit: Option<usize>,
}

pub async fn system_log(_admin: Need<perm::AuditView>, Query(q): Query<LogQuery>) -> Json<Vec<crate::logbuf::LogLine>> {
    Json(crate::logbuf::recent(
        q.level.as_deref().unwrap_or("info"),
        q.q.as_deref().unwrap_or("").trim(),
        q.limit.unwrap_or(500).clamp(1, 5000),
    ))
}

// ---------------------------------------------------------------------------
// Echtzeit-Abfrage
// ---------------------------------------------------------------------------

pub async fn get_live(State(st): State<AppState>, _user: CurrentUser) -> Json<crate::collect::fast::LiveSettings> {
    Json(crate::collect::fast::load_settings(&st.db).await)
}

pub async fn set_live(
    State(st): State<AppState>,
    Need(user, _): Need<perm::SettingsManage>,
    Json(settings): Json<crate::collect::fast::LiveSettings>,
) -> ApiResult<Json<crate::collect::fast::LiveSettings>> {
    settings.validate().map_err(ApiError::BadRequest)?;
    crate::collect::fast::save_settings(&st.db, &settings).await?;
    audit::by(&st.db, &user, "live_settings", json!(settings)).await;
    Ok(Json(settings))
}

// ---------------------------------------------------------------------------
// Systemzustand (CPU, RAM, Dauer der Aufgaben)
// ---------------------------------------------------------------------------

pub async fn system(State(st): State<AppState>, _admin: Need<perm::AuditView>) -> ApiResult<Json<Value>> {
    let (db_mb, devices, monitored, shellys, checks): (f64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT pg_database_size(current_database())::float8 / 1048576,
                (SELECT count(*) FROM devices), (SELECT count(*) FROM devices WHERE monitored),
                (SELECT count(*) FROM devices WHERE integration = 'shelly'), (SELECT count(*) FROM checks WHERE enabled)",
    )
    .fetch_one(&st.db)
    .await?;
    let live = crate::collect::fast::load_settings(&st.db).await;
    Ok(Json(json!({
        "process": crate::perf::process(),
        "tasks": crate::perf::tasks(),
        "db_mb": (db_mb * 10.0).round() / 10.0,
        "devices": devices,
        "monitored": monitored,
        "shellys": shellys,
        "checks": checks,
        "browsers": st.hub.clients(),
        "live_interval_s": live.interval_s,
        "live_enabled": live.enabled,
        "inventory_interval_min": st.config.inventory_interval.as_secs() / 60,
        "monitor_interval_s": st.config.monitor_interval.as_secs(),
    })))
}

// ---------------------------------------------------------------------------
// Wartungsfenster
// ---------------------------------------------------------------------------

pub async fn list_maintenance(State(st): State<AppState>, user: Need<perm::View>) -> ApiResult<Json<Value>> {
    let mut windows: Vec<crate::maintenance::Window> =
        sqlx::query_as(&format!("{} ORDER BY enabled DESC, name", crate::maintenance::SELECT)).fetch_all(&st.db).await?;
    // Eingeschränkte Benutzer sehen nur Fenster, die ausschließlich ihre Sektoren betreffen
    if let Some(allowed) = user.site_filter("view") {
        let mut keep = Vec::new();
        for w in windows {
            if maintenance_scope_ok(&st, &allowed, &w.device_ids, &w.check_ids, &w.site_ids).await? {
                keep.push(w);
            }
        }
        windows = keep;
    }
    let now = Utc::now();
    let tz = scanner::schedule::timezone();
    let list: Vec<Value> = windows
        .iter()
        .map(|w| {
            let mut v = json!(w);
            v["active"] = json!(w.active_at(now, tz));
            v
        })
        .collect();
    // Für die Oberfläche: was ist gerade in Wartung?
    let active: Vec<&crate::maintenance::Window> = windows.iter().filter(|w| w.active_at(now, tz)).collect();
    let all = active.iter().any(|w| w.device_ids.is_empty() && w.check_ids.is_empty() && w.site_ids.is_empty());
    let device_ids: Vec<i64> = active.iter().flat_map(|w| w.device_ids.clone()).collect();
    let check_ids: Vec<i64> = active.iter().flat_map(|w| w.check_ids.clone()).collect();
    let site_ids: Vec<i64> = active.iter().flat_map(|w| w.site_ids.clone()).collect();
    Ok(Json(json!({ "windows": list, "active": { "all": all, "device_ids": device_ids, "check_ids": check_ids, "site_ids": site_ids } })))
}

/// Liegen alle betroffenen Geräte, Dienste und Sektoren in den erlaubten Sektoren?
/// Ein Fenster ohne Auswahl gilt für alles – das dürfen nur Benutzer mit Recht in allen Sektoren.
async fn maintenance_scope_ok(st: &AppState, allowed: &[i64], devices: &[i64], checks: &[i64], sites: &[i64]) -> ApiResult<bool> {
    if devices.is_empty() && checks.is_empty() && sites.is_empty() {
        return Ok(false);
    }
    if sites.iter().any(|s| !allowed.contains(s)) {
        return Ok(false);
    }
    let (outside,): (i64,) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM devices WHERE id = ANY($1) AND NOT site_id = ANY($3))
              + (SELECT count(*) FROM checks WHERE id = ANY($2) AND (site_id IS NULL OR NOT site_id = ANY($3)))",
    )
    .bind(devices)
    .bind(checks)
    .bind(allowed)
    .fetch_one(&st.db)
    .await?;
    Ok(outside == 0)
}

async fn require_maintenance_scope(st: &AppState, user: &CurrentUser, devices: &[i64], checks: &[i64], sites: &[i64]) -> ApiResult<()> {
    match user.site_filter("maintenance.manage") {
        None => Ok(()),
        Some(allowed) if maintenance_scope_ok(st, &allowed, devices, checks, sites).await? => Ok(()),
        Some(_) => Err(ApiError::BadRequest("Wartungsfenster dürfen nur Geräte, Dienste und Sektoren betreffen, für die du zuständig bist".into())),
    }
}

#[derive(Deserialize, Serialize)]
pub struct MaintenanceInput {
    name: String,
    kind: String,
    starts_at: Option<DateTime<Utc>>,
    ends_at: Option<DateTime<Utc>>,
    #[serde(default)]
    days: Vec<i32>,
    time_from: Option<String>,
    time_to: Option<String>,
    #[serde(default)]
    device_ids: Vec<i64>,
    #[serde(default)]
    check_ids: Vec<i64>,
    #[serde(default)]
    site_ids: Vec<i64>,
    enabled: Option<bool>,
}

fn validate_maintenance(m: &MaintenanceInput) -> ApiResult<()> {
    if m.name.trim().is_empty() || m.name.len() > 100 {
        return Err(ApiError::BadRequest("Bitte einen Namen angeben".into()));
    }
    match m.kind.as_str() {
        "once" => match (m.starts_at, m.ends_at) {
            (Some(a), Some(b)) if a < b => Ok(()),
            _ => Err(ApiError::BadRequest("Beginn und Ende angeben (Ende nach Beginn)".into())),
        },
        "weekly" => {
            let ok = |t: &Option<String>| t.as_deref().is_some_and(|t| chrono::NaiveTime::parse_from_str(t, "%H:%M").is_ok());
            if m.days.is_empty() || m.days.iter().any(|d| !(1..=7).contains(d)) {
                return Err(ApiError::BadRequest("Mindestens einen Wochentag wählen".into()));
            }
            if !ok(&m.time_from) || !ok(&m.time_to) {
                return Err(ApiError::BadRequest("Uhrzeiten im Format 03:00 angeben".into()));
            }
            Ok(())
        }
        _ => Err(ApiError::BadRequest("Unbekannte Art".into())),
    }
}

pub async fn create_maintenance(
    State(st): State<AppState>,
    Need(user, _): Need<perm::MaintenanceManage>,
    Json(m): Json<MaintenanceInput>,
) -> ApiResult<Json<Value>> {
    validate_maintenance(&m)?;
    require_maintenance_scope(&st, &user, &m.device_ids, &m.check_ids, &m.site_ids).await?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO maintenance_windows (name, kind, starts_at, ends_at, days, time_from, time_to, device_ids, check_ids, enabled, site_ids)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id",
    )
    .bind(m.name.trim())
    .bind(&m.kind)
    .bind(m.starts_at)
    .bind(m.ends_at)
    .bind(&m.days)
    .bind(&m.time_from)
    .bind(&m.time_to)
    .bind(&m.device_ids)
    .bind(&m.check_ids)
    .bind(m.enabled.unwrap_or(true))
    .bind(&m.site_ids)
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "maintenance_add", json!({ "id": id, "window": m })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_maintenance(
    State(st): State<AppState>,
    Need(user, _): Need<perm::MaintenanceManage>,
    Path(id): Path<i64>,
    Json(m): Json<MaintenanceInput>,
) -> ApiResult<Json<Value>> {
    validate_maintenance(&m)?;
    require_maintenance_scope(&st, &user, &m.device_ids, &m.check_ids, &m.site_ids).await?;
    require_existing_window_scope(&st, &user, id).await?;
    let done = sqlx::query(
        "UPDATE maintenance_windows SET name = $2, kind = $3, starts_at = $4, ends_at = $5, days = $6, time_from = $7,
                time_to = $8, device_ids = $9, check_ids = $10, enabled = COALESCE($11, enabled), site_ids = $12 WHERE id = $1",
    )
    .bind(id)
    .bind(m.name.trim())
    .bind(&m.kind)
    .bind(m.starts_at)
    .bind(m.ends_at)
    .bind(&m.days)
    .bind(&m.time_from)
    .bind(&m.time_to)
    .bind(&m.device_ids)
    .bind(&m.check_ids)
    .bind(m.enabled)
    .bind(&m.site_ids)
    .execute(&st.db)
    .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "maintenance_update", json!({ "id": id })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Bestehendes Fenster: darf der Benutzer es überhaupt ändern?
async fn require_existing_window_scope(st: &AppState, user: &CurrentUser, id: i64) -> ApiResult<()> {
    let row: Option<(Vec<i64>, Vec<i64>, Vec<i64>)> =
        sqlx::query_as("SELECT device_ids, check_ids, site_ids FROM maintenance_windows WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let (devices, checks, sites) = row.ok_or(ApiError::NotFound)?;
    require_maintenance_scope(st, user, &devices, &checks, &sites).await
}

pub async fn delete_maintenance(State(st): State<AppState>, Need(user, _): Need<perm::MaintenanceManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    require_existing_window_scope(&st, &user, id).await?;
    let (name,): (String,) = sqlx::query_as("DELETE FROM maintenance_windows WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "maintenance_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Empfangene Protokolle (Syslog, SNMP-Traps)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RemoteLogQuery {
    device: Option<i64>,
    /// höchste Schwere (0 = Notfall … 7 = Debug)
    severity: Option<i16>,
    q: Option<String>,
    /// `syslog` oder `trap`
    source: Option<String>,
    hours: Option<i32>,
    limit: Option<i64>,
}

#[derive(Serialize, FromRow)]
pub struct RemoteLog {
    time: DateTime<Utc>,
    device_id: Option<i64>,
    device_label: Option<String>,
    source: String,
    facility: i16,
    severity: i16,
    host: Option<String>,
    app: Option<String>,
    message: String,
}

pub async fn remote_logs(State(st): State<AppState>, user: Need<perm::DevicesDiagnose>, Query(q): Query<RemoteLogQuery>) -> ApiResult<Json<Value>> {
    // Meldungen ohne zugeordnetes Gerät sehen nur Benutzer mit dem Recht für alle Sektoren
    let sites = user.site_filter("devices.diagnose");
    let text = q.q.as_deref().map(str::trim).filter(|t| !t.is_empty())
        .map(|t| format!("%{}%", t.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    let rows = sqlx::query_as::<_, RemoteLog>(
        "SELECT m.time, m.device_id, COALESCE(d.name, d.reported_name, d.hostname) AS device_label, host(m.source) AS source,
                m.facility, m.severity, m.host, m.app, m.message
           FROM syslog_messages m LEFT JOIN devices d ON d.id = m.device_id
          WHERE m.time > now() - make_interval(hours => $1)
            AND ($2::bigint IS NULL OR m.device_id = $2)
            AND m.severity <= $3
            AND ($4::text IS NULL OR m.message ILIKE $4 OR m.app ILIKE $4 OR m.host ILIKE $4)
            AND ($5::text IS NULL OR ($5 = 'trap') = (m.app = 'snmp-trap'))
            AND ($7::bigint[] IS NULL OR d.site_id = ANY($7))
          ORDER BY m.time DESC LIMIT $6",
    )
    .bind(q.hours.unwrap_or(24).clamp(1, 24 * 90))
    .bind(q.device)
    .bind(q.severity.unwrap_or(7))
    .bind(&text)
    .bind(q.source.as_deref().filter(|s| *s == "syslog" || *s == "trap"))
    .bind(q.limit.unwrap_or(500).clamp(1, 5000))
    .bind(&sites)
    .fetch_all(&st.db)
    .await?;
    let (last_hour,): (i64,) = sqlx::query_as("SELECT count(*) FROM syslog_messages WHERE time > now() - interval '1 hour'")
        .fetch_one(&st.db)
        .await?;
    Ok(Json(json!({
        "items": rows,
        "last_hour": last_hour,
        "syslog_port": st.config.syslog_port,
        "trap_port": st.config.trap_port,
        "receiver": crate::syslog::status(),
    })))
}

/// Testmeldung an den eigenen Syslog-Empfang schicken
pub async fn remote_logs_test(State(st): State<AppState>, _admin: Need<perm::SettingsManage>) -> ApiResult<Json<Value>> {
    if st.config.syslog_port == 0 {
        return Err(ApiError::BadRequest("Der Syslog-Empfang ist ausgeschaltet (SYSLOG_PORT=0)".into()));
    }
    crate::syslog::send_test(st.config.syslog_port).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Sicherheit: 2FA-Pflicht
// ---------------------------------------------------------------------------

pub async fn get_security(State(st): State<AppState>, _admin: Need<perm::UsersManage>) -> ApiResult<Json<Value>> {
    let (without,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE NOT totp_enabled").fetch_one(&st.db).await?;
    Ok(Json(json!({
        "require_totp": crate::auth::totp_required(&st).await,
        "forced_by_env": st.config.require_totp,
        "users_without_totp": without,
    })))
}

#[derive(Deserialize)]
pub struct SecuritySettings {
    require_totp: bool,
}

pub async fn set_security(
    State(st): State<AppState>,
    Need(user, _): Need<perm::UsersManage>,
    Json(req): Json<SecuritySettings>,
) -> ApiResult<Json<Value>> {
    user.require_recent_auth(&st.db).await?;
    if st.config.require_totp && !req.require_totp {
        return Err(ApiError::BadRequest("Die 2FA-Pflicht ist über REQUIRE_TOTP fest eingeschaltet".into()));
    }
    if req.require_totp {
        // Nicht aussperren: Wer die Pflicht einschaltet, muss 2FA selbst schon nutzen
        let (own,): (bool,) = sqlx::query_as("SELECT totp_enabled FROM users WHERE id = $1").bind(user.id).fetch_one(&st.db).await?;
        if !own {
            return Err(ApiError::BadRequest("Bitte zuerst für dein eigenes Konto 2FA einrichten (Mein Konto)".into()));
        }
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('security', jsonb_build_object('require_totp', $1::bool))
         ON CONFLICT (key) DO UPDATE SET value = settings.value || EXCLUDED.value",
    )
    .bind(req.require_totp)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "security_settings", json!({ "require_totp": req.require_totp })).await;
    get_security(State(st), Need(user, std::marker::PhantomData)).await
}
