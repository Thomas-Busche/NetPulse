//! Dienst-Checks verwalten und auswerten.

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
    checks,
    error::{ApiError, ApiResult},
    AppState,
};

#[derive(Serialize, FromRow)]
pub struct CheckRow {
    id: i64,
    name: String,
    kind: String,
    target: String,
    config: Value,
    interval_s: i32,
    timeout_s: i32,
    device_id: Option<i64>,
    device_label: Option<String>,
    enabled: bool,
    status: String,
    status_since: Option<DateTime<Utc>>,
    last_check: Option<DateTime<Utc>>,
    last_ms: Option<f32>,
    last_message: Option<String>,
    cert_expires_at: Option<DateTime<Utc>>,
    /// Verfügbarkeit der letzten 24 h in Prozent
    uptime_24h: Option<f64>,
    /// Die letzten 40 Ergebnisse (ältestes zuerst) für die Heartbeat-Anzeige
    beats: Option<Vec<bool>>,
    /// Gerade pausiert (z. B. Backup läuft) – Grund
    paused: Option<String>,
    site_id: Option<i64>,
    site_label: Option<String>,
}

const SELECT: &str = "SELECT c.id, c.name, c.kind, c.target, c.config, c.interval_s, c.timeout_s, c.device_id,
        COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)) AS device_label, c.enabled, c.status, c.status_since,
        c.last_check, c.last_ms, c.last_message, c.cert_expires_at,
        (SELECT round(100.0 * avg(CASE WHEN ok THEN 1 ELSE 0 END), 2)::float8 FROM check_results r
          WHERE r.check_id = c.id AND r.time > now() - interval '24 hours') AS uptime_24h,
        (SELECT array_agg(ok ORDER BY time) FROM (SELECT ok, time FROM check_results r WHERE r.check_id = c.id
          ORDER BY time DESC LIMIT 40) x) AS beats,
        (SELECT p.reason || ': ' || array_to_string(p.subjects, ', ') FROM integration_pauses p
          WHERE p.until > now() AND c.id = ANY(p.check_ids) ORDER BY p.started_at LIMIT 1) AS paused,
        c.site_id, s.name AS site_label
   FROM checks c LEFT JOIN devices d ON d.id = c.device_id LEFT JOIN sites s ON s.id = c.site_id";

#[derive(Deserialize)]
pub struct ListQuery {
    site: Option<i64>,
}

/// Dienste ohne Sektor (übergreifend) sehen nur Benutzer mit Recht in allen Sektoren
pub async fn list(State(st): State<AppState>, user: Need<perm::View>, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<CheckRow>>> {
    let sites = crate::sites::filter(&st.db, &user, "view", q.site).await?;
    let sql = format!(
        "{SELECT} WHERE ($1::bigint[] IS NULL OR c.site_id = ANY($1)) ORDER BY (c.status = 'down') DESC, (c.status = 'warn') DESC, c.name"
    );
    Ok(Json(sqlx::query_as::<_, CheckRow>(&sql).bind(&sites).fetch_all(&st.db).await?))
}

/// Recht für einen Dienst prüfen (Sektor des Dienstes; ohne Sektor nur mit Recht in allen Sektoren)
async fn require_check(st: &AppState, user: &CurrentUser, perm: &str, id: i64) -> ApiResult<()> {
    let row: Option<(Option<i64>,)> = sqlx::query_as("SELECT site_id FROM checks WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let (site,) = row.ok_or(ApiError::NotFound)?;
    let ok = match site {
        Some(site) => user.can_site(perm, site),
        None => user.can(perm),
    };
    if ok { Ok(()) } else { Err(ApiError::NotFound) }
}

/// Sektor eines neuen/geänderten Dienstes: ausdrücklich gewählt, sonst der des Geräts
async fn target_site(st: &AppState, user: &CurrentUser, site: Option<i64>, device: Option<i64>) -> ApiResult<Option<i64>> {
    let site = match (site.filter(|s| *s > 0), device) {
        (Some(s), _) => Some(s),
        (None, Some(d)) => sqlx::query_as::<_, (i64,)>("SELECT site_id FROM devices WHERE id = $1").bind(d).fetch_optional(&st.db).await?.map(|r| r.0),
        (None, None) => None,
    };
    let ok = match site {
        Some(s) => user.can_site("checks.manage", s),
        None => user.can("checks.manage"),
    };
    if ok { Ok(site) } else { Err(ApiError::BadRequest("Bitte einen Sektor wählen, für den du Dienste verwalten darfst".into())) }
}

async fn one(st: &AppState, id: i64) -> ApiResult<CheckRow> {
    let sql = format!("{SELECT} WHERE c.id = $1");
    sqlx::query_as::<_, CheckRow>(&sql).bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound)
}

#[derive(Deserialize, Serialize)]
pub struct CheckInput {
    name: Option<String>,
    kind: Option<String>,
    target: Option<String>,
    #[serde(default)]
    config: Option<Value>,
    interval_s: Option<i32>,
    timeout_s: Option<i32>,
    device_id: Option<i64>,
    enabled: Option<bool>,
    /// Sektor (leer = der des Geräts bzw. übergreifend)
    #[serde(default)]
    site_id: Option<i64>,
}

fn validate(kind: &str, target: &str) -> ApiResult<()> {
    if !checks::KINDS.contains(&kind) {
        return Err(ApiError::BadRequest("Unbekannte Check-Art".into()));
    }
    let target = target.trim();
    if target.is_empty() || target.len() > 500 {
        return Err(ApiError::BadRequest("Ziel fehlt".into()));
    }
    if kind == "http" && !(target.starts_with("http://") || target.starts_with("https://")) {
        return Err(ApiError::BadRequest("URL muss mit http:// oder https:// beginnen".into()));
    }
    if kind == "tcp" && !target.contains(':') {
        return Err(ApiError::BadRequest("Bitte Host und Port angeben, z. B. 192.168.1.10:22".into()));
    }
    Ok(())
}

fn clean_config(config: Option<Value>) -> Value {
    match config {
        Some(Value::Object(map)) => Value::Object(map.into_iter().take(20).collect()),
        _ => json!({}),
    }
}

pub async fn create(State(st): State<AppState>, Need(user, _): Need<perm::ChecksManage>, Json(req): Json<CheckInput>) -> ApiResult<Json<CheckRow>> {
    let kind = req.kind.clone().unwrap_or_default();
    let target = req.target.clone().unwrap_or_default();
    validate(&kind, &target)?;
    let site = target_site(&st, &user, req.site_id, req.device_id).await?;
    let name = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or(target.trim()).chars().take(100).collect::<String>();
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO checks (name, kind, target, config, interval_s, timeout_s, device_id, enabled, site_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(&name)
    .bind(&kind)
    .bind(target.trim())
    .bind(clean_config(req.config.clone()))
    .bind(req.interval_s.unwrap_or(60).clamp(10, 86_400))
    .bind(req.timeout_s.unwrap_or(10).clamp(1, 60))
    .bind(req.device_id)
    .bind(req.enabled.unwrap_or(true))
    .bind(site)
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "check_add", json!({ "id": id, "name": name, "target": target })).await;
    Ok(Json(one(&st, id).await?))
}

pub async fn update(
    State(st): State<AppState>,
    Need(user, _): Need<perm::ChecksManage>,
    Path(id): Path<i64>,
    Json(req): Json<CheckInput>,
) -> ApiResult<Json<CheckRow>> {
    require_check(&st, &user, "checks.manage", id).await?;
    let current = one(&st, id).await?;
    let site = target_site(&st, &user, req.site_id.or(current.site_id), req.device_id).await?;
    let kind = req.kind.clone().unwrap_or(current.kind);
    let target = req.target.clone().unwrap_or(current.target);
    validate(&kind, &target)?;
    sqlx::query(
        "UPDATE checks SET name = COALESCE(NULLIF(trim($2), ''), name), kind = $3, target = $4,
                config = COALESCE($5, config), interval_s = COALESCE($6, interval_s), timeout_s = COALESCE($7, timeout_s),
                device_id = $8, enabled = COALESCE($9, enabled), fail_count = 0, last_check = NULL, site_id = $10
          WHERE id = $1",
    )
    .bind(id)
    .bind(&req.name)
    .bind(&kind)
    .bind(target.trim())
    .bind(req.config.clone().map(|c| clean_config(Some(c))))
    .bind(req.interval_s.map(|i| i.clamp(10, 86_400)))
    .bind(req.timeout_s.map(|t| t.clamp(1, 60)))
    .bind(req.device_id)
    .bind(req.enabled)
    .bind(site)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "check_update", json!({ "id": id })).await;
    Ok(Json(one(&st, id).await?))
}

pub async fn remove(State(st): State<AppState>, Need(user, _): Need<perm::ChecksManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    require_check(&st, &user, "checks.manage", id).await?;
    let (name,): (String,) =
        sqlx::query_as("DELETE FROM checks WHERE id = $1 RETURNING name").bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "check_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Sofort prüfen und Ergebnis zurückgeben
pub async fn run_now(State(st): State<AppState>, user: Need<perm::ChecksManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    require_check(&st, &user, "checks.manage", id).await?;
    let check: checks::Check =
        sqlx::query_as("SELECT id, name, kind, target, config, timeout_s, status, fail_count FROM checks WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound)?;
    let outcome = checks::execute(&st, &check).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    Ok(Json(json!({ "outcome": outcome, "check": one(&st, id).await? })))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    hours: Option<i32>,
}

#[derive(Serialize, FromRow)]
pub struct HistoryPoint {
    bucket: DateTime<Utc>,
    ms: Option<f32>,
    availability: Option<f32>,
}

pub async fn history(
    State(st): State<AppState>,
    user: Need<perm::View>,
    Path(id): Path<i64>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<Value>> {
    require_check(&st, &user, "view", id).await?;
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 90);
    let bucket = (hours * 60 / 300).max(1);
    let points = sqlx::query_as::<_, HistoryPoint>(
        "SELECT time_bucket(make_interval(mins => $2), time) AS bucket, avg(ms)::real AS ms,
                avg(CASE WHEN ok THEN 1.0 ELSE 0.0 END)::real AS availability
           FROM check_results WHERE check_id = $1 AND time > now() - make_interval(hours => $3)
          GROUP BY bucket ORDER BY bucket",
    )
    .bind(id)
    .bind(bucket)
    .bind(hours)
    .fetch_all(&st.db)
    .await?;
    let uptime: Vec<(String, Option<f64>)> = sqlx::query_as(
        "SELECT p.label, (SELECT round(100.0 * avg(CASE WHEN ok THEN 1 ELSE 0 END), 3)::float8 FROM check_results
                           WHERE check_id = $1 AND time > now() - p.span)
           FROM (VALUES ('24 h', interval '24 hours'), ('7 Tage', interval '7 days'), ('30 Tage', interval '30 days')) AS p(label, span)",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({
        "check": one(&st, id).await?,
        "points": points,
        "uptime": uptime.into_iter().map(|(label, value)| json!({ "label": label, "value": value })).collect::<Vec<_>>(),
    })))
}
