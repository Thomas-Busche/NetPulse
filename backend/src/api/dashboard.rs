//! Dashboards: das persönliche Layout und weitere benannte Dashboards, die geteilt (alle oder bestimmte
//! Gruppen) und auf einen Sektor beschränkt werden können. Der Aufbau der Widgets wird von der
//! Weboberfläche festgelegt, der Server speichert ihn nur (mit Größenbegrenzung).

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{perm, CurrentUser, Need},
    error::{ApiError, ApiResult},
    AppState,
};

fn default_layout() -> Value {
    json!([
        { "type": "summary", "size": 3 },
        { "type": "internet", "size": 2 },
        { "type": "power", "size": 1 },
        { "type": "smarthome", "size": 3 },
        { "type": "alerts", "size": 1 },
        { "type": "down", "size": 1 },
        { "type": "types", "size": 1 },
        { "type": "events", "size": 2 },
        { "type": "status_chart", "size": 1 },
        { "type": "services", "size": 1 },
        { "type": "new", "size": 1 },
        { "type": "slowest", "size": 1 }
    ])
}

pub async fn load(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let row: Option<(Value,)> = sqlx::query_as("SELECT layout FROM dashboards WHERE user_id = $1")
        .bind(user.id)
        .fetch_optional(&st.db)
        .await?;
    if let Some((layout,)) = row {
        return Ok(Json(layout));
    }
    // Neue Benutzer: Vorlage der Verwaltung, sonst das eingebaute Layout
    let template: Option<(Value,)> = sqlx::query_as("SELECT layout FROM dashboard_views WHERE is_default AND kind = 'dashboard' ORDER BY updated_at DESC LIMIT 1")
        .fetch_optional(&st.db)
        .await?;
    Ok(Json(template.map(|r| r.0).unwrap_or_else(default_layout)))
}

fn check_layout(layout: &Value) -> ApiResult<()> {
    let widgets = layout
        .as_array()
        .ok_or_else(|| ApiError::BadRequest("Layout muss eine Liste von Widgets sein".into()))?;
    if widgets.len() > 50 || layout.to_string().len() > 32_000 {
        return Err(ApiError::BadRequest("Layout ist zu groß".into()));
    }
    Ok(())
}

pub async fn save(
    State(st): State<AppState>,
    user: CurrentUser,
    Json(layout): Json<Value>,
) -> ApiResult<Json<Value>> {
    if user.kiosk {
        return Err(ApiError::Forbidden);
    }
    check_layout(&layout)?;
    sqlx::query(
        "INSERT INTO dashboards (user_id, layout) VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE SET layout = EXCLUDED.layout, updated_at = now()",
    )
    .bind(user.id)
    .bind(&layout)
    .execute(&st.db)
    .await?;
    Ok(Json(layout))
}

// ---------------------------------------------------------------------------
// Puls: kompakte Verlaufsdaten für Mini-Diagramme (Dashboard, Geräteliste, Kopfzeile)
// ---------------------------------------------------------------------------

type PulseCache = std::sync::Mutex<HashMap<Option<Vec<i64>>, (std::time::Instant, Value)>>;

/// Höchstens einmal pro Minute neu berechnen – die Liste wird oft und von mehreren Browsern geladen.
/// Ein Eintrag je Sektor-Auswahl (Benutzer mit gleichen Rechten teilen sich den Eintrag).
fn pulse_cache() -> &'static PulseCache {
    static CACHE: std::sync::OnceLock<PulseCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

#[derive(Deserialize, Default)]
pub struct PulseQuery {
    pub site: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DevicePulse {
    device_id: i64,
    avail_24h: Option<f64>,
    rtt: Option<Vec<Option<f32>>>,
}

#[derive(sqlx::FromRow)]
struct HourPulse {
    hour: chrono::DateTime<chrono::Utc>,
    up_pct: Option<f64>,
    rtt_ms: Option<f64>,
}

/// Verfügbarkeit (24 h) und Antwortzeit-Verlauf (2 h, 20 Punkte) je Gerät; Verlauf des ganzen Netzes (24 h, stündlich)
pub async fn pulse(State(st): State<AppState>, user: Need<perm::View>, Query(q): Query<PulseQuery>) -> ApiResult<Json<Value>> {
    let sites = crate::sites::filter(&st.db, &user, "view", q.site).await?;
    if let Some((at, value)) = pulse_cache().lock().unwrap().get(&sites) {
        if at.elapsed() < std::time::Duration::from_secs(60) {
            return Ok(Json(value.clone()));
        }
    }
    let devices: Vec<DevicePulse> = sqlx::query_as(
        "WITH avail AS (
             SELECT device_id, round(100.0 * avg(CASE WHEN up THEN 1 ELSE 0 END), 2)::float8 AS avail_24h
               FROM device_metrics WHERE time > now() - interval '24 hours' GROUP BY device_id
         ), buckets AS (
             SELECT device_id, time_bucket('6 minutes', time) AS b, avg(rtt_ms)::real AS rtt
               FROM device_metrics WHERE time > now() - interval '2 hours' GROUP BY device_id, b
         ), spark AS (
             SELECT device_id, array_agg(rtt ORDER BY b) AS rtt FROM buckets GROUP BY device_id
         )
         SELECT a.device_id, a.avail_24h, s.rtt FROM avail a LEFT JOIN spark s USING (device_id)
          WHERE $1::bigint[] IS NULL OR a.device_id IN (SELECT id FROM devices WHERE site_id = ANY($1))",
    )
    .bind(&sites)
    .fetch_all(&st.db)
    .await?;
    let hours: Vec<HourPulse> = sqlx::query_as(
        "SELECT time_bucket('1 hour', m.time) AS hour,
                round(100.0 * avg(CASE WHEN m.up THEN 1 ELSE 0 END), 2)::float8 AS up_pct,
                avg(m.rtt_ms)::float8 AS rtt_ms
           FROM device_metrics m JOIN devices d ON d.id = m.device_id AND d.monitored
          WHERE m.time > now() - interval '24 hours' AND ($1::bigint[] IS NULL OR d.site_id = ANY($1))
          GROUP BY hour ORDER BY hour",
    )
    .bind(&sites)
    .fetch_all(&st.db)
    .await?;
    let (checks_total, checks_up, checks_down, checks_warn): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE enabled), count(*) FILTER (WHERE enabled AND status = 'up'),
                count(*) FILTER (WHERE enabled AND status = 'down'), count(*) FILTER (WHERE enabled AND status = 'warn')
           FROM checks WHERE $1::bigint[] IS NULL OR site_id = ANY($1)",
    )
    .bind(&sites)
    .fetch_one(&st.db)
    .await?;
    let (events_24h,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM events e WHERE e.time > now() - interval '24 hours'
            AND ($1::bigint[] IS NULL OR e.device_id IN (SELECT id FROM devices WHERE site_id = ANY($1)))",
    )
    .bind(&sites)
    .fetch_one(&st.db)
        .await?;
    let total_avail = {
        let v: Vec<f64> = hours.iter().filter_map(|h| h.up_pct).collect();
        (!v.is_empty()).then(|| (v.iter().sum::<f64>() / v.len() as f64 * 100.0).round() / 100.0)
    };
    let value = json!({
        "devices": devices.iter().map(|d| (d.device_id.to_string(), json!({ "avail_24h": d.avail_24h, "rtt": d.rtt })))
            .collect::<serde_json::Map<String, Value>>(),
        "network": {
            "avail_24h": total_avail,
            "hours": hours.iter().map(|h| json!({ "t": h.hour, "up_pct": h.up_pct, "rtt_ms": h.rtt_ms })).collect::<Vec<_>>(),
        },
        "checks": { "total": checks_total, "up": checks_up, "down": checks_down, "warn": checks_warn },
        "events_24h": events_24h,
    });
    {
        let mut cache = pulse_cache().lock().unwrap();
        cache.retain(|_, (at, _)| at.elapsed() < std::time::Duration::from_secs(60));
        cache.insert(sites, (std::time::Instant::now(), value.clone()));
    }
    Ok(Json(value))
}

// ---------------------------------------------------------------------------
// Benannte Dashboards (z. B. „Leitstand Halle 2“), teilbar und je Sektor
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ViewInput {
    pub name: String,
    pub layout: Value,
    #[serde(default)]
    pub site_id: Option<i64>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub group_ids: Vec<i64>,
    #[serde(default)]
    pub is_default: bool,
    /// dashboard (Standard) oder leitstand; nur beim Anlegen, danach fest
    #[serde(default = "default_kind")]
    pub kind: String,
}

fn default_kind() -> String {
    "dashboard".into()
}

#[derive(Deserialize, Default)]
pub struct KindQuery {
    /// dashboard (Standard) oder leitstand
    pub kind: Option<String>,
}

fn check_kind(kind: &str) -> ApiResult<()> {
    if matches!(kind, "dashboard" | "leitstand") {
        Ok(())
    } else {
        Err(ApiError::BadRequest("Unbekannte Art (dashboard oder leitstand)".into()))
    }
}

/// Sichtbar: eigene, für alle geteilte und für eine eigene Gruppe geteilte Dashboards
const VISIBLE: &str = "(v.owner_id = $1 OR (v.shared AND (cardinality(v.group_ids) = 0
                        OR v.group_ids && ARRAY(SELECT group_id FROM group_members WHERE user_id = $1))))";

type ViewRow = (i64, String, Option<i64>, Option<String>, Value, Option<i64>, Option<String>, bool, Vec<i64>, bool);

pub async fn list_views(State(st): State<AppState>, user: Need<perm::View>, Query(q): Query<KindQuery>) -> ApiResult<Json<Value>> {
    let kind = q.kind.unwrap_or_else(default_kind);
    check_kind(&kind)?;
    let rows: Vec<ViewRow> = sqlx::query_as(&format!(
        "SELECT v.id, v.name, v.owner_id, u.username, v.layout, v.site_id, s.name, v.shared, v.group_ids, v.is_default
           FROM dashboard_views v LEFT JOIN users u ON u.id = v.owner_id LEFT JOIN sites s ON s.id = v.site_id
          WHERE ({VISIBLE} OR $2) AND v.kind = $3
          ORDER BY v.name"
    ))
    .bind(user.id)
    .bind(user.can("settings.manage"))
    .bind(&kind)
    .fetch_all(&st.db)
    .await?;
    // Sektor-Dashboards nur zeigen, wenn der Benutzer den Sektor sehen darf
    let list: Vec<Value> = rows
        .into_iter()
        .filter(|r| r.5.is_none_or(|site| user.can_site("view", site)))
        .map(|(id, name, owner_id, owner, layout, site_id, site, shared, group_ids, is_default)| {
            json!({
                "id": id, "name": name, "owner_id": owner_id, "owner": owner, "layout": layout, "site_id": site_id,
                "site": site, "shared": shared, "group_ids": group_ids, "is_default": is_default,
                "editable": owner_id == Some(user.id) || user.can("settings.manage"),
            })
        })
        .collect();
    Ok(Json(json!(list)))
}

async fn check_view(st: &AppState, user: &CurrentUser, v: &ViewInput) -> ApiResult<String> {
    let name = v.name.trim().to_string();
    if name.is_empty() || name.len() > 80 {
        return Err(ApiError::BadRequest("Name fehlt oder ist zu lang".into()));
    }
    check_layout(&v.layout)?;
    check_kind(&v.kind)?;
    if let Some(site) = v.site_id {
        user.require_site("view", site)?;
    }
    // Teilen mit anderen und Vorlage für neue Benutzer nur mit Einstellungs-Recht
    if (v.shared || v.is_default) && !user.can("settings.manage") {
        return Err(ApiError::Forbidden);
    }
    let _ = st;
    Ok(name)
}

pub async fn create_view(State(st): State<AppState>, Need(user, _): Need<perm::View>, Json(v): Json<ViewInput>) -> ApiResult<Json<Value>> {
    if user.kiosk {
        return Err(ApiError::Forbidden);
    }
    let name = check_view(&st, &user, &v).await?;
    let mut tx = st.db.begin().await?;
    if v.is_default {
        sqlx::query("UPDATE dashboard_views SET is_default = false WHERE kind = $1").bind(&v.kind).execute(&mut *tx).await?;
    }
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO dashboard_views (name, owner_id, layout, site_id, shared, group_ids, is_default, kind)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(&name)
    .bind(user.id)
    .bind(&v.layout)
    .bind(v.site_id)
    .bind(v.shared)
    .bind(&v.group_ids)
    .bind(v.is_default)
    .bind(&v.kind)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    audit::log(&st.db, Some(user.id), Some(&user.username), "dashboard_view_create", json!({ "id": id, "name": name, "shared": v.shared, "kind": v.kind })).await;
    Ok(Json(json!({ "id": id })))
}

async fn require_editable(st: &AppState, user: &CurrentUser, id: i64) -> ApiResult<()> {
    let owner: Option<(Option<i64>,)> = sqlx::query_as("SELECT owner_id FROM dashboard_views WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let Some((owner,)) = owner else { return Err(ApiError::NotFound) };
    if owner != Some(user.id) && !user.can("settings.manage") {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

pub async fn update_view(
    State(st): State<AppState>,
    Need(user, _): Need<perm::View>,
    Path(id): Path<i64>,
    Json(v): Json<ViewInput>,
) -> ApiResult<Json<Value>> {
    require_editable(&st, &user, id).await?;
    let name = check_view(&st, &user, &v).await?;
    let mut tx = st.db.begin().await?;
    if v.is_default {
        // Nur unter Ansichten derselben Art (Dashboard bzw. Leitstand)
        sqlx::query("UPDATE dashboard_views SET is_default = false WHERE id <> $1 AND kind = (SELECT kind FROM dashboard_views WHERE id = $1)")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "UPDATE dashboard_views SET name = $2, layout = $3, site_id = $4, shared = $5, group_ids = $6, is_default = $7, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(&v.layout)
    .bind(v.site_id)
    .bind(v.shared)
    .bind(&v.group_ids)
    .bind(v.is_default)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    audit::log(&st.db, Some(user.id), Some(&user.username), "dashboard_view_update", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_view(State(st): State<AppState>, Need(user, _): Need<perm::View>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    require_editable(&st, &user, id).await?;
    sqlx::query("DELETE FROM dashboard_views WHERE id = $1").bind(id).execute(&st.db).await?;
    audit::log(&st.db, Some(user.id), Some(&user.username), "dashboard_view_delete", json!({ "id": id })).await;
    Ok(Json(json!({ "ok": true })))
}
