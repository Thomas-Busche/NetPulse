//! Eigene Abfragen und Aktionen (siehe `collect::custom`).
//!
//! Anlegen/Ändern: Recht „Zugangsdaten verwalten“ und frische Anmeldung (Befehle laufen mit diesen Zugangsdaten).
//! Ausführen einer Aktion: Recht „Geräte verwalten“ für den Sektor des Geräts.

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::{
    audit,
    auth::{perm, Need},
    collect::custom::{self, Outcome, Query},
    error::{ApiError, ApiResult},
    AppState,
};

#[derive(Serialize, FromRow)]
pub struct QueryInfo {
    id: i64,
    name: String,
    credential_id: i64,
    credential_name: String,
    credential_kind: String,
    mode: String,
    target: String,
    method: String,
    body: Option<String>,
    extract: Option<String>,
    value_type: String,
    unit: Option<String>,
    device_ids: Option<Vec<i64>>,
    enabled: bool,
    created_at: DateTime<Utc>,
    results_ok: i64,
    results_failed: i64,
}

const SELECT: &str = "SELECT q.id, q.name, q.credential_id, c.name AS credential_name, c.kind AS credential_kind, q.mode, q.target,
                             q.method, q.body, q.extract, q.value_type, q.unit, q.device_ids, q.enabled, q.created_at,
                             (SELECT count(*) FROM custom_query_results r WHERE r.query_id = q.id AND r.ok) AS results_ok,
                             (SELECT count(*) FROM custom_query_results r WHERE r.query_id = q.id AND NOT r.ok) AS results_failed
                        FROM custom_queries q JOIN credentials c ON c.id = q.credential_id";

pub async fn list(State(st): State<AppState>, _admin: Need<perm::CredentialsManage>) -> ApiResult<Json<Vec<QueryInfo>>> {
    let sql = format!("{SELECT} ORDER BY c.name, q.name");
    Ok(Json(sqlx::query_as::<_, QueryInfo>(&sql).fetch_all(&st.db).await?))
}

async fn one(st: &AppState, id: i64) -> ApiResult<QueryInfo> {
    let sql = format!("{SELECT} WHERE q.id = $1");
    sqlx::query_as::<_, QueryInfo>(&sql).bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound)
}

/// Eingaben säubern und prüfen
async fn checked(st: &AppState, mut q: Query) -> ApiResult<Query> {
    q.name = q.name.trim().to_string();
    if q.name.is_empty() || q.name.chars().count() > 100 {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 100 Zeichen) angeben".into()));
    }
    q.method = q.method.trim().to_ascii_uppercase();
    for field in [&mut q.body, &mut q.extract, &mut q.unit] {
        *field = field.take().filter(|v| !v.trim().is_empty());
    }
    if q.unit.as_deref().is_some_and(|u| u.chars().count() > 20) {
        return Err(ApiError::BadRequest("Einheit: höchstens 20 Zeichen".into()));
    }
    if q.body.as_deref().is_some_and(|b| b.len() > 20_000) {
        return Err(ApiError::BadRequest("Inhalt (Body) zu lang".into()));
    }
    let (kind,): (String,) = sqlx::query_as("SELECT kind FROM credentials WHERE id = $1")
        .bind(q.credential_id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| ApiError::BadRequest("Zugangsdaten nicht gefunden".into()))?;
    custom::validate(&q, &kind).map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    if let Some(ids) = &mut q.device_ids {
        ids.sort_unstable();
        ids.dedup();
        if ids.is_empty() {
            q.device_ids = None;
        }
    }
    Ok(q)
}

pub async fn create(State(st): State<AppState>, Need(user, _): Need<perm::CredentialsManage>, Json(req): Json<Query>) -> ApiResult<Json<QueryInfo>> {
    user.require_recent_auth(&st.db).await?;
    let q = checked(&st, req).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO custom_queries (name, credential_id, mode, target, method, body, extract, value_type, unit, device_ids, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (credential_id, name) DO NOTHING RETURNING id",
    )
    .bind(&q.name)
    .bind(q.credential_id)
    .bind(&q.mode)
    .bind(q.target.trim())
    .bind(&q.method)
    .bind(&q.body)
    .bind(&q.extract)
    .bind(&q.value_type)
    .bind(&q.unit)
    .bind(&q.device_ids)
    .bind(q.enabled)
    .fetch_optional(&st.db)
    .await?
    .ok_or_else(|| ApiError::BadRequest(format!("Für diese Zugangsdaten gibt es schon eine Abfrage „{}“", q.name)))?;
    audit::by(&st.db, &user, "query_add", json!({ "id": id, "name": q.name, "mode": q.mode, "target": q.target })).await;
    Ok(Json(one(&st, id).await?))
}

pub async fn update(
    State(st): State<AppState>,
    Need(user, _): Need<perm::CredentialsManage>,
    Path(id): Path<i64>,
    Json(req): Json<Query>,
) -> ApiResult<Json<QueryInfo>> {
    user.require_recent_auth(&st.db).await?;
    let q = checked(&st, req).await?;
    let done = sqlx::query(
        "UPDATE custom_queries SET name = $2, credential_id = $3, mode = $4, target = $5, method = $6, body = $7, extract = $8,
                value_type = $9, unit = $10, device_ids = $11, enabled = $12
          WHERE id = $1",
    )
    .bind(id)
    .bind(&q.name)
    .bind(q.credential_id)
    .bind(&q.mode)
    .bind(q.target.trim())
    .bind(&q.method)
    .bind(&q.body)
    .bind(&q.extract)
    .bind(&q.value_type)
    .bind(&q.unit)
    .bind(&q.device_ids)
    .bind(q.enabled)
    .execute(&st.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            ApiError::BadRequest(format!("Für diese Zugangsdaten gibt es schon eine Abfrage „{}“", q.name))
        }
        other => other.into(),
    })?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "query_update", json!({ "id": id, "name": q.name, "target": q.target })).await;
    Ok(Json(one(&st, id).await?))
}

pub async fn remove(State(st): State<AppState>, Need(user, _): Need<perm::CredentialsManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let (name,): (String,) =
        sqlx::query_as("DELETE FROM custom_queries WHERE id = $1 RETURNING name").bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "query_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct TestRequest {
    device_id: i64,
    #[serde(flatten)]
    query: Query,
}

/// Ungespeicherte Abfrage gegen ein Gerät ausprobieren (zeigt Rohantwort und übernommenen Wert).
/// Aktionen werden hier nicht ausgeführt – sonst würde „Testen“ z. B. ein Gerät herunterfahren.
pub async fn test(
    State(st): State<AppState>,
    Need(user, _): Need<perm::CredentialsManage>,
    Json(req): Json<TestRequest>,
) -> ApiResult<Json<Outcome>> {
    user.require_recent_auth(&st.db).await?;
    let mut q = req.query;
    if q.mode == "action" {
        return Err(ApiError::BadRequest(
            "Aktionen werden beim Testen nicht ausgeführt. Zum Ausprobieren speichern und in der Geräteansicht „Ausführen“ wählen.".into(),
        ));
    }
    q.method = q.method.trim().to_ascii_uppercase();
    let outcome = custom::execute(&st, &q, req.device_id).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    Ok(Json(outcome))
}

#[derive(Deserialize)]
pub struct RunRequest {
    device_id: i64,
}

/// Gespeicherte Abfrage/Aktion an einem Gerät ausführen
pub async fn run(
    State(st): State<AppState>,
    Need(user, _): Need<perm::View>,
    Path(id): Path<i64>,
    Json(req): Json<RunRequest>,
) -> ApiResult<Json<Outcome>> {
    let (mode, name): (String, String) =
        sqlx::query_as("SELECT mode, name FROM custom_queries WHERE id = $1").bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound)?;
    // Lesen: wer das Gerät diagnostizieren darf; Aktion (z. B. herunterfahren): wer Geräte verwalten darf
    let need = if mode == "action" { "devices.manage" } else { "devices.diagnose" };
    user.require_device(&st.db, need, req.device_id).await?;
    if mode == "action" {
        user.require_recent_auth(&st.db).await?;
    }
    let outcome = custom::run(&st, id, req.device_id).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    if mode == "action" {
        audit::by(&st.db, &user, "query_action", json!({ "id": id, "name": name, "device_id": req.device_id, "ok": outcome.ok })).await;
    }
    Ok(Json(outcome))
}

#[derive(Serialize, FromRow)]
pub struct DeviceQuery {
    id: i64,
    name: String,
    mode: String,
    unit: Option<String>,
    value_type: String,
    credential_name: String,
    time: Option<DateTime<Utc>>,
    ok: Option<bool>,
    value_text: Option<String>,
    value_num: Option<f64>,
    error: Option<String>,
}

/// Abfragen und Aktionen, die für ein Gerät gelten, mit letztem Ergebnis (Geräteansicht)
pub async fn for_device(State(st): State<AppState>, Need(user, _): Need<perm::View>, Path(id): Path<i64>) -> ApiResult<Json<Vec<DeviceQuery>>> {
    user.require_device(&st.db, "view", id).await?;
    let rows = sqlx::query_as::<_, DeviceQuery>(
        "SELECT q.id, q.name, q.mode, q.unit, q.value_type, c.name AS credential_name,
                r.time, r.ok, r.value_text, r.value_num, r.error
           FROM custom_queries q
           JOIN credentials c ON c.id = q.credential_id
           LEFT JOIN custom_query_results r ON r.query_id = q.id AND r.device_id = $1
          WHERE q.enabled AND (CASE WHEN q.device_ids IS NULL
                     THEN EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = $1 AND dc.credential_id = q.credential_id)
                     ELSE $1 = ANY(q.device_ids) END)
          ORDER BY q.mode DESC, q.name",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

/// Verlauf der Zahlenwerte einer Abfrage an einem Gerät (letzte 7 Tage, stündlich gemittelt)
pub async fn history(
    State(st): State<AppState>,
    Need(user, _): Need<perm::View>,
    Path((id, device_id)): Path<(i64, i64)>,
) -> ApiResult<Json<Vec<Value>>> {
    user.require_device(&st.db, "view", device_id).await?;
    let rows: Vec<(DateTime<Utc>, f64)> = sqlx::query_as(
        "SELECT time_bucket('1 hour', time) AS t, avg(value) FROM custom_query_values
          WHERE query_id = $1 AND device_id = $2 AND time > now() - interval '7 days'
          GROUP BY t ORDER BY t",
    )
    .bind(id)
    .bind(device_id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows.into_iter().map(|(t, v)| json!({ "bucket": t, "value": v })).collect()))
}
