//! Verbundene Programme: Verwaltung (Admins) und die Schnittstelle für die Programme selbst
//! (`/api/integration/v1/…`, Anmeldung mit `Authorization: Bearer npi_…`). Siehe `crate::integration`.

use axum::{
    extract::{FromRequestParts, Path, State},
    http::{header, request::Parts},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::{
    audit,
    auth::{self, perm, Need},
    error::{ApiError, ApiResult},
    integration::{self, Context, Match, Subject},
    AppState,
};

const KINDS: &[&str] = &["docker-backup-manager", "generic"];

// ---------------------------------------------------------------------------
// Anmeldung der Programme
// ---------------------------------------------------------------------------

/// Ein Programm, das sich mit gültigem Schlüssel gemeldet hat
pub struct Caller {
    id: i64,
    name: String,
    inventory: Vec<Subject>,
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| t.starts_with("npi_"))
            .ok_or(ApiError::Unauthorized)?;
        let row: Option<(i64, String, Value)> =
            sqlx::query_as("SELECT id, name, inventory FROM integrations WHERE token_hash = $1 AND enabled")
                .bind(integration::token_hash(token))
                .fetch_optional(&state.db)
                .await?;
        let (id, name, inventory) = row.ok_or(ApiError::Unauthorized)?;
        let agent: Option<String> = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.chars().filter(|c| !c.is_control()).take(120).collect());
        let _ = sqlx::query("UPDATE integrations SET last_seen_at = now(), last_ip = $2, version = COALESCE($3, version) WHERE id = $1")
            .bind(id)
            .bind(auth::client_ip(&parts.headers))
            .bind(agent)
            .execute(&state.db)
            .await;
        Ok(Self { id, name, inventory: serde_json::from_value(inventory).unwrap_or_default() })
    }
}

/// Container darf als Name oder mit allen Angaben geschickt werden
#[derive(Deserialize)]
#[serde(untagged)]
pub enum SubjectRef {
    Name(String),
    Full(Subject),
}

impl SubjectRef {
    fn into_subject(self, inventory: &[Subject]) -> Option<Subject> {
        let s = match self {
            SubjectRef::Name(name) => Subject { name, ..Default::default() },
            SubjectRef::Full(s) => s,
        };
        s.clean().map(|s| integration::complete(s, inventory))
    }
}

fn split(matches: &[Match]) -> (Vec<i64>, Vec<i64>) {
    let ids = |kind: &str| {
        let mut v: Vec<i64> = matches.iter().filter(|m| m.kind == kind).map(|m| m.id).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    (ids("device"), ids("check"))
}

// ---------------------------------------------------------------------------
// Schnittstelle für die Programme
// ---------------------------------------------------------------------------

/// Verbindungstest
pub async fn hello(caller: Caller) -> Json<Value> {
    Json(json!({
        "ok": true,
        "app": "NetPulse",
        "version": env!("CARGO_PKG_VERSION"),
        "integration": caller.name,
        "max_pause_min": integration::MAX_PAUSE_MIN,
        "default_grace_s": integration::DEFAULT_GRACE_S,
    }))
}

#[derive(Deserialize)]
pub struct InventoryInput {
    subjects: Vec<Subject>,
}

/// Programm meldet seine Container; Antwort: was NetPulse ihnen zuordnet
pub async fn put_inventory(State(st): State<AppState>, caller: Caller, Json(req): Json<InventoryInput>) -> ApiResult<Json<Value>> {
    if req.subjects.len() > 500 {
        return Err(ApiError::BadRequest("Zu viele Einträge (höchstens 500)".into()));
    }
    let subjects: Vec<Subject> = req.subjects.into_iter().filter_map(Subject::clean).collect();
    sqlx::query("UPDATE integrations SET inventory = $2, inventory_at = now() WHERE id = $1")
        .bind(caller.id)
        .bind(serde_json::to_value(&subjects).unwrap_or_default())
        .execute(&st.db)
        .await?;
    let ctx = Context::load(&st.db, caller.id).await?;
    let out: Vec<Value> = subjects.iter().map(|s| json!({ "name": s.name, "matches": ctx.resolve(s) })).collect();
    Ok(Json(json!({ "ok": true, "subjects": out })))
}

#[derive(Deserialize)]
pub struct PauseInput {
    subjects: Vec<SubjectRef>,
    /// spätestes Ende in Minuten (Sicherheitsnetz)
    minutes: Option<i64>,
    reason: Option<String>,
}

/// Überwachung der zugeordneten Geräte/Dienste pausieren (z. B. vor dem Stoppen der Container)
pub async fn pause(State(st): State<AppState>, caller: Caller, Json(req): Json<PauseInput>) -> ApiResult<Json<Value>> {
    if req.subjects.is_empty() || req.subjects.len() > 200 {
        return Err(ApiError::BadRequest("Bitte 1 bis 200 Container angeben".into()));
    }
    let subjects: Vec<Subject> = req.subjects.into_iter().filter_map(|s| s.into_subject(&caller.inventory)).collect();
    let ctx = Context::load(&st.db, caller.id).await?;
    let matches: Vec<Match> = subjects.iter().flat_map(|s| ctx.resolve(s)).collect();
    let (device_ids, check_ids) = split(&matches);
    let minutes = req.minutes.unwrap_or(120).clamp(1, integration::MAX_PAUSE_MIN);
    let reason: String = req
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .unwrap_or("Backup")
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let names: Vec<String> = subjects.iter().map(|s| s.name.clone()).collect();
    let (id, until): (i64, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO integration_pauses (integration_id, subjects, reason, device_ids, check_ids, until)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(mins => $6)) RETURNING id, until",
    )
    .bind(caller.id)
    .bind(&names)
    .bind(&reason)
    .bind(&device_ids)
    .bind(&check_ids)
    .bind(minutes as i32)
    .fetch_one(&st.db)
    .await?;
    tracing::info!(
        "{}: Überwachung pausiert ({reason}: {}) – {} Geräte, {} Dienste, spätestens bis {until}",
        caller.name,
        names.join(", "),
        device_ids.len(),
        check_ids.len()
    );
    st.hub.publish(&json!({ "type": "pause", "id": id, "active": true }));
    let mut dedup: Vec<&Match> = Vec::new();
    for m in &matches {
        if !dedup.iter().any(|d| d.kind == m.kind && d.id == m.id) {
            dedup.push(m);
        }
    }
    Ok(Json(json!({ "id": id, "until": until, "matches": dedup })))
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct EndInput {
    /// Nachlaufzeit in Sekunden, bis wieder geprüft wird
    grace_s: Option<i64>,
}

/// Pause beenden (z. B. nachdem die Container wieder gestartet sind) – nach der Nachlaufzeit wird wieder geprüft
pub async fn end_pause(
    State(st): State<AppState>,
    caller: Caller,
    Path(id): Path<i64>,
    Json(body): Json<EndInput>,
) -> ApiResult<Json<Value>> {
    let grace = body.grace_s.unwrap_or(integration::DEFAULT_GRACE_S).clamp(0, 1800);
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "UPDATE integration_pauses SET ended_at = COALESCE(ended_at, now()),
                until = LEAST(until, now() + make_interval(secs => $3))
          WHERE id = $1 AND integration_id = $2 RETURNING until",
    )
    .bind(id)
    .bind(caller.id)
    .bind(grace as f64)
    .fetch_optional(&st.db)
    .await?;
    let (until,) = row.ok_or(ApiError::NotFound)?;
    st.hub.publish(&json!({ "type": "pause", "id": id, "active": false }));
    Ok(Json(json!({ "ok": true, "until": until })))
}

#[derive(Deserialize)]
pub struct ReportInput {
    /// z. B. "backup", "restore"
    kind: Option<String>,
    subject: String,
    status: Option<String>,
    ok: Option<bool>,
    message: Option<String>,
    duration_s: Option<f32>,
    size_bytes: Option<i64>,
}

fn kind_label(kind: &str) -> String {
    match kind {
        "backup" => "Backup".into(),
        "restore" => "Wiederherstellung".into(),
        other => other.to_string(),
    }
}

/// Ergebnis einer Aufgabe melden; Fehlschläge erscheinen als Ereignis (und lösen ggf. einen Alarm aus)
pub async fn report(State(st): State<AppState>, caller: Caller, Json(req): Json<ReportInput>) -> ApiResult<Json<Value>> {
    let clip = |s: &str, n: usize| -> String { s.trim().chars().filter(|c| !c.is_control()).take(n).collect() };
    let kind = clip(req.kind.as_deref().unwrap_or("backup"), 40).to_lowercase();
    let subject = clip(&req.subject, 200);
    if subject.is_empty() || kind.is_empty() {
        return Err(ApiError::BadRequest("subject fehlt".into()));
    }
    let status = match (req.status.as_deref(), req.ok) {
        (Some(s @ ("ok" | "failed" | "cancelled")), _) => s,
        (None, Some(true)) => "ok",
        (None, Some(false)) => "failed",
        _ => return Err(ApiError::BadRequest("status muss ok, failed oder cancelled sein".into())),
    };
    let message = req.message.as_deref().map(|m| clip(m, 1000)).filter(|m| !m.is_empty());
    sqlx::query(
        "INSERT INTO integration_reports (integration_id, kind, subject, status, message, duration_s, size_bytes)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(caller.id)
    .bind(&kind)
    .bind(&subject)
    .bind(status)
    .bind(&message)
    .bind(req.duration_s.filter(|d| d.is_finite() && *d >= 0.0))
    .bind(req.size_bytes.filter(|s| *s >= 0))
    .execute(&st.db)
    .await?;

    if status == "failed" {
        // Zu welchem Gerät gehört das? Zugeordnetes Gerät des Containers, sonst der Docker-Host
        let s = integration::complete(Subject { name: subject.clone(), ..Default::default() }, &caller.inventory);
        let ctx = Context::load(&st.db, caller.id).await?;
        let device_id = match ctx.resolve(&s).iter().find(|m| m.kind == "device") {
            Some(m) => Some(m.id),
            None => sqlx::query_as::<_, (Option<i64>,)>("SELECT host_device_id FROM integrations WHERE id = $1")
                .bind(caller.id)
                .fetch_one(&st.db)
                .await?
                .0,
        };
        let text = format!(
            "{} von „{subject}“ fehlgeschlagen ({}){}",
            kind_label(&kind),
            caller.name,
            message.as_deref().map(|m| format!(": {m}")).unwrap_or_default()
        );
        sqlx::query("INSERT INTO events (device_id, kind, message) VALUES ($1, 'job_failed', $2)")
            .bind(device_id)
            .bind(text)
            .execute(&st.db)
            .await?;
    }
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Verwaltung (Admins)
// ---------------------------------------------------------------------------

#[derive(FromRow)]
struct Row {
    id: i64,
    name: String,
    kind: String,
    token_hint: String,
    host_device_id: Option<i64>,
    enabled: bool,
    inventory: Value,
    inventory_at: Option<DateTime<Utc>>,
    last_seen_at: Option<DateTime<Utc>>,
    last_ip: Option<String>,
    version: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, FromRow)]
struct PauseRow {
    id: i64,
    integration_id: Option<i64>,
    subjects: Vec<String>,
    reason: String,
    device_ids: Vec<i64>,
    check_ids: Vec<i64>,
    started_at: DateTime<Utc>,
    until: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    active: bool,
}

#[derive(Serialize, FromRow, Clone)]
struct ReportRow {
    id: i64,
    integration_id: i64,
    time: DateTime<Utc>,
    kind: String,
    subject: String,
    status: String,
    message: Option<String>,
    duration_s: Option<f32>,
    size_bytes: Option<i64>,
}

async fn integration_json(st: &AppState, r: Row) -> ApiResult<Value> {
    let ctx = Context::load(&st.db, r.id).await?;
    let inventory: Vec<Subject> = serde_json::from_value(r.inventory).unwrap_or_default();
    // letzte Meldung und letzte erfolgreiche je Container
    let last: Vec<ReportRow> = sqlx::query_as(
        "SELECT DISTINCT ON (subject) id, integration_id, time, kind, subject, status, message, duration_s, size_bytes
           FROM integration_reports WHERE integration_id = $1 ORDER BY subject, time DESC",
    )
    .bind(r.id)
    .fetch_all(&st.db)
    .await?;
    let last_ok: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT subject, max(time) FROM integration_reports WHERE integration_id = $1 AND status = 'ok' GROUP BY subject",
    )
    .bind(r.id)
    .fetch_all(&st.db)
    .await?;
    let subjects: Vec<Value> = inventory
        .iter()
        .map(|s| {
            let link = ctx.links.get(&s.name);
            json!({
                "subject": s,
                "matches": ctx.resolve(s),
                "link": link.map(|l| json!({ "auto": l.auto, "device_ids": l.device_ids, "check_ids": l.check_ids })),
                "last_report": last.iter().find(|x| x.subject == s.name),
                "last_ok": last_ok.iter().find(|x| x.0 == s.name).map(|x| x.1),
            })
        })
        .collect();
    let pauses: Vec<PauseRow> = sqlx::query_as(
        "SELECT id, integration_id, subjects, reason, device_ids, check_ids, started_at, until, ended_at, until > now() AS active
           FROM integration_pauses WHERE integration_id = $1 ORDER BY started_at DESC LIMIT 15",
    )
    .bind(r.id)
    .fetch_all(&st.db)
    .await?;
    let reports: Vec<ReportRow> = sqlx::query_as(
        "SELECT id, integration_id, time, kind, subject, status, message, duration_s, size_bytes
           FROM integration_reports WHERE integration_id = $1 ORDER BY time DESC LIMIT 30",
    )
    .bind(r.id)
    .fetch_all(&st.db)
    .await?;
    Ok(json!({
        "id": r.id, "name": r.name, "kind": r.kind, "token_hint": r.token_hint, "host_device_id": r.host_device_id,
        "enabled": r.enabled, "inventory_at": r.inventory_at, "last_seen_at": r.last_seen_at, "last_ip": r.last_ip,
        "version": r.version, "created_at": r.created_at, "subjects": subjects, "pauses": pauses, "reports": reports,
    }))
}

const ROW_SELECT: &str = "SELECT id, name, kind, token_hint, host_device_id, enabled, inventory, inventory_at, last_seen_at, last_ip,
                                 version, created_at FROM integrations";

pub async fn list(State(st): State<AppState>, Need(_user, _): Need<perm::SettingsManage>) -> ApiResult<Json<Value>> {
    let rows: Vec<Row> = sqlx::query_as(&format!("{ROW_SELECT} ORDER BY name")).fetch_all(&st.db).await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(integration_json(&st, r).await?);
    }
    Ok(Json(json!(out)))
}

#[derive(Deserialize, Serialize)]
pub struct CreateInput {
    name: String,
    kind: Option<String>,
    host_device_id: Option<i64>,
}

/// Neues Programm verbinden – der Schlüssel wird nur in dieser Antwort gezeigt
pub async fn create(State(st): State<AppState>, Need(user, _): Need<perm::SettingsManage>, Json(req): Json<CreateInput>) -> ApiResult<Json<Value>> {
    let name: String = req.name.trim().chars().take(100).collect();
    if name.is_empty() {
        return Err(ApiError::BadRequest("Bitte einen Namen angeben".into()));
    }
    let kind = req.kind.as_deref().unwrap_or("generic");
    if !KINDS.contains(&kind) {
        return Err(ApiError::BadRequest("Unbekannte Art".into()));
    }
    let (token, hash, hint) = integration::new_token();
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO integrations (name, kind, token_hash, token_hint, host_device_id) VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&name)
    .bind(kind)
    .bind(hash)
    .bind(&hint)
    .bind(req.host_device_id)
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "integration_add", json!({ "id": id, "name": name, "kind": kind })).await;
    Ok(Json(json!({ "id": id, "token": token, "token_hint": hint })))
}

/// Ändern: name, enabled, host_device_id (null = keiner)
pub async fn update(
    State(st): State<AppState>,
    Need(user, _): Need<perm::SettingsManage>,
    Path(id): Path<i64>,
    Json(req): Json<Value>,
) -> ApiResult<Json<Value>> {
    let name = req["name"].as_str().map(|n| n.trim().chars().take(100).collect::<String>()).filter(|n| !n.is_empty());
    let set_host = req.get("host_device_id").is_some();
    let done = sqlx::query(
        "UPDATE integrations SET name = COALESCE($2, name), enabled = COALESCE($3, enabled),
                host_device_id = CASE WHEN $4 THEN $5 ELSE host_device_id END
          WHERE id = $1",
    )
    .bind(id)
    .bind(name)
    .bind(req["enabled"].as_bool())
    .bind(set_host)
    .bind(req["host_device_id"].as_i64())
    .execute(&st.db)
    .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "integration_update", json!({ "id": id, "change": req })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Neuen Schlüssel erzeugen (der alte wird sofort ungültig)
pub async fn new_token(State(st): State<AppState>, Need(user, _): Need<perm::SettingsManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let (token, hash, hint) = integration::new_token();
    let done = sqlx::query("UPDATE integrations SET token_hash = $2, token_hint = $3 WHERE id = $1")
        .bind(id)
        .bind(hash)
        .bind(&hint)
        .execute(&st.db)
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "integration_token", json!({ "id": id })).await;
    Ok(Json(json!({ "token": token, "token_hint": hint })))
}

pub async fn remove(State(st): State<AppState>, Need(user, _): Need<perm::SettingsManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let (name,): (String,) = sqlx::query_as("DELETE FROM integrations WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "integration_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize, Serialize)]
pub struct LinkInput {
    subject: String,
    #[serde(default)]
    device_ids: Vec<i64>,
    #[serde(default)]
    check_ids: Vec<i64>,
    auto: Option<bool>,
}

/// Zuordnung eines Containers von Hand festlegen (leer + auto = wieder nur automatisch)
pub async fn set_link(
    State(st): State<AppState>,
    Need(user, _): Need<perm::SettingsManage>,
    Path(id): Path<i64>,
    Json(req): Json<LinkInput>,
) -> ApiResult<Json<Value>> {
    let subject: String = req.subject.trim().chars().take(200).collect();
    if subject.is_empty() {
        return Err(ApiError::BadRequest("Container fehlt".into()));
    }
    let auto = req.auto.unwrap_or(true);
    if auto && req.device_ids.is_empty() && req.check_ids.is_empty() {
        sqlx::query("DELETE FROM integration_links WHERE integration_id = $1 AND subject = $2")
            .bind(id)
            .bind(&subject)
            .execute(&st.db)
            .await?;
    } else {
        sqlx::query(
            "INSERT INTO integration_links (integration_id, subject, device_ids, check_ids, auto) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (integration_id, subject) DO UPDATE SET device_ids = $3, check_ids = $4, auto = $5",
        )
        .bind(id)
        .bind(&subject)
        .bind(&req.device_ids)
        .bind(&req.check_ids)
        .bind(auto)
        .execute(&st.db)
        .await?;
    }
    audit::by(&st.db, &user, "integration_link", json!({ "id": id, "link": req })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Pause von Hand sofort beenden
pub async fn stop_pause(State(st): State<AppState>, Need(user, _): Need<perm::SettingsManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let done = sqlx::query("UPDATE integration_pauses SET until = now(), ended_at = COALESCE(ended_at, now()) WHERE id = $1 AND until > now()")
        .bind(id)
        .execute(&st.db)
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "pause_end", json!({ "id": id })).await;
    st.hub.publish(&json!({ "type": "pause", "id": id, "active": false }));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, FromRow)]
pub struct ActivePause {
    id: i64,
    source: String,
    subjects: Vec<String>,
    reason: String,
    until: DateTime<Utc>,
    /// Programm hat „fertig“ gemeldet – läuft nur noch die Nachlaufzeit
    finishing: bool,
    devices: i32,
    checks: i32,
}

/// Aktive Pausen (für Hinweise in Dashboard, Geräten und Diensten)
pub async fn active_pauses(State(st): State<AppState>, _user: Need<perm::View>) -> ApiResult<Json<Vec<ActivePause>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT p.id, COALESCE(i.name, '–') AS source, p.subjects, p.reason, p.until, p.ended_at IS NOT NULL AS finishing,
                    cardinality(p.device_ids) AS devices, cardinality(p.check_ids) AS checks
               FROM integration_pauses p LEFT JOIN integrations i ON i.id = p.integration_id
              WHERE p.until > now() ORDER BY p.started_at",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}
