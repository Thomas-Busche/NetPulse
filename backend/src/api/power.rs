//! Ein/Aus: Aufwecken und Herunterfahren je Gerät, Gerätegruppen und Zeitpläne (`crate::power`).

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{NaiveTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{perm, CurrentUser, Need},
    error::{ApiError, ApiResult},
    power::{self, Action, PowerConfig, Schedule},
    AppState,
};

fn action(name: &str) -> ApiResult<Action> {
    Action::parse(name).ok_or(ApiError::NotFound)
}

// ---------------------------------------------------------------------------
// Einzelnes Gerät
// ---------------------------------------------------------------------------

/// Einstellungen + was NetPulse dazu weiß (MAC, Broadcast-Ziele, SSH-Zugang, Gruppen)
pub async fn get_device(State(st): State<AppState>, user: Need<perm::View>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    user.require_device(&st.db, "view", id).await?;
    let (ip, mac, os, power): (String, Option<String>, Option<String>, Value) =
        sqlx::query_as("SELECT host(ip), mac, COALESCE(inventory->'ssh'->>'os', os), power FROM devices WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    let cfg: PowerConfig = serde_json::from_value(power).unwrap_or_default();
    let targets = power::wol_targets(&st.db, &ip, &cfg).await;
    let ssh: Vec<(i64, String)> = sqlx::query_as(
        "SELECT c.id, c.name FROM credentials c JOIN device_credentials dc ON dc.credential_id = c.id
          WHERE dc.device_id = $1 AND c.kind LIKE 'ssh%' ORDER BY c.id",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let groups: Vec<(i64, String)> = sqlx::query_as(
        "SELECT g.id, g.name FROM device_groups g JOIN device_group_members m ON m.group_id = g.id WHERE m.device_id = $1 ORDER BY g.name",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({
        "config": cfg,
        "mac": mac,
        "os": os,
        "wol_targets": targets.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
        "ssh_credentials": ssh.into_iter().map(|(id, name)| json!({ "id": id, "name": name })).collect::<Vec<_>>(),
        "groups": groups.into_iter().map(|(id, name)| json!({ "id": id, "name": name })).collect::<Vec<_>>(),
    })))
}

pub async fn put_device(
    State(st): State<AppState>,
    Need(user, _): Need<perm::DevicesManage>,
    Path(id): Path<i64>,
    Json(cfg): Json<PowerConfig>,
) -> ApiResult<Json<Value>> {
    user.require_device(&st.db, "devices.manage", id).await?;
    let cfg = cfg.validate().map_err(ApiError::BadRequest)?;
    // Eine fremde Zugangsangabe auszuwählen schickt deren Passwort an dieses Gerät –
    // deshalb nur mit dem Recht, Zugangsdaten zu verwalten (wie beim Zuordnen)
    let (old,): (Value,) = sqlx::query_as("SELECT power FROM devices WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let old: PowerConfig = serde_json::from_value(old).unwrap_or_default();
    for (new, before, kinds) in [
        (cfg.ssh_credential_id, old.ssh_credential_id, "ssh%"),
        (cfg.http_credential_id, old.http_credential_id, "%"),
    ] {
        if new != before && new.is_some() {
            if !user.can("credentials.manage") {
                return Err(ApiError::BadRequest("Zugangsdaten auswählen darf nur, wer Zugangsdaten verwalten darf".into()));
            }
            let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM credentials WHERE id = $1 AND kind LIKE $2")
                .bind(new)
                .bind(kinds)
                .fetch_optional(&st.db)
                .await?;
            if exists.is_none() {
                return Err(ApiError::BadRequest("Diese Zugangsdaten passen nicht".into()));
            }
        }
    }
    sqlx::query("UPDATE devices SET power = $2 WHERE id = $1").bind(id).bind(json!(cfg)).execute(&st.db).await?;
    audit::by(&st.db, &user, "device_power_settings", json!({ "device_id": id, "wake": cfg.wake_method(), "shutdown": cfg.shutdown_method() })).await;
    Ok(Json(json!({ "ok": true })))
}

/// POST /api/devices/{id}/wake bzw. /shutdown
pub async fn run_device(
    State(st): State<AppState>,
    Need(user, _): Need<perm::DevicesManage>,
    Path((id, name)): Path<(i64, String)>,
) -> ApiResult<Json<Value>> {
    let action = action(&name)?;
    user.require_device(&st.db, "devices.manage", id).await?;
    let outcome = power::execute(&st, id, action, false, &format!("von {}", user.username)).await;
    audit::by(&st.db, &user, &format!("device_{name}"), json!({ "device_id": id, "ok": outcome.ok, "message": outcome.message })).await;
    Ok(Json(json!(outcome)))
}

// ---------------------------------------------------------------------------
// Gruppen
// ---------------------------------------------------------------------------

/// Liegen alle Geräte in Sektoren, für die der Benutzer `perm` hat?
async fn devices_allowed(st: &AppState, user: &CurrentUser, perm: &str, ids: &[i64]) -> ApiResult<bool> {
    let Some(allowed) = user.site_filter(perm) else { return Ok(true) };
    let (outside,): (i64,) = sqlx::query_as("SELECT count(*) FROM devices WHERE id = ANY($1) AND NOT site_id = ANY($2)")
        .bind(ids)
        .bind(&allowed)
        .fetch_one(&st.db)
        .await?;
    Ok(outside == 0)
}

async fn group_members(st: &AppState, group_id: i64) -> ApiResult<Vec<i64>> {
    let rows: Vec<(i64,)> = sqlx::query_as("SELECT device_id FROM device_group_members WHERE group_id = $1")
        .bind(group_id)
        .fetch_all(&st.db)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn list_groups(State(st): State<AppState>, user: Need<perm::View>) -> ApiResult<Json<Value>> {
    let rows: Vec<(i64, String, Option<String>, Vec<i64>)> = sqlx::query_as(
        "SELECT g.id, g.name, g.notes,
                COALESCE(array_agg(m.device_id ORDER BY m.device_id) FILTER (WHERE m.device_id IS NOT NULL), '{}')
           FROM device_groups g LEFT JOIN device_group_members m ON m.group_id = g.id
          GROUP BY g.id ORDER BY g.name",
    )
    .fetch_all(&st.db)
    .await?;
    // Eingeschränkte Benutzer sehen nur Mitglieder aus ihren Sektoren
    let visible: Option<Vec<i64>> = match user.site_filter("view") {
        None => None,
        Some(sites) => Some(
            sqlx::query_as::<_, (i64,)>("SELECT id FROM devices WHERE site_id = ANY($1)")
                .bind(&sites)
                .fetch_all(&st.db)
                .await?
                .into_iter()
                .map(|(id,)| id)
                .collect(),
        ),
    };
    let list: Vec<Value> = rows
        .into_iter()
        .map(|(id, name, notes, members)| {
            let all = members.len();
            let members: Vec<i64> = match &visible {
                None => members,
                Some(v) => members.into_iter().filter(|m| v.contains(m)).collect(),
            };
            json!({ "id": id, "name": name, "notes": notes, "device_ids": members, "hidden_members": all - members.len() })
        })
        .collect();
    Ok(Json(json!(list)))
}

#[derive(Deserialize)]
pub struct GroupInput {
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    device_ids: Vec<i64>,
}

impl GroupInput {
    fn check(&self) -> ApiResult<()> {
        let n = self.name.trim().chars().count();
        if n == 0 || n > 100 {
            return Err(ApiError::BadRequest("Name: 1 bis 100 Zeichen".into()));
        }
        if self.notes.as_deref().is_some_and(|t| t.chars().count() > 2000) {
            return Err(ApiError::BadRequest("Notiz ist zu lang".into()));
        }
        Ok(())
    }
}

fn unique_name(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::BadRequest("Eine Gruppe mit diesem Namen gibt es schon".into()),
        _ => e.into(),
    }
}

async fn save_members(tx: &mut sqlx::PgConnection, group_id: i64, ids: &[i64]) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM device_group_members WHERE group_id = $1").bind(group_id).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO device_group_members (group_id, device_id) SELECT $1, id FROM devices WHERE id = ANY($2) ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(ids)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

pub async fn create_group(
    State(st): State<AppState>,
    Need(user, _): Need<perm::DevicesManage>,
    Json(req): Json<GroupInput>,
) -> ApiResult<Json<Value>> {
    req.check()?;
    if !devices_allowed(&st, &user, "devices.manage", &req.device_ids).await? {
        return Err(ApiError::BadRequest("Nur Geräte aus deinen Sektoren".into()));
    }
    let mut tx = st.db.begin().await?;
    let (id,): (i64,) = sqlx::query_as("INSERT INTO device_groups (name, notes) VALUES ($1, NULLIF(trim($2), '')) RETURNING id")
        .bind(req.name.trim())
        .bind(&req.notes)
        .fetch_one(&mut *tx)
        .await
        .map_err(unique_name)?;
    save_members(&mut tx, id, &req.device_ids).await?;
    tx.commit().await?;
    audit::by(&st.db, &user, "device_group_create", json!({ "id": id, "name": req.name.trim(), "devices": req.device_ids.len() })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_group(
    State(st): State<AppState>,
    Need(user, _): Need<perm::DevicesManage>,
    Path(id): Path<i64>,
    Json(req): Json<GroupInput>,
) -> ApiResult<Json<Value>> {
    req.check()?;
    let current = group_members(&st, id).await?;
    if !devices_allowed(&st, &user, "devices.manage", &current).await? || !devices_allowed(&st, &user, "devices.manage", &req.device_ids).await? {
        return Err(ApiError::BadRequest("Die Gruppe enthält Geräte außerhalb deiner Sektoren".into()));
    }
    let mut tx = st.db.begin().await?;
    let done = sqlx::query("UPDATE device_groups SET name = $2, notes = NULLIF(trim($3), '') WHERE id = $1")
        .bind(id)
        .bind(req.name.trim())
        .bind(&req.notes)
        .execute(&mut *tx)
        .await
        .map_err(unique_name)?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    save_members(&mut tx, id, &req.device_ids).await?;
    tx.commit().await?;
    audit::by(&st.db, &user, "device_group_update", json!({ "id": id, "name": req.name.trim(), "devices": req.device_ids.len() })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_group(State(st): State<AppState>, Need(user, _): Need<perm::DevicesManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let current = group_members(&st, id).await?;
    if !devices_allowed(&st, &user, "devices.manage", &current).await? {
        return Err(ApiError::BadRequest("Die Gruppe enthält Geräte außerhalb deiner Sektoren".into()));
    }
    sqlx::query("DELETE FROM device_groups WHERE id = $1").bind(id).execute(&st.db).await?;
    // Zeitpläne verweisen per ID-Liste – Verweis entfernen
    sqlx::query("UPDATE power_schedules SET group_ids = array_remove(group_ids, $1)").bind(id).execute(&st.db).await?;
    audit::by(&st.db, &user, "device_group_delete", json!({ "id": id })).await;
    Ok(Json(json!({ "ok": true })))
}

/// POST /api/device-groups/{id}/wake bzw. /shutdown – nur Geräte, die der Benutzer verwalten darf
pub async fn run_group(
    State(st): State<AppState>,
    Need(user, _): Need<perm::DevicesManage>,
    Path((id, name)): Path<(i64, String)>,
) -> ApiResult<Json<Value>> {
    let action = action(&name)?;
    let members = group_members(&st, id).await?;
    let allowed: Vec<i64> = match user.site_filter("devices.manage") {
        None => members,
        Some(sites) => sqlx::query_as::<_, (i64,)>("SELECT id FROM devices WHERE id = ANY($1) AND site_id = ANY($2)")
            .bind(&members)
            .bind(&sites)
            .fetch_all(&st.db)
            .await?
            .into_iter()
            .map(|(id,)| id)
            .collect(),
    };
    let outcomes = power::execute_many(&st, allowed, action, false, &format!("Gruppe, von {}", user.username)).await;
    let summary = power::summarize(&outcomes);
    audit::by(&st.db, &user, &format!("device_group_{name}"), json!({ "group_id": id, "result": summary })).await;
    Ok(Json(json!({ "summary": summary, "results": outcomes })))
}

// ---------------------------------------------------------------------------
// Zeitpläne
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ScheduleInput {
    name: String,
    action: String,
    days: Vec<i32>,
    time: String,
    #[serde(default)]
    device_ids: Vec<i64>,
    #[serde(default)]
    group_ids: Vec<i64>,
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}

impl ScheduleInput {
    fn check(&mut self) -> ApiResult<()> {
        let bad = |m: &str| Err(ApiError::BadRequest(m.into()));
        let n = self.name.trim().chars().count();
        if n == 0 || n > 100 {
            return bad("Name: 1 bis 100 Zeichen");
        }
        if Action::parse(&self.action).is_none() {
            return bad("Aktion: Aufwecken oder Herunterfahren");
        }
        self.days.sort_unstable();
        self.days.dedup();
        if self.days.is_empty() || self.days.iter().any(|d| !(1..=7).contains(d)) {
            return bad("Bitte mindestens einen Wochentag wählen");
        }
        self.time = self.time.trim().to_string();
        if NaiveTime::parse_from_str(&self.time, "%H:%M").is_err() {
            return bad("Uhrzeit im Format 22:00");
        }
        if self.device_ids.is_empty() && self.group_ids.is_empty() {
            return bad("Bitte Geräte oder Gruppen wählen");
        }
        Ok(())
    }
}

/// Alle betroffenen Geräte (auch über Gruppen) in erlaubten Sektoren?
async fn schedule_allowed(st: &AppState, user: &CurrentUser, perm: &str, devices: &[i64], groups: &[i64]) -> ApiResult<bool> {
    if user.site_filter(perm).is_none() {
        return Ok(true);
    }
    let ids = power::resolve(&st.db, devices, groups).await?;
    devices_allowed(st, user, perm, &ids).await
}

pub async fn list_schedules(State(st): State<AppState>, user: Need<perm::View>) -> ApiResult<Json<Value>> {
    let rows: Vec<Schedule> = sqlx::query_as(&format!("{} ORDER BY time, name", power::SELECT_SCHEDULES)).fetch_all(&st.db).await?;
    let mut list = Vec::new();
    for s in rows {
        if schedule_allowed(&st, &user, "view", &s.device_ids, &s.group_ids).await? {
            list.push(power::describe(&s));
        }
    }
    Ok(Json(json!({ "schedules": list, "timezone": crate::scanner::schedule::timezone().name() })))
}

pub async fn create_schedule(
    State(st): State<AppState>,
    Need(user, _): Need<perm::DevicesManage>,
    Json(mut req): Json<ScheduleInput>,
) -> ApiResult<Json<Value>> {
    req.check()?;
    if !schedule_allowed(&st, &user, "devices.manage", &req.device_ids, &req.group_ids).await? {
        return Err(ApiError::BadRequest("Nur Geräte aus deinen Sektoren".into()));
    }
    // last_run_at = jetzt: ein gerade vergangener Termin wird nicht sofort nachgeholt
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO power_schedules (name, action, days, time, device_ids, group_ids, enabled, last_run_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now()) RETURNING id",
    )
    .bind(req.name.trim())
    .bind(&req.action)
    .bind(&req.days)
    .bind(&req.time)
    .bind(&req.device_ids)
    .bind(&req.group_ids)
    .bind(req.enabled)
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "power_schedule_create", json!({ "id": id, "name": req.name.trim(), "action": req.action, "time": req.time })).await;
    Ok(Json(json!({ "id": id })))
}

async fn load_schedule(st: &AppState, id: i64) -> ApiResult<Schedule> {
    sqlx::query_as(&format!("{} WHERE id = $1", power::SELECT_SCHEDULES))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)
}

pub async fn update_schedule(
    State(st): State<AppState>,
    Need(user, _): Need<perm::DevicesManage>,
    Path(id): Path<i64>,
    Json(mut req): Json<ScheduleInput>,
) -> ApiResult<Json<Value>> {
    req.check()?;
    let old = load_schedule(&st, id).await?;
    if !schedule_allowed(&st, &user, "devices.manage", &old.device_ids, &old.group_ids).await?
        || !schedule_allowed(&st, &user, "devices.manage", &req.device_ids, &req.group_ids).await?
    {
        return Err(ApiError::BadRequest("Der Zeitplan betrifft Geräte außerhalb deiner Sektoren".into()));
    }
    sqlx::query(
        "UPDATE power_schedules SET name = $2, action = $3, days = $4, time = $5, device_ids = $6, group_ids = $7, enabled = $8,
                last_run_at = CASE WHEN time <> $5 OR days <> $4 OR NOT enabled THEN now() ELSE last_run_at END
          WHERE id = $1",
    )
    .bind(id)
    .bind(req.name.trim())
    .bind(&req.action)
    .bind(&req.days)
    .bind(&req.time)
    .bind(&req.device_ids)
    .bind(&req.group_ids)
    .bind(req.enabled)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "power_schedule_update", json!({ "id": id, "name": req.name.trim(), "action": req.action, "time": req.time })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_schedule(State(st): State<AppState>, Need(user, _): Need<perm::DevicesManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let old = load_schedule(&st, id).await?;
    if !schedule_allowed(&st, &user, "devices.manage", &old.device_ids, &old.group_ids).await? {
        return Err(ApiError::BadRequest("Der Zeitplan betrifft Geräte außerhalb deiner Sektoren".into()));
    }
    sqlx::query("DELETE FROM power_schedules WHERE id = $1").bind(id).execute(&st.db).await?;
    audit::by(&st.db, &user, "power_schedule_delete", json!({ "id": id, "name": old.name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Zeitplan sofort ausführen (zum Ausprobieren); Geräte, die schon an/aus sind, werden übersprungen
pub async fn run_schedule_now(State(st): State<AppState>, Need(user, _): Need<perm::DevicesManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let s = load_schedule(&st, id).await?;
    if !schedule_allowed(&st, &user, "devices.manage", &s.device_ids, &s.group_ids).await? {
        return Err(ApiError::BadRequest("Der Zeitplan betrifft Geräte außerhalb deiner Sektoren".into()));
    }
    let outcomes = power::run_schedule(&st, &s, true).await;
    let summary = power::summarize(&outcomes);
    sqlx::query("UPDATE power_schedules SET last_run_at = $2 WHERE id = $1").bind(id).bind(Utc::now()).execute(&st.db).await?;
    audit::by(&st.db, &user, "power_schedule_run", json!({ "id": id, "result": summary })).await;
    Ok(Json(json!({ "summary": summary, "results": outcomes })))
}
