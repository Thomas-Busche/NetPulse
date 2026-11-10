//! Benutzer, Gruppen, Rollen und API-Schlüssel.
//!
//! Änderungen an Benutzern, Gruppen und Rollen sind kritisch: Sie verlangen eine kurz zuvor erneut
//! bestätigte Anmeldung (`/api/me/reauth`). Es bleibt immer mindestens ein aktiver Administrator übrig.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool, Postgres, Transaction};

use crate::{
    audit,
    auth::{self, perm, CurrentUser, Need},
    error::{ApiError, ApiResult},
    AppState,
};

// ---------------------------------------------------------------------------
// Gemeinsam
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Assignment {
    role_id: i64,
    /// `None` = alle Sektoren
    #[serde(default)]
    site_id: Option<i64>,
}

fn valid_username(name: &str) -> bool {
    (3..=64).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
}

fn clean(text: Option<&str>, max: usize) -> Option<String> {
    text.map(str::trim).filter(|t| !t.is_empty()).map(|t| t.chars().take(max).collect())
}

/// Aktive Administratoren (Rolle mit allen Rechten für alle Sektoren – direkt oder über eine Gruppe)
async fn admin_count(tx: &mut Transaction<'_, Postgres>) -> sqlx::Result<i64> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(DISTINCT u.id) FROM users u
          WHERE NOT u.disabled AND EXISTS (
              SELECT 1 FROM role_assignments ra JOIN roles r ON r.id = ra.role_id
               WHERE r.all_permissions AND ra.site_id IS NULL
                 AND (ra.user_id = u.id OR ra.group_id IN (SELECT group_id FROM group_members WHERE user_id = u.id)))",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(n)
}

async fn ensure_admin_left(tx: &mut Transaction<'_, Postgres>) -> ApiResult<()> {
    if admin_count(tx).await? == 0 {
        return Err(ApiError::BadRequest("Es muss mindestens ein aktiver Administrator (alle Rechte, alle Sektoren) bleiben".into()));
    }
    Ok(())
}

async fn set_assignments(tx: &mut Transaction<'_, Postgres>, column: &str, owner: i64, list: &[Assignment]) -> ApiResult<()> {
    // Spaltenname stammt aus dem Code („user_id“/„group_id“), nicht aus der Anfrage
    sqlx::query(&format!("DELETE FROM role_assignments WHERE {column} = $1")).bind(owner).execute(&mut **tx).await?;
    for a in list {
        let inserted = sqlx::query(&format!(
            "INSERT INTO role_assignments (role_id, {column}, site_id)
             SELECT r.id, $2, $3 FROM roles r WHERE r.id = $1 AND ($3::bigint IS NULL OR EXISTS (SELECT 1 FROM sites WHERE id = $3))
             ON CONFLICT DO NOTHING"
        ))
        .bind(a.role_id)
        .bind(owner)
        .bind(a.site_id)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() == 0 {
            // Doppelte Einträge sind egal, unbekannte Rollen/Sektoren nicht
            let (exists,): (bool,) = sqlx::query_as(&format!(
                "SELECT EXISTS (SELECT 1 FROM role_assignments WHERE role_id = $1 AND {column} = $2 AND site_id IS NOT DISTINCT FROM $3)"
            ))
            .bind(a.role_id)
            .bind(owner)
            .bind(a.site_id)
            .fetch_one(&mut **tx)
            .await?;
            if !exists {
                return Err(ApiError::BadRequest("Unbekannte Rolle oder unbekannter Sektor".into()));
            }
        }
    }
    Ok(())
}

async fn assignments_of(db: &PgPool, column: &str, owner: i64) -> sqlx::Result<Value> {
    let rows: Vec<(i64, String, Option<i64>, Option<String>)> = sqlx::query_as(&format!(
        "SELECT ra.role_id, r.name, ra.site_id, s.name FROM role_assignments ra JOIN roles r ON r.id = ra.role_id
           LEFT JOIN sites s ON s.id = ra.site_id WHERE ra.{column} = $1 ORDER BY r.name, s.name NULLS FIRST"
    ))
    .bind(owner)
    .fetch_all(db)
    .await?;
    Ok(json!(rows
        .into_iter()
        .map(|(role_id, role, site_id, site)| json!({ "role_id": role_id, "role": role, "site_id": site_id, "site": site }))
        .collect::<Vec<_>>()))
}

// ---------------------------------------------------------------------------
// Benutzer
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
struct UserRow {
    id: i64,
    username: String,
    display_name: Option<String>,
    email: Option<String>,
    disabled: bool,
    auth_source: String,
    created_at: DateTime<Utc>,
    last_login: Option<DateTime<Utc>>,
    totp_enabled: bool,
    group_ids: Vec<i64>,
}

const USER_SELECT: &str = "SELECT u.id, u.username, u.display_name, u.email, u.disabled, u.auth_source, u.created_at,
                                  u.last_login, u.totp_enabled,
                                  COALESCE((SELECT array_agg(group_id ORDER BY group_id) FROM group_members WHERE user_id = u.id), '{}') AS group_ids
                             FROM users u";

async fn user_json(db: &PgPool, id: i64) -> ApiResult<Value> {
    let user = sqlx::query_as::<_, UserRow>(&format!("{USER_SELECT} WHERE u.id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut v = json!(user);
    v["assignments"] = assignments_of(db, "user_id", id).await?;
    let (perms, roles) = auth::load_perms(db, id).await?;
    v["roles"] = json!(roles);
    v["is_admin"] = json!(auth::PERMISSIONS.iter().all(|(p, _, _)| perms.can(p)));
    Ok(v)
}

pub async fn list_users(State(st): State<AppState>, _admin: Need<perm::UsersManage>) -> ApiResult<Json<Vec<Value>>> {
    let ids: Vec<(i64,)> = sqlx::query_as("SELECT id FROM users ORDER BY username").fetch_all(&st.db).await?;
    let mut out = Vec::with_capacity(ids.len());
    for (id,) in ids {
        out.push(user_json(&st.db, id).await?);
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct NewUser {
    username: String,
    #[serde(default)]
    password: String,
    /// Konto für die zentrale Anmeldung (OIDC) – ohne eigenes Passwort
    #[serde(default)]
    sso: bool,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    /// Alte Oberfläche/Skripte: „admin“ oder „viewer“
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    assignments: Vec<Assignment>,
    #[serde(default)]
    group_ids: Vec<i64>,
}

async fn legacy_role(db: &PgPool, role: Option<&str>) -> ApiResult<Vec<Assignment>> {
    let name = match role {
        None => return Ok(vec![]),
        Some("admin") => "Administrator",
        Some("viewer") => "Nur lesen",
        Some(_) => return Err(ApiError::BadRequest("Rolle muss 'admin' oder 'viewer' sein".into())),
    };
    let (id,): (i64,) = sqlx::query_as("SELECT id FROM roles WHERE name = $1").bind(name).fetch_one(db).await?;
    Ok(vec![Assignment { role_id: id, site_id: None }])
}

fn validate_email(email: &Option<String>) -> ApiResult<()> {
    if email.as_deref().is_some_and(|e| e.len() > 200 || !e.contains('@') || e.contains(char::is_whitespace)) {
        return Err(ApiError::BadRequest("E-Mail-Adresse ist ungültig".into()));
    }
    Ok(())
}

async fn set_groups(tx: &mut Transaction<'_, Postgres>, user_id: i64, groups: &[i64]) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM group_members WHERE user_id = $1").bind(user_id).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO group_members (group_id, user_id) SELECT g.id, $1 FROM user_groups g WHERE g.id = ANY($2)")
        .bind(user_id)
        .bind(groups)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn add_user(State(st): State<AppState>, Need(admin, _): Need<perm::UsersManage>, Json(req): Json<NewUser>) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    let username = req.username.trim().to_lowercase();
    if !valid_username(&username) {
        return Err(ApiError::BadRequest(
            "Benutzername: 3–64 Zeichen, erlaubt sind a–z, 0–9, Punkt, Minus, Unterstrich und @".into(),
        ));
    }
    if !req.sso {
        auth::validate_password(&req.password).map_err(ApiError::BadRequest)?;
    }
    let email = clean(req.email.as_deref(), 200);
    validate_email(&email)?;
    let mut assignments = req.assignments.clone();
    assignments.extend(legacy_role(&st.db, req.role.as_deref()).await?);

    // SSO-Konten bekommen keinen gültigen Passwort-Hash; die Anmeldung läuft nur über den Anmeldedienst
    let hash = if req.sso { "!sso".to_string() } else { auth::hash_password(req.password).await? };
    let mut tx = st.db.begin().await?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO users (username, password_hash, display_name, email, auth_source) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (username) DO NOTHING RETURNING id",
    )
    .bind(&username)
    .bind(hash)
    .bind(clean(req.display_name.as_deref(), 100))
    .bind(&email)
    .bind(if req.sso { "oidc" } else { "local" })
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::BadRequest(format!("Benutzer '{username}' existiert bereits")))?;
    set_assignments(&mut tx, "user_id", id, &assignments).await?;
    set_groups(&mut tx, id, &req.group_ids).await?;
    tx.commit().await?;

    audit::by(&st.db, &admin, "user_add", json!({ "username": username, "assignments": assignments, "group_ids": req.group_ids })).await;
    Ok(Json(user_json(&st.db, id).await?))
}

#[derive(Deserialize)]
pub struct UserUpdate {
    display_name: Option<String>,
    email: Option<String>,
    disabled: Option<bool>,
    assignments: Option<Vec<Assignment>>,
    group_ids: Option<Vec<i64>>,
}

pub async fn update_user(
    State(st): State<AppState>,
    Need(admin, _): Need<perm::UsersManage>,
    Path(id): Path<i64>,
    Json(req): Json<UserUpdate>,
) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    if id == admin.id && req.disabled == Some(true) {
        return Err(ApiError::BadRequest("Das eigene Konto kann nicht gesperrt werden".into()));
    }
    let email = req.email.as_deref().map(|e| clean(Some(e), 200));
    if let Some(e) = &email {
        validate_email(e)?;
    }
    let mut tx = st.db.begin().await?;
    let done = sqlx::query(
        "UPDATE users SET
             display_name = CASE WHEN $2::text IS NULL THEN display_name ELSE NULLIF(trim($2), '') END,
             email        = CASE WHEN $3 THEN $4 ELSE email END,
             disabled     = COALESCE($5, disabled)
          WHERE id = $1",
    )
    .bind(id)
    .bind(req.display_name.as_deref().map(|d| d.chars().take(100).collect::<String>()))
    .bind(email.is_some())
    .bind(email.flatten())
    .bind(req.disabled)
    .execute(&mut *tx)
    .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    if let Some(list) = &req.assignments {
        set_assignments(&mut tx, "user_id", id, list).await?;
    }
    if let Some(groups) = &req.group_ids {
        set_groups(&mut tx, id, groups).await?;
    }
    ensure_admin_left(&mut tx).await?;
    if req.disabled == Some(true) {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    audit::by(
        &st.db,
        &admin,
        "user_update",
        json!({ "user_id": id, "disabled": req.disabled, "assignments": req.assignments, "group_ids": req.group_ids }),
    )
    .await;
    Ok(Json(user_json(&st.db, id).await?))
}

pub async fn delete_user(State(st): State<AppState>, Need(admin, _): Need<perm::UsersManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    if id == admin.id {
        return Err(ApiError::BadRequest("Das eigene Konto kann nicht gelöscht werden".into()));
    }
    let mut tx = st.db.begin().await?;
    let (username,): (String,) = sqlx::query_as("DELETE FROM users WHERE id = $1 RETURNING username")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    ensure_admin_left(&mut tx).await?;
    tx.commit().await?;
    audit::by(&st.db, &admin, "user_delete", json!({ "username": username })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct PasswordReset {
    password: String,
}

/// Neues Passwort für einen anderen Benutzer (z. B. vergessen); alle seine Sitzungen werden beendet
pub async fn reset_user_password(
    State(st): State<AppState>,
    Need(admin, _): Need<perm::UsersManage>,
    Path(id): Path<i64>,
    Json(req): Json<PasswordReset>,
) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    if id == admin.id {
        return Err(ApiError::BadRequest("Das eigene Passwort bitte unter „Mein Konto“ ändern".into()));
    }
    auth::validate_password(&req.password).map_err(ApiError::BadRequest)?;
    let hash = auth::hash_password(req.password).await?;
    let target: Option<(String,)> =
        sqlx::query_as("UPDATE users SET password_hash = $2 WHERE id = $1 AND auth_source = 'local' RETURNING username")
            .bind(id)
            .bind(hash)
            .fetch_optional(&st.db)
            .await?;
    let (username,) = target.ok_or(ApiError::NotFound)?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&st.db).await?;
    audit::by(&st.db, &admin, "password_reset", json!({ "username": username })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Zwei-Faktor-Anmeldung eines Benutzers zurücksetzen (z. B. Handy verloren)
pub async fn reset_totp(State(st): State<AppState>, Need(admin, _): Need<perm::UsersManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    let target: Option<(String,)> = sqlx::query_as(
        "UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_last_step = NULL WHERE id = $1 RETURNING username",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let (username,) = target.ok_or(ApiError::NotFound)?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&st.db).await?;
    audit::by(&st.db, &admin, "totp_reset", json!({ "username": username })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Alle Sitzungen eines Benutzers beenden (z. B. Handy verloren)
pub async fn end_user_sessions(State(st): State<AppState>, Need(admin, _): Need<perm::UsersManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let done = sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&st.db).await?;
    audit::by(&st.db, &admin, "sessions_revoked", json!({ "user_id": id, "count": done.rows_affected() })).await;
    Ok(Json(json!({ "ended": done.rows_affected() })))
}

// ---------------------------------------------------------------------------
// Rollen
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
struct RoleRow {
    id: i64,
    name: String,
    description: String,
    permissions: Vec<String>,
    all_permissions: bool,
    builtin: bool,
    used: i64,
}

pub async fn permissions(_user: CurrentUser) -> Json<Value> {
    Json(json!(auth::PERMISSIONS
        .iter()
        .map(|(name, label, site)| json!({ "name": name, "label": label, "per_site": site }))
        .collect::<Vec<_>>()))
}

pub async fn list_roles(State(st): State<AppState>, _user: Need<perm::UsersManage>) -> ApiResult<Json<Value>> {
    let rows: Vec<RoleRow> = sqlx::query_as(
        "SELECT r.id, r.name, r.description, r.permissions, r.all_permissions, r.builtin,
                (SELECT count(*) FROM role_assignments a WHERE a.role_id = r.id) AS used
           FROM roles r ORDER BY r.all_permissions DESC, r.builtin DESC, r.name",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!(rows)))
}

#[derive(Deserialize)]
pub struct RoleInput {
    name: String,
    #[serde(default)]
    description: String,
    permissions: Vec<String>,
}

fn validate_role(r: &RoleInput) -> ApiResult<Vec<String>> {
    if r.name.trim().is_empty() || r.name.chars().count() > 60 {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 60 Zeichen) angeben".into()));
    }
    if let Some(bad) = r.permissions.iter().find(|p| !auth::is_permission(p)) {
        return Err(ApiError::BadRequest(format!("Unbekanntes Recht: {bad}")));
    }
    let mut list = r.permissions.clone();
    list.sort();
    list.dedup();
    Ok(list)
}

fn unique_name(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::BadRequest("Dieser Name ist schon vergeben".into()),
        _ => e.into(),
    }
}

pub async fn create_role(State(st): State<AppState>, Need(admin, _): Need<perm::UsersManage>, Json(r): Json<RoleInput>) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    let list = validate_role(&r)?;
    let (id,): (i64,) = sqlx::query_as("INSERT INTO roles (name, description, permissions) VALUES ($1, $2, $3) RETURNING id")
        .bind(r.name.trim())
        .bind(r.description.trim())
        .bind(&list)
        .fetch_one(&st.db)
        .await
        .map_err(unique_name)?;
    audit::by(&st.db, &admin, "role_add", json!({ "role_id": id, "name": r.name, "permissions": list })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_role(
    State(st): State<AppState>,
    Need(admin, _): Need<perm::UsersManage>,
    Path(id): Path<i64>,
    Json(r): Json<RoleInput>,
) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    let list = validate_role(&r)?;
    let mut tx = st.db.begin().await?;
    let done = sqlx::query("UPDATE roles SET name = $2, description = $3, permissions = $4 WHERE id = $1 AND NOT all_permissions")
        .bind(id)
        .bind(r.name.trim())
        .bind(r.description.trim())
        .bind(&list)
        .execute(&mut *tx)
        .await
        .map_err(unique_name)?;
    if done.rows_affected() == 0 {
        return Err(ApiError::BadRequest("Die Rolle „Administrator“ hat immer alle Rechte und kann nicht geändert werden".into()));
    }
    ensure_admin_left(&mut tx).await?;
    tx.commit().await?;
    audit::by(&st.db, &admin, "role_update", json!({ "role_id": id, "name": r.name, "permissions": list })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_role(State(st): State<AppState>, Need(admin, _): Need<perm::UsersManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    let mut tx = st.db.begin().await?;
    let row: Option<(String,)> = sqlx::query_as("DELETE FROM roles WHERE id = $1 AND NOT builtin RETURNING name")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let (name,) = row.ok_or_else(|| ApiError::BadRequest("Mitgelieferte Rollen können nicht gelöscht werden".into()))?;
    ensure_admin_left(&mut tx).await?;
    tx.commit().await?;
    audit::by(&st.db, &admin, "role_delete", json!({ "role_id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Gruppen
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
struct GroupRow {
    id: i64,
    name: String,
    description: String,
    oidc_group: Option<String>,
    member_ids: Vec<i64>,
}

pub async fn list_groups(State(st): State<AppState>, _user: CurrentUser) -> ApiResult<Json<Vec<Value>>> {
    // Namen der Gruppen braucht auch die Alarm-Verwaltung (Benachrichtigung an Gruppen)
    let rows: Vec<GroupRow> = sqlx::query_as(
        "SELECT g.id, g.name, g.description, g.oidc_group,
                COALESCE((SELECT array_agg(user_id ORDER BY user_id) FROM group_members WHERE group_id = g.id), '{}') AS member_ids
           FROM user_groups g ORDER BY g.name",
    )
    .fetch_all(&st.db)
    .await?;
    let mut out = Vec::new();
    for g in rows {
        let id = g.id;
        let mut v = json!(g);
        v["assignments"] = assignments_of(&st.db, "group_id", id).await?;
        out.push(v);
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct GroupInput {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    oidc_group: Option<String>,
    #[serde(default)]
    member_ids: Vec<i64>,
    #[serde(default)]
    assignments: Vec<Assignment>,
}

async fn save_group(tx: &mut Transaction<'_, Postgres>, id: i64, g: &GroupInput) -> ApiResult<()> {
    sqlx::query("DELETE FROM group_members WHERE group_id = $1").bind(id).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO group_members (group_id, user_id) SELECT $1, u.id FROM users u WHERE u.id = ANY($2)")
        .bind(id)
        .bind(&g.member_ids)
        .execute(&mut **tx)
        .await?;
    set_assignments(tx, "group_id", id, &g.assignments).await
}

pub async fn create_group(State(st): State<AppState>, Need(admin, _): Need<perm::UsersManage>, Json(g): Json<GroupInput>) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    if g.name.trim().is_empty() || g.name.chars().count() > 60 {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 60 Zeichen) angeben".into()));
    }
    let mut tx = st.db.begin().await?;
    let (id,): (i64,) = sqlx::query_as("INSERT INTO user_groups (name, description, oidc_group) VALUES ($1, $2, $3) RETURNING id")
        .bind(g.name.trim())
        .bind(g.description.trim())
        .bind(clean(g.oidc_group.as_deref(), 200))
        .fetch_one(&mut *tx)
        .await
        .map_err(unique_name)?;
    save_group(&mut tx, id, &g).await?;
    tx.commit().await?;
    audit::by(&st.db, &admin, "group_add", json!({ "group_id": id, "name": g.name, "members": g.member_ids, "assignments": g.assignments })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_group(
    State(st): State<AppState>,
    Need(admin, _): Need<perm::UsersManage>,
    Path(id): Path<i64>,
    Json(g): Json<GroupInput>,
) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    if g.name.trim().is_empty() || g.name.chars().count() > 60 {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 60 Zeichen) angeben".into()));
    }
    let mut tx = st.db.begin().await?;
    let done = sqlx::query("UPDATE user_groups SET name = $2, description = $3, oidc_group = $4 WHERE id = $1")
        .bind(id)
        .bind(g.name.trim())
        .bind(g.description.trim())
        .bind(clean(g.oidc_group.as_deref(), 200))
        .execute(&mut *tx)
        .await
        .map_err(unique_name)?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    save_group(&mut tx, id, &g).await?;
    ensure_admin_left(&mut tx).await?;
    tx.commit().await?;
    audit::by(&st.db, &admin, "group_update", json!({ "group_id": id, "name": g.name, "members": g.member_ids, "assignments": g.assignments })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_group(State(st): State<AppState>, Need(admin, _): Need<perm::UsersManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    let mut tx = st.db.begin().await?;
    let (name,): (String,) = sqlx::query_as("DELETE FROM user_groups WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    ensure_admin_left(&mut tx).await?;
    tx.commit().await?;
    audit::by(&st.db, &admin, "group_delete", json!({ "group_id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// API-Schlüssel (eigene) und Leitstand-Anmeldung
// ---------------------------------------------------------------------------

type TokenRow = (i64, String, DateTime<Utc>, Option<DateTime<Utc>>, Option<DateTime<Utc>>);

pub async fn list_tokens(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let rows: Vec<TokenRow> = sqlx::query_as(
        "SELECT id, name, created_at, expires_at, last_used FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user.id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|(id, name, created, expires, used)| json!({ "id": id, "name": name, "created_at": created, "expires_at": expires, "last_used": used }))
        .collect::<Vec<_>>())))
}

#[derive(Deserialize)]
pub struct NewToken {
    name: String,
    /// Gültigkeit in Tagen (leer = unbegrenzt)
    #[serde(default)]
    days: Option<i32>,
}

pub async fn create_token(State(st): State<AppState>, user: CurrentUser, Json(req): Json<NewToken>) -> ApiResult<Json<Value>> {
    user.require_recent_auth(&st.db).await?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 60 {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 60 Zeichen) angeben".into()));
    }
    if req.days.is_some_and(|d| !(1..=3650).contains(&d)) {
        return Err(ApiError::BadRequest("Gültigkeit: 1 bis 3650 Tage".into()));
    }
    let token = format!("np_{}", auth::random_token(24));
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO api_tokens (user_id, name, token_hash, expires_at)
         VALUES ($1, $2, $3, CASE WHEN $4::int IS NULL THEN NULL ELSE now() + make_interval(days => $4) END) RETURNING id",
    )
    .bind(user.id)
    .bind(name)
    .bind(auth::token_hash(&token))
    .bind(req.days)
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "api_token_add", json!({ "token_id": id, "name": name, "days": req.days })).await;
    // Der Schlüssel wird nur dieses eine Mal angezeigt
    Ok(Json(json!({ "id": id, "token": token })))
}

pub async fn delete_token(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let done = sqlx::query("DELETE FROM api_tokens WHERE id = $1 AND user_id = $2").bind(id).bind(user.id).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "api_token_delete", json!({ "token_id": id })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct KioskLogin {
    token: String,
}

/// Leitstand-Bildschirm: API-Schlüssel gegen eine 30-Tage-Sitzung tauschen (ohne Passwort am Bildschirm).
/// Diese Sitzung kann nichts Kritisches tun (keine Benutzer, Zugangsdaten, Sicherungen).
pub async fn kiosk_login(State(st): State<AppState>, headers: HeaderMap, Json(req): Json<KioskLogin>) -> ApiResult<Response> {
    let ip = auth::client_ip(&headers).unwrap_or_else(|| "unbekannt".into());
    if !st.login_limiter.try_attempt("kiosk", &ip).await {
        return Err(ApiError::TooManyRequests);
    }
    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT u.id, u.username FROM api_tokens t JOIN users u ON u.id = t.user_id
          WHERE t.token_hash = $1 AND NOT u.disabled AND (t.expires_at IS NULL OR t.expires_at > now())",
    )
    .bind(auth::token_hash(req.token.trim()))
    .fetch_optional(&st.db)
    .await?;
    let Some((user_id, username)) = row else {
        audit::log(&st.db, None, Some("kiosk"), "login_failed", json!({ "ip": ip, "kiosk": true })).await;
        return Err(ApiError::InvalidCredentials);
    };
    st.login_limiter.success("kiosk", &ip).await;
    let hours = 24 * 30;
    let token = auth::create_session_with(&st.db, user_id, hours, &headers, true).await?;
    sqlx::query("UPDATE api_tokens SET last_used = now() WHERE token_hash = $1").bind(auth::token_hash(req.token.trim())).execute(&st.db).await?;
    audit::log(&st.db, Some(user_id), Some(&username), "login", json!({ "ip": ip, "kiosk": true })).await;
    let cookie = auth::session_cookie(&token, i64::from(hours) * 3600, st.config.cookie_secure);
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}
