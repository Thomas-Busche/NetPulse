//! Sicherung herunterladen, einspielen und automatische Sicherungen verwalten (nur Admins).

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    audit, auth,
    auth::{perm, Need},
    backup::{self, Envelope},
    error::{ApiError, ApiResult},
    AppState,
};

const MIN_PASSWORD: usize = 12;

/// Eigenes Konto-Passwort bestätigen – eine Sicherung enthält alle Zugangsdaten im Klartext (verschlüsselt)
async fn confirm_account(st: &AppState, user: &auth::CurrentUser, headers: &HeaderMap, password: &str) -> ApiResult<()> {
    let ip = auth::client_ip(headers).unwrap_or_else(|| "unbekannt".into());
    if !st.login_limiter.try_attempt(&user.username, &ip).await {
        return Err(ApiError::TooManyRequests);
    }
    let (hash,): (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1").bind(user.id).fetch_one(&st.db).await?;
    if !auth::verify_password(password.to_string(), hash).await {
        return Err(ApiError::BadRequest("Dein Konto-Passwort ist falsch".into()));
    }
    st.login_limiter.success(&user.username, &ip).await;
    Ok(())
}

fn check_backup_password(p: &str) -> ApiResult<()> {
    if p.chars().count() < MIN_PASSWORD {
        return Err(ApiError::BadRequest(format!("Das Sicherungs-Passwort braucht mindestens {MIN_PASSWORD} Zeichen")));
    }
    Ok(())
}

fn download(name: &str, body: Vec<u8>) -> Response {
    let mut res = body.into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

#[derive(Deserialize)]
pub struct ExportRequest {
    password: String,
    account_password: String,
}

pub async fn export(
    State(st): State<AppState>,
    Need(user, _): Need<perm::BackupManage>,
    headers: HeaderMap,
    Json(req): Json<ExportRequest>,
) -> ApiResult<Response> {
    check_backup_password(&req.password)?;
    confirm_account(&st, &user, &headers, &req.account_password).await?;
    let payload = backup::export(&st).await?;
    let password = req.password;
    let env = tokio::task::spawn_blocking(move || backup::encrypt(&payload, &password))
        .await
        .map_err(|e| ApiError::Internal(e.into()))??;
    audit::by(&st.db, &user, "backup_export", json!({})).await;
    let name = format!("netpulse-{}.npbackup", chrono::Utc::now().with_timezone(&crate::scanner::schedule::timezone()).format("%Y-%m-%d-%H%M%S"));
    Ok(download(&name, serde_json::to_vec(&env).map_err(|e| ApiError::Internal(e.into()))?))
}

#[derive(Deserialize)]
pub struct RestoreRequest {
    file: Envelope,
    password: String,
    account_password: String,
}

pub async fn restore(
    State(st): State<AppState>,
    Need(user, _): Need<perm::BackupManage>,
    headers: HeaderMap,
    Json(req): Json<RestoreRequest>,
) -> ApiResult<Json<Value>> {
    confirm_account(&st, &user, &headers, &req.account_password).await?;
    let password = req.password;
    let file = req.file;
    let payload = tokio::task::spawn_blocking(move || backup::decrypt(&file, &password))
        .await
        .map_err(|e| ApiError::Internal(e.into()))?
        .map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    let report = backup::restore(&st, &payload)
        .await
        .map_err(|e| ApiError::BadRequest(format!("Wiederherstellung abgebrochen, nichts wurde geändert: {e:#}")))?;
    audit::by(&st.db, &user, "backup_restore", json!({ "created_at": payload["created_at"], "report": report })).await;
    // Geräte gleich neu abfragen
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM devices WHERE monitored").fetch_all(&st.db).await.unwrap_or_default();
    for id in ids {
        let _ = st.poll_tx.send(id);
    }
    Ok(Json(json!({ "ok": true, "created_at": payload["created_at"], "app_version": payload["app_version"], "report": report })))
}

// ---------------------------------------------------------------------------
// Automatische Sicherung
// ---------------------------------------------------------------------------

pub async fn get_auto(State(st): State<AppState>, _admin: Need<perm::BackupManage>) -> ApiResult<Json<Value>> {
    let cfg = backup::load_auto(&st.db).await;
    let files = backup::list_files(&st).await;
    Ok(Json(json!({
        "enabled": cfg.enabled,
        "hour": cfg.hour,
        "keep": cfg.keep,
        "has_password": cfg.password_sealed.is_some(),
        "directory": backup::dir(&st).display().to_string(),
        "files": files.into_iter().map(|(name, size, time)| json!({ "name": name, "size": size, "time": time })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
pub struct AutoRequest {
    enabled: bool,
    hour: u32,
    keep: u32,
    /// neues Passwort (leer = beibehalten)
    password: Option<String>,
}

pub async fn set_auto(State(st): State<AppState>, Need(user, _): Need<perm::BackupManage>, Json(req): Json<AutoRequest>) -> ApiResult<Json<Value>> {
    user.require_recent_auth(&st.db).await?;
    if req.hour > 23 || !(1..=365).contains(&req.keep) {
        return Err(ApiError::BadRequest("Uhrzeit 0–23 und 1–365 Sicherungen".into()));
    }
    let mut cfg = backup::load_auto(&st.db).await;
    if let Some(p) = req.password.as_deref().filter(|p| !p.is_empty()) {
        check_backup_password(p)?;
        cfg.password_sealed = Some(st.vault.seal(&p)?);
    }
    if req.enabled && cfg.password_sealed.is_none() {
        return Err(ApiError::BadRequest("Bitte ein Passwort für die Sicherungen festlegen".into()));
    }
    cfg.enabled = req.enabled;
    cfg.hour = req.hour;
    cfg.keep = req.keep;
    backup::save_auto(&st.db, &cfg).await?;
    audit::by(&st.db, &user, "backup_auto", json!({ "enabled": cfg.enabled, "hour": cfg.hour, "keep": cfg.keep })).await;
    get_auto(State(st), Need(user, std::marker::PhantomData)).await
}

pub async fn run_auto(State(st): State<AppState>, Need(user, _): Need<perm::BackupManage>) -> ApiResult<Json<Value>> {
    let cfg = backup::load_auto(&st.db).await;
    let password: String = cfg
        .password_sealed
        .as_deref()
        .and_then(|s| st.vault.open_value(s).ok())
        .ok_or_else(|| ApiError::BadRequest("Bitte zuerst ein Passwort für die Sicherungen festlegen".into()))?;
    let name = backup::write_auto(&st, &password, cfg.keep).await?;
    audit::by(&st.db, &user, "backup_create", json!({ "file": name })).await;
    Ok(Json(json!({ "ok": true, "file": name })))
}

pub async fn get_file(State(st): State<AppState>, Need(user, _): Need<perm::BackupManage>, Path(name): Path<String>) -> ApiResult<Response> {
    user.require_recent_auth(&st.db).await?;
    if !backup::valid_name(&name) {
        return Err(ApiError::NotFound);
    }
    let body = tokio::fs::read(backup::dir(&st).join(&name)).await.map_err(|_| ApiError::NotFound)?;
    audit::by(&st.db, &user, "backup_download", json!({ "file": name })).await;
    Ok(download(&name, body))
}

pub async fn delete_file(State(st): State<AppState>, Need(user, _): Need<perm::BackupManage>, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    if !backup::valid_name(&name) {
        return Err(ApiError::NotFound);
    }
    tokio::fs::remove_file(backup::dir(&st).join(&name)).await.map_err(|_| ApiError::NotFound)?;
    audit::by(&st.db, &user, "backup_delete", json!({ "file": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Tresor-Schlüssel tauschen (z. B. nach Ausscheiden eines Admins oder nach einem Vorfall)
pub async fn rotate_key(State(st): State<AppState>, Need(user, _): Need<perm::BackupManage>) -> ApiResult<Json<Value>> {
    user.require_recent_auth(&st.db).await?;
    if !st.vault.can_rotate() {
        return Err(ApiError::BadRequest("Der Schlüssel ist über SECRET_KEY fest vorgegeben – Tausch nur dort möglich".into()));
    }
    let (count, backup) = st.vault.rotate(&st.db).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    audit::by(&st.db, &user, "vault_rotate", json!({ "entries": count })).await;
    Ok(Json(json!({ "ok": true, "entries": count, "old_key": backup.file_name().map(|n| n.to_string_lossy().to_string()) })))
}

pub async fn vault_info(State(st): State<AppState>, _user: Need<perm::BackupManage>) -> Json<Value> {
    Json(json!({ "can_rotate": st.vault.can_rotate() }))
}
