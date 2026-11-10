//! Zugangsdaten für SNMP und SSH. Geheimnisse verlassen den Server nie wieder –
//! die API liefert nur Name, Art, Benutzer und Port.

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
    collect::Secret,
    error::{ApiError, ApiResult},
    AppState,
};

const KINDS: &[&str] = &["snmp_v2c", "snmp_v3", "ssh_password", "ssh_key", "http", "unifi", "fritzbox", "opnsense", "mikrotik"];

#[derive(Serialize, FromRow)]
pub struct CredentialInfo {
    id: i64,
    name: String,
    kind: String,
    username: Option<String>,
    port: Option<i32>,
    auto: bool,
    created_at: DateTime<Utc>,
    device_count: i64,
}

const SELECT: &str = "SELECT c.id, c.name, c.kind, c.username, c.port, c.auto, c.created_at,
                             (SELECT count(*) FROM device_credentials dc WHERE dc.credential_id = c.id) AS device_count
                        FROM credentials c";

pub async fn list(State(st): State<AppState>, _admin: Need<perm::CredentialsManage>) -> ApiResult<Json<Vec<CredentialInfo>>> {
    let sql = format!("{SELECT} ORDER BY c.name");
    Ok(Json(sqlx::query_as::<_, CredentialInfo>(&sql).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct CredentialInput {
    name: Option<String>,
    kind: Option<String>,
    username: Option<String>,
    port: Option<i32>,
    auto: Option<bool>,
    /// Nur die mitgeschickten, nicht-leeren Felder werden gesetzt
    #[serde(default)]
    secret: Secret,
}

fn validate(kind: &str, auto: bool) -> ApiResult<()> {
    if !KINDS.contains(&kind) {
        return Err(ApiError::BadRequest("Unbekannte Zugangsart".into()));
    }
    if auto && kind == "snmp_v2c" {
        return Err(ApiError::BadRequest(
            "SNMP v2c sendet die Community unverschlüsselt – nicht automatisch an alle Geräte. Bitte SNMP v3 verwenden \
             oder die Geräte über „Geräte zuordnen“ gezielt auswählen."
                .into(),
        ));
    }
    if auto && (kind == "unifi" || crate::collect::API_KINDS.contains(&kind)) {
        return Err(ApiError::BadRequest(
            "Diese Zugangsdaten werden nur dem jeweiligen Gerät (Controller/Router) fest zugeordnet und nie automatisch ausprobiert.".into(),
        ));
    }
    if auto && kind == "ssh_password" {
        return Err(ApiError::BadRequest(
            "SSH mit Passwort kann aus Sicherheitsgründen nicht automatisch ausprobiert werden – \
             das Passwort würde sonst an jedes Gerät mit offenem SSH-Port gesendet. Bitte Schlüssel verwenden \
             oder Geräte gezielt zuordnen."
                .into(),
        ));
    }
    Ok(())
}

/// Leere Felder aus `update` übernehmen nicht – so bleiben bestehende Geheimnisse erhalten
fn merge(mut base: Secret, update: Secret) -> Secret {
    fn keep(old: &mut Option<String>, new: Option<String>) {
        if let Some(v) = new.filter(|v| !v.is_empty()) {
            *old = Some(v);
        }
    }
    keep(&mut base.community, update.community);
    keep(&mut base.password, update.password);
    keep(&mut base.private_key, update.private_key);
    keep(&mut base.passphrase, update.passphrase);
    keep(&mut base.auth_protocol, update.auth_protocol);
    keep(&mut base.auth_password, update.auth_password);
    keep(&mut base.priv_protocol, update.priv_protocol);
    keep(&mut base.priv_password, update.priv_password);
    base
}

pub async fn create(
    State(st): State<AppState>,
    Need(user, _): Need<perm::CredentialsManage>,
    Json(req): Json<CredentialInput>,
) -> ApiResult<Json<CredentialInfo>> {
    user.require_recent_auth(&st.db).await?;
    let name = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty() && n.chars().count() <= 100);
    let name = name.ok_or_else(|| ApiError::BadRequest("Bitte einen Namen (max. 100 Zeichen) angeben".into()))?;
    let kind = req.kind.as_deref().unwrap_or_default();
    let auto = req.auto.unwrap_or(false);
    validate(kind, auto)?;
    let secret = merge(Secret::default(), req.secret);
    let missing = match kind {
        "snmp_v2c" => secret.community.is_none(),
        "ssh_password" | "http" => secret.password.is_none(),
        "ssh_key" => secret.private_key.is_none(),
        _ => false,
    };
    if missing {
        return Err(ApiError::BadRequest("Bitte Community, Passwort bzw. Schlüssel angeben".into()));
    }
    if kind.starts_with("ssh") && req.username.as_deref().unwrap_or_default().trim().is_empty() {
        return Err(ApiError::BadRequest("Bitte einen Benutzernamen angeben".into()));
    }
    let sealed = st.vault.seal(&secret)?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO credentials (name, kind, username, port, secret, auto) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (name) DO NOTHING RETURNING id",
    )
    .bind(name)
    .bind(kind)
    .bind(req.username.as_deref().map(str::trim).filter(|u| !u.is_empty()))
    .bind(req.port)
    .bind(sealed)
    .bind(auto)
    .fetch_optional(&st.db)
    .await?
    .ok_or_else(|| ApiError::BadRequest(format!("Zugangsdaten „{name}“ existieren bereits")))?;

    if auto {
        // Geräte ohne Zuordnung beim nächsten Durchlauf erneut probieren
        sqlx::query(
            "UPDATE devices SET inventory_at = NULL
              WHERE NOT EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = devices.id)",
        )
        .execute(&st.db)
        .await?;
    }
    audit::by(&st.db, &user, "credential_add", json!({ "id": id, "name": name, "kind": kind, "auto": auto })).await;
    let sql = format!("{SELECT} WHERE c.id = $1");
    Ok(Json(sqlx::query_as::<_, CredentialInfo>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn update(
    State(st): State<AppState>,
    Need(user, _): Need<perm::CredentialsManage>,
    Path(id): Path<i64>,
    Json(req): Json<CredentialInput>,
) -> ApiResult<Json<CredentialInfo>> {
    user.require_recent_auth(&st.db).await?;
    let (kind, sealed, auto): (String, String, bool) =
        sqlx::query_as("SELECT kind, secret, auto FROM credentials WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound)?;
    let auto = req.auto.unwrap_or(auto);
    validate(&kind, auto)?;
    let secret = merge(st.vault.open_value(&sealed)?, req.secret);
    sqlx::query(
        "UPDATE credentials SET
            name = COALESCE(NULLIF(trim($2), ''), name),
            username = CASE WHEN $3::text IS NULL THEN username ELSE NULLIF(trim($3), '') END,
            port = $4, secret = $5, auto = $6
          WHERE id = $1",
    )
    .bind(id)
    .bind(&req.name)
    .bind(&req.username)
    .bind(req.port)
    .bind(st.vault.seal(&secret)?)
    .bind(auto)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "credential_update", json!({ "id": id })).await;
    let sql = format!("{SELECT} WHERE c.id = $1");
    Ok(Json(sqlx::query_as::<_, CredentialInfo>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn remove(
    State(st): State<AppState>,
    Need(user, _): Need<perm::CredentialsManage>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let (name,): (String,) = sqlx::query_as("DELETE FROM credentials WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "credential_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Testen, Suchlauf, Zuordnung
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TestRequest {
    device_id: i64,
}

/// Zugangsdaten gegen ein Gerät testen (ohne Zuordnung) – mit verständlicher Rückmeldung
pub async fn test(
    State(st): State<AppState>,
    _admin: Need<perm::CredentialsManage>,
    Path(id): Path<i64>,
    Json(req): Json<TestRequest>,
) -> ApiResult<Json<crate::collect::check::CheckResult>> {
    crate::collect::check::test_one(&st, id, req.device_id)
        .await
        .map(Json)
        .map_err(|e| ApiError::BadRequest(format!("{e:#}")))
}

#[derive(Deserialize)]
pub struct ScanRequest {
    /// Ohne Angabe: alle passenden Geräte
    device_ids: Option<Vec<i64>>,
}

/// Suchlauf starten: testen und bei Erfolg zuordnen
pub async fn scan(
    State(st): State<AppState>,
    Need(user, _): Need<perm::CredentialsManage>,
    Path(id): Path<i64>,
    Json(req): Json<ScanRequest>,
) -> ApiResult<Json<crate::collect::check::Job>> {
    let count = req.device_ids.as_ref().map(Vec::len);
    let job = crate::collect::check::start_scan(&st, id, req.device_ids)
        .await
        .map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    audit::by(&st.db, &user, "credential_scan", json!({ "id": id, "devices": count })).await;
    Ok(Json(job))
}

pub async fn scan_status(
    State(st): State<AppState>,
    _admin: Need<perm::CredentialsManage>,
    Path(id): Path<i64>,
) -> Json<crate::collect::check::Job> {
    Json(st.cred_jobs.get(id))
}

pub async fn devices(State(st): State<AppState>, _admin: Need<perm::CredentialsManage>, Path(id): Path<i64>) -> ApiResult<Json<Vec<i64>>> {
    let rows: Vec<(i64,)> = sqlx::query_as("SELECT device_id FROM device_credentials WHERE credential_id = $1")
        .bind(id)
        .fetch_all(&st.db)
        .await?;
    Ok(Json(rows.into_iter().map(|r| r.0).collect()))
}

#[derive(Deserialize)]
pub struct AssignRequest {
    device_ids: Vec<i64>,
}

/// Zuordnung ohne Test festlegen (genau diese Geräte)
pub async fn set_devices(
    State(st): State<AppState>,
    Need(user, _): Need<perm::CredentialsManage>,
    Path(id): Path<i64>,
    Json(req): Json<AssignRequest>,
) -> ApiResult<Json<Value>> {
    let mut tx = st.db.begin().await?;
    sqlx::query("DELETE FROM device_credentials WHERE credential_id = $1 AND NOT (device_id = ANY($2))")
        .bind(id)
        .bind(&req.device_ids)
        .execute(&mut *tx)
        .await?;
    let added: Vec<(i64,)> = sqlx::query_as(
        "INSERT INTO device_credentials (device_id, credential_id)
         SELECT d.id, $1 FROM devices d WHERE d.id = ANY($2)
         ON CONFLICT DO NOTHING RETURNING device_id",
    )
    .bind(id)
    .bind(&req.device_ids)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    for (device_id,) in &added {
        let _ = st.poll_tx.send(*device_id);
    }
    audit::by(&st.db, &user, "credential_assign", json!({ "id": id, "devices": req.device_ids.len() })).await;
    Ok(Json(json!({ "ok": true, "added": added.len() })))
}
