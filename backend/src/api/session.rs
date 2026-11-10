//! Login, Logout, eigenes Konto.

use axum::{
    extract::State,
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{self, CurrentUser},
    error::{ApiError, ApiResult},
    AppState,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
    /// 6-stelliger Code aus der Authenticator-App (nur bei aktiver Zwei-Faktor-Anmeldung)
    #[serde(default)]
    code: Option<String>,
}

pub async fn login(State(st): State<AppState>, headers: HeaderMap, Json(req): Json<LoginRequest>) -> ApiResult<Response> {
    let username: String = req.username.trim().to_lowercase().chars().take(64).collect();
    let ip = auth::client_ip(&headers).unwrap_or_else(|| "unbekannt".into());
    // Versuch zählen, bevor geprüft wird (auch parallele Anfragen)
    if !st.login_limiter.try_attempt(&username, &ip).await {
        audit::log(&st.db, None, Some(&username), "login_blocked", json!({ "ip": ip })).await;
        return Err(ApiError::TooManyRequests);
    }

    // Gesperrte Konten und Konten der zentralen Anmeldung (OIDC) können sich nicht mit Passwort anmelden
    let user: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT id, username, password_hash FROM users WHERE username = $1 AND NOT disabled AND auth_source = 'local'",
    )
    .bind(&username)
    .fetch_optional(&st.db)
    .await?;

    // Auch bei unbekanntem Benutzer einen Hash prüfen, damit die Antwortzeit nichts verrät
    let hash = user.as_ref().map(|u| u.2.clone()).unwrap_or_else(|| auth::dummy_hash().to_string());
    let valid = auth::verify_password(req.password, hash).await;

    // `let … else`: Wenn das Muster nicht passt, wird der else-Zweig ausgeführt
    let Some((id, name, _)) = user.filter(|_| valid) else {
        audit::log(&st.db, None, Some(&username), "login_failed", json!({ "ip": ip })).await;
        return Err(ApiError::InvalidCredentials);
    };

    // Zwei-Faktor-Anmeldung: erst nach richtigem Passwort nach dem Code fragen
    let (totp_enabled, totp_secret, last_step): (bool, Option<String>, Option<i64>) =
        sqlx::query_as("SELECT totp_enabled, totp_secret, totp_last_step FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    if totp_enabled {
        let Some(code) = req.code.as_deref().filter(|c| !c.trim().is_empty()) else {
            // Passwort stimmt – dieser Schritt zählt nicht als Fehlversuch
            st.login_limiter.success(&username, &ip).await;
            return Ok(Json(json!({ "totp_required": true })).into_response());
        };
        let secret: String = totp_secret
            .as_deref()
            .and_then(|s| st.vault.open_value(s).ok())
            .ok_or_else(|| ApiError::BadRequest("Zwei-Faktor-Geheimnis nicht lesbar – Admin muss 2FA zurücksetzen".into()))?;
        let Some(step) = crate::totp::verify(&secret, code, chrono::Utc::now().timestamp(), last_step) else {
            audit::log(&st.db, Some(id), Some(&name), "login_failed", json!({ "reason": "totp", "ip": ip })).await;
            return Err(ApiError::BadRequest("Code aus der Authenticator-App ist falsch oder abgelaufen".into()));
        };
        // Nur einmal gültig – auch bei gleichzeitigen Anfragen (bedingtes Update)
        let used = sqlx::query("UPDATE users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)")
            .bind(id)
            .bind(step)
            .execute(&st.db)
            .await?;
        if used.rows_affected() == 0 {
            return Err(ApiError::BadRequest("Code aus der Authenticator-App ist falsch oder abgelaufen".into()));
        }
    }

    st.login_limiter.success(&username, &ip).await;
    let token = auth::create_session(&st.db, id, st.config.session_hours, &headers).await?;
    sqlx::query("UPDATE users SET last_login = now() WHERE id = $1")
        .bind(id)
        .execute(&st.db)
        .await?;
    audit::log(&st.db, Some(id), Some(&name), "login", json!({ "ip": auth::client_ip(&headers) })).await;

    let max_age = i64::from(st.config.session_hours) * 3600;
    let cookie = auth::session_cookie(&token, max_age, st.config.cookie_secure);
    let _ = totp_enabled;
    // Mit dem neuen Cookie den Benutzer samt Rechten laden (gleiche Antwort wie GET /api/me)
    let mut fresh = HeaderMap::new();
    if let Ok(v) = format!("{}={token}", auth::SESSION_COOKIE).parse() {
        fresh.insert(header::COOKIE, v);
    }
    let user = auth::user_from_headers(&st, &fresh).await?.ok_or(ApiError::Unauthorized)?;
    Ok(([(header::SET_COOKIE, cookie)], Json(user)).into_response())
}

pub async fn logout(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = auth::session_token(&headers) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(auth::token_hash(&token))
            .execute(&st.db)
            .await?;
    }
    let cookie = auth::session_cookie("", 0, st.config.cookie_secure);
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

pub async fn me(user: CurrentUser) -> Json<CurrentUser> {
    Json(user)
}

#[derive(Deserialize)]
pub struct PasswordChange {
    old_password: String,
    new_password: String,
}

pub async fn change_password(
    State(st): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Json(req): Json<PasswordChange>,
) -> ApiResult<Json<Value>> {
    auth::validate_password(&req.new_password).map_err(ApiError::BadRequest)?;

    let (hash,): (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&st.db)
        .await?;
    if !auth::verify_password(req.old_password, hash).await {
        return Err(ApiError::BadRequest("Aktuelles Passwort ist falsch".into()));
    }

    let new_hash = auth::hash_password(req.new_password).await?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(user.id)
        .bind(new_hash)
        .execute(&st.db)
        .await?;

    // Alle anderen Sitzungen dieses Benutzers beenden (z. B. auf fremden Geräten)
    let current = auth::session_token(&headers).map(|t| auth::token_hash(&t)).unwrap_or_default();
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
        .bind(user.id)
        .bind(current)
        .execute(&st.db)
        .await?;

    audit::by(&st.db, &user, "password_change", json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Zwei-Faktor-Anmeldung einrichten
// ---------------------------------------------------------------------------

pub async fn totp_status(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let (enabled,): (bool,) = sqlx::query_as("SELECT totp_enabled FROM users WHERE id = $1").bind(user.id).fetch_one(&st.db).await?;
    Ok(Json(json!({ "enabled": enabled, "required": auth::totp_required(&st).await })))
}

/// Neues Geheimnis erzeugen (noch nicht aktiv) und als QR-Code liefern
pub async fn totp_setup(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let (enabled,): (bool,) = sqlx::query_as("SELECT totp_enabled FROM users WHERE id = $1").bind(user.id).fetch_one(&st.db).await?;
    if enabled {
        return Err(ApiError::BadRequest("Zwei-Faktor-Anmeldung ist bereits aktiv – zuerst ausschalten".into()));
    }
    let secret = crate::totp::new_secret();
    let sealed = st.vault.seal(&secret).map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    sqlx::query("UPDATE users SET totp_secret = $2 WHERE id = $1").bind(user.id).bind(sealed).execute(&st.db).await?;
    let uri = crate::totp::uri(&secret, &user.username, "NetPulse");
    let svg = crate::totp::qr_svg(&uri).map(|s| s[s.find("<svg").unwrap_or(0)..].to_string());
    Ok(Json(json!({ "secret": secret, "uri": uri, "qr_svg": svg })))
}

#[derive(Deserialize)]
pub struct TotpCode {
    code: String,
}

pub async fn totp_enable(State(st): State<AppState>, user: CurrentUser, headers: HeaderMap, Json(req): Json<TotpCode>) -> ApiResult<Json<Value>> {
    let (sealed,): (Option<String>,) = sqlx::query_as("SELECT totp_secret FROM users WHERE id = $1").bind(user.id).fetch_one(&st.db).await?;
    let secret: String = sealed
        .as_deref()
        .and_then(|s| st.vault.open_value(s).ok())
        .ok_or_else(|| ApiError::BadRequest("Bitte zuerst „Einrichten“ wählen".into()))?;
    let step = crate::totp::verify(&secret, &req.code, chrono::Utc::now().timestamp(), None)
        .ok_or_else(|| ApiError::BadRequest("Code stimmt nicht – Uhrzeit am Handy prüfen und den aktuellen Code eingeben".into()))?;
    sqlx::query("UPDATE users SET totp_enabled = true, totp_last_step = $2 WHERE id = $1").bind(user.id).bind(step).execute(&st.db).await?;
    // Ab jetzt gilt 2FA: alle anderen (evtl. fremden) Sitzungen abmelden
    let current = auth::session_token(&headers).map(|t| auth::token_hash(&t)).unwrap_or_default();
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2").bind(user.id).bind(current).execute(&st.db).await?;
    audit::by(&st.db, &user, "totp_enabled", json!({})).await;
    Ok(Json(json!({ "enabled": true })))
}

#[derive(Deserialize)]
pub struct TotpDisable {
    password: String,
    code: String,
}

pub async fn totp_disable(State(st): State<AppState>, user: CurrentUser, headers: HeaderMap, Json(req): Json<TotpDisable>) -> ApiResult<Json<Value>> {
    if auth::totp_required(&st).await {
        return Err(ApiError::BadRequest("Zwei-Faktor-Anmeldung ist für alle Benutzer Pflicht und kann nicht ausgeschaltet werden".into()));
    }
    let ip = auth::client_ip(&headers).unwrap_or_else(|| "unbekannt".into());
    if !st.login_limiter.try_attempt(&user.username, &ip).await {
        return Err(ApiError::TooManyRequests);
    }
    let (hash, sealed, last_step): (String, Option<String>, Option<i64>) =
        sqlx::query_as("SELECT password_hash, totp_secret, totp_last_step FROM users WHERE id = $1").bind(user.id).fetch_one(&st.db).await?;
    if !auth::verify_password(req.password, hash).await {
        return Err(ApiError::BadRequest("Passwort ist falsch".into()));
    }
    let secret: Option<String> = sealed.as_deref().and_then(|s| st.vault.open_value(s).ok());
    if !secret.is_some_and(|s| crate::totp::verify(&s, &req.code, chrono::Utc::now().timestamp(), last_step).is_some()) {
        return Err(ApiError::BadRequest("Code aus der Authenticator-App ist falsch".into()));
    }
    st.login_limiter.success(&user.username, &ip).await;
    sqlx::query("UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_last_step = NULL WHERE id = $1")
        .bind(user.id)
        .execute(&st.db)
        .await?;
    audit::by(&st.db, &user, "totp_disabled", json!({})).await;
    Ok(Json(json!({ "enabled": false })))
}

// ---------------------------------------------------------------------------
// Push-Nachrichten an die App
// ---------------------------------------------------------------------------

pub async fn push_key(State(st): State<AppState>, _user: CurrentUser) -> Json<Value> {
    Json(json!({ "public_key": st.vapid.public_key() }))
}

#[derive(Deserialize)]
pub struct PushKeys {
    p256dh: String,
    auth: String,
}

#[derive(Deserialize)]
pub struct PushSubscribe {
    endpoint: String,
    keys: PushKeys,
    #[serde(default)]
    device: Option<String>,
}

/// Nur echte Push-Dienste der Browser-Hersteller – verhindert, dass der Server beliebige Adressen aufruft
fn allowed_push_endpoint(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else { return false };
    let host = url.host_str().unwrap_or_default();
    url.scheme() == "https"
        && ["fcm.googleapis.com", "push.services.mozilla.com", "push.apple.com", "notify.windows.com", "web.push.apple.com"]
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

pub async fn push_subscribe(State(st): State<AppState>, user: CurrentUser, Json(req): Json<PushSubscribe>) -> ApiResult<Json<Value>> {
    if !allowed_push_endpoint(&req.endpoint) || req.endpoint.len() > 1000 || req.keys.p256dh.len() > 200 || req.keys.auth.len() > 100 {
        return Err(ApiError::BadRequest("Unbekannter Push-Dienst".into()));
    }
    let device: Option<String> = req.device.map(|d| d.chars().take(120).collect());
    sqlx::query(
        "INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth, device) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (endpoint) DO UPDATE SET user_id = EXCLUDED.user_id, p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth, device = EXCLUDED.device",
    )
    .bind(user.id)
    .bind(&req.endpoint)
    .bind(&req.keys.p256dh)
    .bind(&req.keys.auth)
    .bind(&device)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "push_subscribe", json!({ "device": device })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct PushUnsubscribe {
    endpoint: Option<String>,
    id: Option<i64>,
}

pub async fn push_unsubscribe(State(st): State<AppState>, user: CurrentUser, Json(req): Json<PushUnsubscribe>) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM push_subscriptions WHERE user_id = $1 AND (endpoint = $2 OR id = $3)")
        .bind(user.id)
        .bind(req.endpoint)
        .bind(req.id)
        .execute(&st.db)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn push_devices(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    #[derive(serde::Serialize, sqlx::FromRow)]
    struct Row {
        id: i64,
        endpoint: String,
        device: Option<String>,
        created_at: chrono::DateTime<chrono::Utc>,
        last_ok_at: Option<chrono::DateTime<chrono::Utc>>,
        last_error: Option<String>,
        last_error_at: Option<chrono::DateTime<chrono::Utc>>,
        last_shown_at: Option<chrono::DateTime<chrono::Utc>>,
        last_show_error: Option<String>,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, endpoint, device, created_at, last_ok_at, last_error, last_error_at, last_shown_at, last_show_error
           FROM push_subscriptions WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user.id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!(rows)))
}

pub async fn push_test(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let message = crate::push::PushMessage {
        title: "NetPulse: Test",
        body: "Push-Nachrichten kommen an. So sehen Alarme auf diesem Gerät aus.",
        severity: "warning",
        url: "/#/alerts",
        tag: "test",
    };
    let r = crate::push::send(&st, Some(&[user.id]), &message).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    Ok(Json(json!({ "sent": r.ok, "failed": r.failed, "errors": r.errors })))
}

// ---------------------------------------------------------------------------
// Angemeldete Sitzungen
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct SessionRow {
    id: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    expires_at: chrono::DateTime<chrono::Utc>,
    user_agent: Option<String>,
    ip: Option<String>,
    current: bool,
}

pub async fn sessions(State(st): State<AppState>, user: CurrentUser, headers: HeaderMap) -> ApiResult<Json<Vec<SessionRow>>> {
    let hash = auth::session_token(&headers).map(|t| auth::token_hash(&t)).unwrap_or_default();
    let rows = sqlx::query_as::<_, SessionRow>(
        "SELECT id, created_at, last_seen, expires_at, user_agent, ip, token_hash = $2 AS current
           FROM sessions WHERE user_id = $1 AND expires_at > now()
          ORDER BY (token_hash = $2) DESC, COALESCE(last_seen, created_at) DESC",
    )
    .bind(user.id)
    .bind(hash)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

/// Eine eigene Sitzung beenden (das Gerät ist sofort abgemeldet)
pub async fn end_session(State(st): State<AppState>, user: CurrentUser, axum::extract::Path(id): axum::extract::Path<i64>) -> ApiResult<Json<Value>> {
    let done = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2").bind(id).bind(user.id).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "session_end", json!({ "session": id })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Alle anderen Sitzungen beenden
pub async fn end_other_sessions(State(st): State<AppState>, user: CurrentUser, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let hash = auth::session_token(&headers).map(|t| auth::token_hash(&t)).unwrap_or_default();
    let done = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2").bind(user.id).bind(hash).execute(&st.db).await?;
    audit::by(&st.db, &user, "session_end_others", json!({ "count": done.rows_affected() })).await;
    Ok(Json(json!({ "ended": done.rows_affected() })))
}

#[derive(Deserialize)]
pub struct PushAck {
    endpoint: String,
    ok: bool,
    error: Option<String>,
}

/// Rückmeldung des Service Workers auf dem Handy: Push empfangen und angezeigt (oder Fehler).
/// Ohne Anmeldung, weil die Sitzung auf dem Handy abgelaufen sein kann; die (geheime) Push-Adresse
/// weist das Gerät aus, und es lassen sich nur deren Zeitstempel ändern.
pub async fn push_ack(State(st): State<AppState>, Json(req): Json<PushAck>) -> ApiResult<Json<Value>> {
    if req.endpoint.len() > 2048 {
        return Err(ApiError::BadRequest("ungültig".into()));
    }
    let error: Option<String> = req.error.map(|e| e.chars().filter(|c| !c.is_control()).take(300).collect());
    sqlx::query(
        "UPDATE push_subscriptions
            SET last_shown_at = CASE WHEN $2 THEN now() ELSE last_shown_at END,
                last_show_error = CASE WHEN $2 THEN NULL ELSE $3 END
          WHERE endpoint = $1",
    )
    .bind(&req.endpoint)
    .bind(req.ok)
    .bind(error)
    .execute(&st.db)
    .await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Erneute Bestätigung vor kritischen Aktionen
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct Reauth {
    password: String,
    #[serde(default)]
    code: Option<String>,
}

/// Passwort (und bei aktiver 2FA den Code) erneut prüfen; danach sind 10 Minuten lang kritische Aktionen möglich
pub async fn reauth(State(st): State<AppState>, user: CurrentUser, headers: HeaderMap, Json(req): Json<Reauth>) -> ApiResult<Json<Value>> {
    let Some(session) = user.session_hash.clone().filter(|_| !user.kiosk && !user.api_token) else {
        return Err(ApiError::Forbidden);
    };
    let ip = auth::client_ip(&headers).unwrap_or_else(|| "unbekannt".into());
    if !st.login_limiter.try_attempt(&user.username, &ip).await {
        return Err(ApiError::TooManyRequests);
    }
    let (hash, source, totp_enabled, sealed, last_step): (String, String, bool, Option<String>, Option<i64>) = sqlx::query_as(
        "SELECT password_hash, auth_source, totp_enabled, totp_secret, totp_last_step FROM users WHERE id = $1",
    )
    .bind(user.id)
    .fetch_one(&st.db)
    .await?;
    if source != "local" {
        return Err(ApiError::BadRequest("Konto der zentralen Anmeldung: bitte ab- und neu anmelden".into()));
    }
    if !auth::verify_password(req.password, hash).await {
        audit::by(&st.db, &user, "reauth_failed", json!({ "ip": ip })).await;
        return Err(ApiError::BadRequest("Passwort ist falsch".into()));
    }
    if totp_enabled {
        let secret: Option<String> = sealed.as_deref().and_then(|s| st.vault.open_value(s).ok());
        let code = req.code.unwrap_or_default();
        let Some(step) = secret.and_then(|s| crate::totp::verify(&s, &code, chrono::Utc::now().timestamp(), last_step)) else {
            return Err(ApiError::BadRequest("Code aus der Authenticator-App fehlt oder ist falsch".into()));
        };
        sqlx::query("UPDATE users SET totp_last_step = $2 WHERE id = $1").bind(user.id).bind(step).execute(&st.db).await?;
    }
    st.login_limiter.success(&user.username, &ip).await;
    sqlx::query("UPDATE sessions SET reauth_at = now() WHERE token_hash = $1").bind(session).execute(&st.db).await?;
    audit::by(&st.db, &user, "reauth", json!({ "ip": ip })).await;
    Ok(Json(json!({ "ok": true, "totp": totp_enabled })))
}
