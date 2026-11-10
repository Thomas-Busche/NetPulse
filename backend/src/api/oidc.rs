//! Zentrale Anmeldung (OpenID Connect): Entra ID, Keycloak, Authentik, Authelia …
//!
//! Ablauf (Authorization Code mit PKCE):
//! 1. `/api/oidc/start` merkt sich `state`, `nonce` und PKCE-Prüfwert in `oidc_states` und im Browser
//!    (kurzlebiges Cookie) und leitet zum Anmeldedienst weiter.
//! 2. `/api/oidc/callback` prüft `state` gegen Datenbank und Cookie, tauscht den Code direkt beim
//!    Anmeldedienst (TLS) gegen Tokens und prüft das ID-Token (Aussteller, Empfänger, Ablauf, Nonce).
//!    Die Signatur muss dabei nicht geprüft werden, weil das Token direkt über TLS vom Dienst kommt
//!    (OpenID Connect Core 3.1.3.7, Punkt 6).
//! 3. Das NetPulse-Konto wird über `oidc_subject` gefunden, beim ersten Mal über den Benutzernamen
//!    verknüpft oder – falls eingeschaltet – neu angelegt. Gruppen mit hinterlegtem OIDC-Gruppennamen
//!    werden abgeglichen; Rechte kommen wie gewohnt über Rollen der Gruppen bzw. des Benutzers.

use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    audit,
    auth::{self, perm, Need},
    error::{ApiError, ApiResult},
    AppState,
};

const STATE_COOKIE: &str = "netpulse_oidc";

/// Gespeicherte Einstellungen (Schlüssel `oidc` in `settings`; das Client-Geheimnis liegt im Tresor)
#[derive(Serialize, Deserialize, Default, Clone)]
struct Settings {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    label: String,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret_sealed: Option<String>,
    #[serde(default)]
    groups_claim: String,
    #[serde(default)]
    auto_create: bool,
}

impl Settings {
    fn label(&self) -> String {
        if self.label.trim().is_empty() { "Zentrale Anmeldung".into() } else { self.label.clone() }
    }
    fn groups_claim(&self) -> &str {
        if self.groups_claim.trim().is_empty() { "groups" } else { self.groups_claim.trim() }
    }
}

async fn load(st: &AppState) -> ApiResult<Settings> {
    let value: Option<Value> = sqlx::query_scalar("SELECT value FROM settings WHERE key = 'oidc'").fetch_optional(&st.db).await?;
    Ok(value.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default())
}

fn redirect_uri(st: &AppState) -> Option<String> {
    st.config.public_url.as_deref().map(|u| format!("{}/api/oidc/callback", u.trim_end_matches('/')))
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

async fn discover(issuer: &str) -> anyhow::Result<Discovery> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let r = http().get(&url).send().await?;
    if !r.status().is_success() {
        anyhow::bail!("{url} antwortete {}", r.status());
    }
    let d: Discovery = r.json().await?;
    for endpoint in [&d.authorization_endpoint, &d.token_endpoint] {
        if !endpoint.starts_with("https://") {
            anyhow::bail!("Der Anmeldedienst nennt eine Adresse ohne HTTPS: {endpoint}");
        }
    }
    Ok(d)
}

// ---------------------------------------------------------------------------
// Einstellungen
// ---------------------------------------------------------------------------

pub async fn get_settings(State(st): State<AppState>, _admin: Need<perm::UsersManage>) -> ApiResult<Json<Value>> {
    let s = load(&st).await?;
    Ok(Json(json!({
        "enabled": s.enabled, "label": s.label, "issuer": s.issuer, "client_id": s.client_id,
        "has_secret": s.client_secret_sealed.is_some(), "groups_claim": s.groups_claim, "auto_create": s.auto_create,
        "redirect_uri": redirect_uri(&st),
    })))
}

#[derive(Deserialize)]
pub struct SettingsInput {
    enabled: bool,
    #[serde(default)]
    label: String,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    client_id: String,
    /// leer = bisheriges Geheimnis behalten
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    groups_claim: String,
    #[serde(default)]
    auto_create: bool,
}

pub async fn put_settings(State(st): State<AppState>, Need(admin, _): Need<perm::UsersManage>, Json(req): Json<SettingsInput>) -> ApiResult<Json<Value>> {
    admin.require_recent_auth(&st.db).await?;
    let old = load(&st).await?;
    let issuer = req.issuer.trim().trim_end_matches('/').to_string();
    let client_id = req.client_id.trim().to_string();
    let secret_sealed = match req.client_secret.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(secret) => Some(st.vault.seal(&secret.to_string()).map_err(ApiError::Internal)?),
        None => old.client_secret_sealed.clone(),
    };
    if req.enabled {
        if redirect_uri(&st).is_none() {
            return Err(ApiError::BadRequest("Für die zentrale Anmeldung muss PUBLIC_URL (bzw. SITE_ADDRESS) gesetzt sein".into()));
        }
        if !issuer.starts_with("https://") {
            return Err(ApiError::BadRequest("Aussteller (Issuer) muss mit https:// beginnen".into()));
        }
        if client_id.is_empty() || secret_sealed.is_none() {
            return Err(ApiError::BadRequest("Bitte Client-ID und Client-Geheimnis angeben".into()));
        }
        let found = discover(&issuer).await.map_err(|e| ApiError::BadRequest(format!("Anmeldedienst nicht erreichbar: {e:#}")))?;
        if found.issuer.trim_end_matches('/') != issuer {
            return Err(ApiError::BadRequest(format!("Der Dienst meldet einen anderen Aussteller: {}", found.issuer)));
        }
    }
    let s = Settings {
        enabled: req.enabled,
        label: req.label.trim().chars().take(60).collect(),
        issuer,
        client_id,
        client_secret_sealed: secret_sealed,
        groups_claim: req.groups_claim.trim().chars().take(100).collect(),
        auto_create: req.auto_create,
    };
    sqlx::query("INSERT INTO settings (key, value) VALUES ('oidc', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(serde_json::to_value(&s).map_err(|e| ApiError::Internal(e.into()))?)
        .execute(&st.db)
        .await?;
    audit::by(&st.db, &admin, "oidc_settings", json!({ "enabled": s.enabled, "issuer": s.issuer, "auto_create": s.auto_create })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Für die Anmeldeseite: gibt es eine zentrale Anmeldung?
pub async fn info(State(st): State<AppState>) -> ApiResult<Json<Value>> {
    let s = load(&st).await?;
    let enabled = s.enabled && redirect_uri(&st).is_some();
    Ok(Json(json!({ "enabled": enabled, "label": if enabled { Some(s.label()) } else { None } })))
}

// ---------------------------------------------------------------------------
// Anmeldung
// ---------------------------------------------------------------------------

fn fail(message: &str) -> Response {
    let target = format!("/#sso-error={}", urlencode(message));
    Redirect::to(&target).into_response()
}

fn urlencode(text: &str) -> String {
    text.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn state_cookie(value: &str, max_age: i64, secure: bool) -> String {
    // Lax: der Rücksprung vom Anmeldedienst ist eine seitenübergreifende Navigation
    format!("{STATE_COOKIE}={value}; Path=/api/oidc; HttpOnly; SameSite=Lax; Max-Age={max_age}{}", if secure { "; Secure" } else { "" })
}

pub async fn start(State(st): State<AppState>) -> Response {
    match start_inner(&st).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Zentrale Anmeldung: Start fehlgeschlagen: {e:#}");
            fail("Anmeldedienst nicht erreichbar")
        }
    }
}

async fn start_inner(st: &AppState) -> anyhow::Result<Response> {
    let s = load(st).await.map_err(|_| anyhow::anyhow!("Einstellungen nicht lesbar"))?;
    let Some(redirect) = redirect_uri(st).filter(|_| s.enabled) else {
        return Ok(fail("Zentrale Anmeldung ist nicht eingerichtet"));
    };
    let d = discover(&s.issuer).await?;
    let state = auth::random_token(24);
    let nonce = auth::random_token(24);
    let verifier = auth::random_token(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    sqlx::query("DELETE FROM oidc_states WHERE created_at < now() - interval '1 hour'").execute(&st.db).await?;
    sqlx::query("INSERT INTO oidc_states (state, verifier, nonce) VALUES ($1, $2, $3)")
        .bind(&state)
        .bind(&verifier)
        .bind(&nonce)
        .execute(&st.db)
        .await?;
    let mut url = reqwest::Url::parse(&d.authorization_endpoint)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &s.client_id)
        .append_pair("redirect_uri", &redirect)
        .append_pair("scope", "openid profile email")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let cookie = state_cookie(&state, 600, st.config.cookie_secure);
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to(url.as_str())).into_response())
}

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn callback(State(st): State<AppState>, headers: HeaderMap, Query(q): Query<Callback>) -> Response {
    let clear = state_cookie("", 0, st.config.cookie_secure);
    let result = callback_inner(&st, &headers, q).await;
    let mut response = match result {
        Ok(r) => r,
        Err(Failure::User(message)) => fail(&message),
        Err(Failure::Internal(e)) => {
            tracing::warn!("Zentrale Anmeldung fehlgeschlagen: {e:#}");
            fail("Anmeldung beim Anmeldedienst fehlgeschlagen – Details im System-Log")
        }
    };
    if let Ok(v) = clear.parse() {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
    response
}

enum Failure {
    User(String),
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for Failure {
    fn from(e: E) -> Self {
        Failure::Internal(e.into())
    }
}

fn user_error(message: impl Into<String>) -> Failure {
    Failure::User(message.into())
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.to_string())
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    access_token: Option<String>,
}

/// Nutzdaten eines JWT lesen (ohne Signaturprüfung – siehe Modulbeschreibung)
fn jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?).ok()
}

/// Prüft Aussteller, Empfänger, Ablauf und Nonce des ID-Tokens
fn check_id_token(claims: &Value, issuer: &str, client_id: &str, nonce: &str, now: i64) -> Result<(), String> {
    if claims["iss"].as_str().map(|i| i.trim_end_matches('/')) != Some(issuer.trim_end_matches('/')) {
        return Err("ID-Token: falscher Aussteller".into());
    }
    let aud_ok = match &claims["aud"] {
        Value::String(a) => a == client_id,
        Value::Array(list) => list.iter().any(|a| a.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err("ID-Token: falscher Empfänger".into());
    }
    if claims["exp"].as_i64().is_none_or(|exp| exp + 60 < now) {
        return Err("ID-Token: abgelaufen".into());
    }
    if claims["nonce"].as_str() != Some(nonce) {
        return Err("ID-Token: Nonce passt nicht".into());
    }
    Ok(())
}

/// Gruppen aus einem Claim (Liste oder durch Komma getrennt); verschachtelte Claims mit Punkt, z. B. `realm_access.roles`
fn groups_from(claims: &Value, claim: &str) -> Vec<String> {
    let mut v = claims;
    for part in claim.split('.') {
        v = &v[part];
    }
    match v {
        Value::Array(list) => list.iter().filter_map(|g| g.as_str()).map(str::to_string).collect(),
        Value::String(s) => s.split(',').map(|g| g.trim().to_string()).filter(|g| !g.is_empty()).collect(),
        _ => vec![],
    }
}

/// Benutzername aus den Angaben des Anmeldedienstes (nur erlaubte Zeichen)
fn username_from(claims: &Value) -> Option<String> {
    let raw = claims["preferred_username"].as_str().or(claims["email"].as_str())?;
    let name: String = raw
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-@".contains(c) { c } else { '_' })
        .take(64)
        .collect();
    (name.len() >= 3).then_some(name)
}

async fn callback_inner(st: &AppState, headers: &HeaderMap, q: Callback) -> Result<Response, Failure> {
    if let Some(err) = q.error {
        let detail = q.error_description.unwrap_or_default();
        return Err(user_error(format!("Anmeldedienst meldet: {err} {detail}").trim().chars().take(200).collect::<String>()));
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return Err(user_error("Unvollständige Antwort des Anmeldedienstes"));
    };
    // Gegen Login-CSRF: state muss zu genau diesem Browser gehören
    if cookie_value(headers, STATE_COOKIE).as_deref() != Some(state.as_str()) {
        return Err(user_error("Anmeldung abgelaufen oder in einem anderen Browser begonnen – bitte erneut versuchen"));
    }
    let row: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM oidc_states WHERE state = $1 AND created_at > now() - interval '10 minutes' RETURNING verifier, nonce",
    )
    .bind(&state)
    .fetch_optional(&st.db)
    .await?;
    let Some((verifier, nonce)) = row else {
        return Err(user_error("Anmeldung abgelaufen – bitte erneut versuchen"));
    };
    let s = load(st).await.map_err(|_| anyhow::anyhow!("Einstellungen nicht lesbar"))?;
    let redirect = redirect_uri(st).filter(|_| s.enabled).ok_or_else(|| user_error("Zentrale Anmeldung ist nicht eingerichtet"))?;
    let secret: String = st.vault.open_value(s.client_secret_sealed.as_deref().unwrap_or_default())?;
    let d = discover(&s.issuer).await?;

    // Code gegen Tokens tauschen
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("code_verifier", verifier.as_str()),
        ("client_id", s.client_id.as_str()),
    ];
    let basic = d.token_endpoint_auth_methods_supported.as_ref().is_none_or(|m| m.iter().any(|x| x == "client_secret_basic"));
    let mut request = http().post(&d.token_endpoint);
    request = if basic {
        request.basic_auth(urlencode(&s.client_id), Some(urlencode(&secret))).form(&form)
    } else {
        let mut with_secret = form.to_vec();
        with_secret.push(("client_secret", secret.as_str()));
        request.form(&with_secret)
    };
    let r = request.send().await?;
    if !r.status().is_success() {
        let status = r.status();
        let body: String = r.text().await.unwrap_or_default().chars().take(300).collect();
        return Err(Failure::Internal(anyhow::anyhow!("Token-Abruf: {status} {body}")));
    }
    let tokens: TokenResponse = r.json().await?;
    let id_token = tokens.id_token.ok_or_else(|| anyhow::anyhow!("Antwort enthält kein ID-Token"))?;
    let mut claims = jwt_claims(&id_token).ok_or_else(|| anyhow::anyhow!("ID-Token nicht lesbar"))?;
    check_id_token(&claims, &d.issuer, &s.client_id, &nonce, chrono::Utc::now().timestamp()).map_err(Failure::User)?;
    let subject = claims["sub"].as_str().filter(|s| !s.is_empty()).map(str::to_string).ok_or_else(|| user_error("ID-Token ohne Kennung (sub)"))?;

    // Weitere Angaben (Gruppen, E-Mail) liefern manche Dienste nur über userinfo
    if let (Some(url), Some(access)) = (&d.userinfo_endpoint, &tokens.access_token) {
        if let Ok(r) = http().get(url).bearer_auth(access).send().await {
            if let Ok(Value::Object(extra)) = r.json::<Value>().await {
                if extra.get("sub").and_then(Value::as_str) == Some(subject.as_str()) {
                    for (k, v) in extra {
                        if claims.get(&k).is_none() {
                            claims[&k] = v;
                        }
                    }
                }
            }
        }
    }

    let user_id = find_or_create(st, &s, &subject, &claims).await?;
    sync_groups(st, user_id, &groups_from(&claims, s.groups_claim())).await?;

    let token = auth::create_session(&st.db, user_id, st.config.session_hours, headers).await?;
    // Gerade beim Anmeldedienst bestätigt – zählt als frische Anmeldung für kritische Aktionen
    sqlx::query("UPDATE sessions SET reauth_at = now() WHERE token_hash = $1").bind(auth::token_hash(&token)).execute(&st.db).await?;
    let (name,): (String,) = sqlx::query_as("UPDATE users SET last_login = now() WHERE id = $1 RETURNING username").bind(user_id).fetch_one(&st.db).await?;
    audit::log(&st.db, Some(user_id), Some(&name), "login", json!({ "ip": auth::client_ip(headers), "method": "oidc" })).await;
    let cookie = auth::session_cookie(&token, i64::from(st.config.session_hours) * 3600, st.config.cookie_secure);
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response())
}

async fn find_or_create(st: &AppState, s: &Settings, subject: &str, claims: &Value) -> Result<i64, Failure> {
    let display = claims["name"].as_str().map(|n| n.trim().chars().take(100).collect::<String>()).filter(|n| !n.is_empty());
    let email = claims["email"].as_str().filter(|e| e.contains('@') && e.len() <= 200).map(str::to_string);
    let known: Option<(i64, bool)> = sqlx::query_as("SELECT id, disabled FROM users WHERE oidc_subject = $1").bind(subject).fetch_optional(&st.db).await?;
    let (id, disabled) = match known {
        Some(found) => found,
        None => {
            let username = username_from(claims).ok_or_else(|| user_error("Der Anmeldedienst liefert keinen Benutzernamen (preferred_username/email)"))?;
            // Vorbereitetes Konto (Benutzer → „Zentrale Anmeldung“) verknüpfen – nie ein Konto mit eigenem Passwort
            let linked: Option<(i64, bool)> = sqlx::query_as(
                "UPDATE users SET oidc_subject = $2 WHERE username = $1 AND auth_source = 'oidc' AND oidc_subject IS NULL RETURNING id, disabled",
            )
            .bind(&username)
            .bind(subject)
            .fetch_optional(&st.db)
            .await?;
            match linked {
                Some(found) => found,
                None if s.auto_create => {
                    let mut candidate = username.clone();
                    let mut created = None;
                    for n in 2..20 {
                        let row: Option<(i64,)> = sqlx::query_as(
                            "INSERT INTO users (username, password_hash, display_name, email, auth_source, oidc_subject)
                             VALUES ($1, '!sso', $2, $3, 'oidc', $4) ON CONFLICT (username) DO NOTHING RETURNING id",
                        )
                        .bind(&candidate)
                        .bind(&display)
                        .bind(&email)
                        .bind(subject)
                        .fetch_optional(&st.db)
                        .await?;
                        if let Some((id,)) = row {
                            created = Some(id);
                            break;
                        }
                        candidate = format!("{}-{n}", username.chars().take(60).collect::<String>());
                    }
                    let id = created.ok_or_else(|| user_error("Kein freier Benutzername gefunden"))?;
                    audit::log(&st.db, Some(id), Some(&candidate), "user_add", json!({ "username": candidate, "source": "oidc" })).await;
                    (id, false)
                }
                None => {
                    return Err(user_error(format!(
                        "Für „{username}“ gibt es kein NetPulse-Konto. Ein Admin kann es unter Benutzer anlegen (Anmeldung: zentral)."
                    )))
                }
            }
        }
    };
    if disabled {
        return Err(user_error("Dieses Konto ist in NetPulse gesperrt"));
    }
    sqlx::query("UPDATE users SET display_name = COALESCE($2, display_name), email = COALESCE($3, email) WHERE id = $1")
        .bind(id)
        .bind(&display)
        .bind(&email)
        .execute(&st.db)
        .await?;
    Ok(id)
}

/// Mitgliedschaften in Gruppen mit OIDC-Gruppennamen an die Angaben des Anmeldedienstes anpassen
async fn sync_groups(st: &AppState, user_id: i64, groups: &[String]) -> Result<(), Failure> {
    let mut tx = st.db.begin().await?;
    sqlx::query(
        "DELETE FROM group_members m USING user_groups g
          WHERE m.group_id = g.id AND m.user_id = $1 AND g.oidc_group IS NOT NULL AND NOT (g.oidc_group = ANY($2))",
    )
    .bind(user_id)
    .bind(groups)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO group_members (group_id, user_id) SELECT id, $1 FROM user_groups WHERE oidc_group = ANY($2)
         ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(groups)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_token_pruefen() {
        let claims = json!({ "iss": "https://id.example.org/realms/a", "aud": ["netpulse", "x"], "exp": 2000, "nonce": "n1", "sub": "u" });
        assert!(check_id_token(&claims, "https://id.example.org/realms/a/", "netpulse", "n1", 1000).is_ok());
        assert!(check_id_token(&claims, "https://evil.example.org", "netpulse", "n1", 1000).is_err());
        assert!(check_id_token(&claims, "https://id.example.org/realms/a", "andere", "n1", 1000).is_err());
        assert!(check_id_token(&claims, "https://id.example.org/realms/a", "netpulse", "n2", 1000).is_err());
        assert!(check_id_token(&claims, "https://id.example.org/realms/a", "netpulse", "n1", 3000).is_err());
    }

    #[test]
    fn gruppen_und_namen() {
        let claims = json!({ "groups": ["NetPulse-Admins", "IT"], "realm_access": { "roles": ["np-nord"] }, "preferred_username": "Max Muster" });
        assert_eq!(groups_from(&claims, "groups"), vec!["NetPulse-Admins", "IT"]);
        assert_eq!(groups_from(&claims, "realm_access.roles"), vec!["np-nord"]);
        assert!(groups_from(&claims, "fehlt").is_empty());
        assert_eq!(username_from(&claims).as_deref(), Some("max_muster"));
        let token = format!("x.{}.y", URL_SAFE_NO_PAD.encode(br#"{"sub":"abc"}"#));
        assert_eq!(jwt_claims(&token).unwrap()["sub"], "abc");
    }
}
