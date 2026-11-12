//! Anmeldung und Zugriffsschutz.
//!
//! - Passwörter: Argon2id (aktueller Standard, u. a. vom BSI empfohlen)
//! - Sitzungen: zufälliges 256-Bit-Token im HttpOnly-Cookie, in der DB nur als SHA-256-Hash
//! - CSRF-Schutz: SameSite=Strict + Pflicht-Header bei allen ändernden Anfragen
//! - Brute-Force-Schutz: Grenzen je Benutzer+IP, je IP und je Benutzer (siehe unten)

use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    sync::OnceLock,
};

use argon2::{
    password_hash::{
        rand_core::{OsRng, RngCore},
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use axum::{
    extract::{FromRequestParts, Request},
    http::{header, request::Parts, HeaderMap, Method},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{error::ApiError, AppState};

pub const SESSION_COOKIE: &str = "netpulse_session";
/// Mit HTTPS: `__Host-`-Präfix – der Browser akzeptiert das Cookie dann nur von genau diesem Host
/// (keine Übernahme durch Nachbar-Subdomains hinter demselben Proxy)
pub const SESSION_COOKIE_SECURE: &str = "__Host-netpulse_session";
/// Diesen Header muss jede ändernde Anfrage mitschicken. Fremde Webseiten können
/// ihn wegen der Same-Origin-Policy nicht setzen.
const CSRF_HEADER: &str = "x-netpulse-csrf";

// ---------------------------------------------------------------------------
// Passwörter
// ---------------------------------------------------------------------------

/// Erst-Anmeldung einer neuen Installation (steht im Handbuch).
/// Gilt nur bis zur ersten Anmeldung – danach muss ein eigenes Passwort gesetzt werden.
pub const DEFAULT_ADMIN_USER: &str = "admin";
pub const DEFAULT_ADMIN_PASSWORD: &str = "Admin123!";

pub fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < 12 {
        return Err("Passwort muss mindestens 12 Zeichen lang sein".into());
    }
    if password.len() > 256 {
        return Err("Passwort ist zu lang".into());
    }
    Ok(())
}

/// Hashing ist absichtlich rechenintensiv, deshalb läuft es in einem eigenen Thread
/// und blockiert den Webserver nicht.
/// Höchstens 4 gleichzeitige Argon2-Berechnungen (je ~19 MB RAM) – schützt NAS/Pi vor Überlastung
fn argon_slots() -> &'static tokio::sync::Semaphore {
    static SLOTS: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    SLOTS.get_or_init(|| tokio::sync::Semaphore::new(4))
}

pub async fn hash_password(password: String) -> anyhow::Result<String> {
    let _slot = argon_slots().acquire().await?;
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("Passwort-Hashing fehlgeschlagen: {e}"))
    })
    .await?
}

pub async fn verify_password(password: String, hash: String) -> bool {
    let Ok(_slot) = argon_slots().acquire().await else { return false };
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Hash, gegen den bei unbekannten Benutzernamen geprüft wird. So dauert ein Login-Versuch
/// immer gleich lang und verrät nicht, ob ein Benutzer existiert.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"netpulse-dummy-password", &salt)
            .expect("Argon2 mit Standardparametern")
            .to_string()
    })
}

// ---------------------------------------------------------------------------
// Sitzungen
// ---------------------------------------------------------------------------

/// Kryptografisch sicherer Zufallswert als Hex-Text (`bytes` Byte → doppelt so viele Zeichen)
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub async fn create_session(db: &PgPool, user_id: i64, hours: i32, headers: &HeaderMap) -> Result<String, sqlx::Error> {
    create_session_with(db, user_id, hours, headers, false).await
}

/// `kiosk`: Sitzung eines Leitstand-Bildschirms (keine kritischen Aktionen möglich)
pub async fn create_session_with(db: &PgPool, user_id: i64, hours: i32, headers: &HeaderMap, kiosk: bool) -> Result<String, sqlx::Error> {
    let token = random_token(32);
    let user_agent: Option<String> = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(300).collect());
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at, user_agent, ip, last_seen, kiosk, reauth_at)
         VALUES ($1, $2, now() + make_interval(hours => $3), $4, $5, now(), $6, CASE WHEN $6 THEN NULL ELSE now() END)",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .bind(hours)
    .bind(user_agent)
    .bind(client_ip(headers))
    .bind(kiosk)
    .execute(db)
    .await?;
    Ok(token)
}

/// Adresse des Browsers für die Anzeige (vom vorgeschalteten Proxy gemeldet; nur zur Information)
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim).filter(|v| !v.is_empty());
    header("x-real-ip")
        .or_else(|| header("x-forwarded-for").and_then(|v| v.split(',').next()).map(str::trim))
        .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string)
}

/// Ist die Sitzung noch gültig? (für lange offene Verbindungen wie den Live-Stream)
pub async fn session_valid(db: &PgPool, token_hash: &[u8]) -> bool {
    sqlx::query_as::<_, (i64,)>("SELECT 1 FROM sessions WHERE token_hash = $1 AND expires_at > now()")
        .bind(token_hash)
        .fetch_optional(db)
        .await
        .map(|r| r.is_some())
        // Datenbank nicht erreichbar: lieber die Verbindung beenden (der Browser baut sie neu auf und prüft erneut)
        .unwrap_or(false)
}

pub fn session_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    if secure {
        format!("{SESSION_COOKIE_SECURE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}; Secure")
    } else {
        format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}")
    }
}

/// Liest das Sitzungs-Token aus dem Cookie-Header.
pub fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE_SECURE || *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_string())
}

// ---------------------------------------------------------------------------
// Rechte
// ---------------------------------------------------------------------------
//
// Ein Benutzer bekommt Rollen – direkt oder über Gruppen – entweder für alle Sektoren oder für einen Sektor
// (dann auch für alle Unter-Sektoren). Eine Rolle ist eine Liste von Rechten. Rechte, die sich auf Geräte
// beziehen („je Sektor“), wirken bei einer Zuweisung an einen Sektor nur dort; Verwaltungsrechte (Benutzer,
// Zugangsdaten, Sicherung …) wirken nur, wenn die Rolle für alle Sektoren vergeben ist.

/// Alle Rechte: (Name, Beschreibung, je Sektor vergebbar)
pub const PERMISSIONS: &[(&str, &str, bool)] = &[
    ("view", "Geräte, Status, Dienste, Alarme und Dashboards ansehen", true),
    ("devices.manage", "Geräte anlegen, bearbeiten, löschen, abfragen und übernehmen", true),
    ("devices.diagnose", "Diagnose, SNMP-Explorer, Client-Listen mit MAC-Adressen und Protokolle (Syslog)", true),
    ("alerts.ack", "Alarme bestätigen", true),
    ("checks.manage", "Dienste (Webseiten, Ports, Zertifikate) anlegen und ändern", true),
    ("maintenance.manage", "Wartungsfenster verwalten", true),
    ("alerts.manage", "Alarmregeln und Benachrichtigungskanäle verwalten", false),
    ("networks.manage", "Sektoren, Netze, Geräte-Suche und Probes verwalten", false),
    ("credentials.manage", "Zugangsdaten (SNMP, SSH, APIs) verwalten", false),
    ("users.manage", "Benutzer, Gruppen, Rollen und zentrale Anmeldung verwalten", false),
    ("settings.manage", "Einstellungen, Statusseite, Echtzeit, verbundene Programme, Energie", false),
    ("backup.manage", "Sicherung, Wiederherstellung und Tresor-Schlüssel", false),
    ("audit.view", "Audit-Log und System-Log ansehen", false),
];

pub fn is_permission(name: &str) -> bool {
    PERMISSIONS.iter().any(|(p, _, _)| *p == name)
}

fn site_scoped(name: &str) -> bool {
    PERMISSIONS.iter().any(|(p, _, scoped)| *p == name && *scoped)
}

/// Wirksame Rechte eines Benutzers
#[derive(Clone, Default, Serialize, Debug, PartialEq)]
pub struct Perms {
    /// Rechte in allen Sektoren
    pub global: BTreeSet<String>,
    /// Rechte nur in bestimmten Sektoren (bereits auf Unter-Sektoren erweitert, ohne die globalen)
    pub sites: BTreeMap<i64, BTreeSet<String>>,
}

impl Perms {
    /// Recht für alle Sektoren
    pub fn can(&self, perm: &str) -> bool {
        self.global.contains(perm)
    }
    /// Recht in diesem Sektor
    pub fn can_site(&self, perm: &str, site_id: i64) -> bool {
        self.can(perm) || self.sites.get(&site_id).is_some_and(|s| s.contains(perm))
    }
    /// Recht irgendwo (für den Zugang zu einer Seite; die Daten werden dann nach Sektor gefiltert)
    pub fn can_any(&self, perm: &str) -> bool {
        self.can(perm) || self.sites.values().any(|s| s.contains(perm))
    }
    /// `None` = alle Sektoren, sonst die erlaubten Sektoren (für `site_id = ANY($n)` in SQL)
    pub fn site_filter(&self, perm: &str) -> Option<Vec<i64>> {
        if self.can(perm) {
            return None;
        }
        Some(self.sites.iter().filter(|(_, p)| p.contains(perm)).map(|(id, _)| *id).collect())
    }

    /// Nur dieses eine Recht behalten (für Bildschirm-Sitzungen)
    pub fn only(self, perm: &str) -> Self {
        let keep = |set: BTreeSet<String>| set.into_iter().filter(|p| p == perm).collect::<BTreeSet<_>>();
        Perms {
            global: keep(self.global),
            sites: self.sites.into_iter().map(|(id, set)| (id, keep(set))).filter(|(_, set)| !set.is_empty()).collect(),
        }
    }

    /// Aus Zuweisungen (Rechte, Sektor) und dem Sektor-Baum (id, parent_id) berechnen
    pub fn build(assignments: &[(Vec<String>, Option<i64>)], tree: &[(i64, Option<i64>)]) -> Self {
        let mut perms = Perms::default();
        for (list, site) in assignments {
            if site.is_none() {
                perms.global.extend(list.iter().cloned());
            }
        }
        for (list, site) in assignments {
            let Some(site) = site else { continue };
            let scoped: Vec<&String> = list.iter().filter(|p| site_scoped(p) && !perms.global.contains(*p)).collect();
            if scoped.is_empty() {
                continue;
            }
            for id in descendants(*site, tree) {
                perms.sites.entry(id).or_default().extend(scoped.iter().map(|p| (*p).clone()));
            }
        }
        perms
    }
}

/// Sektor und alle Unter-Sektoren (schützt vor Kreisen)
pub fn descendants(root: i64, tree: &[(i64, Option<i64>)]) -> Vec<i64> {
    let mut out = vec![root];
    let mut i = 0;
    while i < out.len() && out.len() <= tree.len() + 1 {
        let current = out[i];
        for (id, parent) in tree {
            if *parent == Some(current) && !out.contains(id) {
                out.push(*id);
            }
        }
        i += 1;
    }
    out
}

/// Aktive Benutzer, die dieses Recht im Sektor haben (`None` = Recht für alle Sektoren nötig).
/// Für Empfänger von Push-Nachrichten: niemand soll Meldungen über Sektoren bekommen, die er nicht sehen darf.
pub async fn users_with(db: &PgPool, perm: &str, site: Option<i64>) -> sqlx::Result<Vec<i64>> {
    let ids: Vec<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE NOT disabled").fetch_all(db).await?;
    let mut out = Vec::new();
    for (id,) in ids {
        let (perms, _) = load_perms(db, id).await?;
        let ok = match site {
            Some(site) => perms.can_site(perm, site),
            None => perms.can(perm),
        };
        if ok {
            out.push(id);
        }
    }
    Ok(out)
}

/// Rechte eines Benutzers aus der Datenbank laden
pub async fn load_perms(db: &PgPool, user_id: i64) -> sqlx::Result<(Perms, Vec<String>)> {
    let rows: Vec<(String, bool, Vec<String>, Option<i64>)> = sqlx::query_as(
        "WITH a AS (
             SELECT role_id, site_id FROM role_assignments WHERE user_id = $1
             UNION
             SELECT ra.role_id, ra.site_id FROM role_assignments ra
               JOIN group_members gm ON gm.group_id = ra.group_id WHERE gm.user_id = $1
         )
         SELECT r.name, r.all_permissions, r.permissions, a.site_id FROM a JOIN roles r ON r.id = a.role_id",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    let all: Vec<String> = PERMISSIONS.iter().map(|(p, _, _)| p.to_string()).collect();
    let assignments: Vec<(Vec<String>, Option<i64>)> =
        rows.iter().map(|(_, every, list, site)| (if *every { all.clone() } else { list.clone() }, *site)).collect();
    let tree: Vec<(i64, Option<i64>)> = if assignments.iter().any(|(_, s)| s.is_some()) {
        sqlx::query_as("SELECT id, parent_id FROM sites").fetch_all(db).await?
    } else {
        vec![]
    };
    let mut roles: Vec<String> = rows.into_iter().map(|r| r.0).collect();
    roles.sort();
    roles.dedup();
    Ok((Perms::build(&assignments, &tree), roles))
}

// ---------------------------------------------------------------------------
// Extraktoren: Ein Handler, der `CurrentUser` als Parameter nimmt, ist automatisch
// nur für angemeldete Benutzer erreichbar; `Need<perm::X>` nur mit dem Recht X.
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize)]
pub struct CurrentUser {
    pub id: i64,
    pub username: String,
    pub display_name: Option<String>,
    /// Kurzbeschreibung für die Anzeige („Administrator“, „Nur lesen“, „Benutzerdefiniert“)
    pub role: String,
    /// Namen der zugewiesenen Rollen (direkt und über Gruppen)
    pub roles: Vec<String>,
    /// 2FA ist Pflicht, aber noch nicht eingerichtet → nur „Mein Konto“ ist erreichbar
    pub totp_setup_required: bool,
    /// Anmeldung mit Standard- oder Notfall-Kennwort → erst ein eigenes Passwort setzen
    pub password_change_required: bool,
    pub permissions: Perms,
    /// Leitstand-Bildschirm (Sitzung über API-Schlüssel) – keine kritischen Aktionen
    pub kiosk: bool,
    /// Angemeldet mit API-Schlüssel statt Sitzung
    pub api_token: bool,
    #[serde(skip)]
    pub session_hash: Option<Vec<u8>>,
}

impl CurrentUser {
    pub fn can(&self, perm: &str) -> bool {
        self.permissions.can(perm)
    }
    pub fn can_site(&self, perm: &str, site_id: i64) -> bool {
        self.permissions.can_site(perm, site_id)
    }
    pub fn site_filter(&self, perm: &str) -> Option<Vec<i64>> {
        self.permissions.site_filter(perm)
    }
    pub fn require(&self, perm: &str) -> Result<(), ApiError> {
        if self.can(perm) { Ok(()) } else { Err(ApiError::Forbidden) }
    }
    pub fn require_site(&self, perm: &str, site_id: i64) -> Result<(), ApiError> {
        if self.can_site(perm, site_id) { Ok(()) } else { Err(ApiError::Forbidden) }
    }

    /// Kritische Aktion: Passwort muss in den letzten 10 Minuten eingegeben worden sein (Anmeldung oder Bestätigung).
    /// Mit API-Schlüssel oder am Leitstand-Bildschirm nie möglich.
    pub async fn require_recent_auth(&self, db: &PgPool) -> Result<(), ApiError> {
        if self.kiosk || self.api_token {
            return Err(ApiError::Forbidden);
        }
        let Some(hash) = &self.session_hash else { return Err(ApiError::ReauthRequired) };
        let recent: Option<(bool,)> = sqlx::query_as(
            "SELECT COALESCE(reauth_at > now() - interval '10 minutes', false) FROM sessions WHERE token_hash = $1",
        )
        .bind(hash)
        .fetch_optional(db)
        .await?;
        if recent.is_some_and(|r| r.0) { Ok(()) } else { Err(ApiError::ReauthRequired) }
    }

    /// Geräte-Sektor prüfen (für Aktionen an einem bestimmten Gerät)
    pub async fn require_device(&self, db: &PgPool, perm: &str, device_id: i64) -> Result<i64, ApiError> {
        let site: Option<(i64,)> = sqlx::query_as("SELECT site_id FROM devices WHERE id = $1").bind(device_id).fetch_optional(db).await?;
        let (site,) = site.ok_or(ApiError::NotFound)?;
        if self.can_site(perm, site) {
            Ok(site)
        } else if self.can_site("view", site) {
            Err(ApiError::Forbidden)
        } else {
            // Wer das Gerät nicht sehen darf, erfährt auch nicht, dass es existiert
            Err(ApiError::NotFound)
        }
    }
}

fn summary_role(roles: &[String], perms: &Perms) -> String {
    if PERMISSIONS.iter().all(|(p, _, _)| perms.can(p)) {
        "admin".into()
    } else if roles.len() == 1 {
        roles[0].clone()
    } else if roles.is_empty() {
        "ohne Rolle".into()
    } else {
        "mehrere Rollen".into()
    }
}

/// Ist die Zwei-Faktor-Anmeldung für alle Pflicht? (Umgebungsvariable oder Einstellung)
pub async fn totp_required(state: &AppState) -> bool {
    if state.config.require_totp {
        return true;
    }
    sqlx::query_scalar::<_, bool>("SELECT COALESCE((value->>'require_totp')::bool, false) FROM settings WHERE key = 'security'")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// Solange 2FA fehlt, sind nur diese Pfade erlaubt: Konto ansehen, 2FA einrichten, Passwort ändern, abmelden
fn allowed_without_totp(path: &str) -> bool {
    let path = path.strip_prefix("/api").unwrap_or(path);
    matches!(path, "/me" | "/me/totp" | "/me/totp/setup" | "/me/totp/enable" | "/me/password" | "/me/sessions" | "/me/reauth" | "/logout")
}

/// API-Schlüssel aus `Authorization: Bearer np_…`
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    token.starts_with("np_").then(|| token.to_string())
}

/// Benutzer zu einer Sitzung (Cookie) oder einem API-Schlüssel laden
pub async fn user_from_headers(state: &AppState, headers: &HeaderMap) -> Result<Option<CurrentUser>, ApiError> {
    type Row = (i64, String, Option<String>, bool, bool, bool);
    let (row, api_token, session_hash): (Option<Row>, bool, Option<Vec<u8>>) = if let Some(token) = bearer_token(headers) {
        let hash = token_hash(&token);
        let row: Option<Row> = sqlx::query_as(
            "UPDATE api_tokens t SET last_used = now() FROM users u
              WHERE t.token_hash = $1 AND u.id = t.user_id AND NOT u.disabled AND (t.expires_at IS NULL OR t.expires_at > now())
              RETURNING u.id, u.username, u.display_name, false, false, false",
        )
        .bind(&hash)
        .fetch_optional(&state.db)
        .await?;
        (row, true, None)
    } else {
        let Some(token) = session_token(headers) else { return Ok(None) };
        let hash = token_hash(&token);
        let row: Option<Row> = sqlx::query_as(
            "SELECT u.id, u.username, u.display_name,
                    (NOT u.totp_enabled AND u.auth_source = 'local' AND NOT s.kiosk
                         AND ($2 OR COALESCE((SELECT (value->>'require_totp')::bool FROM settings WHERE key = 'security'), false))),
                    s.kiosk,
                    (u.must_change_password AND NOT s.kiosk)
               FROM sessions s JOIN users u ON u.id = s.user_id
              WHERE s.token_hash = $1 AND s.expires_at > now() AND NOT u.disabled",
        )
        .bind(&hash)
        .bind(state.config.require_totp)
        .fetch_optional(&state.db)
        .await?;
        (row, false, Some(hash))
    };
    let Some((id, username, display_name, totp_setup_required, kiosk, password_change_required)) = row else { return Ok(None) };
    let (mut permissions, roles) = load_perms(&state.db, id).await?;
    if kiosk {
        // Leitstand-Bildschirm: nur ansehen, egal welche Rechte der Benutzer sonst hat
        permissions = permissions.only("view");
    }
    Ok(Some(CurrentUser {
        id,
        username,
        display_name,
        role: summary_role(&roles, &permissions),
        roles,
        totp_setup_required,
        password_change_required,
        permissions,
        kiosk,
        api_token,
        session_hash,
    }))
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        if let Some(user) = parts.extensions.get::<CurrentUser>() {
            return Ok(user.clone());
        }
        let user = user_from_headers(state, &parts.headers).await?.ok_or(ApiError::Unauthorized)?;
        if user.password_change_required && !allowed_without_totp(parts.uri.path()) {
            return Err(ApiError::PasswordChangeRequired);
        }
        if user.totp_setup_required && !allowed_without_totp(parts.uri.path()) {
            return Err(ApiError::TotpSetupRequired);
        }
        if let Some(hash) = user.session_hash.clone() {
            // „Zuletzt aktiv“ höchstens einmal pro Minute schreiben
            let db = state.db.clone();
            tokio::spawn(async move {
                let _ = sqlx::query(
                    "UPDATE sessions SET last_seen = now() WHERE token_hash = $1 AND (last_seen IS NULL OR last_seen < now() - interval '1 minute')",
                )
                .bind(hash)
                .execute(&db)
                .await;
            });
        }
        parts.extensions.insert(user.clone());
        Ok(user)
    }
}

/// Recht als Typ – für `Need<perm::DevicesManage>` in Handler-Signaturen
pub trait Permission {
    const NAME: &'static str;
}

pub mod perm {
    macro_rules! permissions {
        ($($ty:ident => $name:literal),* $(,)?) => {
            $(pub struct $ty; impl super::Permission for $ty { const NAME: &'static str = $name; })*
        };
    }
    permissions! {
        View => "view",
        DevicesManage => "devices.manage",
        DevicesDiagnose => "devices.diagnose",
        AlertsAck => "alerts.ack",
        ChecksManage => "checks.manage",
        MaintenanceManage => "maintenance.manage",
        AlertsManage => "alerts.manage",
        NetworksManage => "networks.manage",
        CredentialsManage => "credentials.manage",
        UsersManage => "users.manage",
        SettingsManage => "settings.manage",
        BackupManage => "backup.manage",
        AuditView => "audit.view",
    }
}

/// Angemeldeter Benutzer, der das Recht `P` hat – für alle Sektoren oder mindestens einen
/// (Daten und Aktionen werden im Handler dann nach Sektor gefiltert).
pub struct Need<P: Permission>(pub CurrentUser, pub PhantomData<P>);

impl<P: Permission> std::ops::Deref for Need<P> {
    type Target = CurrentUser;
    fn deref(&self) -> &CurrentUser {
        &self.0
    }
}

impl<P: Permission + Send + Sync> FromRequestParts<AppState> for Need<P> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        if user.permissions.can_any(P::NAME) {
            Ok(Need(user, PhantomData))
        } else {
            Err(ApiError::Forbidden)
        }
    }
}

/// Middleware: Ändernde Anfragen (POST, PUT, PATCH, DELETE) ohne CSRF-Header ablehnen.
/// Anfragen mit API-Schlüssel (`Authorization: Bearer`) brauchen ihn nicht: Fremde Webseiten können
/// diesen Header ohne CORS-Freigabe nicht setzen, und dann zählt nur der Schlüssel, nicht das Cookie.
pub async fn csrf_guard(request: Request, next: Next) -> Response {
    let safe_method = matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let has_header = request.headers().get(CSRF_HEADER).is_some_and(|v| v == "1");
    let bearer = bearer_token(request.headers()).is_some();
    if !safe_method && !has_header && !bearer {
        return ApiError::Forbidden.into_response();
    }
    next.run(request).await
}

// ---------------------------------------------------------------------------
// Brute-Force-Schutz
// ---------------------------------------------------------------------------
//
// Jeder Versuch wird VOR der Passwortprüfung gezählt (auch parallele Anfragen) und erst bei
// Erfolg zurückgenommen. Die Zähler liegen in der Datenbank und überstehen so einen Neustart.
// Grenzen je 15 Minuten:
// - Benutzer + IP: 5 Versuche  → ein Angreifer sperrt nur sich selbst, nicht den echten Benutzer
// - IP:           20 Versuche  → gegen das Durchprobieren vieler Benutzernamen
// - Benutzer:     50 Versuche  → gegen verteilte Angriffe von vielen Adressen

const LIMIT_USER_IP: i32 = 5;
const LIMIT_IP: i32 = 20;
const LIMIT_USER: i32 = 50;

pub struct LoginLimiter {
    db: PgPool,
}

impl LoginLimiter {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    fn keys(username: &str, ip: &str) -> [(String, i32); 3] {
        [
            (format!("ui:{username}|{ip}"), LIMIT_USER_IP),
            (format!("i:{ip}"), LIMIT_IP),
            (format!("u:{username}"), LIMIT_USER),
        ]
    }

    /// Versuch anmelden; `false` = gesperrt (dann nicht prüfen)
    pub async fn try_attempt(&self, username: &str, ip: &str) -> bool {
        let keys = Self::keys(username, ip);
        let names: Vec<String> = keys.iter().map(|(k, _)| k.clone()).collect();
        let counts: Result<Vec<(String, i32)>, _> = sqlx::query_as(
            "INSERT INTO login_attempts (key, count, since) SELECT k, 1, now() FROM unnest($1::text[]) k
             ON CONFLICT (key) DO UPDATE SET
                 count = CASE WHEN login_attempts.since < now() - interval '15 minutes' THEN 1 ELSE login_attempts.count + 1 END,
                 since = CASE WHEN login_attempts.since < now() - interval '15 minutes' THEN now() ELSE login_attempts.since END
             RETURNING key, count",
        )
        .bind(&names)
        .fetch_all(&self.db)
        .await;
        match counts {
            Ok(counts) => !Self::blocked(&keys, &counts),
            Err(e) => {
                // Ohne Datenbank kann ohnehin niemand angemeldet werden
                tracing::warn!("Login-Sperre nicht prüfbar: {e}");
                false
            }
        }
    }

    fn blocked(keys: &[(String, i32)], counts: &[(String, i32)]) -> bool {
        counts.iter().any(|(key, n)| keys.iter().any(|(k, limit)| k == key && n > limit))
    }

    /// Erfolgreiche Prüfung: Versuch wieder abziehen
    pub async fn success(&self, username: &str, ip: &str) {
        let [(user_ip, _), (ip_key, _), (user, _)] = Self::keys(username, ip);
        let _ = sqlx::query("DELETE FROM login_attempts WHERE key = $1").bind(user_ip).execute(&self.db).await;
        let _ = sqlx::query("UPDATE login_attempts SET count = GREATEST(count - 1, 0) WHERE key = ANY($1)")
            .bind(vec![ip_key, user])
            .execute(&self.db)
            .await;
    }

    /// Alte Einträge löschen (stündlich)
    pub async fn cleanup(db: &PgPool) {
        let _ = sqlx::query("DELETE FROM login_attempts WHERE since < now() - interval '1 hour'").execute(db).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sperre_ab_grenze() {
        let keys = LoginLimiter::keys("admin", "203.0.113.9");
        assert!(!LoginLimiter::blocked(&keys, &[("ui:admin|203.0.113.9".into(), 5)]));
        assert!(LoginLimiter::blocked(&keys, &[("ui:admin|203.0.113.9".into(), 6)]));
        assert!(!LoginLimiter::blocked(&keys, &[("i:203.0.113.9".into(), 20)]));
        assert!(LoginLimiter::blocked(&keys, &[("u:admin".into(), 51)]));
    }

    fn set(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn rechte_je_sektor() {
        // Baum: 1 → 2 → 3, 4 eigenständig
        let tree = [(1, None), (2, Some(1)), (3, Some(2)), (4, None)];
        let perms = Perms::build(
            &[(set(&["view"]), None), (set(&["devices.manage", "users.manage", "view"]), Some(2))],
            &tree,
        );
        assert!(perms.can("view"));
        assert!(perms.can_site("view", 4));
        assert!(!perms.can("devices.manage"));
        assert!(perms.can_site("devices.manage", 2));
        assert!(perms.can_site("devices.manage", 3), "Unter-Sektor erbt");
        assert!(!perms.can_site("devices.manage", 1), "übergeordneter Sektor nicht");
        assert!(!perms.can_any("users.manage"), "Verwaltungsrechte nur global");
        assert_eq!(perms.site_filter("view"), None);
        assert_eq!(perms.site_filter("devices.manage"), Some(vec![2, 3]));
        assert_eq!(perms.site_filter("alerts.ack"), Some(vec![]));
    }

    #[test]
    fn baum_mit_kreis_endet() {
        let tree = [(1, Some(2)), (2, Some(1))];
        let mut d = descendants(1, &tree);
        d.sort();
        assert_eq!(d, vec![1, 2]);
    }
}
