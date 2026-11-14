//! Eigene Abfragen und Aktionen – für Geräte, Dienste und Hersteller, die NetPulse nicht von Haus aus kennt.
//!
//! Eine Abfrage gehört zu einer Zugangsangabe; das Protokoll ergibt sich aus deren Art:
//! - SSH (`ssh_password`, `ssh_key`): beliebiger Befehl, Ausgabe = Antwort
//! - HTTP (`http_basic`, `http_token`, `http`): Pfad oder URL zum selben Gerät, GET/POST/…
//! - SNMP (`snmp_v2c`, `snmp_v3`): OID; liefert sie keinen Wert, wird darunter gelesen (Walk)
//!
//! Aus der Antwort wird optional ein Wert übernommen (JSON-Pfad oder „Text, hinter dem der Wert steht“),
//! als Text oder Zahl. Zahlen landen zusätzlich im Verlauf (`custom_query_values`).
//!
//! `mode = 'read'` läuft bei jeder Inventar-Abfrage der zugeordneten Geräte,
//! `mode = 'action'` nur ausdrücklich (Knopf in der Geräteansicht, Zeitplan anderer Funktionen über [`run`]).
//! Zugangsdaten gehen nie an Geräte, denen sie nicht zugeordnet sind; HTTP-URLs müssen auf das Gerät selbst zeigen.

use std::{net::Ipv4Addr, time::Duration};

use anyhow::{anyhow, bail, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use reqwest::{header, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

use super::{check::load_credential, snmp, ssh, tls, Credential};
use crate::AppState;

const MAX_BODY: usize = 1024 * 1024;
/// So viel Rohausgabe wird gespeichert/angezeigt
const MAX_OUTPUT: usize = 4000;

/// Definition einer Abfrage (Zeile aus `custom_queries` oder ungespeichert zum Testen)
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Query {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    pub credential_id: i64,
    #[serde(default = "default_mode")]
    pub mode: String,
    pub target: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub extract: Option<String>,
    #[serde(default = "default_type")]
    pub value_type: String,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub device_ids: Option<Vec<i64>>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_mode() -> String {
    "read".into()
}
fn default_method() -> String {
    "GET".into()
}
fn default_type() -> String {
    "text".into()
}
fn default_true() -> bool {
    true
}

pub const QUERY_COLUMNS: &str = "id, name, credential_id, mode, target, method, body, extract, value_type, unit, device_ids, enabled";

/// Ergebnis einer Abfrage/Aktion
#[derive(Clone, Debug, Serialize, Default)]
pub struct Outcome {
    pub ok: bool,
    /// Übernommener Wert (Text)
    pub value: Option<String>,
    /// Übernommener Wert als Zahl (bei `value_type = number`)
    pub number: Option<f64>,
    /// Rohe Antwort (gekürzt) – zum Einrichten der Auswertung
    pub output: String,
    /// Verständliche Meldung (Fehler oder Zusammenfassung)
    pub message: String,
}

/// Welches Protokoll eine Zugangsart nutzt
pub fn protocol(kind: &str) -> Option<&'static str> {
    match kind {
        "ssh_password" | "ssh_key" => Some("ssh"),
        "snmp_v2c" | "snmp_v3" => Some("snmp"),
        "http" | "http_basic" | "http_token" => Some("http"),
        _ => None,
    }
}

/// Prüft eine Definition auf offensichtliche Fehler (vor dem Speichern)
pub fn validate(q: &Query, kind: &str) -> Result<()> {
    let proto = protocol(kind)
        .ok_or_else(|| anyhow!("Mit dieser Zugangsart sind keine eigenen Abfragen möglich – bitte SSH-, HTTP- oder SNMP-Zugangsdaten wählen"))?;
    if !["read", "action"].contains(&q.mode.as_str()) {
        bail!("Unbekannte Art (Abfrage oder Aktion)");
    }
    if !["text", "number"].contains(&q.value_type.as_str()) {
        bail!("Unbekannter Werttyp");
    }
    let target = q.target.trim();
    if target.is_empty() || target.len() > 4000 {
        bail!("Bitte Befehl, Pfad bzw. OID angeben (max. 4000 Zeichen)");
    }
    match proto {
        "snmp" => {
            parse_oid(target)?;
        }
        "http" => {
            if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&q.method.as_str()) {
                bail!("Unbekannte HTTP-Methode");
            }
            if !(target.starts_with('/') || target.starts_with("http://") || target.starts_with("https://")) {
                bail!("HTTP: Pfad mit „/“ beginnen (z. B. /api/status) oder vollständige URL zum Gerät angeben");
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_oid(text: &str) -> Result<Vec<u64>> {
    let parts: Result<Vec<u64>, _> = text.trim().trim_start_matches('.').split('.').map(str::parse::<u64>).collect();
    match parts {
        Ok(p) if p.len() >= 2 => Ok(p),
        _ => bail!("„{text}“ ist keine gültige OID (Beispiel: 1.3.6.1.2.1.1.3.0)"),
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

pub struct HttpReply {
    pub url: String,
    pub status: StatusCode,
    pub body: String,
    /// Fingerabdruck des TLS-Zertifikats beim ersten Kontakt (zum Merken)
    pub pin: Option<String>,
}

fn opt<'a>(cred: &'a Credential, key: &str) -> Option<&'a str> {
    cred.options.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

/// URL zum Gerät bauen. Vollständige URLs sind nur erlaubt, wenn sie auf das Gerät selbst zeigen –
/// so können Zugangsdaten nicht an fremde Server gehen.
fn build_url(ip: Ipv4Addr, cred: &Credential, target: &str) -> Result<String> {
    let target = target.trim();
    if target.starts_with("http://") || target.starts_with("https://") {
        let url = reqwest::Url::parse(target).map_err(|e| anyhow!("URL ungültig: {e}"))?;
        if url.host_str() != Some(ip.to_string().as_str()) {
            bail!("Die URL muss auf das Gerät selbst zeigen ({ip}) – Zugangsdaten werden nicht an andere Adressen gesendet");
        }
        return Ok(url.to_string());
    }
    let scheme = match opt(cred, "scheme") {
        Some("http") => "http",
        Some(_) => "https",
        None if cred.kind == "http" || cred.port == Some(80) => "http",
        None => "https",
    };
    let port = match (scheme, cred.port) {
        (_, None) | ("http", Some(80)) | ("https", Some(443)) => String::new(),
        (_, Some(p)) => format!(":{p}"),
    };
    Ok(format!("{scheme}://{ip}{port}{target}"))
}

fn param(challenge: &str, key: &str) -> Option<String> {
    let start = challenge.find(&format!("{key}="))? + key.len() + 1;
    let rest = &challenge[start..];
    Some(if let Some(quoted) = rest.strip_prefix('"') { quoted[..quoted.find('"')?].to_string() } else { rest.split(',').next()?.trim().to_string() })
}

/// HTTP-Digest (RFC 7616) mit MD5 oder SHA-256
fn digest_header(challenge: &str, method: &str, uri: &str, user: &str, password: &str) -> Option<String> {
    let realm = param(challenge, "realm")?;
    let nonce = param(challenge, "nonce")?;
    let algorithm = param(challenge, "algorithm").unwrap_or_else(|| "MD5".into());
    let hash = |s: String| -> Option<String> {
        if algorithm.eq_ignore_ascii_case("SHA-256") {
            Some(hex::encode(sha2::Sha256::digest(s.as_bytes())))
        } else if algorithm.eq_ignore_ascii_case("MD5") {
            Some(hex::encode(md5::Md5::digest(s.as_bytes())))
        } else {
            None
        }
    };
    let mut cnonce = [0u8; 8];
    OsRng.fill_bytes(&mut cnonce);
    let cnonce = hex::encode(cnonce);
    let ha1 = hash(format!("{user}:{realm}:{password}"))?;
    let ha2 = hash(format!("{method}:{uri}"))?;
    let qop = param(challenge, "qop");
    let mut header = if qop.is_some() {
        let response = hash(format!("{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}"))?;
        format!(
            r#"Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, qop=auth, nc=00000001, cnonce="{cnonce}", response="{response}""#
        )
    } else {
        let response = hash(format!("{ha1}:{nonce}:{ha2}"))?;
        format!(r#"Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm={algorithm}, response="{response}""#)
    };
    if let Some(opaque) = param(challenge, "opaque") {
        header.push_str(&format!(r#", opaque="{opaque}""#));
    }
    Some(header)
}

/// HTTP-Anfrage mit den Zugangsdaten an das Gerät. HTTPS mit gemerktem Zertifikat (wie bei UniFi/OPNsense).
pub async fn http_request(
    ip: Ipv4Addr,
    cred: &Credential,
    tls_pin: Option<&str>,
    method: &str,
    target: &str,
    body: Option<&str>,
) -> Result<HttpReply> {
    let url = build_url(ip, cred, target)?;
    let pin = tls::Pin::new(tls_pin);
    let client = tls::client(pin.clone())?;
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| anyhow!("Unbekannte HTTP-Methode {method}"))?;
    let user = cred.username.clone().unwrap_or_default();
    let password = cred.secret.password.clone().unwrap_or_default();

    let build = |auth: Option<String>| {
        let mut request = client.request(method.clone(), &url);
        match cred.kind.as_str() {
            "http_token" => {
                let token = cred.secret.token.clone().or_else(|| cred.secret.password.clone()).unwrap_or_default();
                let name = opt(cred, "header").unwrap_or("Authorization");
                let prefix = match cred.options.get("prefix").and_then(Value::as_str) {
                    Some(p) => p.to_string(),
                    None if name.eq_ignore_ascii_case("authorization") => "Bearer ".into(),
                    None => String::new(),
                };
                request = request.header(name, format!("{prefix}{token}"));
            }
            "http_basic" | "http" if auth.is_none() && opt(cred, "auth") != Some("digest") && !password.is_empty() => {
                request = request.basic_auth(&user, Some(&password));
            }
            _ => {}
        }
        if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        if let Some(body) = body.filter(|b| !b.is_empty()) {
            let kind = if serde_json::from_str::<Value>(body).is_ok() { "application/json" } else { "text/plain; charset=utf-8" };
            request = request.header(header::CONTENT_TYPE, kind).body(body.to_string());
        }
        request
    };

    let send = |request: reqwest::RequestBuilder| async {
        request.send().await.map_err(|e| {
            let e = anyhow::Error::from(e);
            if tls::pin_mismatch(&e) {
                anyhow!(tls::PIN_CHANGED)
            } else {
                anyhow!("{url}: {}", short_error(&e))
            }
        })
    };
    let mut response = send(build(None)).await?;
    if response.status() == StatusCode::UNAUTHORIZED && cred.kind != "http_token" && !password.is_empty() {
        let challenge = response.headers().get(header::WWW_AUTHENTICATE).and_then(|h| h.to_str().ok()).unwrap_or_default().to_string();
        if challenge.trim_start().to_ascii_lowercase().starts_with("digest") {
            let uri = reqwest::Url::parse(&url).map(|u| match u.query() {
                Some(q) => format!("{}?{q}", u.path()),
                None => u.path().to_string(),
            })?;
            let auth = digest_header(&challenge, method.as_str(), &uri, &user, &password)
                .ok_or_else(|| anyhow!("Unbekanntes Digest-Verfahren des Geräts"))?;
            response = send(build(Some(auth))).await?;
        }
    }
    let status = response.status();
    let mut bytes = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await? {
        bytes.extend_from_slice(&chunk);
        if bytes.len() >= MAX_BODY {
            break;
        }
    }
    Ok(HttpReply { url, status, body: String::from_utf8_lossy(&bytes).into_owned(), pin: if tls_pin.is_none() { pin.seen() } else { None } })
}

fn short_error(e: &anyhow::Error) -> String {
    let text = format!("{e:#}");
    if text.contains("connect") || text.contains("Connection refused") {
        "keine Verbindung (Port/Protokoll http/https richtig?)".into()
    } else if text.contains("timed out") || text.contains("timeout") {
        "Zeitüberschreitung".into()
    } else {
        text
    }
}

// ---------------------------------------------------------------------------
// Auswertung
// ---------------------------------------------------------------------------

/// Wert per JSON-Pfad („a.b.0.c“) lesen
fn json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.trim().trim_start_matches("$.").split('.').filter(|p| !p.is_empty()).try_fold(value, |v, key| match v {
        Value::Array(items) => key.parse::<usize>().ok().and_then(|i| items.get(i)),
        Value::Object(map) => map.get(key),
        _ => None,
    })
}

/// Erste Zahl im Text („Temp: 41,5 °C“ → 41.5)
fn first_number(text: &str) -> Option<f64> {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let starts = chars[i].is_ascii_digit() || (chars[i] == '-' && chars.get(i + 1).is_some_and(char::is_ascii_digit));
        if starts {
            let mut j = i + 1;
            while j < chars.len()
                && (chars[j].is_ascii_digit() || ((chars[j] == '.' || chars[j] == ',') && chars.get(j + 1).is_some_and(char::is_ascii_digit)))
            {
                j += 1;
            }
            let number: String = chars[i..j].iter().map(|c| if *c == ',' { '.' } else { *c }).collect();
            return number.parse().ok();
        }
        i += 1;
    }
    None
}

/// Wert aus der Antwort übernehmen
pub fn extract(raw: &str, rule: Option<&str>, value_type: &str) -> Result<(String, Option<f64>)> {
    let rule = rule.map(str::trim).filter(|r| !r.is_empty());
    let text = match rule {
        None => raw.trim().to_string(),
        Some(rule) => match serde_json::from_str::<Value>(raw) {
            Ok(json) => match json_path(&json, rule) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Null) | None => {
                    bail!("JSON-Pfad „{rule}“ nicht in der Antwort gefunden")
                }
                Some(other) => other.to_string(),
            },
            Err(_) => {
                let line = raw.lines().find(|l| l.contains(rule)).ok_or_else(|| anyhow!("„{rule}“ nicht in der Antwort gefunden"))?;
                let after = &line[line.find(rule).unwrap_or(0) + rule.len()..];
                after.trim().trim_start_matches([':', '=']).trim().to_string()
            }
        },
    };
    let text: String = text.chars().take(500).collect();
    if value_type == "number" {
        let n = if text.eq_ignore_ascii_case("true") {
            Some(1.0)
        } else if text.eq_ignore_ascii_case("false") {
            Some(0.0)
        } else {
            first_number(&text)
        };
        let n = n.ok_or_else(|| anyhow!("Keine Zahl im Wert „{}“ gefunden", text.chars().take(80).collect::<String>()))?;
        return Ok((text, Some(n)));
    }
    Ok((text, None))
}

fn clip(text: &str) -> String {
    if text.chars().count() > MAX_OUTPUT {
        format!("{} …", text.chars().take(MAX_OUTPUT).collect::<String>())
    } else {
        text.to_string()
    }
}

// ---------------------------------------------------------------------------
// Ausführen
// ---------------------------------------------------------------------------

/// Gerätedaten, die für eine Abfrage gebraucht werden
#[derive(sqlx::FromRow)]
struct Target {
    ip: String,
    label: String,
    ssh_host_key: Option<String>,
    tls_pin: Option<String>,
}

async fn load_target(state: &AppState, device_id: i64) -> Result<Target> {
    sqlx::query_as(
        "SELECT host(ip) AS ip, COALESCE(name, reported_name, hostname, host(ip)) AS label, ssh_host_key, tls_pin
           FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| anyhow!("Gerät nicht gefunden"))
}

/// Antwort holen (ohne Auswertung). Merkt SSH-Host-Schlüssel und TLS-Zertifikat beim ersten Kontakt.
async fn fetch(state: &AppState, q: &Query, cred: &Credential, device_id: i64, t: &Target) -> Result<String> {
    let ip: Ipv4Addr = t.ip.parse().map_err(|_| anyhow!("Nur IPv4 wird unterstützt"))?;
    let action = q.mode == "action";
    match protocol(&cred.kind) {
        Some("ssh") => {
            let result = ssh::run_command_status(ip, cred, t.ssh_host_key.as_deref(), q.target.trim()).await;
            match result {
                Ok((code, out, host_key)) => {
                    if t.ssh_host_key.is_none() && !host_key.is_empty() {
                        sqlx::query("UPDATE devices SET ssh_host_key = $2 WHERE id = $1 AND ssh_host_key IS NULL")
                            .bind(device_id)
                            .bind(host_key)
                            .execute(&state.db)
                            .await?;
                    }
                    // Beim Herunterfahren/Neustart beendet das Gerät oft die Verbindung, bevor ein Exit-Code kommt
                    if code != 0 && !(action && code == 255 && out.trim().is_empty()) {
                        bail!(
                            "Befehl endete mit Code {code}{}",
                            if out.trim().is_empty() { String::new() } else { format!(": {}", clip(out.trim())) }
                        );
                    }
                    Ok(out)
                }
                Err(ssh::SshError::HostKeyChanged { .. }) => {
                    bail!("SSH-Host-Schlüssel hat sich geändert – Befehl NICHT ausgeführt (beim Gerät zurücksetzen, falls neu installiert)")
                }
                Err(ssh::SshError::Failed(e)) => bail!("SSH: {e}"),
            }
        }
        Some("http") => {
            let reply = http_request(ip, cred, t.tls_pin.as_deref(), &q.method, &q.target, q.body.as_deref()).await?;
            if let Some(pin) = &reply.pin {
                sqlx::query("UPDATE devices SET tls_pin = $2 WHERE id = $1 AND tls_pin IS NULL").bind(device_id).bind(pin).execute(&state.db).await?;
            }
            if !reply.status.is_success() {
                let hint = match reply.status {
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => " – Anmeldung abgelehnt (Benutzer/Passwort/Token oder Rechte prüfen)",
                    StatusCode::NOT_FOUND => " – Pfad gibt es auf dem Gerät nicht",
                    _ => "",
                };
                bail!("{} antwortete mit {}{hint}", reply.url, reply.status);
            }
            Ok(reply.body)
        }
        Some("snmp") => {
            let oid = parse_oid(&q.target)?;
            let mut session = snmp::open(ip, cred).await?;
            let values = snmp::get(&mut session, &[&oid]).await?;
            if let Some(text) = values.first().and_then(|(_, v)| v.text()) {
                return Ok(text);
            }
            // Keine Einzel-OID → Tabelle/Teilbaum darunter lesen
            let rows = snmp::walk(&mut session, &oid, 200).await?;
            if rows.is_empty() {
                bail!("OID {} liefert keinen Wert (gibt es sie auf dem Gerät? Mit dem SNMP-Explorer nachsehen)", q.target.trim());
            }
            Ok(rows.iter().map(|(o, v)| format!("{} = {}", snmp::dotted(&o[oid.len()..]), v.describe().1)).collect::<Vec<_>>().join("\n"))
        }
        _ => bail!("Mit dieser Zugangsart sind keine eigenen Abfragen möglich"),
    }
}

/// Abfrage gegen ein Gerät ausführen und auswerten – ohne zu speichern (z. B. „Testen“ im Dialog)
pub async fn execute(state: &AppState, q: &Query, device_id: i64) -> Result<Outcome> {
    let cred = load_credential(state, q.credential_id).await?;
    validate(q, &cred.kind)?;
    let target = load_target(state, device_id).await?;
    let raw = tokio::time::timeout(Duration::from_secs(60), Box::pin(fetch(state, q, &cred, device_id, &target)))
        .await
        .map_err(|_| anyhow!("Zeitüberschreitung (60 s)"))?;
    let raw = match raw {
        Ok(raw) => raw,
        Err(e) => return Ok(Outcome { ok: false, message: format!("{e:#}"), ..Default::default() }),
    };
    let output = clip(&raw);
    if q.mode == "action" && q.extract.as_deref().is_none_or(|e| e.trim().is_empty()) {
        return Ok(Outcome {
            ok: true, message: format!("„{}“ auf {} ausgeführt", display_name(q), target.label), output, ..Default::default()
        });
    }
    match extract(&raw, q.extract.as_deref(), &q.value_type) {
        Ok((value, number)) => {
            let unit = q.unit.as_deref().map(|u| format!(" {u}")).unwrap_or_default();
            let shown: String = number.map(|n| n.to_string()).unwrap_or_else(|| value.chars().take(120).collect());
            Ok(Outcome { ok: true, message: format!("{}: {shown}{unit}", display_name(q)), value: Some(value), number, output })
        }
        Err(e) => Ok(Outcome { ok: false, message: format!("{e:#}"), output, ..Default::default() }),
    }
}

fn display_name(q: &Query) -> &str {
    if q.name.trim().is_empty() {
        q.target.trim()
    } else {
        q.name.trim()
    }
}

pub async fn load(state: &AppState, query_id: i64) -> Result<Query> {
    sqlx::query_as(&format!("SELECT {QUERY_COLUMNS} FROM custom_queries WHERE id = $1"))
        .bind(query_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| anyhow!("Abfrage nicht gefunden"))
}

/// Gilt die Abfrage für das Gerät? (Zugangsdaten zugeordnet oder Gerät ausdrücklich ausgewählt)
pub async fn applies(state: &AppState, q: &Query, device_id: i64) -> Result<bool> {
    if let Some(ids) = &q.device_ids {
        return Ok(ids.contains(&device_id));
    }
    let (linked,): (bool,) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM device_credentials WHERE device_id = $1 AND credential_id = $2)")
        .bind(device_id)
        .bind(q.credential_id)
        .fetch_one(&state.db)
        .await?;
    Ok(linked)
}

async fn store(state: &AppState, q: &Query, device_id: i64, outcome: &Outcome) -> Result<()> {
    sqlx::query(
        "INSERT INTO custom_query_results (query_id, device_id, time, ok, value_text, value_num, error)
         VALUES ($1, $2, now(), $3, $4, $5, $6)
         ON CONFLICT (query_id, device_id) DO UPDATE SET
            time = now(), ok = EXCLUDED.ok, error = EXCLUDED.error,
            -- letzten guten Wert behalten, damit die Anzeige bei einem Aussetzer nicht leer wird
            value_text = COALESCE(EXCLUDED.value_text, custom_query_results.value_text),
            value_num = COALESCE(EXCLUDED.value_num, custom_query_results.value_num)",
    )
    .bind(q.id)
    .bind(device_id)
    .bind(outcome.ok)
    .bind(outcome.value.as_deref().or((q.mode == "action" && outcome.ok).then_some(outcome.message.as_str())))
    .bind(outcome.number)
    .bind((!outcome.ok).then_some(outcome.message.as_str()))
    .execute(&state.db)
    .await?;
    if let (Some(n), "read") = (outcome.number, q.mode.as_str()) {
        sqlx::query("INSERT INTO custom_query_values (time, query_id, device_id, value) VALUES (now(), $1, $2, $3)")
            .bind(q.id)
            .bind(device_id)
            .bind(n)
            .execute(&state.db)
            .await?;
    }
    Ok(())
}

/// Gespeicherte Abfrage oder Aktion ausdrücklich ausführen und das Ergebnis speichern.
/// Für andere Funktionen (z. B. Herunterfahren nach Zeitplan): `custom::run(&state, query_id, device_id)`.
pub async fn run(state: &AppState, query_id: i64, device_id: i64) -> Result<Outcome> {
    let q = load(state, query_id).await?;
    if !applies(state, &q, device_id).await? {
        bail!("Diese Abfrage gilt nicht für das Gerät – Zugangsdaten dem Gerät zuordnen oder das Gerät in der Abfrage auswählen");
    }
    let outcome = execute(state, &q, device_id).await?;
    store(state, &q, device_id, &outcome).await?;
    let event = if q.mode == "action" { "custom_action" } else { "custom_query" };
    if q.mode == "action" {
        let text = if outcome.ok {
            format!("Aktion „{}“ ausgeführt", q.name)
        } else {
            format!("Aktion „{}“ fehlgeschlagen: {}", q.name, outcome.message)
        };
        crate::scanner::add_event(&state.db, device_id, event, &text).await?;
    }
    Ok(outcome)
}

/// Alle regelmäßigen Abfragen eines Geräts (aus der Inventar-Abfrage heraus). Liefert Protokollzeilen.
pub async fn run_for_device(state: &AppState, device_id: i64) -> Result<Vec<(bool, String)>> {
    let queries: Vec<Query> = sqlx::query_as(&format!(
        "SELECT {QUERY_COLUMNS} FROM custom_queries q
          WHERE q.enabled AND q.mode = 'read'
            AND (CASE WHEN q.device_ids IS NULL
                      THEN EXISTS (SELECT 1 FROM device_credentials dc WHERE dc.device_id = $1 AND dc.credential_id = q.credential_id)
                      ELSE $1 = ANY(q.device_ids) END)
          ORDER BY q.id"
    ))
    .bind(device_id)
    .fetch_all(&state.db)
    .await?;
    let mut lines = Vec::new();
    for q in queries {
        let outcome = match Box::pin(execute(state, &q, device_id)).await {
            Ok(o) => o,
            Err(e) => Outcome { ok: false, message: format!("{e:#}"), ..Default::default() },
        };
        store(state, &q, device_id, &outcome).await?;
        lines.push((outcome.ok, format!("Eigene Abfrage „{}“: {}", q.name, outcome.message)));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_pfad() {
        let raw = r#"{"data":{"temp":41.5,"disks":[{"name":"sda"}]},"ok":true}"#;
        assert_eq!(extract(raw, Some("data.temp"), "number").unwrap().1, Some(41.5));
        assert_eq!(extract(raw, Some("data.disks.0.name"), "text").unwrap().0, "sda");
        assert_eq!(extract(raw, Some("ok"), "number").unwrap().1, Some(1.0));
        assert!(extract(raw, Some("data.fehlt"), "text").is_err());
    }

    #[test]
    fn text_nach_marke() {
        let raw = "Model: DX4800\nTemperature: 41,5 °C\n";
        assert_eq!(extract(raw, Some("Temperature"), "number").unwrap().1, Some(41.5));
        assert_eq!(extract(raw, Some("Model:"), "text").unwrap().0, "DX4800");
        assert_eq!(extract(" 12345.67 89.0\n", None, "number").unwrap().1, Some(12345.67));
        assert_eq!(extract("load -3 x", None, "number").unwrap().1, Some(-3.0));
    }

    #[test]
    fn oid_pruefen() {
        assert_eq!(parse_oid(".1.3.6.1.2.1.1.3.0").unwrap().len(), 9);
        assert!(parse_oid("sysUpTime").is_err());
    }

    #[test]
    fn url_nur_zum_geraet() {
        let cred = Credential {
            id: 1,
            name: "x".into(),
            kind: "http_basic".into(),
            username: None,
            port: Some(8006),
            secret: Default::default(),
            linked: true,
            options: serde_json::json!({}),
        };
        let ip: Ipv4Addr = "192.168.1.10".parse().unwrap();
        assert_eq!(build_url(ip, &cred, "/api2/json/version").unwrap(), "https://192.168.1.10:8006/api2/json/version");
        assert!(build_url(ip, &cred, "https://example.org/steal").is_err());
        assert!(build_url(ip, &cred, "https://192.168.1.10:8006/x").is_ok());
        let plain = Credential { options: serde_json::json!({"scheme": "http"}), port: None, ..cred };
        assert_eq!(build_url(ip, &plain, "/status").unwrap(), "http://192.168.1.10/status");
    }
}
