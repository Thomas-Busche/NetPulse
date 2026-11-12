//! Verbundene Programme („Zahnräder“): Andere Werkzeuge im Heimnetz – z. B. der Docker Backup Manager –
//! melden sich mit einem eigenen Schlüssel bei NetPulse und können
//!
//! - **Überwachung pausieren**, solange sie Container für ein Backup stoppen. Betroffene Geräte und Dienste
//!   werden dann gar nicht geprüft: keine Messwerte, keine Ereignisse, keine Alarme, kein Abzug bei der
//!   Verfügbarkeit. Jede Pause hat ein spätestes Ende – meldet sich das Programm nicht zurück (Absturz),
//!   läuft die Überwachung von selbst weiter.
//! - **Ergebnisse melden** (Backup erfolgreich/fehlgeschlagen) – dafür gibt es eigene Alarm-Regeln.
//! - **Ihre Container melden** (Inventar), damit man vorab sieht und einstellen kann, welche Dienste und
//!   Geräte in NetPulse zu welchem Container gehören.
//!
//! Der Schlüssel erlaubt nur diese Dinge – keinen Zugriff auf Geräte, Zugangsdaten oder Einstellungen.
//! In der Datenbank liegt er nur als SHA-256-Hash.

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};

use crate::AppState;

/// Bedingung „Gerät `devices.id` ist gerade nicht pausiert“ (für die Erreichbarkeitsprüfung)
pub const DEVICE_NOT_PAUSED: &str =
    "NOT EXISTS (SELECT 1 FROM integration_pauses p WHERE p.until > now() AND devices.id = ANY(p.device_ids))";
/// Bedingung „Dienst `checks.id` ist gerade nicht pausiert“
pub const CHECK_NOT_PAUSED: &str =
    "NOT EXISTS (SELECT 1 FROM integration_pauses p WHERE p.until > now() AND checks.id = ANY(p.check_ids))";

/// Längste erlaubte Pause (Sicherheitsnetz gegen „vergessene“ Pausen)
pub const MAX_PAUSE_MIN: i64 = 12 * 60;
/// Nachlaufzeit nach „fertig“, bis wieder geprüft wird (Container brauchen eine Weile zum Hochfahren)
pub const DEFAULT_GRACE_S: i64 = 180;

// ---------------------------------------------------------------------------
// Schlüssel
// ---------------------------------------------------------------------------

/// Neuer Schlüssel: `npi_` + 256 Bit Zufall (hex). Liefert (Schlüssel, Hash, Kurzform zum Wiedererkennen).
pub fn new_token() -> (String, Vec<u8>, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = format!("npi_{}", hex::encode(bytes));
    let hint = format!("npi_…{}", &token[token.len() - 4..]);
    let hash = token_hash(&token);
    (token, hash, hint)
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.trim().as_bytes()).to_vec()
}

// ---------------------------------------------------------------------------
// Inventar & automatische Zuordnung
// ---------------------------------------------------------------------------

/// Ein Container bzw. eine Aufgabe, wie das Programm sie meldet
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Subject {
    pub name: String,
    /// Compose-Projekt (z. B. „immich“ für immich_server, immich_postgres …)
    #[serde(default)]
    pub project: Option<String>,
    /// eigene IP-Adressen (macvlan/ipvlan – dann ist der Container ein eigenes Gerät im Netz)
    #[serde(default)]
    pub ips: Vec<String>,
    /// auf dem Host veröffentlichte Ports
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub running: Option<bool>,
    /// Wird regelmäßig gesichert (für die Regel „Kein aktuelles Backup“)
    #[serde(default)]
    pub scheduled: Option<bool>,
}

impl Subject {
    pub fn clean(mut self) -> Option<Self> {
        self.name = self.name.trim().chars().filter(|c| !c.is_control()).take(200).collect();
        if self.name.is_empty() {
            return None;
        }
        self.project = self.project.map(|p| p.trim().chars().take(200).collect::<String>()).filter(|p| !p.is_empty());
        self.image = self.image.map(|p| p.chars().take(300).collect());
        self.ips.retain(|ip| ip.parse::<IpAddr>().is_ok());
        self.ips.truncate(16);
        self.ports.sort_unstable();
        self.ports.dedup();
        self.ports.truncate(64);
        Some(self)
    }
}

#[derive(FromRow, Clone)]
pub struct DeviceRef {
    pub id: i64,
    pub ip: String,
    pub label: String,
}

#[derive(FromRow, Clone)]
pub struct CheckRef {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub device_id: Option<i64>,
}

/// Gefundene Zuordnung mit Begründung (für die Anzeige)
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Match {
    /// "device" oder "check"
    pub kind: &'static str,
    pub id: i64,
    pub label: String,
    pub why: String,
}

/// Allgemeine Wörter, die zu viele falsche Treffer ergäben
const STOPWORDS: &[&str] = &[
    "server", "service", "dienst", "home", "test", "proxy", "admin", "port", "check", "status", "http", "https", "webseite",
    "login", "intern", "extern", "local", "main", "data", "database", "datenbank", "docker", "container", "backup", "web",
    "worker", "redis", "postgres", "mariadb", "mysql", "nginx", "latest", "stable", "beta", "dev",
];

/// Bedeutungstragende Wörter (Kleinbuchstaben, mind. 4 Zeichen, keine Allerweltswörter)
fn words(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= 4 && !STOPWORDS.contains(w) && !w.chars().all(|c| c.is_ascii_digit()))
        .map(str::to_string)
        .collect()
}

/// Passen zwei Wörter zusammen? Gleich, oder das kürzere (≥ 5 Zeichen) steckt im längeren
/// („cloud“ ↔ „nextcloud“, „immich“ ↔ „immichserver“)
fn word_match(a: &str, b: &str) -> bool {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    short == long || (short.chars().count() >= 5 && long.contains(short))
}

/// Host und Port aus dem Ziel eines Dienst-Checks
pub fn target_host_port(kind: &str, target: &str) -> Option<(String, Option<u16>)> {
    let t = target.trim();
    match kind {
        "http" => {
            let url = reqwest::Url::parse(t).ok()?;
            Some((url.host_str()?.trim_matches(['[', ']']).to_lowercase(), url.port_or_known_default()))
        }
        "tcp" | "tls" => {
            if let Ok(sa) = t.parse::<std::net::SocketAddr>() {
                return Some((sa.ip().to_string(), Some(sa.port())));
            }
            match t.rsplit_once(':') {
                Some((h, p)) => Some((h.trim_matches(['[', ']']).to_lowercase(), p.parse().ok())),
                None => Some((t.to_lowercase(), if kind == "tls" { Some(443) } else { None })),
            }
        }
        _ => None,
    }
}

/// Welche Geräte und Dienste gehören zu diesem Container? `host_ips`: Adressen des Docker-Hosts.
pub fn auto_match(s: &Subject, host_ips: &[String], devices: &[DeviceRef], checks: &[CheckRef]) -> Vec<Match> {
    let mut out: Vec<Match> = Vec::new();
    let mut subject_words = words(&s.name);
    if let Some(p) = &s.project {
        subject_words.extend(words(p));
    }

    // Eigene IP des Containers = eigenes Gerät in NetPulse
    let own_devices: Vec<&DeviceRef> = devices.iter().filter(|d| s.ips.contains(&d.ip)).collect();
    for d in &own_devices {
        out.push(Match { kind: "device", id: d.id, label: d.label.clone(), why: format!("eigene IP-Adresse {}", d.ip) });
    }

    let own_ids: Vec<i64> = own_devices.iter().map(|d| d.id).collect();
    for c in checks {
        if let Some(why) = check_reason(c, s, host_ips, &own_ids, &subject_words) {
            out.push(Match { kind: "check", id: c.id, label: c.name.clone(), why });
        }
    }
    out
}

/// Warum gehört dieser Dienst-Check zum Container? (None = gehört nicht dazu)
fn check_reason(c: &CheckRef, s: &Subject, host_ips: &[String], own_ids: &[i64], subject_words: &[String]) -> Option<String> {
    if c.device_id.is_some_and(|id| own_ids.contains(&id)) {
        return Some("gehört zum Gerät des Containers".to_string());
    }
    let target = target_host_port(&c.kind, &c.target);
    if let Some((host, port)) = &target {
        if s.ips.contains(host) {
            return Some(format!("Ziel ist die IP des Containers ({host})"));
        }
        if let Some(port) = port {
            if host_ips.contains(host) && s.ports.contains(port) {
                return Some(format!("veröffentlichter Port {port} auf dem Docker-Host"));
            }
        }
    }
    // Namen: Check-Name und erster Teil des Hostnamens (cloud.example.de → „cloud“)
    let mut check_words = words(&c.name);
    if let Some((host, _)) = &target {
        if host.parse::<IpAddr>().is_err() {
            if let Some(first) = host.split('.').next() {
                check_words.extend(words(first));
            }
        }
    }
    check_words
        .iter()
        .find_map(|cw| subject_words.iter().find(|sw| word_match(cw, sw)).map(|sw| format!("Name passt („{cw}“ ↔ „{sw}“)")))
}

#[derive(FromRow, Clone)]
pub struct Link {
    pub subject: String,
    pub device_ids: Vec<i64>,
    pub check_ids: Vec<i64>,
    pub auto: bool,
}

/// Alles, was zum Zuordnen nötig ist (einmal laden, für viele Container verwenden)
pub struct Context {
    pub host_ips: Vec<String>,
    pub devices: Vec<DeviceRef>,
    pub checks: Vec<CheckRef>,
    pub links: BTreeMap<String, Link>,
}

impl Context {
    pub async fn load(db: &PgPool, integration_id: i64) -> sqlx::Result<Self> {
        let host_ips: Vec<String> = sqlx::query_as::<_, (String,)>(
            "SELECT host(d.ip) FROM integrations i JOIN devices d ON d.id = i.host_device_id WHERE i.id = $1",
        )
        .bind(integration_id)
        .fetch_all(db)
        .await?
        .into_iter()
        .map(|r| r.0)
        .collect();
        let devices: Vec<DeviceRef> =
            sqlx::query_as("SELECT id, host(ip) AS ip, COALESCE(name, reported_name, hostname, host(ip)) AS label FROM devices")
                .fetch_all(db)
                .await?;
        let checks: Vec<CheckRef> = sqlx::query_as("SELECT id, name, kind, target, device_id FROM checks").fetch_all(db).await?;
        let links: Vec<Link> =
            sqlx::query_as("SELECT subject, device_ids, check_ids, auto FROM integration_links WHERE integration_id = $1")
                .bind(integration_id)
                .fetch_all(db)
                .await?;
        Ok(Self { host_ips, devices, checks, links: links.into_iter().map(|l| (l.subject.clone(), l)).collect() })
    }

    /// Zuordnung für einen Container: von Hand festgelegte plus (sofern nicht abgeschaltet) automatische
    pub fn resolve(&self, s: &Subject) -> Vec<Match> {
        let link = self.links.get(&s.name);
        let mut out = if link.is_none_or(|l| l.auto) { auto_match(s, &self.host_ips, &self.devices, &self.checks) } else { Vec::new() };
        if let Some(l) = link {
            for id in &l.device_ids {
                if let Some(d) = self.devices.iter().find(|d| d.id == *id) {
                    if !out.iter().any(|m| m.kind == "device" && m.id == *id) {
                        out.push(Match { kind: "device", id: *id, label: d.label.clone(), why: "von Hand zugeordnet".into() });
                    }
                }
            }
            for id in &l.check_ids {
                if let Some(c) = self.checks.iter().find(|c| c.id == *id) {
                    if !out.iter().any(|m| m.kind == "check" && m.id == *id) {
                        out.push(Match { kind: "check", id: *id, label: c.name.clone(), why: "von Hand zugeordnet".into() });
                    }
                }
            }
        }
        out
    }
}

/// Gemeldeten Container um bekannte Angaben aus dem Inventar ergänzen (das Programm darf auch nur Namen schicken)
pub fn complete(s: Subject, inventory: &[Subject]) -> Subject {
    match inventory.iter().find(|i| i.name == s.name) {
        Some(known) => Subject {
            project: s.project.or_else(|| known.project.clone()),
            ips: if s.ips.is_empty() { known.ips.clone() } else { s.ips },
            ports: if s.ports.is_empty() { known.ports.clone() } else { s.ports },
            image: s.image.or_else(|| known.image.clone()),
            ..s
        },
        None => s,
    }
}

// ---------------------------------------------------------------------------
// Pflege
// ---------------------------------------------------------------------------

/// Stündlich: alte Pausen und Meldungen löschen (Datensparsamkeit)
pub async fn run(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let _ = sqlx::query("DELETE FROM integration_pauses WHERE until < now() - interval '90 days'").execute(&state.db).await;
        let _ = sqlx::query("DELETE FROM integration_reports WHERE time < now() - interval '400 days'").execute(&state.db).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(name: &str, project: Option<&str>) -> Subject {
        Subject { name: name.into(), project: project.map(Into::into), ..Default::default() }
    }

    fn check(id: i64, name: &str, kind: &str, target: &str) -> CheckRef {
        CheckRef { id, name: name.into(), kind: kind.into(), target: target.into(), device_id: None }
    }

    #[test]
    fn ziele() {
        assert_eq!(target_host_port("http", "https://cloud.example.de/status"), Some(("cloud.example.de".into(), Some(443))));
        assert_eq!(target_host_port("http", "http://10.10.10.15:2283"), Some(("10.10.10.15".into(), Some(2283))));
        assert_eq!(target_host_port("tcp", "10.10.10.15:5432"), Some(("10.10.10.15".into(), Some(5432))));
        assert_eq!(target_host_port("tls", "nas.local"), Some(("nas.local".into(), Some(443))));
        assert_eq!(target_host_port("dns", "example.de"), None);
    }

    #[test]
    fn zuordnung() {
        let checks = vec![
            check(1, "Nextcloud", "http", "https://cloud.example.org"),
            check(2, "Immich Fotos", "http", "http://10.10.10.15:2283"),
            check(3, "Home Assistant", "http", "http://10.10.10.20:8123"),
            check(4, "Webseite", "http", "https://www.example.de"),
            check(5, "UniFi", "tcp", "10.10.10.6:443"),
        ];
        let devices = vec![DeviceRef { id: 9, ip: "10.10.10.6".into(), label: "UniFi OS".into() }];
        let host = vec!["10.10.10.15".to_string()];
        let ids = |s: &Subject| auto_match(s, &host, &devices, &checks).iter().map(|m| (m.kind, m.id)).collect::<Vec<_>>();

        // Name: „nextcloud“ steckt im Containernamen, auch bei der Datenbank von Nextcloud AIO
        assert_eq!(ids(&subject("nextcloud-aio-database", None)), vec![("check", 1)]);
        // Port auf dem Docker-Host
        let mut immich_db = subject("immich_postgres", Some("immich"));
        assert_eq!(ids(&immich_db), vec![("check", 2)], "über das Compose-Projekt");
        immich_db.project = None;
        immich_db.ports = vec![2283];
        assert_eq!(ids(&immich_db), vec![("check", 2)], "über den veröffentlichten Port");
        // eigene IP → Gerät und dessen Dienste
        let mut unifi = subject("unifi-os-server", None);
        unifi.ips = vec!["10.10.10.6".into()];
        assert_eq!(ids(&unifi), vec![("device", 9), ("check", 5)]);
        // keine Zufallstreffer über Allerweltswörter
        assert!(ids(&subject("homepage", None)).is_empty());
        assert!(ids(&subject("redis", None)).is_empty());
        assert!(ids(&subject("web", Some("webseite"))).is_empty());
    }
}
