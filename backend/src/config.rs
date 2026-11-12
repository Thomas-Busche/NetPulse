//! Konfiguration über Umgebungsvariablen (werden in docker-compose.yml bzw. .env gesetzt).

use std::{env, str::FromStr, time::Duration};

use anyhow::{anyhow, Context, Result};

// Bewusst kein `Debug`: Die Struktur enthält Passwörter, die nie in Logs landen sollen.
pub struct Config {
    pub database_url: String,
    pub listen_addr: String,
    pub web_dir: String,
    /// Cookie nur über HTTPS senden (hinter dem Caddy-Proxy immer der Fall)
    pub cookie_secure: bool,
    pub session_hours: i32,
    pub discovery_interval: Duration,
    pub monitor_interval: Duration,
    pub metrics_retention_days: i32,
    pub events_retention_days: i32,
    pub audit_retention_days: i32,
    pub initial_networks: Vec<String>,
    /// Ablage für den Tresor-Schlüssel (Docker-Volume)
    pub data_dir: String,
    /// Tresor-Schlüssel direkt vorgeben (64 Hex-Zeichen); sonst wird er in `data_dir` erzeugt
    pub secret_key: Option<String>,
    /// Abstand der tiefen Abfragen (SNMP/SSH)
    pub inventory_interval: Duration,
    /// Öffentliche Adresse der Oberfläche – für Links in Benachrichtigungen
    pub public_url: Option<String>,
    /// Syslog-Empfang (UDP), 0 = aus
    pub syslog_port: u16,
    /// SNMP-Trap-Empfang (UDP), 0 = aus
    pub trap_port: u16,
    /// Erlaubte Trap-Communities (leer = alle)
    pub trap_communities: Vec<String>,
    pub syslog_retention_days: i32,
    /// Zwei-Faktor-Anmeldung für alle Benutzer erzwingen (fest, in der Oberfläche nicht abschaltbar)
    pub require_totp: bool,
    /// Größe des Datenbank-Verbindungspools
    pub db_max_connections: u32,
    /// So viele fehlgeschlagene Prüfungen in Folge, bevor ein Gerät als „down“ gilt (dämpft Flattern)
    pub monitor_fail_threshold: i32,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: env::var("DATABASE_URL").context("Umgebungsvariable DATABASE_URL fehlt")?,
            listen_addr: string("LISTEN_ADDR", "127.0.0.1:8080"),
            web_dir: string("WEB_DIR", "./web"),
            cookie_secure: !matches!(optional("COOKIE_SECURE").as_deref(), Some("false" | "0" | "no")),
            session_hours: number("SESSION_HOURS", 12)?,
            discovery_interval: Duration::from_secs(60 * number::<u64>("DISCOVERY_INTERVAL_MIN", 15)?.max(1)),
            monitor_interval: Duration::from_secs(number::<u64>("MONITOR_INTERVAL_SEC", 60)?.max(10)),
            metrics_retention_days: number("RETENTION_METRICS_DAYS", 90)?,
            events_retention_days: number("RETENTION_EVENTS_DAYS", 180)?,
            audit_retention_days: number("RETENTION_AUDIT_DAYS", 365)?,
            initial_networks: optional("SCAN_NETWORKS")
                .map(|s| s.split(',').map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).collect())
                .unwrap_or_default(),
            data_dir: string("DATA_DIR", "/data"),
            secret_key: optional("SECRET_KEY"),
            inventory_interval: Duration::from_secs(60 * number::<u64>("INVENTORY_INTERVAL_MIN", 5)?.max(1)),
            public_url: optional("PUBLIC_URL")
                .or_else(|| optional("SITE_ADDRESS"))
                .map(|u| u.trim_end_matches('/').to_string()),
            syslog_port: number("SYSLOG_PORT", 5514)?,
            trap_port: number("TRAP_PORT", 1162)?,
            trap_communities: optional("TRAP_COMMUNITY")
                .map(|s| s.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect())
                .unwrap_or_default(),
            syslog_retention_days: number("RETENTION_SYSLOG_DAYS", 30)?,
            require_totp: matches!(optional("REQUIRE_TOTP").as_deref(), Some("true" | "1" | "yes")),
            db_max_connections: number::<u32>("DB_MAX_CONNECTIONS", 20)?.clamp(5, 500),
            monitor_fail_threshold: number::<i32>("MONITOR_FAIL_THRESHOLD", 2)?.clamp(1, 20),
        })
    }
}

fn optional(key: &str) -> Option<String> {
    env::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn string(key: &str, default: &str) -> String {
    optional(key).unwrap_or_else(|| default.to_string())
}

/// Liest eine Zahl; `T` ist der gewünschte Zahlentyp (z. B. u64 oder i32).
fn number<T: FromStr>(key: &str, default: T) -> Result<T> {
    match optional(key) {
        Some(v) => v.parse().map_err(|_| anyhow!("{key}: ungültiger Wert '{v}'")),
        None => Ok(default),
    }
}
