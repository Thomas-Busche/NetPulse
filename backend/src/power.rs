//! Ein/Aus: Geräte aufwecken (Wake-on-LAN oder HTTP-Aufruf) und herunterfahren (SSH oder HTTP-Aufruf),
//! einzeln, für Gerätegruppen und nach Zeitplan.
//!
//! **Wake-on-LAN:** „Magic Packet“ (6 × 0xFF, dann 16 × die MAC-Adresse) per UDP-Broadcast an Port 9.
//! Ziele: die Broadcast-Adresse des freigegebenen Netzes, in dem das Gerät liegt, eine eigene Adresse
//! (z. B. für ein anderes VLAN, wenn der Router gerichtete Broadcasts weiterleitet) und 255.255.255.255.
//! Damit das Paket im LAN ankommt, muss der Container im Host-Netz laufen (`network_mode: host`, Standard).
//!
//! **Herunterfahren** hat keinen universellen Standard. Wege:
//! - SSH mit einer Zugangsangabe aus dem Tresor: Linux/NAS/Raspberry Pi über `shutdown`/`poweroff`
//!   (als root oder per `sudo` ohne Passwort für genau diesen Befehl), Windows (OpenSSH) über `shutdown /s`;
//!   alternativ ein eigener Befehl
//! - HTTP-Aufruf (z. B. Home Assistant, Shelly-Steckdose ausschalten, eigene Skripte), optional mit Benutzer/Passwort
//!
//! **Zeitpläne** laufen an gewählten Wochentagen zu einer Uhrzeit (Zeitzone aus `TZ`). Ein Termin wird
//! höchstens 15 Minuten nachgeholt (z. B. nach einem Neustart) – nie Stunden später.

use std::{net::Ipv4Addr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Datelike, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::net::UdpSocket;

use crate::{
    collect::{self, ssh, Credential, Secret},
    scanner, AppState,
};

/// Einstellungen je Gerät (Spalte `devices.power`)
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct PowerConfig {
    /// "wol" (Standard), "http" oder "none"
    pub wake: String,
    /// Abweichende MAC-Adresse für Wake-on-LAN (sonst die erkannte)
    pub wol_mac: Option<String>,
    /// Zusätzliche Broadcast-Adresse, z. B. 192.168.20.255 für ein anderes VLAN
    pub wol_broadcast: Option<String>,
    pub wol_port: Option<u16>,
    pub wake_url: Option<String>,
    /// "ssh" (Standard), "http" oder "none"
    pub shutdown: String,
    /// Eigener Befehl statt des automatischen
    pub shutdown_command: Option<String>,
    /// SSH-Zugangsangabe; leer = die dem Gerät zugeordnete
    pub ssh_credential_id: Option<i64>,
    pub shutdown_url: Option<String>,
    /// "GET" oder "POST" (Standard)
    pub http_method: Option<String>,
    /// Zugangsangabe für den HTTP-Aufruf (Benutzer + Passwort, Basic-Auth)
    pub http_credential_id: Option<i64>,
}

impl PowerConfig {
    pub fn wake_method(&self) -> &str {
        if self.wake.is_empty() { "wol" } else { &self.wake }
    }
    pub fn shutdown_method(&self) -> &str {
        if self.shutdown.is_empty() { "ssh" } else { &self.shutdown }
    }

    /// Prüfen und aufräumen (leere Texte → None)
    pub fn validate(mut self) -> Result<Self, String> {
        let clean = |v: &mut Option<String>| {
            *v = v.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        };
        clean(&mut self.wol_mac);
        clean(&mut self.wol_broadcast);
        clean(&mut self.wake_url);
        clean(&mut self.shutdown_command);
        clean(&mut self.shutdown_url);
        clean(&mut self.http_method);
        if !["", "wol", "http", "none"].contains(&self.wake.as_str()) {
            return Err("Unbekannte Art zum Aufwecken".into());
        }
        if !["", "ssh", "http", "none"].contains(&self.shutdown.as_str()) {
            return Err("Unbekannte Art zum Herunterfahren".into());
        }
        if let Some(mac) = &self.wol_mac {
            parse_mac(mac).ok_or_else(|| format!("„{mac}“ ist keine MAC-Adresse"))?;
        }
        if let Some(b) = &self.wol_broadcast {
            b.parse::<Ipv4Addr>().map_err(|_| format!("„{b}“ ist keine IPv4-Adresse"))?;
        }
        if self.wol_port == Some(0) {
            self.wol_port = None;
        }
        for url in [&self.wake_url, &self.shutdown_url].into_iter().flatten() {
            if !(url.starts_with("http://") || url.starts_with("https://")) || url.len() > 2000 {
                return Err("Die Adresse muss mit http:// oder https:// beginnen".into());
            }
        }
        if self.wake == "http" && self.wake_url.is_none() {
            return Err("Bitte eine Adresse zum Aufwecken angeben".into());
        }
        if self.shutdown == "http" && self.shutdown_url.is_none() {
            return Err("Bitte eine Adresse zum Herunterfahren angeben".into());
        }
        if self.shutdown_command.as_deref().is_some_and(|c| c.len() > 1000) {
            return Err("Befehl ist zu lang".into());
        }
        if let Some(m) = &self.http_method {
            let m = m.to_uppercase();
            if !["GET", "POST", "PUT"].contains(&m.as_str()) {
                return Err("HTTP-Methode: GET, POST oder PUT".into());
            }
            self.http_method = Some(m);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Wake,
    Shutdown,
}

impl Action {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "wake" => Some(Action::Wake),
            "shutdown" => Some(Action::Shutdown),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Action::Wake => "Aufwecken",
            Action::Shutdown => "Herunterfahren",
        }
    }
    fn event_kind(self) -> &'static str {
        match self {
            Action::Wake => "power_wake",
            Action::Shutdown => "power_shutdown",
        }
    }
}

/// Ergebnis je Gerät
#[derive(Serialize, Clone, Debug)]
pub struct Outcome {
    pub device_id: i64,
    pub label: String,
    /// true = ausgeführt, false = Fehler, None = übersprungen (z. B. schon an/aus)
    pub ok: Option<bool>,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Wake-on-LAN
// ---------------------------------------------------------------------------

/// „aa:bb:cc:dd:ee:ff“, „AA-BB-…“, „aabb.ccdd.eeff“ oder „aabbccddeeff“
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 || s.chars().any(|c| !(c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.' | ' '))) {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

pub fn magic_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut packet = [0xFFu8; 102];
    for i in 0..16 {
        packet[6 + i * 6..12 + i * 6].copy_from_slice(&mac);
    }
    packet
}

/// Sendet das Magic Packet dreimal an jedes Ziel; liefert die erreichten Ziele
pub async fn send_wol(mac: [u8; 6], targets: &[Ipv4Addr], port: u16) -> Result<Vec<String>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.context("UDP-Socket")?;
    socket.set_broadcast(true).context("Broadcast erlauben")?;
    let packet = magic_packet(mac);
    let mut sent = Vec::new();
    let mut last_error = None;
    for target in targets {
        let mut ok = false;
        for _ in 0..3 {
            match socket.send_to(&packet, (*target, port)).await {
                Ok(_) => ok = true,
                Err(e) => last_error = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        if ok {
            sent.push(format!("{target}:{port}"));
        }
    }
    if sent.is_empty() {
        bail!("Senden fehlgeschlagen: {}", last_error.map(|e| e.to_string()).unwrap_or_else(|| "kein Ziel".into()));
    }
    Ok(sent)
}

/// Broadcast-Ziele für ein Gerät: eigene Adresse, Broadcast der passenden freigegebenen Netze, 255.255.255.255
pub async fn wol_targets(db: &PgPool, ip: &str, cfg: &PowerConfig) -> Vec<Ipv4Addr> {
    let mut targets: Vec<Ipv4Addr> = Vec::new();
    if let Some(b) = cfg.wol_broadcast.as_deref().and_then(|b| b.parse().ok()) {
        targets.push(b);
    }
    let nets: Vec<(String,)> = sqlx::query_as(
        "SELECT host(broadcast(cidr)) FROM networks WHERE family(cidr) = 4 AND cidr >>= $1::inet ORDER BY masklen(cidr) DESC",
    )
    .bind(ip)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    for (b,) in nets {
        if let Ok(addr) = b.parse::<Ipv4Addr>() {
            if !targets.contains(&addr) {
                targets.push(addr);
            }
        }
    }
    if !targets.contains(&Ipv4Addr::BROADCAST) {
        targets.push(Ipv4Addr::BROADCAST);
    }
    targets
}

// ---------------------------------------------------------------------------
// Herunterfahren
// ---------------------------------------------------------------------------

/// POSIX-Skript (über `sh -s`): passenden Befehl suchen, Rechte prüfen, dann mit 2 s Verzögerung ausschalten –
/// so kommt die Antwort noch zurück, bevor die Verbindung abbricht.
const POSIX_SHUTDOWN: &str = r#"
CMD=""
for c in /sbin/shutdown /usr/sbin/shutdown /sbin/poweroff /usr/sbin/poweroff /bin/systemctl /usr/bin/systemctl; do
  [ -x "$c" ] && { CMD=$c; break; }
done
[ -z "$CMD" ] && { echo "FEHLT kein shutdown/poweroff gefunden"; exit 4; }
case "$CMD" in
  *shutdown) ARGS="-h now" ;;
  *systemctl) ARGS="poweroff" ;;
  *) ARGS="" ;;
esac
if [ "$(id -u)" = 0 ]; then S=""
elif command -v sudo >/dev/null 2>&1 && sudo -n -l $CMD $ARGS >/dev/null 2>&1; then S="sudo -n"
else echo "RECHTE $(id -un) darf $CMD $ARGS nicht ohne Passwort ausführen"; exit 3
fi
nohup sh -c "sleep 2; $S $CMD $ARGS" >/dev/null 2>&1 &
echo "OK $S $CMD $ARGS"
"#;

const WINDOWS_SHUTDOWN: &str = "shutdown /s /t 5 /f /c \"NetPulse: geplantes Herunterfahren\"";

#[derive(sqlx::FromRow)]
struct CredentialRow {
    id: i64,
    name: String,
    kind: String,
    username: Option<String>,
    port: Option<i32>,
    secret: String,
}

async fn load_credential(state: &AppState, id: i64) -> Result<Credential> {
    let row: Option<CredentialRow> = sqlx::query_as("SELECT id, name, kind, username, port, secret FROM credentials WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    let row = row.ok_or_else(|| anyhow!("Gewählte Zugangsdaten gibt es nicht mehr"))?;
    let secret: Secret = state.vault.open_value(&row.secret)?;
    Ok(Credential { id: row.id, name: row.name, kind: row.kind, username: row.username, port: row.port, secret, linked: true })
}

#[derive(sqlx::FromRow)]
struct Target {
    id: i64,
    ip: String,
    mac: Option<String>,
    label: String,
    status: String,
    os: Option<String>,
    ssh_host_key: Option<String>,
    #[sqlx(json)]
    power: PowerConfig,
}

async fn load_target(db: &PgPool, id: i64) -> Result<Target> {
    sqlx::query_as(
        "SELECT id, host(ip) AS ip, mac, COALESCE(name, reported_name, hostname, host(ip)) AS label, status,
                COALESCE(inventory->'ssh'->>'os', os) AS os, ssh_host_key, power
           FROM devices WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| anyhow!("Gerät nicht gefunden"))
}

async fn wake(state: &AppState, t: &Target) -> Result<String> {
    match t.power.wake_method() {
        "none" => bail!("Aufwecken ist für dieses Gerät ausgeschaltet"),
        "http" => http_call(state, &t.power, t.power.wake_url.as_deref().unwrap_or_default()).await,
        _ => {
            let mac_text = t.power.wol_mac.clone().or_else(|| t.mac.clone()).ok_or_else(|| {
                anyhow!("Keine MAC-Adresse bekannt – unter Ein/Aus eintragen (Gerät liegt evtl. hinter einem Router)")
            })?;
            let mac = parse_mac(&mac_text).ok_or_else(|| anyhow!("„{mac_text}“ ist keine gültige MAC-Adresse"))?;
            let targets = wol_targets(&state.db, &t.ip, &t.power).await;
            let sent = send_wol(mac, &targets, t.power.wol_port.unwrap_or(9)).await?;
            Ok(format!("Magic Packet an {mac_text} gesendet ({})", sent.join(", ")))
        }
    }
}

async fn shutdown(state: &AppState, t: &Target) -> Result<String> {
    match t.power.shutdown_method() {
        "none" => bail!("Herunterfahren ist für dieses Gerät ausgeschaltet"),
        "http" => http_call(state, &t.power, t.power.shutdown_url.as_deref().unwrap_or_default()).await,
        _ => shutdown_ssh(state, t).await,
    }
}

async fn shutdown_ssh(state: &AppState, t: &Target) -> Result<String> {
    let addr: Ipv4Addr = t.ip.parse().map_err(|_| anyhow!("Herunterfahren per SSH geht nur mit IPv4-Adresse"))?;
    let cred = match t.power.ssh_credential_id {
        Some(id) => load_credential(state, id).await?,
        None => collect::load_credentials(state, t.id)
            .await?
            .into_iter()
            .find(|c| c.linked && c.kind.starts_with("ssh"))
            .ok_or_else(|| anyhow!("Keine SSH-Zugangsdaten zugeordnet – unter Einstellungen → Zugangsdaten oder Ein/Aus wählen"))?,
    };
    if !cred.kind.starts_with("ssh") {
        bail!("„{}“ ist keine SSH-Zugangsangabe", cred.name);
    }
    let windows = t.os.as_deref().is_some_and(|o| o.to_lowercase().contains("windows"));
    let (command, script) = match (&t.power.shutdown_command, windows) {
        (Some(custom), _) => (custom.as_str(), None),
        (None, true) => (WINDOWS_SHUTDOWN, None),
        (None, false) => ("sh -s", Some(POSIX_SHUTDOWN)),
    };
    let (code, out, host_key) = match ssh::run_action(addr, &cred, t.ssh_host_key.as_deref(), command, script).await {
        Ok(r) => r,
        Err(ssh::SshError::HostKeyChanged { .. }) => {
            bail!("SSH-Host-Schlüssel hat sich geändert – abgebrochen (in den Geräte-Einstellungen zurücksetzen, falls neu installiert)")
        }
        Err(ssh::SshError::Failed(e)) => bail!("SSH mit „{}“: {e}", cred.name),
    };
    if t.ssh_host_key.is_none() && !host_key.is_empty() {
        let _ = sqlx::query("UPDATE devices SET ssh_host_key = $2 WHERE id = $1 AND ssh_host_key IS NULL")
            .bind(t.id)
            .bind(&host_key)
            .execute(&state.db)
            .await;
    }
    let out = out.trim();
    let short: String = out.chars().take(300).collect();
    if let Some(reason) = out.strip_prefix("RECHTE ") {
        bail!(
            "Keine Rechte: {reason}. Abhilfe: als root anmelden oder per sudoers erlauben, z. B. \
             „{} ALL=(root) NOPASSWD: /sbin/shutdown“",
            cred.username.as_deref().unwrap_or("netpulse")
        );
    }
    if let Some(reason) = out.strip_prefix("FEHLT ") {
        bail!("{reason}");
    }
    // Ein eigener Befehl darf die Verbindung trennen (dann kommt oft kein Exit-Code mehr)
    if code != 0 && !(t.power.shutdown_command.is_some() && code == 255) {
        bail!("Befehl endete mit Code {code}{}", if short.is_empty() { String::new() } else { format!(": {short}") });
    }
    Ok(if windows && t.power.shutdown_command.is_none() {
        format!("Windows fährt in 5 Sekunden herunter (SSH mit „{}“)", cred.name)
    } else if short.is_empty() {
        format!("Befehl gesendet (SSH mit „{}“)", cred.name)
    } else if let Some(cmd) = short.strip_prefix("OK ") {
        format!("Fährt in 2 Sekunden herunter: {} (SSH mit „{}“)", cmd.trim(), cred.name)
    } else {
        format!("{short} (SSH mit „{}“)", cred.name)
    })
}

async fn http_call(state: &AppState, cfg: &PowerConfig, url: &str) -> Result<String> {
    if url.is_empty() {
        bail!("Keine Adresse hinterlegt");
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("NetPulse/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let method = cfg.http_method.as_deref().unwrap_or("POST");
    let mut request = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        _ => client.post(url),
    };
    if let Some(id) = cfg.http_credential_id {
        let cred = load_credential(state, id).await?;
        request = request.basic_auth(cred.username.clone().unwrap_or_default(), cred.secret.password.clone());
    }
    let response = request.send().await.map_err(|e| anyhow!("Aufruf fehlgeschlagen: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("Antwort {status}");
    }
    Ok(format!("{method} {} → {status}", strip_query(url)))
}

/// Für Meldungen: Abfrage-Teil (oft mit Schlüsseln) weglassen
fn strip_query(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

// ---------------------------------------------------------------------------
// Ausführen (Knopf, Gruppe, Zeitplan)
// ---------------------------------------------------------------------------

/// Aktion für ein Gerät ausführen und als Ereignis festhalten.
/// `skip_if_done`: bei Zeitplänen nichts tun, wenn das Gerät schon an (bzw. aus) ist.
pub async fn execute(state: &AppState, device_id: i64, action: Action, skip_if_done: bool, origin: &str) -> Outcome {
    let target = match load_target(&state.db, device_id).await {
        Ok(t) => t,
        Err(e) => return Outcome { device_id, label: format!("#{device_id}"), ok: Some(false), message: format!("{e:#}") },
    };
    if skip_if_done {
        let done = match action {
            Action::Wake => target.status == "up",
            Action::Shutdown => target.status == "down",
        };
        if done {
            let message = if action == Action::Wake { "läuft bereits" } else { "ist bereits aus" };
            return Outcome { device_id, label: target.label, ok: None, message: message.into() };
        }
    }
    let result = match action {
        Action::Wake => wake(state, &target).await,
        Action::Shutdown => shutdown(state, &target).await,
    };
    let (ok, message) = match result {
        Ok(m) => (true, m),
        Err(e) => (false, format!("{e:#}")),
    };
    let text = format!("{} ({origin}) {}: {message}", action.label(), if ok { "ausgeführt" } else { "fehlgeschlagen" });
    let _ = scanner::add_event(&state.db, device_id, action.event_kind(), &text).await;
    if ok {
        tracing::info!("{}: {text}", target.label);
    } else {
        tracing::warn!("{}: {text}", target.label);
    }
    Outcome { device_id, label: target.label, ok: Some(ok), message }
}

pub async fn execute_many(state: &AppState, ids: Vec<i64>, action: Action, skip_if_done: bool, origin: &str) -> Vec<Outcome> {
    stream::iter(ids)
        .map(|id| execute(state, id, action, skip_if_done, origin))
        .buffer_unordered(16)
        .collect()
        .await
}

/// Geräte + alle Mitglieder der Gruppen, ohne Doppelte
pub async fn resolve(db: &PgPool, device_ids: &[i64], group_ids: &[i64]) -> sqlx::Result<Vec<i64>> {
    let ids: Vec<(i64,)> = sqlx::query_as(
        "SELECT id FROM devices WHERE id = ANY($1)
          UNION SELECT device_id FROM device_group_members WHERE group_id = ANY($2)
          ORDER BY 1",
    )
    .bind(device_ids)
    .bind(group_ids)
    .fetch_all(db)
    .await?;
    Ok(ids.into_iter().map(|(id,)| id).collect())
}

pub fn summarize(outcomes: &[Outcome]) -> String {
    let ok = outcomes.iter().filter(|o| o.ok == Some(true)).count();
    let failed = outcomes.iter().filter(|o| o.ok == Some(false)).count();
    let skipped = outcomes.iter().filter(|o| o.ok.is_none()).count();
    let mut text = format!("{ok} ausgeführt");
    if failed > 0 {
        let names: Vec<&str> = outcomes.iter().filter(|o| o.ok == Some(false)).map(|o| o.label.as_str()).take(5).collect();
        text.push_str(&format!(", {failed} fehlgeschlagen ({})", names.join(", ")));
    }
    if skipped > 0 {
        text.push_str(&format!(", {skipped} übersprungen"));
    }
    if outcomes.is_empty() {
        text = "keine Geräte".into();
    }
    text
}

// ---------------------------------------------------------------------------
// Zeitpläne
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, sqlx::FromRow, Clone, Debug)]
pub struct Schedule {
    pub id: i64,
    pub name: String,
    pub action: String,
    pub days: Vec<i32>,
    pub time: String,
    pub device_ids: Vec<i64>,
    pub group_ids: Vec<i64>,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_result: Option<String>,
}

pub const SELECT_SCHEDULES: &str =
    "SELECT id, name, action, days, time, device_ids, group_ids, enabled, last_run_at, last_result FROM power_schedules";

/// Wie lange ein verpasster Termin noch nachgeholt wird
const CATCH_UP_MIN: i64 = 15;

impl Schedule {
    /// Fälliger Termin (UTC), falls zwischen „jetzt − 15 min“ und „jetzt“ einer lag
    pub fn due_slot(&self, now: DateTime<Utc>, tz: Tz) -> Option<DateTime<Utc>> {
        let time = NaiveTime::parse_from_str(self.time.trim(), "%H:%M").ok()?;
        let local_today = now.with_timezone(&tz).date_naive();
        // heute und gestern (Termin kurz vor Mitternacht, geprüft kurz danach)
        for date in [local_today, local_today.pred_opt()?] {
            if !self.days.contains(&(date.weekday().number_from_monday() as i32)) {
                continue;
            }
            let Some(slot) = tz.from_local_datetime(&date.and_time(time)).earliest() else { continue };
            let slot = slot.with_timezone(&Utc);
            if slot <= now && now - slot < chrono::Duration::minutes(CATCH_UP_MIN) {
                return Some(slot);
            }
        }
        None
    }

    /// Nächster Termin (für die Anzeige)
    pub fn next_run(&self, now: DateTime<Utc>, tz: Tz) -> Option<DateTime<Utc>> {
        if !self.enabled {
            return None;
        }
        let time = NaiveTime::parse_from_str(self.time.trim(), "%H:%M").ok()?;
        let mut date = now.with_timezone(&tz).date_naive();
        for _ in 0..8 {
            if self.days.contains(&(date.weekday().number_from_monday() as i32)) {
                if let Some(slot) = tz.from_local_datetime(&date.and_time(time)).earliest() {
                    let slot = slot.with_timezone(&Utc);
                    if slot > now {
                        return Some(slot);
                    }
                }
            }
            date = date.succ_opt()?;
        }
        None
    }
}

/// Hintergrund-Task: prüft alle 30 s, ob ein Zeitplan fällig ist
pub async fn run(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;
        if let Err(e) = run_due(&state).await {
            tracing::warn!("Ein/Aus-Zeitpläne: {e:#}");
        }
    }
}

async fn run_due(state: &AppState) -> Result<()> {
    let schedules: Vec<Schedule> = sqlx::query_as(&format!("{SELECT_SCHEDULES} WHERE enabled")).fetch_all(&state.db).await?;
    let now = Utc::now();
    let tz = scanner::schedule::timezone();
    for s in schedules {
        let Some(slot) = s.due_slot(now, tz) else { continue };
        if s.last_run_at.is_some_and(|last| last >= slot) {
            continue;
        }
        // Erst vermerken, dann ausführen – so läuft ein Termin nie doppelt
        let claimed = sqlx::query(
            "UPDATE power_schedules SET last_run_at = $2 WHERE id = $1 AND (last_run_at IS NULL OR last_run_at < $3)",
        )
        .bind(s.id)
        .bind(now)
        .bind(slot)
        .execute(&state.db)
        .await?
        .rows_affected();
        if claimed == 0 {
            continue;
        }
        let state = state.clone();
        tokio::spawn(async move { run_schedule(&state, &s, true).await });
    }
    Ok(())
}

/// Zeitplan ausführen (`skip_if_done`: Geräte, die schon an/aus sind, überspringen)
pub async fn run_schedule(state: &AppState, s: &Schedule, skip_if_done: bool) -> Vec<Outcome> {
    let Some(action) = Action::parse(&s.action) else { return vec![] };
    let ids = resolve(&state.db, &s.device_ids, &s.group_ids).await.unwrap_or_default();
    let outcomes = execute_many(state, ids, action, skip_if_done, &format!("Zeitplan „{}“", s.name)).await;
    let summary = summarize(&outcomes);
    tracing::info!("Zeitplan „{}“ ({}): {summary}", s.name, action.label());
    let _ = sqlx::query("UPDATE power_schedules SET last_result = $2 WHERE id = $1")
        .bind(s.id)
        .bind(&summary)
        .execute(&state.db)
        .await;
    outcomes
}

/// Kurzbeschreibung für die API (Status „läuft“, nächster Termin)
pub fn describe(s: &Schedule) -> Value {
    let mut v = json!(s);
    v["next_run"] = json!(s.next_run(Utc::now(), scanner::schedule::timezone()));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formats() {
        let want = Some([0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]);
        assert_eq!(parse_mac("aa:bb:cc:01:02:03"), want);
        assert_eq!(parse_mac("AA-BB-CC-01-02-03"), want);
        assert_eq!(parse_mac("aabb.cc01.0203"), want);
        assert_eq!(parse_mac("aabbcc010203"), want);
        assert_eq!(parse_mac("aa:bb:cc:01:02"), None);
        assert_eq!(parse_mac("zz:bb:cc:01:02:03"), None);
    }

    #[test]
    fn packet_layout() {
        let mac = [1, 2, 3, 4, 5, 6];
        let p = magic_packet(mac);
        assert_eq!(&p[..6], &[0xFF; 6]);
        assert_eq!(&p[6..12], &mac);
        assert_eq!(&p[96..102], &mac);
    }

    fn schedule(days: Vec<i32>, time: &str) -> Schedule {
        Schedule {
            id: 1,
            name: "t".into(),
            action: "shutdown".into(),
            days,
            time: time.into(),
            device_ids: vec![],
            group_ids: vec![],
            enabled: true,
            last_run_at: None,
            last_result: None,
        }
    }

    #[test]
    fn due_and_next() {
        let tz = chrono_tz::Europe::Berlin;
        // Freitag, 14.11.2026, 22:05 Ortszeit (21:05 UTC)
        let now = Utc.with_ymd_and_hms(2026, 11, 14, 21, 5, 0).unwrap();
        let s = schedule(vec![5, 6], "22:00");
        // 14.11.2026 ist ein Samstag (6)
        assert_eq!(s.due_slot(now, tz), Some(Utc.with_ymd_and_hms(2026, 11, 14, 21, 0, 0).unwrap()));
        // 20 Minuten später: nicht mehr nachholen
        assert_eq!(s.due_slot(now + chrono::Duration::minutes(20), tz), None);
        // falscher Wochentag
        assert_eq!(schedule(vec![1], "22:00").due_slot(now, tz), None);
        // über Mitternacht: Termin 23:55 am Samstag, geprüft Sonntag 00:05
        let after_midnight = Utc.with_ymd_and_hms(2026, 11, 14, 23, 5, 0).unwrap();
        assert!(schedule(vec![6], "23:55").due_slot(after_midnight, tz).is_some());
        // nächster Termin: Montag 07:00 → 16.11. 06:00 UTC
        assert_eq!(schedule(vec![1], "07:00").next_run(now, tz), Some(Utc.with_ymd_and_hms(2026, 11, 16, 6, 0, 0).unwrap()));
    }
}
