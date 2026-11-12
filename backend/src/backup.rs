//! Sicherung und Wiederherstellung der Konfiguration.
//!
//! Eine Sicherung enthält alles, was man eingestellt hat: Netze, Geräte (Namen, Typen, Rollen, Notizen …),
//! Zugangsdaten, Benachrichtigungen, Alarm-Regeln, Dienste, Wartungsfenster, Benutzer, Dashboards,
//! Einstellungen und die Energie-Tageswerte – aber keine Messverläufe und Protokolle.
//!
//! Die Datei ist mit einem eigenen Passwort verschlüsselt (Argon2id → AES-256-GCM, vorher gzip).
//! Gespeicherte Geheimnisse stehen darin entschlüsselt, damit die Sicherung auch auf einer neuen
//! Installation mit anderem Tresor-Schlüssel funktioniert – deshalb ist das Passwort Pflicht.
//!
//! Beim Einspielen werden Einträge über natürliche Schlüssel zugeordnet (Gerät → IP, Netz → CIDR,
//! Benutzer → Name …) und aktualisiert oder neu angelegt. Nichts Vorhandenes wird gelöscht, und der
//! Messverlauf bekannter Geräte bleibt erhalten.

use std::{
    collections::HashMap,
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Postgres, Transaction};

use crate::AppState;

pub const FORMAT: &str = "netpulse-backup";
/// 2: Sektoren, Rollen, Gruppen, Rechte je Sektor, geteilte Dashboards
const VERSION: u32 = 2;
/// Einstellungen, die mitgesichert werden (keine Laufzeit-Zustände wie „letzter Scan“)
const SETTINGS: &[&str] = &["discovery_schedule", "smtp", "status_page", "security", "energy", "live_settings", "oidc", "setup"];
const KDF_M: u32 = 64 * 1024;
const KDF_T: u32 = 3;

// ---------------------------------------------------------------------------
// Verschlüsselung
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub format: String,
    pub version: u32,
    pub created_at: String,
    kdf: String,
    m: u32,
    t: u32,
    p: u32,
    salt: String,
    nonce: String,
    data: String,
}

fn derive_key(password: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32]> {
    // Obergrenzen, damit eine manipulierte Datei den Server nicht lahmlegt
    if m > 256 * 1024 || t > 10 || p > 4 {
        bail!("Unbekannte Schlüssel-Parameter in der Sicherung");
    }
    let params = argon2::Params::new(m, t, p, Some(32)).map_err(|e| anyhow!("{e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon.hash_password_into(password.as_bytes(), salt, &mut key).map_err(|e| anyhow!("{e}"))?;
    Ok(key)
}

pub fn encrypt(payload: &Value, password: &str) -> Result<Envelope> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&serde_json::to_vec(payload)?)?;
    let plain = gz.finish()?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(password, &salt, KDF_M, KDF_T, 1)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
        .map_err(|_| anyhow!("Verschlüsselung fehlgeschlagen"))?;
    Ok(Envelope {
        format: FORMAT.into(),
        version: VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        kdf: "argon2id".into(),
        m: KDF_M,
        t: KDF_T,
        p: 1,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        data: B64.encode(cipher),
    })
}

pub fn decrypt(env: &Envelope, password: &str) -> Result<Value> {
    if env.format != FORMAT || env.kdf != "argon2id" {
        bail!("Das ist keine NetPulse-Sicherung");
    }
    if env.version > VERSION {
        bail!("Die Sicherung stammt von einer neueren NetPulse-Version – bitte zuerst NetPulse aktualisieren");
    }
    let salt = B64.decode(&env.salt).context("Sicherung beschädigt")?;
    let nonce = B64.decode(&env.nonce).context("Sicherung beschädigt")?;
    let data = B64.decode(&env.data).context("Sicherung beschädigt")?;
    if nonce.len() != 12 {
        bail!("Sicherung beschädigt");
    }
    let key = derive_key(password, &salt, env.m, env.t, env.p)?;
    let plain = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .decrypt(Nonce::from_slice(&nonce), data.as_slice())
        .map_err(|_| anyhow!("Passwort falsch oder Datei beschädigt"))?;
    // Entpacken mit Obergrenze (Schutz vor „Zip-Bomben“)
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(plain.as_slice()).take(512 * 1024 * 1024).read_to_end(&mut out)?;
    let payload: Value = serde_json::from_slice(&out).context("Sicherung beschädigt")?;
    if payload["format"] != FORMAT {
        bail!("Das ist keine NetPulse-Sicherung");
    }
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Sichern
// ---------------------------------------------------------------------------

async fn rows(db: &PgPool, sql: &str) -> Result<Vec<Value>> {
    let v: Value = sqlx::query_scalar(&format!("SELECT COALESCE(jsonb_agg(t), '[]'::jsonb) FROM ({sql}) t")).fetch_one(db).await?;
    Ok(v.as_array().cloned().unwrap_or_default())
}

/// Alles Einstellbare als JSON; Geheimnisse entschlüsselt
pub async fn export(state: &AppState) -> Result<Value> {
    let db = &state.db;
    let vault = &state.vault;
    let open = |sealed: &Value| -> Value {
        sealed.as_str().and_then(|s| vault.open_value::<Value>(s).ok()).unwrap_or(Value::Null)
    };

    let mut credentials = rows(db, "SELECT id, name, kind, username, port, secret, auto FROM credentials").await?;
    for c in &mut credentials {
        c["secret"] = open(&c["secret"]);
    }
    let mut channels = rows(db, "SELECT id, name, kind, config, enabled FROM notification_channels").await?;
    for c in &mut channels {
        c["config"] = open(&c["config"]);
    }
    let mut users = rows(
        db,
        "SELECT id, username, password_hash, totp_secret, totp_enabled, display_name, email, disabled, auth_source, oidc_subject FROM users",
    )
    .await?;
    for u in &mut users {
        u["totp_secret"] = open(&u["totp_secret"]);
    }
    let mut settings = rows(db, &format!(
        "SELECT key, value FROM settings WHERE key IN ({})",
        SETTINGS.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(", ")
    ))
    .await?;
    for s in &mut settings {
        if s["key"] == "smtp" {
            s["value"] = json!({ "plain": open(&s["value"]["sealed"]) });
        }
        if s["key"] == "oidc" {
            let plain = open(&s["value"]["client_secret_sealed"]);
            if let Some(map) = s["value"].as_object_mut() {
                map.remove("client_secret_sealed");
                map.insert("client_secret_plain".into(), plain);
            }
        }
    }

    Ok(json!({
        "format": FORMAT,
        "version": VERSION,
        "created_at": chrono::Utc::now(),
        "app_version": env!("CARGO_PKG_VERSION"),
        "sites": rows(db, "SELECT id, name, description, parent_id, position FROM sites ORDER BY id").await?,
        "networks": rows(db, "SELECT cidr::text AS cidr, name, enabled, site_id, vlan_id, host(gateway) AS gateway, description, schedule
                                FROM networks").await?,
        "credentials": credentials,
        "device_categories": rows(db, "SELECT id, name, icon, color, position, auto_types FROM device_categories ORDER BY position, id").await?,
        "devices": rows(db, "SELECT id, host(ip) AS ip, mac, hostname, name, notes, monitored, device_type, device_type_manual,
                                    wan_interface, wan_interface_manual, parent_id, parent_manual, energy_role, ssh_host_key, tls_pin,
                                    vendor, model, os, reported_name, integration, first_seen, open_ports, site_id, tags,
                                    priority, category_id, category_manual
                               FROM devices").await?,
        "device_credentials": rows(db, "SELECT device_id, credential_id FROM device_credentials").await?,
        "channels": channels,
        "checks": rows(db, "SELECT id, name, kind, target, config, interval_s, timeout_s, device_id, enabled, site_id FROM checks").await?,
        "alert_rules": rows(db, "SELECT name, kind, device_id, threshold, duration_min, channel_ids, notify_recovery, enabled,
                                        repeat_min, check_id, pattern, site_id, tag, severity, group_ids, escalate_after_min,
                                        escalate_channel_ids, escalate_group_ids FROM alert_rules").await?,
        "maintenance": rows(db, "SELECT name, kind, starts_at, ends_at, days, time_from, time_to, device_ids, check_ids, site_ids, enabled
                                   FROM maintenance_windows").await?,
        "users": users,
        "roles": rows(db, "SELECT id, name, description, permissions, all_permissions, builtin FROM roles").await?,
        "groups": rows(db, "SELECT id, name, description, oidc_group FROM user_groups").await?,
        "group_members": rows(db, "SELECT group_id, user_id FROM group_members").await?,
        "role_assignments": rows(db, "SELECT role_id, user_id, group_id, site_id FROM role_assignments").await?,
        "dashboards": rows(db, "SELECT user_id, layout FROM dashboards").await?,
        "dashboard_views": rows(db, "SELECT name, owner_id, layout, site_id, shared, group_ids, is_default, kind FROM dashboard_views").await?,
        "settings": settings,
        "energy_daily": rows(db, "SELECT day, device_id, pos_wh, neg_wh, minutes FROM energy_daily").await?,
    }))
}

// ---------------------------------------------------------------------------
// Einspielen
// ---------------------------------------------------------------------------

#[derive(Serialize, Default, Debug)]
pub struct RestoreReport {
    pub sites: usize,
    pub networks: usize,
    pub devices: usize,
    pub credentials: usize,
    pub channels: usize,
    pub checks: usize,
    pub alert_rules: usize,
    pub maintenance: usize,
    pub users: usize,
    pub roles: usize,
    pub groups: usize,
    pub settings: usize,
    pub energy_days: usize,
}

type Ids = HashMap<i64, i64>;

fn list<'a>(p: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    p[key].as_array().map(|a| a.iter()).into_iter().flatten()
}

fn map_id(ids: &Ids, v: &Value) -> Option<i64> {
    v.as_i64().and_then(|id| ids.get(&id).copied())
}

fn map_ids(ids: &Ids, v: &Value) -> Vec<i64> {
    v.as_array().map(|a| a.iter().filter_map(|x| map_id(ids, x)).collect()).unwrap_or_default()
}

/// Vorhandene ID über eine Suche finden, sonst None
async fn find(tx: &mut Transaction<'_, Postgres>, sql: &str, binds: &[&str]) -> Result<Option<i64>> {
    let mut q = sqlx::query_scalar::<_, i64>(sql);
    for b in binds {
        q = q.bind(*b);
    }
    Ok(q.fetch_optional(&mut **tx).await?)
}

pub async fn restore(state: &AppState, p: &Value) -> Result<RestoreReport> {
    let vault = &state.vault;
    let mut report = RestoreReport::default();
    let mut tx = state.db.begin().await?;
    let s = |v: &Value| v.as_str().map(str::to_string);

    // Sektoren (Name + übergeordneter Sektor); der Standard-Sektor bleibt der Standard-Sektor
    let mut site_ids = Ids::new();
    site_ids.insert(crate::sites::DEFAULT_SITE, crate::sites::DEFAULT_SITE);
    let sites: Vec<&Value> = list(p, "sites").collect();
    // Eltern vor Kindern anlegen; höchstens so viele Runden wie Sektoren (Schutz vor Kreisen)
    for _ in 0..=sites.len() {
        let mut progress = false;
        for site in &sites {
            let (Some(old), Some(name)) = (site["id"].as_i64(), site["name"].as_str()) else { continue };
            if site_ids.contains_key(&old) {
                continue;
            }
            let parent = match site["parent_id"].as_i64() {
                None => None,
                Some(p) => match site_ids.get(&p) {
                    Some(id) => Some(*id),
                    None => continue, // Eltern-Sektor kommt erst in einer späteren Runde
                },
            };
            let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM sites WHERE name = $1 AND parent_id IS NOT DISTINCT FROM $2 LIMIT 1")
                .bind(name)
                .bind(parent)
                .fetch_optional(&mut *tx)
                .await?;
            let id = match existing {
                Some(id) => id,
                None => {
                    sqlx::query_scalar("INSERT INTO sites (name, description, parent_id, position) VALUES ($1, $2, $3, $4) RETURNING id")
                        .bind(name)
                        .bind(site["description"].as_str().unwrap_or(""))
                        .bind(parent)
                        .bind(site["position"].as_i64().unwrap_or(0) as i32)
                        .fetch_one(&mut *tx)
                        .await?
                }
            };
            site_ids.insert(old, id);
            report.sites += 1;
            progress = true;
        }
        if !progress {
            break;
        }
    }
    // Ältere Sicherungen ohne Sektoren: alles in den Standard-Sektor
    let site_of = |v: &Value| map_id(&site_ids, v).unwrap_or(crate::sites::DEFAULT_SITE);

    // Netze
    for n in list(p, "networks") {
        sqlx::query(
            "INSERT INTO networks (cidr, name, enabled, site_id, vlan_id, gateway, description, schedule)
             VALUES ($1::cidr, $2, $3, $4, $5, $6::inet, COALESCE($7, ''), $8)
             ON CONFLICT (site_id, cidr) DO UPDATE SET name = EXCLUDED.name, enabled = EXCLUDED.enabled, vlan_id = EXCLUDED.vlan_id,
                    gateway = EXCLUDED.gateway, description = EXCLUDED.description, schedule = EXCLUDED.schedule",
        )
        .bind(s(&n["cidr"]))
        .bind(s(&n["name"]))
        .bind(n["enabled"].as_bool().unwrap_or(true))
        .bind(site_of(&n["site_id"]))
        .bind(n["vlan_id"].as_i64().map(|v| v as i32))
        .bind(s(&n["gateway"]))
        .bind(s(&n["description"]))
        .bind(n.get("schedule").filter(|v| !v.is_null()))
        .execute(&mut *tx)
        .await?;
        report.networks += 1;
    }

    // Zugangsdaten (Name + Art)
    let mut cred_ids = Ids::new();
    for c in list(p, "credentials") {
        let (Some(old), Some(name), Some(kind)) = (c["id"].as_i64(), c["name"].as_str(), c["kind"].as_str()) else { continue };
        if c["secret"].is_null() {
            continue; // Geheimnis war nicht lesbar – lieber auslassen als leer anlegen
        }
        let sealed = vault.seal(&c["secret"])?;
        let port = c["port"].as_i64().map(|v| v as i32);
        let id = match find(&mut tx, "SELECT id FROM credentials WHERE name = $1 AND kind = $2 ORDER BY id LIMIT 1", &[name, kind]).await? {
            Some(id) => {
                sqlx::query("UPDATE credentials SET username = $2, port = $3, secret = $4, auto = $5 WHERE id = $1")
                    .bind(id)
                    .bind(s(&c["username"]))
                    .bind(port)
                    .bind(&sealed)
                    .bind(c["auto"].as_bool().unwrap_or(false))
                    .execute(&mut *tx)
                    .await?;
                id
            }
            None => {
                sqlx::query_scalar(
                    "INSERT INTO credentials (name, kind, username, port, secret, auto) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                )
                .bind(name)
                .bind(kind)
                .bind(s(&c["username"]))
                .bind(port)
                .bind(&sealed)
                .bind(c["auto"].as_bool().unwrap_or(false))
                .fetch_one(&mut *tx)
                .await?
            }
        };
        cred_ids.insert(old, id);
        report.credentials += 1;
    }

    // Gerätekategorien (Name)
    let mut cat_ids = Ids::new();
    for c in list(p, "device_categories") {
        let (Some(old), Some(name)) = (c["id"].as_i64(), c["name"].as_str()) else { continue };
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO device_categories (name, icon, color, position, auto_types)
             SELECT $1, COALESCE(r.icon, 'category'), COALESCE(r.color, '#64748b'), COALESCE(r.position, 0), COALESCE(r.auto_types, '{}')
               FROM jsonb_to_record($2) AS r(icon text, color text, position int, auto_types text[])
             ON CONFLICT (name) DO UPDATE SET icon = EXCLUDED.icon, color = EXCLUDED.color, position = EXCLUDED.position,
                    auto_types = EXCLUDED.auto_types
             RETURNING id",
        )
        .bind(name)
        .bind(c)
        .fetch_one(&mut *tx)
        .await?;
        cat_ids.insert(old, id);
    }

    // Geräte (IP): Eingestelltes aus der Sicherung, Erkanntes nur ergänzen
    let mut dev_ids = Ids::new();
    for d in list(p, "devices") {
        let Some(old) = d["id"].as_i64() else { continue };
        let mut d = d.clone();
        d["site_id"] = json!(site_of(&d["site_id"]));
        d["category_id"] = json!(map_id(&cat_ids, &d["category_id"]));
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO devices (ip, mac, hostname, name, notes, monitored, device_type, device_type_manual, wan_interface,
                                  wan_interface_manual, parent_manual, energy_role, ssh_host_key, tls_pin, vendor, model, os,
                                  reported_name, integration, first_seen, open_ports, site_id, tags, priority, category_id, category_manual)
             SELECT r.ip::inet, r.mac, r.hostname, r.name, r.notes, COALESCE(r.monitored, true), r.device_type,
                    COALESCE(r.device_type_manual, false), r.wan_interface, COALESCE(r.wan_interface_manual, false),
                    COALESCE(r.parent_manual, false), r.energy_role, r.ssh_host_key, r.tls_pin, r.vendor, r.model, r.os,
                    r.reported_name, r.integration, COALESCE(r.first_seen, now()), COALESCE(r.open_ports, '{}'),
                    r.site_id, COALESCE(r.tags, '{}'), COALESCE(r.priority, 'normal'), r.category_id,
                    COALESCE(r.category_manual, false)
               FROM jsonb_to_record($1) AS r(ip text, mac text, hostname text, name text, notes text, monitored bool,
                    device_type text, device_type_manual bool, wan_interface text, wan_interface_manual bool, parent_manual bool,
                    energy_role text, ssh_host_key text, tls_pin text, vendor text, model text, os text, reported_name text,
                    integration text, first_seen timestamptz, open_ports int[], site_id bigint, tags text[],
                    priority text, category_id bigint, category_manual bool)
             ON CONFLICT (site_id, ip) DO UPDATE SET tags = EXCLUDED.tags,
                    priority = EXCLUDED.priority, category_id = EXCLUDED.category_id, category_manual = EXCLUDED.category_manual,
                    name = EXCLUDED.name, notes = EXCLUDED.notes, monitored = EXCLUDED.monitored,
                    device_type = CASE WHEN EXCLUDED.device_type_manual THEN EXCLUDED.device_type ELSE devices.device_type END,
                    device_type_manual = EXCLUDED.device_type_manual,
                    wan_interface = CASE WHEN EXCLUDED.wan_interface_manual THEN EXCLUDED.wan_interface ELSE devices.wan_interface END,
                    wan_interface_manual = EXCLUDED.wan_interface_manual,
                    parent_manual = EXCLUDED.parent_manual, energy_role = EXCLUDED.energy_role,
                    ssh_host_key = COALESCE(devices.ssh_host_key, EXCLUDED.ssh_host_key),
                    tls_pin = COALESCE(devices.tls_pin, EXCLUDED.tls_pin),
                    mac = COALESCE(devices.mac, EXCLUDED.mac), hostname = COALESCE(devices.hostname, EXCLUDED.hostname),
                    vendor = COALESCE(devices.vendor, EXCLUDED.vendor), model = COALESCE(devices.model, EXCLUDED.model),
                    first_seen = LEAST(devices.first_seen, EXCLUDED.first_seen)
             RETURNING id",
        )
        .bind(&d)
        .fetch_one(&mut *tx)
        .await?;
        dev_ids.insert(old, id);
        report.devices += 1;
    }
    // „Hängt ab von“ erst, wenn alle Geräte da sind
    for d in list(p, "devices") {
        if let (Some(id), Some(parent)) = (map_id(&dev_ids, &d["id"]), map_id(&dev_ids, &d["parent_id"])) {
            sqlx::query("UPDATE devices SET parent_id = $2 WHERE id = $1").bind(id).bind(parent).execute(&mut *tx).await?;
        }
    }
    for dc in list(p, "device_credentials") {
        if let (Some(dev), Some(cred)) = (map_id(&dev_ids, &dc["device_id"]), map_id(&cred_ids, &dc["credential_id"])) {
            sqlx::query("INSERT INTO device_credentials (device_id, credential_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(dev)
                .bind(cred)
                .execute(&mut *tx)
                .await?;
        }
    }

    // Benachrichtigungskanäle (Name)
    let mut chan_ids = Ids::new();
    for c in list(p, "channels") {
        let (Some(old), Some(name), Some(kind)) = (c["id"].as_i64(), c["name"].as_str(), c["kind"].as_str()) else { continue };
        if c["config"].is_null() {
            continue;
        }
        let sealed = vault.seal(&c["config"])?;
        let enabled = c["enabled"].as_bool().unwrap_or(true);
        let id = match find(&mut tx, "SELECT id FROM notification_channels WHERE name = $1 ORDER BY id LIMIT 1", &[name]).await? {
            Some(id) => {
                sqlx::query("UPDATE notification_channels SET kind = $2, config = $3, enabled = $4 WHERE id = $1")
                    .bind(id)
                    .bind(kind)
                    .bind(&sealed)
                    .bind(enabled)
                    .execute(&mut *tx)
                    .await?;
                id
            }
            None => {
                sqlx::query_scalar("INSERT INTO notification_channels (name, kind, config, enabled) VALUES ($1, $2, $3, $4) RETURNING id")
                    .bind(name)
                    .bind(kind)
                    .bind(&sealed)
                    .bind(enabled)
                    .fetch_one(&mut *tx)
                    .await?
            }
        };
        chan_ids.insert(old, id);
        report.channels += 1;
    }

    // Dienste (Name + Art + Ziel)
    let mut check_ids = Ids::new();
    for c in list(p, "checks") {
        let (Some(old), Some(name), Some(kind), Some(target)) =
            (c["id"].as_i64(), c["name"].as_str(), c["kind"].as_str(), c["target"].as_str())
        else {
            continue;
        };
        let device = map_id(&dev_ids, &c["device_id"]);
        let site = map_id(&site_ids, &c["site_id"]);
        let interval = c["interval_s"].as_i64().unwrap_or(60) as i32;
        let timeout = c["timeout_s"].as_i64().unwrap_or(10) as i32;
        let enabled = c["enabled"].as_bool().unwrap_or(true);
        let existing =
            find(&mut tx, "SELECT id FROM checks WHERE name = $1 AND kind = $2 AND target = $3 ORDER BY id LIMIT 1", &[name, kind, target])
                .await?;
        let id = match existing {
            Some(id) => {
                sqlx::query("UPDATE checks SET config = $2, interval_s = $3, timeout_s = $4, device_id = $5, enabled = $6, site_id = $7 WHERE id = $1")
                    .bind(id)
                    .bind(&c["config"])
                    .bind(interval)
                    .bind(timeout)
                    .bind(device)
                    .bind(enabled)
                    .bind(site)
                    .execute(&mut *tx)
                    .await?;
                id
            }
            None => {
                sqlx::query_scalar(
                    "INSERT INTO checks (name, kind, target, config, interval_s, timeout_s, device_id, enabled, site_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
                )
                .bind(name)
                .bind(kind)
                .bind(target)
                .bind(&c["config"])
                .bind(interval)
                .bind(timeout)
                .bind(device)
                .bind(enabled)
                .bind(site)
                .fetch_one(&mut *tx)
                .await?
            }
        };
        check_ids.insert(old, id);
        report.checks += 1;
    }

    // Rollen (Name): eingebaute bleiben unverändert, eigene werden übernommen
    let mut role_ids = Ids::new();
    for r in list(p, "roles") {
        let (Some(old), Some(name)) = (r["id"].as_i64(), r["name"].as_str()) else { continue };
        let perms: Vec<String> = r["permissions"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).filter(|p| crate::auth::is_permission(p)).map(str::to_string).collect())
            .unwrap_or_default();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO roles (name, description, permissions, all_permissions) VALUES ($1, $2, $3, $4)
             ON CONFLICT (name) DO UPDATE SET
                    description = CASE WHEN roles.builtin THEN roles.description ELSE EXCLUDED.description END,
                    permissions = CASE WHEN roles.builtin THEN roles.permissions ELSE EXCLUDED.permissions END,
                    all_permissions = CASE WHEN roles.builtin THEN roles.all_permissions ELSE EXCLUDED.all_permissions END
             RETURNING id",
        )
        .bind(name)
        .bind(r["description"].as_str().unwrap_or(""))
        .bind(&perms)
        .bind(r["all_permissions"].as_bool().unwrap_or(false))
        .fetch_one(&mut *tx)
        .await?;
        role_ids.insert(old, id);
        report.roles += 1;
    }

    // Benutzergruppen (Name)
    let mut group_ids = Ids::new();
    for g in list(p, "groups") {
        let (Some(old), Some(name)) = (g["id"].as_i64(), g["name"].as_str()) else { continue };
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO user_groups (name, description, oidc_group) VALUES ($1, $2, $3)
             ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, oidc_group = EXCLUDED.oidc_group
             RETURNING id",
        )
        .bind(name)
        .bind(g["description"].as_str().unwrap_or(""))
        .bind(s(&g["oidc_group"]))
        .fetch_one(&mut *tx)
        .await?;
        group_ids.insert(old, id);
        report.groups += 1;
    }

    // Alarm-Regeln (Name + Art)
    for r in list(p, "alert_rules") {
        let (Some(name), Some(kind)) = (r["name"].as_str(), r["kind"].as_str()) else { continue };
        // Regel für ein bestimmtes Gerät/einen Dienst, das es nicht mehr gibt → auslassen statt „für alle“
        let device = map_id(&dev_ids, &r["device_id"]);
        let check = map_id(&check_ids, &r["check_id"]);
        let site = map_id(&site_ids, &r["site_id"]);
        if (!r["device_id"].is_null() && device.is_none()) || (!r["check_id"].is_null() && check.is_none()) || (!r["site_id"].is_null() && site.is_none()) {
            continue;
        }
        let existing = find(&mut tx, "SELECT id FROM alert_rules WHERE name = $1 AND kind = $2 ORDER BY id LIMIT 1", &[name, kind]).await?;
        sqlx::query(
            "INSERT INTO alert_rules (id, name, kind, device_id, threshold, duration_min, channel_ids, notify_recovery, enabled,
                                      repeat_min, check_id, pattern, site_id, tag, severity, group_ids, escalate_after_min,
                                      escalate_channel_ids, escalate_group_ids)
             VALUES (COALESCE($1, nextval(pg_get_serial_sequence('alert_rules', 'id'))), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                     $13, $14, $15, $16, COALESCE($17, 0), $18, $19)
             ON CONFLICT (id) DO UPDATE SET device_id = EXCLUDED.device_id, threshold = EXCLUDED.threshold,
                    duration_min = EXCLUDED.duration_min, channel_ids = EXCLUDED.channel_ids, notify_recovery = EXCLUDED.notify_recovery,
                    enabled = EXCLUDED.enabled, repeat_min = EXCLUDED.repeat_min, check_id = EXCLUDED.check_id, pattern = EXCLUDED.pattern,
                    site_id = EXCLUDED.site_id, tag = EXCLUDED.tag, severity = EXCLUDED.severity, group_ids = EXCLUDED.group_ids,
                    escalate_after_min = EXCLUDED.escalate_after_min, escalate_channel_ids = EXCLUDED.escalate_channel_ids,
                    escalate_group_ids = EXCLUDED.escalate_group_ids",
        )
        .bind(existing)
        .bind(name)
        .bind(kind)
        .bind(device)
        .bind(r["threshold"].as_f64().map(|v| v as f32))
        .bind(r["duration_min"].as_i64().map(|v| v as i32))
        .bind(map_ids(&chan_ids, &r["channel_ids"]))
        .bind(r["notify_recovery"].as_bool().unwrap_or(true))
        .bind(r["enabled"].as_bool().unwrap_or(true))
        .bind(r["repeat_min"].as_i64().map(|v| v as i32))
        .bind(check)
        .bind(s(&r["pattern"]))
        .bind(site)
        .bind(s(&r["tag"]))
        .bind(s(&r["severity"]).filter(|v| ["info", "warning", "critical"].contains(&v.as_str())))
        .bind(map_ids(&group_ids, &r["group_ids"]))
        .bind(r["escalate_after_min"].as_i64().map(|v| v as i32))
        .bind(map_ids(&chan_ids, &r["escalate_channel_ids"]))
        .bind(map_ids(&group_ids, &r["escalate_group_ids"]))
        .execute(&mut *tx)
        .await?;
        report.alert_rules += 1;
    }

    // Wartungsfenster (Name)
    for m in list(p, "maintenance") {
        let Some(name) = m["name"].as_str() else { continue };
        let mut row = m.clone();
        row["device_ids"] = json!(map_ids(&dev_ids, &m["device_ids"]));
        row["check_ids"] = json!(map_ids(&check_ids, &m["check_ids"]));
        row["site_ids"] = json!(map_ids(&site_ids, &m["site_ids"]));
        let existing = find(&mut tx, "SELECT id FROM maintenance_windows WHERE name = $1 ORDER BY id LIMIT 1", &[name]).await?;
        if let Some(id) = existing {
            sqlx::query("DELETE FROM maintenance_windows WHERE id = $1").bind(id).execute(&mut *tx).await?;
        }
        sqlx::query(
            "INSERT INTO maintenance_windows (name, kind, starts_at, ends_at, days, time_from, time_to, device_ids, check_ids, site_ids, enabled)
             SELECT r.name, r.kind, r.starts_at, r.ends_at, r.days, r.time_from, r.time_to, COALESCE(r.device_ids, '{}'),
                    COALESCE(r.check_ids, '{}'), COALESCE(r.site_ids, '{}'), COALESCE(r.enabled, true)
               FROM jsonb_to_record($1) AS r(name text, kind text, starts_at timestamptz, ends_at timestamptz, days int[],
                    time_from text, time_to text, device_ids bigint[], check_ids bigint[], site_ids bigint[], enabled bool)",
        )
        .bind(&row)
        .execute(&mut *tx)
        .await?;
        report.maintenance += 1;
    }

    // Benutzer (Name)
    let mut user_ids = Ids::new();
    for u in list(p, "users") {
        let (Some(old), Some(name), Some(hash)) = (u["id"].as_i64(), u["username"].as_str(), u["password_hash"].as_str()) else {
            continue;
        };
        let totp: Option<String> = match u["totp_secret"].as_str() {
            Some(secret) => Some(vault.seal(&secret)?),
            None => None,
        };
        let totp_enabled = u["totp_enabled"].as_bool().unwrap_or(false) && totp.is_some();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO users (username, password_hash, totp_secret, totp_enabled, display_name, email, disabled, auth_source, oidc_subject)
             VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, false), COALESCE($8, 'local'), $9)
             ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash,
                    totp_secret = EXCLUDED.totp_secret, totp_enabled = EXCLUDED.totp_enabled, totp_last_step = NULL,
                    display_name = EXCLUDED.display_name, email = EXCLUDED.email, disabled = EXCLUDED.disabled,
                    auth_source = EXCLUDED.auth_source, oidc_subject = EXCLUDED.oidc_subject
             RETURNING id",
        )
        .bind(name)
        .bind(hash)
        .bind(totp)
        .bind(totp_enabled)
        .bind(s(&u["display_name"]))
        .bind(s(&u["email"]))
        .bind(u["disabled"].as_bool())
        .bind(s(&u["auth_source"]).filter(|a| a == "local" || a == "oidc"))
        .bind(s(&u["oidc_subject"]))
        .fetch_one(&mut *tx)
        .await?;
        user_ids.insert(old, id);
        report.users += 1;
        // Sicherung im alten Format: Rolle „admin“/„viewer“ als Rollen-Zuweisung für alle Sektoren
        if let Some(role) = u["role"].as_str() {
            let role_name = if role == "admin" { "Administrator" } else { "Nur lesen" };
            sqlx::query("DELETE FROM role_assignments WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO role_assignments (role_id, user_id) SELECT id, $1 FROM roles WHERE name = $2")
                .bind(id)
                .bind(role_name)
                .execute(&mut *tx)
                .await?;
        }
    }

    // Gruppen-Mitgliedschaften und Rollen-Zuweisungen der eingespielten Benutzer/Gruppen ersetzen
    if p["role_assignments"].is_array() {
        let users: Vec<i64> = user_ids.values().copied().collect();
        let groups: Vec<i64> = group_ids.values().copied().collect();
        sqlx::query("DELETE FROM role_assignments WHERE user_id = ANY($1) OR group_id = ANY($2)")
            .bind(&users)
            .bind(&groups)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM group_members WHERE group_id = ANY($1)").bind(&groups).execute(&mut *tx).await?;
    }
    for m in list(p, "group_members") {
        if let (Some(g), Some(u)) = (map_id(&group_ids, &m["group_id"]), map_id(&user_ids, &m["user_id"])) {
            sqlx::query("INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(g)
                .bind(u)
                .execute(&mut *tx)
                .await?;
        }
    }
    for a in list(p, "role_assignments") {
        let Some(role) = map_id(&role_ids, &a["role_id"]) else { continue };
        let user = map_id(&user_ids, &a["user_id"]);
        let group = map_id(&group_ids, &a["group_id"]);
        let site = map_id(&site_ids, &a["site_id"]);
        if user.is_none() == group.is_none() || (!a["site_id"].is_null() && site.is_none()) {
            continue;
        }
        sqlx::query("INSERT INTO role_assignments (role_id, user_id, group_id, site_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING")
            .bind(role)
            .bind(user)
            .bind(group)
            .bind(site)
            .execute(&mut *tx)
            .await?;
    }
    // Nach dem Einspielen muss es weiterhin einen Administrator geben
    let (admins,): (i64,) = sqlx::query_as(
        "SELECT count(DISTINCT u.id) FROM users u
           JOIN role_assignments a ON a.site_id IS NULL AND (a.user_id = u.id OR a.group_id IN (SELECT group_id FROM group_members WHERE user_id = u.id))
           JOIN roles r ON r.id = a.role_id AND r.all_permissions
          WHERE NOT u.disabled",
    )
    .fetch_one(&mut *tx)
    .await?;
    if admins == 0 {
        anyhow::bail!("Die Sicherung enthält keinen aktiven Administrator – Einspielen abgebrochen");
    }

    // Dashboards: Geräte-Verweise in den Kacheln umschreiben
    for d in list(p, "dashboards") {
        let Some(user) = map_id(&user_ids, &d["user_id"]) else { continue };
        let mut layout = d["layout"].clone();
        if let Some(widgets) = layout.as_array_mut() {
            for w in widgets {
                remap_widget(w, &dev_ids);
            }
        }
        sqlx::query(
            "INSERT INTO dashboards (user_id, layout) VALUES ($1, $2)
             ON CONFLICT (user_id) DO UPDATE SET layout = EXCLUDED.layout, updated_at = now()",
        )
        .bind(user)
        .bind(&layout)
        .execute(&mut *tx)
        .await?;
    }

    // Benannte und geteilte Dashboards (Name + Besitzer)
    for v in list(p, "dashboard_views") {
        let Some(name) = v["name"].as_str() else { continue };
        let owner = map_id(&user_ids, &v["owner_id"]);
        if !v["owner_id"].is_null() && owner.is_none() {
            continue;
        }
        let kind = v["kind"].as_str().filter(|k| matches!(*k, "dashboard" | "leitstand")).unwrap_or("dashboard");
        let mut layout = v["layout"].clone();
        if let Some(widgets) = layout.as_array_mut() {
            for w in widgets {
                remap_widget(w, &dev_ids);
                // Leitstand-Blöcke verweisen auf Kategorien
                if w["categories"].is_array() {
                    w["categories"] = json!(map_ids(&cat_ids, &w["categories"]));
                }
            }
        }
        sqlx::query("DELETE FROM dashboard_views WHERE name = $1 AND owner_id IS NOT DISTINCT FROM $2 AND kind = $3")
            .bind(name)
            .bind(owner)
            .bind(kind)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO dashboard_views (name, owner_id, layout, site_id, shared, group_ids, is_default, kind)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(name)
        .bind(owner)
        .bind(&layout)
        .bind(map_id(&site_ids, &v["site_id"]))
        .bind(v["shared"].as_bool().unwrap_or(false))
        .bind(map_ids(&group_ids, &v["group_ids"]))
        .bind(v["is_default"].as_bool().unwrap_or(false))
        .bind(kind)
        .execute(&mut *tx)
        .await?;
    }

    // Einstellungen
    for st in list(p, "settings") {
        let Some(key) = st["key"].as_str().filter(|k| SETTINGS.contains(k)) else { continue };
        let mut value = st["value"].clone();
        match key {
            "smtp" => {
                let plain: Map<String, Value> = value["plain"].as_object().cloned().unwrap_or_default();
                value = json!({ "sealed": vault.seal(&plain)? });
            }
            "oidc" => {
                if let Some(map) = value.as_object_mut() {
                    let sealed = match map.remove("client_secret_plain") {
                        Some(Value::String(secret)) => json!(vault.seal(&secret)?),
                        _ => Value::Null,
                    };
                    map.insert("client_secret_sealed".into(), sealed);
                }
            }
            "status_page" => {
                if let Some(items) = value["items"].as_array_mut() {
                    items.retain_mut(|i| {
                        let ids = if i["kind"] == "check" { &check_ids } else { &dev_ids };
                        match map_id(ids, &i["id"]) {
                            Some(new) => {
                                i["id"] = json!(new);
                                true
                            }
                            None => false,
                        }
                    });
                }
            }
            "energy" => value["main_id"] = json!(map_id(&dev_ids, &value["main_id"])),
            _ => {}
        }
        sqlx::query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
            .bind(key)
            .bind(&value)
            .execute(&mut *tx)
            .await?;
        report.settings += 1;
    }

    // Energie-Tageswerte: vollständigere Tage gewinnen
    let (mut days, mut devs, mut pos, mut neg, mut minutes) = (vec![], vec![], vec![], vec![], vec![]);
    for e in list(p, "energy_daily") {
        let (Some(day), Some(dev)) = (e["day"].as_str().and_then(|d| d.parse::<chrono::NaiveDate>().ok()), map_id(&dev_ids, &e["device_id"])) else {
            continue;
        };
        days.push(day);
        devs.push(dev);
        pos.push(e["pos_wh"].as_f64().unwrap_or(0.0));
        neg.push(e["neg_wh"].as_f64().unwrap_or(0.0));
        minutes.push(e["minutes"].as_i64().unwrap_or(0) as i32);
    }
    report.energy_days = days.len();
    sqlx::query(
        "INSERT INTO energy_daily (day, device_id, pos_wh, neg_wh, minutes)
         SELECT * FROM UNNEST($1::date[], $2::bigint[], $3::float8[], $4::float8[], $5::int[])
         ON CONFLICT (day, device_id) DO UPDATE SET pos_wh = EXCLUDED.pos_wh, neg_wh = EXCLUDED.neg_wh, minutes = EXCLUDED.minutes
          WHERE EXCLUDED.minutes > energy_daily.minutes",
    )
    .bind(&days)
    .bind(&devs)
    .bind(&pos)
    .bind(&neg)
    .bind(&minutes)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(report)
}

/// Geräte-IDs in einer Dashboard-Kachel auf die neuen IDs umschreiben
fn remap_widget(w: &mut Value, ids: &Ids) {
    for key in ["device_id", "main_id"] {
        if !w[key].is_null() {
            w[key] = json!(map_id(ids, &w[key]));
        }
    }
    if w["include"].is_array() {
        w["include"] = json!(map_ids(ids, &w["include"]));
    }
}

// ---------------------------------------------------------------------------
// Automatische Sicherung
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AutoSettings {
    pub enabled: bool,
    /// Uhrzeit (Stunde, Ortszeit)
    pub hour: u32,
    /// Wie viele Sicherungen behalten
    pub keep: u32,
    /// Passwort für die Dateien – im Tresor verschlüsselt, nie an den Browser
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_sealed: Option<String>,
}

impl Default for AutoSettings {
    fn default() -> Self {
        Self { enabled: false, hour: 2, keep: 14, password_sealed: None }
    }
}

pub async fn load_auto(db: &PgPool) -> AutoSettings {
    sqlx::query_scalar::<_, Value>("SELECT value FROM settings WHERE key = 'backup_auto'")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

pub async fn save_auto(db: &PgPool, s: &AutoSettings) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES ('backup_auto', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(serde_json::to_value(s).unwrap_or_default())
        .execute(db)
        .await?;
    Ok(())
}

pub fn dir(state: &AppState) -> PathBuf {
    PathBuf::from(&state.config.data_dir).join("backups")
}

/// Gültiger Dateiname einer automatischen Sicherung (Schutz vor Pfad-Tricks beim Herunterladen)
pub fn valid_name(name: &str) -> bool {
    name.starts_with("netpulse-")
        && name.ends_with(".npbackup")
        && name.len() < 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !name.contains("..")
}

/// Sicherung erstellen und im Datenverzeichnis ablegen; alte Dateien aufräumen
pub async fn write_auto(state: &AppState, password: &str, keep: u32) -> Result<String> {
    let payload = export(state).await?;
    let password = password.to_string();
    let env = tokio::task::spawn_blocking(move || encrypt(&payload, &password)).await??;
    let dir = dir(state);
    tokio::fs::create_dir_all(&dir).await.with_context(|| format!("{} nicht anlegbar", dir.display()))?;
    let now = chrono::Utc::now().with_timezone(&crate::scanner::schedule::timezone());
    let name = format!("netpulse-{}.npbackup", now.format("%Y-%m-%d-%H%M%S"));
    let path = dir.join(&name);
    tokio::fs::write(&path, serde_json::to_vec(&env)?).await?;
    // Nur für den App-Benutzer lesbar
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await;
    }
    // Älteste löschen
    let mut files: Vec<String> = list_files(state).await.into_iter().map(|f| f.0).collect();
    files.sort();
    while files.len() > keep.max(1) as usize {
        let old = files.remove(0);
        let _ = tokio::fs::remove_file(dir.join(old)).await;
    }
    Ok(name)
}

/// (Name, Größe in Byte, geändert) aller abgelegten Sicherungen, neueste zuerst
pub async fn list_files(state: &AppState) -> Vec<(String, u64, Option<chrono::DateTime<chrono::Utc>>)> {
    let mut out = vec![];
    if let Ok(mut rd) = tokio::fs::read_dir(dir(state)).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if !valid_name(&name) {
                continue;
            }
            let meta = entry.metadata().await.ok();
            out.push((
                name,
                meta.as_ref().map(|m| m.len()).unwrap_or(0),
                meta.and_then(|m| m.modified().ok()).map(chrono::DateTime::<chrono::Utc>::from),
            ));
        }
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    out
}

/// Hintergrund-Aufgabe: einmal täglich zur eingestellten Stunde sichern
pub async fn run(state: AppState) {
    let mut last_day = None;
    loop {
        tokio::time::sleep(Duration::from_secs(300)).await;
        let cfg = load_auto(&state.db).await;
        if !cfg.enabled {
            continue;
        }
        let now = chrono::Utc::now().with_timezone(&crate::scanner::schedule::timezone());
        use chrono::Timelike;
        if now.hour() != cfg.hour || last_day == Some(now.date_naive()) {
            continue;
        }
        last_day = Some(now.date_naive());
        let Some(password) = cfg.password_sealed.as_deref().and_then(|s| state.vault.open_value::<String>(s).ok()) else {
            tracing::warn!("Automatische Sicherung: Passwort nicht lesbar – bitte unter System neu setzen");
            continue;
        };
        match write_auto(&state, &password, cfg.keep).await {
            Ok(name) => tracing::info!("Automatische Sicherung erstellt: {name}"),
            Err(e) => tracing::warn!("Automatische Sicherung fehlgeschlagen: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verschluesseln_und_entschluesseln() {
        let payload = json!({ "format": FORMAT, "devices": [{ "ip": "10.0.0.1" }] });
        let env = encrypt(&payload, "ein-langes-passwort").unwrap();
        assert_eq!(decrypt(&env, "ein-langes-passwort").unwrap(), payload);
        assert!(decrypt(&env, "falsches-passwort").is_err());
    }

    #[test]
    fn dateinamen() {
        assert!(valid_name("netpulse-2026-09-25-020000.npbackup"));
        assert!(!valid_name("../secret.key"));
        assert!(!valid_name("netpulse-../../x.npbackup"));
        assert!(!valid_name("netpulse-x/y.npbackup"));
    }

    #[test]
    fn dashboard_ids() {
        let ids = Ids::from([(4, 40), (2, 20)]);
        let mut w = json!({ "type": "power", "include": [4, 9], "main_id": 4 });
        remap_widget(&mut w, &ids);
        assert_eq!(w, json!({ "type": "power", "include": [40], "main_id": 40 }));
        let mut w = json!({ "type": "device", "device_id": 2 });
        remap_widget(&mut w, &ids);
        assert_eq!(w["device_id"], 20);
    }
}
