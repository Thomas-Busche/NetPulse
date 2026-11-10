//! Zustellung an die Kanäle: sofort, gesammelt (Sammelmeldung) oder nach der Ruhezeit.
//!
//! Einstellungen je Kanal (liegen in dessen Konfiguration):
//! - `digest_min`  : Meldungen so viele Minuten sammeln und dann als eine Nachricht schicken (0 = sofort)
//! - `quiet_from` / `quiet_to` : Ruhezeit („22:00“ bis „07:00“); Meldungen werden danach gesammelt zugestellt
//! - `quiet_critical` : kritische Meldungen trotz Ruhezeit sofort senden
//!
//! Der E-Mail-Server wird zentral eingetragen (Einstellung `smtp`) und gilt für alle E-Mail-Kanäle,
//! sofern ein Kanal keinen eigenen Server hat.

use std::time::Duration;

use anyhow::Result;
use chrono::{NaiveTime, Timelike};
use serde_json::{json, Map, Value};

use super::notify::{self, Notification, Severity};
use crate::AppState;

// ---------------------------------------------------------------------------
// Zentraler E-Mail-Server
// ---------------------------------------------------------------------------

/// Felder des zentralen Servers (ohne Empfänger)
pub const SMTP_FIELDS: &[&str] = &["host", "port", "security", "username", "password", "from", "from_name"];

pub async fn load_smtp(state: &AppState) -> Map<String, Value> {
    let row: Option<(Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = 'smtp'")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    row.and_then(|(v,)| v["sealed"].as_str().map(str::to_string))
        .and_then(|sealed| state.vault.open_value::<Map<String, Value>>(&sealed).ok())
        .unwrap_or_default()
}

pub async fn save_smtp(state: &AppState, config: &Map<String, Value>) -> Result<()> {
    let sealed = state.vault.seal(config)?;
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('smtp', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(json!({ "sealed": sealed }))
    .execute(&state.db)
    .await?;
    Ok(())
}

/// Kanal ohne eigenen Server → zentralen Server übernehmen
async fn with_smtp(state: &AppState, mut config: Value) -> Value {
    let own = config["host"].as_str().is_some_and(|h| !h.trim().is_empty());
    if !own {
        for (key, value) in load_smtp(state).await {
            config[key] = value;
        }
    }
    config
}

// ---------------------------------------------------------------------------
// Senden
// ---------------------------------------------------------------------------

/// Sofort über einen Kanal senden (ohne Sammeln/Ruhezeit)
pub async fn send_now(state: &AppState, kind: &str, config: Value, n: &Notification) -> Result<()> {
    let _perf = crate::perf::Timer::new("Benachrichtigung senden");
    match kind {
        "app" => {
            let url = n.device_id.map_or_else(|| "/#/alerts".to_string(), |id| format!("/#/device/{id}"));
            let tag = n.vars.get("tag").cloned().unwrap_or_else(|| "netpulse".into());
            let message = crate::push::PushMessage { title: &n.title, body: &n.message, severity: n.severity.name(), url: &url, tag: &tag };
            let users = app_recipients(state, n).await?;
            crate::push::send(state, Some(&users), &message).await?.into_result()?;
            Ok(())
        }
        "email" => notify::send(kind, &with_smtp(state, config).await, n).await,
        _ => notify::send(kind, &config, n).await,
    }
}

/// Push nur an Benutzer, die das betroffene Gerät (bzw. den Dienst) sehen dürfen;
/// Meldungen ohne Gerät nur an Benutzer mit Sicht auf alle Sektoren.
async fn app_recipients(state: &AppState, n: &Notification) -> Result<Vec<i64>> {
    let site: Option<(i64,)> = if let Some(id) = n.device_id {
        sqlx::query_as("SELECT site_id FROM devices WHERE id = $1").bind(id).fetch_optional(&state.db).await?
    } else if let Some(id) = n.check_id {
        sqlx::query_as("SELECT site_id FROM checks WHERE id = $1").bind(id).fetch_optional(&state.db).await?
    } else {
        None
    };
    Ok(crate::auth::users_with(&state.db, "view", site.map(|s| s.0)).await?)
}

/// An die Mitglieder von Benutzergruppen: Push an deren Geräte, E-Mail an deren Adressen (über den zentralen Server)
pub async fn to_groups(state: &AppState, group_ids: &[i64], n: &Notification) {
    if group_ids.is_empty() {
        return;
    }
    let members: Vec<(i64, Option<String>)> = match sqlx::query_as(
        "SELECT DISTINCT u.id, u.email FROM group_members m JOIN users u ON u.id = m.user_id
          WHERE m.group_id = ANY($1) AND NOT u.disabled",
    )
    .bind(group_ids)
    .fetch_all(&state.db)
    .await
    {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Gruppenmitglieder nicht ladbar: {e}");
            return;
        }
    };
    // Nur Mitglieder, die das Gerät sehen dürfen
    let allowed = app_recipients(state, n).await.unwrap_or_default();
    let members: Vec<_> = members.into_iter().filter(|(id, _)| allowed.contains(id)).collect();
    if members.is_empty() {
        return;
    }
    let ids: Vec<i64> = members.iter().map(|m| m.0).collect();
    let url = n.device_id.map_or_else(|| "/#/alerts".to_string(), |id| format!("/#/device/{id}"));
    let tag = n.vars.get("tag").cloned().unwrap_or_else(|| "netpulse".into());
    let message = crate::push::PushMessage { title: &n.title, body: &n.message, severity: n.severity.name(), url: &url, tag: &tag };
    if let Err(e) = crate::push::send(state, Some(&ids), &message).await {
        tracing::warn!("Push an Gruppe fehlgeschlagen: {e:#}");
    }
    let mails: Vec<String> = members.into_iter().filter_map(|m| m.1).filter(|m| m.contains('@')).collect();
    if !mails.is_empty() && load_smtp(state).await.contains_key("host") {
        let config = with_smtp(state, json!({ "to": mails.join(",") })).await;
        if let Err(e) = notify::send("email", &config, n).await {
            tracing::warn!("E-Mail an Gruppe fehlgeschlagen: {e:#}");
        }
    }
}

fn parse_time(v: &Value) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(v.as_str()?.trim(), "%H:%M").ok()
}

/// Liegt `now` in der Ruhezeit (auch über Mitternacht, z. B. 22:00–07:00)?
pub fn in_quiet(config: &Value, now: NaiveTime) -> bool {
    let (Some(from), Some(to)) = (parse_time(&config["quiet_from"]), parse_time(&config["quiet_to"])) else { return false };
    if from <= to {
        now >= from && now < to
    } else {
        now >= from || now < to
    }
}

fn local_now() -> NaiveTime {
    let now = chrono::Utc::now().with_timezone(&crate::scanner::schedule::timezone());
    NaiveTime::from_hms_opt(now.hour(), now.minute(), 0).unwrap_or_default()
}

/// An einen Kanal zustellen – sofort oder in die Warteschlange (Sammeln/Ruhezeit)
pub async fn to_channel(state: &AppState, id: i64, name: &str, kind: &str, config: Value, n: &Notification) {
    let digest = config["digest_min"].as_i64().unwrap_or(0) > 0;
    let bypass = n.severity == Severity::Critical && config["quiet_critical"].as_bool().unwrap_or(true);
    let quiet = in_quiet(&config, local_now()) && !bypass;
    if digest || quiet {
        let queued = sqlx::query("INSERT INTO notification_queue (channel_id, payload) VALUES ($1, $2)")
            .bind(id)
            .bind(json!(n))
            .execute(&state.db)
            .await;
        match queued {
            Ok(_) => tracing::info!(
                "Meldung „{}“ für {name} {}",
                n.title,
                if quiet { "wegen Ruhezeit zurückgestellt" } else { "für die Sammelmeldung vorgemerkt" }
            ),
            Err(e) => tracing::warn!("Meldung konnte nicht vorgemerkt werden: {e}"),
        }
        return;
    }
    let result = send_now(state, kind, config, n).await;
    record(state, id, &result).await;
    match result {
        Ok(()) => tracing::info!("Benachrichtigung „{}“ über {name} gesendet", n.title),
        Err(e) => tracing::warn!("Benachrichtigung über Kanal {id} ({name}) fehlgeschlagen: {e:#}"),
    }
}

/// Ergebnis eines Versands beim Kanal merken (für die Anzeige unter „Benachrichtigungen“)
pub async fn record(state: &AppState, channel_id: i64, result: &Result<()>) {
    let error = result.as_ref().err().map(|e| format!("{e:#}").chars().take(500).collect::<String>());
    let _ = sqlx::query(
        "UPDATE notification_channels SET last_attempt_at = now(),
                last_ok_at = CASE WHEN $2::text IS NULL THEN now() ELSE last_ok_at END, last_error = $2
          WHERE id = $1",
    )
    .bind(channel_id)
    .bind(error)
    .execute(&state.db)
    .await;
}

/// Mehrere Meldungen zu einer zusammenfassen
pub fn combine(items: &[Notification]) -> Notification {
    if items.len() == 1 {
        return items[0].clone();
    }
    let severity = items.iter().map(|n| n.severity).max().unwrap_or(Severity::Info);
    let problems = items.iter().filter(|n| n.severity >= Severity::Warning).count();
    let lines: Vec<String> = items
        .iter()
        .map(|n| {
            // nur die Uhrzeit (Datum steht im Betreff/Kopf)
            let time = n.vars.get("zeit").and_then(|t| t.split(' ').nth(1)).map(|t| format!("{t} · ")).unwrap_or_default();
            format!("{} {time}{}: {}", n.severity.emoji(), n.title, n.message)
        })
        .collect();
    let mut n = Notification::new(
        match problems {
            0 => format!("{} Meldungen", items.len()),
            1 => format!("{} Meldungen (1 Problem)", items.len()),
            p => format!("{} Meldungen ({p} Probleme)", items.len()),
        },
        lines.join("\n"),
        severity,
        items.iter().find_map(|n| n.link.clone()).map(|l| l.split("/#/").next().unwrap_or(&l).to_string() + "/#/alerts"),
    );
    n.vars.insert("tag".into(), "sammel".into());
    n
}

/// Warteschlangen abarbeiten: alle 30 s prüfen, ob Sammelzeit oder Ruhezeit vorbei ist
pub async fn run(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;
        if let Err(e) = flush(&state).await {
            tracing::warn!("Sammelmeldungen: {e:#}");
        }
    }
}

async fn flush(state: &AppState) -> Result<()> {
    let waiting: Vec<(i64, String, String, String, i64)> = sqlx::query_as(
        "SELECT c.id, c.name, c.kind, c.config, EXTRACT(EPOCH FROM now() - min(q.created_at))::bigint
           FROM notification_queue q JOIN notification_channels c ON c.id = q.channel_id
          GROUP BY c.id, c.name, c.kind, c.config",
    )
    .fetch_all(&state.db)
    .await?;
    for (id, name, kind, sealed, age_s) in waiting {
        let config: Value = state.vault.open_value(&sealed)?;
        if in_quiet(&config, local_now()) {
            continue;
        }
        let digest_min = config["digest_min"].as_i64().unwrap_or(0);
        if age_s < digest_min * 60 {
            continue;
        }
        let rows: Vec<(i64, Value)> =
            sqlx::query_as("DELETE FROM notification_queue WHERE channel_id = $1 RETURNING id, payload").bind(id).fetch_all(&state.db).await?;
        let mut items: Vec<Notification> = rows.into_iter().filter_map(|(_, v)| serde_json::from_value(v).ok()).collect();
        if items.is_empty() {
            continue;
        }
        items.sort_by_key(|n| n.vars.get("zeit").cloned());
        let n = combine(&items);
        let result = send_now(state, &kind, config, &n).await;
        record(state, id, &result).await;
        match result {
            Ok(()) => tracing::info!("Sammelmeldung mit {} Einträgen über {name} gesendet", items.len()),
            Err(e) => tracing::warn!("Sammelmeldung über {name} fehlgeschlagen: {e:#}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruhezeit() {
        let cfg = json!({ "quiet_from": "22:00", "quiet_to": "07:00" });
        let t = |s: &str| NaiveTime::parse_from_str(s, "%H:%M").unwrap();
        assert!(in_quiet(&cfg, t("23:30")));
        assert!(in_quiet(&cfg, t("06:59")));
        assert!(!in_quiet(&cfg, t("07:00")));
        assert!(!in_quiet(&cfg, t("12:00")));
        assert!(in_quiet(&json!({ "quiet_from": "12:00", "quiet_to": "13:00" }), t("12:30")));
        assert!(!in_quiet(&json!({}), t("12:30")));
    }

    #[test]
    fn sammelmeldung() {
        let items = vec![
            Notification::new("Offline: NAS", "NAS ist nicht erreichbar", Severity::Critical, None),
            Notification::new("Wieder online: AP", "AP ist wieder erreichbar", Severity::Resolved, None),
        ];
        let n = combine(&items);
        assert_eq!(n.severity, Severity::Critical);
        assert_eq!(n.title, "2 Meldungen (1 Problem)");
        assert_eq!(n.message.lines().count(), 2);
    }
}
