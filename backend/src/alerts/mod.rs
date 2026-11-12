//! Alarmierung: prüft alle 20 Sekunden die Regeln und verschickt Benachrichtigungen.
//!
//! Regeltypen:
//! - `device_down`  : Gerät länger als `duration_min` Minuten offline (mit Entwarnung)
//! - `new_device`   : neues Gerät im Netz
//! - `mac_changed`  : MAC-Adresse einer IP hat sich geändert (möglicher Angriff)
//! - `disk_usage`, `cpu_usage`, `mem_usage`, `temperature`: Schwellwert aus SNMP/SSH-Messwerten
//! - `job_failed`   : ein verbundenes Programm meldet eine fehlgeschlagene Aufgabe (z. B. Backup)
//! - `job_missing`  : regelmäßig gesicherter Container hat seit `threshold` Stunden kein erfolgreiches Backup
//!
//! Solange ein Alarm offen ist, erinnert NetPulse auf Wunsch alle `repeat_min` Minuten daran.

pub mod deliver;
pub mod notify;

use std::time::Duration;

use anyhow::Result;
use serde_json::Value;
use sqlx::FromRow;

use crate::AppState;
use notify::{Notification, Severity};

#[derive(FromRow, Clone)]
pub(crate) struct Rule {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub device_id: Option<i64>,
    pub threshold: Option<f32>,
    pub duration_min: i32,
    pub channel_ids: Vec<i64>,
    pub notify_recovery: bool,
    pub repeat_min: i32,
    pub check_id: Option<i64>,
    pub pattern: Option<String>,
    /// Nur Geräte/Dienste in diesem Sektor (inkl. Unter-Sektoren)
    pub site_id: Option<i64>,
    /// Nur Geräte mit diesem Tag
    pub tag: Option<String>,
    /// Feste Schwere statt der Voreinstellung der Regelart
    pub severity: Option<String>,
    /// Benutzergruppen, die zusätzlich benachrichtigt werden
    pub group_ids: Vec<i64>,
    /// Eskalation: unbestätigt nach so vielen Minuten an weitere Kanäle/Gruppen (0 = aus)
    pub escalate_after_min: i32,
    pub escalate_channel_ids: Vec<i64>,
    pub escalate_group_ids: Vec<i64>,
    /// Aus `site_id` berechnet: der Sektor mit allen Unter-Sektoren
    #[sqlx(skip)]
    pub sites: Option<Vec<i64>>,
}

pub async fn run(state: AppState) {
    tokio::time::sleep(Duration::from_secs(15)).await;
    // Beim Start nur neue Ereignisse melden, nicht die komplette Historie
    let mut cursor: i64 = sqlx::query_as::<_, (Option<i64>,)>("SELECT max(id) FROM events")
        .fetch_one(&state.db)
        .await
        .map(|r| r.0.unwrap_or(0))
        .unwrap_or(0);
    let mut tick = tokio::time::interval(Duration::from_secs(20));
    loop {
        tick.tick().await;
        match evaluate(&state, cursor).await {
            Ok(new_cursor) => cursor = new_cursor,
            Err(e) => tracing::error!("Alarmprüfung fehlgeschlagen: {e:#}"),
        }
    }
}

async fn evaluate(state: &AppState, cursor: i64) -> Result<i64> {
    let _perf = crate::perf::Timer::new("Alarmprüfung");
    let mut rules: Vec<Rule> = sqlx::query_as(
        "SELECT id, name, kind, device_id, threshold, duration_min, channel_ids, notify_recovery, repeat_min, check_id, pattern,
                site_id, tag, severity, group_ids, escalate_after_min, escalate_channel_ids, escalate_group_ids
           FROM alert_rules WHERE enabled",
    )
    .fetch_all(&state.db)
    .await?;
    if rules.iter().any(|r| r.site_id.is_some()) {
        let tree = crate::sites::tree(&state.db).await?;
        for rule in &mut rules {
            rule.sites = rule.site_id.map(|s| crate::auth::descendants(s, &tree));
        }
    }

    let new_cursor = event_rules(state, &rules, cursor).await?;
    for rule in &rules {
        let result = match rule.kind.as_str() {
            "device_down" => device_down(state, rule).await,
            "disk_usage" | "cpu_usage" | "mem_usage" | "temperature" => threshold(state, rule).await,
            "check_down" => check_down(state, rule).await,
            "cert_expiry" => cert_expiry(state, rule).await,
            "syslog_match" => syslog_match(state, rule).await,
            "job_missing" => job_missing(state, rule).await,
            _ => Ok(()),
        };
        if let Err(e) = result {
            tracing::error!("Regel „{}“: {e:#}", rule.name);
        }
    }
    if let Err(e) = reminders(state, &rules).await {
        tracing::error!("Erinnerungen: {e:#}");
    }
    if let Err(e) = escalations(state, &rules).await {
        tracing::error!("Eskalation: {e:#}");
    }
    Ok(new_cursor)
}

/// SQL-Bedingung für Sektor und Tag einer Regel (Gerät mit Alias `d`, Parameter `$a` = Sektoren, `$b` = Tag)
fn scope_sql(a: u8, b: u8) -> String {
    format!("(${a}::bigint[] IS NULL OR d.site_id = ANY(${a})) AND (${b}::text IS NULL OR ${b} = ANY(d.tags))")
}

/// Passt ein Gerät (Sektor, Tags) zur Regel?
fn in_scope(rule: &Rule, site: Option<i64>, tags: &[String]) -> bool {
    let site_ok = rule.sites.as_ref().is_none_or(|s| site.is_some_and(|id| s.contains(&id)));
    let tag_ok = rule.tag.as_ref().is_none_or(|t| tags.contains(t));
    site_ok && tag_ok
}

fn device_link(state: &AppState, device_id: i64) -> Option<String> {
    state.config.public_url.as_ref().map(|u| format!("{u}/#/device/{device_id}"))
}

/// Ereignisbasierte Regeln: neues Gerät, MAC geändert
async fn event_rules(state: &AppState, rules: &[Rule], cursor: i64) -> Result<i64> {
    let events: Vec<(i64, Option<i64>, String, String)> = sqlx::query_as(
        "SELECT id, device_id, kind, message FROM events
          WHERE id > $1 AND kind IN ('discovered', 'mac_changed', 'ssh_key_changed', 'job_failed') ORDER BY id LIMIT 500",
    )
    .bind(cursor)
    .fetch_all(&state.db)
    .await?;
    let mut last = cursor;
    for (event_id, device_id, kind, message) in events {
        last = event_id;
        let rule_kind = match kind.as_str() {
            "discovered" => "new_device",
            "job_failed" => "job_failed",
            _ => "mac_changed", // auch geänderte SSH-Host-Schlüssel sind sicherheitsrelevant
        };
        for rule in rules.iter().filter(|r| r.kind == rule_kind) {
            if rule.device_id.is_some() && rule.device_id != device_id {
                continue;
            }
            if rule.sites.is_some() || rule.tag.is_some() {
                let row: Option<(i64, Vec<String>)> = match device_id {
                    Some(id) => sqlx::query_as("SELECT site_id, tags FROM devices WHERE id = $1").bind(id).fetch_optional(&state.db).await?,
                    None => None,
                };
                let (site, tags) = row.map_or((None, Vec::new()), |(s, t)| (Some(s), t));
                if !in_scope(rule, site, &tags) {
                    continue;
                }
            }
            // Aufgaben-Regeln: optional nur für Container, deren Name den Suchtext enthält
            if rule_kind == "job_failed" && !matches_pattern(rule, &message) {
                continue;
            }
            sqlx::query("INSERT INTO alerts (rule_id, device_id, message, resolved_at, severity) VALUES ($1, $2, $3, now(), $4)")
                .bind(rule.id)
                .bind(device_id)
                .bind(&message)
                .bind(severity_of(rule))
                .execute(&state.db)
                .await?;
            let severity = if rule_kind == "new_device" { Severity::Info } else { Severity::Warning };
            let title = match rule_kind {
                "new_device" => "Neues Gerät im Netz",
                "job_failed" if message.starts_with("Backup") => "Backup fehlgeschlagen",
                "job_failed" => "Aufgabe fehlgeschlagen",
                _ => "Sicherheitshinweis",
            };
            let mut n = Notification::new(title, message.clone(), severity, device_id.and_then(|id| device_link(state, id)));
            n.device_id = device_id;
            dispatch(state, rule, n).await;
        }
    }
    Ok(last)
}

async fn device_down(state: &AppState, rule: &Rule) -> Result<()> {
    // Neue Ausfälle
    // Geräte hinter einem ebenfalls ausgefallenen Elterngerät (Switch, AP …) werden nicht einzeln gemeldet –
    // die Meldung des Elterngeräts nennt stattdessen die Zahl der betroffenen Geräte.
    let down: Vec<(i64, String, i64, i64)> = sqlx::query_as(&format!(
        "WITH RECURSIVE anc(child, ancestor, depth) AS (
             SELECT id, parent_id, 1 FROM devices WHERE parent_id IS NOT NULL
           UNION ALL
             SELECT anc.child, p.parent_id, anc.depth + 1 FROM anc JOIN devices p ON p.id = anc.ancestor
              WHERE p.parent_id IS NOT NULL AND anc.depth < 8
         )
         SELECT d.id, COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)) || ' (' || host(d.ip) || ')',
                (EXTRACT(EPOCH FROM now() - d.status_since) / 60)::bigint,
                (SELECT count(DISTINCT c.id) FROM anc JOIN devices c ON c.id = anc.child
                  WHERE anc.ancestor = d.id AND c.status = 'down' AND c.monitored)
           FROM devices d
          WHERE d.monitored AND d.status = 'down'
            AND d.status_since <= now() - make_interval(mins => $1)
            AND ($2::bigint IS NULL OR d.id = $2) AND {}
            AND NOT EXISTS (SELECT 1 FROM anc JOIN devices a ON a.id = anc.ancestor
                             WHERE anc.child = d.id AND a.status = 'down' AND a.monitored)",
        scope_sql(3, 4)
    ))
    .bind(rule.duration_min)
    .bind(rule.device_id)
    .bind(&rule.sites)
    .bind(&rule.tag)
    .fetch_all(&state.db)
    .await?;
    for (device_id, label, minutes, dependents) in down {
        let mut message = if minutes > 0 { format!("{label} ist seit {minutes} Min. nicht erreichbar") } else { format!("{label} ist nicht erreichbar") };
        if dependents > 0 {
            message.push_str(&if dependents == 1 {
                " – dahinter ist 1 abhängiges Gerät ebenfalls nicht erreichbar".to_string()
            } else {
                format!(" – dahinter sind {dependents} abhängige Geräte ebenfalls nicht erreichbar")
            });
        }
        if open_alert(state, rule, Some(device_id), &message, None).await? {
            let n = Notification::new(format!("Offline: {label}"), message, Severity::Critical, device_link(state, device_id))
                .device(device_id);
            let n = if minutes > 0 { n.var("wert", format!("seit {minutes} Min. offline")) } else { n };
            dispatch(state, rule, n).await;
        }
    }

    // Entwarnung für wieder erreichbare (oder nicht mehr überwachte) Geräte
    let resolved: Vec<(i64, String, i64)> = sqlx::query_as(
        "UPDATE alerts a SET resolved_at = now()
           FROM devices d
          WHERE a.rule_id = $1 AND a.resolved_at IS NULL AND d.id = a.device_id
            AND (d.status <> 'down' OR NOT d.monitored)
          RETURNING d.id, COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)) || ' (' || host(d.ip) || ')',
                    (EXTRACT(EPOCH FROM a.resolved_at - a.opened_at) / 60)::bigint",
    )
    .bind(rule.id)
    .fetch_all(&state.db)
    .await?;
    if rule.notify_recovery {
        for (device_id, label, minutes) in resolved {
            let n = Notification::new(
                format!("Wieder online: {label}"),
                format!("{label} ist wieder erreichbar (Alarm bestand {minutes} Min.)"),
                Severity::Resolved,
                device_link(state, device_id),
            )
            .device(device_id)
            .var("wert", format!("{minutes} Min. Ausfall"));
            dispatch(state, rule, n).await;
        }
    }
    Ok(())
}

async fn threshold(state: &AppState, rule: &Rule) -> Result<()> {
    let Some(limit) = rule.threshold else { return Ok(()) };
    // Spaltenname stammt aus einer festen Liste – kein SQL aus Benutzereingaben
    let (column, what, unit) = match rule.kind.as_str() {
        "disk_usage" => ("disk_pct", "Speicherbelegung", "%"),
        "cpu_usage" => ("cpu_pct", "CPU-Auslastung", "%"),
        "mem_usage" => ("mem_pct", "RAM-Auslastung", "%"),
        _ => ("temp_c", "Temperatur", "°C"),
    };
    // Wert muss über die gesamte Dauer über dem Schwellwert liegen (mindestens die letzte Messung)
    let window = rule.duration_min.max(0);
    let rows: Vec<(i64, String, Option<f32>, Option<f32>)> = sqlx::query_as(&format!(
        "SELECT s.device_id, COALESCE(d.name, d.hostname, host(d.ip)) || ' (' || host(d.ip) || ')',
                (array_agg(s.{column} ORDER BY s.time DESC))[1],
                min(s.{column}) FILTER (WHERE s.time > now() - make_interval(mins => $2))
           FROM device_stats s JOIN devices d ON d.id = s.device_id
          WHERE s.time > now() - make_interval(mins => GREATEST($2, 0) + 15)
            AND s.{column} IS NOT NULL AND ($1::bigint IS NULL OR s.device_id = $1) AND {scope}
          GROUP BY s.device_id, d.name, d.hostname, d.ip",
        scope = scope_sql(3, 4)
    ))
    .bind(rule.device_id)
    .bind(window)
    .bind(&rule.sites)
    .bind(&rule.tag)
    .fetch_all(&state.db)
    .await?;

    for (device_id, label, latest, window_min) in rows {
        let Some(latest) = latest else { continue };
        let sustained = if window > 0 { window_min.unwrap_or(latest) } else { latest };
        if sustained > limit {
            let message = format!("{what} von {label} liegt bei {latest:.0} {unit} (Grenze {limit:.0} {unit})");
            if open_alert(state, rule, Some(device_id), &message, Some(latest)).await? {
                let n = Notification::new(format!("{what} hoch: {label}"), message, Severity::Warning, device_link(state, device_id))
                    .device(device_id)
                    .var("wert", format!("{latest:.0} {unit} (Grenze {limit:.0} {unit})"));
                dispatch(state, rule, n).await;
            }
        } else if latest <= limit {
            let closed: Option<(i64,)> = sqlx::query_as(
                "UPDATE alerts SET resolved_at = now() WHERE rule_id = $1 AND device_id = $2 AND resolved_at IS NULL RETURNING id",
            )
            .bind(rule.id)
            .bind(device_id)
            .fetch_optional(&state.db)
            .await?;
            if closed.is_some() && rule.notify_recovery {
                let n = Notification::new(
                    format!("{what} wieder normal: {label}"),
                    format!("{what} von {label} liegt wieder bei {latest:.0} {unit}"),
                    Severity::Resolved,
                    device_link(state, device_id),
                )
                .device(device_id)
                .var("wert", format!("{latest:.0} {unit}"));
                dispatch(state, rule, n).await;
            }
        }
    }
    Ok(())
}

fn check_link(state: &AppState) -> Option<String> {
    state.config.public_url.as_ref().map(|u| format!("{u}/#/checks"))
}

/// Dienst-Check ausgefallen (länger als `duration_min`)
async fn check_down(state: &AppState, rule: &Rule) -> Result<()> {
    type Down = (i64, String, String, Option<String>, Option<i64>, i64);
    let down: Vec<Down> = sqlx::query_as(
        "SELECT c.id, c.name, c.target, c.last_message, c.device_id, (EXTRACT(EPOCH FROM now() - c.status_since) / 60)::bigint
           FROM checks c LEFT JOIN devices d ON d.id = c.device_id
          WHERE c.enabled AND c.status = 'down' AND c.status_since <= now() - make_interval(mins => $1)
            AND ($2::bigint IS NULL OR c.id = $2)
            AND ($3::bigint[] IS NULL OR c.site_id = ANY($3)) AND ($4::text IS NULL OR $4 = ANY(d.tags))",
    )
    .bind(rule.duration_min)
    .bind(rule.check_id)
    .bind(&rule.sites)
    .bind(&rule.tag)
    .fetch_all(&state.db)
    .await?;
    for (check_id, name, target, reason, device_id, minutes) in down {
        let reason = reason.unwrap_or_default();
        let message = format!("Dienst „{name}“ ({target}) funktioniert nicht: {reason}");
        if open_check_alert(state, rule, check_id, device_id, &message).await? {
            let mut n = Notification::new(format!("Dienst ausgefallen: {name}"), message, Severity::Critical, check_link(state))
                .var("geraet", &name)
                .var("ip", format!("({target})"))
                .var("wert", reason);
            if minutes > 0 {
                n = n.var("wert", format!("seit {minutes} Min."));
            }
            n.device_id = device_id;
            n.check_id = Some(check_id);
            dispatch(state, rule, n).await;
        }
    }
    let resolved: Vec<(i64, String, String, Option<i64>, i64)> = sqlx::query_as(
        "UPDATE alerts a SET resolved_at = now()
           FROM checks c
          WHERE a.rule_id = $1 AND a.resolved_at IS NULL AND c.id = a.check_id AND (c.status <> 'down' OR NOT c.enabled)
          RETURNING c.id, c.name, c.target, c.device_id, (EXTRACT(EPOCH FROM a.resolved_at - a.opened_at) / 60)::bigint",
    )
    .bind(rule.id)
    .fetch_all(&state.db)
    .await?;
    if rule.notify_recovery {
        for (check_id, name, target, device_id, minutes) in resolved {
            let mut n = Notification::new(
                format!("Dienst wieder da: {name}"),
                format!("Dienst „{name}“ ({target}) funktioniert wieder (Ausfall {minutes} Min.)"),
                Severity::Resolved,
                check_link(state),
            )
            .var("geraet", &name)
            .var("ip", format!("({target})"));
            n.device_id = device_id;
            n.check_id = Some(check_id);
            dispatch(state, rule, n).await;
        }
    }
    Ok(())
}

/// Zertifikat läuft in weniger als `threshold` Tagen ab
async fn cert_expiry(state: &AppState, rule: &Rule) -> Result<()> {
    let days = rule.threshold.unwrap_or(14.0).max(0.0);
    type Expiring = (i64, String, String, Option<i64>, chrono::DateTime<chrono::Utc>);
    let expiring: Vec<Expiring> = sqlx::query_as(
        "SELECT c.id, c.name, c.target, c.device_id, c.cert_expires_at FROM checks c LEFT JOIN devices d ON d.id = c.device_id
          WHERE c.enabled AND c.cert_expires_at IS NOT NULL AND c.cert_expires_at < now() + make_interval(days => $1)
            AND ($2::bigint IS NULL OR c.id = $2)
            AND ($3::bigint[] IS NULL OR c.site_id = ANY($3)) AND ($4::text IS NULL OR $4 = ANY(d.tags))",
    )
    .bind(days as i32)
    .bind(rule.check_id)
    .bind(&rule.sites)
    .bind(&rule.tag)
    .fetch_all(&state.db)
    .await?;
    for (check_id, name, target, device_id, until) in expiring {
        let left = (until - chrono::Utc::now()).num_days();
        let message = if left < 0 {
            format!("Zertifikat von „{name}“ ({target}) ist seit {} abgelaufen", until.format("%d.%m.%Y"))
        } else {
            format!("Zertifikat von „{name}“ ({target}) läuft in {left} Tagen ab ({})", until.format("%d.%m.%Y"))
        };
        if open_check_alert(state, rule, check_id, device_id, &message).await? {
            let mut n = Notification::new(format!("Zertifikat läuft ab: {name}"), message, Severity::Warning, check_link(state))
                .var("geraet", &name)
                .var("ip", format!("({target})"))
                .var("wert", format!("noch {left} Tage"));
            n.device_id = device_id;
            n.check_id = Some(check_id);
            dispatch(state, rule, n).await;
        }
    }
    // Erneuerte Zertifikate: Alarm schließen
    sqlx::query(
        "UPDATE alerts a SET resolved_at = now() FROM checks c
          WHERE a.rule_id = $1 AND a.resolved_at IS NULL AND c.id = a.check_id
            AND (c.cert_expires_at IS NULL OR c.cert_expires_at >= now() + make_interval(days => $2))",
    )
    .bind(rule.id)
    .bind(days as i32)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn open_check_alert(state: &AppState, rule: &Rule, check_id: i64, device_id: Option<i64>, message: &str) -> sqlx::Result<bool> {
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO alerts (rule_id, check_id, device_id, message, last_notified_at, severity) VALUES ($1, $2, NULL, $3, now(), $4)
         ON CONFLICT (rule_id, (COALESCE(device_id, 0)), (COALESCE(check_id, 0))) WHERE resolved_at IS NULL DO NOTHING
         RETURNING id",
    )
    .bind(rule.id)
    .bind(check_id)
    .bind(message)
    .bind(severity_of(rule))
    .fetch_optional(&state.db)
    .await?;
    let _ = device_id;
    Ok(inserted.is_some())
}

fn matches_pattern(rule: &Rule, text: &str) -> bool {
    rule.pattern.as_deref().map(str::trim).filter(|p| !p.is_empty()).is_none_or(|p| text.to_lowercase().contains(&p.to_lowercase()))
}

/// Regelmäßig gesicherte Container ohne erfolgreiches Backup in den letzten `threshold` Stunden
/// (ein Sammelalarm je Regel; Entwarnung, sobald alle wieder aktuell sind)
async fn job_missing(state: &AppState, rule: &Rule) -> Result<()> {
    let hours = f64::from(rule.threshold.unwrap_or(26.0)).max(1.0);
    type Row = (String, String, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT i.name, s->>'name',
                (SELECT max(r.time) FROM integration_reports r
                  WHERE r.integration_id = i.id AND r.subject = s->>'name' AND r.kind = 'backup' AND r.status = 'ok'),
                i.created_at
           FROM integrations i CROSS JOIN LATERAL jsonb_array_elements(i.inventory) s
          WHERE i.enabled AND COALESCE((s->>'scheduled')::boolean, false)",
    )
    .fetch_all(&state.db)
    .await?;
    let limit = chrono::Utc::now() - chrono::Duration::minutes((hours * 60.0) as i64);
    let stale: Vec<String> = rows
        .into_iter()
        .filter(|(_, subject, last, since)| last.unwrap_or(*since) < limit && matches_pattern(rule, subject))
        .map(|(_, subject, last, _)| match last {
            Some(t) => format!("{subject} (zuletzt vor {} h)", (chrono::Utc::now() - t).num_hours()),
            None => format!("{subject} (noch nie)"),
        })
        .collect();
    if !stale.is_empty() {
        let message = format!("Kein erfolgreiches Backup in den letzten {hours:.0} Stunden: {}", stale.join(", "));
        if open_alert(state, rule, None, &message, Some(stale.len() as f32)).await? {
            let n = Notification::new("Backup überfällig", message, Severity::Warning, None).var("wert", format!("{} Container", stale.len()));
            dispatch(state, rule, n).await;
        }
        return Ok(());
    }
    let resolved: Vec<(i64,)> = sqlx::query_as("UPDATE alerts SET resolved_at = now() WHERE rule_id = $1 AND resolved_at IS NULL RETURNING id")
        .bind(rule.id)
        .fetch_all(&state.db)
        .await?;
    if rule.notify_recovery && !resolved.is_empty() {
        let n = Notification::new("Backups wieder aktuell", "Alle regelmäßig gesicherten Container haben ein aktuelles Backup", Severity::Resolved, None);
        dispatch(state, rule, n).await;
    }
    Ok(())
}

/// Bis wann Protokollmeldungen je Regel schon geprüft wurden (beim Start: ab jetzt)
fn syslog_cursor() -> &'static std::sync::Mutex<std::collections::HashMap<i64, chrono::DateTime<chrono::Utc>>> {
    static CURSOR: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<i64, chrono::DateTime<chrono::Utc>>>> =
        std::sync::OnceLock::new();
    CURSOR.get_or_init(Default::default)
}

/// Neue Syslog-/Trap-Meldungen, die zur Regel passen (Suchtext, höchstens Schwere X) – eine Nachricht je Gerät
async fn syslog_match(state: &AppState, rule: &Rule) -> Result<()> {
    let now = chrono::Utc::now();
    let since = *syslog_cursor().lock().unwrap().entry(rule.id).or_insert(now);
    let pattern = rule.pattern.as_deref().map(str::trim).filter(|p| !p.is_empty()).map(|p| {
        // Platzhalter von ILIKE entschärfen
        format!("%{}%", p.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"))
    });
    let max_severity = rule.threshold.map_or(7, |t| t as i16);
    type Hit = (Option<i64>, String, i64, String, i16, chrono::DateTime<chrono::Utc>);
    let hits: Vec<Hit> = sqlx::query_as(
        "SELECT m.device_id, COALESCE(d.name, d.reported_name, d.hostname, host(m.source)) || ' (' || host(m.source) || ')',
                count(*), (array_agg(m.message ORDER BY m.time DESC))[1], min(m.severity), max(m.time)
           FROM syslog_messages m LEFT JOIN devices d ON d.id = m.device_id
          WHERE m.time > $1 AND m.severity <= $2
            AND ($3::text IS NULL OR m.message ILIKE $3 OR m.app ILIKE $3)
            AND ($4::bigint IS NULL OR m.device_id = $4)
            AND ($5::bigint[] IS NULL OR d.site_id = ANY($5)) AND ($6::text IS NULL OR $6 = ANY(d.tags))
          GROUP BY m.device_id, d.name, d.reported_name, d.hostname, m.source",
    )
    .bind(since)
    .bind(max_severity)
    .bind(&pattern)
    .bind(rule.device_id)
    .bind(&rule.sites)
    .bind(&rule.tag)
    .fetch_all(&state.db)
    .await?;
    let newest = hits.iter().map(|h| h.5).max().unwrap_or(since).max(since);
    syslog_cursor().lock().unwrap().insert(rule.id, newest);
    // Schutz vor Benachrichtigungs-Flut (z. B. gefälschte Absender): höchstens 5 Einzelmeldungen je Durchlauf
    let extra = hits.len().saturating_sub(5);
    if extra > 0 {
        let total: i64 = hits.iter().skip(5).map(|h| h.2).sum();
        let n = Notification::new(
            format!("Protokoll: {extra} weitere Absender"),
            format!("{total} weitere passende Meldungen von {extra} weiteren Absendern – Details unter Protokolle"),
            Severity::Warning,
            state.config.public_url.as_ref().map(|u| format!("{u}/#/syslog")),
        );
        dispatch(state, rule, n).await;
    }
    for (device_id, label, count, sample, severity, _) in hits.into_iter().take(5) {
        let message = if count == 1 { sample.clone() } else { format!("{count} Meldungen, zuletzt: {sample}") };
        sqlx::query("INSERT INTO alerts (rule_id, device_id, message, resolved_at, severity) VALUES ($1, $2, $3, now(), $4)")
            .bind(rule.id)
            .bind(device_id)
            .bind(&message)
            .bind(severity_of(rule))
            .execute(&state.db)
            .await?;
        let level = match severity {
            0..=2 => Severity::Critical,
            3 | 4 => Severity::Warning,
            _ => Severity::Info,
        };
        let mut n = Notification::new(format!("Protokoll: {label}"), message, level, state.config.public_url.as_ref().map(|u| format!("{u}/#/syslog")))
            .var("wert", format!("{count} Meldung(en)"));
        n.device_id = device_id;
        dispatch(state, rule, n).await;
    }
    Ok(())
}

/// Offene Alarme erneut melden, solange sie bestehen (je Regel einstellbar)
async fn reminders(state: &AppState, rules: &[Rule]) -> Result<()> {
    for rule in rules.iter().filter(|r| r.repeat_min > 0) {
        // Meldung ohne die ursprüngliche Dauer („seit 5 Min.“) – die aktuelle Dauer kommt dazu
        let due: Vec<(i64, Option<i64>, String, i32, i64)> = sqlx::query_as(
            "UPDATE alerts SET last_notified_at = now(), notify_count = notify_count + 1
              WHERE rule_id = $1 AND resolved_at IS NULL AND acknowledged_at IS NULL
                AND COALESCE(last_notified_at, opened_at) <= now() - make_interval(mins => $2)
              RETURNING id, device_id, message, notify_count, (EXTRACT(EPOCH FROM now() - opened_at) / 60)::bigint",
        )
        .bind(rule.id)
        .bind(rule.repeat_min)
        .fetch_all(&state.db)
        .await?;
        for (_, device_id, message, count, minutes) in due {
            // Bestätigte Alarme werden oben ausgefiltert – wer sich kümmert, wird nicht weiter erinnert
            let severity = if matches!(rule.kind.as_str(), "device_down" | "check_down") { Severity::Critical } else { Severity::Warning };
            let mut n = Notification::new(
                format!("Erinnerung ({count}.): {}", rule.name),
                format!("{} – besteht seit {minutes} Min.", strip_duration(&message)),
                severity,
                device_id.and_then(|id| device_link(state, id)),
            );
            n.device_id = device_id;
            dispatch(state, rule, n).await;
        }
    }
    Ok(())
}

/// „NAS ist seit 5 Min. nicht erreichbar“ → „NAS ist nicht erreichbar“
fn strip_duration(message: &str) -> String {
    match (message.find(" seit "), message.find(" Min. ")) {
        (Some(a), Some(b)) if b > a => format!("{}{}", &message[..a], &message[b + 5..]),
        _ => message.to_string(),
    }
}

/// Legt einen offenen Alarm an; `false`, wenn für Regel+Gerät schon einer offen ist.
async fn open_alert(state: &AppState, rule: &Rule, device_id: Option<i64>, message: &str, value: Option<f32>) -> sqlx::Result<bool> {
    // Ohne feste Schwere der Regel bestimmt die Priorität des Geräts mit (wichtig = eine Stufe höher, unwichtig = Hinweis)
    let inserted: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO alerts (rule_id, device_id, message, value, last_notified_at, severity)
         VALUES ($1, $2, $3, $4, now(),
                 CASE WHEN $6 THEN $5 ELSE COALESCE((SELECT CASE d.priority
                     WHEN 'high' THEN CASE $5 WHEN 'info' THEN 'warning' ELSE 'critical' END
                     WHEN 'low' THEN 'info' ELSE $5 END FROM devices d WHERE d.id = $2), $5) END)
         ON CONFLICT (rule_id, (COALESCE(device_id, 0)), (COALESCE(check_id, 0))) WHERE resolved_at IS NULL DO NOTHING
         RETURNING id",
    )
    .bind(rule.id)
    .bind(device_id)
    .bind(message)
    .bind(value)
    .bind(severity_of(rule))
    .bind(rule.severity.is_some())
    .fetch_optional(&state.db)
    .await?;
    Ok(inserted.is_some())
}

/// Voreingestellte Schwere je Regelart (für die Anzeige im Leitstand)
pub fn default_severity(kind: &str) -> &'static str {
    match kind {
        "device_down" | "check_down" => "critical",
        "new_device" => "info",
        _ => "warning",
    }
}

fn severity_of(rule: &Rule) -> String {
    rule.severity.clone().unwrap_or_else(|| default_severity(&rule.kind).to_string())
}

/// Schwere nach Priorität des Geräts: wichtig = eine Stufe höher, unwichtig = nur Hinweis
pub fn by_priority(severity: Severity, priority: &str) -> Severity {
    match (priority, severity) {
        (_, Severity::Resolved) => Severity::Resolved,
        ("high", Severity::Info) => Severity::Warning,
        ("high", _) => Severity::Critical,
        ("low", _) => Severity::Info,
        _ => severity,
    }
}

fn parse_severity(name: &str) -> Severity {
    match name {
        "critical" => Severity::Critical,
        "info" => Severity::Info,
        _ => Severity::Warning,
    }
}

/// Unbestätigte Alarme nach `escalate_after_min` Minuten einmalig an die Eskalationskanäle und -gruppen melden
async fn escalations(state: &AppState, rules: &[Rule]) -> Result<()> {
    for rule in rules.iter().filter(|r| r.escalate_after_min > 0) {
        if rule.escalate_channel_ids.is_empty() && rule.escalate_group_ids.is_empty() {
            continue;
        }
        let due: Vec<(Option<i64>, Option<i64>, String, i64)> = sqlx::query_as(
            "UPDATE alerts SET escalated_at = now()
              WHERE rule_id = $1 AND resolved_at IS NULL AND acknowledged_at IS NULL AND escalated_at IS NULL
                AND opened_at <= now() - make_interval(mins => $2)
              RETURNING device_id, check_id, message, (EXTRACT(EPOCH FROM now() - opened_at) / 60)::bigint",
        )
        .bind(rule.id)
        .bind(rule.escalate_after_min)
        .fetch_all(&state.db)
        .await?;
        for (device_id, check_id, message, minutes) in due {
            let mut n = Notification::new(
                format!("Eskalation: {}", rule.name),
                format!("{} – seit {minutes} Min. nicht bestätigt", strip_duration(&message)),
                Severity::Critical,
                device_id.and_then(|id| device_link(state, id)),
            );
            n.device_id = device_id;
            n.check_id = check_id;
            let target = Targets { channels: &rule.escalate_channel_ids, groups: &rule.escalate_group_ids };
            deliver_to(state, rule, n, target).await;
        }
    }
    Ok(())
}

struct Targets<'a> {
    channels: &'a [i64],
    groups: &'a [i64],
}

/// Platzhalter ergänzen, im Browser anzeigen und an alle Kanäle der Regel zustellen
async fn dispatch(state: &AppState, rule: &Rule, n: Notification) {
    let target = Targets { channels: &rule.channel_ids, groups: &rule.group_ids };
    deliver_to(state, rule, n, target).await;
}

async fn deliver_to(state: &AppState, rule: &Rule, mut n: Notification, target: Targets<'_>) {
    // Feste Schwere der Regel (Entwarnungen bleiben Entwarnungen)
    if let (Some(name), false) = (&rule.severity, n.severity == Severity::Resolved) {
        n.severity = parse_severity(name);
    } else if let (None, Some(device_id), false) = (&rule.severity, n.device_id, n.severity == Severity::Resolved) {
        // Keine feste Schwere: Priorität des Geräts berücksichtigen
        if let Ok(Some((priority,))) =
            sqlx::query_as::<_, (String,)>("SELECT priority FROM devices WHERE id = $1").bind(device_id).fetch_optional(&state.db).await
        {
            n.severity = by_priority(n.severity, &priority);
        }
    }
    // Wartungsfenster: aufzeichnen ja, benachrichtigen nein
    if let Some(window) = crate::maintenance::active_for(&state.db, n.device_id, n.check_id).await {
        tracing::info!("„{}“ nicht gemeldet – Wartungsfenster „{window}“ aktiv", n.title);
        return;
    }
    n.vars.insert("regel".into(), rule.name.clone());
    n.vars.insert(
        "zeit".into(),
        chrono::Utc::now().with_timezone(&crate::scanner::schedule::timezone()).format("%d.%m.%Y %H:%M").to_string(),
    );
    n.vars.insert("tag".into(), format!("rule-{}-{}", rule.id, n.device_id.unwrap_or(0)));
    if let Some(device_id) = n.device_id {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT COALESCE(name, reported_name, hostname, host(ip)), host(ip) FROM devices WHERE id = $1")
                .bind(device_id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        if let Some((label, ip)) = row {
            n.vars.insert("geraet".into(), label);
            n.vars.insert("ip".into(), format!("({ip})"));
        }
    }

    // Sofort als Hinweis in allen offenen Browsern anzeigen (unabhängig von den Kanälen)
    state.hub.publish(&serde_json::json!({
        "type": "alert",
        "title": n.title,
        "message": n.message,
        "severity": n.severity.name(),
        "rule": rule.name,
        "device_id": n.device_id,
        "check_id": n.check_id,
    }));
    deliver::to_groups(state, target.groups, &n).await;
    let channels: Vec<(i64, String, String, String)> = match sqlx::query_as(
        "SELECT id, name, kind, config FROM notification_channels WHERE enabled AND id = ANY($1)",
    )
    .bind(target.channels)
    .fetch_all(&state.db)
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Kanäle nicht ladbar: {e}");
            return;
        }
    };
    for (id, name, kind, sealed) in channels {
        match state.vault.open_value::<Value>(&sealed) {
            Ok(config) => deliver::to_channel(state, id, &name, &kind, config, &n).await,
            Err(e) => tracing::warn!("Kanal {id} ({name}) nicht lesbar: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schwere_nach_prioritaet() {
        assert_eq!(by_priority(Severity::Warning, "high"), Severity::Critical);
        assert_eq!(by_priority(Severity::Info, "high"), Severity::Warning);
        assert_eq!(by_priority(Severity::Critical, "low"), Severity::Info);
        assert_eq!(by_priority(Severity::Warning, "normal"), Severity::Warning);
        assert_eq!(by_priority(Severity::Resolved, "high"), Severity::Resolved);
    }

    #[test]
    fn dauer_entfernen() {
        assert_eq!(strip_duration("NAS (10.0.0.5) ist seit 5 Min. nicht erreichbar"), "NAS (10.0.0.5) ist nicht erreichbar");
        assert_eq!(strip_duration("CPU hoch"), "CPU hoch");
    }

    fn rule(sites: Option<Vec<i64>>, tag: Option<&str>) -> Rule {
        Rule {
            id: 1,
            name: "r".into(),
            kind: "device_down".into(),
            device_id: None,
            threshold: None,
            duration_min: 0,
            channel_ids: vec![],
            notify_recovery: false,
            repeat_min: 0,
            check_id: None,
            pattern: None,
            site_id: None,
            tag: tag.map(str::to_string),
            severity: None,
            group_ids: vec![],
            escalate_after_min: 0,
            escalate_channel_ids: vec![],
            escalate_group_ids: vec![],
            sites,
        }
    }

    #[test]
    fn regel_bereich() {
        assert!(in_scope(&rule(None, None), None, &[]));
        assert!(in_scope(&rule(Some(vec![2, 3]), None), Some(3), &[]));
        assert!(!in_scope(&rule(Some(vec![2, 3]), None), Some(1), &[]));
        assert!(!in_scope(&rule(Some(vec![2]), None), None, &[]));
        assert!(in_scope(&rule(None, Some("kritisch")), Some(1), &["kritisch".into()]));
        assert!(!in_scope(&rule(None, Some("kritisch")), Some(1), &["test".into()]));
    }
}
