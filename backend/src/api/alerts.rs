//! Benachrichtigungskanäle, Alarmregeln und ausgelöste Alarme.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::FromRow;

use crate::{
    alerts::notify::{self, Notification, Severity},
    audit,
    auth::{perm, Need},
    error::{ApiError, ApiResult},
    AppState,
};

const CHANNEL_KINDS: &[&str] = &["email", "ntfy", "gotify", "telegram", "discord", "teams", "webhook", "app"];
const RULE_KINDS: &[&str] = &[
    "device_down", "new_device", "mac_changed", "disk_usage", "cpu_usage", "mem_usage", "temperature", "check_down", "cert_expiry",
    "syslog_match", "job_failed", "job_missing",
];
const MASK: &str = "••••••";

// ---------------------------------------------------------------------------
// Kanäle
// ---------------------------------------------------------------------------

/// Geheime Felder für die Anzeige maskieren
fn masked(config: &Value) -> Value {
    let mut out = config.as_object().cloned().unwrap_or_default();
    for key in notify::SECRET_FIELDS {
        if out.get(*key).and_then(Value::as_str).is_some_and(|v| !v.is_empty()) {
            out.insert((*key).to_string(), json!(MASK));
        }
    }
    Value::Object(out)
}

async fn channel_json(st: &AppState, id: i64) -> ApiResult<Value> {
    type Row = (String, String, String, bool, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<String>);
    let (name, kind, sealed, enabled, last_attempt_at, last_ok_at, last_error): Row = sqlx::query_as(
        "SELECT name, kind, config, enabled, last_attempt_at, last_ok_at, last_error FROM notification_channels WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let config: Value = st.vault.open_value(&sealed)?;
    // Wie viele Regeln nutzen den Kanal? (0 = er wird nie verwendet)
    let (rules,): (i64,) = sqlx::query_as("SELECT count(*) FROM alert_rules WHERE enabled AND $1 = ANY(channel_ids)").bind(id).fetch_one(&st.db).await?;
    let push_devices: Option<i64> = if kind == "app" {
        Some(sqlx::query_scalar("SELECT count(*) FROM push_subscriptions").fetch_one(&st.db).await?)
    } else {
        None
    };
    Ok(json!({
        "id": id, "name": name, "kind": kind, "enabled": enabled, "config": masked(&config),
        "last_attempt_at": last_attempt_at, "last_ok_at": last_ok_at, "last_error": last_error,
        "rules": rules, "push_devices": push_devices,
    }))
}

pub async fn list_channels(State(st): State<AppState>, _admin: Need<perm::AlertsManage>) -> ApiResult<Json<Vec<Value>>> {
    let ids: Vec<(i64,)> = sqlx::query_as("SELECT id FROM notification_channels ORDER BY name").fetch_all(&st.db).await?;
    let mut out = Vec::new();
    for (id,) in ids {
        out.push(channel_json(&st, id).await?);
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct ChannelInput {
    name: Option<String>,
    kind: Option<String>,
    enabled: Option<bool>,
    #[serde(default)]
    config: Map<String, Value>,
}

pub async fn create_channel(
    State(st): State<AppState>,
    Need(user, _): Need<perm::AlertsManage>,
    Json(req): Json<ChannelInput>,
) -> ApiResult<Json<Value>> {
    let name = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or("Kanal");
    let kind = req.kind.as_deref().unwrap_or_default();
    if !CHANNEL_KINDS.contains(&kind) {
        return Err(ApiError::BadRequest("Unbekannter Kanaltyp".into()));
    }
    let config = Value::Object(req.config);
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO notification_channels (name, kind, config, enabled) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(name)
    .bind(kind)
    .bind(st.vault.seal(&config)?)
    .bind(req.enabled.unwrap_or(true))
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "channel_add", json!({ "id": id, "name": name, "kind": kind })).await;
    Ok(Json(channel_json(&st, id).await?))
}

pub async fn update_channel(
    State(st): State<AppState>,
    Need(user, _): Need<perm::AlertsManage>,
    Path(id): Path<i64>,
    Json(req): Json<ChannelInput>,
) -> ApiResult<Json<Value>> {
    let (sealed,): (String,) = sqlx::query_as("SELECT config FROM notification_channels WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut config: Map<String, Value> = st.vault.open_value(&sealed)?;
    // Wird die Zieladresse geändert, dürfen gespeicherte Geheimnisse nicht still an den neuen Server gehen
    let target_changed = ["server", "host"].iter().any(|k| {
        req.config.get(*k).is_some_and(|v| v.as_str() != Some(MASK) && Some(v) != config.get(*k))
    });
    if target_changed {
        let secret_kept = notify::SECRET_FIELDS.iter().any(|k| {
            config.get(*k).and_then(Value::as_str).is_some_and(|v| !v.is_empty())
                && req.config.get(*k).is_none_or(|v| v.as_str() == Some(MASK))
        });
        if secret_kept {
            return Err(ApiError::BadRequest("Server geändert – bitte Passwort/Token ebenfalls neu eingeben".into()));
        }
    }
    for (key, value) in req.config {
        // Maskierte Werte bedeuten „unverändert lassen“
        if value.as_str() != Some(MASK) {
            config.insert(key, value);
        }
    }
    sqlx::query(
        "UPDATE notification_channels SET name = COALESCE(NULLIF(trim($2), ''), name),
                enabled = COALESCE($3, enabled), config = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(&req.name)
    .bind(req.enabled)
    .bind(st.vault.seal(&Value::Object(config))?)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "channel_update", json!({ "id": id })).await;
    Ok(Json(channel_json(&st, id).await?))
}

pub async fn delete_channel(
    State(st): State<AppState>,
    Need(user, _): Need<perm::AlertsManage>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let (name,): (String,) = sqlx::query_as("DELETE FROM notification_channels WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    sqlx::query("UPDATE alert_rules SET channel_ids = array_remove(channel_ids, $1)")
        .bind(id)
        .execute(&st.db)
        .await?;
    audit::by(&st.db, &user, "channel_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Testnachricht senden – zeigt Fehler direkt in der Oberfläche an
pub async fn test_channel(State(st): State<AppState>, _admin: Need<perm::AlertsManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let (kind, sealed): (String, String) =
        sqlx::query_as("SELECT kind, config FROM notification_channels WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound)?;
    let config: Value = st.vault.open_value(&sealed)?;
    let notification = Notification::new(
        "Testnachricht von NetPulse",
        "Wenn du das liest, funktioniert dieser Benachrichtigungskanal. 🎉",
        Severity::Info,
        st.config.public_url.clone(),
    )
    .var("geraet", "Beispiel-NAS")
    .var("ip", "(192.168.178.10)")
    .var("regel", "Test")
    .var("wert", "42 %");
    if kind == "app" {
        let message = crate::push::PushMessage {
            title: &notification.title,
            body: &notification.message,
            severity: "warning",
            url: "/#/alerts",
            tag: "test",
        };
        let result = crate::push::send(&st, None, &message).await.and_then(|r| {
            let (sent, failed, errors) = (r.ok, r.failed, r.errors.clone());
            r.into_result().map(|_| (sent, failed, errors))
        });
        crate::alerts::deliver::record(&st, id, &result.as_ref().map(|_| ()).map_err(|e| anyhow::anyhow!("{e:#}"))).await;
        let (sent, failed, errors) = result.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
        return Ok(Json(json!({ "ok": true, "sent": sent, "failed": failed, "errors": errors })));
    }
    let result = crate::alerts::deliver::send_now(&st, &kind, config, &notification).await;
    crate::alerts::deliver::record(&st, id, &result).await;
    result.map_err(|e| ApiError::BadRequest(format!("Senden fehlgeschlagen: {e:#}")))?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Zentraler E-Mail-Server
// ---------------------------------------------------------------------------

pub async fn get_smtp(State(st): State<AppState>, _admin: Need<perm::AlertsManage>) -> Json<Value> {
    let config = Value::Object(crate::alerts::deliver::load_smtp(&st).await);
    Json(json!({ "config": masked(&config), "configured": config["host"].as_str().is_some_and(|h| !h.is_empty()) }))
}

pub async fn set_smtp(State(st): State<AppState>, Need(user, _): Need<perm::AlertsManage>, Json(req): Json<Map<String, Value>>) -> ApiResult<Json<Value>> {
    let mut config = crate::alerts::deliver::load_smtp(&st).await;
    for key in crate::alerts::deliver::SMTP_FIELDS {
        if let Some(value) = req.get(*key) {
            if value.as_str() != Some(MASK) {
                config.insert((*key).to_string(), value.clone());
            }
        }
    }
    if let Some(from) = config.get("from").and_then(Value::as_str).filter(|f| !f.is_empty()) {
        from.parse::<lettre::Address>().map_err(|_| ApiError::BadRequest("Absenderadresse ist ungültig".into()))?;
    }
    crate::alerts::deliver::save_smtp(&st, &config).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    audit::by(&st.db, &user, "smtp_update", json!({ "host": config.get("host") })).await;
    Ok(get_smtp(State(st), Need(user, std::marker::PhantomData)).await)
}

#[derive(Deserialize)]
pub struct SmtpTest {
    to: String,
}

pub async fn test_smtp(State(st): State<AppState>, _admin: Need<perm::AlertsManage>, Json(req): Json<SmtpTest>) -> ApiResult<Json<Value>> {
    let notification = Notification::new(
        "E-Mail-Server funktioniert",
        "Diese Testnachricht wurde über den zentralen E-Mail-Server von NetPulse verschickt.",
        Severity::Info,
        st.config.public_url.clone(),
    )
    .var("regel", "Test");
    crate::alerts::deliver::send_now(&st, "email", json!({ "to": req.to }), &notification)
        .await
        .map_err(|e| ApiError::BadRequest(format!("Senden fehlgeschlagen: {e:#}")))?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Regeln
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct RuleRow {
    id: i64,
    name: String,
    kind: String,
    device_id: Option<i64>,
    device_label: Option<String>,
    threshold: Option<f32>,
    duration_min: i32,
    channel_ids: Vec<i64>,
    notify_recovery: bool,
    enabled: bool,
    repeat_min: i32,
    check_id: Option<i64>,
    check_label: Option<String>,
    pattern: Option<String>,
    site_id: Option<i64>,
    site_label: Option<String>,
    tag: Option<String>,
    severity: Option<String>,
    group_ids: Vec<i64>,
    escalate_after_min: i32,
    escalate_channel_ids: Vec<i64>,
    escalate_group_ids: Vec<i64>,
}

const RULE_SELECT: &str = "SELECT r.id, r.name, r.kind, r.device_id, COALESCE(d.name, d.hostname, host(d.ip)) AS device_label,
                                  r.threshold, r.duration_min, r.channel_ids, r.notify_recovery, r.enabled, r.repeat_min,
                                  r.check_id, c.name AS check_label, r.pattern, r.site_id, s.name AS site_label, r.tag, r.severity,
                                  r.group_ids, r.escalate_after_min, r.escalate_channel_ids, r.escalate_group_ids
                             FROM alert_rules r LEFT JOIN devices d ON d.id = r.device_id LEFT JOIN checks c ON c.id = r.check_id
                             LEFT JOIN sites s ON s.id = r.site_id";

pub async fn list_rules(State(st): State<AppState>, _admin: Need<perm::AlertsManage>) -> ApiResult<Json<Vec<RuleRow>>> {
    let sql = format!("{RULE_SELECT} ORDER BY r.name");
    Ok(Json(sqlx::query_as::<_, RuleRow>(&sql).fetch_all(&st.db).await?))
}

#[derive(Deserialize, Serialize)]
pub struct RuleInput {
    name: Option<String>,
    kind: Option<String>,
    device_id: Option<i64>,
    threshold: Option<f32>,
    duration_min: Option<i32>,
    channel_ids: Option<Vec<i64>>,
    notify_recovery: Option<bool>,
    enabled: Option<bool>,
    /// Erinnerung alle X Minuten, solange der Alarm offen ist (0 = aus)
    repeat_min: Option<i32>,
    /// Nur für Check-Regeln: bestimmter Check (leer = alle)
    check_id: Option<i64>,
    /// Nur für Protokoll-Regeln: Suchtext
    pattern: Option<String>,
    /// Nur Geräte/Dienste in diesem Sektor (inkl. Unter-Sektoren)
    site_id: Option<i64>,
    /// Nur Geräte mit diesem Tag (Gerätegruppe)
    tag: Option<String>,
    /// info | warning | critical; leer = automatisch
    severity: Option<String>,
    /// Benutzergruppen, die benachrichtigt werden (App-Push und E-Mail an die Mitglieder)
    group_ids: Option<Vec<i64>>,
    /// Eskalation nach X Minuten ohne Bestätigung (0 = aus)
    escalate_after_min: Option<i32>,
    escalate_channel_ids: Option<Vec<i64>>,
    escalate_group_ids: Option<Vec<i64>>,
}

fn check_rule_fields(req: &RuleInput) -> ApiResult<()> {
    if req.severity.as_deref().is_some_and(|s| !s.is_empty() && !matches!(s, "info" | "warning" | "critical")) {
        return Err(ApiError::BadRequest("Schwere muss info, warning oder critical sein".into()));
    }
    if req.tag.as_deref().is_some_and(|t| t.chars().count() > 40) {
        return Err(ApiError::BadRequest("Tag darf höchstens 40 Zeichen haben".into()));
    }
    Ok(())
}

fn clean_tag(tag: &Option<String>) -> Option<String> {
    tag.as_deref().map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty())
}

pub async fn create_rule(
    State(st): State<AppState>,
    Need(user, _): Need<perm::AlertsManage>,
    Json(req): Json<RuleInput>,
) -> ApiResult<Json<RuleRow>> {
    let kind = req.kind.as_deref().unwrap_or_default();
    if !RULE_KINDS.contains(&kind) {
        return Err(ApiError::BadRequest("Unbekannter Regeltyp".into()));
    }
    let needs_threshold = matches!(kind, "disk_usage" | "cpu_usage" | "mem_usage" | "temperature" | "cert_expiry" | "job_missing");
    if needs_threshold && req.threshold.is_none() {
        return Err(ApiError::BadRequest("Bitte einen Schwellwert angeben".into()));
    }
    check_rule_fields(&req)?;
    let name = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or(kind);
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO alert_rules (name, kind, device_id, threshold, duration_min, channel_ids, notify_recovery, enabled, repeat_min, check_id, pattern,
                                  site_id, tag, severity, group_ids, escalate_after_min, escalate_channel_ids, escalate_group_ids)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULLIF($14, ''), $15, $16, $17, $18) RETURNING id",
    )
    .bind(name)
    .bind(kind)
    .bind(req.device_id)
    .bind(req.threshold)
    .bind(req.duration_min.unwrap_or(if kind == "device_down" { 5 } else { 0 }).clamp(0, 10_080))
    .bind(req.channel_ids.clone().unwrap_or_default())
    .bind(req.notify_recovery.unwrap_or(true))
    .bind(req.enabled.unwrap_or(true))
    .bind(req.repeat_min.unwrap_or(0).clamp(0, 10_080))
    .bind(req.check_id)
    .bind(req.pattern.as_deref().map(str::trim).filter(|p| !p.is_empty()).map(|p| p.chars().take(200).collect::<String>()))
    .bind(req.site_id)
    .bind(clean_tag(&req.tag))
    .bind(&req.severity)
    .bind(req.group_ids.clone().unwrap_or_default())
    .bind(req.escalate_after_min.unwrap_or(0).clamp(0, 10_080))
    .bind(req.escalate_channel_ids.clone().unwrap_or_default())
    .bind(req.escalate_group_ids.clone().unwrap_or_default())
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "rule_add", json!({ "id": id, "rule": req })).await;
    let sql = format!("{RULE_SELECT} WHERE r.id = $1");
    Ok(Json(sqlx::query_as::<_, RuleRow>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn update_rule(
    State(st): State<AppState>,
    Need(user, _): Need<perm::AlertsManage>,
    Path(id): Path<i64>,
    Json(req): Json<RuleInput>,
) -> ApiResult<Json<RuleRow>> {
    check_rule_fields(&req)?;
    let updated = sqlx::query(
        "UPDATE alert_rules SET
            name = COALESCE(NULLIF(trim($2), ''), name),
            device_id = $3,
            threshold = COALESCE($4, threshold),
            duration_min = COALESCE($5, duration_min),
            channel_ids = COALESCE($6, channel_ids),
            notify_recovery = COALESCE($7, notify_recovery),
            enabled = COALESCE($8, enabled),
            repeat_min = COALESCE($9, repeat_min),
            check_id = $10,
            pattern = CASE WHEN $11::text IS NULL THEN pattern ELSE NULLIF(trim($11), '') END,
            site_id = $12,
            tag = $13,
            severity = NULLIF($14, ''),
            group_ids = COALESCE($15, group_ids),
            escalate_after_min = COALESCE($16, escalate_after_min),
            escalate_channel_ids = COALESCE($17, escalate_channel_ids),
            escalate_group_ids = COALESCE($18, escalate_group_ids)
          WHERE id = $1",
    )
    .bind(id)
    .bind(&req.name)
    .bind(req.device_id)
    .bind(req.threshold)
    .bind(req.duration_min.map(|d| d.clamp(0, 10_080)))
    .bind(&req.channel_ids)
    .bind(req.notify_recovery)
    .bind(req.enabled)
    .bind(req.repeat_min.map(|r| r.clamp(0, 10_080)))
    .bind(req.check_id)
    .bind(req.pattern.as_deref().map(|p| p.chars().take(200).collect::<String>()))
    .bind(req.site_id)
    .bind(clean_tag(&req.tag))
    .bind(&req.severity)
    .bind(&req.group_ids)
    .bind(req.escalate_after_min.map(|m| m.clamp(0, 10_080)))
    .bind(&req.escalate_channel_ids)
    .bind(&req.escalate_group_ids)
    .execute(&st.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "rule_update", json!({ "id": id, "rule": req })).await;
    let sql = format!("{RULE_SELECT} WHERE r.id = $1");
    Ok(Json(sqlx::query_as::<_, RuleRow>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn delete_rule(
    State(st): State<AppState>,
    Need(user, _): Need<perm::AlertsManage>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let (name,): (String,) = sqlx::query_as("DELETE FROM alert_rules WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "rule_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Alarme
// ---------------------------------------------------------------------------

#[derive(Serialize, FromRow)]
pub struct AlertRow {
    id: i64,
    rule_name: String,
    rule_kind: String,
    device_id: Option<i64>,
    device_label: Option<String>,
    check_id: Option<i64>,
    opened_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    message: String,
    severity: Option<String>,
    site_id: Option<i64>,
    site_label: Option<String>,
    acknowledged_at: Option<DateTime<Utc>>,
    acknowledged_by: Option<String>,
    ack_comment: Option<String>,
    escalated_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct AlertQuery {
    open: Option<bool>,
    limit: Option<i64>,
    site: Option<i64>,
}

pub async fn list_alerts(
    State(st): State<AppState>,
    user: Need<perm::View>,
    Query(q): Query<AlertQuery>,
) -> ApiResult<Json<Vec<AlertRow>>> {
    let sites = crate::sites::filter(&st.db, &user, "view", q.site).await?;
    let alerts = sqlx::query_as::<_, AlertRow>(
        "SELECT a.id, r.name AS rule_name, r.kind AS rule_kind, a.device_id,
                COALESCE(d.name, d.reported_name, d.hostname, host(d.ip), c.name) AS device_label, a.check_id,
                a.opened_at, a.resolved_at, a.message, a.severity, COALESCE(d.site_id, c.site_id) AS site_id, s.name AS site_label,
                a.acknowledged_at, u.username AS acknowledged_by, a.ack_comment, a.escalated_at
           FROM alerts a JOIN alert_rules r ON r.id = a.rule_id LEFT JOIN devices d ON d.id = a.device_id
                LEFT JOIN checks c ON c.id = a.check_id LEFT JOIN sites s ON s.id = COALESCE(d.site_id, c.site_id)
                LEFT JOIN users u ON u.id = a.acknowledged_by
          WHERE (NOT $1 OR a.resolved_at IS NULL)
            AND ($3::bigint[] IS NULL OR COALESCE(d.site_id, c.site_id) = ANY($3))
          ORDER BY (a.resolved_at IS NULL) DESC, a.opened_at DESC
          LIMIT $2",
    )
    .bind(q.open.unwrap_or(false))
    .bind(q.limit.unwrap_or(200).clamp(1, 1000))
    .bind(&sites)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(alerts))
}

#[derive(Deserialize)]
pub struct AckInput {
    #[serde(default)]
    comment: Option<String>,
    /// `false` = Bestätigung zurücknehmen
    #[serde(default = "yes")]
    acknowledge: bool,
}

fn yes() -> bool {
    true
}

/// Alarm bestätigen („ich kümmere mich“): keine Erinnerungen und keine Eskalation mehr; Ampel wird gelb statt rot
pub async fn acknowledge(
    State(st): State<AppState>,
    Need(user, _): Need<perm::AlertsAck>,
    Path(id): Path<i64>,
    Json(req): Json<AckInput>,
) -> ApiResult<Json<Value>> {
    let site: Option<(Option<i64>,)> = sqlx::query_as(
        "SELECT COALESCE(d.site_id, c.site_id) FROM alerts a LEFT JOIN devices d ON d.id = a.device_id
           LEFT JOIN checks c ON c.id = a.check_id WHERE a.id = $1 AND a.resolved_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let (site,) = site.ok_or(ApiError::NotFound)?;
    match site {
        Some(site) => user.require_site("alerts.ack", site)?,
        None => user.require("alerts.ack")?,
    }
    let comment: Option<String> = req.comment.as_deref().map(str::trim).filter(|c| !c.is_empty()).map(|c| c.chars().take(500).collect());
    sqlx::query(
        "UPDATE alerts SET acknowledged_at = CASE WHEN $2 THEN now() END, acknowledged_by = CASE WHEN $2 THEN $3::bigint END,
                ack_comment = CASE WHEN $2 THEN $4 END
          WHERE id = $1",
    )
    .bind(id)
    .bind(req.acknowledge)
    .bind(user.id)
    .bind(&comment)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, if req.acknowledge { "alert_ack" } else { "alert_unack" }, json!({ "alert_id": id, "site_id": site, "comment": comment })).await;
    st.hub.publish(&json!({ "type": "ack", "id": id, "acknowledged": req.acknowledge, "by": user.username, "site_id": site }));
    Ok(Json(json!({ "ok": true })))
}
