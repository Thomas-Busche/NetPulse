//! Sektoren verwalten und Leitstand: Gesamtzustand je Sektor und „Jetzt kaputt“-Liste.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;

use crate::{
    audit,
    auth::{self, perm, CurrentUser, Need},
    error::{ApiError, ApiResult},
    sites::DEFAULT_SITE,
    AppState,
};

#[derive(Serialize, FromRow, Clone)]
pub struct Site {
    id: i64,
    name: String,
    description: String,
    parent_id: Option<i64>,
    position: i32,
    device_count: i64,
    network_count: i64,
    probe: Option<String>,
}

const SITE_SELECT: &str = "SELECT s.id, s.name, s.description, s.parent_id, s.position,
                                  (SELECT count(*) FROM devices d WHERE d.site_id = s.id) AS device_count,
                                  (SELECT count(*) FROM networks n WHERE n.site_id = s.id) AS network_count,
                                  (SELECT p.name FROM probes p WHERE p.site_id = s.id) AS probe
                             FROM sites s";

/// Sektoren, die der Benutzer sehen darf (für Auswahllisten und Filter)
pub async fn list(State(st): State<AppState>, user: CurrentUser) -> ApiResult<Json<Vec<Site>>> {
    let allowed = user.site_filter("view");
    let sql = format!("{SITE_SELECT} WHERE ($1::bigint[] IS NULL OR s.id = ANY($1)) ORDER BY s.position, s.name");
    Ok(Json(sqlx::query_as::<_, Site>(&sql).bind(&allowed).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct SiteInput {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    parent_id: Option<i64>,
    #[serde(default)]
    position: Option<i32>,
}

fn validate(s: &SiteInput) -> ApiResult<()> {
    if s.name.trim().is_empty() || s.name.chars().count() > 100 {
        return Err(ApiError::BadRequest("Bitte einen Namen (max. 100 Zeichen) angeben".into()));
    }
    if s.description.chars().count() > 500 {
        return Err(ApiError::BadRequest("Beschreibung darf höchstens 500 Zeichen haben".into()));
    }
    Ok(())
}

pub async fn create(State(st): State<AppState>, Need(user, _): Need<perm::NetworksManage>, Json(s): Json<SiteInput>) -> ApiResult<Json<Site>> {
    validate(&s)?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO sites (name, description, parent_id, position)
         SELECT $1, $2, (SELECT id FROM sites WHERE id = $3), COALESCE($4, 0) RETURNING id",
    )
    .bind(s.name.trim())
    .bind(s.description.trim())
    .bind(s.parent_id)
    .bind(s.position)
    .fetch_one(&st.db)
    .await?;
    audit::by(&st.db, &user, "site_add", json!({ "site_id": id, "name": s.name, "parent_id": s.parent_id })).await;
    let sql = format!("{SITE_SELECT} WHERE s.id = $1");
    Ok(Json(sqlx::query_as::<_, Site>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn update(
    State(st): State<AppState>,
    Need(user, _): Need<perm::NetworksManage>,
    Path(id): Path<i64>,
    Json(s): Json<SiteInput>,
) -> ApiResult<Json<Site>> {
    validate(&s)?;
    if let Some(parent) = s.parent_id {
        // Kein Kreis: der neue übergeordnete Sektor darf nicht unter diesem liegen
        let tree = crate::sites::tree(&st.db).await?;
        if auth::descendants(id, &tree).contains(&parent) {
            return Err(ApiError::BadRequest("Ein Sektor kann nicht unter sich selbst oder einem seiner Unter-Sektoren liegen".into()));
        }
    }
    let done = sqlx::query(
        "UPDATE sites SET name = $2, description = $3, parent_id = (SELECT id FROM sites WHERE id = $4), position = COALESCE($5, position)
          WHERE id = $1",
    )
    .bind(id)
    .bind(s.name.trim())
    .bind(s.description.trim())
    .bind(s.parent_id)
    .bind(s.position)
    .execute(&st.db)
    .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::by(&st.db, &user, "site_update", json!({ "site_id": id, "name": s.name, "parent_id": s.parent_id })).await;
    let sql = format!("{SITE_SELECT} WHERE s.id = $1");
    Ok(Json(sqlx::query_as::<_, Site>(&sql).bind(id).fetch_one(&st.db).await?))
}

pub async fn remove(State(st): State<AppState>, Need(user, _): Need<perm::NetworksManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    if id == DEFAULT_SITE {
        return Err(ApiError::BadRequest("Der Standard-Sektor kann nicht gelöscht werden (aber umbenannt)".into()));
    }
    let (devices, networks, children): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM devices WHERE site_id = $1), (SELECT count(*) FROM networks WHERE site_id = $1),
                (SELECT count(*) FROM sites WHERE parent_id = $1)",
    )
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    if devices + networks + children > 0 {
        return Err(ApiError::BadRequest(format!(
            "Der Sektor enthält noch {devices} Geräte, {networks} Netze und {children} Unter-Sektoren – bitte zuerst verschieben"
        )));
    }
    let (name,): (String,) = sqlx::query_as("DELETE FROM sites WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "site_delete", json!({ "site_id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct MoveDevices {
    device_ids: Vec<i64>,
}

/// Geräte in diesen Sektor verschieben (z. B. nach dem Anlegen neuer Sektoren)
pub async fn move_devices(
    State(st): State<AppState>,
    Need(user, _): Need<perm::DevicesManage>,
    Path(id): Path<i64>,
    Json(req): Json<MoveDevices>,
) -> ApiResult<Json<Value>> {
    user.require_site("devices.manage", id)?;
    if let Some(allowed) = user.site_filter("devices.manage") {
        let (outside,): (i64,) = sqlx::query_as("SELECT count(*) FROM devices WHERE id = ANY($1) AND NOT site_id = ANY($2)")
            .bind(&req.device_ids)
            .bind(&allowed)
            .fetch_one(&st.db)
            .await?;
        if outside > 0 {
            return Err(ApiError::Forbidden);
        }
    }
    let done = sqlx::query("UPDATE devices SET site_id = $1 WHERE id = ANY($2) AND site_id <> $1")
        .bind(id)
        .bind(&req.device_ids)
        .execute(&st.db)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                ApiError::BadRequest("Im Ziel-Sektor gibt es schon ein Gerät mit derselben IP-Adresse".into())
            }
            _ => e.into(),
        })?;
    audit::by(&st.db, &user, "devices_move", json!({ "site_id": id, "device_ids": req.device_ids })).await;
    Ok(Json(json!({ "moved": done.rows_affected() })))
}

// ---------------------------------------------------------------------------
// Leitstand
// ---------------------------------------------------------------------------

#[derive(FromRow)]
struct SiteCounts {
    site_id: i64,
    devices: i64,
    monitored: i64,
    up: i64,
    down: i64,
    /// davon als unwichtig markiert (machen die Ampel nicht gelb)
    down_low: i64,
    unknown: i64,
    avail_24h: Option<f64>,
}

#[derive(Deserialize)]
pub struct SiteQuery {
    site: Option<i64>,
}

/// Zustand je Sektor: Ampel, Zählwerte, offene Alarme, Dienste, Wartung, Probe.
/// `rollup` fasst jeden Sektor mit allen Unter-Sektoren zusammen.
pub async fn status(State(st): State<AppState>, user: Need<perm::View>, Query(q): Query<SiteQuery>) -> ApiResult<Json<Value>> {
    let filter = crate::sites::filter(&st.db, &user, "view", q.site).await?;
    let sites: Vec<Site> = sqlx::query_as(&format!("{SITE_SELECT} WHERE ($1::bigint[] IS NULL OR s.id = ANY($1)) ORDER BY s.position, s.name"))
        .bind(&filter)
        .fetch_all(&st.db)
        .await?;
    let counts: Vec<SiteCounts> = sqlx::query_as(
        "SELECT d.site_id, count(*) AS devices, count(*) FILTER (WHERE d.monitored) AS monitored,
                count(*) FILTER (WHERE d.monitored AND d.status = 'up') AS up,
                count(*) FILTER (WHERE d.monitored AND d.status = 'down') AS down,
                count(*) FILTER (WHERE d.monitored AND d.status = 'down' AND d.priority = 'low') AS down_low,
                count(*) FILTER (WHERE d.monitored AND d.status = 'unknown') AS unknown,
                (SELECT round(100.0 * avg(CASE WHEN m.up THEN 1 ELSE 0 END), 2)::float8 FROM device_metrics m
                   JOIN devices x ON x.id = m.device_id WHERE x.site_id = d.site_id AND m.time > now() - interval '24 hours') AS avail_24h
           FROM devices d WHERE ($1::bigint[] IS NULL OR d.site_id = ANY($1)) GROUP BY d.site_id",
    )
    .bind(&filter)
    .fetch_all(&st.db)
    .await?;
    // Offene Alarme je Sektor und Schwere (bestätigt/unbestätigt)
    let alerts: Vec<(i64, String, bool, i64)> = sqlx::query_as(
        "SELECT COALESCE(d.site_id, c.site_id, 0), COALESCE(a.severity, 'warning'), a.acknowledged_at IS NOT NULL, count(*)
           FROM alerts a LEFT JOIN devices d ON d.id = a.device_id LEFT JOIN checks c ON c.id = a.check_id
          WHERE a.resolved_at IS NULL GROUP BY 1, 2, 3",
    )
    .fetch_all(&st.db)
    .await?;
    let checks: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT site_id, count(*) FILTER (WHERE enabled), count(*) FILTER (WHERE enabled AND status = 'down')
           FROM checks WHERE site_id IS NOT NULL GROUP BY site_id",
    )
    .fetch_all(&st.db)
    .await?;
    let probes: Vec<(i64, String, Option<DateTime<Utc>>, bool)> =
        sqlx::query_as("SELECT site_id, name, last_seen, enabled FROM probes").fetch_all(&st.db).await?;
    let now = Utc::now();
    let tz = crate::scanner::schedule::timezone();
    let windows: Vec<crate::maintenance::Window> = crate::maintenance::load(&st.db).await;
    let tree = crate::sites::tree(&st.db).await?;
    let ancestors = |id: i64| -> Vec<i64> {
        let mut chain = vec![id];
        let mut current = id;
        while let Some((_, Some(parent))) = tree.iter().find(|(s, _)| *s == current) {
            if chain.contains(parent) || chain.len() > 20 {
                break;
            }
            chain.push(*parent);
            current = *parent;
        }
        chain
    };

    let mut own: HashMap<i64, Value> = HashMap::new();
    for site in &sites {
        let c = counts.iter().find(|c| c.site_id == site.id);
        let sev = |severity: &str, acked: bool| {
            alerts.iter().filter(|a| a.0 == site.id && a.1 == severity && a.2 == acked).map(|a| a.3).sum::<i64>()
        };
        let (checks_total, checks_down) = checks.iter().find(|c| c.0 == site.id).map_or((0, 0), |c| (c.1, c.2));
        let probe = probes.iter().find(|p| p.0 == site.id).map(|p| {
            let online = p.3 && p.2.is_some_and(|t| (now - t).num_seconds() < 300);
            json!({ "name": p.1, "last_seen": p.2, "online": online, "enabled": p.3 })
        });
        let chain = ancestors(site.id);
        let maintenance: Vec<String> = windows
            .iter()
            .filter(|w| w.active_at(now, tz) && w.site_ids.iter().any(|s| chain.contains(s)))
            .map(|w| w.name.clone())
            .collect();
        own.insert(
            site.id,
            json!({
                "devices": c.map_or(0, |c| c.devices), "monitored": c.map_or(0, |c| c.monitored),
                "up": c.map_or(0, |c| c.up), "down": c.map_or(0, |c| c.down), "down_low": c.map_or(0, |c| c.down_low),
                "unknown": c.map_or(0, |c| c.unknown),
                "avail_24h": c.and_then(|c| c.avail_24h),
                "alerts": {
                    "critical": sev("critical", false), "warning": sev("warning", false), "info": sev("info", false),
                    "acknowledged": sev("critical", true) + sev("warning", true) + sev("info", true),
                },
                "checks": { "total": checks_total, "down": checks_down },
                "probe": probe,
                "maintenance": maintenance,
            }),
        );
    }

    let num = |v: &Value, path: &[&str]| path.iter().fold(v, |v, k| &v[*k]).as_i64().unwrap_or(0);
    let mut out = Vec::new();
    for site in &sites {
        let subtree = auth::descendants(site.id, &tree);
        let parts: Vec<&Value> = subtree.iter().filter_map(|id| own.get(id)).collect();
        let sum = |path: &[&str]| parts.iter().map(|v| num(v, path)).sum::<i64>();
        let rollup = json!({
            "devices": sum(&["devices"]), "monitored": sum(&["monitored"]), "up": sum(&["up"]), "down": sum(&["down"]),
            "down_low": sum(&["down_low"]),
            "unknown": sum(&["unknown"]),
            "alerts": { "critical": sum(&["alerts", "critical"]), "warning": sum(&["alerts", "warning"]),
                        "info": sum(&["alerts", "info"]), "acknowledged": sum(&["alerts", "acknowledged"]) },
            "checks": { "total": sum(&["checks", "total"]), "down": sum(&["checks", "down"]) },
            "probes_offline": parts.iter().filter(|v| v["probe"]["online"] == json!(false)).count(),
            "maintenance": parts.iter().any(|v| v["maintenance"].as_array().is_some_and(|m| !m.is_empty())),
        });
        let state = traffic_light(&rollup);
        let mut v = json!(site);
        v["own"] = own.get(&site.id).cloned().unwrap_or(Value::Null);
        v["rollup"] = rollup;
        v["state"] = json!(state);
        out.push(v);
    }
    // Übergreifende Alarme (ohne Sektor, z. B. neue Geräte ohne Zuordnung) nur mit Recht für alle Sektoren
    let global = if user.can("view") {
        let sev = |severity: &str| alerts.iter().filter(|a| a.0 == 0 && a.1 == severity && !a.2).map(|a| a.3).sum::<i64>();
        json!({ "critical": sev("critical"), "warning": sev("warning"), "info": sev("info") })
    } else {
        Value::Null
    };
    Ok(Json(json!({ "sites": out, "global_alerts": global, "time": now })))
}

/// Ampel: rot = unbestätigter kritischer Alarm oder Dienst aus; gelb = Warnung, bestätigter Alarm,
/// Gerät offline (außer unwichtige) oder Probe nicht erreichbar; blau = Wartung; sonst grün.
pub fn traffic_light(r: &Value) -> &'static str {
    let n = |path: &[&str]| path.iter().fold(r, |v, k| &v[*k]).as_i64().unwrap_or(0);
    if n(&["alerts", "critical"]) > 0 || n(&["checks", "down"]) > 0 {
        "red"
    } else if n(&["alerts", "warning"]) > 0 || n(&["alerts", "acknowledged"]) > 0 || n(&["down"]) - n(&["down_low"]) > 0 || n(&["probes_offline"]) > 0 {
        "yellow"
    } else if r["maintenance"] == json!(true) {
        "maintenance"
    } else {
        "green"
    }
}

type DownRow = (i64, String, String, i64, String, Option<DateTime<Utc>>, String, String);
type CheckRow = (i64, String, String, Option<i64>, Option<String>, Option<DateTime<Utc>>, Option<String>);

/// „Jetzt kaputt“: offene Alarme, ausgefallene Geräte und Dienste – nach Schwere und Dauer sortiert
pub async fn problems(State(st): State<AppState>, user: Need<perm::View>, Query(q): Query<SiteQuery>) -> ApiResult<Json<Value>> {
    let filter = crate::sites::filter(&st.db, &user, "view", q.site).await?;
    type AlertRow = (i64, DateTime<Utc>, String, Option<String>, Option<i64>, Option<String>, Option<i64>, Option<String>,
                     Option<DateTime<Utc>>, Option<String>, Option<String>, String, Option<i64>, Option<String>);
    let alerts: Vec<AlertRow> = sqlx::query_as(
        "SELECT a.id, a.opened_at, a.message, a.severity, a.device_id,
                COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)), COALESCE(d.site_id, c.site_id), s.name,
                a.acknowledged_at, u.username, a.ack_comment, r.name, a.check_id, d.priority
           FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
           LEFT JOIN devices d ON d.id = a.device_id LEFT JOIN checks c ON c.id = a.check_id
           LEFT JOIN sites s ON s.id = COALESCE(d.site_id, c.site_id)
           LEFT JOIN users u ON u.id = a.acknowledged_by
          WHERE a.resolved_at IS NULL
            AND ($1::bigint[] IS NULL OR COALESCE(d.site_id, c.site_id) = ANY($1))",
    )
    .bind(&filter)
    .fetch_all(&st.db)
    .await?;
    // Ausgefallene Geräte ohne offenen Alarm (z. B. keine Regel) – als Hinweis
    let down: Vec<DownRow> = sqlx::query_as(
        "SELECT d.id, COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)), host(d.ip), d.site_id, s.name, d.status_since,
                COALESCE(d.device_type, 'unknown'), d.priority
           FROM devices d JOIN sites s ON s.id = d.site_id
          WHERE d.monitored AND d.status = 'down' AND ($1::bigint[] IS NULL OR d.site_id = ANY($1))
            AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.device_id = d.id AND a.resolved_at IS NULL)
          ORDER BY d.status_since LIMIT 200",
    )
    .bind(&filter)
    .fetch_all(&st.db)
    .await?;
    let checks: Vec<CheckRow> = sqlx::query_as(
        "SELECT c.id, c.name, c.target, c.site_id, s.name, c.status_since, c.last_message
           FROM checks c LEFT JOIN sites s ON s.id = c.site_id
          WHERE c.enabled AND c.status = 'down'
            AND ($1::bigint[] IS NULL OR c.site_id = ANY($1))
            AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.check_id = c.id AND a.resolved_at IS NULL)",
    )
    .bind(&filter)
    .fetch_all(&st.db)
    .await?;

    let rank = |s: &str| match s {
        "critical" => 0,
        "warning" => 1,
        "info" => 2,
        _ => 3,
    };
    // Wichtige Geräte innerhalb derselben Schwere zuerst
    let prio_rank = |p: Option<&str>| match p {
        Some("high") => 0,
        Some("low") => 2,
        _ => 1,
    };
    let mut items: Vec<(i32, bool, i32, DateTime<Utc>, Value)> = Vec::new();
    for (id, opened, message, severity, device_id, device, site_id, site, acked_at, acked_by, comment, rule, check_id, priority) in alerts {
        let severity = severity.unwrap_or_else(|| "warning".into());
        let acked = acked_at.is_some();
        items.push((rank(&severity), acked, prio_rank(priority.as_deref()), opened, json!({
            "kind": "alert", "id": id, "since": opened, "message": message, "severity": severity, "rule": rule, "priority": priority,
            "device_id": device_id, "device": device, "check_id": check_id, "site_id": site_id, "site": site,
            "acknowledged_at": acked_at, "acknowledged_by": acked_by, "ack_comment": comment,
        })));
    }
    for (id, label, ip, site_id, site, since, kind, priority) in down {
        let since = since.unwrap_or_else(Utc::now);
        // Ohne Alarmregel: Schwere nach Priorität (wichtig = kritisch, unwichtig = Hinweis)
        let severity = match priority.as_str() {
            "high" => "critical",
            "low" => "info",
            _ => "warning",
        };
        items.push((rank(severity), false, prio_rank(Some(&priority)), since, json!({
            "kind": "device", "id": id, "since": since, "message": format!("{label} ({ip}) ist nicht erreichbar"),
            "severity": severity, "priority": priority, "device_id": id, "device": label, "device_type": kind, "site_id": site_id, "site": site,
        })));
    }
    for (id, name, target, site_id, site, since, reason) in checks {
        let since = since.unwrap_or_else(Utc::now);
        items.push((0, false, 1, since, json!({
            "kind": "check", "id": id, "since": since,
            "message": format!("Dienst „{name}“ ({target}) funktioniert nicht{}", reason.map(|r| format!(": {r}")).unwrap_or_default()),
            "severity": "critical", "check_id": id, "site_id": site_id, "site": site,
        })));
    }
    // Unbestätigtes zuerst, dann nach Schwere, dann am längsten bestehend
    items.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)).then(a.2.cmp(&b.2)).then(a.3.cmp(&b.3)));
    Ok(Json(json!(items.into_iter().map(|i| i.4).collect::<Vec<_>>())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ampel() {
        let base = json!({ "down": 0, "alerts": { "critical": 0, "warning": 0, "acknowledged": 0 }, "checks": { "down": 0 },
                           "probes_offline": 0, "maintenance": false });
        assert_eq!(traffic_light(&base), "green");
        let mut r = base.clone();
        r["alerts"]["critical"] = json!(1);
        assert_eq!(traffic_light(&r), "red");
        let mut r = base.clone();
        r["down"] = json!(2);
        assert_eq!(traffic_light(&r), "yellow");
        r["down_low"] = json!(2);
        assert_eq!(traffic_light(&r), "green", "unwichtige Geräte offline = kein Grund für Gelb");
        let mut r = base.clone();
        r["alerts"]["acknowledged"] = json!(1);
        assert_eq!(traffic_light(&r), "yellow", "bestätigt = in Arbeit, nicht mehr rot");
        let mut r = base;
        r["maintenance"] = json!(true);
        assert_eq!(traffic_light(&r), "maintenance");
    }
}
