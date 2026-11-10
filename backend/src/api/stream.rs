//! Live-Meldungen per Server-Sent Events (`GET /api/stream`).
//!
//! Der Browser hält eine Verbindung offen und bekommt neue Messwerte und Statuswechsel sofort,
//! ohne ständig nachzufragen. Nach 30 Minuten wird die Verbindung beendet; der Browser baut sie
//! automatisch neu auf – dabei wird die Anmeldung erneut geprüft.

use std::{
    collections::HashSet,
    convert::Infallible,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    extract::State,
    http::{header::HeaderName, HeaderValue},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use futures::{stream, Stream, StreamExt};
use serde_json::Value;
use sqlx::PgPool;
use tokio::sync::broadcast::error::RecvError;

use crate::{auth::CurrentUser, AppState};

/// `X-Accel-Buffering: no`: Nginx (z. B. Nginx Proxy Manager) leitet die Meldungen sofort weiter
pub async fn events(State(st): State<AppState>, user: CurrentUser, headers: axum::http::HeaderMap) -> impl IntoResponse {
    let hash = crate::auth::session_token(&headers).map(|t| crate::auth::token_hash(&t)).unwrap_or_default();
    (
        [(HeaderName::from_static("x-accel-buffering"), HeaderValue::from_static("no"))],
        sse(st, user, hash),
    )
}

/// Was ein auf Sektoren beschränkter Benutzer sehen darf. `None` = alles.
#[derive(Default)]
struct Scope {
    sites: Vec<i64>,
    devices: HashSet<i64>,
    checks: HashSet<i64>,
}

async fn load_scope(db: &PgPool, sites: &[i64]) -> sqlx::Result<Scope> {
    let devices: Vec<(i64,)> = sqlx::query_as("SELECT id FROM devices WHERE site_id = ANY($1)").bind(sites).fetch_all(db).await?;
    let checks: Vec<(i64,)> = sqlx::query_as("SELECT id FROM checks WHERE site_id = ANY($1)").bind(sites).fetch_all(db).await?;
    Ok(Scope {
        sites: sites.to_vec(),
        devices: devices.into_iter().map(|r| r.0).collect(),
        checks: checks.into_iter().map(|r| r.0).collect(),
    })
}

/// Meldung für einen eingeschränkten Benutzer zuschneiden. Unbekannte Arten werden verworfen (fail-closed).
fn restrict(message: &str, scope: &Scope, syslog: bool) -> Option<String> {
    let mut v: Value = serde_json::from_str(message).ok()?;
    let id_in = |v: &Value, set: &HashSet<i64>| v.as_i64().is_some_and(|id| set.contains(&id));
    match v["type"].as_str()? {
        "status" | "shelly" => {
            let list = v["devices"].as_array_mut()?;
            list.retain(|d| id_in(&d["id"], &scope.devices));
            if list.is_empty() && v["full"] != Value::Bool(true) {
                return None;
            }
            // Summen über alle Sektoren nicht an eingeschränkte Benutzer geben
            if let Some(o) = v.as_object_mut() {
                o.remove("totals");
                o.remove("total_power_w");
            }
        }
        "check" if !id_in(&v["id"], &scope.checks) => return None,
        "alert" if !id_in(&v["device_id"], &scope.devices) => return None,
        "ack" if !v["site_id"].as_i64().is_some_and(|s| scope.sites.contains(&s)) => return None,
        "syslog" if !syslog => return None,
        "check" | "alert" | "ack" | "syslog" | "unifi" | "pause" => {}
        _ => return None,
    }
    Some(v.to_string())
}

fn sse(st: AppState, user: CurrentUser, hash: Vec<u8>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Protokollmeldungen (Syslog/Traps) nur mit Diagnose-Recht für alle Sektoren – wie die Seite „Protokolle“
    let syslog = user.site_filter("devices.diagnose").is_none() && user.can("devices.diagnose");
    let restricted = user.site_filter("view");
    let scope: Option<Arc<RwLock<Scope>>> = restricted.as_ref().map(|_| Arc::new(RwLock::new(Scope::default())));
    // Endet nach 30 Minuten oder sobald die Sitzung abgemeldet wurde (Prüfung alle 30 s).
    // Bei eingeschränkten Benutzern wird dabei auch die Liste der sichtbaren Geräte aufgefrischt.
    let db = st.db.clone();
    let refresh = scope.clone();
    let sites = restricted.clone().unwrap_or_default();
    let end = async move {
        let started = std::time::Instant::now();
        loop {
            if let Some(scope) = &refresh {
                match load_scope(&db, &sites).await {
                    Ok(s) => *scope.write().unwrap() = s,
                    // Ohne gültige Liste nichts weitergeben
                    Err(_) => *scope.write().unwrap() = Scope { sites: Vec::new(), ..Default::default() },
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
            if started.elapsed() > Duration::from_secs(30 * 60) || !crate::auth::session_valid(&db, &hash).await {
                break;
            }
        }
    };
    let rx = st.hub.subscribe();
    let first = st.hub.snapshot().to_string();
    let first_scope = scope.clone();
    let initial = stream::once(async move {
        // Erste Liste laden, bevor der Gesamtstand gefiltert wird
        if let (Some(scope), Some(sites)) = (&first_scope, &restricted) {
            if let Ok(s) = load_scope(&st.db, sites).await {
                *scope.write().unwrap() = s;
            }
        }
        let data = match &first_scope {
            Some(scope) => restrict(&first, &scope.read().unwrap(), syslog).unwrap_or_else(|| "{}".into()),
            None => first,
        };
        Ok(Event::default().data(data))
    });
    let updates = stream::unfold(rx, move |mut rx| {
        let scope = scope.clone();
        async move {
            loop {
                match rx.recv().await {
                    Ok(message) => {
                        let out = match &scope {
                            Some(scope) => match restrict(&message, &scope.read().unwrap(), syslog) {
                                Some(m) => m,
                                None => continue,
                            },
                            None if !syslog && message.contains("\"type\":\"syslog\"") => continue,
                            None => message.to_string(),
                        };
                        return Some((Ok(Event::default().data(out)), rx));
                    }
                    // Browser zu langsam: verpasste Zwischenstände überspringen
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => return None,
                }
            }
        }
    });
    let stream = initial.chain(updates).take_until(end);
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eingeschraenkte_meldungen() {
        let scope = Scope { sites: vec![2], devices: [5].into_iter().collect(), checks: [7].into_iter().collect() };
        let m = r#"{"type":"status","devices":[{"id":5},{"id":6}]}"#;
        assert_eq!(restrict(m, &scope, false).unwrap(), r#"{"devices":[{"id":5}],"type":"status"}"#);
        assert!(restrict(r#"{"type":"status","devices":[{"id":6}]}"#, &scope, false).is_none());
        assert!(restrict(r#"{"type":"check","id":8}"#, &scope, false).is_none());
        assert!(restrict(r#"{"type":"alert","device_id":null}"#, &scope, false).is_none());
        assert!(restrict(r#"{"type":"syslog","items":[]}"#, &scope, false).is_none());
        assert!(restrict(r#"{"type":"neu"}"#, &scope, true).is_none());
        assert!(restrict(r#"{"type":"ack","site_id":2}"#, &scope, false).is_some());
    }
}
