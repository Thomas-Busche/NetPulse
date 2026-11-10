//! Wartungsfenster: In dieser Zeit werden für die betroffenen Geräte/Dienste keine Alarme verschickt
//! (z. B. geplante Updates, nächtlicher Neustart). Überwacht und aufgezeichnet wird trotzdem.
//!
//! - `once`   : einmalig von `starts_at` bis `ends_at`
//! - `weekly` : jede Woche an den Tagen `days` (1 = Montag … 7 = Sonntag) von `time_from` bis `time_to`
//!   (über Mitternacht möglich, z. B. 23:00–02:00; Zeitzone wie beim Such-Zeitplan)
//!
//! Leere Geräte- und Dienstlisten bedeuten: gilt für alles.

use chrono::{DateTime, Datelike, NaiveTime, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Serialize, Deserialize, sqlx::FromRow, Clone, Debug)]
pub struct Window {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
    pub days: Vec<i32>,
    pub time_from: Option<String>,
    pub time_to: Option<String>,
    pub device_ids: Vec<i64>,
    pub check_ids: Vec<i64>,
    pub enabled: bool,
    /// Ganze Sektoren (inkl. Unter-Sektoren)
    pub site_ids: Vec<i64>,
}

pub const SELECT: &str =
    "SELECT id, name, kind, starts_at, ends_at, days, time_from, time_to, device_ids, check_ids, enabled, site_ids FROM maintenance_windows";

fn parse(t: &Option<String>) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(t.as_deref()?.trim(), "%H:%M").ok()
}

impl Window {
    /// Ist das Fenster zum Zeitpunkt `now` aktiv?
    pub fn active_at(&self, now: DateTime<Utc>, tz: Tz) -> bool {
        if !self.enabled {
            return false;
        }
        match self.kind.as_str() {
            "once" => matches!((self.starts_at, self.ends_at), (Some(a), Some(b)) if a <= now && now < b),
            "weekly" => {
                let (Some(from), Some(to)) = (parse(&self.time_from), parse(&self.time_to)) else { return false };
                let local = now.with_timezone(&tz);
                let today = local.weekday().number_from_monday() as i32;
                let yesterday = if today == 1 { 7 } else { today - 1 };
                let time = local.time();
                if from <= to {
                    self.days.contains(&today) && time >= from && time < to
                } else {
                    // über Mitternacht: Beginn am gewählten Tag, Ende am Folgetag
                    (self.days.contains(&today) && time >= from) || (self.days.contains(&yesterday) && time < to)
                }
            }
            _ => false,
        }
    }

    /// `sites`: Sektor des Geräts/Dienstes und alle übergeordneten Sektoren
    pub fn covers(&self, device_id: Option<i64>, check_id: Option<i64>, sites: &[i64]) -> bool {
        let all = self.device_ids.is_empty() && self.check_ids.is_empty() && self.site_ids.is_empty();
        all || device_id.is_some_and(|d| self.device_ids.contains(&d))
            || check_id.is_some_and(|c| self.check_ids.contains(&c))
            || sites.iter().any(|s| self.site_ids.contains(s))
    }
}

pub async fn load(db: &PgPool) -> Vec<Window> {
    sqlx::query_as::<_, Window>(&format!("{SELECT} WHERE enabled")).fetch_all(db).await.unwrap_or_default()
}

/// Name des aktiven Wartungsfensters für Gerät/Dienst, falls eines greift
pub async fn active_for(db: &PgPool, device_id: Option<i64>, check_id: Option<i64>) -> Option<String> {
    let now = Utc::now();
    let tz = crate::scanner::schedule::timezone();
    let active: Vec<Window> = load(db).await.into_iter().filter(|w| w.active_at(now, tz)).collect();
    if active.is_empty() {
        return None;
    }
    let sites = if active.iter().any(|w| !w.site_ids.is_empty()) { site_chain(db, device_id, check_id).await } else { vec![] };
    active.into_iter().find(|w| w.covers(device_id, check_id, &sites)).map(|w| w.name)
}

/// Sektor eines Geräts/Dienstes und alle übergeordneten Sektoren
async fn site_chain(db: &PgPool, device_id: Option<i64>, check_id: Option<i64>) -> Vec<i64> {
    sqlx::query_scalar::<_, i64>(
        "WITH RECURSIVE up(id, depth) AS (
             SELECT COALESCE((SELECT site_id FROM devices WHERE id = $1), (SELECT site_id FROM checks WHERE id = $2)), 0
           UNION ALL
             SELECT s.parent_id, up.depth + 1 FROM up JOIN sites s ON s.id = up.id WHERE s.parent_id IS NOT NULL AND up.depth < 20
         )
         SELECT id FROM up WHERE id IS NOT NULL",
    )
    .bind(device_id)
    .bind(check_id)
    .fetch_all(db)
    .await
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weekly(days: Vec<i32>, from: &str, to: &str) -> Window {
        Window {
            id: 1,
            name: "Updates".into(),
            kind: "weekly".into(),
            starts_at: None,
            ends_at: None,
            days,
            time_from: Some(from.into()),
            time_to: Some(to.into()),
            device_ids: vec![5],
            check_ids: vec![],
            enabled: true,
            site_ids: vec![],
        }
    }

    #[test]
    fn woechentlich() {
        let tz = chrono_tz::Europe::Berlin;
        // Donnerstag, 24.09.2026, 23:30 Berlin = 21:30 UTC
        let thu_2330: DateTime<Utc> = "2026-09-24T21:30:00Z".parse().unwrap();
        let fri_0130: DateTime<Utc> = "2026-09-24T23:30:00Z".parse().unwrap();
        let w = weekly(vec![4], "23:00", "02:00");
        assert!(w.active_at(thu_2330, tz));
        assert!(w.active_at(fri_0130, tz), "über Mitternacht bis Freitag 02:00");
        assert!(!weekly(vec![5], "23:00", "02:00").active_at(thu_2330, tz));
        assert!(weekly(vec![4], "20:00", "23:45").active_at(thu_2330, tz));
        assert!(w.covers(Some(5), None, &[]) && !w.covers(Some(6), None, &[]));
        let mut site = weekly(vec![4], "23:00", "02:00");
        site.device_ids.clear();
        site.site_ids = vec![3];
        assert!(site.covers(Some(9), None, &[7, 3, 1]), "Unter-Sektor von 3");
        assert!(!site.covers(Some(9), None, &[1]));
    }

    #[test]
    fn einmalig() {
        let mut w = weekly(vec![], "00:00", "00:00");
        w.kind = "once".into();
        w.starts_at = Some("2026-09-24T10:00:00Z".parse().unwrap());
        w.ends_at = Some("2026-09-24T12:00:00Z".parse().unwrap());
        assert!(w.active_at("2026-09-24T11:00:00Z".parse().unwrap(), chrono_tz::UTC));
        assert!(!w.active_at("2026-09-24T12:00:00Z".parse().unwrap(), chrono_tz::UTC));
        w.device_ids.clear();
        assert!(w.covers(Some(99), None, &[]), "leere Listen gelten für alles");
    }
}
