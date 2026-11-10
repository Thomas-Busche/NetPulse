//! Energie-Auswertung: Tages-, Monats- und Jahreswerte, Kosten und Einstellungen.

use std::collections::{BTreeMap, HashMap};

use axum::{
    extract::{Query, State},
    Json,
};
use chrono::{Datelike, Months, NaiveDate};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{perm, Need},
    energy::{self, EnergySettings, Flow, Model},
    error::{ApiError, ApiResult},
    AppState,
};

pub async fn get_settings(State(st): State<AppState>, _user: Need<perm::View>) -> Json<EnergySettings> {
    Json(energy::load_settings(&st.db).await)
}

pub async fn set_settings(
    State(st): State<AppState>,
    Need(user, _): Need<perm::SettingsManage>,
    Json(settings): Json<EnergySettings>,
) -> ApiResult<Json<EnergySettings>> {
    settings.validate().map_err(ApiError::BadRequest)?;
    if let Some(id) = settings.main_id {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1)").bind(id).fetch_one(&st.db).await?;
        if !exists {
            return Err(ApiError::BadRequest("Hauptzähler nicht gefunden".into()));
        }
    }
    energy::save_settings(&st.db, &settings).await?;
    audit::by(&st.db, &user, "energy_settings", json!(settings)).await;
    Ok(Json(settings))
}

#[derive(Deserialize)]
pub struct ReportQuery {
    /// „month“ (Tage eines Monats), „year“ (Monate eines Jahres) oder „all“ (Jahre)
    range: Option<String>,
    /// z. B. 2026-09 bzw. 2026
    at: Option<String>,
}

pub async fn report(State(st): State<AppState>, _user: Need<perm::View>, Query(q): Query<ReportQuery>) -> ApiResult<Json<Value>> {
    let today = chrono::Utc::now().with_timezone(&crate::scanner::schedule::timezone()).date_naive();
    let range = q.range.as_deref().unwrap_or("month");
    let bad = || ApiError::BadRequest("Ungültiger Zeitraum".into());
    // Zeitraum [from, to) und Einteilung der Balken
    let (from, to, unit) = match range {
        "month" => {
            let first = match q.at.as_deref() {
                Some(m) => NaiveDate::parse_from_str(&format!("{m}-01"), "%Y-%m-%d").map_err(|_| bad())?,
                None => today.with_day(1).ok_or_else(bad)?,
            };
            (first, first + Months::new(1), "day")
        }
        "year" => {
            let year: i32 = match q.at.as_deref() {
                Some(y) => y.parse().map_err(|_| bad())?,
                None => today.year(),
            };
            let first = NaiveDate::from_ymd_opt(year, 1, 1).ok_or_else(bad)?;
            (first, first + Months::new(12), "month")
        }
        "all" => (NaiveDate::from_ymd_opt(2000, 1, 1).ok_or_else(bad)?, today + chrono::Days::new(1), "year"),
        _ => return Err(bad()),
    };

    let settings = energy::load_settings(&st.db).await;
    let sql = format!(
        "SELECT d.id, COALESCE(d.name, d.reported_name, d.hostname, host(d.ip)), {role}
           FROM devices d
          WHERE d.id = $1 OR EXISTS (SELECT 1 FROM energy_daily e WHERE e.device_id = d.id)
             OR d.id IN (SELECT DISTINCT device_id FROM device_stats WHERE power_w IS NOT NULL AND time > now() - interval '1 day')",
        role = energy::ROLE_SQL
    );
    let devices: Vec<(i64, String, String)> = sqlx::query_as(&sql).bind(settings.main_id.unwrap_or(-1)).fetch_all(&st.db).await?;
    let model = Model {
        roles: devices.iter().map(|(id, _, role)| (*id, role.clone())).collect(),
        main_id: settings.main_id,
        net: settings.main_mode != "gross",
        price_ct: settings.price_ct,
        feed_in_ct: settings.feed_in_ct,
    };

    let rows: Vec<(NaiveDate, i64, f64, f64)> = sqlx::query_as(
        "SELECT date_trunc($3, day)::date, device_id, sum(pos_wh) / 1000.0, sum(neg_wh) / 1000.0
           FROM energy_daily WHERE day >= $1 AND day < $2 GROUP BY 1, 2",
    )
    .bind(from)
    .bind(to)
    .bind(unit)
    .fetch_all(&st.db)
    .await?;

    // Balken: jeder Tag/Monat im Zeitraum (auch ohne Daten), bei „all“ nur Jahre mit Daten
    let mut buckets: BTreeMap<NaiveDate, HashMap<i64, Flow>> = BTreeMap::new();
    if unit != "year" {
        let mut d = from;
        while d < to {
            buckets.insert(d, HashMap::new());
            d = if unit == "day" { d + chrono::Days::new(1) } else { d + Months::new(1) };
        }
    }
    let mut total: HashMap<i64, Flow> = HashMap::new();
    for (bucket, id, pos, neg) in rows {
        let f = buckets.entry(bucket).or_default().entry(id).or_default();
        f.pos += pos;
        f.neg += neg;
        let t = total.entry(id).or_default();
        t.pos += pos;
        t.neg += neg;
    }

    let first_day: Option<NaiveDate> = sqlx::query_scalar("SELECT min(day) FROM energy_daily").fetch_one(&st.db).await?;
    let label = |id: i64| devices.iter().find(|d| d.0 == id).map(|d| d.1.clone()).unwrap_or_else(|| format!("#{id}"));
    let mut per_device: Vec<Value> = total
        .iter()
        .map(|(id, f)| {
            json!({
                "id": id,
                "label": label(*id),
                "role": model.roles.get(id).cloned().unwrap_or_else(|| "consumer".into()),
                "main": Some(*id) == model.main_id,
                "kwh": round(f.abs()),
                "pos_kwh": round(f.pos),
                "neg_kwh": round(f.neg),
            })
        })
        .collect();
    per_device.sort_by(|a, b| b["kwh"].as_f64().partial_cmp(&a["kwh"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));

    Ok(Json(json!({
        "range": range,
        "from": from,
        "to": to,
        "unit": unit,
        "today": today,
        "first_day": first_day,
        "settings": settings,
        "totals": model.figures(&total),
        "buckets": buckets
            .iter()
            .map(|(start, flows)| json!({ "start": start, "has_data": !flows.is_empty(), "figures": model.figures(flows) }))
            .collect::<Vec<_>>(),
        "devices": per_device,
        // Auswahl für den Hauptzähler: alle Geräte mit Strommessung
        "meters": devices.iter().map(|(id, label, role)| json!({ "id": id, "label": label, "role": role })).collect::<Vec<_>>(),
    })))
}

fn round(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}
