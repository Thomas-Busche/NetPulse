//! Einrichtungs-Assistent: Was ist schon eingerichtet, welche Router gibt es, welcher Zugang passt?
//!
//! Der Assistent selbst läuft in der Oberfläche und nutzt die normalen Schnittstellen (Netze, Zugangsdaten,
//! Kanäle). Hier gibt es nur die Übersicht dafür und den Merker „Einrichtung abgeschlossen“.

use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{perm, Need},
    error::ApiResult,
    routers, scanner, sites, AppState,
};

const PERM: &str = "networks.manage";

/// Ist die Einrichtung erledigt? Ohne Eintrag: nur bei einer neuen Installation (noch keine Geräte) nicht
pub async fn is_done(st: &AppState) -> sqlx::Result<bool> {
    let flag: Option<bool> = sqlx::query_scalar("SELECT (value->>'done')::bool FROM settings WHERE key = 'setup'").fetch_optional(&st.db).await?.flatten();
    match flag {
        Some(done) => Ok(done),
        None => sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM devices)").fetch_one(&st.db).await,
    }
}

#[derive(sqlx::FromRow)]
struct GatewayRow {
    site_id: i64,
    site_name: String,
    ip: String,
    device_id: Option<i64>,
    name: Option<String>,
    hostname: Option<String>,
    vendor: Option<String>,
    model: Option<String>,
    os: Option<String>,
    open_ports: Option<Vec<i32>>,
    status: Option<String>,
    credential_kinds: Option<Vec<String>>,
}

pub async fn overview(State(st): State<AppState>, Need(user, _): Need<perm::NetworksManage>) -> ApiResult<Json<Value>> {
    let site_filter = user.site_filter(PERM);
    // Gateways der eingetragenen Netze; im Hauptstandort zusätzlich die aus der Routing-Tabelle des Servers
    let local: Vec<String> = scanner::local::gateways().into_iter().map(|(_, gw)| gw.to_string()).collect();
    let rows: Vec<GatewayRow> = sqlx::query_as(
        "WITH gw AS (
             SELECT DISTINCT n.site_id, n.gateway AS ip FROM networks n WHERE n.gateway IS NOT NULL
             UNION
             SELECT $2, g::inet FROM unnest($3::text[]) g
         )
         SELECT gw.site_id, s.name AS site_name, host(gw.ip) AS ip, d.id AS device_id, d.name, d.hostname, d.vendor, d.model, d.os,
                d.open_ports, d.status,
                (SELECT array_agg(DISTINCT c.kind) FROM device_credentials dc JOIN credentials c ON c.id = dc.credential_id
                  WHERE dc.device_id = d.id) AS credential_kinds
           FROM gw JOIN sites s ON s.id = gw.site_id
           LEFT JOIN devices d ON d.site_id = gw.site_id AND d.ip = gw.ip
          WHERE ($1::bigint[] IS NULL OR gw.site_id = ANY($1))
          ORDER BY gw.site_id, gw.ip",
    )
    .bind(&site_filter)
    .bind(sites::DEFAULT_SITE)
    .bind(&local)
    .fetch_all(&st.db)
    .await?;

    let gateways: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let family = routers::identify(&routers::Clues {
                vendor: r.vendor.as_deref(),
                hostname: r.hostname.as_deref(),
                model: r.model.as_deref(),
                os: r.os.as_deref(),
                open_ports: r.open_ports.as_deref().unwrap_or_default(),
            });
            json!({
                "site_id": r.site_id, "site_name": r.site_name, "ip": r.ip,
                "device": r.device_id.map(|id| json!({
                    "id": id, "name": r.name, "hostname": r.hostname, "vendor": r.vendor, "model": r.model, "status": r.status,
                })),
                "family": family,
                "credential_kinds": r.credential_kinds.unwrap_or_default(),
            })
        })
        .collect();

    let (networks, devices, credentials, channels): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM networks WHERE $1::bigint[] IS NULL OR site_id = ANY($1)),
                (SELECT count(*) FROM devices WHERE $1::bigint[] IS NULL OR site_id = ANY($1)),
                (SELECT count(*) FROM credentials),
                (SELECT count(*) FROM notification_channels WHERE enabled)",
    )
    .bind(&site_filter)
    .fetch_one(&st.db)
    .await?;

    let catalog: Vec<&routers::Family> = routers::CATALOG.iter().chain(std::iter::once(&routers::GENERIC)).collect();
    Ok(Json(json!({
        "done": is_done(&st).await?,
        "counts": { "networks": networks, "devices": devices, "credentials": credentials, "channels": channels },
        "gateways": gateways,
        "catalog": catalog,
    })))
}

#[derive(Deserialize)]
pub struct SetupState {
    done: bool,
}

/// Einrichtung als erledigt markieren (oder zurücksetzen, um den Assistenten erneut anzubieten)
pub async fn set_state(
    State(st): State<AppState>,
    Need(user, _): Need<perm::NetworksManage>,
    Json(req): Json<SetupState>,
) -> ApiResult<Json<Value>> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('setup', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(json!({ "done": req.done, "by": user.username }))
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "setup", json!({ "done": req.done })).await;
    Ok(Json(json!({ "done": req.done })))
}
