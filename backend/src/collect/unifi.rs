//! UniFi-Controller (UniFi OS Server, Cloud Key, Dream Machine, UniFi Network Application).
//!
//! Zwei Wege, beide nur lesend:
//! 1. **API-Schlüssel** (empfohlen): offizielle „Network Integration API“ unter
//!    `/proxy/network/integration/v1` mit Header `X-API-KEY`. Kein Login, daher auch mit
//!    aktivierter Zwei-Faktor-Anmeldung. Schlüssel anlegen: UniFi Network → Einstellungen →
//!    Control Plane → Integrations.
//! 2. **Lokales Konto** (Benutzer + Passwort, ohne 2FA): klassische API nach `/api/auth/login`.
//!    Ist 2FA aktiv, meldet der Controller „2FA-Code nötig“ – dann Weg 1 nutzen.
//!
//! Ports: UniFi OS Server 11443, UniFi OS-Konsolen 443, ältere Network Application 8443.
//! Der Controller hat meist ein selbst signiertes Zertifikat. Es wird beim ersten Kontakt gemerkt
//! (Fingerabdruck, wie beim SSH-Host-Schlüssel); ändert es sich, wird nichts gesendet.

use std::{collections::HashMap, net::Ipv4Addr};

use anyhow::{anyhow, bail, Context, Result};
use futures::{stream, StreamExt};
use reqwest::{header, Client, StatusCode};
use serde_json::{json, Value};

use super::{
    tls::{self, Pin},
    Credential,
};

const DEFAULT_PORTS: &[u16] = &[11443, 443, 8443];
const MAX_CLIENTS: usize = 2000;

/// Eingetragener Port zuerst, danach die üblichen – ein falsch eingetragener Port (z. B. 8443 statt
/// 11443 beim UniFi OS Server) soll die Verbindung nicht verhindern
fn ports(cred: &Credential) -> Vec<u16> {
    let mut out: Vec<u16> = cred.port.and_then(|p| u16::try_from(p).ok()).into_iter().collect();
    for p in DEFAULT_PORTS {
        if !out.contains(p) {
            out.push(*p);
        }
    }
    out
}

/// Liest Sites, Geräte (mit aktueller Auslastung) und Clients des Controllers.
/// `pinned`: gemerkter Zertifikats-Fingerabdruck; zurück kommt der gesehene (zum Merken beim ersten Mal).
pub async fn collect(ip: Ipv4Addr, cred: &Credential, pinned: Option<&str>) -> Result<(Value, Option<String>)> {
    let secret = cred.secret.password.clone().filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("API-Schlüssel bzw. Passwort fehlt"))?;
    let pin = Pin::new(pinned);
    let http = tls::client(pin.clone())?;
    let username = cred.username.clone().filter(|u| !u.trim().is_empty());
    let mut last_error = anyhow!("Controller nicht erreichbar");
    let ports = ports(cred);
    let mut tried = Vec::new();
    for &port in &ports {
        tried.push(port.to_string());
        let base = format!("https://{ip}:{port}");
        let result = match &username {
            None => integration(&http, &base, &secret).await,
            Some(user) => classic(&http, &base, user, &secret).await,
        };
        match result {
            Ok(mut data) => {
                data["port"] = json!(port);
                return Ok((data, pin.seen()));
            }
            // Der Pin-Fehler steckt tief in der Fehlerkette (reqwest → hyper → rustls) – ganze Kette prüfen
            Err(e) if tls::pin_mismatch(&e) => {
                bail!(
                    "Das Zertifikat des Controllers hat sich geändert – Zugangsdaten wurden NICHT gesendet (möglicher Angriff). \
                     Wurde der Controller neu installiert, beim Gerät unter „Einstellungen“ den gespeicherten Schlüssel zurücksetzen."
                );
            }
            Err(e) => {
                let unreachable = e.downcast_ref::<reqwest::Error>().is_some_and(|r| r.is_connect() || r.is_timeout());
                last_error = if unreachable {
                    anyhow!(
                        "Keine UniFi-Oberfläche erreichbar (geprüft: Port {}). Läuft der Controller als Docker-Container \
                         mit eigener IP (macvlan) auf demselben Host wie NetPulse, braucht der Host eine Brücke dorthin – \
                         siehe docs/ABFRAGEN.md, „Docker-Container mit eigener IP“. Sonst im Browser nachsehen, unter \
                         welchem Port die UniFi-Oberfläche läuft, und ihn bei den Zugangsdaten eintragen",
                        tried.join(", ")
                    )
                } else {
                    e.context(format!("Port {port}"))
                };
                if !unreachable {
                    // Port antwortet, aber mit Fehler: weitere Ports bringen nichts
                    break;
                }
            }
        }
    }
    Err(last_error)
}

// ---------------------------------------------------------------------------
// Offizielle Integration-API (API-Schlüssel)
// ---------------------------------------------------------------------------

async fn get_key(http: &Client, url: &str, key: &str) -> Result<Value> {
    let response = http.get(url).header("X-API-KEY", key).header(header::ACCEPT, "application/json").send().await?;
    match response.status() {
        s if s.is_success() => Ok(response.json().await?),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => bail!("API-Schlüssel wird abgelehnt (ungültig oder gelöscht?)"),
        StatusCode::NOT_FOUND => bail!("Integration-API nicht gefunden – UniFi Network 9 oder neuer nötig"),
        s => bail!("Controller antwortete mit {s}"),
    }
}

/// Alle Seiten einer Liste holen (`offset`/`limit`, Antwort `{ data, totalCount }`)
async fn get_all(http: &Client, url: &str, key: &str, max: usize) -> Result<(Vec<Value>, u64)> {
    let mut items = Vec::new();
    loop {
        let sep = if url.contains('?') { '&' } else { '?' };
        let page = get_key(http, &format!("{url}{sep}offset={}&limit=200", items.len()), key).await?;
        let data = page["data"].as_array().cloned().unwrap_or_default();
        let total = page["totalCount"].as_u64().unwrap_or((items.len() + data.len()) as u64);
        let empty = data.is_empty();
        items.extend(data);
        if empty || items.len() as u64 >= total || items.len() >= max {
            return Ok((items, total));
        }
    }
}

async fn integration(http: &Client, base: &str, key: &str) -> Result<Value> {
    // Pfad je nach Plattform: UniFi OS mit Proxy, eigenständige Network Application ohne
    let mut api = format!("{base}/proxy/network/integration/v1");
    let info = match get_key(http, &format!("{api}/info"), key).await {
        Ok(info) => info,
        Err(e) if e.to_string().contains("nicht gefunden") => {
            api = format!("{base}/integration/v1");
            get_key(http, &format!("{api}/info"), key).await?
        }
        Err(e) => return Err(e),
    };
    let (sites, _) = get_all(http, &format!("{api}/sites"), key, 100).await?;
    let mut out_sites = Vec::new();
    let mut devices = Vec::new();
    let mut clients = Vec::new();
    let mut clients_total = 0;
    // Datenraten, Signal usw. je Client gibt es nur in der klassischen API – der API-Schlüssel wird dort
    // von neueren Versionen ebenfalls angenommen. Klappt es nicht, bleiben die Basisdaten.
    let mut details_error: Option<String> = None;
    let mut details_ok = false;
    for site in &sites {
        let site_id = site["id"].as_str().unwrap_or_default().to_string();
        let site_name = site["name"].as_str().unwrap_or("Standard").to_string();
        let site_ref = site["internalReference"].as_str().unwrap_or("default").to_string();
        let rich: HashMap<String, Value> = match classic_clients_with_key(http, base, key, &site_ref).await {
            Ok(list) => {
                details_ok = true;
                list.into_iter().filter_map(|c| Some((c["mac"].as_str()?.to_lowercase(), c))).collect()
            }
            Err(e) => {
                details_error.get_or_insert_with(|| format!("{e:#}"));
                HashMap::new()
            }
        };
        let (site_devices, _) = get_all(http, &format!("{api}/sites/{site_id}/devices"), key, 1000).await?;
        let (site_clients, total) = get_all(http, &format!("{api}/sites/{site_id}/clients"), key, MAX_CLIENTS).await.unwrap_or_default();
        clients_total += total;

        // Aktuelle Auslastung je Gerät (parallel, höchstens 8 gleichzeitig)
        let urls: Vec<String> = site_devices
            .iter()
            .map(|d| format!("{api}/sites/{site_id}/devices/{}/statistics/latest", d["id"].as_str().unwrap_or_default()))
            .collect();
        let stats: Vec<Value> = stream::iter(urls)
            .map(|url| {
                let (http, key) = (http.clone(), key.to_string());
                async move { get_key(&http, &url, &key).await.unwrap_or(Value::Null) }
            })
            .buffered(8)
            .collect()
            .await;

        let mut per_device_clients = std::collections::HashMap::<String, u64>::new();
        for c in &site_clients {
            if let Some(up) = c["uplinkDeviceId"].as_str() {
                *per_device_clients.entry(up.to_string()).or_default() += 1;
            }
        }
        for (d, s) in site_devices.iter().zip(stats) {
            let id = d["id"].as_str().unwrap_or_default();
            devices.push(json!({
                "site": site_name,
                "name": d["name"],
                "model": d["model"],
                "mac": d["macAddress"].as_str().map(str::to_lowercase),
                "ip": d["ipAddress"],
                "state": d["state"].as_str().map(str::to_lowercase),
                "firmware": d["firmwareVersion"],
                "uptime_s": s["uptimeSec"],
                "cpu_pct": s["cpuUtilizationPct"],
                "mem_pct": s["memoryUtilizationPct"],
                "load_1m": s["loadAverage1Min"],
                "tx_bps": s["uplink"]["txRateBps"],
                "rx_bps": s["uplink"]["rxRateBps"],
                "clients": per_device_clients.get(id).copied().unwrap_or(0),
                "radios": d["interfaces"]["radios"],
            }));
        }
        let mac_of: HashMap<&str, String> = site_devices
            .iter()
            .filter_map(|d| Some((d["id"].as_str()?, d["macAddress"].as_str()?.to_lowercase())))
            .collect();
        let name_of: HashMap<String, String> = site_devices
            .iter()
            .filter_map(|d| Some((d["macAddress"].as_str()?.to_lowercase(), d["name"].as_str()?.to_string())))
            .collect();
        for c in site_clients {
            let mac = c["macAddress"].as_str().map(str::to_lowercase);
            let uplink = c["uplinkDeviceId"].as_str().and_then(|id| mac_of.get(id)).cloned();
            // Basis aus der Integration-API, ergänzt um die Details der klassischen API
            let mut entry = match mac.as_deref().and_then(|m| rich.get(m)) {
                Some(r) => r.clone(),
                None => json!({}),
            };
            let obj = entry.as_object_mut().expect("json-Objekt");
            let mut set = |k: &str, v: Value| {
                if !v.is_null() && obj.get(k).is_none_or(Value::is_null) {
                    obj.insert(k.into(), v);
                }
            };
            set("name", c["name"].clone());
            set("mac", json!(mac));
            set("ip", c["ipAddress"].clone());
            set("type", json!(c["type"].as_str().map(str::to_lowercase)));
            set("connected_at", c["connectedAt"].clone());
            set("uplink_mac", json!(uplink));
            let up = obj.get("uplink_mac").and_then(Value::as_str).and_then(|m| name_of.get(m)).cloned();
            obj.insert("uplink_name".into(), json!(up));
            obj.insert("site".into(), json!(site_name));
            clients.push(entry);
        }
        out_sites.push(json!({ "name": site_name, "devices": site_devices.len(), "clients": total }));
    }
    Ok(summarize(json!({
        "api": "integration",
        "version": info["applicationVersion"],
        "sites": out_sites,
        "devices": devices,
        "clients": clients,
        "clients_total": clients_total,
        // Datenraten/Signal je Client verfügbar? Sonst der Grund
        "client_details": if details_ok { json!({ "ok": true }) } else { json!({ "ok": false, "reason": details_error }) },
    })))
}

/// Klassische Client-Liste (`stat/sta`) mit dem API-Schlüssel – liefert Datenraten, Signal, SSID …
async fn classic_clients_with_key(http: &Client, base: &str, key: &str, site: &str) -> Result<Vec<Value>> {
    let url = format!("{base}/proxy/network/api/s/{site}/stat/sta");
    let response = http.get(&url).header("X-API-KEY", key).header(header::ACCEPT, "application/json").send().await?;
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        bail!("Der Controller gibt Datenraten je Client nicht mit dem API-Schlüssel heraus");
    }
    if !status.is_success() {
        bail!("Client-Details: Controller antwortete mit {status}");
    }
    let body: Value = response.json().await.context("Client-Details nicht lesbar")?;
    Ok(body["data"].as_array().map(|list| list.iter().map(client_details).collect()).unwrap_or_default())
}

/// Einheitliche Client-Daten aus der klassischen API.
/// Richtung: UniFi zählt aus Sicht des Access Points/Switches – „tx“ geht zum Client (= dessen Download).
fn client_details(c: &Value) -> Value {
    let num = |v: &Value| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()));
    let wired = c["is_wired"].as_bool() == Some(true);
    let rate = |key: &str| num(&c[format!("{key}-r")]).or_else(|| num(&c[format!("wired-{key}-r")])).map(|b| b * 8.0);
    let total = |key: &str| num(&c[key]).or_else(|| num(&c[format!("wired-{key}")]));
    let band = match c["radio"].as_str() {
        Some("ng") => Some("2,4 GHz"),
        Some("na") => Some("5 GHz"),
        Some("6e") => Some("6 GHz"),
        _ => None,
    };
    let uptime = num(&c["uptime"]);
    json!({
        "name": c["name"].as_str().filter(|s| !s.is_empty()).or(c["hostname"].as_str()),
        "hostname": c["hostname"],
        "mac": c["mac"].as_str().map(str::to_lowercase),
        "ip": c["ip"],
        "vendor": c["oui"].as_str().filter(|s| !s.is_empty()),
        "type": if wired { "wired" } else { "wireless" },
        "uplink_mac": c["ap_mac"].as_str().or(c["sw_mac"].as_str()).map(str::to_lowercase),
        "switch_port": c["sw_port"],
        "ssid": c["essid"],
        "band": band,
        "wifi_standard": c["radio_proto"].as_str().map(|p| format!("Wi-Fi {}", match p {
            "be" => "7", "ax" => "6", "ac" => "5", "n" => "4", other => other,
        })),
        "channel": c["channel"],
        "signal_dbm": num(&c["signal"]).or_else(|| num(&c["rssi"]).map(|r| r - 95.0)),
        "satisfaction": num(&c["satisfaction"]),
        "link_down_kbps": num(&c["tx_rate"]),
        "link_up_kbps": num(&c["rx_rate"]),
        "down_bps": rate("tx_bytes"),
        "up_bps": rate("rx_bytes"),
        "down_bytes": total("tx_bytes"),
        "up_bytes": total("rx_bytes"),
        "uptime_s": uptime,
        "connected_at": uptime.map(|u| chrono::Utc::now() - chrono::Duration::seconds(u as i64)),
        "network": c["network"],
        "vlan": c["vlan"],
        "guest": c["is_guest"],
    })
}

// ---------------------------------------------------------------------------
// Klassische API mit lokalem Konto
// ---------------------------------------------------------------------------

async fn classic(http: &Client, base: &str, user: &str, password: &str) -> Result<Value> {
    // UniFi OS; ältere Network Application nutzt /api/login ohne /proxy/network
    let mut unifi_os = true;
    let mut response = http
        .post(format!("{base}/api/auth/login"))
        .json(&json!({ "username": user, "password": password, "rememberMe": false }))
        .send()
        .await?;
    if response.status() == StatusCode::NOT_FOUND {
        unifi_os = false;
        response = http.post(format!("{base}/api/login")).json(&json!({ "username": user, "password": password })).send().await?;
    }
    let status = response.status();
    let csrf = response.headers().get("x-csrf-token").and_then(|v| v.to_str().ok()).map(str::to_string);
    let body = response.text().await.unwrap_or_default();
    if status.as_u16() == 499 || body.contains("2fa") || body.contains("2Fa") || body.contains("MFA") {
        bail!("Für dieses Konto ist die Zwei-Faktor-Anmeldung aktiv – stattdessen einen API-Schlüssel verwenden \
               (UniFi Network → Einstellungen → Control Plane → Integrations) oder ein lokales Nur-Lese-Konto ohne 2FA anlegen");
    }
    if !status.is_success() {
        bail!("Anmeldung fehlgeschlagen ({status}) – Benutzername/Passwort prüfen (lokales Konto, kein UI-Konto)");
    }
    let prefix = if unifi_os { format!("{base}/proxy/network") } else { base.to_string() };
    let get = |path: String| {
        let mut request = http.get(format!("{prefix}{path}"));
        if let Some(token) = &csrf {
            request = request.header("X-CSRF-Token", token);
        }
        async move {
            let response = request.send().await?;
            if !response.status().is_success() {
                bail!("Controller antwortete mit {}", response.status());
            }
            response.json::<Value>().await.context("Antwort nicht lesbar")
        }
    };
    let sites = get("/api/self/sites".into()).await?;
    let mut out_sites = Vec::new();
    let mut devices = Vec::new();
    let mut clients = Vec::new();
    let mut version = Value::Null;
    for site in sites["data"].as_array().into_iter().flatten() {
        let name = site["name"].as_str().unwrap_or("default");
        let label = site["desc"].as_str().unwrap_or(name).to_string();
        let site_devices = get(format!("/api/s/{name}/stat/device")).await.unwrap_or(Value::Null);
        let site_clients = get(format!("/api/s/{name}/stat/sta")).await.unwrap_or(Value::Null);
        if version.is_null() {
            version = get(format!("/api/s/{name}/stat/sysinfo")).await.map(|v| v["data"][0]["version"].clone()).unwrap_or(Value::Null);
        }
        let list = site_devices["data"].as_array().cloned().unwrap_or_default();
        let sta = site_clients["data"].as_array().cloned().unwrap_or_default();
        for d in &list {
            let num = |v: &Value| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()));
            devices.push(json!({
                "site": label,
                "name": d["name"].as_str().or(d["hostname"].as_str()),
                "model": d["model"],
                "mac": d["mac"].as_str().map(str::to_lowercase),
                "ip": d["ip"],
                "state": match d["state"].as_i64() { Some(1) => "online", Some(0) => "offline", Some(_) => "pending", None => "unknown" },
                "firmware": d["version"],
                "uptime_s": d["uptime"],
                "cpu_pct": num(&d["system-stats"]["cpu"]),
                "mem_pct": num(&d["system-stats"]["mem"]),
                "load_1m": num(&d["sys_stats"]["loadavg_1"]),
                "tx_bps": d["uplink"]["tx_bytes-r"].as_f64().map(|b| b * 8.0),
                "rx_bps": d["uplink"]["rx_bytes-r"].as_f64().map(|b| b * 8.0),
                "clients": d["num_sta"],
            }));
        }
        let name_of: HashMap<String, String> = list
            .iter()
            .filter_map(|d| Some((d["mac"].as_str()?.to_lowercase(), d["name"].as_str().or(d["hostname"].as_str())?.to_string())))
            .collect();
        for c in &sta {
            let mut entry = client_details(c);
            let up = entry["uplink_mac"].as_str().and_then(|m| name_of.get(m)).cloned();
            entry["uplink_name"] = json!(up);
            entry["site"] = json!(label);
            clients.push(entry);
        }
        out_sites.push(json!({ "name": label, "devices": list.len(), "clients": sta.len() }));
    }
    let _ = http.post(format!("{base}/api/{}logout", if unifi_os { "auth/" } else { "" })).send().await;
    let clients_total = clients.len();
    Ok(summarize(json!({
        "api": "classic",
        "version": version,
        "sites": out_sites,
        "devices": devices,
        "clients": clients,
        "clients_total": clients_total,
        "client_details": { "ok": true },
    })))
}

fn summarize(mut data: Value) -> Value {
    let devices = data["devices"].as_array().cloned().unwrap_or_default();
    let online = devices.iter().filter(|d| d["state"] == "online" || d["state"] == "connected").count();
    data["devices_total"] = json!(devices.len());
    data["devices_online"] = json!(online);
    if let Some(list) = data["clients"].as_array_mut() {
        list.truncate(MAX_CLIENTS);
    }
    data
}

/// Gerätetyp aus dem UniFi-Modell – Kürzel (klassische API, z. B. „U7PG2“) oder Verkaufsname
/// (Integration-API, z. B. „AC Mesh“, „US 24 PoE 250W“, „Dream Machine Pro“)
pub fn device_type(model: &str) -> Option<&'static str> {
    let m = model.to_uppercase();
    let has = |words: &[&str]| words.iter().any(|w| m.contains(w));
    if ["UDM", "UDR", "UCG", "UXG", "USG", "UDW", "UX", "EFG"].iter().any(|p| m.starts_with(p))
        || has(&["DREAM MACHINE", "DREAM ROUTER", "CLOUD GATEWAY", "GATEWAY", "SECURITY GATEWAY", "EXPRESS"])
    {
        Some("router")
    } else if m.starts_with("USW") || (m.starts_with("US") && !m.starts_with("USP")) || m.starts_with("ECS") || has(&["SWITCH"]) {
        Some("switch")
    } else if ["U6", "U7", "UAP", "UAL", "UK", "UWB", "E7", "U5", "UBB", "AC ", "NANOHD", "FLEXHD", "BEACONHD"].iter().any(|p| m.starts_with(p))
        || has(&["MESH", "IN-WALL", "ACCESS POINT", "LITE AP", "LR AP", "PRO AP"])
    {
        Some("access_point")
    } else if m.starts_with("UVC") || m.starts_with("G4") || m.starts_with("G5") || m.starts_with("G6") {
        Some("camera")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modelle() {
        assert_eq!(device_type("U6-Pro"), Some("access_point"));
        assert_eq!(device_type("USW-Lite-8-PoE"), Some("switch"));
        assert_eq!(device_type("UDM-Pro"), Some("router"));
        assert_eq!(device_type("UCG-Ultra"), Some("router"));
        assert_eq!(device_type("Foo"), None);
        // Verkaufsnamen aus der Integration-API
        assert_eq!(device_type("AC Mesh"), Some("access_point"));
        assert_eq!(device_type("US 24 PoE 250W"), Some("switch"));
        assert_eq!(device_type("USW Lite 8 PoE"), Some("switch"));
        assert_eq!(device_type("Dream Machine Pro"), Some("router"));
        assert_eq!(device_type("U6 Long-Range"), Some("access_point"));
    }

    #[test]
    fn client_details_aus_klassischer_api() {
        let c = json!({ "mac": "AA:BB:CC:00:00:01", "hostname": "handy", "essid": "Heim", "radio": "na", "radio_proto": "ax",
            "signal": -61, "tx_bytes-r": 1000, "rx_bytes-r": 250, "tx_bytes": 5_000_000, "ap_mac": "11:22:33:44:55:66", "uptime": 120 });
        let d = client_details(&c);
        assert_eq!(d["name"], "handy");
        assert_eq!(d["mac"], "aa:bb:cc:00:00:01");
        assert_eq!(d["band"], "5 GHz");
        assert_eq!(d["wifi_standard"], "Wi-Fi 6");
        assert_eq!(d["signal_dbm"], -61.0);
        assert_eq!(d["down_bps"], 8000.0);
        assert_eq!(d["up_bps"], 2000.0);
        assert_eq!(d["uplink_mac"], "11:22:33:44:55:66");
        assert_eq!(d["type"], "wireless");
    }

    fn cred(port: Option<i32>) -> Credential {
        Credential { id: 1, name: "UniFi".into(), kind: "unifi".into(), username: None, port, secret: Default::default(), linked: true, options: serde_json::Value::Null }
    }

    #[test]
    fn eingetragener_port_zuerst_dann_standard() {
        assert_eq!(ports(&cred(Some(8443))), vec![8443, 11443, 443]);
        assert_eq!(ports(&cred(Some(9443))), vec![9443, 11443, 443, 8443]);
        assert_eq!(ports(&cred(None)), vec![11443, 443, 8443]);
    }
}
