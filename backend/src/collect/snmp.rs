//! SNMP-Abfrage (v2c und v3) für Router, Switches, Drucker, USV, NAS …
//!
//! Gelesen werden nur Standard-MIBs, die fast jedes Gerät kennt:
//! SNMPv2-MIB (System), IF-MIB (Schnittstellen), HOST-RESOURCES-MIB (CPU, RAM, Speicher),
//! Printer-MIB (Toner, Papierfächer, Seitenzähler), UPS-MIB (Akku), ENTITY-MIB (Modell, Seriennummer), LLDP-MIB (Nachbarn)
//! sowie die Synology-MIB (Modell, Temperatur).

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Map, Value};
use snmp2::{v3, AsyncSession, Oid};

use super::Credential;

const TIMEOUT: Duration = Duration::from_secs(2);

/// Eigene, besitzende Kopie eines SNMP-Werts (die Bibliothek leiht nur den Empfangspuffer aus)
#[derive(Debug, Clone)]
pub(crate) enum Val {
    Int(i64),
    Uint(u64),
    Bytes(Vec<u8>),
    Oid(String),
    Ip([u8; 4]),
    Missing,
}

impl Val {
    fn of(value: &snmp2::Value) -> Self {
        use snmp2::Value as V;
        match value {
            V::Integer(n) => Val::Int(*n),
            V::Counter32(n) | V::Unsigned32(n) | V::Timeticks(n) => Val::Uint(u64::from(*n)),
            V::Counter64(n) => Val::Uint(*n),
            V::OctetString(bytes) | V::Opaque(bytes) => Val::Bytes(bytes.to_vec()),
            V::ObjectIdentifier(oid) => Val::Oid(oid.to_id_string()),
            V::IpAddress(ip) => Val::Ip(*ip),
            _ => Val::Missing,
        }
    }

    pub(crate) fn text(&self) -> Option<String> {
        match self {
            Val::Bytes(b) => {
                let text = String::from_utf8_lossy(b).trim_matches(char::from(0)).trim().to_string();
                (!text.is_empty()).then_some(text)
            }
            Val::Int(n) => Some(n.to_string()),
            Val::Uint(n) => Some(n.to_string()),
            Val::Oid(s) => Some(s.clone()),
            Val::Ip(ip) => Some(Ipv4Addr::from(*ip).to_string()),
            Val::Missing => None,
        }
    }

    pub(crate) fn num(&self) -> Option<f64> {
        match self {
            Val::Int(n) => Some(*n as f64),
            Val::Uint(n) => Some(*n as f64),
            Val::Bytes(b) => String::from_utf8_lossy(b).trim().parse().ok(),
            _ => None,
        }
    }

    /// Typ und lesbarer Wert für den SNMP-Explorer
    pub(crate) fn describe(&self) -> (&'static str, String) {
        match self {
            Val::Int(n) => ("Integer", n.to_string()),
            Val::Uint(n) => ("Zähler", n.to_string()),
            Val::Oid(o) => ("OID", o.clone()),
            Val::Ip(ip) => ("IP-Adresse", Ipv4Addr::from(*ip).to_string()),
            Val::Missing => ("fehlt", String::new()),
            Val::Bytes(b) => match std::str::from_utf8(b) {
                // Text, wenn gültiges UTF-8 ohne Steuerzeichen (außer Zeilenumbruch/Tab)
                Ok(text) if !text.is_empty() && !text.chars().any(|c| c.is_control() && !c.is_whitespace()) => {
                    ("Text", text.to_string())
                }
                _ => ("Hex", b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")),
            },
        }
    }

    fn mac(&self) -> Option<String> {
        match self {
            Val::Bytes(b) if b.len() == 6 => {
                Some(b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"))
            }
            _ => None,
        }
    }
}

/// Fehler der SNMP-Bibliothek in verständliche Hinweise übersetzen
fn friendly(e: &snmp2::Error) -> String {
    let raw = format!("{e:?}");
    let hint = if raw.contains("AuthFailure") || raw.contains("AuthUpdateFailed") || raw.contains("UnknownUsername") {
        "Anmeldung abgelehnt – Benutzername, Auth-Passwort oder Auth-Verfahren (SHA/MD5) stimmen nicht"
    } else if raw.contains("Crypto") || raw.contains("Decrypt") || raw.contains("Priv") {
        "Verschlüsselung passt nicht – Verschlüsselungs-Passwort oder -Verfahren (AES/DES) prüfen"
    } else if raw.contains("Receive") || raw.contains("Send") || raw.contains("ConnectionRefused") {
        "Gerät antwortet nicht auf SNMP (UDP-Port 161 geschlossen – ist SNMP am Gerät aktiviert?)"
    } else if raw.contains("CommunityMismatch") {
        "Community stimmt nicht"
    } else {
        return format!("SNMP-Fehler: {raw}");
    };
    format!("{hint} ({raw})")
}

fn oid(parts: &[u64]) -> Result<Oid<'static>> {
    Oid::from(parts).map_err(|e| anyhow!("Ungültige OID: {e:?}"))
}

fn oid_parts(oid: &Oid) -> Vec<u64> {
    oid.iter().map(|it| it.collect()).unwrap_or_default()
}

pub(crate) async fn open(ip: Ipv4Addr, cred: &Credential) -> Result<AsyncSession> {
    let port = cred.port.and_then(|p| u16::try_from(p).ok()).unwrap_or(161);
    let addr = SocketAddr::from((ip, port));
    let secret = &cred.secret;
    match cred.kind.as_str() {
        "snmp_v2c" => {
            let community = secret.community.as_deref().unwrap_or("public");
            Ok(AsyncSession::new_v2c(addr, community.as_bytes(), 1).await?)
        }
        "snmp_v3" => {
            let username = cred.username.as_deref().unwrap_or_default();
            let auth_password = secret.auth_password.as_deref().unwrap_or_default();
            let mut security = v3::Security::new(username.as_bytes(), auth_password.as_bytes());
            let auth_proto = secret.auth_protocol.as_deref().unwrap_or("sha1");
            if auth_proto != "none" {
                security = security.with_auth_protocol(match auth_proto {
                    "md5" => v3::AuthProtocol::Md5,
                    "sha224" => v3::AuthProtocol::Sha224,
                    "sha256" => v3::AuthProtocol::Sha256,
                    "sha384" => v3::AuthProtocol::Sha384,
                    "sha512" => v3::AuthProtocol::Sha512,
                    _ => v3::AuthProtocol::Sha1,
                });
            }
            let priv_proto = secret.priv_protocol.as_deref().unwrap_or("none");
            let auth = match (auth_proto, priv_proto) {
                ("none", _) => v3::Auth::NoAuthNoPriv,
                (_, "none") => v3::Auth::AuthNoPriv,
                (_, cipher) => v3::Auth::AuthPriv {
                    cipher: match cipher {
                        "des" => v3::Cipher::Des,
                        "aes192" => v3::Cipher::Aes192,
                        "aes256" => v3::Cipher::Aes256,
                        _ => v3::Cipher::Aes128,
                    },
                    privacy_password: secret.priv_password.clone().unwrap_or_default().into_bytes(),
                },
            };
            security = security.with_auth(auth);
            let mut session = AsyncSession::new_v3(addr, 1, security).await?;
            // Engine-ID des Agenten ermitteln (Pflicht bei v3)
            match tokio::time::timeout(TIMEOUT * 2, session.init()).await {
                Ok(Ok(())) => Ok(session),
                Ok(Err(e)) => bail!("{}", friendly(&e)),
                Err(_) => bail!("Zeitüberschreitung (keine Antwort auf SNMPv3)"),
            }
        }
        other => bail!("{other} ist keine SNMP-Zugangsart"),
    }
}

/// GET mehrerer Werte (mit einer Wiederholung bei UDP-Verlust)
pub(crate) async fn get(session: &mut AsyncSession, oids: &[&[u64]]) -> Result<Vec<(Vec<u64>, Val)>> {
    let oids: Vec<Oid<'static>> = oids.iter().map(|o| oid(o)).collect::<Result<_>>()?;
    let refs: Vec<&Oid> = oids.iter().collect();
    for attempt in 0..2 {
        match tokio::time::timeout(TIMEOUT, session.get_many(&refs)).await {
            Ok(Ok(pdu)) => return Ok(pdu.varbinds.map(|(o, v)| (oid_parts(&o), Val::of(&v))).collect()),
            Ok(Err(e)) => bail!("{}", friendly(&e)),
            Err(_) if attempt == 0 => continue,
            Err(_) => bail!("Zeitüberschreitung – Gerät antwortet nicht auf SNMP (Community/Benutzer richtig?)"),
        }
    }
    unreachable!()
}

/// Alle Werte unterhalb einer OID lesen (GETBULK), höchstens `max` Einträge
pub(crate) async fn walk(session: &mut AsyncSession, base: &[u64], max: usize) -> Result<Vec<(Vec<u64>, Val)>> {
    let mut out = Vec::new();
    let mut current = base.to_vec();
    'outer: loop {
        let start = oid(&current)?;
        let mut response = None;
        for _ in 0..2 {
            match tokio::time::timeout(TIMEOUT, session.getbulk(&[&start], 0, 25)).await {
                Ok(Ok(pdu)) => {
                    response = Some(pdu.varbinds.map(|(o, v)| (oid_parts(&o), Val::of(&v))).collect::<Vec<_>>());
                    break;
                }
                Ok(Err(e)) => bail!("{}", friendly(&e)),
                Err(_) => continue,
            }
        }
        let Some(rows) = response else { bail!("Zeitüberschreitung beim Lesen von {}", dotted(base)) };
        if rows.is_empty() {
            break;
        }
        for (name, value) in rows {
            if !name.starts_with(base) || matches!(value, Val::Missing) || name <= current {
                break 'outer;
            }
            current = name.clone();
            out.push((name, value));
            if out.len() >= max {
                break 'outer;
            }
        }
    }
    Ok(out)
}

pub(crate) fn dotted(parts: &[u64]) -> String {
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// Spalte einer Tabelle: Index (Rest der OID) → Wert
pub(crate) async fn column(session: &mut AsyncSession, base: &[u64], max: usize) -> BTreeMap<Vec<u64>, Val> {
    walk(session, base, max)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| (name[base.len()..].to_vec(), value))
        .collect()
}

// Wichtige OIDs
const SYSTEM: &[u64] = &[1, 3, 6, 1, 2, 1, 1];
pub(crate) const IF_TABLE: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1];
pub(crate) const IFX_TABLE: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1];
const HR_STORAGE: &[u64] = &[1, 3, 6, 1, 2, 1, 25, 2, 3, 1];
const HR_PROCESSOR_LOAD: &[u64] = &[1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2];
const UPS_MIB: &[u64] = &[1, 3, 6, 1, 2, 1, 33, 1];
const ENTITY_PHYSICAL: &[u64] = &[1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1];
const LLDP_REM_SYSNAME: &[u64] = &[1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9];
const SYNOLOGY_SYSTEM: &[u64] = &[1, 3, 6, 1, 4, 1, 6574, 1];

pub(crate) fn with(base: &[u64], tail: &[u64]) -> Vec<u64> {
    base.iter().chain(tail).copied().collect()
}

pub async fn collect(ip: Ipv4Addr, cred: &Credential) -> Result<Value> {
    let mut s = open(ip, cred).await?;
    let mut data = Map::new();

    // System-Gruppe – schlägt sie fehl, sind die Zugangsdaten falsch oder SNMP ist aus
    let sys: Vec<Vec<u64>> = (1..=6).map(|i| with(SYSTEM, &[i, 0])).collect();
    let sys_refs: Vec<&[u64]> = sys.iter().map(Vec::as_slice).collect();
    let system = get(&mut s, &sys_refs).await?;
    let field = |i: u64| system.iter().find(|(o, _)| o == &with(SYSTEM, &[i, 0])).map(|(_, v)| v.clone());
    if field(1).and_then(|v| v.text()).is_none() && field(5).and_then(|v| v.text()).is_none() {
        bail!("Gerät liefert keine SNMP-Systemdaten");
    }
    data.insert("sys_descr".into(), json!(field(1).and_then(|v| v.text())));
    data.insert("sys_object_id".into(), json!(field(2).and_then(|v| v.text())));
    data.insert("uptime_s".into(), json!(field(3).and_then(|v| v.num()).map(|t| (t / 100.0) as u64)));
    data.insert("sys_contact".into(), json!(field(4).and_then(|v| v.text())));
    data.insert("sys_name".into(), json!(field(5).and_then(|v| v.text())));
    data.insert("sys_location".into(), json!(field(6).and_then(|v| v.text())));

    // Schnittstellen (IF-MIB, 64-Bit-Zähler aus ifXTable wenn vorhanden)
    let descr = column(&mut s, &with(IF_TABLE, &[2]), 256).await;
    if !descr.is_empty() {
        let if_type = column(&mut s, &with(IF_TABLE, &[3]), 256).await;
        let speed = column(&mut s, &with(IF_TABLE, &[5]), 256).await;
        let phys = column(&mut s, &with(IF_TABLE, &[6]), 256).await;
        let oper = column(&mut s, &with(IF_TABLE, &[8]), 256).await;
        let in32 = column(&mut s, &with(IF_TABLE, &[10]), 256).await;
        let out32 = column(&mut s, &with(IF_TABLE, &[16]), 256).await;
        let name = column(&mut s, &with(IFX_TABLE, &[1]), 256).await;
        let in64 = column(&mut s, &with(IFX_TABLE, &[6]), 256).await;
        let out64 = column(&mut s, &with(IFX_TABLE, &[10]), 256).await;
        let high_speed = column(&mut s, &with(IFX_TABLE, &[15]), 256).await;
        let alias = column(&mut s, &with(IFX_TABLE, &[18]), 256).await;
        let interfaces: Vec<Value> = descr
            .iter()
            .take(128)
            .map(|(idx, d)| {
                let num = |m: &BTreeMap<Vec<u64>, Val>| m.get(idx).and_then(Val::num);
                let speed_mbps = num(&high_speed).filter(|v| *v > 0.0).or_else(|| num(&speed).map(|b| b / 1e6));
                json!({
                    "index": idx.first(),
                    "name": name.get(idx).and_then(Val::text).or_else(|| d.text()),
                    "descr": d.text(),
                    "alias": alias.get(idx).and_then(Val::text),
                    "type": num(&if_type),
                    "oper": match num(&oper) { Some(1.0) => "up", Some(2.0) => "down", Some(5.0) => "dormant", _ => "unknown" },
                    "speed_mbps": speed_mbps,
                    "mac": phys.get(idx).and_then(Val::mac),
                    "rx_bytes": num(&in64).or_else(|| num(&in32)),
                    "tx_bytes": num(&out64).or_else(|| num(&out32)),
                })
            })
            .collect();
        data.insert("interfaces".into(), Value::Array(interfaces));
    }

    // Speicher und RAM (HOST-RESOURCES-MIB)
    let storage_type = column(&mut s, &with(HR_STORAGE, &[2]), 128).await;
    if !storage_type.is_empty() {
        let descr = column(&mut s, &with(HR_STORAGE, &[3]), 128).await;
        let units = column(&mut s, &with(HR_STORAGE, &[4]), 128).await;
        let size = column(&mut s, &with(HR_STORAGE, &[5]), 128).await;
        let used = column(&mut s, &with(HR_STORAGE, &[6]), 128).await;
        let storage: Vec<Value> = storage_type
            .iter()
            .filter_map(|(idx, kind)| {
                let kind = match kind {
                    Val::Oid(o) if o.ends_with(".25.2.1.2") => "ram",
                    Val::Oid(o) if o.ends_with(".25.2.1.4") => "disk",
                    Val::Oid(o) if o.ends_with(".25.2.1.3") => "virtual",
                    _ => "other",
                };
                let unit = units.get(idx).and_then(Val::num).unwrap_or(1.0);
                let size_b = size.get(idx).and_then(Val::num)? * unit;
                let used_b = used.get(idx).and_then(Val::num).unwrap_or(0.0) * unit;
                (size_b > 0.0).then(|| {
                    json!({
                        "descr": descr.get(idx).and_then(Val::text),
                        "kind": kind,
                        "size_bytes": size_b,
                        "used_bytes": used_b,
                        "pct": (used_b / size_b * 1000.0).round() / 10.0,
                    })
                })
            })
            .collect();
        data.insert("storage".into(), Value::Array(storage));
    }

    // CPU-Last: Mittelwert aller Kerne
    let loads: Vec<f64> = column(&mut s, HR_PROCESSOR_LOAD, 256).await.values().filter_map(Val::num).collect();
    if !loads.is_empty() {
        data.insert("cpu_pct".into(), json!(loads.iter().sum::<f64>() / loads.len() as f64));
        data.insert("cpu_cores".into(), json!(loads.len()));
    }

    // Drucker: Füllstände (Toner, Tinte, Trommel …), Papierfächer, Seitenzähler, Status
    if let Some((supplies, info)) = super::printer::collect(&mut s).await {
        data.insert("printer".into(), Value::Array(supplies));
        data.insert("printer_info".into(), info);
    }

    // USV (UPS-MIB)
    let ups = get(
        &mut s,
        &[
            &with(UPS_MIB, &[1, 1, 0]),
            &with(UPS_MIB, &[1, 2, 0]),
            &with(UPS_MIB, &[2, 1, 0]),
            &with(UPS_MIB, &[2, 3, 0]),
            &with(UPS_MIB, &[2, 4, 0]),
            &with(UPS_MIB, &[4, 1, 0]),
        ],
    )
    .await
    .unwrap_or_default();
    let ups_field = |tail: &[u64]| ups.iter().find(|(o, _)| o == &with(UPS_MIB, tail)).map(|(_, v)| v.clone());
    if let Some(charge) = ups_field(&[2, 4, 0]).and_then(|v| v.num()) {
        data.insert(
            "ups".into(),
            json!({
                "manufacturer": ups_field(&[1, 1, 0]).and_then(|v| v.text()),
                "model": ups_field(&[1, 2, 0]).and_then(|v| v.text()),
                "battery_status": match ups_field(&[2, 1, 0]).and_then(|v| v.num()) {
                    Some(2.0) => "normal", Some(3.0) => "niedrig", Some(4.0) => "leer", _ => "unbekannt",
                },
                "runtime_min": ups_field(&[2, 3, 0]).and_then(|v| v.num()),
                "charge_pct": charge,
                "on_battery": ups_field(&[4, 1, 0]).and_then(|v| v.num()) == Some(5.0),
            }),
        );
    }

    // Synology-NAS: Modell, Seriennummer, Temperatur
    let syno = get(
        &mut s,
        &[
            &with(SYNOLOGY_SYSTEM, &[1, 0]),
            &with(SYNOLOGY_SYSTEM, &[2, 0]),
            &with(SYNOLOGY_SYSTEM, &[5, 1, 0]),
            &with(SYNOLOGY_SYSTEM, &[5, 2, 0]),
            &with(SYNOLOGY_SYSTEM, &[5, 3, 0]),
        ],
    )
    .await
    .unwrap_or_default();
    let syno_field = |tail: &[u64]| syno.iter().find(|(o, _)| o == &with(SYNOLOGY_SYSTEM, tail)).map(|(_, v)| v.clone());
    if let Some(model) = syno_field(&[5, 1, 0]).and_then(|v| v.text()) {
        data.insert(
            "synology".into(),
            json!({
                "model": model,
                "serial": syno_field(&[5, 2, 0]).and_then(|v| v.text()),
                "version": syno_field(&[5, 3, 0]).and_then(|v| v.text()),
                "temp_c": syno_field(&[2, 0]).and_then(|v| v.num()),
                "status_ok": syno_field(&[1, 0]).and_then(|v| v.num()) == Some(1.0),
            }),
        );
    }

    // Modell und Seriennummer (ENTITY-MIB) – erste nicht-leere Angabe
    let models = column(&mut s, &with(ENTITY_PHYSICAL, &[13]), 32).await;
    let serials = column(&mut s, &with(ENTITY_PHYSICAL, &[11]), 32).await;
    data.insert("model".into(), json!(models.values().find_map(Val::text)));
    data.insert("serial".into(), json!(serials.values().find_map(Val::text)));

    // LLDP-Nachbarn (für eine spätere Netzwerkkarte)
    let neighbors: Vec<String> = column(&mut s, LLDP_REM_SYSNAME, 64).await.values().filter_map(Val::text).collect();
    if !neighbors.is_empty() {
        data.insert("lldp_neighbors".into(), json!(neighbors));
    }

    // Internet-Anschluss: Schnittstelle der Standardroute (RFC1213 ipRouteIfIndex für 0.0.0.0)
    if let Ok(route) = get(&mut s, &[&[1, 3, 6, 1, 2, 1, 4, 21, 1, 2, 0, 0, 0, 0]]).await {
        if let Some(if_index) = route.first().and_then(|(_, v)| v.num()) {
            let name = data["interfaces"]
                .as_array()
                .and_then(|list| list.iter().find(|i| i["index"].as_f64() == Some(if_index)))
                .and_then(|i| i["name"].as_str().map(str::to_string));
            data.insert("default_route_if".into(), json!(name));
        }
    }

    // Prozesse und angemeldete Benutzer (HOST-RESOURCES-MIB)
    if let Ok(hr) = get(&mut s, &[&[1, 3, 6, 1, 2, 1, 25, 1, 5, 0], &[1, 3, 6, 1, 2, 1, 25, 1, 6, 0]]).await {
        data.insert("users".into(), json!(hr.first().and_then(|(_, v)| v.num())));
        data.insert("processes".into(), json!(hr.get(1).and_then(|(_, v)| v.num())));
    }

    // Temperatur- und weitere Sensoren (ENTITY-SENSOR-MIB, viele Switches und Router)
    let sensor_value = column(&mut s, &with(ENTITY_SENSOR, &[4]), 64).await;
    if !sensor_value.is_empty() {
        let sensor_type = column(&mut s, &with(ENTITY_SENSOR, &[1]), 64).await;
        let sensor_scale = column(&mut s, &with(ENTITY_SENSOR, &[2]), 64).await;
        let sensor_precision = column(&mut s, &with(ENTITY_SENSOR, &[3]), 64).await;
        let names = column(&mut s, &with(ENTITY_PHYSICAL, &[7]), 256).await;
        let sensors: Vec<Value> = sensor_value
            .iter()
            .filter_map(|(idx, value)| {
                let kind = match sensor_type.get(idx).and_then(Val::num)? as i64 {
                    3 => "Spannung (V)",
                    4 => "Spannung DC (V)",
                    5 => "Strom (A)",
                    6 => "Leistung (W)",
                    8 => "Temperatur (°C)",
                    10 => "Lüfter (U/min)",
                    _ => return None,
                };
                // Skalierung (9 = Einheit ohne Vorsatz) und Nachkommastellen
                let scale = sensor_scale.get(idx).and_then(Val::num).unwrap_or(9.0);
                let precision = sensor_precision.get(idx).and_then(Val::num).unwrap_or(0.0);
                let raw = value.num()?;
                let v = raw * 10f64.powi(((scale - 9.0) * 3.0) as i32) / 10f64.powi(precision as i32);
                Some(json!({ "name": names.get(idx).and_then(Val::text), "kind": kind, "value": (v * 10.0).round() / 10.0 }))
            })
            .collect();
        if let Some(max_temp) = sensors
            .iter()
            .filter(|x| x["kind"] == "Temperatur (°C)")
            .filter_map(|x| x["value"].as_f64())
            .reduce(f64::max)
        {
            data.insert("temp_c".into(), json!(max_temp));
        }
        data.insert("sensors".into(), Value::Array(sensors));
    }

    // Herstellerprofile: ein GET erkennt, welche Hersteller-MIBs das Gerät kennt
    let probe = get(
        &mut s,
        &[
            &[1, 3, 6, 1, 4, 1, 41112, 1, 6, 3, 3, 0],      // UniFi: Modell
            &[1, 3, 6, 1, 4, 1, 14988, 1, 1, 4, 4, 0],      // MikroTik: RouterOS-Version
            &[1, 3, 6, 1, 4, 1, 318, 1, 1, 1, 1, 1, 1, 0],  // APC: USV-Modell
            &[1, 3, 6, 1, 4, 1, 12325, 1, 200, 1, 1, 1, 0], // pf-Firewall (pfSense/OPNsense mit bsnmpd)
        ],
    )
    .await
    .unwrap_or_default();
    let present = |i: usize| probe.get(i).is_some_and(|(_, v)| !matches!(v, Val::Missing));

    if present(0) {
        data.insert("unifi".into(), unifi(&mut s).await);
    }
    if present(1) {
        data.insert("mikrotik".into(), mikrotik(&mut s, probe[1].1.text()).await);
    }
    if present(2) && !data.contains_key("ups") {
        if let Some(ups) = apc(&mut s).await {
            data.insert("ups".into(), ups);
        }
    }
    if present(3) {
        let states = get(&mut s, &[&[1, 3, 6, 1, 4, 1, 12325, 1, 200, 1, 3, 1, 0]]).await.unwrap_or_default();
        data.insert(
            "firewall".into(),
            json!({ "running": probe[3].1.num() == Some(1.0), "states": states.first().and_then(|(_, v)| v.num()) }),
        );
    }
    if data.contains_key("synology") {
        let extra = synology_storage(&mut s).await;
        if let Some(obj) = data.get_mut("synology").and_then(Value::as_object_mut) {
            obj.extend(extra);
        }
    }

    // Verbundene Geräte: Switch-Port je MAC (Weiterleitungstabelle) und IP ↔ MAC (ARP)
    let clients = net_clients(&mut s, data.get("interfaces")).await;
    if !clients.is_empty() {
        data.insert("net_clients".into(), Value::Array(clients));
    }

    Ok(Value::Object(data))
}

const DOT1D_BASE_PORT_IFINDEX: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
const DOT1D_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
const DOT1D_TP_FDB_STATUS: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 3];
const DOT1Q_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2];
const DOT1Q_TP_FDB_STATUS: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 3];
const IP_NET_TO_MEDIA_PHYS: &[u64] = &[1, 3, 6, 1, 2, 1, 4, 22, 1, 2];
const MAX_FDB: usize = 4096;

/// Herstellerunabhängig: Weiterleitungstabelle (BRIDGE-/Q-BRIDGE-MIB) und ARP-Tabelle (IP-MIB)
async fn net_clients(s: &mut AsyncSession, interfaces: Option<&Value>) -> Vec<Value> {
    use super::netclients;
    let port_if = column(s, DOT1D_BASE_PORT_IFINDEX, 1024).await;
    let if_name = |port: u64| -> String {
        let if_index = port_if.get(&vec![port]).and_then(Val::num);
        if_index
            .and_then(|i| {
                interfaces?.as_array()?.iter().find(|x| x["index"].as_f64() == Some(i)).map(|x| {
                    let name = x["name"].as_str().unwrap_or_default();
                    match x["alias"].as_str().filter(|a| !a.is_empty()) {
                        Some(alias) => format!("{name} ({alias})"),
                        None => name.to_string(),
                    }
                })
            })
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("Port {port}"))
    };
    let mac_of = |octets: &[u64]| -> Option<String> {
        (octets.len() == 6).then(|| octets.iter().map(|b| format!("{:02x}", b & 0xff)).collect::<Vec<_>>().join(":"))
    };
    // Status 3 = gelernt (4 = eigene Adresse des Switches → auslassen)
    let mut fdb: Vec<(String, String, Option<u64>)> = Vec::new();
    let q_ports = column(s, DOT1Q_TP_FDB_PORT, MAX_FDB).await;
    if !q_ports.is_empty() {
        let status = column(s, DOT1Q_TP_FDB_STATUS, MAX_FDB).await;
        for (idx, port) in &q_ports {
            let (Some(port), Some(mac)) = (port.num().map(|p| p as u64), idx.get(1..).and_then(mac_of)) else { continue };
            if port == 0 || status.get(idx).and_then(Val::num).is_some_and(|st| st != 3.0) {
                continue;
            }
            fdb.push((mac, if_name(port), idx.first().copied()));
        }
    } else {
        let ports = column(s, DOT1D_TP_FDB_PORT, MAX_FDB).await;
        let status = column(s, DOT1D_TP_FDB_STATUS, MAX_FDB).await;
        for (idx, port) in &ports {
            let (Some(port), Some(mac)) = (port.num().map(|p| p as u64), mac_of(idx)) else { continue };
            if port == 0 || status.get(idx).and_then(Val::num).is_some_and(|st| st != 3.0) {
                continue;
            }
            fdb.push((mac, if_name(port), None));
        }
    }
    let mut out = netclients::from_fdb(&fdb);

    // ARP: Index = ifIndex.a.b.c.d → MAC
    let arp = column(s, IP_NET_TO_MEDIA_PHYS, MAX_FDB).await;
    for (idx, value) in &arp {
        let (Some(mac), Some(ip)) = (value.mac(), idx.get(1..5)) else { continue };
        if ip.len() != 4 {
            continue;
        }
        let ip = ip.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
        let mut c = netclients::client("router", &mac);
        c.insert("ip".into(), json!(ip));
        out.push(Value::Object(c));
    }
    out
}

const ENTITY_SENSOR: &[u64] = &[1, 3, 6, 1, 2, 1, 99, 1, 1, 1];

/// UniFi-Access-Point (UBNT-UniFi-MIB): WLANs, Clients je WLAN, Funkkanäle, Kanalauslastung
async fn unifi(s: &mut AsyncSession) -> Value {
    const SYSTEM: &[u64] = &[1, 3, 6, 1, 4, 1, 41112, 1, 6, 3];
    const RADIO: &[u64] = &[1, 3, 6, 1, 4, 1, 41112, 1, 6, 1, 1, 1];
    const VAP: &[u64] = &[1, 3, 6, 1, 4, 1, 41112, 1, 6, 1, 2, 1];
    let system = get(s, &[&with(SYSTEM, &[3, 0]), &with(SYSTEM, &[6, 0])]).await.unwrap_or_default();
    let radio_name = column(s, &with(RADIO, &[2]), 16).await;
    let radio_band = column(s, &with(RADIO, &[3]), 16).await;
    let cu_total = column(s, &with(RADIO, &[6]), 16).await;
    let radios: Vec<Value> = radio_name
        .iter()
        .map(|(idx, name)| {
            let band = radio_band.get(idx).and_then(Val::text).unwrap_or_default();
            let band = match band.as_str() {
                "ng" => "2,4 GHz".to_string(),
                "na" => "5 GHz".to_string(),
                "6e" => "6 GHz".to_string(),
                other => other.to_string(),
            };
            json!({ "name": name.text(), "band": band, "utilization_pct": cu_total.get(idx).and_then(Val::num) })
        })
        .collect();
    let essid = column(s, &with(VAP, &[6]), 64).await;
    let channel = column(s, &with(VAP, &[4]), 64).await;
    let stations = column(s, &with(VAP, &[8]), 64).await;
    let vap_radio = column(s, &with(VAP, &[9]), 64).await;
    let rx = column(s, &with(VAP, &[10]), 64).await;
    let tx = column(s, &with(VAP, &[16]), 64).await;
    let vaps: Vec<Value> = essid
        .iter()
        .map(|(idx, name)| {
            json!({
                "ssid": name.text(),
                "channel": channel.get(idx).and_then(Val::num),
                "radio": vap_radio.get(idx).and_then(Val::text),
                "clients": stations.get(idx).and_then(Val::num),
                "rx_bytes": rx.get(idx).and_then(Val::num),
                "tx_bytes": tx.get(idx).and_then(Val::num),
            })
        })
        .collect();
    let clients: f64 = vaps.iter().filter_map(|v| v["clients"].as_f64()).sum();
    json!({
        "model": system.first().and_then(|(_, v)| v.text()),
        "version": system.get(1).and_then(|(_, v)| v.text()),
        "radios": radios,
        "wlans": vaps,
        "clients": clients,
    })
}

/// MikroTik (MIKROTIK-MIB): Temperatur, Spannung, WLAN-Clients
async fn mikrotik(s: &mut AsyncSession, version: Option<String>) -> Value {
    const HEALTH: &[u64] = &[1, 3, 6, 1, 4, 1, 14988, 1, 1, 3];
    let health = get(s, &[&with(HEALTH, &[8, 0]), &with(HEALTH, &[10, 0]), &with(HEALTH, &[11, 0])])
        .await
        .unwrap_or_default();
    let tenth = |i: usize| health.get(i).and_then(|(_, v)| v.num()).map(|x| x / 10.0);
    let clients: f64 =
        column(s, &[1, 3, 6, 1, 4, 1, 14988, 1, 1, 1, 3, 1, 6], 32).await.values().filter_map(Val::num).sum();
    json!({
        "version": version,
        "voltage_v": tenth(0),
        "temp_c": tenth(1),
        "cpu_temp_c": tenth(2),
        "clients": clients,
    })
}

/// APC-USV (PowerNet-MIB), falls das Gerät die Standard-UPS-MIB nicht kennt
async fn apc(s: &mut AsyncSession) -> Option<Value> {
    const UPS: &[u64] = &[1, 3, 6, 1, 4, 1, 318, 1, 1, 1];
    let v = get(
        s,
        &[
            &with(UPS, &[1, 1, 1, 0]),
            &with(UPS, &[2, 2, 1, 0]),
            &with(UPS, &[2, 2, 3, 0]),
            &with(UPS, &[4, 1, 1, 0]),
            &with(UPS, &[4, 2, 3, 0]),
        ],
    )
    .await
    .ok()?;
    let at = |i: usize| v.get(i).map(|(_, x)| x.clone()).unwrap_or(Val::Missing);
    Some(json!({
        "manufacturer": "APC",
        "model": at(0).text(),
        "charge_pct": at(1).num()?,
        "runtime_min": at(2).num().map(|t| (t / 6000.0).round()),
        "battery_status": "unbekannt",
        "on_battery": at(3).num() == Some(3.0),
        "load_pct": at(4).num(),
    }))
}

/// Synology: Festplatten mit Temperatur und Zustand, RAID-Volumes
async fn synology_storage(s: &mut AsyncSession) -> Map<String, Value> {
    const DISK: &[u64] = &[1, 3, 6, 1, 4, 1, 6574, 2, 1, 1];
    const RAID: &[u64] = &[1, 3, 6, 1, 4, 1, 6574, 3, 1, 1];
    let mut out = Map::new();
    let disk_id = column(s, &with(DISK, &[2]), 64).await;
    if !disk_id.is_empty() {
        let model = column(s, &with(DISK, &[3]), 64).await;
        let status = column(s, &with(DISK, &[5]), 64).await;
        let temp = column(s, &with(DISK, &[6]), 64).await;
        let disks: Vec<Value> = disk_id
            .iter()
            .map(|(idx, id)| {
                let status = match status.get(idx).and_then(Val::num).map(|v| v as i64) {
                    Some(1) => "normal",
                    Some(2) => "initialisiert",
                    Some(3) => "nicht initialisiert",
                    Some(4) => "Systempartition defekt",
                    Some(5) => "defekt",
                    _ => "unbekannt",
                };
                json!({ "id": id.text(), "model": model.get(idx).and_then(Val::text), "status": status,
                        "temp_c": temp.get(idx).and_then(Val::num) })
            })
            .collect();
        out.insert("disks".into(), Value::Array(disks));
    }
    let raid_name = column(s, &with(RAID, &[2]), 32).await;
    if !raid_name.is_empty() {
        let status = column(s, &with(RAID, &[3]), 32).await;
        let free = column(s, &with(RAID, &[4]), 32).await;
        let total = column(s, &with(RAID, &[5]), 32).await;
        let volumes: Vec<Value> = raid_name
            .iter()
            .map(|(idx, name)| {
                let total = total.get(idx).and_then(Val::num);
                let free = free.get(idx).and_then(Val::num);
                let status = match status.get(idx).and_then(Val::num).map(|v| v as i64) {
                    Some(1) => "normal",
                    Some(2) => "wird repariert",
                    Some(3) => "wird migriert",
                    Some(4) => "wird erweitert",
                    Some(11) => "beeinträchtigt",
                    Some(12) => "abgestürzt",
                    Some(21) => "Datenbereinigung",
                    _ => "unbekannt",
                };
                let used = total.zip(free).map(|(t, f)| t - f);
                let pct = total.zip(free).filter(|(t, _)| *t > 0.0).map(|(t, f)| ((t - f) / t * 1000.0).round() / 10.0);
                json!({ "name": name.text(), "status": status, "total_bytes": total, "used_bytes": used, "pct": pct })
            })
            .collect();
        out.insert("volumes".into(), Value::Array(volumes));
    }
    out
}

/// Schnell: nur CPU-Last und RAM-Belegung (für die Live-Ansicht, HOST-RESOURCES-MIB)
pub async fn system_quick(ip: std::net::Ipv4Addr, cred: &super::Credential) -> Result<(Option<f64>, Option<f64>)> {
    let mut s = open(ip, cred).await?;
    let loads: Vec<f64> = column(&mut s, HR_PROCESSOR_LOAD, 256).await.values().filter_map(Val::num).collect();
    let cpu = (!loads.is_empty()).then(|| loads.iter().sum::<f64>() / loads.len() as f64);
    let types = column(&mut s, &with(HR_STORAGE, &[2]), 128).await;
    let mut mem = None;
    if let Some((idx, _)) = types.iter().find(|(_, t)| matches!(t, Val::Oid(o) if o.ends_with(".25.2.1.2"))) {
        let mut oid_size = with(HR_STORAGE, &[5]);
        oid_size.extend_from_slice(idx);
        let mut oid_used = with(HR_STORAGE, &[6]);
        oid_used.extend_from_slice(idx);
        let values = get(&mut s, &[&oid_size[..], &oid_used[..]]).await.unwrap_or_default();
        let num = |i: usize| values.get(i).and_then(|(_, v)| v.num());
        if let (Some(size), Some(used)) = (num(0), num(1)) {
            if size > 0.0 {
                mem = Some(used / size * 100.0);
            }
        }
    }
    Ok((cpu, mem))
}
