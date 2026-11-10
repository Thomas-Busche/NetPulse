//! Empfang von Protokollmeldungen: Syslog (UDP, RFC 3164 und 5424) und SNMP-Traps (v1/v2c).
//!
//! Geräte wie OPNsense, UniFi, Synology oder Switches schicken ihre Meldungen an NetPulse
//! (Standard: Syslog UDP 5514, Traps UDP 1162 – die Standardports 514/162 bräuchten Root-Rechte).
//! Die Meldungen werden gesammelt, einmal pro Sekunde gespeichert, dem passenden Gerät
//! zugeordnet (über die Absender-IP) und live an die Oberfläche geschickt.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use tokio::{net::UdpSocket, sync::mpsc};

use crate::AppState;

#[derive(Serialize, Clone, Debug)]
pub struct LogMsg {
    pub time: DateTime<Utc>,
    pub source: IpAddr,
    pub facility: i16,
    /// 0 = Notfall … 7 = Debug (wie bei Syslog)
    pub severity: i16,
    pub host: Option<String>,
    pub app: Option<String>,
    pub message: String,
}

static DROPPED: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Empfangs-Diagnose: läuft der Empfang, was kam an, wer wurde abgewiesen?
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Stats {
    /// Listener → None = läuft, Some(Fehler)
    listeners: HashMap<&'static str, Option<String>>,
    received: HashMap<&'static str, (u64, Option<DateTime<Utc>>)>,
    /// Abgewiesene Absender (nicht in den erlaubten Netzen): IP → (Anzahl, zuletzt, Art)
    rejected: HashMap<IpAddr, (u64, DateTime<Utc>, &'static str)>,
}

static STATS: Mutex<Option<Stats>> = Mutex::new(None);

fn with_stats(f: impl FnOnce(&mut Stats)) {
    if let Ok(mut guard) = STATS.lock() {
        f(guard.get_or_insert_with(Stats::default));
    }
}

fn note_listener(kind: &'static str, error: Option<String>) {
    with_stats(|s| {
        s.listeners.insert(kind, error);
    });
}

fn note_received(kind: &'static str) {
    with_stats(|s| {
        let e = s.received.entry(kind).or_default();
        e.0 += 1;
        e.1 = Some(Utc::now());
    });
}

fn note_rejected(ip: IpAddr, kind: &'static str) {
    with_stats(|s| {
        // Begrenzen, damit viele verschiedene Absender den Speicher nicht füllen
        if s.rejected.len() >= 50 && !s.rejected.contains_key(&ip) {
            return;
        }
        let e = s.rejected.entry(ip).or_insert((0, Utc::now(), kind));
        e.0 += 1;
        e.1 = Utc::now();
        e.2 = kind;
    });
}

/// Zustand des Empfangs für die Oberfläche
pub fn status() -> serde_json::Value {
    let guard = STATS.lock().ok();
    let s = guard.as_ref().and_then(|g| g.as_ref());
    let listener = |k: &str| match s.and_then(|s| s.listeners.get(k)) {
        Some(None) => json!({ "running": true }),
        Some(Some(e)) => json!({ "running": false, "error": e }),
        None => json!({ "running": false }),
    };
    let received = |k: &str| {
        let (n, last) = s.and_then(|s| s.received.get(k)).copied().unwrap_or_default();
        json!({ "count": n, "last": last })
    };
    let mut rejected: Vec<_> = s
        .map(|s| s.rejected.iter().map(|(ip, (n, last, kind))| json!({ "ip": ip, "count": n, "last": last, "kind": kind })).collect())
        .unwrap_or_default();
    rejected.sort_by(|a, b| b["last"].as_str().cmp(&a["last"].as_str()));
    json!({
        "syslog": listener("syslog"),
        "trap": listener("trap"),
        "received_syslog": received("syslog"),
        "received_trap": received("trap"),
        "rejected": rejected,
        "allow_fixed": std::env::var("SYSLOG_ALLOW").ok().filter(|s| !s.trim().is_empty()),
    })
}

/// Testmeldung an den eigenen Empfänger schicken (prüft, ob der Empfang arbeitet)
pub async fn send_test(port: u16) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let msg = "<14>1 - netpulse netpulse-test - - - Testmeldung: Der Protokoll-Empfang von NetPulse funktioniert.";
    socket.send_to(msg.as_bytes(), ("127.0.0.1", port)).await?;
    Ok(())
}

/// Von wem werden Meldungen angenommen? `SYSLOG_ALLOW`: Liste von Netzen (CIDR) oder `any`;
/// Standard: nur aus den freigegebenen Scan-Netzen (Liste wird jede Minute neu geladen)
#[derive(Clone, Default)]
struct Allow {
    any: bool,
    nets: std::sync::Arc<std::sync::RwLock<Vec<(u32, u32)>>>,
}

impl Allow {
    fn permits(&self, ip: IpAddr) -> bool {
        if self.any || ip.is_loopback() {
            return true;
        }
        let IpAddr::V4(v4) = ip else { return false };
        let n = u32::from(v4);
        self.nets.read().unwrap().iter().any(|(net, mask)| n & mask == *net)
    }
}

fn parse_net(cidr: &str) -> Option<(u32, u32)> {
    let (addr, prefix) = crate::scanner::net::parse_cidr(cidr.trim()).ok()?;
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
    Some((u32::from(addr) & mask, mask))
}

async fn allow_list(state: AppState) -> Allow {
    let fixed = std::env::var("SYSLOG_ALLOW").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let allow = Allow { any: fixed.as_deref() == Some("any"), ..Default::default() };
    if allow.any {
        return allow;
    }
    if let Some(list) = fixed {
        *allow.nets.write().unwrap() = list.split(',').filter_map(parse_net).collect();
        return allow;
    }
    let nets = allow.nets.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(rows) = sqlx::query_as::<_, (String,)>("SELECT cidr::text FROM networks WHERE enabled").fetch_all(&state.db).await {
                *nets.write().unwrap() = rows.iter().filter_map(|(c,)| parse_net(c)).collect();
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
    allow
}

pub fn start(state: &AppState) {
    let (tx, rx) = mpsc::channel::<LogMsg>(2_000);
    tokio::spawn(writer(state.clone(), rx));
    let state = state.clone();
    tokio::spawn(async move {
        let allow = allow_list(state.clone()).await;
        if state.config.syslog_port > 0 {
            tokio::spawn(syslog_listener(state.config.syslog_port, tx.clone(), allow.clone()));
        }
        if state.config.trap_port > 0 {
            tokio::spawn(trap_listener(state.clone(), state.config.trap_port, tx, allow));
        }
    });
}

fn queue(tx: &mpsc::Sender<LogMsg>, msg: LogMsg) {
    if tx.try_send(msg).is_err() {
        // Überlastschutz: bei einer Flut lieber Meldungen verwerfen als den Speicher zu füllen
        if DROPPED.fetch_add(1, Ordering::Relaxed).is_multiple_of(1000) {
            tracing::warn!("Protokoll-Empfang überlastet – Meldungen werden verworfen");
        }
    }
}

// ---------------------------------------------------------------------------
// Syslog
// ---------------------------------------------------------------------------

async fn syslog_listener(port: u16, tx: mpsc::Sender<LogMsg>, allow: Allow) {
    let socket = match UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Syslog-Empfang auf UDP {port} nicht möglich: {e} (Port belegt? SYSLOG_PORT ändern oder 0 = aus)");
            note_listener("syslog", Some(e.to_string()));
            return;
        }
    };
    tracing::info!("Syslog-Empfang auf UDP {port}");
    note_listener("syslog", None);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else { continue };
        if !allow.permits(from.ip()) {
            note_rejected(from.ip(), "syslog");
            continue;
        }
        note_received("syslog");
        let text = String::from_utf8_lossy(&buf[..n]);
        let (facility, severity, host, app, message) = parse_syslog(&text);
        queue(&tx, LogMsg { time: Utc::now(), source: from.ip(), facility, severity, host, app, message });
    }
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// (Facility, Schwere, Host, Programm, Text) aus einer Syslog-Zeile
pub fn parse_syslog(raw: &str) -> (i16, i16, Option<String>, Option<String>, String) {
    let raw = raw.trim_end_matches(['\n', '\r', '\0']).trim_start_matches('\u{feff}');
    let (pri, mut rest) = match raw.strip_prefix('<').and_then(|r| r.split_once('>')) {
        Some((p, r)) if p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()) => (p.parse::<i16>().unwrap_or(13), r),
        _ => (13, raw), // ohne Kopf: user.notice
    };
    let (facility, severity) = (pri / 8, pri % 8);
    let dash = |s: &str| (s != "-" && !s.is_empty()).then(|| s.to_string());

    // RFC 5424: „1 ZEIT HOST APP PROCID MSGID [SD] Text“
    if let Some(r) = rest.strip_prefix("1 ") {
        let mut parts = r.splitn(6, ' ');
        let (_time, host, app, _pid, _msgid) = (parts.next(), parts.next(), parts.next(), parts.next(), parts.next());
        let mut msg = parts.next().unwrap_or_default();
        if let Some(m) = msg.strip_prefix("- ") {
            msg = m;
        } else if msg == "-" {
            msg = "";
        } else {
            // strukturierte Daten [..][..] überspringen
            while msg.starts_with('[') {
                let mut depth_quote = false;
                let mut end = None;
                for (i, c) in msg.char_indices() {
                    match c {
                        '"' => depth_quote = !depth_quote,
                        ']' if !depth_quote => {
                            end = Some(i);
                            break;
                        }
                        _ => {}
                    }
                }
                match end {
                    Some(i) => msg = msg[i + 1..].trim_start(),
                    None => break,
                }
            }
        }
        return clip(facility, severity, host.and_then(dash), app.and_then(dash), msg.trim_start_matches('\u{feff}').trim().to_string());
    }

    // RFC 3164: „Mmm dd hh:mm:ss HOST TAG[PID]: Text“ (Zeitstempel und Host optional)
    if rest.len() > 16 && MONTHS.iter().any(|m| rest.starts_with(m)) && rest.as_bytes().get(15) == Some(&b' ') {
        rest = &rest[16..];
    } else if rest.len() > 20 && rest.as_bytes()[..4].iter().all(u8::is_ascii_digit) && rest.as_bytes().get(4) == Some(&b'-') {
        // ISO-Zeitstempel mancher Geräte
        rest = rest.split_once(' ').map_or("", |(_, r)| r);
    }
    let mut host = None;
    let mut app = None;
    let mut msg = rest;
    let first = rest.split(' ').next().unwrap_or_default();
    let tag_of = |token: &str| -> Option<String> {
        let t = token.trim_end_matches(':');
        let t = t.split('[').next().unwrap_or(t);
        (!t.is_empty() && t.len() <= 48).then(|| t.to_string())
    };
    if first.ends_with(':') || first.contains('[') {
        app = tag_of(first);
        msg = rest[first.len()..].trim_start();
    } else if !first.is_empty() {
        let after = rest[first.len()..].trim_start();
        let second = after.split(' ').next().unwrap_or_default();
        if second.ends_with(':') || (second.contains('[') && second.ends_with("]:")) {
            host = Some(first.to_string());
            app = tag_of(second);
            msg = after[second.len()..].trim_start();
        }
    }
    clip(facility, severity, host, app, msg.trim().to_string())
}

/// Längen begrenzen (Schutz vor riesigen Paketen)
fn clip(facility: i16, severity: i16, host: Option<String>, app: Option<String>, msg: String) -> (i16, i16, Option<String>, Option<String>, String) {
    let cut = |s: String, n: usize| s.chars().take(n).collect::<String>();
    (facility, severity, host.map(|h| cut(h, 64)), app.map(|a| cut(a, 64)), cut(msg, 2000))
}

// ---------------------------------------------------------------------------
// SNMP-Traps
// ---------------------------------------------------------------------------

async fn trap_listener(state: AppState, port: u16, tx: mpsc::Sender<LogMsg>, allow: Allow) {
    let socket = match UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("SNMP-Trap-Empfang auf UDP {port} nicht möglich: {e} (TRAP_PORT ändern oder 0 = aus)");
            note_listener("trap", Some(e.to_string()));
            return;
        }
    };
    tracing::info!("SNMP-Trap-Empfang auf UDP {port}");
    note_listener("trap", None);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else { continue };
        if !allow.permits(from.ip()) {
            note_rejected(from.ip(), "trap");
            continue;
        }
        note_received("trap");
        match parse_trap(&buf[..n]) {
            Some(trap) => {
                let communities = &state.config.trap_communities;
                if !communities.is_empty() && !communities.contains(&trap.community) {
                    tracing::debug!("SNMP-Trap von {from} mit unbekannter Community verworfen");
                    continue;
                }
                let msg = describe_trap(&state, &trap, from).await;
                queue(&tx, msg);
            }
            None => tracing::debug!("Unlesbares SNMP-Paket von {from} (nur v1/v2c-Traps werden unterstützt)"),
        }
    }
}

#[derive(Debug)]
pub struct Trap {
    pub community: String,
    pub trap_oid: Vec<u64>,
    pub agent: Option<Ipv4Addr>,
    pub varbinds: Vec<(Vec<u64>, String)>,
}

struct Ber<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Ber<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.buf.get(self.pos)?;
        let first = *self.buf.get(self.pos + 1)? as usize;
        let mut p = self.pos + 2;
        let len = if first < 0x80 {
            first
        } else {
            let n = first & 0x7f;
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for _ in 0..n {
                len = (len << 8) | *self.buf.get(p)? as usize;
                p += 1;
            }
            len
        };
        let value = self.buf.get(p..p + len)?;
        self.pos = p + len;
        Some((tag, value))
    }
}

fn int(v: &[u8]) -> i64 {
    let mut n: i64 = if v.first().is_some_and(|b| b & 0x80 != 0) { -1 } else { 0 };
    for b in v.iter().take(8) {
        n = (n << 8) | i64::from(*b);
    }
    n
}

fn uint(v: &[u8]) -> u64 {
    v.iter().take(8).fold(0u64, |n, b| (n << 8) | u64::from(*b))
}

/// OID aus BER; höchstens 128 Teile (SNMP-Grenze) – längere gelten als ungültig
fn oid(v: &[u8]) -> Vec<u64> {
    if v.len() > 256 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    for (i, b) in v.iter().enumerate() {
        acc = (acc << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            if out.is_empty() && i < v.len() {
                let (a, b) = if acc < 40 { (0, acc) } else if acc < 80 { (1, acc - 40) } else { (2, acc - 80) };
                out.push(a);
                out.push(b);
            } else {
                out.push(acc);
            }
            acc = 0;
        }
    }
    out
}

fn dotted(o: &[u64]) -> String {
    o.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

fn value(tag: u8, v: &[u8]) -> String {
    match tag {
        0x02 => int(v).to_string(),
        0x04 => {
            let printable = v.iter().all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'\n' || *b == b'\t');
            if printable || std::str::from_utf8(v).is_ok_and(|s| !s.chars().any(char::is_control)) {
                String::from_utf8_lossy(v).trim().to_string()
            } else {
                v.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
            }
        }
        0x06 => dotted(&oid(v)),
        0x40 if v.len() == 4 => Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string(),
        0x41 | 0x42 | 0x46 => uint(v).to_string(),
        0x43 => format!("{} s", uint(v) / 100),
        0x05 => "–".into(),
        _ => format!("({} Bytes)", v.len()),
    }
}

const SNMP_TRAP_OID: &[u64] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];
const SYS_UPTIME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];

/// (OID, Typ, Rohwert)
type VarBind<'a> = (Vec<u64>, u8, &'a [u8]);

fn varbinds(data: &[u8]) -> Option<Vec<VarBind<'_>>> {
    let mut list = Ber::new(data);
    let mut out = Vec::new();
    while !list.done() && out.len() < 64 {
        let (_, vb) = list.tlv()?;
        let mut vb = Ber::new(vb);
        let (_, name) = vb.tlv()?;
        let (tag, val) = vb.tlv()?;
        out.push((oid(name), tag, val));
    }
    Some(out)
}

/// SNMP v1- und v2c-Traps (auch Informs) lesen
pub fn parse_trap(buf: &[u8]) -> Option<Trap> {
    let (outer_tag, outer) = Ber::new(buf).tlv()?;
    if outer_tag != 0x30 {
        return None;
    }
    let mut msg = Ber::new(outer);
    let (_, version) = msg.tlv()?;
    let version = int(version);
    if version > 1 {
        return None; // v3 (verschlüsselt) wird nicht unterstützt
    }
    let (_, community) = msg.tlv()?;
    let (pdu_tag, pdu) = msg.tlv()?;
    let mut pdu = Ber::new(pdu);
    match pdu_tag {
        0xA4 => {
            let (_, enterprise) = pdu.tlv()?;
            let (_, agent) = pdu.tlv()?;
            let (_, generic) = pdu.tlv()?;
            let (_, specific) = pdu.tlv()?;
            let _timestamp = pdu.tlv()?;
            let (_, vbs) = pdu.tlv()?;
            let generic = int(generic);
            let trap_oid = if (0..6).contains(&generic) {
                vec![1, 3, 6, 1, 6, 3, 1, 1, 5, generic as u64 + 1]
            } else {
                let mut o = oid(enterprise);
                o.extend([0, int(specific).max(0) as u64]);
                o
            };
            Some(Trap {
                community: String::from_utf8_lossy(community).into_owned(),
                trap_oid,
                agent: (agent.len() == 4).then(|| Ipv4Addr::new(agent[0], agent[1], agent[2], agent[3])),
                varbinds: varbinds(vbs)?.into_iter().map(|(o, t, v)| (o, value(t, v))).collect(),
            })
        }
        0xA7 | 0xA6 => {
            let _request_id = pdu.tlv()?;
            let _error = pdu.tlv()?;
            let _index = pdu.tlv()?;
            let (_, vbs) = pdu.tlv()?;
            let list = varbinds(vbs)?;
            let trap_oid = list.iter().find(|(o, t, _)| o == SNMP_TRAP_OID && *t == 0x06).map(|(_, _, v)| oid(v))?;
            Some(Trap {
                community: String::from_utf8_lossy(community).into_owned(),
                trap_oid,
                agent: None,
                varbinds: list
                    .into_iter()
                    .filter(|(o, _, _)| o != SNMP_TRAP_OID && o != SYS_UPTIME)
                    .map(|(o, t, v)| (o, value(t, v)))
                    .collect(),
            })
        }
        _ => None,
    }
}

async fn describe_trap(state: &AppState, trap: &Trap, from: SocketAddr) -> LogMsg {
    let mut oids = vec![trap.trap_oid.clone()];
    oids.extend(trap.varbinds.iter().map(|(o, _)| o.clone()));
    let names = crate::mib::names_for(&state.db, &oids).await.unwrap_or_default();
    let name_of = |o: &Vec<u64>| names.get(o).cloned().unwrap_or_else(|| dotted(o));
    let trap_name = name_of(&trap.trap_oid);
    let details: Vec<String> = trap.varbinds.iter().take(20).map(|(o, v)| format!("{}={v}", name_of(o))).collect();
    let mut message = if details.is_empty() { trap_name.clone() } else { format!("{trap_name}: {}", details.join(", ")) };
    // v1-Traps nennen eine eigene Agent-Adresse – fälschbar, deshalb nur als Hinweis, nicht als Absender
    if let Some(agent) = trap.agent.filter(|a| !a.is_unspecified() && IpAddr::V4(*a) != from.ip()) {
        message.push_str(&format!(" (meldet Agent-Adresse {agent})"));
    }
    message.truncate(message.char_indices().nth(2000).map_or(message.len(), |(i, _)| i));
    let lower = trap_name.to_lowercase();
    let severity = if lower.contains("linkdown") || lower.contains("authenticationfailure") || lower.contains("fail") {
        4
    } else if lower.contains("linkup") {
        6
    } else {
        5
    };
    LogMsg {
        time: Utc::now(),
        source: from.ip(),
        facility: -1,
        severity,
        host: None,
        app: Some("snmp-trap".into()),
        message,
    }
}

// ---------------------------------------------------------------------------
// Speichern
// ---------------------------------------------------------------------------

async fn writer(state: AppState, mut rx: mpsc::Receiver<LogMsg>) {
    let mut batch: Vec<LogMsg> = Vec::with_capacity(1000);
    loop {
        // Warten bis zur ersten Meldung, dann bis zu 1 s sammeln
        let Some(first) = rx.recv().await else { return };
        batch.push(first);
        let deadline = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(deadline);
        while batch.len() < 1000 {
            tokio::select! {
                m = rx.recv() => match m { Some(m) => batch.push(m), None => break },
                _ = &mut deadline => break,
            }
        }
        let _perf = crate::perf::Timer::new("Syslog/Traps speichern");
        let result = sqlx::query(
            "INSERT INTO syslog_messages (time, device_id, source, facility, severity, host, app, message)
             SELECT u.time, (SELECT d.id FROM devices d WHERE d.ip = u.src::inet
                       ORDER BY EXISTS (SELECT 1 FROM probes p WHERE p.site_id = d.site_id AND p.enabled), d.id LIMIT 1), u.src::inet, u.fac, u.sev, u.host, u.app, u.msg
               FROM UNNEST($1::timestamptz[], $2::text[], $3::int2[], $4::int2[], $5::text[], $6::text[], $7::text[])
                    AS u(time, src, fac, sev, host, app, msg)",
        )
        .bind(batch.iter().map(|m| m.time).collect::<Vec<_>>())
        .bind(batch.iter().map(|m| m.source.to_string()).collect::<Vec<_>>())
        .bind(batch.iter().map(|m| m.facility).collect::<Vec<_>>())
        .bind(batch.iter().map(|m| m.severity).collect::<Vec<_>>())
        .bind(batch.iter().map(|m| m.host.clone()).collect::<Vec<_>>())
        .bind(batch.iter().map(|m| m.app.clone()).collect::<Vec<_>>())
        .bind(batch.iter().map(|m| m.message.chars().take(4000).collect::<String>()).collect::<Vec<_>>())
        .execute(&state.db)
        .await;
        if let Err(e) = result {
            tracing::warn!("Protokollmeldungen konnten nicht gespeichert werden: {e}");
        }
        // Live an offene Browser (höchstens 50 pro Sekunde)
        let recent: Vec<&LogMsg> = batch.iter().rev().take(50).collect();
        state.hub.publish(&json!({ "type": "syslog", "items": recent, "count": batch.len() }));
        batch.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3164() {
        let (fac, sev, host, app, msg) = parse_syslog("<14>Sep 24 11:00:00 U6-Pro hostapd[1234]: ath1: STA 11:22:33 associated");
        assert_eq!((fac, sev), (1, 6));
        assert_eq!(host.as_deref(), Some("U6-Pro"));
        assert_eq!(app.as_deref(), Some("hostapd"));
        assert_eq!(msg, "ath1: STA 11:22:33 associated");
        let (_, _, host, app, msg) = parse_syslog("<30>dnsmasq: query A example.de");
        assert_eq!((host, app.as_deref(), msg.as_str()), (None, Some("dnsmasq"), "query A example.de"));
    }

    #[test]
    fn rfc5424() {
        let (fac, sev, host, app, msg) = parse_syslog(
            "<13>1 2026-09-24T11:00:00+02:00 OPNsense.localdomain filterlog 12345 - [meta sequenceId=\"1\"] 5,,,1000,vtnet0,match,block,in",
        );
        assert_eq!((fac, sev), (1, 5));
        assert_eq!(host.as_deref(), Some("OPNsense.localdomain"));
        assert_eq!(app.as_deref(), Some("filterlog"));
        assert_eq!(msg, "5,,,1000,vtnet0,match,block,in");
        let (_, _, _, _, msg) = parse_syslog("<34>1 2026-09-24T11:00:00Z host sshd - - - Failed password for root");
        assert_eq!(msg, "Failed password for root");
    }

    /// v2c-Trap „linkDown“ mit ifIndex = 3, von Hand kodiert
    #[test]
    fn trap_v2c() {
        let varbind = |oid: &[u8], val: &[u8]| {
            let mut inner = vec![0x06, oid.len() as u8];
            inner.extend_from_slice(oid);
            inner.extend_from_slice(val);
            let mut out = vec![0x30, inner.len() as u8];
            out.extend(inner);
            out
        };
        let mut vbs = Vec::new();
        vbs.extend(varbind(&[0x2b, 6, 1, 2, 1, 1, 3, 0], &[0x43, 1, 100]));
        vbs.extend(varbind(&[0x2b, 6, 1, 6, 3, 1, 1, 4, 1, 0], &[0x06, 9, 0x2b, 6, 1, 6, 3, 1, 1, 5, 3]));
        vbs.extend(varbind(&[0x2b, 6, 1, 2, 1, 2, 2, 1, 1, 3], &[0x02, 1, 3]));
        let mut pdu = vec![0x02, 1, 7, 0x02, 1, 0, 0x02, 1, 0, 0x30, vbs.len() as u8];
        pdu.extend(vbs);
        let mut msg = vec![0x02, 1, 1, 0x04, 6];
        msg.extend_from_slice(b"public");
        msg.push(0xA7);
        msg.push(pdu.len() as u8);
        msg.extend(pdu);
        let mut packet = vec![0x30, msg.len() as u8];
        packet.extend(msg);
        let trap = parse_trap(&packet).unwrap();
        assert_eq!(trap.community, "public");
        assert_eq!(trap.trap_oid, vec![1, 3, 6, 1, 6, 3, 1, 1, 5, 3]);
        assert_eq!(trap.varbinds, vec![(vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 3], "3".to_string())]);
        assert!(parse_trap(b"garbage").is_none());
    }
}
