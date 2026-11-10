//! Geräteerkennung: durchsucht die freigegebenen Netze nach aktiven Geräten.
//!
//! Jedes Netz wird einzeln gescannt. Aufträge kommen über einen Kanal:
//! - für alle Netze nach Zeitplan (siehe `schedule`: Intervall, täglich zu festen Uhrzeiten oder nur manuell),
//! - sofort für ein gerade hinzugefügtes Netz (hat Vorrang vor dem Rest eines laufenden Durchlaufs),
//! - „Jetzt scannen“ in der Oberfläche.
//!
//! Ablauf je Netz:
//! 1. Jede Adresse per ICMP-Ping prüfen, bei fehlender Antwort per TCP-Verbindungsversuch
//! 2. ARP-Tabelle lesen: findet auch Geräte, die Ping und TCP blockieren (nur lokales Segment)
//! 3. Für jedes aktive Gerät Ports, DNS-Name und Hersteller ermitteln, Typ erkennen, speichern

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::Ipv4Addr,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use anyhow::Result;
use chrono::Utc;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{
    oui,
    scanner::{
        add_event,
        names,
        net::{self, Pinger},
        reclassify, schedule, ScanRequest,
    },
    AppState,
};

/// Gleichzeitig geprüfte Adressen. Bewusst begrenzt: Jede Adresse im lokalen Netz erzeugt einen
/// ARP-Eintrag, und die Nachbartabelle des Kernels fasst standardmäßig nur ca. 1024 Einträge.
const SWEEP_PARALLEL: usize = 128;

pub async fn run(state: AppState, pinger: Arc<Pinger>, mut requests: UnboundedReceiver<ScanRequest>) {
    // Kurz warten, damit der Webserver zuerst startet
    tokio::time::sleep(Duration::from_secs(5)).await;
    // Ein Neustart des Containers löst nur dann einen Scan aus, wenn das so eingestellt ist
    // oder laut Zeitplan ohnehin einer fällig (bzw. verpasst) ist.
    let mut scan_now = schedule::load(&state.db, &state.config).await.on_start;

    loop {
        let first = if std::mem::take(&mut scan_now) {
            ScanRequest::All
        } else {
            match wait_for_work(&state, &mut requests).await {
                Some(request) => request,
                None => return,
            }
        };

        let mut queue: VecDeque<i64> = VecDeque::new();
        let mut full = false;
        take(first, &mut queue, &mut full);
        while let Ok(request) = requests.try_recv() {
            take(request, &mut queue, &mut full);
        }
        if full {
            if let Err(e) = schedule::set_last_full_scan(&state.db, Utc::now()).await {
                tracing::error!("Zeitpunkt des Scans konnte nicht gespeichert werden: {e}");
            }
            match enabled_network_ids(&state).await {
                Ok(ids) => {
                    tracing::info!("Vollständiger Scan von {} Netz(en) startet", ids.len());
                    for id in ids {
                        if !queue.contains(&id) {
                            queue.push_back(id);
                        }
                    }
                }
                Err(e) => tracing::error!("Netze konnten nicht geladen werden: {e:#}"),
            }
        }

        while let Some(network_id) = queue.pop_front() {
            if let Err(e) = scan_network(&state, &pinger, network_id, queue.len()).await {
                tracing::error!("Scan von Netz {network_id} fehlgeschlagen: {e:#}");
            }
            // Während des Scans eingegangene Aufträge berücksichtigen
            while let Ok(request) = requests.try_recv() {
                if let ScanRequest::Network(id) = request {
                    if !queue.contains(&id) {
                        queue.push_front(id);
                    }
                }
            }
        }
        state.scan_progress.finish();
    }
}

/// Wartet auf einen Auftrag aus der Oberfläche oder den nächsten Termin laut Zeitplan.
/// Der Zeitplan wird mindestens jede Minute neu gelesen, Änderungen greifen also sofort.
async fn wait_for_work(state: &AppState, requests: &mut UnboundedReceiver<ScanRequest>) -> Option<ScanRequest> {
    loop {
        let plan = schedule::load(&state.db, &state.config).await;
        let last = schedule::last_full_scan(&state.db).await;
        let now = Utc::now();
        let due = schedule::next_due(&plan, last, now, schedule::timezone());
        if due.is_some_and(|d| d <= now) {
            return Some(ScanRequest::All);
        }
        // Netze mit eigenem Zeitplan (gerechnet ab ihrem letzten Scan)
        if let Some(id) = own_schedule_due(state, now).await {
            return Some(ScanRequest::Network(id));
        }
        let wait = due
            .and_then(|d| (d - now).to_std().ok())
            .unwrap_or(Duration::from_secs(60))
            .min(Duration::from_secs(60));
        tokio::select! {
            request = requests.recv() => return request,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

fn take(request: ScanRequest, queue: &mut VecDeque<i64>, full: &mut bool) {
    match request {
        ScanRequest::All => *full = true,
        // Einzelaufträge (z. B. neues Netz) kommen nach vorne
        ScanRequest::Network(id) if !queue.contains(&id) => queue.push_front(id),
        ScanRequest::Network(_) => {}
    }
}

/// Netze für den vollständigen Scan: aktiv, ohne eigenen Zeitplan, in Sektoren ohne Probe
async fn enabled_network_ids(state: &AppState) -> sqlx::Result<Vec<i64>> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT n.id FROM networks n
          WHERE n.enabled AND n.schedule IS NULL
            AND NOT EXISTS (SELECT 1 FROM probes p WHERE p.site_id = n.site_id AND p.enabled)
          ORDER BY masklen(n.cidr) DESC, n.cidr",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Erstes Netz mit eigenem Zeitplan, dessen Termin erreicht ist
async fn own_schedule_due(state: &AppState, now: chrono::DateTime<Utc>) -> Option<i64> {
    let rows: Vec<(i64, serde_json::Value, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT n.id, n.schedule, n.last_scan_at FROM networks n
          WHERE n.enabled AND n.schedule IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM probes p WHERE p.site_id = n.site_id AND p.enabled)",
    )
    .fetch_all(&state.db)
    .await
    .ok()?;
    rows.into_iter().find_map(|(id, plan, last)| {
        let plan: schedule::Schedule = serde_json::from_value(plan).ok()?;
        schedule::next_due(&plan, last, now, schedule::timezone()).filter(|d| *d <= now).map(|_| id)
    })
}

async fn scan_network(state: &AppState, pinger: &Arc<Pinger>, network_id: i64, queued: usize) -> Result<()> {
    let _perf = crate::perf::Timer::new("Netz-Scan");
    // Netze in Sektoren mit Probe scannt die Probe vor Ort
    let Some((cidr, site_id)): Option<(String, i64)> = sqlx::query_as(
        "SELECT n.cidr::text, n.site_id FROM networks n
          WHERE n.id = $1 AND n.enabled AND NOT EXISTS (SELECT 1 FROM probes p WHERE p.site_id = n.site_id AND p.enabled)",
    )
    .bind(network_id)
    .fetch_optional(&state.db)
    .await?
    else {
        return Ok(()); // inzwischen gelöscht, deaktiviert oder von einer Probe übernommen
    };
    if cidr.contains(':') {
        return scan_ipv6_network(state, network_id, site_id, &cidr).await;
    }
    let (addr, prefix) = net::parse_cidr(&cidr)?;
    let targets = net::hosts(addr, prefix);
    let started = Instant::now();
    let progress = state.scan_progress.clone();
    progress.start(&cidr, targets.len(), queued);
    tracing::info!("Scan startet: {cidr} ({} Adressen)", targets.len());

    // 1. Wer antwortet? Ein Ping (600 ms), sonst TCP-Verbindungsversuch (400 ms); 2. ARP-Tabelle
    let found = sweep(pinger, &targets, Some(&progress)).await;
    progress.found.store(found.len(), Ordering::Relaxed);

    // 3. Details sammeln und speichern (16 Geräte parallel, je Gerät ~30 Port-Prüfungen)
    let count = found.len();
    let results: Vec<Result<()>> = stream::iter(found)
        .map(|(ip, rtt, mac)| {
            let state = state.clone();
            async move { store_device(&state, site_id, ip, rtt, mac).await }
        })
        .buffer_unordered(16)
        .collect()
        .await;
    for error in results.into_iter().filter_map(Result::err) {
        tracing::warn!("Gerät konnte nicht gespeichert werden: {error:#}");
    }

    let duration = started.elapsed().as_secs();
    sqlx::query(
        "UPDATE networks SET last_scan_at = now(), last_scan_found = $2, last_scan_duration_s = $3 WHERE id = $1",
    )
    .bind(network_id)
    .bind(count as i32)
    .bind(duration as i32)
    .execute(&state.db)
    .await?;
    let summary = json!({
        "time": chrono::Utc::now(),
        "network": cidr,
        "found": count,
        "scanned": targets.len(),
        "duration_s": duration,
    });
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('last_discovery', $1)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(summary)
    .execute(&state.db)
    .await?;
    tracing::info!("Scan von {cidr} abgeschlossen: {count} aktive Geräte in {duration} s");
    Ok(())
}

/// IPv6: Ein /64 lässt sich nicht durchsuchen – die Nachbartabelle des Kernels (NDP) verrät, wer zuletzt
/// gesprochen hat. Geräte, deren MAC-Adresse im Sektor schon (mit IPv4) bekannt ist, werden nicht doppelt angelegt.
async fn scan_ipv6_network(state: &AppState, network_id: i64, site_id: i64, cidr: &str) -> Result<()> {
    let started = Instant::now();
    let (net_addr, prefix) = net::parse_cidr6(cidr)?;
    let neighbors = net::read_ndp_table();
    let mut found = 0;
    for (ip, mac) in neighbors.into_iter().filter(|(ip, _)| net::in_prefix6(*ip, net_addr, prefix)) {
        let (known,): (bool,) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM devices WHERE site_id = $1 AND lower(mac) = $2)")
            .bind(site_id)
            .bind(&mac)
            .fetch_one(&state.db)
            .await?;
        found += 1;
        if known {
            continue;
        }
        let vendor = oui::lookup(&mac);
        let inserted: Option<(i64,)> = sqlx::query_as(
            "INSERT INTO devices (ip, mac, vendor, status, status_since, last_seen, site_id)
             VALUES ($1::inet, $2, $3, 'unknown', now(), now(), $4)
             ON CONFLICT (site_id, ip) DO NOTHING RETURNING id",
        )
        .bind(ip.to_string())
        .bind(&mac)
        .bind(&vendor)
        .bind(site_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
        if let Some((id,)) = inserted {
            reclassify(&state.db, id).await?;
            let vendor_info = vendor.map(|v| format!(", {v}")).unwrap_or_default();
            add_event(&state.db, id, "discovered", &format!("Neues Gerät entdeckt (IPv6): {ip}{vendor_info}")).await?;
        }
    }
    sqlx::query("UPDATE networks SET last_scan_at = now(), last_scan_found = $2, last_scan_duration_s = $3 WHERE id = $1")
        .bind(network_id)
        .bind(found)
        .bind(started.elapsed().as_secs() as i32)
        .execute(&state.db)
        .await?;
    tracing::info!("IPv6-Netz {cidr}: {found} Nachbarn in der NDP-Tabelle");
    Ok(())
}

pub(crate) async fn store_device(state: &AppState, site_id: i64, ip: Ipv4Addr, rtt: Option<Duration>, mac: Option<String>) -> Result<()> {
    let facts = gather(ip, rtt, mac).await;
    save_host(state, site_id, &facts).await
}

/// Was über eine Adresse herausgefunden wurde – vom Server selbst oder von einer Probe vor Ort
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostFacts {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub rtt_ms: Option<f32>,
    pub ports: Vec<u16>,
    pub hostname: Option<String>,
    pub reported_name: Option<String>,
    #[serde(default)]
    pub shelly: bool,
    pub model: Option<String>,
}

/// Offene Ports, Namen (DNS, mDNS/Bonjour, NetBIOS) und Shelly-Erkennung für eine Adresse
pub async fn gather(ip: Ipv4Addr, rtt: Option<Duration>, mac: Option<String>) -> HostFacts {
    let ports = net::scan_ports(ip).await;
    let shelly_probe = async {
        if ports.contains(&80) {
            crate::collect::shelly::probe(ip).await
        } else {
            None
        }
    };
    let (hostname, mdns, netbios, shelly) =
        tokio::join!(net::reverse_dns(ip), names::mdns_name(ip), names::netbios_name(ip), shelly_probe);
    HostFacts {
        ip,
        mac,
        rtt_ms: rtt.map(|d| d.as_secs_f32() * 1000.0),
        ports,
        hostname,
        reported_name: shelly.as_ref().and_then(|s| s.name.clone()).or(mdns).or(netbios),
        shelly: shelly.is_some(),
        model: shelly.and_then(|s| s.model),
    }
}

/// Gefundenes Gerät speichern (neu oder aktualisieren) und Ereignisse schreiben
pub async fn save_host(state: &AppState, site_id: i64, f: &HostFacts) -> Result<()> {
    let ip = f.ip;
    let ports: Vec<i32> = f.ports.iter().map(|p| i32::from(*p)).collect();
    let mac = f.mac.as_ref().map(|m| m.to_lowercase()).filter(|m| m.len() <= 17);
    let integration = f.shelly.then_some("shelly");
    let vendor = if f.shelly { Some("Shelly".to_string()) } else { mac.as_deref().and_then(oui::lookup) };
    let clip = |v: &Option<String>| v.as_ref().map(|t| t.chars().take(200).collect::<String>());
    let (hostname, reported_name, model) = (clip(&f.hostname), clip(&f.reported_name), clip(&f.model));

    // Einfügen oder aktualisieren. `xmax = 0` ist ein PostgreSQL-Trick, um zu erkennen,
    // ob die Zeile neu eingefügt wurde; `old` liefert die vorherige MAC-Adresse.
    let (id, inserted, old_mac): (i64, bool, Option<String>) = sqlx::query_as(
        "WITH old AS (SELECT mac FROM devices WHERE ip = $1::inet AND site_id = $10)
         INSERT INTO devices (ip, mac, hostname, vendor, open_ports, status, status_since, last_rtt_ms, last_seen, last_check,
                              reported_name, integration, model, site_id)
         VALUES ($1::inet, $2, $3, $4, $5, 'up', now(), $6, now(), now(), $7, $8, $9, $10)
         ON CONFLICT (site_id, ip) DO UPDATE SET
             mac           = COALESCE(EXCLUDED.mac, devices.mac),
             hostname      = COALESCE(EXCLUDED.hostname, devices.hostname),
             vendor        = COALESCE(EXCLUDED.vendor, devices.vendor),
             open_ports    = EXCLUDED.open_ports,
             reported_name = COALESCE(EXCLUDED.reported_name, devices.reported_name),
             integration   = COALESCE(EXCLUDED.integration, devices.integration),
             model         = COALESCE(devices.model, EXCLUDED.model),
             last_seen     = now()
         RETURNING id, (xmax = 0), (SELECT mac FROM old)",
    )
    .bind(ip.to_string())
    .bind(&mac)
    .bind(&hostname)
    .bind(&vendor)
    .bind(&ports)
    .bind(f.rtt_ms)
    .bind(&reported_name)
    .bind(integration)
    .bind(&model)
    .bind(site_id)
    .fetch_one(&state.db)
    .await?;

    reclassify(&state.db, id).await?;

    let label = reported_name.or(hostname).unwrap_or_else(|| ip.to_string());
    if inserted {
        let vendor_info = vendor.map(|v| format!(", {v}")).unwrap_or_default();
        add_event(&state.db, id, "discovered", &format!("Neues Gerät entdeckt: {label} ({ip}{vendor_info})")).await?;
    } else if let (Some(old), Some(new)) = (&old_mac, &mac) {
        if old != new {
            let message = format!(
                "MAC-Adresse von {ip} hat sich geändert: {old} → {new} (neues Gerät oder möglicher ARP-Spoofing-Versuch)"
            );
            add_event(&state.db, id, "mac_changed", &message).await?;
        }
    }
    Ok(())
}

/// Wer antwortet in diesem Netz? Ping, sonst TCP; dazu alles, was danach in der ARP-Tabelle steht.
/// Liefert Adresse, Antwortzeit und MAC-Adresse (wird auch von Probes benutzt).
pub async fn sweep(pinger: &Arc<Pinger>, targets: &[Ipv4Addr], progress: Option<&Arc<super::ScanProgress>>) -> Vec<(Ipv4Addr, Option<Duration>, Option<String>)> {
    let alive: Vec<(Ipv4Addr, Option<Duration>)> = stream::iter(targets.iter().copied())
        .map(|ip| {
            let pinger = pinger.clone();
            let progress = progress.cloned();
            async move {
                let rtt = match pinger.ping(ip, Duration::from_millis(600), 1).await {
                    Some(rtt) => Some(rtt),
                    None => net::tcp_alive(ip, net::LIVENESS_PORTS, Duration::from_millis(400)).await,
                };
                if let Some(p) = &progress {
                    p.done.fetch_add(1, Ordering::Relaxed);
                    if rtt.is_some() {
                        p.found.fetch_add(1, Ordering::Relaxed);
                    }
                }
                (ip, rtt)
            }
        })
        .buffer_unordered(SWEEP_PARALLEL)
        .filter_map(|(ip, rtt)| async move { rtt.map(|rtt| (ip, Some(rtt))) })
        .collect()
        .await;
    let mut found: HashMap<Ipv4Addr, Option<Duration>> = alive.into_iter().collect();
    // Der Kernel hat beim Pingen jede antwortende MAC-Adresse gelernt
    let arp = net::read_arp_table();
    let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    for ip in arp.keys().filter(|ip| wanted.contains(ip)) {
        found.entry(*ip).or_insert(None);
    }
    found.into_iter().map(|(ip, rtt)| (ip, rtt, arp.get(&ip).cloned())).collect()
}
