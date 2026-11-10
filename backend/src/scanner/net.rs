//! Netzwerk-Hilfsfunktionen: Netze zerlegen, ICMP-Ping, TCP-Prüfung, ARP-Tabelle, Reverse-DNS.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicU16, Ordering},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use futures::future::join_all;
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use tokio::net::TcpStream;

/// Ports, die bei der Erkennung geprüft werden. Sie verraten viel über den Gerätetyp
/// (z. B. 9100 = Drucker, 8006 = Proxmox, 5000/5001 = Synology, 3389 = Windows-RDP).
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 548, 554, 631, 993, 1883, 3306, 3389, 5000, 5001,
    5432, 5900, 5985, 5986, 8006, 8080, 8443, 9100, 11443,
];

/// Ports für die Erreichbarkeitsprüfung, wenn ein Gerät nicht auf Ping antwortet
/// (Windows blockiert Ping z. B. standardmäßig).
pub const LIVENESS_PORTS: &[u16] = &[443, 80, 22, 445, 3389];

/// Größtes erlaubtes Netz pro Eintrag: /16 = 65.534 Adressen (ein Scan dauert dann einige Minuten)
pub const MIN_PREFIX: u8 = 16;

/// Zerlegt „192.168.1.0/24“ in Netzadresse und Präfix. Host-Bits werden auf 0 gesetzt,
/// aus „192.168.1.17/24“ wird also „192.168.1.0/24“.
pub fn parse_cidr(input: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = input
        .trim()
        .split_once('/')
        .context("Netz bitte im Format 192.168.1.0/24 angeben")?;
    let addr: Ipv4Addr = addr.parse().context("Ungültige IPv4-Adresse")?;
    let prefix: u8 = prefix.parse().context("Ungültiges Präfix")?;
    if prefix > 32 {
        bail!("Präfix muss zwischen /{MIN_PREFIX} und /32 liegen");
    }
    if prefix < MIN_PREFIX {
        bail!("Netz zu groß: höchstens /{MIN_PREFIX} (65.534 Adressen) pro Eintrag – bitte aufteilen");
    }
    let mask = u32::MAX << (32 - prefix);
    Ok((Ipv4Addr::from(u32::from(addr) & mask), prefix))
}

/// IPv6-Netz („2001:db8:1::/64“) → Netzadresse und Präfix. Größere Netze als /32 sind nicht sinnvoll.
pub fn parse_cidr6(input: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, prefix) = input.trim().split_once('/').context("Netz bitte im Format 2001:db8::/64 angeben")?;
    let addr: Ipv6Addr = addr.parse().context("Ungültige IPv6-Adresse")?;
    let prefix: u8 = prefix.parse().context("Ungültiges Präfix")?;
    if !(32..=128).contains(&prefix) {
        bail!("IPv6-Präfix muss zwischen /32 und /128 liegen");
    }
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix)) };
    Ok((Ipv6Addr::from(u128::from(addr) & mask), prefix))
}

pub fn in_prefix6(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix)) };
    u128::from(ip) & mask == u128::from(net) & mask
}

/// Alle nutzbaren Host-Adressen eines Netzes (ohne Netz- und Broadcast-Adresse).
pub fn hosts(network: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let start = u32::from(network);
    let size = 1u32 << (32 - prefix);
    let range = if prefix >= 31 { 0..size } else { 1..size - 1 };
    range.map(|i| Ipv4Addr::from(start + i)).collect()
}

// ---------------------------------------------------------------------------
// ICMP-Ping
// ---------------------------------------------------------------------------

pub struct Pinger {
    /// `None`, wenn ICMP nicht erlaubt ist (fehlende Capability NET_RAW)
    client: Option<Client>,
    /// ICMPv6 (`None`, wenn der Host kein IPv6 hat)
    client6: Option<Client>,
    next_id: AtomicU16,
}

impl Pinger {
    pub fn new() -> Self {
        let client = match Client::new(&Config::default()) {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::warn!(
                    "ICMP-Ping nicht verfügbar ({e}) – es werden nur TCP-Prüfungen genutzt. \
                     Der Container braucht die Capability NET_RAW."
                );
                None
            }
        };
        let client6 = Client::new(&Config::builder().kind(ICMP::V6).build()).ok();
        Self { client, client6, next_id: AtomicU16::new(1) }
    }

    /// Sendet bis zu `tries` Pings. Liefert die Antwortzeit oder `None`.
    pub async fn ping(&self, ip: Ipv4Addr, timeout: Duration, tries: u16) -> Option<Duration> {
        self.ping_ip(IpAddr::V4(ip), timeout, tries).await
    }

    /// Wie `ping`, auch für IPv6
    pub async fn ping_ip(&self, ip: IpAddr, timeout: Duration, tries: u16) -> Option<Duration> {
        let client = if ip.is_ipv6() { self.client6.as_ref()? } else { self.client.as_ref()? };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut pinger = client.pinger(ip, PingIdentifier(id)).await;
        pinger.timeout(timeout);
        for seq in 0..tries {
            if let Ok((_, rtt)) = pinger.ping(PingSequence(seq), &[0u8; 32]).await {
                return Some(rtt);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

pub enum TcpResult {
    /// Port offen
    Open(Duration),
    /// Port geschlossen – das Gerät hat aber geantwortet, ist also erreichbar
    Refused(Duration),
    /// Keine Antwort (Gerät aus oder Firewall verwirft)
    NoAnswer,
}

pub async fn tcp_probe(ip: impl Into<IpAddr>, port: u16, timeout: Duration) -> TcpResult {
    let ip: IpAddr = ip.into();
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::from((ip, port)))).await {
        Ok(Ok(_)) => TcpResult::Open(started.elapsed()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            TcpResult::Refused(started.elapsed())
        }
        _ => TcpResult::NoAnswer,
    }
}

/// Prüft mehrere Ports gleichzeitig; liefert die schnellste Antwortzeit, falls das Gerät reagiert.
pub async fn tcp_alive(ip: impl Into<IpAddr>, ports: &[u16], timeout: Duration) -> Option<Duration> {
    let ip: IpAddr = ip.into();
    let probes = ports.iter().map(|&port| tcp_probe(ip, port, timeout));
    join_all(probes)
        .await
        .into_iter()
        .filter_map(|result| match result {
            TcpResult::Open(rtt) | TcpResult::Refused(rtt) => Some(rtt),
            TcpResult::NoAnswer => None,
        })
        .min()
}

/// Liefert alle offenen Ports aus `COMMON_PORTS`.
pub async fn scan_ports(ip: Ipv4Addr) -> Vec<u16> {
    let probes = COMMON_PORTS.iter().map(|&port| async move {
        matches!(tcp_probe(ip, port, Duration::from_millis(700)).await, TcpResult::Open(_)).then_some(port)
    });
    join_all(probes).await.into_iter().flatten().collect()
}

// ---------------------------------------------------------------------------
// ARP und DNS
// ---------------------------------------------------------------------------

/// Liest die ARP-Tabelle des Linux-Kernels (IP → MAC). Funktioniert nur mit
/// `network_mode: host` und nur für Geräte im selben Netzsegment.
pub fn read_arp_table() -> HashMap<Ipv4Addr, String> {
    let Ok(content) = std::fs::read_to_string("/proc/net/arp") else {
        return HashMap::new();
    };
    // Format: IP address  HW type  Flags  HW address  Mask  Device
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let ip: Ipv4Addr = cols.first()?.parse().ok()?;
            let flags = u32::from_str_radix(cols.get(2)?.trim_start_matches("0x"), 16).ok()?;
            let mac = cols.get(3)?.to_lowercase();
            // Flag 0x2 = Eintrag vollständig aufgelöst
            (flags & 0x2 != 0 && mac != "00:00:00:00:00:00").then_some((ip, mac))
        })
        .collect()
}

/// IPv6-Nachbartabelle (NDP) des Kernels über Netlink: globale Adressen → MAC.
/// Funktioniert wie die ARP-Tabelle nur mit `network_mode: host`; ohne IPv6 ist sie leer.
pub fn read_ndp_table() -> HashMap<Ipv6Addr, String> {
    netlink::neighbors(libc::AF_INET6 as u8)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(addr, mac)| {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(addr.as_slice()).ok()?);
            let link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
            (!link_local && !ip.is_multicast() && !ip.is_loopback() && mac.len() == 6)
                .then(|| (ip, mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")))
        })
        .filter(|(_, mac)| mac != "00:00:00:00:00:00")
        .collect()
}

/// Minimaler Netlink-Client: RTM_GETNEIGH-Dump (Adresse, Link-Layer-Adresse) für erreichbare/veraltete Nachbarn
mod netlink {
    use std::io;

    const NLMSG_HDR: usize = 16;
    const NDMSG: usize = 12;
    const RTM_NEWNEIGH: u16 = 28;
    const RTM_GETNEIGH: u16 = 30;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    const NLMSG_DONE: u16 = 3;
    const NLMSG_ERROR: u16 = 2;
    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;
    /// NUD_INCOMPLETE | NUD_FAILED | NUD_NOARP
    const NUD_SKIP: u16 = 0x01 | 0x20 | 0x40;

    fn align(n: usize) -> usize {
        (n + 3) & !3
    }

    pub fn neighbors(family: u8) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        // SAFETY: einfache Socket-Aufrufe mit korrekt bemessenen Puffern; der Deskriptor wird immer geschlossen
        unsafe {
            let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let result = (|| {
                let mut req = [0u8; NLMSG_HDR + NDMSG];
                req[0..4].copy_from_slice(&((NLMSG_HDR + NDMSG) as u32).to_ne_bytes());
                req[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
                req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
                req[8..12].copy_from_slice(&1u32.to_ne_bytes());
                req[NLMSG_HDR] = family;
                if libc::send(fd, req.as_ptr().cast(), req.len(), 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut out = Vec::new();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0);
                    if n <= 0 {
                        return if n == 0 { Ok(out) } else { Err(io::Error::last_os_error()) };
                    }
                    if parse(&buf[..n as usize], &mut out) {
                        return Ok(out);
                    }
                }
            })();
            libc::close(fd);
            result
        }
    }

    /// Wertet eine Antwort aus; `true` = Ende des Dumps
    fn parse(data: &[u8], out: &mut Vec<(Vec<u8>, Vec<u8>)>) -> bool {
        let mut off = 0;
        while off + NLMSG_HDR <= data.len() {
            let len = u32::from_ne_bytes(data[off..off + 4].try_into().unwrap_or_default()) as usize;
            let kind = u16::from_ne_bytes(data[off + 4..off + 6].try_into().unwrap_or_default());
            if len < NLMSG_HDR || off + len > data.len() {
                return true;
            }
            match kind {
                NLMSG_DONE | NLMSG_ERROR => return true,
                RTM_NEWNEIGH if len >= NLMSG_HDR + NDMSG => {
                    let msg = &data[off + NLMSG_HDR..off + len];
                    let state = u16::from_ne_bytes([msg[8], msg[9]]);
                    let (mut dst, mut ll) = (None, None);
                    let mut a = NDMSG;
                    while a + 4 <= msg.len() {
                        let alen = u16::from_ne_bytes([msg[a], msg[a + 1]]) as usize;
                        let akind = u16::from_ne_bytes([msg[a + 2], msg[a + 3]]);
                        if alen < 4 || a + alen > msg.len() {
                            break;
                        }
                        let value = msg[a + 4..a + alen].to_vec();
                        match akind {
                            NDA_DST => dst = Some(value),
                            NDA_LLADDR => ll = Some(value),
                            _ => {}
                        }
                        a += align(alen);
                    }
                    if let (Some(d), Some(l)) = (dst, ll) {
                        if state & NUD_SKIP == 0 {
                            out.push((d, l));
                        }
                    }
                }
                _ => {}
            }
            off += align(len);
        }
        false
    }
}

/// Rückwärtsauflösung IP → Name (z. B. „nas.fritz.box“), höchstens 3 Sekunden.
pub async fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    let name = tokio::time::timeout(Duration::from_secs(3), lookup).await.ok()?.ok()??;
    let name = name.trim_end_matches('.').to_string();
    (name != ip.to_string()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_wird_normalisiert() {
        let (addr, prefix) = parse_cidr("192.168.1.17/24").unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn zu_grosse_netze_werden_abgelehnt() {
        assert!(parse_cidr("10.0.0.0/8").is_err());
        assert!(parse_cidr("10.0.0.0/15").is_err());
        assert_eq!(parse_cidr("10.10.0.0/16").unwrap().1, 16);
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("kein-netz").is_err());
    }

    #[test]
    fn ipv6_netze() {
        let (net, prefix) = parse_cidr6("2001:db8:1:2::17/64").unwrap();
        assert_eq!(net, "2001:db8:1:2::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(prefix, 64);
        assert!(in_prefix6("2001:db8:1:2::abcd".parse().unwrap(), net, prefix));
        assert!(!in_prefix6("2001:db8:1:3::1".parse().unwrap(), net, prefix));
        assert!(parse_cidr6("2001:db8::/16").is_err());
    }

    #[test]
    fn ndp_tabelle_lesbar() {
        // Darf nie abstürzen – auch ohne IPv6 oder Netlink-Rechte
        let _ = read_ndp_table();
    }

    #[test]
    fn hosts_ohne_netz_und_broadcast() {
        let hosts = hosts(Ipv4Addr::new(192, 168, 1, 0), 24);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hosts.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
        assert_eq!(super::hosts(Ipv4Addr::new(10, 0, 0, 5), 32), vec![Ipv4Addr::new(10, 0, 0, 5)]);
    }
}
