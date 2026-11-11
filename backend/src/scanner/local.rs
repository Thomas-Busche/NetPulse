//! Eigene Netze automatisch erkennen: Schnittstellen des Hosts (bzw. der Probe) und Standard-Gateway.
//!
//! Damit läuft NetPulse in jedem Netz ohne Vorwissen über Adressbereiche oder Router: Beim ersten Start
//! ohne `SCAN_NETWORKS` (oder mit `SCAN_NETWORKS=auto`) werden die direkt angeschlossenen IPv4-Netze
//! freigegeben, in der Oberfläche lassen sie sich unter *Netzwerke → Netze erkennen* jederzeit
//! vorschlagen. Voraussetzung ist `network_mode: host` – sonst sieht der Container nur sein Docker-Netz.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::net::MIN_PREFIX;

/// Ein direkt angeschlossenes Netz
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalNetwork {
    /// Netz in CIDR-Schreibweise, z. B. „192.168.1.0/24“
    pub cidr: String,
    /// Schnittstelle, z. B. „eth0“
    pub interface: String,
    /// Eigene Adresse in diesem Netz
    pub address: String,
    /// Router dieses Netzes (aus der Routing-Tabelle), falls bekannt
    pub gateway: Option<String>,
    /// Das tatsächliche Netz war größer als /16 und wurde auf das /24 um die eigene Adresse verkleinert
    pub narrowed: bool,
}

/// Schnittstellen, die nie ein echtes LAN sind (Docker, VMs, VPN-Tunnel, Kubernetes …)
const VIRTUAL_PREFIXES: &[&str] = &[
    "lo", "docker", "br-", "veth", "virbr", "vnet", "cni", "flannel", "cali", "weave", "kube", "tun", "tap",
    "wg", "tailscale", "zt", "lxc", "lxd", "podman", "vboxnet", "vmnet", "hassio",
];

fn is_virtual(interface: &str) -> bool {
    VIRTUAL_PREFIXES.iter().any(|p| interface.starts_with(p))
}

/// Adressen, die kein scanbares LAN sind
fn is_scannable(addr: Ipv4Addr) -> bool {
    !(addr.is_loopback() || addr.is_link_local() || addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast())
        // 100.64.0.0/10 (Carrier-Grade-NAT, Tailscale) – gehört dem Provider, nicht dem eigenen Netz
        && !(addr.octets()[0] == 100 && (addr.octets()[1] & 0xc0) == 64)
}

/// Netz aus Adresse und Präfix; Netze größer als /16 werden auf das /24 um die eigene Adresse begrenzt
pub fn network_of(addr: Ipv4Addr, prefix: u8) -> (Ipv4Addr, u8, bool) {
    let (prefix, narrowed) = if prefix < MIN_PREFIX { (24, true) } else { (prefix.min(32), false) };
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
    (Ipv4Addr::from(u32::from(addr) & mask), prefix, narrowed)
}

/// IPv4-Adressen aller Schnittstellen: (Schnittstelle, Adresse, Präfix)
fn interface_addresses() -> Vec<(String, Ipv4Addr, u8)> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs liefert eine verkettete Liste, die wir nur lesen und mit freeifaddrs freigeben
    unsafe {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut cur = list;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() || i32::from((*ifa.ifa_addr).sa_family) != libc::AF_INET {
                continue;
            }
            let flags = ifa.ifa_flags;
            if flags & libc::IFF_UP as u32 == 0 || flags & libc::IFF_LOOPBACK as u32 != 0 {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
            let mask = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let prefix = u32::from_be(mask.sin_addr.s_addr).leading_ones() as u8;
            out.push((name, ip, prefix));
        }
        libc::freeifaddrs(list);
    }
    out
}

/// Gateways aus `/proc/net/route`: (Schnittstelle, Gateway); Standardrouten (0.0.0.0/0) zuerst
pub fn gateways() -> Vec<(String, Ipv4Addr)> {
    std::fs::read_to_string("/proc/net/route").map(|c| parse_routes(&c)).unwrap_or_default()
}

/// Spalten: Iface Destination Gateway Flags … Mask (Adressen hexadezimal, Byte-Reihenfolge des Hosts)
fn parse_routes(content: &str) -> Vec<(String, Ipv4Addr)> {
    const RTF_GATEWAY: u32 = 0x2;
    // Der Kernel gibt die Adresse im Speicherlayout aus – native Bytes = Netzwerk-Reihenfolge
    let hex = |s: &str| u32::from_str_radix(s, 16).ok().map(|v| Ipv4Addr::from(v.to_ne_bytes()));
    let mut routes: Vec<(bool, String, Ipv4Addr)> = content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (iface, dest, gw, flags) = (f.first()?, hex(f.get(1)?)?, hex(f.get(2)?)?, u32::from_str_radix(f.get(3)?, 16).ok()?);
            (flags & RTF_GATEWAY != 0 && !gw.is_unspecified()).then(|| (dest.is_unspecified(), iface.to_string(), gw))
        })
        .collect();
    routes.sort_by_key(|r| !r.0);
    let mut out: Vec<(String, Ipv4Addr)> = Vec::new();
    for (_, iface, gw) in routes {
        if !out.iter().any(|(i, g)| *i == iface && *g == gw) {
            out.push((iface, gw));
        }
    }
    out
}

fn in_net(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
    u32::from(ip) & mask == u32::from(net) & mask
}

/// Alle direkt angeschlossenen, scanbaren IPv4-Netze mit ihrem Gateway
pub fn detect() -> Vec<LocalNetwork> {
    build(&interface_addresses(), &gateways())
}

fn build(addrs: &[(String, Ipv4Addr, u8)], gws: &[(String, Ipv4Addr)]) -> Vec<LocalNetwork> {
    let mut out: Vec<LocalNetwork> = Vec::new();
    for (iface, ip, prefix) in addrs {
        if is_virtual(iface) || !is_scannable(*ip) || *prefix >= 31 {
            continue;
        }
        let (net, prefix_used, narrowed) = network_of(*ip, *prefix);
        let cidr = format!("{net}/{prefix_used}");
        if out.iter().any(|n| n.cidr == cidr) {
            continue;
        }
        // Gateway: eine Route über diese Schnittstelle, deren Ziel im eigenen (ursprünglichen) Netz liegt
        let gateway = gws
            .iter()
            .find(|(i, g)| i == iface && in_net(*g, *ip, *prefix))
            .map(|(_, g)| g.to_string());
        out.push(LocalNetwork { cidr, interface: iface.clone(), address: ip.to_string(), gateway, narrowed });
    }
    // Netz mit Standardroute zuerst – das ist meist das „Haupt-LAN“
    let default_if = gws.first().map(|(i, _)| i.as_str());
    out.sort_by_key(|n| Some(n.interface.as_str()) != default_if);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_are_parsed() {
        let content = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                       eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                       eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
                       eth1\t000A0A0A\t010A0A0A\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        let routes = parse_routes(content);
        // Auf Little-Endian-Hosts (x86, ARM) steht „0101A8C0“ für 192.168.1.1
        if cfg!(target_endian = "little") {
            assert_eq!(routes, vec![("eth0".into(), Ipv4Addr::new(192, 168, 1, 1)), ("eth1".into(), Ipv4Addr::new(10, 10, 10, 1))]);
        }
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn detects_lan_and_skips_virtual() {
        let addrs = vec![
            ("lo".to_string(), Ipv4Addr::new(127, 0, 0, 1), 8),
            ("docker0".to_string(), Ipv4Addr::new(172, 17, 0, 1), 16),
            ("eth0".to_string(), Ipv4Addr::new(10, 20, 30, 40), 24),
            ("tailscale0".to_string(), Ipv4Addr::new(100, 101, 102, 103), 32),
            ("eth1".to_string(), Ipv4Addr::new(172, 20, 5, 9), 8),
            ("wlan0".to_string(), Ipv4Addr::new(169, 254, 3, 3), 16),
        ];
        let gws = vec![("eth0".to_string(), Ipv4Addr::new(10, 20, 30, 1))];
        let nets = build(&addrs, &gws);
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].cidr, "10.20.30.0/24");
        assert_eq!(nets[0].gateway.as_deref(), Some("10.20.30.1"));
        assert!(!nets[0].narrowed);
        assert_eq!(nets[1].cidr, "172.20.5.0/24");
        assert!(nets[1].narrowed);
        assert_eq!(nets[1].gateway, None);
    }

    #[test]
    fn detect_does_not_panic() {
        for n in detect() {
            println!("{n:?}");
            assert!(crate::scanner::net::parse_cidr(&n.cidr).is_ok());
        }
    }

    #[test]
    fn cgnat_is_not_scannable() {
        assert!(!is_scannable(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_scannable(Ipv4Addr::new(100, 128, 0, 1)));
        assert!(is_scannable(Ipv4Addr::new(192, 168, 0, 10)));
    }
}
