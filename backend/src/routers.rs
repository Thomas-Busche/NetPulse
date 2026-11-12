//! Router-Katalog: Welcher Router ist das, und wie fragt NetPulse ihn am besten ab?
//!
//! NetPulse überwacht jeden Router per Ping und erkennt ihn als Gateway – egal von welchem Hersteller.
//! Für mehr Details (verbundene Geräte, Schnittstellen, Datenraten, CPU) braucht es einen Zugang.
//! Dieser Katalog ordnet ein Gerät anhand von Hersteller (MAC), Hostname, Modell und Betriebssystem
//! einer Router-Familie zu und nennt die passenden Zugangsarten (in der Reihenfolge der Empfehlung)
//! samt kurzer Anleitung. Unbekannte Router landen bei „Anderer Router“ (SNMP oder SSH).

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Family {
    pub key: &'static str,
    pub label: &'static str,
    /// Zugangsarten (Schlüssel wie bei den Zugangsdaten), beste zuerst; leer = keine Schnittstelle
    pub methods: &'static [&'static str],
    /// Kurze Anleitung: Wo schaltet man den Zugang am Router ein?
    pub guide: &'static str,
    #[serde(skip)]
    needles: &'static [&'static str],
}

const fn f(
    key: &'static str,
    label: &'static str,
    needles: &'static [&'static str],
    methods: &'static [&'static str],
    guide: &'static str,
) -> Family {
    Family { key, label, methods, guide, needles }
}

const NO_API: &str = "Dieser Router bietet keine offene Schnittstelle für Überwachungsprogramme. NetPulse überwacht ihn trotzdem \
    (Erreichbarkeit, Antwortzeit, Ausfälle) und findet alle Geräte im Netz per Scan – Zugangsdaten sind hier nicht nötig.";

/// Reihenfolge = Priorität: Betriebssysteme und genaue Namen vor Herstellern (OpenWrt auf einem TP-Link ist OpenWrt)
pub const CATALOG: &[Family] = &[
    // --- Betriebssysteme / Firmware, die auf fremder Hardware laufen ---
    f("opnsense", "OPNsense", &["opnsense"], &["opnsense", "snmp_v3", "ssh_key"],
      "System → Zugang → Benutzer: Benutzer mit Leserechten anlegen („Diagnostics: ARP Table“, „Reporting: Traffic“, \
       „Services: DHCP … Leases“) und unter „API-Schlüssel“ einen Schlüssel erzeugen. Schlüssel ins Feld „API-Schlüssel“, Secret ins Feld „API-Secret“."),
    f("pfsense", "pfSense", &["pfsense", "netgate"], &["snmp_v3", "snmp_v2c", "ssh_key"],
      "Services → SNMP: Dienst einschalten, eine eigene Community (nicht „public“) vergeben und an die LAN-Schnittstelle binden. \
       Alternativ System → Advanced → Secure Shell mit Schlüssel."),
    f("openwrt", "OpenWrt / GL.iNet / Turris", &["openwrt", "lede", "gl technologies", "gl-inet", "glinet", "turris", "cz.nic"],
      &["ssh_key", "ssh_password", "snmp_v2c"],
      "SSH ist bei OpenWrt bereits aktiv (System → Administration → SSH-Zugang). Am besten einen Schlüssel hinterlegen. \
       Liefert verbundene Geräte, WLAN-Signal, DHCP-Namen und Schnittstellen."),
    f("ddwrt", "DD-WRT / FreshTomato", &["dd-wrt", "ddwrt", "tomato"], &["snmp_v2c", "ssh_password"],
      "Dienste → SNMP einschalten (eigene Community) bzw. Dienste → Secure Shell aktivieren."),
    f("edgeos", "Ubiquiti EdgeRouter / VyOS", &["edgerouter", "edgeos", "ubnt", "vyos", "er-x", "er-4", "er-12"],
      &["snmp_v2c", "ssh_key", "ssh_password"],
      "Config Tree → service → snmp: Community setzen, oder SSH (bei EdgeOS standardmäßig an) mit Schlüssel."),
    f("srm", "Synology Router (SRM)", &["srm", "synology router", "rt2600", "rt6600", "mr2200", "wrx560"], &["snmp_v3", "ssh_password"],
      "Netzwerkcenter → SNMP aktivieren (am besten v3) bzw. Steuerung → Dienste → SSH."),
    f("ipfire", "IPFire / Endian / Securepoint", &["ipfire", "endian", "securepoint"], &["snmp_v3", "snmp_v2c", "ssh_key"],
      "In der Weboberfläche SNMP einschalten (bei IPFire per Add-on „net-snmp“) oder SSH mit Schlüssel freigeben."),
    // --- Router mit eigener Schnittstelle in NetPulse ---
    f("fritzbox", "AVM FRITZ!Box", &["fritz", "avm audiovisuelles", "avm gmbh"], &["fritzbox"],
      "Heimnetz → Netzwerk → Netzwerkeinstellungen → „Zugriff für Anwendungen zulassen“ einschalten und unter System → \
       FRITZ!Box-Benutzer einen eigenen Benutzer anlegen. Liefert alle Geräte mit Namen, LAN/WLAN, Signal und Geschwindigkeit."),
    f("mikrotik", "MikroTik RouterOS", &["mikrotik", "routerboard", "routeros"], &["mikrotik", "snmp_v3", "ssh_key"],
      "RouterOS 7: Benutzer mit Gruppe „read“ anlegen und unter IP → Services „www-ssl“ (443) oder „www“ (80, nur LAN) einschalten."),
    f("unifi", "Ubiquiti UniFi Gateway (UDM, UCG, UXG, USG)", &["ubiquiti", "udm", "ucg", "uxg", "usg", "unifi", "dream machine", "cloud gateway"],
      &["unifi", "ssh_key"],
      "UniFi Network → Einstellungen → Control Plane → Integrations → „Create API Key“. Benutzername leer lassen, Schlüssel ins Passwortfeld. \
       Liefert alle Clients, Access Points, Switch-Ports und Datenraten."),
    // --- Provider-Router ohne Schnittstelle ---
    f("speedport", "Telekom Speedport", &["speedport", "askey", "sercomm"], &[], NO_API),
    f("vodafone", "Vodafone Station / EasyBox", &["easybox", "easy.box", "vodafone", "compal broadband", "hitron", "arris"], &[], NO_API),
    f("o2", "o2 HomeBox", &["o2.box", "homebox"], &[], NO_API),
    f("isp", "Provider-Router (Sagemcom, Technicolor, Arcadyan, ZTE …)", &["sagemcom", "technicolor", "arcadyan", "zte corporation", "vantiva", "nokia shanghai", "genexis"],
      &[], NO_API),
    f("mesh", "Mesh-System (eero, Google/Nest Wifi, Deco, Orbi, Starlink)", &["eero", "google", "nest wifi", "deco", "orbi", "space exploration", "starlink"],
      &[], NO_API),
    // --- Hersteller (Heim und Büro) ---
    f("asus", "ASUS (auch Asuswrt-Merlin)", &["asustek", "asus", "rt-ax", "rt-ac", "gt-ax", "zenwifi"], &["ssh_password", "ssh_key", "snmp_v2c"],
      "Administration → System → „SSH aktivieren“ (nur LAN) einschalten. Mit Asuswrt-Merlin geht auch SNMP. Liefert ARP-Tabelle und DHCP-Namen."),
    f("tplink", "TP-Link (Archer, Omada, ER)", &["tp-link", "tplink", "omada", "archer"], &["snmp_v2c", "snmp_v3"],
      "Omada-Gateways und ER-Router: Einstellungen → SNMP einschalten. Archer-Heimrouter haben keine Schnittstelle – dort genügt die Grundüberwachung."),
    f("netgear", "NETGEAR", &["netgear", "routerlogin", "nighthawk"], &["snmp_v2c"],
      "Business-Geräte (Orbi Pro, ProSAFE): SNMP in der Weboberfläche einschalten. Nighthawk/Orbi für zu Hause haben keine Schnittstelle."),
    f("linksys", "Linksys / Belkin", &["linksys", "belkin", "velop"], &[], NO_API),
    f("draytek", "DrayTek Vigor", &["draytek", "vigor"], &["snmp_v3", "snmp_v2c", "ssh_password"],
      "System Maintenance → SNMP: Agent einschalten (am besten v3) und den Zugriff auf das LAN beschränken."),
    f("lancom", "LANCOM", &["lancom"], &["snmp_v3", "snmp_v2c", "ssh_password"],
      "LANconfig → Management → SNMP: SNMPv3-Benutzer mit Leserechten anlegen."),
    f("zyxel", "Zyxel (USG, ATP, VMG, Nebula)", &["zyxel"], &["snmp_v2c", "snmp_v3", "ssh_password"],
      "System → SNMP einschalten und eine eigene Community vergeben; bei Nebula im Cloud-Portal unter Site-wide → SNMP."),
    f("teltonika", "Teltonika (RUT, RUTX, TRB)", &["teltonika", "rutx", "rut9", "rut2"], &["snmp_v2c", "snmp_v3", "ssh_password"],
      "Services → SNMP einschalten (Paket ggf. unter System → Package Manager nachinstallieren)."),
    f("peplink", "Peplink / Pepwave", &["peplink", "pepwave"], &["snmp_v2c", "snmp_v3"], "System → SNMP: SNMP v2c/v3 einschalten."),
    f("huawei", "Huawei", &["huawei"], &["snmp_v2c", "snmp_v3", "ssh_password"],
      "Business-Router (AR, NetEngine): „snmp-agent“ mit eigener Community konfigurieren. Heimrouter haben meist keine Schnittstelle."),
    // --- Business-Netzwerk und Firewalls ---
    f("cisco", "Cisco / Meraki", &["cisco", "meraki", "ios-xe", "ios xe"], &["snmp_v3", "snmp_v2c", "ssh_password"],
      "IOS: „snmp-server group/user … v3 priv“ mit Leserechten; Meraki: Organisation → Einstellungen → SNMP."),
    f("juniper", "Juniper (SRX, MX, EX)", &["juniper", "junos"], &["snmp_v3", "snmp_v2c", "ssh_key"],
      "„set snmp v3 usm local-engine user …“ oder eine Community mit „authorization read-only“."),
    f("aruba", "HPE Aruba", &["aruba", "hewlett packard enterprise"], &["snmp_v3", "snmp_v2c", "ssh_password"],
      "System → SNMP: SNMPv3-Benutzer mit Leserechten anlegen."),
    f("fortinet", "Fortinet FortiGate", &["fortinet", "fortigate", "fortios"], &["snmp_v3", "snmp_v2c"],
      "System → SNMP: Agent einschalten, v3-Benutzer anlegen und SNMP auf der LAN-Schnittstelle erlauben (Network → Interfaces → Administrative Access)."),
    f("sophos", "Sophos Firewall / UTM", &["sophos", "cyberoam"], &["snmp_v3", "snmp_v2c"],
      "Administration → SNMP: Agent einschalten, v3-Benutzer anlegen und SNMP in der Zone LAN erlauben."),
    f("sonicwall", "SonicWall", &["sonicwall"], &["snmp_v3", "snmp_v2c"], "Device → Settings → SNMP einschalten und auf der LAN-Schnittstelle zulassen."),
    f("watchguard", "WatchGuard Firebox", &["watchguard", "firebox"], &["snmp_v3", "snmp_v2c"], "System → SNMP: v3 einschalten und eine Richtlinie für SNMP aus dem LAN anlegen."),
    f("paloalto", "Palo Alto Networks", &["palo alto", "pan-os"], &["snmp_v3", "snmp_v2c"],
      "Device → Setup → Operations → SNMP Setup; im Management-Profil der Schnittstelle SNMP erlauben."),
    f("checkpoint", "Check Point", &["check point", "checkpoint", "gaia"], &["snmp_v3", "snmp_v2c"], "Gaia-Portal → System Management → SNMP einschalten."),
    f("linux", "Linux-Router (Debian, Ubuntu, Raspberry Pi …)", &["linux", "debian", "ubuntu", "raspberry", "raspbian", "alpine", "fedora"],
      &["ssh_key", "ssh_password", "snmp_v2c"],
      "SSH mit Schlüssel und einem Benutzer ohne Root-Rechte. Liefert ARP-Tabelle, DHCP-Leases (dnsmasq), Schnittstellen und Last."),
];

/// Für alles, was der Katalog nicht kennt
pub const GENERIC: Family = f("generic", "Anderer Router", &[], &["snmp_v3", "snmp_v2c", "ssh_key", "ssh_password"],
    "Fast jeder Business-Router spricht SNMP, viele Router mit Linux-Unterbau auch SSH. In der Weboberfläche des Routers nach \
     „SNMP“ suchen, einschalten und eine eigene Community (nicht „public“) bzw. einen v3-Benutzer mit Leserechten anlegen. \
     Hat der Router beides nicht, überwacht NetPulse ihn trotzdem (Erreichbarkeit, Antwortzeit, Ausfälle).");

/// Was über das Gerät bekannt ist (alles optional)
#[derive(Default)]
pub struct Clues<'a> {
    pub vendor: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub model: Option<&'a str>,
    pub os: Option<&'a str>,
    pub open_ports: &'a [i32],
}

/// Passende Router-Familie; ohne Treffer [`GENERIC`]
pub fn identify(c: &Clues) -> &'static Family {
    let text = [c.os, c.model, c.hostname, c.vendor].into_iter().flatten().collect::<Vec<_>>().join(" | ").to_lowercase();
    if let Some(fam) = CATALOG.iter().find(|fam| fam.needles.iter().any(|n| text.contains(n))) {
        return fam;
    }
    // Typische Ports, wenn sonst nichts verrät, was es ist
    let has = |p: i32| c.open_ports.contains(&p);
    let find = |k: &str| CATALOG.iter().find(|fam| fam.key == k);
    let guess = if has(49000) {
        find("fritzbox")
    } else if has(8728) || has(8291) {
        find("mikrotik")
    } else {
        None
    };
    guess.unwrap_or(&GENERIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(vendor: Option<&str>, hostname: Option<&str>, os: Option<&str>) -> &'static str {
        identify(&Clues { vendor, hostname, os, ..Default::default() }).key
    }

    #[test]
    fn erkennt_router_familien() {
        assert_eq!(id(Some("AVM Audiovisuelles Marketing und Computersysteme GmbH"), None, None), "fritzbox");
        assert_eq!(id(None, Some("fritz.box"), None), "fritzbox");
        assert_eq!(id(Some("TP-LINK TECHNOLOGIES CO.,LTD."), Some("openwrt.lan"), None), "openwrt");
        assert_eq!(id(Some("TP-LINK TECHNOLOGIES CO.,LTD."), None, None), "tplink");
        assert_eq!(id(None, Some("speedport.ip"), None), "speedport");
        assert_eq!(id(Some("Sagemcom Broadband SAS"), None, None), "isp");
        assert_eq!(id(Some("Ubiquiti Inc"), None, None), "unifi");
        assert_eq!(id(Some("Ubiquiti Inc"), Some("edgerouter-x"), None), "edgeos");
        assert_eq!(id(None, None, Some("FreeBSD 14 OPNsense")), "opnsense");
        assert_eq!(id(Some("Fortinet, Inc."), None, None), "fortinet");
        assert_eq!(id(Some("Shenzhen Unbekannt"), None, None), "generic");
    }

    #[test]
    fn ports_als_letzter_hinweis() {
        assert_eq!(identify(&Clues { open_ports: &[53, 80, 49000], ..Default::default() }).key, "fritzbox");
        assert_eq!(identify(&Clues { open_ports: &[8291], ..Default::default() }).key, "mikrotik");
    }

    #[test]
    fn methoden_sind_gueltige_zugangsarten() {
        let kinds = ["snmp_v2c", "snmp_v3", "ssh_password", "ssh_key", "http", "unifi", "fritzbox", "opnsense", "mikrotik"];
        for fam in CATALOG.iter().chain(std::iter::once(&GENERIC)) {
            assert!(fam.methods.iter().all(|m| kinds.contains(m)), "{}", fam.key);
            assert!(!fam.guide.is_empty());
        }
        let mut keys: Vec<_> = CATALOG.iter().map(|f| f.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), CATALOG.len(), "Schlüssel doppelt");
    }
}
