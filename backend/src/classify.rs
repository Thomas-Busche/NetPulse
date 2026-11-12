//! Gerätetyp erkennen.
//!
//! Die Regeln sind nach Verlässlichkeit sortiert: Was ein Gerät selbst per SSH/SNMP über sich sagt,
//! zählt mehr als Hersteller, Hostname oder offene Ports. Ein von Hand gesetzter Typ wird nie
//! überschrieben (siehe `device_type_manual`).

use serde_json::Value;

/// Alle bekannten Gerätetypen (Schlüssel werden auch von der Weboberfläche verwendet)
pub const TYPES: &[&str] = &[
    "router", "switch", "access_point", "firewall", "network", "server", "hypervisor", "nas", "printer",
    "camera", "windows", "linux", "raspberry_pi", "apple", "computer", "phone", "tablet", "tv", "speaker",
    "console", "ups", "iot", "unknown",
];

pub struct Hints<'a> {
    pub ip: &'a str,
    pub open_ports: &'a [i32],
    pub hostname: Option<&'a str>,
    pub vendor: Option<&'a str>,
    pub random_mac: bool,
    pub inventory: Option<&'a Value>,
    /// Modellbezeichnung (z. B. aus dem UniFi-Controller)
    pub model: Option<&'a str>,
    /// Die Adresse ist Gateway eines Netzes (eingetragen oder aus der Routing-Tabelle erkannt)
    pub gateway: bool,
}

pub fn classify(h: &Hints) -> &'static str {
    let kind = from_inventory(h)
        .or_else(|| from_model(h))
        .or_else(|| from_hostname(h))
        .or_else(|| from_vendor_and_ports(h))
        .unwrap_or("unknown");
    // Das Gateway eines Netzes ist – egal von welchem Hersteller – dessen Router. Nur eine erkannte
    // Firewall (OPNsense, pfSense, Fortinet …) bleibt die genauere Angabe.
    if h.gateway && !matches!(kind, "router" | "firewall") {
        return "router";
    }
    kind
}

fn has(h: &Hints, port: i32) -> bool {
    h.open_ports.contains(&port)
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

/// 1. Selbstauskunft des Geräts über SSH oder SNMP
fn from_inventory(h: &Hints) -> Option<&'static str> {
    let inv = h.inventory?;

    // UniFi-Controller: ist er selbst ein UniFi-Gerät (Dream Machine, Cloud Gateway …), dessen Typ – sonst Server
    if let Some(unifi) = inv.get("unifi") {
        let own = unifi["devices"].as_array().into_iter().flatten().find(|d| d["ip"].as_str() == Some(h.ip));
        if let Some(kind) = own.and_then(|d| d["model"].as_str()).and_then(crate::collect::unifi::device_type) {
            return Some(kind);
        }
        if inv.get("ssh").is_none() && inv.get("snmp").is_none() {
            return Some("server");
        }
    }

    if let Some(ssh) = inv.get("ssh") {
        let os = ssh["os"].as_str().unwrap_or_default().to_lowercase();
        if os.contains("opnsense") || os.contains("pfsense") {
            return Some("firewall");
        }
        if ssh["platform"] == "windows" {
            return Some(if os.contains("server") { "server" } else { "windows" });
        }
        if !ssh["proxmox"].is_null() {
            return Some("hypervisor");
        }
        if !ssh["synology"].is_null() || os.contains("synology") || os.contains("qnap") {
            return Some("nas");
        }
        let board = ssh["board"].as_str().unwrap_or_default().to_lowercase();
        if board.contains("raspberry") || os.contains("raspbian") {
            return Some("raspberry_pi");
        }
        if ssh["platform"] == "linux" {
            return Some("linux");
        }
    }

    if let Some(snmp) = inv.get("snmp") {
        if snmp["printer"].as_array().is_some_and(|p| !p.is_empty()) {
            return Some("printer");
        }
        if snmp["ups"].is_object() {
            return Some("ups");
        }
        if snmp["synology"].is_object() {
            return Some("nas");
        }
        let descr = snmp["sys_descr"].as_str().unwrap_or_default().to_lowercase();
        let rules: &[(&[&str], &str)] = &[
            (&["pfsense", "opnsense", "fortigate", "sophos", "sonicwall", "watchguard"], "firewall"),
            (&["fritz!box", "routeros", "edgeos", "openwrt", "router", "vyos", "draytek"], "router"),
            (&["access point", "uap", "unifi ap", "aironet"], "access_point"),
            (&["switch", "procurve", "catalyst", "usw", "gs108", "gs308", "sg350", "cbs3"], "switch"),
            (&["synology", "diskstation", "qnap", "truenas", "freenas"], "nas"),
            (&["vmware esxi", "proxmox"], "hypervisor"),
            (&["windows"], "windows"),
            (&["printer", "laserjet", "officejet"], "printer"),
            (&["linux"], "linux"),
        ];
        for (needles, kind) in rules {
            if contains_any(&descr, needles) {
                return Some(kind);
            }
        }
    }
    None
}

/// UniFi-Modellkürzel (U6-Pro, USW-Lite-8-PoE …), nur bei Ubiquiti-Geräten
fn from_model(h: &Hints) -> Option<&'static str> {
    let vendor = h.vendor?.to_lowercase();
    if !vendor.contains("ubiquiti") {
        return None;
    }
    crate::collect::unifi::device_type(h.model?)
}

/// 2. Sprechende Hostnamen („DESKTOP-4F2K“, „iPhone-von-Anna“, „diskstation“ …)
fn from_hostname(h: &Hints) -> Option<&'static str> {
    let name = h.hostname?.to_lowercase();
    let first = name.split('.').next().unwrap_or(&name);
    // Typische Namen, unter denen Provider-Router sich im eigenen Netz melden
    // (FRITZ!Box, Speedport, EasyBox, o2 HomeBox, NETGEAR, ASUS, OpenWrt …)
    if (name.ends_with("fritz.box") && first == "fritz")
        || matches!(first, "speedport" | "easy" | "easybox" | "o2" | "homebox" | "routerlogin" | "openwrt" | "dsldevice" | "gateway")
            && name.contains('.')
    {
        return Some("router");
    }
    let rules: &[(&[&str], &str)] = &[
        (&["iphone", "android", "galaxy", "pixel-", "redmi", "oneplus", "huawei-p"], "phone"),
        (&["ipad", "tablet", "tab-"], "tablet"),
        (&["macbook", "imac", "mac-mini", "macmini", "mac-pro"], "apple"),
        (&["desktop-", "laptop-", "win10", "win11", "windows"], "windows"),
        (&["printer", "drucker", "brn", "epson", "hp-printer", "npi"], "printer"),
        (&["diskstation", "rackstation", "synology", "qnap", "truenas", "-nas", "nas-"], "nas"),
        (&["raspberrypi", "raspberry", "rpi"], "raspberry_pi"),
        (&["proxmox", "pve", "esxi"], "hypervisor"),
        (&["opnsense", "pfsense"], "firewall"),
        (&["fritz", "router", "gateway", "edgerouter", "unifi-gateway", "speedport", "easybox", "openwrt"], "router"),
        (&["switch", "usw-"], "switch"),
        (&["uap-", "u6-", "access-point", "-ap-"], "access_point"),
        (&["kamera", "camera", "-cam", "cam-", "ipcam"], "camera"),
        (&["chromecast", "firetv", "fire-tv", "appletv", "apple-tv", "-tv", "tv-"], "tv"),
        (&["echo", "alexa", "sonos", "homepod", "google-home", "nest-"], "speaker"),
        (&["playstation", "ps4", "ps5", "xbox", "nintendo", "switch-oled"], "console"),
        (&["shelly", "tasmota", "esp-", "esp32", "esp8266", "tuya", "hue-bridge", "homeassistant"], "iot"),
    ];
    if first == "nas" {
        return Some("nas");
    }
    rules.iter().find(|(needles, _)| contains_any(first, needles)).map(|(_, kind)| *kind)
}

/// 3. Hersteller (MAC-Adresse) und typische Dienste
fn from_vendor_and_ports(h: &Hints) -> Option<&'static str> {
    let vendor = h.vendor.unwrap_or_default().to_lowercase();
    let v = |needles: &[&str]| contains_any(&vendor, needles);

    if has(h, 9100) || (v(&["brother", "epson", "kyocera", "lexmark", "xerox", "ricoh", "konica", "oki data"])) {
        return Some("printer");
    }
    if has(h, 8006) {
        return Some("hypervisor");
    }
    if v(&["hikvision", "dahua", "axis comm", "reolink", "hanwha", "uniview", "foscam", "amcrest", "mobotix"]) {
        return Some("camera");
    }
    if v(&["synology", "qnap", "asustor", "buffalo", "terramaster"]) || (has(h, 5000) && has(h, 5001)) {
        return Some("nas");
    }
    if v(&["american power conversion", "apc by schneider", "eaton"]) {
        return Some("ups");
    }
    if v(&["avm audiovisuelles", "avm gmbh"]) || vendor == "avm" {
        return Some("router");
    }
    // Typische Hersteller von Provider-Routern (Kabel, DSL, Glasfaser) und kleinen Routern
    if v(&["mikrotik", "routerboard", "draytek", "lancom", "sagemcom", "technicolor", "arcadyan", "sercomm", "compal broadband", "askey", "zyxel communications", "gl technologies", "teltonika", "peplink"]) {
        return Some("router");
    }
    if v(&["ubiquiti"]) {
        return Some("access_point");
    }
    if v(&["fortinet", "sophos", "sonicwall", "watchguard", "palo alto", "netgate"]) {
        return Some("firewall");
    }
    if v(&["cisco", "juniper", "aruba", "zyxel", "d-link", "netgear", "tp-link", "extreme networks", "hewlett packard enterprise"]) {
        return Some("network");
    }
    if v(&["raspberry pi"]) {
        return Some("raspberry_pi");
    }
    if v(&["espressif", "tuya", "shelly", "allterco", "itead", "signify", "philips lighting", "ikea", "tado", "nuki", "bosch thermotechnik", "eq-3"]) {
        return Some("iot");
    }
    if v(&["sonos", "bose", "amazon technologies", "harman"]) {
        return Some("speaker");
    }
    if v(&["nintendo", "sony interactive"]) {
        return Some("console");
    }
    if v(&["lg electronics", "hisense", "tcl", "vestel", "tp vision", "roku"]) {
        return Some("tv");
    }
    if v(&["apple"]) {
        return Some(if has(h, 22) || has(h, 548) || has(h, 5900) { "apple" } else { "phone" });
    }
    if v(&["google"]) {
        return Some("speaker");
    }
    if has(h, 5985) || has(h, 5986) || has(h, 3389) || (has(h, 139) && has(h, 445) && !has(h, 22)) {
        return Some("windows");
    }
    let last_octet = h.ip.rsplit('.').next().unwrap_or_default();
    if has(h, 53) && (has(h, 80) || has(h, 443) || last_octet == "1" || last_octet == "254") {
        return Some("router");
    }
    if h.random_mac && h.open_ports.is_empty() {
        return Some("phone");
    }
    if has(h, 22) {
        return Some("linux");
    }
    if v(&["intel", "realtek", "dell", "lenovo", "asustek", "hewlett", "hp inc", "giga-byte", "micro-star", "fujitsu", "acer", "microsoft"]) {
        return Some("computer");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hints<'a>(ip: &'a str, ports: &'a [i32], host: Option<&'a str>, vendor: Option<&'a str>) -> Hints<'a> {
        Hints { ip, open_ports: ports, hostname: host, vendor, random_mac: false, inventory: None, model: None, gateway: false }
    }

    #[test]
    fn typische_geraete() {
        assert_eq!(classify(&hints("10.0.0.1", &[53, 80, 443], Some("fritz.box"), Some("AVM Audiovisuelles Marketing und Computersysteme"))), "router");
        assert_eq!(classify(&hints("10.0.0.20", &[80, 443, 9100], None, Some("HP Inc"))), "printer");
        assert_eq!(classify(&hints("10.0.0.5", &[22, 80, 443, 5000, 5001], None, Some("Synology"))), "nas");
        assert_eq!(classify(&hints("10.0.0.9", &[22], None, Some("Raspberry Pi Trading"))), "raspberry_pi");
        assert_eq!(classify(&hints("10.0.0.30", &[135, 139, 445, 3389], Some("DESKTOP-4F2K.fritz.box"), Some("Intel"))), "windows");
        assert_eq!(classify(&hints("10.0.0.40", &[8006, 22], None, None)), "hypervisor");
        assert_eq!(classify(&hints("10.0.0.50", &[], Some("iPhone-von-Anna"), None)), "phone");
        assert_eq!(classify(&hints("10.0.0.60", &[], None, None)), "unknown");
    }

    #[test]
    fn gateway_ist_router_egal_welcher_hersteller() {
        // Unbekannter Provider-Router ohne sprechenden Namen
        let h = Hints { gateway: true, ..hints("172.16.4.1", &[53, 80], None, Some("Shenzhen Something")) };
        assert_eq!(classify(&h), "router");
        // UniFi-Gateway würde nach Hersteller sonst als Access Point gelten
        let h = Hints { gateway: true, ..hints("10.1.0.1", &[22, 443], None, Some("Ubiquiti Inc")) };
        assert_eq!(classify(&h), "router");
        // Eine erkannte Firewall bleibt Firewall
        let h = Hints { gateway: true, ..hints("10.1.0.1", &[443], Some("opnsense.lan"), None) };
        assert_eq!(classify(&h), "firewall");
    }

    #[test]
    fn provider_router_namen() {
        assert_eq!(classify(&hints("192.168.2.1", &[80], Some("speedport.ip"), None)), "router");
        assert_eq!(classify(&hints("192.168.2.1", &[80], Some("easy.box"), None)), "router");
        assert_eq!(classify(&hints("192.168.1.1", &[80], Some("o2.box"), None)), "router");
        assert_eq!(classify(&hints("192.168.0.1", &[80], None, Some("Sagemcom Broadband SAS"))), "router");
        // „o2“ ohne Domain ist nur ein Gerätename
        assert_ne!(classify(&hints("192.168.1.9", &[], Some("o2"), None)), "router");
    }

    #[test]
    fn selbstauskunft_hat_vorrang() {
        let inv = json!({ "ssh": { "platform": "windows", "os": "Microsoft Windows Server 2022 Standard" } });
        let h = Hints { inventory: Some(&inv), ..hints("10.0.0.7", &[22], Some("pi"), Some("Raspberry Pi")) };
        assert_eq!(classify(&h), "server");

        let inv = json!({ "snmp": { "sys_descr": "Cisco IOS Software, C2960 Switch", "printer": [] } });
        let h = Hints { inventory: Some(&inv), ..hints("10.0.0.2", &[22, 80], None, Some("Cisco Systems")) };
        assert_eq!(classify(&h), "switch");
    }
}
