//! SSH-Abfrage für Linux, NAS, Proxmox, Raspberry Pi – und Windows (eingebauter OpenSSH-Server).
//!
//! Es werden nur **lesende** Befehle ausgeführt. Root-Rechte sind nicht nötig.
//! Der Host-Schlüssel des Geräts wird beim ersten Kontakt gespeichert („Trust on first use“);
//! ändert er sich später, wird die Verbindung abgelehnt (Schutz vor Man-in-the-Middle).

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use russh::{
    client::{self, Handle},
    keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate},
    ChannelMsg, Disconnect,
};
use serde_json::{json, Map, Value};

use super::Credential;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_OUTPUT: usize = 1024 * 1024;

pub enum SshError {
    /// Der Host-Schlüssel stimmt nicht mehr mit dem gespeicherten überein
    HostKeyChanged { expected: String, seen: String },
    Failed(String),
}

impl From<anyhow::Error> for SshError {
    fn from(e: anyhow::Error) -> Self {
        SshError::Failed(format!("{e:#}"))
    }
}

pub struct SshResult {
    pub data: Value,
    pub host_key: String,
}

struct Client {
    expected: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fingerprint = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256).to_string(),
            PublicKeyOrCertificate::Certificate(cert) => cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
        };
        let accepted = self.expected.as_ref().is_none_or(|e| *e == fingerprint);
        *self.seen.lock().unwrap() = Some(fingerprint);
        Ok(accepted)
    }
}

pub async fn collect(ip: Ipv4Addr, cred: &Credential, expected_host_key: Option<&str>) -> Result<SshResult, SshError> {
    let (session, host_key) = connect(ip, cred, expected_host_key).await?;
    let data = run_collection(&session).await;
    let _ = session.disconnect(Disconnect::ByApplication, "", "de").await;
    Ok(SshResult { data: data?, host_key })
}

/// Einzelnen lesenden Befehl ausführen (für die Live-Ansicht)
pub async fn run_command(
    ip: Ipv4Addr,
    cred: &Credential,
    expected_host_key: Option<&str>,
    command: &str,
) -> Result<String, SshError> {
    let (session, _) = connect(ip, cred, expected_host_key).await?;
    let result = exec(&session, command, None).await;
    let _ = session.disconnect(Disconnect::ByApplication, "", "de").await;
    Ok(result?.1)
}

/// Befehl ausführen, optional mit einem Skript über stdin (für Aktionen wie „Herunterfahren“, `power.rs`).
/// Liefert (Exit-Code, Ausgabe, Host-Schlüssel). Kein Pool: Aktionen sind selten.
pub async fn run_action(
    ip: Ipv4Addr,
    cred: &Credential,
    expected_host_key: Option<&str>,
    command: &str,
    stdin: Option<&str>,
) -> Result<(u32, String, String), SshError> {
    let (session, host_key) = connect(ip, cred, expected_host_key).await?;
    let result = exec(&session, command, stdin.map(str::as_bytes)).await;
    let _ = session.disconnect(Disconnect::ByApplication, "", "de").await;
    let (code, out) = result?;
    Ok((code, out, host_key))
}

/// Offene Sitzungen für die Live-Ansicht (Gerät + Zugangsdaten → Sitzung, zuletzt benutzt).
/// Spart den teuren Verbindungsaufbau alle 2 Sekunden – auf NetPulse und auf dem Gerät.
type Pool = Mutex<HashMap<(Ipv4Addr, i64), (Arc<Handle<Client>>, std::time::Instant)>>;

fn pool() -> &'static Pool {
    static POOL: std::sync::OnceLock<Pool> = std::sync::OnceLock::new();
    POOL.get_or_init(Pool::default)
}

/// POSIX-Skript über `sh -s` ausführen – unabhängig von der Login-Shell (OPNsense/pfSense nutzen
/// z. B. csh). Die Sitzung wird weiterverwendet, weil die Live-Ansicht alle 2 s fragt.
pub async fn run_script_pooled(
    ip: Ipv4Addr,
    cred: &Credential,
    expected_host_key: Option<&str>,
    script: &str,
) -> Result<String, SshError> {
    let key = (ip, cred.id);
    let existing = {
        let mut map = pool().lock().unwrap();
        // Unbenutzte Sitzungen schließen (die Gegenstelle beendet sie ohnehin nach 30 s)
        map.retain(|_, (_, used)| used.elapsed() < Duration::from_secs(25));
        map.get(&key).map(|(h, _)| h.clone())
    };
    if let Some(session) = existing {
        if let Ok((_, out)) = exec(&session, "sh -s", Some(script.as_bytes())).await {
            if let Some(entry) = pool().lock().unwrap().get_mut(&key) {
                entry.1 = std::time::Instant::now();
            }
            return Ok(out);
        }
        pool().lock().unwrap().remove(&key);
    }
    let (session, _) = connect(ip, cred, expected_host_key).await?;
    let session = Arc::new(session);
    let result = exec(&session, "sh -s", Some(script.as_bytes())).await;
    if result.is_ok() {
        pool().lock().unwrap().insert(key, (session, std::time::Instant::now()));
    }
    Ok(result?.1)
}

async fn connect(
    ip: Ipv4Addr,
    cred: &Credential,
    expected_host_key: Option<&str>,
) -> Result<(Handle<Client>, String), SshError> {
    let port = cred.port.and_then(|p| u16::try_from(p).ok()).unwrap_or(22);
    let seen = Arc::new(Mutex::new(None));
    let handler = Client { expected: expected_host_key.map(str::to_string), seen: seen.clone() };
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });

    let connect = tokio::time::timeout(CONNECT_TIMEOUT, client::connect(config, (ip, port), handler)).await;
    let seen_key = seen.lock().unwrap().clone();
    let mut session = match connect {
        Ok(Ok(session)) => session,
        Ok(Err(e)) => {
            if let (Some(expected), Some(seen)) = (expected_host_key, seen_key) {
                if expected != seen {
                    return Err(SshError::HostKeyChanged { expected: expected.to_string(), seen });
                }
            }
            return Err(SshError::Failed(format!("Verbindung fehlgeschlagen: {e}")));
        }
        Err(_) => return Err(SshError::Failed(format!("Keine Antwort auf Port {port}"))),
    };
    let host_key = seen.lock().unwrap().clone().unwrap_or_default();
    authenticate(&mut session, cred).await?;
    Ok((session, host_key))
}

async fn authenticate(session: &mut Handle<Client>, cred: &Credential) -> Result<()> {
    let user = cred.username.clone().unwrap_or_else(|| "root".into());
    let result = match cred.kind.as_str() {
        "ssh_password" => {
            let password = cred.secret.password.clone().unwrap_or_default();
            session.authenticate_password(user, password).await?
        }
        "ssh_key" => {
            let pem = cred.secret.private_key.as_deref().ok_or_else(|| anyhow!("Kein privater Schlüssel hinterlegt"))?;
            let key = russh::keys::decode_secret_key(pem, cred.secret.passphrase.as_deref())
                .map_err(|e| anyhow!("Privater Schlüssel nicht lesbar: {e}"))?;
            let hash = session.best_supported_rsa_hash().await?.flatten();
            session
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await?
        }
        other => bail!("{other} ist keine SSH-Zugangsart"),
    };
    if !result.success() {
        bail!("Anmeldung fehlgeschlagen (Benutzer oder Passwort/Schlüssel falsch)");
    }
    Ok(())
}

/// Führt einen Befehl aus; optional mit Eingabe über stdin. Liefert (Exit-Code, stdout).
async fn exec(session: &Handle<Client>, command: &str, stdin: Option<&[u8]>) -> Result<(u32, String)> {
    let run = async {
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, command).await?;
        if let Some(input) = stdin {
            channel.data(input).await?;
            channel.eof().await?;
        }
        let mut out = Vec::new();
        let mut code = 255;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } if out.len() < MAX_OUTPUT => out.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => code = exit_status,
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>((code, String::from_utf8_lossy(&out).into_owned()))
    };
    tokio::time::timeout(COMMAND_TIMEOUT, run)
        .await
        .map_err(|_| anyhow!("Zeitüberschreitung bei „{command}“"))?
}

async fn run_collection(session: &Handle<Client>) -> Result<Value> {
    let (code, uname) = exec(session, "uname -s", None).await?;
    if code == 0 && !uname.trim().is_empty() {
        let (_, output) = exec(session, "sh -s", Some(POSIX_SCRIPT.as_bytes())).await?;
        Ok(parse_posix(&output, uname.trim()))
    } else {
        // Windows: PowerShell-Skript als Base64 (UTF-16LE) übergeben – umgeht alle Quoting-Probleme
        let utf16: Vec<u8> = WINDOWS_SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let command = format!(
            "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
            B64.encode(utf16)
        );
        let (_, output) = exec(session, &command, None).await?;
        parse_windows(&output)
    }
}

/// Liest Systemdaten unter Linux (und eingeschränkt macOS/BSD). Ausgabe: key=value je Zeile.
const POSIX_SCRIPT: &str = r#"
export LC_ALL=C
echo "hostname=$(hostname 2>/dev/null)"
if [ -r /etc/os-release ]; then . /etc/os-release; echo "os=${PRETTY_NAME:-$NAME}"; fi
command -v sw_vers >/dev/null 2>&1 && echo "os=macOS $(sw_vers -productVersion)"
echo "kernel=$(uname -sr)"
echo "arch=$(uname -m)"
[ -r /proc/uptime ] && echo "uptime_s=$(cut -d. -f1 /proc/uptime)"
if [ -r /proc/cpuinfo ]; then
  echo "cpu_model=$(grep -m1 -E '^(model name|Model|Hardware|cpu model)' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
  echo "cpu_cores=$(grep -c ^processor /proc/cpuinfo)"
fi
[ -r /proc/loadavg ] && echo "load=$(cut -d' ' -f1-3 /proc/loadavg)"
if [ -r /proc/stat ]; then
  echo "cpu_a=$(head -1 /proc/stat)"; sleep 1; echo "cpu_b=$(head -1 /proc/stat)"
fi
[ -r /proc/meminfo ] && grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo | awk '{sub(":","",$1); print "mem_"$1"="$2}'
for f in sys_vendor product_name product_version board_vendor board_name bios_version; do
  [ -r /sys/class/dmi/id/$f ] && echo "dmi_$f=$(cat /sys/class/dmi/id/$f 2>/dev/null)"
done
[ -r /proc/device-tree/model ] && echo "dt_model=$(tr -d '\000' < /proc/device-tree/model)"
for z in /sys/class/thermal/thermal_zone*/temp; do [ -r "$z" ] && echo "temp=$(cat "$z")"; done 2>/dev/null
df -PTk 2>/dev/null | awk 'NR>1 {print "disk="$1"|"$2"|"$3"|"$4"|"$7}'
for i in /sys/class/net/*; do
  n=${i##*/}; [ "$n" = lo ] && continue
  echo "if=$n|$(cat $i/operstate 2>/dev/null)|$(cat $i/speed 2>/dev/null)|$(cat $i/address 2>/dev/null)|$(cat $i/statistics/rx_bytes 2>/dev/null)|$(cat $i/statistics/tx_bytes 2>/dev/null)"
done 2>/dev/null
command -v ip >/dev/null 2>&1 && ip -o -4 addr show 2>/dev/null | awk '{print "ip="$2"|"$4}'
command -v ip >/dev/null 2>&1 && echo "default_if=$(ip route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i+1); exit }}')"
command -v systemctl >/dev/null 2>&1 && echo "failed_units=$(systemctl --failed --no-legend 2>/dev/null | wc -l)"
command -v docker >/dev/null 2>&1 && docker ps -q >/dev/null 2>&1 && echo "containers=$(docker ps -q | wc -l)"
[ -f /var/run/reboot-required ] && echo "reboot_required=1"
command -v pveversion >/dev/null 2>&1 && echo "proxmox=$(pveversion 2>/dev/null)"
[ -r /etc/synoinfo.conf ] && echo "synology=$(grep -m1 '^upnpmodelname' /etc/synoinfo.conf | cut -d'"' -f2)"
[ -r /etc.defaults/VERSION ] && echo "os=DSM $(. /etc.defaults/VERSION; echo "$productversion")"
# FreeBSD, OPNsense, pfSense: dieselben Kennwerte über sysctl, netstat, ifconfig und route
if [ "$(uname -s)" = "FreeBSD" ]; then
  if command -v opnsense-version >/dev/null 2>&1; then echo "os=$(opnsense-version 2>/dev/null)"
  elif [ -r /etc/version ] && [ -d /usr/local/pfSense ]; then echo "os=pfSense $(cat /etc/version)"
  else echo "os=FreeBSD $(freebsd-version 2>/dev/null)"; fi
  echo "cpu_model=$(sysctl -n hw.model 2>/dev/null)"
  echo "cpu_cores=$(sysctl -n hw.ncpu 2>/dev/null)"
  boot=$(sysctl -n kern.boottime 2>/dev/null | sed 's/.*sec = \([0-9]*\).*/\1/')
  [ -n "$boot" ] && echo "uptime_s=$(( $(date +%s) - boot ))"
  echo "load=$(sysctl -n vm.loadavg 2>/dev/null | tr -d '{}' | awk '{print $1, $2, $3}')"
  # kern.cp_time: user nice sys intr idle → als „user nice system idle“ ausgeben
  echo "cpu_a=cpu $(sysctl -n kern.cp_time | awk '{print $1, $2, $3 + $4, $5}')"; sleep 1
  echo "cpu_b=cpu $(sysctl -n kern.cp_time | awk '{print $1, $2, $3 + $4, $5}')"
  page=$(sysctl -n hw.pagesize); free=$(sysctl -n vm.stats.vm.v_free_count); inact=$(sysctl -n vm.stats.vm.v_inactive_count)
  echo "mem_MemTotal=$(( $(sysctl -n hw.physmem) / 1024 ))"
  echo "mem_MemAvailable=$(( (free + inact) * page / 1024 ))"
  for t in $(sysctl -n dev.cpu.0.temperature hw.acpi.thermal.tz0.temperature 2>/dev/null); do echo "temp=${t%C}"; done
  df -kP 2>/dev/null | awk 'NR>1 && ($6 == "/" || $1 ~ /^\/dev\//) {print "disk="$1"|bsd|"$2"|"$3"|"$6}'
  netstat -ibn 2>/dev/null | awk 'NR>1 && $3 ~ /^<Link/ {n=$1; sub(/\*$/, "", n); m=($4 ~ /:/) ? $4 : "-"; print n, m, $(NF-4), $(NF-1)}' |
  while read -r n m rx tx; do
    case "$n" in lo*|pflog*|pfsync*|enc*) continue;; esac
    info=$(ifconfig "$n" 2>/dev/null)
    st=$(echo "$info" | awk '/status:/ {print $2; exit}')
    sp=$(echo "$info" | sed -n 's/.*media:.*(\([0-9]*\)\(G*\)base.*/\1 \2/p' | awk 'NR==1 {print ($2 == "G") ? $1 * 1000 : $1}')
    case "$st" in active|associated|"") st=up;; *) st=down;; esac
    [ "$m" = "-" ] && m=""
    echo "if=$n|$st|$sp|$m|$rx|$tx"
  done
  ifconfig 2>/dev/null | awk '/^[a-z]/ {i=$1; sub(":", "", i)} /inet / {print "ip="i"|"$2}'
  echo "default_if=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')"
fi
# Verbundene Geräte – nur auf Routern/Access Points (WLAN-Stationen oder DHCP-Server vorhanden):
# WLAN-Stationen (iw), DHCP-Leases (dnsmasq/OpenWrt, Kea, ISC) und die ARP-Tabelle für IP ↔ MAC
router=
if command -v iw >/dev/null 2>&1; then
  for w in $(iw dev 2>/dev/null | awk '$1 == "Interface" {print $2}'); do
    info=$(iw dev "$w" info 2>/dev/null)
    echo "$info" | grep -q "type AP" || continue
    router=1
    echo "wifi_if=$w|$(echo "$info" | sed -n 's/^[[:space:]]*ssid //p' | head -1)|$(echo "$info" | awk '$1 == "channel" {gsub(/\(/, "", $3); print $2"|"$3; exit}')"
    iw dev "$w" station dump 2>/dev/null | sed "s/^/sta=$w|/"
  done
fi
for f in /tmp/dhcp.leases /var/lib/misc/dnsmasq.leases /var/db/dnsmasq.leases /tmp/dnsmasq.leases; do
  [ -r "$f" ] && { router=1; awk 'NF >= 4 {print "lease="$2"|"$3"|"$4}' "$f"; }
done
if [ -r /var/db/kea/kea-leases4.csv ]; then router=1; awk -F, 'NR > 1 && $2 != "" {print "lease="$2"|"$1"|"$9}' /var/db/kea/kea-leases4.csv; fi
if [ -r /var/dhcpd/var/db/dhcpd.leases ]; then
  router=1
  awk '/^lease / {ip=$2; m=""; h=""} /hardware ethernet/ {m=$3; sub(";", "", m)} /client-hostname/ {h=$2; gsub(/[";]/, "", h)} /^}/ {if (m != "") print "lease="m"|"ip"|"h}' /var/dhcpd/var/db/dhcpd.leases
fi
if [ -n "$router" ]; then
  if command -v ip >/dev/null 2>&1; then
    ip neigh show 2>/dev/null | awk '{m=""; d=""; for (i = 1; i < NF; i++) {if ($i == "lladdr") m=$(i+1); if ($i == "dev") d=$(i+1)} if (m != "") print "neigh="$1"|"m"|"d}'
  else
    arp -an 2>/dev/null | awk '$4 ~ /:/ {ip=$2; gsub(/[()]/, "", ip); print "neigh="ip"|"$4"|"$6}'
  fi
fi
exit 0
"#;

/// Liest Systemdaten unter Windows über CIM/WMI und gibt sie als JSON aus.
const WINDOWS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cpu = @(Get-CimInstance Win32_Processor)
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  @{ mount = $_.DeviceID; type = $_.FileSystem; size_bytes = [int64]$_.Size; free_bytes = [int64]$_.FreeSpace } })
$nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
  @{ name = $_.Description; mac = $_.MACAddress; ips = @($_.IPAddress) } })
$hotfix = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$stopped = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'").Count
$reboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
[pscustomobject]@{
  hostname = $env:COMPUTERNAME; domain = $cs.Domain
  os = $os.Caption; version = $os.Version; build = $os.BuildNumber; arch = $os.OSArchitecture
  uptime_s = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
  vendor = $cs.Manufacturer; model = $cs.Model; serial = $bios.SerialNumber; bios = $bios.SMBIOSBIOSVersion
  cpu_model = $cpu[0].Name; cpu_cores = ($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum
  cpu_pct = ($cpu | Measure-Object LoadPercentage -Average).Average
  mem_total_kb = [int64]$os.TotalVisibleMemorySize; mem_free_kb = [int64]$os.FreePhysicalMemory
  disks = $disks; nics = $nics; stopped_auto_services = $stopped; reboot_required = $reboot
  last_hotfix = if ($hotfix) { $hotfix.InstalledOn.ToString('yyyy-MM-dd') } else { $null }
} | ConvertTo-Json -Depth 4 -Compress
"#;

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn parse_posix(output: &str, uname: &str) -> Value {
    let mut map = Map::new();
    let mut multi: std::collections::HashMap<&str, Vec<&str>> = Default::default();
    // Zeilen für die Client-Liste (Einrückung von „iw station dump“ bleibt erhalten)
    let mut client_lines: Vec<(&str, &str)> = Vec::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        if matches!(key, "wifi_if" | "sta" | "neigh" | "lease") {
            client_lines.push((key, value));
            continue;
        }
        match key {
            "temp" | "disk" | "if" | "ip" => multi.entry(key).or_default().push(value),
            _ if !value.trim().is_empty() => {
                map.insert(key.to_string(), json!(value.trim()));
            }
            _ => {}
        }
    }
    let get = |k: &str| map.get(k).and_then(Value::as_str).map(str::to_string);
    let num = |k: &str| get(k).and_then(|v| v.parse::<f64>().ok());

    let mut data = Map::new();
    data.insert("platform".into(), json!(if uname == "Linux" { "linux".to_string() } else { uname.to_lowercase() }));
    for key in ["hostname", "os", "kernel", "arch", "cpu_model", "proxmox", "synology"] {
        data.insert(key.into(), json!(get(key)));
    }
    data.insert("default_route_if".into(), json!(get("default_if")));
    data.insert("uptime_s".into(), json!(num("uptime_s")));
    data.insert("cpu_cores".into(), json!(num("cpu_cores")));
    data.insert(
        "load".into(),
        json!(get("load").map(|l| l.split_whitespace().filter_map(|x| x.parse::<f64>().ok()).collect::<Vec<_>>())),
    );

    // CPU-Auslastung aus zwei /proc/stat-Stichproben im Abstand von 1 s
    if let (Some(a), Some(b)) = (get("cpu_a"), get("cpu_b")) {
        let parse = |s: &str| s.split_whitespace().skip(1).filter_map(|x| x.parse::<f64>().ok()).collect::<Vec<_>>();
        let (a, b) = (parse(&a), parse(&b));
        if a.len() >= 4 && b.len() >= 4 {
            let total: f64 = b.iter().sum::<f64>() - a.iter().sum::<f64>();
            let idle = (b[3] + b.get(4).unwrap_or(&0.0)) - (a[3] + a.get(4).unwrap_or(&0.0));
            if total > 0.0 {
                data.insert("cpu_pct".into(), json!(round1(100.0 * (1.0 - idle / total))));
            }
        }
    }

    if let (Some(total), Some(avail)) = (num("mem_MemTotal"), num("mem_MemAvailable")) {
        data.insert("mem_total_kb".into(), json!(total));
        data.insert("mem_available_kb".into(), json!(avail));
        if total > 0.0 {
            data.insert("mem_pct".into(), json!(round1(100.0 * (1.0 - avail / total))));
        }
    }
    data.insert("swap_total_kb".into(), json!(num("mem_SwapTotal")));
    data.insert("swap_free_kb".into(), json!(num("mem_SwapFree")));

    let board = get("dt_model").or_else(|| get("dmi_product_name"));
    data.insert("board".into(), json!(board));
    data.insert("vendor".into(), json!(get("dmi_sys_vendor").or_else(|| get("dmi_board_vendor"))));
    data.insert("model".into(), json!(board.or_else(|| get("dmi_board_name"))));
    data.insert("bios".into(), json!(get("dmi_bios_version")));

    let temps: Vec<f64> = multi.get("temp").into_iter().flatten().filter_map(|t| t.trim().parse::<f64>().ok()).collect();
    if let Some(max) = temps.iter().copied().reduce(f64::max) {
        data.insert("temp_c".into(), json!(round1(if max > 1000.0 { max / 1000.0 } else { max })));
    }

    const SKIP_FS: &[&str] = &["tmpfs", "devtmpfs", "overlay", "squashfs", "efivarfs", "proc", "sysfs", "devfs", "nullfs", "autofs", "fdescfs"];
    let mut seen_dev = std::collections::HashSet::new();
    let disks: Vec<Value> = multi
        .get("disk")
        .into_iter()
        .flatten()
        .filter_map(|line| {
            let p: Vec<&str> = line.split('|').collect();
            let (dev, fs, size, used, mount) = (p.first()?, p.get(1)?, p.get(2)?, p.get(3)?, p.get(4)?);
            let size: f64 = size.parse().ok()?;
            let used: f64 = used.parse().ok()?;
            if SKIP_FS.contains(fs) || size <= 0.0 || !seen_dev.insert(dev.to_string()) {
                return None;
            }
            Some(json!({
                "device": dev, "type": fs, "mount": mount,
                "size_bytes": size * 1024.0, "used_bytes": used * 1024.0,
                "pct": round1(used / size * 100.0),
            }))
        })
        .collect();
    data.insert("disks".into(), Value::Array(disks));

    let interfaces: Vec<Value> = multi
        .get("if")
        .into_iter()
        .flatten()
        .filter_map(|line| {
            let p: Vec<&str> = line.split('|').collect();
            let name = p.first()?;
            if name.starts_with("veth") || name.starts_with("br-") || name.starts_with("docker") {
                return None;
            }
            let n = |i: usize| p.get(i).and_then(|v| v.trim().parse::<f64>().ok());
            Some(json!({
                "name": name, "oper": p.get(1).map(|s| s.trim()), "speed_mbps": n(2).filter(|s| *s > 0.0),
                "mac": p.get(3), "rx_bytes": n(4), "tx_bytes": n(5),
            }))
        })
        .collect();
    data.insert("interfaces".into(), Value::Array(interfaces));
    let ips: Vec<Value> = multi
        .get("ip")
        .into_iter()
        .flatten()
        .filter_map(|l| l.split_once('|').map(|(i, a)| json!({ "iface": i, "addr": a })))
        .collect();
    data.insert("ips".into(), Value::Array(ips));
    data.insert("failed_units".into(), json!(num("failed_units")));
    data.insert("containers".into(), json!(num("containers")));
    data.insert("reboot_required".into(), json!(get("reboot_required").is_some()));
    if !client_lines.is_empty() {
        let key = get("hostname").unwrap_or_else(|| "ssh".into());
        data.insert("net_clients".into(), Value::Array(super::netclients::from_ssh(&client_lines, &key)));
    }
    Value::Object(data)
}

fn parse_windows(output: &str) -> Result<Value> {
    // PowerShell schreibt über SSH manchmal Fortschrittsdaten („#< CLIXML“) davor – nur das JSON nehmen
    let start = output.find('{').ok_or_else(|| anyhow!("Keine Antwort von PowerShell – ist es ein Windows-Gerät?"))?;
    let end = output.rfind('}').ok_or_else(|| anyhow!("Unvollständige Antwort von PowerShell"))?;
    let raw: Value = serde_json::from_str(output.get(start..=end).ok_or_else(|| anyhow!("Unvollständige Antwort von PowerShell"))?)?;
    let mut data = raw.as_object().cloned().unwrap_or_default();
    data.insert("platform".into(), json!("windows"));

    let total = raw["mem_total_kb"].as_f64();
    let free = raw["mem_free_kb"].as_f64();
    if let (Some(total), Some(free)) = (total, free) {
        if total > 0.0 {
            data.insert("mem_pct".into(), json!(round1(100.0 * (1.0 - free / total))));
        }
    }
    let as_list = |v: &Value| match v {
        Value::Array(a) => a.clone(),
        Value::Null => vec![],
        other => vec![other.clone()],
    };
    let disks: Vec<Value> = as_list(&raw["disks"])
        .into_iter()
        .filter_map(|d| {
            let size = d["size_bytes"].as_f64()?;
            let free = d["free_bytes"].as_f64().unwrap_or(0.0);
            (size > 0.0).then(|| {
                json!({
                    "mount": d["mount"], "type": d["type"], "size_bytes": size, "used_bytes": size - free,
                    "pct": round1((size - free) / size * 100.0),
                })
            })
        })
        .collect();
    data.insert("disks".into(), Value::Array(disks));
    data.insert("nics".into(), Value::Array(as_list(&raw["nics"])));
    Ok(Value::Object(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_ausgabe_wird_ausgewertet() {
        let out = "hostname=pi\nos=Debian GNU/Linux 12 (bookworm)\ncpu_cores=4\n\
                   cpu_a=cpu 100 0 100 800 0 0 0 0\ncpu_b=cpu 150 0 150 900 0 0 0 0\n\
                   mem_MemTotal=1000\nmem_MemAvailable=250\ntemp=51234\ntemp=48000\n\
                   dt_model=Raspberry Pi 4 Model B Rev 1.4\n\
                   disk=/dev/root|ext4|1000|400|/\ndisk=tmpfs|tmpfs|100|1|/run\n\
                   if=eth0|up|1000|dc:a6:32:00:00:01|12345|678\nif=veth1|up||x|1|1\n";
        let v = parse_posix(out, "Linux");
        assert_eq!(v["platform"], "linux");
        assert_eq!(v["cpu_pct"], 50.0);
        assert_eq!(v["mem_pct"], 75.0);
        assert_eq!(v["temp_c"], 51.2);
        assert_eq!(v["board"], "Raspberry Pi 4 Model B Rev 1.4");
        assert_eq!(v["disks"].as_array().unwrap().len(), 1);
        assert_eq!(v["disks"][0]["pct"], 40.0);
        assert_eq!(v["interfaces"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn windows_ausgabe_wird_ausgewertet() {
        let out = "#< CLIXML\r\n{\"hostname\":\"PC1\",\"os\":\"Microsoft Windows 11 Pro\",\"mem_total_kb\":1000,\"mem_free_kb\":400,\
                   \"disks\":{\"mount\":\"C:\",\"type\":\"NTFS\",\"size_bytes\":200,\"free_bytes\":50},\"nics\":null}";
        let v = parse_windows(out).unwrap();
        assert_eq!(v["platform"], "windows");
        assert_eq!(v["mem_pct"], 60.0);
        assert_eq!(v["disks"][0]["pct"], 75.0);
    }
}

