//! Windows-Remoteverwaltung (WinRM, WS-Management) – Windows ohne Zusatzsoftware abfragen und steuern.
//!
//! Ablauf: Shell anlegen → Befehl starten → Ausgabe abholen (bis „Done“) → Shell schließen.
//! Befehle laufen als PowerShell (`-EncodedCommand`, umgeht alle Quoting-Probleme).
//!
//! Anmeldung:
//! - **NTLM** (Standard von Windows) über **HTTPS** (Port 5986, Zertifikat wird beim ersten Kontakt gemerkt).
//!   Über HTTP verlangt Windows bei NTLM Nachrichtenverschlüsselung – das wird nicht unterstützt.
//! - **Basic** (muss am Gerät eingeschaltet werden, nur lokale Konten), über HTTPS oder – nur im LAN und mit
//!   `AllowUnencrypted` – über HTTP (Port 5985).

use std::{net::Ipv4Addr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use reqwest::{header, Client, StatusCode};
use serde_json::Value;

use super::{tls, Credential};

const RESOURCE: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
const NS: &str = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell""#;
/// Gesamtdauer eines Befehls
const COMMAND_LIMIT: Duration = Duration::from_secs(60);

/// Ergebnis eines Befehls
pub struct Output {
    pub code: i64,
    pub stdout: String,
    pub stderr: String,
    /// Fingerabdruck des TLS-Zertifikats beim ersten Kontakt
    pub pin: Option<String>,
}

fn opt<'a>(cred: &'a Credential, key: &str) -> Option<&'a str> {
    cred.options.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

fn uuid() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b).to_uppercase();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Text zwischen `<…:tag …>` und `</…:tag>` (Namensraum-Präfix egal)
fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(pos) = xml[from..].find(tag) {
        let at = from + pos;
        from = at + tag.len();
        let before = xml[..at].chars().last();
        let after = xml[at + tag.len()..].chars().next();
        // Muss ein Start-Tag sein: „<tag“ oder „<prefix:tag“, gefolgt von „>“ oder Leerzeichen
        if !matches!(before, Some('<') | Some(':')) || !matches!(after, Some('>') | Some(' ')) {
            continue;
        }
        let open = xml[..at].rfind('<')?;
        if xml[open + 1..at].contains('/') {
            continue;
        }
        let start = at + xml[at..].find('>')? + 1;
        if xml[..start].ends_with("/>") {
            return Some("");
        }
        let end = start + xml[start..].find("</")?;
        return Some(&xml[start..end]);
    }
    None
}

/// Alle Ausgabeblöcke eines Streams („stdout“/„stderr“) zusammensetzen
fn streams(xml: &str, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let marker = format!("Name=\"{name}\"");
    let mut from = 0;
    while let Some(pos) = xml[from..].find(&marker) {
        let at = from + pos;
        from = at + marker.len();
        let Some(gt) = xml[at..].find('>') else { break };
        let tag_end = at + gt;
        if xml[..tag_end + 1].ends_with("/>") {
            continue;
        }
        let Some(end) = xml[tag_end + 1..].find("</") else { break };
        if let Ok(bytes) = B64.decode(xml[tag_end + 1..tag_end + 1 + end].trim()) {
            out.extend(bytes);
        }
    }
    out
}

/// Verständliche Fehlermeldung aus einer SOAP-Fault-Antwort
fn fault(xml: &str) -> String {
    let text = element(xml, "Message")
        .or_else(|| element(xml, "Text"))
        .map(|t| t.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| xml.chars().take(300).collect());
    text.replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

// ---------------------------------------------------------------------------
// NTLMv2 (MS-NLMP) – nur Anmeldung, keine Signatur/Verschlüsselung (dafür HTTPS)
// ---------------------------------------------------------------------------

const NTLM_FLAGS: u32 = 0x0000_0001 // UNICODE
    | 0x0000_0004 // REQUEST_TARGET
    | 0x0000_0200 // NTLM
    | 0x0000_8000 // ALWAYS_SIGN
    | 0x0008_0000 // EXTENDED_SESSIONSECURITY
    | 0x0080_0000 // TARGET_INFO
    | 0x2000_0000 // 128
    | 0x8000_0000; // 56

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Hmac<md5::Md5> as Mac>::new_from_slice(key).expect("HMAC nimmt jeden Schlüssel");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

fn ntowf_v2(user: &str, domain: &str, password: &str) -> [u8; 16] {
    let nt_hash = Md4::digest(utf16(password));
    hmac_md5(&nt_hash, &[&utf16(&format!("{}{domain}", user.to_uppercase()))])
}

fn negotiate_message() -> Vec<u8> {
    let mut m = b"NTLMSSP\0".to_vec();
    m.extend(1u32.to_le_bytes());
    m.extend(NTLM_FLAGS.to_le_bytes());
    m.extend([0u8; 16]); // Domäne und Arbeitsstation leer
    m
}

struct Challenge {
    server: [u8; 8],
    target_info: Vec<u8>,
}

fn parse_challenge(msg: &[u8]) -> Result<Challenge> {
    if msg.len() < 48 || &msg[..8] != b"NTLMSSP\0" || msg[8] != 2 {
        bail!("Ungültige NTLM-Antwort des Geräts");
    }
    let mut server = [0u8; 8];
    server.copy_from_slice(&msg[24..32]);
    let len = u16::from_le_bytes([msg[40], msg[41]]) as usize;
    let off = u32::from_le_bytes([msg[44], msg[45], msg[46], msg[47]]) as usize;
    let target_info = msg.get(off..off + len).ok_or_else(|| anyhow!("NTLM-Antwort unvollständig"))?.to_vec();
    Ok(Challenge { server, target_info })
}

/// NTLMv2-Antwort (NtChallengeResponse) für Benutzer/Domäne/Passwort
fn nt_response(ntowf: &[u8; 16], c: &Challenge, client: &[u8; 8], time: u64) -> Vec<u8> {
    let mut temp = vec![1u8, 1, 0, 0, 0, 0, 0, 0];
    temp.extend(time.to_le_bytes());
    temp.extend(client);
    temp.extend([0u8; 4]);
    temp.extend(&c.target_info);
    temp.extend([0u8; 4]);
    let proof = hmac_md5(ntowf, &[&c.server, &temp]);
    let mut out = proof.to_vec();
    out.extend(temp);
    out
}

fn authenticate_message(user: &str, domain: &str, password: &str, c: &Challenge) -> Vec<u8> {
    let ntowf = ntowf_v2(user, domain, password);
    let mut client = [0u8; 8];
    OsRng.fill_bytes(&mut client);
    // Windows-Zeit: 100-ns-Schritte seit 1601
    let time = (chrono::Utc::now().timestamp_micros() as u64 + 11_644_473_600_000_000) * 10;
    let nt = nt_response(&ntowf, c, &client, time);
    let mut lm = hmac_md5(&ntowf, &[&c.server, &client]).to_vec();
    lm.extend(client);
    let workstation = utf16("NETPULSE");
    let fields: [Vec<u8>; 6] = [lm, nt, utf16(domain), utf16(user), workstation, Vec::new()];
    let mut header = b"NTLMSSP\0".to_vec();
    header.extend(3u32.to_le_bytes());
    let mut payload: Vec<u8> = Vec::new();
    let mut offset = 8 + 4 + 6 * 8 + 4;
    for f in &fields {
        header.extend((f.len() as u16).to_le_bytes());
        header.extend((f.len() as u16).to_le_bytes());
        header.extend((offset as u32).to_le_bytes());
        offset += f.len();
        payload.extend(f);
    }
    header.extend(NTLM_FLAGS.to_le_bytes());
    header.extend(payload);
    header
}

/// „DOMÄNE\benutzer“ oder „benutzer@domäne“ → (Benutzer, Domäne)
fn split_user(raw: &str) -> (String, String) {
    if let Some((domain, user)) = raw.split_once('\\') {
        (user.to_string(), domain.to_string())
    } else if let Some((user, domain)) = raw.split_once('@') {
        (user.to_string(), domain.to_string())
    } else {
        (raw.to_string(), String::new())
    }
}

// ---------------------------------------------------------------------------
// Verbindung
// ---------------------------------------------------------------------------

struct Session {
    client: Client,
    pin: std::sync::Arc<tls::Pin>,
    url: String,
    user: String,
    password: String,
    basic: bool,
    authenticated: bool,
}

impl Session {
    fn new(ip: Ipv4Addr, cred: &Credential, tls_pin: Option<&str>) -> Result<Self> {
        let https = opt(cred, "scheme") != Some("http");
        let port = cred.port.unwrap_or(if https { 5986 } else { 5985 });
        let basic = opt(cred, "auth") == Some("basic");
        if !https && !basic {
            bail!("WinRM über HTTP geht nur mit Basic-Anmeldung – bitte HTTPS (Port 5986) verwenden oder Anmeldung „Basic“ wählen");
        }
        let pin = tls::Pin::new(tls_pin);
        Ok(Self {
            client: tls::client(pin.clone())?,
            pin,
            url: format!("{}://{ip}:{port}/wsman", if https { "https" } else { "http" }),
            user: cred.username.clone().unwrap_or_default(),
            password: cred.secret.password.clone().unwrap_or_default(),
            basic,
            authenticated: false,
        })
    }

    async fn post(&self, body: &str, auth: Option<String>) -> Result<(StatusCode, String, Vec<String>)> {
        let mut request = self
            .client
            .post(&self.url)
            .header(header::CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .timeout(Duration::from_secs(30))
            .body(body.to_string());
        if self.basic {
            request = request.basic_auth(&self.user, Some(&self.password));
        } else if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        let response = request.send().await.map_err(|e| {
            let e = anyhow::Error::from(e);
            if tls::pin_mismatch(&e) {
                anyhow!(tls::PIN_CHANGED)
            } else if tls::unreachable(&e) {
                anyhow!("keine Verbindung zu {} – WinRM am Gerät eingeschaltet und Port in der Firewall frei?", self.url)
            } else {
                e
            }
        })?;
        let status = response.status();
        let challenges = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|h| h.to_str().ok().map(str::to_string))
            .collect();
        Ok((status, response.text().await.unwrap_or_default(), challenges))
    }

    /// SOAP-Anfrage senden; meldet sich bei Bedarf per NTLM an (Verbindung bleibt danach angemeldet)
    async fn send(&mut self, body: &str) -> Result<String> {
        for attempt in 0..2 {
            let (status, text, challenges) = if self.basic || self.authenticated {
                self.post(body, None).await?
            } else {
                self.ntlm(body).await?
            };
            match status {
                s if s.is_success() => {
                    self.authenticated = true;
                    return Ok(text);
                }
                StatusCode::UNAUTHORIZED if self.authenticated && attempt == 0 => {
                    // Neue Verbindung im Pool – erneut anmelden
                    self.authenticated = false;
                }
                StatusCode::UNAUTHORIZED => {
                    let offered = challenges.join(", ");
                    if self.basic && !offered.to_ascii_lowercase().contains("basic") {
                        bail!("Basic-Anmeldung ist am Gerät ausgeschaltet (angeboten: {offered}) – Anmeldung „automatisch (NTLM)“ wählen");
                    }
                    bail!("Anmeldung abgelehnt – Benutzer/Passwort prüfen (Domänenkonto als DOMÄNE\\benutzer); Konto braucht Zugriff auf WinRM (Gruppe „Remoteverwaltungsbenutzer“ oder Administratoren)");
                }
                // Receive: „noch keine neue Ausgabe innerhalb von OperationTimeout“ – kein echter Fehler
                _ if text.contains("2150858793") => bail!("WinRM: noch keine Ausgabe (2150858793)"),
                s => bail!("WinRM antwortete mit {s}: {}", fault(&text)),
            }
        }
        bail!("Anmeldung fehlgeschlagen")
    }

    async fn ntlm(&mut self, body: &str) -> Result<(StatusCode, String, Vec<String>)> {
        let (status, text, challenges) =
            self.post(body, Some(format!("Negotiate {}", B64.encode(negotiate_message())))).await?;
        if status != StatusCode::UNAUTHORIZED {
            return Ok((status, text, challenges));
        }
        let token = challenges
            .iter()
            .find_map(|c| c.strip_prefix("Negotiate ").or_else(|| c.strip_prefix("NTLM ")))
            .map(str::trim)
            .ok_or_else(|| {
                if challenges.iter().any(|c| c.to_ascii_lowercase().starts_with("basic")) {
                    anyhow!("Das Gerät bietet nur Basic-Anmeldung an – bei den Zugangsdaten Anmeldung „Basic“ wählen")
                } else {
                    anyhow!("Das Gerät bietet keine NTLM-Anmeldung an ({})", challenges.join(", "))
                }
            })?;
        let challenge = parse_challenge(&B64.decode(token).context("NTLM-Antwort nicht lesbar")?)?;
        let (user, domain) = split_user(&self.user);
        let auth = authenticate_message(&user, &domain, &self.password, &challenge);
        self.post(body, Some(format!("Negotiate {}", B64.encode(auth)))).await
    }

    fn envelope(&self, action: &str, selector: Option<&str>, options: &str, body: &str) -> String {
        let selector = selector
            .map(|id| format!(r#"<w:SelectorSet><w:Selector Name="ShellId">{id}</w:Selector></w:SelectorSet>"#))
            .unwrap_or_default();
        format!(
            r#"<s:Envelope {NS}><s:Header><a:To>{url}</a:To><a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action s:mustUnderstand="true">{action}</a:Action><w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize><a:MessageID>uuid:{id}</a:MessageID><w:Locale xml:lang="de-DE" s:mustUnderstand="false"/><w:OperationTimeout>PT20S</w:OperationTimeout><w:ResourceURI s:mustUnderstand="true">{RESOURCE}</w:ResourceURI>{selector}{options}</s:Header><s:Body>{body}</s:Body></s:Envelope>"#,
            url = xml_escape(&self.url),
            id = uuid(),
        )
    }
}

/// PowerShell-Befehl auf einem Windows-Gerät ausführen
pub async fn run(ip: Ipv4Addr, cred: &Credential, tls_pin: Option<&str>, script: &str) -> Result<Output> {
    let mut s = Session::new(ip, cred, tls_pin)?;
    let create = s.envelope(
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
        None,
        r#"<w:OptionSet><w:Option Name="WINRS_NOPROFILE">TRUE</w:Option><w:Option Name="WINRS_CODEPAGE">65001</w:Option></w:OptionSet>"#,
        "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>",
    );
    let reply = s.send(&create).await?;
    let shell = element(&reply, "ShellId").map(str::trim).filter(|v| !v.is_empty()).ok_or_else(|| anyhow!("WinRM: keine Shell erhalten"))?.to_string();
    let result = command(&mut s, &shell, script).await;
    let delete = s.envelope("http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", Some(&shell), "", "");
    let _ = s.send(&delete).await;
    let pin = if tls_pin.is_none() { s.pin.seen() } else { None };
    result.map(|mut o| {
        o.pin = pin;
        o
    })
}

async fn command(s: &mut Session, shell: &str, script: &str) -> Result<Output> {
    let encoded = B64.encode(utf16(script));
    let cmd = s.envelope(
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
        Some(shell),
        r#"<w:OptionSet><w:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</w:Option><w:Option Name="WINRS_SKIP_CMD_SHELL">TRUE</w:Option></w:OptionSet>"#,
        &format!(
            "<rsp:CommandLine><rsp:Command>powershell.exe</rsp:Command><rsp:Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}</rsp:Arguments></rsp:CommandLine>"
        ),
    );
    let reply = s.send(&cmd).await?;
    let id = element(&reply, "CommandId").map(str::trim).filter(|v| !v.is_empty()).ok_or_else(|| anyhow!("WinRM: Befehl nicht gestartet"))?.to_string();
    let receive = s.envelope(
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
        Some(shell),
        "",
        &format!(r#"<rsp:Receive><rsp:DesiredStream CommandId="{id}">stdout stderr</rsp:DesiredStream></rsp:Receive>"#),
    );
    let started = std::time::Instant::now();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    loop {
        let reply = match s.send(&receive).await {
            Ok(r) => r,
            // „Zeitüberschreitung“ heißt nur: noch keine neue Ausgabe – weiter warten
            Err(e) if format!("{e:#}").contains("2150858793") || format!("{e:#}").to_lowercase().contains("timed out") => {
                if started.elapsed() > COMMAND_LIMIT {
                    bail!("Zeitüberschreitung ({} s)", COMMAND_LIMIT.as_secs());
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        stdout.extend(streams(&reply, "stdout"));
        stderr.extend(streams(&reply, "stderr"));
        if reply.contains("CommandState/Done") {
            let code = element(&reply, "ExitCode").and_then(|c| c.trim().parse().ok()).unwrap_or(0);
            return Ok(Output {
                code,
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: clean_stderr(&String::from_utf8_lossy(&stderr)),
                pin: None,
            });
        }
        if started.elapsed() > COMMAND_LIMIT {
            bail!("Zeitüberschreitung ({} s)", COMMAND_LIMIT.as_secs());
        }
    }
}

/// PowerShell schreibt Fortschritt als CLIXML auf stderr – lesbaren Text herausziehen
fn clean_stderr(raw: &str) -> String {
    if !raw.contains("#< CLIXML") {
        return raw.trim().to_string();
    }
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(pos) = rest.find("<S S=\"Error\">") {
        rest = &rest[pos + 13..];
        if let Some(end) = rest.find("</S>") {
            out.push(rest[..end].replace("_x000D__x000A_", "").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"));
            rest = &rest[end..];
        }
    }
    out.join(" ").trim().to_string()
}

/// Inventar wie bei Windows über SSH (gleiches PowerShell-Skript, gleiche Auswertung)
pub async fn collect(ip: Ipv4Addr, cred: &Credential, tls_pin: Option<&str>) -> Result<(Value, Option<String>)> {
    let out = run(ip, cred, tls_pin, super::ssh::WINDOWS_SCRIPT).await?;
    if out.code != 0 && out.stdout.trim().is_empty() {
        bail!("PowerShell meldet Fehler {}: {}", out.code, out.stderr);
    }
    let mut data = super::ssh::parse_windows(&out.stdout)?;
    data["via"] = Value::from("winrm");
    Ok((data, out.pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Testwerte aus MS-NLMP 4.2.4 (NTLMv2)
    #[test]
    fn ntlmv2_nach_spezifikation() {
        let ntowf = ntowf_v2("User", "Domain", "Password");
        assert_eq!(hex::encode(ntowf), "0c868a403bfd7a93a3001ef22ef02e3f");
        let mut target_info = Vec::new();
        for (kind, text) in [(2u16, "Domain"), (1u16, "Server")] {
            let v = utf16(text);
            target_info.extend(kind.to_le_bytes());
            target_info.extend((v.len() as u16).to_le_bytes());
            target_info.extend(v);
        }
        target_info.extend([0u8; 4]);
        let c = Challenge { server: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], target_info };
        let nt = nt_response(&ntowf, &c, &[0xaa; 8], 0);
        assert_eq!(hex::encode(&nt[..16]), "68cd0ab851e51c96aabc927bebef6a1c");
    }

    #[test]
    fn xml_lesen() {
        let reply = r#"<s:Body><rsp:Shell><rsp:ShellId>ABC-1</rsp:ShellId></rsp:Shell><w:Selector Name="ShellId">X</w:Selector></s:Body>"#;
        assert_eq!(element(reply, "ShellId"), Some("ABC-1"));
        let recv = r#"<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="1">aGFs</rsp:Stream><rsp:Stream Name="stdout" CommandId="1">bG8=</rsp:Stream><rsp:Stream Name="stdout" CommandId="1" End="true"></rsp:Stream><rsp:Stream Name="stderr" CommandId="1" End="true"/><rsp:CommandState CommandId="1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>3</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>"#;
        assert_eq!(String::from_utf8(streams(recv, "stdout")).unwrap(), "hallo");
        assert!(streams(recv, "stderr").is_empty());
        assert_eq!(element(recv, "ExitCode"), Some("3"));
    }

    #[test]
    fn benutzer_mit_domaene() {
        assert_eq!(split_user("FIRMA\\max"), ("max".into(), "FIRMA".into()));
        assert_eq!(split_user("max@firma.local"), ("max".into(), "firma.local".into()));
        assert_eq!(split_user("admin"), ("admin".into(), String::new()));
    }
}
