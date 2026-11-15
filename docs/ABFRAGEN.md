# Tiefe Abfragen einrichten (SNMP & SSH)

Ohne Zugangsdaten sieht NetPulse, **ob** ein Gerät da ist, welche Dienste es anbietet und wie schnell es antwortet.
Mit SNMP oder SSH kommen **CPU, RAM, Festplatten, Temperaturen, Schnittstellen, Datenverkehr, Toner, USV-Akku,
Betriebssystem, Modell und Seriennummer** dazu.

Grundregeln:
- Immer ein **eigenes Konto nur mit Leserechten** für NetPulse anlegen, nie das Admin-Konto verwenden.
- **SNMP v3** statt v2c (v2c überträgt die Community unverschlüsselt).
- **SSH-Schlüssel** statt Passwort. Schlüssel können auch automatisch bei mehreren Geräten ausprobiert werden,
  Passwörter aus Sicherheitsgründen nicht.
- NetPulse merkt sich beim ersten Kontakt den SSH-Host-Schlüssel. Ändert er sich später, stoppt die Abfrage und es gibt
  einen Sicherheitshinweis (Schutz vor Man-in-the-Middle-Angriffen).

In NetPulse: **Zugangsdaten → Hinzufügen**. Danach öffnet sich automatisch die Geräteauswahl:
- **Testen & zuordnen:** Alle passenden Geräte sind vorausgewählt. NetPulse probiert die Zugangsdaten bei jedem aus und
  ordnet sie nur dort zu, wo die Anmeldung klappt. Das Ergebnis (✓ mit Gerätename bzw. ✗ mit Grund) steht direkt daneben.
- **Testen:** eine Zugangsangabe an einem einzelnen Gerät prüfen, ohne etwas zu ändern.
- **Automatisch:** Neue Geräte werden künftig selbst durchprobiert (SNMP, SSH-Schlüssel, Shelly).

---

## SSH-Schlüssel für NetPulse erzeugen (einmalig)

Auf dem PC (Windows-Terminal, Linux oder macOS):

```bash
ssh-keygen -t ed25519 -C netpulse -f netpulse_key
```

Das erzeugt zwei Dateien:
- `netpulse_key` ist der **private** Schlüssel. Seinen Inhalt kopierst du in NetPulse unter Zugangsdaten → „SSH mit Schlüssel“.
- `netpulse_key.pub` ist der **öffentliche** Schlüssel. Er kommt auf die Zielgeräte (siehe unten).

---

## Linux, Raspberry Pi, Proxmox

```bash
# Benutzer ohne Passwort und ohne sudo-Rechte anlegen
sudo adduser --disabled-password --gecos "" netpulse
sudo mkdir -p /home/netpulse/.ssh
sudo nano /home/netpulse/.ssh/authorized_keys      # Inhalt von netpulse_key.pub einfügen
sudo chown -R netpulse:netpulse /home/netpulse/.ssh
sudo chmod 700 /home/netpulse/.ssh && sudo chmod 600 /home/netpulse/.ssh/authorized_keys
```

Optional, für die Zahl laufender Docker-Container: `sudo usermod -aG docker netpulse`.
Achtung: Mitglieder der Gruppe docker haben faktisch Root-Rechte, das also nur bewusst setzen.

## Synology NAS

**SNMP (einfach, empfohlen):** Systemsteuerung → Terminal & SNMP → SNMP →
„SNMPv3-Dienst aktivieren“, Benutzername und Passwörter setzen, Protokoll SHA/AES.
NetPulse liest dann Modell, DSM-Version, Temperatur, Speicherbelegung und Schnittstellen.

**SSH (mehr Details):** Systemsteuerung → Terminal & SNMP → SSH aktivieren. Einen Benutzer ohne Admin-Rechte anlegen.
Hinweis: Bei Synology dürfen sich per SSH standardmäßig nur Administratoren anmelden. Für den Alltag reicht SNMP.

## QNAP, TrueNAS, Unraid

SNMP v3 in den Systemeinstellungen aktivieren (Netzwerk-/Dienste-Bereich) oder wie bei Linux einen SSH-Benutzer anlegen.

## Windows 10/11 und Windows Server

Windows bringt einen **OpenSSH-Server** mit. NetPulse fragt Windows darüber per PowerShell/CIM ab
(Hardware, Betriebssystem, CPU, RAM, Laufwerke, Netzwerkkarten, letztes Update, gestoppte Dienste).

In einer **PowerShell als Administrator**:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
# Firewall-Regel wird normalerweise automatisch angelegt; sonst:
New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server" -Protocol TCP -LocalPort 22 -Action Allow
```

Lokales Konto für NetPulse (Standardbenutzer, **kein** Administrator):

```powershell
$pw = Read-Host -AsSecureString "Passwort für netpulse"
New-LocalUser -Name netpulse -Password $pw -PasswordNeverExpires -Description "NetPulse Monitoring (nur lesen)"
```

Schlüssel statt Passwort: Inhalt von `netpulse_key.pub` in `C:\Users\netpulse\.ssh\authorized_keys` ablegen.

In der **Firma** lässt sich das per Gruppenrichtlinie oder Intune auf alle Rechner verteilen. Vorher bitte die Hinweise zum
Betriebsrat in [DATENSCHUTZ.md](DATENSCHUTZ.md) beachten.

> **Warum SSH und nicht WinRM?** Der Windows-eigene Fernverwaltungsdienst WinRM braucht für eine sichere Verbindung
> NTLM- oder Kerberos-Verschlüsselung oder ein HTTPS-Zertifikat auf jedem Rechner. OpenSSH ist bei aktuellen
> Windows-Versionen eingebaut, sicher verschlüsselt und funktioniert mit Schlüsseln. WinRM ist für eine spätere Version geplant.

## Switches, Router, Access Points

Fast alle verwalteten Geräte (Cisco, HPE/Aruba, Ubiquiti UniFi, MikroTik, Netgear, TP-Link Omada, Zyxel, Lancom …)
unterstützen SNMP. Im Webinterface unter „SNMP“ **v3** aktivieren, Benutzer mit Leserechten, SHA-256 + AES.
NetPulse liest Schnittstellen (Status, Geschwindigkeit, Datenverkehr), CPU/RAM (falls angeboten), Modell,
Seriennummer und LLDP-Nachbarn.

- **UniFi:** Network-App → Einstellungen → System → SNMP (v3).
- **MikroTik:** `/snmp set enabled=yes` und `/snmp community` bzw. v3-Benutzer anlegen.
- **FRITZ!Box:** unterstützt **kein SNMP**. NetPulse erkennt sie trotzdem als Router und überwacht die Erreichbarkeit.
  Die Abfrage über die FRITZ!Box-Schnittstelle (TR-064) ist geplant.

## Shelly (Steckdosen, Relais, Rollladen, Energiezähler)

NetPulse erkennt Shellys automatisch (Gen1 sowie Gen2/Gen3/Gen4 „Plus/Pro/Mini“) und liest ihren **Namen**,
Schaltzustand, **Leistung (W)**, Zählerstand (kWh), Spannung, Temperatur, WLAN-Signal und verfügbare Updates.

- **Ohne Passwort am Shelly:** Es ist nichts zu tun.
- **Mit Passwort:** unter Zugangsdaten → **„HTTP / Web-Anmeldung (z. B. Shelly)“** einmal Benutzer (`admin`) und Passwort
  eintragen und **„automatisch bei allen passenden Geräten verwenden“** aktivieren. Damit gilt der Eintrag für alle Shellys.
  - Das Passwort geht nur an Geräte, die sich vorher als Shelly ausgewiesen haben.
  - Gen2 und neuer nutzen eine Digest-Anmeldung (SHA-256); das Passwort wird dabei nie im Klartext übertragen.
    Gen1-Geräte kennen nur die einfache Basic-Anmeldung, dort sichert nur das eigene WLAN die Übertragung.
  - Haben Shellys unterschiedliche Passwörter, einfach mehrere Einträge anlegen. NetPulse probiert sie der Reihe nach durch.

Die aktuelle Leistung aller Shellys zeigt das Dashboard-Widget **„Stromverbrauch“**.

## UniFi (UniFi OS Server, Cloud Key, Dream Machine, Cloud Gateway)

NetPulse liest den **UniFi-Controller** aus: alle Access Points, Switches und Gateways mit Status, Modell, Firmware,
CPU/RAM, Uplink-Datenrate, Laufzeit und Anzahl der Clients – plus die Liste der Clients. Die Werte werden automatisch
auf die passenden Geräte in NetPulse übertragen (Zuordnung über die MAC-Adresse): Access Points und Switches bekommen
Namen, Modell, Gerätetyp und Verlaufsdiagramme, Clients ohne eigenen Namen bekommen den Namen aus dem Controller.

**Empfohlen – API-Schlüssel (funktioniert auch mit Zwei-Faktor-Anmeldung):**
1. UniFi Network öffnen → **Einstellungen → Control Plane → Integrations** → **Create API Key**.
2. In NetPulse unter **Zugangsdaten** → Art **„UniFi-Controller (API-Schlüssel)“**, Benutzername leer lassen,
   den Schlüssel ins Feld „API-Schlüssel“ einfügen.
3. Die Zugangsdaten **dem Controller-Gerät zuordnen** (im Zuordnen-Dialog vorausgewählt: Geräte mit Port 11443/8443).

**Alternative – lokales Konto ohne 2FA:** In UniFi OS unter *Admins & Users* ein lokales Konto mit der Rolle
„Nur anzeigen“ anlegen (ohne Zwei-Faktor, *Restrict to local access only*). In NetPulse Benutzername + Passwort eintragen.
Ist beim Konto 2FA aktiv, meldet NetPulse das ausdrücklich – ein 2FA-Code kann nicht automatisch eingegeben werden.

**Clients im Detail:** Beim Controller gibt es die Reiter **„UniFi“** (Access Points/Switches) und **„Clients“**:
Name, IP/MAC, Hersteller, an welchem Access Point bzw. Switch-Port, SSID, Band, Kanal, WLAN-Standard, **Signal (dBm)**,
**Download/Upload gerade**, übertragene Datenmenge und Verbindungsdauer – durchsuch- und sortierbar, jede Minute neu.
Jedes Client-Gerät zeigt in seiner Übersicht die WLAN-Verbindung; Datenraten und Signal landen im **Verlauf**.
Für das Dashboard gibt es die Kacheln **„Top-Verbraucher im Netz“** und **„Schwaches WLAN“**.
Datenraten und Signal je Client liefert UniFi nur über die klassische Schnittstelle. NetPulse versucht sie mit dem
API-Schlüssel; nimmt der Controller ihn dort nicht an, steht im Reiter „Clients“ ein Hinweis – dann das lokale
Nur-Lese-Konto (siehe oben) statt des Schlüssels verwenden.

Ports: UniFi OS Server **11443**, UniFi-OS-Konsolen **443**, ältere Network Application **8443** – NetPulse probiert
zuerst den eingetragenen Port und danach die übrigen. Das (meist selbst signierte) Zertifikat des Controllers wird beim
ersten Kontakt gemerkt; ändert es sich, sendet NetPulse nichts mehr und meldet es („Zertifikat geändert“). Nach einer
Neuinstallation des Controllers beim Gerät unter „Einstellungen“ den gespeicherten Schlüssel zurücksetzen.
Die Zugangsdaten werden nie automatisch ausprobiert, sondern nur an das fest zugeordnete Gerät gesendet.

## Verbundene Geräte von Routern, Switches und Access Points

Wie bei UniFi kann NetPulse von vielen weiteren Geräten lesen, **welche Geräte verbunden sind** – mit Namen,
IP, MAC, Anschluss (Switch-Port bzw. WLAN), WLAN-Signal und Datenrate, soweit das Gerät es hergibt.
Alle Quellen werden je MAC-Adresse zusammengeführt (die aussagekräftigste gewinnt) und erscheinen:

- in der **Geräteliste** (Spalte/Zeile „Verbindung“, Filter nach WLAN/Kabel/Access Point),
- beim Router/Switch/Controller im Reiter **„Verbundene Geräte“**,
- beim einzelnen Gerät in der Übersicht („WLAN-Verbindung laut …“) und im Verlauf (Datenrate, Signal),
- in den Dashboard-Kacheln **„Top-Verbraucher im Netz“** und **„Schwaches WLAN“**.

Geräte, die ein Router kennt, NetPulse aber noch nicht (z. B. aus anderen VLANs), lassen sich in der Geräteliste
mit **„Als Geräte übernehmen“** auf einmal anlegen. Nie wird etwas an den Geräten verändert.

| Quelle | Zugangsart | liefert |
|---|---|---|
| UniFi | UniFi-Controller | alles, inkl. Signal und Datenrate je Client (siehe oben) |
| AVM FRITZ!Box | FRITZ!Box (TR-064) | alle Geräte mit Namen, LAN-Port bzw. WLAN, WLAN-Signal (in %), Geschwindigkeit |
| OPNsense | OPNsense (API-Schlüssel) | alle Geräte **aller VLANs** mit Namen (DHCP), Hersteller, VLAN und **Datenrate** |
| MikroTik | MikroTik RouterOS (REST) | WLAN-Clients mit Signal und Datenrate, Bridge-Port, ARP, DHCP-Namen |
| Linux/OpenWrt-Router und -Access-Points | SSH | WLAN-Stationen mit Signal, Datenrate, SSID, Band; DHCP-Namen; ARP |
| OPNsense/pfSense per SSH | SSH | DHCP-Namen (ISC/Kea/Dnsmasq) und ARP-Tabelle |
| verwaltete Switches (jeder Hersteller) | SNMP | an welchem **Port** ein Gerät hängt (BRIDGE-/Q-BRIDGE-MIB); ARP-Tabelle von Routern |

Datenraten entstehen aus Byte-Zählern und erscheinen daher ab der **zweiten** Abfrage. FRITZ!Box, OPNsense und
MikroTik werden – wie UniFi – **jede Minute** aktualisiert, SSH/SNMP im normalen Abfragetakt (Standard 5 Minuten).

### AVM FRITZ!Box
1. In der FRITZ!Box: **Heimnetz → Netzwerk → Netzwerkeinstellungen → „Zugriff für Anwendungen zulassen“** einschalten.
2. **System → FRITZ!Box-Benutzer → Benutzer hinzufügen** (z. B. „netpulse“, eigenes Passwort, keine weiteren Rechte nötig).
3. In NetPulse unter **Zugangsdaten** → Art **„AVM FRITZ!Box (TR-064)“**, Benutzer + Passwort, Port leer (49000).
4. Zugangsdaten der FRITZ!Box zuordnen („Geräte zuordnen“ → FRITZ!Box auswählen → „Testen & zuordnen“).

Die Anmeldung läuft per HTTP-Digest – das Passwort wird nie im Klartext übertragen. Die WLAN-Signalstärke meldet die
FRITZ!Box in Prozent; NetPulse rechnet sie ungefähr in dBm um (angezeigt mit Hinweis „geschätzt“).
Datenraten je Gerät gibt die FRITZ!Box nicht heraus.

### OPNsense (API)
1. **System → Zugang → Benutzer → +**: Benutzer „netpulse“ (Anmeldung per Oberfläche nicht nötig).
2. **Berechtigungen** (nur lesend): *Diagnostics: ARP Table*, *Reporting: Traffic*, sowie je nach DHCP-Server
   *Services: DHCPv4: Leases* bzw. *Services: Kea DHCP* / *Services: Dnsmasq DNS/DHCP*.
3. Beim Benutzer unter **API-Schlüssel → +** einen Schlüssel erzeugen (Datei mit `key` und `secret` wird heruntergeladen).
4. In NetPulse: Art **„OPNsense (API-Schlüssel)“**, Feld „API-Schlüssel“ = `key`, „API-Secret“ = `secret`, Port leer (443)
   bzw. der Port der OPNsense-Weboberfläche. Der OPNsense zuordnen.

Das (meist selbst signierte) Zertifikat wird beim ersten Kontakt gemerkt; ändert es sich, sendet NetPulse den Schlüssel
nicht mehr. Die Datenrate je Gerät kommt aus „Top Talkers“ aller internen Schnittstellen (WAN wird ausgelassen).

### MikroTik RouterOS 7
1. **System → Users → Groups**: vorhandene Gruppe **„read“** nutzen, Benutzer „netpulse“ anlegen.
2. **IP → Services**: **www-ssl** (Port 443, Zertifikat nötig) oder **www** (Port 80 – nur im LAN verwenden) einschalten,
   am besten mit „Available From“ auf die IP des NetPulse-Hosts beschränkt.
3. In NetPulse: Art **„MikroTik RouterOS (REST-API)“**, Benutzer + Passwort, Port 443 (bzw. 80). Dem Router zuordnen.

Unterstützt werden die WLAN-Pakete „wireless“, „wifi“ (ab 7.13) und CAPsMAN.

### Linux- und OpenWrt-Router/Access-Points (SSH)
Funktioniert automatisch mit den normalen SSH-Zugangsdaten (Schlüssel empfohlen), sobald das Gerät ein
**WLAN im AP-Modus** (`iw`) oder einen **DHCP-Server** (dnsmasq, Kea, ISC) hat. Gelesen werden `iw dev … station dump`,
die Lease-Dateien und `ip neigh`/`arp -an`. Unter OpenWrt: `opkg install iw` (falls nicht vorhanden).

### Verwaltete Switches (SNMP)
Mit normalen SNMP-Zugangsdaten liest NetPulse die Weiterleitungstabelle (BRIDGE-MIB/Q-BRIDGE-MIB) und ordnet jedes
Gerät dem **Port** zu, an dem es direkt hängt. Ports mit mehr als drei MAC-Adressen gelten als Verbindung zu einem
weiteren Switch/Access Point und werden dafür nicht verwendet. Router liefern per SNMP zusätzlich ihre ARP-Tabelle.

## Protokolle: Syslog und SNMP-Traps

NetPulse nimmt Protokollmeldungen per **Syslog (UDP 5514)** und **SNMP-Traps (UDP 1162, v1/v2c)** an.
Als Ziel die IP-Adresse des NetPulse-Hosts eintragen:

- **OPNsense:** System → Einstellungen → Protokollierung → Remote → „+“: Transport UDP(4), Anwendungen nach Wunsch
  (z. B. „filter“, „audit“, „system“), Hostname = NetPulse-IP, Port 5514.
- **UniFi:** Einstellungen → Control Plane → Integrations bzw. System → „Remote Syslog Server“ (Port 5514).
- **Synology:** Protokoll-Center → Protokolle senden → Server = NetPulse-IP, Port 5514, UDP, Format BSD.
- **Linux (rsyslog):** `/etc/rsyslog.d/90-netpulse.conf` mit `*.warning @NETPULSE-IP:5514`.
- **Switches/Drucker/USV:** SNMP-Trap-Ziel = NetPulse-IP, Port 1162, Community wie eingestellt
  (mit `TRAP_COMMUNITY` lässt sich die Annahme auf bestimmte Communities beschränken).

Die Meldungen erscheinen unter **Protokolle** und beim Gerät im Tab **„Protokoll“** (Zuordnung über die Absender-IP).
Mit der Alarmregel **„Protokollmeldung“** gibt es Benachrichtigungen, z. B. bei „Failed password“ oder „linkDown“.
Die Standardports 514/162 würden Root-Rechte im Container erfordern; deshalb 5514/1162.

## Gerätenamen

NetPulse fragt jeden gefundenen Gerätenamen aus mehreren Quellen ab (der erste Treffer zählt):
1. Name aus dem Gerät selbst (Shelly, SNMP `sysName`, SSH-Hostname)
2. **mDNS/Bonjour** (Apple, Drucker, Chromecast, Sonos, ESPHome, Shelly …)
3. **NetBIOS** (Windows-PCs, Samba)
4. DNS-Name (z. B. von der FRITZ!Box)

Ein eigener Anzeigename (Gerät → Einstellungen) hat immer Vorrang.

## Live-Ansicht und SNMP-Explorer

- **Live:** Bei Geräten mit SNMP- oder SSH-Zugang zeigt der Reiter „Live“ die Datenrate jeder Schnittstelle, aktualisiert
  alle 2 Sekunden. Die WAN-Schnittstelle von Routern und Firewalls (z. B. **OPNsense** mit dem Plugin `os-net-snmp`) wird
  über die Standardroute erkannt und im Dashboard-Widget **„Internet“** angezeigt. Falls die Erkennung nicht passt:
  Gerät → Schnittstellen → Schnittstelle anklicken → „Als Internet markieren“.
- **SNMP-Explorer:** liest beliebige Werte eines Geräts, mit Namen aus rund **4.800 MIBs** (IETF/IANA und die Hersteller-MIBs
  der LibreNMS-Sammlung, knapp 960.000 benannte Werte). Suche per OID oder Name, z. B. `ifXTable`, `unifiVapTable` oder
  `enterprises`. Die Namensliste belegt etwa 160 MB in der Datenbank.

## Drucker

Netzwerkdrucker haben SNMP meist schon aktiv (oft v1/v2c mit Community `public`). Dann reicht ein SNMP-v2c-Eintrag
mit Community `public`, am besten fest dem Drucker zugeordnet statt „automatisch“.

NetPulse liest die Standard-Printer-MIB (RFC 3805), die fast alle Netzwerkdrucker kennen (HP, Brother, Canon,
Kyocera, Epson, Lexmark, Ricoh, Xerox …). Im Reiter **System** des Druckers stehen dann:

- Füllstand von Toner bzw. Tinte je Farbe, Trommel, Fixiereinheit und Resttonerbehälter
- Papierfächer mit Papierformat und Füllstand
- Seitenzähler, Druckerstatus (bereit, druckt, wärmt auf) und Störungen wie Papierstau, Klappe offen, kein Papier
- Meldungen, die der Drucker selbst anzeigt, und der Text im Bedienfeld

Manche Drucker melden bei Fremdkartuschen keinen genauen Wert, sondern nur „noch vorhanden“. Das wird so angezeigt.

Für eine Warnung bei wenig Toner unter **Alarme → Regeln** die Regel **Toner/Tinte fast leer** anlegen
(Voreinstellung 15 %). Sie gilt für einen Drucker oder alle, meldet einmal je Drucker und schließt sich nach dem
Kartuschenwechsel von selbst. Die Werte werden bei jeder tiefen Abfrage aktualisiert (`INVENTORY_INTERVAL_MIN`, Standard 5 Minuten).

## USV (APC, Eaton, CyberPower …)

Mit Netzwerkkarte: SNMP v3 im Webinterface der Karte aktivieren. NetPulse liest Ladezustand, Restlaufzeit und
Akkuzustand und erkennt, wenn die USV auf Akkubetrieb läuft.

---

## Docker-Container mit eigener IP (macvlan/ipvlan) auf demselben Host

Läuft ein Gerät als Docker-Container mit **eigener LAN-IP** (Netzwerk-Typ `macvlan` oder `ipvlan`, z. B. ein
UniFi OS Server mit 10.10.10.6) auf **demselben** NAS wie NetPulse, dann kann NetPulse ihn weder anpingen noch
abfragen – obwohl er vom PC aus erreichbar ist. Das ist eine bekannte Eigenschaft von macvlan: Der Host und
seine Container im Host-Netz (wie NetPulse) können Container mit eigener IP auf derselben Netzwerkkarte
nicht erreichen.

**Abhilfe: eine kleine „Brücke“ auf dem Host** (einmal per SSH als root, Werte anpassen):

```bash
# 1. Netzwerkkarte des NAS herausfinden (die mit der NAS-IP, z. B. eth0, bond0 oder br0)
ip -br addr | grep 10.10.10.15

# 2. Brücke anlegen: freie IP im selben Netz wählen (hier 10.10.10.254, nicht im DHCP-Bereich!)
ip link add np-shim link eth0 type macvlan mode bridge
ip addr add 10.10.10.254/32 dev np-shim
ip link set np-shim up
# 3. Den Container (oder das ganze macvlan-Netz) über die Brücke erreichen
ip route add 10.10.10.6/32 dev np-shim
```

Danach sollte `ping 10.10.10.6` auf dem NAS klappen – und NetPulse erreicht den Container.
Die Einstellung geht beim Neustart verloren. Dauerhaft z. B. als systemd-Dienst
`/etc/systemd/system/np-shim.service`:

```ini
[Unit]
Description=Brücke zu macvlan-Containern (NetPulse)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip link add np-shim link eth0 type macvlan mode bridge; ip addr add 10.10.10.254/32 dev np-shim; ip link set np-shim up; ip route add 10.10.10.6/32 dev np-shim'
ExecStop=/bin/sh -c 'ip link del np-shim'

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now np-shim
```

**Alternative:** den Container statt mit eigener IP im normalen Bridge-Netz mit Port-Freigaben betreiben
(dann ist er unter der NAS-IP erreichbar, z. B. `https://10.10.10.15:11443`). Bei UniFi müssen die Geräte
dann allerdings neu auf die NAS-IP „informiert“ werden – die Brücke ist meist einfacher.

## Fehlersuche

| Meldung in NetPulse | Ursache / Lösung |
|---|---|
| „Zeitüberschreitung – Gerät antwortet nicht auf SNMP“ | SNMP aus, falsche Community/Benutzer, Firewall blockiert UDP 161 |
| „SNMPv3-Anmeldung fehlgeschlagen“ | Benutzer, Passwörter oder Protokolle (SHA/AES) stimmen nicht überein |
| „Anmeldung fehlgeschlagen“ (SSH) | Benutzer, Passwort oder Schlüssel falsch; Schlüssel in `authorized_keys`? |
| „Keine Antwort auf Port 22“ | SSH-Dienst aus oder Firewall |
| „SSH-Host-Schlüssel hat sich geändert“ | Gerät neu installiert → in der Geräteansicht „Schlüssel vergessen“. Sonst: möglicher Angriff prüfen! |
