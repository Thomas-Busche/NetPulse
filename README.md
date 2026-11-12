# NetPulse – agentenloses Netzwerk-Monitoring

NetPulse findet automatisch alle Geräte in deinen Netzen und prüft sie laufend auf Erreichbarkeit.
Die Ergebnisse zeigt ein konfigurierbares Web-Dashboard. Auf den Zielgeräten muss **nichts
installiert** werden. Alles läuft in Docker, z. B. auf einem NAS oder Raspberry Pi.

| Baustein | Technik |
|---|---|
| Backend, Scanner | Rust (tokio, axum, sqlx) |
| Datenbank | PostgreSQL 17 + TimescaleDB (Zeitreihen, Kompression, automatische Löschfristen) |
| Weboberfläche | HTML/CSS/JavaScript ohne Build-Schritt und ohne externe Abhängigkeiten |
| HTTPS | Caddy mit eigener lokaler Zertifizierungsstelle |

📖 **[Handbuch](docs/HANDBUCH.md)** – Installation, alle Funktionen und Einstellungen, Sicherheit, Sicherung, Fehlersuche.

## Funktionen

- **Sektoren:** Standorte, Filialen, Gebäude oder abgeschottete Netze als Baum (Firma → Filiale → Etage).
  Netze, Geräte, Dienste, Alarmregeln und Wartungsfenster gehören zu einem Sektor; Rechte gelten je Sektor.
- **Leitstand:** Ampel je Sektor, Liste „Jetzt kaputt“ (offline, kritisch, quittiert), Vollbild- und **Kiosk-Modus**
  für Wandbildschirme (Anmeldung mit API-Schlüssel, nur ansehen), Sektoren automatisch durchschalten.
- **Benutzer, Gruppen, Rollen:** frei definierbare Rollen aus feinen Rechten (z. B. „Geräte bearbeiten“, „Alarme
  quittieren“), Zuweisung an Benutzer oder Gruppen – für alle Sektoren oder nur einen. **Zentrale Anmeldung (SSO)**
  über OpenID Connect (Entra ID, Keycloak, Authentik …) mit Gruppenabgleich, **API-Schlüssel** für Skripte.
- **Probes:** ein kleiner NetPulse-Ableger (`netpulse probe`) prüft entfernte Sektoren vor Ort und meldet nur über
  ausgehendes HTTPS – kein VPN, keine Portfreigabe in der Filiale.
- **Läuft in jedem Netz, mit jedem Router:** erkennt die eigenen Netze samt Gateway selbst; ein
  **Einrichtungs-Assistent** führt beim ersten Start durch Netz, Router (über 30 Router-Familien mit passender
  Zugangsart und Anleitung), optionale Zugangsdaten und Benachrichtigung.
- **Geräteerkennung:** Ping, TCP, ARP, Reverse-DNS, 28 typische Ports, **Hersteller aus der MAC-Adresse**
  (IEEE-Liste mit über 40.000 Einträgen) und **automatische Erkennung des Gerätetyps** (Router, Switch, NAS, Drucker,
  Windows-PC, Smartphone, Kamera, Smart Home …) mit passenden Icons.
- **Überwachung:** minütliche Erreichbarkeitsprüfung mit Antwortzeit, Verlauf bis 90 Tage.
- **Tiefe Abfragen ohne Agent** ([Einrichtung](docs/ABFRAGEN.md)):
  - **SNMP v2c/v3:** Schnittstellen und Datenverkehr, CPU, RAM, Speicher, Modell/Seriennummer, Drucker-Füllstände,
    USV-Akku, Synology-Temperatur, LLDP-Nachbarn
  - **SSH (Linux, NAS, Proxmox, Raspberry Pi, Windows mit OpenSSH):** Betriebssystem, Kernel, CPU, RAM, Festplatten,
    Temperaturen, Netzwerk, fehlgeschlagene Dienste, Container, Windows-Updates, Neustart nötig
- **Live-Datenraten** jeder Schnittstelle mit Animation (alle 2 s), Dashboard-Widget **„Internet“** mit Live-Download/-Upload
  (WAN-Erkennung z. B. bei OPNsense über die Standardroute), Verlauf je Schnittstelle.
- **Herstellerprofile:** UniFi (WLANs, Clients je WLAN, Kanalauslastung), Synology (Festplatten, Temperaturen, RAID),
  MikroTik, APC, pf-Firewalls, Sensoren (ENTITY-SENSOR-MIB).
- **Shelly** (Gen1–Gen4): Name, Schaltzustand, Leistung, Energie, Temperatur, Updates; eine Zugangsangabe für alle Shellys.
- **Echtzeit:** Shellys werden alle 5 s abgefragt (einstellbar), die Werte gehen per Server-Sent Events sofort an den Browser –
  Dashboard-Widgets **„Stromverbrauch live“** (mit Verlauf) und **„Smart Home live“** (Kacheln mit Schaltzustand),
  Live-Tab je Gerät, Statuswechsel und **Alarme erscheinen sofort als Hinweis** in der Oberfläche.
- **Such-Zeitplan:** neue Geräte täglich zu festen Uhrzeiten, im festen Abstand oder nur manuell suchen – kein Scan bei jedem Neustart.
- **Dienste** (wie Uptime Kuma): Webseiten mit Suchwort, TLS-Zertifikate (Ablauf, Vertrauen), TCP-Ports, DNS –
  Heartbeat-Balken, Verfügbarkeit 24 h/7/30 Tage, Alarme bei Ausfall oder ablaufendem Zertifikat.
- **Protokolle:** Empfang von **Syslog** (UDP 5514, RFC 3164/5424) und **SNMP-Traps** (UDP 1162, v1/v2c, Namen aus der
  MIB-Datenbank), durchsuchbar, live, Alarmregel „Protokollmeldung“ (z. B. „Failed password“).
- **Wartungsfenster** (einmalig/wöchentlich) und **Abhängigkeiten** (ein Alarm für den Switch statt vieler für die
  Geräte dahinter; automatisch aus UniFi), **Netzwerkkarte** und **öffentliche Statusseite** über geheimen Link.
- **Alarm-Zustellung:** zentraler E-Mail-Server, HTML-Mails mit Vorlagen, Erinnerungen, Sammelmeldungen, Ruhezeiten.
- **Fehlersuche:** Tab **„Diagnose“** je Gerät (jeder Abfrageschritt: SNMP, SSH, Shelly – mit Ursache) und Seite **„System-Log“**.
- **UniFi-Controller** (UniFi OS Server, Dream Machine, Cloud Key) per **API-Schlüssel – auch bei aktiver 2FA**:
  alle Access Points/Switches mit Status, CPU/RAM, Clients, Uplink; Namen und Werte landen automatisch bei den Geräten.
- **Gerätenamen** aus mDNS/Bonjour, NetBIOS, SNMP, SSH, DNS und dem UniFi-Controller.
- **SNMP-Explorer** mit Namen aus ~4.800 MIBs (knapp 960.000 benannte Werte).
- **Alarmierung:** Schweregrad, **Quittieren** mit Kommentar, Regeln je Sektor oder Schlagwort, Benachrichtigung
  von Gruppen (App-Push und E-Mail), **Eskalation** nach X Minuten ohne Quittung, Flatterschutz (`MONITOR_FAIL_THRESHOLD`).
- **Alarme** mit Entwarnung: Gerät offline, neues Gerät im Netz, MAC-/SSH-Schlüssel geändert, Speicher voll,
  CPU/RAM/Temperatur hoch. Versand über **ntfy (Handy-Push), E-Mail, Telegram, Gotify, Discord, Microsoft Teams, Webhook**.
- **Weboberfläche:** modernes Design (hell/dunkel), Geräte als Karten oder Tabelle, Detailseiten mit Diagrammen,
  frei anpassbares Dashboard, Live-Fortschritt beim Scannen, Handy-tauglich.
- **NetPulse-App:** als App aufs Handy installierbar (PWA), **Push-Nachrichten** bei Alarmen, Zugriff von außen über
  den eigenen Reverse-Proxy (z. B. Nginx Proxy Manager) – siehe unten.
- **Sicherheit:** Rollen und Rechte je Sektor, **Zwei-Faktor-Anmeldung (TOTP)**, erneute Passwortabfrage vor kritischen Aktionen, Audit-Log, Zugangsdaten AES-256-verschlüsselt, siehe unten.

Handbuch: [docs/HANDBUCH.md](docs/HANDBUCH.md) · Aufbau und Roadmap: [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md) · Datenschutz und Recht: [docs/DATENSCHUTZ.md](docs/DATENSCHUTZ.md)

---

## Installation mit Portainer (empfohlen)

GitHub baut bei jeder Änderung fertige Images für Intel/AMD und Raspberry Pi
(`ghcr.io/sirbuschi2003/netpulse`). Es muss also nichts kompiliert werden.

1. In Portainer: **Stacks → Add stack**, Name `netpulse`.
2. Build method **Repository** wählen:
   | Feld | Wert |
   |---|---|
   | Repository URL | `https://github.com/Sirbuschi2003/NetPulse` |
   | Repository reference | `refs/heads/main` |
   | Compose path | `deploy/portainer-stack.yml` |
3. Unter **Environment variables** eintragen:
   | Name | Beispiel | Hinweis |
   |---|---|---|
   | `DB_PASSWORD` | `a8f3…` (lang, zufällig) | nur Buchstaben und Ziffern, z. B. von `openssl rand -hex 24` |
   | `SITE_ADDRESS` | `https://192.168.1.10:8443` | IP deines NAS/Pi und Port |
   | `SCAN_NETWORKS` | leer | leer = eigenes Netz automatisch erkennen; sonst z. B. `192.168.1.0/24` |
4. **Deploy the stack**. Nach etwa einer Minute ist NetPulse unter `SITE_ADDRESS` erreichbar.
5. **Anmelden** mit Benutzer `admin` und Passwort `NetPulse-Admin`. Danach verlangt NetPulse sofort ein
   eigenes Passwort (mind. 12 Zeichen) – vorher ist nichts anderes erreichbar.

**Anmeldung klappt nicht?** Das Standardkennwort gilt nur bei einer leeren Datenbank (neues Volume). Notfall:
Container `netpulse-app` → *Console* → `netpulse reset-password admin` (zeigt ein neues Kennwort, das nach der
Anmeldung ebenfalls geändert werden muss).

**Updates:** Stack öffnen → **Pull and redeploy** und dabei *Re-pull image* aktivieren.
Wer es automatisch mag, schaltet im Stack **GitOps updates** ein.

**Port belegt?** („Address already in use“ im Log): NetPulse nutzt das Netzwerk des Hosts direkt.
Ist ein Port schon vergeben, einfach eine zusätzliche Variable setzen:
`APP_PORT` (Standard 18080), `DB_PORT` (Standard 5433) oder für die Weboberfläche
einen anderen Port in `SITE_ADDRESS`.

**Wichtig – Backup:** Das Volume `app-data` enthält den Tresor-Schlüssel `secret.key`. Ohne ihn sind gespeicherte
Zugangsdaten nach einer Neuinstallation nicht mehr lesbar. Also mitsichern (oder `SECRET_KEY` fest vorgeben).

**Stammzertifikat für den Browser** (gegen die Zertifikatswarnung): In Portainer den Container
`netpulse-proxy` öffnen → **Console** → *Connect* → `cat /data/caddy/pki/authorities/local/root.crt`
eingeben, die Ausgabe in eine Datei `netpulse-root.crt` kopieren und wie unten beschrieben importieren.

---

## Installation auf NAS / Raspberry Pi / Linux-Server (ohne Portainer)

**Voraussetzungen:** 64-Bit-Linux mit Docker und Docker Compose
(Raspberry Pi 4/5 mit 64-Bit-Raspberry-Pi-OS, Synology mit Container Manager, QNAP, Unraid, Ubuntu/Debian).
Mindestens 2 GB RAM.

1. Projekt auf das Gerät holen:
   ```bash
   git clone https://github.com/Sirbuschi2003/NetPulse.git
   cd NetPulse
   ```
2. Konfiguration anlegen:
   ```bash
   cp .env.example .env
   ```
   In `.env` mindestens `DB_PASSWORD` und `SITE_ADDRESS` setzen. `SCAN_NETWORKS` kann leer bleiben – dann erkennt NetPulse das eigene Netz samt Router selbst.
3. Starten:
   ```bash
   docker compose up -d --build
   ```
   Der erste Build auf einem Raspberry Pi dauert 15–30 Minuten. Schneller geht es, wenn du das Image
   auf dem PC baust (siehe unten).
4. Im Browser `SITE_ADDRESS` öffnen, z. B. `https://192.168.1.10:8443`.
   Anmelden mit `admin` / `NetPulse-Admin` – danach muss sofort ein eigenes Passwort gesetzt werden.

### Image auf dem PC für den Raspberry Pi bauen

Dafür muss Docker Desktop auf dem PC laufen. Rust musst du nicht installieren.

```bash
docker buildx build --platform linux/arm64 -t netpulse:latest --output type=docker,dest=netpulse-arm64.tar .
```

Die Datei `netpulse-arm64.tar` auf den Pi kopieren und dort laden:

```bash
docker load -i netpulse-arm64.tar
```

Anschließend auf dem Pi `docker compose up -d` ausführen, **ohne** `--build`.
Für Intel/AMD-NAS (z. B. die meisten Synology-Geräte) `linux/amd64` statt `linux/arm64` verwenden.

### Browser-Warnung zum Zertifikat abstellen

Caddy erzeugt eine eigene lokale Zertifizierungsstelle. Ihr Stammzertifikat holst du so:

```bash
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./netpulse-root.crt
```

Unter Windows: Doppelklick auf die Datei → *Zertifikat installieren* → *Lokaler Computer* →
*Vertrauenswürdige Stammzertifizierungsstellen*. In der Firma kann die IT das Zertifikat per
Gruppenrichtlinie verteilen oder ein Zertifikat der firmeneigenen CA verwenden.

---

## Entwicklung & Test unter Windows

```bash
docker compose -f docker-compose.dev.yml up --build
```

Danach https://localhost:8443 öffnen. Docker Desktop sieht das echte Heimnetz nur eingeschränkt
(keine MAC-Adressen). Zum Ausprobieren eignet sich das Docker-interne Netz
(`docker network inspect netpulse-dev_default` zeigt es an).

Rust-Tests und Lints ohne lokale Rust-Installation:

```bash
docker run --rm -v "${PWD}/backend:/src" -w /src rust:1-bookworm cargo test
```

---

## Zugriff von außen & NetPulse-App (Handy)

NetPulse lässt sich wie eine App aufs Handy installieren und schickt Alarme als **Push-Nachricht**. Dafür muss
NetPulse unter einer eigenen Adresse mit **gültigem Zertifikat** erreichbar sein – z. B. über einen vorhandenen
**Nginx Proxy Manager (NPM)** als `https://monitoring.example.de`.

1. **Vorher Zwei-Faktor-Anmeldung einschalten:** *Mein Konto → Zwei-Faktor-Anmeldung → Einrichten* (für alle Konten).
   Ohne 2FA NetPulse nicht ins Internet stellen.
2. **Eingang für den Proxy freigeben:** im Portainer-Stack `PROXY_LISTEN=http://<LAN-IP des Hosts>:18081` setzen
   (z. B. `http://192.168.1.10:18081`) und `PUBLIC_URL=https://monitoring.example.de` (für Links in Nachrichten).
   Port 18081 ist unverschlüsseltes HTTP: **nie am Router freigeben** – ins Internet geht nur NPM (Port 443).
   Ebenso Syslog (5514) und Traps (1162) nie am Router freigeben.
3. **In NPM einen Proxy Host anlegen:**
   - Domain: `monitoring.example.de`, Scheme `http`, Forward Hostname/IP: IP des NAS, Port `18081`
   - **Websockets Support** an, **Block Common Exploits** an
   - Reiter *SSL*: Let's-Encrypt-Zertifikat anfordern, **Force SSL** und **HTTP/2** an, **HSTS** an
   - Der Live-Stream funktioniert ohne weitere Einstellungen (NetPulse sendet `X-Accel-Buffering: no`).
4. Am Router Port 443 zu NPM weiterleiten (falls noch nicht geschehen) und den DNS-Eintrag auf die eigene IP setzen.
5. **App installieren:** `https://monitoring.example.de` auf dem Handy öffnen –
   Android/Chrome: Menü → *App installieren*; iPhone/Safari: *Teilen → Zum Home-Bildschirm*.
   Dann in der App *Mein Konto → Push auf diesem Gerät aktivieren* und die Test-Nachricht senden.
6. Unter **Benachrichtigungen** einen Kanal **„NetPulse-App“** anlegen und in den Alarmregeln auswählen.

Push-Nachrichten sind Ende-zu-Ende verschlüsselt (Web Push, RFC 8291): Die Push-Dienste von Google/Apple/Mozilla
sehen nur den verschlüsselten Inhalt. Alternativ ohne Zugriff von außen: VPN (z. B. WireGuard) zum Heimnetz.

## Konfiguration (`.env`)

| Variable | Standard | Bedeutung |
|---|---|---|
| `DB_PASSWORD` | – (Pflicht) | Passwort der Datenbank; nur Buchstaben und Ziffern |
| `SITE_ADDRESS` | `https://localhost:8443` | Adresse der Weboberfläche |
| `SCAN_NETWORKS` | `auto` | Netze beim ersten Start, z. B. `192.168.1.0/24,10.0.10.0/24`; leer/`auto` = angeschlossene Netze automatisch erkennen (mit anderen Netzen kombinierbar: `auto,10.0.10.0/24`), `off` = keine |
| `INITIAL_ADMIN_USER` / `_PASSWORD` | `admin` / `NetPulse-Admin` | Erstes Admin-Konto (optional; ohne Passwort-Variable muss es nach der ersten Anmeldung geändert werden) |
| `DISCOVERY_INTERVAL_MIN` | 15 | Vorgabe für den Modus „regelmäßig“; der Such-Zeitplan selbst wird unter **Netzwerke** eingestellt (Standard: täglich 03:00, kein Scan beim Neustart) |
| `PROXY_LISTEN` | http://127.0.0.1:18081 | Eingang für einen vorgeschalteten Reverse-Proxy (z. B. `http://:18081` für Nginx Proxy Manager) |
| `SYSLOG_PORT` | 5514 | Syslog-Empfang (UDP), 0 = aus |
| `TRAP_PORT` | 1162 | SNMP-Trap-Empfang (UDP), 0 = aus |
| `TRAP_COMMUNITY` | – | nur Traps mit dieser Community annehmen (mehrere mit Komma) |
| `SYSLOG_ALLOW` | Scan-Netze | von welchen Netzen Syslog/Traps angenommen werden (CIDR, Komma) oder `any` |
| `RETENTION_SYSLOG_DAYS` | 30 | Aufbewahrung der Protokollmeldungen |
| `TZ` | Europe/Berlin | Zeitzone für die Uhrzeiten im Such-Zeitplan |
| `MONITOR_INTERVAL_SEC` | 60 | Abstand der Erreichbarkeitsprüfungen in Sekunden |
| `RETENTION_METRICS_DAYS` | 90 | Aufbewahrung der Messwerte |
| `RETENTION_EVENTS_DAYS` | 180 | Aufbewahrung der Ereignisse |
| `RETENTION_AUDIT_DAYS` | 365 | Aufbewahrung des Audit-Logs |
| `INVENTORY_INTERVAL_MIN` | 5 | Abstand der tiefen Abfragen (SNMP/SSH) |
| `PUBLIC_URL` | = `SITE_ADDRESS` | Adresse für Links in Benachrichtigungen |
| `REQUIRE_TOTP` | false | `true` = alle Benutzer müssen Zwei-Faktor-Anmeldung nutzen (fest); sonst unter **Benutzer** schaltbar |
| `SECRET_KEY` | – (wird erzeugt) | Tresor-Schlüssel (64 Hex-Zeichen), falls nicht aus `/data/secret.key` |
| `DB_PORT` / `APP_PORT` | 5433 / 18080 | Interne Ports auf dem Host (nur 127.0.0.1) |
| `DB_MAX_CONNECTIONS` | 20 | Größe des Datenbank-Verbindungspools (5–500); bei vielen Sektoren/Probes erhöhen |
| `MONITOR_FAIL_THRESHOLD` | 2 | So viele Fehlschläge in Folge, bevor ein Gerät als offline gilt (1–20, Flatterschutz) |

**Probe** (`deploy/probe-stack.yml`, Befehl `netpulse probe`): `NETPULSE_SERVER` (Adresse des Servers, `https://…`) und
`PROBE_TOKEN` (Schlüssel `npp_…`, unter **Netzwerke → Probes** angelegt). Nur zum Testen im LAN: `PROBE_ALLOW_HTTP=true`.

## Sicherheit auf einen Blick

- Von außen erreichbar ist nur HTTPS (Caddy); Datenbank und App lauschen nur auf `127.0.0.1`.
- Die App läuft ohne root-Rechte, mit schreibgeschütztem Dateisystem und nur der Capability `NET_RAW` (für Ping).
- Passwörter werden mit Argon2id gespeichert, Sitzungs-Tokens nur als SHA-256-Hash.
- Zugangsdaten (SNMP, SSH) und Kanal-Geheimnisse werden AES-256-GCM-verschlüsselt gespeichert; der Schlüssel liegt außerhalb der Datenbank.
- SSH-Host-Schlüssel werden beim ersten Kontakt gemerkt, Änderungen stoppen die Abfrage (Schutz vor Man-in-the-Middle).
- SSH-Passwörter werden nie „auf Verdacht“ an fremde Geräte gesendet.
- Cookies sind `HttpOnly`, `Secure` und `SameSite=Strict`; dazu kommt ein CSRF-Header und nach 5 Fehlversuchen eine Login-Sperre
  (in der Datenbank – gilt auch nach einem Neustart).
- Kritische Aktionen (Benutzer, Rollen, Sicherung, Zugangsdaten, Tresor) verlangen eine frische Anmeldung (Passwort erneut, 10 Minuten gültig);
  mit API-Schlüsseln sind sie gar nicht möglich.
- Rechte gelten je Sektor – auch im Live-Stream: Meldungen zu fremden Sektoren werden nicht ausgeliefert.
- Der Tresor-Schlüssel lässt sich unter **Sicherung → Tresor-Schlüssel** tauschen; alle Geheimnisse werden dabei neu verschlüsselt.
- Strenge Content-Security-Policy, HSTS und keine externen Skripte oder CDNs.
- Gescannt werden nur Netze, die ein Admin ausdrücklich freigegeben hat (höchstens /16 je Eintrag).
- Das Audit-Log protokolliert alle Anmeldungen und Änderungen.
- Zwei-Faktor-Anmeldung (TOTP) kann für alle Benutzer vorgeschrieben werden (**Benutzer → Zwei-Faktor-Pflicht** oder `REQUIRE_TOTP=true`).
  Wer sie noch nicht hat, kommt nach der Anmeldung nur an die Einrichtung.
- Auch der Datenbank-Container läuft ohne unnötige Linux-Rechte (`cap_drop: ALL`, nur das für den Start Nötige).
- Die Images werden aus diesem Repository gebaut, mit Sigstore signiert und mit Herkunftsangabe (Provenance) und SBOM versehen;
  alle GitHub-Actions sind auf feste Commits gepinnt. Signatur prüfen:
  ```bash
  cosign verify ghcr.io/sirbuschi2003/netpulse:latest     --certificate-identity-regexp 'https://github.com/Sirbuschi2003/NetPulse/'     --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

## Backup

**In der Oberfläche (empfohlen):** Unter **Verwaltung → Sicherung**
- eine verschlüsselte Sicherung herunterladen (eigenes Passwort, Argon2id + AES-256-GCM),
- eine Sicherung einspielen – auch auf einer neuen Installation; Geräte werden über die IP zugeordnet,
  nichts wird gelöscht und der Messverlauf vorhandener Geräte bleibt erhalten,
- eine tägliche automatische Sicherung einschalten (Dateien unter `/data/backups` im Volume `app-data`;
  bitte zusätzlich auf ein anderes Gerät kopieren).

Enthalten sind alle Einstellungen, Geräte, Zugangsdaten, Benachrichtigungen, Regeln, Dienste, Wartungsfenster,
Benutzer (inkl. 2FA), Dashboards, Statusseite und Energie-Tageswerte – keine Messverläufe und Protokolle.

**Komplette Datenbank inkl. Messverlauf:**

```bash
docker compose exec db pg_dump -U netpulse -p 5433 -h 127.0.0.1 netpulse | gzip > netpulse-backup.sql.gz
```
Dazu gehört dann auch `/data/secret.key` aus dem Volume `app-data` – ohne ihn sind die gespeicherten Zugangsdaten nicht lesbar.

## Projektstruktur

```
backend/            Rust-Quellcode
  migrations/       Datenbankschema (wird beim Start automatisch angewendet)
  src/api/          REST-API (Login, Geräte, Dashboard, Verwaltung)
  src/scanner/      Discovery und Statusprüfung
  src/collect/      Tiefe Abfragen (SNMP, SSH)
  src/alerts/       Alarmregeln und Benachrichtigungen
  data/oui.tsv      Herstellerliste (IEEE)
  src/auth.rs       Passwörter, Sitzungen, Rollen, Brute-Force-Schutz
web/                Weboberfläche (index.html, app.js, style.css)
docs/               Architektur, Datenschutz, Einrichtung der Abfragen, Roadmap
deploy/             Stack-Datei für Portainer (fertige Images)
proxy/              Caddy-Image mit eingebauter Konfiguration
.github/workflows/  Automatische Tests und Image-Builds
Dockerfile          Multi-Arch-Build (amd64 + arm64)
docker-compose.yml  Produktivbetrieb (Host-Netzwerk)
docker-compose.dev.yml  Test unter Windows/macOS
Caddyfile           HTTPS und Sicherheits-Header
```
