# NetPulse – Handbuch

Dieses Handbuch beschreibt NetPulse vollständig: Installation, Einrichtung, jede Seite der Oberfläche, alle
Einstellungen, Sicherheit, Sicherung und Fehlersuche. Es richtet sich an Anwender ohne Programmierkenntnisse.

Weitere Dokumente:
- [ABFRAGEN.md](ABFRAGEN.md) – Schritt-für-Schritt-Anleitungen, wie man Router, NAS, Switches, Windows, Shelly, UniFi,
  FRITZ!Box, OPNsense und MikroTik für die Abfrage vorbereitet
- [DATENSCHUTZ.md](DATENSCHUTZ.md) – Datenschutz (DSGVO) und rechtliche Hinweise
- [ARCHITEKTUR.md](ARCHITEKTUR.md) – technischer Aufbau (für Entwickler)

---

## Inhalt

1. [Was ist NetPulse?](#1-was-ist-netpulse)
2. [Voraussetzungen](#2-voraussetzungen)
3. [Installation](#3-installation)
4. [Erste Schritte](#4-erste-schritte)
5. [Die Oberfläche im Überblick](#5-die-oberfläche-im-überblick)
6. [Dashboard](#6-dashboard)
7. [Geräte](#7-geräte)
8. [Gerätedetails](#8-gerätedetails)
9. [Netzwerke und Such-Zeitplan](#9-netzwerke-und-such-zeitplan)
10. [Zugangsdaten](#10-zugangsdaten)
11. [Verbundene Geräte (Clients)](#11-verbundene-geräte-clients)
12. [Alarme und Regeln](#12-alarme-und-regeln)
13. [Benachrichtigungen](#13-benachrichtigungen)
14. [NetPulse-App und Push-Nachrichten](#14-netpulse-app-und-push-nachrichten)
15. [Dienste (Webseiten, Ports, Zertifikate)](#15-dienste-webseiten-ports-zertifikate)
16. [Netzwerkkarte und Abhängigkeiten](#16-netzwerkkarte-und-abhängigkeiten)
17. [Energie](#17-energie)
18. [Protokolle (Syslog und SNMP-Traps)](#18-protokolle-syslog-und-snmp-traps)
19. [Statusseite](#19-statusseite)
20. [Wartung](#20-wartung)
21. [Ereignisse, Audit-Log und System-Log](#21-ereignisse-audit-log-und-system-log)
22. [Benutzer, Gruppen, Rollen und Anmeldung](#22-benutzer-gruppen-rollen-und-anmeldung)
23. [Mein Konto](#23-mein-konto)
24. [Sicherung und Wiederherstellung](#24-sicherung-und-wiederherstellung)
25. [Zugriff von außen](#25-zugriff-von-außen)
26. [Sicherheit im Detail](#26-sicherheit-im-detail)
27. [Aktualisieren, Umziehen, Entfernen](#27-aktualisieren-umziehen-entfernen)
28. [Fehlersuche und häufige Fragen](#28-fehlersuche-und-häufige-fragen)
29. [Anhang: Umgebungsvariablen, Ports, Aufbewahrung](#29-anhang-umgebungsvariablen-ports-aufbewahrung)

---

## 1. Was ist NetPulse?

NetPulse ist ein **Netzwerk-Monitoring ohne Agenten**: Es findet die Geräte in deinen Netzen, prüft laufend, ob sie
erreichbar sind, liest – wenn du Zugangsdaten hinterlegst – Details wie CPU, Arbeitsspeicher, Festplatten,
Datenverkehr, WLAN-Clients und Stromverbrauch aus und meldet Probleme per E-Mail, Push-Nachricht oder Messenger.
Auf den überwachten Geräten wird **nichts installiert**.

**Was NetPulse kann – kurz:**

| Bereich | Was passiert |
|---|---|
| Geräteerkennung | Findet Geräte per Ping, TCP und ARP, erkennt Hersteller (aus der MAC-Adresse), Namen (DNS, mDNS, NetBIOS) und Gerätetyp |
| Erreichbarkeit | Prüft jede Minute, misst die Antwortzeit, hält den Verlauf bis zu 90 Tage |
| Tiefe Abfragen | SNMP (Switches, Router, NAS, Drucker, USV), SSH (Linux, NAS, Windows mit OpenSSH), Shelly, UniFi, FRITZ!Box, OPNsense, MikroTik |
| Live-Werte | Datenraten der Schnittstellen alle 2 s, Shelly-Leistung alle 5 s, CPU/RAM live |
| Verbundene Geräte | Welches Gerät hängt an welchem Access Point/Switch-Port, WLAN-Signal, Datenrate je Gerät |
| Dienste | Webseiten, Ports, DNS, TLS-Zertifikate (wie „Uptime Kuma“) |
| Protokolle | Empfang von Syslog-Meldungen und SNMP-Traps |
| Energie | Verbrauch, PV-Erzeugung, Netzbezug, Einspeisung, Autarkie, Kosten – live und als Tages-/Monats-/Jahreswerte |
| Alarme | Regeln für Ausfälle, Schwellwerte, neue Geräte, Sicherheitshinweise, Dienste, Protokollmeldungen |
| Benachrichtigung | E-Mail, NetPulse-App (Push), ntfy, Telegram, Gotify, Discord, Microsoft Teams, Webhook |
| Statusseite | Öffentliche Übersicht über einen geheimen Link, ohne Anmeldung |
| Sicherheit | Rollen, Zwei-Faktor-Anmeldung (auch als Pflicht), verschlüsselte Zugangsdaten, Audit-Log |
| Sicherung | Verschlüsselte Sicherung der Konfiguration, auch automatisch täglich |

**Aufbau:** NetPulse besteht aus drei Docker-Containern:

```
Browser / Handy-App
      │ HTTPS (Port 8443)            ┌──────────────────────────────────┐
      ▼                              │  netpulse-proxy  (Caddy)         │
┌───────────────┐  intern, nur      │  HTTPS, Sicherheits-Header        │
│ netpulse-app  │◄─127.0.0.1:18080──┤  optional Eingang für NPM (18081) │
│ (Rust)        │                   └──────────────────────────────────┘
│ Scanner,      │── Ping/SNMP/SSH/HTTP ──► Geräte im Netz
│ Abfragen,     │◄─ Syslog 5514 / Traps 1162 (UDP) ── Geräte im Netz
│ Alarme, API   │
└──────┬────────┘
       │ intern, nur 127.0.0.1:5433
┌──────▼────────┐
│ netpulse-db   │  PostgreSQL + TimescaleDB (Messwerte, Einstellungen)
└───────────────┘
```

Alle drei Container nutzen das Netzwerk des Hosts direkt (`network_mode: host`), damit der Scanner die Geräte im
Heimnetz sieht. Von außen erreichbar ist nur die HTTPS-Oberfläche.

---

## 2. Voraussetzungen

| | Mindestens | Empfohlen |
|---|---|---|
| Hardware | 64-Bit-Linux-Rechner: NAS (Synology, QNAP, Ugreen, Unraid, TrueNAS), Raspberry Pi 4/5, Mini-PC | 4 GB RAM |
| Arbeitsspeicher | 2 GB | 4 GB |
| Speicherplatz | 2 GB | 10 GB (Messwerte für 90 Tage) |
| Software | Docker und Docker Compose (oder Portainer) | Portainer |
| Netz | Der Host muss die zu überwachenden Netze erreichen | fest vergebene IP für den Host |

**Hinweise:**
- Unter **Windows/macOS mit Docker Desktop** läuft NetPulse zum Ausprobieren, sieht das echte Heimnetz aber nur
  eingeschränkt (keine MAC-Adressen). Für den Dauerbetrieb einen Linux-Host verwenden.
- Überwache **nur eigene Netze** oder Netze, für die du eine ausdrückliche Erlaubnis hast. Das Scannen fremder Netze
  kann strafbar sein (§§ 202a ff. StGB).

---

## 3. Installation

### 3.1 Mit Portainer (empfohlen)

Fertige Images für Intel/AMD und ARM (Raspberry Pi) baut GitHub bei jeder Änderung – es wird nichts kompiliert.

1. In Portainer: **Stacks → Add stack**, Name `netpulse`.
2. **Build method: Repository**:

   | Feld | Wert |
   |---|---|
   | Repository URL | `https://github.com/Sirbuschi2003/NetPulse` |
   | Repository reference | `refs/heads/main` |
   | Compose path | `deploy/portainer-stack.yml` |

3. Unter **Environment variables** mindestens eintragen:

   | Name | Beispiel | Bedeutung |
   |---|---|---|
   | `DB_PASSWORD` | `8f3a…` (lang, zufällig) | Passwort der Datenbank – nur Buchstaben und Ziffern, z. B. aus `openssl rand -hex 24` |
   | `SITE_ADDRESS` | `https://192.168.1.10:8443` | Adresse, unter der du NetPulse im LAN öffnest (IP des Hosts + Port) |
   | `SCAN_NETWORKS` | leer | Netze, die beim ersten Start freigegeben werden (später in der Oberfläche änderbar). Leer = das Netz des Hosts samt Router automatisch erkennen |
   | `INITIAL_ADMIN_PASSWORD` | mind. 12 Zeichen | Passwort des ersten Admins `admin` |

   Alle weiteren Variablen stehen im [Anhang](#29-anhang-umgebungsvariablen-ports-aufbewahrung).
4. **Deploy the stack**. Nach etwa einer Minute ist NetPulse unter `SITE_ADDRESS` erreichbar.

### 3.2 Mit Docker Compose (ohne Portainer)

```bash
git clone https://github.com/Sirbuschi2003/NetPulse.git
cd NetPulse
cp .env.example .env        # DB_PASSWORD und SITE_ADDRESS eintragen (SCAN_NETWORKS optional)
docker compose up -d
```

Ohne `INITIAL_ADMIN_PASSWORD` erzeugt NetPulse ein zufälliges Passwort und schreibt es **nur ins Container-Log**:

```bash
docker compose logs app | grep Passwort
```

### 3.3 Browser-Warnung zum Zertifikat

Im LAN nutzt NetPulse ein Zertifikat einer eigenen lokalen Zertifizierungsstelle. Der Browser warnt deshalb beim ersten
Aufruf. Einmalig das Stammzertifikat importieren:

- **Portainer:** Container `netpulse-proxy` → *Console* → *Connect* →
  `cat /data/caddy/pki/authorities/local/root.crt` → Ausgabe als `netpulse-root.crt` speichern.
- **Compose:** `docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./netpulse-root.crt`
- **Windows:** Doppelklick → *Zertifikat installieren* → *Lokaler Computer* → *Vertrauenswürdige Stammzertifizierungsstellen*.
- **macOS:** Schlüsselbundverwaltung → *System* → Datei hineinziehen → *Immer vertrauen*.
- **Android/iPhone:** Datei öffnen und als CA-Zertifikat installieren (iPhone zusätzlich: *Einstellungen → Allgemein →
  Info → Zertifikatsvertrauenseinstellungen* aktivieren).

Für den Zugriff von unterwegs mit echtem Zertifikat siehe [Kapitel 25](#25-zugriff-von-außen).

### 3.4 Port bereits belegt?

Meldet das Log „Address already in use“, ist ein Port auf dem Host schon vergeben. Abhilfe über Variablen:
`APP_PORT` (Standard 18080), `DB_PORT` (Standard 5433), `SYSLOG_PORT` (5514), `TRAP_PORT` (1162) oder einen anderen
Port in `SITE_ADDRESS`.

---

## 4. Erste Schritte

1. **Anmelden** mit Benutzer `admin` und dem Passwort aus der Installation.
2. **Eigenes Passwort setzen:** *Mein Konto → Passwort ändern* (mind. 12 Zeichen).
3. **Zwei-Faktor-Anmeldung einrichten:** *Mein Konto → Zwei-Faktor-Anmeldung → Einrichten*, QR-Code mit einer
   Authenticator-App scannen (Google/Microsoft Authenticator, Aegis, 2FAS, Bitwarden …), Code eingeben.
   **Pflicht, bevor NetPulse aus dem Internet erreichbar ist.**
4. **Netze prüfen:** *Netzwerke* – die Netze aus `SCAN_NETWORKS` (bzw. bei leerem Wert die automatisch erkannten
   Netze des Hosts) sind freigegeben und werden gleich gescannt. Weitere Netze (z. B. IoT-VLAN) hier hinzufügen oder
   über **Netze erkennen** vorschlagen lassen.
5. **Geräte ansehen:** *Geräte* – nach dem ersten Scan erscheinen alle gefundenen Geräte mit Typ, Hersteller und Status.
   Fehlt ein Gerät (z. B. in einem anderen Netz oder hinter einem VPN): **„Gerät hinzufügen“**.
6. **Zugangsdaten anlegen** für mehr Details: *Zugangsdaten → Hinzufügen*, z. B. SNMP v3 für Switches, SSH-Schlüssel
   für Linux/NAS, Shelly-Passwort, UniFi-API-Schlüssel, FRITZ!Box. Nach dem Speichern öffnet sich
   **„Geräte zuordnen“** – passende Geräte sind vorausgewählt, **„Testen & zuordnen“** prüft sie direkt.
7. **Benachrichtigungen einrichten:** *Benachrichtigungen* – E-Mail-Server und/oder Kanäle (App, ntfy, Telegram …) anlegen,
   mit „Test“ prüfen.
8. **Alarmregeln anlegen:** *Alarme → Regeln → Regel anlegen*, z. B. „Gerät offline“ für wichtige Geräte.
9. **Dashboard anpassen:** *Dashboard → Anpassen* – Kacheln hinzufügen, anordnen, Größe ändern.
10. **Sicherung einrichten:** *Sicherung* – eine Sicherung herunterladen und die tägliche automatische Sicherung einschalten.

---

## 5. Die Oberfläche im Überblick

**Seitenleiste:**

| Übersicht | Verwaltung (nur Admins) |
|---|---|
| Dashboard | Netzwerke |
| Geräte | Zugangsdaten |
| Alarme | Protokolle |
| Dienste | Statusseite |
| Netzwerkkarte | Wartung |
| Energie | Benachrichtigungen |
| Ereignisse | Benutzer, Audit-Log, System-Log, Sicherung |

**Oben rechts:**
- **LIVE-Anzeige** – grün, solange der Live-Stream zum Server steht (Statuswechsel, Alarme und Shelly-Werte kommen sofort).
- **Suchfeld** – Gerät nach Name, IP, MAC oder Hersteller suchen (Enter öffnet die gefilterte Geräteliste).

**Unten in der Seitenleiste:** eigener Benutzername (öffnet *Mein Konto*), Hell/Dunkel-Umschalter, Abmelden.

**Allgemeines:**
- Seiten aktualisieren sich selbst (je nach Seite alle 5 s bis 10 min). **Während du tippst** oder ungespeicherte
  Eingaben hast, wird nichts neu geladen.
- Alarme erscheinen sofort als Hinweis unten rechts, auch wenn du gerade eine andere Seite offen hast.
- Die Oberfläche funktioniert auf dem Handy; die Seitenleiste öffnet sich dort über das Menü-Symbol.
- Rollen: **Administrator** darf alles, **Nur lesen** sieht alles außer Verwaltung und kann nichts ändern.

---

## 6. Dashboard

Das Dashboard ist **je Benutzer** frei zusammenstellbar: **Anpassen** → über „+ Widget hinzufügen“ Kacheln ergänzen
(Liste unten), mit den Pfeilen oder per Ziehen verschieben, Breite umschalten (1/3, 2/3, 3/3), Zahnrad (bei „Gerät“ und
„Energie live“) für die Einstellungen, ✕ zum Entfernen – dann **Speichern** (oder **Abbrechen**).

| Kachel | Inhalt |
|---|---|
| Übersicht | Geräte gesamt, online, offline, offene Alarme, neu in 24 h – jeweils mit Link zur gefilterten Liste |
| Internet | Live-Download/-Upload der Internet-Schnittstelle (WAN) mit Verlauf; WAN wird automatisch erkannt (z. B. OPNsense-Standardroute) |
| Energie live | Verbrauch, PV-Erzeugung, Netzbezug/Einspeisung; Zahnrad: Geräteauswahl, Hauptzähler, Rolle je Gerät (siehe [Kapitel 17](#17-energie)) |
| Smart Home live | Kacheln aller Shellys mit Schaltzustand und Leistung (live) |
| Dienste | Status aller Dienste (Webseiten, Ports, Zertifikate) |
| Offene Alarme | Aktuell ausgelöste Alarme |
| Nicht erreichbar | Geräte, die gerade offline sind |
| Gerätetypen | Verteilung der Geräte nach Typ |
| Letzte Ereignisse | Online/offline, neue Geräte, Sicherheitshinweise |
| Verteilung | Online/offline/unbekannt als Diagramm |
| Dienste im Netz | Welche Dienste (Ports) im Netz am häufigsten angeboten werden |
| Neu entdeckt (7 Tage) | Geräte, die neu im Netz sind |
| Langsamste Antwortzeiten | Geräte mit der höchsten Antwortzeit |
| Top-Verbraucher im Netz | Geräte mit der höchsten aktuellen Datenrate (aus UniFi, OPNsense, MikroTik, Access Points) |
| Schwaches WLAN | WLAN-Geräte mit schlechtem Empfang (schwächer als −70 dBm) |
| Gerät | Ein Gerät deiner Wahl – mehrere Messwerte gleichzeitig wählbar: Antwortzeit & Verfügbarkeit, CPU, RAM, Speicher, Temperatur, Netzwerk-Verlauf, Internet live, Datenraten live, Stromverbrauch, Clients |

Über jeder Kachel steht der Titel; ein Klick auf Werte führt meist zur passenden Detailseite.

**Geteilte Ansichten:** Wer Einstellungen verwalten darf, kann ein Dashboard-Layout als Ansicht speichern, für alle
freigeben und als **Standard** markieren – Benutzer ohne eigenes Layout sehen dann diese Ansicht. Über den Sektor-Filter
zeigt das Dashboard nur die Werte eines Sektors.

### 6.1 Leitstand und Kiosk

Der **Leitstand** ist die Übersicht für Bereitschaft und Wandbildschirm:

- **Ampel je Sektor** (rot = Störung, gelb = Warnung, blau = Wartung, grün = in Ordnung) mit Zahl der Geräte, Ausfälle
  und offenen Alarme; ein Klick filtert die Liste.
- **„Jetzt kaputt“:** alle Geräte offline, ausgefallene Dienste und offene Alarme, nach Schweregrad sortiert;
  quittierte Alarme sind markiert (wer, wann, Kommentar).
- **Vollbild** und **Sektoren durchschalten** (alle 20 s der nächste Sektor) für Bildschirme in der Leitwarte.

**Kiosk-Modus:** Unter *Mein Konto → API-Schlüssel* einen Schlüssel anlegen und am Bildschirm auf der Anmeldeseite
**„Als Leitstand-Bildschirm anmelden“** wählen. Die Kiosk-Sitzung kann nur ansehen (auch wenn das Konto mehr dürfte)
und öffnet direkt den Leitstand.

---

## 7. Geräte

### 7.1 Geräteliste

- **Ansicht:** Karten oder Tabelle (Umschalter oben rechts; wird gemerkt).
- **Filter:** Freitext (Name, IP, MAC, Hersteller, Port, Access Point, SSID), Status (online/offline/unbekannt/nicht
  überwacht/neu), Gerätetyp und – sobald eine Quelle für verbundene Geräte eingebunden ist – **Verbindung**
  (nur WLAN, nur Kabel, an einem bestimmten Access Point/Switch).
- **Verbindung:** Karten und Tabelle zeigen, woran ein Gerät hängt (Access Point/Switch-Port), das WLAN-Signal und die
  aktuelle Datenrate – aus UniFi, FRITZ!Box, OPNsense, MikroTik, Access Points oder Switches.
- **Symbole:** ⚠ = die letzte tiefe Abfrage schlug fehl (Details im Reiter *Diagnose*), 🔑 = Zugangsdaten zugeordnet,
  Watt-Anzeige bei Strommessern (live).

### 7.2 Gerät von Hand hinzufügen

**Geräte → Gerät hinzufügen** (nur Admin): IP-Adresse oder Hostname, optional Name, Gerätetyp, Zugangsdaten und Notiz.
NetPulse untersucht das Gerät sofort wie beim Scan (Ports, Namen, Hersteller, Shelly) und überwacht es.
Funktioniert auch für Geräte **außerhalb der Scan-Netze** (andere Standorte per VPN, Server im Internet).

### 7.3 Geräte aus Routern übernehmen und aufräumen

Kennen UniFi, FRITZ!Box, OPNsense, MikroTik oder ein Access Point Geräte, die NetPulse noch nicht hat (typisch: andere
VLANs, die nicht gescannt werden), erscheint über der Liste ein Hinweis mit **„Ansehen & auswählen“**. Die Liste zeigt
Name, IP/MAC und Quelle; **mögliche Doppelte** (gleicher Name wie ein vorhandenes Gerät – z. B. ein Handy mit wechselnder
„privater WLAN-Adresse“) sind markiert und nicht vorausgewählt. **„Ausgewählte übernehmen“** legt sie an.
Reine ARP-Einträge (nur IP ↔ MAC, oft veraltet oder Docker-intern) werden bewusst nie angeboten.

Sind übernommene Geräte offline oder doppelt, erscheint **„Aufräumen“**: Die Liste zeigt alle übernommenen Geräte,
offline und doppelte sind vorausgewählt, **„Ausgewählte löschen“** entfernt sie.

### 7.4 Gerätetyp und Namen

- Der **Typ** wird automatisch erkannt (Ports, Hersteller, Hostname, SNMP/SSH-Daten, UniFi-Modell). Falsch? Beim Gerät
  unter *Einstellungen* von Hand setzen – „(manuell)“ bleibt dann fest.
- Der **angezeigte Name** ist in dieser Reihenfolge: eigener Name → vom Gerät gemeldeter Name (SNMP, SSH, Shelly, UniFi,
  FRITZ!Box, DHCP) → DNS-Name → IP.

---

## 8. Gerätedetails

Oben: Symbol, Name, Status, Typ, IP, Hersteller, Betriebssystem/Modell. Rechts **„Jetzt abfragen“** (startet die tiefe
Abfrage sofort) und „Alle Geräte“. Welche Reiter erscheinen, hängt davon ab, was über das Gerät bekannt ist.

| Reiter | Inhalt |
|---|---|
| **Übersicht** | Details (IP, MAC, Hersteller, Hostname, Antwortzeit, Status seit, erstmals/zuletzt gesehen, Dienste/Ports, Notizen), Messwerte (CPU, RAM, Speicher, Temperatur, Leistung, Clients), **Verbindung laut UniFi/FRITZ!Box/…** (Access Point, WLAN, Signal, Geschwindigkeit, Datenrate), Antwortzeit-Diagramm mit Verfügbarkeit (Ausfälle rot hinterlegt) |
| **Live** | Datenraten aller Schnittstellen alle 2 s (SNMP/SSH) mit CPU/RAM live; bei Shellys Leistung, Schaltzustand, Energie in Echtzeit |
| **UniFi** | nur beim UniFi-Controller: alle Access Points/Switches mit Status, Modell, IP, Clients, CPU, RAM, Uplink, Laufzeit, Firmware |
| **Verbundene Geräte** | bei Controllern, Routern, Switches, Access Points: alle verbundenen Geräte mit Suche, Filtern und Sortierung (siehe [Kapitel 11](#11-verbundene-geräte-clients)) |
| **System** | Betriebssystem, Kernel, Hardware, Seriennummer, Laufzeit, Sensoren, Drucker-Füllstände, USV, Synology-Details, Shelly-Kanäle, WLAN-Verbindung laut Controller |
| **Schnittstellen** | alle Netzwerk-Schnittstellen mit Status, Geschwindigkeit, Datenverkehr und Verlauf je Schnittstelle |
| **Speicher** | Festplatten/Volumes mit Belegung |
| **Verlauf** | Diagramme über 24 h / 7 / 30 / 90 Tage: Antwortzeit & Ausfälle, Auslastung, Leistung, Clients, Datenverkehr (bei Clients: Download/Upload), WLAN-Signal, Temperatur |
| **Ereignisse** | online/offline, neu, MAC geändert, Dienste … |
| **SNMP-Explorer** | (Admin, SNMP) beliebige Werte des Geräts lesen – mit Namen aus ~4.800 MIBs |
| **Diagnose** | jede Abfrage Schritt für Schritt: welche Zugangsdaten probiert wurden, was klappte, was nicht – mit Erklärung und Tipp |
| **Protokoll** | (Admin) Syslog-Meldungen und Traps dieses Geräts der letzten 7 Tage |
| **Einstellungen** | (Admin) siehe unten |

**Einstellungen eines Geräts:**

| Einstellung | Wirkung |
|---|---|
| Name, Notizen | eigener Anzeigename, freie Notiz |
| Überwachen | aus = keine Erreichbarkeitsprüfung, keine Alarme (Gerät bleibt in der Liste) |
| Gerätetyp | automatisch oder fest |
| Internet-Schnittstelle | welche Schnittstelle der Internet-Anschluss ist (für die Kachel „Internet“); automatisch oder fest |
| Hängt ab von | übergeordnetes Gerät (Switch, Access Point, Router) – für Abhängigkeiten und Netzwerkkarte; automatisch (aus UniFi/Routern/Switches), keins oder fest |
| Rolle der Strommessung | Verbrauch, Erzeugung (PV/Balkonkraftwerk) oder Netz-Zähler (nur bei Strommessern) |
| Zugangsdaten | welche Zugangsdaten für die tiefe Abfrage verwendet werden, „Zuordnen & abfragen“ |
| Gemerkte Schlüssel vergessen | SSH-Host-Schlüssel bzw. TLS-Zertifikat neu lernen – nur nach einer Neuinstallation des Geräts |
| Gerät löschen | entfernt das Gerät mit allen Messwerten (ein neuer Scan findet es ggf. wieder) |

---

## 9. Netzwerke und Such-Zeitplan

**Netzwerke** (nur Admin):

- **Freigegebene Netze:** Nur diese Netze werden nach Geräten durchsucht (CIDR-Schreibweise, z. B. `192.168.1.0/24`,
  höchstens `/16` je Eintrag). Pro Netz: Anzahl Geräte, letzter Scan, **Jetzt scannen**, **Entfernen** (gefundene
  Geräte bleiben erhalten).
- **Netz hinzufügen:** CIDR und Name – das neue Netz wird sofort gescannt.
- **Netze erkennen:** schlägt die Netze vor, in denen NetPulse selbst eine Adresse hat – mit dem Router aus der
  Routing-Tabelle als Gateway. Für einen Sektor mit Probe kommen die Vorschläge von der Probe vor Ort. Docker-, VPN-
  und VM-Netze werden übersprungen; ein größeres Netz als `/16` wird auf das `/24` um die eigene Adresse begrenzt.
  **Übernehmen** trägt das Netz ein und scannt es sofort.
- **Alle scannen:** startet einen vollständigen Suchlauf.

> **Jedes Netz, jeder Router:** NetPulse braucht kein Wissen über Adressbereich oder Router-Hersteller. Das Gerät,
> das als Gateway eines Netzes eingetragen bzw. erkannt ist, gilt automatisch als Router – auch ohne bekannten
> Hersteller oder Namen. Für mehr Details (verbundene Geräte, WLAN, Datenraten) einen passenden Zugang hinterlegen:
> FRITZ!Box, OPNsense, MikroTik oder UniFi über ihre API, alle anderen Router (OpenWrt, pfSense, DrayTek, LANCOM,
> Cisco, Provider-Router mit SNMP …) über SNMP oder SSH.

**Such-Zeitplan:**

| Modus | Bedeutung |
|---|---|
| Täglich zu festen Uhrzeiten | z. B. 03:00 (Standard) – mehrere Uhrzeiten möglich |
| Regelmäßig im festen Abstand | z. B. alle 60 Minuten |
| Nur manuell | nur „Alle scannen“ bzw. neue Netze |

„Beim Start scannen“ ist standardmäßig aus – ein Neustart löst also keinen Suchlauf aus. Verpasste Termine (z. B. Host
war aus) werden einmal nachgeholt. Die Uhrzeiten gelten in der Zeitzone `TZ` (Standard Europe/Berlin).

Die **Erreichbarkeitsprüfung** bekannter Geräte läuft unabhängig davon jede Minute (`MONITOR_INTERVAL_SEC`).

**Echtzeit (Shelly):** Hier lässt sich die schnelle Abfrage der Shellys ein-/ausschalten und der Takt einstellen
(Standard 5 s).

Jedes Netz gehört zu einem **Sektor** und kann VLAN, Gateway, Beschreibung und einen **eigenen Such-Zeitplan** haben
(Stift-Symbol in der Liste). Netze lassen sich auch einzeln abschalten, ohne sie zu löschen.

### 9.1 Sektoren

Unter **Sektoren** wird das Netz in Standorte oder Bereiche gegliedert – als Baum, z. B. *Firma → Filiale Nord → Lager*.
Netze, Geräte, Dienste, Alarmregeln und Wartungsfenster gehören jeweils zu einem Sektor. Neu gefundene Geräte landen im
Sektor ihres Netzes; Geräte lassen sich von Hand oder gesammelt in einen anderen Sektor verschieben.

Rechte gelten je Sektor (siehe [Kapitel 22](#22-benutzer-gruppen-rollen-und-anmeldung)): Wer nur für „Filiale Nord“
berechtigt ist, sieht nur deren Geräte, Alarme, Dienste und Live-Meldungen. Ein Recht auf einen Sektor gilt auch für
dessen Unter-Sektoren. Der Sektor **Hauptstandort** ist immer vorhanden und nimmt alles auf, was keinem anderen
Sektor zugeordnet ist.

### 9.2 Probes für entfernte Sektoren

Liegt ein Sektor hinter einer Firewall oder in einer Filiale, die der Server nicht direkt erreicht, übernimmt eine
**Probe** die Suche und Prüfung vor Ort. Sie braucht nur **ausgehend HTTPS** zum NetPulse-Server – keine
Portfreigabe, kein VPN.

1. **Netzwerke → Probes für entfernte Sektoren:** Name und Sektor wählen, **Probe anlegen**. Der Schlüssel (`npp_…`)
   wird nur einmal angezeigt.
2. In der Filiale den Stack `deploy/probe-stack.yml` starten (z. B. in Portainer) mit
   `NETPULSE_SERVER=https://monitoring.example.de` und `PROBE_TOKEN=npp_…`.
3. Nach spätestens einer Minute steht die Probe auf **verbunden**.

Die Probe holt sich regelmäßig die Netze und Geräte ihres Sektors, prüft die Erreichbarkeit im Takt von
`MONITOR_INTERVAL_SEC`, sucht die Netze im Takt der Gerätesuche ab und meldet alles zurück. Der Server prüft Sektoren
mit Probe dann nicht mehr selbst. Eine Probe darf nur Ergebnisse für ihren eigenen Sektor melden. Ist ihr Schlüssel in
falsche Hände geraten: **Schlüssel-Symbol → neuen Schlüssel erzeugen** (der alte gilt sofort nicht mehr) oder Probe abschalten.

Tiefe Abfragen (SNMP, SSH, Shelly) laufen weiterhin vom Server aus; die Probe übernimmt Suche und Erreichbarkeit.

---

## 10. Zugangsdaten

Für Details über Erreichbarkeit hinaus braucht NetPulse Lesezugriff auf die Geräte. **Verwende eigene Konten mit
reinen Leserechten** – NetPulse führt nur lesende Abfragen aus. Einrichtung je Gerät: [ABFRAGEN.md](ABFRAGEN.md).

| Art | Für | Hinweis |
|---|---|---|
| SNMP v2c | Switches, Router, Drucker, USV, NAS | Community geht unverschlüsselt übers Netz – nur gezielt zuordnen |
| SNMP v3 (empfohlen) | dito | Benutzer, SHA-256 + AES-128 empfohlen |
| SSH mit Schlüssel (empfohlen) | Linux, NAS, Proxmox, Pi, OpenWrt, OPNsense, Windows (OpenSSH) | Schlüssel erzeugen siehe ABFRAGEN.md |
| SSH mit Passwort | dito | wird **nie automatisch** ausprobiert, nur an ausgewählte Geräte |
| HTTP / Web-Anmeldung | Shelly | geht nur an Geräte, die sich als Shelly ausgewiesen haben (Gen2+ per Digest) |
| UniFi-Controller | UniFi OS Server, Dream Machine, Cloud Key | API-Schlüssel (funktioniert mit 2FA) oder lokales Konto |
| AVM FRITZ!Box | FRITZ!Box | TR-064, Digest-Anmeldung |
| OPNsense | OPNsense-Firewall | API-Schlüssel + Secret eines Nur-Lese-Benutzers |
| MikroTik | RouterOS 7 | REST-API, Benutzer der Gruppe „read“ |

**Automatisch vs. zugeordnet:**
- **„Automatisch bei allen passenden Geräten verwenden“** (SNMP v3, SSH-Schlüssel, Shelly): NetPulse probiert die
  Zugangsdaten bei passenden Geräten selbst aus und ordnet sie bei Erfolg fest zu.
- **Fest zugeordnet** (immer bei SSH-Passwort, SNMP v2c, UniFi, FRITZ!Box, OPNsense, MikroTik): Die Zugangsdaten gehen
  nur an die Geräte, die du auswählst.

**Geräte zuordnen:** Beim Anlegen oder über **„Geräte“** bei den Zugangsdaten. Die Liste lässt sich durchsuchen und nach
Typ filtern; passende Geräte sind vorausgewählt. **„Testen & zuordnen“** prüft jedes Gerät und ordnet nur zu, wo die
Anmeldung klappt – das Ergebnis steht je Gerät daneben. **„Ohne Test speichern“** ordnet direkt zu.

**„Testen“** bei einer Zugangsangabe prüft gegen ein ausgewähltes Gerät, ohne zuzuordnen.

Zugangsdaten werden **AES-256-GCM-verschlüsselt** gespeichert und nie wieder angezeigt; beim Bearbeiten bleiben leere
Geheimnis-Felder unverändert.

---

## 11. Verbundene Geräte (Clients)

NetPulse sammelt aus mehreren Quellen, **welche Geräte wo verbunden sind**:

| Quelle | liefert |
|---|---|
| UniFi-Controller | WLAN/Kabel, Access Point bzw. Switch-Port, SSID, Band, Kanal, WLAN-Standard, Signal (dBm), Verbindungsqualität, Verbindungsgeschwindigkeit, **Download/Upload**, übertragene Datenmenge, Netz/VLAN, Gast |
| FRITZ!Box | alle aktiven Geräte mit Namen, LAN-Port bzw. WLAN, SSID/Kanal, **Signal** (in %, in dBm umgerechnet), Geschwindigkeit |
| OPNsense | alle Geräte aller VLANs mit Namen (DHCP), Hersteller, VLAN und **Datenrate** (Top Talkers) |
| MikroTik | WLAN-Clients mit Signal und **Datenrate**, Bridge-Port, ARP, DHCP-Namen |
| Linux/OpenWrt-Access-Points (SSH) | WLAN-Stationen mit Signal, **Datenrate**, SSID, Band, Verbindungsdauer; DHCP-Namen; ARP |
| Switches (SNMP) | an welchem **Port** ein Gerät direkt hängt |
| Router (SSH/SNMP) | ARP-Tabelle und DHCP-Leases (IP, MAC, Name) |

**Zusammenführung:** Einträge werden je MAC-Adresse zusammengeführt. Pro Angabe gewinnt die aussagekräftigste Quelle
(UniFi vor MikroTik vor FRITZ!Box vor Access Point vor OPNsense vor Switch vor ARP/DHCP). Ein Gerät kann so z. B. den
Namen von der FRITZ!Box, das VLAN von OPNsense und Signal/Datenrate von UniFi bekommen.

**Wo erscheint was?**
- **Geräteliste:** Verbindung, Signal und Datenrate je Gerät, Filter nach WLAN/Kabel/Access Point.
- **Reiter „Verbundene Geräte“** beim Controller/Router/Switch: Kennzahlen (Clients, im WLAN, per Kabel, gesamte
  Datenrate), Suche, Filter nach Verbindung und Access Point, Sortierung per Klick auf die Spaltenüberschrift.
  Ein Klick auf die Client-Zahl eines Access Points im Reiter *UniFi* filtert direkt darauf.
- **Gerät → Übersicht:** Kasten „WLAN-Verbindung laut …“ mit allen Angaben und den Quellen.
- **Gerät → Verlauf:** Download/Upload und WLAN-Signal über die Zeit.
- **Dashboard:** Kacheln „Top-Verbraucher im Netz“ und „Schwaches WLAN“.

**Aktualisierung:** UniFi, FRITZ!Box, OPNsense und MikroTik jede Minute; SSH und SNMP im normalen Abfragetakt
(`INVENTORY_INTERVAL_MIN`, Standard 5 Minuten). Datenraten aus Byte-Zählern entstehen ab der zweiten Abfrage.

**Signal-Bewertung:** besser als −60 dBm = sehr gut, bis −67 dBm = gut, bis −75 dBm = mäßig, darunter = schwach.
Zusätzlich zur Farbe zeigen vier Balken und der Zahlenwert die Qualität.

**UniFi – Datenraten je Client fehlen?** Die gibt UniFi nur über die ältere Schnittstelle heraus. NetPulse versucht sie
mit dem API-Schlüssel; nimmt der Controller ihn dort nicht an, erscheint im Reiter ein Hinweis. Abhilfe: in UniFi ein
lokales Konto mit Rolle „Nur ansehen“ und „Auf lokalen Zugriff beschränken“ (ohne 2FA) anlegen und bei den
Zugangsdaten Benutzername + Passwort statt des Schlüssels eintragen.

---

## 12. Alarme und Regeln

**Alarme → Offene Alarme:** alle aktuellen Alarme mit Status, Meldung, Regel, ausgelöst/behoben. Behobene Alarme bleiben
zur Nachverfolgung sichtbar.

**Alarme → Regeln → Regel anlegen** (Admin). Die Arten sind nach Themen gruppiert:

| Gruppe | Art | Parameter |
|---|---|---|
| Geräte | Gerät offline | Gerät (oder alle), Dauer in Minuten |
| | CPU-Auslastung hoch | Schwelle in %, Dauer |
| | RAM-Auslastung hoch | Schwelle in %, Dauer |
| | Speicher fast voll | Schwelle in % |
| | Temperatur hoch | Schwelle in °C |
| Dienste | Dienst ausgefallen | Dienst (oder alle) |
| | Zertifikat läuft ab | Dienst, Tage vor Ablauf |
| Protokolle | Protokollmeldung (Syslog/Trap) | Suchtext (leer = alle), Mindest-Stufe, Gerät |
| Sicherheit & Netz | Neues Gerät im Netz | – |
| | Sicherheitshinweis (MAC/SSH-Schlüssel geändert) | – |

**Für alle Regeln:**
- **Bereich:** nur ein Sektor (samt Unter-Sektoren) und/oder nur Geräte mit einem bestimmten **Schlagwort** (z. B. `kritisch`, `server`).
- **Schweregrad:** Kritisch, Warnung oder Hinweis (Standard je nach Art); bestimmt Sortierung, Ton und Push-Priorität.
- **Gruppen benachrichtigen:** Mitglieder bekommen App-Push und E-Mail (über den zentralen E-Mail-Server).
- **Eskalation:** Ist ein Alarm nach X Minuten nicht quittiert, gehen weitere Kanäle bzw. Gruppen los (einmal je Alarm).
- **Kanäle:** wohin gemeldet wird (siehe [Kapitel 13](#13-benachrichtigungen)). Ohne Kanal erscheint der Alarm nur in NetPulse.
- **Entwarnung senden:** meldet, wenn das Problem vorbei ist.
- **Erinnern, solange der Alarm besteht – alle … Minuten** (0 = nie).
- **Aktiv:** Regel vorübergehend ausschalten, ohne sie zu löschen.
- Geräte- und Dienst-Auswahl lassen sich durchsuchen.

**Quittieren:** Mit dem Haken in der Alarmliste (oder im Leitstand) übernimmt man einen Alarm – optional mit
Kommentar („Techniker ist unterwegs“). Quittierte Alarme erinnern nicht mehr und eskalieren nicht; die Quittung lässt
sich zurücknehmen. Dafür braucht es das Recht *Alarme quittieren* im Sektor des Alarms.

**Flatterschutz:** Ein Gerät gilt erst nach `MONITOR_FAIL_THRESHOLD` Fehlschlägen in Folge (Standard 2) als offline –
ein einzelner verlorener Ping löst keinen Alarm aus.

**Intelligente Unterdrückung:**
- **Abhängigkeiten:** Fällt ein Switch aus, kommt *ein* Alarm für den Switch – nicht einer für jedes Gerät dahinter
  (die Meldung nennt die Zahl der betroffenen Geräte). Grundlage ist „Hängt ab von“ ([Kapitel 16](#16-netzwerkkarte-und-abhängigkeiten)).
- **Wartungsfenster:** Während einer Wartung werden für die betroffenen Geräte/Dienste keine Alarme verschickt ([Kapitel 20](#20-wartung)).
- **Protokollmeldungen:** Viele Treffer werden je Gerät zusammengefasst (höchstens 5 einzelne Meldungen, dann eine Zusammenfassung).

---

## 13. Benachrichtigungen

### 13.1 Zentraler E-Mail-Server

*Benachrichtigungen → E-Mail-Server:* SMTP-Server, Port, Verschlüsselung (STARTTLS/TLS/keine), Benutzer, Passwort,
Absender. **„Test-Mail senden“** prüft die Einstellungen. Alle E-Mail-Kanäle nutzen diesen Server, sofern sie keinen
eigenen haben.

### 13.2 Kanäle

| Kanal | Einrichtung |
|---|---|
| **NetPulse-App** | Push aufs Handy/den PC, auf dem unter *Mein Konto* Push aktiviert wurde ([Kapitel 14](#14-netpulse-app-und-push-nachrichten)) |
| **E-Mail** | Empfänger (mehrere mit Komma), Betreff- und Text-Vorlage, optional eigener SMTP-Server |
| **ntfy** | Server (z. B. `https://ntfy.sh`), langes zufälliges Thema, optional Token; App „ntfy“ installieren, Thema abonnieren |
| **Telegram** | Bot bei @BotFather anlegen, Bot-Token und Chat-ID (z. B. über @userinfobot) |
| **Gotify** | Server-URL und App-Token |
| **Discord** | Webhook-URL des Kanals |
| **Microsoft Teams** | Kanal → Workflows → „Beim Empfang einer Webhookanforderung in einem Kanal posten“ → URL |
| **Webhook** | eigene URL; optionales Geheimnis kommt im Header `X-NetPulse-Secret` |

**„Test“** bei jedem Kanal schickt eine Probenachricht.

### 13.3 Vorlagen (E-Mail)

Platzhalter für Betreff und Text: `{{titel}}`, `{{meldung}}`, `{{schwere}}`, `{{geraet}}`, `{{ip}}`, `{{regel}}`,
`{{wert}}`, `{{zeit}}`, `{{link}}`. Zeilen, deren Platzhalter leer ist (z. B. „Wert:“), werden weggelassen.
Die Mail kommt als übersichtliche HTML-Nachricht mit Textfassung; `{{link}}` führt direkt zum Gerät
(dafür `PUBLIC_URL` setzen).

### 13.4 Zustellung (für jeden Kanal)

| Einstellung | Wirkung |
|---|---|
| Sammeln: … Minuten bündeln | statt vieler Einzelmeldungen eine Sammelmeldung (0 = sofort) |
| Ruhezeit von/bis | z. B. 22:00–07:00 – Meldungen werden danach zugestellt |
| Kritische Alarme trotz Ruhezeit sofort | z. B. „Gerät offline“ kommt auch nachts |

Zugangsdaten der Kanäle (Tokens, Passwörter) werden verschlüsselt gespeichert und nicht wieder angezeigt.
Wird der Server eines Kanals geändert, müssen die Geheimnisse neu eingegeben werden (Schutz vor Umleitung).

---

## 14. NetPulse-App und Push-Nachrichten

NetPulse lässt sich als App (PWA) installieren und schickt Alarme als **Push-Nachricht**.

**Voraussetzung:** NetPulse ist über HTTPS mit **gültigem Zertifikat** erreichbar – in der Regel über den eigenen
Reverse-Proxy ([Kapitel 25](#25-zugriff-von-außen)). Mit dem lokalen Zertifikat funktioniert Push nicht zuverlässig.

1. NetPulse im Browser öffnen:
   - **Android/Chrome/Edge:** Menü → *App installieren* (oder Knopf „App installieren“ in NetPulse)
   - **iPhone/iPad (Safari):** *Teilen → Zum Home-Bildschirm* (Push erst ab iOS 16.4 und nur aus der installierten App)
   - **Windows/macOS (Chrome/Edge):** Symbol „App installieren“ in der Adressleiste
   - **Firefox** kann keine Web-Apps installieren – Chrome, Edge oder Safari verwenden.
2. In der App anmelden, *Mein Konto → Push auf diesem Gerät aktivieren*, Test-Nachricht senden.
3. Unter *Benachrichtigungen* einen Kanal **„NetPulse-App“** anlegen und in den Alarmregeln auswählen.

**Android: Pop-up mit Ton.** NetPulse sendet Warnungen und kritische Alarme mit höchster Dringlichkeit und Vibration.
Ob Android sie zusätzlich **oben als Pop-up mit Ton** einblendet, legt Android je App fest – einmal einstellen:
*Einstellungen → Apps → NetPulse* (bei manchen Handys *Chrome*) *→ Benachrichtigungen* → die Kategorie mit „netpulse“
bzw. deiner Adresse öffnen → **„Warnmeldung“ / „Standard“ mit Ton** wählen und **„Als Pop-up anzeigen“** (Samsung:
„Pop-up“, Xiaomi: „Schwebende Benachrichtigungen“) einschalten. Zusätzlich prüfen: *Nicht stören* aus bzw. NetPulse
als Ausnahme, Akku-Optimierung für NetPulse/Chrome aus. Die **Test-Nachricht** unter *Mein Konto* verhält sich wie ein
echter Alarm – damit lässt sich die Einstellung prüfen.

Unter *Mein Konto* stehen alle Geräte mit aktiviertem Push; einzelne lassen sich entfernen.
Push-Nachrichten sind Ende-zu-Ende verschlüsselt (Web Push, RFC 8291) – die Push-Dienste von Google/Apple/Mozilla
sehen nur verschlüsselten Inhalt.

---

## 15. Dienste (Webseiten, Ports, Zertifikate)

**Dienste → Dienst hinzufügen** – überwacht Dienste unabhängig von der Geräte-Erreichbarkeit:

| Art | Ziel | Optionen |
|---|---|---|
| Webseite / HTTP(S) | URL | Suchwort im Inhalt (auch „darf nicht vorkommen“), erwarteter Status (Standard 200–399, z. B. `200,401`), Methode GET/HEAD, Zertifikat mitüberwachen, selbst signierte Zertifikate akzeptieren, Warnung X Tage vor Ablauf |
| Port (TCP) | Host:Port | – |
| DNS-Auflösung | Name | DNS-Server, A/AAAA, erwartete Adresse |
| TLS-Zertifikat | Host:Port | Warnung X Tage vor Ablauf, selbst signierte akzeptieren |

Für alle: Prüfabstand (Standard 60 s), Zeitlimit, **Ausfall erst nach X Fehlversuchen**, zugehöriges Gerät, aktiv.

Die Liste zeigt je Dienst einen **Heartbeat-Balken**, Antwortzeit, Verfügbarkeit (24 h / 7 / 30 Tage) und bei
Zertifikaten das Ablaufdatum. Ein Klick öffnet den Verlauf. Alarme über die Regelarten „Dienst ausgefallen“ und
„Zertifikat läuft ab“.

---

## 16. Netzwerkkarte und Abhängigkeiten

Die **Netzwerkkarte** zeigt die Geräte als Baum: Router → Switches → Access Points → Endgeräte, mit Status-Farben.
Zoom über die Knöpfe. Linien: **durchgezogen** = bekannte Verbindung (aus UniFi, Routern, Switches oder von Hand),
**gestrichelt** = vermutet (Gerät hängt vermutlich direkt am Router).

Die Verbindungen kommen aus **„Hängt ab von“** jedes Geräts:
- **automatisch** aus UniFi (Access Point/Switch des Clients), FRITZ!Box/MikroTik/Access Points (direkt verbunden) und
  Switches (Port-Zuordnung),
- **von Hand** beim Gerät unter *Einstellungen* (mit Suche; Schleifen werden verhindert).

Die Abhängigkeiten nutzt auch die Alarmierung: Ist das übergeordnete Gerät offline, werden die Geräte dahinter nicht
einzeln gemeldet.

---

## 17. Energie

### 17.1 Strommessungen und Rollen

Strommessungen kommen von Shellys (Steckdosen, Relais mit Messung, Energiezähler wie Pro 3EM). Jede Messung hat eine
**Rolle** (beim Gerät unter *Einstellungen* oder im Zahnrad der Energie-Kachel):

| Rolle | Bedeutung |
|---|---|
| Verbrauch | normaler Verbraucher (Standard) |
| Erzeugung | PV-Anlage, Balkonkraftwerk – wird automatisch erkannt, wenn der Name „Balkon“, „Solar“, „PV“, „BKW“, „Wechselrichter“ … enthält |
| Netz | Zähler am Hausanschluss |

### 17.2 Der Hauptzähler (saldierend)

Ein Zähler am Hausanschluss misst **saldierend**: **positiv = Netzbezug, negativ = Einspeisung**. Die PV-Erzeugung ist
darin schon verrechnet. NetPulse rechnet daher:

- **Netzbezug** = Zählerwert (wenn positiv), **Einspeisung** = −Zählerwert (wenn negativ)
- **Hausverbrauch** = Zählerwert + Erzeugung

Beispiele: Zähler +1000 W, PV 600 W → Bezug 1000 W, Verbrauch 1600 W. Zähler −200 W, PV 600 W → Einspeisung 200 W,
Verbrauch 400 W.

Misst dein Zähler ausnahmsweise den **Gesamtverbrauch** (ohne PV-Abzug), stellst du die Messart auf
„Gesamtverbrauch des Hauses“ um.

### 17.3 Kachel „Energie live“

Zeigt Verbrauch, Erzeugung, Netzbezug bzw. Einspeisung und die Aufschlüsselung je Gerät – live alle paar Sekunden.
Das **Zahnrad** öffnet: welche Geräte einbezogen werden, welcher der Hauptzähler ist, die Messart und die Rolle je Gerät.

### 17.4 Seite „Energie“

Auswertung nach **Monat** (Tage), **Jahr** (Monate) oder **Gesamt** (Jahre), mit Pfeilen zum Blättern:

- **Kacheln:** Verbrauch, PV-Ertrag, Netzbezug (mit Kosten), Einspeisung, **Autarkie** (Anteil des Verbrauchs aus
  eigener Erzeugung), **Eigenverbrauch** (Anteil der Erzeugung selbst genutzt), **Ersparnis**.
- **Diagramm Verbrauch:** je Balken „aus dem Netz“ und „aus eigener Erzeugung“.
- **Diagramm Erzeugung:** „selbst genutzt“ und „eingespeist“.
- Maus über einen Balken zeigt die genauen Werte; „Werte als Tabelle“ listet alles auf.
- **Geräte im Zeitraum:** Energie je Messung.
- **Einstellungen** (Admin): Hauptzähler, Messart, **Strompreis** und **Einspeisevergütung** in ct/kWh
  (für Kosten und Ersparnis).

Die Tageswerte werden alle 10 Minuten aus den Minutenwerten berechnet und **dauerhaft** gespeichert – auch nachdem die
Minutenwerte nach der Aufbewahrungszeit gelöscht wurden. Beim ersten Start rechnet NetPulse rückwirkend alles Vorhandene aus.

---

## 18. Protokolle (Syslog und SNMP-Traps)

NetPulse empfängt Protokollmeldungen, die Geräte aktiv schicken:

| | Port (UDP) | Standard der Geräte |
|---|---|---|
| Syslog (RFC 3164 und 5424) | **5514** | meist 514 – **5514 eintragen!** |
| SNMP-Traps (v1/v2c) | **1162** | meist 162 – **1162 eintragen!** |

(Die Standardports unter 1024 bräuchten Root-Rechte; über `SYSLOG_PORT`/`TRAP_PORT` änderbar.)

**Einrichtung auf den Geräten** (Ziel = IP des NetPulse-Hosts):
- **OPNsense:** System → Einstellungen → Protokollierung → Remote → Ziel hinzufügen: UDP, Port 5514
- **UniFi:** Einstellungen → Control Plane → Integrations/System → „Remote Syslog Server“, Port 5514
- **Synology:** Protokoll-Center → Protokolle senden
- **Linux (rsyslog):** `*.* @IP:5514` in `/etc/rsyslog.d/netpulse.conf`, dann `systemctl restart rsyslog`
- **Traps:** Trap-Ziel = NetPulse-IP, Port 1162, Community wie `TRAP_COMMUNITY`

**Seite „Protokolle“:** Filter nach Gerät, Mindest-Stufe, Quelle (Syslog/Traps), Zeitraum und Freitext; neue Meldungen
erscheinen live (Häkchen „live“). Oben zeigt ein Kasten:
- ob der Empfang **läuft** (bzw. warum nicht, z. B. Port belegt),
- wie viele Meldungen seit dem Start angekommen sind und wann zuletzt,
- **abgewiesene Absender** – Meldungen werden nur aus den freigegebenen Scan-Netzen angenommen (Schutz vor
  gefälschten Meldungen). Liegt ein Absender woanders (z. B. ein Docker-Container mit 172.x-Adresse), das Netz unter
  *Netzwerke* freigeben oder `SYSLOG_ALLOW` setzen (z. B. `10.10.10.0/24,172.16.0.0/12` oder `any`),
- **„Testmeldung senden“** – prüft, ob der Empfang selbst funktioniert.

Traps werden mit Namen aus der MIB-Datenbank lesbar dargestellt. Alarme über die Regelart „Protokollmeldung“.
Aufbewahrung: `RETENTION_SYSLOG_DAYS` (Standard 30 Tage).

---

## 19. Statusseite

Eine **öffentliche Übersicht** für Familie, Kollegen oder Kunden – ohne Anmeldung, über einen **geheimen Link**.

*Statusseite* (Admin):
1. **Aktiv** einschalten, **Titel** und **Beschreibung** vergeben.
2. **Einträge hinzufügen** (Geräte oder Dienste, mit Suche). Je Eintrag: **Anzeigename** (z. B. „Internet“ statt
   „fritz.box“), **Abschnitt** (Gruppierung), **Details anzeigen** (Antwortzeit und Datenverkehr der letzten 24 h, bei
   Geräten mit Internet-Schnittstelle der Internet-Verkehr).
3. Den **geheimen Link** kopieren und weitergeben. **„Neuen Link erzeugen“** macht den alten sofort ungültig.

Die öffentliche Seite zeigt je Eintrag den Status, die Verfügbarkeit der letzten 30 Tage als Balken und optional die
Details; sie aktualisiert sich alle 15 Sekunden selbst („Live“-Punkt, „aktualisiert vor X s“).

**Sicherheit:** Der Schlüssel steht im Teil hinter `#` und wird nur als Header übertragen (landet nicht in Server-Logs).
Die Seite zeigt **nur** die freigegebenen Einträge mit ihren Anzeigenamen – keine IP-Adressen, internen Namen oder
anderen Geräte; ohne Anzeigenamen erscheinen neutrale Bezeichnungen. Die Antworten sind zwischengespeichert, um Last
durch häufige Aufrufe abzufangen.

---

## 20. Wartung

*Wartung → Wartungsfenster anlegen* (Admin):

| Art | Einstellungen |
|---|---|
| Einmalig | Beginn und Ende (Datum/Uhrzeit) |
| Wöchentlich | Wochentage und Uhrzeit von–bis (z. B. Sonntag 03:00–05:00 für Updates) |

Dazu die betroffenen **Geräte** und/oder **Dienste** (leer = alle). Während eines aktiven Fensters werden für diese keine
Alarme verschickt; Messungen laufen weiter. Fenster lassen sich deaktivieren, ohne sie zu löschen.

### 20.1 Verbundene Programme (z. B. Docker Backup Manager)

Andere Programme im Heimnetz können wie Zahnräder in NetPulse eingreifen. Wichtigster Fall: Der **Docker Backup
Manager** stoppt für ein konsistentes Backup Container wie Nextcloud oder Immich. Ohne Kopplung meldet NetPulse dann
„Dienst ausgefallen“, verschickt Alarme und zeigt den Ausfall im Verlauf. Mit Kopplung passiert Folgendes:

1. **Vor dem Stoppen** bittet der Backup Manager NetPulse um eine **Pause** für die betroffenen Container.
2. NetPulse prüft die zugehörigen **Dienste und Geräte gar nicht** mehr. Es gibt also keine Messwerte, keine Ereignisse
   und keine Alarme, und die Zeit zählt nicht gegen die Verfügbarkeit. In den Listen steht dort „pausiert“, auf der Seite
   *Dienste* oben ein Hinweis.
3. **Nach dem Neustart** meldet der Backup Manager „fertig“. NetPulse wartet noch die **Nachlaufzeit** (Standard 3 Minuten,
   damit die Container hochfahren können) und überwacht dann wieder normal. Läuft ein Container danach nicht, kommt der
   Alarm ganz normal.
4. **Sicherheitsnetz:** Jede Pause hat ein spätestes Ende (Standard 4 Stunden, höchstens 12). Stürzt der Backup Manager ab
   oder ist er nicht erreichbar, überwacht NetPulse danach von selbst weiter.
5. Zusätzlich meldet der Backup Manager **jedes Backup-Ergebnis**. Dafür gibt es zwei Alarm-Regeln (*Alarme → Regeln →
   Backups*):
   - **Backup fehlgeschlagen**: sofort, optional nur für Container mit einem bestimmten Namen.
   - **Backup überfällig**: Ein regelmäßig gesicherter Container (einer, der in einem aktiven Zeitplan steckt) hatte seit X
     Stunden kein erfolgreiches Backup, z. B. 26 bei täglichen Backups. Das fällt auch auf, wenn der Backup Manager gar
     nicht mehr läuft.

Fehlgeschlagene Backups erscheinen außerdem unter *Ereignisse*. Erfolgreiche Backups landen nur in der Liste beim
verbundenen Programm.

**Einrichten**

1. In NetPulse: *Verwaltung → Verbundene Programme → Programm verbinden*.
   - Art „Docker Backup Manager“ wählen.
   - Als **Docker-Host** das NAS auswählen, auf dem die Container laufen.
   - *Schlüssel erzeugen* klicken und den Schlüssel (`npi_…`) kopieren. Er wird nur einmal angezeigt; NetPulse speichert nur
     einen Hash davon.
2. Im Docker Backup Manager: *Einstellungen → NetPulse-Überwachung*.
   - Adresse eintragen, z. B. `http://10.10.10.15:18081` (Eingang für den Reverse-Proxy im LAN) oder
     `https://monitoring.example.de`.
   - Den Schlüssel einfügen.
   - *Kopplung eingeschaltet* anhaken und *Verbindung testen* klicken.
   - Bei `https://…:8443` mit dem eigenen NetPulse-Zertifikat zusätzlich „Zertifikat prüfen“ ausschalten.
3. Der Test zeigt, welche Dienste und Geräte NetPulse welchem Container zuordnet. Dieselbe Liste steht in NetPulse unter
   *Verbundene Programme*.

**Zuordnung Container → Dienste/Geräte**

NetPulse erkennt die Zuordnung automatisch. Fährt man mit der Maus über einen Eintrag, steht der Grund dabei. Erkannt wird:

| Merkmal | Beispiel |
|---|---|
| Eigene IP-Adresse des Containers (macvlan) | UniFi OS Server mit 10.10.10.6 → Gerät 10.10.10.6 und dessen Dienste |
| Veröffentlichter Port auf dem Docker-Host | Container veröffentlicht Port 2283 → Dienst `http://NAS:2283` |
| Passender Name (Container, Compose-Projekt, Hostname der Adresse) | `nextcloud-aio-database` → Dienst „Nextcloud“ (`https://cloud.example.de`) |

Allerweltswörter wie *server*, *web* oder *db* zählen nicht. Mit dem Stift-Symbol lässt sich die Zuordnung je Container
von Hand ergänzen oder die automatische Erkennung abschalten.

Wird eine ganze Gruppe gesichert (Landscape, z. B. alle Nextcloud-Container), pausiert der Backup Manager die **gesamte
Gruppe** für die Dauer des Laufs. Grund: Nextcloud ist auch dann gestört, wenn gerade nur seine Datenbank gesichert wird.
Gepaust wird nur, wenn Container wirklich gestoppt werden („Container stoppen“ im Zeitplan). Auch Wiederherstellungen
pausieren den Container.

**Für eigene Skripte**

Die Schnittstelle ist allgemein gehalten. Jedes Skript, z. B. ein eigener Cron-Job, kann sie mit einem eigenen Schlüssel
(Art „Anderes Programm“) nutzen. Die Aufrufe stehen unten auf der Seite *Verbundene Programme*, zum Beispiel:

```bash
KEY=npi_...
NP=http://10.10.10.15:18081
ID=$(curl -s -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json"   -d '{"subjects":["nextcloud"],"minutes":60,"reason":"Update"}' $NP/api/integration/v1/pause | jq .id)
# … Arbeiten …
curl -s -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json"   -d '{"grace_s":120}' $NP/api/integration/v1/pause/$ID/end
```

Der Schlüssel erlaubt nur diese Aufrufe, also Pausen, Meldungen und die Containerliste. Er gibt keinen Zugriff auf Geräte,
Zugangsdaten oder Einstellungen. Unter *Einstellungen* des Programms lässt er sich jederzeit erneuern oder sperren.
Die Kopplung gehört nicht zur NetPulse-Sicherung (Kapitel 24). Nach einer Wiederherstellung auf einem neuen System
verbindest du das Programm einfach neu.

---

## 21. Ereignisse, Audit-Log und System-Log

- **Ereignisse:** alle Zustandswechsel und Hinweise (online/offline, neues Gerät, angelegt, MAC geändert,
  SSH-Schlüssel geändert, Dienst ausgefallen/wieder ok …) mit Link zum Gerät.
- **Audit-Log** (Admin): wer wann was getan hat – Anmeldungen (auch fehlgeschlagene), Änderungen an Geräten,
  Zugangsdaten, Regeln, Benutzern, Sicherungen, Einstellungen. Aufbewahrung `RETENTION_AUDIT_DAYS` (365 Tage).
- **System-Log** (Admin): die letzten Meldungen des NetPulse-Servers (auch die einzelnen Abfrageschritte),
  filterbar, optional automatisch aktualisiert. Darüber **„Systemzustand von NetPulse“**: CPU jetzt und im Schnitt seit
  Start, Arbeitsspeicher, Datenbankgröße, offene Browser und eine Tabelle der **Aufgaben** mit Läufen pro Minute,
  Dauer und Anteil an der Laufzeit (hilft bei hoher CPU-Last).

---

## 22. Benutzer, Gruppen, Rollen und Anmeldung

**Rechte und Rollen.** Eine **Rolle** ist ein Bündel feiner Rechte, z. B. *Ansehen*, *Geräte bearbeiten*, *Geräte
diagnostizieren*, *Alarme quittieren*, *Alarmregeln verwalten*, *Netze verwalten*, *Dienste verwalten*, *Wartung*,
*Zugangsdaten verwalten*, *Benutzer verwalten*, *Einstellungen*, *Sicherung*. Mitgeliefert sind **Administrator**
(immer alle Rechte), **Netzwerk-Techniker**, **Bereitschaft** und **Nur lesen**; eigene Rollen lassen sich unter
*Benutzer → Rollen* anlegen.

**Zuweisung je Sektor.** Rollen werden einem Benutzer oder einer **Gruppe** zugewiesen – für *alle Sektoren* oder nur
für einen Sektor (inklusive Unter-Sektoren). Beispiel: Gruppe „Team Nord“ hat *Netzwerk-Techniker* in „Filiale Nord“
und *Nur lesen* überall. Die Oberfläche blendet aus, was jemand nicht darf; der Server prüft jede Anfrage selbst.

*Benutzer* (Recht *Benutzer verwalten*):

| Aktion | |
|---|---|
| Benutzer anlegen | Name, Passwort (mind. 12 Zeichen) oder **zentrale Anmeldung**, Rollen je Sektor, Gruppen |
| Bearbeiten | Anzeigename, E-Mail (für Gruppen-Benachrichtigungen), Rollen, Gruppen, deaktivieren |
| Neues Passwort setzen | für einen anderen Benutzer (z. B. vergessen) – er wird überall abgemeldet |
| 2FA zurücksetzen | z. B. Handy verloren – beendet auch alle Sitzungen des Benutzers |
| Überall abmelden | beendet alle Sitzungen des Benutzers |
| Löschen | es muss immer ein aktiver Administrator übrig bleiben |

*Gruppen* bündeln Benutzer (z. B. „Bereitschaft“); Rollen einer Gruppe gelten für alle Mitglieder, und Alarmregeln
können Gruppen direkt benachrichtigen.

**Erneute Bestätigung.** Kritische Aktionen (Benutzer und Rollen ändern, Zugangsdaten, Sicherung, Tresor-Schlüssel,
Probes) verlangen, dass das Passwort in den letzten 10 Minuten bestätigt wurde – NetPulse fragt dann kurz nach.
Mit API-Schlüsseln sind diese Aktionen nicht möglich.

**Zentrale Anmeldung (SSO, OpenID Connect).** Unter *Benutzer → Sicherheit*:

1. Beim Anmeldedienst (Entra ID, Keycloak, Authentik, Authelia, Google Workspace …) eine Anwendung anlegen
   (*Web*, vertraulicher Client) und als Rücksprung-Adresse `https://<PUBLIC_URL>/api/oidc/callback` eintragen.
   `PUBLIC_URL` (bzw. `SITE_ADDRESS`) muss gesetzt sein.
2. In NetPulse Aussteller (Issuer-URL), Client-ID und Client-Secret eintragen und einschalten. NetPulse prüft dabei, ob
   der Dienst erreichbar ist.
3. **Gruppen-Claim** (Standard `groups`, bei Keycloak z. B. `realm_access.roles`): Bei jeder Anmeldung wird der
   Benutzer Mitglied aller NetPulse-Gruppen, deren *Name beim zentralen Anmeldedienst* im Claim steht – und aus den
   übrigen so verknüpften Gruppen entfernt. So kommen die Rechte zentral aus dem Verzeichnis.
4. **Neue Benutzer automatisch anlegen** oder Konten vorher unter *Benutzer anlegen → Anmeldung über den zentralen
   Anmeldedienst* vorbereiten (gleicher Benutzername wie `preferred_username`). Konten mit eigenem Passwort werden
   nie automatisch verknüpft.

Auf der Anmeldeseite erscheint dann **„Anmelden mit …“**. Zwei-Faktor-Pflicht und Anmeldeschutz regelt bei diesen
Konten der Anmeldedienst.

**API-Schlüssel** (*Mein Konto*): für Skripte (`Authorization: Bearer np_…`) und Leitstand-Bildschirme; ein Schlüssel
hat die Rechte des Kontos, optional mit Ablaufdatum.

**Zwei-Faktor-Pflicht:** Schalter **„Alle Benutzer müssen 2FA nutzen“** (oder fest über `REQUIRE_TOTP=true`).
Benutzer ohne 2FA kommen nach der Anmeldung nur noch an die Einrichtung in *Mein Konto*; bereits eingerichtete 2FA lässt
sich dann nicht mehr ausschalten. Einschalten geht nur, wenn du 2FA selbst schon nutzt (damit du dich nicht aussperrst).

**Anmeldeschutz:** (in der Datenbank gespeichert, gilt auch nach einem Neustart) Nach 5 Fehlversuchen für Benutzer+IP (bzw. 20 je IP, 50 je Benutzer) in 15 Minuten wird die
Anmeldung vorübergehend gesperrt. Sitzungen laufen nach `SESSION_HOURS` (Standard 12 h) ab.

**Admin-Passwort vergessen (einziger Admin)?** Auf dem Docker-Host:

```bash
docker exec -it netpulse-app netpulse reset-password admin
```

Das setzt ein neues zufälliges Passwort (wird angezeigt) und beendet alle Sitzungen. Mit `--2fa` am Ende wird zusätzlich
die Zwei-Faktor-Anmeldung zurückgesetzt. Ohne Benutzernamen listet der Befehl alle Benutzer. Das geht nur mit Zugriff
auf den Docker-Host (Portainer: Container `netpulse-app` → *Console* → Befehl ohne `docker exec -it netpulse-app`).

---

## 23. Mein Konto

- **Passwort ändern** – alle anderen Sitzungen werden dabei abgemeldet.
- **Zwei-Faktor-Anmeldung** – einrichten (QR-Code oder Schlüssel von Hand), ausschalten (Passwort + aktueller Code).
- **Angemeldete Geräte (Sitzungen)** – alle Browser/Handys, in denen du angemeldet bist (Gerät, Browser, IP, zuletzt
  aktiv); einzeln abmelden oder **„Alle anderen abmelden“**.
- **NetPulse-App & Push** – Push auf diesem Gerät aktivieren, Test-Nachricht, Liste der Geräte mit Push (je Gerät
  „zuletzt zugestellt“, „auf dem Gerät angezeigt“ bzw. der Fehler).
- **Alarmtöne auf diesem Gerät** – eigener Ton je Schwere (kritisch, Warnung, Entwarnung, Hinweis): Sirene, Alarmhupe,
  Wecker, Piepton, Gong, Glocke, Sonar, sanfter Hinweis, Entwarnung oder kein Ton; Lautstärke; kritische Alarme auf
  Wunsch alle 10 s wiederholen, bis der Hinweis geschlossen wird. Gilt, solange NetPulse offen ist (auch als Tab im
  Hintergrund), und je Gerät/Browser.
- **Alarmton auch bei geschlossener App (Android):** Eine Web-App darf keinen eigenen Ton mitschicken – Android nimmt den
  Ton der App-Kategorie. Deshalb lässt sich jeder Alarmton mit ⬇ **als Tondatei speichern** (`NetPulse-….wav` unter
  *Downloads*) und dann unter *Einstellungen → Apps → NetPulse → Benachrichtigungen → Kategorie → Ton → „+“ / „Ton
  hinzufügen“* auswählen (notfalls die Datei mit *Dateien* in den Ordner `Notifications` verschieben). Android erlaubt
  einen Ton je App; getrennte Töne je Priorität und Dauer-Alarm bietet die App **ntfy**.

---

## 24. Sicherung und Wiederherstellung

*Sicherung* (Admin):

**Sicherung herunterladen:** Eine Datei `netpulse-JJJJ-MM-TT-hhmmss.npbackup` mit allem Eingestellten: Netze, Geräte
(Namen, Typen, Rollen, Notizen, Abhängigkeiten), Zugangsdaten, Benachrichtigungskanäle und E-Mail-Server, Alarmregeln,
Dienste, Wartungsfenster, Benutzer (inkl. 2FA), Dashboards, Statusseite, Energie-Einstellungen und Energie-Tageswerte.
**Nicht enthalten:** Messverläufe, Ereignisse, Protokolle.
- Du vergibst ein **eigenes Passwort** (mind. 12 Zeichen) – ohne dieses Passwort lässt sich die Sicherung nicht öffnen.
  Gut aufheben!
- Zur Bestätigung ist dein **Konto-Passwort** nötig (die Datei enthält alle Zugangsdaten, verschlüsselt).
- Verschlüsselung: Argon2id (Schlüssel aus dem Passwort) + AES-256-GCM, vorher komprimiert.

**Sicherung einspielen:** Datei wählen, Passwort der Sicherung und dein Konto-Passwort eingeben. Einträge werden über
natürliche Merkmale zugeordnet (Gerät → IP, Netz → CIDR, Benutzer → Name, Kanal/Regel/Dienst → Name) und aktualisiert
oder neu angelegt; Verweise (Regeln, Statusseite, Dashboard, Hauptzähler) werden passend umgeschrieben. **Es wird nichts
gelöscht**, der Messverlauf vorhandener Geräte bleibt. Alles geschieht in einem Schritt – schlägt etwas fehl, bleibt
alles unverändert. Funktioniert auch auf einer **neuen Installation** (anderer Tresor-Schlüssel ist kein Problem).
Benutzer aus der Sicherung bekommen ihr damaliges Passwort und ihre 2FA zurück.

**Automatische Sicherung:** täglich zur eingestellten Uhrzeit, die letzten X Dateien werden aufgehoben. Ablage im
Daten-Volume unter `/data/backups` (Volume `app-data`). Liste mit Herunterladen und Löschen, **„Jetzt sichern“**.
Das Passwort der automatischen Sicherung liegt verschlüsselt im Tresor. **Kopiere die Dateien regelmäßig auf ein
anderes Gerät** (z. B. per Hyper Backup, rsync) – eine Sicherung nur auf demselben NAS hilft nicht bei einem Plattenausfall.

**Komplette Datenbank mit Messverlauf** (für Umzüge mit allen Diagrammen):

```bash
docker exec netpulse-db pg_dump -U netpulse -p 5433 -h 127.0.0.1 netpulse | gzip > netpulse-db.sql.gz
```

Dazu gehört dann auch `/data/secret.key` aus dem Volume `app-data` – ohne ihn sind die gespeicherten Zugangsdaten nicht
lesbar (oder `SECRET_KEY` fest vorgeben).

**Tresor-Schlüssel tauschen:** *Sicherung → Tresor-Schlüssel → Schlüssel jetzt tauschen* verschlüsselt alle Geheimnisse
(Zugangsdaten, Kanäle, 2FA, E-Mail-Server, Sicherungs-Passwort, zentrale Anmeldung) mit einem neuen Schlüssel. Sinnvoll,
wenn jemand mit Zugriff auf den Server ausgeschieden ist. Der alte Schlüssel bleibt als `secret.key.old-…` liegen –
ältere Datenbank-Abzüge brauchen ihn weiterhin. Danach die neue `secret.key` mitsichern. Mit fest vorgegebenem
`SECRET_KEY` geht das nur über die Variable.

---

## 25. Zugriff von außen

Für Push-Nachrichten und den Zugriff von unterwegs braucht NetPulse eine eigene Adresse mit gültigem Zertifikat.
Empfohlen: vorhandener **Nginx Proxy Manager (NPM)**.

**Vorher unbedingt:** Zwei-Faktor-Anmeldung für alle Konten (am besten die 2FA-Pflicht einschalten).

1. **Eingang für den Proxy:** im Stack `PROXY_LISTEN=http://<LAN-IP des Hosts>:18081` setzen
   (z. B. `http://10.10.10.15:18081`) und `PUBLIC_URL=https://monitoring.example.de`. Stack neu starten.
   Port 18081 ist unverschlüsseltes HTTP – **nie am Router freigeben**.
2. **NPM → Proxy Host hinzufügen:**
   - Domain: `monitoring.example.de`
   - Scheme **`http`** (nicht https!), Forward Hostname/IP: LAN-IP des Hosts, Port **18081**
   - *Websockets Support* an, *Block Common Exploits* an
   - Reiter *SSL*: Let's-Encrypt-Zertifikat, *Force SSL*, *HTTP/2*, *HSTS* an
3. Am Router nur Port 443 (und 80 für Let's Encrypt) zu NPM weiterleiten, DNS-Eintrag auf die eigene IP setzen.
4. `https://monitoring.example.de` öffnen – fertig. App installieren siehe [Kapitel 14](#14-netpulse-app-und-push-nachrichten).

NetPulse übernimmt die echte Absender-IP nur von Proxys aus privaten Netzen (für Login-Sperre und Audit-Log). Der
Live-Stream funktioniert ohne weitere Einstellungen.

**Syslog (5514) und Traps (1162) nie am Router freigeben.** Alternative ohne Freigabe: VPN (z. B. WireGuard) ins Heimnetz.

---

## 26. Sicherheit im Detail

| Bereich | Maßnahme |
|---|---|
| Netz | Von außen nur HTTPS (Caddy bzw. dein Proxy); App und Datenbank lauschen nur auf 127.0.0.1 |
| Container | App ohne root, schreibgeschütztes Dateisystem, nur Capability `NET_RAW` (Ping); Datenbank ohne unnötige Rechte; `no-new-privileges` |
| Anmeldung | Argon2id-Passwort-Hashes, Sitzungs-Tokens nur als SHA-256 gespeichert, `__Host-`-Cookie mit HttpOnly/Secure/SameSite=Strict, CSRF-Header, Login-Sperre |
| 2FA | TOTP (RFC 6238), jeder Code nur einmal gültig, optional Pflicht für alle |
| Zugangsdaten | AES-256-GCM, Schlüssel außerhalb der Datenbank (`/data/secret.key`), nie wieder angezeigt, in Protokollen geschwärzt |
| Geräte | SSH-Host-Schlüssel und TLS-Zertifikate werden beim ersten Kontakt gemerkt – Änderungen stoppen die Abfrage (Schutz vor Man-in-the-Middle); SSH-Passwörter und Router-Zugänge werden nie „auf Verdacht“ an fremde Geräte gesendet |
| Oberfläche | strenge Content-Security-Policy (kein fremdes JavaScript, keine Inline-Skripte), HSTS, keine externen Dienste/CDNs |
| Scannen | nur ausdrücklich freigegebene Netze, höchstens /16 je Eintrag |
| Protokollempfang | nur aus freigegebenen Netzen, Mengenbegrenzung gegen Überflutung |
| Nachvollziehbarkeit | Audit-Log aller Anmeldungen und Änderungen |
| Lieferkette | Images aus diesem Repository, mit Sigstore signiert, mit SBOM und Herkunftsnachweis; GitHub-Actions auf feste Versionen gepinnt |

**Image-Signatur prüfen:**

```bash
cosign verify ghcr.io/sirbuschi2003/netpulse:latest \
  --certificate-identity-regexp 'https://github.com/Sirbuschi2003/NetPulse/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Datenschutz (welche Daten, wie lange, Hinweise für Firmen): [DATENSCHUTZ.md](DATENSCHUTZ.md).

---

## 27. Aktualisieren, Umziehen, Entfernen

**Aktualisieren (Portainer):** Stack öffnen → **Pull and redeploy** mit *Re-pull image*. Danach im Browser **Strg+F5**
(bzw. die App einmal schließen und neu öffnen). Datenbank-Änderungen werden beim Start automatisch eingespielt.
Automatisch: im Stack *GitOps updates* einschalten.

**Aktualisieren (Compose):** `git pull && docker compose pull && docker compose up -d`

**Umziehen auf einen neuen Host:**
1. Auf dem alten System eine **Sicherung** herunterladen (Kapitel 24).
2. NetPulse auf dem neuen Host installieren.
3. Sicherung einspielen. (Mit Messverlauf: stattdessen Datenbank-Dump und `secret.key` übernehmen.)

**Entfernen:** Stack löschen, danach die Volumes `db-data`, `app-data`, `caddy-data`, `caddy-config` entfernen.

---

## 28. Fehlersuche und häufige Fragen

**Allgemein zuerst:** beim Gerät den Reiter **Diagnose** öffnen – dort steht jeder Abfrageschritt mit Ursache und Tipp.
Für NetPulse selbst: **System-Log**.

**Es werden keine oder kaum Geräte gefunden**
- Ist das Netz unter *Netzwerke* freigegeben und stimmt die CIDR-Angabe?
- Läuft NetPulse unter Docker Desktop (Windows/macOS)? Dann sieht es das Heimnetz nur eingeschränkt.
- Manche Geräte antworten weder auf Ping noch auf gängige Ports (z. B. Handys im Ruhezustand) – sie erscheinen, sobald
  sie aktiv sind, oder lassen sich über einen Router/Controller übernehmen (Kapitel 7.3).

**Ein Gerät ist erreichbar, NetPulse kann es aber nicht anpingen/abfragen**
- Läuft es als **Docker-Container mit eigener IP (macvlan/ipvlan) auf demselben Host** wie NetPulse? Dann kann der Host
  es technisch nicht erreichen. Lösung: eine kleine Brücke auf dem Host – Anleitung in
  [ABFRAGEN.md → „Docker-Container mit eigener IP“](ABFRAGEN.md).
- Firewall auf dem Gerät/zwischen den Netzen (VLANs)?

**UniFi: „Keine UniFi-Oberfläche erreichbar“**
- Port prüfen: UniFi OS Server meist 11443, Konsolen 443, alte Network Application 8443. NetPulse probiert alle; den
  richtigen im Browser nachsehen und bei den Zugangsdaten eintragen.
- macvlan-Fall (siehe oben).
- „Zertifikat geändert“: Controller neu installiert? Beim Gerät *Einstellungen → Gemerkte Schlüssel vergessen*.

**UniFi: keine Datenraten/Signale je Client** → Kapitel 11, lokales Nur-Lese-Konto.

**FRITZ!Box: „Port 49000 nicht erreichbar“** → „Zugriff für Anwendungen zulassen“ einschalten.
**OPNsense: „Keine Berechtigung für …“** → dem API-Benutzer das genannte Recht geben.
**MikroTik: „Port nicht erreichbar“** → IP → Services: www-ssl (oder www mit Port 80) einschalten.

**„Protokolle“ ist leer**
- Kasten oben prüfen: Läuft der Empfang? Kommt die **Testmeldung** an?
- Auf dem Gerät **Port 5514** (nicht 514) eingetragen?
- Steht der Absender unter „Abgewiesen“? → Netz freigeben oder `SYSLOG_ALLOW` setzen.

**Nginx Proxy Manager: 502 Bad Gateway**
- In NPM muss das Scheme **`http`** sein (nicht https) und der Port 18081.
- `PROXY_LISTEN` muss auf die **LAN-IP** zeigen (z. B. `http://10.10.10.15:18081`), nicht auf 127.0.0.1, wenn NPM in
  einem eigenen Container läuft.

**Alarme kommen nicht aufs Handy (Push)** – der Reihe nach prüfen:
1. *Benachrichtigungen*: Spalte **Zustellung** beim Kanal „NetPulse-App“ – dort stehen der letzte Erfolg, der letzte
   Fehler mit Grund, „von keiner Alarmregel verwendet“ und „auf keinem Gerät ist Push aktiviert“.
2. *Alarme → Regeln*: Steht bei der Regel **„kein Kanal – nur in NetPulse“**? Dann die Regel bearbeiten und den Kanal
   „NetPulse-App“ anhaken.
3. *Mein Konto* **in der App auf dem Handy**: Push aktiviert? Die Liste „Geräte mit Push-Nachrichten“ zeigt je Gerät
   „zuletzt zugestellt“ bzw. den Fehler. **Test-Nachricht** senden.
4. Fehler „Anmeldung abgelaufen“ oder „Absenderschlüssel passt nicht“: Push auf dem Handy aus- und wieder einschalten.
5. Kommt die Test-Nachricht an, aber keine Alarme: Ruhezeit oder „Sammeln“ beim Kanal eingestellt?
6. Handy-Einstellungen: Benachrichtigungen für die App/Chrome erlaubt, Energiesparmodus schränkt die App nicht ein.

**App lässt sich nicht installieren**
- Gültiges Zertifikat nötig (Zugriff über NPM, Kapitel 25) – nicht über `https://IP:8443`.
- Firefox kann keine Web-Apps installieren → Chrome/Edge/Safari.
- iPhone: Push nur aus der installierten App, ab iOS 16.4.

**E-Mails kommen nicht an**
- *Benachrichtigungen → E-Mail-Server → Test-Mail* – die Fehlermeldung nennt die Ursache (Anmeldung, Port,
  Verschlüsselung). Port 587 = STARTTLS, 465 = TLS.
- Spam-Ordner prüfen; Absenderadresse muss zum Mail-Konto passen.
- Ruhezeit oder Sammeln aktiv?

**Energie-Werte stimmen nicht**
- Hauptzähler und Messart prüfen (Kapitel 17.2): ein Zähler am Hausanschluss ist fast immer **saldierend**.
- Rolle der PV-Messung = „Erzeugung“?
- Datenraten und Tageswerte entstehen mit Verzögerung (Tageswerte alle 10 Minuten).

**Hohe CPU-Last des NAS**
- *System-Log → Systemzustand*: welche Aufgabe kostet am meisten?
- Echtzeit-Takt der Shellys erhöhen (*Netzwerke → Echtzeit*), `INVENTORY_INTERVAL_MIN` erhöhen, sehr große Netze
  (/16) meiden, Such-Zeitplan auf „täglich“.

**Eingaben verschwinden beim Tippen** – behoben; bitte aktualisieren (Strg+F5).

**Passwort vergessen / 2FA-Handy verloren** – ein anderer Admin hilft unter *Benutzer*; sonst der Notfall-Befehl in
Kapitel 22.

**Nach einem Update sieht die Oberfläche alt aus** – Strg+F5 bzw. App neu öffnen.

**Speicher läuft voll** – Aufbewahrungszeiten verkürzen (`RETENTION_*`). Messwerte werden komprimiert und nach der
Frist automatisch gelöscht.

---

## 29. Anhang: Umgebungsvariablen, Ports, Aufbewahrung

### 29.1 Umgebungsvariablen

| Variable | Standard | Bedeutung |
|---|---|---|
| `DB_PASSWORD` | – (Pflicht) | Passwort der Datenbank (nur Buchstaben und Ziffern) |
| `SITE_ADDRESS` | – (Pflicht) | Adresse der Weboberfläche im LAN, z. B. `https://192.168.1.10:8443` |
| `SCAN_NETWORKS` | `auto` | Netze beim ersten Start (Komma-getrennt); leer/`auto` = angeschlossene Netze automatisch erkennen, kombinierbar (`auto,10.0.10.0/24`), `off` = keine |
| `INITIAL_ADMIN_USER` / `INITIAL_ADMIN_PASSWORD` | `admin` / zufällig | erstes Admin-Konto (nur beim allerersten Start) |
| `PUBLIC_URL` | = `SITE_ADDRESS` | Adresse für Links in Benachrichtigungen und für Push (z. B. `https://monitoring.example.de`) |
| `PROXY_LISTEN` | `http://127.0.0.1:18081` | Eingang für einen vorgeschalteten Reverse-Proxy (NPM) |
| `REQUIRE_TOTP` | `false` | `true` = Zwei-Faktor-Anmeldung für alle Pflicht (fest) |
| `SESSION_HOURS` | 12 | Gültigkeit einer Anmeldung in Stunden |
| `TZ` | `Europe/Berlin` | Zeitzone (Such-Zeitplan, Tageswerte, Sicherungen) |
| `DISCOVERY_INTERVAL_MIN` | 15 | Vorgabe für den Such-Modus „regelmäßig“ |
| `MONITOR_INTERVAL_SEC` | 60 | Abstand der Erreichbarkeitsprüfungen |
| `INVENTORY_INTERVAL_MIN` | 5 | Abstand der tiefen Abfragen (SNMP/SSH) |
| `SYSLOG_PORT` | 5514 | Syslog-Empfang (UDP), 0 = aus |
| `TRAP_PORT` | 1162 | Trap-Empfang (UDP), 0 = aus |
| `TRAP_COMMUNITY` | – | nur Traps mit dieser Community (mehrere mit Komma) |
| `SYSLOG_ALLOW` | Scan-Netze | von wo Syslog/Traps angenommen werden (CIDR, Komma) oder `any` |
| `RETENTION_METRICS_DAYS` | 90 | Aufbewahrung der Messwerte |
| `RETENTION_EVENTS_DAYS` | 180 | Aufbewahrung der Ereignisse |
| `RETENTION_AUDIT_DAYS` | 365 | Aufbewahrung des Audit-Logs |
| `RETENTION_SYSLOG_DAYS` | 30 | Aufbewahrung der Protokollmeldungen |
| `SECRET_KEY` | – (wird erzeugt) | Tresor-Schlüssel (64 Hex-Zeichen), falls nicht aus `/data/secret.key` |
| `DB_PORT` / `APP_PORT` | 5433 / 18080 | interne Ports auf dem Host (nur 127.0.0.1) |
| `NETPULSE_VERSION` | `latest` | Image-Version (z. B. fest auf eine Version setzen) |
| `RUST_LOG` | `info` | Ausführlichkeit des Server-Logs (`debug` für Fehlersuche) |
| `DB_MAX_CONNECTIONS` | 20 | Größe des Datenbank-Verbindungspools (5–500) |
| `MONITOR_FAIL_THRESHOLD` | 2 | Fehlschläge in Folge, bevor ein Gerät als offline gilt (1–20) |

Nur für die **Probe** (`netpulse probe`, siehe [9.2](#92-probes-für-entfernte-sektoren)):

| Variable | Standard | Bedeutung |
|---|---|---|
| `NETPULSE_SERVER` | – (Pflicht) | Adresse des NetPulse-Servers, `https://…` |
| `PROBE_TOKEN` | – (Pflicht) | Schlüssel der Probe (`npp_…`) |
| `PROBE_ALLOW_HTTP` | `false` | `true` erlaubt `http://` – nur zum Testen im LAN |

### 29.2 Ports

| Port | Protokoll | Wer | Zweck | Von außen? |
|---|---|---|---|---|
| 8443 (aus `SITE_ADDRESS`) | TCP/HTTPS | Proxy | Weboberfläche im LAN | nein (höchstens über NPM) |
| 18081 | TCP/HTTP | Proxy | Eingang für NPM (`PROXY_LISTEN`) | **nie** |
| 18080 | TCP | App | intern (nur 127.0.0.1) | nein |
| 5433 | TCP | Datenbank | intern (nur 127.0.0.1) | nein |
| 5514 | UDP | App | Syslog-Empfang | **nie** |
| 1162 | UDP | App | SNMP-Trap-Empfang | **nie** |

NetPulse selbst verbindet sich zu den Geräten über: ICMP (Ping), TCP (Ports), SNMP (UDP 161), SSH (22), HTTP/HTTPS
(Shelly, UniFi, OPNsense, MikroTik), TR-064 (FRITZ!Box, 49000), mDNS (5353) und NetBIOS (137).

### 29.3 Datenaufbewahrung

| Daten | Aufbewahrung |
|---|---|
| Erreichbarkeit/Antwortzeiten, Messwerte (CPU, RAM, Datenraten, Leistung, Signal) | `RETENTION_METRICS_DAYS` (90 Tage), nach 7 Tagen komprimiert |
| Energie-Tageswerte | dauerhaft (klein) |
| Ereignisse | `RETENTION_EVENTS_DAYS` (180 Tage) |
| Protokollmeldungen | `RETENTION_SYSLOG_DAYS` (30 Tage) |
| Audit-Log | `RETENTION_AUDIT_DAYS` (365 Tage) |
| Sitzungen | bis zum Ablauf (`SESSION_HOURS`) |
| Automatische Sicherungen | die eingestellte Anzahl |
| Pausen verbundener Programme | 90 Tage |
| Backup-Meldungen verbundener Programme | 400 Tage |

### 29.4 Begriffe

| Begriff | Erklärung |
|---|---|
| Agentenlos | auf den überwachten Geräten wird nichts installiert |
| CIDR | Schreibweise für Netze, z. B. `192.168.1.0/24` = 192.168.1.0–255 |
| SNMP | Standard-Protokoll, über das Netzwerkgeräte Werte bereitstellen |
| MIB | Beschreibung, welche Werte ein Gerät per SNMP liefert |
| Syslog / Trap | Meldungen, die Geräte von sich aus an einen Empfänger schicken |
| WAN | Internet-Anschluss |
| dBm | Einheit der WLAN-Signalstärke; näher an 0 = stärker (−50 sehr gut, −80 schwach) |
| saldierender Zähler | zeigt Bezug positiv und Einspeisung negativ |
| Autarkie | Anteil des Verbrauchs, der aus eigener Erzeugung gedeckt wird |
| macvlan | Docker-Netz, in dem ein Container eine eigene LAN-IP hat |
| PWA | Web-App, die sich wie eine normale App installieren lässt |
| TOTP / 2FA | sechsstelliger Einmal-Code aus einer Authenticator-App als zweiter Faktor |
