-- Flexible Zugangsdaten: allgemeine HTTP-Zugänge für beliebige Geräte/Dienste und eigene Abfragen/Aktionen.

-- Neue Arten: HTTP mit Benutzer + Passwort (Basic/Digest), HTTP mit Token/API-Schlüssel,
-- Windows-Remoteverwaltung (WinRM, PowerShell)
ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check
    CHECK (kind IN ('snmp_v2c', 'snmp_v3', 'ssh_password', 'ssh_key', 'http', 'http_basic', 'http_token', 'winrm',
                    'unifi', 'fritzbox', 'opnsense', 'mikrotik'));

-- Nicht geheime Einstellungen je Zugangsangabe, z. B.
--   vendor:  frei wählbarer Hersteller/Dienst („Synology“, „Proxmox“, „Home Assistant“ …)
--   scheme:  "https" | "http" (HTTP-Arten)
--   header:  Header für das Token (Standard „Authorization“ mit „Bearer “)
--   prefix:  Vorsatz vor dem Token (Standard „Bearer “, leer bei z. B. „X-API-Key“)
--   test_path: Pfad für „Testen“ (Standard „/“)
ALTER TABLE credentials ADD COLUMN options JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Eigene Abfragen und Aktionen. Das Protokoll ergibt sich aus der Zugangsart:
--   SSH  → target ist ein Befehl (läuft über `sh -c` bzw. die Login-Shell)
--   WinRM → target ist ein PowerShell-Befehl
--   HTTP → target ist ein Pfad („/api/status“) oder eine vollständige URL zum selben Gerät
--   SNMP → target ist eine OID („1.3.6.1.2.1.1.3.0“); ohne Wert wird darunter gelesen (Walk)
-- mode 'read' läuft bei jeder Inventar-Abfrage, mode 'action' nur auf Knopfdruck
-- oder durch andere Funktionen (z. B. Herunterfahren nach Zeitplan).
CREATE TABLE custom_queries (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL,
    credential_id BIGINT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    mode          TEXT NOT NULL DEFAULT 'read' CHECK (mode IN ('read', 'action')),
    target        TEXT NOT NULL,
    method        TEXT NOT NULL DEFAULT 'GET' CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
    body          TEXT,
    -- Was aus der Antwort übernommen wird: JSON-Pfad („data.temp“, „items.0.name“) oder
    -- Text, hinter dem der Wert steht („Temperature:“); leer = ganze Antwort
    extract       TEXT,
    value_type    TEXT NOT NULL DEFAULT 'text' CHECK (value_type IN ('text', 'number')),
    unit          TEXT,
    -- NULL = alle Geräte, denen die Zugangsdaten zugeordnet sind
    device_ids    BIGINT[],
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (credential_id, name)
);

-- Letztes Ergebnis je Abfrage und Gerät
CREATE TABLE custom_query_results (
    query_id   BIGINT NOT NULL REFERENCES custom_queries(id) ON DELETE CASCADE,
    device_id  BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    time       TIMESTAMPTZ NOT NULL DEFAULT now(),
    ok         BOOLEAN NOT NULL,
    value_text TEXT,
    value_num  DOUBLE PRECISION,
    error      TEXT,
    PRIMARY KEY (query_id, device_id)
);

-- Verlauf der Zahlenwerte (für Diagramme)
CREATE TABLE custom_query_values (
    time      TIMESTAMPTZ NOT NULL,
    query_id  BIGINT NOT NULL REFERENCES custom_queries(id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    value     DOUBLE PRECISION NOT NULL
);
SELECT create_hypertable('custom_query_values', by_range('time', INTERVAL '7 days'));
CREATE INDEX custom_query_values_idx ON custom_query_values (query_id, device_id, time DESC);
