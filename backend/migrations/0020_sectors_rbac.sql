-- Sektoren (Standorte/Bereiche), Rechte je Sektor, Gruppen, Alarm-Bestätigung, Probes, geteilte Dashboards.
--
-- Bestehende Installationen: Alle Netze und Geräte landen im Sektor „Hauptstandort“ (id 1),
-- Admins bekommen die Rolle „Administrator“, lesende Benutzer die Rolle „Nur lesen“ – jeweils für alle Sektoren.

-- ---------------------------------------------------------------------------
-- Sektoren
-- ---------------------------------------------------------------------------

CREATE TABLE sites (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    -- Übergeordneter Sektor (z. B. Firma → Gebäude → Etage); Rechte gelten auch für alle Unter-Sektoren
    parent_id   BIGINT REFERENCES sites(id) ON DELETE RESTRICT,
    position    INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (parent_id IS NULL OR parent_id <> id)
);
INSERT INTO sites (id, name, description) VALUES (1, 'Hauptstandort', 'Standard-Sektor');
SELECT setval('sites_id_seq', 1);

ALTER TABLE networks
    ADD COLUMN site_id     BIGINT NOT NULL DEFAULT 1 REFERENCES sites(id) ON DELETE RESTRICT,
    ADD COLUMN vlan_id     INT CHECK (vlan_id BETWEEN 1 AND 4094),
    ADD COLUMN gateway     INET,
    ADD COLUMN description TEXT NOT NULL DEFAULT '',
    -- Eigener Such-Zeitplan für dieses Netz (NULL = globaler Zeitplan)
    ADD COLUMN schedule    JSONB;
ALTER TABLE networks DROP CONSTRAINT networks_cidr_key;
ALTER TABLE networks ADD CONSTRAINT networks_site_cidr_key UNIQUE (site_id, cidr);

-- Gleiche Adressbereiche in verschiedenen Sektoren sind erlaubt (z. B. zwei Filialen mit 192.168.1.0/24)
ALTER TABLE devices
    ADD COLUMN site_id    BIGINT NOT NULL DEFAULT 1 REFERENCES sites(id) ON DELETE RESTRICT,
    ADD COLUMN tags       TEXT[] NOT NULL DEFAULT '{}',
    -- Fehlversuche in Folge: erst ab einer Schwelle gilt ein Gerät als offline (gegen Flattern)
    ADD COLUMN fail_count INT NOT NULL DEFAULT 0;
ALTER TABLE devices DROP CONSTRAINT devices_ip_key;
ALTER TABLE devices ADD CONSTRAINT devices_site_ip_key UNIQUE (site_id, ip);
CREATE INDEX devices_site_idx ON devices (site_id);
CREATE INDEX devices_tags_idx ON devices USING gin (tags);

-- Dienste können einem Sektor zugeordnet werden (NULL = übergreifend, z. B. Internet-Dienste)
ALTER TABLE checks ADD COLUMN site_id BIGINT REFERENCES sites(id) ON DELETE SET NULL;
UPDATE checks c SET site_id = d.site_id FROM devices d WHERE d.id = c.device_id;

-- Wartungsfenster für ganze Sektoren
ALTER TABLE maintenance_windows ADD COLUMN site_ids BIGINT[] NOT NULL DEFAULT '{}';

-- ---------------------------------------------------------------------------
-- Benutzer, Gruppen, Rollen
-- ---------------------------------------------------------------------------

ALTER TABLE users
    ADD COLUMN display_name TEXT,
    ADD COLUMN email        TEXT,
    ADD COLUMN disabled     BOOLEAN NOT NULL DEFAULT false,
    -- local = Passwort in NetPulse, oidc = zentrale Anmeldung (Entra ID, Keycloak, Authentik …)
    ADD COLUMN auth_source  TEXT NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'oidc')),
    ADD COLUMN oidc_subject TEXT UNIQUE;

CREATE TABLE roles (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT '',
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    -- Hat immer alle Rechte, auch künftig hinzukommende
    all_permissions BOOLEAN NOT NULL DEFAULT false,
    builtin         BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO roles (name, description, permissions, all_permissions, builtin) VALUES
    ('Administrator', 'Alle Rechte, auch Benutzer, Zugangsdaten, Sicherung und Einstellungen', '{}', true, true),
    ('Netzwerk-Techniker', 'Geräte, Netze, Dienste, Wartung und Diagnose; keine Benutzer- und Systemverwaltung',
        '{view,devices.manage,devices.diagnose,alerts.ack,checks.manage,maintenance.manage}', false, true),
    ('Bereitschaft', 'Alles sehen und Alarme bestätigen', '{view,alerts.ack}', false, true),
    ('Nur lesen', 'Alles sehen, nichts ändern', '{view}', false, true),
    ('Leitstand-Anzeige', 'Für Wandbildschirme: nur Statusübersicht', '{view}', false, true);

CREATE TABLE user_groups (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    -- Name der Gruppe beim zentralen Anmeldedienst (OIDC-Claim „groups“); Mitglieder werden bei der Anmeldung abgeglichen
    oidc_group  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE group_members (
    group_id BIGINT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    user_id  BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user_idx ON group_members (user_id);

-- Wer (Benutzer oder Gruppe) hat welche Rolle wo (Sektor inkl. Unter-Sektoren; NULL = alle Sektoren)
CREATE TABLE role_assignments (
    id       BIGSERIAL PRIMARY KEY,
    role_id  BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    user_id  BIGINT REFERENCES users(id) ON DELETE CASCADE,
    group_id BIGINT REFERENCES user_groups(id) ON DELETE CASCADE,
    site_id  BIGINT REFERENCES sites(id) ON DELETE CASCADE,
    CHECK ((user_id IS NULL) <> (group_id IS NULL))
);
CREATE UNIQUE INDEX role_assignments_unique
    ON role_assignments (role_id, COALESCE(user_id, 0), COALESCE(group_id, 0), COALESCE(site_id, 0));
CREATE INDEX role_assignments_user_idx ON role_assignments (user_id);
CREATE INDEX role_assignments_group_idx ON role_assignments (group_id);

INSERT INTO role_assignments (role_id, user_id)
    SELECT r.id, u.id FROM users u JOIN roles r ON r.name = CASE WHEN u.role = 'admin' THEN 'Administrator' ELSE 'Nur lesen' END;
ALTER TABLE users DROP COLUMN role;

-- Erneute Bestätigung (Passwort/Code) vor kritischen Aktionen; Bildschirm-Sitzungen (Leitstand)
ALTER TABLE sessions
    ADD COLUMN reauth_at TIMESTAMPTZ,
    ADD COLUMN kiosk     BOOLEAN NOT NULL DEFAULT false;

-- API-Schlüssel für Skripte und Leitstand-Bildschirme (handeln mit den Rechten ihres Benutzers)
CREATE TABLE api_tokens (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    last_used  TIMESTAMPTZ
);

-- Login-Sperre überlebt Neustarts
CREATE TABLE login_attempts (
    key   TEXT PRIMARY KEY,
    count INT NOT NULL,
    since TIMESTAMPTZ NOT NULL
);

-- Zentrale Anmeldung: Zwischenspeicher für laufende Anmeldungen (Schutz vor CSRF/Replay)
CREATE TABLE oidc_states (
    state      TEXT PRIMARY KEY,
    verifier   TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Alarmierung
-- ---------------------------------------------------------------------------

ALTER TABLE alerts
    ADD COLUMN severity        TEXT,
    ADD COLUMN acknowledged_at TIMESTAMPTZ,
    ADD COLUMN acknowledged_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN ack_comment     TEXT,
    ADD COLUMN escalated_at    TIMESTAMPTZ;
CREATE INDEX alerts_open_idx ON alerts (opened_at DESC) WHERE resolved_at IS NULL;

ALTER TABLE alert_rules
    -- Geltungsbereich zusätzlich zu einem einzelnen Gerät: Sektor (inkl. Unter-Sektoren) und/oder Gerätegruppe (Tag)
    ADD COLUMN site_id              BIGINT REFERENCES sites(id) ON DELETE CASCADE,
    ADD COLUMN tag                  TEXT,
    -- NULL = automatisch (je Regeltyp)
    ADD COLUMN severity             TEXT CHECK (severity IN ('info', 'warning', 'critical')),
    -- Benachrichtigung an Benutzergruppen (App-Push an die Mitglieder, E-Mail an ihre Adressen)
    ADD COLUMN group_ids            BIGINT[] NOT NULL DEFAULT '{}',
    -- Eskalation: nach X Minuten ohne Bestätigung zusätzlich an diese Kanäle/Gruppen
    ADD COLUMN escalate_after_min   INT NOT NULL DEFAULT 0,
    ADD COLUMN escalate_channel_ids BIGINT[] NOT NULL DEFAULT '{}',
    ADD COLUMN escalate_group_ids   BIGINT[] NOT NULL DEFAULT '{}';

-- ---------------------------------------------------------------------------
-- Probes: kleine NetPulse-Ableger in entfernten Sektoren (scannen und prüfen dort lokal)
-- ---------------------------------------------------------------------------

CREATE TABLE probes (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    site_id    BIGINT NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    last_seen  TIMESTAMPTZ,
    version    TEXT,
    address    TEXT,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Weitere Dashboards: benannt, teilbar, optional auf einen Sektor beschränkt
-- ---------------------------------------------------------------------------

CREATE TABLE dashboard_views (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    owner_id   BIGINT REFERENCES users(id) ON DELETE CASCADE,
    layout     JSONB NOT NULL,
    site_id    BIGINT REFERENCES sites(id) ON DELETE SET NULL,
    -- Für alle sichtbar oder nur für bestimmte Gruppen
    shared     BOOLEAN NOT NULL DEFAULT false,
    group_ids  BIGINT[] NOT NULL DEFAULT '{}',
    -- Vorlage für neue Benutzer
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
