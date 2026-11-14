-- Ein/Aus: Wake-on-LAN, Herunterfahren, Gerätegruppen und Zeitpläne

-- Gerätegruppen (z. B. „Büro-PCs“, „Server im Keller“); ein Gerät kann in mehreren Gruppen sein
CREATE TABLE device_groups (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    notes      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_group_members (
    group_id  BIGINT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, device_id)
);
CREATE INDEX device_group_members_device_idx ON device_group_members (device_id);

-- Wie ein Gerät aufgeweckt und heruntergefahren wird (Methode, Broadcast-Adresse, eigener Befehl, URL …).
-- Passwörter liegen nie hier, sondern verschlüsselt in `credentials` (Verweis über die ID).
ALTER TABLE devices ADD COLUMN power JSONB NOT NULL DEFAULT '{}';

-- Zeitpläne: an den Wochentagen `days` (1 = Montag … 7 = Sonntag) um `time` (HH:MM, Zeitzone aus TZ)
-- die Geräte `device_ids` und alle Mitglieder der Gruppen `group_ids` aufwecken oder herunterfahren
CREATE TABLE power_schedules (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    action      TEXT NOT NULL CHECK (action IN ('wake', 'shutdown')),
    days        INT[] NOT NULL DEFAULT '{1,2,3,4,5,6,7}',
    time        TEXT NOT NULL,
    device_ids  BIGINT[] NOT NULL DEFAULT '{}',
    group_ids   BIGINT[] NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    last_result TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
