-- Priorität und Kategorien je Gerät, frei gestaltbarer Leitstand.

-- ---------------------------------------------------------------------------
-- Kategorien (frei definierbar: Name, Symbol, Farbe, Reihenfolge)
-- ---------------------------------------------------------------------------

CREATE TABLE device_categories (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    icon        TEXT NOT NULL DEFAULT 'category',
    color       TEXT NOT NULL DEFAULT '#64748b' CHECK (color ~ '^#[0-9a-fA-F]{6}$'),
    position    INT NOT NULL DEFAULT 0,
    -- Geräte dieser Typen landen automatisch hier, solange von Hand nichts anderes eingestellt ist
    auto_types  TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO device_categories (name, icon, color, position, auto_types) VALUES
    ('Server',       'server',          '#2563eb', 10, '{server,hypervisor,linux,nas,raspberry_pi,ups}'),
    ('Netzwerk',     'network',         '#0891b2', 20, '{router,switch,access_point,firewall,network}'),
    ('Clients',      'device-desktop',  '#7c3aed', 30, '{windows,apple,computer}'),
    ('WLAN-Geräte',  'wifi',            '#db2777', 40, '{phone,tablet,console}'),
    ('Smart Home',   'bulb',            '#16a34a', 50, '{iot,camera,speaker,tv}'),
    ('Drucker',      'printer',         '#ca8a04', 60, '{printer}');

-- category_manual = false: Kategorie ergibt sich aus dem Gerätetyp (siehe auto_types);
-- category_manual = true und category_id NULL: bewusst ohne Kategorie
ALTER TABLE devices
    ADD COLUMN priority        TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('high', 'normal', 'low')),
    ADD COLUMN category_id     BIGINT REFERENCES device_categories(id) ON DELETE SET NULL,
    ADD COLUMN category_manual BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX devices_category_idx ON devices (category_id);

-- Wird eine Kategorie gelöscht, fallen ihre Geräte wieder auf die automatische Zuordnung zurück
CREATE FUNCTION devices_category_deleted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE devices SET category_manual = false WHERE category_id = OLD.id;
    RETURN OLD;
END $$;
CREATE TRIGGER device_categories_before_delete BEFORE DELETE ON device_categories
    FOR EACH ROW EXECUTE FUNCTION devices_category_deleted();

-- ---------------------------------------------------------------------------
-- Leitstand-Ansichten: dieselbe Tabelle wie die benannten Dashboards, aber eigene Art
-- ---------------------------------------------------------------------------

ALTER TABLE dashboard_views
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'dashboard' CHECK (kind IN ('dashboard', 'leitstand'));
