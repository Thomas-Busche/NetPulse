-- Persönliche Einstellung des Leitstands je Benutzer: welche Elemente in welcher Reihenfolge angezeigt werden.
-- Ein Leitstand-Bildschirm (Kiosk) zeigt die Einstellung des Kontos, mit dem er angemeldet ist.
CREATE TABLE leitstand_layouts (
    user_id    BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    layout     JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
