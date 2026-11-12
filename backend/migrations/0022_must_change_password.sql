-- Erster Admin mit Standardkennwort (bzw. Notfall-Reset): nach der Anmeldung muss ein eigenes Passwort gesetzt werden
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT false;
