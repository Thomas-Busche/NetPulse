-- Netze, die eine Probe an ihrem Standort selbst erkannt hat (Schnittstellen + Gateway).
-- Dienen als Vorschlag unter „Netzwerke → Netze erkennen“ für den Sektor der Probe.
ALTER TABLE probes ADD COLUMN local_networks JSONB;
