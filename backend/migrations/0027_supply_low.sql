-- Alarmregel „Toner/Tinte fast leer“ (Verbrauchsmaterial von Druckern über die Printer-MIB)
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ('device_down', 'new_device', 'mac_changed',
    'disk_usage', 'cpu_usage', 'mem_usage', 'temperature', 'check_down', 'cert_expiry', 'syslog_match', 'job_failed', 'job_missing',
    'supply_low'));
