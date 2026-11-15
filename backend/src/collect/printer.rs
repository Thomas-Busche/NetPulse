//! Drucker über die Standard-Printer-MIB (RFC 3805) und HOST-RESOURCES-MIB lesen –
//! herstellerunabhängig: Verbrauchsmaterial mit Farbe, Papierfächer, Seitenzähler,
//! Druckerstatus, Fehlerzustände und aktive Meldungen des Druckers.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use snmp2::AsyncSession;

use super::snmp::{column, with, Val};

const SUPPLIES: &[u64] = &[1, 3, 6, 1, 2, 1, 43, 11, 1, 1];
const COLORANT_VALUE: &[u64] = &[1, 3, 6, 1, 2, 1, 43, 12, 1, 1, 4];
const INPUT: &[u64] = &[1, 3, 6, 1, 2, 1, 43, 8, 2, 1];
const MARKER_LIFE_COUNT: &[u64] = &[1, 3, 6, 1, 2, 1, 43, 10, 2, 1, 4];
const ALERT_SEVERITY: &[u64] = &[1, 3, 6, 1, 2, 1, 43, 18, 1, 1, 2];
const ALERT_DESCRIPTION: &[u64] = &[1, 3, 6, 1, 2, 1, 43, 18, 1, 1, 8];
const CONSOLE_TEXT: &[u64] = &[1, 3, 6, 1, 2, 1, 43, 16, 5, 1, 2];
const HR_PRINTER_STATUS: &[u64] = &[1, 3, 6, 1, 2, 1, 25, 3, 5, 1, 1];
const HR_PRINTER_ERRORS: &[u64] = &[1, 3, 6, 1, 2, 1, 25, 3, 5, 1, 2];

/// Verbrauchsmaterial (Liste) und weitere Druckerangaben; `None`, wenn das Gerät keine Printer-MIB kennt
pub async fn collect(s: &mut AsyncSession) -> Option<(Vec<Value>, Value)> {
    let descr = column(s, &with(SUPPLIES, &[6]), 64).await;
    if descr.is_empty() {
        return None;
    }
    let colorant_idx = column(s, &with(SUPPLIES, &[3]), 64).await;
    let class = column(s, &with(SUPPLIES, &[4]), 64).await;
    let kind = column(s, &with(SUPPLIES, &[5]), 64).await;
    let max = column(s, &with(SUPPLIES, &[8]), 64).await;
    let level = column(s, &with(SUPPLIES, &[9]), 64).await;
    let colorants = column(s, COLORANT_VALUE, 64).await;

    let supplies = descr
        .iter()
        .map(|(idx, d)| {
            let num = |m: &BTreeMap<Vec<u64>, Val>| m.get(idx).and_then(Val::num);
            // Farbe: Index zeigt in die Farbmittel-Tabelle desselben Druckers (hrDeviceIndex.colorantIndex)
            let color = num(&colorant_idx)
                .filter(|c| *c > 0.0)
                .and_then(|c| colorants.get(&vec![idx[0], c as u64]))
                .and_then(Val::text);
            supply(d.text(), num(&class), num(&kind), color, num(&level), num(&max))
        })
        .collect();

    let mut info = Map::new();

    // Gesamt-Seitenzähler (erstes Druckwerk)
    if let Some(count) = column(s, MARKER_LIFE_COUNT, 8).await.values().find_map(Val::num) {
        info.insert("page_count".into(), json!(count));
    }

    // Status und Fehlerzustände aus der HOST-RESOURCES-MIB
    if let Some(status) = column(s, HR_PRINTER_STATUS, 4).await.values().find_map(Val::num) {
        info.insert("status".into(), json!(printer_status(status)));
    }
    if let Some(Val::Bytes(bits)) = column(s, HR_PRINTER_ERRORS, 4).await.into_values().next() {
        let errors = error_states(&bits);
        if !errors.is_empty() {
            info.insert("errors".into(), json!(errors));
        }
    }

    // Papierfächer
    let tray_name = column(s, &with(INPUT, &[13]), 32).await;
    if !tray_name.is_empty() {
        let tray_descr = column(s, &with(INPUT, &[18]), 32).await;
        let tray_max = column(s, &with(INPUT, &[9]), 32).await;
        let tray_level = column(s, &with(INPUT, &[10]), 32).await;
        let media = column(s, &with(INPUT, &[12]), 32).await;
        let trays: Vec<Value> = tray_name
            .iter()
            .map(|(idx, name)| {
                let num = |m: &BTreeMap<Vec<u64>, Val>| m.get(idx).and_then(Val::num);
                let (pct, state) = level_state(num(&tray_level), num(&tray_max), true);
                json!({
                    "name": name.text().or_else(|| tray_descr.get(idx).and_then(Val::text)),
                    "media": media.get(idx).and_then(Val::text),
                    "level": num(&tray_level),
                    "max": num(&tray_max),
                    "pct": pct,
                    "state": state,
                })
            })
            .collect();
        info.insert("trays".into(), Value::Array(trays));
    }

    // Aktive Meldungen des Druckers (z. B. „Toner fast leer“, „Papierstau“)
    let alert_text = column(s, ALERT_DESCRIPTION, 32).await;
    if !alert_text.is_empty() {
        let severity = column(s, ALERT_SEVERITY, 32).await;
        let mut alerts: Vec<Value> = Vec::new();
        for (idx, text) in &alert_text {
            let Some(message) = text.text() else { continue };
            if alerts.iter().any(|a| a["message"] == message) {
                continue;
            }
            let level = match severity.get(idx).and_then(Val::num) {
                Some(3.0) => "critical",
                Some(4.0) | Some(5.0) => "warning",
                _ => "info",
            };
            alerts.push(json!({ "message": message, "severity": level }));
        }
        if !alerts.is_empty() {
            info.insert("alerts".into(), Value::Array(alerts));
        }
    }

    // Text im Bedienfeld
    let display: Vec<String> = column(s, CONSOLE_TEXT, 8).await.values().filter_map(Val::text).collect();
    if !display.is_empty() {
        info.insert("display".into(), json!(display));
    }

    Some((supplies, Value::Object(info)))
}

/// Ein Eintrag der prtMarkerSuppliesTable als JSON
fn supply(descr: Option<String>, class: Option<f64>, kind: Option<f64>, color: Option<String>, level: Option<f64>, max: Option<f64>) -> Value {
    // Klasse 4 = Behälter, der sich füllt (Resttoner, Resttinte)
    let receptacle = class == Some(4.0) || matches!(kind, Some(4.0) | Some(8.0));
    let (pct, state) = level_state(level, max, !receptacle);
    json!({
        "descr": descr,
        "kind": supply_kind(kind),
        "color": color.map(|c| c.to_lowercase()).filter(|c| c != "unknown" && c != "none"),
        "receptacle": receptacle,
        "level": level,
        "max": max,
        "pct": pct,
        "state": state,
    })
}

/// Prozent und Zustand aus Füllstand/Kapazität. Sonderwerte der MIB: -1 = sonstiges, -2 = unbekannt, -3 = „noch etwas vorhanden“.
fn level_state(level: Option<f64>, max: Option<f64>, consumed: bool) -> (Option<f64>, &'static str) {
    match (level, max) {
        (Some(l), Some(m)) if l >= 0.0 && m > 0.0 => {
            let pct = (l / m * 100.0).round().clamp(0.0, 100.0);
            let state = if consumed {
                if pct <= 0.0 { "empty" } else if pct <= 15.0 { "low" } else { "ok" }
            } else if pct >= 100.0 {
                "full"
            } else if pct >= 85.0 {
                "almost_full"
            } else {
                "ok"
            };
            (Some(pct), state)
        }
        (Some(0.0), _) if consumed => (None, "empty"),
        (Some(-3.0), _) => (None, "some"),
        _ => (None, "unknown"),
    }
}

fn supply_kind(kind: Option<f64>) -> &'static str {
    match kind.map(|k| k as i64) {
        Some(3) | Some(21) => "toner",
        Some(4) | Some(8) => "waste",
        Some(5) | Some(6) | Some(7) | Some(30) => "ink",
        Some(9) => "drum",
        Some(10) => "developer",
        Some(15) => "fuser",
        Some(20) | Some(22) | Some(23) => "transfer",
        Some(32) => "staples",
        _ => "other",
    }
}

fn printer_status(code: f64) -> &'static str {
    match code as i64 {
        3 => "idle",
        4 => "printing",
        5 => "warmup",
        _ => "unknown",
    }
}

/// hrPrinterDetectedErrorState: Bitfeld, Bit 0 ist das höchstwertige Bit des ersten Bytes
fn error_states(bits: &[u8]) -> Vec<&'static str> {
    const NAMES: [&str; 16] = [
        "Papier fast leer",
        "Kein Papier",
        "Toner fast leer",
        "Kein Toner",
        "Klappe offen",
        "Papierstau",
        "Offline",
        "Wartung erforderlich",
        "Papierfach fehlt",
        "Ausgabefach fehlt",
        "Verbrauchsmaterial fehlt",
        "Ausgabefach fast voll",
        "Ausgabefach voll",
        "Papierfach leer",
        "Wartung überfällig",
        "",
    ];
    (0..16)
        .filter(|bit| bits.get(bit / 8).is_some_and(|b| b & (0x80 >> (bit % 8)) != 0))
        .map(|bit| NAMES[bit])
        .filter(|n| !n.is_empty())
        .collect()
}

/// Verbrauchsmaterial unter `limit` Prozent (Behälter für Resttoner: über `100 - limit` Prozent).
/// Liefert eine lesbare Liste und den niedrigsten Restwert.
pub fn low_supplies(supplies: &[Value], limit: f64) -> (Vec<String>, Option<f64>) {
    let mut names = Vec::new();
    let mut lowest: Option<f64> = None;
    for s in supplies {
        let receptacle = s["receptacle"].as_bool().unwrap_or(false);
        let name = s["descr"].as_str().unwrap_or("Verbrauchsmaterial");
        let remaining = s["pct"].as_f64().map(|p| if receptacle { 100.0 - p } else { p });
        let empty = s["state"] == "empty" || s["state"] == "full";
        match remaining {
            Some(r) if r <= limit => {
                names.push(if receptacle { format!("{name} {:.0} % voll", 100.0 - r) } else { format!("{name} {r:.0} %") });
                lowest = Some(lowest.map_or(r, |l: f64| l.min(r)));
            }
            None if empty => {
                names.push(format!("{name} {}", if receptacle { "voll" } else { "leer" }));
                lowest = Some(0.0);
            }
            _ => {}
        }
    }
    (names, lowest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuellstand() {
        assert_eq!(level_state(Some(50.0), Some(100.0), true), (Some(50.0), "ok"));
        assert_eq!(level_state(Some(300.0), Some(3000.0), true), (Some(10.0), "low"));
        assert_eq!(level_state(Some(0.0), Some(100.0), true), (Some(0.0), "empty"));
        assert_eq!(level_state(Some(-3.0), Some(100.0), true), (None, "some"));
        assert_eq!(level_state(Some(-2.0), Some(-2.0), true), (None, "unknown"));
        assert_eq!(level_state(Some(90.0), Some(100.0), false), (Some(90.0), "almost_full"));
    }

    #[test]
    fn fehlerbits() {
        // Bit 3 (Kein Toner) und Bit 5 (Papierstau) im ersten Byte, Bit 13 (Fach leer) im zweiten
        assert_eq!(error_states(&[0b0001_0100, 0b0000_0100]), vec!["Kein Toner", "Papierstau", "Papierfach leer"]);
        assert!(error_states(&[0, 0]).is_empty());
    }

    #[test]
    fn wenig_material() {
        let list = vec![
            supply(Some("Black Toner".into()), Some(3.0), Some(21.0), Some("black".into()), Some(8.0), Some(100.0)),
            supply(Some("Cyan Toner".into()), Some(3.0), Some(21.0), Some("cyan".into()), Some(60.0), Some(100.0)),
            supply(Some("Waste Toner".into()), Some(4.0), Some(4.0), None, Some(95.0), Some(100.0)),
            supply(Some("Drum".into()), Some(3.0), Some(9.0), None, Some(-3.0), Some(100.0)),
        ];
        assert_eq!(list[0]["kind"], "toner");
        assert_eq!(list[0]["color"], "black");
        let (names, lowest) = low_supplies(&list, 15.0);
        assert_eq!(names, vec!["Black Toner 8 %", "Waste Toner 95 % voll"]);
        assert_eq!(lowest, Some(5.0));
    }
}
