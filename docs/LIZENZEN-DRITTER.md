# Lizenzen verwendeter Fremdbestandteile

NetPulse selbst steht unter der AGPL-3.0-or-later (siehe [LICENSE](../LICENSE)).
Die folgenden Bestandteile stammen aus anderen Projekten und stehen unter ihren eigenen Lizenzen.
Alle sind mit der AGPL-3.0 vereinbar.

## Im Programm enthalten

| Bestandteil | Lizenz | Hinweis |
|---|---|---|
| Rust-Bibliotheken (rund 450 Crates, siehe `backend/Cargo.lock`) | MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0, CDLA-Permissive-2.0, 0BSD, Unlicense | ausschließlich freizügige Lizenzen; Liste erzeugen mit `cargo metadata` oder `cargo license` |
| Tabler Icons (`web/icons.svg`) | MIT | Copyright Paweł Kuna, Lizenztext in `web/icons-LICENSE.txt` |
| Herstellerliste `backend/data/oui.tsv` | IEEE Registration Authority (öffentliche Liste) | reine Zuordnung MAC-Präfix → Hersteller |
| SNMP-Namen `backend/data/mibnames.tsv.gz` | Daten aus IETF-/IANA-MIBs und Hersteller-MIBs (Sammlung des LibreNMS-Projekts, GPL-3.0) | nur die Zuordnung OID → Name, keine MIB-Dateien |

## Getrennte Container (nicht Teil von NetPulse)

| Image | Lizenz |
|---|---|
| `caddy:2` (Proxy) | Apache-2.0 |
| `timescale/timescaledb` (Datenbank) | PostgreSQL-Lizenz bzw. Timescale License für einige Zusatzfunktionen |
| `debian:bookworm-slim` (Basis des NetPulse-Images) | Debian-Pakete unter ihren jeweiligen freien Lizenzen |

## Marke

Name und Logo „BuscheHome“ sind keine Fremdbestandteile, stehen aber ebenfalls nicht unter der
AGPL, siehe [TRADEMARK.md](../TRADEMARK.md).
