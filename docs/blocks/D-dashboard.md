# Block D — Dashboard mit Tags und Stale-Detection

## Ziel

Das Dashboard `/` zeigt alle registrierten Server als Karten mit Severity-Badges, KEV-Counter, Last-Seen, Stale- und DB-Stale-Indikatoren. Tag-Filter-Chips funktionieren mit OR/AND-Modus, URL-persistent für Bookmarks. "Aufmerksamkeit nötig"-Sektion oben listet Stale-Server, KEV-betroffene Server und Server mit veralteter Trivy-DB. Theme-Toggle funktioniert. Server-Tagging in der Detail-Header.

## Vorbereitung — zu lesende Sektionen

- `ARCHITECTURE.md` §7 (UI — `/` Dashboard, Tag-Filter, "Aufmerksamkeit nötig", Theme)
- `ARCHITECTURE.md` §14 (Stale-Detection — Server und Trivy-DB, 30h Default)
- `ARCHITECTURE.md` §15 (Triage-Signale — KEV als zentrales Dashboard-Signal)

## Aufgaben

1. `app/views/dashboard.py`: `/` rendert Server-Karten mit allen Counts, Tag-Filter aus Query-String, "Aufmerksamkeit nötig"-Sektion via SQL-Aggregation.
2. Templates: `dashboard/index.html`, `dashboard/_card.html` (Partial), `dashboard/_attention.html` (Partial), `dashboard/_tag_filter.html`.
3. SQL-Helper für Severity-Counts pro Server (Default-Severity-Schwelle berücksichtigen).
4. Stale-Detection als View-Helper: `is_stale(server, now)` und `is_db_stale(server, now)` mit konfigurierbaren Thresholds aus Settings.
5. URL-Filter-Parsing mit Pydantic-Schema in `app/schemas/dashboard_filter.py` (Tags-Liste, Severity-Override, KEV-only).
6. Theme-Toggle JS-Snippet in `static/js/theme.js` (~20 Zeilen Alpine + localStorage).
7. Tag-Bearbeitung im Server-Detail-Header (HTMX-Inline, Add/Remove pro Tag).
8. Server-Detail-Header (`/servers/{id}` ohne Findings-Tabelle noch — die kommt in Block E).

## Was NICHT in diesem Block

- Keine Findings-Tabelle (Block E).
- Keine Bulk-Operationen (Block F).
- Kein SSE-Live-Update (Block H — vorerst Reload-Button reicht).

## Definition of Done

### Datei-Existenz

- [ ] `app/views/dashboard.py`, `app/schemas/dashboard_filter.py`
- [ ] Templates `dashboard/index.html`, `dashboard/_card.html`, `dashboard/_attention.html`, `dashboard/_tag_filter.html`
- [ ] `static/js/theme.js`, DaisyUI-Theme-Konfiguration in `base.html`

### Statische Checks

- [ ] cmd: `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] grep: kein `|safe` in `dashboard/*.html`
- [ ] grep: alle Filter-Werte werden via Query-String gelesen (kein Form-State im Server)

### Tests

- [ ] cmd: `pytest tests/views/test_dashboard.py -v` → grün (Card-Rendering, Filter, Aggregation)
- [ ] cmd: `pytest tests/services/test_stale_detection.py -v` → grün (Threshold-Logik für beide Stale-Typen)

### Verhaltens-Checks

- [ ] manual: Mit 3 registrierten Servern (verschiedene Tags, einer stale, einer KEV-betroffen): Dashboard zeigt korrekte Karten, Filter funktioniert, "Aufmerksamkeit"-Sektion zeigt die richtigen Server. Screenshots unter `docs/blocks/D-evidence/`.
- [ ] manual: URL `/?tags=prod,web&kev_only=true` zeigt nur passende Server, Bookmark funktioniert nach Reload.
- [ ] manual: Theme-Toggle wechselt sofort, Reload behält Wahl.
- [ ] manual: Tag im Server-Detail entfernen → Dashboard-Filter aktualisiert.

### Dokumentation

- [ ] `STATE.md` aktualisiert.
