# Block F — Bulk-Operationen, globale Suche, Audit-View, CSV-Export

## Ziel

Skalierbarkeit für Flotten-Triage: Checkbox-Bulk-Acknowledge in Server-Detail-Liste, globale CVE-/Paket-/Server-Suche mit "Alle Vorkommen abhaken über die ganze Flotte"-Funktion plus Bestätigungs-Modal mit dry-run-Zähler. Audit-View mit Filtern (Tag, Server, Action, Datum) und CSV-Export. CSV-Export auch aus Findings-Listen.

## Vorbereitung — zu lesende Sektionen

- `ARCHITECTURE.md` §6 (`POST /findings/bulk-acknowledge` mit dry_run, `/findings/search`)
- `ARCHITECTURE.md` §7 (Bulk-UI, globale Suche, Audit-View)
- `ARCHITECTURE.md` §13 (Audit-Log — neue Action `finding.bulk_acknowledged` mit IDs in metadata)

## Aufgaben

1. `app/api/bulk.py`: `POST /findings/bulk-acknowledge` mit zwei Flavors (`finding_ids`-Liste vs. `cve_id`/`package_name`-Match-Kriterium). `dry_run`-Modus liefert `{count, server_count, finding_ids}`. Volle Variante schreibt einen Bulk-Audit-Event mit IDs in `metadata`-jsonb.
2. `app/views/search.py`: `/findings/search?q=…` mit CVE-/Paket-/Server-Suche. Tag-Filter wie auf Dashboard. Aggregations-Header bei CVE-Suche ("CVE-X betrifft N Server, M open").
3. `app/views/audit_view.py`: `/audit` mit Filter (Datum, Actor, Action-Typ, Server, Tag), pagination 50 pro Seite. CSV-Export-Endpunkt `/audit/export.csv?<filter>`.
4. `app/views/findings.py` (Erweiterung): `/findings/export.csv?<filter>` für gefilterte Findings.
5. Templates: `findings/search.html` mit Bulk-Bestätigungs-Modal, `audit/list.html`, `findings/_bulk_action_bar.html` (Action-Bar im Server-Detail wenn Auswahl > 0).
6. JavaScript für Checkbox-Auswahl-State (Alpine.js, ~30 Zeilen).
7. `app/services/csv_export.py` mit Streaming-Response (Server soll bei großen Filtern nicht alles in RAM halten).

## Was NICHT in diesem Block

- Keine LLM-Anbindung (Block G).
- Keine SSE-Live-Updates (Block H).

## Definition of Done

### Datei-Existenz

- [ ] `app/api/bulk.py`, `app/views/search.py`, `app/views/audit_view.py`, `app/services/csv_export.py`
- [ ] Templates `findings/search.html`, `audit/list.html`, `findings/_bulk_action_bar.html`

### Statische Checks

- [ ] cmd: `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] grep: `dry_run` in `app/api/bulk.py` (zwei-Phasen-Bulk)

### Tests

- [ ] cmd: `pytest tests/api/test_bulk_acknowledge.py -v` → grün (beide Flavors, dry_run gibt korrekte Counts, Bulk-Event hat alle IDs in metadata)
- [ ] cmd: `pytest tests/views/test_search.py -v` → grün (CVE-Suche mit Aggregation, Tag-Filter, Paket-/Server-Suche)
- [ ] cmd: `pytest tests/views/test_audit.py -v` → grün (Filter-Kombinationen, Pagination)
- [ ] cmd: `pytest tests/services/test_csv_export.py -v` → grün (Streaming, Spalten-Reihenfolge stabil)
- [ ] cmd: `pytest tests/adversarial/test_csv_injection.py -v` → grün (CSV-Felder beginnend mit `=`, `+`, `-`, `@` werden mit `'` escaped)

### Verhaltens-Checks

- [ ] manual: Auf Server-Detail 5 Findings auswählen, Bulk-Acknowledge → Modal zeigt "5 Findings", Comment optional, Bestätigung → alle 5 abgehakt, ein Audit-Event mit IDs.
- [ ] manual: Globale Suche nach `CVE-2024-XXXXX` (real aus Fixtures) → Aggregation oben zeigt N Server. "Alle abhaken"-Knopf → dry_run-Modal mit "X Findings auf Y Servern", Bestätigung wirkt.
- [ ] manual: Audit-View nach Tag `prod` filtern → nur Events deren Target-Server das Tag trägt.
- [ ] manual: CSV-Export aus Findings-Liste öffnen, in Excel laden, keine Formel-Injection.
- [ ] Screenshots der Bulk-Workflows unter `docs/blocks/F-evidence/`.

### Dokumentation

- [ ] `STATE.md` aktualisiert.
