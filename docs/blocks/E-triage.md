# Block E — Triage in der Server-Detail-View

## Ziel

`/servers/{id}` wird die Triage-Hauptansicht. Drei View-Modi: Liste (Default), Group-by-Package, Diff-seit-letztem-Scan. Filter-Chips, Triage-Sortierung nach KEV/EPSS/CVSS, Quick-Copy-Icons. Finding-Detail-Modal mit voller CVE-Info und Notes-Thread. Acknowledge-Modal mit *optionalem* Kommentar (Pflicht-Kommentare sind verboten — siehe ADR-006). Re-Open-Flow analog. Class-Toggle für OS-Pakete vs. Library-Findings.

## Vorbereitung — zu lesende Sektionen

- `ARCHITECTURE.md` §5 (`findings`, `finding_notes` — Schema)
- `ARCHITECTURE.md` §6 (Endpoints `/findings/{id}/acknowledge`, `/reopen`, `/notes`)
- `ARCHITECTURE.md` §7 (Server-Detail mit drei View-Modi, Finding-Detail-Modal)
- `ARCHITECTURE.md` §15 (Triage-Signale — Sortier-Reihenfolge, Default-Sort)
- `docs/decisions/0006-no-forced-comments.md`

## Aufgaben

1. `app/views/server_detail.py`: `/servers/{id}` mit View-Modus aus Query-String, Filter-State aus URL.
2. `app/services/findings_query.py`: parametrisierte Queries für die drei View-Modi inkl. Default-Sortierung (KEV desc, EPSS desc, CVSS desc, Severity desc, first_seen_at asc).
3. `app/services/diff_view.py`: Diff-Berechnung via `LAG()`-Window-Function über die zwei letzten Scans.
4. `app/views/findings.py`: `POST /findings/{id}/acknowledge`, `POST /findings/{id}/reopen`, `POST /findings/{id}/notes`, `DELETE /findings/{id}/notes/{note_id}`. Comment optional. Audit-Events.
5. Templates: `servers/detail.html`, `servers/_view_list.html`, `servers/_view_group.html`, `servers/_view_diff.html`, `findings/_detail_modal.html`, `findings/_ack_modal.html`, `findings/_notes_thread.html`. Alle mit HTMX-Targets für partielle Updates.
6. Quick-Copy-Icon-Component als kleines Alpine-Snippet (clipboard-API + Toast).
7. Class-Toggle (`os-pkgs` / `lang-pkgs` / beide) als Filter-Chip mit Default "beide" wobei OS-Findings oben sortiert werden.
8. Adversarial-Test: Trivy-Daten mit XSS-Payload in CVE-Title rendern → Skript wird nicht ausgeführt.

## Was NICHT in diesem Block

- Keine Bulk-Operationen (Block F).
- Keine globale Suche (Block F).
- Keine LLM-Bewertung (Block G).

## Definition of Done

### Datei-Existenz

- [ ] `app/views/server_detail.py`, `app/views/findings.py`
- [ ] `app/services/findings_query.py`, `app/services/diff_view.py`
- [ ] Templates: alle in der Aufgabe genannten Partials und Modals

### Statische Checks

- [ ] cmd: `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] grep: kein `required=True` ODER `validators=[InputRequired()]` auf `comment`-Feldern in Forms
- [ ] grep: kein `|safe` in `findings/*.html` oder `servers/*.html`
- [ ] grep: `nh3.clean(` für jeden Markdown-/HTML-Render-Pfad

### Tests

- [ ] cmd: `pytest tests/views/test_server_detail.py -v` → grün (alle 3 Views, Filter, Sort)
- [ ] cmd: `pytest tests/services/test_findings_query.py -v` → grün (Default-Sort produziert KEV-zuerst)
- [ ] cmd: `pytest tests/services/test_diff_view.py -v` → grün (Neu/Resolved/Verändert korrekt klassifiziert)
- [ ] cmd: `pytest tests/views/test_findings_actions.py -v` → grün (Ack mit/ohne Comment, Reopen, Notes-CRUD, Audit-Events)
- [ ] cmd: `pytest tests/adversarial/test_xss_in_cve_title.py -v` → grün (Skript-Payload wird escaped, nicht ausgeführt)

### Verhaltens-Checks

- [ ] manual: Server mit Findings öffnen, alle drei View-Modi durchklicken, Filter setzen, Sortierung manuell verifizieren (KEV oben).
- [ ] manual: Finding abhaken OHNE Kommentar → Status ändert sich, Audit-Event wird geschrieben, kein Note-Eintrag.
- [ ] manual: Finding abhaken MIT Kommentar → Note erscheint im Thread mit `author='system-ack'`.
- [ ] manual: Re-Open auf acknowledged Finding → Status zurück, Audit-Event, optional Comment als zweite Note.
- [ ] manual: Group-by-Package-Knopf am Paket-Header → alle Sub-CVEs gemeinsam abgehakt mit einem Bulk-Audit-Event.
- [ ] manual: Quick-Copy-Icon auf CVE-ID kopiert wirklich in Clipboard, Toast erscheint.
- [ ] Screenshots aller drei Modi unter `docs/blocks/E-evidence/`.

### Dokumentation

- [ ] `STATE.md` aktualisiert.
