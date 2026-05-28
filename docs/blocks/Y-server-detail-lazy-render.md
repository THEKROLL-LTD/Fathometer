# Block Y — Server-Detail Lazy-Render-Architektur + Triage-Queue-Pagination

**Spec-Quelle:** [ADR-0039](../decisions/0039-server-detail-lazy-render-architecture.md)
**Branch:** `feat/block-y-server-detail-lazy-render`
**Zielversion:** v0.14.0
**Vorgänger:** Block X (ADR-0038, Server-Detail Triage-First Content-Refactor), Block Q (ADR-0025, Lazy-Group-Findings).
**Status:** Geplant

## Ziel

Server-Detail Initial-Render liefert nur Header + Group-Cards + Risk-Band-Akkordeon-Header. Alle übrigen Sektionen werden als HTMX-Fragmente parallel nachgeladen. Triage-Queue-Findings sind collapsed, lazy und paginiert (10/Seite). Daten-Zugriff über SQL-Projektionen statt ORM-Hydration.

**Erwartetes Ergebnis:** Initial-Render mit ~6–8 Queries statt ~17–19, keine Finding-Hydration im Critical Path, First-Paint in Bruchteilen der bisherigen Zeit. Triage-Queue lädt nie mehr als 10 Findings auf einmal.

> **Update 2026-05-28 (ADR-0039 §3 revidiert):** Die Triage-Pagination wurde von "Mehr laden"-Append-Button auf seitenbasierte Vor/Zurück-Navigation umgestellt (Footer `Seite N von M · X Findings` + `‹`/`›`, Markup wie Design `ServerDetail.jsx`), und die Page-Size von 25 auf 10 reduziert. Die Phase-C-Beschreibung unten beschreibt noch das ursprüngliche Append-Modell — die ADR ist die aktuelle Quelle der Wahrheit.

## Spec-Referenzen (Pflicht-Lektüre)

1. **ADR-0039 komplett** — Architektur-Entscheidung, Endpoint-Übersicht, Projektions-Tabellen, Verworfenes.
2. **ADR-0038 §6 (Risk-Band Top-Level Accordion)** — aktuelles Akkordeon-Markup, `_RISK_BAND_SECTION_ORDER`, `risk_band_section.html`.
3. **ADR-0025 §2–3 (Lazy-Group-Findings, Pending-Findings)** — HTMX-Lazy-Pattern für Findings innerhalb von Groups (gleiches Pattern, hier auf Risk-Band-Ebene angewandt).
4. **CLAUDE.md §HTMX-OOB-Single-Source-Pattern** — ein Partial für Initial-Render und OOB-Pfad.
5. **`app/views/server_detail.py`** — `show()`, `_render_findings_section`, `_build_risk_band_sections`, `_load_application_groups_for_server`, alle Fragment-Endpoints.
6. **`app/templates/servers/detail.html`** — Haupt-Template, Sektions-Platzhalter.
7. **`app/templates/servers/_view_groups.html`** + **`_partials/risk_band_section.html`** — aktuelles Akkordeon-Markup.
8. **`app/templates/servers/_partials/group_findings_table.html`** — Finding-Row-Markup (Referenz für Triage-Row-Partial).

## Out of scope (explizit)

- Dashboard-Performance (Block V, ADR-0030 Phasen A/C/D).
- Sidebar-Lazy-Load (Block V, ADR-0030 Phase C/Befund 8).
- SQL-Aggregation für `severity_history` (Block V, ADR-0030 Phase E) — die Sparkline/Trend-Endpoints in diesem Block rufen die bestehenden Service-Funktionen auf; deren interne Optimierung ist Scope Block V.
- `heartbeats_for_servers` schmale Projektion (Block V, ADR-0030 Befund 6) — der Heartbeat-Fragment-Endpoint ruft den bestehenden Service auf.
- Re-Design der Fragment-Skeleton-Animationen (eigener Folge-Block).
- Neue Schema-Migration.

## Modell-Änderungen

**Keine.** Block Y ist Code-only — keine Alembic-Migration, kein Schema-Touch.

## Phasen

### Phase A — Initial-Render-Reduktion + Projektionen

**Ziel:** `show()` auf das Minimum reduzieren. Alles was nicht im First-Paint sichtbar ist, wird aus dem Request entfernt.

**Dateien:**

- `app/views/server_detail.py::show` — Aufrufe entfernen: `severity_snapshots_for_server`, `daily_severity_counts_for_server`, `heartbeats_for_servers`, `_load_host_snapshot`, `_build_risk_band_sections`, Noise-Count + Noise-Findings. Tendency-Berechnung auf leichtgewichtige 7-vs-7-Tage-Query umstellen (neue Helper-Funktion `_tendency_quick(sess, server_id) -> Tendency`).
- `app/views/server_detail.py::_render_findings_section` — `_build_risk_band_sections`-Aufruf durch neue Funktion `_risk_band_header_counts(sess, server_id) -> dict[str, int]` ersetzen. Liefert ein `SELECT risk_band, COUNT(*) … WHERE status='open' GROUP BY risk_band`.
- `app/views/server_detail.py::_load_application_groups_for_server` — Queries (2), (3), (4) auf Projektionen umstellen:
  - Query (2): `select(ApplicationGroup.id, ApplicationGroup.label, ApplicationGroup.explanation)` statt `select(ApplicationGroup)`.
  - Query (3): `select(AGE.group_id, AGE.risk_band, AGE.risk_band_reason, AGE.worst_finding_id)` statt `select(ApplicationGroupEvaluation)`.
  - Query (4): `select(Finding.id, Finding.identifier_key, Finding.package_name)` statt `select(Finding)`.
  - Rückgabe als `list[dict]` bleibt, aber die Werte sind Named-Tuples/Rows statt ORM-Objekte. Template-Zugriff bleibt Attribut-basiert (SQLAlchemy Row-Objekte unterstützen `.`-Zugriff).
- `app/views/server_detail.py` — `_build_risk_band_sections` und `_assemble_risk_band_sections` löschen (inkl. `_SEVERITY_SORT_RANK`, `_RISK_BAND_SECTION_ORDER` falls nur dort konsumiert).
- `app/views/server_detail.py` — Query-Deduplizierung: `_load_pending_grouping_counts` und `_load_action_required_counts` in eine Funktion zusammenlegen. `count_findings` KEV-Subquery via `FILTER`-Aggregat einbauen.
- `app/templates/servers/detail.html` — Sparkline-, Heartbeat-, Host-Snapshot-, Noise-Sektionen auf `hx-trigger="load"`-Platzhalter umstellen. Heartbeat und Severity-Trend nutzen die Design-Skeleton-Variante (`sd-skel-frame` + `--skel`-Modifier-Klassen, siehe Phase B für Details). Host-Snapshot/Noise bekommen kompakte Spinner-Slots.
- `app/templates/servers/_view_groups.html` — Risk-Band-Sektionen rendern nur noch Header (Band-Name + Count), kein `section.findings` mehr.
- `app/templates/servers/_partials/risk_band_section.html` — Body-Bereich auf HTMX-Lazy-Load-Slot umstellen (`hx-get`, `hx-trigger="toggle"`).

**Tests:**

- Bestehende Tests für `_build_risk_band_sections` / `_assemble_risk_band_sections` löschen oder auf die neuen Funktionen migrieren.
- Neue Tests: `_risk_band_header_counts` liefert korrekte Counts pro Band.
- Neue Tests: `_tendency_quick` liefert korrekte Tendency bei verschiedenen Datenlagen.
- Neue Tests: `_load_application_groups_for_server` liefert Projektionen (keine ORM-Objekte, korrekte Felder).
- Neue Tests: Query-Deduplizierung — zusammengelegte Funktion liefert total + pending pro Band.
- Template-Render-Tests: Initial-Render enthält Risk-Band-Header mit Counts, enthält HTMX-Platzhalter, enthält **keine** Finding-Rows.

**DoD-A:**

1. `show()` führt keine `severity_snapshots_for_server`, `daily_severity_counts_for_server`, `heartbeats_for_servers`, `_load_host_snapshot`, `_build_risk_band_sections` Aufrufe mehr durch.
2. `grep -rn "_build_risk_band_sections\|_assemble_risk_band_sections" app/` liefert nichts.
3. `grep -rn "select(Finding)" app/views/server_detail.py` liefert nichts (keine volle Finding-Hydration mehr in der View).
4. `grep -rn "select(ApplicationGroup)" app/views/server_detail.py` liefert nichts (nur Projektionen).
5. `ruff check . && ruff format --check . && mypy app/` PASS.
6. Default-`pytest` PASS.

### Phase B — HTMX-Fragment-Endpoints (Sparklines, Heartbeat, Host-Snapshot, Trend, Noise)

**Ziel:** Die aus `show()` entfernten Sektionen als eigenständige Fragment-Endpoints bereitstellen.

**Dateien:**

- `app/views/server_detail.py` — fünf neue Endpoints:
  - `GET /<id>/fragments/sparklines` — ruft `severity_snapshots_for_server(sess, server.id, days=30)` auf, rendert Sparkline-Partial.
  - `GET /<id>/fragments/heartbeat` — ruft `heartbeats_for_servers(sess, [server.id], days=30)` auf, rendert Heartbeat-Bar-Partial.
  - `GET /<id>/fragments/host-snapshot` — ruft `_load_host_snapshot(sess, server.id)` auf, rendert Host-Snapshot-Partial.
  - `GET /<id>/fragments/trend` — ruft `daily_severity_counts_for_server` + `severity_snapshots_for_server` auf, rendert Trend-Chart + aktualisiert Tendency per OOB-Swap falls abweichend vom Quick-Estimate.
  - `GET /<id>/fragments/noise` — Noise-Count + Noise-Findings (max 50), rendert Noise-Modal-Content-Partial.
- Alle Endpoints: `@login_required`, revoked/retired-404-Guard per shared Decorator oder Helper.
- Bestehende Partials (`_heartbeat_large.html`, Host-Snapshot-Pills, Sparkline-/Trend-Templates) werden als eigenständige Fragment-Responses gerendert. HTMX-OOB-Single-Source-Pattern: gleiche Partials, OOB-Conditional per Flag.
- `app/templates/servers/detail.html` — Platzhalter aus Phase A werden mit konkreten `hx-get`-URLs und `hx-swap="innerHTML"` oder `outerHTML` versehen. **Skeleton-Markup nutzt die bestehende Scan-Animation aus dem Design** (`docs/design/ServerDetail.jsx`, `server-detail.css`):
  - **Heartbeat-Platzhalter:** `<div class="sd-heartbeat-frame sd-skel-frame">` + 30 `<span class="sd-heartbeat__tick sd-heartbeat__tick--skel">` — identische Dimensionen wie die Live-Bar.
  - **Severity-Trend-Platzhalter:** `<div class="sd-trend-frame sd-skel-frame">` + 30 `<div class="sd-trend-col sd-trend-col--skel">` — identische Column-Breite.
  - **KPI-Tiles-Platzhalter:** `<div class="sd-tile sd-tile--skel sd-skel-frame">` mit Em-Dash statt Zahl, Sparkline-Bars als `--border-subtle`.
  - Die `sd-skel-frame`-Klasse triggert die `@keyframes skel-scan`-Animation (1.8 s cyan-Gradient-Sweep, `mix-blend-mode: screen`). Der Fragment-Response liefert Live-Markup ohne `sd-skel-frame`; HTMX-Swap ersetzt das Skeleton nahtlos.
  - **Host-Snapshot und Noise:** kein Chart-Skeleton nötig (hinter Klick/Toggle), kompakter Inline-Spinner oder leerer Slot reicht.

**Tests:**

- Pro Endpoint: Grundlegender Response-Test (200, enthält erwartetes Markup-Fragment).
- Pro Endpoint: 404 bei unbekanntem Server, 404 bei revoked/retired Server.
- Pro Endpoint: `@login_required`-Guard (302 Redirect bei unauthentifiziertem Request).
- Template-Smoke: Detail-Seite rendert `hx-get`-Attribute für alle fünf Fragment-URLs.

**DoD-B:**

1. Alle fünf Fragment-Endpoints liefern 200 mit korrektem Partial-Content.
2. Detail-Seite (`GET /<id>`) enthält `hx-get` für alle fünf Fragment-URLs.
3. `ruff check . && ruff format --check . && mypy app/` PASS.
4. Default-`pytest` PASS, mindestens 15 neue Tests grün.

### Phase C — Triage-Queue: Collapsed + Lazy + Paginiert

**Ziel:** Risk-Band-Akkordeons laden Findings erst bei Expand, paginiert mit 25 pro Seite.

**Dateien:**

- `app/views/server_detail.py` — neuer Endpoint `GET /<id>/triage/<band>`:
  - `band`-Parameter: Whitelist-Validierung gegen `_RISK_BAND_SECTION_ORDER` (oder Nachfolger-Konstante), 400 bei ungültigem Band.
  - `page`-Parameter: `request.args.get("page", 1, type=int)`, Minimum 1.
  - Query mit **Projektion** (13 Spalten, siehe ADR-0039 §4):
    ```python
    select(
        Finding.id, Finding.identifier_key, Finding.title,
        Finding.package_name, Finding.installed_version, Finding.fixed_version,
        Finding.epss_score, Finding.cvss_v3_score, Finding.severity,
        Finding.is_kev, Finding.risk_band_reason, Finding.status,
        Finding.finding_class,
    ).where(
        Finding.server_id == server_id,
        Finding.status == FindingStatus.OPEN,
        Finding.risk_band == band,
    ).order_by(
        Finding.is_kev.desc(),
        Finding.severity.asc(),
        Finding.epss_score.desc().nulls_last(),
    ).limit(26).offset((page - 1) * 25)
    ```
  - Response: Fragment-Partial mit bis zu 25 Finding-Rows. Wenn 26 Rows zurückkommen: "Mehr laden"-Button am Ende mit `hx-get="/<id>/triage/<band>?page=<N+1>"`, `hx-swap="outerHTML"` (der Button ersetzt sich selbst durch die nächste Seite + ggf. neuen Button).
- `app/templates/servers/_partials/triage_findings_page.html` — neues Partial: rendert Finding-Rows (Markup analog `risk_band_section.html` Finding-Stack, aber aus Projektions-Tuples statt ORM-Objekten) + optionaler "Mehr laden"-Button.
- `app/templates/servers/_partials/risk_band_section.html` — Body-Bereich: HTMX-Lazy-Load-Slot mit `hx-get="/<id>/triage/<band>?page=1"`, `hx-trigger="toggle"`, Spinner-Placeholder.
- Default-Open-Band: das höchste nicht-leere Band bekommt `<details open>` im Template und einen sofortigen `hx-trigger="load"` statt `toggle` — damit der Operator beim Seitenaufruf sofort Findings sieht (erste Seite lädt automatisch).

**Tests:**

- Triage-Endpoint: korrekte Findings für Band, korrekte Sortierung (KEV first, dann Severity, dann EPSS).
- Triage-Endpoint: Pagination — Page 1 liefert 25, Page 2 liefert Rest, "Mehr laden"-Button nur wenn > 25.
- Triage-Endpoint: 400 bei ungültigem Band, 404 bei unbekanntem Server.
- Triage-Endpoint: leeres Band liefert leeren Response (kein Error).
- Triage-Endpoint: Projektion enthält genau die 13 erwarteten Felder, keine ORM-Objekte.
- Template-Smoke: Risk-Band-Section enthält `hx-get`-URL mit korrektem Band, Default-Open-Band hat `open`-Attribut.

**DoD-C:**

1. `GET /<id>/triage/escalate?page=1` liefert max 25 Finding-Rows als Partial.
2. "Mehr laden"-Button erscheint nur wenn mehr als 25 Findings im Band existieren.
3. Sort-Reihenfolge ist `is_kev DESC, severity ASC, epss_score DESC NULLS LAST` (verifiziert per Test).
4. Ungültiges Band liefert 400, nicht 500.
5. Default-Open-Band (höchstes nicht-leeres) hat `<details open>` + `hx-trigger="load"`.
6. `ruff check . && ruff format --check . && mypy app/` PASS.
7. Default-`pytest` PASS, mindestens 10 neue Tests grün.

### Phase D — Aufräumen + Drift-Tests

**Ziel:** Alten Code entfernen, Drift-Regressions-Tests sicherstellen, Konsistenz prüfen.

**Dateien:**

- Verwaiste Imports, Helper, Konstanten aus `server_detail.py` entfernen (grep nach unbenutzten Symbolen).
- `tests/` — alte Tests für `_build_risk_band_sections`, `_assemble_risk_band_sections` final entfernen falls in Phase A nur auskommentiert/geskippt.
- Drift-Regressions-Tests pro OOB-fähigem Fragment (CLAUDE.md §HTMX-OOB-Single-Source-Pattern): wenn ein Fragment-Partial sowohl im Initial-Render (als Skeleton) als auch im Fragment-Response verwendet wird, struktureller Vergleich beider Pfade (gleiche IDs, gleiche CSS-Klassen, gleiche `data-*`-Keys).
- `app/views/server_detail.py` — finaler grep: `select(Finding)` darf nur noch im Flat-Mode-Pfad (`list_findings`) und in Fragment-Endpoints vorkommen die bewusst volle Objekte brauchen (aktuell: keiner).

**Tests:**

- Drift-Tests: Initial-Skeleton vs. Fragment-Response für Heartbeat, Sparklines, Host-Snapshot.
- Grep-Verifikation: kein `select(Finding)` außer in bewusst dokumentierten Stellen.
- Coverage-Check: alle neuen Endpoints haben mindestens einen Happy-Path + einen Error-Path Test.

**DoD-D:**

1. `grep -rn "select(Finding)" app/views/server_detail.py` liefert nur bewusst dokumentierte Stellen (Flat-Mode `list_findings`).
2. `grep -rn "_build_risk_band_sections\|_assemble_risk_band_sections\|_SEVERITY_SORT_RANK" app/ tests/` liefert nichts.
3. Drift-Regressions-Tests für alle Fragment-Partials grün.
4. `ruff check . && ruff format --check . && mypy app/` PASS.
5. Default-`pytest` PASS, keine Test-Regressions.

## Phasen-Abhängigkeiten

```
A (Initial-Render-Reduktion) → keine externe Abhängigkeit, Grundlage für B + C
B (Fragment-Endpoints) → braucht A (Platzhalter im Template)
C (Triage-Queue Lazy + Paginated) → braucht A (Risk-Band-Header-Counts)
D (Aufräumen + Drift-Tests) → braucht A + B + C
```

Empfohlene Reihenfolge: **A → B → C → D**. B und C können nach A parallel laufen (unabhängige Endpoints/Templates). D ist der Abschluss-Sweep.

Jede Phase ist ein eigener Commit auf `feat/block-y-server-detail-lazy-render`. Reviewer-Approval am Ende jeder Phase. Sicherheits-relevant: nur die neuen Endpoints (`@login_required`, Band-Whitelist, Server-404-Guard) — kein neuer User-Input über String-Parameter hinaus.

## Risiken & Mitigation

| Risiko | Mitigation |
|---|---|
| **Browser-Connection-Pool-Saturation** durch parallele `hx-trigger="load"`-Requests (HTTP/1.1 Limit 6) | Maximal 5 Fragment-Endpoints parallel. Falls kritisch: OOB-Multi-Response (ein Request, mehrere Sektionen) als Folge-Optimierung. |
| **Skeleton-Layout-Sprung** beim Daten-Swap | Skeleton-Markup mit identischen Dimensionen zum Live-Markup. Visueller QA-Check beim Phase-B-Review. |
| **Template-Zugriff auf Projektions-Tuples bricht** (`.title` statt `["title"]`) | SQLAlchemy `Row`-Objekte unterstützen Attribut-Zugriff. Alternativ: `._asdict()` in der View, Übergabe als Dict-Liste. Template-Render-Tests in jeder Phase. |
| **"Mehr laden"-Button-Race** (Operator klickt doppelt) | `hx-indicator` + `hx-disabled-elt="this"` auf dem Button — HTMX deaktiviert ihn während des Requests. |
| **Flat-Mode-Pfad regressiert** (`list_findings` bei aktivem Filter/Sort) | Flat-Mode-Pfad bleibt unverändert (Phase A entfernt nur den Default-Group-Pfad-Code). Bestehende Tests decken ihn ab. |
| **Sort-Divergenz** zwischen SQL-ORDER-BY und bisheriger Python-Sort | SQL-Sort bildet die bisherige `_assemble_risk_band_sections`-Logik 1:1 ab. Verifikation per Test: gleiche Reihenfolge bei identischem Datenset. |

## NICHT in Block Y

- Dashboard-Performance, Sidebar-Lazy-Load, SQL-Aggregation Trend-Services → Block V (ADR-0030).
- Heartbeat-/Sparkline-Service-interne Projektions-Optimierung → Block V (ADR-0030 Befund 6).
- Fragment-Skeleton-Animation-Design → eigener Folge-Block.
- Flat-Mode-Findings-Pfad Refactor → TD-012.
- OOB-Multi-Response-Konsolidierung (ein Request statt 5 Fragment-Requests) → Re-Open-Trigger in ADR-0039.

## Definition of Done (Block-Gesamt)

- `ruff check . && ruff format --check .` PASS.
- `mypy app/` PASS.
- Default-`pytest` PASS, keine Regression.
- `show()` macht **keine** `severity_snapshots_for_server`, `daily_severity_counts_for_server`, `heartbeats_for_servers`, `_load_host_snapshot`, `_build_risk_band_sections` Aufrufe.
- `_build_risk_band_sections` und `_assemble_risk_band_sections` existieren nicht mehr.
- Alle Fragment-Endpoints liefern 200 mit korrektem Partial.
- Triage-Queue ist paginiert (25/Seite), Sort korrekt, "Mehr laden" funktional.
- Kein `select(Finding)` in `_render_findings_section` oder `_load_application_groups_for_server`.
- Drift-Tests für alle OOB-fähigen Fragment-Partials grün.

## Bewusst nicht in der DoD

- Performance-Bench-Läufe (nur auf ausdrückliche User-Anweisung).
- `db_integration`-Tests (nur auf ausdrückliche User-Anweisung).
- Docker-Compose-Smoke.
- Browser-/Playwright-Tests.

## Migrations

Keine. Block Y ist Code-only.

## Tag-Strategie

`v0.14.0` zu setzen nach Branch-Merge auf main.
