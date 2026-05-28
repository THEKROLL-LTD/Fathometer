# Block Y — Orchestrator-Prompt

Kopiere diesen Prompt als Startnachricht in eine neue Claude-Code-Session.

---

Du bist der Orchestrator für **Block Y — Server-Detail Lazy-Render-Architektur + Triage-Queue-Pagination**. Deine Aufgabe ist es, die vier Phasen (A → B → C → D) durch Delegation an Subagenten umzusetzen. Du schreibst selbst keinen Produktionscode — du liest, planst, delegierst, verifizierst und koordinierst.

## Pflicht-Lektüre vor dem ersten Schritt

Lies diese Dateien **komplett**, bevor du irgendetwas delegierst:

1. `CLAUDE.md` — Coding-Conventions, Test-Konvention, Pflicht-Timeouts, HTMX-OOB-Single-Source-Pattern.
2. `docs/decisions/0039-server-detail-lazy-render-architecture.md` — die ADR. Architektur-Entscheidung, Endpoint-Übersicht, Projektions-Tabellen, Skeleton-States, Verworfenes.
3. `docs/blocks/Y-server-detail-lazy-render.md` — Block-Spec mit Phasen, DoD, Risiken.
4. `app/views/server_detail.py` — der Hauptangriffspunkt. Lies die Funktionen `show()`, `_render_findings_section`, `_build_risk_band_sections`, `_assemble_risk_band_sections`, `_load_application_groups_for_server`, `_load_pending_grouping_counts`, `_load_action_required_counts`, `_load_host_snapshot`.
5. `app/templates/servers/detail.html` — Haupt-Template.
6. `app/templates/servers/_view_groups.html` + `app/templates/servers/_partials/risk_band_section.html` — aktuelles Akkordeon-Markup.
7. `app/templates/servers/_partials/group_findings_table.html` — Finding-Row-Markup (Referenz für den Triage-Partial).
8. `docs/design/ServerDetail.jsx` — Design-Referenz. Zeigt die Skeleton-States (`skel`-Prop) für Heartbeat, Severity-Trend und KPI-Tiles. CSS-Klassen: `sd-skel-frame`, `sd-heartbeat__tick--skel`, `sd-trend-col--skel`, `sd-tile--skel`.
9. `frontend/src/css/components/server-detail.css` — bereits portiertes CSS, enthält die `sd-skel-frame`-Animation und `--skel`-Modifier.

## Branch

Erstelle den Branch `feat/block-y-server-detail-lazy-render` von `main` bevor du Phase A delegierst.

## Erlaubte Quality-Gates

Verbindlich für dich UND alle Subagenten — keine Ausnahmen:

1. **Linter** — `ruff check .`, `ruff format --check .`
2. **Static Analyzer** — `mypy app/`
3. **Pure-Unit-Tests** — `pytest` Default-Selektion (ohne `-m db_integration|acceptance|integration|bench`).

**Verboten:** `pytest -m db_integration|acceptance|integration|bench`, `bats`, `RUN_E2E=1`, Docker-Compose, Browser-Tests. Keine proaktiven Aufrufe, keine neuen `.bats`-/.sh-Test-Dateien.

Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf). Keine pytest-Aufrufe ohne Timeout.

## Phasen-Ablauf

### Phase A — Initial-Render-Reduktion + Projektionen

**Delegiere an einen `backend-implementer`-Subagenten** mit folgendem Prompt:

> Du implementierst **Block Y Phase A** — Initial-Render-Reduktion + Projektionen für die Server-Detail-Seite.
>
> **Lies zuerst:**
> - `CLAUDE.md` (Coding-Conventions, Test-Konvention, HTMX-OOB-Pattern)
> - `docs/decisions/0039-server-detail-lazy-render-architecture.md` §1, §4, §5
> - `docs/blocks/Y-server-detail-lazy-render.md` Phase A komplett
> - `app/views/server_detail.py` — insbesondere `show()`, `_render_findings_section`, `_build_risk_band_sections`, `_assemble_risk_band_sections`, `_load_application_groups_for_server`, `_load_pending_grouping_counts`, `_load_action_required_counts`
>
> **Was du tust:**
>
> 1. In `show()`: Aufrufe entfernen für `severity_snapshots_for_server`, `daily_severity_counts_for_server`, `heartbeats_for_servers`, `_load_host_snapshot`, `_build_risk_band_sections`, Noise-Count + Noise-Findings. Die Template-Context-Keys für diese Sektionen durch leere Platzhalter ersetzen oder ganz entfernen (prüfe welche Keys das Template mandatory braucht).
>
> 2. Neue Funktion `_tendency_quick(sess, server_id) -> Tendency`: leichtgewichtige 7-vs-7-Tage-Query (zwei COUNTs oder CASE-Aggregat) statt der vollen 30-Tage-Aggregation. Ersetzt den `tendency_from_counts(trend_data)`-Aufruf in `show()`.
>
> 3. Neue Funktion `_risk_band_header_counts(sess, server_id) -> dict[str, int]`: `SELECT risk_band, COUNT(*) FROM findings WHERE server_id=:sid AND status='open' GROUP BY risk_band`. Ersetzt `_build_risk_band_sections` in `_render_findings_section`.
>
> 4. `_load_application_groups_for_server` — Queries (2), (3), (4) auf Projektionen umstellen:
>    - Query (2): `select(ApplicationGroup.id, ApplicationGroup.label, ApplicationGroup.explanation)`
>    - Query (3): `select(AGE.group_id, AGE.risk_band, AGE.risk_band_reason, AGE.worst_finding_id)`
>    - Query (4): `select(Finding.id, Finding.identifier_key, Finding.package_name)`
>    - Rückgabe bleibt `list[dict]`, Werte sind SQLAlchemy `Row`-Objekte (unterstützen `.`-Attribut-Zugriff im Template).
>
> 5. `_build_risk_band_sections` und `_assemble_risk_band_sections` komplett löschen, inkl. `_SEVERITY_SORT_RANK`. Prüfe ob `_RISK_BAND_SECTION_ORDER` noch anderswo konsumiert wird — wenn ja, behalten; wenn nur dort, löschen.
>
> 6. Query-Deduplizierung: `_load_pending_grouping_counts` und `_load_action_required_counts` zusammenlegen in eine Funktion die beides liefert (total + pending pro Band via FILTER-Aggregat). `count_findings` KEV-Subquery via `COUNT(*) FILTER (WHERE is_kev)` einbauen.
>
> 7. Templates anpassen:
>    - `detail.html` — Sektionen für Sparklines, Heartbeat, Host-Snapshot, Noise auf `hx-trigger="load"`-Platzhalter umstellen. Heartbeat: `<div class="sd-heartbeat-frame sd-skel-frame">` + 30 `sd-heartbeat__tick--skel`-Spans. Trend: `<div class="sd-trend-frame sd-skel-frame">` + 30 `sd-trend-col--skel`-Divs. Host-Snapshot/Noise: kompakter Spinner-Slot. Die `hx-get`-URLs werden in Phase B konkretisiert — verwende vorerst die geplante URL-Struktur: `{{ url_for('server_detail.<fragment_name>', server_id=server.id) }}`.
>    - `_view_groups.html` — Risk-Band-Sektionen rendern nur Header (Band-Name + Count).
>    - `_partials/risk_band_section.html` — Body-Bereich auf HTMX-Lazy-Load-Slot umstellen.
>
> **Tests (schreibe sie):**
> - `_risk_band_header_counts` liefert korrekte Counts pro Band (Mock-Session).
> - `_tendency_quick` liefert korrekte Tendency bei steigend/fallend/stabil.
> - `_load_application_groups_for_server` liefert Projektionen statt ORM-Objekte.
> - Query-Deduplizierung: zusammengelegte Funktion liefert total + pending korrekt.
> - Template-Render: Initial-Render enthält Risk-Band-Header, enthält `hx-trigger`, enthält **keine** Finding-Rows.
> - Bestehende Tests für `_build_risk_band_sections` / `_assemble_risk_band_sections` löschen oder migrieren.
>
> **Quality-Gates (alle müssen grün sein):**
> - `ruff check . && ruff format --check .`
> - `mypy app/`
> - `pytest` Default-Selektion (Bash timeout: 120000 ms)
>
> Erlaubte Quality-Gates: ruff, mypy (Linter/Analyzer), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien. Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

**Nach Rückkehr des Implementers:** Verifiziere die DoD-A selbst:
```bash
grep -rn "_build_risk_band_sections\|_assemble_risk_band_sections" app/
grep -rn "select(Finding)" app/views/server_detail.py
grep -rn "select(ApplicationGroup)" app/views/server_detail.py
```
Dann delegiere an einen `reviewer`-Subagenten:

> Du reviewst **Block Y Phase A**. Lies `docs/blocks/Y-server-detail-lazy-render.md` Phase A DoD. Prüfe:
> 1. DoD-A Punkte 1–6 sind alle erfüllt.
> 2. Keine `select(Finding)` oder `select(ApplicationGroup)` in `app/views/server_detail.py` (nur Projektionen).
> 3. Templates enthalten `hx-trigger="load"`-Platzhalter, keine Finding-Rows im Initial-Render.
> 4. Neue Funktionen haben Type-Annotations (`mypy --strict`-konform).
> 5. Kein `|safe` auf Client- oder LLM-Daten in Templates.
> 6. Keine Pflicht-Kommentare in der UI (ADR-0006).
> Du hast **kein Schreibrecht**. Führe die Quality-Gates selbst aus: `ruff check . && ruff format --check . && mypy app/ && pytest` (Bash timeout: 120000). Wenn REJECT: konkretes Feedback mit Datei:Zeile. Wenn APPROVE: APPROVE-PHASE-A.
>
> Erlaubte Quality-Gates: ruff, mypy (Linter/Analyzer), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe.

Bei REJECT → Feedback an den Implementer, Loop. Bei APPROVE → weiter zu Phase B.

---

### Phase B — HTMX-Fragment-Endpoints

**Delegiere an einen `backend-implementer`-Subagenten:**

> Du implementierst **Block Y Phase B** — HTMX-Fragment-Endpoints für die Server-Detail-Seite.
>
> **Lies zuerst:**
> - `CLAUDE.md` (Coding-Conventions, Test-Konvention, HTMX-OOB-Pattern)
> - `docs/decisions/0039-server-detail-lazy-render-architecture.md` §2, Skeleton-States-Absatz
> - `docs/blocks/Y-server-detail-lazy-render.md` Phase B komplett
> - `docs/design/ServerDetail.jsx` — Skeleton-Pattern (`skel`-Prop bei Heartbeat, SeverityTrend, HeaderStats)
> - `frontend/src/css/components/server-detail.css` — `sd-skel-frame`, `--skel`-Modifier
> - `app/views/server_detail.py` — den aktuellen Stand nach Phase A
> - Die bestehenden Partials: Heartbeat (`_heartbeat_large.html` oder aktueller Name), Host-Snapshot-Pills, Sparkline-/Trend-Templates
>
> **Was du tust:**
>
> 1. Fünf neue Endpoints in `app/views/server_detail.py` (oder einem neuen `server_detail_fragments.py`-Blueprint falls die Datei zu groß wird — Implementer-Entscheidung):
>    - `GET /<id>/fragments/sparklines` — `severity_snapshots_for_server(sess, server.id, days=30)`, rendert Sparkline-Partial.
>    - `GET /<id>/fragments/heartbeat` — `heartbeats_for_servers(sess, [server.id], days=30)`, rendert Heartbeat-Bar-Partial.
>    - `GET /<id>/fragments/host-snapshot` — `_load_host_snapshot(sess, server.id)`, rendert Host-Snapshot-Partial.
>    - `GET /<id>/fragments/trend` — `daily_severity_counts_for_server` + `severity_snapshots_for_server`, rendert Trend-Chart. Optional: OOB-Swap für Tendency falls der Quick-Estimate aus Phase A abweicht.
>    - `GET /<id>/fragments/noise` — Noise-Count + Noise-Findings (max 50), rendert Noise-Modal-Content.
>
> 2. Alle Endpoints: `@login_required`, revoked/retired-404-Guard. Nutze einen shared Helper oder Decorator (prüfe ob `show()` schon einen hat den du wiederverwenden kannst).
>
> 3. HTMX-OOB-Single-Source-Pattern beachten: wenn ein Partial sowohl als Skeleton (Initial-Render) als auch als Live-Fragment gerendert wird, gleiche Datei mit Conditional-Flag (`{% if skel %}…{% endif %}`). Keine zwei separaten Templates mit kopiertem Markup.
>
> 4. `detail.html` — Skeleton-Platzhalter aus Phase A mit den konkreten `hx-get`-URLs versehen:
>    - Heartbeat: `sd-heartbeat-frame sd-skel-frame` + 30 `sd-heartbeat__tick--skel`-Spans, `hx-get` auf heartbeat-Fragment, `hx-trigger="load"`, `hx-swap="outerHTML"`.
>    - Severity-Trend: `sd-trend-frame sd-skel-frame` + 30 `sd-trend-col--skel`-Divs, analog.
>    - KPI-Tiles: `sd-tile--skel sd-skel-frame` mit Em-Dash, analog.
>    - Host-Snapshot/Noise: kompakter Spinner, `hx-trigger="load"` bzw. Modal-Open-Trigger.
>
> **Tests:**
> - Pro Endpoint: 200-Response mit erwartetem Markup.
> - Pro Endpoint: 404 bei unbekanntem Server, 404 bei revoked/retired.
> - Pro Endpoint: 302 bei unauthentifiziertem Request.
> - Template-Smoke: `GET /<id>` enthält `hx-get` für alle fünf Fragment-URLs.
>
> **Quality-Gates:** `ruff check . && ruff format --check . && mypy app/ && pytest` (Bash timeout: 120000).
>
> Erlaubte Quality-Gates: ruff, mypy (Linter/Analyzer), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien. Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

**Reviewer-Delegation** analog Phase A, mit DoD-B als Checkliste.

---

### Phase C — Triage-Queue: Collapsed + Lazy + Paginiert

**Delegiere an einen `backend-implementer`-Subagenten:**

> Du implementierst **Block Y Phase C** — Triage-Queue mit Collapsed-Akkordeons, Lazy-Load und Pagination.
>
> **Lies zuerst:**
> - `CLAUDE.md` (Coding-Conventions, Test-Konvention)
> - `docs/decisions/0039-server-detail-lazy-render-architecture.md` §3
> - `docs/blocks/Y-server-detail-lazy-render.md` Phase C komplett
> - `app/views/server_detail.py` — aktueller Stand nach Phase A+B
> - `app/templates/servers/_partials/risk_band_section.html` — aktuelles Akkordeon-Markup
> - `app/templates/servers/_partials/group_findings_table.html` — Finding-Row-Markup als Referenz
>
> **Was du tust:**
>
> 1. Neuer Endpoint `GET /<id>/triage/<band>`:
>    - `band`-Whitelist-Validierung (400 bei ungültig).
>    - `page`-Parameter: `request.args.get("page", 1, type=int)`, Minimum 1.
>    - **Projektion-Query** (13 Spalten): `Finding.id, .identifier_key, .title, .package_name, .installed_version, .fixed_version, .epss_score, .cvss_v3_score, .severity, .is_kev, .risk_band_reason, .status, .finding_class`. **Kein `select(Finding)`**.
>    - Sort: `is_kev DESC, severity ASC, epss_score DESC NULLS LAST`.
>    - `LIMIT 26 OFFSET (page-1)*25`. Wenn 26 Rows: "Mehr laden"-Button.
>    - `@login_required`, revoked/retired-404-Guard.
>
> 2. Neues Partial `_partials/triage_findings_page.html`:
>    - Rendert bis zu 25 Finding-Rows (Markup analog `risk_band_section.html` Finding-Stack, aber aus Projektions-Rows statt ORM-Objekten).
>    - Optionaler "Mehr laden"-Button: `hx-get="/<id>/triage/<band>?page=<N+1>"`, `hx-swap="outerHTML"`, `hx-disabled-elt="this"`.
>    - Kein `|safe` auf `risk_band_reason` oder andere LLM-Daten — Jinja-Autoescape ist Pflicht.
>
> 3. `_partials/risk_band_section.html` anpassen:
>    - Body-Bereich: `hx-get="/<id>/triage/<band>?page=1"`, Spinner-Placeholder.
>    - Default-Open-Band (höchstes nicht-leeres): `<details open>` + `hx-trigger="load"` (lädt sofort).
>    - Alle anderen: `hx-trigger="toggle"` (lädt bei Expand).
>
> **Tests:**
> - Korrekte Findings für Band, korrekte Sortierung.
> - Pagination: Page 1 liefert 25, "Mehr laden" nur bei > 25.
> - 400 bei ungültigem Band, 404 bei unbekanntem Server.
> - Leeres Band liefert leeren Response.
> - Projektion: keine ORM-Objekte im Response.
> - Template: Default-Open-Band hat `open` + `hx-trigger="load"`.
>
> **Quality-Gates:** `ruff check . && ruff format --check . && mypy app/ && pytest` (Bash timeout: 120000).
>
> Erlaubte Quality-Gates: ruff, mypy (Linter/Analyzer), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien. Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

**Reviewer-Delegation** analog, mit DoD-C.

---

### Phase D — Aufräumen + Drift-Tests

**Delegiere an einen `test-writer`-Subagenten:**

> Du räumst nach **Block Y Phasen A–C** auf und schreibst Drift-Regressions-Tests.
>
> **Lies zuerst:**
> - `CLAUDE.md` (HTMX-OOB-Single-Source-Pattern, Test-Konvention)
> - `docs/blocks/Y-server-detail-lazy-render.md` Phase D komplett
>
> **Was du tust:**
>
> 1. Verwaiste Imports, Helper, Konstanten aus `app/views/server_detail.py` entfernen. `grep -rn` nach allen gelöschten Funktionsnamen, alten Imports, unbenutzten Konstanten.
>
> 2. `tests/` — alte Tests für `_build_risk_band_sections`, `_assemble_risk_band_sections` final entfernen falls noch vorhanden.
>
> 3. Drift-Regressions-Tests schreiben (CLAUDE.md §HTMX-OOB-Single-Source-Pattern): für jeden Fragment-Partial der sowohl als Skeleton (Initial-Render) als auch als Live-Fragment existiert:
>    - Struktureller Vergleich: gleiche IDs, gleiches Klassen-Set pro Element, gleiche `data-*`-Keys.
>    - Heartbeat, Sparklines, Host-Snapshot — mindestens je ein Drift-Test.
>
> 4. Finale Grep-Verifikation:
>    - `grep -rn "select(Finding)" app/views/server_detail.py` — nur im Flat-Mode-Pfad (`list_findings`).
>    - `grep -rn "_build_risk_band_sections\|_assemble_risk_band_sections\|_SEVERITY_SORT_RANK" app/ tests/` — nichts.
>
> 5. Coverage-Audit: jeder neue Endpoint aus Phase B und C hat mindestens einen Happy-Path und einen Error-Path Test.
>
> **Quality-Gates:** `ruff check . && ruff format --check . && mypy app/ && pytest` (Bash timeout: 120000).
>
> Erlaubte Quality-Gates: ruff, mypy (Linter/Analyzer), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien. Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

**Reviewer-Delegation** analog, mit DoD-D. Wenn der Reviewer APPROVE-PHASE-D gibt:

---

## Nach allen vier Phasen

1. Verifiziere die **Block-Gesamt-DoD** aus `docs/blocks/Y-server-detail-lazy-render.md`:
   - `show()` macht keine der entfernten Aufrufe.
   - `_build_risk_band_sections` / `_assemble_risk_band_sections` existieren nicht.
   - Alle Fragment-Endpoints liefern 200.
   - Triage-Queue paginiert, Sort korrekt.
   - Kein `select(Finding)` in `_render_findings_section` / `_load_application_groups_for_server`.
   - Drift-Tests grün.

2. Aktualisiere `docs/blocks/STATE.md`:
   - Block Y Status von `Geplant` auf `Abgeschlossen (YYYY-MM-DD)`.
   - Commit-Tabelle mit Phase-Commits eintragen.
   - Test-Kennzahlen (passed/skipped/deselected, Laufzeit).

3. Schreibe eine PR-Beschreibung für `feat/block-y-server-detail-lazy-render → main`.

4. **STOP** — frage den User ob der Branch gemerged werden soll.

## Allgemeine Regeln für alle Subagenten-Prompts

Jeder Subagent-Prompt enthält wörtlich:

- „Erlaubte Quality-Gates: ruff, mypy (Linter/Analyzer), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien."
- „Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf)."
- Die zu lesenden Dateien explizit mit Pfad und Sektion.
- Die Phase-DoD als Abschluss-Checkliste.

Reviewer-Subagenten haben **kein Schreibrecht**. Sie führen die Quality-Gates selbst aus und prüfen die DoD. Bei REJECT: konkretes Feedback. Bei APPROVE: explizites `APPROVE-PHASE-X`.

Verstöße gegen die Test-Konvention (verbotene Marker, fehlende Timeouts) werden vom Orchestrator zurückgewiesen — egal ob Implementer oder Reviewer.
