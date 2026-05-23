# Block V — Performance-Tuning UI-Views

**Spec-Quelle:** [ADR-0030](../decisions/0030-server-detail-performance.md)
**Branch:** `feat/block-v-ui-performance`
**Zielversion:** v0.12.0
**Vorgänger:** Block U (v0.11.0, ADR-0029 Worker-Concurrency). Block T (ADR-0028 Junction) ist Voraussetzung der Application-Group-Loader-Aggregate aus dem Server-Detail.
**Status:** Geplant

## Ziel

Dashboard `/` und Server-Detail `/servers/<id>` rendern signifikant schneller. Konkrete DoD-Ziele aus ADR-0030 §Definition of Done:

- Dashboard Server-Zeit median **< 800 ms** (heute Wallclock 3.45 s, 2 Server / 18 537 Findings).
- Server-Detail Server-Zeit median **< 1.5 s** (heute Wallclock 7.88 s, 9 224 OPEN-Findings).
- DB-Query-Count Dashboard **≤ 6** (heute 12–14), Server-Detail **≤ 12** (heute 17–22).
- Trend-Sektion **< 100 ms** Server-Zeit.
- Sidebar zeigt echte Server-Namen ≤ 500 ms nach Page-Open; Heartbeats + ESCALATE/ACT erscheinen ≤ 2 s danach via Skeleton-Swap.

**Nicht-Ziele:** Re-Design der Sidebar/Dashboard-UI (das Block-V-Skeleton-Markup folgt dem heutigen Layout-Vertrag; das neue Cyan/Grau/Grün-Design plus Scan-Animation kommt im separaten Re-Design-Block). Sowie sämtliche Punkte aus ADR-0030 §"Weitere Performance-Aspekte" — eigene Folge-ADRs.

## Spec-Referenzen (Pflicht-Lektüre)

1. **ADR-0030 komplett** — neun Befunde, fünf Phasen, Konsequenzen, DoD.
2. **ADR-0017 (Dashboard-Pane-Pattern)** — HX-Pfad vs. Full-Page-Pfad, gemeinsamer Pane-Context. Bleibt unverändert.
3. **ADR-0018 (Header-Stats / 50-Tage-Trend)** — Sparklines, Daily-Counts, Tendency. Implementierungs-intern getauscht, Format/Semantik unverändert.
4. **ADR-0019 (Sidebar-Polling)** — wird durch Phase C inhaltlich erweitert: Polling-Endpoint wird zum **einzigen** Daten-Pfad für Sidebar-Aggregate; Cadence (10 s, sichtbarer Tab) bleibt, zusätzlicher `load`-Trigger für Initial-Lazy-Load.
5. **ADR-0023 §Application-Grouping-Loader-Aggregate** und ADR-0028 §Junction — Server-Detail-Group-Cards bleiben unverändert; Block V berührt nur den Trend-/Header-Pfad.
6. **`app/views/dashboard.py`** komplett — `_build_pane_context`, `_load_open_aggregates`, `_load_risk_kpi_counters`. Phase A + D Hauptangriffsfläche.
7. **`app/views/server_detail.py::show`** und `_render_findings_section` — Phase B Hauptangriffsfläche.
8. **`app/views/_sidebar_context.py`** — Context-Processor + Polling-Endpoint. Phase C Hauptangriffsfläche.
9. **`app/services/severity_history.py`** + **`app/services/trend.py`** — Phase B und Phase E ändern beide Services additiv (vorgeladene Rows + SQL-Pfad).
10. **`app/services/heartbeat_aggregation.py`** — Phase C ändert die `select(Finding)`-Projektion auf schmal.
11. **`app/services/quick_stats.py`** und **`app/templates/sidebar/_quick_stats.html`** — Phase A löscht beide.
12. **`app/templates/sidebar/_server_list.html`** und **`_server_row.html`** — Phase C ändert HTMX-Trigger und fügt Skeleton-Markup ein.
13. **CLAUDE.md §"Test-Konvention — Default vs. On-Demand"** — Verbindlich für jeden Implementer-Agenten. Block V macht keinerlei Schema-Touch, keine `db_integration`-Tests pflichtig — alle Phasen pure-unit-testbar.

## Modell-Änderungen

**Keine.** Block V ist Code-only — keine Alembic-Migration, keine neue Settings-Spalte, keine Schema-Drift. Das ist absichtlich Teil der Risiko-Minimierung.

## Phasen

### Phase A — Dead-Code-Entfernung (Befund 9)

**Dateien:**
- `app/services/quick_stats.py` — komplett löschen.
- `app/templates/sidebar/_quick_stats.html` — komplett löschen.
- `app/views/dashboard.py::_build_pane_context` — `get_quick_stats`-Call und `quick_stats`-Context-Key entfernen.
- `app/views/_sidebar_context.py::build_sidebar_context` — `get_quick_stats`-Call und `quick_stats`-Context-Key entfernen; `QuickStats`-Import weg.
- `app/templates/base_app.html` — Doc-Comment-Verweis auf `quick_stats` entfernen (Z. 10).
- `app/templates/dashboard/_detail_pane.html` — Doc-Comment-Verweis auf `quick_stats` entfernen (Z. 23).
- `tests/services/test_quick_stats.py` — löschen.
- Adversarial-/Integration-Tests grep nach `quick_stats` und sauber migrieren oder löschen.

**Tests:**
- `tests/views/test_dashboard.py` (existierender, Pure-Unit) — etwaige `quick_stats`-Assertions raus.
- `tests/views/test_sidebar_context.py` (falls existent) — analog.
- Default-`pytest` muss grün bleiben, keine `ModuleNotFoundError` oder `AttributeError` auf `quick_stats`.

**DoD-A:**
1. `grep -rn "quick_stats" app/ tests/` liefert **nichts**.
2. `ruff check . && ruff format --check . && mypy app/` PASS.
3. Default-`pytest -v 2>&1 | tee /tmp/v_phase_a.txt` PASS, Test-Anzahl reduziert sich um die gelöschten Tests, keine neuen FAIL.

### Phase B — Server-Detail Quick-Wins (Befunde 1 + 2)

**Dateien:**
- `app/services/severity_history.py` — `severity_snapshots_for_server` und `daily_severity_counts_for_server` bekommen einen optionalen `rows: list[_FindingRow] | None = None`-Parameter. Wenn `None`, läuft heutiger `_load_findings`-Pfad; wenn gesetzt, wird der DB-Aufruf übersprungen. Pure-Helper (`_compute_snapshots`, `_compute_daily_counts`) unverändert.
- `app/services/trend.py` — neue Pure-Funktion `tendency_from_counts(counts: list[DailySeverityCount], days_short=7, days_long=50, threshold=0.05) -> Tendency`. `compute_tendency(session, server_id, …)` bleibt als dünner Wrapper bestehen, der die Counts lädt und an die Pure-Funktion delegiert (Backward-Compat für Bestands-Aufrufer in Tests).
- `app/views/server_detail.py::show` — gemeinsamer `_load_findings`-Call vor den Aggregator-Aufrufen, Row-Liste an `severity_snapshots_for_server(rows=…)` und `daily_severity_counts_for_server(rows=…)` weiterreichen. Tendency wird aus `trend_data` per `tendency_from_counts(trend_data)` abgeleitet — kein separater `compute_tendency`-Call mehr.
- `app/views/server_detail.py::_render_findings_section` — `list_findings`-Call hinter Conditional `_force_flat or _filters_active or not _sort_default` (gleiche Logik wie heute im Template) ziehen. Wenn die flache Liste nicht gerendert wird, leere Liste in den Context.

**Tests:**
- `tests/services/test_severity_history.py` — neuer Test für vorgeladene `rows=`-Variante.
- `tests/services/test_trend.py` — neuer Test für `tendency_from_counts` als Pure-Funktion. Bestehende `compute_tendency`-Tests bleiben.
- `tests/views/test_server_detail.py` (Pure-Unit) — Test dass im Group-Default-Pfad `findings`-Context-Key leer ist, im Flat-Pfad gefüllt.

**DoD-B:**
1. `_load_findings` läuft im Server-Detail-View nur noch **einmal** (Logging-Check: structlog-Marker oder Test-Spy auf den Service-Call).
2. `list_findings` läuft im Group-Default-Pfad **gar nicht**.
3. `mypy app/` PASS.
4. Default-`pytest` PASS, mindestens 3 neue Tests grün.

### Phase C — Sidebar Lazy-HTMX-Load (Befund 8, erschlägt 4 + 6 + 7)

**Dateien:**
- `app/views/_sidebar_context.py::build_sidebar_context` — auf **billig-only** schrumpfen: liefert nur noch `sidebar_servers` (Server-Liste mit eager `tag_links`), `active_server_id` (vom View überschrieben), `filter_tags`. Keine `heartbeats_for_servers`-, keine `get_quick_stats`-Aufrufe mehr (letztere ist eh in Phase A weg). `available_tags` als billige `select(Tag)`-Query bleibt.
- `app/views/_sidebar_context.py::sidebar_partial` (Endpoint `/_partials/sidebar`) — wird zur **alleinigen** Quelle der teuren Aggregate. Liefert das `<ul id="server-list">`-Fragment inklusive Heartbeats, ESCALATE-/ACT-Counts pro Server und Header-Counter (`HOSTS`, `ALARM`).
- `app/services/heartbeat_aggregation.py::heartbeats_for_servers` — schmale Projektion: `select(Finding.server_id, Finding.severity, Finding.first_seen_at, Finding.acknowledged_at, Finding.resolved_at, Finding.is_kev, Finding.kev_added_at)` statt `select(Finding)`. Tuple-Iteration in der Loader-Schleife, kein ORM-Hydrate mehr. Öffentliche Signatur (`dict[int, list[DailyStatus]]`) unverändert.
- **Neuer Service** `app/services/sidebar_risk_counts.py` (oder analoger Pfad) mit Funktion `escalate_act_counts_by_server(session, server_ids: list[int]) -> dict[int, dict[str, int]]`. Eine Query: `SELECT server_id, risk_band, COUNT(*) FROM findings WHERE status='open' AND risk_band IN ('escalate','act') AND server_id IN (...) GROUP BY server_id, risk_band`. Rückgabe: `{server_id: {"escalate": n, "act": m}}`. Header-`ALARM` ist `len({sid for sid, c in result.items() if c.get('escalate', 0) > 0})`.
- `app/templates/sidebar/_server_list.html` — HTMX-Trigger von `every 10s [...]` auf `load, every 60s [document.visibilityState === 'visible']` umstellen. **Polling-Intervall von 10 s auf 60 s erhöht** (bewusste Spec-Änderung im Rahmen von Phase C, siehe ADR-0030 §Konsequenzen). Header-Markup (`HOSTS · ALARM`) ergänzen — `HOSTS` initial echt aus `sidebar_servers | length`, `ALARM` mit Skeleton-Wrapper.
- `app/templates/sidebar/_server_row.html` — Skeleton-Markup für Heartbeat-Bar (50 Cells), ESCALATE-Spalte, ACT-Spalte. Live-Werte werden vom Polling-Endpoint via `outerHTML`-Swap eingesetzt. Skeleton-Klassen so wählen, dass das Re-Design später nur die Animation austauscht (Layout/Größe stabil).
- `app/templates/sidebar/_heartbeat_bar.html` — optional: Skeleton-Variante per `{% if cells is none %}` rendern, dieselbe Datei. Alternative: separater Partial `_heartbeat_skeleton.html`. Implementer-Entscheidung; Layout-Footprint identisch.

**Tests:**
- `tests/services/test_heartbeat_aggregation.py` — Test gegen schmale Projektion (Pure-Unit mit Fake-Session, Tuple-Return), Verhalten unverändert.
- `tests/services/test_sidebar_risk_counts.py` — neu, Pure-Unit für die GROUP-BY-Aggregation.
- `tests/views/test_sidebar_context.py` — `build_sidebar_context` liefert nur billige Felder, kein Heartbeat-Loader-Aufruf (Test-Spy).
- `tests/views/test_sidebar_partial.py` — Polling-Endpoint liefert Heartbeats + Risk-Counts + Header.
- Template-Smoke-Tests (Pure-Unit gegen Jinja-Render-Output): Skeleton-Markup ist im initialen `/`-Render vorhanden; Polling-Endpoint-Output enthält Live-Werte.

**DoD-C:**
1. `build_sidebar_context` ruft **kein** `heartbeats_for_servers` oder `get_quick_stats` mehr auf (Test-Spy oder grep).
2. `heartbeats_for_servers` lädt **kein** `select(Finding)` mehr (grep oder Test).
3. Initialer `/`-Render enthält Server-Liste + Skeleton-Markup; Polling-Endpoint liefert Live-Daten.
4. HTMX-Trigger ist `load, every 60s [...]` — sichtbar im gerenderten Markup.
5. Default-`pytest` PASS, mindestens 5 neue Tests grün.

### Phase D — Dashboard-Risk-Aggregate-Konsolidierung (Befund 5)

**Dateien:**
- `app/views/dashboard.py::_load_open_aggregates` — zwei Queries (Severity-GROUP-BY + KEV-Count) in eine Query mit `func.count().filter(...)` pro Bucket konsolidieren. Beispiel-Skizze:
  ```python
  stmt = (
      select(
          Finding.server_id,
          func.count().filter(Finding.severity == Severity.CRITICAL).label("crit"),
          func.count().filter(Finding.severity == Severity.HIGH).label("high"),
          func.count().filter(Finding.severity == Severity.MEDIUM).label("medium"),
          func.count().filter(Finding.severity == Severity.LOW).label("low"),
          func.count().filter(Finding.severity == Severity.UNKNOWN).label("unknown"),
          func.count().filter(Finding.is_kev.is_(True)).label("kev"),
      )
      .where(Finding.status == FindingStatus.OPEN)
      .group_by(Finding.server_id)
  )
  ```
- `app/views/dashboard.py::_load_risk_kpi_counters` — drei Findings-Aggregate (Risk-Band-GROUP-BY, Yes-Server-DISTINCT, Severity-Strip-GROUP-BY) in eine Query mit `COUNT(*) FILTER (...)`-Buckets pro `risk_band` + pro `severity`-Wert. Active-Server-Count bleibt eigenständig (operiert auf `servers`-Tabelle, nicht `findings`); `yes_servers`-Count wird aus dem Pro-Server-Aggregat (siehe Phase C, oder Inline) abgeleitet — keine separate Distinct-Query mehr.
- ggf. gemeinsamer Helper `app/services/dashboard_aggregates.py` falls die Funktionen wachsen.

**Tests:**
- `tests/views/test_dashboard.py` — Verhalten unverändert, alte Test-Assertions auf Counter-Werte greifen weiter.
- `tests/services/test_dashboard_aggregates.py` — falls neuer Helper.

**DoD-D:**
1. `_load_open_aggregates` macht **eine** Query (grep oder Test-Spy: `session.execute`-Calls zählen).
2. `_load_risk_kpi_counters` macht **eine** Findings-Query plus eine Server-Tabellen-Query (heute 4 Queries).
3. Phase D **trägt ihren Anteil zur Block-V-Gesamt-Schranke** aus ADR-0030 §DoD bei: Dashboard-Findings-relevante Queries von 5–7 auf 2 reduziert (`_load_open_aggregates` 1 + `_load_risk_kpi_counters` 1 = 2 Findings-Queries + 1 Server-Count). Die ≤ 6-Gesamt-Schranke wird erst nach Phasen C + E erreicht (Phase C eliminiert Sidebar-Heartbeat-Pfad, Phase E konsolidiert `daily_severity_counts_fleet`/`daily_stale_server_counts`); Phase D allein landet nach Code-Walk bei 9 Queries (heute 12–14).
4. `mypy app/` PASS.
5. Default-`pytest` PASS.

### Phase E — SQL-Aggregation für `severity_history` (Befund 3)

**Dateien:**
- `app/services/severity_history.py` — neue Helper `_load_daily_aggregates_sql(session, server_id, days)` mit `generate_series` + `COUNT(*) FILTER (...)` pro Tag-Bucket. Aufruf-Pfad: `severity_snapshots_for_server` und `daily_severity_counts_for_server` nutzen den SQL-Pfad als Default. Pure-Python-Pfad (`_compute_snapshots`, `_compute_daily_counts`) bleibt im Code für Tests und als Fallback per Feature-Flag oder Environment-Override (Implementer-Entscheidung; ohne Flag ist Cutover akzeptabel solange Tests grün).
- `app/services/severity_history.py::daily_severity_counts_fleet` — analog auf SQL-`generate_series`-Aggregation umstellen. Diff-Array-Walk-Code kann ersatzlos weg oder als Fallback bleiben (Implementer-Wahl).
- `app/services/trend.py::tendency_from_counts` — keine Änderung; konsumiert weiterhin die `DailySeverityCount`-Liste.

**Tests:**
- `tests/services/test_severity_history.py` — Pure-Unit-Tests bleiben gegen die Python-Aggregations-Helper. SQL-Pfad wird über `db_integration`-Marker getestet (nur auf User-Anweisung gefahren); Pure-Unit-Test gegen den **SQL-String** (kompiliertes Statement matcht Erwartung) als billige Coverage-Schicht.

**DoD-E:**
1. `severity_snapshots_for_server` / `daily_severity_counts_for_server` führen für die 50-Tage-Aggregation **eine** SQL-Query aus statt Python-Loop über alle Findings.
2. Trend-Sektion-Render auf Server-Detail-View **< 100 ms** Server-Zeit (Latency-Logger oder structlog-Marker mit `time.perf_counter()`).
3. Default-`pytest` PASS, keine Regression in `tests/services/test_severity_history.py` / `test_trend.py`.

## Phasen-Abhängigkeiten

```
A (Dead Code) → keine Abhängigkeit, kann zuerst, schafft Klarheit
B (Server-Detail Quick-Wins) → unabhängig von A, kann parallel
C (Sidebar Lazy-Load) → braucht A (kein quick_stats mehr)
D (Dashboard-Aggregate-Konsolidierung) → unabhängig von A/B/C
E (SQL-Trend-Aggregation) → setzt B voraus (gemeinsamer rows-Loader-Pfad als Stepping-Stone)
```

Empfohlene Implementer-Reihenfolge: **A → B → C → D → E**. A → C ist die einzige harte Abhängigkeit; B kann parallel zu C laufen; D ist unabhängig; E am Ende, weil die kleinen Gewinne (A–D) zusammen den Großteil des wahrnehmbaren Effekts liefern und E am aufwendigsten ist.

Jede Phase ist ein eigener Commit auf `feat/block-v-ui-performance`. Reviewer-Approval am Ende jeder Phase. Sicherheits-relevant ist keine Phase (kein neuer Auth-Pfad, keine neuen User-Inputs).

## Risiken & Mitigation

| Risiko | Mitigation |
|---|---|
| **Sidebar-Skeleton verschiebt Layout beim Daten-Swap** | Skeleton-Markup mit identischen Cell-Größen / `min-width`-Tokens. Visueller QA-Check beim Phase-C-Review. |
| **Operator ohne JavaScript sieht permanent Skeleton-Sidebar** | Akzeptable Degradation für Admin-UI im internen Netz (ADR-0030 §Risiken). Falls operativ relevant: `<noscript>`-Fallback mit dem alten Inline-Render. |
| **HTMX-Polling-Race beim ersten Page-Load** (abgebrochener Sidebar-Request mit `NS_BINDING_ABORTED` heute schon beobachtet) | Mit dem `load`-Trigger feuert nur **ein** initialer Request; der 10-s-Polling-Cycle setzt erst danach ein. Falls Race besteht: HTMX `hx-trigger` mit `delay:100ms` als Backstop, oder `htmx:load`-Event-Listener statt CSS-Trigger. |
| **Tag-Filter wird beim Lazy-Sidebar-Request vergessen** | Endpoint nimmt heute schon `request.args.getlist("tag")` entgegen; Template-Link muss den Filter mitschicken. Test in Phase C: Tag-Filter im Polling-URL vorhanden, Sidebar-Antwort respektiert ihn. |
| **`active_server_id`-Highlight verschwindet kurz beim Lazy-Swap** | Initial-Render setzt das Highlight korrekt aus `active_server_id` (View-Context); der Lazy-Swap muss den aktiven Server beibehalten. Polling-Endpoint nimmt `active_server_id` als Query-Param (heute schon). |
| **Phase E SQL-Pfad weicht in Edge-Cases vom Python-Pfad ab** | Pure-Python-Aggregations-Helper bleiben als Test-Doubles, werden weiterhin via Pure-Unit getestet. SQL-Pfad bekommt Test gegen kompilierten Statement-String plus optional db_integration-Markered Verhaltens-Vergleich (auf User-Anweisung). |
| **`select(Finding)` versteckt sich noch anderswo** | grep nach `select(Finding)` in `app/services/` und `app/views/` als Phase-C-Verification-Step. Heartbeat-Pfad ist der teuerste, aber andere full-Row-Selects sollten gleich mit überprüft werden. |
| **Test-Coverage-Lücke beim Lazy-Polling-Endpoint** | Phase C definiert mindestens 5 Tests; Polling-Endpoint braucht denselben Coverage-Stand wie der heutige Inline-Pfad. |

## NICHT in Block V

Aus ADR-0030 §"Weitere Performance-Aspekte" — bewusst aus Scope ausgeschlossen, eigene Folge-ADRs oder TD-Einträge:

- `/findings` Cross-Server-Liste bei wachsender Server-Anzahl.
- Worker-Lese-Pfade (Pass-1/Pass-2-Inputs, heute mehrfache `Finding`-Selects pro Job-Batch).
- `_load_action_required_counts` + `_quick_counts_for_server` (Server-Detail) FILTER-Aggregat-Konsolidierung.
- `_load_application_groups_for_server`-Sortierung in SQL statt Python.
- EXPLAIN-Walk bei wachsender Findings-Tabelle (Re-Check, ob Composite-Indices greifen).
- Server-side Render-Time-Instrumentierung (`time` / structlog-Latenz-Logger).
- DB-Pool-Sizing-Review für Flask-App (analog ADR-0029 §6).
- Pre-Computed Materialized Views.
- In-Memory-Cache für Trend-Daten.
- Status-Indikator-Logik (cyan/grau/grün) und Skeleton-Scan-Animation — separater Re-Design-Block.

Falls einer dieser Punkte operativ relevant wird, eigener Folge-ADR oder TD-Eintrag in `docs/techdebt.md`.

## Cutover & Operator-Impact

Kein Schema-Touch, keine Migration, keine Operator-Aktion über den Pod-Restart hinaus.

Erwartete Operator-Schritte nach Deploy v0.12.0:

1. Pod-Restart `secscan-app` (neue View-Code-Pfade).
2. Sanity-Check: `/` öffnen, prüfen ob Sidebar mit Skeleton kurz aufblitzt und dann Live-Daten erscheinen.
3. Sanity-Check: `/servers/<id>` für einen großen Server (z. B. rke2-sv-1 mit 9k Findings) öffnen, prüfen ob TTFB spürbar schneller ist.

Kein Worker-Restart, kein DB-Touch, kein Settings-UI-Touch. Rollback durch Branch-Revert; alle Änderungen sind Code-only.
