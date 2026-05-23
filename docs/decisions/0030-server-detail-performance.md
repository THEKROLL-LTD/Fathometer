## ADR-0030 — Performance-Tuning UI-Views

**Status:** Akzeptiert · **Akzeptiert:** 2026-05-23 · **Datum:** 2026-05-23 · **Block:** V (Implementation, `docs/blocks/V-ui-performance.md` noch anzulegen) · **Bezug:** ARCHITECTURE.md §7 (Server-Detail-View, Dashboard), §7a (Sidebar/QuickStats), ADR-0017 (Dashboard-Pane-Pattern), ADR-0018 (Header-Stats / 50-Tage-Trend), ADR-0019 (Sidebar-Polling), ADR-0020 (Cross-Server-Sparklines), ADR-0022 (Risk-KPI-Header), ADR-0023 (Application-Grouping-Loader-Aggregate), ADR-0025 (Server-Detail-Slim-Down, Lazy-Group-Findings), ADR-0028 (Application-Group-Evaluations-Junction).

## Kontext

Operator-Befund 2026-05-23 unter Realbetrieb (k8s, CNPG, 2 Server, 18 537 Findings, ~9 224 OPEN pro Server, LLM-Pass-1+2 abgeschlossen):

| Route | Wallclock | Bemerkung |
|---|---|---|
| `GET /servers/2` | **7.88 s** | flotter Server, ~9 200 OPEN-Findings |
| `GET /_partials/sidebar` (parallel) | **2.54 s** | + 1 abgebrochener Polling-Call (`NS_BINDING_ABORTED`) |
| `GET /` (Dashboard) | **3.45 s** | nur 2 Server, dominierte von Aggregat-Queries |
| `GET /_partials/sidebar` (parallel Dashboard) | **2.31 s** | Sidebar-Polling-Refresh |

Server-Hardware nicht ausgelastet (CPU/Mem-Headroom reichlich). DB-Roundtrip-Latenz vernachlässigbar (App im Cluster, DB-Service direkt erreichbar). Bottleneck liegt im App-Code, nicht in Hardware oder Netz.

Vorgehen für den ADR: erst alle Befunde sammeln, dann Lösungs-Reihenfolge nach Effekt-/Aufwand-Ratio festlegen, dann Block zuweisen und implementieren.

## Befunde

### Befund 1 — Dreifache redundante `_load_findings`-Calls + dreifache O(days × N)-Python-Schleifen

In `app/views/server_detail.py:461-466` ruft die Detail-Route nacheinander auf:

```python
tendency       = compute_tendency(sess, server.id)                          # ruft daily_severity_counts intern
sparklines     = severity_snapshots_for_server(sess, server.id, days=50)
trend_data     = daily_severity_counts_for_server(sess, server.id, days=50)
kev_events_50d = count_kev_events_50d(sess, server.id)
```

`compute_tendency` (`app/services/trend.py:78`) ruft intern `daily_severity_counts_for_server` mit denselben 50 Tagen auf wie der direkte Call drei Zeilen später — **redundant**. Sparklines und Daily-Counts haben separate Loader, laden aber **dieselbe Row-Liste**.

`_load_findings` (`app/services/severity_history.py:148`) führt jedes Mal einen Seq Scan über die `findings`-Tabelle aus. Bei rke2-sv-1 (server_id=2):

```
EXPLAIN (ANALYZE, BUFFERS) SELECT severity, first_seen_at, acknowledged_at, resolved_at, kev_added_at, is_kev
FROM findings WHERE server_id = 2 AND (acknowledged_at IS NULL OR acknowledged_at >= NOW()-INTERVAL '50 days')
              AND (resolved_at IS NULL OR resolved_at >= NOW()-INTERVAL '50 days');
→ Seq Scan, 9224 Rows, Execution Time: 62.926 ms
```

Drei identische Calls × 63 ms = **≈ 190 ms reine DB-Roundtrip-Zeit** für die Trend-Sektion. Schmerzhafter ist die Python-Seite:

- `_compute_snapshots`: 50 Tage × 9 224 Rows = **461 200** `_is_open_at`-Aufrufe + Dict-Updates pro Call.
- `_compute_daily_counts`: 50 × 9 224 = **461 200** Iterationen pro Call; läuft **zweimal** (via `compute_tendency` und direkt).

Summe: **≈ 1.4 Millionen Python-Iterationen** mit datetime-Vergleichen, Enum-Lookups und Dict-Schreibzugriffen — geschätzt 2–5 s CPU-Zeit auf CPython ohne Optimierung, je nach Container-CPU-Budget.

**Lösungsskizze:**
- Tendency aus dem ohnehin berechneten `trend_data` ableiten — `compute_tendency` wird zu einer Pure-Funktion `tendency_from_counts(counts, …)` ohne eigenen Loader-Call.
- Einen gemeinsamen `_load_findings`-Call vor den Aggregatoren, Row-Liste an `_compute_snapshots` und `_compute_daily_counts` weiterreichen. Public-API der Services bleibt für andere Aufrufer erhalten; intern wird die Row-Liste injizierbar.
- Längerfristig: siehe Befund 3.

### Befund 2 — `list_findings` im Group-Default-Pfad unkonditional

`app/views/server_detail.py:_render_findings_section` ruft unkonditional `list_findings(…, limit=500)`. Im Default-Pfad (kein User-Filter, Sort `risk desc`) rendert das Template aber `_view_groups.html` und die flache Liste wird verworfen — die Findings pro Group werden per HTMX lazy nachgeladen.

EXPLAIN für die Query:

```
EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM findings WHERE server_id=2 AND status='open'
ORDER BY is_kev DESC, epss_score DESC NULLS LAST, cvss_v3_score DESC NULLS LAST LIMIT 500;
→ Seq Scan + TopN-Sort, 9224 Rows gescannt, Execution Time: 47.832 ms
```

Plus `selectinload(Finding.notes)` als zweite Query. Im Default-Pfad: ~50 ms DB + verworfene Render-Daten + irrelevanter Memory-Footprint.

**Lösungsskizze:**
- Die im Template stehende Conditional (`_force_flat or _filters_active or not _sort_default`, siehe `_findings_section.html:122-133`) im View-Code dupliziert auswerten und `list_findings` nur dann aufrufen wenn die flache Liste auch gerendert wird. Default-Page-Load spart ~50 ms DB + N-Row-Hydration + Notes-Loader.
- Alternativ: Template-Side-Effect prüfen — falls die Section auch `findings` außerhalb des Flat-Mode liest (z. B. für `total_findings`-Eyebrow oder Bulk-Form), Counts aus `count_findings` statt aus `findings | length` ableiten.

### Befund 3 — Trend-Aggregation in SQL statt Python-Loop

`_compute_snapshots` und `_compute_daily_counts` laufen heute als O(days × findings)-Python-Loop. Postgres kann das deutlich kompakter:

```sql
-- Skizze, Details bei Umsetzung:
WITH days AS (
  SELECT generate_series((NOW() - INTERVAL '49 days')::date, NOW()::date, '1 day')::date AS d
),
findings_in_window AS (
  SELECT severity, first_seen_at, acknowledged_at, resolved_at, kev_added_at, is_kev
  FROM findings WHERE server_id = $1
)
SELECT d.d,
  count(*) FILTER (WHERE severity='critical' AND is_open_at(f, d)) AS crit,
  count(*) FILTER (WHERE severity='high'     AND is_open_at(f, d)) AS high,
  ...
FROM days d LEFT JOIN findings_in_window f ON TRUE
GROUP BY d.d ORDER BY d.d;
```

Die `is_open_at`-Logik ist eine einfache `CASE`/`AND`-Kombination, kein UDF-Bedarf. Erwartung: **< 50 ms gesamt** für Sparklines + Daily-Counts gegenüber heutigen 1.4 M Python-Iterationen.

**Lösungsskizze:**
- Eine einzige SQL-Query liefert sowohl die Sparkline-Reihen als auch die Daily-Counts (gleicher GROUP BY day, andere FILTER-Aggregate). Tendency wird aus dem Result-Set abgeleitet.
- `_FindingRow`-Datenklasse und `_is_open_at`-Pure-Function bleiben für Unit-Tests bestehen — der SQL-Pfad ist additiv und kann mit Feature-Flag oder per Cutover eingeführt werden.
- Aufwand am höchsten der drei Punkte, Effekt potenziell der größte (sub-100 ms Trend-Sektion statt 2–3 s).

## Befunde Dashboard (`GET /`)

### Befund 4 — Sidebar-Context-Processor läuft doppelt pro Request

> **Hinweis:** Befund 8 (Sidebar-Lazy-Load) erschlägt diesen Befund teilweise — wenn die Sidebar via secondary HTMX-Request kommt, verschwindet der Doppel-Build durch View + Context-Processor im selben Request. Bleibt relevant für Routen, die weiterhin Sidebar inline rendern wollen (falls es solche gibt).


`app/__init__.py:405-432` registriert `_inject_sidebar_context` als globalen `@app.context_processor`. Dieser baut bei jedem authentifizierten Non-HX-Request unkonditional `build_sidebar_context()`. Innerhalb davon:

- 1× `select(Server) … selectinload(tag_links).tag` (Sidebar-Server-Liste)
- 1× `select(Tag)` (Tag-Chip-Filter)
- 1× `heartbeats_for_servers(…)` → 2 DB-Queries (Findings + Scans über alle Server-IDs)
- 1× `get_quick_stats(…)` → 2 DB-Queries (Findings-FILTER-Aggregat + Server-Read)

Das Dashboard-View setzt **gleichzeitig** seinen eigenen `quick_stats` und `available_tags` per View-Context (`_build_pane_context` zieht `get_quick_stats` und `select(Tag)` direkt). Flask priorisiert View-Context über Context-Processor — das Template sieht die View-Werte, aber **die DB-Queries des Context-Processors sind bereits durchgelaufen und werden verworfen**:

```
View-Pfad:  get_quick_stats(filter_tags=filt.tags, now=now)   ← landet im Template
            select(Tag)                                         ← landet im Template
Context:    get_quick_stats(filter_tags=None,      now=now)    ← Query gemacht, Ergebnis weggeworfen
            select(Tag)                                         ← Query gemacht, Ergebnis weggeworfen
            select(Server) + heartbeats_for_servers()           ← nur über Context genutzt
```

Doppelte `get_quick_stats`- und `Tag`-Queries pro Page-Load. Beim parallelen `/_partials/sidebar`-Polling läuft `build_sidebar_context` **erneut** komplett — keine Caching-Schicht dazwischen.

**Lösungsskizze:**
- Context-Processor in einen Lazy-Builder umwandeln, der nur die Keys baut, die das Template tatsächlich anfragt — oder die Verantwortung umkehren: Dashboard-View setzt explizit, Context-Processor liefert nur die Sidebar-spezifischen Keys (`sidebar_servers`, `sidebar_heartbeats`), nicht `quick_stats`/`available_tags`.
- Sidebar-Polling-Endpoint und Full-Page-Render via gemeinsamem Cache (per-Request-G-Object oder kurzer In-Process-LRU) bedienen — derselbe Polling-Request triggert sonst denselben Datenstand neu.

### Befund 5 — Sechs bis acht Seq Scans auf `findings` pro Dashboard-Render

Das Dashboard aggregiert mehrfach über die OPEN-Findings-Menge mit überlappenden Filtern. Jeder einzelne dieser Calls macht heute einen separaten Seq Scan (kein Composite-Index greift, weil der Planner bei der aktuellen Größe Seq Scan bevorzugt):

| # | Quelle | Was wird gezählt | EXPLAIN |
|---|---|---|---|
| 1 | `_load_open_aggregates` (severity) | GROUP BY (server_id, severity), OPEN | Seq Scan, **15.6 ms** |
| 2 | `_load_open_aggregates` (KEV) | GROUP BY server_id, OPEN+is_kev | Seq Scan, ~12 ms |
| 3 | `_load_risk_kpi_counters` (1) | GROUP BY risk_band, OPEN | Seq Scan, ~12 ms |
| 4 | `_load_risk_kpi_counters` (2) | COUNT DISTINCT server_id, OPEN + yes_bands + JOIN | Seq Scan + Hash Join, ~20 ms |
| 5 | `_load_risk_kpi_counters` (3) | GROUP BY severity, OPEN | Seq Scan, ~12 ms |
| 6 | `get_quick_stats` (View) | 4× FILTER COUNT, OPEN | Seq Scan, ~12 ms |
| 7 | `get_quick_stats` (Context-Processor) | identisch zu #6 | Seq Scan, ~12 ms (siehe Befund 4) |
| 8 | `daily_severity_counts_fleet` | Seq Scan + smarter Diff-Array-Walk | Seq Scan, **32.9 ms** |

Summe: **~120–150 ms** rein für DB-Aggregate, die alle dieselbe Tabelle scannen. Bei wachsender Findings-Tabelle skaliert das linear; bei 200 k Findings sind das 2–3 s nur für die Seq Scans.

**Lösungsskizze:**
- Befunde 1–7 lassen sich in **eine** SQL-Query mit FILTER-Aggregaten konsolidieren (`COUNT(*) FILTER (WHERE …)` pro Bucket). Postgres erledigt das in einem einzigen Seq Scan plus Hash-Buckets — Erwartung sub-30 ms.
- `_load_open_aggregates` als triviale Quick-Win-Stufe schon vor der großen Konsolidierung: die zwei Queries (severity GROUP BY + KEV) in eine mit `FILTER (WHERE is_kev)` zusammenführen.
- Befund 8 (`daily_severity_counts_fleet`) gehört zur SQL-Aggregations-Stufe aus Befund 3 — gleiche Strategie, `generate_series` + FILTER-Aggregat in Postgres.

### Befund 6 — `heartbeats_for_servers` lädt komplette `Finding`-Rows statt schmaler Projektion

> **Hinweis:** Befund 8 verlangt die schmale Projektion als Voraussetzung — ohne sie verlagert der Lazy-Batch nur den Hydrate-Aufwand, eliminiert ihn nicht. Befund 6 wird damit Teil der Befund-8-Umsetzung statt eigenständige Maßnahme.


`app/services/heartbeat_aggregation.py:227-234`:

```python
f_stmt = select(Finding).where(
    Finding.server_id.in_(server_ids),
    (Finding.resolved_at.is_(None)) | (Finding.resolved_at >= start_dt),
)
findings_by_server: dict[int, list[Finding]] = defaultdict(list)
for f in session.execute(f_stmt).scalars().all():
    findings_by_server[f.server_id].append(f)
```

`select(Finding)` zieht alle Spalten (`width=1606` laut EXPLAIN, inkl. `data`-JSONB-Spalten, Identifier-Strings, Notes-IDs etc.). Die Aggregation braucht aber nur `server_id`, `severity`, `first_seen_at`, `acknowledged_at`, `resolved_at`, `is_kev`, `kev_added_at`. Bei 18 000+ Rows ist das ein **~30 MB Hydrate** in SQLAlchemy-Objekte pro Heartbeat-Build — und der läuft pro Page-Load **zweimal** (Context-Processor + Polling-Endpoint), und im Server-Detail nochmal.

**Lösungsskizze:**
- Auf Column-Tuple-`select(Finding.server_id, Finding.severity, …)` umstellen, wie es `daily_severity_counts_fleet` bereits macht. Erwartete Einsparung: 80–90 % Memory + ORM-Hydrate-Zeit.
- Sortierung im SQL (`ORDER BY server_id, first_seen_at`), damit die Python-Schleife linear durchläuft statt `defaultdict.append`.

### Befund 7 — Sidebar-Polling triggert vollen Sidebar-Rebuild ohne Cache

> **Hinweis:** Mit Befund 8 wird der Polling-Endpoint zum **einzigen** Pfad, der die Sidebar-Daten baut (Initial-Render hat dann nur noch Skeleton). Der „Doppel-Build pro Request" verschwindet damit — Per-Request-Cache wird obsolet. Der eigentliche `heartbeats_for_servers`-Aufruf bleibt teuer und ist über Befund 6 (schmale Projektion) zu adressieren.


`/_partials/sidebar` läuft alle 10 s (ADR-0019) und ruft `build_sidebar_context()` komplett neu. Das beinhaltet `heartbeats_for_servers` (Befund 6), `get_quick_stats` (Seq Scan) und `select(Server)` mit eager-loaded Tags. Bei 50 Tagen Heartbeat-Fenster + 2 Servern aktuell harmlos, aber:

- Der Polling-Endpoint und der Dashboard-Render machen **dieselbe Arbeit zwei Mal** innerhalb desselben Sekundenfensters (Page-Load → Sidebar-Render im Page + Sidebar-Polling-Refresh kurz danach).
- Mit wachsender Server-/Findings-Anzahl skaliert das nicht (Befunde 5+6).
- Im Browser-Network-Tab zwei Sidebar-Requests sichtbar — einer 2.54 s + 1 abgebrochener — Hinweis auf Race-Pattern (Page-Load triggert Sidebar-Build via Context-Processor **und** HTMX-Polling kurz danach).

**Lösungsskizze:**
- Per-Request-Cache (Flask `g.sidebar_ctx`) damit Context-Processor und expliziter Polling-Endpoint im selben Request nicht doppelt bauen.
- Optional: kurzer In-Process-Cache (5–10 s TTL) für die Sidebar-Daten in dem Wissen, dass der Polling-Endpoint absichtlich freshe Daten will — aber der Doppel-Build innerhalb eines Requests bleibt eliminierbar.
- Abgebrochener Sidebar-Request aus dem Network-Tab (`NS_BINDING_ABORTED`) noch separat zu untersuchen — möglicherweise HTMX-Race beim ersten Page-Load (Sidebar-Polling startet bevor Page fertig ist).

### Befund 8 — Sidebar-Daten via Lazy-HTMX-Request nach Page-Render (Sammel-Maßnahme)

Heute rendert der initiale `/`-Response (und jeder andere Non-HX-Page-Load) die komplette Sidebar inkl. Heartbeats inline (Context-Processor blockt TTFB mit den teuren Aggregaten). Server-Liste selbst (Name, Tags, Lifecycle-Status, Outdated-Marker) ist billig zu laden und sollte im Critical Path bleiben; die teuren Aggregate (Heartbeats, Quick-Stats) müssen raus.

Dieser Befund fasst Befunde 4, 6 und 7 zu einer architektonischen Einzel-Maßnahme zusammen.

**Lösungsskizze:**

1. **Initialer Page-Render liefert die Sidebar-Struktur echt aus.** Server-Liste (Name, Tags, Status-Pill, Outdated-Marker) ist bereits im Memory durch die ohnehin laufende `_load_servers`-Query mit `selectinload(tag_links)`. Operator sieht beim Page-Open sofort die korrekte Server-Anzahl, sortiert, mit Namen — kein „leerer" Zustand, keine Layout-Sprünge.

2. **Skeleton-Loading-Animation für die teuren Teile**, **nicht** „leer" und **nicht** generischer Spinner. Konkrete Skeleton-Slots in der neuen Sidebar (Re-Design noch ausstehend, Datenanforderungen aber bekannt):
   - **Heartbeat-Bar:** Skeleton in Spec-Länge (50 Cells), visuell identische Größe zur fertigen Bar damit das Layout beim Daten-Swap nicht springt.
   - **ESCALATE-Spaltenwert pro Server-Row:** Placeholder in Ziffern-Breite.
   - **ACT-Spaltenwert pro Server-Row:** identisch.
   - **Header-Count `ALARM`** (Server-Anzahl mit Escalate-Findings): Placeholder. **`HOSTS`-Count** ist initial bereits echt (kommt aus der ohnehin laufenden `_load_servers`-Query — Operator sieht beim Page-Open sofort „ah, 20 Server, da kommen jetzt Daten rein").
   - **Status-Indikator pro Server-Row** (Re-Design ersetzt heutige Status-Pill durch farbigen Punkt vor dem Servernamen, Mapping zu cyan/grau/grün wird im Re-Design-Block spezifiziert): Skeleton wenn farbe vom Aggregat abhängt; falls vom Server-Lifecycle (`retired_at`/`revoked_at`) abhängig, initial echt.
   - **Animation-Style** (pulse, Scan-Animation o.ä.) wird vom Re-Design-Block spezifiziert; aus Performance-Sicht ist nur entscheidend, dass das Layout zwischen Skeleton und Live-Daten stabil bleibt (identische Cell-Größen, kein Reflow beim Swap).
   - **Skeleton-Row-Anzahl = echte Server-Anzahl**, nicht fix N Placeholders.

3. **Direkt nach Page-Load** triggert HTMX **einen** `/_partials/sidebar`-Request (Trigger-Wechsel im `_server_list.html` von `every 10s [...]` auf `load, every 10s [document.visibilityState === 'visible']`), Outer-HTML-Swap der Server-Liste. Heartbeats + Quick-Stats sind dann da, Skeleton verschwindet, Layout bleibt stabil durch identische Cell-Größen.

4. **Batch über alle sichtbaren Server**, nicht einzeln pro Server. Einzeln pro Server explizit verworfen (siehe Verworfen-Sektion): 50+ Server würden 50 HTTP-Roundtrips × 50 Flask-Auth-Decorator × 100+ DB-Queries × HTTP/1.1-6-Connection-Limit erzeugen; Batch macht 1 Roundtrip + 3 Queries mit `WHERE server_id IN (…)` und die Composite-Indices greifen sauber. Konkret liefert der Batch-Pfad:
   - **Pro-Server-Risk-Aggregat:** eine Query `SELECT server_id, risk_band, COUNT(*) FROM findings WHERE status='open' AND risk_band IN ('escalate','act') GROUP BY server_id, risk_band` — deckt sowohl die ESCALATE- als auch die ACT-Spalte ab.
   - **Heartbeat-Daten:** Findings + Scans über `server_id.in_(…)` (schmale Projektion gemäß Befund 6) — 2 Queries.
   - **Header-Count `ALARM`** ist als Side-Compute aus dem Pro-Server-Aggregat ableitbar (`Anzahl Server mit escalate > 0`), keine separate Query nötig.

5. **Batch-Pfad nutzt schmale Projektion** (siehe Befund 6): `select(Finding.server_id, Finding.severity, Finding.first_seen_at, Finding.acknowledged_at, Finding.resolved_at, Finding.is_kev, Finding.kev_added_at)` statt `select(Finding)`. Sonst kompensiert die SQLAlchemy-Hydrate-Last (~30 MB bei 18k Rows mit JSONB-Spalten) den HTTP-Roundtrip-Gewinn — netto Effekt minimal.

6. **Cache-Verhalten:** Sidebar-Polling alle 10 s bei sichtbarem Tab bleibt unverändert (ADR-0019). Der initiale Lazy-Load nutzt denselben Endpoint — kein neuer Code-Pfad nötig, nur der HTMX-Trigger erweitert sich um `load`.

**Erwartete Wirkung (Schätzung, nicht profiled):**
- `/` TTFB von 3.45 s → **~ 0.8–1.2 s** (Critical Path ohne teure Aggregate).
- Heartbeats / Quick-Stats erscheinen 1–2 s nach Page-Render via Skeleton-Swap.
- Wirkung gilt analog für `/servers/<id>` und alle anderen Non-HX-Routen, die heute via Context-Processor die Sidebar inline ziehen.

**Risiken / Edge-Cases:**
- Tag-Filter (`?tag=prod`) muss an den Lazy-Request weitergegeben werden — der Endpoint nimmt heute schon `request.args.getlist("tag")` entgegen, sollte sauber passen.
- `active_server_id`-Highlight beim ersten Render: Server-Liste ist da, Highlight kann initial direkt aus dem View-Context kommen — kein extra Roundtrip nötig.
- Operator ohne JavaScript: HTMX-Lazy-Load fällt aus; Sidebar bleibt im Skeleton-Zustand. Akzeptable Degradation für eine Admin-UI im internen Netz; falls relevant, Server-Side-Fallback via `<noscript>` möglich.
- Skeleton muss in beiden Themes (`dark`/`light`) funktionieren — Animation-Pattern liefert der Re-Design-Block.

### Befund 9 — `get_quick_stats()` ist Dead Code im aktiven Render-Pfad

`app/services/quick_stats.py` wird vom Dashboard-View (`_build_pane_context`) **und** vom Sidebar-Context-Processor (`build_sidebar_context`) aufgerufen — beide stellen `quick_stats` in den Template-Context. Das aktive Template `dashboard/_detail_pane.html` referenziert `quick_stats` nirgendwo; das Partial `app/templates/sidebar/_quick_stats.html` ist ohne `{% include %}`-Aufrufer. Beide Aggregat-Queries laufen pro Request, das Ergebnis wird vollständig verworfen.

Heute geliefert (und nirgends gerendert): `total_open`, `kev_open`, `critical_open`, `high_open`, `stale_servers`.

**Was die neue Sidebar braucht** (Re-Design-Block, siehe Befund 8): ESCALATE- und ACT-Count **pro Server** plus Header-Counter `HOSTS` und `ALARM`. Das ist eine andere Aggregat-Form (per-Server GROUP BY statt fleet-weite Single-Row-Counter), wird im Lazy-Sidebar-Endpoint berechnet und ersetzt `get_quick_stats()` nicht 1:1, sondern ersatzlos.

**Lösungsskizze:**
- `get_quick_stats()`-Call aus `_build_pane_context` (Dashboard-View) und `build_sidebar_context` (Sidebar-Context-Processor) entfernen.
- `app/services/quick_stats.py` ersatzlos löschen, `_quick_stats.html`-Partial mit.
- Aufrufer in Tests (`tests/services/test_quick_stats.py`) und ggf. weitere Doku-/ADR-Verweise entfernen.
- Falls in Zukunft ein flotten-weiter Counter doch wieder gebraucht wird (z. B. „X Server stale" als Banner), als eigene Maßnahme im Re-Design-Block beantragen.

**Ersparnis:** 2 Findings-Queries × 2 Aufrufer = 4 redundante DB-Calls pro Request, plus die `is_stale`-Python-Schleife über alle Server. Bei wachsender Server-Anzahl skaliert die Schleife linear — Wegfall ist Effekt-positiv unabhängig von Befund 8.

## Weitere Performance-Aspekte (bewusst deferred, eigene ADRs/Tech-Debt)

> Bewusst aus dem Scope dieses ADR ausgeschlossen. Wenn ein Punkt operativ relevant wird, eigener Folge-ADR oder TD-Eintrag in `docs/techdebt.md`. Nicht-Ziel-Liste, nicht „TODO für Block V":

- **`/findings` Cross-Server-Liste** (`findings.list_findings_cross_server`) bei wachsender Server-Anzahl.
- **Worker-Lese-Pfade** für Pass-1/Pass-2-Inputs — heute mehrfache `Finding`-Selects pro Job-Batch.
- **`_load_action_required_counts` + `_quick_counts_for_server`** (Server-Detail) machen ähnliche FILTER-Aggregate auf derselben Tabelle — Kandidat für Konsolidierung in eine einzige Query, analog zu Befund 5.
- **`_load_application_groups_for_server`-Sortierung** läuft heute in Python; bei vielen Groups (>100) wird das SQL-Sort interessanter.
- **EXPLAIN-Walk** über alle Queries bei wachsender Findings-Tabelle: heute Seq Scans, der Planner wechselt automatisch sobald die Selektivität stimmt — Re-Check nach Ingest-Wachstum, ob `ix_findings_server_status` / `ix_findings_server_risk_band` dann greifen.
- **Server-side Render-Time vs. Wire-Time-Instrumentierung**: 7.88 s / 3.45 s sind Browser-perceived; reine Server-Zeit per `time` / structlog-Latenz noch zu instrumentieren (kein expliziter Render-Latenz-Logger heute).
- **DB-Pool-Sizing in der Flask-App** vs. die für den Worker bereits in ADR-0029 §6 definierten Werte.
- **Abgebrochener Sidebar-Request** (`NS_BINDING_ABORTED` in Server-Detail- UND Dashboard-Network-Tab) — HTMX-Polling-Race beim ersten Page-Load zu untersuchen.
- **`get_quick_stats.stale_servers`-Loop** läuft heute in Python (`servers.iter → is_stale(srv)`). Mit Befund 9 entfällt der Call ersatzlos; sollte später ein „Stale-Server"-Counter doch wieder benötigt werden, ist `WHERE last_scan_at + (interval × N hours) < NOW()`-Filter direkt in der Server-Query der saubere Pfad — nicht Python-Loop.

## Entscheidung

Die neun Befunde werden in **fünf Phasen** in Block V umgesetzt, geordnet nach Aufwand-/Effekt-Ratio und Reduktion des Risikos pro Schritt. Jede Phase ist eigenständig mergebar; nach jeder Phase muss Default-`pytest` grün sein, kein DB-Schema-Touch nötig (alle Maßnahmen sind Code-only):

### Phase A — Dead-Code-Entfernung (Befund 9)

- `app/services/quick_stats.py` ersatzlos löschen, `app/templates/sidebar/_quick_stats.html` mit.
- `get_quick_stats`-Calls aus `app/views/dashboard.py::_build_pane_context` und `app/views/_sidebar_context.py::build_sidebar_context` entfernen, dazugehörige Context-Keys (`quick_stats`) raus.
- `tests/services/test_quick_stats.py` löschen; Adversarial-Tests prüfen falls vorhanden.
- **Effekt:** 4 redundante DB-Calls pro Request weg, Code-Komplexität sinkt, Klarheit für Phase C.

### Phase B — Server-Detail Quick-Wins (Befunde 1 + 2)

- `compute_tendency` zu einer reinen Funktion `tendency_from_counts(counts, days_short, days_long, threshold)` umbauen, keine Session-Abhängigkeit mehr.
- In `app/views/server_detail.py::show` einen gemeinsamen `_load_findings`-Call vor `severity_snapshots_for_server` / `daily_severity_counts_for_server` ziehen; beide Aggregatoren bekommen die Row-Liste injiziert (Public-API erhält rückwärtskompatible Wrapper mit Session-Fallback).
- `list_findings`-Aufruf in `_render_findings_section` hinter Conditional `_force_flat or _filters_active or not _sort_default` ziehen — wenn `_view_groups.html` rendert, wird nicht geladen.
- **Effekt:** 2× `_load_findings` weniger, ~920k Python-Iterationen weniger, 1 verworfene Query weg.

### Phase C — Sidebar Lazy-HTMX-Load (Befund 8, erschlägt 4 + 6 + 7)

- `_inject_sidebar_context`-Context-Processor liefert nur noch die billigen Felder: `sidebar_servers` (Namen, Tags, Lifecycle-Status, Outdated-Marker), `active_server_id`. Keine Heartbeats, keine Aggregate.
- Neuer Lazy-Endpoint-Output für `/_partials/sidebar`: ESCALATE-/ACT-Counts pro Server (eine GROUP-BY-Query), Heartbeat-Daten (Findings + Scans über `server_id.in_(…)`, schmale Projektion mit den 7 für Heartbeat nötigen Spalten), ALARM-Header-Count als Side-Compute.
- `_server_list.html`-HTMX-Trigger von `every 10s [...]` auf `load, every 10s [document.visibilityState === 'visible']` umstellen — initialer Lazy-Load direkt nach Page-Render.
- Skeleton-Markup für Heartbeat-Bar (50 Cells), ESCALATE-/ACT-Spalte und ALARM-Header-Count; Skeleton-Row-Anzahl = echte Server-Anzahl. Animation-Style liefert der Re-Design-Block; aus Performance-Sicht muss das Layout zwischen Skeleton und Live-Daten stabil bleiben (identische Cell-Größen).
- **Effekt:** TTFB für `/` und `/servers/<id>` sinkt um die teuren Sidebar-Aggregate; Sidebar-Daten erscheinen ≤2 s nach Initial-Render.

### Phase D — Dashboard-Risk-Aggregate-Konsolidierung (Befund 5)

- `_load_open_aggregates`: zwei Queries (Severity-GROUP-BY + KEV-Aggregat) in eine mit `FILTER (WHERE is_kev)` zusammenführen.
- `_load_risk_kpi_counters`: drei separate Findings-Aggregate (Risk-Band-GROUP-BY, Yes-Server-DISTINCT, Severity-Strip-GROUP-BY) in eine Query mit `COUNT(*) FILTER (WHERE …)` pro benötigtem Bucket konsolidieren. Active-Server-Count bleibt eigenständig (operiert auf `servers`-Tabelle, nicht auf `findings`).
- **Effekt:** Dashboard-Findings-Scans von 5–7 auf 1–2 reduziert; Server-Zeit-Einsparung im Dashboard-View geschätzt 80–130 ms.

### Phase E — SQL-Aggregation für `severity_history` (Befund 3)

- `severity_snapshots_for_server` und `daily_severity_counts_for_server` bekommen einen SQL-Pfad mit `generate_series` + `COUNT(*) FILTER (…)`-Aggregaten pro Tag. Pure-Python-Pfad bleibt als Fallback und für Pure-Unit-Tests bestehen (additive Migration, keine Schnittstellen-Änderung).
- `daily_severity_counts_fleet` profitiert analog (heute schon smart aggregiert, aber Seq Scan dominiert bei wachsender Tabelle).
- **Effekt:** Trend-Sektion <100 ms statt 2–3 s; größter absoluter Gewinn auf `/servers/<id>`.

Phase A→B→C→D→E ist die empfohlene Reihenfolge. Phase B kann parallel zu C laufen (unterschiedliche Views), Phase D ist von keiner anderen abhängig, Phase E setzt nichts voraus aber lohnt sich erst nach den anderen — da die kleinen Gewinne (A–D) zusammen den Großteil des wahrnehmbaren Effekts liefern.

## Konsequenzen

- **ADR-0018 (50-Tage-Trend)** bleibt inhaltlich gültig. Die SQL-Aggregation in Phase E ist eine Implementierungs-interne Umstellung — die exposed Metriken (Sparklines, Daily-Counts, Tendency) ändern weder Format noch Semantik. Pure-Aggregations-Funktionen (`_compute_snapshots`, `_compute_daily_counts`) bleiben als Test-Doubles erhalten.
- **ADR-0019 (Sidebar-Polling)** wird durch Phase C inhaltlich erweitert: der Polling-Endpoint wird zum **einzigen** Daten-Pfad für Sidebar-Aggregate; der bisherige Inline-Render durch Context-Processor entfällt. **Polling-Cadence wird von 10 s auf 60 s erhöht** (nur bei sichtbarem Tab) — bewusste Reduktion der Background-Last; Heartbeat-/Risk-Counts ändern sich operativ langsam genug, dass minütliches Polling ausreicht. Initialer Lazy-Load nutzt denselben Endpoint via zusätzlichem `load`-Trigger.
- **`get_quick_stats`-Service entfällt ersatzlos.** Aufrufer im Worker- oder Test-Code (falls existent) müssen migrieren oder die neue per-Server-Aggregat-Variante aus Phase C nutzen. Sollte später ein flotten-weiter Counter wieder gebraucht werden, ist das ein neuer Befund/eigener ADR.
- **Service-Public-API-Änderungen:**
  - `compute_tendency(session, server_id, …)` → neue Pure-Funktion `tendency_from_counts(counts, …)`; alte Signatur bleibt als dünner Wrapper für Bestands-Aufrufer.
  - `severity_snapshots_for_server` / `daily_severity_counts_for_server` bekommen optional einen vorgeladenen `rows`-Parameter, der Session-Aufruf wird optional.
  - `heartbeats_for_servers` wechselt intern auf schmale Projektion; öffentliche Signatur (`dict[int, list[DailyStatus]]`) bleibt erhalten.
- **Pure-Unit-Test-Coverage:** alle SQL-Pfade aus Phase D/E sind additiv — die Pure-Python-Aggregations-Helper bleiben aufrufbar und werden weiterhin als Default-Test-Pfad genutzt. SQL-Pfade werden über die View-Routes integration-getestet (db_integration-Marker, nur auf User-Anweisung gefahren) oder via Test-Doubles für die Aggregat-SQL-Strings.
- **Migration-Plan:** Phasen einzeln mergbar. Jede Phase eigener Commit, Default-`pytest` grün als Phase-DoD. Kein Schema-Touch — keine Alembic-Migration in dieser Block-V-Umsetzung.
- **Block-V-Datei** `docs/blocks/V-ui-performance.md` ist im Block-Start anzulegen mit den fünf Phasen als Tasks und der DoD aus diesem ADR übernommen.

## Messung / Definition of Done

- `GET /` (Dashboard) für 2–20 Server / ≤ 100 k Findings: **Server-Zeit median < 800 ms** (heute Browser-Wallclock 3.45 s).
- `GET /servers/<id>` für 9 000-Findings-Server: **Server-Zeit median < 1.5 s** (heute Browser-Wallclock 7.88 s).
- DB-Query-Count Dashboard-View **≤ 6** (heute 12–14 inkl. doppeltem Sidebar-Build und Dead-Code-`quick_stats`).
- DB-Query-Count Server-Detail-View **≤ 12** (heute 17–22 inkl. dreifacher `_load_findings` und unkonditionalem `list_findings`).
- Trend-Sektion (Sparklines + Daily + Tendency) **< 100 ms** Server-Zeit.
- Sidebar zeigt echte Server-Namen ≤ 500 ms nach Page-Open; Heartbeats + ESCALATE/ACT erscheinen via Skeleton-Swap ≤ 2 s danach.
- Default-`pytest` grün, keine Regression in den Pure-Unit-Tests für `severity_history`, `stale_history`, `heartbeat_aggregation`, `trend`, `findings_query`, `dashboard` (View-Helper).
- `app/services/quick_stats.py` und `app/templates/sidebar/_quick_stats.html` sind gelöscht; keine verwaisten Aufrufer oder Template-Verweise.

## Verworfen

**Pre-Computed Materialized View für Daily-Counts (täglich gerefresht).** Verworfen zugunsten on-the-fly SQL-Aggregation (Phase E). Mat-View bringt nur Vorteil bei stündlich+ wiederkehrenden Reads — Dashboard-/Detail-Views laden nicht oft genug, und Refresh-Trigger bei jedem Ingest/Re-Eval würde das Schema und den Worker komplizieren ohne klaren Performance-Gewinn.

**In-Memory-Cache (Flask-Caching / functools-lru) für Trend-Daten pro Server-ID.** Verworfen wegen Cache-Invalidierung bei jedem Ingest/Re-Eval/Risk-Re-Score; die Invalidierungs-Logik wäre aufwändiger als die nach Phase E direkt aggregierte Query, und ein Multi-Instance-Deploy (Out-of-Scope laut ARCHITECTURE §17) würde Cache-Drift erzeugen.

**Verworfen (zu Befund 8): Heartbeat-Lazy-Load mit einem Request pro Server.**

Naheliegende Alternative zum Batch wäre ein HTMX-Request pro Server-Row (50 Server = 50 parallele `/servers/<id>/heartbeat`-Calls). Bewusst verworfen:

| Posten | Einzeln pro Server (50) | Batch (1 Request) |
|---|---|---|
| HTTP-Roundtrips | 50 | 1 |
| Flask-Request-Setup × `@login_required` × DB-Session-Acquire | 50× | 1× |
| DB-Queries | 50 × 2 = 100 (Findings + Scans pro Server) | 2 (`server_id.in_(…)`) |
| Browser-Parallelitäts-Limit HTTP/1.1 | max. 6 gleichzeitig → 9 Wellen sequenziell | 1 Connection |
| Flask-DB-Pool-Druck | 50 parallel — Pool-Saturation bei Default-Sizing (5–10) | 1 Slot |

Progressive UX (Server 1–6 erscheinen schon während 44 noch laden) wäre der einzige reale Vorteil. Mit der schmalen Projektion aus Befund 6 ist der Batch-Lauf in ~200–400 ms durch — kein wahrnehmbarer Vorteil von „einzeln". Bei sehr großen Flotten (>200 Server) wäre Chunked-Batch (erste 20 inline, Rest als 1 weiterer Batch) die saubere Eskalations-Stufe, nicht N-Einzelrequests.
