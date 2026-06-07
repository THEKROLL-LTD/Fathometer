# ADR-0035 — Daily-Risk-State als Heartbeat-Mapping + Viewport-Lazy-Loading

**Status:** Akzeptiert · **Datum:** 2026-05-23 · **Block:** W — Redesign Phase 1

Bezug: [ADR-0019](0019-dashboard-polling-not-sse.md) (Polling-Strategie), [ADR-0022](0022-risk-based-prioritization.md) (Risk-Band-Modell), [ADR-0030](0030-server-detail-performance.md) (Sidebar-Lazy-Load aus Block V), [ADR-0033](0033-brand-identity-fathometer.md) §3 (Color-Reduction-Rule "nur escalate trägt cyan"), [ADR-0036](0036-single-pane-polling-hx-preserve.md) (Polling-Pattern für Dashboard).

## Kontext

### Heutiges Heartbeat-Mapping (post-Block-V, v0.11.0)

`app/services/heartbeat_aggregation.py::heartbeats_for_servers` aggregiert pro `(server_id, day)` einen `DailyStatus`:
- `max_severity: Severity | None` — höchste CVSS-Severity offener Findings am Tagesende (`critical`/`high`/`medium`/`low`/`unknown` oder None)
- `kev_count: int` — Anzahl OPEN+KEV-Findings
- `had_scan: bool`

Sidebar-Heartbeat-Bar (`sidebar/_heartbeat_bar.html`) mappt das auf 6 visuelle Zustände: `critical` → bg-error rot, `high` → bg-warning orange, `medium` → bg-accent, `low` → bg-info, `unknown` → bg-base-content/40, None+had_scan → bg-success/40, None+!had_scan → bg-base-300 grau. KEV-Cell bekommt zusätzlich `ring-1 ring-error`.

### Konflikt mit dem neuen Design

ADR-0033 Color-Reduction-Rule: **nur „escalate" trägt cyan, alles andere ist grau**. Das heutige Mapping zeigt aber für jeden Tag mit `medium` oder `high` ein deutliches Farb-Signal (bg-warning orange, bg-accent magenta), die im Design-Doctrine als "rainbow of OK states" abgelehnt werden.

Design-Mock (`docs/design/app.jsx::HeartbeatStrip`) zeigt vier visuelle Zustände, alle abgeleitet aus dem **Server-Risk-State** (nicht aus der CVSS-Severity der Findings):
- `alarm` → cyan (escalate state — server hat ≥1 OPEN escalate-Finding)
- `warn` → text-secondary mit 0.7-Opacity (act/mitigate state)
- `ok` → border-visible grau (alles geclearter, monitor/noise)
- `unknown` → text-ghost mit 0.35-Opacity (kein Scan, oder unknown-only)

Heartbeat-Anzahl im Design: **30 Ticks** statt heute 50. Achse-Label `-30d ↔ today`. Begründung User (2026-05-23): mehr horizontaler Platz pro Tick + weniger Findings-Loop-Iteration pro Aggregation.

### Performance-Kontext

Block V (ADR-0030) hat den initialen Sidebar-Render auf billige Daten beschränkt (nur Server-Liste mit Tags) und teure Aggregate auf den HTMX-Polling-Endpoint `/_partials/sidebar` ausgelagert. Polling-Cadence: 60 s sichtbarer-Tab. `heartbeats_for_servers` nutzt schmale Projektion (7 Spalten, kein ORM-Hydrate). `escalate_act_counts_by_server` macht eine GROUP-BY-Query für alle Server-Counts.

Heute bei ~50 Servern: Polling-Endpoint-Response in ~150 ms (Block-V-Messung). Bei Flotten mit 200+ Servern: Heartbeat-Aggregation ist O(N × F) wo F = Findings pro Server, plus jeweils 50 Tage Python-Loop. Skalierungs-Limit ist erreichbar.

Drei Strategien geprüft:

1. **Live-Aggregation erweitern** (kein Schema-Change) — gewählt.
2. **Materialized-Tabelle `daily_risk_state`**: Schneller Lookup, aber Worker-Sync-Pfad, Backfill-Migration, Konsistenz-Risiken. Verworfen für Phase 1, dokumentiert als [TD-013](../techdebt.md#td-013--materialized-daily_risk_state-tabelle) für späteren Skalierungs-Bedarf.
3. **SQL-only Aggregation mit `generate_series`**: Phase E von Block V hatte das für `severity_history` gemacht. Verworfen für Heartbeat weil die Python-Loop-Logik (`first_seen_at <= end_of_day(D)` + `(resolved_at IS NULL OR resolved_at > end_of_day(D))`) als SQL-`CASE WHEN`-Ausdruck deutlich unleserlicher wird und die Test-Story (`tests/services/test_heartbeat_aggregation.py`) wesentlich aufwendiger.

## Entscheidung

### 1. Heartbeat zeigt Server-Risk-State pro Tag

**`DailyStatus`-Dataclass** (in `app/services/heartbeat_aggregation.py`) bekommt **ein** zusätzliches Feld:

```python
@dataclass(frozen=True, slots=True)
class DailyStatus:
    day: date
    max_severity: Severity | None       # bleibt — Server-Detail-Heatmap (Phase 2) nutzt es noch
    kev_count: int                       # bleibt — Server-Detail-Heatmap nutzt es noch
    had_scan: bool                       # bleibt
    dominant_risk_band: RiskBand | None  # NEU — höchster Risk-Band offener Findings am Tagesende
```

`max_severity`/`kev_count` bleiben aus Backwards-Compat — der Server-Detail-Heatmap-Code (`app/templates/servers/_heartbeat_large.html`) konsumiert beides und wird in Phase 1 nicht angefasst (out of scope). Phase 2 (Server-Detail-Redesign) kann das aufräumen.

**Risk-Band-Reduce-Logik** in `_aggregate_one_server`:

```python
_RISK_BAND_RANK = {
    RiskBand.ESCALATE: 7,
    RiskBand.ACT:      6,
    RiskBand.MITIGATE: 5,
    RiskBand.PENDING:  4,
    RiskBand.MONITOR:  3,
    RiskBand.NOISE:    2,
    RiskBand.UNKNOWN:  1,
}
# pro Tag: max(rank(f.risk_band) for f in active_findings_at(d))
```

**Projection-Query-Erweiterung** in `heartbeats_for_servers`:

```python
f_stmt = select(
    Finding.server_id,
    Finding.severity,
    Finding.first_seen_at,
    Finding.acknowledged_at,
    Finding.resolved_at,
    Finding.is_kev,
    Finding.kev_added_at,
    Finding.risk_band,        # NEU — 8. Spalte
).where(...)
```

Plus ein Feld in `_FindingRow`-NamedTuple und ein paralleler Reduce in der Aggregations-Schleife. Praktisch null Mehraufwand (zusätzliche Spalte in der Projection, ein zusätzlicher Loop-Body-Check).

### 2. Frontend-Mapping

Sidebar-Template `sidebar/_heartbeat_bar.html` (im Block-W-Redesign-Pfad — der Legacy-Pfad bleibt aus Backwards-Compat für nicht-redesignte Heatmaps unverändert):

```
dominant_risk_band → CSS-Klasse
─────────────────────────────────────
escalate           → beat--alarm     bg-accent (cyan)
act, mitigate      → beat--warn      bg-text-secondary opacity-0.7
pending, monitor, 
noise              → beat--ok        bg-border-visible (grau)
unknown            → beat--unknown   bg-text-ghost opacity-0.35
None (kein Finding)→ beat--ok        wie ok — keine Findings = nominal
```

KEV-Indicator (heute `ring-1 ring-error`) entfällt **im Sidebar-Heartbeat** — KEV-Information ist heute in den Findings-Detail-Pages sichtbar, der Sidebar-Heartbeat ist ein Skim-Signal. Heatmap auf Server-Detail-Page (Phase 2) kann KEV-Ring beibehalten.

### 3. 30 Ticks statt 50

`heartbeats_for_servers(..., days=30)` als neuer Default. Achsen-Label `-30d ↔ today`. Reduktion bedeutet:
- 40 % weniger Python-Loop-Iterations pro Server (30 statt 50 Tage)
- 40 % weniger DOM-Cells pro Skeleton + Live-Render
- Achse-Label-Wechsel im Template

`heartbeat_for_server` (Single-Server-Variante, von Server-Detail-Heatmap konsumiert) behält Default `days=50` — Heatmap braucht die längere Historie für die Trend-Sektion. Sidebar-Aufruf-Site übergibt explizit `days=30`.

### 4. Viewport-Lazy-Loading

**Pattern:**
- Initial-Render: `GET /` liefert Sidebar mit Server-Liste (Skeleton-Heartbeats + Skeleton-Counts für **alle** Server). Wie heute (post-Block V).
- Initial-Lazy-Fetch nach Page-Load: `GET /_partials/sidebar` läuft wie heute genau **einmal** via Hidden-`load`-Trigger (Pattern aus Block V Phase C). Liefert Live-Aggregate für **alle** Server.
- Polling alle 60 s: `POST /_partials/sidebar/batch` mit JSON-Body `{"server_ids": [...]}` — nur die aktuell sichtbaren Server-Rows (über IntersectionObserver im Client festgestellt). Statt heutigem GET-all.
- Scroll-Trigger: wenn neue Rows in den Viewport scrollen (IntersectionObserver-Callback), client-State markiert sie als „stale" → die Cell rendert sofort Skeleton-Animation → nächster 60-s-Tick (oder ein eigener `POST /_partials/sidebar/batch` mit nur diesen IDs) lädt die neuen Aggregate nach.
- Beim Polling-Swap: pro Server-Row staggered L→R-Reveal-Animation (`skel-materialize` Keyframe, 600 ms each, 18 ms-Versatz pro Tick — Pattern aus `useFleetLoading` im Design-Mock).

**Neuer Endpoint:**

```python
# app/views/sidebar_partials.py::sidebar_batch
@sidebar_partials_bp.post("/sidebar/batch")
@login_required
def sidebar_batch():
    payload = request.get_json(silent=True) or {}
    server_ids_raw = payload.get("server_ids", [])
    if not isinstance(server_ids_raw, list) or len(server_ids_raw) > 200:
        abort(400)
    server_ids = [int(x) for x in server_ids_raw if isinstance(x, int | str)]
    # Whitelist gegen DB: nur Server-IDs die in der heutigen Filter-Auswahl sind
    visible_ids = _filter_authorized_server_ids(server_ids, filter_tags=request.args.getlist("tag"))
    heartbeats = heartbeats_for_servers(sess, visible_ids, days=30)
    counts = escalate_act_counts_by_server(sess, visible_ids)
    # Rückgabe: HTMX-Fragment mit `<li>`-Rows als OOB-Swaps (siehe ADR-0036)
    return render_template("sidebar/_batch_response.html", ...)
```

**Client-JS (`sidebar_viewport.js`):**
- IntersectionObserver mit `rootMargin: "200px"` (vorlaufender Buffer, damit Server vor dem tatsächlichen Sichtbar-Werden geladen werden)
- Track-Set `visibleServerIds: Set<int>` updated bei jedem `intersect`/`disappear`-Event
- 60-s-Polling-Tick liest `visibleServerIds`, POSTet die Liste an `/sidebar/batch`
- Beim Initial-Page-Load: kein `/sidebar/batch` — der `load`-Trigger auf `/_partials/sidebar` lädt erstmal alle. Danach übernimmt Viewport-Pattern.

**Server-Side: kein Per-Server-Request.** Endpoint nimmt eine Batch-Liste. Frontend feuert **einen** Request pro Polling-Tick mit allen aktuell sichtbaren IDs (typisch 10–20 bei 50-Server-Flotte, gesamtes Set bei kleiner Flotte). Verhindert N+1-HTTP-Anti-Pattern.

### 5. Polling-Cadence-Konsolidierung

- **Sidebar:** 60 s bleibt (Block V Phase C). `sidebar_partial` für Initial-Lazy-Load, `sidebar_batch` für Polling-Re-Fetch.
- **Dashboard-Pane:** heute 10 s → **60 s** (ADR-Festziehung, Phase F-Änderung im Block W). Action-Card mit Scan-Animation profitiert von `hx-preserve` + OOB-Werte-Swaps (siehe ADR-0036).
- **Last-Refresh-Eyebrow:** clientseitig `setInterval(30_000)` — kein Server-Roundtrip. Format `HH:MM UTC`, lokales `new Date().getUTCHours()`/`getUTCMinutes()`.

## Konsequenzen

### Performance

**Bei kleiner Flotte (≤50 Server):**
- Polling-Tick: heute alle 50 Server (1 GET-Request, ~150 ms Server-Zeit). Block W: alle 50 sind sichtbar (kein Scroll), 1 POST-Request, ~155 ms. Praktisch identisch.
- Vorteil: Risk-Band-Reduce zusätzlich kostet <5 % (eine weitere Spalte in der Projection, eine Loop-Body-Op).
- Dashboard-Polling von 10 s auf 60 s: 6× weniger Polling-Last pro offenem Tab. Großer Win.

**Bei großer Flotte (200+ Server):**
- Polling-Tick: heute alle 200 Server (1 GET-Request, ~600 ms+ Server-Zeit, alle 60 s, alle Server). Block W: nur ~20 sichtbare Rows (1 POST-Request, ~80 ms). 10× schneller pro Tick.
- Scroll-Verhalten: User scrollt durch 200 Server → Skeleton-Animation für gerade sichtbare Rows → nach max. 60 s sind die nachgeladen. Akzeptable Latenz für „inspecting"-Workflow.
- Initial-Lazy-Load (alle Server beim ersten Page-Load) bleibt — das ist der Trade-off für „beim Öffnen sieht der Operator was los ist".

### Risiken

- **Viewport-Race:** wenn ein User schnell scrollt, kann die `visibleServerIds`-Liste schneller wachsen als der Polling-Tick (60 s) verarbeitet. Mitigation: Scroll-Trigger feuert einen extra Batch-Request für „neue sichtbare IDs" sofort (debounced 200 ms). Implementer-Detail in `sidebar_viewport.js`.
- **`risk_band` IS NULL** in der DB: Findings können `risk_band = NULL` haben wenn die Risk-Engine nie gelaufen ist (Edge-Case). Aggregations-Reduce behandelt `None` als „skippen" → wenn keine Findings mit Risk-Band an dem Tag, fällt der Cell auf `dominant_risk_band = None` → Frontend rendert `beat--ok`. Akzeptabel.
- **Server-Detail-Heatmap (Phase 2):** wird `dominant_risk_band` nicht konsumieren — bleibt auf `max_severity` bis sie selbst redesigned wird. Drift zwischen Sidebar und Server-Detail-Heatmap ist akzeptiert (zwei Mappings nebeneinander für eine Phase).
- **Initial-Render zeigt Skeleton-Heartbeat für alle Server**, dann der `load`-Trigger lädt alle — User sieht für 1–2 s die Scan-Probe-Animation auf allen Rows, dann Materialize-Fade. Das ist gewollt (Design-Wave-Effekt). Wenn Lazy-Load länger braucht: Skeleton-Animation bleibt sichtbar.

### Tests

- Pure-Unit: `tests/services/test_heartbeat_aggregation.py` erweitert um `dominant_risk_band`-Reduce-Tests.
- Pure-Unit: `tests/views/test_sidebar_batch.py` für den neuen Batch-Endpoint (Mock-Session, Whitelist-Logic, 400 bei invaliden Bodies).
- Pure-Unit: `tests/services/test_sidebar_group_aggregates.py` (siehe ADR-0034) bekommt einen Test für „leeres Group-Set" und „gemischtes Group-Set".
- Template-Smoke-Test (Pure-Unit): `tests/templates/test_heartbeat_30_ticks.py` prüft dass das gerenderte Markup genau 30 `<span>`-Cells enthält.
- **Kein** `db_integration`-Test pflichtig für die Aggregations-Erweiterung (Pure-Funktion, Fake-Findings im Test reichen).

## Verworfen

- **Materialized-Tabelle `daily_risk_state`** in Block W: zu viel Migration-/Sync-Aufwand für aktuelle Flotten-Größe. Als [TD-013](../techdebt.md#td-013--materialized-daily_risk_state-tabelle) für späteren Skalierungs-Bedarf dokumentiert. **→ Aufgehoben durch das Addendum 2026-06-07 (unten): Strategie 2 wird umgesetzt.**
- **SQL-only Aggregation mit `generate_series` + COUNT FILTER**: zu unleserlich, Test-Story aufwendiger als Python-Loop, kein klarer Performance-Gewinn bei aktueller Größenordnung. **→ bleibt verworfen für den Render-Pfad; im Worker-Batch (Addendum) ist das Lesbarkeits-/Test-Argument hinfällig.**
- **Per-Server-Polling-Endpoint** (`GET /servers/<id>/heartbeat`): würde N parallele HTTP-Requests pro Sidebar-Refresh feuern (50+ Requests pro Polling-Tick). Server-/Browser-Last unakzeptabel. Batch-Endpoint löst das.
- **Dashboard-Polling 10 s beibehalten:** im Re-Design mit Scan-Animationen verstärkt sich der Animation-Restart-Effekt — siehe ADR-0036. Konsolidierung auf 60 s plus `hx-preserve`-Pattern.
- **Heartbeat 50 Ticks beibehalten:** User-Entscheidung (2026-05-23) für 30 — weniger Daten, mehr horizontal Platz, näher am Design-Mock.

## Re-Open-Trigger

- Wenn Live-Aggregation bei einer Flotte mit ~500+ Servern + 100k+ Findings die Polling-Latency über ein akzeptables Budget (~500 ms Server-Zeit pro Batch) drückt: TD-013 angreifen (Materialized-Tabelle + Worker-Sync).
- Wenn Server-Detail-Heatmap (Phase 2) auf `dominant_risk_band` umgestellt wird: `max_severity` aus `DailyStatus` entfernen, Aggregations-Service vereinfachen.
- Wenn Operator-Feedback negativ zur 30-Tage-Heartbeat ist (z.B. „ich brauche 50 Tage Kontext für Compliance-Audits"): konfigurierbar machen (`settings.sidebar_heartbeat_days`), oder Cadence-Switch im UI.
- Wenn KEV-Information im Sidebar-Heartbeat vermisst wird: dedizierter KEV-Indicator-Spalte (z.B. `kev`-Spalte neben `escalate`/`act`) — separate ADR.

## Addendum 2026-06-07 — Strategie 2 (`daily_risk_state`) wird umgesetzt

**Status:** Akzeptiert · Ergänzt und revidiert die Phase-1-Entscheidung oben (Strategie 1 „Live-Aggregation").

**Auslöser:** EXPLAIN gegen die echte DB (`scripts/perf/explain_server_detail.sql`) zeigte bei einem Server mit 25.9k offenen / 33.6k Findings, dass die Live-Heartbeat-Aggregation (`heartbeats_for_servers`) im Batch ~71k Rows / ~349 MB Buffer zieht und O(N×F×30) in Python rollt. Das in Phase 1 dokumentierte Skalierungs-Limit (siehe [TD-013](../techdebt.md#td-013--materialized-daily_risk_state-tabelle)) ist damit als Operator-Symptom erreicht — die Phase-1-Begründung „bei aktueller Flotten-Größe unkritisch" gilt nicht mehr.

**Revision der Phase-1-Verwerfung:** Strategie 2 wird umgesetzt, jedoch in einer einfacheren Form als ursprünglich skizziert — **„Vergangenheit einfrieren, heute live"** statt rollierender Voll-Neuberechnung:

- **Vergangene Tage sind unveränderlich.** Ein Worker-Sub-Tick finalisiert per Anti-Join-`INSERT … ON CONFLICT DO NOTHING` alle noch fehlenden `(server, day)`-Paare im Fenster `[today-30, gestern]` (catch-up-sicher bei Worker-Downtime, idempotent, deckt neue Server ab und ist zugleich der Backfill). Möglich, weil `first_seen_at` beim Re-Ingest stabil bleibt und `had_scan` aus append-only `scans` kommt.
- **Der heutige Tag wird live aggregiert** — als billiges Bestands-Aggregat über die aktuell offenen Findings (nutzt `ix_findings_server_open_triage`), kein 30-Tage-Loop.
- **Read-Path liest strikt die Tabelle** (29 frozen Cells) + 1 Live-Today-Cell pro Server; **kein** Live-Fallback. Fehlende Vergangenheits-Cells (Worker noch nie gelaufen) rendern als `unknown`/grau bis zum nächsten Tick; der Deploy-Backfill (= erster Finalisierungs-Lauf) verhindert das im Normalfall.

**Bewusste Approximation:** Eingefrorene Tage spiegeln spätere **rückwirkende** Änderungen nicht wider (Re-Open eines alt-resolved Findings, späte Pass-2-`risk_band`-Zuordnung, nachträgliche Severity-Revision). Für einen 30-Tage-**Visual**-Heartbeat (4 Zustände) akzeptiert. **Der Heartbeat ist keine Audit-Quelle.** Die Pass-2-Lag-Kante wird gemildert, indem ein Tag erst nach vollständigem Ablauf (frühestens am Folgetag) finalisiert wird.

**Konsistenz-Pflicht:** Die SQL-Tagesende-Range (`first_seen_at <= eod(D) AND (resolved_at IS NULL OR resolved_at > eod(D))`) muss exakt der Python-Logik in `heartbeat_aggregation.py::_aggregate_one_server` entsprechen — abgesichert durch einen **Paritäts-Test** (Live-Aggregation als Oracle), bevor der Read-Path umgestellt wird.

**Komponenten:**

- Tabelle `daily_risk_state (server_id, day, dominant_risk_band, max_severity, kev_count, had_scan, updated_at)`, PK `(server_id, day)`, Index auf `day` (Migration 0020).
- `app/services/daily_risk_state.py`: `finalize_pending_days(session)` (Anti-Join-UPSERT) + `today_live_aggregate(session, server_ids)`.
- `heartbeat_aggregation.py::heartbeats_for_servers` liest Tabelle + merged die Today-Cell; die bisherige Live-Aggregation bleibt als Funktion (Oracle für den Paritäts-Test).
- Worker-Sub-Tick `_run_daily_risk_state_finalize()` in `llm_worker.py::_run_subticks` mit eigener Cadence-Konstante (~5 min Check; Schreiben nur wenn Paare fehlen).

Strategie 3 (SQL-only im Render-Pfad) bleibt verworfen; die SQL-Aggregation läuft hier **im Worker-Batch**, nicht pro Render.
