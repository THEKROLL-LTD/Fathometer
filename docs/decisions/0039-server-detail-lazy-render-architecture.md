## ADR-0039 — Server-Detail Lazy-Render-Architektur + Triage-Queue-Pagination

**Status:** Akzeptiert · **Datum:** 2026-05-27 · **Block:** Y (Implementation, `docs/blocks/Y-server-detail-lazy-render.md`) · **Bezug:** ADR-0030 (Performance-Befunde, insbes. Befunde 1–3), ADR-0038 (Triage-First Content-Refactor, Block X), ADR-0025 (Server-Detail-Slim-Down, Lazy-Group-Findings), ARCHITECTURE.md §7 (Server-Detail-View).

## Kontext

Block X (ADR-0038) hat die Server-Detail-Seite inhaltlich auf Triage-First umgebaut. Das Rendering-Pattern blieb aber unverändert: `show()` baut den kompletten Seitenzustand synchron in einem einzigen Request auf — 17–19 SQL-Queries, davon mehrere mit voller ORM-Hydration — bevor ein Byte HTML rausgeht. ADR-0030 identifiziert die Symptome (redundante Queries, Python-Loops, Dead Code) und schlägt phasenweise Optimierungen innerhalb des bestehenden Patterns vor.

Das grundsätzliche Problem ist architektonischer Natur:

1. **Eager-Load-Everything-Upfront:** Die Seite besteht aus unabhängigen Sektionen (Header, Sparklines, Heartbeat, Host-Snapshot, Triage-Queue, Noise-Modal), aber alle werden im selben Request geladen. HTMX ist bereits im Projekt und wird für Group-Findings und Pending-Findings-Lazy-Load eingesetzt — aber die umgebenden Sektionen werden eagerly mitgeliefert.

2. **ORM-Hydration statt Projektionen:** `_build_risk_band_sections` macht `select(Finding)` und hydriert jedes offene Finding als volles Python-Objekt (alle Spalten, Identity-Map, Change-Tracking) — nur um vier Attribute (`risk_band`, `is_kev`, `severity`, `epss_score`) für Gruppierung/Sortierung abzufragen. `_load_application_groups_for_server` lädt ApplicationGroup-, Evaluation- und Worst-Finding-Objekte vollständig, obwohl die Group-Cards nur eine Handvoll Felder rendern.

3. **Triage-Queue ohne Pagination:** Die Risk-Band-Akkordeons laden und rendern alle Findings sofort. Bei 2000+ Escalate-Findings entsteht eine monolithische HTML-Tabelle die kein Operator durchscrollt.

Diese ADR löst das architektonische Problem, statt Symptome innerhalb des bestehenden Patterns zu optimieren.

## Entscheidung

### 1. Initial-Render auf das Minimum reduzieren

`show()` liefert nur noch Daten für den First-Paint — was der Operator sofort sieht:

- **Header:** Server-Metadaten, Quick-Counts (CRIT/HIGH/MED/LOW/KEV), Tendency-Pfeil, Action-Required-Counts.
- **Application-Group-Cards:** Inventar mit Projektionen (Label, Risk-Band, Count, Worst-Finding-Titel).
- **Triage-Queue-Akkordeon-Header:** Pro Risk-Band nur der Count — ein einziges `SELECT risk_band, COUNT(*) … GROUP BY risk_band`.

Alles andere wird HTMX-Fragment.

#### Aus `show()` entfernt:

| Heute in `show()` | Neu | Queries gespart |
|---|---|---|
| `severity_snapshots_for_server` (30-Tage-Sparkline) | Fragment-Endpoint, `hx-trigger="load"` | 1 |
| `daily_severity_counts_for_server` (Trend-Aggregation) | Fragment-Endpoint, `hx-trigger="load"` | 1 |
| `heartbeats_for_servers` (30-Tage-Heartbeat) | Fragment-Endpoint, `hx-trigger="load"` | 1–2 |
| `_load_host_snapshot` (Listeners, Services, Processes) | Fragment-Endpoint, `hx-trigger="load"` | 3 |
| `_build_risk_band_sections` (alle Findings hydriert) | **Gelöscht.** Ersetzt durch Header-Counts + paginierte Lazy-Endpoints | 1 (+ Hydration) |
| Noise-Count + Noise-Findings | Fragment-Endpoint, Trigger bei Modal-Open | 1–2 |

#### Tendency-Berechnung

Tendency-Pfeil steht im Header und muss im Initial-Render da sein. Statt der vollen 30-Tage-Aggregation: eine leichtgewichtige Query die letzte 7 vs. vorherige 7 Tage vergleicht (zwei COUNTs oder ein CASE-Aggregat). `tendency_from_counts` (ADR-0030 Phase B, bereits umgesetzt) bleibt als Pure-Funktion erhalten — sie wird vom Trend-Fragment-Endpoint konsumiert.

### 2. Neue HTMX-Fragment-Endpoints

| Endpoint | Trigger | Liefert |
|---|---|---|
| `GET /<id>/fragments/sparklines` | `hx-trigger="load"` | 30-Tage-Sparkline-Partial |
| `GET /<id>/fragments/heartbeat` | `hx-trigger="load"` | Heartbeat-Bar-Partial |
| `GET /<id>/fragments/host-snapshot` | `hx-trigger="load"` | Listeners/Services/Processes-Panels |
| `GET /<id>/fragments/trend` | `hx-trigger="load"` | Trend-Chart + Tendency (volle Aggregation) |
| `GET /<id>/fragments/noise` | Modal-Open-Event | Noise-Count + Preview-Liste (max 50) — **entfallen per ADR-0044** |
| `GET /<id>/triage/<band>?page=1` | Akkordeon-Expand | Paginierte Findings für ein Risk-Band |

Die `load`-Trigger feuern sofort nach Initial-Paint — der Browser rendert die Seite instant, die Sektionen füllen sich parallel nach. Triage-Findings laden erst bei Klick.

#### Skeleton-States mit Scan-Animation

Die Platzhalter im Initial-Render sind **keine** generischen Spinner. Das Design (`docs/design/ServerDetail.jsx`, `server-detail.css`) definiert pro Chart eine Skeleton-Variante mit der `sd-skel-frame`-Klasse — ein cyan-Gradient-Sweep (`@keyframes skel-scan`, 1.8 s, `mix-blend-mode: screen`) der über die Skeleton-Elemente läuft. Konkret:

- **Heartbeat:** `sd-heartbeat-frame sd-skel-frame` + 30 `sd-heartbeat__tick--skel`-Spans (identische Dimensionen wie Live-Ticks).
- **Severity-Trend:** `sd-trend-frame sd-skel-frame` + 30 `sd-trend-col--skel`-Divs (identische Column-Breite).
- **KPI-Tiles:** `sd-tile--skel sd-skel-frame` + Em-Dash statt Zahl, Sparkline-Bars als `--border-subtle`.

Der HTMX-Fragment-Response liefert das Live-Markup **ohne** `sd-skel-frame`; HTMX ersetzt das Skeleton per `hx-swap="innerHTML"` oder `outerHTML`. Kein Layout-Sprung, weil Skeleton und Live identische Dimensionen haben.

Host-Snapshot und Noise-Modal brauchen kein Chart-Skeleton — dort reicht ein kompakter Inline-Spinner oder ein leerer Slot, weil diese Sektionen hinter einem Klick/Toggle liegen und nicht im initialen Viewport sichtbar sind.

Alle Endpoints: `@login_required`, revoked/retired-404-Guard, Server-Existenz-Check. Triage-Endpoint: `band`-Whitelist-Validierung (400 bei ungültigem Band).

### 3. Triage-Queue: Collapsed + Lazy + Paginiert

**Aktuell:** `_build_risk_band_sections` → `select(Finding)` → alle Findings hydriert → alle Bands im Template → monolithische Tabellen.

**Neu:**

- Initial-Render zeigt pro Band nur den Akkordeon-Header: `ESCALATE (47)`, `ACT (312)`, `MONITOR (89)` — aus dem `GROUP BY risk_band` aus §1.
- Alle Bands **collapsed** (`<details>` ohne `open`). Default-Open: das höchste nicht-leere Band (Escalate wenn vorhanden) — triggert sofort seinen Lazy-Load.
- Bei Expand: `hx-get="/<id>/triage/escalate?page=1"` mit `hx-trigger="toggle"` lädt die erste Seite.
- **Page-Size 10.** Query: `LIMIT 10 OFFSET :offset`. Ein zusätzlicher `SELECT COUNT(*)` auf demselben `WHERE` liefert den Gesamt-Count für die Pagination-Metadaten (`total_pages`, Footer-Zähler).
- **Pagination via seitenbasierter Vor/Zurück-Navigation** (Footer `Seite N von M · X Findings` + zwei `‹`/`›`-Buttons, Markup-Klassen `workflow-card__footer` + `workflow-card__pager` aus dem Design `docs/design/ServerDetail.jsx`). Jede Navigation **ersetzt** den Band-Body (`hx-swap="innerHTML"` auf `#risk-band-<band>-body`) — kein Append, kein Infinite-Scroll. Der Operator arbeitet bewusst Seite für Seite durch die Triage-Queue. **Update (2026-05-28):** ersetzt das ursprünglich vorgesehene "Mehr laden"-Append-Modell — siehe §Verworfen. Page-Size von 25 auf 10 reduziert (Operator-Wunsch: kürzere, überschaubarere Seiten).
- Sort-Reihenfolge pro Band: `is_kev DESC, severity ASC (CRITICAL=0), epss_score DESC NULLS LAST` — identisch zur bisherigen `_assemble_risk_band_sections`-Logik, jetzt aber in SQL.

**Gelöschter Code:** `_build_risk_band_sections` und `_assemble_risk_band_sections` werden ersatzlos entfernt. Die Sort-Logik wandert in die SQL-Query des Triage-Endpoints.

### 4. Projektionen statt ORM-Hydration

Überall wo kein volles ORM-Objekt nötig ist, wird `select(Model)` durch `select(Model.col1, Model.col2, …)` ersetzt. Die Ergebnisse werden als Named-Tuples oder Dicts ans Template übergeben.

#### Triage-Endpoint (`/<id>/triage/<band>`)

```
SELECT id, identifier_key, title, package_name, installed_version,
       fixed_version, epss_score, cvss_v3_score, severity, is_kev,
       risk_band_reason, status, finding_class
FROM findings
WHERE server_id = :sid AND status = 'open' AND risk_band = :band
ORDER BY is_kev DESC, severity ASC, epss_score DESC NULLS LAST
LIMIT 10 OFFSET :offset
```

Plus ein `SELECT COUNT(*) FROM findings WHERE server_id = :sid AND status = 'open' AND risk_band = :band` für `total` / `total_pages` (Footer + Vor/Zurück-Aktivierung).

13 Spalten statt ~30+ bei `select(Finding)`. Kein ORM-Objekt, kein Change-Tracking, kein Identity-Map-Overhead.

#### `_load_application_groups_for_server` — Projektionen

Die 4-Query-Batch-Struktur bleibt, aber jede Query projiziert nur die benötigten Spalten:

| Query | Heute | Neu (Projektion) |
|---|---|---|
| (1) Count-Aggregat | `GROUP BY application_group_id` | Unverändert (war schon Aggregat) |
| (2) Group-Metadaten | `select(ApplicationGroup)` | `select(AG.id, AG.label, AG.explanation)` |
| (3) Junction-Batch | `select(ApplicationGroupEvaluation)` | `select(AGE.group_id, AGE.risk_band, AGE.risk_band_reason, AGE.worst_finding_id)` |
| (4) Worst-Finding | `select(Finding)` | `select(F.id, F.identifier_key, F.package_name)` |

#### Sparklines/Heartbeat/Host-Snapshot-Endpoints

Diese behalten ihre bestehenden Query-Patterns — die Lazy-Auslagerung allein eliminiert sie aus dem Critical Path. Projektions-Optimierung in diesen Services ist Scope von ADR-0030 Block V (insbes. `heartbeats_for_servers` Befund 6).

### 5. Query-Deduplizierung

`_load_pending_grouping_counts` und `_load_action_required_counts` führen nahezu identisches SQL aus (`GROUP BY risk_band` auf OPEN-Findings, Unterschied nur `application_group_id IS NULL`). Zusammenlegen in eine Query mit zwei FILTER-Aggregaten:

```sql
SELECT risk_band,
       COUNT(*) AS total,
       COUNT(*) FILTER (WHERE application_group_id IS NULL) AS pending
FROM findings
WHERE server_id = :sid AND status = 'open'
GROUP BY risk_band
```

`count_findings` KEV-Subquery wird in die Status-GROUP-BY eingebaut via `COUNT(*) FILTER (WHERE is_kev)`.

## Begründung

ADR-0030 optimiert innerhalb des Eager-Load-Patterns: geteilte Row-Listen, SQL-Aggregate statt Python-Loops, Dead-Code-Removal. Das löst die Symptome — 7.88 s wird schneller — aber die Architektur bleibt: ein Request, alles synchron, volle ORM-Objekte.

Diese ADR ändert die Rendering-Architektur: der Initial-Render liefert nur was der Operator sofort sieht, alles andere kommt als parallele HTMX-Fragmente. Die Triage-Queue wird paginiert statt monolithisch. Daten werden als Projektionen geholt statt als ORM-Objekte.

Der Effekt ist multiplikativ: weniger Queries im Critical Path × weniger Daten pro Query × weniger Python-Overhead pro Row = First-Paint in Bruchteilen der bisherigen Zeit.

HTMX-Lazy-Load ist kein neues Pattern im Projekt — Group-Findings (ADR-0025, Block Q) und Sidebar-Viewport-Loading (ADR-0035, Block W) nutzen es bereits. Diese ADR wendet dasselbe Pattern auf die restlichen Server-Detail-Sektionen an.

## Konsequenzen

- **`_build_risk_band_sections` + `_assemble_risk_band_sections` werden gelöscht.** Die Sort-Logik (`is_kev DESC, severity, epss_score`) wandert in die SQL-Query des Triage-Endpoints. Die Pure-Function `_assemble_risk_band_sections` ist damit nicht mehr nötig — ihre Tests werden durch Tests des neuen Endpoints ersetzt.
- **`_render_findings_section` wird schlanker.** Liefert nur noch: Counts, Application-Groups (mit Projektionen), Risk-Band-Header-Counts. Keine Findings-Hydration mehr.
- **Template-Änderungen:** `_view_groups.html` und `risk_band_section.html` rendern im Initial-Pfad nur noch Header mit Counts + Skeleton/Spinner-Slot. Finding-Rows kommen aus dem Triage-Fragment-Endpoint. `detail.html` bekommt `hx-trigger="load"`-Platzhalter für Sparklines, Heartbeat, Host-Snapshot.
- **ADR-0030 bleibt unverändert gültig.** Die Server-Detail-Befunde (1, 2, 3) werden durch diese ADR architektonisch anders gelöst. Dashboard- und Sidebar-Befunde (4–9) bleiben eigenständig in Block V. Block V Phase B/E werden durch Block Y funktional obsolet für den Server-Detail-Pfad, können aber unverändert stehen bleiben — der Code den sie optimieren würden wird von Block Y gelöscht oder umgebaut.
- **Keine Schema-Migration.** Alle Änderungen sind Code-only.
- **HTMX-OOB-Single-Source-Pattern** (CLAUDE.md) gilt für alle neuen Fragment-Endpoints: wenn ein Fragment sowohl im Initial-Render als auch via OOB-Swap geliefert wird, teilt es dasselbe Partial mit Conditional-Flag.

## Verworfen

**SSR-Streaming (Chunked Transfer-Encoding).** Flask unterstützt Streaming-Responses, aber Jinja2-Templates rendern blockierend — das Template wartet auf alle Context-Variablen bevor es mit dem Render beginnt. HTMX-Fragmente sind das natürliche Streaming-Primitiv für diesen Stack.

**Client-Side-State-Management (Alpine-Store für Findings).** Zu viel JavaScript-Komplexität für die HTMX-Architektur. Server-Side-Rendering mit HTMX-Fragments ist das etablierte Pattern im Projekt.

**Infinite-Scroll für Triage-Queue.** Verworfen. Triage ist ein bewusster Operator-Workflow — der Operator soll eine überschaubare Seite abarbeiten und dann gezielt navigieren, nicht endlos scrollen.

**"Mehr laden"-Append-Button (ursprüngliche Entscheidung, revidiert 2026-05-28).** Die erste Block-Y-Implementierung lud Folgeseiten via "Mehr laden"-Button an die bestehende Liste an (`LIMIT 26`-"gibt's noch mehr?"-Check, kein Total-Count). Revidiert zugunsten seitenbasierter Vor/Zurück-Navigation, weil das Design (`docs/design/ServerDetail.jsx`, WorkflowCard-Footer) den Pager mit `Seite N von M · X Findings` bereits vorsieht und der Operator den Gesamt-Umfang (`von M`) sehen soll, statt blind weiterzuladen. Der Footer ersetzt den Band-Body seitenweise (`hx-swap="innerHTML"`). Kostet einen zusätzlichen `COUNT(*)`-Roundtrip pro Page-Load — akzeptiert für die bessere Übersicht.

**Tendency im Fragment statt Initial-Render.** Der Tendency-Pfeil steht prominent im Header; ein nachladendes "?" oder Skeleton dort wäre visuell störend. Die leichtgewichtige 7-vs-7-Tage-Query (zwei COUNTs) ist schnell genug für den Critical Path.

## Re-Open-Trigger

- Wenn die Fragment-Endpoints durch zu viele parallele HTMX-Requests den Browser-Connection-Pool saturieren (HTTP/1.1 Limit 6) — dann Batch-Fragment-Endpoint oder OOB-Multi-Response prüfen.
- Wenn Operatoren Findings über mehrere Risk-Bands hinweg gleichzeitig sehen wollen (Triage-Workflow ändert sich) — dann Collapsed-Default überdenken.
- Wenn die 10er-Page-Size für bestimmte Operator-Workflows zu klein (zu viel Klicken) oder zu groß ist — Page-Size konfigurierbar machen oder anpassen.
