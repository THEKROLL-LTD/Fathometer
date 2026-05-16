# Block M — Dashboard-Redesign: Cross-Server-Findings + KPI-Sparklines + /findings/search-Entfernung

**Typ:** Visual + Backend-Feature-Block · **Branch-Vorschlag:** `feat/block-m-dashboard-findings` · **Zielversion:** v0.6.0 · **Vorgänger:** Block L (v0.5.0, ADR-0019 Polling) · **Spec:** [ADR-0020](../decisions/0020-dashboard-cross-server-findings.md) · **Visueller Soll-Stand:** Screenshot aus dem Cowork-Anhang vom 2026-05-16; bei Block-M-Start als statischer HTML-Stand (`docs/blocks/M-mockup-prototype.html`) im selben Tailwind/DaisyUI-Setup ablegen und 1:1 vergleichen.

## Ziel

Das Dashboard-Pane (`app/templates/dashboard/_detail_pane.html`) wird vollständig auf den neuen Design-Wurf umgebaut: KPI-Cards mit 50-Tage-Sparklines (analog Block-K-Server-Detail), eine cross-server Findings-Tabelle mit erweiterter Filter-Bar inklusive Volltext-Suche/Status-Filter/Bulk-Ack/CSV. Die alte Quick-Stats-Inline-Card, die Filter-Bar mit `Anwenden`-Button, die Aufmerksamkeits-Sektion und der dashed-border-Platzhalter fallen weg. Die globale Such-View `/findings/search` wird ersatzlos entfernt — das Dashboard übernimmt diese Rolle.

Hintergrund und Begründung: siehe ADR-0020.

## Vorbereitung — zu lesende Sektionen

- [ADR-0020](../decisions/0020-dashboard-cross-server-findings.md) (komplett)
- [ADR-0016](../decisions/0016-header-and-profile-dropdown.md) — wird durch ADR-0020 partiell abgelöst, Kontext für den Dashboard-Pane-Begriff
- [ADR-0017](../decisions/0017-dashboard-pane-single-partial.md) (bleibt aktiv)
- [ADR-0018](../decisions/0018-server-detail-visual-alignment.md) §§ KPI-Card-Pattern + Sort-Header-Macro + Bulk-Ack-Toolbar (Wiederverwendung)
- [ADR-0019](../decisions/0019-dashboard-polling-not-sse.md) — Polling-Wrapper bleibt; Filter-URL-Konsistenz beachten
- `ARCHITECTURE.md` §7 (Dashboard-Beschreibung, wird in diesem Block aktualisiert)
- `ARCHITECTURE.md` §15 (Sortier-Defaults)
- `docs/blocks/K-server-detail-visual.md` Tasks #6 (Partials), #8 (Findings-Section), #9 (Bulk-Ack-Modal)
- `docs/blocks/L-dashboard-polling.md` Punkt 11 (Polling-Wrapper-Markup auf dem Pane)

Subagent-Aufrufe nennen die Sektionen explizit.

## Aufgaben

### Phase A — Backend-Services und Schemas

#### Task #1 — `DashboardFilter` erweitern (`backend-implementer`)

`app/schemas/dashboard_filter.py`:

- Neue Felder:
  - `q: str | None = None` — `field_validator` schneidet auf 128 Chars, leerer String → `None`.
  - `status: Literal["open","acknowledged","resolved","all"] = "open"` (UI-Default `offen`).
  - `sort: Literal["server","cve","pkg","epss","cvss","sev","status","first_seen"] = "sev"`.
  - `dir: Literal["asc","desc"] = "desc"`.
- `from_request()` parst alle neuen Felder, validiert gegen Whitelists (`_VALID_STATUS`, `_VALID_SORTS`, `_VALID_DIRS`), `log.debug` bei Reject, fällt auf Default zurück.
- Neue Methode `to_query_string(*, override: dict[str, str] | None = None) -> str` analog `FindingsViewFilter.to_query_string()`. Default-Werte werden **nicht** serialisiert (kompakte URLs); Override-Mechanismus zum Re-Build von Links mit modifiziertem Einzel-Feld.
- `is_active` erweitert: liefert `True` sobald irgendeines der Felder vom Default abweicht (`q`, `status != "open"`, `severity`, `kev_only`, `stale_only`, oder `tags` nicht leer; `sort`/`dir` zählen NICHT als „aktiv", weil Sort eine UI-Aktion ist und keine Inhalts-Einschränkung).

**DoD:**

- Unit-Tests: jedes Whitelist-Fallback (gültiger Wert akzeptiert, ungültiger → Default + log.debug), `q` mit 200 Chars wird auf 128 gecapped, `to_query_string()` Roundtrip (parse → serialize → parse → identisch).
- `mypy --strict` PASS.

#### Task #2 — Cross-Server-Findings-Query (`backend-implementer`)

`app/services/findings_query.py`:

- Neuer Literal-Alias `FindingsCrossSortKey = Literal["server","cve","pkg","epss","cvss","sev","status","first_seen"]`.
- Neue interne Map `_SORT_COLUMNS_CROSS: dict[str, Any]` analog `_SORT_COLUMNS` aus Block K, mit zusätzlichem Eintrag `"server": Server.name`. Die anderen Keys teilen die Block-K-Mapping-Werte.
- Helper `_apply_tag_filter_cross(stmt, tags: list[str])` — wandert aus `app/views/search.py:_apply_tag_filter` hierher (Search-Modul wird in Task #7 gelöscht; die Helper-Logik bleibt erhalten).
- Neue Public-Funktion:

  ```python
  def list_findings_cross_server(
      session: Session,
      filt: DashboardFilter,
      *,
      limit: int = 200,
      sort: FindingsCrossSortKey = "sev",
      dir: FindingsSortDir = "desc",
      now: datetime | None = None,
  ) -> tuple[list[Finding], int]:
      """Liefert (results, total_count). Eager-load Server (+ tag_links.tag)
      via selectinload. Stale-Filter wirkt via `Server.last_scan_at`-Check
      (Reuse `is_stale(srv, now)` aus stale_detection — Python-side Post-
      Filter auf einer Server-ID-Subset-Query, weil is_stale expected_scan_
      interval_h einbezieht und nicht in einer einzigen Where-Clause
      ausdrueckbar ist)."""
  ```

- Filter-Anwendung:
  - `q`: OR-Where über `Finding.identifier_key.ilike("%q%")`, `Finding.package_name.ilike("%q%")`, `Finding.title.ilike("%q%")`, `Server.name.ilike("%q%")` (letzteres via JOIN).
  - `tags`: OR-Subset via `_apply_tag_filter_cross`.
  - `severity`: Threshold via `_SEVERITY_THRESHOLD_VALUES`-Map aus Block E.
  - `status`: `_STATUS_VALUES_BY_FILTER`-Map.
  - `kev_only`: `Finding.is_kev.is_(True)`.
  - `stale_only`: Server-Subset-Query auf stale-Server-IDs (Python-side aus `is_stale`-Iteration), `Finding.server_id.in_(stale_ids)`.
- Sortierung: `_SORT_COLUMNS_CROSS[sort]` mit `.asc()`/`.desc()` + `nulls_last`, sekundärer Tiebreak auf `Finding.identifier_key.asc()` (deterministisch).
- `total_count`: separate `SELECT COUNT(*) FROM (gefiltertes Select)` — exakt, nicht estimated.
- Limit anwenden auf das Listen-Ergebnis, nicht auf den Count.

**DoD:**

- Service-Unit-Tests in `tests/services/test_findings_query_cross.py`:
  - leerer Filter → alle OPEN-Findings sortiert per §15-Default
  - `q="CVE-2024-6387"` → exakter Identifier-Match
  - `q="openssh"` → Substring auf `package_name`
  - `q="edge-02"` → Substring auf `Server.name`
  - `kev_only=True` → nur KEV-Findings
  - `stale_only=True` → nur Findings auf stale Servern (Test setzt `Server.last_scan_at` jenseits des Intervalls)
  - Truncation: 250 Findings angelegt, Limit 200 → 200 zurück + total_count == 250
  - `sort="server", dir="asc"` → alphabetische Server-Reihenfolge
- `mypy --strict` PASS.

#### Task #3 — Flotten-Daily-Severity-Snapshots (`backend-implementer`)

`app/services/severity_history.py`:

- Neue Public-Funktion:

  ```python
  def daily_severity_counts_fleet(
      session: Session,
      *,
      days: int = 50,
      now: datetime | None = None,
  ) -> dict[Literal["total","kev","critical","high"], list[int]]:
      """Pro Bucket eine Liste von `days` ints (Tag 0 = `now - days + 1` end-
      of-day, Tag `days-1` = `now` end-of-day). Output-Buckets:
      - 'total': alle OPEN-Findings (Severity-agnostisch)
      - 'kev':   OPEN + is_kev=True
      - 'critical': OPEN + severity=CRITICAL
      - 'high':  OPEN + severity=HIGH
      Definition OPEN-am-Tag-T wie severity_snapshots_for_server."""
  ```

- Implementierung: `SELECT first_seen_at, acknowledged_at, resolved_at, severity, is_kev FROM findings` ohne Server-Filter; Python-side in 50 Buckets pro Output-Key einsortieren. Helper-Funktion `_bucket_for_day(t, end_of_days: list[datetime])` deduzbar.
- Performance-Mini-Bench: 50k Findings × 50 Tage muss < 200 ms (lokal in CI, ohne docker compose) bleiben. Bench läuft als `@pytest.mark.bench` und ist von der normalen Suite ausgeschlossen via `-m "not bench"`.

**DoD:**

- Unit-Tests in `tests/services/test_severity_history_fleet.py`:
  - Nur OPEN-Findings: jede Sparkline ist eine konstante Linie auf der jeweiligen Severity
  - Gemischt OPEN/ack/resolved: Severity-Buckets stimmen pro Tag (Test-Daten mit explizit gesetzten Lifecycle-Timestamps)
  - KEV-Sub-Bucket: 2 KEV + 3 non-KEV im OPEN → `kev=2`, `total=5`
  - Leere Flotte: alle 50 Werte = 0 (kein Crash, kein NaN)
- `mypy --strict` PASS.

#### Task #4 — Daily-Stale-Server-History (`backend-implementer`)

Neue Datei `app/services/stale_history.py`:

```python
def daily_stale_server_counts(
    session: Session,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> list[int]:
    """Pro Tag T (aeltester zuerst, Index 0 = now-days+1): Anzahl aktiver
    Server, die am Ende von T stale waren.

    Aktiv-am-Tag-T:
    - retired_at IS NULL OR retired_at > end_of_day(T)
    - revoked_at IS NULL OR revoked_at > end_of_day(T)
    - created_at <= end_of_day(T)

    Stale-am-Tag-T: kein Scan mit received_at <= end_of_day(T), ODER
    end_of_day(T) - latest_scan.received_at > 2 * expected_scan_interval_h.
    Factor 2 ist die Definition aus stale_detection.is_stale()."""
```

- Implementation: einmal `SELECT id, expected_scan_interval_h, created_at, retired_at, revoked_at FROM servers`. Einmal `SELECT server_id, received_at FROM scans WHERE received_at >= now - (days + max_interval_d) ORDER BY server_id, received_at`. Server-wise gruppieren, pro Tag T Python-side latest-scan-binsearch.
- Performance-Mini-Bench: 200 Server × 50 Tage muss < 100 ms bleiben.

**DoD:**

- Unit-Tests in `tests/services/test_stale_history.py`:
  - Alle Server immer frisch → alle 50 Werte = 0
  - Server retire-mid-window → ab Retire-Tag nicht mehr gezählt
  - Server mit `expected_scan_interval_h=168` (Wochenintervall) und letztem Scan vor 16 Tagen → ab Tag 14 stale, davor nicht
  - Server vor 30 Tagen erstellt, kein Scan → Tag 0–29 nicht aktiv, ab Tag 30 stale-zähler hochgehen? — exakte Logik: Server gilt ab Tag 30 als aktiv (created_at <= end_of_day(30)) und ist sofort stale (kein Scan)
- Mini-Bench `@pytest.mark.bench` mit 200 Servern × 50 Tagen < 100 ms.
- `mypy --strict` PASS.

#### Task #5 — `_build_pane_context()` erweitern (`backend-implementer`)

`app/views/dashboard.py`:

- `DashboardFilter.from_request(request.args)` (Felder aus Task #1 berücksichtigt).
- Aufruf `findings_results, findings_total = list_findings_cross_server(sess, filt, limit=200, sort=filt.sort, dir=filt.dir, now=now)`.
- Aufruf `kpi_sparklines = daily_severity_counts_fleet(sess, days=50, now=now)`.
- Aufruf `stale_sparkline = daily_stale_server_counts(sess, days=50, now=now)`.
- `quick_stats = get_quick_stats(sess, filter_tags=filt.tags or None, now=now)` bleibt (für KPI-Counter-Heute-Werte; Sparklines kommen aus den Services oben).
- `attention`-Block raus.
- `_apply_filters(cards, filt)` und Server-Card-Builder bleiben **bestehen**, damit der Sidebar-Server-Count weiterhin funktioniert (`servers`-Variable im Context wird vom Sidebar-Layout konsumiert, Block I). Im Pane selbst wird `servers | length` nur für den Header-Counter `{{ visible_servers }} Server sichtbar` gebraucht.
- Zusätzliche Context-Variablen: `view_filter=filt`, `findings=findings_results`, `findings_total=findings_total`, `kpi_sparklines=kpi_sparklines`, `stale_sparkline=stale_sparkline`, `bulk_form=BulkActionForm()`, `csrf_form=CSRFOnlyForm()`.

**DoD:**

- `mypy --strict` PASS.
- View-Test in `tests/views/test_dashboard.py:test_dashboard_pane_context_complete` — alle erwarteten Keys im Context-Dict gesetzt, alle alten (`attention`) nicht mehr.

#### Task #6 — Cross-Server-CSV-Export (`backend-implementer`)

`app/views/findings.py:export_csv` (oder zentrale Logik in `app/services/csv_export.py`):

- Wenn `server_id`-Parameter fehlt → Cross-Server-Modus:
  - Zusätzliche erste Spalte `Server` (= `finding.server.name`).
  - Filter-Felder kommen aus `DashboardFilter.from_request(request.args)` (q, tags, severity, status, kev_only, stale_only, sort, dir).
  - Limit greift **nicht** für CSV — alle Treffer.
- Wenn `server_id` gesetzt → bestehendes Verhalten aus Block K/F (per-Server, mode-abhängig flach/gruppiert/diff). Unverändert.
- Formula-Injection-Mitigation aus Block F: `'`-Prefix auf Zellen, die mit `=/+/-/@/\t/\r` anfangen. Wirkt zusätzlich auf die neue `Server`-Spalte.

**DoD:**

- Unit-Tests in `tests/services/test_csv_export_cross.py`:
  - 5 Findings auf 3 Servern → 6 Zeilen (1 Header + 5 Daten), korrekte Server-Spalte
  - Server-Name `=cmd|...` bekommt `'`-Prefix
  - Filter `?q=openssh` filtert vor Export
- `mypy --strict` PASS.

#### Task #7 — `/findings/search` ersatzlos entfernen (`backend-implementer`)

- `app/views/search.py` (≈350 LoC) **löschen**.
- `app/templates/findings/search.html` löschen. Falls dort Sub-Templates inkludiert werden (`_aggregation.html`, etc.), die auch löschen — Symbol-Sweep im Reviewer-Schritt deckt das ab.
- `app/__init__.py`: `from app.views.search import search_bp` raus, `app.register_blueprint(search_bp)` raus.
- `app/templates/base_app.html`: Sticky-Sidebar-Such-Form (`/`-Shortcut) → `action="{{ url_for('dashboard.index') }}"`, `name="q"`. Falls dort JS-Logik (CVE-Auto-Detect, kind-Switch) ist: entfernen.
- `app/static/js/*`: etwaige `search`-spezifische JS-Bausteine (CVE-Highlighting, kind-Dropdown) entfernen.
- Helper-Funktion `_apply_tag_filter` aus `search.py` ist in Task #2 nach `findings_query.py` umgezogen — gleicher PR.

**DoD:**

- `git grep -nE 'search_bp|SearchHit|SearchAggregation|/findings/search|findings/search' -- ':!docs/decisions/0020-*' ':!docs/blocks/M-*' ':!CHANGELOG.md'` → leer.
- `tests/views/test_search.py` und `tests/services/test_search*` gelöscht.

### Phase B — Templates

#### Task #8 — `dashboard/_detail_pane.html` komplett neu (`frontend-implementer`)

Komplett-Rewrite. Vorschlag-Skelett:

```jinja
{# Dashboard-Pane (ADR-0020). Variablen-Vertrag siehe Docstring unten. #}
<div id="dashboard-pane"
     class="max-w-[1600px] mx-auto px-6 py-6 space-y-8"
     hx-get="{{ request.path }}{% if request.query_string %}?{{ request.query_string.decode() }}{% endif %}"
     hx-trigger="every 10s [document.visibilityState === 'visible']"
     hx-target="this"
     hx-swap="outerHTML"
     hx-headers='{"HX-Request": "true"}'>

  <header class="flex items-end justify-between gap-3 flex-wrap">
    <div>
      <div class="text-[10px] uppercase tracking-[0.12em] font-mono opacity-65">DASHBOARD</div>
      <h1 class="font-mono text-2xl lg:text-3xl mt-1">Alle Findings</h1>
    </div>
    <div class="text-xs opacity-60">
      {{ servers | length }} Server sichtbar
      {% if filter.is_active %}<span class="badge badge-ghost badge-sm ml-1">gefiltert</span>{% endif %}
    </div>
  </header>

  {% include "dashboard/_kpi_cards.html" %}

  {% include "dashboard/_findings_section.html" %}
</div>
```

Variablen-Vertrag-Docstring oben dokumentiert exhaustiv: `servers`, `filter` (DashboardFilter), `quick_stats`, `kpi_sparklines`, `stale_sparkline`, `view_filter`, `findings`, `findings_total`, `available_tags`, `severity_threshold`, `bulk_form`, `csrf_form`. Alte Variablen (`attention`, `db_stale_threshold_h`, `filter_tags`) nicht mehr gelistet (Context-Processor ggf. entfernen, wenn nirgendwo sonst benutzt).

Polling-Wrapper aus Block L (ADR-0019) bleibt auf dem äußeren `<div id="dashboard-pane">`. `staleTick`-Wrapper aus Block L bleibt im Sidebar, nicht hier.

#### Task #9 — `dashboard/_kpi_cards.html` neu (`frontend-implementer`)

5-Spalten-Grid mit fünf Includes von `servers/_kpi_card.html`:

```jinja
<section class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
  {% include "servers/_kpi_card.html" with context only
     label="TOTAL OPEN", value=quick_stats.total_open, tone="base",
     sparkline=kpi_sparklines.total, link_url=url_for('dashboard.index') ~ "#findings-section" %}
  {% include "servers/_kpi_card.html" with context only
     label="KEV", value=quick_stats.kev_open, tone="error", kev_indicator=true,
     sparkline=kpi_sparklines.kev,
     link_url=url_for('dashboard.index') ~ "?kev_only=1#findings-section" %}
  {% include "servers/_kpi_card.html" with context only
     label="CRITICAL", value=quick_stats.critical_open, tone="error",
     sparkline=kpi_sparklines.critical,
     link_url=url_for('dashboard.index') ~ "?severity=critical#findings-section" %}
  {% include "servers/_kpi_card.html" with context only
     label="HIGH", value=quick_stats.high_open, tone="warning",
     sparkline=kpi_sparklines.high,
     link_url=url_for('dashboard.index') ~ "?severity=high#findings-section" %}
  {% include "servers/_kpi_card.html" with context only
     label="STALE-SERVER", value=quick_stats.stale_servers, tone="base",
     sparkline=stale_sparkline,
     link_url=url_for('dashboard.index') ~ "?stale_only=1#findings-section" %}
</section>
```

Hinweis: Jinja `{% include … with context only %}` erlaubt explizit Parameter-Übergabe. Falls die `with`-Form bei euch nicht funktioniert (abhängig von Jinja-Env-Setup), Alternative ist ein dünner Macro-Wrapper. Implementer wählt den simplen Pfad und dokumentiert die Wahl im PR-Kommentar.

#### Task #9a — `servers/_kpi_card.html` um `link_url`-Parameter erweitern (`frontend-implementer`)

Bestehender Partial (`app/templates/servers/_kpi_card.html`):

- Neuer optionaler Parameter `link_url` (Default `None`).
- Wenn `link_url` gesetzt: äußeres `<div>` wird zu `<a href="{{ link_url }}" hx-get="{{ link_url }}" hx-target="#detail-pane" hx-swap="outerHTML" hx-push-url="true" class="… hover:bg-base-300 transition-colors">`.
- Wenn `link_url=None`: Verhalten bleibt wie Block K (statischer `<div>`).
- Tone `base` ist bereits als implizites Else im Macro angelegt — explizit als gültiger Tone whitelisten und im Docstring dokumentieren (`tone="base"` mit `text-base-content` + grauem Stroke).

**DoD für Tasks #8/#9/#9a:**

- Visueller Smoke der Card-Grid in 3 Viewport-Breiten (1-Spalte mobile, 3-Spalten md, 5-Spalten lg).
- Klick auf jede Card setzt korrekten URL-Filter und triggert HTMX-Swap.
- Block-K-Server-Detail-View weiterhin unverändert visuell (Card ohne `link_url` rendert als `<div>`).

#### Task #10 — `dashboard/_findings_section.html` neu (`frontend-implementer`)

Markup nach Vorbild `servers/_findings_section.html` aus Block K, aber:

- Section-ID `findings-section` (gleiche ID wie Server-Detail, weil pro Page nur eine existiert).
- Eyebrow: `TRIAGE QUEUE · ALLE SERVER`.
- Title: `Findings`.
- Toolbar rechts: nur CSV-Dropdown (kein Mode-Toggle, kein Bulk-Ack-Button hier — Bulk-Ack-Button wandert in einen separaten conditional-rendered Bereich, der erscheint sobald Selection > 0).
- Filter-Bar-Include `{% include "dashboard/_findings_filter_bar.html" %}` als eigene Zeile unter dem Section-Header, oberhalb der Bulk-Toolbar.
- Optionale Bulk-Toolbar (`x-show="selected.length > 0"`): „auswahl ack ·N"-Button + Clear-Auswahl-Button.
- Truncation-Hinweis (Task #11) unterhalb der Tabelle, conditional auf `findings_total > findings | length`.
- Tabelle:
  - Bulk-Select-Checkbox-Spalte (`<th>` mit Master-Checkbox, `<td>` mit Row-Checkbox).
  - Server-Spalte (`{{ sort_header('server', 'Server', filt=view_filter, route='dashboard.index') }}`) — Inhalt: Server-Name + Tag-Pills (`#prod #kubernetes` als `<a class="opacity-70 hover:opacity-100" style="color: tag.color">#name</a>`).
  - CVE/Titel-Spalte (sortbar auf `cve`) — CVE-ID + KEV-Badge inline + Titel als zweite Zeile (`text-xs opacity-70`).
  - Paket-Spalte (sortbar auf `pkg`) — `package_name` + Location (`@/usr/sbin/sshd`) als zweite Zeile.
  - EPSS-Spalte (sortbar auf `epss`) — `EPSS NN%` mit Tone-Färbung.
  - CVSS-Spalte (sortbar auf `cvss`) — `CVSS X.X` mit Tone-Färbung.
  - Severity-Spalte (sortbar auf `sev`) — Badge.
  - Status-Spalte (sortbar auf `status`) — Pill.
  - Erstmals-Spalte (sortbar auf `first_seen`) — Datum `YYYY-MM-DD`.
- `data-test`-Attribute auf den Spalten-Headers + Row-Identifier (Server-ID + Finding-ID), damit View-Tests stabil targeten können.

#### Task #11 — `dashboard/_findings_filter_bar.html` neu (`frontend-implementer`)

```jinja
<form class="bg-base-200/60 rounded-box p-3 flex items-center gap-3 flex-wrap text-sm"
      aria-label="Findings-Filter">
  <span class="opacity-60 font-medium">Filter:</span>

  <input type="search" name="q"
         value="{{ view_filter.q or '' }}"
         placeholder="Server, CVE, Paket, Titel…"
         maxlength="128"
         class="input input-bordered input-sm w-56"
         hx-get="{{ url_for('dashboard.index') }}"
         hx-trigger="keyup changed delay:400ms"
         hx-target="#findings-section"
         hx-select="#findings-section"
         hx-swap="outerHTML"
         hx-include="closest form"
         hx-push-url="true"
         data-test="filter-q" />

  <select name="tag"
          class="select select-bordered select-sm"
          hx-get="{{ url_for('dashboard.index') }}" hx-trigger="change"
          hx-target="#findings-section" hx-select="#findings-section" hx-swap="outerHTML"
          hx-include="closest form" hx-push-url="true"
          data-test="filter-tag">
    <option value="">Tag: alle</option>
    {% for tag in available_tags %}
      <option value="{{ tag.name }}" {% if tag.name in view_filter.tags %}selected{% endif %}>{{ tag.name }}</option>
    {% endfor %}
  </select>

  <select name="severity"
          class="select select-bordered select-sm"
          hx-get="…" hx-trigger="change" hx-target="#findings-section" …
          data-test="filter-severity">
    <option value="">Severity: alle</option>
    <option value="critical" {% if view_filter.severity and view_filter.severity.value == 'critical' %}selected{% endif %}>Severity: critical+</option>
    <option value="high"     {% if view_filter.severity and view_filter.severity.value == 'high' %}selected{% endif %}>Severity: high+</option>
    <option value="medium"   {% if view_filter.severity and view_filter.severity.value == 'medium' %}selected{% endif %}>Severity: medium+</option>
    <option value="low"      {% if view_filter.severity and view_filter.severity.value == 'low' %}selected{% endif %}>Severity: low+</option>
  </select>

  <select name="status"
          class="select select-bordered select-sm"
          hx-get="…" hx-trigger="change" …
          data-test="filter-status">
    <option value="open"         {% if view_filter.status == 'open' %}selected{% endif %}>Status: offen</option>
    <option value="acknowledged" {% if view_filter.status == 'acknowledged' %}selected{% endif %}>Status: acknowledged</option>
    <option value="resolved"     {% if view_filter.status == 'resolved' %}selected{% endif %}>Status: resolved</option>
    <option value="all"          {% if view_filter.status == 'all' %}selected{% endif %}>Status: alle</option>
  </select>

  <label class="label cursor-pointer gap-1 py-0">
    <input type="checkbox" name="kev_only" value="1"
           class="checkbox checkbox-sm checkbox-error"
           {% if view_filter.kev_only %}checked{% endif %}
           hx-get="…" hx-trigger="change" …
           data-test="filter-kev-only" />
    <span>nur KEV</span>
  </label>

  <label class="label cursor-pointer gap-1 py-0">
    <input type="checkbox" name="stale_only" value="1"
           class="checkbox checkbox-sm checkbox-warning"
           {% if view_filter.stale_only %}checked{% endif %}
           hx-get="…" hx-trigger="change" …
           data-test="filter-stale-only" />
    <span>nur stale</span>
  </label>

  <div class="ml-auto flex items-center gap-2">
    {% if filter.is_active %}
      <a href="{{ url_for('dashboard.index') }}"
         class="btn btn-ghost btn-xs"
         data-test="filter-reset">Reset</a>
    {% endif %}
    {# CSV-Dropdown wandert in die Section-Toolbar (Task #10); hier nichts. #}
  </div>
</form>
```

Hinweis: `hx-include="closest form"` sorgt dafür, dass alle Felder bei jedem Trigger mitgeschickt werden — egal welcher Input gerade auslöst.

#### Task #12 — `_macros.html:sort_header()` um `route`-Parameter erweitern (`frontend-implementer`)

Aktuelles Macro (Block K) hat die View-Route entweder hartkodiert oder als Default-Parameter. Erweitern:

```jinja
{% macro sort_header(field, label, filt, route='server_detail.show', route_kwargs={}) %}
  …
  hx-get="{{ url_for(route, **route_kwargs) }}?{{ filt.to_query_string(override={'sort': field, 'dir': new_dir}) }}"
  …
{% endmacro %}
```

Block-K-Aufrufe (`servers/_findings_section.html`) bekommen `route='server_detail.show'` + `route_kwargs={'server_id': server.id}`. Block-M-Aufrufe (`dashboard/_findings_section.html`) bekommen `route='dashboard.index'` ohne kwargs.

**DoD:** Bestehende Block-K-View-Tests bleiben grün; neue Block-M-View-Tests rendern sort-header-Links auf `dashboard.index`.

#### Task #13 — Truncation-Notice-Block (`frontend-implementer`)

Innerhalb `dashboard/_findings_section.html` unter der Tabelle:

```jinja
{% if findings_total > findings | length %}
  <div class="text-xs opacity-70 text-center py-3 bg-base-200/40 rounded-box mt-2"
       data-test="truncation-notice">
    Anzeige auf {{ findings | length }} begrenzt — {{ findings_total - (findings | length) }} weitere Treffer.
    Filter verfeinern oder
    <a class="link" href="{{ url_for('findings.export_csv') }}?{{ view_filter.to_query_string() }}"
       download data-test="truncation-csv-link">CSV exportieren</a>.
  </div>
{% endif %}
```

#### Task #14 — Template-Cleanup (`frontend-implementer`)

- `app/templates/dashboard/_quick_stats.html` löschen.
- `app/templates/dashboard/_filter_bar.html` löschen.
- `app/templates/dashboard/_attention.html` löschen.
- Sidebar-Variante `app/templates/sidebar/_quick_stats.html` (falls vorhanden) **bleibt** — Block I-Sidebar zeigt die Sidebar-Quick-Stats weiterhin.
- `grep -nE "_attention|_quick_stats\.html|_filter_bar\.html"` auf `app/templates/` — alle restlichen Treffer prüfen und ggf. mit-entfernen.

### Phase C — View-Code und Header-Suche

#### Task #15 — `app/views/dashboard.py:index()` finalisieren (`backend-implementer`)

- `_build_pane_context()` aus Task #5 vollständig nutzen.
- HTMX-Branch bleibt aus ADR-0017: `is_hx_request(request) → "dashboard/_detail_pane.html"`, sonst `"dashboard/index.html"`.
- Keine separate HX-Route für `#findings-section`-Swap; der Filter-/Sort-Trigger nutzt `hx-target="#findings-section"` + `hx-select="#findings-section"` und holt den vollen Pane (eigentlich Polling-Wrapper) — der Browser swappt nur das Sub-Tree.
- `mypy --strict` PASS.

#### Task #16 — Header-Sidebar-Such-Form umstellen (`frontend-implementer`)

`app/templates/base_app.html`:

- Sticky-Sidebar-Such-Form (`/`-Shortcut, Block-I-Refinement, ADR-0016):
  - `action="{{ url_for('dashboard.index') }}"` (vorher `findings.search` oder `search.search`).
  - `name="q"`.
  - Etwaige CVE-Auto-Detect-JS-Logik im selben File (z.B. ein `kind=cve`-Auto-Switch) entfällt.
- `app/static/js/*`: Such-spezifisches JS prüfen und ggf. trimmen (Symbol-Sweep im Reviewer-Schritt).

### Phase D — Tests

#### Task #17 — Service-Unit-Tests

Siehe Tasks #2, #3, #4, #6 — jede neue Service-Funktion bekommt ihr eigenes Test-File mit den dort genannten Cases.

#### Task #18 — View-Tests `tests/views/test_dashboard.py`

Neue Tests (zusätzlich zu bestehenden Dashboard-Tests, die ggf. an das neue Markup angepasst werden):

- `test_dashboard_renders_kpi_cards_with_sparklines` — 5 `_kpi_card.html`-SVG-Marker im Markup, Sparkline-Pfad sichtbar.
- `test_dashboard_renders_findings_table_with_server_column` — Server-Spalten-Header (`data-test="sort-header-server"`) + Row-Server-Name + Tag-Pills.
- `test_dashboard_filter_q_matches_cve_identifier` — `?q=CVE-2024-6387` filtert auf exakt diese CVE.
- `test_dashboard_filter_q_matches_package_substring` — `?q=openssh` matched mehrere Findings.
- `test_dashboard_filter_q_matches_server_name` — `?q=edge-02` matched alle Findings auf dem Server.
- `test_dashboard_filter_status_acknowledged_only_changes_table` — KPI-Counter bleiben OPEN, Tabelle nur ACK.
- `test_dashboard_filter_sort_by_server_asc` — Server-Name-Reihenfolge alphabetisch.
- `test_dashboard_kpi_card_click_sets_filter` — Card-`hx-get` setzt korrekten Query.
- `test_dashboard_kpi_total_open_card_resets_filter` — Total-Card linkt zu `/` ohne Query (außer #findings-section-Anchor).
- `test_dashboard_truncation_notice_when_total_exceeds_limit` — 250 Findings → Notice mit `+50 weitere`.
- `test_dashboard_no_attention_section` — `_attention.html`-Marker nicht im Output.
- `test_dashboard_no_platzhalter` — kein `border-dashed`-Block im Output.
- `test_dashboard_hx_partial_swap_findings_section_via_hx_select` — `hx-target="#findings-section"` im sort-header-Macro.
- `test_dashboard_search_route_404` — `GET /findings/search` → 404.
- `test_dashboard_csv_export_cross_server_uses_filter` — `/findings/export.csv?q=…&tag=…&severity=…` liefert gefilterte CSV mit Server-Spalte.

#### Task #19 — Adversarial-Tests

- `tests/adversarial/test_dashboard_sort_param_injection.py` — `?sort=DROP TABLE findings` → fällt auf Default `sev`; keine SQL-Exception.
- `tests/adversarial/test_dashboard_q_xss.py` — `?q=<script>alert(1)</script>` rendert escaped; kein `|safe` im Filter-Echo (Input-Value-Attribut).
- `tests/adversarial/test_dashboard_q_sql_injection.py` — `?q=' OR 1=1--` matched keine Findings (gebindet); keine SQL-Exception.
- `tests/adversarial/test_dashboard_csv_formula_injection_server_name.py` — Server-Name `=cmd|...` bekommt `'`-Prefix in der CSV-Server-Spalte.

#### Task #20 — Cleanup-Tests

- `tests/views/test_search.py` und etwaige `tests/services/test_search*` **löschen**.
- Bestehende `tests/views/test_dashboard.py`-Tests, die gegen `_attention.html`/`_filter_bar.html`/`_quick_stats.html`-Markup oder gegen den `Anwenden`-Button assertieren, **anpassen** an das neue Markup oder löschen, wenn obsolete.

### Phase E — Reviewer + Release

#### Task #21 — DoD-Checks (`reviewer`)

```
ruff check . && ruff format --check .
mypy app/
pytest -v --cov=app --cov-fail-under=85
pytest tests/services/test_findings_query_cross.py \
       tests/services/test_severity_history_fleet.py \
       tests/services/test_stale_history.py \
       tests/services/test_csv_export_cross.py -v
pytest tests/views/test_dashboard.py -v
pytest tests/adversarial/ -v
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
docker compose up -d --build && curl -fsSL http://localhost:8000/healthz
```

Plus visueller Diff gegen das Cowork-Screenshot (Browser-Tab nebeneinander); Screenshot des laufenden Stands unter `docs/blocks/M-evidence/dashboard.png` ablegen.

#### Task #22 — Security-Auditor (`security-auditor`)

Pflicht für Block M, weil neue User-Input-Surface (`q`-Such-Feld) auf den DB-Layer durchgereicht wird und in CSV exportiert wird. Audit-Punkte:

- `q`-Field gebindet (ilike mit Param), kein f-String-SQL.
- `q`-Field rendert escaped im Filter-Bar-Input-`value`-Attribut (kein `|safe`).
- `sort`/`dir` Whitelist-only (kein User-String im ORDER BY).
- CSV-Formula-Injection-Mitigation auf Server-Spalte aktiv.
- Bulk-Acknowledge cross-server: Endpoint aus Block F prüft Auth + CSRF (sollte unverändert greifen, aber explizit verifizieren).

#### Task #23 — Spec- und State-Updates (`reviewer`)

- `ARCHITECTURE.md §7` Dashboard-Absatz umschreiben:
  - KPI-Cards mit Sparklines (statt flacher Counter).
  - Findings-Section mit Filter-Bar (Hybrid-Auto-Submit), Truncation-Hinweis, Bulk-Ack, CSV.
  - Kein Platzhalter, keine Attention-Sektion.
  - `/findings/search` als entfernt vermerkt.
- `ARCHITECTURE.md §15`: `server` als zusätzlicher Sort-Key auf der Dashboard-Tabelle erwähnen.
- `ARCHITECTURE.md §17` Out-of-Scope-Liste prüfen — Pagination ist out-of-scope (siehe Re-Open-Trigger ADR-0020), kein neuer Eintrag nötig.
- `docs/decisions/README.md` Index-Tabelle: ADR-0020 ergänzen, ADR-0016 Status auf „Superseded by 0020" setzen.
- `docs/blocks/STATE.md`: Block M unter „Completed" mit Datum, Branch, Test-Anzahl, Coverage. Backlog-Tabelle aktualisieren.
- `CHANGELOG.md`: v0.6.0-Sektion mit Verweis auf ADR-0020 und Liste der entfernten Symbole (`/findings/search`, `_attention.html`, `_filter_bar.html` (alt), `_quick_stats.html` (alt)).

#### Task #24 — Tag `v0.6.0`

Nach Reviewer- und Security-Auditor-Freigabe und allen DoD-Checks grün:

```
git tag -a v0.6.0 -m "Block M — Dashboard-Redesign (ADR-0020)"
git push --tags
```

## Was NICHT in diesem Block

- Keine Pagination im Findings-Table (Re-Open-Trigger ADR-0020).
- Keine CVE-Aggregation (komplett entfernt; Re-Open-Trigger).
- Kein Modal-Drilldown auf CVE.
- Kein `/findings/search`-Redirect (saubere Removal).
- Keine Sparkline pro Server (Cross-Server-Aggregat reicht).
- Keine persistente Daily-Snapshot-Tabelle (weder Severity- noch Stale).
- Kein Multi-Tag-Select-Widget (Single-Select UI, Multi via URL).
- Keine Anpassung am LLM-Chat oder am Server-Detail-View (Block-K-Output bleibt unverändert).

## Definition of Done

### Datei-Existenz

- [ ] `app/views/search.py` existiert nicht mehr
- [ ] `app/templates/findings/search.html` existiert nicht mehr
- [ ] `app/templates/dashboard/_quick_stats.html` existiert nicht mehr
- [ ] `app/templates/dashboard/_filter_bar.html` existiert nicht mehr
- [ ] `app/templates/dashboard/_attention.html` existiert nicht mehr
- [ ] `app/templates/dashboard/_kpi_cards.html` existiert
- [ ] `app/templates/dashboard/_findings_section.html` existiert
- [ ] `app/templates/dashboard/_findings_filter_bar.html` existiert
- [ ] `app/services/stale_history.py` existiert
- [ ] `docs/decisions/0020-dashboard-cross-server-findings.md` ist Status „Akzeptiert"
- [ ] `docs/decisions/0016-header-and-profile-dropdown.md` ist Status „Superseded by 0020"
- [ ] `CHANGELOG.md` enthält v0.6.0-Eintrag mit ADR-0020-Verweis

### Statische Checks

- [ ] `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] `pytest -v --cov=app --cov-fail-under=85` → exit 0
- [ ] `pytest tests/adversarial/ -v` → alle grün
- [ ] `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` → exit 0 (keine neue Migration in Block M, Roundtrip muss aber grün bleiben)

### Symbol-Sweep

- [ ] `git grep -nE 'search_bp|SearchHit|SearchAggregation|/findings/search|findings/search' -- ':!docs/decisions/0020-*' ':!docs/blocks/M-*' ':!CHANGELOG.md' ':!docs/blocks/F-*' ':!docs/blocks/STATE.md'` → leer
- [ ] `git grep -nE '_attention\.html|dashboard/_quick_stats\.html|dashboard/_filter_bar\.html|Platzhalter' -- ':!docs/decisions/0020-*' ':!docs/blocks/M-*' ':!CHANGELOG.md' ':!docs/blocks/D-*' ':!docs/blocks/I-*'` → leer

### Build und Image

- [ ] `docker build -t secscan:latest .` → exit 0
- [ ] `docker images secscan:latest --format '{{.Size}}'` → < 200 MB
- [ ] `docker compose up -d --build` → alle Container healthy
- [ ] `curl -fsSL http://localhost:8000/healthz` → 200

### Visueller Smoke

- [ ] Browser-Vergleich Cowork-Screenshot vs. laufender Stand, Header / KPI-Cards / Findings-Section: Layout, Typografie, Farben, Spacings, Interaktion 1:1 (±2 px Toleranz).
- [ ] Screenshot des laufenden Stands unter `docs/blocks/M-evidence/dashboard.png`.

### E2E-Manual

- [ ] Browser-DevTools-Network während offenem Dashboard: Polling-Requests alle 10 s gegen `dashboard.index` (aus Block L unverändert).
- [ ] Filter setzen (`?severity=critical`), 15 s warten → URL und Tabelle bleiben auf `severity=critical`.
- [ ] Such-Feld: schnell `openss` tippen → genau ein Request 400 ms nach letztem Keystroke (Debounce).
- [ ] KPI-Card-Klick auf KEV → URL springt auf `?kev_only=1`, Tabelle aktualisiert, KEV-Card bleibt visuell unverändert.
- [ ] `/findings/search` aufrufen → 404.
- [ ] CSV-Export mit aktivem Filter `?q=openssh` → CSV hat nur openssh-Findings, mit `Server`-Spalte.
- [ ] Bulk-Select 3 Findings auf verschiedenen Servern → Bulk-Ack-Button erscheint, Modal listet alle 3, Submit → alle 3 ACK, Audit-Event `bulk.acknowledged` mit Server-IDs.

### State-Update

- [ ] `docs/blocks/STATE.md` Block M unter „Completed" verschoben mit Datum, Test-Anzahl, Coverage, Branch.
- [ ] Tag `v0.6.0` gesetzt nach Reviewer- und Security-Auditor-Freigabe.

## Risiken und Mitigation

- **Flotten-Daily-Counts > 200 ms** bei großen Datasets → Mini-Bench in Task #3 + Re-Open-Trigger persistente Tabelle (ADR-0020).
- **Stale-Reconstruction-Bug bei Server-Retire-Mid-Window** → Unit-Test in Task #4 (Case „Server retire-mid-window").
- **`q`-Field als SQL-Injection-Surface** → ORM-only mit `ilike`-Bind; Adversarial-Test in Task #19.
- **`q`-Field als XSS-Surface** im Filter-Echo (Input-Value-Attribut) → kein `|safe`, autoescaping standardmäßig aktiv; Adversarial-Test in Task #19. Match-Highlight im Tabellen-Render bleibt **bewusst unimplementiert** (kein `|safe` auf User-Input).
- **HTMX-Filter-Polling-Race** mit Block-L-Polling: beide pollen `#dashboard-pane` alle 10 s. Filter-Submit setzt URL → Polling-Re-Fetch nutzt `request.path?query_string` und holt den Filter mit. **Test:** Filter setzen, 10 s warten, kein Reset. Falls doch beobachtbar: Polling-Re-Fetch in der Filter-Submit-Phase pausieren (Alpine-State-Flag, Re-Open-Trigger).
- **CSV-Endpoint-Wiederverwendung kollidiert mit Server-Detail-Modi** → zwei Code-Pfade in `findings.export_csv()` sind okay (`server_id` gesetzt vs. fehlt); Server-Detail-Modi (flach/gruppiert/diff) bleiben strikt server-detail-spezifisch.
- **Bulk-Ack cross-server** — Endpoint aus Block F akzeptiert `finding_ids` cross-server (Server-ID nicht in der Payload). Sollte direkt funktionieren, aber Test in Task #18 (`test_dashboard_bulk_ack_cross_server`) muss explizit assertieren.
- **`stale_only`-Filter ist Python-side Post-Filter** und kombiniert mit `q` ineffizient (zwei Subquerys plus IN). Bei realer Flotte messen; falls > 200 ms, materialisierte Stale-Server-View prüfen (Re-Open-Trigger).
- **ADR-0016-Supersession** — ADR-0016 hat noch viel Inhalt zu Header/Profile-Dropdown der nicht abgelöst wird. „Superseded by 0020" muss präzise sein: nur die Dashboard-Pane-Layout-Sektionen. Reviewer prüft die Wortwahl in ADR-0016.

## Reihenfolge

Phase A (Backend) → Phase B (Templates) → Phase C (View + Header-Suche) → Phase D (Tests) → Phase E (Reviewer + Security-Auditor + Release).

Innerhalb von Phase A: Tasks #1–#4 sind unabhängig und können parallel laufen. #5 + #6 nach #1–#4. #7 (Search-Removal) unabhängig parallel.

Innerhalb von Phase B: #9a vor #9 (Partial-Erweiterung vor Verwendung). #10–#13 parallel. #14 zuletzt.

Phase C wartet auf Phase A + Teile von B (#9a wegen `link_url`-Parameter).

Phase D wartet auf Phase A + B + C.

## Implementer-Brief (für `Agent`-Delegation)

Empfohlene Aufteilung:

1. **`backend-implementer`** mit Scope „Phase A Tasks #1–#7". Liest ADR-0020 komplett, ADR-0018 §Backend-Pipeline, `ARCHITECTURE.md §7 + §15`, Block-K-Brief Phase A.
2. **`frontend-implementer`** mit Scope „Phase B Tasks #8–#14 + Phase C Task #16". Liest ADR-0020 komplett, ADR-0017, ADR-0018 §KPI-Card-Pattern, Block-K-Brief Phase B + #6/#8/#9.
3. **`backend-implementer`** (zweite Runde) mit Scope „Phase C Task #15". Liest ADR-0020 §Backend-Pipeline + ADR-0017.
4. **`test-writer`** mit Scope „Phase D Tasks #17–#20".
5. **`reviewer`** mit der DoD-Checkliste oben.
6. **`security-auditor`** mit Task #22-Scope.

Server-Detail-View-Code (`app/views/server_detail.py`, `app/templates/servers/detail.html`, `app/templates/servers/_findings_section.html`, `app/templates/servers/_*_view*.html`) ist außerhalb der Implementer-Scopes — bleibt unverändert. Wer als Implementer Änderungen dort vorschlägt: ablehnen und auf ADR-0020 §Out-of-Scope verweisen.

LLM-Chat-Code (`app/api/llm_chat.py`, `app/static/js/llm_chat.js`, `app/templates/chat/*`) ist ebenfalls außerhalb des Scopes. SSE-Stream im LLM-Chat bleibt aus Block L unangetastet.

## Roll-Back-Plan

Block M ist ein Visual-Block ohne DB-Migration und ohne externe API-Breakage (außer `/findings/search`-Removal, das keinen extern dokumentierten Endpoint trifft). Falls Probleme einen Roll-Back erfordern:

1. Branch `feat/block-m-dashboard-findings` verwerfen oder Revert-PR.
2. ADR-0020 auf Status „Verworfen" setzen, ADR-0016 zurück auf „Akzeptiert".
3. Alternative Lösungsrichtung in neuer ADR.
4. Live-System läuft auf `v0.5.0` (Block L Polling) weiter.

Falls der Search-Removal-Teil sich nachträglich als Bug erweist (z.B. existierender Use-Case taucht auf): Search kann aus dem Git-History per Cherry-Pick eines reverse-Removal-Commits wiederhergestellt werden. Solange das in v0.6.x passiert, ist es ein Patch-Release; ab v0.7.x neue ADR.
