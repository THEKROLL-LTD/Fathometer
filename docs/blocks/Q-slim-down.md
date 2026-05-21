# Block Q — Server-Detail- und Dashboard-Entschlackung, dedizierte Findings-Seite

**Typ:** Refactor + Scope-Reduktion · **Branch-Vorschlag:** `feat/block-q-slim-down` · **Zielversion:** v0.10.0 · **Vorgänger:** v0.9.6 (2026-05-20) · **Spec:** [ADR-0025](../decisions/0025-server-detail-and-findings-slim-down.md)

## Ziel

Fünf zusammenhängende Umbau-Punkte ohne neue Features:

1. **Findings-View-Modi `gruppiert` und `diff` entfernen.** Code, Templates, Tests, CSV-Export-Varianten und Spec-Sektionen ersatzlos streichen. Verbleibender Modus ist der heutige `list`-Modus (Application-Group-Cards plus Pending-Grouping).

2. **Application-Group-Card-Findings: HTMX-Lazy-Load.** Cards default collapsed, Findings-Tabelle pro Group via HTMX nachgeladen, Initial-Render reduziert auf Counts plus Group-Metadaten plus Worst-Finding-Batch.

3. **Pending-Grouping-Sektion: HTMX-Lazy-Load pro Risk-Band-Bucket.** Initial-Render reduziert auf eine Aggregat-Counts-Query; pro Band ein collapsed `<details>`-Rollup mit Pill und Count; Findings nachgeladen.

4. **`active`-Status-Pille im Server-Detail-Header entfällt.** Pill-Reihe nur noch für revoked/retired plus die anderen Auffälligkeits-Marker. Settings-Server-Liste behält die Pille (anderer Kontext).

5. **Cross-Server-Findings-Tabelle zieht vom Dashboard auf neue `/findings`-Seite.** Neuer Nav-Eintrag, Default-State leer, expliziter Submit-Button (kein Auto-Submit), klassische nummerierte Pagination (50/Seite). Dashboard verliert die Findings-Section ersatzlos.

**Wichtige Abgrenzung:** Block Q fasst die drei `_load_findings()`-Aufrufe im Server-Detail-Header (`compute_tendency`, `severity_snapshots_for_server`, `daily_severity_counts_for_server`) **nicht** an. Das ist ein separater Performance-Block (Re-Open-Trigger in ADR-0025, vermutlich Block R).

## Vorbereitung — zu lesende Sektionen

- [ADR-0025](../decisions/0025-server-detail-and-findings-slim-down.md) (komplett)
- [ADR-0018](../decisions/0018-server-detail-visual-alignment.md) — wird in Modi-Aufzählung und Header-Pill-Reihe überschrieben
- [ADR-0020](../decisions/0020-dashboard-cross-server-findings.md) — Findings-Section-Layout, Filter-Bar, Sortierung, Truncation-Logik (wird durch Pagination ersetzt)
- [ADR-0023](../decisions/0023-llm-risk-reviewer-and-application-grouping.md) §UI-Konsequenzen — Group-Card-Render bleibt strukturell, Default-Expand-Logik entfällt
- [ADR-0019](../decisions/0019-dashboard-polling-not-sse.md) — Polling-Wrapper bleibt auf dem Dashboard-Pane
- `app/views/server_detail.py` — `show()`, `_render_findings_section`, `_load_application_groups_for_server`, `_load_ungrouped_findings_for_server`
- `app/views/dashboard.py` — die heute hier lebende Findings-Filter-/-Query-Logik wandert in `app/views/findings.py`
- `app/views/findings.py` — heute nur CSV-Export, bekommt den neuen HTML-View
- `app/services/findings_query.py` — `group_findings_by_package`, `PackageGroup`, `list_findings_cross_server` (neuer `offset`-Param)
- `app/services/diff_view.py` — komplett zu löschen
- `app/services/csv_export.py` — `csv_mode`-Varianten reduzieren
- `app/schemas/dashboard_filter.py` — zieht semantisch in den Findings-View um (Rename optional, siehe Task F.6)
- `app/schemas/findings_view_filter.py` — `mode`-Feld entfällt
- `app/templates/servers/detail.html` — Header-Pill-Reihe (Task D.1)
- `app/templates/servers/_findings_section.html` — Mode-Segment + Mode-Switch entfällt
- `app/templates/servers/_view_group.html`, `_view_diff.html` — zu löschen
- `app/templates/_partials/application_group_card.html` — Lazy-Load-Slot
- `app/templates/_partials/group_findings_table.html` — wird das Fragment-Template des Endpoints
- `app/templates/servers/_view_groups.html` — Pending-Grouping-Sektion auf Counts-Only umstellen
- `app/templates/dashboard/_findings_section.html` — wandert auf neue Findings-Seite
- `app/templates/base_app.html` (oder wo der Header lebt) — neuer Nav-Eintrag
- `ARCHITECTURE.md §7` — wird in der Server-Detail- und Dashboard-Sektion angepasst (siehe Task F.1)

Subagent-Aufrufe nennen die Sektionen explizit.

## Aufgaben

### Phase A — Findings-Modi `gruppiert` und `diff` ausbauen

#### Task A.1 — Service-Layer-Bereinigung (`backend-implementer`)

- `app/services/diff_view.py` löschen. Imports in `app/views/server_detail.py` und allen anderen Modulen entfernen.
- In `app/services/findings_query.py` entfernen: `group_findings_by_package()`, `PackageGroup`-Dataclass plus deren Re-Exports am Modul-Ende. `FindingsFilter` und `list_findings()` bleiben.
- In `app/services/csv_export.py` die `csv_mode`-Varianten `gruppiert` und `diff` löschen. Verbleibend nur die flache Variante (heute `flach`). Funktion umbenennen falls die Variante explizit benannt war.
- `app/views/findings.py::export_csv` bekommt keinen `csv_mode`-Param mehr.

**DoD:**
- `grep -r "compute_diff\|DiffSection\|group_findings_by_package\|PackageGroup" app/ tests/ docs/` liefert keine Treffer mehr (außer in `docs/decisions/0025-*.md` und `docs/blocks/Q-slim-down.md`).
- `grep -r "csv_mode" app/` liefert keine Treffer.
- `ruff check . && ruff format --check .` PASS.
- `mypy app/` PASS.
- Bestehende `tests/services/test_findings_query.py` ohne `group_findings_by_package`-Tests grün.

#### Task A.2 — View-Layer-Bereinigung (`backend-implementer`)

- In `app/views/server_detail.py::_render_findings_section` den Mode-Branch entfernen. Nur der `list`-Pfad bleibt. `view_filter.mode`-Lesungen löschen.
- `app/schemas/findings_view_filter.py`: `mode`-Feld entfällt. `FindingsViewFilter.from_request` ignoriert `?mode=`-Param still (kein Error, kein Redirect). `to_query_string`-Helper entfernt `mode` aus dem Output.
- Templates löschen: `app/templates/servers/_view_group.html`, `app/templates/servers/_view_diff.html`.
- In `app/templates/servers/_findings_section.html`:
  - Mode-Segment-Block (`<div class="join">`-Reihe mit `flach`/`gruppiert`/`diff`) ersatzlos entfernen.
  - `{% if view_filter.mode == 'list' %} … {% elif … %} … {% else %} … {% endif %}`-Switch entfernen, der Body rendert direkt den heutigen `list`-Pfad (Application-Group-Cards bzw. flache Tabelle bei aktivem Filter oder `?flat=1`).
  - Der `{% set _filters_active = … %}`/`{% set _force_flat = … %}`-Block bleibt unverändert (entscheidet zwischen `_view_groups.html` und `_view_list.html`).
  - CSV-Dropdown auf einen einzelnen `<a>`-Link reduzieren statt `for csv_mode in …`-Schleife.

**DoD:**
- `grep -rn "mode='diff'\|mode='group'\|mode=\"diff\"\|mode=\"group\"" app/` liefert keine Treffer.
- Server-Detail rendert mit `?mode=group` oder `?mode=diff` ohne Fehler die Standard-List-Ansicht. Test: `tests/views/test_server_detail.py::test_unknown_mode_falls_back_to_list` (neuer Test).
- Bestehende Tests in `tests/views/test_server_detail.py`, die Mode-Toggle-Buttons oder Group-/Diff-Renderings prüfen, sind entweder gelöscht oder auf den List-Pfad umgeschrieben.
- `tests/views/test_server_detail_redesign.py` und `tests/views/test_server_detail_action_required.py` grün.

#### Task A.3 — Test- und Fixture-Bereinigung (`test-writer`)

- `tests/services/test_diff_view.py` komplett löschen.
- In `tests/services/test_findings_query.py` alle `group_findings_by_package`-Tests entfernen (üblicherweise eine eigene Test-Klasse oder `class TestGroupByPackage`).
- In `tests/views/test_server_detail.py` alle `mode=group`/`mode=diff`-Render-Tests löschen oder als `test_unknown_mode_falls_back_to_list` zusammenfassen.

**DoD:**
- `pytest tests/services/test_diff_view.py` → file not found (gelöscht).
- `pytest tests/services/test_findings_query.py -k group_findings_by_package` → 0 collected.
- `pytest tests/views/ -v` grün, Anzahl Tests ist nach Cleanup niedriger als vorher (Delta erwartbar 5-15).

### Phase B — Application-Group-Card-Findings auf HTMX-Lazy

#### Task B.1 — Counts-Aggregate plus Group-Metadaten-Lader (`backend-implementer`)

- In `app/views/server_detail.py::_load_application_groups_for_server`:
  - Per-Group-Findings-Query (`SELECT Finding WHERE application_group_id == grp.id`) entfernen.
  - Stattdessen Count-Aggregat: `select(Finding.application_group_id, func.count(Finding.id)).where(Finding.server_id == ..., Finding.status == OPEN, Finding.application_group_id.is_not(None)).group_by(Finding.application_group_id)`. Liefert ein `dict[group_id, count]`.
  - Worst-Finding-Batch-Query bleibt unverändert.
  - Rückgabe-Format pro Entry: `{"group": ApplicationGroup, "count": int, "worst_finding": Finding | None}` (kein `findings`-Feld mehr).
- Action-Needed-Sektion-Helper (`_build_action_sections`) ist davon nicht betroffen — er liest nur `entry.group.label`, `entry.worst_finding.identifier_key`, `entry.group.risk_band_reason`. Anpassung: `entry["findings"]`-Zugriffe entfernen (gibt es nicht mehr; Logik nutzte sie ohnehin nicht).

**DoD:**
- `_load_application_groups_for_server` führt am Initial-Render exakt 3 Queries aus: Group-Metadaten, Worst-Finding-Batch, Count-Aggregat. Verifizierbar via `SQLALCHEMY_ECHO=true` im Test oder via `sqlalchemy.event.listens_for(Engine, "before_execute")`-Hook.
- Server mit 15 Application-Groups löst beim Render von `/servers/<id>` (HTMX-Lazy-Path) **nicht** 15 separate Findings-Queries aus.
- Unit-Test: `tests/views/test_server_detail_lazy_groups.py::test_initial_render_no_per_group_findings_query`.

#### Task B.2 — Lazy-Load-Endpoint für Group-Findings (`backend-implementer`)

- Neuer Endpoint `app/views/server_detail.py::group_findings_fragment`:
  ```python
  @server_detail_bp.get("/<int:server_id>/groups/<int:group_id>/findings")
  @login_required
  def group_findings_fragment(server_id: int, group_id: int) -> str:
      server = _load_server_with_tags(server_id)
      if server is None:
          abort(404)
      sess = get_session()
      findings = list(sess.execute(
          select(Finding)
          .where(
              Finding.server_id == server_id,
              Finding.application_group_id == group_id,
              Finding.status == FindingStatus.OPEN,
          )
          .order_by(
              Finding.is_kev.desc(),
              nulls_last(Finding.epss_score.desc()),
              nulls_last(Finding.cvss_v3_score.desc()),
              Finding.first_seen_at.asc(),
          )
      ).scalars().all())
      if not findings:
          abort(404)
      return render_template(
          "_partials/group_findings_table.html",
          findings=findings,
      )
  ```
- `app/templates/_partials/group_findings_table.html` bleibt das Render-Target — funktioniert heute schon mit `findings`-Var.

**DoD:**
- `GET /servers/1/groups/42/findings` als angemeldeter User mit existierender Group-OPEN-Findings → 200, HTML-Fragment ohne `<html>`/`<body>` (Partial).
- `GET /servers/1/groups/42/findings` ohne Login → 302 zum Login (`@login_required`).
- `GET /servers/1/groups/9999/findings` → 404 (Cross-Server-/Cross-Group-Schutz via leerem Query-Ergebnis).
- `GET /servers/9999/groups/42/findings` → 404 (Server nicht gefunden).
- Unit-Tests in `tests/views/test_server_detail_lazy_groups.py`: Happy-Path, Cross-Server-Group, Login-Required, leerer Group-Bucket.

#### Task B.3 — Card-Template auf Lazy umstellen (`frontend-implementer`)

- In `app/templates/_partials/application_group_card.html`:
  - `open_default`-Variable entfernen. `<details>` rendert immer ohne `open`-Attribut.
  - Findings-Count-Badge im Card-Header bekommt seinen Wert aus `count` statt aus `findings | length`.
  - Im Drill-down-`<details>`-Body den `{% include "_partials/group_findings_table.html" %}` ersetzen durch:
    ```jinja
    <details data-test="group-findings-details">
      <summary class="cursor-pointer text-sm opacity-80 select-none">
        Show all {{ count }} {% if count == 1 %}finding{% else %}findings{% endif %}
      </summary>
      <div class="mt-2"
           hx-get="{{ url_for('server_detail.group_findings_fragment',
                              server_id=server.id, group_id=group.id) }}"
           hx-trigger="toggle once from:closest details, click once from:closest summary"
           hx-swap="innerHTML"
           data-test="group-findings-lazy-slot">
        <div class="opacity-60 text-xs italic px-3 py-2">
          <span class="loading loading-spinner loading-xs align-middle mr-1"></span>
          Lade Findings…
        </div>
      </div>
    </details>
    ```
- In `app/templates/servers/_view_groups.html` den `_open` und das `open_default=_open`-Argument entfernen.

**DoD:**
- Initial-Render einer Server-Detail-Seite mit 10 Application-Groups: Browser-DevTools zeigt 1 Initial-Request, danach 1 HTMX-Request pro aufgeklappter Card.
- Wiederholtes Auf-/Zuklappen einer Card löst genau 1 HTMX-Request aus (`once`-Modifier).
- Manueller Test mit deaktiviertem JavaScript: Card bleibt collapsed, Findings nicht sichtbar — der „kein JS"-Fall ist explizit nicht supported (HTMX-Standard im Projekt, siehe ADR-0001).

### Phase C — Pending-Grouping-Sektion auf HTMX-Lazy

#### Task C.1 — Aggregat-Counts statt Findings-Load (`backend-implementer`)

- `_load_ungrouped_findings_for_server` aus `app/views/server_detail.py` entfernen.
- Neuer Helper `_load_pending_grouping_counts(sess, server_id)`:
  ```python
  def _load_pending_grouping_counts(sess: Any, server_id: int) -> dict[str, int]:
      stmt = (
          select(Finding.risk_band, func.count(Finding.id))
          .where(
              Finding.server_id == server_id,
              Finding.application_group_id.is_(None),
              Finding.status == FindingStatus.OPEN,
          )
          .group_by(Finding.risk_band)
      )
      out: dict[str, int] = {}
      for band, n in sess.execute(stmt).all():
          if band is not None:
              out[band] = int(n)
      # Default für alle bekannten Bands auf 0 setzen, damit Templates
      # deterministisch iterieren können.
      for band in ("escalate","act","mitigate","pending","unknown","monitor","noise"):
          out.setdefault(band, 0)
      return out
  ```
- In `_render_findings_section` den `ungrouped_findings`-Slot durch `pending_grouping_counts` ersetzen; `view_filter.mode == "list"`-Branch ruft den neuen Helper auf.

**DoD:**
- `_render_findings_section` macht für die Pending-Sektion exakt 1 Query (das GROUP-BY-Aggregat).
- Unit-Test: `tests/views/test_server_detail_pending_lazy.py::test_initial_render_no_findings_query_for_pending`.

#### Task C.2 — Lazy-Load-Endpoint für Pending-Findings (`backend-implementer`)

- Neuer Endpoint:
  ```python
  _PENDING_BANDS = ("escalate","act","mitigate","pending","unknown","monitor","noise")

  @server_detail_bp.get("/<int:server_id>/findings/pending")
  @login_required
  def pending_findings_fragment(server_id: int) -> str:
      band = request.args.get("risk_band")
      if band not in _PENDING_BANDS:
          abort(400)
      sess = get_session()
      findings = list(sess.execute(
          select(Finding)
          .where(
              Finding.server_id == server_id,
              Finding.application_group_id.is_(None),
              Finding.status == FindingStatus.OPEN,
              Finding.risk_band == band,
          )
          .order_by(
              Finding.is_kev.desc(),
              nulls_last(Finding.epss_score.desc()),
              nulls_last(Finding.cvss_v3_score.desc()),
              Finding.first_seen_at.asc(),
          )
      ).scalars().all())
      if not findings:
          abort(404)
      return render_template(
          "_partials/pending_findings_table.html",
          findings=findings,
          risk_band=band,
      )
  ```
- Neues Fragment-Template `app/templates/_partials/pending_findings_table.html` mit dem `<tbody>`-Markup, das heute in `_view_list.html` pro Risk-Band gerendert wird (Spalten unverändert, Sortierung backend-fix).

**DoD:**
- `GET /servers/1/findings/pending?risk_band=monitor` als angemeldeter User → 200, HTML-Fragment.
- `?risk_band=invalid` → 400.
- `?risk_band=`-fehlt → 400.
- Server ohne Pending-Findings im angefragten Band → 404.
- Ohne Login → 302 Login-Redirect.

#### Task C.3 — Pending-Sektion-Template umbauen (`frontend-implementer`)

- In `app/templates/servers/_view_groups.html` den `{% if ungrouped_findings %} … {% endif %}`-Block ersetzen durch:
  ```jinja
  {%- set _total_pending = pending_grouping_counts.values() | sum -%}
  {% if _total_pending > 0 %}
    <section class="mt-6" data-test="pending-grouping-section">
      <header class="flex items-center gap-2 mb-2">
        <span class="loading loading-spinner loading-xs opacity-60" aria-hidden="true"></span>
        <h3 class="text-sm font-mono uppercase tracking-[0.12em] opacity-65">
          Pending grouping
        </h3>
        <span class="badge badge-ghost badge-sm">
          {{ _total_pending }} {% if _total_pending == 1 %}finding{% else %}findings{% endif %}
        </span>
      </header>
      <p class="text-xs opacity-60 mb-2">
        These findings have not been assigned to an application group yet.
        The risk reviewer worker will pick them up shortly.
      </p>
      <div class="space-y-1">
        {% for band, count in pending_grouping_counts.items() if count > 0 %}
          <details class="rounded border border-base-300 bg-base-200/40"
                   data-test="pending-band-{{ band }}">
            <summary class="px-3 py-2 cursor-pointer flex items-center gap-3">
              {% with band_value=band, as_link=false, compact=true, show_count=false %}
                {% include "_partials/risk_band_pill.html" %}
              {% endwith %}
              <span class="opacity-70 text-sm">{{ count }} findings</span>
            </summary>
            <div hx-get="{{ url_for('server_detail.pending_findings_fragment',
                                    server_id=server.id) }}?risk_band={{ band }}"
                 hx-trigger="toggle once from:closest details, click once from:closest summary"
                 hx-swap="innerHTML"
                 data-test="pending-band-lazy-slot">
              <div class="opacity-60 text-xs italic px-3 py-2">
                <span class="loading loading-spinner loading-xs align-middle mr-1"></span>
                Lade Findings…
              </div>
            </div>
          </details>
        {% endfor %}
      </div>
    </section>
  {% endif %}
  ```
- In `app/views/server_detail.py::show` den Template-Kwarg-Block: `ungrouped_findings` durch `pending_grouping_counts` ersetzen.

**DoD:**
- Server-Detail mit 272 Pending-Findings rendert keine einzige Findings-Row im Initial-HTML. Verifikation: HTML-Snapshot-Test oder `assert "finding-row" not in initial_html`.
- Pro Band-`<details>` lädt das erste Aufklappen die zugehörigen Findings, weiteres Auf-/Zuklappen löst keinen Request aus.
- Wenn `_total_pending == 0`: Pending-Sektion wird gar nicht gerendert.

### Phase D — `active`-Pille raus, Templates angleichen

#### Task D.1 — Pill-Reihe verkürzen (`frontend-implementer`)

- In `app/templates/servers/detail.html` (etwa Zeile 69-81) den `{% if revoked %} … {% elif retired %} … {% else %} active {% endif %}`-Block ersetzen durch:
  ```jinja
  {% if server.revoked_at %}
    <span class="badge badge-sm badge-error font-mono"
          title="Widerrufen am {{ server.revoked_at.strftime('%Y-%m-%d %H:%M') }}">
      revoked
    </span>
  {% elif server.retired_at %}
    <span class="badge badge-sm badge-ghost font-mono"
          title="Stillgelegt am {{ server.retired_at.strftime('%Y-%m-%d %H:%M') }}">
      retired
    </span>
  {% endif %}
  ```
- Alle anderen Pills (`scan_stale`, `db_stale`, `agent_outdated`, `trivy_outdated`, `trivy_db_stale`, `action_required`) bleiben unverändert.
- `app/templates/settings/servers.html` Zeile ~122 mit der grünen `active`-Badge **bleibt unverändert** (anderer Kontext).

**DoD:**
- Render eines aktiven Servers ohne Stale-/Outdated-Marker: HTML enthält keine `>active<`-Badge im Server-Detail-Header.
- Render eines revoked Servers: HTML enthält `>revoked<`-Badge.
- Render eines retired Servers: HTML enthält `>retired<`-Badge.
- Settings/servers-Liste: `>active<`-Badge bleibt für aktive Server sichtbar (Regression-Test).

#### Task D.2 — Tests anpassen (`test-writer`)

- In `tests/views/test_server_detail*.py` alle Assertions, die im Default-Fall (aktiver Server) die `active`-Pille erwarten, umkehren auf „Pill-Reihe enthält keine `active`-Badge".
- Neuer Test: `test_active_pill_removed_for_active_server_in_detail_header`.
- Regression-Test in `tests/views/test_settings_servers.py` (falls vorhanden, sonst neu): `active`-Pille bleibt in der Settings-Server-Liste sichtbar.

**DoD:**
- `pytest tests/views/test_server_detail*.py -v` grün.
- `grep -rn ">active<" app/templates/servers/` liefert keine Treffer.

### Phase E — Cross-Server-Findings auf `/findings`-Seite

#### Task E.1 — Backend: Pagination im `list_findings_cross_server` (`backend-implementer`)

- `app/services/findings_query.py::list_findings_cross_server` bekommt einen `offset: int = 0`-Parameter zusätzlich zum `limit`.
- Default für `limit` bleibt wie heute, der neue View nutzt aber explizit `limit=50`.
- `offset` wird vor dem `list_stmt.limit(limit)` als `list_stmt.offset(offset).limit(limit)` angefügt. `total_count`-Berechnung bleibt unverändert (gilt für den vollen gefilterten Satz, nicht für die aktuelle Seite).
- Signatur:
  ```python
  def list_findings_cross_server(
      session: Session,
      filt: DashboardFilter,
      *,
      limit: int = 200,
      offset: int = 0,
      sort: FindingsCrossSortKey = "risk",
      dir: FindingsSortDir = "desc",
      now: datetime | None = None,
  ) -> tuple[list[Finding], int]: ...
  ```

**DoD:**
- Unit-Test: `tests/services/test_findings_query.py::test_cross_server_offset_pagination` mit 75 Fixture-Findings, `limit=50`, `offset=0` → 50 Treffer, `offset=50` → 25 Treffer, `total_count=75` in beiden Fällen.

#### Task E.2 — Neue View `/findings` (`backend-implementer`)

- `app/views/findings.py`: neuer `findings_bp = Blueprint("findings", __name__, url_prefix="/findings")`.
  - Heutiger `export_csv`-Endpoint behält seine URL (`/findings/export.csv` o.ä., wie aktuell konfiguriert), der CSV-Mode-Param entfällt (Task A.1).
  - Neuer `@findings_bp.get("/")` HTML-Handler `index()`:
    ```python
    @findings_bp.get("/")
    @login_required
    def index() -> str:
        filt = DashboardFilter.from_request(request.args, ...)
        page = max(1, int(request.args.get("page", "1")))
        per_page = 50
        sort = request.args.get("sort", "risk")
        dir_ = request.args.get("dir", "desc")
        sess = get_session()

        is_filtered = _filter_is_active(filt) or _explicit_sort(request.args)
        findings, total = ([], 0)
        if is_filtered:
            findings, total = list_findings_cross_server(
                sess, filt,
                limit=per_page,
                offset=(page - 1) * per_page,
                sort=sort, dir=dir_,
            )
        return render_template(
            "findings/index.html",
            filt=filt,
            findings=findings,
            total=total,
            page=page,
            per_page=per_page,
            total_pages=(total + per_page - 1) // per_page if total > 0 else 0,
            is_filtered=is_filtered,
            total_findings=_count_open_findings(sess),
            visible_servers=_count_active_servers(sess),
            sort=sort, dir=dir_,
        )
    ```
- `_filter_is_active(filt)`-Helper prüft die in ADR-0025 §(5) gelistete Filter-Aktiv-Definition.
- `_explicit_sort(args)`-Helper prüft ob `sort` oder `dir` in der URL-Query stehen (Power-User-Sort-Bookmark zählt als „User will Findings sehen").
- `_count_open_findings(sess)` und `_count_active_servers(sess)` sind billige Aggregat-Counts.
- Blueprint in `app/__init__.py` registrieren.

**DoD:**
- `GET /findings` ohne Filter, eingeloggt → 200, HTML enthält Empty-State-Block (siehe Task E.4), keine Findings-Row.
- `GET /findings?q=foo` → 200, HTML enthält Filter-Bar mit ausgefülltem `q=foo`, plus Findings (falls Treffer) oder „Kein Treffer für diesen Filter."-Hinweis.
- `GET /findings?page=2` ohne sonstigen Filter → Empty-State (Page allein ohne Filter triggert nicht).
- `GET /findings?sort=epss&dir=desc` ohne Filter → rendert die Tabelle (expliziter Sort ist User-Intent).
- Ohne Login → 302 Login-Redirect.

#### Task E.3 — Header-Navigation: Neuer `Findings`-Eintrag (`frontend-implementer`)

- In `app/templates/base_app.html` (oder dem geteilten Header-Partial) den Nav-Block um einen zweiten `<a>` neben `Dashboard` erweitern. Active-Highlight per `request.endpoint`-Check (`'findings.index'`).
- Bisheriger Suche-Eintrag (falls noch vorhanden aus ADR-0020) zeigt jetzt auf `/findings` statt auf das Dashboard.

**DoD:**
- Header zeigt „Dashboard" und „Findings" als sichtbare Nav-Items.
- Klick auf „Findings" lädt `/findings` und hebt den Eintrag visuell hervor.
- Klick auf „Dashboard" lädt `/` und hebt dort den Eintrag hervor.

#### Task E.4 — Findings-Template (`frontend-implementer`)

- Neues Template `app/templates/findings/index.html`. Erbt von `base_app.html`. Layout:
  - **Header:** Eyebrow `FINDINGS`, Title „Findings", rechts ein kleiner Counter `{{ total }} Treffer · Seite {{ page }} von {{ total_pages }}` (nur wenn `is_filtered and total > 0`).
  - **Filter-Bar als `<form method="get" action="/findings">`:**
    - `q`-Input (Such-Feld).
    - `tag`-Select (Default „alle Tags").
    - `risk_band`-Select.
    - `application_group`-Select.
    - `action`-Select.
    - `severity`-Select.
    - `status`-Select (Default `offen`).
    - `kev_only`-Checkbox.
    - `stale_only`-Checkbox.
    - Submit-Button **„Anwenden"** (rechts).
    - Versteckte `sort`/`dir`-Inputs werden bei Submit beibehalten (damit eine aktive Sort-Wahl beim erneuten Filter-Submit nicht verloren geht).
    - **Keine** `hx-trigger`-Attribute auf Filterfeldern.
  - **Tabelle:** wiederverwendet das heutige `dashboard/_findings_section.html`-Markup, abzüglich Heartbeat-Spalte (Heartbeat existiert dort nicht; nur Sicherheitscheck dass keine Heartbeat-Renderings reinrutschen).
  - **Pager unter der Tabelle:**
    ```jinja
    {% if total > 0 %}
      <nav class="flex items-center justify-between gap-3 mt-3 font-mono text-xs"
           aria-label="Pagination">
        {%- set _qs_base = request.args.to_dict(flat=True) -%}
        {%- set _ = _qs_base.pop('page', None) -%}
        {%- set _prev_qs = _qs_base | merge_dict({'page': page-1}) -%}
        {%- set _next_qs = _qs_base | merge_dict({'page': page+1}) -%}
        <a href="?{{ _prev_qs | urlencode }}"
           class="btn btn-xs btn-ghost {% if page <= 1 %}btn-disabled{% endif %}"
           {% if page <= 1 %}aria-disabled="true"{% endif %}>« vorherige</a>
        <span class="opacity-65">Seite {{ page }} von {{ total_pages }}</span>
        <a href="?{{ _next_qs | urlencode }}"
           class="btn btn-xs btn-ghost {% if page >= total_pages %}btn-disabled{% endif %}"
           {% if page >= total_pages %}aria-disabled="true"{% endif %}>nächste »</a>
      </nav>
    {% elif is_filtered %}
      <p class="opacity-60 text-sm italic mt-4">Kein Treffer für diesen Filter.</p>
    {% endif %}
    ```
  - **Empty-State-Block (wenn nicht `is_filtered`):**
    ```jinja
    <div class="card bg-base-200/40 border border-base-300">
      <div class="card-body items-center text-center py-12">
        <p class="text-base">Filter setzen oder suchen — die Tabelle bleibt sonst leer.</p>
        <p class="text-sm opacity-65">
          Insgesamt <span class="font-mono font-semibold">{{ total_findings }}</span> Findings über
          <span class="font-mono font-semibold">{{ visible_servers }}</span> Server.
        </p>
      </div>
    </div>
    ```
- Ein `merge_dict`-Jinja-Filter wird im Projekt entweder schon registriert oder ist im Block-Q-Scope neu (Hilfsfilter `app/template_filters.py`).

**DoD:**
- `/findings` Default-Render: Empty-State sichtbar, keine Tabelle, kein Pager.
- `/findings?q=foo` Render: Tabelle plus Pager sichtbar.
- Klick auf „nächste »" navigiert zu `?q=foo&page=2`, Page-Inhalt ändert sich, Filter bleibt.
- `<form method="get">`-Submit ändert die URL und führt zum Re-Render.
- Snapshot-Test: HTML enthält keinen `hx-trigger`-Attribut im Filter-Form (Auto-Submit ist out).

#### Task E.5 — Dashboard-Findings-Section ausbauen (`frontend-implementer`)

- `app/templates/dashboard/_findings_section.html` löschen (Inhalt zieht nach `findings/index.html` um, wo nötig).
- `app/templates/dashboard/index.html` (oder `_detail_pane.html`): den Findings-Section-Include entfernen. KPI-Cards, Risk-Band-Pills, Severity-Strip bleiben unverändert.
- KPI-Card-Links umbiegen: `link_url="/?kev_only=1"` → `link_url="/findings?kev_only=1"` etc.
- In `app/views/dashboard.py`: `list_findings_cross_server`-Aufruf entfernen, `DashboardFilter`-Import bleibt nur soweit für KPI-Aggregation benötigt (eigentlich nicht — siehe Task F.6). Filter-Bar-Render entfällt.

**DoD:**
- `GET /` zeigt KPI-Cards plus Pills plus Severity-Strip, **keine** Findings-Tabelle, **keine** Filter-Bar, **keinen** CSV-Export-Button.
- Klick auf eine KPI-Card (z.B. `KEV`) navigiert zu `/findings?kev_only=1` und zeigt dort die gefilterte Tabelle.
- Dashboard-Polling-Wrapper aktualisiert nur noch die KPI-/Pill-/Strip-Werte.

#### Task E.6 — CSV-Export auf neuer Findings-Route (`backend-implementer`)

- `export_csv` bleibt auf seinem heutigen URL-Pfad. Der View-Layer übergibt die `DashboardFilter`-Instanz unverändert. Export-Scope ignoriert `page`/`per_page` (alle gefilterten Treffer, kein Offset). Die in ADR-0020 erwähnte Truncation-Logik (200-Limit-Hinweis) entfällt — der Export gibt alle Treffer aus.
- CSV-Link in `findings/index.html` zeigt mit den aktuellen Filter-Query-Params (ohne `page`) auf den Export-Endpoint.

**DoD:**
- `GET /findings/export.csv?q=foo&severity=high` (oder welcher URL-Pfad heute existiert) liefert CSV mit allen Treffern, nicht nur Seite 1.
- `tests/services/test_csv_export.py` grün, `csv_mode`-Tests gelöscht.

### Phase F — Spec-Anpassungen und Aufräumen

#### Task F.1 — ARCHITECTURE.md §7 anpassen (`docs-update`)

- §7 wird in der Server-Detail-Sektion auf den einen verbleibenden Findings-Modus reduziert:
  - Die drei Modi-Bullets (`Liste`, `Gruppiert nach Paket`, `Diff seit letztem Scan`) werden ersetzt durch eine einzelne Beschreibung des List-Modus (Application-Group-Cards plus Pending-Grouping).
  - Verweise auf den Mode-Toggle in der Toolbar entfallen.
- §7 wird in der Dashboard-Sektion gekürzt:
  - Block „Findings-Section" mit Filter-Bar, Tabelle, Bulk-Ack-Toolbar entfällt aus dem Dashboard-Abschnitt.
  - Neue Section-Erwähnung: „**`/findings`** zeigt die Cross-Server-Findings-Tabelle als dedizierte Seite mit Filter-Bar, expliziter Submit-Schaltfläche, klassischer Pagination (50/Seite, `?page=N`) und CSV-Export. Default-State leer; Tabelle erscheint erst nach Filter- oder Sort-Eingabe."
- Sub-Erwähnungen der `active`-Pille (z.B. „Status-Pill-Reihe (active + ggf. stale + ggf. db veraltet)") werden auf „Status-Pill-Reihe (revoked/retired plus auffällige Marker wie stale, db veraltet, agent-/trivy-outdated)" verkürzt.

**DoD:**
- `grep -n "gruppiert\|diff seit letztem Scan\|Mode-Toggle" ARCHITECTURE.md` liefert keine Treffer mehr in §7.
- §7 hat einen neuen Absatz zu `/findings`.

#### Task F.2 — STATE.md erweitern (`docs-update`)

- Neuer Top-Eintrag in `docs/blocks/STATE.md`: „**Block Q geplant — Server-Detail- und Dashboard-Entschlackung, dedizierte Findings-Seite — Spec abgenommen 2026-05-21.**" mit Verweis auf ADR-0025 und diese Block-Datei.
- Sub-Sektion „Was Block Q tut" mit den fünf Punkten aus ADR-0025 §Entscheidung in Kurzform.
- Sub-Sektion „Was Block Q **nicht** tut": triple-`_load_findings()`-Konsolidierung (eigener Folge-Block), Endless-Scroll, Bulk-Ack über Group-Grenzen, alte ADR-Status-Migration.

**DoD:**
- STATE.md hat neuen Block-Q-Header oben.
- v0.9.6-Block bleibt darunter unverändert.

#### Task F.3 — ADR-Index aktualisieren (`docs-update`)

- In `docs/decisions/README.md` Index-Tabelle: neue Zeile für ADR-0025 mit Status `Akzeptiert`. Optional: ADR-0018 und ADR-0020 auf `Teilweise abgelöst durch ADR-0025` setzen (nicht-blockierend, kann auch im Folge-PR).

**DoD:**
- `docs/decisions/README.md` enthält Zeile für ADR-0025.

#### Task F.4 — `FindingsViewFilter.mode` cleanup (`backend-implementer`)

- Mit Task A.2 erledigt. Hier nur als Wartungs-Hinweis: `app/schemas/findings_view_filter.py` hat nach Block Q keine `mode`-Definition mehr. Pydantic-`from_request`-Helper ignoriert `?mode=`-Param still.

**DoD:**
- `grep -n "mode" app/schemas/findings_view_filter.py` zeigt nur Sort/Filter-Logik, keinen Mode-Slot.

#### Task F.5 — Tests „Mode unbekannt" und „URL-Bookmark" (`test-writer`)

- `tests/views/test_server_detail.py::test_legacy_group_mode_url_renders_list` — `GET /servers/1?mode=group` rendert ohne 4xx/5xx den Standard-List-View.
- `tests/views/test_server_detail.py::test_legacy_diff_mode_url_renders_list` — analog für `?mode=diff`.

**DoD:**
- Beide Tests grün.

#### Task F.6 — `DashboardFilter` umbenennen (optional, `backend-implementer`)

- **Optional in diesem Block.** Wenn nicht jetzt, dann als Re-Open-Trigger nachgereicht: `app/schemas/dashboard_filter.py` umbenennen auf `app/schemas/findings_list_filter.py`, Klasse `DashboardFilter` → `FindingsListFilter`. Alle Import-Sites anpassen.
- Wenn in diesem Block ausgeführt: kein Re-Export-Stub, kein Backward-Compat-Alias — Block Q ist eine geschlossene Umbau-Einheit.

**DoD (wenn ausgeführt):**
- `grep -rn "DashboardFilter" app/ tests/` liefert keine Treffer.
- `grep -rn "FindingsListFilter" app/ tests/` liefert die erwarteten Stellen.

### Phase G — Verifikation, Smoketests, Performance-Bench

#### Task G.1 — Manual-Smoketest-Liste (`reviewer`)

Verifikations-Checkliste vor Block-Q-Abschluss:

- `GET /` zeigt KPI-Cards, **keine** Findings-Tabelle.
- KPI-Card-Klick führt auf `/findings?<filter>`.
- `GET /findings` (ohne Param) zeigt Empty-State, kein DB-Query auf `finding`-Tabelle außer dem `total_findings`-Counter (verifizierbar via `SQLALCHEMY_ECHO`).
- `GET /findings?q=foo` rendert Tabelle plus Pager.
- Pager-Navigation (`«`/`»`) funktioniert, URL ändert sich.
- CSV-Export liefert alle Treffer, nicht nur die aktuelle Seite.
- `GET /servers/<id>` rendert mit 10+ Application-Groups: kein einziger `<table>`-Tag im Application-Group-Card-Drill-down-`<details>` ist im Initial-HTML enthalten (alle leer/Spinner).
- Auf-Klick einer Group-Card lädt Findings via HTMX, sichtbar in DevTools-Network.
- Zuklappen/Aufklappen löst keinen Re-Fetch aus.
- Pending-Grouping-Sektion rendert Counts-Only, Findings-Lazy.
- `GET /servers/<id>?mode=group` rendert ohne Error den List-View.
- Header eines aktiven Servers ohne Auffälligkeit hat **keine** `active`-Badge mehr; bei Stale hat er den Stale-Marker.
- Findings-Page-Submit ändert URL erst nach Klick auf „Anwenden".

**DoD:** Alle Checkboxen grün, Reviewer bestätigt schriftlich im PR.

#### Task G.2 — Performance-Mini-Bench (`reviewer`)

Vergleich `/servers/<id>` vor und nach Block Q gegen denselben Server (k3s-Fixture mit 400+ Findings in einer Group plus 250+ Pending-Findings):

- DB-Query-Anzahl im Initial-Render (Vorher: Anzahl Group-Findings-Queries + Pending-Findings-Load; Nachher: 3 Aggregate plus Group-Metadaten plus Worst-Finding-Batch).
- Wallclock-Zeit `/servers/<id>` Initial-Render (Hand-Stopuhr oder `flask-debugtoolbar`-Messung) — Erwartung: spürbar schneller, exakter Faktor abhängig von Datenmenge.

**DoD:** Mess-Werte in der finalen STATE.md-Update-Zeile von Block Q dokumentiert.

#### Task G.3 — CI-Gates (`reviewer`)

- `ruff check . && ruff format --check .` PASS.
- `mypy app/` PASS.
- `pytest -v` PASS, Anzahl Tests nach Cleanup niedriger als vorher (Delta erwartet -10 bis -25 wegen gelöschter Mode-Tests).
- `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` PASS — Block Q hat keine Migration, der Roundtrip muss trotzdem grün bleiben.
- `docker compose up -d --build && curl -fsSL http://localhost:8000/healthz` → 200.

**DoD:** Alle Gates grün, Reviewer-Approve im PR.

## Out of Scope für Block Q

- *Triple-Aggregations-Konsolidierung im Server-Detail-Header*: `compute_tendency` + `severity_snapshots_for_server` + `daily_severity_counts_for_server` werden in Block R behandelt. Separater Re-Open-Trigger in ADR-0025.
- *Endless-Scroll auf der Findings-Seite*: page-based gewinnt. Re-Open-Trigger falls Operator-Feedback das fordert.
- *Bulk-Ack über Application-Group-Grenzen*: Bulk-Selection bleibt auf expandierte Cards beschränkt.
- *ADR-0018/0020-Status-Migration auf `Superseded by ADR-0025`*: optionaler Doku-PR nach Block Q.
- *Filter-Reset-Button*: nicht angefragt, nicht im Scope.
- *Mobile-responsive Findings-Tabelle*: out-of-scope per ADR-0009.

## Definition of Done — Block Q gesamt

- Alle Tasks A.1 bis G.3 mit DoD-Bullets geprüft.
- Reviewer-Approve im PR.
- STATE.md hat einen Block-Q-Abschluss-Eintrag analog zu v0.9.6 mit Test-Anzahl-Delta, Coverage-Wert, CI-Gate-Status und Operator-Impact-Notiz.
- ADR-0025 ist im README-Index gelistet.
- Branch `feat/block-q-slim-down` ist gemergt; Tag `v0.10.0` zu setzen.
