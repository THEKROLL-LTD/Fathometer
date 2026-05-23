# Block W — Redesign Phase 1 (Login + Dashboard + App-Shell)

**Spec-Quelle:** [ADR-0032](../decisions/0032-frontend-build-plain-css.md), [ADR-0033](../decisions/0033-brand-identity-fathometer.md), [ADR-0034](../decisions/0034-host-group-data-model.md), [ADR-0035](../decisions/0035-daily-risk-state-heartbeat-mapping.md), [ADR-0036](../decisions/0036-single-pane-polling-hx-preserve.md)
**Branch:** `feat/block-w-redesign-phase-1`
**Zielversion:** v0.12.0
**Vorgänger:** Block V (v0.11.0, ADR-0030 Sidebar-Lazy-Load)
**Status:** Implementiert (Addendum 2026-05-23 — Tailwind/DaisyUI komplett raus, Legacy-Shim)

## Addendum 2026-05-23 — Tailwind/DaisyUI komplett entfernt

Browser-Verifikation am Dual-Stack-Modell (Phase 1) zeigte zwei Klassen
von Cascade-Konflikten, die sich praktisch nicht ohne `!important`-
Salat oder Specificity-Boost-Wars beheben lassen: (1) DaisyUI definiert
eigene Klassen mit Namen wie `.footer`, `.stats`, `.stat`, `.toast`,
`.alert` — kollidieren mit gleichnamigen Plain-CSS-Komponenten; (2)
Tailwind-`forms`-Plugin styled `[type='text']`/`[type='password']` mit
weißem Background + blauem Focus-Border, gewinnt bei gleicher Specificity
durch Source-Order.

Statt mit Cascade-Hacks weiterzumachen wurde **ADR-0032 Phase 2
vorgezogen**: Tailwind-CDN + DaisyUI-CDN + Alpine-CDN + HTMX-CDN sind
komplett aus `base.html` und `base_app.html` entfernt. `window.tailwind.
config`-Safelist-Inline-Script weg. Alpine + HTMX kommen jetzt
ausschließlich aus `vendor.js`.

Für die noch nicht redesigneten Templates (Settings, Server-Detail,
Findings, Audit, Setup-Wizard, Chat, Dashboard-`_card.html`,
`_partials/*`, `_empty/*`) wurde `frontend/src/css/components/legacy-
shim.css` eingeführt — eine Minimal-CSS-Schicht die ~150 der häufigsten
Tailwind-/DaisyUI-Klassen mit „benutzbar, nicht hübsch"-Defaults belegt
(siehe ADR-0032 Addendum für Details). Wenn ein zukünftiger Block
eine Surface redesigned, wandert das spezifische Styling in
`frontend/src/css/components/<surface>.css` und die Templates wechseln
auf BEM-Plain-CSS. Der Shim schrumpft schrittweise.

**Files entfernt/aktualisiert für das Addendum:**

- `app/templates/base_app.html` — alle CDN-Tags + Safelist-Inline-Script raus
- `app/templates/base.html` — analog
- `frontend/src/css/components/legacy-shim.css` — neu, ~450 Zeilen
- `frontend/src/css/app.css` — Shim als letzter `@import`
- `tests/templates/test_tailwind_safelist.py` — als `pytest.skip` deprecated markiert
- `tests/views/test_script_load_order.py` — `ALPINE_MARKER` von CDN-URL auf `js/vendor.js`-Bundle-Namen umgestellt

**Bundle-Größe:** App-CSS 26 KB → 41 KB un-gzipped (+15 KB für Shim,
~5 KB gzipped). Bleibt deutlich unter dem alten Dual-Stack-Total
(Tailwind ~50 KB + DaisyUI ~200 KB).

**Verification nach Addendum:** ruff PASS, ruff format PASS (320 files),
mypy PASS (84 source files), pytest 1511 passed / 208 skipped (DB-
Integration ohne Postgres) / 662 deselected / 0 failures.

**TD-010 ist final erledigt.**

---

## Original-Block-Spec (vor Addendum)

## Ziel

Frontend-Redesign der Login-Page, der App-Shell (Topbar / Sidebar / Footer / Background-Grid) und des Dashboard-Pane gemäß `docs/design/`. Brand-Identity Fathometer eingeführt. Eigene Frontend-Build-Toolchain (plain CSS + esbuild, kein Tailwind/DaisyUI im neuen Design — Tailwind-CDN bleibt Phase 1 für die Legacy-Surfaces). Server-Risk-State als Heartbeat-Mapping (4 visuelle Zustände, 30 Ticks). Viewport-Aware Sidebar-Polling. Sysline als neues Dashboard-Element. Action-Card mit kontinuierlicher Scan-Beam-Animation.

**Konkrete DoD-Ziele:**

- Login-Page rendert das neue Design (1:1 zu `docs/design/Login.html` + `login.jsx`) als Jinja-Template, englische Strings, plain-CSS-Klassen.
- Dashboard-Pane rendert Action-Card + Nominal-Card + Triage-Row + Severity-Strip + Sysline + Eyebrow-mit-LastRefresh, englische Strings, plain-CSS-Klassen, alle Scan-Animationen kontinuierlich (ADR-0036).
- Topbar zeigt Fathometer-Logo (animierter SVG-Sweep) + Wordmark `Fathometer` + Subline `CVE Intelligence` + Nav `Dashboard`/`Findings` + Profile-Dropdown (englisch). Header ersetzt den `s`-Square-Placeholder.
- Sidebar zeigt Gruppen oben (eingeklappt) + Ungrouped flach darunter, Heartbeat-Bar mit 30 Ticks im Risk-State-Mapping, Skeleton-Scan-Probe-Animation, Materialize-Reveal-Wave beim Lazy-Swap, IntersectionObserver-Viewport-Pattern.
- Footer auf allen Routen sichtbar mit dynamischer Version aus `SECSCAN_VERSION`-Env, GitHub-Links.
- esbuild + lightningcss-Build-Pipeline in `frontend/`-Verzeichnis, Multi-Stage-Dockerfile mit Node-Build-Stage, Asset-Manifest, JetBrains-Mono woff2 self-hosted.
- Migration 0014 (`alembic/versions/0014_block_w_server_groups.py`, `down_revision="0013_remove_default_theme"`) für `server_groups`-Tabelle + `servers.group_id`-Spalte.
- Default-`pytest` grün (Pure-Unit-Tests, keine `db_integration` proaktiv).
- `ruff check . && ruff format --check . && mypy app/` PASS.
- `docker compose up -d --build` startet drei Container healthy nach <30 s, `/healthz` 200.

**Nicht-Ziele:**

- Server-Detail-Redesign (eigener Block, vermutlich W+1)
- Settings-/Findings-/Audit-/Setup-Wizard-Redesign (eigene Blocks)
- Host-Group-CRUD-UI (kommt mit Server-Detail-Redesign)
- Add-Host-UI (kommt mit Server-Detail-Redesign)
- Tailwind/DaisyUI komplett rauswerfen (Phase 2 — separater Block der die Legacy-Templates migriert, dann TD-010 final erledigt)
- Repo-Rename `secscan` → `fathometer` (separater ADR notwendig)

## Spec-Referenzen (Pflicht-Lektüre)

1. **ADR-0032 komplett** — Build-Toolchain, Multi-Stage-Dockerfile, Asset-Manifest, Dual-Stack-Übergang.
2. **ADR-0033 komplett** — Brand, Logo, Typography, Color-Doctrine, Easing-Doctrine, Verbotsliste, Sprach-Policy.
3. **ADR-0034 komplett** — Schema-Migration, Sidebar-Verhalten bei null/gemischten Groups.
4. **ADR-0035 komplett** — Heartbeat-Risk-State-Mapping, 30 Ticks, Viewport-Lazy, Cadence-Konsolidierung 60 s.
5. **ADR-0036 komplett** — Dashboard-Polling-Pattern mit hx-preserve + OOB-Swaps.
6. **`docs/design/Dashboard.html` + `app.jsx` + `styles.css` + `design-tokens.css` + `data.js`** — Quelle aller Tokens, Komponenten, Animationen, Interaktions-Patterns. JSX-Komponenten sind Referenz-Implementierung; Jinja+Alpine+vanilla-JS Port behält die Struktur.
7. **`docs/design/Login.html` + `login.jsx`** — Login-Spec.
8. **ADR-0017** (Dashboard-Pane-Single-Partial) — Pane-Render-Pattern bleibt erhalten, Detail-Pane-Datei ist EINE Quelle.
9. **ADR-0019** (Polling statt SSE) — bleibt strukturell, Cadence ändert sich (siehe ADR-0035, ADR-0036).
10. **ADR-0022** (Risk-Band-Modell) — Datenquelle für die neue Heartbeat-Reduce-Logik. `Finding.risk_band` ist die Wahrheits-Spalte.
11. **ADR-0030** (Block V — Sidebar-Lazy-Pattern) — Heartbeats-Projection, escalate_act_counts_by_server, HTMX-Trigger-Pattern. Phase-W-C baut darauf auf.
12. **`app/templates/base.html` + `base_app.html`** — Shell-Templates, hier wird esbuild-Manifest-Helper integriert und die Plain-CSS-Bundle-Tags ergänzt.
13. **`app/templates/layout/_header.html`** — wird durch das neue Topbar-Markup ersetzt (Phase B).
14. **`app/templates/sidebar/*.html`** — Server-Liste/Heartbeat/Search werden refactored, Group-Header-Section ist neu (Phase C).
15. **`app/templates/dashboard/_detail_pane.html` + `_kpi_cards.html` + `_partials/action_required_card.html` + `_partials/risk_band_pill.html`** — werden komplett ersetzt durch die neuen Stat-Cards / Triage / Severity / Sysline (Phasen D + E + F).
16. **`app/templates/login.html`** — Vollständiger Rewrite (Phase G).
17. **`app/services/heartbeat_aggregation.py`** — `DailyStatus`-Erweiterung um `dominant_risk_band`, Projection-Spalte (Phase D).
18. **`app/services/sidebar_risk_counts.py`** (existiert seit Block V) — wird in Phase C um Group-Aggregation ergänzt oder durch neuen Service `sidebar_group_aggregates.py` parallel ergänzt.
19. **`app/views/_sidebar_context.py`** — Group-Sektion-Aufbau, Viewport-Batch-Endpoint (Phase C).
20. **`app/views/dashboard.py`** — KPI-Endpoint umstellen auf OOB-Response-Pattern (Phase F).
21. **`app/views/dashboard_partials.py`** (neu) — `/_partials/dashboard/kpis`-Endpoint (Phase F).
22. **CLAUDE.md §"Test-Konvention — Default vs. On-Demand"** — strikt einhalten. Block W macht eine Schema-Migration (0014) — Alembic-Roundtrip-Test ist `db_integration` und läuft NUR auf User-Anweisung, nicht proaktiv im Default-Lauf.
23. **CLAUDE.md §"pytest-Aufruf — Pflicht-Timeout"** — jeder pytest-Aufruf mit `timeout: 120000` ms (Default) bzw. `60000` ms (fokussierter Sub-Lauf).

## Modell-Änderungen

**Migration 0014** (`alembic/versions/0014_block_w_server_groups.py`):

- Tabelle `server_groups` (id PK, name UNIQUE+CHECK, position INT, created_at TIMESTAMPTZ)
- Spalte `servers.group_id` (nullable, FK → `server_groups.id` ON DELETE SET NULL)
- Index `ix_servers_group_id`

Siehe ADR-0034 §"Migration 0014" für das vollständige Skript.

**Backwards-compatibility:** Alle existierenden Server bekommen `group_id = NULL` (Default-Verhalten von `ADD COLUMN` ohne `server_default`). Keine Daten-Migration, kein Backfill.

**`Server` Pydantic-Modell + ORM-Modell** in `app/models.py`:
- Neue Relationship `group: Mapped[ServerGroup | None]` (lazy=`selectin` für Sidebar-Context).
- Neue Klasse `ServerGroup(Base)` mit Mapped-Attributen entsprechend Migration.

## Phasen

### Phase A — Frontend-Build-Toolchain + Design-Tokens

**Dateien:**
- `frontend/package.json` neu: dependencies `esbuild@~0.21`, `lightningcss@~1.27`, `lightningcss-cli@~1.27`. Scripts `build`, `watch`. Engines `node>=20`.
- `frontend/package-lock.json` neu (committed nach `npm install`).
- `frontend/esbuild.config.mjs` neu: baut CSS via lightningcss (Input: `frontend/src/css/app.css`, Output: `app/static/dist/css/app.{hash}.css`) und JS via esbuild (Inputs: `frontend/src/js/vendor.js` + `frontend/src/js/app.js`, Outputs gehashed). Manifest-Generation als JSON.
- `frontend/src/css/tokens.css` neu: 1:1 aus `docs/design/design-tokens.css` (mit `@font-face`-Pfaden auf `../fonts/JetBrainsMono-*.woff2` umgeschrieben).
- `frontend/src/css/app.css` neu: importiert `tokens.css`, definiert die globalen Reset-Rules, `.bg-grid`, `.app`-Grid-Layout. Spätere Phasen ergänzen Komponenten-Stylesheets.
- `frontend/src/fonts/JetBrainsMono-{Light,Regular,Bold}.woff2` neu: kopiert aus `docs/design/fonts/`.
- `frontend/src/js/vendor.js` neu: `import 'alpinejs'; import 'htmx.org';` (esbuild bundled die als IIFE die `window.Alpine` und `window.htmx` setzt).
- `Dockerfile` (existierend): neue Multi-Stage-Definition. Stage 1 `node:20-alpine` für Frontend-Build, Stage 2 Python-Slim. `COPY --from=frontend-build /repo/app/static/dist app/static/dist`.
- `app/__init__.py`: neuer Context-Processor `_asset_url(filename)` der das `manifest.json` einmalig beim App-Start lädt und das gehashed-Filename returned. Helper als Jinja-Global registrieren (`app.jinja_env.globals["asset_url"] = _asset_url`).
- `app/templates/base.html` + `base_app.html`: zusätzliche `<link rel="stylesheet" href="{{ asset_url('css/app.css') }}">` + `<script defer src="{{ asset_url('js/vendor.js') }}">` + `<script defer src="{{ asset_url('js/app.js') }}">`. **Tailwind-/DaisyUI-CDN-Tags bleiben** (Dual-Stack Phase 1).
- `.dockerignore`: `frontend/node_modules/` ausschließen.
- `.gitignore`: `frontend/node_modules/` und `app/static/dist/` ausschließen.

**Tests:**
- `tests/test_asset_manifest.py` (Pure-Unit): testet `_asset_url` mit Mock-Manifest-Dict (`{"css/app.css": "css/app.abc123.css"}`), Error-Pfad bei fehlendem Key, Error-Pfad bei fehlendem Manifest-File.
- Template-Smoke-Test (Pure-Unit): `base.html` + `base_app.html` rendern enthält `<link>` mit dem geseedeten Hash-Filename.
- **Kein** Build-Pipeline-Test (Toolchain ist deterministisch — CI bricht den Docker-Build wenn npm/esbuild fehlschlägt).

**DoD-A:**
1. `docker compose build` läuft durch, kein Node in Stage 2.
2. Image-Größe: < +500 KB gegenüber heute (esbuild-Bundle + Fonts).
3. `app/static/dist/manifest.json` existiert nach Build und enthält Mappings für `css/app.css`, `js/vendor.js`, `js/app.js`.
4. `ruff check . && ruff format --check . && mypy app/` PASS.
5. Default-`pytest` PASS, mind. 4 neue Tests grün (Asset-Manifest + Template-Smoke).

### Phase B — Layout-Shell (Topbar + Footer + Background-Grid)

**Dateien:**
- `frontend/src/css/components/topbar.css` neu: Topbar-Layout, Logo-Animationen (`fathom-sweep`, `op-pulse`), Wordmark-Stack, Nav-Items, Profile-Dropdown.
- `frontend/src/css/components/footer.css` neu: Footer-Bar, Link-Hover, Tagline.
- `frontend/src/css/components/profile-menu.css` neu: Dropdown-Animation (`profile-menu-in`), Menu-Item-Hover-Pattern, Danger-Item-Override.
- `frontend/src/css/app.css`: `@import` der drei neuen Komponenten-Dateien.
- `app/templates/_macros.html` (existierend) erweitern: neuer Macro `{% macro fathometer_logo(class="topbar__logo") %}` mit dem SVG-Markup aus `docs/design/app.jsx::FathometerLogo` portiert.
- `app/templates/layout/_header.html`: **kompletter Rewrite**. Markup gemäß `docs/design/app.jsx::TopBar` (englische Strings, Fathometer-Logo-Macro, Wordmark, Nav `Dashboard`/`Findings`, Profile-Dropdown).
- `app/templates/layout/_profile_dropdown.html`: **kompletter Rewrite**. Englische Strings (`Logged in as`, `Settings`, `Audit`, `Logout`), `>` Prompt vor dem `Logged in as`-Label, Icon-SVGs (Cog/Document/Logout) inline.
- Neuer Footer-Partial `app/templates/layout/_footer.html`: Markup gemäß `docs/design/app.jsx::App()`-Footer-Section. Version-Link nutzt `{{ secscan_version }}` aus Context-Processor.
- `app/__init__.py`: neuer Context-Processor `_inject_version()` liest `os.environ.get("SECSCAN_VERSION", "dev")` und stellt `secscan_version` als Template-Global zur Verfügung. **Sicherheits-Check:** der Wert muss durch eine Regex `^[A-Za-z0-9._-]+$` validiert werden bevor er ins Template kommt — Default `"dev"` bei Invaliden Werten (verhindert XSS via Env-Var-Injection).
- `app/templates/base.html` + `base_app.html`: `_header.html`-Include unverändert (jetzt das neue Markup), `_footer.html`-Include vor `</body>` einbauen, `<div class="bg-grid">` direkt nach `<body>` einsetzen.

**Tests:**
- Pure-Unit Template-Smoke: `tests/templates/test_topbar_render.py` prüft Topbar-Markup (Fathometer-Wordmark, CVE-Intelligence-Subline, Nav-Items, Profile-Avatar).
- Pure-Unit Template-Smoke: `tests/templates/test_footer_render.py` prüft Footer-Links (Releases-URL mit korrekter Version, GitHub-URL, Tagline).
- Pure-Unit Template-Smoke: `tests/templates/test_bg_grid_present.py` prüft dass `<div class="bg-grid">` im Body steht.
- Pure-Unit: `tests/test_secscan_version_context.py` testet `_inject_version` mit valider Version (`"v0.12.0"`), invalider Version (`"$(rm -rf /)"`), fehlendem Env-Var (Default `"dev"`).
- Pure-Unit: `tests/templates/test_fathometer_logo_macro.py` prüft SVG-Markup-Korrektheit (alle Pfade vorhanden, `aria-label="Fathometer"`).

**DoD-B:**
1. Topbar zeigt im Browser-Smoke-Check (manuelle Verifikation durch Operator) das animierte Logo, Wordmark, Subline, Nav, Profile-Avatar.
2. Footer zeigt v{VERSION} Link, docs Link, github Icon-Link, Tagline rechts.
3. `<div class="bg-grid">` im Markup auf allen App-Routen + Login.
4. Profile-Dropdown auf Klick: zeigt "Logged in as <username>", Settings, Audit, Logout (Englisch).
5. `grep -rn "secscan</a>" app/templates/` liefert **nichts** (alter Wordmark weg).
6. `grep -rn "FATHOMETER" app/templates/` liefert **nichts** (ALLCAPS-Variante verworfen, Markup ist Mixed Case).
7. Default-`pytest` PASS, mind. 5 neue Tests grün.

### Phase C — Sidebar (Group-Sections + Viewport-Lazy + Schema-Migration 0014)

**Hinweis:** Migration-Nummer ist **0014** weil 0013 bereits durch `0013_remove_default_theme` (ADR-0031, Theme-Switcher-Removal) belegt ist. `down_revision="0013_remove_default_theme"`.

**Dateien:**
- `alembic/versions/0014_block_w_server_groups.py` neu (siehe ADR-0034 §Migration). `revision="0014_block_w_server_groups"`, `down_revision="0013_remove_default_theme"`.
- `app/models.py`: neue `ServerGroup`-Klasse, `Server.group_id`-Spalte, Relationship `Server.group: Mapped[ServerGroup | None]`.
- `app/services/sidebar_group_aggregates.py` neu: `group_counts(session)` GROUP-BY-Aggregation (siehe ADR-0034 §Aggregat-Counts).
- `app/services/heartbeat_aggregation.py`: `DailyStatus` bekommt Feld `dominant_risk_band: RiskBand | None`. `_FindingRow` bekommt Feld `risk_band: RiskBand | None`. Projection-Query in `heartbeats_for_servers` ergänzt um `Finding.risk_band`. Reduce-Loop in `_aggregate_one_server` parallel zur Severity-Reduktion. `heartbeats_for_servers` Default `days=30` (siehe ADR-0035).
- `app/views/_sidebar_context.py::build_sidebar_context`: zusätzlich `sidebar_groups: list[ServerGroup]` laden (eine `select(ServerGroup).order_by(ServerGroup.position, ServerGroup.name)`-Query). `server_group_aggregates` aus dem neuen Service für die Header-Counts. Pro Server wird `group_id` mitgegeben.
- `app/views/sidebar_partials.py` (existierend) erweitern: Endpoint-Response unterstützt Group-Sektion-Render. Plus neuer Endpoint `@sidebar_partials_bp.post("/sidebar/batch")` (siehe ADR-0035 §Endpoint-Sketch).
- `frontend/src/css/components/sidebar.css` neu: Sidebar-Layout, Filter-Input, Meta-Header, Col-Header, Group-Header (`hostgroup`), Host-Row (`host`), Heartbeat-Bar + Skeleton (`host__beat`, `host__beat__probe`, `skel-scan`, `skel-materialize`), Stat-Skeleton (`stat-skel`).
- `app/templates/sidebar/_search.html`: kompletter Rewrite, englisch (`filter hosts ( / )`), plain-CSS-Klassen.
- `app/templates/sidebar/_server_list.html`: kompletter Rewrite. Wenn `sidebar_groups` leer: flache Host-Liste. Sonst: zwei Sektionen — Groups oben (jeder Group via `_group_section.html`-Partial), Ungrouped flach darunter.
- `app/templates/sidebar/_group_section.html` neu: chevron + Group-Name + Host-Count + escalate/act-Aggregate. Default `<details>` ohne `open`-Attribut (= collapsed). Hosts darin via `_server_row.html`.
- `app/templates/sidebar/_server_row.html`: kompletter Rewrite. Host-Dot (cyan wenn alarm, grau sonst), Host-Name (mono), OS-Details-Subline (`os · kernel · arch`), Heartbeat-Bar (30 Ticks), escalate/act-Counts. Skeleton-Markup wenn `cells is none` / `risk is None`.
- `app/templates/sidebar/_heartbeat_bar.html`: kompletter Rewrite. Mapping nach `dominant_risk_band` (siehe ADR-0035 §Frontend-Mapping). 30 Cells. Skeleton-Path mit `host__beat__probe`-Scan-Animation.
- `frontend/src/js/sidebar_viewport.js` neu: IntersectionObserver (`rootMargin: "200px"`), `visibleServerIds`-Set, Debounced-Scroll-Trigger für neue sichtbare IDs, 60-s-Polling-Tick POSTet die Liste an `/_partials/sidebar/batch`.
- `frontend/src/js/sidebar_loading_wave.js` neu: lauscht auf `htmx:afterSwap` für `#server-list`-Target, iteriert Host-Rows, setzt pro Row `transitionDelay: i*18ms + 80–320ms jitter` + 220 ms Base. Implementiert das Stagger-Reveal-Pattern aus `useFleetLoading`.
- `frontend/src/js/app.js`: importiert `sidebar_viewport.js`, `sidebar_loading_wave.js`, `dashboard_scan_sync.js` (Phase E), plus existierende `sidebar.js`, `bulk_ack.js`, `stale.js`, `sse_highlight.js`, `llm_settings.js`. esbuild bundled das alles in `app.{hash}.js`.

**Tests:**
- Pure-Unit: `tests/services/test_heartbeat_aggregation.py` erweitern: Tests für `dominant_risk_band`-Reduce mit verschiedenen Risk-Band-Kombinationen + Null-Handling.
- Pure-Unit: `tests/services/test_sidebar_group_aggregates.py` neu: GROUP-BY-Aggregation mit Fake-Session.
- Pure-Unit: `tests/views/test_sidebar_context.py` erweitern: Group-Sektion-Aufbau, leere Groups → flache Liste, gemischte Groups → Groups oben + Ungrouped unten.
- Pure-Unit: `tests/views/test_sidebar_batch.py` neu: Batch-Endpoint, Whitelist-Logic, 400 bei invaliden Bodies, 400 bei >200 IDs, korrekte OOB-Marker im Response.
- Pure-Unit: `tests/templates/test_sidebar_group_render.py` neu: Reihenfolge "Groups oben, Ungrouped unten", chevron-collapsed-Default, Auto-Expand bei Filter (Test-Inputs simulieren Filter-State).
- Pure-Unit: `tests/templates/test_heartbeat_30_ticks.py` neu: gerendetes Markup hat genau 30 `<span>`-Cells.
- **Kein** `db_integration`-Test pflichtig — Aggregations-Logik ist Pure-Funktion, Migration läuft im manuellen Smoke (User-Anweisung für Alembic-Roundtrip).

**DoD-C:**
1. `alembic upgrade head` läuft (manueller User-Smoke, kein proaktiver Test-Run).
2. `app/services/heartbeat_aggregation.py::DailyStatus` hat das Feld `dominant_risk_band` (grep).
3. Sidebar-Template rendert bei leerer `server_groups`-Tabelle eine flache Liste; bei mind. 1 Group eine Group-Sektion oben.
4. `POST /_partials/sidebar/batch` ist als Route registriert (Flask-URL-Map-Inspect oder Pure-Unit-Test).
5. `frontend/src/js/sidebar_viewport.js` registriert IntersectionObserver mit `rootMargin: "200px"` (grep).
6. Heartbeat-Bar-Markup zeigt genau 30 Cells.
7. Default-`pytest` PASS, mind. 12 neue Tests grün.
8. `mypy app/` PASS (neues Model + neuer Service + erweitertes Aggregat).

### Phase D — Dashboard: Action-Card + Nominal-Card + Stat-Animationen

**Dateien:**
- `frontend/src/css/components/stat-card.css` neu: `.stat`, `.stat--alarm` (Scan-Beam-Pseudo-Elemente `::before`/`::after`, Scan-Animations `stat-scan`/`stat-scanlines`/`scan-flash`), `.stat--safe`, `.stat__label`, `.stat__num`, `.stat__sub`, `.stat__cta`. 1:1 aus `docs/design/styles.css`.
- `frontend/src/js/dashboard_scan_sync.js` neu: Vanilla-JS-Port von `useScanFlashSync`. Exportiert `function syncScanFlash(rootElement)` der per `getBoundingClientRect()` jedem `.scan-flash` ein `animation-delay` setzt. Setup-Hook: ein `htmx:oobAfterSwap`-Listener (debounced 50 ms) re-applied auf `#action-needed-card`-Container.
- `app/templates/dashboard/_action_needed_card.html` neu: Markup gemäß `docs/design/app.jsx::ActionNeededCard`. ScanChars-Splitting per Jinja-Macro (`{% macro scan_chars(text) %}` in `_macros.html`).
- `app/templates/dashboard/_nominal_card.html` neu: Markup gemäß `docs/design/app.jsx::App()` `stat--safe`-Block. Englisch (`[nominal]`, `/ N hosts`, `N monitor · N noise · N unknown`).
- `app/templates/dashboard/_detail_pane.html`: bereinigt. Entfernt: `dashboard/_kpi_cards.html`, `_partials/action_required_card.html`, `_partials/risk_band_pill.html` (Tier-1+2+3-Cards aus Block O). Neu: Eyebrow mit `id="dashboard-eyebrow"` + `id="dashboard-last-refresh"`-Span, `<section class="stats">` mit beiden Cards.
- `app/templates/dashboard/_kpi_cards.html`: **gelöscht** (durch Action+Nominal-Cards ersetzt).
- `app/templates/_partials/action_required_card.html`: **gelöscht**.
- `app/templates/_partials/risk_band_pill.html`: **gelöscht** (Risk-Bands wandern in die Triage-Row, Phase E).
- `app/views/dashboard.py::_build_pane_context`: Context-Keys angepasst (`action_needed_card_data`, `nominal_card_data` als Tuples mit `{server_count, escalate, act, pending, hosts_total}` bzw. `{monitor, noise, unknown, hosts_total}`).

**Tests:**
- Pure-Unit: `tests/templates/test_action_needed_card_render.py` prüft ScanChars-Splitting (jeder Char ist eigener `<span class="scan-flash">`), Brackets-Wrapping, CTA-Text, Sub-Counter-Format.
- Pure-Unit: `tests/templates/test_nominal_card_render.py` prüft englische Strings, Sub-Counter-Format.
- Pure-Unit: `tests/templates/test_dashboard_legacy_partials_gone.py`: `grep` auf gelöschte Templates → liefert nichts. Plus: keine Import-Site mehr in Views/Templates.
- Pure-Unit: `tests/views/test_dashboard_context.py` aktualisieren: neue Context-Keys, alte sind weg.

**DoD-D:**
1. `grep -rn "action_required_card\|risk_band_pill\|_kpi_cards" app/templates/` liefert **nichts**.
2. Action-Card-Markup im Render enthält pro Char der Zahl einen `<span class="scan-flash">`-Span.
3. Nominal-Card zeigt `[nominal]`, `/ N hosts`, englischen Sub-Counter.
4. `frontend/src/js/dashboard_scan_sync.js` lauscht auf `htmx:oobAfterSwap` (grep).
5. Default-`pytest` PASS, mind. 4 neue Tests grün.

### Phase E — Dashboard: Triage-Row + Severity-Strip

**Dateien:**
- `frontend/src/css/components/triage.css` neu: `.triage`-Grid (7 Spalten), Cell-Borders, Hover-State, escalate/act-Cell-Accent-Label.
- `frontend/src/css/components/severity.css` neu: `.severity`-Flex, Item-Layout, max-normalized Bar mit cyan-Fill für critical.
- `app/templates/dashboard/_triage_row.html` neu: Markup gemäß `docs/design/app.jsx::TriageRow`. 7 Buckets: `escalate · act · mitigate · pending · monitor · noise · unknown`. Klick führt auf `/findings?risk_band=<bucket>`.
- `app/templates/dashboard/_severity_strip.html` neu: Markup gemäß `SeverityStrip`. 4 Items: `critical · high · medium · low`. Bars max-normalized client-seitig (style-Attribute mit `width: {percent}%`).
- `app/templates/dashboard/_detail_pane.html`: Triage-Row und Severity-Strip einbinden mit IDs `triage-row` und `severity-strip` für OOB-Swap-Targets.
- `app/views/dashboard.py::_build_pane_context`: neue Context-Keys `triage_counts` (dict mit 7 Buckets) und `severity_counts` (dict mit 4 Severities, plus `max_count` für Bar-Normalization).
- `app/services/dashboard_kpis.py` neu: kapselt `_load_triage_counts(session)` (GROUP-BY auf `Finding.risk_band` über OPEN-Findings) und `_load_severity_counts(session)` (GROUP-BY auf `Finding.severity` über OPEN-Findings, plus `max` für Bar-Normalization). Beide als Pure-Unit-testbare Funktionen.

**Tests:**
- Pure-Unit: `tests/services/test_dashboard_kpis.py`: `_load_triage_counts` und `_load_severity_counts` mit Fake-Session-Tuple-Returns.
- Pure-Unit: `tests/templates/test_triage_row_render.py`: 7 Buckets in korrekter Reihenfolge, escalate+act tragen `triage__cell--accent`-Klasse wenn count > 0, jeder Cell mit `data-test="triage-cell-<bucket>"`.
- Pure-Unit: `tests/templates/test_severity_strip_render.py`: 4 Severities, Bar-Width-Style mit korrekter Prozentzahl, critical bekommt `severity__item--crit`.

**DoD-E:**
1. Triage-Row-Markup hat 7 Cells in der Design-Reihenfolge.
2. Severity-Strip-Markup hat 4 Items mit max-normalisierten Bars.
3. Klick auf eine Triage-Cell linkt auf `/findings?risk_band=<bucket>` (href-Check).
4. `mypy app/` PASS.
5. Default-`pytest` PASS, mind. 5 neue Tests grün.

### Phase F — Sysline + OOB-Polling-Endpoint (`/_partials/dashboard/kpis`)

**Dateien:**
- `frontend/src/css/components/sysline.css` neu: terminal-Style Line, accent-`>`-Prompt, Pipe-Separator.
- `app/templates/dashboard/_sysline.html` neu: Markup gemäß `docs/design/app.jsx::App()` Sysline-Section. 4 Felder: `last scan`, `epss-feed`, `kev-feed`, `worker`.
- `app/services/sysline_context.py` neu: `build_sysline_context(session) -> SyslineContext`-Funktion. Liefert dict:
  ```python
  {
      "last_scan_ago": "3m" | "Nh" | "Nd" | None,    # max(Server.last_scan_at)
      "epss_feed_status": "synced" | "stale" | "never",   # FeedPullLog last success für 'epss'
      "kev_feed_status": "synced" | "stale" | "never",    # analog
      "worker_status": "healthy" | "down" | None,           # Setting.llm_worker_heartbeat_at < 30s; None wenn LLM-Mode == 'off'
  }
  ```
  - "stale" wenn Pull-Zeit >24h
  - "never" wenn kein erfolgreicher Pull existiert
  - Pure-Unit-testbar mit Fake-Session
- `app/views/dashboard_partials.py` neu: Blueprint `dashboard_partials_bp` mit Route `GET /_partials/dashboard/kpis`. Liefert OOB-Response mit Targets `action-needed-num`, `action-needed-hosts-total`, `action-needed-sub`, `nominal-card`, `triage-row`, `severity-strip`, `sysline`, `dashboard-last-refresh`.
- `app/templates/dashboard/_kpis_oob_response.html` neu: OOB-Wrapper-Template (siehe ADR-0036 §Endpoint-Response-Skizze).
- `app/templates/dashboard/_detail_pane.html`: HTMX-Polling-Trigger umstellen:
  ```html
  <div id="dashboard-pane"
       hx-get="/_partials/dashboard/kpis"
       hx-trigger="every 60s [document.visibilityState === 'visible']"
       hx-swap="none">
  ```
  + `<div class="stat stat--alarm" id="action-needed-card" hx-preserve="true">` für Animation-Preservation.
- `frontend/src/js/dashboard_last_refresh.js` neu: `setInterval(30_000)`-Hook der `#dashboard-last-refresh`-Span mit aktueller `HH:MM UTC`-Zeit befüllt.
- `frontend/src/js/app.js`: neuer Import.
- `app/__init__.py`: `dashboard_partials_bp` registrieren.

**Tests:**
- Pure-Unit: `tests/services/test_sysline_context.py`: alle 4 Status-Felder mit verschiedenen DB-States (synced, stale, never, LLM-off → worker=None).
- Pure-Unit: `tests/views/test_dashboard_kpis_partial.py`: Endpoint-Response enthält OOB-Marker für alle 8 Targets, **kein** `action-needed-card`-Wrapper im Response-Markup.
- Pure-Unit: `tests/templates/test_dashboard_pane_structure.py`: Pane hat `hx-preserve="true"` auf `#action-needed-card`, `hx-swap="none"` auf `#dashboard-pane`, korrekte Polling-Cadence 60s.
- Pure-Unit: `tests/templates/test_sysline_render.py`: alle 4 Felder, accent-Prompt am Anfang, Pipe-Separatoren.

**DoD-F:**
1. `GET /_partials/dashboard/kpis` antwortet mit OOB-Fragmenten (Route registriert).
2. Polling-Cadence im Pane-Markup ist `every 60s [document.visibilityState === 'visible']` (grep).
3. Action-Card-Wrapper hat `hx-preserve="true"` (grep).
4. Sysline rendert 4 Status-Felder.
5. `dashboard_last_refresh.js` setzt `setInterval(30_000)` (grep).
6. Default-`pytest` PASS, mind. 6 neue Tests grün.

### Phase G — Login-Page + Final-Polish

**Dateien:**
- `frontend/src/css/components/auth.css` neu: `.app--auth`-Grid (Topbar/Main/Footer ohne Sidebar), `.auth__panel` mit Accent-Left-Bar, `.auth__eyebrow`/`__title`/`__sub`/`__form`/`__field`/`__input`/`__status`/`__submit`. 1:1 aus `docs/design/styles.css`.
- `app/templates/login.html`: **kompletter Rewrite**. Englische Strings:
  - Title `Operator credentials.` (display-font 36 px)
  - Eyebrow `> authenticate`
  - Sub `No signup. No reset. No SSO. Internal operators only.`
  - Field-Labels `username` / `password` (uppercase mono via CSS)
  - Submit `authenticate →`
  - Status-Line zeigt Hint / `[access denied] · {form-errors}` / `> verifying…` (letzteres nur wenn JS-Submit busy → out of scope für Phase 1, akzeptable Degradation: Submit ist sync-form-post wie heute, busy-State entfällt).
  - **Trade-off:** Form ist klassisches `<form method="post">` (kein HTMX, kein JS-busy-State). Verifying-Animation aus dem Design-Mock wird in Phase 1 nicht implementiert. Der Server validiert → Redirect zum Dashboard oder zurück mit Flash-Error. Re-Open-Trigger falls Operator-Feedback es vermisst.
- `app/templates/base.html`: Login extends `base.html`. Header-/Footer-Include nutzt Macros + `_header.html`-Auth-Variante. `_header.html` bekommt eine `auth_mode`-Variante (kein Nav, kein Profile — nur Logo + Wordmark) via Conditional-Block oder eigenes `_header_auth.html`-Partial (Implementer-Wahl).
- `app/templates/setup/*.html`: **nicht angefasst** in Phase 1. Bleibt deutsch + Tailwind/DaisyUI (Dual-Stack).
- `app/templates/_empty/no_servers.html`: minimal anpassen falls die Sidebar leer ist (englisch, plain CSS).
- `app/templates/_empty/no_findings.html` + `_empty/no_audit.html`: bleiben in Phase 1 unangetastet (gehören zu Findings-/Audit-Surfaces, die bleiben deutsch).
- Final-Check: Settings/Server-Detail/Findings/Audit/Setup laden im Dual-Stack korrekt (Tailwind-CDN + DaisyUI-CDN funktional, neue Topbar/Footer/bg-grid darüber).

**Tests:**
- Pure-Unit: `tests/views/test_login_render.py`: englische Strings, `> authenticate`-Eyebrow, `Operator credentials.`-Title, Submit-Button-Label `authenticate`, Form-Field-Labels.
- Pure-Unit: `tests/views/test_auth_error_render.py`: bei `form.errors` rendered die Status-Line `[access denied] · ...`.
- Pure-Unit: `tests/templates/test_settings_legacy_still_renders.py`: Settings-Page rendert noch (Tailwind-Klassen vorhanden, kein Crash).
- Pure-Unit: `tests/templates/test_server_detail_legacy_still_renders.py`: Server-Detail rendert noch.

**DoD-G:**
1. Login-Markup enthält die exakten englischen Strings aus dem Design.
2. Login-Topbar zeigt nur Logo + Wordmark (kein Nav, kein Profile).
3. Settings/Server-Detail/Findings/Audit-Templates rendern weiter (Smoke-Tests).
4. `grep -rn "Anmelden\|Bitte melde dich" app/templates/login.html` liefert **nichts** (Login ist englisch).
5. `grep -rn "Bitte melde dich" app/templates/setup/` liefert **weiterhin etwas** (Setup ist out-of-scope deutsch).
6. Default-`pytest` PASS, mind. 4 neue Tests grün.
7. `docker compose up -d --build` startet drei Container healthy, `/healthz` 200, `GET /login` rendert das neue Login-Markup.

## Phasen-Abhängigkeiten

```
A (Build-Toolchain + Tokens) → keine Abhängigkeit, MUSS zuerst (alle anderen Phasen brauchen das Bundle-System)
B (Topbar + Footer + bg-grid) → braucht A (CSS-Imports + Asset-Manifest)
C (Sidebar + Schema 0014) → braucht A; unabhängig von B aber im selben Branch
D (Action-Card + Nominal-Card) → braucht A, B (Topbar-Layout existiert); unabhängig von C
E (Triage + Severity-Strip) → braucht D (gleicher Pane, Tests bauen auf D-Context auf)
F (Sysline + OOB-Polling) → braucht D + E (alle KPI-Targets müssen existieren bevor OOB-Endpoint sie liefert)
G (Login + Final-Polish) → braucht A, B (Topbar-Auth-Variante)
```

**Empfohlene Implementer-Reihenfolge:** A → B → C → D → E → F → G. C kann parallel zu B/D laufen (anderes File-Set). G ist Final-Check, läuft als letzte Phase.

**Phase-Commit-Strategie:** Jede Phase ist ein eigener Commit auf `feat/block-w-redesign-phase-1`. Reviewer-Approval am Ende jeder Phase. Sicherheits-relevant ist nur Phase C (Migration + neuer POST-Endpoint mit Body-Validation) — Security-Auditor-Subagent läuft dort zusätzlich.

## Risiken & Mitigation

| Risiko | Mitigation |
|---|---|
| **Dual-Stack lädt zu viel Asset-Last** (Tailwind+DaisyUI-CDN + neues plain-CSS-Bundle parallel) | Akzeptable Phase-1-Übergangs-Kosten. ADR-0032 dokumentiert die Auflösung in Phase 2. CSP-Engziehung kommt mit Phase 2. |
| **`hx-preserve`-Pattern unklar implementiert → Action-Card wird trotzdem ersetzt** | Pure-Unit-Test `test_dashboard_kpis_partial.py` prüft explizit dass die Response **kein** `action-needed-card`-Wrapper enthält. Reviewer prüft Pattern bei Phase F. |
| **`useScanFlashSync`-JS funktioniert nicht in allen Browsern** (z.B. Safari mit anderem getBoundingClientRect-Timing) | Akzeptable Degradation: ohne JS flashen alle .scan-flash-Spans synchron statt sequenziell. Funktional OK. Browser-Smoke-Check als Phase-F-DoD-Item. |
| **IntersectionObserver wird auf alten Browsern nicht unterstützt** (sehr selten 2026, aber denkbar) | Polyfill via esbuild-Bundle möglich; alternativ Fallback "lade immer alle Server" wenn `'IntersectionObserver' in window === false`. Implementer-Entscheidung in Phase C. |
| **Migration 0014 schlägt fehl bei großen `servers`-Tabellen** | ADD COLUMN ohne DEFAULT ist O(1) in Postgres ab Version 11+. Pre-Existing `servers`-Indexe sind nicht betroffen. Risiko minimal. |
| **Group-Sektion-Header verschwindet hinter zugeklappten Gruppen** | Verhindert durch User-Entscheidung "Gruppen oben, eingeklappt" + Auto-Expand bei Filter. Headers bleiben sichtbar weil sie 30–40 px hoch sind und die Sidebar oben sticky-search hat. |
| **Sprach-Mix in der Phase-1-UI** (Login englisch, Setup-Wizard deutsch, Settings deutsch) | Akzeptable Übergangs-Hässlichkeit. ADR-0033 Sprach-Policy dokumentiert das. Operator-Feedback beim Phase-G-Smoke-Check. |
| **Brand-Konflikt: `Fathometer` in Topbar/Footer, `secscan` in Browser-Tabs/`<title>`** | Phase B + Phase G updaten `<title>`-Block in `base.html` + `base_app.html` auf `Fathometer · ...`. `secscan` bleibt nur in Repo-Slug + Code-Identifiern (siehe ADR-0033 §Renaming-Scope). |
| **Operator beschwert sich über Animationen** (z.B. „die scan-Flash macht mich nervös") | Phase-G-Smoke-Check inklusive Operator-Walkthrough. Wenn Pushback: Animations-Cycle in CSS-Variable rausziehen (z.B. `--dur-scan: 5.4s`) damit später `prefers-reduced-motion`-Override leicht machbar. |
| **`SECSCAN_VERSION` Env-Var fehlt oder ungültig** | Phase B Context-Processor validiert via Regex, Default `"dev"`. Test deckt invalide Werte ab. |
| **Asset-Hashing-Manifest wird im Image vergessen** | Phase A Dockerfile `COPY --from=frontend-build` zieht `manifest.json` explizit mit. CI-Smoke (Stage-2-Build) kann `manifest.json` existence-checken. |

## Operator-Smoke-Checks (manuell, nach Block-W-Abschluss)

Diese Checks laufen **nicht** im pytest-Default-Lauf — sie sind Operator-Walkthrough-Items für die Pre-Release-Verifikation:

1. **Login-Page-Rendering**: `GET /login` zeigt das neue Markup, Background-Grid sichtbar, Logo animiert (Sweep + Echo-Pulse), Submit-Form englisch.
2. **Dashboard-Initial-Load**: `GET /` zeigt Topbar (Logo + Wordmark + Nav + Profile), Sidebar mit Skeleton-Heartbeats für alle Server, Dashboard-Pane mit Action-Card (Scan-Beam läuft), Nominal-Card, Triage, Severity, Sysline, Footer.
3. **Sidebar-Lazy-Load**: Nach ~1–2 s materialisieren die Heartbeat-Cells via Stagger-Reveal-Wave, escalate/act-Counts erscheinen, alarm-Counter im Header zeigt N.
4. **Sidebar-Scroll**: Bei >20 Servern (oder schmalem Browser-Fenster) zeigt Scroll-Verhalten Skeleton für neu sichtbare Rows, Live-Daten kommen via Batch-Endpoint nach.
5. **Group-Sektion**: Wenn Operator manuell via `psql` eine `server_groups`-Row anlegt und ein paar Server `group_id` setzt, zeigt die Sidebar nach Reload Gruppen oben (eingeklappt) + Ungrouped flach darunter. Klick auf Group-Header expandiert.
6. **Dashboard-Polling**: Nach 60 s feuert der OOB-Endpoint, Werte updaten, Scan-Beam-Animation **bleibt durchgehend** (kein Restart-Flash).
7. **Last-Refresh-Eyebrow**: Aktualisiert sich alle 30 s clientseitig.
8. **Footer-Links**: `v{VERSION}`-Link führt auf Releases-Page (oder zumindest auf gültige GitHub-URL), GitHub-Link funktioniert.
9. **Profile-Dropdown**: Klick auf Avatar zeigt Dropdown mit Materialize-Animation, Englisch (`Logged in as <username>`, Settings, Audit, Logout).
10. **Legacy-Surfaces funktional**: Klick auf "Findings" / "Audit" / "Settings" lädt die alten deutschen Tailwind-/DaisyUI-Templates ohne Layout-Bruch (Dual-Stack-Smoke).
11. **`docker compose up -d --build`** baut Image, drei Container healthy, `/healthz` 200, keine Console-Errors im Browser.
12. **Alembic-Roundtrip** (User-Anweisung, `db_integration`): `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` PASS.
