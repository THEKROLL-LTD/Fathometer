# Orchestrator-State

Single source of truth für den Implementierungs-Fortschritt. Wird von der Hauptsession bei jedem Start gelesen und nach jedem Block-Übergang aktualisiert.

## Status

**TICKET-009 abgeschlossen 2026-06-04 — Server-scoped Bulk-Acknowledge pro Risk-Band (ADR-0044).** Branch `feat/ticket-009-per-band-bulk-ack`, drei Etappen mit je eigenem Commit. **Keine Schema-Migration.** Reviewer APPROVED-ETAPPE-1/-2/-3, Security-Auditor APPROVED (kein ROT/GELB) für Etappe 1 (neue Mass-Ack-Fläche). Default-`pytest` 2229 passed / 201 skipped / 658 deselected, `ruff`/`mypy app/` grün.

- **Etappe 1 — Schema + API (Flavor C).** `BulkAckServerScope {server_id, risk_band}` mit Band-Whitelist (`escalate/act/mitigate/monitor/noise`; `pending`/`unknown` → 422), XOR-Validator auf drei Flavors erweitert. Endpoint resolved server-seitig per `WHERE server_id AND risk_band AND status='open'` (kein `.limit()`, kein ID-Transport); `dry_run` liefert `count` + max. 5 `examples`; Apply per direktem `UPDATE … rowcount`. Audit `finding_ids[:50]` gecappt (immer befüllt), `count` voll, `server_scope` in Metadata. Notes als ein Bulk-Insert (alle Flavors). JSON-404-Guard (revoked/retired/unbekannt). `tests/api/test_bulk_acknowledge.py` neu (war nur als `.pyc` vorhanden). 75 Pure-Unit-/Adversarial-Tests.
- **Etappe 2 — Frontend.** `risk_band_section.html`: Hover-Control pro Band (außer `pending`) im `<summary>`, Modal als Sibling des `<details>`. Generisches `bulk_ack_band_modal.html` (Beispiele aus `dry_run` via `x-for`, max. 5 + „… and N more", Confirm-Pflicht, Kommentar optional). `bulk_ack_band.js` (Alpine, `server_scope`-Payload, CSRF via `X-CSRFToken`). CSS Hover-Reveal (`visibility`, grau→cyan, `focus-within`). 14 neue Template-Tests.
- **Etappe 3 — Cleanup + Doku.** `noise_fragment`-Route+Funktion, `noise_fragment.html`, `_bulk_ack_noise_modal.html`, `bulk_ack_noise.js` (+2 Includes), `sd-noise-toolbar`-Slot und `risk_band_filter`/`skipped_non_noise_ids` (Schema + Endpoint + Response/Audit) entfernt. Noise-Tests gelöscht, Fragment-Tests angepasst. ARCHITECTURE §6/§7a, ADR-0022/0039-Ablöse-Verweise, ADR-0044 im Index, CHANGELOG. **`noise_count` für Band-Counts bleibt.**

**Bewusst weggelassen / Re-Open-Trigger (ADR-0044):** OOB-Count-Refresh nach Apply (Full-Reload bleibt), Batched-UPDATE für 100k-Findings-Server, Bulk-Ack für `pending`/`unknown`. **Operator-Manual-Sanity-Check offen** (Hover-Reveal + cyan-Hover je Band, Modal-Preview-Count == Band-Count, Apply auf Band > 50 Findings ackt alle, `pending` ohne Control) — vom User nach Merge abzuhaken.

**MVP + UI v2 + ADR-0016 bis ADR-0038 + Block-X-Server-Detail-Content-Refactor abgeschlossen — Ziel v0.13.0 (2026-05-24). Block Y (ADR-0039) geplant.**

**Block AA abgeschlossen 2026-05-28 — Finding-Detail Inline (ADR-0041).** Branch `feat/block-aa-finding-detail-inline`, fünf Phasen A→E. Zielversion v0.16.0. **Eine Migration `0016_block_aa_add_primary_url`** (`findings.primary_url VARCHAR(2048) NULL`, idempotent, kein Backfill — Alembic-Roundtrip steht beim User an). Default-`pytest` 2108 passed / 204 skipped / 659 deselected (~24 s), `ruff`/`mypy app/` grün, Frontend-Build grün.

- **Phase A** — `findings.primary_url` persistiert: Migration 0016 + ORM-Spalte + `_build_finding_row`/`ON CONFLICT`-Eintrag `primary_url`. Pydantic-Validator (HttpUrl/http(s)/NUL/Length) bestand bereits. 6 neue Pure-Unit-Tests.
- **Phase B** — Backend-ORM-Hydration: `triage_band_fragment` von 13-Spalten-Projektion (ADR-0039) zurück auf `select(Finding).options(selectinload(Finding.notes))`; `list_bucket_findings` + Group-/Pending-Lazy-Fragmente ergänzen `selectinload(notes)`; alle Listen-Endpoints reichen `note_form`/`csrf_form`/`ack_form`/`reopen_form` durch. ~10 neue Tests.
- **Phase C** — Single-Source-Inline-Body `_partials/finding_inline_body.html` (KI-Reason + Action-Button, Description, Primary-URL, References, Notes + Ack/Reopen-Modal via Alpine `x-data` pro `<details>`). In alle vier Listen-Templates included. Neue token-only BEM-Klassen in `server-detail.css`. Drift- + XSS-Tests Pflicht. ~25 neue/migrierte Template-Tests; Autoescape-Doktrin (kein `|safe`) verifiziert.
- **Phase D** — Flat-Pfad gelöscht: `_view_list.html`, `findings/_detail_modal.html`, `_partials/pending_findings_table.html` entfernt; `_is_flat_mode` + Flat-Branch raus; `_findings_section.html` rendert unkonditional die Group-View; `pending_findings_fragment` rendert jetzt die `<details>`-Variante (`group_findings_table.html`). `grep -r "flat=1" app/` leer. `?flat=1`-Test-Suite migriert (8 `test_is_flat_mode_*` gelöscht, Integration-/Adversarial-Tests auf neue Markup-/Fragment-Realität bzw. DB-Persistenz umgestellt).
- **Phase E** — Aufräumen + Docs: `list_findings` behalten mit „kein App-Konsument mehr"-Docstring-Hinweis; ARCHITECTURE.md §Findings-Ansicht + Ursachen-Felder, CHANGELOG (v0.16.0), ADR-0025-Status (Flat-Switch Superseded by 0041), decisions/README (0041-Zeile) aktualisiert.

**Bewusste Regressionen (User-Entscheidung 2026-05-28, Re-Open-Trigger in ADR-0041):** (1) **URL-Filter** (`status`/`kev_only`/`q`/`class`/…) narrowen die Server-Detail-Ansicht nicht mehr — sie waren ein Flat-only-Feature ohne Filter-Bar-UI; die Lazy-Group-View-Queries sind filter-unaware (Counts-Header bleibt filter-aware). (2) **Ursachen-Sub-Zeile** (`target_path`/`vendor_ids`/`package_purl`) entfällt als UI-Surface (Daten bleiben persistiert).

**Operator-Smokes offen** (13 Punkte aus Block-AA-Spec §Phase E, vom User vor Merge abzuhaken). **Alembic-Roundtrip `pytest -m db_integration -k 0016` + migrierte db_integration-Suiten** stehen ebenfalls beim User an.

**Tag `v0.16.0` zu setzen** (nach Branch-Merge auf main, gemäß [Tag-only-on-main-after-Merge]).

**Block Z abgeschlossen 2026-05-28 — Group + Tag Hybrid-Lifecycle (ADR-0040).** Branch `feat/block-z-group-tag-hybrid`, fünf Phasen A→E, ein Sammel-Commit (forms.py + settings.py spannen mehrere Phasen, daher nicht pro Phase trennbar). Zielversion v0.15.0. **Keine Schema-Migration — Code-only.** Reviewer APPROVED-BLOCK-Z, Security-Auditor APPROVED (Phase A + Phase C/D zweite Welle; ein ROT-Finding aus Phase A — whitespace-only Gruppenname → 500 via NoResultFound — gefixt via `ServerGroupCreateForm.validate_name` + Regression-Test). Default-`pytest` 2047 passed / 205 skipped / 662 deselected (~22 s), keine Regression; ~130 neue Pure-Unit-Tests.

- **Phase A** — Inline-Create-Endpoints: `POST /servers/<id>/settings/group/create` + `/tags/create` in `server_settings.py`. Atomar mit Server-Zuweisung, `position = COALESCE(MAX,-1)+1`, Tag-Default-Color `#6b7280`, Race-Catch (IntegrityError → Re-Fetch). Audit `group.created`/`tag.created` mit `metadata.via="server_settings"` (nur bei echter Anlage) + `server.group_changed`/`server.tag.added`. Forms `ServerGroupCreateForm`/`ServerTagCreateForm` (geteilte `SERVER_GROUP_NAME_REGEX`-Konstante).
- **Phase B** — Server-Settings Combobox-UI: Inline-Eingabefeld + „+ Anlegen" für Tag + Gruppe unter den bestehenden Selects (HTML5 `form="…"`-Sub-Form-Pattern, Hidden-Forms `group-create-form`/`tag-create-form`). Neue CSS-Klasse `.sd-inline-create`. Bestehende Picker unverändert.
- **Phase C** — `/settings/groups` Manage-Only: `groups_list`/`groups_rename`/`groups_delete`/`groups_move` (Up/Down-Swap). Kein Create-Pfad. Member-Count via LEFT-JOIN-Aggregat. Delete = ON-DELETE-SET-NULL (kein Server gelöscht). Forms `GroupRenameForm`/`GroupMoveForm`. Template `settings/groups.html` (sd-* via neuer `settings-manage.css`), Nav-Eintrag „Gruppen". Audit `group.renamed`/`group.deleted`/`group.moved`.
- **Phase D** — `/settings/tags` Refactor: `tags_create` ersatzlos entfernt (POST → 405), neu `tags_rename`/`tags_color`. Template komplett auf sd-* umgeschrieben (kein DaisyUI), kein Anlege-Form, Hint-Block. Forms `TagRenameForm`/`TagColorForm`. Audit `tag.renamed`/`tag.color_changed`. Zwei obsolete adversarial-HTTP-Create-Tests gelöscht (Regex/Form-Pure-Unit-Tests bleiben).
- **Phase E** — Aufräumen: neue Event-Typen in `audit_view.KNOWN_ACTIONS` (filterbar), Sidebar-Empty-Group-Regressions-Test (`group_counts()` liefert keine member-losen Gruppen — Query FROM servers), `docs/operations.md`-Workflow-Absatz.

**Bewusst weggelassen / Re-Open (ADR-0040 §Re-Open):** Drag-Drop-Reorder, Bulk-Server-Move, Group-Filter (`?group=N`), Group-Beschreibung/Icon/Farbe, `Tag.position`, M:N-Multi-Group, Auto-Delete leerer Gruppen. **`legacy-shim.css`-Schrumpfung** weiter aufgeschoben — `.card`/`.btn`/`.input-bordered` aus Tags/Groups raus, aber noch von Findings/Audit/Setup/Chat gebraucht (DoD-D #4 bleibt offen bis zur vollständigen Redesign-Welle). **Operator-Smokes offen** (Browser): Inline-Anlage, Up/Down-Reorder, Color-Picker, Delete-Confirm.

**Tag `v0.15.0` zu setzen** (nach Branch-Merge auf main, gemäß [Tag-only-on-main-after-Merge]).

**Block Y geplant 2026-05-27 — Server-Detail Lazy-Render-Architektur + Triage-Queue-Pagination (ADR-0039).** Branch `feat/block-y-server-detail-lazy-render`, vier Phasen (A: Initial-Render-Reduktion + Projektionen, B: HTMX-Fragment-Endpoints, C: Triage-Queue Collapsed + Lazy + Paginiert, D: Aufräumen + Drift-Tests). Zielversion v0.14.0. Keine Schema-Migration. Löst das Eager-Load-Everything-Pattern in `show()` auf: 17–19 Queries → ~6–8 im Critical Path, Rest parallel via HTMX-Fragmente. `_build_risk_band_sections` + `_assemble_risk_band_sections` werden gelöscht (volle Finding-Hydration weg). Triage-Queue wird paginiert (25/Seite, "Mehr laden"). `_load_application_groups_for_server` wechselt auf SQL-Projektionen statt ORM-Objekte. Query-Deduplizierung (pending_grouping + action_required zusammenlegen). Block V (ADR-0030, Dashboard + Sidebar) bleibt eigenständig geplant.

**Block X abgeschlossen 2026-05-24 — Server-Detail Content-Refactor + Style-Adoption (ADR-0038).** Branch `feat/block-x-server-detail-content`, acht Phasen-Commits A0 → G. Reviewer APPROVED-BLOCK-X mit einem GELB-Item (G6-Shim-Audit), das im Phase-G-Commit-Body dokumentiert ist. Security-Auditor APPROVED (Phase B + Phase G). **+242 neue Pure-Unit-Tests** über den ganzen Block (Baseline 1813 → 2055 passed). Default-Suite `pytest` ~43 s, 2055 passed / 6 skipped / 662 deselected.

**Commits in Reihenfolge:**

| Commit | Inhalt | Δ Tests |
|---|---|---:|
| `9f4e5be` | feat(block-x-phase-a0): css foundation + js helper | +10 |
| `3ac2cf8` | feat(block-x-phase-a): header sysline + dl-meta-grid removal | +7 |
| `d42f4cb` | feat(block-x-phase-b): server settings sub-view (tags + group + scan-interval) | +38 |
| `ec9ca87` | feat(block-x-phase-c): host-snapshot kollabiert zu zwei header-pills | +57 |
| `b3d31a3` | feat(block-x-phase-d): workflow-card-drilldown table + pagination stub | +17 |
| `73503f4` | feat(block-x-phase-e): heartbeat 30/4 + severity-trend ohne 50T + skeletons | +43 |
| `3897209` | feat(block-x-phase-f): risk-band top-level accordion in triage queue | +30 |
| `f858a08` | feat(block-x-phase-g): action-needed pill + inline AI reason + bulk noise + status pills | +40 |

Plus ein Vorab-Commit `ebc3ceb docs(claude): HTMX-OOB single-source pattern (TICKET-005 lessons)` auf main (TICKET-005-Doktrin nachgereicht).

**Was die acht Phasen geliefert haben:**

1. **Phase A0 — CSS-Foundation + JS-Helper (commit `9f4e5be`).** `docs/design/server-detail.css` (1159 Z., Claude-Design-Output) → `frontend/src/css/components/server-detail.css` (1162 Z., 1:1-Port mit Token-Mapping, 0 raw hex außerhalb von Header-Kommentaren). Verbleibende rgba-Transparenzen tragen `TODO(token)`-Marker. `@import` in `app.css` zwischen `auth.css` und `legacy-shim.css`. Neues `frontend/src/js/server_detail.js` (301 Z.) mit drei Exports: `setupScanFlashSync(rootEl)` (ResizeObserver + document.fonts.ready, debounced 50 ms auf htmx:oobAfterSwap, Phase-Reset-Schutz nur bei geänderter Span-Anzahl), `serverPillPanels` Alpine-Component (Single-Open-State für die zwei Header-Pills), `setupServerDetailHeartbeatTip(rootEl)` (Event-Delegation analog `sidebar_heartbeat_tip.js`, textContent-only XSS-Defense). `initServerDetailModule(rootEl)` als Combined-Entry-Point; `app.js` hängt sie an `htmx:afterSettle` + `DOMContentLoaded` mit defensivem `.sd-detail-root`-Selektor.

2. **Phase A — Header-Sysline + dl-meta-grid-Removal (commit `3ac2cf8`).** OS-Zeile auf `os · kernel · arch` reduziert; „letzter scan" raus (war doppelt mit dem alten `<dl>`). Neue `<div class="sd-sysline">` direkt darunter mit drei Segmenten in fester Reihenfolge `> expected interval N h · last scan <relative> · trivy-db <relative>`. Tooltips auf `<time>`-Elementen via `title=` (absolute Zeitstempel ISO + strftime). `<dl class="grid grid-cols-2 md:grid-cols-4">` mit vier Kindern (Erwarteter Intervall, Letzter Scan, Trivy-DB, KEV-Ereignisse · 50T) ersatzlos entfernt. View-Context: `count_kev_events_50d`-Import + Berechnung + Render-Kwarg ersatzlos raus; Service-Funktion mit `.. deprecated::`-Docstring + `warnings.warn(DeprecationWarning)` markiert, bleibt im `__all__`.

3. **Phase B — Settings-Sub-View (commit `d42f4cb`).** Neues Blueprint `server_settings` in `app/views/server_settings.py` mit 5 Routes: `GET /servers/<id>/settings/` (Vollseite + HX-Fragment), `POST /tags/add` (move aus `server_detail.py`), `POST /tags/<tag_id>/remove`, `POST /group` (neu), `POST /scan-interval` (neu). Alle `@login_required` + revoked/retired-404-Guard + CSRF via Flask-WTF + `group_id`-Whitelist (Defense-in-Depth: WTForms-choices + expliziter Loop-Check) + `scan_interval_h NumberRange(1, 168)`. Neue Forms `ServerGroupForm` (SelectField mit coerce-Lambda) + `ServerScanIntervalForm` in `app/forms.py`. Audit-Events `server.group_changed` + `server.scan_interval_changed` mit `metadata={from, to}` (No-Op-Guard: kein Event bei `from == to`). Template `servers/settings.html` (drei Sektionen) + `_tag_editor.html` URL-Endpoints umgeschrieben (fixt 44 adversarial-Tests). Detail-View: Hashtag-Zeile + Tag-Editor-Akkordeon ersatzlos raus; Zahnrad-Button mit `data-test="server-settings-link"`. Group-Pre-Selection-Fix: ServerGroupForm wird mit `data={"group_id": str(server.group_id) or "none"}` instanziiert. **Security-Auditor APPROVED-mit-GELB:** zwei Folge-PR-Kandidaten (CSRF-Fail-Redirect-Ziel + Gear-Button Tailwind-Klassen). TD-015 in `docs/techdebt.md` für orphaned `_render_tag_editor`-Helper.

4. **Phase C — Host-Snapshot-Pills + Listener-Exposure (commit `ec9ca87`).** `_partials/host_snapshot.html` ersatzlos **GELÖSCHT** — Sektion verschwindet. Zwei neue Header-Pills `<button class="sd-chip">` (Listeners + Active services) mit `data-test="pill-listeners|services"` direkt unter der Sysline; binden an `x-data="serverPillPanels"` (Single-Open-State). Pills `disabled` mit Tooltip „Update agent to ≥ 0.3.0 for snapshot" wenn `host_state_snapshot_at IS NULL` (Panel-Partials gar nicht included, nicht nur versteckt). Neue Panel-Partials `_partials/server_pill_listeners.html` (4-Spalten-Tabelle Process · Addr:port · Proto · Exposure mit `sd-listener-tag` / `sd-listener-tag--exposed`) + `_partials/server_pill_services.html` (Mono-Liste der systemd-Unit-Namen). Keine Pagination, Inner-Scroll bei langen Listen via `overflow-y:auto; max-height:360px`. Neuer Service `app/services/listener_exposure.py::classify_exposure(addr: str) -> Literal["LOOPBACK", "PUBLIC EXPOSED"]` mit stdlib `ipaddress.ip_address().is_loopback` (einheitlich IPv4 + IPv6). Fail-safe: ungültige Eingaben → `"PUBLIC EXPOSED"`. IPv6-Brackets `[::1]:8000` werden gestripped, Whitespace getrimmt, IPv4-mapped-IPv6 `::ffff:127.0.0.1` korrekt als LOOPBACK. Keine Schema-Migration, keine Persistenz-Spalte. `_load_host_snapshot` mappt `ServerListener`-ORM auf `list[dict]` mit `exposure`-Key.

5. **Phase D — Workflow-Card-Drilldown (commit `b3d31a3`).** Operator-Workflows-Cards (`_action_needed_section.html`) bekommen den 3-Spalten-Drilldown sauber gerendert: Tabellen-Klasse von DaisyUI-`table table-xs w-full` auf `workflow-card__drilldown` umbenannt; Sub-Line der Group-Labels entfällt (Spec §D2); Pagination-Stub `<div class="workflow-card__pagination">` ab > 25 Groups mit „Seite 1 von N"-Info und zwei disabled Buttons (Ceiling-Division `(n // 25) + (1 if n % 25 else 0)`). Reason-Spalte rendert `entry.evaluation.risk_band_reason` unter Jinja-Autoescape (kein `|safe`). Backend (`_build_action_sections`) unverändert — Daten waren schon seit Block T vollständig. +22 Zeilen CSS in `server-detail.css` für `workflow-card__drilldown` + `workflow-card__pagination*`, token-only.

6. **Phase E — Heartbeat 30/4 + Severity-Trend ohne 50T + Skeleton-States (commit `73503f4`).** Backend: `days=50 → days=30` an drei Stellen (`severity_snapshots_for_server`, `daily_severity_counts_for_server`, `heartbeats_for_servers`). `_heartbeat_large.html` SVG-Markup (50 Cells / 7-Severity-Bands) ersatzlos raus; neu 30 `<span class="sd-heartbeat__tick sd-heartbeat__tick--<band>">` mit `data-day/data-band/data-had-scan`-Attributen. 4-Band-Mapping aus `cell.dominant_risk_band`: `escalate→escalate`, `act→act`, `mitigate|pending|monitor|noise→nominal`, `'unknown'-String oder None→unknown`. Template-Bug-Fix während Phase E: ursprüngliche Logik `{% elif _raw_band %}` matchte den `'unknown'`-String fälschlich als `nominal`; Fix `{% elif _raw_band and _raw_band != 'unknown' %}`. Skel-State (`skel=True`): 30 `sd-heartbeat__tick--skel`-Spans. Legende mit vier `sd-legend-swatch--*`-Elementen. `_stacked_bar_chart.html` SVG raus, neu div-based `sd-trend-col` mit `sd-trend-seg--{critical,high,medium,low}` + Skel-State. `_kpi_card.html` DaisyUI-Tailwind raus, neu `sd-tile`-Klassen + Skel-State (Em-Dash `—` statt Zahl, kein Sparkline). `detail.html`: Wrapper-Klasse `sd-detail-root` (Hook für `setupServerDetailHeartbeatTip`), `trendRange: '50T' → '30T'`, `sd-tiles`-Wrapper für HeaderStats, Lebenszeichen-Eyebrow „50 Tage" → „30 Tage", Range-Toggle ohne 50T-Button, Empty-State `— never scanned` bei `host_state_snapshot_at IS NULL` (kein Skel-Scan-Beam in dem Fall).

7. **Phase F — Risk-Band-Top-Level-Accordion (commit `3897209`).** Backend: neue Konstante `_RISK_BAND_SECTION_ORDER = ("escalate", "act", "mitigate", "pending", "monitor", "noise")` plus Pure-Function `_build_risk_band_sections(application_groups, pending_grouping_counts) → list[dict]` mit pro Slot `band/groups/pending_count/total_count/is_empty/default_open`. Default-Open: ESCALATE bei nicht-leerem ESCALATE; sonst erster nicht-leerer Slot. `evaluation=None` oder `evaluation.risk_band` außerhalb der 6-Slot-Liste (z. B. `'unknown'`) landet im PENDING-Slot. `pending_grouping_counts` (Findings ohne `application_group_id`) komplett in den PENDING-Slot. Frontend: neues `_partials/risk_band_section.html` (95 Z.) — wiederverwendbares `<details data-test="risk-band-<band>">`-Partial mit Summary (Chevron + risk-band-pill + total_count) und Body (Card-Container + optionaler PENDING-Sub-Block). Rendert nichts wenn `section.is_empty`. `_view_groups.html` von 126 → 41 Z. reduziert: alter Loop ersetzt durch Loop über `risk_band_sections`. +40 Z. CSS für `sd-risk-band-section*`-Klassen, token-only. Lazy-Load-Hooks unverändert — kein neuer HTMX-Endpoint nötig (Spec §F5).

8. **Phase G — Action-Needed-Pill + Inline-Reason + Bulk + Status-Pills (commit `f858a08`).** `_partials/action_required_pill.html` komplett neu: Render-Condition verschärft auf `yes_subcounts.escalate + yes_subcounts.act > 0` (Spec §G1) — bei pending/unknown-only oder monitor+noise-only rendert KEINE Pill mehr (kein „Safe"-Pill mehr; ADR-0025 §4-Prinzip). Markup von Tailwind-`badge` auf `sd-status-pill sd-status-pill--alert|--update` mit Accent-Left-Bar. Scan-Flash via `{{ scan_chars('action needed') }}`-Macro + Brackets-Spans mit `scan-flash`-Animation; `useScanFlashSync`-Hook aus Phase A0 timet die Spans. Status-Pill-Reihe in `detail.html`: `scan_stale AND db_stale` → kombinierte Pill `<span class="sd-status-flag" data-test="pill-stale-combined">stale</span>` mit englischem Tooltip; einzeln bei nur einem Bedingung. Drei deutsche Tooltips übersetzt (`Widerrufen am → Revoked on`, `Stillgelegt am → Decommissioned on`, `Letzter Scan aelter als / Trivy-DB veraltet → englisch`). Outdated-Pills (Block N) bleiben einzeln (Spec §9b). `_partials/group_findings_table.html` Finding-Row von `<tr>` zu `<details class="sd-finding" id="finding-<id>" data-test="group-finding-row-<id>">`-Stack umgebaut: `<div class="sd-findings-stack">` statt `<table>`; Inline-Reason-Block `sd-finding__reason` rendert nur wenn `f.risk_band_reason` truthy. **Kein `|safe`** — Jinja-Autoescape ist Pflicht (Spec §G4 für LLM-Output-XSS-Defense). Bulk-Toolbar G5 verifiziert ohne Re-Implementierung (existiert seit Block O). +27 Zeilen CSS in `server-detail.css` (`.sd-status-pill--alert|--update|__sub`, `.sd-findings-stack`, `.sd-finding__metrics|__reason|__reason-eyebrow|__reason-text`), token-only. G6-Legacy-Shim-Audit dokumentiert (>50 DaisyUI-Komponenten-Klassen aus Detail-View-Sicht obsolet, vollständige Liste im Phase-G-Commit-Body; legacy-shim.css unangetastet weil noch von Settings/Audit/Findings/Chat/Setup gebraucht). **Security-Auditor APPROVED ohne ROT/GELB.**

**Operator-Realbetriebs-Impact:**

- **Server-Detail-Seite** ist jetzt triage-first: Action-Needed-Pill blinkt nur bei tatsächlichen `escalate+act`-Findings (kein „pending"-Burn-Out mehr); Risk-Band-Accordion sortiert die Application-Groups in sechs Operator-Dringlichkeits-Slots; Inline-AI-Reason zeigt die LLM-Begründung pro Finding ohne Modal-Wechsel.
- **Settings-Sub-View** `/servers/<id>/settings/` über Zahnrad-Button: Tags + Group-Selector + Scan-Intervall (1–168 h) — bisher waren Group-Zuordnung und Scan-Intervall nur via Agent-Install setzbar.
- **Host-Snapshot** kollabiert in zwei Header-Pills mit Slide-Down-Panels: Listener-Tabelle hat neue Exposure-Spalte (`LOOPBACK` neutral, `PUBLIC EXPOSED` cyan-outline; fail-safe bei ungültigen Adressen).
- **Heartbeat** zeigt 30 Tage in 4 Risk-Bands (ADR-0035-konsistent mit Sidebar/Dashboard).
- **Bulk-Ack-Noise-Shortcut** „Acknowledge all noise on this server (N)" bleibt unverändert seit Block O — server-side risk_band_filter dropped fremde IDs hart.

**Bewusst weggelassen / Re-Open-Trigger:**

- **Host-Group-CRUD-UI** — Settings-Sub-View pickt nur aus existierenden Groups; Anlegen/Löschen/Umbenennen bleibt einem Folge-Block.
- **Add-Host-UI** — analog.
- **Repo-Rename `secscan` → `fathometer`** — separater ADR notwendig.
- **Performance-Re-Tuning** — keine Bench-Läufe; die zwei neuen Aggregator-Queries (Risk-Band-Top-Level + Workflow-Card-Drilldown) sind nicht messbar drückend, aber Operator kann jederzeit Bench-Lauf anfordern.
- **Settings/Findings/Audit/Chat/Setup-Redesign** — eigene Folge-Blöcke.
- **`legacy-shim.css` ausdünnen** — Audit dokumentiert >50 DaisyUI-Klassen die aus Detail-View-Sicht obsolet sind; aktuell sind sie aber noch von anderen Surfaces gebraucht. Removal-PR nach vollständiger Redesign-Welle (Aufwand ~2 h).
- **GELB-Items aus Security-Audit Phase B** — CSRF-Fail-Redirect-Ziel `add_tag`/`remove_tag` zeigt auf `server_detail.show` statt `server_settings.show` (UX-Inkonsistenz, kein Sicherheitsrisiko); Gear-Button verwendet noch `btn btn-sm btn-ghost` (Legacy-Shim-OK per ADR-0032-Addendum). Beide als Folge-PR-Kandidaten.
- **`count_kev_events_50d`-Removal** — Funktion ist deprecated-markiert (Phase A) und kann in einem Cleanup-PR sauber gelöscht werden sobald keine Test-Konsumenten mehr existieren.
- **TD-015 `_render_tag_editor`-Removal** (Phase B) — orphaned Helper in `server_detail.py`, Cleanup nach Block-X-Merge.

**Tag `v0.13.0` zu setzen** (nach Branch-Merge auf main, gemäß [Tag-only-on-main-after-Merge]).

**Block W abgeschlossen 2026-05-24 — Frontend-Redesign Phase 1 (Login + Dashboard + App-Shell) + ADR-0032-Phase-2-Vorziehung.** Branch `feat/block-w-redesign-phase-1`, neun Commits (1 Spec-Foundation + 7 Phase-Commits + 1 Addendum-Commit). Fünf neue ADRs (0032–0036), Migration 0014, neuer Frontend-Build-Stack (esbuild + lightningcss + Plain-CSS + JetBrains-Mono self-hosted).

**Commits in Reihenfolge:**

| Commit | Inhalt |
|---|---|
| `63c8017` | docs(block-w): spec foundation (ADR-0032..0036 + block spec + design assets) |
| `d49311e` | feat(block-w-phase-a): frontend-build-toolchain + asset-manifest |
| `46f4deb` | feat(block-w-phase-b): topbar + footer + bg-grid + fathometer-logo |
| `101e27d` | feat(block-w-phase-c): sidebar groups + viewport-lazy + migration 0014 |
| `f51c21a` | feat(block-w-phase-d): action-card + nominal-card + scan-sync |
| `c0d0eed` | feat(block-w-phase-e): triage-row + severity-strip + dashboard-kpis |
| `31878f6` | feat(block-w-phase-f): sysline + OOB-polling + hx-preserve |
| `ad2cc21` | feat(block-w-phase-g): login rewrite + auth.css + legacy smokes |
| `d2550ba` | feat(block-w): shell-fix + addendum (Tailwind/DaisyUI raus + Legacy-Shim) |

**Fünf neue ADRs:**

- **ADR-0032** — Frontend-Build-Toolchain: Plain CSS + esbuild + lightningcss, kein Tailwind/DaisyUI. **Phase 2 wurde im Addendum vorgezogen** — löst ADR-0001 final ab (Status: Superseded by ADR-0032), TD-010 final erledigt.
- **ADR-0033** — Brand-Identity Fathometer (Logo, Wordmark "Fathometer · CVE Intelligence", JetBrains-Mono self-hosted, Color-Reduction "nur escalate trägt cyan", Easing-Doctrine, Border-Radius-/Box-Shadow-Verbotsliste, Sprach-Policy englisch).
- **ADR-0034** — Host-Group-Datenmodell (1:N, `server_groups`-Tabelle + nullable `servers.group_id`, Migration 0014, Sidebar-Verhalten "Gruppen oben eingeklappt → Ungrouped flach unten", CRUD out-of-Block-W).
- **ADR-0035** — Daily-Risk-State als Heartbeat-Mapping (4 Zustände aus `Finding.risk_band`, 30 Ticks statt 50, Live-Aggregation ohne Schema-Change, Viewport-Aware Lazy-Loading via IntersectionObserver + Batch-Endpoint, Polling-Cadence 60 s).
- **ADR-0036** — Single-Pane Dashboard-Polling mit hx-preserve + OOB-Swaps (Action-Card-Animation-Preservation, ein KPI-Endpoint `/_partials/dashboard/kpis`).

**Was die sieben Phasen geliefert haben (12 neue Pure-Unit-Tests Phase A, 45 Phase B, 84 Phase C, 50 Phase D, 24 Phase E, 56 Phase F, 25 Phase G — **~296 neue Tests** über den Block):**

1. **Phase A — Build-Toolchain + Tokens (commit `d49311e`).** Neues `frontend/`-Verzeichnis (`package.json`, `package-lock.json`, `esbuild.config.mjs` mit `bundleAsync` + SHA-256-Content-Hash + Cleanup, `src/css/{tokens,app}.css`, `src/js/{vendor,app}.js`, 3 JetBrains-Mono woff2). `app/__init__.py` Lazy-Cache + `_asset_url`-Jinja-Global mit Production-RuntimeError bei Missing-Key + Dev-Fallback. `base.html` + `base_app.html` ergänzte Bundle-Tags (im Initial-Stand parallel zu CDN, im Addendum-Commit dann CDN-frei). Dockerfile neue `frontend-build`-Stage (node:20-alpine) → `COPY --from=frontend-build` in runtime-builder.

2. **Phase B — Topbar + Footer + bg-grid + Fathometer-Logo (commit `46f4deb`).** 3 neue CSS-Komponenten (`topbar.css`, `footer.css`, `profile-menu.css`) mit Logo-Animationen (`fathom-sweep`, `op-pulse`), Wordmark-Stack, Profile-Dropdown. `_macros.html::fathometer_logo` (SVG 1:1 aus `app.jsx::FathometerLogo`). `layout/_header.html` + `_profile_dropdown.html` kompletter Rewrite englisch, degraded sauber wenn nicht authentifiziert. `layout/_footer.html` neu mit Version-Link (Doppel-`v`-Bug gefixt via `_ver_tag`-Normalisierung). `_inject_version`-Context-Processor mit Regex-Härtung `^[A-Za-z0-9._-]+$` max 64 Chars, Fallback `"dev"`.

3. **Phase C — Sidebar + Migration 0014 + Viewport-Lazy (commit `101e27d`).** Migration `0014_block_w_server_groups` (server_groups + nullable `servers.group_id` FK ON DELETE SET NULL + Index, backwards-compatible). `ServerGroup`-ORM-Klasse mit Relationship `lazy="selectin"`. `sidebar_group_aggregates.group_counts()` als ein LEFT-JOIN-GROUP-BY. `heartbeat_aggregation.DailyStatus.dominant_risk_band` + `_RISK_BAND_RANK`-Reduce, `days=30`-Default. POST `/_partials/sidebar/batch` mit `@login_required` + Pydantic `extra="forbid"` + `max_length=200` + DB-Whitelist + OOB-Response (security-audited APPROVED). Sidebar-Templates kompletter Rewrite (Groups oben eingeklappt + Ungrouped flach unten, 30-Tick-Heartbeat mit 4-Zustand-Mapping). `sidebar_viewport.js` IntersectionObserver `rootMargin=200px` + 60-s-Polling-POST + CSRF-Header. `sidebar_loading_wave.js` Stagger-Reveal. **lightningcss-Build-Fix:** `transform()` → `bundleAsync()` (CSS-Bundle wuchs von 1.2 KB auf 16 KB weil @imports jetzt aufgelöst werden).

4. **Phase D — Action-Card + Nominal-Card (commit `f51c21a`).** `stat-card.css` mit Scan-Beam-Animationen (`@keyframes stat-scan` mit `mix-blend-mode: screen`, `stat-scanlines`, `scan-flash`). `scan_chars`-Macro splittet Text in per-Char-Spans + `visually-hidden`-Volltext für Screenreader. `_action_needed_card.html` (`stat--alarm`) + `_nominal_card.html` (`stat--safe` ohne Cyan per Color-Doctrine). `dashboard_scan_sync.js` Vanilla-JS-Port von `useScanFlashSync` mit debounced 50-ms-Re-Sync auf `htmx:oobAfterSwap`. `dashboard_kpis.py::_load_action_needed_card_data` + `_load_nominal_card_data`. Legacy-Templates gelöscht (`_kpi_cards.html`, `action_required_card.html`); `risk_band_pill.html` bleibt (noch von Findings/Servers genutzt).

5. **Phase E — Triage-Row + Severity-Strip (commit `c0d0eed`).** `triage.css` + `severity.css`. `_triage_row.html` (7 Buckets in Design-Reihenfolge mit `<a>`-Cells, `data-test` pro Bucket, Accent-Klasse nur bei count>0). `_severity_strip.html` (4 Severities mit serverseitig berechnetem `width %` für Bar-Fill). `dashboard_kpis._load_triage_counts` (Dual-Mode: schnell aus `risk_bands_by_server` oder Standalone-GROUP-BY) + `_load_severity_counts` mit `max_count=1`-Schutz gegen Division-by-Zero.

6. **Phase F — Sysline + OOB-Polling (commit `31878f6`).** `sysline_context.build_sysline_context` mit 4 ORM-Queries (max `Server.last_scan_at`, 2× max `FeedPullLog.completed_at` für `epss`/`cisa_kev`, `Settings`-Singleton). `dashboard_partials.dashboard_partials_bp` mit `GET /_partials/dashboard/kpis` (`@login_required`) liefert OOB-Response über 8 Targets — **kein** `#action-needed-card`-Wrapper im Response damit Scan-Beam-Animation durchgehend läuft (via `hx-preserve="true"` auf der Initial-Card). `_detail_pane.html` Polling umgestellt auf `hx-get="/_partials/dashboard/kpis"`, `hx-trigger="every 60s [document.visibilityState === 'visible']"`, `hx-swap="none"`. `dashboard_last_refresh.js` mit `setInterval(30_000)` für `HH:MM UTC`-Anzeige.

7. **Phase G — Login-Rewrite + Final-Polish (commit `ad2cc21`).** `auth.css` mit `.app--auth`-Grid + `.auth__panel` Accent-Left-Bar. `login.html` kompletter Rewrite englisch (`Operator credentials.`, `> authenticate`, `No signup. No reset. No SSO. Internal operators only.`, Submit `authenticate →`, Status-Line mit `[access denied] · <flash>` bei Error). `base.html` `page_content`-Block-Erweiterung damit Login die DaisyUI-Flash-Banner umgehen und das eigene Layout rendern kann (rückwärtskompatibel). `_empty/no_servers.html` englisch + plain CSS. Backend-View `auth_bp.login` unverändert (war kompatibel). Legacy-Surface-Smokes für Settings + Server-Detail (Dual-Stack lebt weiter).

**Addendum-Commit `d2550ba` — Shell-Fix + ADR-0032 Phase 2 vorgezogen (2026-05-24).** Browser-Smoke nach den 7 Phasen-Commits zeigte Cascade-Konflikte: DaisyUI eigene `.footer`/`.stats`/`.stat`/`.toast`/`.alert`-Klassen und Tailwind-`forms`-Plugin-Override auf `[type='text']`/`[type='password']` kollidierten mit dem neuen Plain-CSS. Statt mit `!important` zu hacken, hat der Operator **ADR-0032 Phase 2 vorgezogen**:

- Alle CDN-Tags (Tailwind, DaisyUI, Alpine, HTMX) raus aus `base.html` + `base_app.html`. Alpine + HTMX kommen jetzt ausschließlich aus dem esbuild-`vendor.js`-Bundle.
- `frontend/src/css/components/legacy-shim.css` (~450 Zeilen) liefert Minimal-Styles für die ~150 häufigsten Tailwind-/DaisyUI-Klassen in noch nicht redesigneten Templates (Settings/Server-Detail/Findings/Audit/Setup/Chat/Dashboard-`_card.html`/`_partials/*`/`_empty/*`). Pages bleiben benutzbar, sind nicht hübsch.
- Shell-Fixes: `base*.html` Body-Tailwind-Klassen raus, `<div class="app">` als Grid-Wurzel, Topbar/Sidebar/Main/Footer als direkte Grid-Children. `_detail_pane.html` Klassen-Drift gefixt (`.dashboard__eyebrow` → `.eyebrow`), Section-Labels für Triage und Severity ergänzt. `_action_needed_card.html` CTA "triage now" → "open triage queue", `action needed`-Text raus aus `scan_chars` (nur Brackets flashen). `_sysline.html` `.sysline__prompt` → `.prompt`, Separator inline. `login.html` eigenes App-Wrapping raus (kommt jetzt aus `base.html`). CSS-Source-Order: `.app--auth`/`.main--auth`/`.topbar--auth` aus `auth.css` in `app.css` verschoben (musste NACH `.app` stehen). `auth.css` `:-webkit-autofill`-Overrides gegen Chrome-Autofill-White.
- Animation-Fix: `dashboard_scan_sync.js` re-syncen nur wenn sich die Span-Anzahl ändert (sonst Phase-Reset bei jedem OOB-Tick). `scan-flash`-Keyframe 1:1 zurück auf Design-Original.
- `test_tailwind_safelist.py` als `pytest.skip` deprecated (Löschung beim nächsten Repo-Cleanup).
- Doc-Updates: ADR-0001 auf `Superseded by ADR-0032`. ADR-0032 Addendum-Sektion mit Phase-2-Vorziehung und Legacy-Shim. **TD-010 final als ERLEDIGT markiert.** decisions/README.md Status-Zeilen aktualisiert.

**Migration 0014** (server_groups + servers.group_id) wurde am 2026-05-23 vom Operator als db_integration verifiziert: Roundtrip (`downgrade base → upgrade head → downgrade -1 → upgrade head`) clean, alle 5 CHECK/UNIQUE-Probes grün, ON-DELETE-SET-NULL-Semantik korrekt.

**Verifikations-Ergebnisse Endstand (post-Addendum):**

- **Default-`pytest`:** 1713 passed, 6 skipped (5 E2E + 1 deprecated `test_tailwind_safelist.py`), 662 deselected in 40 s. Vom Phase-G-Endstand 1717 auf 1713 → −4 Tests, verursacht durch das ADR-0032-Phase-2-Vorziehen (Tailwind-Safelist-Tests `test_script_load_order.py`-Anpassungen und einige Smoke-Tests die Tailwind-CDN-Verifikation gemacht haben).
- **Lint/Type-Gates:** `ruff check .` PASS, `ruff format --check .` PASS (320 Files), `mypy app/` PASS (84 Source-Files, no issues).
- **Über den ganzen Block:** ~296 neue Pure-Unit-Tests + ~30 angepasste Tests (Sidebar-Partial, Tailwind-Safelist-Deprecation, Dashboard-Context-Mock-Erweiterungen).

**Operator-Realbetriebs-Impact:**

- **Bundle statt CDN:** Production-Browser zieht keine externen Assets mehr (kein cdn.tailwindcss.com, kein cdn.jsdelivr.net) — passt zu `docs/operations.md` "keine externen asset calls"-Vorgabe. **Air-Gap-Deployments brauchen die CDN-Domains nicht mehr im Egress-Whitelist** (Phase-1-Dual-Stack-Anforderung ist mit dem Addendum entfallen).
- **Brand-Identity:** Fathometer-Wordmark sichtbar in Topbar + Footer + `<title>` + Login. `secscan` bleibt nur als Repo-Slug + Code-Identifier (Repo-Rename ist out-of-Scope).
- **Single-Pane-Polling:** 60-s-Cadence statt 10-s, OOB-Swaps statt Full-Pane-Replace. Scan-Beam-Animation läuft durchgehend (hx-preserve). Dashboard-Render-Kosten pro Tick reduziert auf nur die KPI-Aggregate.
- **Heartbeat-Bars:** 30 Ticks (statt 50) mit 4-Zustand-Mapping aus `dominant_risk_band`. Viewport-Aware-Lazy-Loading lädt initial nur die ~10 sichtbaren Server statt aller; bei Scroll werden neu sichtbare nachgeladen via Batch-POST.
- **Operator-Bookmarks:** `/login` rendert neuen englischen Login. Alle existierenden Setup/Settings/Findings/Audit/Server-Detail-Pfade funktionieren weiter (legacy-shim.css deckt sie minimal ab).

**Bewusst weggelassen / Re-Open-Trigger:**

- Server-Detail-Redesign, Settings/Findings/Audit-Redesign — eigene Folge-Blöcke (vermutlich W+1 und W+2).
- Host-Group-CRUD-UI — kommt mit Server-Detail-Redesign.
- Add-Host-UI — kommt mit Server-Detail-Redesign.
- Legacy-Shim-Schrumpfung — wandert pro redesigntem Template in dessen eigene Komponenten-CSS.
- Repo-Rename `secscan` → `fathometer` (separater ADR notwendig wegen Code-Identifier-Sweep, Package-Name, Container-Image-Name).
- `test_tailwind_safelist.py` finale Löschung (heute pytest.skip, Cleanup-PR beim nächsten Repo-Touchpoint).
- TD-014 (Sidebar-Polling-Endpoints Rate-Limit, ~30 Min, security-auditor GELB-1 aus Phase C).

**Tag `v0.12.0` zu setzen** (nach Branch-Merge auf main, gemäß [Tag-only-on-main-after-Merge]).

**Post-W-Bugfix 2026-05-24 — TICKET-005 Heartbeat-Bar Template-Bug, OOB-Drift, Hover-Overlay.** Branch `fix/block-w-heartbeat-tooltip`, zwei Commits:

| Commit | Inhalt |
|---|---|
| `c8cc4fd` | fix(block-w): heartbeat dominant_risk_band template bug + oob drift |
| `ac3692f` | feat(block-w): heartbeat hover overlay |

Drei Defekte aus Block W Phase C (`101e27d`) bereinigt:

1. **Template-Bug:** `_heartbeat_bar.html:30` resolved `cell.dominant_risk_band.value` auf einem plain `str` zu `Undefined`, jeder Mapping-Branch fiel in den `else`-Zweig — alle 30 Cells uniform grau, obwohl Aggregation auf rke2-sv-0 ~4246 OPEN-Findings mit `risk_band='escalate'` zählt. Fix: `.value` raus. Mock-Test-Helper `_make_cell` setzte einen MagicMock mit `.value`-Attribut und hat den Bug damit ~2 Wochen verschleiert — Helper jetzt direkt auf String, alle 7 `_to_*`-Mapping-Tests verifizieren nun das echte Verhalten.
2. **OOB-Drift:** `_partials/sidebar_batch_oob.html` rendete eigenes `host__beat__cell--*`-Klassen-Schema und IDs die im Initial-Render gar nicht existierten — Per-Row-Viewport-OOB-Update-Pfad war seit Block-W-Merge tot. Fix via neuem Single-Source-Pattern: `_heartbeat_bar.html` + neues `_counts.html` werden in beiden Pfaden includiert, OOB-Conditional via `oob_swap`-Flag. `host__beat__cell`-Schema komplett aus dem Repo entfernt.
3. **Hover-Tooltip:** Browser-Native `title="…"` durch Design-konformes `.heartbeat-tip`-Overlay ersetzt (Custom-DIV mit Datum + State-Label + optionaler "no scan"-Hint). `_heartbeat_bar.html` Live-Cells haben jetzt `data-day`/`data-band`/`data-had-scan` (statt `title=`); `frontend/src/css/components/sidebar.css` enthält neuen `.heartbeat-tip`-Stack inkl. `@keyframes heartbeat-tip-in`; `frontend/src/js/sidebar_heartbeat_tip.js` mit Event-Delegation, WeakMap-Cleanup, `textContent`-only (XSS-Defense).

**Neue Pure-Unit-Tests (25 total):**
- `tests/templates/test_sidebar_heartbeat_drift.py` (7 Tests) — Initial-vs-OOB-Render strukturell vergleichen.
- `tests/templates/test_heartbeat_ids_present.py` (5 Tests) — ID-Anker + OOB-Conditional-Flag.
- `tests/templates/test_heartbeat_tooltip_data_attrs.py` (12 Tests) — `title=` raus, neue `data-*` gesetzt, Skeleton unangetastet.
- `tests/templates/test_heartbeat_30_ticks.py` — `_make_cell`-Helper umgestellt (direkter String statt `.value`-Mock).

**CLAUDE.md §HTMX-OOB-Single-Source-Pattern** ist mit diesem Ticket etabliert und hier sein erster Anwendungsfall (Defekt 2 war der Auslöser).

**Verifikations-Endstand:**
- Default-`pytest`: 1813 passed, 6 skipped, 662 deselected in ~40 s.
- `ruff check . && ruff format --check .` PASS (328 Files), `mypy app/` PASS (85 Source-Files).
- `cd frontend && npm run build` PASS, neue Asset-Hashes im `app/static/dist/manifest.json`.

**Operator-Smoke offen** (8 Punkte aus TICKET-005 §Schritt 6, vom User abzuhaken vor Merge auf `main`):
1. Sidebar lädt — letzte 2–3 Cells für rke2-sv-0 sind cyan (`beat--alarm`).
2. Hover über cyan-Cell zeigt Overlay mit Datum + `ESCALATE`-Label in cyan, keine Hint-Zeile (`had_scan=true`).
3. Hover über graue Cell ohne Scan zeigt Datum + `NOMINAL` + Hint-Zeile "no scan".
4. Hover-Animation läuft (200 ms fade-in mit Y-translate).
5. Kein nativer Browser-Tooltip mehr.
6. Nach 60 s Polling-Tick: Heartbeat-Bar wird via OOB-Batch korrekt aktualisiert.
7. IntersectionObserver-Scroll: Skeleton für neu sichtbare Rows, Live-Daten kommen via Batch-POST nach.
8. Keine Console-Errors.

**Branch-Merge auf `main`** direkt nach Operator-OK (Pattern wie TICKET-004); kein eigener Tag (Bugfix-Release läuft mit `v0.12.0` mit).

---

**Block U abgeschlossen 2026-05-23 — Parallele LLM-Job-Verarbeitung im einzigen Worker-Prozess.** Branch `feat/block-u-worker-concurrency`, sieben Phasen in Reihenfolge A → B → D → C → F → G → E (alle pro Phase vom `reviewer`-Subagent APPROVED). Einzelner Block-Abschluss-Commit auf User-Wunsch (statt sieben Phase-Commits — Option 2 aus der Workflow-Frage). ADR-0029 ist die Quelle der Wahrheit; CLAUDE.md/ARCHITECTURE.md unverändert.

**Was Block U geliefert hat (sieben Phasen):**

1. **Phase A — Schema + Settings.** Migration `0012_block_u_worker_concurrency` mit zwei neuen `Setting`-Spalten plus CheckConstraints: `llm_worker_job_concurrency` (INT NOT NULL, BETWEEN 1 AND 200, Default 1) und `llm_debug_log_success_sample_rate` (INT NOT NULL, BETWEEN 1 AND 1000, Default 10). Pydantic-Spiegel in `app/config.py` mit `Field(ge=…, le=…)` und Env-Var-Override (`SECSCAN_LLM_WORKER_JOB_CONCURRENCY`, `SECSCAN_LLM_DEBUG_LOG_SUCCESS_SAMPLE_RATE`). `llm_debug_log_max_rows`-Pydantic-Default 500 → 2000 (kein Schema-Touch).

2. **Phase B — Persistenter Async-Client mit Fingerprint-Cache.** Neue Modul-State + Helper in `app/workers/llm_worker.py`: `_compute_client_fingerprint(base_url, model, api_key) -> (str, str, sha256_hex)`, `async _get_or_build_async_client(session) -> (LlmClient, str)` mit `asyncio.Lock` und `await aclose()` beim Mismatch, neuer Log-Marker `llm_worker.client_rebuilt reason=fingerprint_changed …`, `_get_reviewer_for_job(session) -> (reviewer, owns_client)` (Live-Pfad `owns_client=False`, Test-Hook-Pfad `owns_client=True`). `_do_pass1`/`_do_pass2` öffnen jeweils eine Setup-Session, `finally`-Block schließt nur noch konditional bei `owns_client=True`. TLS-/httpx-Pool des `AsyncOpenAI` bleibt über Job-Grenzen erhalten.

3. **Phase D — DB-Pool-Sizing + Pass-2-Cache-Conflict.** Neue Pure-Funktion `_compute_pool_sizing(N) -> (max(N*2, 10), N)` in `app/workers/llm_worker.py`. `_get_session_factory` nutzt sie und übergibt `pool_size`/`max_overflow`/`pool_pre_ping=True` an `create_engine`; einmaliger Log-Marker `llm_worker.engine_built pool_size=… max_overflow=…`. Engine-Lifetime-Singleton (kein Hot-Reload der Pool-Größe — Operator-Pod-Restart fürs Hochregeln). `app/services/llm_cache.py::store` umgestellt von ORM-`session.add` auf `sqlalchemy.dialects.postgresql.insert(...).on_conflict_do_nothing(index_elements=["cache_key"])`; Return-Typ jetzt `None`. `record_hit`/`lookup` unverändert.

4. **Phase C — Async-Dispatcher mit Greedy Slot-Refill (Herzstück).** `main()` ruft jetzt `asyncio.run(_run_async_main())` zwischen `_start_heartbeat_thread()` und `_stop_heartbeat_thread()`. Neuer Dispatcher-Loop in `_run_async_main`: `asyncio.create_task(_process_one_async(job_id, mode))` mit `set[asyncio.Task]` und `add_done_callback(in_flight.discard)`, `asyncio.wait(in_flight, return_when=FIRST_COMPLETED)`, Greedy-Refill bis `cap`. `_pick_next_job_id`-Bedingungen prüfen `_get_mode_throttled` (off → break), `_budget_ok_throttled` (False → break). Shutdown-Drain mit `asyncio.wait_for(asyncio.gather(…), timeout=30.0)` plus WARNING-Log bei TimeoutError. `_tick()` → `_run_subticks()` umbenannt — enthält nur noch Reaper, Eviction, Feed-Pull, Ingest, Retention (Pickup/Mode/Budget sind im Dispatcher). Neue Konstante `CONCURRENCY_CHECK_INTERVAL_SEC = 30.0` und `_get_concurrency_throttled()` mit Cache + Log-Marker `llm_worker.concurrency_changed from=N to=M`. Heartbeat-Daemon-Thread komplett unangetastet (eigener Thread mit `threading.Event.wait`, eigene DB-Session, kein Event-Loop-Touch). `_process_one_async` returnt `dict | None` mit `{"duration_ms", "cache_hit"}` für Phase-F-Counter.

5. **Phase F — Logging-Refactor (Status-Snapshot statt Per-Job-Lärm).** 15 `log.info`-Calls entfernt (12 Marker, davon `llm_call_started`/`llm_call_completed`/`pass2_skipped` je 2x): `job_picked`, `job_done`, `pass1_started`, `pass2_started`, `llm_call_started`, `llm_call_completed`, `pass1_persist_done`, `pass2_persist_done`, `pass2_cache_lookup`, `pass2_cache_hit_applied`, `pass1_skipped`, `pass2_skipped`. `_usage_tokens`-Helper entfernt (war nur von den Completed-Logs konsumiert). Neue Modul-State `_status_counters = {"done", "failed", "cache_hits", "durations_ms"}` plus `_DURATION_WINDOW_CAP=100`, Helper `_push_duration`, `_reset_status_counters`. `_record_task_completion(task)` mit `task.exception()`-vor-`task.result()`-Order. `_maybe_emit_status_snapshot(in_flight, cap)` mit 30-s-Cadence, defensives `try/except` um DB-Read, Log-Format `llm_worker.status in_flight=X/Y queued=… done_30s=… failed_30s=… cache_hits_30s=… budget_pct=… avg_call_ms=…`. Per-Job-Forensik läuft ausschließlich über `llm_debug_log`-Tabelle. Alle sechs Lifecycle-INFO-Logs aus B/C/D vorhanden (`dispatcher_started`, `dispatcher_shutdown`, `concurrency_changed`, `client_rebuilt`, `shutdown_drain`, `engine_built`) — keine neuen Lifecycle-Logs nötig.

6. **Phase G — Debug-Log-Skalierung für N=200.** Neue Public-Funktion `should_sample_debug_log(job_id, job_type, status, sample_rate) -> bool` in `app/services/llm_debug_log.py` (non-success → 1:1, sample_rate ≤ 1 → True, sonst `abs(hash((job_id, job_type))) % sample_rate == 0`). Im `_record_pass_debug_log`-Worker-Helper als Pre-Insert-Gate konsultiert. `DEBUG_LOG_EVICTION_INTERVAL_SEC` von `600.0` → `60.0`. `evict_old`-Count-Cap-Pfad umgestellt von `NOT IN` auf CTE-DELETE: `DELETE … USING (SELECT id FROM llm_debug_log ORDER BY created_at DESC, id DESC OFFSET :max_rows) AS to_evict WHERE …`. `ORDER BY created_at DESC, id DESC` als Tie-Breaker für Sub-Sekunden-Kollision. `text(…)` mit `:max_rows`-Bind (CLAUDE.md-Regel eingehalten). Time-Cap-DELETE-Pfad unverändert.

7. **Phase E — Settings-UI + Master-Key-Gate.** Neue `LlmReviewerConcurrencyForm` in `app/forms.py` mit `IntegerField` (NumberRange 1..200) + `PasswordField` (Length 10..128) + CSRF. Neuer POST-Handler `llm_reviewer_change_concurrency` an Route `POST /settings/llm-reviewer/concurrency` in `app/views/settings.py`: `@login_required`, Master-Key-Check via `_verify_master_key_from_form` (→ `hmac.compare_digest`), 400 (Form-Invalid/Bounds), 403 (Master-Key falsch), 302 (Success/No-Op). Audit-Event `llm.concurrency_changed` mit `target_type="settings"`, `target_id="1"`, Metadata `{"from": old, "to": new}` (kein Event bei No-Op). Template `app/templates/settings/llm_reviewer.html` bekommt Concurrency-Card mit `data-test="llm-current-concurrency"` und Modal mit Range-Slider 1..200 + Master-Key-Input (Alpine-State `concurrencyOpen`). MVP-Vereinfachung: nur persistierter Wert angezeigt, **kein** Live-`in_flight`-Counter (Re-Open-Trigger in ADR-0029). Worker liest binnen <30 s neu via `_get_concurrency_throttled` (aus Phase C).

**Verifikations-Ergebnisse (alle Phasen, in Reihenfolge der Subagent-APPROVE-Meldungen):**

- **Default-`pytest`** über alle Phasen-Endstände: zuletzt **1360 passed, 5 skipped (E2E), 669 deselected** in ~32 s. Keine Regression in keiner Phase.
- **Test-Anzahl Block-U-spezifisch:** Phase A 34 + Phase B 10 + Phase D 14 + Phase C 14 + Phase F 10 + Phase G 73 (8 logisch) + Phase E 8 = **163 neue Pure-Unit-Tests**. Plus 7 migrierte Tests (`test_llm_worker.py::test_main_returns_when_shutdown_flag_set`, 5 Adversarial-Corrupted-Payload-Tests) und 1 gelöschter (Sequenz-Test semantisch durch Dispatcher-N=1/N=5/Drain/Mode-off/Budget-off ersetzt). Plus Anpassungen in 4 `db_integration`-Files (`tests/integration/test_llm_worker_db.py`, `test_block_p_e2e_observation.py`, `test_block_p_e2e_live.py`, `test_block_p_mode_switch.py`, `test_llm_cache_db.py`) für `_tick`→`_run_subticks`/`_process_job`→`_process_one_async`/`store()→None`-Migration — angefasst, nicht ausgeführt.
- **Lint/Type-Gates:** `ruff check .` PASS, `ruff format --check .` PASS (280 Files), `mypy app/` PASS (79 Source Files, no issues).
- **Test-Pollution-Fix in Phase B:** `test_base_url_change_triggers_rebuild_and_acloses_old` brauchte initial einen Logger-State-Restore-Fix (autouse-Fixture für `secscan.llm_worker`-Logger plus eigener Handler statt `caplog`) — Reviewer hatte beim ersten Lauf REJECTed wegen Default-Suite-Failure, nach Fix grün. Pattern dokumentiert in `tests/workers/test_llm_worker_async_client.py:46-69`.
- **Open Heavy-Suite-Verifikationen (User-Anweisung):** Alembic-Roundtrip `pytest -m db_integration -k 0012`, `test_llm_cache_db.py::test_store_inserts_row` (lookup-Roundtrip nach Cache-Conflict-Umstellung), `test_llm_worker_db.py`/`test_block_p_*.py` (`_tick`→`_run_subticks`-Migration verifizieren), Phase-F-Negativ-Marker-Smoke `test_pass1_does_not_emit_removed_phase_markers`. Default-Pure-Unit ist grün.

**Operator-Realbetriebs-Impact:** Block U ist **backward-compatible per Default** (Migration setzt `llm_worker_job_concurrency = 1` → Verhalten identisch mit pre-v0.11.0). Operator regelt manuell via `/settings/llm-reviewer` hoch wenn er Throughput braucht; Worker liest neuen Wert binnen <30 s. Pool-Größe wird beim Worker-Pod-Start aus dem Settings-Wert berechnet — bei Concurrency-Hochregelung über initialen Pool-Cap hinaus muss der Pod neu gestartet werden (kein Crash, nur Throughput-Limit auf alter Pool-Größe bis Restart). Status-Snapshot alle 30 s im Container-Log statt Per-Job-Spam (~126 Log-Lines/min → ~2/min idle, ~5/min unter Last) — Per-Job-Forensik im `/settings/llm-reviewer/debug-log`-Tab via Sampling 1:10 für Successes (Errors immer voll). Debug-Log-Eviction von 10-Min-Cadence auf 1-Min plus CTE-DELETE statt `NOT IN` — bei N=200 läuft die Tabelle deutlich kontrollierter.

**Bewusst weggelassen / Re-Open-Trigger (alle in ADR-0029 §Out of Scope / §Re-Open):**

- Multi-Worker-Container (zweiter Pod, verteiltes Rate-Limit, Redis-Backend) — ARCHITECTURE.md §17.
- Pass-1/Pass-2-Concurrency-Split (eine globale Concurrency reicht für MVP).
- Adaptive Concurrency / 429-Auto-Throttle.
- LLM-Chat-Concurrency (Block-G-Surface — eigene Folge-ADR).
- Status-Snapshot-Persistierung in DB für Live-`in_flight`-Anzeige im UI ohne Container-Log-Read (Re-Open in Phase E falls operativ schmerzhaft — heute zeigt das Settings-UI nur den persistierten Concurrency-Wert).
- Status-getrennter Debug-Log-Cap (Success-Bucket vs Error-Bucket mit separaten Caps).
- Dynamisches DB-Pool-Resize ohne Engine-Rebuild.
- Per-Provider-Concurrency-Profile.
- `async`-SQLAlchemy / `asyncpg`-Migration (Folge-Block falls Phase-C Event-Loop-Stalls produziert — heutige Sessions <50 ms, akzeptiert).

**Tag `v0.11.0` zu setzen** (nach Branch-Merge auf main, gemäß [Tag-only-on-main-after-Merge]).

---

**MVP + UI v2 + ADR-0016 bis ADR-0023 + Block-P-Iteration v0.9.3 + Pass-1-Batching v0.9.4 + Worker-Stability v0.9.5 + Worker-Idle-Throttle v0.9.6 + Server-Detail/Findings-Slim-Down v0.10.0 + TICKET-004-Test-Suite-Entkopplung — v0.10.0 (2026-05-22).**

**TICKET-004 abgeschlossen 2026-05-22 — Test-Suite schrittweise von DB-/HTTP-Abhaengigkeiten entkoppelt, 10 Slices, 545 Tests aus todo_mock entfernt.** Direkt auf `main` committet (kein Feature-Branch, weil reines Test-Refactoring ohne Produkt-Aenderung), keine Schema-Migration, keine Alembic-Datei. Tag `v0.10.0` bleibt — TICKET-004 ist Maintenance, kein Release-Trigger.

**Was TICKET-004 geliefert hat (10 Slices in chronologischer Reihenfolge):**

| Slice | Commit | Inhalt | todo_mock-Δ | db_integration-Δ |
|---|---|---|---:|---:|
| Pre-Work | `d5d355e` | `db_integration`-Marker registriert, `_ACCEPTANCE_PATH_PREFIXES`-/`_MOCKED_UNIT_FILES`-Auto-Marker-System in `tests/conftest.py`, `test_stale_detection.py` als erster DB-frei-Refactor | (Marker-Setup) | |
| 1 | `94a6f02` | `test_csv_export.py` Pure-Split | 0 | +3 |
| 2 | `b6db1a2` | `test_findings_query{,_cross}.py` Bulk-Migration (Postgres-SQL-Semantik) | −24 | +24 |
| 3 | `2d34e3c` | 4 Aggregations-Services (`quick_stats`, `severity_history`, `stale_history`, `heartbeat_aggregation`) Pure-Split mit 3 module-private Pure-Function-Extraktionen | −32 | +16 |
| 4 | `e0a1cc0` | 3 LLM-Services (`llm_cache`, `llm_debug_log`, `llm_provider_switch`) — gemischt Bulk + Pure-Split | −14 | +22 |
| 5 | `ed08a8b` | `test_feed_enrichment.py` Pure-Split entlang vorhandener Block-Grenze | 0 | +17 |
| 6 | `615b533` | 3 kleine Worker-Files (`error_classification`, `healthcheck`, `token_budget`) Pure-Split, `_is_alive`-Extraktion in `healthcheck.py` | −23 | +15 |
| 7 | `04740fa` | `test_llm_worker.py` Bulk-Migration mit 6 Pure-Rest | −32 | +26 |
| 8 | `3890aa7` | 9 API-Route-Files Bulk-Migration | −124 | +124 |
| 9 | `a37bbaa` | 36 View-Test-Files Bulk-Migration | −293 | +293 |
| 10 | `ad2a880` | `test_csv_export_cross.py` Catch-Up-Migration | −3 | +3 |
| **Summe** | | | **−545** | **+543** |

**Kennzahlen Endstand:**

- `pytest --collect-only -q`: **1805** total (vorher 1782 — +23 Pure-Edge-Cases aus Slices 3+6).
- Default-Selection (kein Marker excluded): **1159** (vorher 1674, −515).
- `pytest -m todo_mock`: **240** (vorher 785, **−545 / −69 %**).
- `pytest -m db_integration`: **646** (vorher 103, **+543 / +527 %**).
- **Default-`pytest`-Laufzeit: 1150 passed, 5 skipped, 650 deselected in 29.89 s.** Vorher 5:01 → jetzt 0:30 = **10× schneller.**

**Service-DI-Aenderungen waehrend TICKET-004:** drei verhalten-neutrale Pure-Function-Extraktionen (Wrapper-Delegation, kein Verhalten geaendert):

- `app/services/severity_history.py`: `_compute_snapshots`, `_compute_daily_counts` (Slice 3).
- `app/services/stale_history.py`: `_compute_stale_counts` (Slice 3).
- `app/workers/healthcheck.py`: `_is_alive(heartbeat_at, now, max_age_sec)` (Slice 6, +12 LOC).

Plus ein Doku-Kommentar in `app/services/heartbeat_aggregation.py`. Insgesamt unter 100 LOC Service-Diff. mypy gruen. `__all__` aller drei Services unveraendert — die neuen Pure-Helper bleiben module-private.

**Folge-Tech-Debt** (in `docs/techdebt.md` dokumentiert):

- **TD-005** (existierend): Test-Migration MED/HIGH zu Mocks — partial discharge durch Slices 1-9.
- **TD-011** (neu, Slice 8): Default-Coverage-Luecke fuer `/api/register`, `/api/keys/rotate`, `/api/findings/acknowledge` — diese Endpoints haben keinen Service-Layer-Test, Bulk-Migration entfernt die einzige Coverage aus dem Default-Lauf. Aufwand ~4-6 h Service-Layer-Extraktion + Pure-Unit-Tests.
- **TD-012** (neu, Slice 9): View-Route-Handler enthalten noch inline Geschaeftslogik / SQL-Queries — Voraussetzung fuer DB-frei-Refactor der View-Tests und eigenstaendig wertvoll fuer Lesbarkeit/Regression-Sicherheit. Aufwand ~8-10 h fuer fuenf groessere View-Module.

**Rest-Menge 240 todo_mock-Tests, bewusst akzeptiert:**

- **174 Adversarial-Route-Tests** (19 Files): XSS-, SQL-Inj-, CSV-Inj-, gzip-bomb-, sort-param-Tests. **Bewusst nicht migriert** — Sicherheits-Smokes sollen im Default-CI greifen. Marker `todo_mock` ist hier semantisch ein Misnomer; eine optionale Umetikettierung als `security_smoke` ist Folge-PR-Kandidat (~30 Min Doku + 5 LOC conftest-Aenderung).
- **66 weitere todo_mock-Tests** (Adversarial-Pure-Call 26, Services 25, Auth+Setup 23) als Folge-Aufgabe unter TD-005 belassen; Aufwand ~5-7 h total mit klarem Coverage-Plan.

**Neue Test-Konvention in `CLAUDE.md`** (Sektion „Test-Konvention — Default vs. On-Demand") niedergeschrieben: `db_integration`, `acceptance`, `integration`, `bench` und `RUN_E2E` laufen ausschliesslich auf ausdrueckliche User-Anweisung, nicht proaktiv. Default-Verifikation in der Entwicklung ist nur `pytest` (Default-Selektor) oder fokussierte `pytest <ziel-pfade>`-Laeufe.

**Bewusst weggelassen / Re-Open-Trigger:**

- Vollstaendige todo_mock-Eliminierung — als bewusste Rest-Menge dokumentiert.
- Adversarial-Marker-Rename auf `security_smoke` — kosmetische Folge-PR.
- TD-011-Service-Layer-Extraktion fuer register/keys_rotate/bulk_acknowledge — eigener Folge-Arbeitsblock, nicht TICKET-004-Scope.
- TD-012-View-Route-Architektur-Aufraeumung — eigener Folge-Arbeitsblock.

**Operator-Impact:** Default-`pytest` in der Entwicklung jetzt 10× schneller (30 s statt 5 min) — die laufende Iteration bei Code-Aenderungen wird spuerbar schneller. RC-Verifikation laeuft ueber `pytest -m db_integration` (~3-5 min mit echter Postgres) oder die volle Suite. Keine Aenderung am Produktverhalten, keine Schema-Migration, keine ADR-Aenderung.

---

**MVP + UI v2 + ADR-0016 + ADR-0017 + ADR-0018 + ADR-0019 + ADR-0020 + ADR-0021 + ADR-0022 + ADR-0023 + Block-P-Iteration v0.9.3 + Pass-1-Batching v0.9.4 + Worker-Stability v0.9.5 + Worker-Idle-Throttle v0.9.6 + Server-Detail/Findings-Slim-Down v0.10.0 — v0.10.0 (2026-05-21).**

**Block Q abgeschlossen 2026-05-21 — Server-Detail- und Dashboard-Entschlackung, dedizierte `/findings`-Seite.** Branch `feat/block-q-slim-down` mit sechs Sub-Commits (`4980b10` Spec-Foundation, `dc9d374` Phase A, `44b43f3` Phase B, `b14b5d2` Phase C, `64d003f` Phase D, `8a24549` Phase E inkl. F.5-Bookmark-Regressionen und Test-Cleanup). Keine Schema-Migration, keine Alembic-Datei berührt. ADR-0025 ist die Quelle der Wahrheit; ARCHITECTURE.md §7 ist auf die fünf Umbau-Punkte angeglichen.

**Was Block Q geliefert hat (wörtlich aus ADR-0025 §Entscheidung):**

1. **Findings-View-Modi `gruppiert` und `diff` ersatzlos entfernt.** `compute_diff`, `DiffSection`, `group_findings_by_package`, `PackageGroup`, CSV-Mode-Varianten (`FINDINGS_CSV_COLUMNS_GROUPED`/`_DIFF`, `CsvExportMode`) und die zugehörigen Templates (`_view_group.html`, `_view_diff.html`) sind weg. `FindingsViewFilter.mode` und die `?mode=`-URL-Param-Logik sind raus; veraltete Bookmark-URLs `?mode=group`/`?mode=diff` werden still ignoriert und rendern den List-Pfad. CSV-Export-Dropdown reduziert auf einen einzelnen `<a download>`-Link. ~1050 LOC netto entfernt.

2. **Application-Group-Cards default collapsed, Findings via HTMX lazy.** Neuer Endpoint `GET /servers/<server_id>/groups/<group_id>/findings` (`server_detail.group_findings_fragment`) liefert das `group_findings_table.html`-Fragment. `_load_application_groups_for_server` braucht jetzt drei feste SELECT-Statements: Count-Aggregat (`GROUP BY application_group_id`), Group-Metadaten-Batch (`WHERE id IN (...)`), Worst-Finding-Batch (`WHERE id IN (...)`). Per-Group-Findings-Query-Schleife ist weg — Reduktion von **O(N) auf O(1)** für das Card-Inventar. Card-Template rendert immer `<details>` ohne `open`-Attribut; HTMX-Trigger ist `toggle once from:closest details, click once from:closest summary` (Safari-Doppel-Trigger-Fallback). Spinner-Placeholder „Lade Findings…" im Lazy-Slot.

3. **Pending-Grouping-Sektion gleich behandelt.** `_load_ungrouped_findings_for_server` (heute Limit-500-Eager) ist weg; `_load_pending_grouping_counts(sess, server_id)` liefert ein 7-Band-Dict (escalate→noise, Default 0) in deterministischer Insertion-Order via Comprehension über `_PENDING_BANDS`-Konstante. Neuer Endpoint `GET /servers/<server_id>/findings/pending?risk_band=<band>` (`server_detail.pending_findings_fragment`) mit Whitelist-400 (Param fehlt oder ungültig) und 404-Pfaden (Server unbekannt, Bucket leer, grouped Finding in selbem Band). Neues Fragment-Template `_partials/pending_findings_table.html` (Markup analog `group_findings_table.html`).

4. **`active`-Status-Pille im Server-Detail-Header weg.** `app/templates/servers/detail.html` Pill-Reihe verkürzt: nur noch `{% if revoked %}…{% elif retired %}…{% endif %}` plus die Auffälligkeits-Marker (stale, db-veraltet, agent-outdated, trivy-outdated, trivy-db-stale, action-required). Aktive Server ohne Auffälligkeit zeigen jetzt keine Status-Pille. `app/templates/settings/servers.html` (CRUD-Liste) bleibt unangetastet — dort hilft die explizite Pille zur Unterscheidung von revoked/retired (anderer Kontext).

5. **Cross-Server-Findings-Tabelle auf dedizierte `/findings`-Seite.** Neuer Blueprint-Handler `findings.index` (`@findings_bp.get("", strict_slashes=False)`) rendert `app/templates/findings/index.html`. Default-State ohne Filter und ohne expliziten `?sort=`/`?dir=` zeigt einen Empty-State-Block mit `total_findings`/`visible_servers`-Countern; keine Findings-Query feuert. Filter-Bar ist `<form method="get">` mit Submit-Button „Anwenden", keine `hx-trigger`-Attribute. Sort/Dir liegen als Hidden-Inputs im Form (sticky beim Filter-Submit). Pagination klassisch nummeriert: 50 Findings/Seite, URL-Param `?page=N`, Pager mit «/»-Disabled-States an den Rändern. CSV-Export-Link zeigt mit aktivem Filter ohne `page`-Param auf `findings.export_csv` — Scope ist alle gefilterten Treffer (CSV-Stream hat kein Limit, verifiziert). Header-Nav bekommt einen zweiten Eintrag „Findings" neben „Dashboard"; Active-Highlight via `request.endpoint`. KPI-Cards/Risk-Band-Pills/Quick-Stats-Counter zeigen jetzt auf `/findings?…`. Dashboard verliert die Findings-Section ersatzlos (`_findings_section.html`, `_findings_filter_bar.html` gelöscht); Polling-Wrapper auf `#dashboard-pane` bleibt, Inhalt ist jetzt kleiner.

**`list_findings_cross_server`-Signatur** bekommt einen `offset: int = 0`-Kwarg (`offset(...).limit(...)`); `total_count` bleibt Pre-Offset/Pre-Limit aus dem gefilterten Subselect.

**Was bewusst weggelassen wurde (Re-Open-Trigger):**

- *Triple-`_load_findings()`-Konsolidierung im Server-Detail-Header* (`compute_tendency` + `severity_snapshots_for_server` + `daily_severity_counts_for_server`) — drei identische DB-Queries plus drei O(F×50)-Python-Loops über dieselbe Datenbasis bleiben unberührt. Separater Performance-Folge-Block (vermutlich **Block R**).
- *DashboardFilter-Rename auf FindingsListFilter* (Task F.6). Optional ausgelassen, weil der `view_filter=filt`-Alias-Trick im neuen Index-Handler funktioniert und `DashboardFilter` semantisch heute beide Surfaces bedient (Dashboard-KPIs und Findings-Tabelle teilen die Tag-/Severity-/Status-Felder). **Re-Open-Trigger:** wenn der Symbolname in einer Folge-PR stört, Datei umbenennen auf `app/schemas/findings_list_filter.py`, Klasse auf `FindingsListFilter`, alle Import-Sites anpassen — kein Re-Export-Stub.
- *ADR-0018/0020-Status-Migration* auf `Superseded by ADR-0025`. Index ist bereits auf „Teilweise abgelöst durch 0025" gesetzt; vollständige Header-Status-Aktualisierung in den ADR-Files selbst kann als kleiner Doku-PR nach v0.10.0-Tag laufen.

**Verifikations-Ergebnisse (Phase-G Reviewer-Approve):**

- **Test-Anzahl 1670 collected** (vorher 1655; **Delta +15**, DoD-Erwartung war −10 bis −25). Grund: ~80 gelöschte Diff-/Group-Mode-Tests wurden durch die deutlich umfangreicheren Lazy-Load- und Pending-Counts-Tests überkompensiert (neue Test-Files: `test_server_detail_lazy_groups.py` 478 LOC mit 8 Tests, `test_server_detail_pending_lazy.py` 633 LOC mit 15 Tests, `test_findings_index.py` 231 LOC mit 6 Tests, `test_server_detail_status_pills.py` 143 LOC mit 3 Tests, `test_settings_servers_active_pill.py` mit 1 Regression-Test). **Volle Suite `pytest tests/views/ tests/adversarial/` 729 passed** im sauberen Lauf; gelegentliche `psycopg.errors.AdminShutdown`-Flakes bei parallelen DB-Tests sind Test-Infrastruktur und in isolierten Re-Runs grün — kein Code-Regression.
- **Lint/Type-Gates:** `ruff check . && ruff format --check .` PASS; `mypy app/` PASS (76 source files).
- **Alembic-Roundtrip** (`upgrade head && downgrade -1 && upgrade head`) grün gegen Test-Postgres (Block Q fügt keine Migration hinzu; `0008 → 0007 → 0008` sauber).
- **Docker-Compose-Up + `/healthz`** grün — drei Container (db/app/secscan-llm-worker) healthy.
- **Performance-Erwartung** per Code-Analyse bestätigt: Card-Inventar-Queries auf `/servers/<id>` von **2+N+1** auf **fix 4** reduziert (Count + Group-Meta + Worst-Finding + Pending-Counts), Findings-Listen werden via zwei neue HTMX-Lazy-Endpoints (`group_findings_fragment`, `pending_findings_fragment`) nachgeladen. **Wallclock-Bench NOT MEASURED** — Operator soll in der Live-Umgebung mit echter k3s-Fixture-DB die Initial-Render-Zeit gegenmessen.

**Manuelle Operator-Smoketests offen** (vor Tag-Schluss): Pager-Navigation visuell, CSV-Export gegen aktiven Filter, HTMX-Toggle-Verhalten in Firefox/Chrome/Safari (Cards öffnen + schließen + erneutes Öffnen löst keinen Re-Fetch aus).

**Operator-Realbetriebs-Impact:** k3s-Server mit 400+ Findings in einer Group plus 250+ ungroupierten Pending-Findings rendert `/servers/<id>` deutlich schneller (Code-Lese: O(N)→O(1) Queries, Eager-Render der Drilldown-Tabellen entfällt komplett). Operator-URL-Bookmarks mit `?mode=group`/`?mode=diff` sind nicht broken, sie zeigen jetzt den List-Pfad (still ignoriert). Operator-URL-Bookmarks für die alte Dashboard-Findings-Section (`/?q=…&severity=…&kev_only=1`) zeigen nichts Filterbares mehr im Dashboard — Operator muss auf `/findings?…` umstellen; falls in der Praxis störend, ein UI-Hinweis im Dashboard kann später nachgereicht werden (separater Doku-PR).

**Tag `v0.10.0` zu setzen** (nach Branch-Merge auf main).

---

**MVP + UI v2 + ADR-0016-Refinement + ADR-0017-Pane-Konsolidierung + ADR-0018-Server-Detail-Redesign + ADR-0019-Polling + ADR-0020-Dashboard-Redesign + ADR-0021-Bootstrap-Installer + ADR-0022-Risk-Engine + ADR-0023-LLM-Risk-Reviewer + Block-P-Iteration v0.9.3 + Pass-1-Batching v0.9.4 + Worker-Stability v0.9.5 + Worker-Idle-Throttle v0.9.6 — v0.9.6 (2026-05-20).**

**Patch v0.9.6 abgeschlossen 2026-05-20 — Worker-Idle-CPU-Optimierung + CI-Build-Speedup.** Direkt auf main committed (`acb162d` CI-Workflow-Fix, `2784a86` Worker-Throttle), Tag `v0.9.6` zeigt auf `2784a86`. Keine Schema-Migration, Spec-Files unverändert.

Operator-Befund nach v0.9.5-Deploy: `secscan-llm-worker`-Pod bei leerer Queue zeigte **219 mCPU** (~22% einer Core) — zu viel für „nichts zu tun". Ursache: `_tick()` lief mit 2s-Cadence durch vier separate SQL-Roundtrips (Budget-Reset, Mode-Check, Budget-Check, Pickup), plus Heartbeat-Thread alle 10s → ~126 Queries/Minute Idle-Last.

Drei Throttling-Mechanismen in `app/workers/llm_worker.py`:

- **Mode-Check-Cache** (`MODE_CHECK_INTERVAL_SEC=30`): `_get_mode_throttled()` cached `settings.block_p_llm_mode` für 30s. Mode-Wechsel wirkt nach <30s. Bei Wechsel `llm_worker.mode_changed from=… to=…` geloggt.
- **Budget-Check-Cache** (`BUDGET_CHECK_INTERVAL_SEC=60`): `_budget_ok_throttled()` cached Budget-OK für 60s und ruft `maybe_reset_budget` im selben Intervall. Trade-off: bei Budget-Erschöpfung mid-Cycle bis 60s weiter Job-Pickup — paar % Overshoot statt stundenlanger Free-Pass.
- **Idle-Backoff** (`IDLE_BACKOFF_MAX_SEC=30`, `IDLE_BACKOFF_FACTOR=1.5`): bei leerer Queue wächst Sleep exponentiell von `_poll_interval()` (2s) bis 30s-Cap. Erfolgreicher Pickup resettet sofort → Job-Latency bleibt < 2s bei aktiver Queue.

Erwartete Idle-SQL-Last Steady-State: ~2 Queries/Minute (Stale-Reaper + Heartbeat) statt vorher ~126.

**Test-Helper** `invalidate_throttle_caches_for_tests()` neu — Tests die Mode mid-test wechseln rufen ihn explizit zwischen `_tick()`-Aufrufen.

**CI-Workflow-Fix** in `.github/workflows/release.yml`: arm64-Build temporär abgeschaltet (QEMU-Emulation 5-10× langsamer als nativ); GHA-Cache mit expliziter `scope=release` damit Tag-Builds den Cache über Tag-Grenzen teilen. Erwartete Build-Time von ~7m (v0.9.4) auf ~2-3m beim ersten Run, ~30-60s bei Folge-Tag-Builds mit unverändertem `pyproject.toml`. v0.9.6-Build wird der erste „cold" Run mit `scope=release`-Cache-Write, ab v0.9.7-Tag sollten die `CACHED`-Marker im Build-Log sichtbar werden.

**1609 Tests grün** (+6 v0.9.6: Backoff-Exponential, Reset-bei-Pickup, Mode-Cache 30s, Mode-Refresh, Budget-Cache 60s, Idle-Tick-Backoff). Coverage 91%. `ruff check`/`ruff format --check`/`mypy app/`/`shellcheck agent/*.sh` PASS. Docker-Compose-Up nach Build: drei Container healthy, Worker-Log zeigt initial `llm_worker.mode_changed from=None to=observation` (initialer DB-Read), danach keine weiteren Mode-Queries in den folgenden 30s.

**Operator-Realbetriebs-Impact:** Worker-CPU bei leerer Queue erwartet drastisch runter (von 219 mCPU auf < 50 mCPU). Mode-/Budget-Änderungen werden mit max 30/60s Latenz wirksam — operativ irrelevant.

**Bewusst weggelassen:** weitere Hot-Path-Optimierungen (Stale-Reaper-Throttle, Heartbeat-Cadence-Tuning) — aktueller Befund war primär die 2s-Polling-Cadence der vier SQL-Calls, das ist jetzt addressiert. Falls Idle-CPU nach Deploy noch zu hoch ist, py-spy-Profiling als nächster Schritt.

---

**MVP + UI v2 + ADR-0016-Refinement + ADR-0017-Pane-Konsolidierung + ADR-0018-Server-Detail-Redesign + ADR-0019-Polling + ADR-0020-Dashboard-Redesign + ADR-0021-Bootstrap-Installer + ADR-0022-Risk-Engine + ADR-0023-LLM-Risk-Reviewer + Block-P-Iteration v0.9.3 + Pass-1-Batching v0.9.4 + Worker-Stability v0.9.5 — v0.9.5 (2026-05-20).**

**Patch v0.9.5 abgeschlossen 2026-05-20 — Worker-Stability-Hotfix nach k8s-Pod-Restart-Loop und blindem Debug-Log.** Branch `fix/v0.9.5-worker-stability`. Vier zusammenhängende Mini-Fixes, keine Schema-Migration, Spec-Files unverändert:

- **(1) LABEL_PATTERN-Spec-Drift behoben.** `app/services/llm_risk_reviewer.py::LABEL_PATTERN` von `^[a-z0-9][a-z0-9_-]{0,63}$` auf `^[a-z0-9][a-z0-9._-]{0,63}$` (mit Punkt — wie in Spec `docs/blocks/P-evidence/prompt-pass1-final.md` Z. 63). Punkt ist legitim für Distro-Pakete mit Version im Paketnamen (z.B. `linux-modules-5.15.0-177-generic`, `libstdc++6.0.30`).

- **(2) Debug-Log bei Validation-Errors zeigt jetzt die echte LLM-Response.** `LLMInvalidResponseError` trägt optionales `.meta`-Attribut; `LLMRiskReviewer.pass1_detect_groups`/`pass2_evaluate_groups` hängen das Meta-Dict (raw_content/extracted_json/reasoning_field/usage/prompts) bei Validator-Wurf an die Exception. Worker liest `exc.meta` und persistiert komplett — Operator-Blindheit beim Debug-Log-Inspect behoben.

- **(3) Heartbeat-Daemon-Thread.** Bisher Heartbeat im `_tick()` geschrieben → blockierte 60-120s im LLM-Call → k8s-livenessProbe (`HEARTBEAT_MAX_AGE_SEC=30` × `failureThreshold=3 × periodSeconds=30=90s`) killte den Pod → Job blieb in `in_progress`. Jetzt: `_heartbeat_loop` läuft als Daemon-Thread, schreibt alle 10s unabhängig vom Tick. `main()` startet (`_start_heartbeat_thread`) vor der Schleife, bei `_shutdown` graceful join mit 5s Timeout (`_stop_heartbeat_thread`). K8s/Docker-Compose-Probe-Settings unverändert.

- **(4) Worker-Logging-Erweiterung.** Phasen-Logs für jede Pass-1/Pass-2-Phase (`pass1_started`/`pass2_started`/`llm_call_started`/`llm_call_completed`/`llm_call_failed`/`pass1_persist_done`/`pass2_cache_lookup`/`pass2_cache_hit_applied`/`pass2_persist_done`/`budget_exhausted`/`stale_reaped_count`/`heartbeat_thread_started`+`_stopped`), Token-Counts via neuem `_usage_tokens(meta)`-Helper aus `meta.usage`.

**1603 Tests grün (+12 neue v0.9.5-Tests: 2 Heartbeat-Thread-Lifecycle, 2 Validator-Meta-Attach, 1 Worker-Debug-Log-Insert-bei-Validation-Error, 2 LABEL_PATTERN-Punkt-Accept + Regression, 4 Logging-Marker-Smoke + Edge-Case-Coverage), Coverage 91 %.** `ruff check`/`ruff format --check`/`mypy app/`/`shellcheck agent/*.sh` PASS. `docker compose up -d --build` startet alle drei Container healthy, neues Log `heartbeat_thread_started interval_sec=10.0` direkt nach Start sichtbar.

**Operator-Realbetriebs-Impact:** Pod-Restart-Loop in k8s gestoppt; Heartbeat-Thread hält Worker auch während 60-120s-LLM-Calls "alive". Operator sieht im Debug-Log-Tab jetzt die echte LLM-Response auch bei Validator-Errors (vorher leere Bodies). Pass-1 mit legitim-versionierten Distro-Paket-Labels (Kernel-Module-Bundles) läuft durch. **Bewusst weggelassen:** Spec-Härtung für Kernel-Paket-Labels (Regel-1 "no versions" vs Regel-3 "package_name") — Operator-Entscheidung, separate ADR falls Group-Library mit `linux-modules-*`-Versionen zu unübersichtlich wird. **Tag `v0.9.5` zu setzen.**

---

**MVP + UI v2 + ADR-0016-Refinement + ADR-0017-Pane-Konsolidierung + ADR-0018-Server-Detail-Redesign + ADR-0019-Polling + ADR-0020-Dashboard-Redesign + ADR-0021-Bootstrap-Installer + ADR-0022-Risk-Engine + ADR-0023-LLM-Risk-Reviewer + Block-P-Iteration v0.9.3 + Pass-1-Batching v0.9.4 — v0.9.4 (2026-05-20).**

**Patch v0.9.4 abgeschlossen 2026-05-20 — Hotfix für 400-BadRequestError aus dem Worker** (`Requested input length 231381 exceeds maximum input length 131071`). Branch `fix/v0.9.4-pass1-batching`. Vier zusammenhängende Mini-Fixes, keine Schema-Migration:

- **(1) Pass-1-Batching mit Affinity-Sort.** `app/api/scans.py` Block-P-Hook splittet ungroupierte Findings in Batches à `llm_pass1_findings_per_batch` (Default 100, range 5..2000, ENV-konfigurierbar via `SECSCAN_LLM_PASS1_FINDINGS_PER_BATCH`) nach deterministischem Affinity-Sort im neuen Helper `app/services/group_matcher.py::affinity_sort_for_pass1` (Sort-Key `(target_path-Top-3-Segments, package_name, id)`). Pass-2-Jobs hängen via `depends_on` am letzten Pass-1-Job des Batches — Single-Concurrency-Worker arbeitet `llm_jobs` ORDER BY created_at ab, alle Pass-1-Batches sind also `done` bevor Pass-2 startet. Cross-Batch-Konsistenz für Group-Labels über Label-Idempotenz (`temperature=0` aus Fix 2) plus Backend-Merge in `_persist_pass1_groups`.

- **(2) `temperature=0` im LLM-Call.** `chat_completion_json_with_meta` in `app/services/llm_risk_reviewer.py` setzt jetzt explizit `temperature=0` — Spec-Drift behoben, P-evidence-Files hatten das immer vorgesehen.

- **(3) `BadRequestError`/`APIStatusError` als LLM-Fehler klassifiziert.** `app/workers/llm_worker.py::_classify_error` und die `is_timeout_or_llm`-Marker-Liste erkennen OpenAI-SDK-Fehler jetzt als `llm_api_error` (statt `other`). Audit-Metadata und Worker-Log markieren entsprechend.

- **(4) Docker-Compose-Healthcheck-Timeout 5s → 10s** für den `secscan-llm-worker`-Container (`docker-compose.yml`). Pre-existing seit v0.9.1: Cold-Python-Probe inkl. DB-Connect dauert unter ARM64 ~6s, 5s waren zu knapp. Heartbeat-Cadence intern (10s) und Healthcheck-Schwellwert (30s) unverändert.

**1591 Tests grün (+20 neue v0.9.4-Tests: 4 Affinity-Sort, 5 Pass-1-Batching mit Audit-Count und Pass-2-depends_on-Verifikation, 2 `temperature=0`-Asserts, 9 Error-Classification). Coverage 91 %** (Threshold 85 %). `ruff check`/`ruff format --check`/`mypy app/`/`shellcheck agent/*.sh` PASS. `docker compose up -d --build` startet drei Container alle healthy nach ~30s, `/healthz` 200. Image-Size unverändert ~192 MB.

**Operator-Impact** bei 9000-Findings-Flotte (User-Beobachtung 2026-05-20): vorher 1 Pass-1-Job mit 231k Tokens → 3× 400 → `status='failed'`, kein Block-P-Output; **nachher** ~90 Pass-1-Jobs à 100 Findings (~25k Tokens je Job) sequenziell sauber, ApplicationGroups inkrementell aufgebaut via Label-Merge. Cost-Schätzung bei DeepInfra-Preisen: ~$0.30 für den initialen Re-Eval, danach trägt der GroupMatcher-Cache.

**Operator-Diagnose-Skript** `probe_response_format.py` im Repo (analog `probe_gpt_oss.py` im `ruff.toml`-Exclude) — testet `response_format`-Varianten gegen DeepInfra mit vollem Error-Body-Print, dokumentiert dass alle vier Varianten 200 OK liefern (das war NICHT der 400-Grund).

**Spec-Files unverändert** (ADR-0023 Update v0.9.3, P-evidence/prompt-pass{1,2}-final.md) — v0.9.4 ist reines Verteilungs-/Latenz-Fix ohne Bewertungs-Semantik-Änderung. **Tag `v0.9.4` zu setzen.**

---

**MVP + UI v2 + ADR-0016-Refinement + ADR-0017-Pane-Konsolidierung + ADR-0018-Server-Detail-Redesign + ADR-0019-Polling + ADR-0020-Dashboard-Redesign + ADR-0021-Bootstrap-Installer + ADR-0022-Risk-Engine + ADR-0023-LLM-Risk-Reviewer + Block-P-Iteration v0.9.3 — v0.9.3 (2026-05-20).**

**Patch v0.9.3 abgeschlossen 2026-05-20 — sieben zusammenhängende Block-P-Anpassungen** (kein neuer Block, ein konsolidiertes Patch-Release mit einer einzigen Alembic-Migration `0007_block_p_v093.py`). Branch `feat/v0.9.3-block-p-iteration`. Reviewer **APPROVE** (alle 29 DoD-Items grün, drei kosmetische Doku-NOTES adressiert). Security-Auditor **ACCEPTABLE WITH NOTES → APPROVED** (alle acht Pflicht-Punkte PASS, Privacy-Disclaimer im Debug-Log-Tab als Hotfix nachgereicht). **1571 Tests grün (+94 vs. v0.9.0; +81 neue v0.9.3-Tests in 5 Buckets plus 13 Fix-Anpassungen für Tuple-Return-Refactor und neue Pass-2-action_type-Pflicht in Adversarial-/Worker-Tests). Coverage **91 %** (Threshold 85 %). `ruff check`/`ruff format --check`/`mypy app/` (70 source files)/`shellcheck agent/*.sh` PASS. Alembic-Roundtrip (0006 ↔ 0007) PASS gegen Postgres-17-Container. `docker compose up -d --build` startet drei Container (`db`, `app`, `secscan-llm-worker`) healthy nach ~25s, `/healthz` 200, `/settings/llm-reviewer` 302 (Login-Redirect erwartet). Image-Size unverändert ~192 MB (kein Lib-Hinzufügen, nur Code-Erweiterung).

**Was die sieben Punkte tatsächlich umsetzen:**

**(1) Pass-1-Prompt-Iteration + Modell-Default-Wechsel.** Nach zwei Test-Runden mit sieben LLM-Modellen (DeepSeek-V3.2/V4-Flash, MiniMax-M2.5, Qwen3-Instruct/Thinking, Phi-4, GPT-OSS-120B) bestand `openai/gpt-oss-120b` alle zehn Test-2-Kriterien fehlerfrei. Wechsel des Block-P-Default von DeepSeek-V3 (Block-G-Wrapper-Erbe) auf GPT-OSS-120B (Apache 2.0, self-hostbar — DSGVO-Operator-Option ohne Code-Change). Pass-1-System-Prompt erweitert um sieben Härtungs-Aspekte: Cross-Language-Bundle-Regel, Multi-Path-Application-Regel, Trailing-Slash-Pflicht, Defense-in-Depth-Vorgabe, Anti-Generic-Pattern-Liste, Halluzinations-Schutz, Bundle-vs-Library-PURL-Unterscheidung. Volltext unter [`docs/blocks/P-evidence/prompt-pass1-final.md`](P-evidence/prompt-pass1-final.md).

**(2) Tags raus aus allen LLM-Eingaben.** Server-Tags sind User-vergebene Freitext-Labels (Block D) ohne garantierte Semantik. Block P verlässt sich für Exposure-Bestimmung ausschließlich auf objektive Listener-Adressen aus dem Host-Snapshot. `_render_pass2_prompt()` strippt Tags aus dem Host-Context-Block. Spätere ADR kann explizite Server-Flags für Exposure-Override einführen (`network_exposure`-Enum etc.), das wäre eigenes Schema mit garantierter Semantik.

**(3) Risk-Band-Reduktion auf vier aktive Werte.** `mitigate` wird deprecated. Begründung: Trennlinie zwischen `escalate` (KEV+exposed) und `mitigate` (HIGH+exposed+no-patch) hat sich operativ nicht als hilfreich erwiesen — beide kommunizieren „sofort handeln", unterscheiden sich nur in der Aktions-Art. Aktions-Art wandert in den `risk_band_reason`-Text. Neues Mapping: escalate = KEV+exposed ODER HIGH/CRITICAL+exposed+no-patch; act = HIGH/CRITICAL+exposed+has-patch+not-KEV; monitor/noise unverändert. `mitigate` bleibt als Enum-Wert für historische Daten und Validator-Backward-Compat, LLM produziert ihn nicht mehr. Bestehende `mitigate`-Findings werden bei nächstem Re-Ingest natürlich neu klassifiziert.

**(4) `action_type` + `group_kind` + „Was zu tun ist"-UI-Sektion.** Die 4-Band-Reduktion aus (3) löst nur die Dringlichkeits-Frage — Operator sieht escalate-Findings aber muss Reason-Text lesen um zu wissen ob Patch oder Mitigation fällig ist. Zwei neue Group-Felder schließen die Lücke: `action_type` (`patch`/`mitigate`/`watch`/`none`/`investigate`, vom LLM in Pass 2 gesetzt) und `group_kind` (`os_package`/`application_bundle`, deterministisch beim Group-Insert aus `match_rules` derived). Neue Server-Detail-UI-Sektion „Was zu tun ist" zwischen Sub-Line und Host-Snapshot mit bis zu fünf Cards: ESCALATE · Distro patchen (mit Group-Label-Liste), ESCALATE · App-Update einspielen (mit App-Label-Liste), ESCALATE · Kein Patch — mitigieren (mit Group-Label-Liste), ACT · Distro patchen (nur Counter, keine Liste — bei act zu viel Visual-Noise), ACT · App-Update einspielen (nur Counter). Sektion wird komplett ausgeblendet wenn keine Group mit `risk_band ∈ {escalate, act}` existiert. Drill-down per `<details>`-Tag, default collapsed, expandiert die Findings-Tabelle für die zugehörigen Groups.

**(5) Reasoning-Block-Handling im Response-Parser.** GPT-OSS-120B (neuer Default ab v0.9.3) ist ein Reasoning-Modell und produziert einen `analysis`-Channel (Harmony-Format) bevor das eigentliche JSON kommt. Beobachtetes Pass-2-Token-Volumen: ~1400 Tokens für 5 Groups, davon ~900 Tokens Reasoning. Je nach Provider-Adapter (DeepInfra, Groq, vLLM, Ollama) landet der Reasoning-Block in `message.reasoning` (separat), wird komplett gestrippt oder erscheint vor dem JSON in `message.content`. Letzteres würde unser `json.loads()` zerschießen. Defensive Extraktion in `_extract_json_from_response()` (neu): drei Schichten — Reasoning-Wrapper-Patterns (Harmony, `<think>`, `[REASONING]`), Markdown-Code-Fences, Greedy-Brace-Fallback. Helper läuft IMMER zwischen `message.content` und `json.loads()`, schützt vor Provider-Wechsel. Plus: optionales `message.reasoning`/`reasoning_content`-Feld wird gelesen und im Debug-Log separat festgehalten. Token-Budget-Default `LLM_TOKEN_BUDGET_DAILY` von 1M auf 2M angehoben wegen beobachteter Reasoning-Token-Last.

**(6) Listener-Interpretation defensiv + LLM-Reasoning statt Hartlogik.** Operator-Feedback nach Iteration 5: RFC1918-Listener (10.x/172.16.x/192.168.x) als „internal only" auf monitor zu schieben ist Wunschdenken — realistische Bedrohungsvektoren (Lateral Movement, Port-Forward, Reverse-Proxy, VPN, kompromittierte Endpoints im selben Netz) machen jede spezifische Bind-Adresse potenziell exposed. Wir können aus Listener-Daten nicht beweisen dass etwas nicht erreichbar ist. Nur Loopback (`127.0.0.1`/`::1`) ist beweisbar nicht netzwerk-erreichbar. Drei Klassifikations-Zustände: PUBLIC-EXPOSED (`0.0.0.0`/`::` ODER spezifische IP inkl. RFC1918), LOOPBACK-ONLY (nur `127.0.0.1`/`::1`), NO-LISTENER (aktive Komponente ohne Socket). LLM darf via Angriffsketten-Reasoning UPGRADE/DOWNGRADE-Korrekturen anwenden (LOOPBACK-Library via exposed Service erreichbar → upgrade; PUBLIC-EXPOSED mit nachweisbar nicht-erreichbarem Code-Pfad → downgrade). monitor wird operativ enger. Default für aktive Komponenten mit Patch ist jetzt act. Reason-Cap zurück auf 256 Chars (Reasoning-Kette braucht Platz). Test-Case-Auswirkung: postgresql auf 10.0.0.5:5432 → act statt monitor.

**(7) LLM-Debug-Log-Tabelle.** Neue Tabelle `llm_debug_log` persistiert pro Pass-1/Pass-2-Job das Request/Response-Tupel für Operator-Inspektion. Eviction kombiniert Count- und Time-Cap (`LLM_DEBUG_LOG_MAX_ROWS=500`, `LLM_DEBUG_LOG_MAX_AGE_DAYS=14`), Per-Row-Body-Cap 64 KB. Eviction-Sub-Tick im Worker alle 10 Minuten. UI: neuer Sub-Tab unter `/settings/llm-reviewer` mit den letzten 50 Einträgen plus Drill-down auf JSON-Bodies.

ADR-0023 mit Update-Sektion v0.9.3 für alle sieben Punkte (Quelle der Wahrheit). Code-Touchpoints — **neu:** `app/services/llm_prompts.py` (Verbatim-Konstanten `PASS1_SYSTEM_PROMPT` und `PASS2_SYSTEM_PROMPT` aus den zwei `docs/blocks/P-evidence/prompt-passN-final.md`-Files), `app/services/llm_debug_log.py` (`record()` mit Per-Body-64KB-Cap, `evict_old()` mit Time+Count-Cap), `alembic/versions/0007_block_p_v093.py` (konsolidierte Schema-Migration mit `action_type`+`group_kind`-CheckConstraints + Backfill + `llm_debug_log`-CREATE + drei Indizes + FK-ON-DELETE-SET-NULL), `app/templates/servers/_action_needed_section.html` (5-Card-Sektion mit `<details>`-Drill-down, ESCALATE-Cards mit Label-Liste +N-more, ACT-Cards nur Counter), `app/templates/settings/llm_debug_log.html` (Sub-Tab mit Privacy-Disclaimer-Notice). **Geändert:** `app/services/llm_risk_reviewer.py` (Prompt-Re-Export aus `llm_prompts`, neuer `_extract_json_from_response()`-Helper mit drei Defense-Schichten, neuer `_extract_reasoning()`-Helper inkl. `model_extra`-Bucket-Pfad für DeepInfra-GPT-OSS, neuer `chat_completion_json_with_meta()`-Tuple-Return-Helper, Pass-1/Pass-2-Methoden jetzt Tuple-Return mit Meta-Dict, `action_type`-Pflichtfeld auf `Pass2Evaluation`, `ALLOWED_BAND_ACTION_COMBOS`-Whitelist plus Legacy-`mitigate`→`escalate`-Mapping mit structlog-Warning, `_render_pass2_prompt` ohne Tags), `app/workers/llm_worker.py` (Tuple-Unpacking, `_record_pass_debug_log()`-Hook bei Success/Error, Eviction-Sub-Tick alle 10min, `derive_group_kind`-Calls in `_persist_pass1_groups`, `_apply_pass2_to_group(action_type=...)`), `app/models.py` (`ApplicationGroup.action_type`+`group_kind` mit CheckConstraints, `LLMRiskCache.action_type`, neue `LLMDebugLog`-Klasse mit drei Indizes), `app/services/group_matcher.py` (`derive_group_kind`-Helper), `app/services/llm_cache.py` (`action_type`-Spalte gelesen/geschrieben), `app/config.py` (`llm_token_budget_daily` 1M→2M, drei neue Debug-Log-Konstanten), `app/views/settings.py` (Route `/settings/llm-reviewer/debug-log` + `_llm_reviewer_stats.active_model`-Indikator), `app/views/llm_settings.py` (DeepInfra-Preset-Modell-Default auf `openai/gpt-oss-120b`), `app/views/server_detail.py` (`_build_action_sections()`-Helper, im `show`-Handler aufgerufen), `app/templates/servers/detail.html` (Include direkt vor Host-Snapshot), `app/templates/settings/llm_reviewer.html` (Sub-Tab-Switcher + "Aktives Modell"-Indikator). **Test-Buckets:** A — Prompt-Marker (14 Tests), B — `_extract_json_from_response` (7), C — `_extract_reasoning` (6), D — Combo-Whitelist (18), E — Legacy-`mitigate`-Mapping mit Warning (2), F+G+H — Migration-Roundtrip + `group_kind`-Backfill + FK-ON-DELETE-SET-NULL (19), I — Debug-Log Body-Cap + Eviction (13), J — "Was zu tun ist"-View-Tests inkl. Card-Order und +N-more-Truncation (10), K — GPT-OSS-Harmony-Mock-Smoke (2). Reviewer-Re-Open-Trigger (alle nicht-blockierend, Folge-PR-Kandidaten): CHANGELOG-Stilkonsolidierung (zwei `### Added`-Blöcke nacheinander), Migrations-Namen-Platzhalter `XXXX_block_p_v093.py` → `0007_block_p_v093.py`, STATE.md-Inkonsistenz „fünf vs. sieben Punkte" (mit dem v0.9.3-Update-Commit erschlagen). Security-Auditor-Re-Open-Trigger: README-Doku-Hinweis zur DSGVO-Betrachtung der Host-Snapshot-Felder die der LLM-Provider beim Pass-2-Call sieht (Listener-Adressen, Process-`comm`, Kernel-Module, aktive Services).

Block P (ADR-0023) abgeschlossen: LLM-basierte Final-Bewertung pro
Application-Group als Two-Pass-Architektur, asynchron in eigenem
Worker-Container. Pass 1 (`group_detection`) erzeugt aus ungroupierten
`pending`-Findings neue `application_groups`-Eintraege mit wieder-
verwendbaren Match-Patterns (`path_prefixes` / `pkg_name_exact` /
`pkg_name_glob` / `pkg_purl_pattern`). Pass 2 (`risk_evaluation`)
bewertet pro Group das `risk_band` mit Server-Kontext (compact-form
ohne PIDs/args/timestamps, ~2-4K Tokens). Worker `secscan-llm-worker`
laeuft in eigenem Container (entrypoint `python -m app.workers.llm_worker`,
keine eingehenden Ports, nur DB-Connect + LLM-Provider-Egress), Single-
Concurrency-Default, 2s-Polling auf `llm_jobs` mit
`SELECT FOR UPDATE SKIP LOCKED`, Dependency-Check (Pass-2-Jobs warten
auf Pass-1 via `depends_on`), Stale-Reaper alle 60s reset `in_progress`-
Jobs aelter als 10 min auf `queued` mit exponential backoff (max 3
Attempts → `failed`). Heartbeat alle 10s in `settings.llm_worker_heartbeat_at`,
Healthcheck-Skript `app/workers/healthcheck.py` exit 0/1 abhaengig von
< 30s Heartbeat-Alter. Two-Level-Caching: Pass-1-Cache *ist* die
`application_groups`-Library (deterministischer Pattern-Match via
`GroupMatcher`-Singleton mit `_lock`); Pass-2-Cache als
`llm_risk_cache`-Tabelle mit SHA256-Key ueber
`(group_id, group_findings_fp, cve_data_fp, server_context_fp)`,
TTL 30 Tage + LRU bei > 100K Rows. Feature-Flag `BLOCK_P_LLM_MODE`
(Settings-Spalte, CheckConstraint `off`/`observation`/`live`) fuer
stufenweise Inbetriebnahme. `observation`-Mode schreibt
`would_call`-Marker statt echter LLM-Calls — ermoeglicht
Cache-Befuellung und Cost-Math vor Scharfschaltung. Token-Budget
`SECSCAN_LLM_TOKEN_BUDGET_DAILY` (Default 1M) mit 00:00-UTC-Reset;
sowohl Pass-1- als auch Pass-2-Verbrauch wird verbucht (post-Security-
Auditor-Hotfix). Bei Budget-Erschoepfung: Worker pausiert, einmaliges
Audit `llm.budget_exhausted` pro Reset-Zyklus. UI: Findings auf
Server-Detail werden zukuenftig nach `application_group_id` gruppiert
(Group-Cards mit Label/Risk-Pill/Findings-Count/Reason-Mono-Box/
Worst-Finding-Anker/Drill-down-`<details>`), default-expanded ab
`pending` aufwaerts, default-collapsed fuer `monitor`/`noise`.
Ungroupierte Findings landen in „Pending grouping"-Sektion am Ende.
`evaluating`-State mit Spinner solange Worker arbeitet. Dashboard-
Findings-Tabelle bekommt `Group`-Spalte (zwischen Risk und Severity)
und `application_group`-Filter-Select. Settings-Tab `/settings/llm-reviewer`
zeigt Mode + Queue-/Library-/Cache-/Token-Stats + Worker-Liveness mit
Master-Key-gated Mode-Wechsel und DSGVO-Privacy-Notice (Modal mit
Confirm-Checkbox) beim Wechsel auf `live`; Re-queue-Backlog-Button
fuer observation→live-Transition. LLM-Output-Validierung strikt:
JSON-Schema, Label-Regex `^[a-z0-9][a-z0-9_-]{0,63}$`, Vollstaendigkeits-
Check Pass-1 (jedes Input-Finding in genau einer Group ODER
`ungrouped`), `risk_band ∈ {escalate,act,mitigate,monitor,noise}` —
`pending`/`unknown` LLM-verboten via Pydantic-Literal + Backend-Set-Check
+ DB-CheckConstraints (Defense-in-Depth dreifach). `worst_finding_id`
muss Group-Mitglied sein, `reason` ≤ 256 chars, NUL-frei. Pattern-
Defensiv-Trim gegen Injection (`/etc/passwd`-Pfade technisch erlaubt
aber harmlos; `*`-only, `"/"`-allein, leerer String, Non-ASCII werden
gedroppt). LLM-Output ueberschreibt Pre-Triage-Bands nicht direkt —
Pass 2 setzt `Finding.risk_band_source='llm'`, Block-O-Pre-Triage-Loop
im Ingest skipt diese Findings beim Re-Ingest. Provider-Wiederverwendung
des Block-G-LLM-Wrappers (DeepSeek-V3 default). **Bewusst weggelassen:**
konkrete Update-Befehle in Reason-Texten, konkrete Versions-Empfehlungen,
manueller Risk-Band-Override per UI, manueller Group-Merge/Split per UI,
Multi-Provider-LLM-Switch fuer Risk-Reviewer, Detail-LLM-Begruendung
pro Finding (Reasoning lebt auf Group-Ebene), Daily-Re-Eval-Job fuer
stale Cache-Eintraege, Group-Trend-Reports, DSGVO-Notice in
README/Bootstrap-Installer (nur Settings-Tab beim Mode-Wechsel) —
alle in §17 nachgetragen. MIN_AGENT_VERSION bleibt 0.1.0.

1477 Tests gruen (vorher 1226; +251 neue Phase-A-bis-H-Tests: 33 Phase A
+ 46 Phase B + 21 Phase C + 8 Phase D + 25 Phase E + 13 Phase F +
0 Phase G + 105 Phase H). Coverage **91.70 %** (Threshold 85 %); 421
adversarial PASS (+95 Block-P-Cases: Pass-1-Halluzination/Missing/
Label-Regex, Pass-2-Halluzination/Invalid-Band/Worst-Not-In-Group/
NUL-Reason, Worker-Race-SKIP-LOCKED, Worker-Corrupted-Payload,
Cache-Key-Collision). Block-P-Module-Coverage: `group_matcher` 97 %,
`llm_cache` 97 %, `llm_fingerprints` 100 %, `llm_risk_reviewer` 87 %,
`llm_budget` 95 %, `workers/llm_worker` 83 %, `workers/healthcheck` 92 %.
`ruff check`/`ruff format --check`/`mypy app/` (68 source files)/
`shellcheck agent/*.sh` PASS. Alembic-Roundtrip (0004 ↔ 0005 ↔ 0006)
PASS gegen Postgres-17-Container. `docker build` + `docker compose up
--build` startet drei Container (`db`, `app`, `secscan-llm-worker`)
alle healthy nach ~30s, `/healthz` 200, `/settings/llm-reviewer` 302
(Login-Redirect erwartet). Image-Size **192 MB** (Delta +1 MB vs.
v0.8.0 — Worker-Modul + Healthcheck). Reviewer APPROVE; Security-
Auditor **ACCEPTABLE WITH NOTES → SECURITY APPROVED** (alle 10 Pflicht-
Punkte PASS: LLM-Output-Validation strikt, pending/unknown dreifach
verboten, Worker-Container ohne eingehende Ports, Mode-Wechsel master_key-
gated mit Audit, Token-Budget-Cap funktioniert, `risk_band` hat keinen
direkten User-Input-Pfad, Worker-Race mit SKIP-LOCKED bewiesen,
DSGVO-Notice via Frontend-Modal mit Confirm-Checkbox plus Master-Key-
Backend-Gate, Pattern-Defensiv-Trim gegen Injection, Cache-Key
deterministisch und Reihenfolge-sensitiv. **Pre-Tag-Hotfix:**
Pass-1-Token-Buchung in `_do_pass1` ergaenzt — Tages-Cap deckt jetzt
auch Pass-1-LLM-Calls). Drei Re-Open-Trigger als optionale Folge-PRs:
Worker auf structlog umstellen, `ON CONFLICT DO NOTHING` in
`_persist_pass1_groups` fuer Multi-Worker-Skalierung, Setup-Wizard-
DSGVO-Notice mit konkreter Feld-Liste. Tag `v0.9.0` zu setzen.
## Status

**MVP + UI v2 + ADR-0016-Refinement + ADR-0017-Pane-Konsolidierung + ADR-0018-Server-Detail-Redesign + ADR-0019-Polling + ADR-0020-Dashboard-Redesign + ADR-0021-Bootstrap-Installer + ADR-0022-Risk-Engine — v0.8.0 (2026-05-18).**

Block O (ADR-0022) abgeschlossen: Deterministische Pre-Triage-Risk-
Engine plus Host-Snapshot-Sammlung plus CVSS-Vendor-Resolver plus
Risk-zentrisches UI-Redesign. Pro Finding ein Band aus
`{noise, monitor, pending, unknown}` allein aus max-Severity-aller-
Provider + EPSS + KEV (defensive Cuts: KEV → pending,
max-sev >= HIGH → pending, EPSS >= 0.1 → pending, MEDIUM → monitor,
sonst noise; ohne Snapshot → unknown). LLM-Final-Bewertung
(`escalate`/`act`/`mitigate`) bleibt out-of-scope und kommt in Block P;
`risk_band_source = "llm"` ueberlebt Re-Ingest. Agent v0.3.0 sammelt
vier Host-State-Bloecke (Listener via `ss`/Fallback `netstat`,
Prozesse via `ps`, Kernel-Module via `lsmod`, systemd-Services) in
sourcabler Lib `agent/lib_host_state.sh`, mit `tools_available`/`gaps`-
Tracking und ASCII-only-Filterung (`LC_ALL=C` + Non-ASCII-Drop).
Backend persistiert die vier Bloecke truncate+insert pro Server in
neuen Tabellen `server_listeners`/`server_processes`/
`server_kernel_modules`/`server_services`. `host_state.parse_failed`
ist resilient: Pydantic- oder SQLAlchemy-Fehler verwirft den Snapshot,
Findings-Ingest laeuft trotzdem, Pre-Triage faellt auf
`snapshot_available=False`. Sechs neue Finding-Spalten (`risk_band`,
`risk_band_reason`, `risk_band_source`, `risk_band_computed_at`,
`severity_by_provider` JSONB, `vendor_status`) plus
`Server.host_state_snapshot_at` plus zwei Indizes (partial-`open` +
server_risk_band) in Migration 0004. UI: drei-Tier-Dashboard
(zwei Action-Required-Cards prominent, sieben Risk-Band-Pills mit
Escalate-Pulse, Severity-Strip kompakt), Server-Detail-Header mit
drei-Varianten-Action-Pill (rot Action-needed mit Sub-Counter / gruen
Safe / grau Update-agent), neue `<section id="host-snapshot">` direkt
unter dem Header (default-collapsed, max 5 Listener inline mit Tooltip
auf `process.args` — Jinja-Autoescape verifiziert via XSS-Adversarial),
Findings-Tabelle gruppiert nach `risk_band` mit Section-Headers
(default-expanded ab `pending` aufwaerts, default-collapsed fuer
monitor/noise/unknown), Bulk-Ack-Noise-Button mit Modal und Server-
Side-`risk_band_filter="noise"`-Filter im bestehenden Block-F-Endpoint
(eingeschleuste non-noise-IDs werden gedroppt und in
`skipped_non_noise_ids` der Response gelistet). Default-Sort wechselt
von `sev` zu `risk` mit `RISK_BAND_SORT_RANK` (70/60/50/40/30/20/10/
NULL=0); CVSS-Severity rutscht in den Tiebreak-Tail
(KEV → EPSS → CVSS-Rank → identifier_key). `severity_by_provider`
persistiert Trivys `VendorSeverity`-Map (max 16 Provider, ASCII-only,
numerische Severity-Werte 0..4 zu Strings normalisiert).
`vendor_status` haelt normalisierten Trivy-`Status`
(`affected`/`fixed`/`investigating`/`will_not_fix`/`eol`/
`not_affected`/`unknown`) — Block P wird das als LLM-Eingabe-Signal
nutzen. **Bewusst weggelassen:** LLM-Risk-Reasoning, Host-Snapshot-
Historisierung, manueller Risk-Override, Patch-Alter-Eskalation,
Exposure-Mapping als statisches Asset, OpenRC-/Alpine-Services,
Daily-Re-Eval-Job — alle in §17 nachgetragen. Privacy-Hinweis zu
Process-Args in ARCHITECTURE §9 mit DSGVO-Empfehlung dokumentiert
(README-Notice als optionaler Re-Open-Trigger vom Security-Auditor
benannt). MIN_AGENT_VERSION bleibt 0.1.0 — alte Agents weiter
akzeptiert, Findings landen in `risk_band="unknown"`.

1226 Tests gruen (vorher 992; +234 Block-O-Tests: 53 Phase A,
62+1 bench Phase B, 12 Phase C, 21 Phase D, 10 Phase E, 69 Phase G,
plus 6 angepasste Block-M/K-Tests). Coverage **92.42 %**
(Threshold 85 %); 326 adversarial PASS (+69 neue Block-O-Cases:
KEV/HIGH/EPSS-Kombinations-Tabellen, Pre-Triage-No-Snapshot-Safety,
Pre-Triage-No-LLM-Override, Host-State-XSS, Listener-Addr-Validierung
mit ipaddress-Modul, Host-State-Max-Lengths 10k-Reject, Bulk-Ack-
Noise-Strict). `ruff check` / `ruff format --check` / `mypy app/`
(60 source files) / `shellcheck agent/*.sh` PASS. Alembic-Roundtrip
(0004 ↔ 0003) PASS im Container. `docker build` + `docker compose up
--build` + `/healthz` PASS, Image-Size **191 MB** (Delta 0 MB vs.
v0.7.x — Engine ist reines Python). Reviewer APPROVE nach drei
mechanischen Fixes (ruff RUF003/S104/I001-Adversarial-Files,
ruff format, CHANGELOG-v0.8.0-Eintrag); Security-Auditor
**ACCEPTABLE WITH NOTES → SECURITY APPROVED** (alle 8 Pflicht-Punkte
PASS: Pre-Triage schluckt keine Eskalationen, unknown-Default
konservativ, Bulk-Ack-Server-Side-Filter unumgehbar, Pydantic-
Validatoren strikt fuer IP/Port/ASCII, risk_band hat keinen
User-Input-Pfad, alle Band-Bewegungen produzieren `risk.band_changed`,
DSGVO-Aspekt der Process-Args als bewusste MVP-Entscheidung
dokumentiert + Re-Open-Trigger benannt, LLM-Bands ueberleben
Re-Ingest). Tag `v0.8.0` zu setzen.

Block N (ADR-0021) abgeschlossen: Backend-gehosteter interaktiver
Bootstrap-Installer ueber `curl -fsSL .../install.sh | sudo bash`
mit sechs-Phasen-Wizard (Jinja-Template ~720 Bash-Zeilen, englische
TTY-UI, Master-Key silent via `/dev/tty`, Trivy-SHA256-Verifikation,
systemd-Timer plus Cron-Fallback, Unattended-Modus). Drei neue
Public-Endpoints `/install.sh`, `/agent/files/<name>`, `/agent/version`
in PUBLIC_PATHS-Allowlist. Veraltet-Indikatoren im Server-Detail-Header
(drei conditional Pills) und Sidebar-Server-Liste (`⚠`-Sub-Marker)
basierend auf `agent_version`/`trivy_version`/`trivy_db_updated_at`
gegen Code-Konstanten `MIN_AGENT_VERSION="0.1.0"`/
`MIN_TRIVY_VERSION="0.70.0"`/`TRIVY_DB_STALE_THRESHOLD_DAYS=7`.
Agent-Skript auf `0.2.0` mit `host.trivy_version` im Envelope und
`jq 'del(.Results[].Packages)'`-Strip (raw 4.95 MB → 400–700 KB,
Fallback auf ungestripped bei jq-Fehler). Fuenf neue Ursachen-Felder
pro Finding (`package_purl`, `target_path`, `result_type`,
`severity_source`, `vendor_ids`) extrahiert aus `Vulnerability.
PkgIdentifier`/`SeveritySource`/`VendorIDs`/`Result.Type`/`Target`.
UI-Sub-Zeile in beiden Findings-Tabellen mit Distro-Pill plus
Vendor-IDs fuer os-pkgs bzw. Library-Type-Pill plus Datei-Pfad in
Mono-Font fuer lang-pkgs, Fallback aus `package_name`-`@`-Split fuer
Alt-Daten (ADR-0011-Uebergangsformat). **Bewusst weggelassen:**
statisches Update-Befehl-Mapping — kommt als eigener LLM-basierter
Block nach v0.7.0.

992 Tests grün (vorher 884; +108 neue Block-N-Tests), Coverage
**92.16 %** (Threshold 85 %); 254 adversarial PASS (+14 Block-N-Cases:
Path-Traversal, no-secrets in /install.sh, outdated-Agent-Reject,
public-no-auth-Garantie, PURL-XSS, VendorIDs-Injection). `ruff check`
/ `ruff format --check` / `mypy app/` / `shellcheck agent/*.sh` PASS,
Alembic-Roundtrip (0003 ↔ 0002) PASS im Container,
`docker compose up --build` + `/healthz` + `/install.sh` + `/agent/
version` + `/agent/files/secscan-agent.sh` PASS, Image-Size 191 MB
(unveraendert vs. v0.6.x). Reviewer APPROVE nach `.dockerignore`-Fix
(`agent` aus der Exclude-Liste entfernt), Security-Auditor
ACCEPTABLE WITH NOTES (alle 8 Pflicht-Punkte PASS, zwei optionale
Doku-Notes: Rate-Limit auf `/install.sh`/`/agent/files/` als Reverse-
Proxy-Aufgabe + README-Hinweis dazu). Tag `v0.7.0` zu setzen.

**MVP + UI v2 + ADR-0016-Refinement + ADR-0017-Pane-Konsolidierung + ADR-0018-Server-Detail-Redesign + ADR-0019-Polling + ADR-0020-Dashboard-Redesign — v0.6.0 (2026-05-16).**

Block M (ADR-0020) abgeschlossen: Dashboard-Pane umgebaut auf KPI-Cards
mit 50-Tage-Sparklines (`Total`/`KEV`/`Critical`/`High`/`Stale-Server`,
filter-unabhaengig, klickbar als Quick-Filter) und eine cross-server
Findings-Triage-Tabelle mit Hybrid-Auto-Submit-Filter (`q`, `tag`,
`severity`, `status`, `kev_only`, `stale_only`, sortierbare Spalten
inkl. neuem `server`-Sort-Key, debounced 400 ms `q`-Keyup). Hartes Limit
200 Rows + Truncation-Notice mit CSV-Eskalation; CSV-Export cross-server
mit `Server`-Spalte und Formula-Injection-Mitigation. Bulk-Ack
wiederverwendet den Block-F-Endpoint cross-server. `/findings/search`
ersatzlos entfernt — Sticky-Sidebar-Such-Slot zeigt jetzt auf
`dashboard.index?q=...`. Alte Quick-Stats-Inline-Card, Filter-Bar mit
`Anwenden`-Button, Aufmerksamkeits-Sektion und dashed-border-Platzhalter
sind ersatzlos weg.

869 Tests grün, Coverage 91.78 % (Threshold 85 %); 224 adversarial Tests
grün. `ruff check`/`ruff format --check`/`mypy app/` PASS, Alembic-
Roundtrip PASS, `docker compose up --build` + `/healthz` PASS, Image-Size
191 MB. Reviewer APPROVE, Security-Auditor ACCEPTABLE WITH NOTES
(beide kosmetisch adressiert: Doc-Korrektur in `app/api/__init__.py` und
ilike-Metachar-Cleanup als optionaler Re-Open-Trigger dokumentiert).

Block L (ADR-0019) abgeschlossen: Dashboard-Live-Updates laufen jetzt
über HTMX-Polling statt SSE. `GET /events`, `EventBus` und der
in-process Publish-Hook im Scan-Ingest sind ersatzlos entfernt;
LLM-Chat-Streaming (`GET /chat/<id>/stream`) bleibt unverändert SSE.
Pane (`#dashboard-pane`) und Sidebar-Server-Liste (`#server-list` über
neue Route `GET /_partials/sidebar`) polen alle 10 s mit
`document.visibilityState === 'visible'`-Gating und `hx-swap="outerHTML"`.
Aktive Filter (`?severity=...`, `?tag=...`) bleiben über
`request.path` + optionaler `request.query_string` im Re-Fetch erhalten.

785 Tests grün, Coverage 92.35 % (Threshold 85 %); 177 adversarial
Tests grün. `ruff check`/`ruff format --check`/`mypy app/` PASS,
Alembic-Roundtrip PASS, `docker compose up --build` + `/healthz` PASS,
Image-Size 191 MB. `docker stats` Idle-CPU 0.04 % unter offenem Tab —
deutlich unter der ADR-0019-Schwelle.

Block K (ADR-0018) abgeschlossen: Server-Detail-View vollständig nach
dem dritten Design-Bundle (`S5lepfeL8MeibyHP1ojRbw`) umgebaut. Header
mit Hostname-Hashtag-Tags und Status-Pill-Reihe; HeaderStats mit
`text-[64px]` Total-Counter + Tendenz-Label + vier KPI-Kacheln mit
50-Tage-Sparklines; eigene Lebenszeichen-Sektion (`HeartbeatLarge`
height=56 + Meta-Grid); Severity-Trend-Sektion mit StackedBarChart;
Findings-Tabelle ohne Filter-Bar, mit sortierbaren Spalten-Headern
(server-side via `?sort=...&dir=...`), Mode-Segment-Toolbar,
Bulk-Select und mode-abhängigem CSV-Export.

797 Tests grün (+69 neue Block-K-Tests; 5 e2e SKIPPED ohne Backend).
`ruff check`/`ruff format --check` (Block-K-Outputs) + `mypy app/`
PASS, Alembic-Roundtrip PASS, `docker compose up --build` + `/healthz`
PASS. Performance-Bench Daily-Snapshots 10k Findings × 50 Tage
standalone ~80–100 ms (ADR-0018-Schwelle), unter Suite-Last
moderater Slack. Tag `v0.4.0` zu setzen.


## Aktueller Block

(keiner — Block V abgeschlossen 2026-05-23, Branch `feat/block-v-ui-performance` uncommitted; Commit + Merge auf User-Anweisung)

## Completed

- **TICKET-006 — Findings Cross-Server Bucket-View (ADR-0037)** · abgeschlossen 2026-05-24 · Branch `feat/ticket-006-findings-bucket-view` · Default-Gates **gruen** (ruff/format/mypy/pytest Default-Selektion). Vier Etappen umgesetzt (Service-Layer, View+Routes, Templates+Frontend, Cleanup+Doku), pro Etappe vom `reviewer`-Subagent APPROVED. **Was TICKET-006 geliefert hat:** `/findings` rendert eine Cross-Server Bucket-View nach `(Server, ApplicationGroup)` mit collapsed HTMX-Lazy-Cards; ein Pending-Bucket am Ende der Liste sammelt Findings ohne Group-Zuordnung cross-server. Neuer Service-Layer `app/services/findings_bucket_query.py` mit `list_buckets`/`pending_bucket_header`/`list_bucket_findings`/`resolve_bucket_to_finding_ids` (Single-Source-Filter-Helper). Drei neue Routes (`/findings/bucket`, `/findings/pending`, `/findings/bulk/acknowledge`). Bulk-Acknowledge unterstuetzt Bucket-Header-Selektion (ganzer Bucket auf einen Klick) plus Mix mit Einzel-Finding-IDs. Sort-Selector und Outer-Pagination entfallen ersatzlos. CSV-Export-Pfad unveraendert. **Nicht gemacht (out-of-scope, eigene ADR sobald Real-Daten den Bedarf zeigen):** `pg_trgm`/GIN-Index fuer ILIKE-Performance, Outer-Pagination auf Bucket-Ebene, Sub-Sortierung im Bucket per User-Wahl. **Aktion User:** Manual-Sanity-Check (Bucket-Render, Aufklappen, Bulk-Ack-Bucket-Header), dann Merge nach `main`.

- **V — Performance-Tuning UI-Views (ADR-0030)** · abgeschlossen 2026-05-23 · Branch `feat/block-v-ui-performance` · Default-Gates **grün** (ruff/format/mypy/pytest Default-Selektion **1442 passed**, 5 E2E-skipped, 662 deselected — +82 Tests vs. Block-V-Beginn 1360). Alle fünf Phasen A → B → D → C → E (plus zwei Folge-Fixes nach Reviewer-APPROVE-WITH-NOTES) implementiert, pro Phase vom `reviewer`-Subagent APPROVED. Code-only, keine Alembic-Migration, kein Schema-Touch. **Was Block V geliefert hat:** **Phase A** — `app/services/quick_stats.py` und `app/templates/sidebar/_quick_stats.html` ersatzlos gelöscht (Dead Code: berechnet, aber nirgendwo gerendert; Dashboard-View + Sidebar-Context-Processor riefen es doppelt auf). **Phase B** — neue Pure-Funktion `tendency_from_counts(counts, ...)` in `app/services/trend.py` (delegiert von `compute_tendency`-Wrapper aus), optionaler `rows=`-Parameter auf `severity_snapshots_for_server`/`daily_severity_counts_for_server` (Stepping-Stone für Phase E), gemeinsamer `_load_findings`-Call vor Aggregatoren via neuer Public-Helper `load_findings_for_server`, `list_findings` im Server-Detail-View nur noch im Flat-Mode (`_is_flat_mode`-Helper spiegelt die Template-Conditional aus `_findings_section.html:122-133`); Template `detail.html:Z.42` auf `total_findings = counts.open if counts else (findings | length)`. **Phase D** — `_load_open_aggregates` 2 → 1 Query (eine FILTER-Aggregat-Query liefert Severity/KEV/Risk-Band pro Server), `_load_risk_kpi_counters` 4 → 2 Queries (Findings-FILTER-Aggregat + Active-Server-Count getrennt); Phase-D-Fix nach Reviewer-NOTE: `yes_servers` zählt jetzt nur aktive Server (`active_server_ids` aus bereits geladener `_load_servers`-Liste, Drift bei revoked Servern mit historischen OPEN-Findings geschlossen). **Phase C** — Sidebar-Lazy-HTMX-Load (erschlägt Befunde 4 + 6 + 7): `build_sidebar_context` schmal (nur billige Felder: Server-Liste, Tags, filter_tags), `heartbeats_for_servers` auf schmale 7-Spalten-Projektion mit `_FindingRow`-NamedTuple statt `select(Finding)` (Befund 6: ~30 MB Hydrate-Ersparnis), neuer Pure-Service `app/services/sidebar_risk_counts.py::escalate_act_counts_by_server` (eine GROUP-BY-Query auf `(server_id, risk_band)` mit FILTER `status='open' AND risk_band IN ('escalate','act')`), Polling-Endpoint `/_partials/sidebar` als **einzige** Quelle der teuren Aggregate mit neuen Context-Keys `sidebar_risk_counts`, `hosts_total`, `alarm_count`; Templates `_server_list.html` (HTMX-Trigger von `every 10s` auf **`load, every 60s [document.visibilityState === 'visible']`** umgestellt — bewusste Spec-Änderung im Rahmen Phase C, Polling-Cadence reduziert), Header-Markup `HOSTS · ALARM`, `_server_row.html` mit zwei neuen Spalten ESCALATE/ACT (Skeleton-Fallback bei `risk` falsy, Live-Werte mit `text-error`/`text-warning`/`—`-Marker), `_heartbeat_bar.html` mit `{% if cells %}`-Guard und 50-Cell-Skeleton im Else-Zweig (identische Tailwind-Größenklassen, kein Layout-Sprung beim Swap). **Phase E** — drei neue SQL-Helper in `app/services/severity_history.py`: `_build_server_daily_sql` (`generate_series` + 5× `COUNT(*) FILTER` für Severity/KEV-Events), `_build_kev_open_sql` (separater Helper für OPEN-KEV-Stand-Sparkline), `_build_fleet_daily_sql` (Fleet-Variante mit `total`/`kev`/`critical`/`high`); `severity_snapshots_for_server` und `daily_severity_counts_for_server` nutzen SQL als Default (Python-Aggregator nur noch bei `rows=`-Pfad — Phase-B-Backward-Compat); `daily_severity_counts_fleet` Differenz-Array-Walk ersatzlos durch SQL ersetzt (kein Phase-B-Stepping-Stone für Fleet, semantisch identisch); Phase-E-Fix nach Reviewer-NOTE: Server-Detail-View `show()` ruft Aggregatoren ohne `rows=`-Parameter auf — SQL-Default-Pfad aktiv, `load_findings_for_server` im View nicht mehr nötig (bleibt als Public-API in `severity_history.py` für etwaige Aufrufer/Tests). Pure-Python-Helper (`_compute_snapshots`, `_compute_daily_counts`, `_is_open_at`, `_load_findings`, `_FindingRow`) bleiben für Test-Doubles und `rows=`-Pfad bestehen.

**Verifikations-Ergebnisse (alle Phasen, in Reihenfolge der Subagent-APPROVE-Meldungen):**

- **Default-`pytest`** über alle Phasen-Endstände: zuletzt **1442 passed, 5 skipped (E2E), 662 deselected** in ~32 s. Keine Regression in keiner Phase.
- **Test-Anzahl Block-V-spezifisch:** Phase A 0 (Dead-Code-Removal, gelöscht statt neu geschrieben) + Phase B 22 + Phase D 14 (12 + 2 Fix) + Phase C 34 (7 sidebar_risk_counts + 4 heartbeat_aggregation + 8 sidebar_context + 15 sidebar_partial) + Phase E 12 (11 sql + 1 fix) = **82 neue Pure-Unit-Tests**. Plus eine angefasste Adversarial-Datei (`test_xss_in_heartbeat_tooltip` auf Polling-Endpoint umgestellt) und eine Template-Test-Datei (Eyebrow-Counter im Group-Default-Pfad).
- **Befunde aus ADR-0030 erledigt:** alle neun (1, 2, 3, 4, 5, 6, 7, 8, 9).
- **Code-only, keine Migration:** Block V berührt weder Schema noch Alembic. Operator-Impact ist ein einzelner App-Pod-Restart (kein Worker-Restart, kein DB-Touch).
- **Re-Open-Trigger aus Reviewer-NOTES (alle adressiert oder zur User-Verifikation deferred):** (1) `yes_servers`-Drift bei revoked Servern — durch Phase-D-Fix geschlossen. (2) DoD-D-3-Formulierungs-Präzisierung — Block-V-Doku angepasst (Phase D trägt Anteil zur Gesamt-Schranke ≤ 6 bei, nicht allein erreichbar). (3) DoD-E-Performance-`< 100 ms` Trend-Sektion — Pure-Unit-Default kann das nicht messen, User-Verifikation gegen k8s-DB ausstehend (siehe DoD-Schranken: Dashboard < 800 ms / Server-Detail < 1.5 s sind nur via echte DB-Wallclock-Messung bestätigbar). (4) Timezone-Edge-Case in `generate_series` — korrekt unter UTC-Session-TZ (Standard), akademisch bei anderer DB-TZ. (5) Fleet-Bench-Neukalibrierung (`< 200 ms` → `< 50 ms` möglich, db_integration-Marker, nur auf User-Anweisung). (6) Block-V-Doku-Z.106 (`every 10s` → `every 60s`) — Tippfehler korrigiert.

**Tag `v0.12.0` zu setzen nach Merge auf main.**

- **T — Application-Group-Evaluations als Junction (ADR-0028)** · abgeschlossen 2026-05-22 · Branch `feat/block-t-eval-junction` · Default-Gates **grün** (ruff/format/mypy/pytest Default-Selektion 1205 passed, 5 E2E-skipped, 697 deselected). Alle sieben Phasen (A–G) implementiert: Migration `0011_app_group_evals` (neue Junction-Tabelle `application_group_evaluations` mit Composite-PK `(group_id, server_id)`, 3 Indizes inkl. partial-`worst_finding_id`, 3 CheckConstraints; sieben Eval-Spalten + 2 CheckConstraints aus `application_groups` ersatzlos entfernt), `ApplicationGroupEvaluation`-Model parallel angelegt, Pass-2-Persistierung in `app/workers/llm_worker.py` auf `pg_insert().on_conflict_do_update()` UPSERT umgestellt (zwei Call-Sites — Cache-Hit + Live-LLM; Helper-Rename `_apply_pass2_to_group` → `_upsert_evaluation`), Pass-2-Trigger-Adaption in `app/services/scan_processing.py` (Batch-SELECT auf Junction statt N×grp.risk_band, vermeidet N+1), `inherit_group_risk_to_findings` auf Composite-Match `(Finding.application_group_id == Junction.group_id AND Finding.server_id == Junction.server_id)` umgestellt — Cross-Server-Leak behoben, Server-Detail-Lazy-Load mit viertem Batch-SELECT für Junction-Rows + Templates auf `evaluation`-Variable mit None-Fallback (`application_group_card.html`, `group_evaluating_card.html`, `_view_groups.html`, `_action_needed_section.html`, `settings/llm_reviewer.html`), `tests/services/test_finding_group_inheritance.py` auf Composite-Match-Asserts migriert (8 Pure-Unit-Tests grün). ARCHITECTURE.md §5 ergänzt, ADR-0023 Header mit Persistenz-Schicht-Hinweis, TICKET-002 als "Erledigt durch Block T" markiert. CHANGELOG-Eintrag. `docs/operations.md` Sektion „Block-T-Application-Group-Evaluations" mit UI-Lücke-Hinweis, Force-Scan-Recipe, Junction-Inspect-SQL. **Migration ist Drop & Rebuild (ADR-0028 §Migration)** — bestehende Eval-Werte werden nicht migriert, Pass-2 baut die Junction beim nächsten regulären Scan jedes Servers via `llm_risk_cache`-Hit nahezu kostenlos neu auf. **On-Demand-Verifikation ausstehend** (db_integration-Tests: Alembic-Roundtrip 0011, Pass-2-UPSERT-Lifecycle, Server-Detail-Junction-Render, Cross-Server-Isolation). Branch lokal, Commit auf User-Anweisung. **Tag `v0.11.x` zu setzen nach Merge auf main.**

- **R — Asynchroner Scan-Ingest (ADR-0026)** · abgeschlossen 2026-05-22 (gemerged auf main) · Branch `feat/block-r-async-ingest` · Default-Gates **grün** (ruff/format/mypy/shellcheck/pytest Default-Selektion 1206 passed, 5 E2E-skipped, 685 deselected). Alle acht Phasen (A–H) implementiert: Migration `0010_scan_ingest_jobs` (15-Spalten-Tabelle + 4 Indizes inkl. partial-unique `payload_sha256`, `STORAGE EXTERNAL` auf `payload_gzip`), Edge-Fast-Path hinter `SECSCAN_SCAN_INGEST_ASYNC` (Default off — Sync-Pfad bleibt aktiv) mit `_pre_validate_envelope` und `app/services/scan_ingest_queue.enqueue_or_resolve` (Idempotency + Soft-Cap), Service-Extraktion `app/services/scan_processing.process_scan_envelope` (ehemals inline-Sync-Logik), Worker-Sub-Tick `app/workers/scan_ingest_worker.py` (SELECT FOR UPDATE SKIP LOCKED, atomares Payload-Clear bei `done`, Backoff `30s*2^(attempts-1)`), Stale-Reaper (5min, max 3 attempts), stündlicher Retention-Sweep (Done-Crash-Reste auf NULL, Failed-Zeilen nach 24h DELETE), Status-Endpoint `GET /api/scans/jobs/<id>` mit Server-Scoping (404 statt 403 für Cross-Server), Agent 0.4.0 mit Polling-Loop (2s × 600s, neue Exit-Codes 4/5, `SECSCAN_POLL_MAX_SEC`-Override). 47 Pure-Unit-Tests in 4 Files (`test_scan_processing.py`, `test_scan_processing_result.py`, `test_scan_ingest_worker_unit.py`, `test_scan_status_endpoint_unit.py`). ARCHITECTURE.md §6 (Async-Fast-Path), §9 (Soft-Cap), §13 (`scan.queued`/`scan.ingest_failed`) ergänzt; ADR-0022 mit Worker-Audit-Hinweis ergänzt; CHANGELOG-v0.11.0-Eintrag; `docs/operations.md` Sektion „Block-R-Async-Ingest" mit Cutover-Plan, Queue-Inspect-SQL und Retention-Tabelle. **Bewusste Spec-Abweichung 2026-05-22:** Test-Strategie wurde mid-Block verschärft auf „nur Pure-Unit + Linter + Static-Analyzer", deshalb sind 21 db_integration-Reflection-Tests (`tests/alembic/test_0010_scan_ingest_jobs.py`) und 14 db_integration-Edge-Tests (`tests/api/test_scans_async_edge.py`) zwar im Repo abgelegt aber laufen nur On-Demand; bats-Suite (`tests/agent/test_secscan_agent_polling.bats`) ist **nicht** angelegt; Docker-Compose-Up/healthz-Smoke ausgespart. Block-Spec-DoD-Items A(2), B(4), C(7), D(2), E(2)/(3) sind dadurch als On-Demand-Operator-Verifikation deferred; Default-Verifikation in der Entwicklung ist `pytest` (Pure-Unit) + ruff/mypy/shellcheck — alles grün. Branch ist lokal mit ungetrackten Änderungen, Commit + Merge auf User-Anweisung. **Tag `v0.11.0` zu setzen nach Merge auf main.** · **Nachtrag 2026-05-28 (ADR-0042):** Status-Endpoint `GET /api/scans/jobs/<id>` und Agent-Polling-Loop wieder entfernt — Agent ist Fire-and-Forget (Exit 0 nach 202), `test_scan_status_endpoint_unit.py` gelöscht. Async-Ingest-Kern (Queue, Worker-Sub-Tick, Idempotency, Payload-Transit) bleibt unverändert.

- **v0.9.6-Patch — Worker-Idle-CPU-Throttle + CI-Build-Speedup** · abgeschlossen 2026-05-20 · direkt auf main (`acb162d` CI-Workflow, `2784a86` Worker-Throttle), Tag `v0.9.6` zeigt auf `2784a86`. Mode-/Budget-Cache + Idle-Backoff im Worker reduzieren die Idle-SQL-Last von ~126 Queries/Minute auf ~2; CI-Build-Workflow arm64-only und mit `scope=release` GHA-Cache. 1609 Tests grün (+6 v0.9.6), Coverage 91 %. ruff/format/mypy/shellcheck PASS. Detail siehe Status-Sektion oben. **Tag `v0.9.6` gesetzt.**

- **v0.9.5-Patch — Worker-Stability: LABEL_PATTERN-Spec-Drift + Validator-Meta-an-Exception + Heartbeat-Thread + Logging-Erweiterung** · abgeschlossen 2026-05-20 · Branch `fix/v0.9.5-worker-stability` · Hotfix nach k8s-Pod-Restart-Loop und blindem Debug-Log. Vier zusammenhaengende Mini-Fixes ohne Schema-Migration und ohne Spec-Aenderung. 1603 Tests grün (+12 v0.9.5-Tests), Coverage 91 %. ruff/format/mypy/shellcheck PASS. Docker-Compose-Up zeigt das neue `heartbeat_thread_started`-Log; drei Container healthy. Detail siehe Status-Sektion oben. Operator-Impact: Pod-Restart-Loop gestoppt, Debug-Log-Tab zeigt echte LLM-Response auch bei Validator-Errors. **Tag `v0.9.5` zu setzen.**

- **v0.9.4-Patch — Pass-1-Batching mit Affinity-Sort + `temperature=0` + Error-Klassifikation + Docker-Healthcheck-Timeout** · abgeschlossen 2026-05-20 · Branch `fix/v0.9.4-pass1-batching` · Hotfix nach Worker-Beobachtung `Requested input length 231381 exceeds maximum input length 131071`. Vier zusammenhaengende Mini-Fixes ohne Schema-Migration. 1591 Tests grün (+20 v0.9.4-Tests in vier Buckets), Coverage 91%. `ruff check`/`ruff format --check`/`mypy app/` (70 source files)/`shellcheck agent/*.sh` PASS. Drei-Container-Compose-Up healthy nach ~30s. Detail siehe Status-Sektion oben. Operator-Impact: 9000-Findings-Flotte braucht jetzt ~90 Pass-1-Jobs à 100 Findings statt 1 Riesen-Job-400-Loop. **Tag `v0.9.4` zu setzen.**

- **v0.9.3-Patch — Block-P-Iteration: Pass-1-/Pass-2-Prompt-Iteration + Modell-Default-Wechsel + Tags-Exclusion + Risk-Band-Reduktion + `action_type`/`group_kind` + „Was zu tun ist"-UI + Reasoning-Block-Parser + defensive Listener-Interpretation + `llm_debug_log`** · abgeschlossen 2026-05-20 · Branch `feat/v0.9.3-block-p-iteration` · Reviewer **APPROVE** (29/29 DoD-Items grün; drei kosmetische Doku-NOTES als Re-Open-Trigger gelistet). Security-Auditor **ACCEPTABLE WITH NOTES → APPROVED** (8/8 Pflicht-Punkte PASS; Privacy-Disclaimer im Debug-Log-Template als Hotfix nachgereicht). 1571 Tests grün (+94 vs. v0.9.0), Coverage 91%; 421+ adversarial PASS (mit `action_type`-Pflicht und Combo-Whitelist-Erweiterung in den existierenden Pass-2-Adversarials). `ruff check`/`ruff format --check`/`mypy app/` (70 source files)/`shellcheck agent/*.sh` PASS. Alembic-Roundtrip 0006↔0007 PASS gegen Postgres-17. Drei-Container-Compose-Up healthy. Image-Size unverändert ~192 MB. **Tag `v0.9.3` zu setzen.** Detail siehe Status-Sektion oben. Optionale Folge-PRs: README-DSGVO-Hinweis für Host-Snapshot-Felder beim externen LLM-Provider; CHANGELOG-Stil-Konsolidierung.

- **P — LLM-Risk-Reviewer mit Application-Grouping (Two-Pass) und async Worker (ADR-0023)** · abgeschlossen 2026-05-19 · Branch `feat/block-p` · Reviewer **APPROVE** (alle DoD-Items PASS: Datei-Existenz, ruff/format/mypy/shellcheck/pytest-cov 91.70 %, Adversarial +95 Cases, Block-P-E2E 10 grün, Alembic-Roundtrip 0004↔0005↔0006, Docker-Build 192 MB, drei-Container-Compose-Up healthy). Security-Auditor: **ACCEPTABLE WITH NOTES → SECURITY APPROVED** (10/10 Pflicht-Punkte PASS, drei optionale Re-Open-Trigger als Folge-PR-Kandidaten; Pre-Tag-Hotfix Pass-1-Token-Buchung in `_do_pass1` implementiert). 1477 Tests grün (+251 vs. v0.8.0), Coverage **91.70 %**; 421 adversarial PASS (+95 Block-P-Cases). **Neu:** `app/services/llm_risk_reviewer.py` (`LLMRiskReviewer` mit `pass1_detect_groups()`/`pass2_evaluate_groups()`, `PASS1_RESPONSE_SCHEMA`/`PASS2_RESPONSE_SCHEMA`, Pydantic-Output-Modelle `Pass1Group`/`Pass1Result`/`Pass2Evaluation`/`Pass2Result`, `LABEL_PATTERN`, `MAX_REASON_LEN`, `VALID_RISK_BANDS`, `LLMInvalidResponseError`/`LLMTimeoutError`, Pattern-Defensiv-Trim mit `_sanitize_path_prefix`/`_sanitize_pkg_*`/`_sanitize_purl_pattern`), `app/services/group_matcher.py` (`GroupMatcher` Singleton mit `_lock`, `reload(session)`, `match(finding)` mit 4-stufiger Reihenfolge inkl. ADR-0011-`@target`-Suffix-Strip, `apply_matches_for_server(session, server_id) -> int`), `app/services/llm_cache.py` (`lookup`/`record_hit`/`store`/`lru_evict_if_needed`), `app/services/llm_fingerprints.py` (`group_findings_fingerprint`/`cve_data_fingerprint`/`server_context_fingerprint(server, session=None)`/`make_cache_key`; PIDs/args/snapshot_at NICHT im Server-Context-FP), `app/services/llm_budget.py` (`budget_check`/`budget_consume`/`maybe_reset_budget`/`mark_exhausted_audit_once`/`estimate_tokens`), `app/workers/llm_worker.py` (Worker-Hauptschleife mit Pickup `SELECT FOR UPDATE SKIP LOCKED`, Mode-Branches off/observation/live, Pass-1/Pass-2-Handler mit Cache-Lookup vor LLM-Call, Heartbeat, Stale-Reaper, `_build_reviewer`-Test-Hook), `app/workers/healthcheck.py` (Standalone-Script, < 30s Heartbeat-Check), `app/workers/__init__.py`, `alembic/versions/0005_block_p_llm_groups_jobs_cache.py` (3 create_table + 1 add_column + 1 create_index + Settings-Spalten via Mini-Migration 0006), `alembic/versions/0006_block_p_token_reset_at.py` (Mini-Migration fuer `settings.llm_token_budget_reset_at`-Spalte), `app/templates/_partials/{application_group_card,group_evaluating_card,group_findings_table}.html`, `app/templates/servers/_view_groups.html`, `app/templates/settings/llm_reviewer.html` (Mode-Wechsel-Modal mit Master-Key + DSGVO-Privacy-Notice + Confirm-Checkbox, Stats-Block, Re-queue-Action), `app/static/js/llm_reviewer.js` (Alpine-Komponenten fuer Modal-State), 18 neue Test-Dateien (4 Models, 1 Migration, 5 Services, 1 API-Integration, 2 Workers, 4 Views, 1 Integration-conftest + 3 E2E, 9 Adversarial), 13 Adversarial-Files in Phase H. **Geaendert:** `app/models.py` (`ApplicationGroup`/`LLMJob`/`LLMRiskCache` neue Klassen, `Finding.application_group_id` FK ON DELETE SET NULL plus Relationship, `Setting.block_p_llm_mode`/`.llm_worker_heartbeat_at`/`.llm_token_budget_used_today`/`.llm_token_budget_reset_at`-Spalten mit CheckConstraints), `app/api/scans.py` (Block-P-Hook nach Block-O-Pre-Triage und vor `scan.ingested`: `GroupMatcher.reload(session)` + `apply_matches_for_server` + Pass-1-Job-Insert fuer ungrouped-pending-Findings + Pass-2-Jobs fuer affected Groups mit `depends_on=Pass-1-Job-ID` + `llm.jobs_queued`-Audit), `app/api/bulk.py` (unveraendert — Block-P-Bulk-Ack-Noise nutzt weiterhin Finding-Ebenen-Filter), `app/views/settings.py` (drei neue Routen `/settings/llm-reviewer` GET + POST mode + POST requeue-backlog mit Master-Key-Gate via `_verify_master_key_from_form`), `app/views/dashboard.py` (`available_application_groups`-Context), `app/views/server_detail.py` (`_load_application_groups_for_server` + `_load_ungrouped_findings_for_server`), `app/services/findings_query.py` (`application_group_id`-Filter, `"group"`-Sort-Key mit outer-Join auf `ApplicationGroup.label`), `app/schemas/{dashboard_filter,findings_view_filter}.py` (`application_group_id: int | None`, `"group"`-Sort-Whitelist), `app/forms.py` (`LlmReviewerModeForm`, `LlmReviewerRequeueForm`), `app/templates/dashboard/_findings_section.html` (Group-Spalte nach Risk), `app/templates/dashboard/_findings_filter_bar.html` (Application-Group-Select), `app/templates/servers/_findings_section.html` (Group-Cards-Render mit Filter-Fallback auf flache Liste), `app/templates/settings/_nav.html` (LLM-Reviewer-Eintrag), `app/templates/_macros.html` (`"group"`-Sort-Default-Dir), `docker-compose.yml` (Service `secscan-llm-worker` mit `python -m app.workers.llm_worker`-Entrypoint, depends_on db service_healthy, Healthcheck `python -m app.workers.healthcheck` 30s interval, keine ports), `app/config.py` (`llm_cache_ttl_days`/`llm_cache_max_rows`/`llm_pass1_max_tokens`/`llm_pass2_max_tokens`/`llm_token_budget_daily`/`worker_poll_interval_sec`/`worker_stale_timeout_min`), ARCHITECTURE.md §6 (Envelope unchanged)/§7 (Group-Spalte + Filter)/§7a (Server-Detail Group-Layer)/§12 (neuer Risk-Reviewer-Subabschnitt: Two-Pass-Architektur, Worker-Pattern, Mode-Flag, Token-Budget, Two-Level-Caching, Validierung, LLM-Override-Schutz)/§13 (neue Audit-Actions `llm.mode_changed`/`llm.budget_exhausted`/`risk.llm_group_skipped`)/§17 (sieben neue Out-of-Scope-Punkte), `docs/decisions/0022-risk-based-prioritization.md` (Re-Open-Trigger zeigt jetzt auf ADR-0023), `docs/decisions/0023-...md` Status „Akzeptiert", `docs/decisions/README.md` Index, CHANGELOG.md v0.9.0-Eintrag. **Tag `v0.9.0` zu setzen.**



- **O — Pre-Triage-Risk-Engine + Host-Snapshot + Vendor-Severity + UI-Redesign (ADR-0022)** · abgeschlossen 2026-05-18 · Branch `feat/block-o` · Reviewer APPROVE nach drei mechanischen Fixes (ruff RUF003/S104/I001 in sechs neuen Adversarial-Test-Files, ruff format auf vier davon, CHANGELOG-v0.8.0-Eintrag mit allen vier Bausteinen). Security-Auditor: **ACCEPTABLE WITH NOTES → SECURITY APPROVED** (alle 8 Pflicht-Punkte PASS: Pre-Triage-Cuts schlucken keine Eskalationen, `unknown`-Default ist `action_required=yes`, Bulk-Ack-Server-Side-Filter `risk_band == "noise"` unumgehbar via Request-Manipulation, Pydantic-Validatoren strikt fuer IP-Literal/Port-Range/ASCII/NUL/Length-Bounds, `risk_band`-Spalte hat genau einen Schreibpfad in `app/api/scans.py` Pre-Triage-Schleife nach Auth, alle Band-Bewegungen produzieren `risk.band_changed`-Audit, DSGVO-Aspekt der Process-Args als bewusste MVP-Entscheidung in ARCHITECTURE §9 dokumentiert mit README-Notice als optionaler Re-Open-Trigger, LLM-gesetzte Bands mit `risk_band_source="llm"` ueberleben Re-Ingest). 1226 Tests gruen (+234 vs. v0.7.0; +90 erwartete + Adversarial-Surplus), Coverage **92.42 %**; 326 adversarial PASS (+69 Block-O-Cases). `ruff check`/`ruff format --check`/`mypy app/` (60 source files)/`shellcheck agent/*.sh` PASS, Alembic-Roundtrip (0004 ↔ 0003) PASS, `docker build` + `docker compose up --build` + `/healthz` PASS, Image **191 MB** (Delta 0 MB vs. v0.7.0). **Neu:** `app/services/risk_engine.py` (`RiskBand`/`ActionRequired`/`ACTION_REQUIRED_MAP`/`RISK_BAND_SORT_RANK`/`EPSS_PENDING_THRESHOLD=0.1`/`pretriage()`/`RiskEvaluation`/`normalize_vendor_status()`/`VENDOR_SEVERITY_INT_MAP`/`yes_band_values()`/`no_band_values()`), `app/services/severity_resolver.py` (`severity_for()` mit 13 Distro-Profilen + GHSA-Prio fuer lang-pkgs, `max_severity_across_providers()`, `_score_to_severity()`), `app/services/host_state_ingest.py` (`persist_host_state()` mit truncate+insert pro Server, Dedup auf `(proto,addr,port)`/`pid`/`name`), `agent/lib_host_state.sh` (~330 LOC sourcable Lib mit `collect_listeners`/`collect_processes`/`collect_kernel_modules`/`collect_services` + `build_host_state_json`, POSIX-awk, `ss`/`netstat`-Fallback, `LC_ALL=C`), `alembic/versions/0004_block_o_risk_and_host_state.py` (4 create_table + 7 add_column + 4 create_index), `app/templates/_partials/{host_snapshot,risk_band_pill,action_required_pill,action_required_card}.html`, `app/templates/servers/_bulk_ack_noise_modal.html`, `app/static/js/bulk_ack_noise.js` (Alpine-Komponente, postet `risk_band_filter="noise"`), 13 neue Test-Dateien (3 Schemas, 1 Migration, 5 Services, 2 API-Integration, 1 Agent-Subprocess, 4 Views, 7 Adversarial). **Geaendert:** `app/models.py` (vier Snapshot-Modelle, `Server.host_state_snapshot_at`, sechs Finding-Spalten plus zwei Indizes), `app/api/scans.py` (Reihenfolge Auth → Body → Findings-UPSERT → Snapshot-Persist → Pre-Triage-Schleife → `scan.ingested`; mit `host_state.snapshot_received`/`host_state.parse_failed`/`risk.band_changed`/`risk.pretriage_evaluated` Audit-Events; LLM-Override-Skip `if finding.risk_band_source == "llm": continue`), `app/api/bulk.py` (`risk_band_filter="noise"`-Form-Field, server-side `Finding.risk_band == "noise"`-Drop, `skipped_non_noise_ids` in Response + Audit), `app/schemas/scan_envelope.py` (`HostStateBlock`/`ListenerEntry`/`ProcessEntry` mit IP-Literal/Port-Range/ASCII/NUL-/Length-Validatoren, `TrivyVulnerability.vendor_severity` mit Numeric-zu-String-Normalisierung), `app/schemas/{dashboard_filter,findings_view_filter,bulk_request}.py` (Literal-Felder `risk_band`/`action_required`/`risk_band_filter`), `app/services/findings_ingest.py` (Mapper schreibt `vendor_status` + `severity_by_provider`), `app/services/findings_query.py` (`risk`-Sort-Key mit `case()`-Expression, Filter fuer `risk_band`/`action_required`), `app/views/dashboard.py` (`RiskKpiCounters` + `_load_risk_kpi_counters()`), `app/views/server_detail.py` (`_load_action_required_counts()` + `_load_host_snapshot()` + noise-Findings fuer Modal), `agent/secscan-agent.sh` (`AGENT_VERSION="0.3.0"`, Lib-Source ueber `BASH_SOURCE`-relativen Pfad, host_state-Build im Envelope), Templates `dashboard/_kpi_cards.html` (Tier-Umbau), `dashboard/_findings_filter_bar.html` (zwei neue Selects), `dashboard/_findings_section.html` (Risk-Spalte), `servers/detail.html` (Action-Required-Pill als erste Header-Pill + Host-Snapshot-Sektion), `servers/_view_list.html` (`risk_band`-Gruppierung mit Alpine-Collapsible), `servers/_findings_section.html` (Bulk-Ack-Noise-Button), `base.html`/`base_app.html` (`bulk_ack_noise.js`-Include), ARCHITECTURE.md §6/§7/§7a/§9/§11/§15/§17, `docs/decisions/0022-risk-based-prioritization.md` Status „Akzeptiert", `docs/decisions/README.md` Index, CHANGELOG.md v0.8.0-Eintrag, sechs angepasste Block-M/K-Tests, `tests/views/test_agent_install.py` AGENT_VERSION-Erwartung 0.2.0→0.3.0, `tests/schemas/test_dashboard_filter.py` Default-Sort `sev`→`risk`. **MIN_AGENT_VERSION** bleibt `0.1.0` — alte Agents 0.2.0 weiter akzeptiert, Findings landen ohne `host_state` in `risk_band="unknown"` mit Reason „host snapshot missing — update agent to >= 0.3.0". **Bewusst weggelassen:** LLM-Risk-Reasoning (Block P), Host-Snapshot-Historisierung, manueller Risk-Override, Patch-Alter-Eskalation, Exposure-Mapping als statisches Asset, OpenRC-/Alpine-Services, Daily-Re-Eval-Job, README-Privacy-Notice (vom Security-Auditor als optionaler Re-Open-Trigger benannt). **Tag `v0.8.0` zu setzen.**

- **N — Agent-Bootstrap-Installer + Trivy-Output-Strip + Ursachen-Felder pro Finding (ADR-0021)** · abgeschlossen 2026-05-18 · Branch `feat/block-n-agent-installer` · Reviewer-Freigabe nach `.dockerignore`-Fix (Zeile `agent` entfernt — sonst war das Runtime-Image ohne `agent/`-Verzeichnis und die drei neuen Public-Endpoints 404). Security-Auditor: **ACCEPTABLE WITH NOTES** (alle 8 Pflicht-Punkte PASS — no-secrets in /install.sh, Path-Traversal, PUBLIC_PATHS minimal, Pill-Tooltip-XSS via DaisyUI-CSS-`::before`, outdated-Agent-Reject + Audit, agent.env mode 0600 root:root, Trivy-SHA256-fail-stop, Master-Key niemals in Argv/History/Files; zwei optionale Doku-Notes als Re-Open-Trigger: `@limiter.limit("60/minute")` auf `/install.sh`/`/agent/files/` und README-Hinweis fuer Reverse-Proxy-Allowlist). 992 Tests grün (+108 neue Block-N-Tests), Coverage **92.16 %**; 254 adversarial PASS (+14 neue: Path-Traversal × 9, no-secrets, outdated-Reject, public-no-auth × 3, PURL-XSS, VendorIDs-Injection × 9). `ruff check`/`ruff format --check`/`mypy app/`/`shellcheck agent/*.sh` PASS, Alembic-Roundtrip (0003 ↔ 0002) PASS, `docker compose up --build` + `/healthz` + `/install.sh` + `/agent/version` + `/agent/files/secscan-agent.sh` PASS, Image 191 MB (Delta 0 vs. v0.6.x). Neu: `app/views/agent_install.py` (3 Routes), `app/templates/agent/install.sh.j2` (~720 Bash-Zeilen, sechs-Phasen-Wizard mit TTY/Color/Box-Helpers, `/dev/tty`-Master-Key-Prompt, Trivy-`sha256sum -c`, systemd+Cron-Fallback, Unattended-Modus), `app/services/agent_version.py` (`version_lt`/`is_*_outdated`), `app/services/finding_display.py` (`format_finding_cause()` mit ADR-0011-Fallback-Split), `alembic/versions/0003_block_n_agent_and_finding_cause.py` (7 add_column: 2 Server + 5 Finding — `Server.agent_version` existierte bereits aus 0002), `tests/integration/installer/` (Ubuntu-24.04 + AlmaLinux-9 Dockerfiles + run.sh + Make-Target `test-installer`, alle unter `@pytest.mark.integration`). Geaendert: `agent/secscan-agent.sh` AGENT_VERSION 0.1.0→0.2.0 + `host.trivy_version` + `jq`-Strip mit Raw-Fallback + Englisch, `agent/secscan-register.sh` Englisch, `app/api/scans.py` Agent-Version-Reject (400 + Audit `agent.rejected_outdated`, 401-vor-400-Reihenfolge erhalten), `app/services/findings_ingest.py` `_extract_cause_fields` + UPSERT-Pfad schreibt fuenf Cause-Spalten, `app/schemas/scan_envelope.py` `HostBlock.trivy_version` + `TrivyPkgIdentifier` + `TrivyVulnerability.{pkg_identifier,severity_source,vendor_ids}` + `package_purl`-Property + `MAX_VENDOR_IDS_PER_VULN=32`, `app/__init__.py` Context-Processor + PUBLIC_PATHS-Allowlist um drei Routes + `humanize_delta`-Filter, `app/templates/servers/detail.html` (drei conditional Pills mit Tooltips), `app/templates/sidebar/_server_row.html` (`⚠`-Marker), `app/templates/servers/_view_list.html` + `dashboard/_findings_section.html` (Ursachen-Sub-Zeile). ADR-0011 bleibt waehrend natuerlicher Re-Ingest-Konsolidierung aktiv — `_disambiguated_package_name()` unveraendert, Alt-Daten ohne `target_path` rendert UI per `package_name`-`@`-Split-Fallback. ARCHITECTURE §6 + §11 + §17 aktualisiert. `.dockerignore` `agent` raus. **Tag `v0.7.0` zu setzen.**

- **A — Skelett und Basis** · abgeschlossen 2026-05-14 · Branch `feat/block-a` · Reviewer-Freigabe nach Re-Review (Gunicorn `HOME=/app` + `--worker-tmp-dir /dev/shm`-Fix).
- **B — Datenmodell, Setup-Wizard und Auth** · abgeschlossen 2026-05-14 · Branch `feat/block-b` · Reviewer-Freigabe nach Template-Fix (Pattern-Escape) und Re-Run der adversarial-Tests. 96 Tests grün. Setup-Flow-Screenshot unter `docs/blocks/B-evidence/setup-flow.png`.
- **C — Ingest, Server-Verwaltung und Agent-E2E** · abgeschlossen 2026-05-14 · Branch `feat/block-c` · Reviewer-Freigabe 24 PASS / 0 FAIL. 207 Tests grün, Coverage 91 %. Real-Fixture mit 306 Findings (296 lang-pkgs + 10 os-pkgs) durchläuft Ingest mit Auth-vor-Body-Parse (401 in 22 ms), gzip-Bomb-Bound (413 bei >100 MB), Idempotenz auf Re-Scan. Neue ADR-0011 (`package_name@target`-Disambiguation).
- **D — Dashboard mit Tags und Stale-Detection** · abgeschlossen 2026-05-14 · Branch `feat/block-d` · Reviewer-Freigabe 8 PASS / 0 FAIL / 5 PENDING (Operator-UX). 306 Tests grün (99 neue Block-D-Tests), Coverage 93 %. Dashboard-Screenshot unter `docs/blocks/D-evidence/dashboard.png` mit 3 Servern, KEV-Badge, Stale-Marker, Tag-Filter-Form und Aufmerksamkeits-Sektion.
- **E — Triage in der Server-Detail-View** · abgeschlossen 2026-05-14 · Branch `feat/block-e` · Reviewer-Freigabe 12 PASS / 0 FAIL. 67 neue Block-E-Tests grün (insgesamt 373+ Tests), Coverage 90 % auf Block-E-Modulen. Drei View-Modi (Liste, Group-by-Package, Diff), Modals für Ack/Re-Open mit OPTIONALEM Kommentar (ADR-006), Notes-Thread mit `nh3.clean()`-Markdown-Subset, Quick-Copy-Toast, XSS-Härtung verifiziert. Sicherheits-Fix: `delete_note` mit Owner-Check + 403 für `system-*`-Notes. Screenshots: `docs/blocks/E-evidence/{list,group,diff}.png`.
- **F — Bulk-Operationen, globale Suche, Audit-View, CSV-Export** · abgeschlossen 2026-05-14 · Branch `feat/block-f` · Reviewer-Freigabe 19 PASS / 0 FAIL / 6 PENDING (Operator-UX). 71 neue Block-F-Tests grün (insgesamt 430+ Tests), Coverage 91 % auf Block-F-Modulen. Bulk-Acknowledge mit `dry_run` (Default true) und zwei Flavors (`finding_ids`/`match`), globale Suche mit CVE-Aggregation, Audit-View mit Tag-Filter, CSV-Export mit OWASP-konformer Formula-Injection-Mitigation (`'`-Prefix auf `=/+/-/@/\t/\r`). Bug-Fix: Audit-Type-Cast (`AuditEvent.target_id` VARCHAR ↔ `Server.id` INTEGER). Screenshot: `docs/blocks/F-evidence/search-cve.png`.
- **G — LLM-Integration mit Streaming-Chat** · abgeschlossen 2026-05-15 · Branch `feat/block-g` · Reviewer-Freigabe 27 PASS / 0 FAIL / 8 PENDING. Security-Auditor: ACCEPTABLE WITH NOTES (3 CONCERNS, alle in Block H umgesetzt). 149 neue Block-G-Tests grün (insgesamt 579+ Tests), Coverage 93 % auf Block-G-Modulen. AsyncOpenAI-Wrapper mit Fernet-encrypted API-Key, SSE-Streaming, Prompt-Injection-Marker `<<TRIVY_DATA_START>>`/`<<...END>>`, `nh3`-Allowlist für LLM-Output, Token-Cap (80%-Warning/100%-Block), `llm_base_url`-Whitelist (HTTPS außer localhost), Provider-Wechsel-Hook archiviert aktive Conversations. **Live-Smoke gegen DeepInfra DeepSeek-V3**: 306 Tokens gestreamt (1538 Zeichen Antwort, 23679 prompt + 550 completion), Audit `llm.queried`, Encrypted Key per `down -v` gewipt. Screenshot: `docs/blocks/G-evidence/chat.png`.
- **H — Live-Updates, Production-Hardening, Final-Polish** · abgeschlossen 2026-05-15 · Branch `feat/block-h` · Reviewer-Freigabe nach Re-Review (Image-Size, E2E-Skript-Regex, Screenshot-Defekte gefixt). Final-Security-Auditor: ACCEPTABLE WITH NOTES (1 low CONCERN: per-Server-Auth-Rate-Limit aus §9 als post-v0.1.0-Folge). 629 Tests grün (50 neue Block-H-Tests), Coverage 92.16 %. In-process Event-Bus mit `GET /events` SSE-Endpoint (Heartbeat 30s), Dashboard-Live-Card-Animation, 60s-Stale-Re-Render-Timer. Block-G-Action-Items umgesetzt: ADR-0013 (Fernet-KDF-Beibehalten + Weak-Key-Warning), ADR-0014 (Token-Cap-Best-Effort), `validate_base_url` Port-Range-Check, `@limiter.limit("60/hour")` auf `/chat/<id>/stream` und `/settings/llm/test-connection`, `Authorization` in structlog-Redaction-Pattern. Docker-Image 278 → 191 MB (Three-Stage flat-runtime). `scripts/e2e_smoke.sh` mit Python-Master-Key-Extraktion exit 0 in allen 11 Phasen. README mit nginx/Caddy/IP-Allowlist-Snippets. CHANGELOG.md mit v0.1.0-Eintrag. Screenshot: `docs/blocks/H-evidence/dashboard-live.png`. **Tag `v0.1.0` gesetzt.**
- **I — UI-Modernisierung (Single-Page-Sidebar-Layout)** · abgeschlossen 2026-05-15 · Branch `feat/block-i` · Reviewer-Freigabe 27 PASS / 0 FAIL. Security-Auditor: **CLEAN** (keine neuen Sicherheits-Surfaces, 8 Punkte alle PASS). 45 neue Block-I-Tests grün (insgesamt 674), Coverage 92.54 %. `base_app.html` als Single-Page-Shell mit Sidebar (Quick-Stats, Sticky-Search mit `/`-Shortcut, Tag-Filter, Server-Liste mit Heartbeat-Bars, Settings-Akkordeon) + Detail-Pane (HTMX-Swap, `hx-push-url`). Heartbeat-Aggregation als Python-Service (Variante B, on-the-fly), Performance 50×50<200ms. `_inject_sidebar_context`-Context-Processor injiziert Sidebar-Variablen automatisch. `_partial_shell.html` für HX-Fragmente. Empty-States, Monospace-Cleanup, Quick-Copy-Macro-Fix aus Block F. Funktional gegenüber v0.1.0 unverändert. Screenshots: `docs/blocks/I-evidence/{dashboard,server-detail}.png`. **Tag `v0.2.0` gesetzt.**
- **I-Refinement (ADR-0016) — Header + Profile-Dropdown + Settings-Sekundär-Nav + Master-Key/About** · abgeschlossen 2026-05-15 · Branch `feat/block-i-refinement` · Reviewer-Freigabe 19 PASS / 0 FAIL (nach Lint-Fix). Security-Auditor: **ACCEPTABLE WITH NOTES** (1 low CONCERN — fehlender XSS-Adversarial für Master-Key-Klartext, kein realer Vektor weil URL-safe-Base64-Zeichensatz). 48 neue Tests grün (insgesamt 722), Coverage 92.21 %. Header kompakt (Logo + Dashboard + Suche + Theme-Toggle + Profile-Avatar), Profile-Dropdown flach (Settings/Audit/Logout), Settings-View mit linker Sekundär-Nav (Tags/LLM-Provider/Server-Verwaltung/Master-Key/About). Neue Routen `/settings/master-key` (Rotation mit Confirm-Modal + einmaliger Klartext-Anzeige + Audit-Event `master_key.rotated` mit nur hash_prefix) und `/settings/about` (Version/Build-Hash/Alembic-Revision read-only). `/settings` → 302 auf `/settings/servers/`. Sidebar auf reine Server-Liste reduziert. 3-Modi-Render-Helper `app/views/_settings_shell.py` (Vollseite/Shell-Fragment/Content-only). Conftest-Härtung gegen TRUNCATE-Lock-Hänger via `lock_timeout` + `pg_terminate_backend`. Screenshots: `docs/blocks/I-refinement-evidence/{dashboard,profile-dropdown,settings-servers,settings-master-key,settings-about}.png`. **Tag `v0.3.0` zu setzen.**
- **J — Dashboard-Pane-Konsolidierung (ADR-0017)** · abgeschlossen 2026-05-16 · Branch `feat/block-j-dashboard-pane` · 728 Tests grün (+3 neue Pane-Konsistenz-Regression-Tests), `ruff check` + `mypy app/` + Alembic-Roundtrip PASS. Gemeinsames Partial `dashboard/_detail_pane.html` wird sowohl von der Full-Page-Shell (`dashboard/index.html` via `{% include %}`) als auch direkt vom HX-Pfad in `app/views/dashboard.py` über `_build_pane_context()`-Helper konsumiert. `_pane/welcome.html` plus leeres `_pane/`-Verzeichnis entfernt. `base_app.html`-Welcome-Fallback weg, defensiver `if main_pane`-Zweig bleibt. Regression-Test prüft Pane-Marker-Identität in beiden Render-Pfaden und HX-Fragment-Eigenschaft (kein `<html>`/`<aside>` im Response). Bugfix/Refactor — funktional gegenüber v0.3.0 unverändert.
- **M — Dashboard-Redesign: Cross-Server-Findings + KPI-Sparklines + /findings/search-Entfernung (ADR-0020)** · abgeschlossen 2026-05-16 · Branch `feat/block-m` · Reviewer-Freigabe APPROVE (alle DoD-Items grün, drei PENDING-Items vom Orchestrator beim Final-Commit erledigt). Security-Auditor: ACCEPTABLE WITH NOTES (alle 5 Audit-Punkte PASS; 2 kosmetische NOTES adressiert). 869 Tests grün (+21 neue View-Tests + 20 neue Service-Tests + 48 neue Adversarial-Cases; 1 gelöscht: `tests/views/test_search.py` mit 15 Tests; 5 e2e SKIPPED, 2 Bench-Cases deselected). Coverage 91.78 %, 224 adversarial PASS. `ruff check`/`ruff format --check`/`mypy app/` PASS, Alembic-Roundtrip PASS, `docker compose up --build` + `/healthz` PASS, Image 191 MB. Entfernt: `app/views/search.py` (~350 LoC), `app/templates/findings/search.html`, `_empty/no_search_results.html`, Dashboard-Templates `_quick_stats.html`/`_filter_bar.html`/`_attention.html`, `AttentionSection`-Dataclass + `_build_attention()` aus `app/views/dashboard.py`. Neu: `app/services/stale_history.py` (`daily_stale_server_counts`), `daily_severity_counts_fleet` in `severity_history.py`, `list_findings_cross_server` in `findings_query.py` (Cross-Server-Sort inkl. `server`-Key, OR-`q`-Filter, exakter Pre-Limit-Count), `stream_findings_csv_cross_server` in `csv_export.py`, `dashboard/_kpi_cards.html`/`_findings_section.html`/`_findings_filter_bar.html`. `DashboardFilter` um `q`/`status`/`sort`/`dir` + `to_query_string(override=...)` erweitert. `_macros.html:sort_header()` um optionale `route`/`route_kwargs` erweitert. `servers/_kpi_card.html` um optionalen `link_url`-Parameter erweitert (Block-K-Aufrufer unverändert). Polling-Wrapper aus Block L (`hx-disinherit="*"`) auf neuem Pane-Container unverändert. ARCHITECTURE §7 + §15 auf Block-M-Layout aktualisiert; ADR-0016 als „Teilweise abgelöst durch ADR-0020" markiert; Sidebar-Such-Form zeigt jetzt auf `dashboard.index?q=...`. Beifang aus Auditor-Bericht: Doc-Korrektur in `app/api/__init__.py` (CSRF NICHT global ausgeschaltet) und Kommentar-Cleanup in `app/static/js/stale.js` (`_attention.html`-Referenz raus). **Tag `v0.6.0` zu setzen.**

- **L — Dashboard-Polling statt SSE (ADR-0019)** · abgeschlossen 2026-05-16 · Branch `feat/block-l` · Reviewer-Freigabe APPROVE (alle DoD-Items grün). 785 Tests grün (3 neue: `tests/views/test_dashboard_polling.py`, `tests/views/test_sidebar_partial.py`, `tests/adversarial/test_polling_no_rate_limit.py`; 3 gelöscht: `tests/api/test_events_sse.py`, `tests/api/test_scans_event_publish.py`, `tests/services/test_event_bus.py`; 5 e2e SKIPPED ohne Backend). Coverage 92.35 % (Threshold 85 %), 177 adversarial PASS. `ruff check`/`ruff format --check`/`mypy app/` PASS, Alembic-Roundtrip PASS, `docker compose up --build` + `/healthz` PASS, Image 191 MB, Idle-CPU 0.04 % unter offenem Tab. Entfernt: `app/api/events.py` (116 LoC), `app/services/event_bus.py` (163 LoC), `event_bus.publish`-Hook in `app/api/scans.py`, `init_event_bus(app)` + `events_bp` aus `app/__init__.py`, Alpine-Komponente `dashboardSse(...)` plus `window.dashboardSse`-Export. Neu: Polling-Wrapper in `app/templates/dashboard/_detail_pane.html` (`#dashboard-pane`, `every 10s`, `outerHTML`) und Sidebar-Polling-Route `GET /_partials/sidebar` (`sidebar_partials_bp.sidebar_partial`, `@login_required`) mit Container `#server-list`. JS-Datei `app/static/js/sse.js` umbenannt zu `stale.js`; `staleTick()` unverändert, Doc-Header zugeschnitten. `sse_highlight.js` bleibt (Polling-Highlight via `htmx:afterSettle`). ARCHITECTURE §6/§7/§7a auf Polling umgestellt; §14-Audit-Log-Hinweis von nie-implementiertem `scan.received` auf echtes `scan.ingested` korrigiert. Filter-Persistenz (`request.path` + optionale `request.query_string`) erhalten. **Tag `v0.5.0` zu setzen.**

- **K — Server-Detail-Redesign (ADR-0018)** · abgeschlossen 2026-05-16 · Branch `feat/block-k` · Reviewer-Freigabe nach Re-Review (ruff-format auf 3 neue Test-Files). 797 Tests grün (+69 neue Block-K-Tests: 20 Service-Unit-Tests + 13 View-Tests + 36 Adversarial-Sort-Param + 0 weitere; 5 e2e SKIPPED). `ruff check` + `ruff format --check` (Block-K-Outputs) + `mypy app/` (0 Errors) + Alembic-Roundtrip + `docker compose up --build` + `/healthz` 200 — alles PASS. Neue Services: `app/services/trend.py` (`Tendency`-Enum + `compute_tendency()` avg-7T-vs-avg-50T-±5%-Heuristik), `app/services/severity_history.py` (`DailySeverityCount`-Dataclass + `severity_snapshots_for_server` + `daily_severity_counts_for_server` + `count_kev_events_50d` — on-the-fly aus Finding-Lifecycle, KEINE neue persistente Tabelle). Schema-Erweiterung: `FindingsViewFilter.sort`/`.dir` mit Literal-Whitelist + Fallback-auf-Default. `findings_query.list_findings` mit statischem `_SORT_COLUMNS`-Mapping (ORM-only). CSV-Export `mode=flach|gruppiert|diff` mit Group-Spalte bzw. `DiffStatus`-Spalte und leerer-Diff-Fallback-Hinweis. Templates: `detail.html` komplett umgebaut auf `max-w-[1600px]` mit Header/HeaderStats/Lebenszeichen/Severity-Trend/Tag-Editor-Akkordeon/Findings-Section; `_kpi_card.html`/`_heartbeat_large.html`/`_stacked_bar_chart.html` neu (Inline-SVG, kein Node-Build); `_macros.html` um `sort_header()` und `tendency_label()` erweitert; `_findings_section.html` ohne Filter-Form, mit Mode-Segment + Bulk-Ack-Toolbar + CSV-Dropdown. Bulk-Ack wiederverwendet `POST /api/findings/bulk-acknowledge` aus Block F unverändert. Performance-Bench Daily-Snapshots 10k×50T standalone ~80–100 ms (ADR-0018-Schwelle). Bekannte Limitations dokumentiert in ADR-0018 (Re-Open-Events, 100k-Findings-Server, Re-Open-Trigger für persistente Snapshot-Tabelle). Default-Sort `sev,desc` mit `identifier_key`-Tiebreak ersetzt im Detail-View den §15-`is_kev DESC`-Tiebreak (ADR-konform). **Tag `v0.4.0` zu setzen.**

## Backlog (in Reihenfolge)

| Block | Datei | Status |
|-------|-------|--------|
| A | [A-skeleton.md](A-skeleton.md) | completed 2026-05-14 |
| B | [B-models.md](B-models.md) | completed 2026-05-14 |
| C | [C-ingest.md](C-ingest.md) | completed 2026-05-14 |
| D | [D-dashboard.md](D-dashboard.md) | completed 2026-05-14 |
| E | [E-triage.md](E-triage.md) | completed 2026-05-14 |
| F | [F-bulk.md](F-bulk.md) | completed 2026-05-14 |
| G | [G-llm.md](G-llm.md) | completed 2026-05-15 |
| H | [H-polish.md](H-polish.md) | completed 2026-05-15 — **MVP v0.1.0** |
| I | [I-ui-modernization.md](I-ui-modernization.md) | completed 2026-05-15 — **MVP+UI v2 v0.2.0** |
| I-Refinement | [I-addendum-header-layout.md](I-addendum-header-layout.md) | completed 2026-05-15 — **v0.3.0** (ADR-0016) |
| J | [J-dashboard-pane-consolidation.md](J-dashboard-pane-consolidation.md) | completed 2026-05-16 — ADR-0017 (Dashboard-Pane-Konsolidierung) |
| K | [K-server-detail-visual.md](K-server-detail-visual.md) | completed 2026-05-16 — **v0.4.0** (ADR-0018 Server-Detail-Redesign) |
| L | [L-dashboard-polling.md](L-dashboard-polling.md) | completed 2026-05-16 — **v0.5.0** (ADR-0019 Dashboard-SSE → HTMX-Polling, LLM-Stream-SSE bleibt) |
| M | [M-dashboard-findings.md](M-dashboard-findings.md) | completed 2026-05-16 — **v0.6.0** (ADR-0020 Cross-Server-Findings + KPI-Sparklines, /findings/search-Removal) |
| N | [N-agent-installer.md](N-agent-installer.md) | completed 2026-05-18 — **v0.7.0** (ADR-0021 Bootstrap-Installer + Trivy-Output-Strip + Ursachen-Felder pro Finding) |
| O | [O-risk-engine.md](O-risk-engine.md) | completed 2026-05-18 — **v0.8.0** (ADR-0022 Pre-Triage-Risk-Engine + Host-Snapshot + Vendor-Severity + Risk-zentrisches UI) |
| P | [P-llm-risk-reviewer.md](P-llm-risk-reviewer.md) | completed 2026-05-19 — **v0.9.0** (ADR-0023 LLM-Risk-Reviewer + Application-Grouping + async Worker) |
| R | [R-async-ingest.md](R-async-ingest.md) | completed 2026-05-22 — **v0.11.0** (ADR-0026 Asynchroner Scan-Ingest + Worker-Sub-Tick + Status-Endpoint + Agent 0.4.0 Polling-Loop) · Nachtrag 2026-05-28 (ADR-0042): Status-Endpoint + Polling entfernt, Agent Fire-and-Forget |
| T | [T-eval-junction.md](T-eval-junction.md) | completed 2026-05-22 — **v0.11.x** (ADR-0028 Application-Group-Evaluations als Junction, behebt Cross-Server-Last-Write-Wins) |
| U | [U-worker-concurrency.md](U-worker-concurrency.md) | completed 2026-05-23 — **v0.11.0** (ADR-0029 Parallele LLM-Job-Verarbeitung, In-Process-Concurrency) |
| V | [V-ui-performance.md](V-ui-performance.md) | completed 2026-05-23 — **v0.12.0** (ADR-0030 Performance-Tuning UI-Views — Dashboard + Server-Detail + Sidebar-Lazy-Load) |
| W | [W-redesign-phase-1.md](W-redesign-phase-1.md) | completed 2026-05-24 — **v0.12.0** (ADR-0032..0036 Frontend-Redesign Phase 1 + Tailwind/DaisyUI-Out, Legacy-Shim) |
| X | [X-server-detail-content-refactor.md](X-server-detail-content-refactor.md) | completed 2026-05-24 — **v0.13.0** (ADR-0038 Server-Detail Content-Refactor + Style-Adoption, acht Phasen-Commits, +242 Pure-Unit-Tests) |

## Aktive Blocker

(keine)

## Offene ADR-Wünsche

(keine — ADR-0023 deckt Block P komplett ab. Drei optionale Re-Open-Trigger aus Security-Auditor-Bericht: Worker auf structlog umstellen, `ON CONFLICT DO NOTHING` in `_persist_pass1_groups` fuer Multi-Worker-Skalierung, Setup-Wizard-DSGVO-Notice mit konkreter Feld-Liste. Wenn Implementer eine neue Architektur-Entscheidung braucht, hier eintragen und Spec ergänzen bevor Code geschrieben wird.)

## Update-Konvention

- Beim Block-Start: Status auf "in progress" setzen, Branch-Name notieren.
- Beim Block-Abschluss (nach `reviewer`-Freigabe): Block in "Completed" verschieben mit Datum, nächsten Block als "Aktueller Block" markieren.
- Bei neuen Blockern: in "Aktive Blocker" eintragen mit Datum und Beschreibung.
- Aktive Blocker MÜSSEN aufgelöst sein bevor der Block als completed markiert wird.
