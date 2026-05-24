# Block X — Server-Detail Content-Refactor + Style-Adoption (Triage-First)

**Spec-Quelle:** [ADR-0038](../decisions/0038-server-detail-triage-refactor.md)
**Branch:** `feat/block-x-server-detail-content`
**Zielversion:** v0.13.0
**Vorgänger:** Block W (v0.12.0, ADR-0032/0033/0034/0035/0036 — Frontend-Redesign Phase 1: Login + Dashboard + App-Shell)
**Visueller Soll-Stand:** liegt vor in [`../design/ServerDetail.jsx`](../design/ServerDetail.jsx), [`ServerSettings.jsx`](../design/ServerSettings.jsx), [`server-detail.css`](../design/server-detail.css), [`server-detail-data.js`](../design/server-detail-data.js) (Output aus Claude-Design, 2026-05-24). Inhalts-Mockup-Referenz: [`../ux/mockup-iter-01.html`](../ux/mockup-iter-01.html).
**Status:** Spec bereit

## Lektüre vor dem ersten Commit

1. ARCHITECTURE.md §7 (Server-Detail-View), §7a (Sidebar/QuickStats) — Sektions-Reihenfolge ist hier festgehalten und wird in dieser Spec überschrieben.
2. ADR-0018 (Server-Detail-Sektions-Reihenfolge, Heartbeat-50/7) — wird teilweise abgelöst.
3. ADR-0022 §UI-Redesign (Host-Snapshot-Sektion + Action-Required-Pill) — Host-Snapshot-UI wird abgelöst, Persistenz unangetastet.
4. ADR-0023 §UI-Konsequenzen (Application-Group-Cards + „Was zu tun ist") — wird durch Workflow-Card-Drilldown amendet.
5. ADR-0033 Color-Reduction + ADR-0035 Heartbeat 30/4 — wird auf Detail-Seite angewandt (Re-Anchor, keine Neu-Entscheidung).
6. `docs/ux/mockup-iter-01.html` — Inhaltsmodell-Mockup (Detail-Pane-only).
7. `app/templates/servers/detail.html`, `_partials/host_snapshot.html`, `_action_needed_section.html`, `_findings_section.html`, `_tag_editor.html`, `_heartbeat_large.html`, `_stacked_bar_chart.html`, `_kpi_card.html`.

## Out of scope (explizit)

- **Host-Group-CRUD-UI** — Block X bringt nur die Group-Auswahl im Settings-Sub-View. Anlegen/Löschen/Umbenennen von Groups bleibt einem Folge-Block.
- **Add-Host-UI** — analog.
- **Repo-Rename `secscan` → `fathometer`** — separater ADR notwendig.
- **Performance-Re-Tune** — nur falls die zwei neuen Aggregator-Queries (Risk-Band-Top-Level-Count, Workflow-Card-Drilldown) im Realbetrieb messbar drücken. Bench-Lauf nur auf User-Anweisung (`CLAUDE.md` Test-Konvention).
- **Schema-Migrationen** — keine. Alle neuen Felder im Settings-Sub-View schreiben auf bestehende Spalten (`server.group_id` aus ADR-0034, `server.expected_scan_interval_h` aus Block N).
- **Settings/Findings/Audit-Redesign** — eigene Folge-Blöcke.

## Phasen

### Phase A0 — CSS-Foundation + JS-Helper aus Claude-Design-Output adoptieren

Ziel: bevor Markup-Phasen starten, das fertige `sd-*`-Klassen-Setup aus `docs/design/` in den Frontend-Build einbinden, damit die Folge-Phasen gegen reale Styling-Klassen schreiben können.

Tasks:

- A0-1: `docs/design/server-detail.css` 1:1 nach `frontend/src/css/components/server-detail.css` portieren. Hex-Werte gegen `var(--*)`-Tokens aus `tokens.css` mappen (keine Hardcodes — Token-Inventar prüfen wo nötig erweitern, aber Token-Set ist seit ADR-0033 vollständig).
- A0-2: `frontend/src/css/app.css` — neuen `@import "components/server-detail.css"` hinzufügen (Source-Order: nach `tokens` + Foundation, vor `legacy-shim`).
- A0-3: `frontend/src/js/server_detail.js` (neu) — Vanilla-JS-Port der Helper aus `ServerDetail.jsx`: `useScanFlashSync` als `setupScanFlashSync(rootEl, deps)` mit ResizeObserver + document.fonts.ready; `serverPillPanels()`-Alpine-Component für die zwei `sd-chip`-Slide-Down-Panels (Single-Open-State); `serverDetailHeartbeatTip`-Event-Delegation analog `sidebar_heartbeat_tip.js` aus Block W.
- A0-4: `frontend/src/js/app.js` — `server_detail.js`-Init-Hook bei `htmx:afterSettle` registrieren (Pane-Swap kompatibel).
- A0-5: Tests — `tests/frontend/test_server_detail_bundle.py` (oder analog Block W `test_asset_manifest.py`): Bundle enthält `server-detail.css` und der Manifest-Eintrag löst auf; `tests/frontend/test_server_detail_js.py`: `serverPillPanels()`-Component-Registration ist in `app.js`-Bundle enthalten, kein Tailwind-Klassenname.
- A0-6: Legacy-Shim-Schrumpfung — die Tailwind-/DaisyUI-Klassen die heute in `detail.html`/`_findings_section.html`/`_action_needed_section.html`/`_partials/host_snapshot.html` referenziert sind, müssen post-Block-X nicht mehr aus dem Shim kommen. In Phase G abschließendes Audit: welche Shim-Zeilen sind nach Block X frei?

### Phase A — Header-Sysline + Quickinfo-Konsolidierung + KEV-Tile-Streichung

Ziel: Quickinfos aus dem Lebenszeichen-`<dl>` in die Header-Sysline ziehen, „letzter scan" aus der OS-Zeile entfernen (war doppelt), KEV-Ereignisse · 50T ersatzlos streichen.

Tasks:

- A1: `detail.html`-Header umbauen. OS-Zeile zeigt nur noch `os · kernel · arch`. Neue Sysline darunter (Pattern aus `app/templates/_partials/_sysline.html` aus Block W) mit `> expected interval <N> h · last scan <relative> · trivy-db <relative>`. Tooltips bleiben (absolute Zeitstempel).
- A2: Lebenszeichen-Sektion (`detail.html` Sektion 4) — `<dl class="grid grid-cols-2 md:grid-cols-4 …">`-Block komplett raus.
- A3: View-Context (`app/views/server_detail.py`) — `kev_events_50d` aus `_build_context` entfernen, `count_kev_events_50d` in `app/services/severity_history.py` als deprecated markieren (verwendet von Block X+1 sowieso nicht mehr; finaler Removal in einem Cleanup-PR).
- A4: Tests — `tests/templates/test_detail_header.py` (neu) prüft: OS-Zeile enthält kein „letzter scan", Sysline rendert die drei Quickinfos in der dokumentierten Reihenfolge, KEV-Tile rendert nicht mehr im `<dl>`.

### Phase B — Settings-Sub-View + Tag-/Group-/Interval-Editoren

Ziel: Tag-Editor und neue Group-/Scan-Interval-Editoren in eine dedizierte Sub-View `/servers/<id>/settings`; Tag-Hashtag-Zeile + Tag-Editor-Akkordeon aus der Detail-View entfernen.

Tasks:

- B1: Route `GET /servers/<int:server_id>/settings` in `app/views/server_settings.py` (neu). Vollseite + HX-Fragment, analog `app/views/_settings_shell.py`-Pattern aus ADR-0016 (Block-I-Refinement). Auth `@login_required`. 404 wenn server nicht existiert oder revoked/retired (Owner-Check).
- B2: Template `app/templates/servers/settings.html` (neu). Drei Sektionen: Tags / Group / Scan-Interval. Save-Button pro Sektion (unabhängig speicherbar). „← Back to detail"-Link oben links.
- B3: Tag-Editor — bestehender `_tag_editor.html` wandert hierher (Markup unverändert). Tag-Add/Remove-POST-Handler wandern auf `POST /servers/<id>/settings/tags` (oder bleiben auf bestehender Route, die per `Referer`/HX-Trigger entscheidet — sauberer ist neue Routen-Schicht).
- B4: Group-Selector — neues `POST /servers/<id>/settings/group` mit CSRF-protected Form, schreibt `server.group_id` (FK auf `server_groups`, ADR-0034). Single-Select mit allen existierenden Groups + „— keine —". Validation: nur Groups die existieren; SET NULL ist erlaubt.
- B5: Scan-Interval-Editor — neues `POST /servers/<id>/settings/scan-interval` mit Number-Input (1–168, Default-Anzeige aus `server.expected_scan_interval_h`). Validation: Integer, Range-Check. Audit-Event `server.scan_interval_changed` (alt → neu).
- B6: Detail-View Header — Hashtag-Zeile (`{% if server.tag_links %}<p class="…">…#{{ link.tag.name }}…</p>{% endif %}`) raus. Tag-Editor-Akkordeon-Sektion (Sektion 2) raus. Zahnrad-Icon-Button rechts neben dem KI-Bewertung-Button hinzu, `href="{{ url_for('server_settings.show', server_id=server.id) }}"`.
- B7: Tests — `tests/views/test_server_settings.py` (neu): Vollseite + HX-Fragment-Render, Tag-Add/Remove, Group-Set/Unset, Scan-Interval-Range-Check inkl. Out-of-Range-Reject. `tests/templates/test_detail_header.py` (Phase A) erweitert: Hashtag-Zeile rendert nicht mehr, Zahnrad-Button-Link zeigt auf Settings-Sub-View.

### Phase C — Host-Snapshot-Pills mit Slide-Down-Panels (inkl. Exposure-Klassifizierung + Pill-Umbenennung + keine Pagination)

Ziel: `_partials/host_snapshot.html` als eigenständige Sektion entfernen, stattdessen zwei Header-Pills mit Slide-Down-Panels im Flow, Listener-Tabelle bekommt Exposure-Spalte.

Tasks:

- C1: `detail.html`-Header — zwei neue `<button class="sd-chip" data-test="pill-listeners|services">`-Pills inline am Ende der Header-Sysline mit Counts. Beide haben `aria-controls` auf die Panel-IDs.
- C2: **Pill-Labels:** Pill 1 heißt **„Listeners"** (nicht „Listeners & services") — Begründung in ADR-0038 §(3). Pill 2 heißt „Active services".
- C3: Panel-Partial `_partials/server_pill_listeners.html` (neu) — `<div class="sd-flyout">` mit `<table class="sd-listener-table">`: **vier Spalten** Process · Addr:port · Proto · **Exposure**. Bei `addr matched 127.0.0.0/8 OR ::1` → `<span class="sd-listener-tag">LOOPBACK</span>` (neutral). Sonst → `<span class="sd-listener-tag sd-listener-tag--exposed">PUBLIC EXPOSED</span>` (cyan-outline).
- C4: Panel-Partial `_partials/server_pill_services.html` (neu) — `<div class="sd-flyout">` mit Mono-`·`-Liste der systemd-Unit-Namen.
- C5: **Keine Pagination.** Beide Panels rendern komplette Liste. Bei vielen Einträgen (> ~30) bekommt `.sd-flyout__body` `overflow-y: auto` + `max-height: 360px`. Kein „show more"-Toggle, keine Page-Navigation.
- C6: Render-Helper `app/services/listener_exposure.py` (neu) — `classify_exposure(addr: str) -> Literal["LOOPBACK", "PUBLIC EXPOSED"]`. Pure Function, keine DB-Query, keine Persistenz-Spalte. Verwendet `ipaddress.ip_address(addr).is_loopback`-Pattern aus stdlib für IPv4 + IPv6.
- C7: Alpine-Komponente — bereits in Phase A0-3 angelegt (`serverPillPanels()`), wird hier nur gebunden.
- C8: `_partials/host_snapshot.html` löschen. View-Context (`app/views/server_detail.py`) — `listeners`/`services`/`processes` werden weiterhin gebraucht, jetzt für die Panel-Partials statt für die Sektion. Listener-Records bekommen im View-Context eine zusätzliche `exposure: Literal["LOOPBACK", "PUBLIC EXPOSED"]`-Property pro Eintrag (im Template-Vertrag, nicht am ORM-Modell).
- C9: Empty-State (snapshot_at IS NULL) — Pills rendern als `disabled` mit `title="Update agent to ≥ 0.3.0 for snapshot"`-Tooltip. Panel-Body rendert nicht.
- C10: Tests — `tests/services/test_listener_exposure.py` (neu): `classify_exposure("127.0.0.1") == "LOOPBACK"`, `classify_exposure("0.0.0.0") == "PUBLIC EXPOSED"`, `classify_exposure("::1") == "LOOPBACK"`, `classify_exposure("::") == "PUBLIC EXPOSED"`, externe IPv4/IPv6 → `PUBLIC EXPOSED`, ungültige Eingaben → defensive `PUBLIC EXPOSED` (Fail-safe: lieber Pille zeigen als verschweigen). `tests/templates/test_host_snapshot_pills.py` (neu): Pills rendern mit Counts, Pill-1-Label ist „Listeners" (nicht „Listeners & services"), Disabled-State bei snapshot_at IS NULL, Panel-Partials enthalten die Exposure-Spalte mit den richtigen Klassen-Modifiers, keine Pagination-Controls im Markup.
- C11: Sektion-Removal-Test — `_partials/host_snapshot.html` existiert nicht mehr; `detail.html` enthält kein `data-test="host-snapshot-section"` mehr.

### Phase D — Workflow-Card-Drilldown-Tabelle (Group · Worst Finding · Reason)

Ziel: `_action_needed_section.html`-Cards bekommen beim Expand eine Tabelle mit Group-Drilldown statt nur der Sub-Line der Group-Labels.

Tasks:

- D1: View-Helper `_build_action_sections` (`app/views/server_detail.py`) — die `groups`-Liste pro Card bekommt für jedes Group-Element zusätzlich `worst_finding` (Finding-Object) und `reason` (`application_group_evaluations.reason_text`, ggf. None). Worst-Finding kommt aus dem bestehenden Loader, Reason via existing `application_group_evaluations`-Tabelle (ADR-0028) per LEFT JOIN auf `(group_id, server_id)`.
- D2: `_action_needed_section.html` — Card-Body bekommt eine `<table class="workflow-drilldown">` mit drei Spalten. Sub-Line der Group-Labels (`labels | join(', ')`) entfällt — sie wird durch die Group-Spalte der Tabelle ersetzt.
- D3: Pagination-Stub — wenn `groups | length > 25`: Pagination-Footer „Seite 1 von N" + Disabled-Prev-Next-Buttons. Echte Pagination kommt in einem Folge-PR (Operator-Realität: vermutlich nie > 25 Groups in einer Workflow-Card; Stub damit das Markup-Pattern stabil ist).
- D4: Tests — `tests/services/test_action_sections.py` (existiert vermutlich aus Block P, ergänzen): pro Card-Group sind `worst_finding` und `reason` belegt. `tests/templates/test_action_needed_drilldown.py` (neu): Tabelle rendert drei Spalten, Reason ist im Markup (auto-escaped, kein `|safe`), Pagination-Stub rendert ab > 25 Groups.

### Phase E — Lebenszeichen 30/4 + Severity-Trend ohne 50T + Skeleton-States

Ziel: Detail-Seite zieht ADR-0035 (Heartbeat 30 Ticks / 4 Risk-Band-Zustände aus `dominant_risk_band`) und Severity-Trend-Range-Reduktion auf 24h/7T/30T. Beide Sektionen + die KPI-Tiles aus Phase A bekommen Skeleton-States.

Tasks:

- E1: `_heartbeat_large.html` — komplett umbauen auf `sd-heartbeat`-Klassen aus `server-detail.css` (Phase A0). 30 Ticks, 4 Bands (`sd-heartbeat__tick--unknown|nominal|act|escalate`).
- E2: Hover-Tooltip — `.sd-heartbeat-tip`-Pattern (CSS aus Phase A0, JS-Handler in `server_detail.js`).
- E3: View-Helper — `heartbeat_cells_for_server` aus `app/services/heartbeat_aggregation.py` schon vorhanden seit Block W; nur `days=30`-Default sicherstellen (war 50 in der Detail-Variante).
- E4: Legende — 4-Zustand-Legende (`unknown/nominal/act/escalate`) im `sd-heartbeat__legend`-Container.
- E5: `_stacked_bar_chart.html` — komplett umbauen auf `sd-trend`-Klassen. Range-Toggle entfernt `50T`-Button, behält `24h / 7T / 30T`. Default `30T`.
- E6: **Skeleton-States** für drei Sektionen:
  - **KPI-Tiles** (`_kpi_card.html`): bei `skel=True` Container bekommt `sd-tile--skel sd-skel-frame`, Zahl rendert `—`, Sparkline ist ausgeblendet.
  - **Heartbeat-Strip**: pro Tick-Element `sd-heartbeat__tick--skel`, Container `sd-skel-frame` mit scan-probe-Beam.
  - **Severity-Trend**: pro Bar-Element `sd-trend-col--skel`, Container `sd-skel-frame`.
  - Trigger: HTMX-Initial-Load (hx-indicator vom Polling-Wrapper) und Polling-Re-Render. Skel-State zwischen Request-Issue und Response-Render <200 ms sichtbar — subtiler Wisch, kein Spinner. Pattern identisch zu Sidebar-Heartbeat-Skel aus Block W.
  - Empty-State `host_state_snapshot_at IS NULL` rendert **nicht** den Skel-Scan-Beam — stattdessen Mono-Text „— noch nie gescannt".
- E7: Tests — `tests/services/test_heartbeat_aggregation.py` (existiert): neuer Test für Detail-Variante mit `days=30`. `tests/templates/test_heartbeat_large.py` (neu): rendert 30 Ticks, vier-Bands-Legende, Skel-State-Modifier-Klassen korrekt. `tests/templates/test_severity_trend.py` (existiert): Toggle-Buttons sind nur `[24h, 7T, 30T]`, Skel-State-Klassen korrekt. `tests/templates/test_kpi_card.py` (neu oder erweitert): Skel-State rendert `—` statt Zahl, Sparkline ausgeblendet, `sd-skel-frame`-Modifier-Klasse präsent.

### Phase F — Triage Queue Risk-Band-Top-Level-Accordion

Ziel: Application-Group-Cards (ADR-0023) und Pending-Grouping-Block (ADR-0025) bleiben als Card-Pattern unverändert; neuer Risk-Band-Accordion darüber.

Tasks:

- F1: View-Helper `_build_risk_band_sections` (neu in `app/views/server_detail.py`) — gruppiert die existierenden `application_groups` (von ADR-0025 `_load_application_groups_for_server`) nach `risk_band`. Liefert sechs Slots in `_RISK_BAND_RANK`-Reihenfolge (ESCALATE / ACT / MITIGATE / PENDING / MONITOR / NOISE). Pending-Grouping-Block hängt unter PENDING-Slot.
- F2: Single Aggregat-Query — pro Slot nur `count(*)` für den Header. Card-Bodies kommen lazy via existierende ADR-0025-Card-Lazy-Load-Endpoints (keine neue Route).
- F3: `_partials/risk_band_section.html` (neu) — `<details>`-Slot mit Summary (Chevron + Phase-Badge outline + Count) und Body (Card-Container).
- F4: `_findings_section.html` — Card-Loop wandert in das neue `risk_band_section`-Partial. Default-Expanded-Logik: ESCALATE-Slot offen wenn Count > 0; sonst erster nicht-leerer Slot. Alle anderen Slots collapsed.
- F5: Lazy-Load-Hook — kein neuer Endpoint nötig; existing Card-Lazy-Load aus ADR-0025 §(2) wird durch das Schließen des Risk-Band-Accordions nicht beeinflusst (Cards bleiben collapsed bis ihr eigenes `<details>` geöffnet wird; Risk-Band-Accordion-Toggle ändert nur die Sichtbarkeit der Card-Header).
- F6: Tests — `tests/services/test_risk_band_sections.py` (neu): sechs Slots in Reihenfolge, Card-Distribution stimmt mit `application_group.risk_band` überein, Pending-Block unter PENDING-Slot, Default-Expanded-ESCALATE-Logik. `tests/templates/test_risk_band_accordion.py` (neu): `<details open>` nur auf ESCALATE-Slot bei nicht-leerem ESCALATE, sonst auf erstem nicht-leerem Slot.

### Phase G — Action-Needed-Scan-Flash + Status-Pills + Per-Finding-AI-Assessment + Bulk-Ack-Noise-Shortcut

Ziel: Header-Pille fertigstellen (Animation + Render-Condition), Status-Pills stratten, Inline-AI-Reason, Bulk-Shortcut.

Tasks:

- G1: **Action-Needed-Pill** (`_partials/action_required_pill.html`) — komplett umbauen auf `sd-status-pill`-Klassen aus Phase A0.
  - **Render-Condition verschärft:** Pill rendert nur wenn `yes_subcounts.escalate + yes_subcounts.act > 0`. Bei `pending`/`unknown`-only-Servern rendert sie nicht (heute ja). View-Context-Anpassung in `_inject_action_required_context` oder analog.
  - **Scan-Flash:** Pill-Text in `<span class="scan-chars">` umschließen, pro Zeichen `<span class="scan-flash">` (Pattern aus `_action_needed_card.html` Block W Phase D). `useScanFlashSync`-Vanilla-JS-Pendant aus `server_detail.js` (Phase A0) timet die Spans.
  - **Scan-Beam:** Pill-Container bekommt `stat-scan`-Keyframe analog Dashboard-Card.
  - **Accent-Left-Bar:** `border-left: 3px solid var(--accent)` (Brand-Anker ADR-0033).
- G2: **Status-Pill-Reihe stratten** — `detail.html` Header-Pill-Block: wenn `scan_stale AND db_stale`: eine kombinierte `<span class="sd-status-flag">stale</span>` mit Tooltip listet beide Gründe. Sonst je einzelne Pill mit spezifischem Tooltip. **Outdated-Pills aus Block N (`agent`/`trivy`/`trivy-db`) bleiben einzeln** (verschiedene Operator-Aktionen) — das ist eine **bewusste Abweichung vom Design**, das in `ServerDetail.jsx` Z. 79–80 nur eine generische `trivy-db stale`-Pille zeigt. Markup nutzt drei separate `sd-status-flag`-Elemente, je eine pro zutreffender Bedingung, mit Tooltip-Befehlen aus den bestehenden `is_agent_outdated`/`is_trivy_outdated`/`is_trivy_db_outdated`-Helpers.
- G3: **Per-Finding-AI-Reason** — Application-Group-Card Finding-Zeile von `<tr>` zu `<details>` umbauen. Beim Expand rendert direkt unter der Zeile ein Block: Eyebrow „KI-Bewertung" + Paragraph mit `Finding.risk_band_reason`. Wenn `reason IS NULL`: Block rendert nicht (kein Stub-Text). Klassen (1:1 aus `docs/design/server-detail.css`): `sd-finding` (`<details>`), `sd-finding__summary`, `sd-finding__body`, `sd-finding__reason`.
- G4: **Sicherheit** — `risk_band_reason` ist Pydantic-validiert beim LLM-Ingest (Block O/P), aber Jinja-Autoescape muss laufen. Kein `|safe`.
- G5: **Bulk-Toolbar** — `_findings_section.html` Toolbar bekommt einen neuen Button „Acknowledge all noise on this server (<N>)" wenn `noise_count > 0`. Form-Target ist der existing Block-F-`bulk-acknowledge`-Endpoint mit `match.server_id=<id>` + `match.risk_band=noise`. Confirm-Modal aus Block F (`bulk_ack.js`) wiederverwenden. **Kein Pflicht-Kommentar** (ADR-0006).
- G6: **Legacy-Shim-Audit** — am Block-Ende prüfen welche Tailwind-/DaisyUI-Klassen-Aufrufe nach Block X aus `detail.html`/`_findings_section.html`/`_action_needed_section.html`/`_kpi_card.html`/`_heartbeat_large.html`/`_stacked_bar_chart.html` verschwunden sind. Die entsprechenden Regeln in `legacy-shim.css` markieren oder entfernen (vorsicht: ggf. von anderen ungerefactorten Templates noch genutzt).
- G7: Tests — `tests/templates/test_action_needed_pill.py` (neu oder erweitert): Render-Condition prüft beide Subcounts (`escalate=0, act=0` → kein Render; `escalate=1, act=0` → Render; etc.), Scan-Chars-Markup ist im Output, `sd-status-pill`-Klasse present. `tests/templates/test_finding_inline_reason.py` (neu): Render mit/ohne `risk_band_reason`, Autoescape gegen `<script>`-Payload. `tests/views/test_bulk_ack_noise_shortcut.py` (neu): Button rendert nur bei noise_count > 0, POST mit kombiniertem `server_id + risk_band=noise` matched die richtige Findings-Menge, Confirm-Modal-Pfad wie Block F. `tests/templates/test_status_pills.py` (neu): kombinierte stale-Pill nur wenn beide Bedingungen, sonst einzelne Pills.

## Definition of Done (maschinell prüfbar)

Alle vorherigen Quality-Gates (siehe `CLAUDE.md`):

- `ruff check .` PASS, `ruff format --check .` PASS
- `mypy app/` PASS (no new errors)
- Default-`pytest` (Pure-Unit, ohne `-m db_integration|acceptance|integration|bench`) PASS
- Bash-Timeout ≤ 120000 ms auf jedem pytest-Aufruf

Block-X-spezifische DoD:

0. **Phase A0** — `frontend/src/css/components/server-detail.css` existiert und ist via `@import` in `app.css` eingebunden; `frontend/src/js/server_detail.js` exportiert `setupScanFlashSync` und registriert `serverPillPanels()`-Alpine-Component; Asset-Bundle-Build (esbuild) gibt unter `/static/dist/` die neuen Files mit Content-Hash aus; Manifest-Lookup im Jinja-Template löst auf.
1. **Phase A** — `detail.html` enthält kein `<dl class="grid">` mit vier Spalten mehr; die Header-Sysline rendert die drei Quickinfos in der dokumentierten Reihenfolge; verwendet `sd-sysline`-Klassen aus Phase A0.
2. **Phase B** — Route `GET /servers/<id>/settings` rendert mit den drei Sektionen; Detail-View hat keinen Hashtag-Loop und kein Tag-Editor-Akkordeon mehr; Zahnrad-Button im Header zeigt auf Settings-Sub-View; verwendet `sd-settings`-Klassen.
3. **Phase C** — `_partials/host_snapshot.html` existiert nicht mehr; zwei `<button class="sd-chip" data-test="pill-listeners|services">` rendern in der Header-Sysline; Pill-1 hat Label „Listeners" (nicht „Listeners & services"); `_partials/server_pill_listeners.html` Listener-Tabelle hat vier Spalten inkl. Exposure mit `sd-listener-tag` / `sd-listener-tag--exposed`; `classify_exposure()` liefert die dokumentierten Klassifizierungen für 127.0.0.1 / 0.0.0.0 / ::1 / :: + externe IPs; Slide-Down-Panels öffnen/schließen via `serverPillPanels`-Alpine; **keine Pagination** im Markup; Empty-State rendert disabled Pills.
4. **Phase D** — Workflow-Card-Body enthält `<table class="workflow-card__drilldown">` mit drei Spalten (Group · Worst Finding · Reason); pro Group-Row sind alle drei Werte belegt (Reason kann leer sein wenn Junction-Eval fehlt).
5. **Phase E** — `_heartbeat_large.html` rendert 30 Ticks mit `sd-heartbeat__tick--<band>` aus dem 4-Bands-Set; Severity-Trend-Toggle enthält nur `[24h, 7T, 30T]`, kein `50T`-Button; **Skel-States**: alle drei Sektionen (KPI-Tiles, Heartbeat, Severity-Trend) rendern bei `skel=True` die `sd-skel-frame`/`--skel`-Modifier-Klassen, Zahlen sind `—`, Werte sind ausgeblendet.
6. **Phase F** — Triage-Queue rendert sechs `<details data-test="risk-band-<band>">`-Slots in Reihenfolge `escalate/act/mitigate/pending/monitor/noise`; default-`open` nur auf ESCALATE (bei nicht-leerem ESCALATE) oder erster nicht-leerer.
7. **Phase G** — Action-Needed-Pill rendert nur bei `escalate+act > 0` und enthält `scan-chars`/`scan-flash`-Markup für die Animation; Finding-Zeile rendert `<details class="sd-finding">` mit Inline-Reason-Block (`sd-finding__reason`) bei vorhandenem `risk_band_reason`; Bulk-Toolbar enthält Button „Acknowledge all noise on this server (<N>)" bei noise_count > 0; kombinierte stale-Pill bei `scan_stale AND db_stale`; Legacy-Shim-Audit dokumentiert.

Reviewer-Pflicht: jeder neue HTMX-Endpoint mit OOB-Antwort (in diesem Block keine, aber Konvention bleibt) prüft sich gegen das `CLAUDE.md`-HTMX-OOB-Single-Source-Pattern.

## Bewusst nicht in der DoD

- Kein Bench-Lauf (out-of-scope-Re-Tune; `CLAUDE.md` Test-Konvention erlaubt Benches nur auf User-Anweisung).
- Kein db_integration-Test (alle DoD-Items sind Pure-Unit-prüfbar mit Mocks/Fixtures).
- Kein Docker-Compose-Smoke (existierende Suite `tests/integration/installer/` bleibt unangefasst, läuft auf User-Anweisung).
- Kein Browser-/Playwright-Test der Slide-Down-Panel-Animation (Pure-Unit-Test prüft Klassen-Toggle ohne echte Animation).
- Keine Style-Verifikation gegen den Claude-Design-Output (Block X+1).

## Risiken

- **Drift zwischen Risk-Band-Top-Level-Aggregator und Application-Group-Cards.** Wenn der Aggregator-Pfad andere Risk-Band-Zuordnungen liefert als der Card-Body-Lazy-Load, sieht der Operator inkonsistente Counts. Mitigation: gemeinsame Service-Funktion, eine Single-Source-Aggregation pro Server. Test in Phase F2.
- **Hashtag-Zeile-Removal bricht Bookmarks/Workflows die auf `#tag`-Click-zum-Filter-Pfad bauen.** Sehr unwahrscheinlich (kein dokumentierter Operator-Workflow), aber wenn jemand Bookmarks auf gefilterte Dashboards hat (`/dashboard?tags=<name>`), funktionieren die weiter — nur der Click-Trigger von der Detail-Seite verschwindet. Settings-Sub-View bietet weiter Tag-Editor.
- **Workflow-Card-Drilldown-Pagination-Stub** — wenn ein realer Server > 25 Application-Groups in einer Workflow-Card hat (sehr unwahrscheinlich), zeigt der Stub nur die ersten 25 ohne Navigation. Folge-PR liefert echte Pagination. Bis dahin: Operator sieht oben angepinnte „Seite 1 von N" als Hint.

## Migrations

Keine. Block X ist Markup- und View-Logik-Refactor.

## Tag-Strategie

`v0.13.0` zu setzen nach Branch-Merge auf main (gemäß Tag-only-on-main-after-Merge-Konvention).
