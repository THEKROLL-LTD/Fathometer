# Orchestrator-State

Single source of truth für den Implementierungs-Fortschritt. Wird von der Hauptsession bei jedem Start gelesen und nach jedem Block-Übergang aktualisiert.

## Status

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

(keiner — Block M abgeschlossen 2026-05-16, nächster Block per User-Entscheidung)

## Completed

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

## Aktive Blocker

(keine)

## Offene ADR-Wünsche

(keine — ADR-0020 deckt Block M ab. ADR-0016 wird im Zuge von Block M auf „Superseded by 0020" gesetzt, partiell für die Dashboard-Pane-Layout-Sektionen; Header- und Profile-Dropdown-Teile bleiben gültig. Wenn Implementer eine neue Architektur-Entscheidung braucht, hier eintragen und Spec ergänzen bevor Code geschrieben wird.)

## Update-Konvention

- Beim Block-Start: Status auf "in progress" setzen, Branch-Name notieren.
- Beim Block-Abschluss (nach `reviewer`-Freigabe): Block in "Completed" verschieben mit Datum, nächsten Block als "Aktueller Block" markieren.
- Bei neuen Blockern: in "Aktive Blocker" eintragen mit Datum und Beschreibung.
- Aktive Blocker MÜSSEN aufgelöst sein bevor der Block als completed markiert wird.
