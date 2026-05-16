# Orchestrator-State

Single source of truth für den Implementierungs-Fortschritt. Wird von der Hauptsession bei jedem Start gelesen und nach jedem Block-Übergang aktualisiert.

## Status

**MVP + UI v2 + ADR-0016-Refinement + ADR-0017-Pane-Konsolidierung ready — v0.3.0 (2026-05-16).**

Block J (ADR-0017) abgeschlossen: Dashboard-Detail-Pane wird aus
einem gemeinsamen Jinja-Partial (`dashboard/_detail_pane.html`)
gerendert, Drift zwischen Full-Page- und HX-Pfad beseitigt. Klick
auf Dashboard-Header-Button zeigt identisches Layout wie ein Reload
(Headline „Dashboard", Server-Count, fünf KPI-Kacheln, Platzhalter).
Funktional gegenüber v0.3.0 unverändert.

728 Tests grün (+3 neue Pane-Konsistenz-Regression-Tests, 5 e2e
SKIPPED ohne Backend). `ruff check`, `mypy app/`, Alembic-Roundtrip
(`upgrade → downgrade -1 → upgrade`) PASS. `_pane/welcome.html`
sowie das leere `_pane/`-Verzeichnis entfernt.

## Aktueller Block

**Block K — Server-Detail-Redesign (ADR-0018, Spec-Stand v3 vom 2026-05-16)** · Plan: [K-server-detail-visual.md](K-server-detail-visual.md) · Mockup: [K-mockup-prototype.html](K-mockup-prototype.html) · Branch: noch nicht erstellt · Status: **Spec + Visual-Mockup finalisiert, wartet auf User-Freigabe vor Implementierung**.

Größerer Block als zunächst skizziert — der dritte Design-Wurf (`S5lepfeL8MeibyHP1ojRbw`) bringt neue Backend-Datenpfade plus vollständigen Layout-Refactor. Geplanter Umfang:

- **Header:** Hostname `text-2xl lg:text-3xl font-mono`, Hashtag-Tags (`#name` mit Tag-Color statt Pills), OS-Zeile mit inline „letzter scan vor X h", Status-Pill-Reihe (active + stale + db veraltet bei Bedarf), KI-Bewertung-Button als Primary rechts.
- **HeaderStats:** Großer Total-Findings-Counter (`text-[64px]`) + Tendenz-Label („über 50 tage stabil / steigend / fallend") links; vier KPI-Kacheln mit 50-Tage-Sparklines rechts (KEV/Critical/High/Medium).
- **Lebenszeichen-Sektion:** Größere Heartbeat-Bar als eigene Sektion + 4-Spalten-Meta-Grid (Erwarteter Intervall · Letzter Scan · Trivy-DB-Alter · KEV-Ereignisse · 50T).
- **Severity-Trend-Sektion:** Stacked-Bar-Chart über 50 Tage mit Range-Toggle (24h/7T/30T/50T), Legende mit Counts und Prozenten.
- **FindingsTable-Refactor:** Filter-Bar entfällt komplett; sortierbare Spalten-Header (server-side via `?sort=cvss&dir=desc`); Mode-Toggle (flach/gruppiert/diff) in der Toolbar; Bulk-Select-Checkboxes; „auswahl ack"-Button öffnet Confirm-Modal mit optionalem Kommentar; CSV-Button mode-abhängig (flach/gruppiert/diff).
- **Neue Backend-Services:** `compute_tendency()` (avg-7T vs avg-50T mit ±5% Threshold), `severity_snapshots_for_server()` (on-the-fly Daily-OPEN-Snapshots aus Finding-Lifecycle), `daily_severity_counts_for_server()`, `count_kev_events_50d()`.
- **Schema-Erweiterung:** `FindingsViewFilter` um `sort` und `dir` (Whitelist-Enums).

**Out of Scope:** 1J-Range-Toggle (Re-Open-Trigger), Suche-Input in Server-Detail (globale `/search` bleibt), Klasse-Toggle (OS/Lang), persistente `finding_severity_daily`-Tabelle (alles on-the-fly).

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

## Aktive Blocker

(keine)

## Offene ADR-Wünsche

(keine — ADR-0017 deckt den nächsten Block ab; wenn Implementer eine neue Architektur-Entscheidung braucht, hier eintragen und Spec ergänzen bevor Code geschrieben wird)

## Update-Konvention

- Beim Block-Start: Status auf "in progress" setzen, Branch-Name notieren.
- Beim Block-Abschluss (nach `reviewer`-Freigabe): Block in "Completed" verschieben mit Datum, nächsten Block als "Aktueller Block" markieren.
- Bei neuen Blockern: in "Aktive Blocker" eintragen mit Datum und Beschreibung.
- Aktive Blocker MÜSSEN aufgelöst sein bevor der Block als completed markiert wird.
