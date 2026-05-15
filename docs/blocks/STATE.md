# Orchestrator-State

Single source of truth für den Implementierungs-Fortschritt. Wird von der Hauptsession bei jedem Start gelesen und nach jedem Block-Übergang aktualisiert.

## Status

**MVP + UI v2 ready — v0.2.0 (2026-05-15).**

Alle neun Block-Iterationen A–I abgeschlossen. Block-H-Final-Security-
Audit **ACCEPTABLE WITH NOTES** (1 low CONCERN als post-v0.1.0-Folge),
Block-I-Security-Audit **CLEAN** (keine neuen Surfaces). 674 Tests
grün, Coverage 92.54 %. Docker-Image 191 MB, E2E-Smoke exit 0,
Live-LLM-Smoke gegen DeepInfra DeepSeek-V3 verifiziert.

UI ist als Single-Page-Layout im uptime-kuma-Spirit umgesetzt
(Sidebar + Detail-Pane, Heartbeat-Bars, Quick-Stats, sticky Search
mit `/`-Shortcut). Funktional gegenüber v0.1.0 unverändert.

## Aktueller Block

**Backlog-leer · MVP+UI-v2-Release v0.2.0.** Kein weiterer Block geplant.

## Completed

- **A — Skelett und Basis** · abgeschlossen 2026-05-14 · Branch `feat/block-a` · Reviewer-Freigabe nach Re-Review (Gunicorn `HOME=/app` + `--worker-tmp-dir /dev/shm`-Fix).
- **B — Datenmodell, Setup-Wizard und Auth** · abgeschlossen 2026-05-14 · Branch `feat/block-b` · Reviewer-Freigabe nach Template-Fix (Pattern-Escape) und Re-Run der adversarial-Tests. 96 Tests grün. Setup-Flow-Screenshot unter `docs/blocks/B-evidence/setup-flow.png`.
- **C — Ingest, Server-Verwaltung und Agent-E2E** · abgeschlossen 2026-05-14 · Branch `feat/block-c` · Reviewer-Freigabe 24 PASS / 0 FAIL. 207 Tests grün, Coverage 91 %. Real-Fixture mit 306 Findings (296 lang-pkgs + 10 os-pkgs) durchläuft Ingest mit Auth-vor-Body-Parse (401 in 22 ms), gzip-Bomb-Bound (413 bei >100 MB), Idempotenz auf Re-Scan. Neue ADR-0011 (`package_name@target`-Disambiguation).
- **D — Dashboard mit Tags und Stale-Detection** · abgeschlossen 2026-05-14 · Branch `feat/block-d` · Reviewer-Freigabe 8 PASS / 0 FAIL / 5 PENDING (Operator-UX). 306 Tests grün (99 neue Block-D-Tests), Coverage 93 %. Dashboard-Screenshot unter `docs/blocks/D-evidence/dashboard.png` mit 3 Servern, KEV-Badge, Stale-Marker, Tag-Filter-Form und Aufmerksamkeits-Sektion.
- **E — Triage in der Server-Detail-View** · abgeschlossen 2026-05-14 · Branch `feat/block-e` · Reviewer-Freigabe 12 PASS / 0 FAIL. 67 neue Block-E-Tests grün (insgesamt 373+ Tests), Coverage 90 % auf Block-E-Modulen. Drei View-Modi (Liste, Group-by-Package, Diff), Modals für Ack/Re-Open mit OPTIONALEM Kommentar (ADR-006), Notes-Thread mit `nh3.clean()`-Markdown-Subset, Quick-Copy-Toast, XSS-Härtung verifiziert. Sicherheits-Fix: `delete_note` mit Owner-Check + 403 für `system-*`-Notes. Screenshots: `docs/blocks/E-evidence/{list,group,diff}.png`.
- **F — Bulk-Operationen, globale Suche, Audit-View, CSV-Export** · abgeschlossen 2026-05-14 · Branch `feat/block-f` · Reviewer-Freigabe 19 PASS / 0 FAIL / 6 PENDING (Operator-UX). 71 neue Block-F-Tests grün (insgesamt 430+ Tests), Coverage 91 % auf Block-F-Modulen. Bulk-Acknowledge mit `dry_run` (Default true) und zwei Flavors (`finding_ids`/`match`), globale Suche mit CVE-Aggregation, Audit-View mit Tag-Filter, CSV-Export mit OWASP-konformer Formula-Injection-Mitigation (`'`-Prefix auf `=/+/-/@/\t/\r`). Bug-Fix: Audit-Type-Cast (`AuditEvent.target_id` VARCHAR ↔ `Server.id` INTEGER). Screenshot: `docs/blocks/F-evidence/search-cve.png`.
- **G — LLM-Integration mit Streaming-Chat** · abgeschlossen 2026-05-15 · Branch `feat/block-g` · Reviewer-Freigabe 27 PASS / 0 FAIL / 8 PENDING. Security-Auditor: ACCEPTABLE WITH NOTES (3 CONCERNS, alle in Block H umgesetzt). 149 neue Block-G-Tests grün (insgesamt 579+ Tests), Coverage 93 % auf Block-G-Modulen. AsyncOpenAI-Wrapper mit Fernet-encrypted API-Key, SSE-Streaming, Prompt-Injection-Marker `<<TRIVY_DATA_START>>`/`<<...END>>`, `nh3`-Allowlist für LLM-Output, Token-Cap (80%-Warning/100%-Block), `llm_base_url`-Whitelist (HTTPS außer localhost), Provider-Wechsel-Hook archiviert aktive Conversations. **Live-Smoke gegen DeepInfra DeepSeek-V3**: 306 Tokens gestreamt (1538 Zeichen Antwort, 23679 prompt + 550 completion), Audit `llm.queried`, Encrypted Key per `down -v` gewipt. Screenshot: `docs/blocks/G-evidence/chat.png`.
- **H — Live-Updates, Production-Hardening, Final-Polish** · abgeschlossen 2026-05-15 · Branch `feat/block-h` · Reviewer-Freigabe nach Re-Review (Image-Size, E2E-Skript-Regex, Screenshot-Defekte gefixt). Final-Security-Auditor: ACCEPTABLE WITH NOTES (1 low CONCERN: per-Server-Auth-Rate-Limit aus §9 als post-v0.1.0-Folge). 629 Tests grün (50 neue Block-H-Tests), Coverage 92.16 %. In-process Event-Bus mit `GET /events` SSE-Endpoint (Heartbeat 30s), Dashboard-Live-Card-Animation, 60s-Stale-Re-Render-Timer. Block-G-Action-Items umgesetzt: ADR-0013 (Fernet-KDF-Beibehalten + Weak-Key-Warning), ADR-0014 (Token-Cap-Best-Effort), `validate_base_url` Port-Range-Check, `@limiter.limit("60/hour")` auf `/chat/<id>/stream` und `/settings/llm/test-connection`, `Authorization` in structlog-Redaction-Pattern. Docker-Image 278 → 191 MB (Three-Stage flat-runtime). `scripts/e2e_smoke.sh` mit Python-Master-Key-Extraktion exit 0 in allen 11 Phasen. README mit nginx/Caddy/IP-Allowlist-Snippets. CHANGELOG.md mit v0.1.0-Eintrag. Screenshot: `docs/blocks/H-evidence/dashboard-live.png`. **Tag `v0.1.0` gesetzt.**
- **I — UI-Modernisierung (Single-Page-Sidebar-Layout)** · abgeschlossen 2026-05-15 · Branch `feat/block-i` · Reviewer-Freigabe 27 PASS / 0 FAIL. Security-Auditor: **CLEAN** (keine neuen Sicherheits-Surfaces, 8 Punkte alle PASS). 45 neue Block-I-Tests grün (insgesamt 674), Coverage 92.54 %. `base_app.html` als Single-Page-Shell mit Sidebar (Quick-Stats, Sticky-Search mit `/`-Shortcut, Tag-Filter, Server-Liste mit Heartbeat-Bars, Settings-Akkordeon) + Detail-Pane (HTMX-Swap, `hx-push-url`). Heartbeat-Aggregation als Python-Service (Variante B, on-the-fly), Performance 50×50<200ms. `_inject_sidebar_context`-Context-Processor injiziert Sidebar-Variablen automatisch. `_partial_shell.html` für HX-Fragmente. Empty-States, Monospace-Cleanup, Quick-Copy-Macro-Fix aus Block F. Funktional gegenüber v0.1.0 unverändert. Screenshots: `docs/blocks/I-evidence/{dashboard,server-detail}.png`. **Tag `v0.2.0` zu setzen.**

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

## Aktive Blocker

(keine)

## Offene ADR-Wünsche

(keine — wenn Implementer eine neue Architektur-Entscheidung braucht, hier eintragen und Spec ergänzen bevor Code geschrieben wird)

## Update-Konvention

- Beim Block-Start: Status auf "in progress" setzen, Branch-Name notieren.
- Beim Block-Abschluss (nach `reviewer`-Freigabe): Block in "Completed" verschieben mit Datum, nächsten Block als "Aktueller Block" markieren.
- Bei neuen Blockern: in "Aktive Blocker" eintragen mit Datum und Beschreibung.
- Aktive Blocker MÜSSEN aufgelöst sein bevor der Block als completed markiert wird.
