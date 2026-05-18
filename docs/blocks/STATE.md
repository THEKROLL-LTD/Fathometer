# Orchestrator-State

Single source of truth für den Implementierungs-Fortschritt. Wird von der Hauptsession bei jedem Start gelesen und nach jedem Block-Übergang aktualisiert.

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

**P — LLM-Risk-Reviewer mit Application-Grouping (Two-Pass) und asynchroner Job-Queue** · gestartet 2026-05-18 · Branch `feat/block-p` · Spec [ADR-0023](../decisions/0023-llm-risk-reviewer-and-application-grouping.md) · Brief [P-llm-risk-reviewer.md](P-llm-risk-reviewer.md) · Zielversion v0.9.0.

Fünf Bausteine: (1) Application-Group-Schicht — neue Tabelle `application_groups` plus FK `Finding.application_group_id`, Findings nach Owner-Application (k3s, openssh-server, etc.) gruppiert, Group-Bewertung wird auf alle enthaltenen Findings vererbt (Worst-Case-Band); (2) Two-Pass-LLM-Architektur — Pass 1 detect Groups mit wiederverwendbaren Match-Patterns (Path-Prefix / pkg_name_exact / pkg_name_glob / pkg_purl_pattern), Pass 2 bewertet pro Group mit Server-Kontext (compact-form, ~2-4K Tokens); (3) asynchroner Worker via `llm_jobs`-Tabelle in separatem Container `secscan-llm-worker`, Single-Concurrency-Default, 2s-Polling mit `SELECT FOR UPDATE SKIP LOCKED`, Pass-2-Jobs warten via `depends_on` auf Pass-1; (4) Two-Level-Caching — Pass-1-Cache *ist* die `application_groups`-Library, Pass-2-Cache als `llm_risk_cache`-Tabelle mit `(group_id, group_findings_fp, cve_data_fp, server_context_fp)`-Key, TTL 30d + LRU 100K; (5) UI-Redesign auf Group-Cards mit `evaluating`-State und Feature-Flag `BLOCK_P_LLM_MODE ∈ {off, observation, live}` für stufenweise Inbetriebnahme. Reasons bleiben deskriptiv — keine konkreten Update-Befehle, keine spezifischen Application-Version-Empfehlungen.

## Completed

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
| P | [P-llm-risk-reviewer.md](P-llm-risk-reviewer.md) | in progress (gestartet 2026-05-18) — Zielversion v0.9.0 (ADR-0023 LLM-Risk-Reviewer + Application-Grouping + async Worker) |

## Aktive Blocker

(keine)

## Offene ADR-Wünsche

(keine — ADR-0023 deckt Block P komplett ab inklusive Application-Group-Schicht, Two-Pass-LLM-Architektur, asynchroner Worker-Pattern und UI-Redesign. Wenn Implementer eine neue Architektur-Entscheidung braucht, hier eintragen und Spec ergänzen bevor Code geschrieben wird.)

## Update-Konvention

- Beim Block-Start: Status auf "in progress" setzen, Branch-Name notieren.
- Beim Block-Abschluss (nach `reviewer`-Freigabe): Block in "Completed" verschieben mit Datum, nächsten Block als "Aktueller Block" markieren.
- Bei neuen Blockern: in "Aktive Blocker" eintragen mit Datum und Beschreibung.
- Aktive Blocker MÜSSEN aufgelöst sein bevor der Block als completed markiert wird.
