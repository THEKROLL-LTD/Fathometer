# Changelog

Alle nennenswerten Aenderungen an diesem Projekt werden hier dokumentiert.
Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/),
und das Projekt folgt [Semantic Versioning](https://semver.org/).

## [v0.8.0] — 2026-05-18

Block O (ADR-0022) — Pre-Triage-Risk-Engine + Host-Snapshot-Sammlung +
Vendor-Severity + Risk-zentrisches UI-Redesign.

### Added

- **Deterministische Pre-Triage-Engine** in `app/services/risk_engine.py`.
  Klassifiziert jedes offene Finding pro Scan-Ingest in einen der vier
  Block-O-Bands `noise`, `monitor`, `pending`, `unknown` allein basierend
  auf max-Severity-aller-Provider + EPSS + KEV-Flag — **kein**
  Host-Kontext-Abgleich. Defensive Cuts: KEV-Listing → PENDING,
  max-Severity >= HIGH → PENDING, EPSS >= 0.1 → PENDING, MEDIUM →
  MONITOR, sonst NOISE. Ohne Host-Snapshot landet jedes Finding in
  UNKNOWN (Operator-Hint: „Update agent to >= 0.3.0"). Ergebnis pro
  Finding plus Reason-String wird auf `Finding.risk_band` +
  `.risk_band_reason` + `.risk_band_source="engine"` +
  `.risk_band_computed_at` persistiert.
- **`RiskBand`-Modell mit binaerem `action_required`-Mapping.** Sieben
  Bands `escalate`/`act`/`mitigate` (LLM-Output, Block P) +
  `pending`/`unknown`/`monitor`/`noise` (Engine-Output). `escalate`/
  `act`/`mitigate`/`pending`/`unknown` → `action_required=yes`,
  `monitor`/`noise` → `no`. Mapping deterministisch in
  `ACTION_REQUIRED_MAP`, nicht in der DB.
- **Host-Snapshot-Sammlung im Agent (v0.3.0).** Vier neue
  Collector-Funktionen in `agent/lib_host_state.sh`
  (`collect_listeners`/`processes`/`kernel_modules`/`services`).
  Tool-Verfuegbarkeits-Check via `tools_available`/`gaps`. Fallback-
  Pfade: `ss` → `netstat`; fehlendes `lsmod`/`systemctl` → leerer
  Block + Gap-Eintrag. ASCII-only via `LC_ALL=C` plus Non-ASCII-Drop.
  Typische Envelope-Groesse: +10-30 KB gzipped.
- **CVSS-Vendor-Resolver** `app/services/severity_resolver.py` mit
  `severity_for()` (Anzeige-Severity pro Host-Distro) und
  `max_severity_across_providers()` (Eingabe fuer Pre-Triage). 13
  Distro-Profile + GHSA-Bevorzugung fuer `lang-pkgs`. Trivys
  `VendorSeverity`-Map persistiert in neuer Spalte
  `Finding.severity_by_provider` (JSONB).
- **Vendor-Status-Persistenz.** Trivys `Vulnerability.Status` wird via
  Whitelist auf `{affected, fixed, investigating, will_not_fix, eol,
  not_affected, unknown}` normalisiert und in
  `Finding.vendor_status` (max 32 Chars) persistiert. Block P (LLM)
  liest das als Eingabe-Signal — Block O zeigt es noch nicht im UI.
- **Dashboard-UI-Redesign (Risk-zentrisch).** Drei Tiers:
  (1) zwei prominente Action-Required-Cards `Action needed` + `Safe`
  mit Server-Counts und klickbarem Filter; (2) sieben kompakte Risk-
  Band-Pills `Escalate`/`Act`/`Mitigate`/`Pending`/`Unknown`/`Monitor`/
  `Noise` mit Findings-Counts (Escalate pulsiert); (3) tertiaere
  Severity-Strip CRITICAL/HIGH/MEDIUM/LOW kompakt ohne Klick-Filter.
  Findings-Tabelle bekommt `Risk`-Spalte als erste Sort-Spalte (Default
  DESC), CVSS-Severity rutscht zwischen Status und Erstmals.
- **Server-Detail Action-Required-Pill + Host-Snapshot-Sektion.**
  Header-Pill-Reihe bekommt drei Varianten als ERSTE Pill:
  rot „Action needed — N escalate · M act · K pending",
  gruen „Safe — N monitor · M noise",
  grau „Update agent — host snapshot missing".
  Direkt unter dem Header `<section id="host-snapshot">` mit
  collapsible Listener-/Service-Anzeige (default 5 inline + „N more"-
  Toggle, Process-Args als Tooltip mit HTML-Escape). Findings-Tabelle
  gruppiert nach `risk_band` mit Section-Headers, default-expanded ab
  `pending` aufwaerts, default-collapsed fuer `monitor`/`noise`/
  `unknown`. Per-Finding-Detail-Box zeigt `risk_band_reason` in Mono-
  Font.
- **Bulk-Ack-`noise`-Workflow.** Neuer Button „Acknowledge all noise on
  this server (N)" auf Server-Detail. Modal mit Liste der noise-
  Findings (max 50 inline + „... and N more"). Endpoint
  `POST /api/findings/bulk-acknowledge` um optionalen Form-Parameter
  `risk_band_filter="noise"` erweitert: server-side hartes Filtern
  auf `Finding.risk_band == "noise"`, eingeschleuste non-noise-IDs
  werden gedroppt und in `skipped_non_noise_ids` der Response-Body
  aufgelistet.
- **Filter-Bar-Erweiterung.** Neue `<select>`-Felder `risk_band` und
  `action_required` in der Dashboard-Findings-Filter-Bar.
  `DashboardFilter` und `FindingsViewFilter` um die Literal-Whitelist-
  Felder erweitert. `findings_query.list_findings()` und
  `.list_findings_cross_server()` applizieren beide Filter; Default-
  Sort-Key wechselt von `sev` zu `risk` (DESC).
- **DB-Migration `0004_block_o_risk_and_host_state.py`.** Vier neue
  Tabellen `server_listeners`, `server_processes`,
  `server_kernel_modules`, `server_services` (jeweils mit
  `(server_id, ...)` als PK und FK-CASCADE). Sechs neue
  Finding-Spalten (`risk_band`, `risk_band_reason`,
  `risk_band_source`, `risk_band_computed_at`, `severity_by_provider`
  als JSONB, `vendor_status`). Eine neue Server-Spalte
  `host_state_snapshot_at`. Zwei neue Findings-Indizes:
  `ix_findings_risk_band_open` partial-index
  `WHERE status = 'open'` + `ix_findings_server_risk_band`. Kein
  Backfill — Werte werden beim naechsten Scan gesetzt.
- **Audit-Events.** `host_state.snapshot_received` (pro Scan mit
  Snapshot, Body mit `tools_available`/`gaps`/`listener_count`/
  `process_count`), `host_state.parse_failed` (bei SQLAlchemy- oder
  Pydantic-Fehler im Snapshot-Pfad, Findings-Ingest laeuft trotzdem),
  `risk.pretriage_evaluated` (pro Scan mit `counters`-Map),
  `risk.band_changed` (pro Finding bei Band-Wechsel, mit
  `from`/`to`/`source`/`reason`).

### Changed

- **Sortier-Defaults (ARCHITECTURE.md §15).** `risk_band` ist neuer
  Primary-Sort-Key (`RISK_BAND_SORT_RANK` 70/60/50/40/30/20/10/NULL=0).
  Tiebreak-Kette: KEV DESC → EPSS DESC → CVSS-Severity-Rank DESC →
  `identifier_key` ASC.
- **`ARCHITECTURE.md`** §6 (Envelope mit `host_state`), §7
  (Risk-zentrisches Dashboard), §7a (Server-Detail Risk-Layout), §9
  (Bandbreiten-Hinweis + Privacy-Notice fuer Process-Args), §11
  (Agent v0.3.0), §15 (Pre-Triage-Engine + neue Sort-Order), §17
  (sieben neue Out-of-Scope-Punkte: LLM-Reasoning, Snapshot-
  Historisierung, manueller Risk-Override, Patch-Alter-Eskalation,
  Exposure-Mapping, OpenRC-Services, Daily-Re-Eval).

### Compat-Hinweise

- **Alte Agents (v0.2.0) werden weiterhin akzeptiert.** Ohne
  `host_state` im Envelope landet jedes Finding in
  `risk_band="unknown"` mit Reason „host snapshot missing — update
  agent to >= 0.3.0". `MIN_AGENT_VERSION` bleibt `0.1.0` — Block O
  bumpt NICHT.
- **LLM-Final-Bewertung kommt in v0.9.0 (Block P).** Pre-Triage
  ueberschreibt LLM-gesetzte Bands nicht: Findings mit
  `risk_band_source == "llm"` werden im Ingest skipt. Schema-Slot
  `escalate`/`act`/`mitigate` ist im `RiskBand`-Enum schon da.

### Tests

- 1226 Tests gruen (Vorher v0.7.2: 999; Delta +227 — Block-O-Brief
  hatte ~90 erwartet, Adversarial- und View-Tests sind reicher
  ausgefallen). Coverage **92.42 %** (Threshold 85 %).
- 326 adversarial Tests gruen (Vorher: 257; +69 neue Block-O-Cases:
  Host-Snapshot-XSS, Listener-Addr-Validierung, Pre-Triage-No-
  Snapshot-Safety, Pre-Triage-No-LLM-Override, Host-State-Max-
  Lengths, KEV/HIGH/EPSS-Tabellen-Kombinationen, Bulk-Ack-Noise-
  Strict). 34 Pre-Triage-Tests in
  `tests/services/test_risk_engine_pretriage.py` (DoD verlangt
  >= 25).
- `ruff check` + `ruff format --check` + `mypy app/` +
  `shellcheck agent/*.sh` PASS. Alembic-Roundtrip (0004 ↔ 0003) PASS
  gegen Postgres-17-Container. `docker compose up --build` +
  `/healthz` PASS. Image-Size **191 MB** (= v0.7.x, Delta 0 MB).

## [v0.7.2] — 2026-05-18

Punkt-Fix fuer Phase 6 (Probe-Scan) im Bootstrap-Installer.

### Fixed

- **`probe scan` schlug mit `SECSCAN_URL: readonly variable` fehl.**
  Das Wizard-Toplevel hat `SECSCAN_URL="..."` mit `readonly`
  deklariert. In Phase 6 sourced der Wizard `/etc/secscan/agent.env`
  in einer Subshell (`( set -a; . agent.env; secscan-agent.sh )`).
  Subshells erben `readonly`-Flags, und das `agent.env`-Re-Assignment
  derselben Variable scheiterte sofort — der Probe-Scan endete mit
  `exit 1`, obwohl die Werte identisch waren. Real beobachtet auf
  `rke2-sv-0-1` (Ubuntu 22.04 aarch64) nach dem v0.7.1-Upgrade.
- **Mitigation:** `SECSCAN_URL` wird nicht mehr als `readonly`
  deklariert. Der Wert wird im Wizard ohnehin nirgends veraendert —
  der Defense-Aspekt war ueberzogen. Alle anderen Wizard-Konstanten
  (`RECOMMENDED_TRIVY_VERSION`, `MIN_TRIVY_VERSION`,
  `CURRENT_AGENT_VERSION`, `TRIVY_RELEASE_URL_TEMPLATE`,
  `SECSCAN_PREFIX`/`BIN_DIR`/`CONF_DIR`/`ENV_FILE`, `TTY_INPUT`,
  `UNATTENDED`) bleiben `readonly`, weil sie nicht in `agent.env`
  vorkommen.
- **Operator-Workflow:** Falls Phase 6 bereits einmal mit dem Bug
  durchlief, sind systemd-Unit + Timer in Phase 5 schon scharf —
  der naechste regulaere Timer-Tick versucht es erneut, jetzt
  korrekt. Manueller Trigger: `systemctl start secscan-agent.service`.

### Tests

- `tests/views/test_install_sh_public_url.py::test_install_sh_does_not_make_secscan_url_readonly`
  — verifiziert dass das Template kein `readonly SECSCAN_URL=` mehr
  enthaelt und die Variable als normales Assignment vorhanden ist.
- 999 Tests gruen (+1 vs. v0.7.1), Coverage 92 %.

## [v0.7.1] — 2026-05-18

Defect-Fix-Release fuer Block N. Drei verschraenkte Bugs, die zusammen
verhindert haben, dass der Bootstrap-Installer hinter einem
TLS-terminierenden Reverse-Proxy durchlaeuft.

### Fixed

- **`/install.sh` rendert jetzt HTTPS** wenn das Backend hinter einem
  TLS-terminierenden Reverse-Proxy laeuft. Ursache: ohne ProxyFix sah
  Flask `request.scheme=http`, weil nginx/Caddy intern HTTP nach
  Gunicorn forwarded. `werkzeug.middleware.proxy_fix.ProxyFix` ist
  jetzt aktiv (`x_proto=1`, `x_host=1`, `x_for=1`) und wertet
  `X-Forwarded-Proto`/`X-Forwarded-Host` von genau einem Hop aus. Die
  README-nginx-Snippets setzen `X-Forwarded-Proto $scheme` schon seit
  Block H — ohne diesen Patch wurde der Header aber ignoriert. Real
  beobachtet auf `secscan.thekroll.ltd`: gerendertes
  `SECSCAN_URL=http://...`, beim ersten `POST /api/register`
  HTTP→HTTPS-301-Redirect, `curl -X POST` ohne `-L` haengt.
- **Curl-POST folgt jetzt 30x-Redirects** in `install.sh.j2`,
  `agent/secscan-agent.sh` und `agent/secscan-register.sh`. Neue
  Flags `--post301 --post302 --post303 -L` — Default-Verhalten von
  `curl -L` ist auf 30x den POST in einen GET umzuwandeln, was beim
  `/api/register`-Roundtrip den Body verliert. Mit den drei Flags
  wird der POST-Body neu gesendet.
- **Phase-1-Warn-Hinweis im Wizard** wenn `SECSCAN_URL` mit `http://`
  startet — Operator bekommt eine klare Meldung, dass
  `SECSCAN_PUBLIC_URL=https://...` im Backend gesetzt sein sollte
  (kein hartes Abort, Dev-Setups bleiben moeglich).

### Neu

- **`SECSCAN_PUBLIC_URL`-Env-Var.** Explizite extern sichtbare
  Backend-URL inkl. Schema, z.B. `https://secscan.example.com`. Wird
  in `app.config["EXTERNAL_BASE_URL"]` propagiert und vom Installer-
  Render plus vom `external_base_url`-Context-Processor bevorzugt
  vor `request.host_url`. Empfohlen fuer alle Production-Setups —
  deploy-eindeutige Quelle der Wahrheit unabhaengig vom Proxy-Setup.
  Trailing-Slash wird abgeschnitten. README- und `.env.example`-
  Eintrag entsprechend ergaenzt.

### Tests

- `tests/views/test_install_sh_public_url.py`: sechs Cases fuer die
  drei Render-Pfade (Fallback, ProxyFix-aware,
  `SECSCAN_PUBLIC_URL`-Override) plus drei Sanity-Checks fuer die
  `--post30x -L`-Flags in den drei Bash-Files.
- 998 Tests gruen (+6 vs. v0.7.0), Coverage 92 % (Threshold 85 %).
- `ruff check`/`ruff format --check`/`mypy app/`/`shellcheck agent/*.sh`
  PASS. Image-Size 191 MB unveraendert.

### Migrationen / Operations

- Keine Alembic-Migration.
- Bestehende Deployments: nach dem Upgrade `SECSCAN_PUBLIC_URL` in
  `.env` setzen und einmal `docker compose up -d --force-recreate`.
  Ohne den Wert funktioniert das Backend weiter, der Installer
  rendert dann via ProxyFix-aware `request.host_url` — sofern der
  Reverse-Proxy `X-Forwarded-Proto $scheme` setzt (steht in den
  README-Snippets).

## [v0.7.0] — 2026-05-18

Block N aus [ADR-0021](docs/decisions/0021-agent-bootstrap-installer.md):
Backend-gehosteter interaktiver Bootstrap-Installer, Veraltet-Indikatoren
im UI, Agent-side Trivy-Output-Strip, Ursachen-Felder pro Finding.
Funktional ein groesseres Operator-UX-Update; DB-Schema-Erweiterung um
acht nullable Spalten (zwei Server + fuenf Finding plus der bereits aus
0002 vorhandene `agent_version`), kein Bruch.

### Neu

- **Bootstrap-Installer.** Neuer Operator-Standardpfad fuer die
  Agent-Installation: `curl -fsSL https://secscan.example.com/install.sh |
  sudo bash`. Backend rendert ein Jinja-Template (~720 Bash-Zeilen) mit
  sechs sichtbaren Phasen (System detection / Dependencies / Trivy /
  Server registration / Scheduler / Probe scan), englischsprachiger
  TTY-UI mit Box-Bordern, ANSI-Farben (`NO_COLOR`-respektierend) und
  Status-Symbolen `[ok]` / `[..]` / `[fail]`. Master-Key wird interaktiv
  ueber `/dev/tty` silent abgefragt — kein Argv, keine Shell-History,
  keine ENV-Var. Trivy wird per `sha256sum -c` gegen das `checksums.txt`
  des GitHub-Releases verifiziert. systemd-Service plus -Timer (daily,
  `RandomizedDelaySec=2h`) als Default; Cron-Fallback mit Jitter wenn
  `systemctl` fehlt. Unattended-Modus via `SECSCAN_UNATTENDED=1` plus
  `SECSCAN_MASTER_KEY`/`SECSCAN_SERVER_NAME` fuer Ansible/Cloud-Init.
- **Drei neue Public-Endpoints.** `GET /install.sh` rendert das Wizard-
  Template mit eingebackener `SECSCAN_URL`. `GET /agent/files/<name>`
  liefert `secscan-agent.sh`/`secscan-register.sh` ueber strikte
  Whitelist plus `send_from_directory`. `GET /agent/version` liefert
  JSON mit `current_agent_version`, `min_agent_version`,
  `recommended_trivy_version`, `min_trivy_version`,
  `trivy_release_url_template`. Alle drei in `PUBLIC_PATHS`-Allowlist,
  ohne Auth/CSRF.
- **Veraltet-Indikatoren im UI.** Server-Detail-Header bekommt drei
  conditional Pills (`pill-agent-outdated`, `pill-trivy-outdated`,
  `pill-trivy-db-stale`) mit Tooltips, die den konkreten Update-Befehl
  zeigen. Sidebar-Server-Liste bekommt einen `⚠`-Sub-Marker pro Server,
  falls einer der drei Indikatoren greift. Polling-Wrapper aus Block L
  sorgt fuer automatische Aktualisierung. Schwellen sind Code-Konstanten
  in `app/config.py` (`MIN_AGENT_VERSION="0.1.0"`,
  `MIN_TRIVY_VERSION="0.70.0"`, `TRIVY_DB_STALE_THRESHOLD_DAYS=7`) —
  bewusst nicht UI-aenderbar (Selbstabschaltungs-Falle).
- **Ursachen-Felder pro Finding.** Fuenf neue nullable Finding-Spalten
  `package_purl`, `target_path`, `result_type`, `severity_source`,
  `vendor_ids` werden aus `Vulnerability.PkgIdentifier.PURL`,
  `Result.Target`, `Result.Type`, `Vulnerability.SeveritySource`,
  `Vulnerability.VendorIDs` extrahiert. Findings-Tabelle (Server-Detail
  und Dashboard) zeigt eine Sub-Zeile mit Distro-Pill plus Vendor-IDs
  fuer `os-pkgs` bzw. Library-Type-Pill plus Datei-Pfad in Mono-Font
  fuer `lang-pkgs`. Tooltip mit PURL/Severity-Source. Fallback fuer
  Alt-Daten ohne `target_path` aus dem `@`-Split im `package_name`
  (ADR-0011-Uebergangsformat). **Bewusst weggelassen:** statisches
  Update-Befehl-Mapping (`apt`/`dnf`/`apk`-Snippets) — kommt als
  eigener LLM-basierter Block nach v0.7.0.

### Geaendert

- **Agent-Skript `secscan-agent.sh`** auf Version `0.2.0` gebumpt.
  Sendet `host.trivy_version` zusaetzlich im Envelope. Strippt
  `Results[].Packages` per `jq 'del(.Results[].Packages)'` vor dem
  Envelope-Build (raw ~4.95 MB → 400–700 KB, gzipped ~560 KB →
  100–200 KB; Vuln-Counts und `PkgIdentifier`/`SeveritySource`/
  `VendorIDs` pro Vuln bleiben intakt). Fallback auf ungestripped bei
  `jq`-Fehler — Backend toleriert beides per `extra="ignore"`. Alle
  User-sichtbaren Strings auf Englisch normalisiert.
- **Agent-Skript `secscan-register.sh`** User-Strings auf Englisch
  normalisiert. Aufruf-Hinweis erwaehnt jetzt zusaetzlich
  `curl -fsSL .../install.sh | sudo bash` als bevorzugten Standardpfad.
- **Envelope-Schema.** `HostBlock.trivy_version: str | None`,
  Sub-Modell `TrivyPkgIdentifier(PURL, UID)`, `TrivyVulnerability`
  um `pkg_identifier`/`severity_source`/`vendor_ids` plus Convenience-
  Property `package_purl`. `MAX_VENDOR_IDS_PER_VULN=32`,
  `MAX_VENDOR_ID_LENGTH=128`. Validatoren analog `cwe_ids`/`references`
  — defensives Trim, ASCII-Only, NUL-frei. Forward-Compat via
  `extra="ignore"` unveraendert.
- **Ingest** in `app/api/scans.py` extrahiert `agent_version` und
  `host.trivy_version` aus dem Envelope und schreibt sie auf
  `Server.trivy_version`/`Server.agent_version_seen_at`. Bei
  `version_lt(envelope.agent_version, MIN_AGENT_VERSION)` → 400 mit
  Audit-Event `agent.rejected_outdated`. Auth-Reihenfolge (401 vor
  400) bleibt erhalten.
- **`findings_ingest`** persistiert die fuenf Ursachen-Felder bei
  jedem UPSERT (auch auf Update — Re-Ingest-Konsolidierung). Wenn
  `vuln.severity_source` neu None ist, wird die Spalte auf NULL
  gesetzt (kein historisches Bewahren). `_disambiguated_package_name`
  unveraendert (ADR-0011-Uebergangsformat).
- **`.dockerignore`** `agent/` entfernt — Runtime-Image enthaelt
  jetzt das `agent/`-Verzeichnis, damit `GET /agent/files/<name>`
  in Produktion auch tatsaechlich Inhalte liefert.
- **ARCHITECTURE.md §6** Envelope-Beispiel auf Agent 0.2.0 plus
  `host.trivy_version` plus Ursachen-Feld-Hinweis aktualisiert.
- **ARCHITECTURE.md §11** Installer-Flow als Standardpfad
  dokumentiert; Power-User-Pfad (Repo-Klonen) bleibt als Alternative;
  Forward-Compat-Absatz um UI-Indikatoren ergaenzt. Neue Subsektion
  „Backend-hosted bootstrap installer" mit den drei Routes.
- **ARCHITECTURE.md §17** „LLM-basierte Update-Befehl-Empfehlung pro
  Finding" als expliziter Out-of-Scope-Punkt fuer v0.7.0 ergaenzt.

### DB-Migration

- `alembic/versions/0003_block_n_agent_and_finding_cause.py`. Sieben
  `add_column` (zwei `servers`, fuenf `findings`) — `Server.agent_version`
  existierte bereits aus Migration 0002. Alle nullable, kein Backfill.
  UNIQUE-Constraint `uq_findings_natural_key` unveraendert.
  `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`
  durchlaeuft sauber.

### Tests

- 992 Tests grün (vorher 884), 5 e2e SKIPPED, 4 deselected
  (Bench + Integration). 254 adversarial PASS (+14 Block-N-Cases:
  Path-Traversal, no-secrets, outdated-reject, public-no-auth,
  PURL-XSS, VendorIDs-Injection). Coverage **92.16 %** (Threshold 85 %).
- `tests/integration/installer/` mit Ubuntu 24.04- und AlmaLinux-9-
  Dockerfiles plus `run.sh`. Marker `@pytest.mark.integration`, aus
  Default-Suite via `pyproject.toml`/`pytest.ini` ausgeschlossen.
  Make-Target `make test-installer`.
- Block-N-spezifische Test-Module: `test_agent_constants`,
  `test_agent_version`, `test_scans_envelope_trivy_version`,
  `test_envelope_cause_fields`, `test_findings_ingest_cause_mapping`,
  `test_agent_install`, `test_agent_install_render`,
  `test_agent_install_smoke`, `test_agent_strip`,
  `test_block_n_columns`, `test_finding_display`,
  `test_server_detail_outdated_pills`, `test_sidebar_outdated_marker`,
  `test_findings_section_cause_row`.
- `ruff check`/`ruff format --check`/`mypy app/` PASS;
  `shellcheck agent/*.sh` PASS;
  `docker build` + `docker compose up --build` + `/healthz`/`/install.sh`/
  `/agent/version`/`/agent/files/secscan-agent.sh` PASS;
  Image-Size 191 MB (unveraendert vs. v0.6.x).

### Migrationen / Operations

- `alembic upgrade head` automatisch beim Container-Start
  (Entrypoint unveraendert).
- Bestehende v0.1.0-Agents werden **nicht** abgewiesen
  (`MIN_AGENT_VERSION="0.1.0"`), bekommen aber die Veraltet-Pill in
  der UI sobald `CURRENT_AGENT_VERSION` gebumpt wird. Operator
  migriert via Re-Run des Einzeilers
  `curl -fsSL .../install.sh | sudo bash` — der Installer erkennt
  bestehende Registrierung und ueberspringt Phase 4.

## [v0.6.1] — 2026-05-17

### Fixed

- Ingest-Schema rejecte Trivy-Scans mit > 50 References pro Vulnerability
  hart mit HTTP 422 (`scan.Results.*.Vulnerabilities.*.References:
  too_long`), obwohl der `_validate_references`-Validator defensiv auf
  das Limit trimmen sollte. Ursache: `max_length=…` am Pydantic-Field
  feuert als Built-in-Constraint VOR dem `@field_validator(mode="after")`-
  Trim. Real beobachtet auf einer arm64-Hetzner-Cloud-Instanz
  (Ubuntu 22.04, rke2-Server): der Scan enthielt 20+ Distro-CVEs mit
  jeweils > 50 References (NVD + Ubuntu-Mailinglisten + Vendor-Advisories).
  Fix: `max_length` aus den Field-Definitionen `references` und `cwe_ids`
  in `app/schemas/scan_envelope.py` entfernt — der Trim-Validator ist
  jetzt die einzige Cap-Quelle.

### Changed

- `MAX_REFERENCES_PER_VULN` von 50 auf 100 angehoben.
- `MAX_CWE_IDS_PER_VULN` von 20 auf 50 angehoben.
- ARCHITECTURE §10 Validierungs-Limits entsprechend aktualisiert
  (defensives Trim explizit dokumentiert statt impliziertem Hard-Reject).

### Tests

- `tests/adversarial/test_envelope_validation.py`: vier neue Boundary-
  und Trim-Tests fuer `references` und `cwe_ids` (jeweils
  `_trimmed_above_N` + `_at_N_boundary`). Alter `test_references_max_50`-
  Test umgeschrieben — `pytest.raises(ValidationError)` raus.
- `tests/api/test_scans_ingest.py`: neuer Integration-Regression-Test
  `test_scans_202_accepts_vuln_with_many_references` — Envelope mit 120
  References + 60 CWE-IDs landet als 202 statt 422; DB persistiert die
  defensiv getrimmten Listen (100 bzw. 50).
- 873 Tests grün, Coverage unveraendert ueber Threshold 85 %.

### Migrationen / Operations

- Keine Alembic-Migration. `Finding.references` ist `ARRAY(Text)` und
  `Finding.cwe_ids` ist `ARRAY(String(16))` ohne harte Length-Constraints.
- Bestehende Agents brauchen kein Update — sie senden bereits den
  vollen Trivy-Output; bisher wurden sie nur abgewiesen.

## [v0.6.0] — 2026-05-16

Dashboard-Redesign aus [ADR-0020](docs/decisions/0020-dashboard-cross-server-findings.md).
Das Dashboard-Pane bekommt KPI-Cards mit 50-Tage-Sparklines (analog
Block K Server-Detail) und eine cross-server Findings-Triage-Tabelle mit
Hybrid-Auto-Submit-Filter. Die separate Such-View `/findings/search` faellt
ersatzlos weg — der Sticky-Sidebar-Such-Slot zeigt jetzt auf
`dashboard.index?q=...`. Funktional ein groesseres UX-Update gegenueber
v0.5.0; kein DB-Schema-Bruch, keine API-Compat-Bruchstelle (der entfernte
Endpoint war nicht extern dokumentiert).

### Geaendert — Block M (ADR-0020)

- Dashboard-Pane (`app/templates/dashboard/_detail_pane.html`) komplett
  umgebaut: Header (Eyebrow `DASHBOARD` + Title `Alle Findings`) + KPI-Card-
  Grid (`_kpi_cards.html`) + Findings-Section (`_findings_section.html`).
- Fuenf KPI-Cards (`Total Open`, `KEV`, `Critical`, `High`, `Stale-Server`)
  mit grossem Counter, Eyebrow-Label und filter-unabhaengiger 50-Tage-
  Sparkline. Cards sind klickbar und setzen den passenden Quick-Filter
  (`/?kev_only=1`, `/?severity=critical`, `/?severity=high`, `/?stale_only=1`;
  Total-Card resettet den Filter). Reuse von `servers/_kpi_card.html` mit
  neuem `link_url`-Parameter.
- Findings-Section mit Hybrid-Auto-Submit-Filter (`q`, `tag`, `severity`,
  `status`, `kev_only`, `stale_only`), debounced `q`-Input (400 ms keyup),
  sortierbare Spaltenheader inkl. neuem Sort-Key `server`, Bulk-Select-
  Toolbar (Reuse Block-F-Endpoint cross-server), Truncation-Notice unter
  der Tabelle bei `total > 200`.
- CSV-Export `/findings/export.csv` erweitert: ohne `server_id` cross-server-
  Modus mit `Server`-Spalte und Dashboard-Filter (`q`/`tag`/`severity`/
  `status`/`kev_only`/`stale_only`/`sort`/`dir`). Kein Row-Limit fuer CSV.
- `DashboardFilter` (`app/schemas/dashboard_filter.py`) um `q`, `status`,
  `sort`, `dir` erweitert. Whitelist-Validierung mit `log.debug`-Reject +
  Default-Fallback. Neue Methode `to_query_string(override=...)` fuer
  Re-Build von Filter-URLs.
- `app/services/findings_query.py`: neue Public-Funktion
  `list_findings_cross_server(...)` (eager Server/Tags, OR-`q`-Filter via
  JOIN, stale Python-Post-Filter, ORM-Whitelist-Sort, exakter Pre-Limit-
  COUNT). `_apply_tag_filter_cross` aus dem entfernten Search-View
  hierherportiert.
- `app/services/severity_history.py`: neue Public-Funktion
  `daily_severity_counts_fleet(...)` (Total/KEV/Critical/High Sparklines
  ueber 50 Tage; Differenz-Array-Optimierung, Bench 50k×50d < 200 ms).
- `app/services/stale_history.py` (NEU): `daily_stale_server_counts(...)`
  rekonstruiert die Stale-Server-Reihe aus `Scan.received_at` × `Server.
  expected_scan_interval_h` (Faktor 2, analog `is_stale()`). Bench
  200×50d < 100 ms.
- `_macros.html:sort_header()` um optionale Parameter `route` und
  `route_kwargs` erweitert — gleiche Macro fuer Server-Detail (Block K)
  und Dashboard (Block M).
- ARCHITECTURE §7 + §15 auf die Block-M-Realitaet aktualisiert; ADR-0016
  als „Teilweise abgeloest durch ADR-0020" markiert (Dashboard-Pane-Layout-
  Sektionen — Header/Profile-Dropdown bleiben gueltig).
- Polling-Wrapper aus Block L (`hx-disinherit="*"`) bleibt unveraendert
  auf dem Pane-Container; alle KPI-Card-/Filter-Klicks setzen ihre eigenen
  HTMX-Attribute explizit.

### Entfernt — Block M (ADR-0020)

- `GET /findings/search` (kein extern dokumentierter Endpoint, kein
  Kompatibilitaets-Bruch).
- `app/views/search.py` (≈350 LoC), `app/templates/findings/search.html`,
  `app/templates/_empty/no_search_results.html`.
- `app/templates/dashboard/_quick_stats.html`, `_filter_bar.html`,
  `_attention.html` (durch KPI-Cards + Filter-in-Findings-Section
  abgeloest).
- `AttentionSection`-Dataclass und `_build_attention()` aus
  `app/views/dashboard.py` (Dead-Code nach Template-Entfernung).
- Sidebar-Such-Form-CVE-Auto-Detect-JS und `kind`-Switch in
  `app/static/js/sidebar.js`.

### Tests

- 869 passed, 5 skipped (E2E ohne Backend), Coverage 91.78 % (Threshold
  85 %). 224 adversarial Tests passed.
- Neue Service-Tests: `tests/services/test_findings_query_cross.py`,
  `tests/services/test_severity_history_fleet.py`,
  `tests/services/test_stale_history.py`,
  `tests/services/test_csv_export_cross.py` (inkl. zwei `@pytest.mark.
  bench`-Cases hinter Default-Filter `-m "not bench"`).
- Neue View-Tests in `tests/views/test_dashboard.py` (21 Tests: KPI-
  Cards, Findings-Tabelle, q-/status-/sort-Filter, KPI-Card-Klicks,
  Truncation, HX-Sub-Tree-Swap, /findings/search-404, CSV-Cross-Server,
  Bulk-Ack-Cross-Server, Context-Vertrag).
- Neue Adversarial-Tests: `test_dashboard_sort_param_injection.py`,
  `test_dashboard_q_xss.py`, `test_dashboard_q_sql_injection.py`,
  `test_dashboard_csv_formula_injection_server_name.py`.
- Geloescht: `tests/views/test_search.py` (gesamtes Such-Test-Modul).
- Angepasst: `tests/views/test_header_navigation.py`,
  `tests/views/test_sidebar_layout.py`,
  `tests/views/test_dashboard_pane_consistency.py` (Markup-Drift auf
  Block-M-Marker).

### Security

- Security-Auditor: **ACCEPTABLE WITH NOTES** — alle fuenf Block-M-Audit-
  Punkte PASS (q-SQL via ORM-Bind, q-XSS-Escape im Filter-Echo,
  sort/dir-Whitelist im ORM, CSV-Formula-Injection-Mitigation auf
  Server-Spalte, Bulk-Ack cross-server bleibt `@login_required` + CSRF).
- Zwei kosmetische NOTES adressiert: Doc-Korrektur in `app/api/__init__.
  py` (CSRF ist NICHT global ausgeschaltet, nur einzelne Agent-Endpoints
  per `@csrf.exempt`); ilike-Metachar-Escape fuer `q` als optionaler
  Re-Open-Trigger dokumentiert (`q="%%%"` matched alles, durch 128-Char-
  Cap + 200-Row-Limit kontrolliert).

### Migrationen / Operations

- Keine Alembic-Migration. Roundtrip `upgrade head ↔ downgrade -1 ↔
  upgrade head` PASS.
- Docker-Image 191 MB (< 200 MB).

## [v0.5.0] — 2026-05-16

Stabilitaets-Release aus [ADR-0019](docs/decisions/0019-dashboard-polling-not-sse.md).
Beobachtete Haenger im `docker compose`-Stack (HTTP/1.1-Slot-Limit,
Thread-Pin, EventBus-Worker-Affinity) werden behoben, indem
Dashboard-Live-Updates von Server-Sent-Events auf HTMX-Polling
umgestellt werden. LLM-Chat-Streaming (`GET /chat/<id>/stream`)
bleibt unveraendert SSE — der einzige verbleibende SSE-Endpoint.

Funktional gegenueber v0.4.0 aus User-Sicht unveraendert bis auf die
Update-Latenz: statt < 1 s (SSE-Push) zeigt das Dashboard Aenderungen
mit durchschnittlich ~5 s Verzoegerung an (Polling-Intervall 10 s).
Animations-Verhalten beim Update bleibt identisch (`sse_highlight.js`
laeuft auf `htmx:afterSettle`).

### Geaendert — Block L (ADR-0019)

- Dashboard-Pane (`app/templates/dashboard/_detail_pane.html`) ist jetzt
  ein HTMX-Polling-Container mit `id="dashboard-pane"`,
  `hx-trigger="every 10s [document.visibilityState === 'visible']"`
  und `hx-swap="outerHTML"`. Aktive Filter (`?severity=...`, `?tag=...`)
  werden ueber `request.path` + optionaler `request.query_string` im
  Re-Fetch erhalten.
- Sidebar-Server-Liste (`app/templates/sidebar/_server_list.html`,
  neu extrahiert) polled analog gegen die neue Route
  `GET /_partials/sidebar` (`sidebar_partials_bp.sidebar_partial`,
  `@login_required`).
- ARCHITECTURE §6 / §7 / §7a auf Polling umgestellt; §14-Audit-Log-Hinweis
  korrigiert (`scan.ingested` statt nie-implementiertes `scan.received`).
- Dockerfile-Kommentar: `gthread`-Begruendung verlagert sich auf den
  LLM-Stream-Endpoint allein. Thread-Zahlen `2 × 8` unveraendert.
- README nginx-/Caddy-Snippets ohne `/events`-Block.
- `app/static/js/sse.js` umbenannt zu `app/static/js/stale.js`.
  `staleTick()` unveraendert; `dashboardSse(...)` ersatzlos entfernt.
  `app/static/js/sse_highlight.js` bleibt eingebunden (Polling-Highlight
  laeuft weiter ueber `htmx:afterSettle`), nur der nie mehr gefeuerte
  `secscan:scan-received`-Listener ist raus.

### Entfernt — Block L (ADR-0019)

- `GET /events`-SSE-Endpoint (`app/api/events.py`, 116 LoC) — kein extern
  dokumentierter API-Endpoint, kein Kompatibilitaets-Bruch.
- In-process `EventBus` (`app/services/event_bus.py`, 163 LoC).
- `event_bus.publish("scan.received", ...)`-Hook im Scan-Ingest
  (`app/api/scans.py`).
- `init_event_bus(app)` und `events_bp`-Blueprint-Registrierung in
  `app/__init__.py`.
- Alpine-Komponente `dashboardSse(...)` plus `window.dashboardSse`-Export.

### Tests

- 785 passed, 5 skipped (E2E ohne Backend), Coverage 92.35 %.
- 177 adversarial Tests passed.
- Drei neue Test-Module: `tests/views/test_dashboard_polling.py`,
  `tests/views/test_sidebar_partial.py`,
  `tests/adversarial/test_polling_no_rate_limit.py`.
- Drei geloeschte Test-Module gegen die entfernte SSE-Surface:
  `tests/api/test_events_sse.py`, `tests/api/test_scans_event_publish.py`,
  `tests/services/test_event_bus.py`.

### Migrationen / Operations

- Keine Alembic-Migration noetig (reine Code- und Template-Aenderung).
- Roll-Back-Plan: Branch verwerfen, ADR-0019 auf „Verworfen" setzen,
  alternative Loesung als neue ADR. Live-System laeuft auf v0.4.0
  weiter — SSE-Haenger sind nervig aber nicht datenschaedigend.

## [v0.3.0] — 2026-05-15

UI-Refinement-Release aus ADR-0016. Funktional gegenueber v0.2.0
unveraendert — Layout wird kompakter und an uptime-kuma-Konvention
angeglichen. Plus zwei neue Settings-Sub-Views: Master-Key-Rotation
(schliesst §8-Spec-Luecke) und About.

### Added — Block-I-Refinement (ADR-0016)

- **Header kompakt** in `app/templates/layout/_header.html`: Logo +
  Dashboard-Button + Suche-Button + Theme-Toggle (sichtbares Sun/Moon-
  Icon) + Profile-Avatar mit Initial. Drei Top-Level-Items statt
  vorher fuenf. Logo-Klick und Dashboard-Button identischer Effekt
  (Dashboard-Default).
- **Profile-Dropdown** in `app/templates/layout/_profile_dropdown.html`:
  flache Eintraege Settings → Audit → Logout. Kein Sub-Menue.
  `@click.outside`-Close, `@keydown.escape.window`-Close. Logout als
  CSRF-geschuetztes POST-Form.
- **Settings-View mit Sekundaer-Navigation** im Detail-Pane:
  linke Nav-Liste (`app/templates/settings/_nav.html`) mit Tags,
  LLM-Provider, Server-Verwaltung, Master-Key (Badge "neu"), About.
  Aktiver Eintrag visuell hervorgehoben. Klick swappt nur den
  Content-Bereich rechts via HTMX (`hx-target="#settings-content"`,
  `hx-swap="innerHTML"`, `hx-push-url="true"`).
- **3-Modi-Render-Helper** `app/views/_settings_shell.py`:
  Vollseite (Direkt-URL/Bookmark), Shell-Fragment (HX mit
  `hx-target="#detail-pane"`), Content-only (HX mit
  `hx-target="settings-content"`). Saubere Trennung pro `HX-Target`-
  Header.
- **`/settings`-Alias** → 302 auf `/settings/servers/` (User-
  Klarstellung — Server-Verwaltung ist der haeufiger genutzte Default
  als Tags).
- **Master-Key-Rotation** (`/settings/master-key`):
  - `GET`: rendert Hinweis-Box mit Last-Set-Datum.
  - `POST /rotate` mit Confirm-Modal davor: generiert neuen Master-
    Key via `secrets.token_urlsafe(32)`, Hash-Update in `settings.
    master_key_hash`, einmalige Klartext-Anzeige mit Copy-Button.
  - Audit-Event `master_key.rotated` mit nur `metadata.hash_prefix`
    (8 Hex-Zeichen) — NIEMALS Klartext oder voller Hash.
  - Server-Keys bleiben gueltig (Hash-Trennung).
  - CSRF zwingend.
- **About-View** (`/settings/about`): read-only Versions-Info:
  `app_version` (via `importlib.metadata`), `build_revision`
  (Env-Var `SECSCAN_BUILD_REVISION` mit Fallback `dev`),
  `alembic_revision`, Python-/Flask-/SQLAlchemy-Versionen,
  Trivy-DB-Stale-Server-Count, Healthcheck-Link. Kein
  Secret-Leak (`SECSCAN_ENCRYPTION_KEY`, `master_key_hash`,
  `llm_api_key_encrypted` explizit nicht im Context).
- **Dashboard-Default-Pane** uebernimmt die ehemaligen Sidebar-
  Inhalte: Quick-Stats horizontal (Total open / KEV / Critical /
  High / Stale-Server), Filter-Bar (Tag/Severity/KEV/Stale),
  Platzhalter-Bereich mit expliziter "bewusst leer"-Notiz.
- **Sidebar reduziert** auf reine Server-Liste mit Sticky-Search
  (Placeholder umbenannt auf "Server filtern…") + Heartbeat-Bars.
  Quick-Stats / Filter-Chips / Settings-Footer entfernt.
- **`MasterKeyRotateForm`** in `app/forms.py`: CSRF-only WTForm.
- **`Dockerfile`** mit `ARG SECSCAN_BUILD_REVISION=dev` → `ENV` in
  Runtime-Stage, fuer GitHub-Actions-Release-Workflow per
  `--build-arg ${{ github.sha }}`.

### Fixed

- **Test-Suite-Haenger** (`tests/conftest.py:_truncate_all`):
  `TRUNCATE ... CASCADE` haengte stillschweigend wenn ein
  vorheriger Test eine Connection mit offener Transaction
  hinterlassen hat. Fix: `lock_timeout = '5s'` + `statement_
  timeout = '10s'` + `pg_terminate_backend(pid)`-Cleanup vor dem
  TRUNCATE. Volle Suite laeuft jetzt deterministisch in ~30s
  statt potentiell Endlos-Hang.
- **`pytest-timeout`-Dependency**: ergaenzt, sodass kuenftige
  Haenger nicht den ganzen Lauf blockieren. Alle Test-Aufrufe
  jetzt mit `--timeout=15 --timeout-method=thread`.

### Tests

- 48 neue Tests in `tests/views/`:
  - `test_master_key_rotation.py` (9): Auth, CSRF, Hash-Aenderung,
    Audit-Event mit hash_prefix, Klartext-Schutz, Server-Key-
    Invarianz.
  - `test_about_view.py` (10): alle Versions-Strings, Secret-
    Leak-Check.
  - `test_header_navigation.py` (8): Active-Marker, Logo-Href,
    Dropdown-Reihenfolge, Logout-CSRF, Theme-Toggle.
  - `test_settings_dropdown_swap.py` (20): 3 Render-Modi pro
    5 Sub-Routes.
  - `test_settings_alias_redirect.py` (4): `/settings` →
    `/settings/servers/`.
- 10 bestehende `test_dashboard.py`-Tests umgeschrieben auf neuen
  Detail-Pane-Inhalt (Quick-Stats statt Card-Grid).
- `test_settings_sidebar_swap.py` ersetzt durch
  `test_settings_dropdown_swap.py`.
- **Total: 722 passed**, Coverage 92.21 %.

### Security

- security-auditor-Verdict: **ACCEPTABLE WITH NOTES**.
- CSRF auf `POST /settings/master-key/rotate` zwingend, Test
  verifiziert 400 ohne Token.
- Master-Key-Klartext: nur einmal im UI gerendert (Jinja-
  Autoescape), nie in Logs (structlog redact pattern
  `key|password|token|hash|authorization`), nie in Audit-
  Metadata (nur hash_prefix[:8]).
- About-View Secret-Leak-Tests gruen.
- HX-Target-Header: kein Open-Redirect-/XSS-Vektor (reiner
  String-Vergleich, kein URL-Build).
- 1 low CONCERN: kein dedizierter XSS-Adversarial-Test fuer
  Master-Key-Klartext-Render. Kein realer Angriffsvektor weil
  `secrets.token_urlsafe(32)` zeichen-eingeschraenkt ist
  ([A-Za-z0-9_-]). Defense-in-Depth-Test ist optional
  fuer einen Folge-Block.

### Architektur-Entscheidungen

- **ADR-0016** (Header-Navigation kompakt, Settings und Audit ins
  Profile-Dropdown): Block-I-Plan und ARCHITECTURE §7a werden nicht
  editiert, Deltas im Addendum `docs/blocks/I-addendum-header-
  layout.md` ausgewiesen.
- Default-Settings-Sub-Tab: **Server-Verwaltung** (User-Klarstellung
  gegenueber Addendum-Default Tags) — Server-Verwaltung ist
  haeufiger genutzter Ops-View.

### Screenshots

- `docs/blocks/I-refinement-evidence/dashboard.png` — Header + Sidebar + Quick-Stats + Platzhalter.
- `docs/blocks/I-refinement-evidence/profile-dropdown.png` — flaches Dropdown.
- `docs/blocks/I-refinement-evidence/settings-servers.png` — Settings mit Sekundaer-Nav.
- `docs/blocks/I-refinement-evidence/settings-master-key.png` — Rotations-View.
- `docs/blocks/I-refinement-evidence/settings-about.png` — Versions-Info.

---

## [v0.2.0] — 2026-05-15

UI-Modernisierung als Folge-Release nach v0.1.0. Funktional unveraendert
— gleiche Routen, Endpoints, Daten-Vertraege. Layout wechselt von
Multi-Page-Card-Grid zu Single-Page-Sidebar + Detail-Pane im
uptime-kuma-Spirit.

### Added — Block I: UI-Modernisierung

- **Single-Page-Layout** in neuer `base_app.html`. Sidebar links
  (320/384px) mit Quick-Stats, Sticky-Search (`/`-Shortcut), Tag-Filter,
  Server-Liste mit Heartbeat-Bars, Settings-Akkordeon. Detail-Pane
  rechts mit HTMX-Swap und `hx-push-url`.
- **Heartbeat-Bars** pro Server-Eintrag in der Sidebar. 50 Tage als
  vertikale Pillen, Severity-Farb-Mapping (critical=error,
  high=warning, medium=accent, low=info, unknown=ghost, clean=success/40,
  no-scan=base-300). KEV-Tage zusaetzlich mit `ring-1 ring-error`.
  Tooltip mit 300ms-Delay zeigt Datum, max Severity, KEV-Count,
  Scan-Status. Aggregation als Python-Service (Variante B),
  Performance unter 200 ms fuer 50 Server x 50 Tage.
- **Quick-Stats** als Mini-Block oben in der Sidebar: 5 Counter
  (open / KEV / critical / high / stale-server) mit Filter-Klicks.
- **Sticky-Search-Header** mit `/`-Shortcut. Live-Filter der
  Server-Liste clientseitig (Substring auf Name + Tag-Namen).
  `Enter` oeffnet globale Suche im Detail-Pane, `Esc` leert.
- **Settings als Sidebar-Tab**: kompakte Akkordeon-Liste am unteren
  Sidebar-Rand mit "Server", "Tags", "LLM-Provider", "API-Keys &
  Master-Key", "About".
- **HTMX-Routing-Refactor**: alle authentifizierten View-Routen
  (`/`, `/servers/<id>`, `/findings/search`, `/audit/`, `/settings/*`)
  liefern bei `HX-Request: true` nur das Detail-Pane-Fragment.
  Direkt-URL und Bookmarks funktionieren weiter.
- **Sidebar-Context-Processor**: Flask-`@app.context_processor`
  injiziert Sidebar-Variablen automatisch fuer alle authentifizierten
  Vollseiten-Renders, skipt bei HX-Request und unauthentifizierten
  Routen.
- **Empty-States** mit klaren CTAs unter `app/templates/_empty/`
  (no_servers, no_findings, no_audit, no_search_results).
- **Quick-Copy-Macro-Regression-Fix** aus Block F: `tojson | forceescape`
  verhindert dass JS-Code im Attribut den DOM-Body verschmutzt.
- **Subtle Fade-In bei SSE-Updates**: `htmx:afterSettle`-Listener und
  `secscan:scan-received`-Custom-Event fuegen 1 s `bg-info/20`-Akzent
  an Swap-Targets bzw. Sidebar-Rows.
- **Monospace-Cleanup**: `font-mono`-Klasse auf CVE-IDs, Paketen,
  Versionen, Hostnames, Kerneln, Pfaden, Hash-IDs ueber 6 zentrale
  Templates.

### Tests

- 45 neue Block-I-Tests (Heartbeat-Aggregation, Quick-Stats,
  Sidebar-Layout, Keyboard-Shortcut, Settings-Sidebar-Swap,
  XSS-in-Heartbeat-Tooltip).
- **674 Tests gruen** (629 + 45), Coverage **92.54 %**, Adversarial-
  Suite weiterhin 131/131.
- Performance-Sanity-Test: 50 Server x 50 Tage Heartbeat-Aggregation
  unter 200 ms.

### Security

- security-auditor-Verdict: **CLEAN**.
- XSS-Tests in Server-Namen, Heartbeat-Tooltip-Daten-Attributen,
  Tag-Filter-Pfaden — alle escapeed via Jinja-Autoescape und JS
  `textContent`.
- Quick-Stats SQL ueber SQLAlchemy-ORM mit Bind-Parametern.
- Open-Redirect via `hx-push-url`/`pushState` ausgeschlossen
  (alle HTMX-URLs aus `url_for()`, Search-Pfad mit
  `encodeURIComponent`-Schutz).
- CSRF-Verhalten unveraendert (alle Block-I-Routen sind GET).

### Architektur-Entscheidungen

- **Heartbeat-Aggregation Variante B**: Python-Service mit on-the-fly-
  Aggregation, keine Postgres-Materialized-View. Re-Open-Trigger:
  wenn Sidebar-Render > 200 ms wird.
- **`base.html` vs `base_app.html` Clean-Split**: `base.html` bleibt
  fuer Pre-Auth-Routen (Login, Setup), `base_app.html` ist die App-
  Shell fuer authentifizierte Routen. HX-Fragmente extenden
  `_partial_shell.html`.
- ADR-0012 dokumentiert warum Block I separater Block ist und
  was bewusst draussen bleibt (Dark-Mode-Default, Mobile, Cmd-K,
  Vim-Shortcuts, Optimistic-Updates).

### Was bewusst draussen bleibt (siehe ADR-0012)

- Mobile-Layout (ADR-0009 weiterhin in Kraft).
- Dark-Mode als Default.
- Cmd-K Command-Palette.
- Vim-Style-Keyboard-Shortcuts.
- Optimistic-Updates.
- Loading-Skeletons (HTMX-Default reicht).

### Screenshots

- `docs/blocks/I-evidence/dashboard.png` — Sidebar mit 4 Servern,
  Heartbeat-Bars, Quick-Stats; Detail-Pane mit Dashboard.
- `docs/blocks/I-evidence/server-detail.png` — Sidebar mit aktiver
  Server-Row, Detail-Pane mit Findings-Tabelle.

---

## [v0.1.0] — 2026-05-15

Erstes MVP-Release. Selbst-gehostete Web-App fuer Triage von
Trivy-Filesystem-Scans auf Root-Servern. Spirit: uptime-kuma fuer CVEs.

### Added — Block A: Skelett und Basis

- Flask-App-Factory mit Cross-Cutting-Defaults (Body-Limit 10 MB,
  `flask-limiter` In-Memory, `structlog` JSON-Logging mit Redaction-Filter,
  Jinja-Autoescape, Theme-Cookie).
- `pydantic-settings` Config mit Pflicht-`SECSCAN_ENCRYPTION_KEY` und
  `SECSCAN_SECRET_KEY` aus der Umgebung.
- `/healthz` (DB-Ping) und `/readyz` (unabhaengig vom DB-Zustand).
- Multi-stage `Dockerfile`, `docker-compose.yml` mit Postgres 17 in
  eigenem Container.
- Alembic-Setup mit leerer Baseline-Migration.

### Added — Block B: Datenmodell, Setup-Wizard und Auth

- 12-Tabellen-Datenmodell: `servers`, `scans`, `findings`, `finding_notes`,
  `tags`, `server_tags`, `llm_conversations`, `llm_messages`,
  `llm_conversation_findings`, `users`, `audit_events`, `settings`.
- Setup-Wizard `/setup/{step1,step2,step3}` mit einmaliger
  Master-Key-Anzeige in Step 2.
- Argon2id-Passwort-Hashing fuer Admin-Accounts und Master-Key,
  SHA-256 + `hmac.compare_digest` fuer hochentropische Server-Keys.
- Tag-CRUD-View `/settings/tags` mit Color-Picker.
- Audit-Helper `log_event()` mit strukturiertem Metadata-JSONB.

### Added — Block C: Ingest, Server-Verwaltung und Agent-E2E

- Pydantic-Envelope-Schema mit Regex-Whitelists pro Feldtyp, NUL-Byte-
  Reject und Tiefenlimit (32) gegen JSON-Bomben.
- Gzip-Streaming-Decompress mit 100-MB-Limit gegen Zip-Bombs.
- `POST /api/register` mit einmaliger Server-Key-Vergabe.
- `POST /api/scans` mit strikter Auth-vor-Body-Parse-Reihenfolge
  (Bearer-Vergleich via `hmac.compare_digest` vor Body-Read),
  Dedup-Upsert via `INSERT ... ON CONFLICT`, automatischer Resolve-Phase
  fuer im neuen Scan fehlende Findings.
- `POST /api/keys/rotate` fuer Master- und Server-Key.
- Server-Verwaltungs-View `/settings/servers` mit Revoke und Retire.
- ADR-0011: `package_name@target`-Disambiguation fuer lang-pkgs (zwei
  Findings mit gleicher CVE in unterschiedlichen Targets sind separate
  Findings).
- Referenz-Agent `agent/secscan-agent.sh` und `agent/secscan-register.sh`.

### Added — Block D: Dashboard mit Tags und Stale-Detection

- Dashboard `/` mit Server-Karten, Severity-Badges, KEV-Counter, EPSS-
  Top-Hits.
- Tag-Filter mit OR-/AND-Modus, URL-persistent fuer teilbare Views.
- "Aufmerksamkeit noetig"-Sektion fuer stale Server, KEV-Findings und
  Trivy-DB-veraltet.
- Stale-Detection-Service mit `is_stale` (kein Scan im konfigurierten
  Fenster) und `is_db_stale` (Trivy-DB-Update zu alt).
- Server-Detail-Header mit HTMX-Tag-Inline-Editor.
- Theme-Toggle (Light/Dark) in `static/js/theme.js` extrahiert.

### Added — Block E: Triage in der Server-Detail-View

- Drei View-Modi: Liste, Group-by-Package und Diff-seit-letztem-Scan.
- Triage-Sortierung KEV -> EPSS -> CVSS -> Severity -> `first_seen_at`.
- Finding-Detail-Modal mit Notes-Thread (mehrere Notizen pro Finding).
- Acknowledge- und Re-Open-Flow mit OPTIONALEM Kommentar (ADR-0006 —
  keine Pflicht-Kommentare).
- Markdown-Subset-Rendering fuer Notizen durch `nh3`-Allowlist
  (`p`, `strong`, `em`, `code`, `pre`, `a`, `ul`/`ol`/`li`, `br`).
- Quick-Copy-Icon-Macro mit Toast-Bestaetigung.
- Sicherheits-Fix: `delete_note` mit Owner-Check und 403 fuer
  System-Notes.

### Added — Block F: Bulk-Operationen und globale Suche

- Bulk-Acknowledge mit `dry_run`-Phase (Default true) und zwei Flavors:
  `finding_ids` (explizite Liste) ODER `match` (Kriterien-basiert).
- Globale Suche `/findings/search` mit CVE-, Paket- und Server-Modus.
  Bei CVE-Suche zusaetzlich Aggregations-Header (Anzahl betroffener
  Server, gesamt offene Instanzen).
- Audit-View `/audit` mit Datum-/Actor-/Action-/Server-/Tag-Filtern und
  CSV-Export.
- CSV-Export aus Findings-Liste und Audit-View.
- CSV-Injection-Mitigation per Apostroph-Prefix auf `=`, `+`, `-`, `@`,
  `\t`, `\r` (OWASP-Recommendation).

### Added — Block G: LLM-Integration mit Streaming-Chat

- `AsyncOpenAI`-Wrapper mit Fernet-verschluesseltem API-Key in der DB.
- LLM-Provider-Settings mit Preset-Dropdown (DeepInfra, OpenAI, Ollama,
  custom) und Test-Verbindungs-Button.
- Prompt-Injection-Marker `<<TRIVY_DATA_START>>` / `<<TRIVY_DATA_END>>`
  im System-Prompt, plus explizite Anti-Injection-Instruktion.
- LLM-Chat-View `/chat/<conversation_id>` mit SSE-Token-Streaming.
- Tages-Token-Cap mit 80%-Warn-Banner und 100%-Hard-Block (Reset um
  00:00 UTC).
- Provider-Wechsel archiviert aktive Conversations automatisch.
- `nh3`-Sanitization auf LLM-Output (gleiche Allowlist wie Notizen).
- `llm_base_url`-Whitelist: HTTPS Pflicht ausser `http://localhost`
  und `http://127.0.0.1`.
- ADR-0013: Fernet-KDF (`sha256[:32]`) beibehalten, dafuer
  Weak-Key-Warning beim App-Start und Pflicht-Doku zur Random-Generierung.
- ADR-0014: Token-Cap als Best-Effort dokumentiert (parallele Streams
  koennen den Cap geringfuegig ueberschreiten — Cost-Cap, kein
  Security-Cap).

### Added — Block H: Live-Updates und Production-Hardening

- In-process Event-Bus mit `GET /events` SSE-Endpoint, Heartbeat alle
  30 s.
- Dashboard-Live-Update bei neuen Scans (Card-Highlight-Animation
  ohne Page-Reload).
- Client-seitiger Stale-Re-Render-Timer alle 60 s, damit Stale-Badges
  live aufpoppen ohne neuen Scan.
- `validate_base_url` mit Port-Range-Check (1..65535) — schliesst
  ADR-0014-Action-Item.
- `@limiter.limit("60/hour")` auf SSE-Stream und LLM-Test-Connection.
- `Authorization`-Header im `structlog`-Redaction-Pattern ergaenzt.
- E2E-Smoke-Skript `scripts/e2e_smoke.sh` (Setup-Wizard via curl,
  Agent-Register, Ingest gegen Real-Fixture, Health-/Auth-/Bomb-
  Verifikation).
- Reverse-Proxy-Snippets fuer nginx und Caddy in der README.
- IP-Allowlist-Empfehlung fuer `/api/scans` mit Beispiel-CIDRs.
- Deploy-Checkliste in der README.

### Sicherheits-Eigenschaften (final)

- Auth-vor-Body-Parse auf `/api/scans` — 401 in 22 ms gegen ungueltigen
  Bearer (gemessen in Block-C-Audit).
- Gzip-Bomb-Bound: 413 bei mehr als 100 MB Decompress, Streaming-
  Abbruch.
- Prompt-Injection-Marker und explizite Anti-Injection-Instruktion im
  LLM-System-Prompt.
- LLM-Output durchlaeuft `nh3`-Allowlist (gleiche wie User-Markdown).
- LLM-API-Key Fernet-verschluesselt mit deterministischer Ableitung —
  Pflicht-Doku zur Random-Generierung des `SECSCAN_ENCRYPTION_KEY`.
- `structlog`-Redaction auf `password`, `key`, `token`, `hash`,
  `authorization` in allen Keys und Stack-Traces.
- CSRF-Schutz auf allen state-changing POSTs via Flask-WTF.
- ADR-0006: keine Pflicht-Kommentare auf Comment-Feldern — verhindert
  Bypass-Pseudo-Kommentare und passt zur leisen UX.

### Tests

- 600+ Tests gruen ueber alle Bloecke verteilt (Block A: 25, B: 71,
  C: 71, D: 99, E: 67, F: 71, G: 149, H: noch im Test-Writer).
- Coverage > 85 % auf Block-spezifischen Modulen, `--cov-fail-under=85`
  als CI-Gate.
- Adversarial-Suite: NUL-Bytes, Skript-Tags, gzip-Bomb, Auth-vor-Body-
  Reihenfolge, CSV-Injection, XSS-in-CVE-Title, Prompt-Injection,
  Owner-Bypass auf Notes.

### Bekannte Limitationen

- **Single-User-MVP**: kein RBAC, kein OIDC, ein Admin-Account pro
  Instanz (siehe ARCHITECTURE.md §17 — Multi-User ist explizit out
  of scope).
- **Kein Mobile-Layout**: Desktop-first, Tailwind-Defaults skalieren
  Notfall-tauglich aber nicht optimiert (ADR-0009).
- **Token-Cap ist Best-Effort**: parallele LLM-Streams koennen den Cap
  marginal ueberschreiten (ADR-0014).
- **Fernet-KDF ohne Salt**: `SECSCAN_ENCRYPTION_KEY` muss
  hochentropisch sein (`secrets.token_urlsafe(48)` oder
  `openssl rand -base64 48`); siehe ADR-0013 und README-Quick-Start.
- **In-process Event-Bus**: kein verteilter PubSub, daher Single-
  Instance-Deploy. Mehrere Gunicorn-Worker subscriben unabhaengig —
  Browser-Tabs sehen Updates nur fuer ihren angeschlossenen Worker.
- **Keine Notifications**: Email, Webhook und Discord sind explizit
  v2-Feature, damit der secscan-Server keine zusaetzlichen Secrets
  haelt (siehe ARCHITECTURE.md §1, "Sicherheits-Stance").
