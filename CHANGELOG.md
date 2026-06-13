# Changelog

Alle nennenswerten Aenderungen an diesem Projekt werden hier dokumentiert.
Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/),
und das Projekt folgt [Semantic Versioning](https://semver.org/).

## [Unreleased] — Block AJ (ADR-0063 §Integration): Upstream-Verdikt im Group-Chat-Snapshot

Schliesst die ADR-0055-Snapshot-Erweiterung aus ADR-0063 §Integration: liegt für
eine `(Server, Group)` ein abgeschlossenes Upstream-Check-Verdikt vor, wird es
beim Chat-Start in den eingefrorenen System-Prompt aufgenommen — der Operator
kann mit dem Assistenten darüber reden („warum kein Fix?", „was heisst mitigate
hier?"). Beratend, friert mit dem Snapshot ein, ändert nie den Risk-Band. **Kein
Schema, keine Migration** — liest `upstream_check_results`. Quality-Gates grün.

### Added

- **`build_group_system_prompt(upstream_verdict=None)`** (`group_chat_prompt.py`):
  optionaler 8. Daten-Block „UPSTREAM CHECK (advisory · candidate · verify)"
  zwischen den TRIVY-Markern (untrusted → `_safe` + Marker-Neutralisierung),
  rendert delivery / fixed release / latest version / suggested action / sources /
  checked-at. Omitted bei `None`.
- **`_upstream_verdict_for_snapshot`** (`group_chat.py post_message`): beim
  Lazy-Create wird das Verdikt server-seitig via `lookup_state_for_group`
  (Reuse AI-2) ermittelt und nur bei `status == 'done'` eingefroren.

## [Unreleased] — Block AI-2 (ADR-0063): Agentische Upstream-Update-Suche — Operator-UI

Macht das in AI-1 gebaute Backend operator-nutzbar: Konfiguration im
Provider-Tab (kein psql mehr nötig) + „Check for upstream fix"-Button mit
advisory-Panel auf der `ESCALATE · Upstream fix`-Card. Feature bleibt
**default-off**, beratend, nie band-flippend. Quality-Gates grün:
`ruff`/`ruff format`/`mypy app/`, Pure-Unit (`pytest`). reviewer + security-auditor
(XSS-Fläche) grün. Live-Operator-Browser-Smoke steht beim User an.

### Added

- **Provider-Tab-Config** (`settings/llm_provider.html` + `UpstreamCheckSettingsForm`
  + `update_upstream`-View): Enable-Toggle, Such-Backend (searxng/tavily/firecrawl/
  serper), Base-URL, Fernet-verschlüsselter API-Key + optionale Basic-Auth,
  `llm_research_model`. Secrets via bestehenden `encrypt_api_key`-Helper; Audit
  `upstream_check.configured` (Secrets nur als Feldname). **Kein** Test-Probe.
- **Upstream-Check-Routen** (`app/api/upstream_check.py`, neues Blueprint):
  `POST /servers/<sid>/groups/<gid>/upstream-check` (enqueue, `@login_required`,
  CSRF, `10/min`, `IntegrityError`→409) + `GET …` (Poll-Partial, `120/min`).
  Worst-Upstream-Finding wird **server-seitig** aus `(sid,gid)` abgeleitet (kein
  Client-`finding_id` — IDOR-Schutz), gemeinsamer Group-Guard.
- **Single-Source-Panel** `servers/_partials/upstream_check_panel.html` (Initial-
  Render + Poll + POST-Response, ID `upstream-check-<sid>-<gid>-panel`): States
  idle/running/done/cached/disabled; HTMX-Poll-Attribut **nur** im `running`-State
  (stoppt sich selbst). Verdict + Quellen escaped (kein `|safe`; non-`http(s)`-URLs
  als Text statt `href`). „candidate · verify".
- **Card-State-Lookup** (`upstream_check_state.derive_state`/`worst_upstream_finding`):
  Initial-State pro escalate-upstream-Row ohne Sofort-Poll.

### Changed

- README: der „Agentic upstream check"-Bullet ist jetzt operator-wahr (UI vorhanden)
  und wird mit AI-2 committet.

## [Unreleased] — Block AI-1 (ADR-0063): Agentische Upstream-Update-Suche — Backend

**Optionale, operator-gated, beratende** agentische Suche, ob es für ein
`upstream`-Lane-Finding (lang-pkgs, nicht host-patchbar — ADR-0061/0062) schon
ein gefixtes Upstream-Release gibt. **Default off**, Air-Gap-sicher (Container
weglassen = null Outbound). **Backend-only** (AI-1): Runtime, Worker, Cache,
Config — die Operator-UI (Button + advisory-Panel) folgt in **Block AI-2**, die
Chat-Snapshot-Integration in einem Folge-Block. Quality-Gates grün:
`ruff`/`ruff format`/`mypy app/`, Pure-Unit (`pytest`). Alembic-Roundtrip `0027`
und der Live-Agent-Smoke (echtes Such-Backend + LLM) stehen beim User an.

### Added

- **Dependencies** `pydantic-ai-slim[openai]` + `trafilatura` (nur vom
  `research-worker` importiert; geteiltes Image, in app/llm-worker inert).
- **`fathometer-research-worker`** — neuer optionaler Compose-Service (gleiches
  Image, `python -m app.workers.research_worker`, kein Inbound-Port); pollt
  ausschließlich `upstream_check_results`, fasst `llm_jobs` nicht an.
- **`app/services/upstream_research.py`** — getypte `pydantic-ai`-Agenten-Schleife
  mit eigenen Tools (`web_search` über `httpx` für SearXNG/Tavily/Firecrawl/Serper,
  `fetch_url` über `trafilatura` mit Raw-Datei-Fallback), getyptes `Verdict`,
  deterministischer Konsistenz-Pass, Budget→Finalize-Fallback. **Nie** Auto-Band-Flip.
- **`app/services/upstream_seed.py`** — Seed-Extraktion aus dem Finding
  (Cache-Key = Binary-Basename + installed-component-version; PURL ist die
  Komponente, nicht das Artefakt).
- **`app/services/upstream_check_enqueue.py`** — idempotenter Enqueue (Cache-Hit/
  In-Flight-Dedup, TTL).
- **Migration `0027`** — `upstream_check_results` (Queue+Request+Cache in einer
  Tabelle, `UNIQUE(artifact_module, installed_version)` + `status`) + 7
  `Setting`-Spalten (`upstream_check_enabled` default-off, Such-Backend-Block mit
  Fernet-Secrets, `llm_research_model`) + Research-Worker-Heartbeat.
- **Docs** `docs/operations.md` (neu) — Outbound/Allowlist/Air-Gap; ARCHITECTURE
  §5/§11/§17 + CLAUDE.md §17 opt-in-Ausnahme zu ADR-0050.

## [Unreleased] — Block AH (ADR-0062): Host-Update-Flag — präzise statt pauschal

Verfeinert ADR-0061: ein lang-pkgs-Finding wird nur dann als `upstream`
geführt, wenn der Host es **nicht** per Paketmanager patchen kann. Der
Host-Agent löst pro Binary das besitzende OS-Paket auf und meldet read-only,
ob dessen Repo ein Update hat — ist dem so, wird das Finding von `upstream`
nach `patch` promotet (z. B. wenn Tailscale ein neues, mit gepatchtem Go
gebautes `tailscale`-rpm liefert). Kein State-Change am Host, kein Outbound,
kein LLM. Quality-Gates grün: `ruff`/`ruff format`/`mypy app/`, Pure-Unit
(`pytest`), `shellcheck`. Alembic-Roundtrip `0026`, der `.bats`-Resolver-Lauf
und der Live-Host-Smoke (echter Paketmanager) stehen beim User an.

### Added

- **`host_update_available` (+ `owning_package`/`available_version`)** als
  nullable Finding-Spalten (Migration `0026`, `down_revision=0025`, reiner
  nullable-Add ohne Eval-Rebuild — `NULL` = AG-Verhalten `upstream`).
- **Agent-Resolver** (`collect_host_updates` in `agent/lib_host_state.sh`,
  Agent v0.7.0 / Lib v0.4.0): `rpm -qf`/`dpkg -S` + ein read-only
  `dnf|yum check-update` / `apt-get -s upgrade`, gebündelt pro Paket,
  Timeout-gekapselt; neuer Envelope-Block `host_updates` (Join über
  `target_path`). `MIN_AGENT_VERSION` bleibt `0.1.0` (alte Agenten → `NULL`).
- **„host update ready: `<pkg> <version>`"-Hinweis** auf der Patch-Card
  (Workflow-Tabelle + Group-Card) für ein aus lang-pkgs promotetes Finding.
- **`.bats`-Resolver-Tests** (`tests/agent/test_host_update_resolver.bats`,
  On-Demand-Suite) für die rpm/dpkg/dnf/apt-Output-Parser.

### Changed

- **`fix_lane_for(finding_class, has_fix, host_update_available=None)`** +
  SQL-Spiegel um den Flag erweitert: `lang-pkgs/other & has_fix &
  host_update_available IS TRUE → patch`, sonst `upstream` (NULL-sicher).
- **Envelope** (`scan_envelope.py`): neues `HostUpdateEntry`-Modell +
  optionales `Envelope.host_updates` (`MAX_HOST_UPDATES`=4096, `extra="ignore"`);
  Ingest joint es pro Finding über `target_path`.
- **Agent v0.7.0** (`CURRENT_AGENT_VERSION`), Lib `0.4.0`.

## [Unreleased] — Block AG (ADR-0061): Fix-Ownership — `upstream`-Lane für lang-pkgs-Fixes

lang-pkgs-Fixes (gobinary/jar/node — z. B. die in `tailscaled` einkompilierte
Go-stdlib, CVE-2026-42504) werden nicht mehr fälschlich als host-applizierbarer
Patch behauptet. Eine dritte Fix-Lane **`upstream`** trennt **Fakt** (ein Fix
existiert) von **Applizierbarkeit** (der Operator kann ihn per Paketmanager
einspielen) — deterministisch aus `finding_class`, kein LLM-Urteil, kein
Agent-/Outbound-Change. Quality-Gates grün: `ruff`/`ruff format`/`mypy app/`,
Pure-Unit (`pytest`). Alembic-Roundtrip `0025` und Operator-Browser-Smoke
stehen beim User an.

### Changed

- **Fix-Lane-Partition dreiteilig** (ADR-0061): `fix_lane ∈ {patch, upstream,
  mitigate}`. Neue Single-Source `risk_engine.fix_lane_for(finding_class,
  has_fix)` + spiegelnder SQL-`case` (`fix_lane_sql_case`) lösen die bisher
  verstreuten `fixed_version`/`has_fix`-Ableitungen ab (`pass2_input_selection`,
  `finding_group_inheritance`, `server_detail`). `has_fix & os-pkgs → patch`,
  `has_fix & lang-pkgs/other → upstream`, `not has_fix → mitigate`.
- **`action_type`-Ableitung** um die `upstream`-Zeilen ergänzt (escalate →
  `mitigate`, monitor → `watch`, noise → `none`); kein eigener `action_type`,
  die Lane trägt die Upstream-Semantik. **`act` ist jetzt auch in der
  `upstream`-Lane verboten** (Validator + Lane-Prompt).
- **Pass-2-Cache invalidiert** (`PASS2_PROMPT_VERSION` 3 → 4) wegen der neuen
  Lane-Prompt-Semantik.
- **Server-Detail-Loader** bucketet Lanes jetzt über den abgeleiteten
  `fix_lane`-Ausdruck (nicht mehr nur `has_fix`) — eine Group kann
  os-pkgs-Patch- **und** lang-pkgs-Upstream-Findings tragen (beide `has_fix`).

### Added

- **Migration `0025_upstream_fix_lane`** (`down_revision=0024`): CHECK
  `ck_app_group_evals_fix_lane` → `IN ('patch','mitigate','upstream')`,
  Drop-&-Rebuild der Eval-Rows (organischer Refill beim nächsten Scan).
- **Card „ESCALATE · Upstream fix — mitigate until rebuild"** in den
  Operator-Workflows; die zwei escalate-Cards mit abgeleitetem
  `action_type=mitigate` werden über `fix_lane` diskriminiert. Drei-Wege-Lane-
  Label (patch / upstream / no patch) in Workflow-Tabelle und Group-Card; die
  Fix-Version bleibt sichtbar.

## [Unreleased] — Block AF (ADR-0057): Getrennte Modelle für Reviewer und Chat

Das bisher geteilte `Setting.llm_model` wird in **zwei** Felder getrennt:
**`llm_reviewer_model`** (Rename, nullable, Default `openai/gpt-oss-120b`,
Konsument Risk-Reviewer/Worker Pass 1 + 2) und **`llm_chat_model`** (neu,
`NOT NULL` mit `server_default` `deepseek-ai/DeepSeek-V4-Flash`, Konsument
Per-Group-Chat). **Ein geteilter Provider, zwei Modelle** —
`llm_base_url`/`llm_api_key_encrypted` bleiben gemeinsam, kein Multi-Provider.
Quality-Gates grün: `ruff`/`ruff format`/`mypy app/`, Pure-Unit (`pytest`,
+62 Tests). Alembic-Roundtrip `0024`, Live-Test-Connection-Doppelprobe und
Operator-Browser-Smoke stehen beim User an.

### Changed

- **`settings.llm_model` → `llm_reviewer_model`** (Rename, Migration `0024`,
  `down_revision=0023_block_ae_group_chat`): der Risk-Reviewer (`llm_worker.py`,
  Fingerprint-Cache) liest nun `llm_reviewer_model`; `settings.py::active_model`
  (Reviewer-Screen) ebenso.
- **`build_client_from_settings(..., model_override=None)`** — neuer optionaler
  Parameter; ohne Override greift das Reviewer-Modell, der Chat übergibt
  `llm_chat_model`. `LlmNotConfiguredError`-Check auf das effektiv genutzte
  Modell.
- **Per-Group-Chat nutzt `llm_chat_model`** (`group_chat.py`): SSE-Stream +
  `GroupChatConversation.model`-Snapshot frieren das Chat-Modell ein; laufende
  Konversationen bleiben an ihr gesnapshottetes Modell gebunden.
- **Provider-Tab zeigt zwei Modell-Felder** („Reviewer model" / „Chat model"):
  Preset füllt beide, `llm.provider_changed` feuert bei base_url-, Reviewer-
  oder Chat-Modell-Änderung (Audit-Metadata trägt old/new für beide).
- **Test-Connection probt beide Modelle** (`POST /settings/llm/test-connection`):
  zwei 1-Token-Proben gegen den geteilten Provider, neue 2-Teil-Response
  `{reviewer:{success,latency_ms,model,error}, chat:{…}}`; `error` ist ein
  gemappter Code (`model_not_found`/`provider_error`/`timeout`/`auth_error`/…) —
  kein API-Key, kein roher Exception-Text in der Response.

### Added

- **`settings.llm_chat_model`** (`String(128)`, `NOT NULL`, `server_default`
  `deepseek-ai/DeepSeek-V4-Flash`): dediziertes Chat-Modell. Der forced Backfill
  setzt es für **alle** Zeilen — bei Providern, die das Modell nicht hosten,
  schlägt der Chat mit `404` fehl (bewusst akzeptiert, ADR-0057 §Konsequenzen;
  die Test-Connection-Doppelprobe deckt es auf).

## [Unreleased] — Fix (ADR-0056): Risk-Reviewer-Tages-Cap aus der DB statt Env

### Fixed

- **Risk-Reviewer-Token-Cap kommt jetzt aus `Setting.llm_daily_token_cap`**
  (Operator-steuerbar via Provider-Tab) statt aus dem Env
  `FM_LLM_TOKEN_BUDGET_DAILY` (ADR-0056, korrigiert eine Block-P-Drift gegen
  ADR-0014). Vorher ignorierte der Worker den im UI gesetzten Cap komplett und
  erzwang das Pod-lokale Env — Web-Pod (Default 2 M) und Worker-Pod
  (`FM_LLM_TOKEN_BUDGET_DAILY=1 M`) sahen unterschiedliche Limits, der „Budget &
  cache"-Screen zeigte einen anderen Wert als der Worker erzwang
  (`budget_pct=101`, `job_pickup_paused` trotz 64 wartender Jobs). `budget_check`
  und der `budget_pct`-Status-Snapshot lesen nun `llm_daily_token_cap`; der
  „Budget & cache"-Screen zeigt denselben DB-Wert. Worker übernimmt Änderungen
  binnen ≤ 60 s ohne Pod-Restart. `FM_LLM_TOKEN_BUDGET_DAILY` ist nur noch der
  Install-Seed für frische Rows (`ensure_settings_row`), kein Laufzeit-Cap mehr.

## [Unreleased] — Block AE (ADR-0055): Per-Group AI-Chat

Wieder-Einführung eines LLM-Chats — anders als der mit ADR-0050 entfernte
server-weite Chat: **fokussiert pro `(Server, Application-Group)`**, ausgelöst
über einen „Help"-Button pro Group-Row in den Operator-Workflows. Kontext ist
ein **Snapshot bei Chat-Start** (Host-Fingerprint, Services, Listener inkl.
Exposure und alle OPEN-Findings der Group eingefroren im persistierten
System-Prompt), Antworten streamen per SSE, **kein Token-Cap** (der Cap bleibt
allein dem Risk-Reviewer). Der *server-weite* Chat bleibt verworfen. Quality-Gates
grün: `ruff`/`mypy app/`, Pure-Unit (`pytest`, +69 Tests inkl.
`tests/adversarial/`-Prompt-Injection + XSS). Alembic-Roundtrip `0023` +
db_integration (UNIQUE/CASCADE) + SSE-E2E stehen beim User an.

### Added

- **Per-Group-AI-Chat** (`app/api/group_chat.py`, ADR-0055): vier Browser-Routen
  unter `/servers/<id>/groups/<gid>/chat[…]` — `GET …/chat` (Sub-View-Fragment
  bzw. Vollseite, legt nichts an), `POST …/chat/messages` (User-Message anhängen;
  **Lazy-Create + Snapshot** beim ersten Mal), `GET …/chat/stream` (**SSE**-Token-
  Stream über `LlmClient.stream_chat`, Assistant-Message nach Stream-Ende in
  eigener DB-Session persistiert), `POST …/chat/new` (Konversation
  **CASCADE-löschen**, Empty-State zurück). Alle `@login_required`, CSRF auf POST,
  `flask-limiter` (Stream 60/h, Messages 30/min, Show 120/min), gemeinsamer
  404-Guard (aktiver Server **und** Group mit OPEN-Findings hier —
  `group_findings_fragment`-Semantik gegen Cross-Server/Cross-Group-IDOR). **Kein**
  `llm_budget`-Aufruf, **kein** Function-Calling (ADR-0002), Modell nur aus
  `Setting.llm_model`.
- **Genau eine Konversation pro `(Server, Group)`**, DB-persistiert über
  Reloads/Sessions; „New Chat" löscht sie unwiderruflich (CASCADE auf die
  Messages), die nächste Nachricht legt sie frisch an. Kein Archiv, keine
  Mehrfach-Historie.
- **Help-Button pro Group-Row** (`sd-ask-btn`) in den Operator-Workflows der
  Server-Detail-Seite; öffnet den Chat-Sub-View in derselben Detail-Pane
  (analog Settings-Sub-View). `CHAT_SUGGESTIONS`-Chips im Empty-State
  (single-source-Konstante für Template + Test, Start-Suggestion
  „Explain attack vector").
- **Schema (Migration `0023`, additiv):** Tabellen `group_chat_conversations`
  (`UNIQUE(server_id, application_group_id)`, `model`, `findings_snapshot_at`,
  beide FKs `ON DELETE CASCADE`; `application_group_id` ist `BigInteger`) und
  `group_chat_messages` (Lookup-Index `(conversation_id, created_at, id)`, optionale
  `prompt_tokens`/`completion_tokens`), neuer Postgres-Enum `chat_message_role`
  (`system`/`user`/`assistant`). **Kein Findings-Bridge-Table** — der Snapshot
  lebt im System-Prompt (erste Message, `role=system`).
- **Prompt-Builder** `app/services/group_chat_prompt.py`
  (`build_group_system_prompt`): group-scoped, englisch (ADR-0045), mit
  Anti-Injection-Markern `<<TRIVY_DATA_START>>`/`<<TRIVY_DATA_END>>`,
  portierter `_safe`-Display-Sanitization (Control-Chars/NUL raus, Längen-Cap)
  und **Marker-Neutralisierung** (eingebettete Marker in manipulierten
  Scanner-Strings werden entschärft, damit untrusted Daten den Datenblock nicht
  vorzeitig schließen können).

## [Unreleased] — TICKET-015: Trivy-Bump 0.71.0 + Trivy-Auto-Update im Agent

Agent hält die fathometer-managed Trivy-Binary künftig selbst auf der
empfohlenen Version, statt nur eine „outdated"-Pill anzuzeigen. Quality-Gates
grün: `ruff`/`mypy app/`, `shellcheck`, Pure-Unit (`pytest`,
`tests/agent/test_auto_update.sh`).

### Changed

- **`RECOMMENDED_TRIVY_VERSION` 0.70.0 → 0.71.0**, **`CURRENT_AGENT_VERSION`
  0.5.0 → 0.6.0** (`app/config.py`, gemeinsam mit `AGENT_VERSION="0.6.0"` im
  Skript — ADR-0021-Konvention). **`MIN_TRIVY_VERSION` bleibt bewusst 0.70.0**:
  0.71.0 ist ein Minor-Release ohne Schema-Breaking-Changes, ein MIN-Bump würde
  0.70.0-Hosts unnötig hart als veraltet markieren.

### Added

- **`auto_update_trivy` im wiederkehrenden Agent-Lauf** (`fathometer-agent.sh`):
  läuft **nach** dem Agent-Selbst-Update und **vor** dem Scan. Hebt die
  managed Binary auf `recommended_trivy_version`, wenn die installierte Version
  kleiner ist. Spiegelt die vetted Installer-Logik (`download_pinned_trivy`):
  Tarball + `trivy_<v>_checksums.txt`, **Pflicht-SHA256-Verifikation**, atomarer
  `install` mit `.bak`-Backup, Post-Replace-Re-Verify und Rollback bei
  Fehlschlag. **Nur** `/opt/fathometer/bin/trivy` wird angefasst — ein
  System-Trivy (apt/`usr/bin`) nie. **Fail-soft**: jeder Fehler hält die
  vorhandene Version, der Scan scheitert nie an einem Update. Opt-out /
  Air-Gap via **`FM_TRIVY_AUTO_UPDATE=0`** (Default an); `tar`/`sha256sum` sind
  Soft-Deps des Update-Pfads (fehlen sie → Update-Skip, kein Abbruch).

## [Unreleased] — Server-Action „Delete findings"

Neue Operator-Action im Settings-Server-Dropdown (`/settings/servers`) neben
Rotate-key/Retire/Revoke, um einen defekten Scan-Stand durch Neu-Einspielen zu
reparieren. Quality-Gates grün: `ruff`/`mypy app/`.

### Added

- **`POST /servers/{id}/delete-findings`:** löscht **alle** Findings eines
  Servers (jeden Status) unwiderruflich. Der Server-Eintrag und die Audit-Spur
  bleiben erhalten, `finding_notes` fallen per FK-CASCADE mit; der nächste
  Scan-Ingest hängt frische Findings wieder an dieselbe `server_id`. Bewusst
  kein Soft-Delete und kein Per-Finding-Audit — nur ein
  `server.findings_deleted`-Event mit `deleted_count` in `metadata`. Im
  Dropdown als Danger-Item mit `confirm()`-Dialog; CSRF wie bei Retire/Revoke.
  Neue Audit-Action `server.findings_deleted` in `KNOWN_ACTIONS`
  (Audit-View-Filter).

## [Unreleased] — TICKET-010 (ADR-0052): Operator-Sichten zeigen Jetzt-Zustand

Drei zusammenhängende Konsistenz-Bugs (Befund ftp-server / CVE-2026-31431):
fälschlich für immer RESOLVED bleibende Wiedergänger-Findings, Pass-2-Eval über
geschlossene Findings (Dauer-Re-Enqueue-Schleife) und Server-Detail-Cards die
geschlossene CVEs als „Worst Finding" zeigten. Kein Schema, keine Migration,
kein neuer Endpoint. Quality-Gates grün: `ruff`/`mypy app/`, Default-`pytest`
2329 passed. db_integration-Läufe + Operator-Browser-Smoke stehen beim User an.

### Fixed

- **Reopen-on-Redetect (Bug A):** der Scan-Ingest reopened jetzt vor dem Upsert
  alle RESOLVED-Findings deren `(identifier_key, package_name)` im aktuellen
  Scan wieder auftaucht (`status='open'`, `resolved_at=NULL`). ACK bleibt ACK —
  Operator-Entscheid schlägt Scanner. Neues Feld `findings_reopened` in
  `ScanIngestResult`/`ScanProcessingResult`, `scan.ingested`-Audit-Metadata und
  Worker-JSONB. Bestands-Heal automatisch beim nächsten Scan pro Server.
- **Pass-2 bewertet nur OPEN (Bug B):** beide Finding-Loads in `_do_pass2`
  filtern auf `status='open'` — identische Fingerprint-Domäne wie
  `pass2_enqueue`. Beendet die Dauer-Re-Enqueue-Schleife bei Groups mit
  non-open Findings; geschlossene Findings sind nicht mehr als
  `worst_finding_id` wählbar. Race-Guard: werden alle Findings zwischen
  Job-Pickup und LLM-Call geschlossen, endet der Job als `skipped` ohne Call.
  Einmaliger Cache-Miss-Burst pro betroffener (group, server)-Kombination.
- **Server-Detail Live-Worst-Finding (Bug C):** der Group-Loader ermittelt das
  Worst-Finding pro Group live via `DISTINCT ON` über offene Findings
  (§15-Triage-Order) statt den Eval-Snapshot aufzulösen; die Eval-Row liefert
  nur noch Band/Reason/Action-Type. Bei Drift zwischen Snapshot- und Live-Worst
  rendern Workflow-Card und Group-Card den Hint „re-evaluation pending".

### Added

- **Sofort-Re-Eval bei Triage-Aktionen:** Acknowledge/Reopen/Group-Ack/Bulk-Ack
  (UI + API, alle Flavors) triggern nach erfolgreichem Status-Write
  `enqueue_pass2_for_server(trigger="triage_action")` — idempotent und
  fingerprint-gated, ein Aufruf pro betroffenem Server, kein Aufruf wenn nichts
  geändert wurde. Vorher passierte das Re-Eval erst beim nächsten Scan
  (24-h-Lücke).

## [Unreleased] — ADR-0050: "Request AI Assessment"-Chat-Feature entfernt

Das server-weite interaktive LLM-Chat-Assessment (Block G) wird ersatzlos
entfernt — UI, Routes, Prompts, Chat-Services, JS, DB-Tabellen, Tests. Die
geteilte LLM-Provider-Config und der asynchrone Risk-Reviewer (Block P) bleiben
unverändert. Quality-Gates grün: `ruff`/`ruff format`/`mypy app/`, Default-
`pytest` 2233 passed / 0 failed. **`ARCHITECTURE.md` wird separat (paralleler
Rewrite) nachgezogen.**

### Removed

- **"Request AI assessment"-Button** auf der Server-Detail-Seite (`servers/detail.html`)
  + `sd-ai-button`-CSS.
- **Chat-Blueprint** `app/api/llm_chat.py` (`POST /servers/<id>/chat`,
  `POST /chat/<id>/messages`, `GET /chat/<id>/stream` (SSE), `GET /chat/<id>`,
  `POST /chat/<id>/archive`) inkl. Registration in `app/__init__.py`.
- **Chat-Services:** `llm_prompt.py` (Singular — Chat-System-Prompt),
  `llm_update_hook.py` (`notify_conversations_for_scan` + Aufruf in
  `scan_processing.py`), `llm_token_tracker.py` (Chat-80%/100%-Cap-Banner).
- **Templates/JS:** `app/templates/chat/`, `app/static/js/llm_chat.js`.
- **DB:** Models `LlmConversation`/`LlmMessage`/`LlmConversationFinding` + Enums
  `LlmConversationStatus`/`LlmMessageRole`; **Migration `0017_remove_llm_chat`**
  droppt die drei Tabellen + zwei Postgres-Enums (`downgrade()` rekonstruiert
  sie leer).
- **Provider-Switch-Conversation-Archivierung** (`_archive_active_conversations`
  + Confirm-Modal/Flash) aus `llm_settings.py`/`llm_provider.html`/
  `llm_settings.js`. Context-Processor `_inject_llm_configured`. Audit-Action
  `llm.queried` aus `KNOWN_ACTIONS`.
- **Tests:** `test_llm_chat_db.py`, `test_llm_provider_switch_db.py`,
  `test_llm_update_hook.py`, `test_llm_token_tracker.py`, `test_llm_prompt.py`,
  `tests/adversarial/test_prompt_injection.py` (testete den Chat-Prompt).

### Kept (geteilt mit Risk-Reviewer)

- `llm_client.py`, `llm_budget.py`, der gesamte Risk-Reviewer (Block P), die
  Provider-Config auf `settings` (`llm_base_url`/`llm_model`/
  `llm_api_key_encrypted`/`llm_daily_token_cap`/`llm_provider_name`), der
  `/settings/llm`-Provider-Tab und das Audit-Event `llm.provider_changed`
  (ohne `archived_conversations`-Metadata).

## [Unreleased] — ADR-0047 (Block AD): Settings-Redesign (horizontale Tab-Nav + `s-*`-Schicht)

Zielversion **v0.19.0**. Reines Restyling — keine Routen-/Schema-/Render-Helper-
Änderung, keine Migration, kein neuer Endpoint. Phasen 0→E mit je einem Commit
(Phase C in C1/C2 geteilt). `app/views/_settings_shell.py`, `settings.py` und
`llm_settings.py` unangetastet.

### Changed

- **Settings-Sekundär-Navigation: vertikale 224px-Nav → horizontale Sticky-Tab-
  Leiste** (`.settings-tabs`, ADR-0047). Sieben Tabs in Mockup-Reihenfolge
  (Servers, Tags, Groups, LLM Provider, LLM Reviewer, Master-Key, About).
  HTMX-Vertrag 1:1 erhalten (`hx-get`/`hx-target="#settings-content"`/
  `hx-swap="innerHTML"`/`hx-push-url`/`hx-headers` + `href`-Fallback); aktiver
  Tab via `settings-tabs__item--active` + `aria-selected`, client-seitig
  nachgezogen durch `app/static/js/settings_tabs.js` (die Tab-Leiste liegt
  außerhalb des HTMX-Swap-Targets).
- **Alle sieben Settings-Subseiten auf die `s-*`-Komponentenschicht** portiert
  (`frontend/src/css/components/settings.css`, 1:1-Port aus `docs/design/settings.css`,
  Token-only). DaisyUI/Tailwind raus aus den Settings-Surfaces:
  - `servers.html` → `s-table`/`s-servers__*`/`s-pill`/`s-overflow` (Aktionsmenü
    Alpine); Revoke/Retire-Forms + CSRF + Confirm unverändert.
  - `tags.html` → `s-table`/`s-tags__*`/`s-empty`; Color-Picker als Alpine-Palette-
    Popover + nativer Picker; Rename/Color/Delete-Forms unverändert.
  - `groups.html` → `s-table`/`s-groups__*` inkl. Reorder-Pfeile; Move/Rename/
    Delete-Forms unverändert.
  - `llm_provider.html` → `s-card`/`s-fields-grid`/`s-actions`/`s-feeds`;
    `llmProviderForm`-Alpine-API unverändert, Confirm-Modal als token-Overlay.
  - `llm_reviewer.html` → `s-statusbar`/`s-slider-row`/`s-kpis`/`s-twoup`/`s-kv`/
    `s-subtabs`/`s-table`; drei Master-Key-Modals als token-Overlays.
  - `llm_debug_log.html` → `s-log`/`s-subtabs`, expandierbare Request/Response/
    Reasoning-Einträge.
  - `master_key.html` → `s-key-status`/`s-warning`/`s-key-reveal`; Rotate-Confirm
    als nativer `confirm()`-Dialog.
  - `about.html` → `s-about-grid`.
- **Profile-Dropdown** markiert „Settings" als aktiv (`profile-menu__item--active`)
  wenn der Pfad unter `/settings` liegt; der entsprechende CSS-Block wurde aus
  dem Mockup-CSS nach `profile-menu.css` (Topbar-Scope) verschoben.

#### Folge-Fixes (nach erstem Sichttest)

- **External Feeds (EPSS/CISA-KEV)** vom LLM-Provider- auf den **About**-Tab
  verschoben (read-only; `about_view` reicht jetzt `feed_statuses` durch).
- **Modals** (Provider-Switch + die drei Reviewer-Modals) per `x-teleport="body"`
  an `<body>` gehängt → viewport-zentriert statt oben-links (`.settings` ist
  wegen `container-type:inline-size` sonst Containing-Block für `position:fixed`).
- **Master-Key-Tab-Badge** („new") aus der Nav entfernt.

### Removed

- **`frontend/src/css/components/settings-manage.css`** (ADR-0040-`sd-manage-*`-
  Schicht) gelöscht — durch `s-table`/`s-tags__*`/`s-groups__*` ersetzt;
  `@import` aus `app.css` entfernt.
- `tests/templates/test_settings_legacy_still_renders.py` (Dual-Stack-DaisyUI-
  Smoke) gelöscht — durch `test_settings_nav.py` + `test_settings_subpages_smoke.py`
  ersetzt.

### Notes

- **Mockup-Features ohne Backend weggelassen** (kein Halb-Bau): Debug-Log-Filter/
  Level/Pause/Copy/Live-Stream (TD-017), Tag-Usage-Zählung in der Tags-Ansicht
  (TD-016, View-Vertrag liefert keine Zählung). Eyebrow-Nummerierung „01 / 07"
  bewusst weggelassen (User-Entscheidung).

## [Unreleased] — ADR-0046 (Block AC): Persistenter Sidebar-Group-Aufklapp-Zustand

Zielversion **v0.18.0**. Kein Schema, kein neuer Endpoint, keine Migration,
kein localStorage — Cookie + Server-Render. Drei Phasen (A Server-Read+Render,
B Client-Write, C Doku).

### Added

- **Aufgeklappte Sidebar-Gruppen bleiben aufgeklappt** über den 60-s-Polling-Swap,
  Reload und Browser-Sessions hinweg (ADR-0046). Mechanik:
  - Cookie `sidebar_open_groups` (kommaseparierte Group-IDs, `Max-Age` 1 Jahr,
    `Path=/`, `SameSite=Lax`, `Secure` über HTTPS analog zur Session-Cookie-Config).
  - `app/static/js/sidebar.js`: delegierter `toggle`-Listener in der Capture-Phase
    (das Event bubbelt nicht); schreibt das Cookie bei jedem Toggle komplett neu
    aus dem DOM-Ist-Zustand (kein inkrementelles Add/Remove) und zieht
    `aria-expanded` auf dem `<summary>` nach.
  - `app/views/_sidebar_context.py`: defensiver Cookie-Parser (`set[int]`, nur
    Ints, Nicht-Parsebares verworfen, 512-Zeichen-/64-ID-Cap, niemals 500) und
    `sidebar_open_group_ids` im Context **beider** Render-Pfade (Context-Processor
    + Polling-Endpoint laufen durch `build_sidebar_context()` — single-source).
  - `app/templates/sidebar/_group_section.html`: `open` + `aria-expanded`
    conditional aus `sidebar_open_group_ids`; Undefined-Fallback rendert collapsed.

### Unchanged (bewusst)

- Default ohne Cookie bleibt **alles collapsed** (ADR-0034 §Sidebar-Verhalten) —
  bestehende Sidebar-Tests sind der Regressions-Anker und unverändert grün.
- Kein Auto-Expand bei aktiver Sidebar-Suche (Out of Scope, Re-Open-Trigger
  in ADR-0046). Keine geräteübergreifende Persistenz (Cookie ist pro Browser).

## [Unreleased] — ADR-0045 (Block AB): English-only UI

Zielversion **v0.17.0**. Reiner String-Touch — kein Markup-, Logik-, CSS- oder
Schema-Umbau, keine Migration. Sechs Phasen (A–F), je ein Commit.

### Changed

- **Gesamte operator-sichtbare UI ist jetzt ausschliesslich englisch**
  (ADR-0045, loest ADR-0033 §8 Phase-2-Strategie ab). Betroffen:
  - Jinja-Templates (`app/templates/**` — Settings, Server-Detail, Findings,
    Audit, Setup-Wizard, Chat, Dashboard-Restdeutsch, Partials, Empty-States,
    Modals, `_macros.html`).
  - Flash-Messages und View-lokale Fehlertexte in allen `app/views/*.py`
    (inkl. `abort(...)`-Descriptions und Workflow-Card-Labels in
    `server_detail.py`) gemaess verbindlichem Glossar.
  - WTForms-Validator-Messages und Feld-Labels (`app/forms.py`).
  - JS-Strings (`app/static/js/*.js`): Toasts, Confirm-Texte, Error-States,
    der client-seitige Relative-Time-Mirror in `stale.js`.
  - Relative-Time-Filter `relative_time` in `app/__init__.py`
    (`vor 5min` -> `5m ago`, `noch nie` -> `never`).
  - Chat-LLM-System-Prompt (`app/services/llm_prompt.py`): Antworten jetzt auf
    Englisch; Marker-Konstanten `TRIVY_DATA_START`/`TRIVY_DATA_END`,
    Daten-Block-Aufbau und Finding-Line-Keys byte-identisch (Prompt-Injection-
    Defense unveraendert). Pass-2-Prompts (`llm_prompts.py`) unberuehrt.
  - Chat-JSON-Error-`message`-Werte in `app/api/llm_chat.py` (maschinelle
    `error`-Codes unveraendert).

### Added

- **Sprach-Sweep-Test** `tests/test_ui_language.py` (Pure-Unit, Teil des
  Default-`pytest`): scannt Templates, ausgelieferte JS und String-Literale in
  `app/views/*.py` + `app/forms.py` (Kommentare/Docstrings ausgenommen) gegen
  eine deutsche Marker-Wortliste (Umlaute + `ae/oe/ue`-Transliterationen +
  Wortgrenzen-Marker) und schlaegt bei jedem neuen deutschen UI-String fehl.
  Explizite `_ALLOWLIST` als Ausnahme-Mechanismus.

### Notes

- **Doc-Sprache, Code-Kommentare, Docstrings, ADRs bleiben deutsch**
  (ADR-0045 §Scope). Keine i18n-Infrastruktur, kein Daten-Rollout
  persistierter deutscher Strings (Audit-Metadata/Notes-Bestand).

## [Unreleased] — ADR-0044 (TICKET-009): Per-Band Bulk-Acknowledge

### Server-Detail

- Jedes Risk-Band (ausser `pending`) hat ein "Acknowledge all"-Hover-Control
  am Band-Header (ADR-0044). Klick schaltet inline in eine Bestaetigung
  ("Acknowledge N findings?  Confirm  Cancel") direkt im Band-Header — kein
  Modal, keine Notiz-Eingabe (Design `docs/design/ServerDetail.jsx`).
- Bulk-Ack wirkt jetzt auf **ALLE** offenen Findings des Bands auf diesem
  Server — der Server resolved den Scope selbst (`server_scope`-Flavor C, kein
  ID-Transport durch den Client). Das 50er-Limit des Noise-Workflows entfaellt.
- `pending`/`unknown` sind server-seitig (`risk_band`-Whitelist, 422) vom
  Bulk-Ack ausgenommen — ein Urteil ohne Pass-2-Bewertung bleibt verboten.

### Removed

- "Acknowledge all noise on this host"-Toolbar-Link, das Noise-Fragment
  (`GET /<id>/fragments/noise`), `app/static/js/bulk_ack_noise.js`, das
  Noise-Modal und das Schema-Feld `risk_band_filter` entfallen ersatzlos
  (abgeloest durch ADR-0044, vorher ADR-0022 §Bulk-Ack-Noise / ADR-0039 §2).

## [Unreleased] — ADR-0041 (Block AA): Finding-Detail Inline, Flat-Switch entfernt

Zielversion **v0.16.0**.

### Added

- **Inline-Finding-Body** (`app/templates/_partials/finding_inline_body.html`):
  Klick auf eine Finding-Row klappt jetzt in **jeder** Findings-Liste
  (Server-Detail Group-Drilldown, Triage-Queue, `/findings`-Bucket-View,
  Pending-Sammler) einen einheitlichen Body auf — KI-Bewertung
  (`risk_band_reason`) + „Abhaken …"/„Re-open …"-Button, volle CVE-Beschreibung,
  Primary-URL, Reference-Liste und Notes-Thread. Single-Source-Partial
  (kein Drift zwischen Initial-Render und HTMX-Fragment-Reload).
- **`findings.primary_url`** (Migration `0016_block_aa_add_primary_url`,
  `VARCHAR(2048) NULL`): die Trivy-`PrimaryURL` wird jetzt persistiert (war
  im Envelope-Schema bereits validiert, aber nie geschrieben) und im Inline-Body
  verlinkt. Idempotent — Bestands-Findings bleiben `NULL` bis zum nächsten
  Re-Ingest, kein Backfill.

### Changed

- Paginierte Listen-Endpoints (`triage_band_fragment`, `bucket_fragment`,
  `pending_fragment`, Group-/Pending-Lazy-Fragmente) hydrieren wieder volle
  ORM-`Finding`-Objekte mit `selectinload(Finding.notes)` (ersetzt die
  ADR-0039-Spalten-Projektion — bei Paginations-Größe 10/20 vernachlässigbar).

### Removed

- **Flat-Switch `?flat=1`** und die flache Findings-Tabelle
  (`_view_list.html`), das **Detail-Modal** (`findings/_detail_modal.html`)
  und die `<tr>`-Pending-Tabelle (`_partials/pending_findings_table.html`).
  `_is_flat_mode` + der Flat-Branch in `_render_findings_section` entfallen;
  `_findings_section.html` rendert unkonditional die Group-Card-Ansicht.

### Hinweis / bewusste Regression (Re-Open-Trigger, ADR-0041)

- **URL-Filter** (`status`/`kev_only`/`q`/`class`/…) narrowen die
  Server-Detail-Ansicht **nicht mehr** — sie waren ein Flat-Pfad-only-Feature
  ohne Filter-Bar-UI. Group-View-Queries sind filter-unaware (Counts-Header
  bleibt filter-aware). Dokumentiert in ADR-0041 §Re-Open-Trigger.
- Die **Ursachen-Sub-Zeile** (Block N: `target_path`/`vendor_ids`/
  `package_purl`) entfällt als UI-Surface (Daten bleiben persistiert).

## [Unreleased] — ADR-0042: Agent-Fire-and-Forget, Job-Status-Endpoint entfernt

### Changed

- `secscan-agent.sh`: Der Agent beendet nach der `202`-Annahme sofort mit Exit 0
  (Fire-and-Forget). Polling-Loop entfernt; die Meldung „Scan queued …, waiting
  for processing…" ist weg, stattdessen `Scan accepted (job_id=…)`.
- `POST /api/scans` 202-Body schrumpft von `{job_id, status, status_url}` auf
  `{job_id, status}` — `status_url` zeigte auf den entfernten Endpoint.

### Removed

- **Status-Endpoint `GET /api/scans/jobs/<job_id>`** (`app/api/scans.py`):
  Route `scan_job_status`, Serializer `_serialize_job_status`, Konstante
  `_MAX_ERROR_LEN`. Kein Konsument mehr nach dem Agent-Fire-and-Forget.
- Agent-Exit-Codes 4 (`failed`) und 5 (Polling-Timeout) sowie
  `SECSCAN_POLL_MAX_SEC`-Override.
- `tests/api/test_scan_status_endpoint_unit.py` (testete nur den entfernten
  Serializer); `status_url`-Assert in `test_scans_async_edge.py` und
  Status-Endpoint-Abschnitt in `test_scan_ingest_e2e_flow.py`.

### Notes

- Async-Ingest-Kern (Queue-Tabelle, Edge-Fast-Path, Worker-Sub-Tick,
  Idempotency, Payload-Transit) aus ADR-0026 bleibt unverändert. Scan-Ergebnis
  und -Fehler sieht der Operator weiterhin im Dashboard (ADR-0019) und über die
  Audit-Events `scan.queued`/`scan.ingested`/`scan.ingest_failed`.
- ADR-0042 (`docs/decisions/0042-agent-fire-and-forget-ingest.md`).

## [Unreleased] — TICKET-006: Findings Cross-Server Bucket-View (ADR-0037)

### Findings-Seite

- `/findings` rendert eine Cross-Server Bucket-View nach `(Server, ApplicationGroup)` mit collapsed HTMX-Lazy-Cards (ADR-0037, ersetzt ADR-0025 §(5)).
- Bulk-Acknowledge unterstuetzt Bucket-Header-Selektion (ganzer Bucket auf einen Klick) plus Mix mit Einzel-Finding-IDs.
- Pending-Bucket (Findings ohne Group-Zuordnung) als Cross-Server-Sammler am Ende der Liste mit Server-Spalte.
- Header-Counter zeigt "X Gruppen · Y Findings" statt "X Treffer · Seite N von M".

### Added

- `app/services/findings_bucket_query.py` — `BucketHeader`-Dataclass, `list_buckets()`, `pending_bucket_header()`, `list_bucket_findings()`, `resolve_bucket_to_finding_ids()`. Gemeinsamer `_apply_bucket_filters`-Helper fuer alle vier Public-Funktionen (Single-Source).
- Routes `GET /findings/bucket`, `GET /findings/pending`, `POST /findings/bulk/acknowledge`.
- Templates `_partials/bucket_card.html`, `_partials/pending_bucket_card.html`, `_partials/bucket_findings_table.html`, `_partials/pending_bucket_findings_table.html`, `_partials/bucket_bulk_ack_modal.html`.
- Alpine-Komponente `bucketBulkSelection` in `app/static/js/bucket_bulk_ack.js`.
- 55+ neue Pure-Unit-Tests (14 Service, 22 View, 19 Template).
- ADR-0037 (`docs/decisions/0037-findings-cross-server-bucket-view.md`).

### Changed

- `app/views/findings.py::index()` rendert Bucket-Liste via `list_buckets` statt flacher Tabelle via `list_findings_cross_server`.
- `app/templates/findings/index.html` umgebaut auf Bucket-View. Sort-Hidden-Inputs (`sort`/`dir`) entfernt.
- ARCHITECTURE.md §7 (`/findings`-Beschreibung).

### Removed

- Outer-Pagination auf `/findings` (Bucket-Header werden alle gerendert).
- Sort-Selector auf `/findings` (`?sort=`/`?dir=` werden ignoriert; Spec-fixe Sortierung).
- `_explicit_sort()`-Helper in `app/views/findings.py` (Sort-Bookmark-Trigger entfaellt).
- Backcompat-Stubs in `findings.index()`-Render-Context (Etappe-3-Temporaer).

## [Unreleased] — ADR-0031: Theme-Switcher entfernt

Operator nutzt seit Beginn ausschließlich das Dark-Theme; der Toggle war
toter Code mit Maintenance-Overhead. Mit ADR-0031 ist er ersatzlos entfernt.

### Added

- ADR-0031 (`docs/decisions/0031-theme-switcher-removed.md`) — dokumentiert
  Entscheidung, Konsequenzen und geplante Folge-Arbeit (Option D: npm-Build).
- Alembic-Migration 0013 (`0013_remove_default_theme.py`) — entfernt
  `settings.default_theme` und `ck_settings_theme`-Constraint.

### Changed

- `base.html` und `base_app.html`: `<html data-theme="dark">` statisch
  gesetzt, `color-scheme`-Meta auf `dark` — kein Jinja-Conditional mehr.
- ARCHITECTURE.md §6, §7, Block A, Block D: Theme-Toggle-Referenzen entfernt.
- ADR-0016: Cross-Referenz zu ADR-0031 ergänzt (§"Theme-Toggle" abgelöst).

### Removed

- `app/static/js/theme.js` (94 LOC Alpine-Komponente + Cookie-Handling)
- `_VALID_THEMES`, `_resolve_theme()`, `_inject_theme()`, `_persist_theme()`
  aus `app/__init__.py`
- `settings.default_theme`-Spalte + Check-Constraint (via Migration 0013)
- `THEME_CHOICES`-Konstante und `default_theme`-Feld aus `app/forms.py`
- `default_theme`-Zuweisung und Audit-Metadata-Eintrag aus `app/views/setup.py`
- No-Flash-Theme-Resolver-Script und `theme.js`-Include aus Shell-Templates
- Theme-Toggle-Block (Sun/Moon-SVG) aus `layout/_header.html`
- Theme-Auswahl-Formblock aus `setup/step3.html`
- `tests/test_theme_cookie.py` (4 Tests)
- `default_theme`-Assertions/-Form-Felder aus `tests/setup/test_wizard.py`
- `test_header_theme_toggle_present_with_sun_and_moon` aus
  `tests/integration/test_header_navigation_db.py` (ersetzt durch
  `test_header_has_no_theme_toggle`)
- `"js/theme.js"`-Einträge aus `tests/views/test_script_load_order.py`

## [Unreleased] — Block V: Performance-Tuning UI-Views (ADR-0030)

Dashboard `/` und Server-Detail `/servers/<id>` rendern signifikant
schneller. Sammel-ADR-0030 mit neun Befunden in fünf Phasen umgesetzt,
Code-only (kein Schema-Touch, keine Alembic-Migration).

Befunde + Maßnahmen:

- **Befund 9 (Phase A) — Dead-Code-Entfernung:** `get_quick_stats` wurde
  vom Dashboard-View und vom Sidebar-Context-Processor unkonditional
  aufgerufen, aber im aktiven Template nirgendwo gerendert (Partial
  `_quick_stats.html` ohne `{% include %}`-Aufrufer). Service und
  Partial ersatzlos entfernt — vier redundante Findings-Queries pro
  Request weg.
- **Befund 1 (Phase B) — Server-Detail Trend-Aggregator-Redundanz:**
  `compute_tendency` rief intern `daily_severity_counts_for_server`
  auf, das wenige Zeilen später im View nochmal direkt geladen wurde;
  `severity_snapshots_for_server` lud dieselbe Row-Liste ein drittes
  Mal. Neue Pure-Funktion `tendency_from_counts(counts, …)` in
  `app/services/trend.py` (delegiert von `compute_tendency`-Wrapper
  aus); optionaler `rows=`-Parameter auf beiden Aggregatoren als
  Stepping-Stone für Phase E.
- **Befund 2 (Phase B) — `list_findings` unkonditional im
  Group-Default-Pfad:** Helper `_is_flat_mode` spiegelt die
  Template-Conditional aus `_findings_section.html:122-133` im
  View-Code; `list_findings` läuft nur noch wenn die flache Liste
  tatsächlich gerendert wird. Template `detail.html:Z.42` Eyebrow-
  Counter auf `total_findings = counts.open if counts else (findings |
  length)` umgestellt.
- **Befund 5 (Phase D) — Dashboard-Findings-Aggregat-Konsolidierung:**
  `_load_open_aggregates` 2 → 1 Query (FILTER-Aggregat liefert
  Severity-/KEV-/Risk-Band-Buckets pro Server in einer Query),
  `_load_risk_kpi_counters` 4 → 2 Queries (Findings-FILTER-Aggregat +
  Active-Server-Count getrennt). `yes_servers` wird aus dem bereits
  geladenen `_load_servers`-Result abgeleitet, statt per
  Distinct-Count-JOIN — Filter auf aktive Server (`retired_at IS NULL
  AND revoked_at IS NULL`) explizit erhalten, damit revoked Server mit
  historischen OPEN-Findings nicht in den Yes-Counter mitlaufen.
- **Befunde 4 + 6 + 7 + 8 (Phase C) — Sidebar-Lazy-HTMX-Load
  (Sammel-Maßnahme):** Sidebar-Context-Processor liefert nur noch die
  billigen Felder (Server-Liste, Tags, filter_tags);
  `heartbeats_for_servers` auf schmale 7-Spalten-Projektion
  (`_FindingRow`-NamedTuple) statt `select(Finding)` — ~30 MB
  Hydrate-Ersparnis pro Call. Neuer Pure-Service
  `app/services/sidebar_risk_counts.py::escalate_act_counts_by_server`
  (eine GROUP-BY-Query auf `(server_id, risk_band)`). Polling-Endpoint
  `/_partials/sidebar` ist jetzt die einzige Quelle der teuren
  Aggregate (Heartbeats, Risk-Counts, Header-Counter). HTMX-Trigger
  von `every 10s` auf `load, every 60s [document.visibilityState ===
  'visible']` umgestellt — bewusste Spec-Änderung im Rahmen Phase C
  (siehe ADR-0030 §Konsequenzen). Initialer Render zeigt
  Skeleton-Markup (50 Heartbeat-Cells + ESCALATE/ACT-Spalten +
  ALARM-Header-Count, alle mit `animate-pulse`-Klasse und identischen
  Tailwind-Größenklassen wie die Live-Variante — kein Layout-Sprung
  beim Swap). Server-Anzahl ist initial bereits echt (aus
  `_load_servers`). Neue Sidebar-Datenfelder pro Server-Row: ESCALATE-
  und ACT-Counts plus Header `HOSTS · ALARM`.
- **Befund 3 (Phase E) — SQL-Trend-Aggregation:** Drei neue SQL-Helper
  in `app/services/severity_history.py` mit `generate_series` +
  `COUNT(*) FILTER (...)`: `_build_server_daily_sql`,
  `_build_kev_open_sql`, `_build_fleet_daily_sql`.
  `severity_snapshots_for_server` und `daily_severity_counts_for_server`
  nutzen SQL als Default-Pfad — Phase-B-Python-Aggregator nur noch bei
  `rows=`-Backward-Compat-Pfad. `daily_severity_counts_fleet`-
  Differenz-Array-Walk ersatzlos durch SQL ersetzt.
  Server-Detail-View `show()` ruft Aggregatoren ohne `rows=` →
  SQL-Pfad aktiv im produktiven Render.

### Added

- **Neuer Service** `app/services/sidebar_risk_counts.py` mit
  `escalate_act_counts_by_server(session, server_ids) ->
  dict[int, dict[str, int]]` — pro Server die OPEN-Findings-Counts in
  den Risk-Bands `escalate` und `act`, eine SQL-Query.
- **Neue Public-Funktion** `tendency_from_counts(counts, *,
  days_short=7, days_long=50, threshold=0.05) -> Tendency` in
  `app/services/trend.py` (Pure-Funktion ohne Session-Argument).
- **Neuer Public-Helper** `load_findings_for_server(session, server_id,
  *, days=50, now=None) -> list[_FindingRow]` in
  `app/services/severity_history.py` als dünner Wrapper um den
  Underscore-prefixed `_load_findings`-Helper.
- **Drei neue SQL-Helper** in `app/services/severity_history.py`:
  `_build_server_daily_sql`, `_build_kev_open_sql`,
  `_build_fleet_daily_sql` — alle mit `generate_series` + `COUNT(*)
  FILTER (WHERE …)`-Aggregaten.
- **Optionaler `rows=`-Parameter** (Keyword-only) auf
  `severity_snapshots_for_server` und
  `daily_severity_counts_for_server` — wenn gesetzt, überspringt die
  Funktion den DB-Lade-Pfad und gibt direkt an den Pure-Aggregator
  weiter.
- **Drei neue Sidebar-Context-Keys** im Polling-Endpoint
  `/_partials/sidebar`: `sidebar_risk_counts`, `hosts_total`,
  `alarm_count`. Sidebar-Templates konsumieren sie für ESCALATE/ACT-
  Spalten und Header-Counter; bei Initial-Render-Fallback greift
  Skeleton-Markup.
- **82 neue Pure-Unit-Tests** in 9 Files: `test_tendency_from_counts.py`
  (7), `test_severity_history_sql.py` (11), `test_severity_history.py`
  (+4 für `rows=`-Pfad), `test_server_detail.py` (+12 für
  `_is_flat_mode`, Render-Conditional und SQL-Default-Aktivierung),
  `test_dashboard_phase_d.py` (14), `test_sidebar_risk_counts.py` (7),
  `test_heartbeat_aggregation.py` (+4 für schmale Projektion),
  `test_sidebar_context.py` (8), `test_sidebar_partial.py` (15).

### Changed

- **`app/views/dashboard.py::_load_open_aggregates`** liefert jetzt ein
  3-Tuple `(counts_by_server, kev_by_server, risk_bands_by_server)` —
  eine FILTER-Aggregat-Query statt zwei separate GROUP-BYs.
- **`app/views/dashboard.py::_load_risk_kpi_counters`** bekommt einen
  dritten Parameter `active_server_ids: set[int]` und konsumiert
  `risk_bands_by_server` aus `_load_open_aggregates`; `yes_servers`-
  Ableitung jetzt in Python aus der bereits geladenen Server-Liste,
  ohne separaten Distinct-Count-JOIN. Active-Server-Filter explizit
  über das Set, damit revoked Server nicht miteinfliessen.
- **`app/services/heartbeat_aggregation.py::heartbeats_for_servers`**
  nutzt eine schmale 7-Spalten-Projektion via `_FindingRow`-NamedTuple
  statt `select(Finding)`. Öffentliche Signatur (`dict[int,
  list[DailyStatus]]`) unverändert.
- **`app/services/trend.py::compute_tendency`** ist jetzt ein dünner
  Wrapper: lädt Counts via `daily_severity_counts_for_server` und
  delegiert an `tendency_from_counts`. Backward-Compat erhalten.
- **`app/views/_sidebar_context.py::build_sidebar_context`** schrumpft
  auf billig-only — kein `heartbeats_for_servers`-Call mehr, kein
  `get_quick_stats` (Phase A). Polling-Endpoint `sidebar_partial`
  übernimmt die teuren Aggregate.
- **`app/views/server_detail.py::show`** ruft
  `severity_snapshots_for_server` und
  `daily_severity_counts_for_server` ohne `rows=`-Parameter auf —
  SQL-Default-Pfad ist im produktiven View aktiv. Tendency wird aus
  `trend_data` via `tendency_from_counts` abgeleitet,
  `compute_tendency`-Call entfällt.
- **`app/templates/sidebar/_server_list.html`** HTMX-Trigger
  `load, every 60s [document.visibilityState === 'visible']` (vorher
  `every 10s`). Header-Markup `HOSTS · ALARM` mit data-test-Attributen
  für die zwei Counter.
- **`app/templates/sidebar/_server_row.html`** zwei neue Spalten
  ESCALATE/ACT mit Skeleton-Fallback (`animate-pulse`-Span bei `risk`
  falsy, Live-Werte mit `text-error`/`text-warning`/`—`-Marker).
- **`app/templates/sidebar/_heartbeat_bar.html`** mit `{% if cells %}`-
  Guard; Else-Zweig rendert 50 Skeleton-Cells in identischer
  Tailwind-Größenklasse wie die Live-Cells.
- **`app/templates/servers/detail.html:Z.42`** Eyebrow-Counter
  `{% set total_findings = counts.open if counts else (findings |
  length) %}` — funktioniert auch wenn `findings` im
  Group-Default-Pfad leer ist.
- **`tests/adversarial/test_xss_in_heartbeat_tooltip.py`** auf
  Polling-Endpoint `/_partials/sidebar` umgestellt (Heartbeat-Cells
  kommen nicht mehr beim initialen Page-Render). XSS-Schutz-Eigenschaft
  unverändert, anderer Render-Pfad.

### Removed

- **`app/services/quick_stats.py`** und
  **`app/templates/sidebar/_quick_stats.html`** ersatzlos gelöscht
  (Dead Code).
- **Differenz-Array-Walk** in
  `app/services/severity_history.py::daily_severity_counts_fleet`
  durch SQL-Helper `_build_fleet_daily_sql` ersetzt.
- **Doppelte Heartbeat-Buildung pro Page-Load** (Context-Processor +
  Polling-Endpoint im selben Request) entfällt — Polling-Endpoint ist
  jetzt einziger Build-Pfad.
- **`load_findings_for_server`-Aufruf** in
  `app/views/server_detail.py::show` (nach Phase-E-Aktivierung). Die
  Funktion bleibt als Public-API in `app/services/severity_history.py`
  erhalten (Backward-Compat).
- **`tests/services/test_quick_stats.py`** und
  **`tests/integration/test_quick_stats_db.py`** mit `quick_stats.py`
  gelöscht.

### Performance-Erwartung (DoD-0030 — User-Verifikation gegen k8s-DB ausstehend)

ADR-0030 §Definition of Done listet folgende Wallclock-Ziele, die nur
gegen eine echte Postgres-DB messbar sind (Pure-Unit kann das nicht
abdecken):

- `GET /` (Dashboard) Server-Zeit median **< 800 ms** (heute Wallclock
  3.45 s, 2 Server / 18 537 Findings).
- `GET /servers/<id>` Server-Zeit median **< 1.5 s** (heute Wallclock
  7.88 s, 9 224 OPEN-Findings).
- DB-Query-Count Dashboard **≤ 6**, Server-Detail **≤ 12**.
- Trend-Sektion (Sparklines + Daily + Tendency) **< 100 ms**.
- Sidebar zeigt echte Server-Namen ≤ 500 ms nach Page-Open;
  Heartbeats + ESCALATE/ACT erscheinen ≤ 2 s danach via Skeleton-Swap.

Operator-Verifikation post-Deploy: Pod-Restart `secscan-app`, `/`
öffnen (Sidebar-Skeleton-Swap sichtbar), `/servers/<id>` für einen
großen Server prüfen (TTFB spürbar schneller).

### Bekannte Re-Open-Trigger (deferred, eigene ADRs/Tech-Debt)

- **Timezone-Edge-Case in `generate_series`** — korrekt unter
  UTC-Session-TZ (Standard-Setup), bei anderer DB-TZ Off-by-One an
  Tagesgrenzen möglich. Aktuell akademisch.
- **`test_severity_history_fleet.py`-Bench-Schranke** (heute
  `< 200 ms`) — nach SQL-Pfad neu kalibrierbar (`< 50 ms` plausibel),
  db_integration-Marker, nur auf User-Anweisung gefahren.
- **„Weitere Performance-Aspekte" aus ADR-0030** (bewusst aus Scope
  ausgeschlossen, eigene Folge-ADRs/Tech-Debt-Einträge sobald operativ
  relevant): `/findings` Cross-Server-Liste, Worker-Lese-Pfade,
  `_load_action_required_counts`/`_quick_counts_for_server`-
  Konsolidierung im Server-Detail-Header, Render-Time-Instrumentierung,
  DB-Pool-Sizing-Review, abgebrochener Sidebar-Request
  `NS_BINDING_ABORTED` (HTMX-Race-Analyse), `stale_servers`-Counter
  wenn er später wieder gebraucht wird.

## [Unreleased] — v0.12.0: Scan-Ingest immer Async (Cutover-Abschluss Block R)

Das in ADR-0026 / Block R Phase H als Cutover-Schutz eingefuehrte
Feature-Flag `SECSCAN_SCAN_INGEST_ASYNC` ist ersatzlos entfernt. Async
ist seit v0.12.0 der einzige Pfad — der Sync-Branch in
`app/api/scans.py` ist ersatzlos geloescht. Operator-Setups ohne
laufenden `secscan-llm-worker`-Container sind nicht mehr unterstuetzt.

Auslöser: Agent v0.4.0 erwartet `job_id` im 202-Body und schlaegt mit
Exit 3 fehl wenn das Backend Sync-Body antwortet — der Operator musste
den Flag manuell setzen. Single-Operator-Single-Agent-Setups brauchen
das Cutover-Sicherheitsnetz nicht; das Flag war damit dauerhafte
Bedienfalle.

### Removed

- **`SECSCAN_SCAN_INGEST_ASYNC`-Setting** in `app/config.py` und
  `docker-compose.yml`.
- **Sync-Branch in `app/api/scans.py::ingest_scan`** (inkl. JSON-Pre-Parse
  fuer Agent-Version-Gate und `process_scan_envelope`-Direktaufruf vom
  Edge-Handler). Der Service `app/services/scan_processing.process_scan_envelope`
  bleibt unveraendert — er wird jetzt nur noch vom Worker-Sub-Tick
  aufgerufen.
- **Drei db_integration-Test-Files**: `tests/integration/test_scans_ingest_db.py`,
  `tests/integration/test_scans_risk_pretriage_db.py`,
  `tests/integration/test_scans_block_p_job_queueing_db.py`. Diese
  testeten primaer HTTP→Service-Wiring im Sync-Pfad. Die Logik ist via
  `tests/services/test_scan_processing.py`,
  `tests/workers/test_scan_ingest_worker_unit.py`,
  `tests/api/test_scans_async_edge.py` und
  `tests/services/test_finding_group_inheritance.py` weiter abgedeckt.

### Changed

- **Adversarial-Tests** (`test_host_state_xss.py`,
  `test_pretriage_no_llm_override.py`, `test_outdated_agent_rejected.py`)
  auf den neuen `tests/_helpers.py::run_scan_synchronously`-Helper
  umgestellt (POST + Worker-Sync-Trigger in einem Aufruf).
  `hostname`-Pflichtfeld in den Envelopes ergaenzt (Pre-Validation).
  Error-Response-Format ist jetzt flat `{"error": "agent_outdated"}`
  statt nested `{"error": {"code": "...", "message": "..."}}`.
- **`tests/integration/test_scans_envelope_trivy_version_db.py`**,
  **`tests/integration/test_scans_host_state_db.py`**: `_post()`-Helper
  triggert Worker synchron nach POST (Test-Vorbedingung: DB-State
  unmittelbar nach POST sichtbar).
- **`docs/operations.md`** Block-R-Sektion: Feature-Flag-Cutover-Plan
  durch „Async-only seit v0.12.0"-Hinweis ersetzt.
- **ADR-0026** Header-Status: „Cutover abgeschlossen mit v0.12.0".
- **ARCHITECTURE.md §6** umgeschrieben: Async ist der einzige Pfad
  (kein Verweis auf Sync-Default mehr).

### Migration

Operator muss vor dem Deploy von v0.12.0 sicherstellen, dass der
`secscan-llm-worker`-Container laeuft (depends_on `db: healthy` plus
seit Block R `app: healthy` damit Alembic durch ist). Andernfalls
landen Scans queued aber werden nie verarbeitet — Agent-Polling laeuft
in den 600s-Timeout (Exit 5).

`SECSCAN_SCAN_INGEST_ASYNC=...`-Eintraege in Operator-`.env`-Files
oder Helm-Values koennen ersatzlos entfernt werden; sie sind funktional
inert.

---

## [Unreleased] — Block T: Application-Group-Evaluations als Junction

ADR-0028. Behebt den last-write-wins-Bug zwischen Servern: dieselbe Pattern-
Group hatte auf zwei unterschiedlichen Servern unterschiedliche Bewertungen
(Listener-Profil, Host-Snapshot), das frueher direkte Field-Set auf
`ApplicationGroup` ueberschrieb beim zweiten Scan die Bewertung des ersten.
Sieben Eval-Spalten wandern in eine neue Junction-Tabelle
`application_group_evaluations` mit Composite-PK `(group_id, server_id)`.

### Added

- **Neue Tabelle `application_group_evaluations`** (Migration 0011): pro
  `(group_id, server_id)` eine Junction-Row mit `risk_band` (NOT NULL,
  CHECK in `('escalate','act','mitigate','monitor','noise')`),
  `risk_band_reason`, `risk_band_source` (CHECK in `('llm','manual')`),
  `risk_band_computed_at`, `worst_finding_id` (kein FK — Junction-Row
  ueberlebt Finding-Deletes), `group_findings_fingerprint`, `action_type`.
  Drei Indizes: Composite-PK, `(server_id, risk_band)` fuer Server-Detail-
  Lookups, partial auf `worst_finding_id WHERE NOT NULL` fuer den UI-Render.
- **Pass-2-UPSERT** auf Junction (`pg_insert().on_conflict_do_update()`)
  ersetzt den frueheren `_apply_pass2_to_group(group, ...)`-Helper. Neuer
  Helper: `_upsert_evaluation(session, group_id, server_id, ...)`.
  Cache-Hit-Pfad und Live-LLM-Pfad in `app/workers/llm_worker.py` umgestellt.
- **Pass-2-Trigger-Adaption** in `app/services/scan_processing.py`: heutige
  Skip-Logik (`grp.group_findings_fingerprint == new_fp and grp.risk_band
  is not None`) durch Batch-SELECT auf `application_group_evaluations`
  ersetzt. Vermeidet N+1 (ein SELECT laedt alle Junction-Rows fuer das
  affected_groups-Set vorab).
- **Composite-Match in `inherit_group_risk_to_findings`**
  (`app/services/finding_group_inheritance.py`): UPDATE-FROM jointet jetzt
  auf `(Finding.application_group_id == Junction.group_id AND
  Finding.server_id == Junction.server_id)`. Server-A's Findings erben
  nur aus `(group, A)`-Junction — kein Cross-Server-Leak mehr.
- **Vierter Batch-SELECT** in
  `app/views/server_detail.py::_load_application_groups_for_server`:
  Junction-Rows fuer `(server_id=?, group_id IN ...)`. Group-Cards
  rendern jetzt mit `evaluation`-Variable (Junction-Row oder `None`).
  Fehlende Junction-Row → „Nicht bewertet"-Pille via
  `group_evaluating_card.html`.

### Changed

- **`ApplicationGroup`-Model** verliert sieben Spalten und zwei
  CheckConstraints. Bleibt: fleet-weite Identitaet + Pattern-Library
  (`label`, `explanation`, `path_prefixes`, `pkg_name_*`,
  `pkg_purl_pattern`, `group_kind`, `source`, `detected_at`,
  `last_used_at`).
- **Templates** auf `evaluation`-Variable umgestellt:
  `application_group_card.html`, `_view_groups.html`,
  `_action_needed_section.html`. `settings/llm_reviewer.html`
  Top-Groups-Tabelle Risk-Band-Spalte durch Group-Kind ersetzt (fleet-
  weite Eval-Sicht out-of-MVP, siehe ADR-0028 §Re-Open-Trigger).
- **ARCHITECTURE.md §5** ergaenzt mit Junction-Beschreibung.
- **ADR-0023** Header ergaenzt mit Hinweis-Block, dass die Persistenz-
  Schicht durch ADR-0028 aktualisiert ist.
- **TICKET-002** geschlossen — "Erledigt durch Block T".

### Migration ist Drop & Rebuild — kein Daten-Backfill

Bestehende Eval-Werte auf `application_groups` werden **nicht** in die
Junction migriert (ADR-0028 §Migration). Begruendung: die Werte sind
semantisch falsch (last-write-wins), eine Replikation pro Server wuerde
den Fehler vervielfaeltigen. Pass-2 fuellt die Junction beim naechsten
Scan jedes Servers automatisch neu — Cache-Hits in `llm_risk_cache`
machen den Re-Eval nahezu kostenlos (~95% Hit-Rate erwartet).

### Operator-UI-Luecke nach Deploy

Bis zum ersten Scan jedes Servers nach Deploy zeigt jede Group-Card auf
der Server-Detail-Seite die **„Nicht bewertet"-Pille**. Der Block-P-Hook
im Scan-Ingest-Pfad triggert Pass-2 organisch beim naechsten Scan.
`docs/operations.md` Sektion „Block-T-Application-Group-Evaluations"
beschreibt den Force-Scan-Recipe falls Operator nicht warten will.

### Tests

- **Pure-Unit (Default-CI):** `tests/services/test_finding_group_inheritance.py`
  auf Junction-Composite-Match umgestellt (8 Tests, gruen).
  Gesamt-Suite 1205 passed, 5 E2E-skipped, 697 deselected.
- **On-Demand db_integration** (im Repo abgelegt, ausstehend bis User-OK):
  Schema-Reflection 0011, Pass-2-UPSERT-Pfade (Cache-Hit/Live-LLM/
  Idempotenz/Race), Trigger-Logik, Server-Detail-Render mit Cross-Server-
  Isolation.

---

## [Unreleased] — Block R: Asynchroner Scan-Ingest

ADR-0026. Loest das Agent-Timeout-Problem bei grossen Scans: `POST /api/scans`
antwortet im Async-Modus binnen <1s mit 202 + `job_id`, die volle
Verarbeitung wandert in den `secscan-llm-worker`-Container als neuer
Sub-Tick `scan_ingest_tick`. Default-Feature-Flag `SECSCAN_SCAN_INGEST_ASYNC=false`
haelt den synchronen Pfad aktiv — Cutover ist Operator-gesteuert.

### Added

- **Neue Tabelle `scan_ingest_jobs`** (Migration 0010): Queue fuer den
  Async-Pfad mit `payload_gzip BYTEA STORAGE EXTERNAL`, `payload_sha256
  CHAR(64)` als Idempotency-Key, Lifecycle-Spalten (`status`, `attempts`,
  `next_attempt_at`, `picked_up_by`, `picked_up_at`, `finished_at`,
  `result` JSONB, `error`, `scan_id`). Vier Indizes: Pickup (partial
  `status='queued'`), Stale (partial `status='in_progress'`), Server
  `(server_id, status)`, partial-unique `payload_sha256` auf
  `status IN ('queued','in_progress')` fuer Idempotenz.
- **Async Fast-Path** in `app/api/scans.py` mit Feature-Flag
  `SECSCAN_SCAN_INGEST_ASYNC`: schmale Pre-Validation (`_pre_validate_envelope`,
  manuelles dict-Walking ohne Pydantic-Vollparse), SHA-256-Idempotency,
  Per-Server-Soft-Cap (Default 50 queued/in_progress, ENV
  `SECSCAN_MAX_QUEUED_INGEST_JOBS`), `on_conflict_do_nothing` auf dem
  partial-unique-Index, 202 + `{job_id, status:"queued", status_url}`.
- **Worker-Sub-Tick** `app/workers/scan_ingest_worker.py`: SELECT FOR
  UPDATE SKIP LOCKED, zwei-Session-Pattern (Status-Update +
  Verarbeitung), atomares UPDATE bei `done` (Status + Counts + scan_id +
  `payload_gzip=NULL` im selben Statement — ADR-0005-Transit-Ausnahme),
  Backoff (`30s * 2^(attempts-1)`), Max-Attempts 3.
- **Service-Extraktion** `app/services/scan_processing.py`: ehemals-sync
  Logik aus `app/api/scans.py` als reine Service-Funktion
  `process_scan_envelope(session, server, payload_gzip) ->
  ScanProcessingResult`, vom Edge-Sync-Branch und Worker-Pfad geteilt
  konsumiert. Kein `session.commit()` im Service — Caller committet.
- **Status-Endpoint** `GET /api/scans/jobs/<job_id>`: Bearer-Auth +
  Server-Scoping (Cross-Server-Jobs liefern 404, nicht 403). Body je nach
  Status mit `scan_id`/`counts` (bei `done`) oder `error` (bei `failed`).
- **Stale-Reaper** im Worker fuer `scan_ingest_jobs`: Requeue nach 5 min
  (`SCAN_INGEST_STALE_TIMEOUT_MIN=5`), Fail nach `attempts >= 3`.
- **Retention-Sweep** stuendlich (`SCAN_INGEST_RETENTION_INTERVAL_SEC=3600`):
  Done-Crash-Reste binnen <2h auf `payload_gzip=NULL`, Failed-Jobs nach
  24h Operator-Debugging-Fenster komplett geloescht.
- **Audit-Events** `scan.queued` (Edge, `{job_id, payload_sha256,
  payload_bytes}`) und `scan.ingest_failed` (Worker, `{job_id,
  error_class, error_truncated}`). Idempotente Re-Inserts emittieren
  **kein** zweites `scan.queued`. Bestehende `scan.ingested`,
  `host_state.*`, `risk.pretriage_evaluated`, `llm.jobs_queued` kommen
  jetzt vom Worker (Body unveraendert).
- **Agent 0.4.0** (`agent/secscan-agent.sh`): Polling-Loop nach 202-Response
  auf `GET /api/scans/jobs/<id>` (2s-Intervall, max 600s, ENV
  `SECSCAN_POLL_MAX_SEC` ueberschreibbar). Neue Exit-Codes 4 (Worker-Fail)
  und 5 (Polling-Timeout). Auto-Update zieht 0.4.0 fuer alle Agents
  `>=0.3.1` automatisch.
- **Settings**: `scan_ingest_async`, `max_queued_ingest_jobs`,
  `scan_ingest_max_attempts`, `scan_ingest_stale_timeout_min`,
  `scan_ingest_retention_interval_sec` als Pydantic-Fields mit ENV-
  Variablen.
- **Pure-Unit-Tests** (47 Tests in 3 Files): `tests/services/test_scan_processing.py`
  (Service-Boundary + Aufruf-Reihenfolge), `tests/services/test_scan_processing_result.py`
  (Pydantic-Validation), `tests/workers/test_scan_ingest_worker_unit.py`
  (Backoff, Truncate, Should-Fail, Result-Serialisierung),
  `tests/api/test_scan_status_endpoint_unit.py` (Body-Serialisierung).

### Changed

- **ARCHITECTURE.md** §6 ergaenzt mit Block-R-Fast-Path-Beschreibung,
  §9 ergaenzt mit Per-Server-Soft-Cap, §13 ergaenzt mit `scan.queued`/`scan.ingest_failed`
  und der Edge-vs-Worker-Audit-Reihenfolge.
- **ADR-0022** ergaenzt mit Hinweis dass Pre-Triage-Audit-Events
  (`risk.pretriage_evaluated`, `host_state.*`) im Async-Modus vom Worker
  emittiert werden.
- **`app/api/scans.py`**: Sync-Inline-Logik (JSON-Parse bis llm_hook) durch
  `process_scan_envelope`-Aufruf ersetzt; Verhalten unveraendert.
- **`docker-compose.yml`**: `secscan-llm-worker` wartet jetzt auf
  `app: service_healthy` (nicht nur `db: service_healthy`). Im Cold-Start-
  Race-Window vor der Alembic-Migration hat der Worker sonst `relation
  "scan_ingest_jobs" does not exist`-Fehler produziert (verifiziert im
  Operator-Smoke: 58 Fehler → 0 Fehler nach dem Fix). App-Container haengt
  weiterhin nur an `db: service_healthy`, damit die `alembic upgrade head`-
  Phase im Entrypoint die Migration zuverlaessig durchlaufen kann bevor
  der Worker pickt.

### Fixed

- **Worker UPDATE-Statement bei `done`** (`app/workers/scan_ingest_worker.py`):
  `result = :result::jsonb` zu `result = CAST(:result AS jsonb)` korrigiert.
  SQLAlchemy `text()` mit `:`-Binds interpretiert `::jsonb` als zweiten
  Bind-Parameter, was zu `psycopg.errors.SyntaxError at or near ":"` fuehrte
  und jeden ersten echten Worker-Pickup auf `queued`-Retry zwang. Fix
  verifiziert in `tests/workers/test_scan_ingest_payload_lifecycle.py`.

### Deferred (On-Demand-Verifikation, nicht im CI-Default)

- Alembic-Roundtrip-Test fuer Migration 0010 (existiert als `tests/alembic/test_0010_scan_ingest_jobs.py`, db_integration-Marker).
- `tests/api/test_scans_async_edge.py` (14 Edge-Handler-Tests, db_integration).
- `SELECT FOR UPDATE SKIP LOCKED`-Concurrency-Smoke, atomares Payload-Clear-bei-done,
  Stale-Reaper-Requeue, Retention-Sweep-Delete-bei-failed,
  `on_conflict_do_nothing`-Partial-Index-Verhalten.
- Bats-Suite fuer Agent-Polling-Loop (`tests/agent/test_secscan_agent_polling.bats`).
- Docker-Compose-Up + `/healthz`-Smoke.

Operator fuehrt diese auf Anweisung pro Lauf aus; im Default-CI laeuft
nur Pure-Unit (ruff, mypy, shellcheck, pytest ohne db_integration-Marker).

### Cutover

`docs/operations.md` Abschnitt „Block-R-Async-Ingest" beschreibt den
fuenf-Schritt-Cutover (Deploy mit Flag off → Sanity-Check → Flag on →
Agent-Auto-Update → MIN_AGENT_VERSION-Bump).

---

## [Unreleased] — Block Q: External EPSS/KEV Enrichment

ADR-0024. Loest die Pass-2-Risk-Bewertungsluecke: Trivy 0.70 liefert
weder EPSS noch KEV im JSON-Output, deshalb waren die Pass-2-LLM-
Eskalations-Pfade "KEV-listed" und "EPSS very-high" faktisch tot.

Wir reichern EPSS und KEV jetzt **serverseitig** aus zwei oeffentlichen
Daily-Feeds an, persistiert in zwei eigenen Tabellen, und im Ingest-
Pfad pro Finding gelookupt. Trivy bleibt unveraendert als Scanner.

### Added

- **Agent 0.3.1 self-update + Trivy-DB-Metadaten**: Der Agent prueft vor
  jedem Scan `/agent/version`, laedt bei neuerer Server-Version
  `secscan-agent.sh` von `/agent/files/secscan-agent.sh`, legt `.bak`-
  Recovery-Kopien an und re-exec't sich einmalig mit Guard gegen Loops.
  Zusaetzlich sendet er top-level `trivy_db` aus
  `trivy version --format json`, damit `servers.trivy_db_version` und
  `trivy_db_updated_at` nicht mehr faelschlich `NULL` bleiben, wenn Trivy
  die DB-Metadaten nur pro Vulnerability statt in `scan.Metadata` schreibt.
- **Drei neue DB-Tabellen** (Migration 0008):
  - ``epss_scores`` (~250k Zeilen, ~10 MB): ``cve_id`` PK,
    ``epss_score``, ``epss_percentile``, ``updated_at``.
  - ``cisa_kev_catalog`` (~1500 Eintraege, <1 MB): CISA-Felder inkl.
    ``known_ransomware`` Flag.
  - ``feed_pull_log``: Audit-Trail pro Pull-Versuch, hard-cap 100
    Eintraege pro Feed via Eviction beim naechsten erfolgreichen Pull.
- **Pull-Worker** (``app/workers/feed_enrichment.py``): alle 24h ±30min
  Jitter, Sub-Tick im LLM-Worker analog Stale-Reaper. EPSS via gzip-
  stream-decompress mit 50 MB-Cap, KEV als single-shot Pydantic-
  Validation mit 10 MB-Cap. Defensiv: EPSS-Failure killt nicht den
  KEV-Pull. ``SECSCAN_FEED_PULL_DISABLED=true`` schaltet beide Pulls
  komplett ab (Air-Gap-Setup).
- **Ingest-Anreicherung** (``app/services/findings_ingest.py``): pro
  Scan ein Bulk-IN-Lookup gegen beide Feed-Tabellen, Felder werden
  in-place ueberschrieben. Nicht-CVE-Identifier (GHSA, RHSA, ...)
  ueberspringen den Lookup.
- **Backfill** (``app/services/feed_backfill.py``): nach jedem
  erfolgreichen Pull ein idempotentes ``UPDATE ... FROM`` ueber alle
  bestehenden Findings. Initial-Bootstrap reichert tausende von
  Findings auf einen Schlag an; laufende KEV-Nachpflege (CISA traegt
  CVEs auch im Nachhinein nach) wirkt ohne Re-Scan.
- **UI-Feed-Status**: zweizeiliger Block am Ende der LLM-Settings-Seite
  (``/settings/llm``). Zeigt pro Feed letzten erfolgreichen Pull-
  Zeitpunkt und Row-Count. Rot bei stale (>7 Tage) oder failed
  letztem Pull-Versuch.
- **Audit-Events**: ``feed.epss_pulled``, ``feed.kev_pulled``,
  ``feed.epss_pull_failed``, ``feed.kev_pull_failed`` mit
  ``event_metadata`` (row_count, bytes, duration_ms, error).

### Changed

- **`risk.band_changed`-Audit-Events ersatzlos entfernt** (ADR-0027).
  Das Aggregat ``risk.pretriage_evaluated`` bleibt die einzige Audit-Spur
  fuer Band-Uebergaenge. Bestehende historische Events bleiben in der
  Tabelle erhalten; es gibt keine Cleanup-Migration.
- Findings erben jetzt nach Pass-2-Erfolg und bei jedem Re-Ingest das
  finale ``risk_band`` ihrer ``ApplicationGroup``. Dadurch zaehlt die
  Server-Detail-Pill ``Action needed`` nur noch wirklich ungruppierte
  Pending-/Unknown-Findings statt bereits bewertete Group-Member.
- ``Settings``-Modell um sieben neue Felder erweitert:
  ``feed_pull_disabled``, ``feed_epss_url``, ``feed_kev_url``,
  ``feed_pull_interval_hours``, ``feed_jitter_max_min``,
  ``feed_max_decompressed_mb_epss``, ``feed_max_bytes_kev_mb``.
  Alle ueber ``SECSCAN_FEED_*``-Env-Vars konfigurierbar.
- ``LLM-Risk-Reviewer`` (Pass 2) Renderer und System-Prompt nutzen
  jetzt die persistierten EPSS/KEV-Werte (war vorher Block P).

### Operative Auswirkungen

- **Outbound-Network neu**: Server braucht HTTPS-Zugriff auf
  ``epss.empiricalsecurity.com`` und ``cisa.gov``. Air-Gap-Setup:
  ``SECSCAN_FEED_PULL_DISABLED=true``, Findings bleiben unangereichert,
  UI/LLM funktionieren weiter (Prompt sagt explizit ``epss=n/a``
  nicht als Eskalations-Signal werten).
- **Erster Pull dauert ~10-30s** je nach Netzwerk; danach passiert
  nichts mehr fuer 24h ±30min Jitter.

## [v0.9.6] — 2026-05-20

Worker-Idle-CPU-Optimierung und CI-Build-Speedup. Folge-Patch zu
v0.9.5; keine Schema-Migration, keine Spec-Aenderung.

### Changed

- **Worker-Idle-Polling drastisch reduziert** (``app/workers/
  llm_worker.py``). Operator-Befund: ``secscan-llm-worker``-Pod
  zeigt 219 mCPU im Leerlauf bei leerer Queue — zu viel fuer
  einen Worker der "nichts zu tun" hat. Ursache: ``_tick()`` fuehrt
  alle 2s vier separate SQL-Roundtrips aus (Budget-Reset, Mode-Check,
  Budget-Check, Pickup) plus Heartbeat-Thread alle 10s. Ergibt
  ~126 Queries/Minute Idle-Last.

  Drei Throttling-Mechanismen:

  - **Mode-Check-Cache (``MODE_CHECK_INTERVAL_SEC=30``).**
    ``_get_mode_throttled()`` cached ``settings.block_p_llm_mode``
    fuer 30s. Mode-Wechsel via Settings-UI wird nach <30s wirksam.
    Bei Wechsel wird ``llm_worker.mode_changed from=... to=...``
    geloggt.
  - **Budget-Check-Cache (``BUDGET_CHECK_INTERVAL_SEC=60``).**
    ``_budget_ok_throttled()`` cached die Budget-OK-Antwort fuer 60s
    und ruft ``maybe_reset_budget`` im selben Intervall. Trade-off:
    bei Budget-Erschoepfung mid-Cycle koennen noch bis 60s lang Jobs
    gepickt werden — paar Prozent Overshoot statt stundenlanger
    Free-Pass.
  - **Idle-Backoff** (``IDLE_BACKOFF_MAX_SEC=30``,
    ``IDLE_BACKOFF_FACTOR=1.5``). Bei leerer Queue waechst die
    Sleep-Dauer exponentiell von ``_poll_interval()`` (2s default)
    bis 30s-Cap. Erfolgreicher Pickup setzt den Backoff sofort
    zurueck — Job-Latency bleibt < 2s sobald Jobs reinkommen.

  Erwartete Idle-SQL-Last nach Steady-State (Queue dauerhaft leer):
  ~2 Queries/Minute (Stale-Reaper + Heartbeat) statt vorher ~126.
  Bei aktiver Queue keine Aenderung — Job-Pickup laeuft sofort beim
  ersten Idle-Tick.

  Test-Helper ``invalidate_throttle_caches_for_tests()`` neu —
  Tests die den Mode mid-test wechseln muessen den Cache explizit
  invalidieren bevor sie den naechsten ``_tick()`` machen.

- **CI-Build-Workflow** (``.github/workflows/release.yml``): arm64-
  Build temporaer abgeschaltet (QEMU-Emulation 5-10x langsamer als
  native amd64); GHA-Cache mit expliziter ``scope=release`` damit
  Tag-Builds den Cache ueber Tag-Grenzen teilen. Erwartete Buildtime
  von ~7m (v0.9.4) auf ~2-3m beim ersten Run, ~30-60s bei Folge-
  Tag-Builds mit unveraendertem ``pyproject.toml``.

### Tests

- 6 neue Worker-Tests fuer Idle-Backoff + Mode-/Budget-Cache.
- 1 Integration-Test angepasst (Mode-Switch-Test invalidiert
  Cache explizit).
- Full-Suite: **1609 passed** (vs. 1603 in v0.9.5), 5 skipped (E2E
  master-key-abhaengig), 5 deselected (bench/integration).
  Coverage 91 %. ``ruff check``/``ruff format --check``/``mypy app/``
  PASS.

## [v0.9.5] — 2026-05-20

Hotfix-Bundle fuer den Block-P-Worker. Vier zusammenhaengende Mini-
Fixes nach Operator-Beobachtung in Production (k8s):

  Pod-Restart-Loop mit (1) Label-Validator-Reject auf legitimes
  Distro-Paket-Label "linux-modules-5.15.0-177-generic", (2) leerem
  Debug-Log-Body bei Validation-Errors (Operator blind), (3) SIGTERM
  vom k8s-livenessProbe mitten im LLM-Call, (4) viel zu sparsames
  Worker-Logging.

Keine Schema-Migration, keine Spec-Aenderung (P-evidence-Files und
ADR-0023 unveraendert).

### Fixed

- **LABEL_PATTERN-Spec-Drift behoben.** ``app/services/llm_risk_
  reviewer.py::LABEL_PATTERN`` war ``^[a-z0-9][a-z0-9_-]{0,63}$``,
  Spec (``docs/blocks/P-evidence/prompt-pass1-final.md`` Z. 63 +
  ``app/services/llm_prompts.py``) sagt ``^[a-z0-9][a-z0-9._-]{0,63}$``
  (mit Punkt). Punkt ist legitim fuer Distro-Pakete mit Version im
  Paketnamen wie ``linux-modules-5.15.0-177-generic`` oder
  ``libstdc++6.0.30``. Backend folgt der Spec.

- **Debug-Log bei Validation-Errors zeigt jetzt die echte LLM-
  Response.** Bisher: wenn der Backend-Validator nach erfolgreichem
  LLM-Call wirft (z.B. invalides Label, ungueltige Combo, NUL-Reason),
  speicherte ``_record_pass_debug_log`` ``meta=None`` und damit leere
  ``system_prompt``/``user_prompt``/``raw_content``/``extracted_json``-
  Felder. Operator war im Debug-Log-Tab blind. Jetzt:
  ``LLMInvalidResponseError`` traegt ein optionales ``.meta``-Attribut;
  ``LLMRiskReviewer.pass1_detect_groups`` und ``pass2_evaluate_groups``
  haengen das Meta-Dict bei Validator-Wurf an die Exception. Worker
  liest ``exc.meta`` und persistiert komplett — Operator sieht die
  echte LLM-Response inklusive ``raw_content``, ``extracted_json``,
  ``reasoning_field``, ``usage`` und Prompts.

- **Heartbeat-Daemon-Thread** entkoppelt vom Tick-Loop
  (``app/workers/llm_worker.py``). Bisher wurde der Heartbeat in
  ``_tick()`` geschrieben — bei LLM-Call von 60-120s blockierte
  ``_tick()`` im ``_process_job``, der Heartbeat veraltete, k8s
  livenessProbe (``HEARTBEAT_MAX_AGE_SEC=30`` in ``healthcheck.py``,
  ``failureThreshold=3 x periodSeconds=30=90s``) killte den Pod mitten
  im LLM-Call → Job blieb in ``in_progress`` haengen bis Stale-Reaper
  nach 5 Minuten requeued. Jetzt: ``_heartbeat_loop`` laeuft als
  Daemon-Thread, schreibt alle 10s unabhaengig vom Tick. ``main()``
  startet ihn vor der Schleife (``_start_heartbeat_thread``), bei
  ``_shutdown`` graceful join mit 5s Timeout
  (``_stop_heartbeat_thread``). K8s/Docker-Compose-Probe-Settings
  bleiben unveraendert.

- **Logging-Erweiterung** fuer jede Pass-1- und Pass-2-Phase
  (``app/workers/llm_worker.py``). Bisher: nur ``job_picked``,
  ``job_done``, ``job_failed``. Jetzt zusaetzlich
  ``pass1_started``/``llm_call_started``/``llm_call_completed``/
  ``llm_call_failed``/``pass1_persist_done``/``pass2_started``/
  ``pass2_cache_lookup``/``pass2_cache_hit_applied``/
  ``pass2_persist_done``/``pass1_skipped``/``pass2_skipped``/
  ``budget_exhausted``/``budget_check_passed`` (DEBUG)/
  ``stale_reaped_count``/``heartbeat_thread_started``/
  ``heartbeat_thread_stopped``. Token-Counts aus ``meta.usage`` via
  neuem ``_usage_tokens(meta)``-Helper defensiv extrahiert.

### Tests

- 12 neue Tests gesamt fuer Heartbeat-Thread, Validator-Meta-Attach,
  Debug-Log-Insert-bei-Error, Punkt-im-Label-Akzept, Logging-Marker.
  Full-Suite **1603 passed** (vs. 1591 in v0.9.4), 5 skipped (E2E
  master-key-abhaengig), 5 deselected (bench/integration). Coverage
  91 %. ``ruff check``/``ruff format --check``/``mypy app/`` PASS.

### Worker-Realbetriebs-Impact

Pod-Restart-Loop in k8s ist gestoppt: Heartbeat-Thread haelt den
Worker auch waehrend 60-120s-LLM-Calls "alive", livenessProbe
gruen. Operator sieht im Debug-Log-Tab jetzt die echte
LLM-Response auch bei Validator-Errors. Pass-1 mit legitim-
versionierten Distro-Paket-Labels (Kernel-Module-Bundles)
laeuft durch.

**Bewusst weggelassen**: Spec-Haertung fuer Kernel-Paket-Labels
(Regel-1 "no versions" vs Regel-3 "package_name") — Operator-
Entscheidung, separate ADR falls die Group-Library mit
``linux-modules-*``-Versionen zu unuebersichtlich wird.

## [v0.9.4] — 2026-05-20

Hotfix-Patch zu Block P (ADR-0023). Behebt den 400-BadRequestError
aus dem Worker-Log:

    Requested input length 231381 exceeds maximum input length 131071

Pass-1 (group_detection) hat in einem einzigen LLM-Request alle un-
groupierten pending Findings eines Servers gerendert — bei realer
Flotte sprengt das die 131k-Token-Context-Window von
``openai/gpt-oss-120b``. Vier zusammenhaengende Mini-Fixes, eine
Migration entfaellt (kein Schema-Change).

### Fixed

- **Pass-1-Batching mit Affinity-Sort.** ``app/api/scans.py``
  Block-P-Hook splittet ungroupierte Findings jetzt in Batches à
  ``llm_pass1_findings_per_batch`` (Default 100, konfigurierbar via
  ``SECSCAN_LLM_PASS1_FINDINGS_PER_BATCH``, range 5..2000). Vor dem
  Split laeuft ein deterministischer Affinity-Sort
  (``app/services/group_matcher.py::affinity_sort_for_pass1``) nach
  ``(target_path-Top-3-Segments, package_name, id)`` — Findings die
  zur selben Owner-Application gehoeren landen damit benachbart und
  gehen im selben Chunk zum LLM. Idempotenz von Group-Labels via
  ``temperature=0`` (Fix 2) + Backend-Merge in
  ``_persist_pass1_groups`` (via Label-Lookup) macht Cross-Batch-
  Konsistenz robust ohne Schema-Change. Pass-2-Jobs haengen via
  ``depends_on`` am LETZTEN Pass-1-Job des Batches — Single-
  Concurrency-Worker verarbeitet sie in created_at ASC, also alle
  vorherigen Batches sind ``done`` bevor Pass-2 startet.

- **``temperature=0`` im LLM-Call.** ``chat_completion_json_with_meta``
  in ``app/services/llm_risk_reviewer.py`` setzt jetzt explizit
  ``temperature=0`` im SDK-Aufruf. Spec
  (``docs/blocks/P-evidence/prompt-pass{1,2}-final.md``) hatte das
  immer vorgesehen, im Worker-Call fehlte es bisher — Spec-Drift.
  Hilft der Label-Idempotenz fuer das Pass-1-Batching (Fix 1).

- **``BadRequestError`` wird als LLM-Fehler klassifiziert.**
  ``app/workers/llm_worker.py::_classify_error`` und die
  ``is_timeout_or_llm``-Marker-Liste erkennen jetzt OpenAI-SDK-
  Fehler (``BadRequestError``, ``APIStatusError``, ``error code:``)
  als ``llm_api_error`` statt ``other``. Folge: Audit-Metadata und
  Worker-Log markieren den Fehler korrekt als LLM-bezogen.

- **Docker-Healthcheck-Timeout 5s → 10s** fuer den
  ``secscan-llm-worker``-Container. Pre-existing Issue seit
  Block-P-v0.9.1 (Slim-Healthcheck): Cold-Python-Process plus
  DB-Connect dauert unter ARM64/RKE2 ~6s, 5s Timeout produzierte
  ``unhealthy`` trotz funktionalem Worker. Heartbeat-Cadence intern
  (10s) und Healthcheck-Schwellwert (30s) sind unveraendert —
  Probe-Latenz ist davon entkoppelt.

### Added

- ``probe_response_format.py`` (Operator-Diagnose-Skript,
  ``ruff.toml``-Exclude analog ``probe_gpt_oss.py``): testet
  ``response_format``-Varianten gegen DeepInfra + GPT-OSS-120B mit
  vollem Error-Body-Print, dokumentiert dass alle vier Varianten
  (json_schema strict=True/False, json_object, none) 200 OK
  liefern — ``response_format`` war NICHT der 400-Grund.

### Changed

- ``llm.jobs_queued``-Audit-Event-Metadata: ``pass1_queued`` zaehlt
  jetzt die Anzahl Batches (statt 0/1), neue Felder
  ``pass1_batch_size`` (None falls keine Pass-1-Jobs queued).

### Tests

- 20 neue Tests gesamt (4 Affinity-Sort-Unit-Tests in
  ``tests/services/test_group_matcher.py``, 5 Batching-Tests in
  ``tests/api/test_scans_block_p_job_queueing.py``, 2
  ``temperature=0``-Asserts in ``tests/services/
  test_llm_risk_reviewer.py``, 9 Error-Klassifikations-Tests in
  ``tests/workers/test_error_classification.py``). Full-Suite:
  **1591 passed**, 5 skipped, 5 deselected. Coverage haelt 91 %.

### Spec-Files unveraendert

- ADR-0023 ``Update v0.9.3``-Sektion, ``docs/blocks/P-evidence/
  prompt-pass{1,2}-final.md`` — v0.9.4 ist reines Verteilungs-/
  Latenz-Fix, keine Bewertungs-Semantik-Aenderung.

### Worker-Impact

Bei einer realen Flotte mit ~9000 ungroupierten Findings (User-
Beobachtung am 2026-05-20):
- vorher: 1 Pass-1-Job mit 231k Tokens → 400 → 3x failed →
  ``status='failed'``, kein Block-P-Output
- nachher: ~90 Pass-1-Jobs à 100 Findings, jeweils ~25k Tokens →
  alle 200 → Groups werden inkrementell via Label-Merge in
  ``application_groups`` aufgebaut.

Cost-Schaetzung bei DeepInfra-Preisen: ~$0.30 fuer den initialen
9000-Findings-Re-Eval, danach traegt der GroupMatcher-Cache.

## [v0.9.3] — 2026-05-20

Pass-1-Prompt-Iteration und Modell-Default-Wechsel fuer Block P
(ADR-0023). Kein Schema-Change, keine Migration. Reine Logik- und
Config-Aenderung.

### Changed

- **Default-LLM-Modell fuer Block P** wechselt von DeepSeek-V3 (vom
  Block-G-Wrapper geerbt) auf ``openai/gpt-oss-120b``. Begruendung:
  semantisch staerkstes Modell in zwei Test-Runden mit insgesamt
  sieben Kandidaten (DeepSeek-V3.2, DeepSeek-V4-Flash, MiniMax-M2.5,
  Qwen3-Instruct, Qwen3-Thinking, Phi-4, GPT-OSS-120B), zehn von
  zehn Test-2-Kriterien fehlerfrei bestanden. Plus Apache-2.0-
  Lizenz: Operator mit DSGVO-Strenge kann lokal hosten (vLLM,
  Ollama) ohne Code-Change. Operator-Override per Settings-Tab
  bleibt — falls Operator bei DeepSeek-V3 bleiben moechte, ist das
  ein Mode-Toggle.

- **Pass-1-System-Prompt** in ``app/services/llm_prompts.py::
  PASS1_SYSTEM_PROMPT`` um sieben Haertungs-Aspekte erweitert:

  1. Cross-Language-Bundle-Regel (Regel 6) — npm + pip + maven in
     gemeinsamem Verzeichnis-Pfad bilden eine Owner-Application.
  2. Multi-Path-Application-Regel (Regel 7) — Application an
     mehreren Pfaden (``/usr/local/bin/<app>`` plus
     ``/var/lib/<vendor>/<app>/``) ist eine Group, nicht zwei.
  3. Trailing-Slash-Pflicht fuer Directory-Path-Prefixes.
  4. Defense-in-Depth-Vorgabe — Pattern-Layers so vollstaendig wie
     sinnvoll befuellen (z.B. OS-Paket: pkg_name_exact + pkg_purl_
     pattern).
  5. Anti-Generic-Pattern-Liste mit konkreten verbotenen Beispielen
     (``pkg:golang/stdlib``, ``pkg:maven/``, Versions-Hashes in
     Path-Prefixes).
  6. Halluzinations-Schutz: ``NEVER invent finding_ids that were
     not in the input``.
  7. Bundle-vs-Library-PURL-Unterscheidung — fuer Application-
     Bundles duerfen nur Application-Vendor-PURLs als Pattern,
     niemals transitive Library-PURLs (kein ``pkg:pypi/flask`` als
     webapp-Pattern, kein ``pkg:maven/log4j-core`` als tomcat-
     Pattern).

  Volltext + Test-Evidenz-Matrix aller sieben Modelle:
  ``docs/blocks/P-evidence/prompt-pass1-final.md``.

### Added

- ``docs/blocks/P-evidence/prompt-pass1-final.md`` — finaler Pass-1-
  Prompt-Text, Test-Evidenz-Matrix, Modell-Wahl-Begruendung, Code-
  Touchpoints-Doku. Quelle der Wahrheit fuer kuenftige Prompt-
  Iterationen.
- ADR-0023 ``Update v0.9.3``-Sektion am Ende, dokumentiert den
  Default-Wechsel und die Prompt-Iteration mit Verweis auf das
  Prompt-Final-File.
- ``tests/services/test_llm_prompts.py`` neuer Anti-Regression-Test
  prueft, dass die kritischen Regel-Marker im Prompt enthalten sind
  (``CROSS-LANGUAGE BUNDLES``, ``MULTI-PATH APPLICATIONS``,
  ``DEFENSE IN DEPTH``, ``AVOID OVER-GENERIC PATTERNS``,
  ``BUNDLE PURLs MUST IDENTIFY THE APPLICATION ITSELF``).

- **Pass-2-System-Prompt** in ``app/services/llm_prompts.py::
  PASS2_SYSTEM_PROMPT`` ebenfalls iteriert und um drei strukturelle
  Aenderungen erweitert (Tags-Exclusion, 4-Band-Modell, geschaerfte
  escalate/act-Trennung). Volltext + Test-Evidenz unter
  ``docs/blocks/P-evidence/prompt-pass2-final.md``.

- **Tags werden nicht mehr an das LLM weitergegeben.** Server-Tags
  (Block D) sind User-vergebene Freitext-Labels fuer UI-Gruppierung
  und tragen keine garantierte Semantik. Block P verlaesst sich fuer
  Exposure-Bestimmung ausschliesslich auf objektive Listener-Adressen
  aus dem Host-Snapshot (0.0.0.0/:: = exposed, 127.0.0.1/::1 =
  loopback, RFC1918 = internal). ``_render_pass2_prompt()`` strippt
  die Tags aus dem Host-Context-Block. Tags bleiben in der UI fuer
  Operator-Gruppierung erhalten.

- **Risk-Band ``mitigate`` wird deprecated.** Operativ-Erkenntnis:
  die Trennlinie ``escalate`` (KEV+exposed) vs. ``mitigate``
  (HIGH+exposed+no-patch) hat keinen Mehrwert — beide kommunizieren
  „sofort handeln", unterscheiden sich nur in der Aktions-Art. Die
  Aktions-Art (patchen vs. anders mitigieren) wandert in den
  ``risk_band_reason``-Text. Neues Mapping:

    escalate = KEV+exposed · ODER · HIGH/CRITICAL+exposed+no-patch
    act      = HIGH/CRITICAL+exposed+has-patch+not-KEV
    monitor  = unveraendert (moderate Severity oder RFC1918/Loopback
               oder unklare Exposure)
    noise    = unveraendert (Application nicht aktiv)

  ``mitigate`` bleibt als Enum-Wert fuer historische Daten und
  Validator-Backward-Compat, LLM produziert ihn nicht mehr.
  Bestehende ``mitigate``-Findings werden beim naechsten Scan-Re-
  Ingest natuerlich neu klassifiziert (escalate oder act je nach
  Patch-Status). DB-CheckConstraint, Pydantic-Literal,
  ``ACTION_REQUIRED_MAP`` bleiben strukturell.

### Added

- ``docs/blocks/P-evidence/prompt-pass1-final.md`` — finaler Pass-1-
  Prompt-Text, Test-Evidenz-Matrix, Modell-Wahl-Begruendung, Code-
  Touchpoints-Doku. Quelle der Wahrheit fuer kuenftige Prompt-
  Iterationen.
- ``docs/blocks/P-evidence/prompt-pass2-final.md`` — analog fuer
  Pass 2, mit Test-Evidenz aus den Risk-Band-Iterations-Runden.
- ADR-0023 ``Update v0.9.3``-Sektion am Ende, dokumentiert alle vier
  Aenderungs-Punkte (Pass-1, Tags-Exclusion, Band-Reduktion, Debug-
  Log) mit Verweis auf die Prompt-Final-Files.
- ``tests/services/test_llm_prompts.py`` neue Anti-Regression-Tests
  pruefen die kritischen Regel-Marker in beiden Prompts.
- ``tests/services/test_llm_risk_reviewer.py`` vier neue Tests fuer
  ``_extract_json_from_response``: ``_strips_harmony_channel``,
  ``_strips_think_tags``, ``_strips_markdown_fences``,
  ``_fallback_greedy_braces``.
- **Zwei neue Group-Felder ``action_type`` und ``group_kind``** plus
  neue Server-Detail-UI-Sektion „Was zu tun ist". Schliesst die UX-
  Luecke aus der Band-Reduktion oben: Operator sieht jetzt
  strukturiert ob er patchen, App-vendor-update einspielen, oder
  anders mitigieren muss — ohne den Free-Text-Reason lesen zu
  muessen.

  ``action_type`` (varchar(16), vom LLM in Pass 2 gesetzt):
    patch        — Patch verfuegbar, einspielen
                   (erlaubt fuer escalate(a) und act)
    mitigate     — Kein Patch, anders eindaemmen
                   (erlaubt fuer escalate(b))
    watch        — beobachten (erlaubt fuer monitor)
    none         — Komponente nicht aktiv (erlaubt fuer noise)
    investigate  — Pre-Triage-Default fuer pending/unknown

  ``group_kind`` (varchar(20), deterministisch vom Backend beim
  Insert aus ``match_rules`` derived — KEIN LLM-Input):
    application_bundle — path_prefixes non-empty (k3s, jenkins,
                         apache2, grafana, ...)
    os_package         — nur pkg_name_exact / pkg_purl_pattern
                         befuellt (openssh-server, openssl, ...)

  Backend-Validator ``_validate_pass2_response()`` prueft erlaubte
  ``(risk_band, action_type)``-Kombinationen analog zu den anderen
  Validations-Schichten aus v0.9.0.

  Pass-2-Output-Schema erweitert um das eine Feld; Reason wird
  kuerzer (~180 Chars statt 256), weil Aktions-Art nicht mehr im
  Free-Text kommuniziert werden muss.

  Neue Server-Detail-UI-Sektion „Was zu tun ist" zwischen Sub-Line
  und Host-Snapshot. Sektion wird komplett ausgeblendet wenn keine
  Group mit ``risk_band IN (escalate, act)`` existiert. Bis zu
  fuenf Cards in Operator-Dringlichkeits-Reihenfolge:

    1. ESCALATE · Distro patchen
       (Group-Label-Liste, max 3-5 inline, dann „+N more")
    2. ESCALATE · App-Update einspielen
       (App-Label-Liste analog)
    3. ESCALATE · Kein Patch — mitigieren
       (Group-Label-Liste analog)
    4. ACT · Distro patchen (normal cycle)
       (KEINE Label-Liste, nur Counter — bei act zu viel Noise)
    5. ACT · App-Update einspielen (normal cycle)
       (KEINE Label-Liste, nur Counter)

  Jede Card hat ``<details>``-Drill-down (default collapsed) mit
  der Findings-Tabelle fuer die zugehoerigen Groups.

  Header-Pill-Reihe (inkl. „Action needed"-Top-Level-Pill),
  Host-Snapshot, Tags-Akkordeon, KPI-Cards mit Sparklines,
  Lebenszeichen, Severity-Trend, untere Findings-Tabelle bleiben
  unveraendert.

- **Reasoning-Block-Handling im Response-Parser.** Der Default-
  Modell-Wechsel auf GPT-OSS-120B (Punkt 1) bringt ein Reasoning-
  Modell ins Spiel mit Harmony-Format-Output (`analysis`-Channel
  vor dem finalen JSON). Beobachtete Pass-2-Token-Last: ~1400
  Tokens fuer 5 Groups, davon ~900 Tokens Reasoning. Je nach
  Provider-Adapter (DeepInfra, Groq, vLLM, Ollama) landet der
  Reasoning-Block in ``message.reasoning`` (separat), wird
  gestrippt, ODER erscheint vor dem JSON in ``message.content``.
  Letzteres haette unser bestehendes ``json.loads(content)`` mit
  ``LLMInvalidResponseError`` gefuehrt — alle Block-P-Jobs waeren
  silently in ``failed`` gelandet.
  
  Neuer Helper ``_extract_json_from_response(content) -> str`` in
  ``app/services/llm_risk_reviewer.py`` mit drei Defense-Schichten:
  
    1. Bekannte Reasoning-Wrapper-Patterns strippen (Regex):
       - GPT-OSS Harmony: ``<|channel|>analysis<|message|>...<|end|>``
       - DeepSeek-R1 / generic: ``<think>...</think>``
       - Llama-Style: ``[REASONING]...[/REASONING]``
    2. Markdown-Code-Fences strippen (``` ```json ... ``` ```).
    3. Greedy-Brace-Extraktion als Fallback (erstes ``{`` bis
       letztes ``}``).
  
  Helper laeuft IMMER zwischen ``message.content`` und
  ``json.loads()``, auch wenn der aktuelle Provider sauberen JSON
  liefert — schuetzt vor Provider-Wechsel und kostet nichts.
  
  ``chat_completion_json`` liest zusaetzlich Reasoning-Content
  ueber mehrere Provider-Patterns ueber neuen Helper
  ``_extract_reasoning(message)`` — verifiziert per
  DeepInfra-Probe-Lauf 2026-05-XX gegen openai/gpt-oss-120b:
  
    - OpenAI o1-Pattern: ``message.reasoning``
    - DeepSeek-R1-Pattern: ``message.reasoning_content``
    - DeepInfra-GPT-OSS via OpenAI SDK:
      ``message.model_extra["reasoning_content"]`` (Pydantic V2
      ``extra="allow"``-Bucket — wichtig, ``getattr(msg, "reasoning")``
      findet das NICHT)
    - Fallback: None
  
  Wert landet in ``llm_debug_log.response_body.reasoning_field``,
  getrennt von ``raw_content`` und ``extracted_json``.
  
  Beobachtung aus Probe-Lauf: DeepInfra-GPT-OSS-120B liefert
  ``message.content`` clean (kein Strip noetig), Reasoning lebt
  ausschliesslich in ``model_extra``. Token-Aufteilung nicht
  separat ausgewiesen (``completion_tokens`` enthaelt Reasoning
  und JSON gemeinsam); bei 3 Test-Groups: 543 prompt + 616
  completion = 1159 total, geschaetzt ~370 Reasoning und ~240 JSON.

- **Listener-Interpretation defensiv + LLM-Reasoning statt Hart-
  logik.** Die urspruengliche Pass-2-Definition behandelte
  RFC1918-Listener als „internal only" und schob die Findings
  automatisch auf monitor. Operator-Feedback nach Iteration 5:
  das ist Wunschdenken. Realistische Bedrohungsvektoren fuer
  einen 10.0.0.5:5432-Listener: Lateral Movement nach Compromise
  eines anderen Hosts im selben Netz, Port-Forward am Router,
  Reverse-Proxy davor, VPN-Zugang, kompromittierter Endpoint im
  selben Netz. Wir koennen aus Listener-Daten nicht beweisen
  dass etwas nicht erreichbar ist. Nur Loopback ist beweisbar
  nicht netzwerk-erreichbar.
  
  Drei Klassifikations-Zustaende:
    - PUBLIC-EXPOSED: 0.0.0.0/:: ODER spezifische IP (RFC1918
      ODER Public). Defensive Annahme: exposed.
    - LOOPBACK-ONLY: nur 127.0.0.1/::1. Nicht netzwerk-erreichbar.
    - NO-LISTENER: aktive Komponente ohne Netzwerk-Socket.
  
  LLM-Reasoning-Spielraum (statt Hartlogik): das Modell darf
  UPGRADE (LOOPBACK-Komponente erreichbar via exposed Service ->
  treat as PUBLIC-EXPOSED) und DOWNGRADE (PUBLIC-EXPOSED mit
  nachweisbar nicht-erreichbarem Code-Pfad -> monitor) anwenden,
  basierend auf CVE-Beschreibung und Host-Kontext. System-Prompt
  fordert „Be a thinking analyst" und Reasoning-Kette im
  reason-Text.
  
  Konsequenzen:
    - monitor wird operativ enger. Default fuer aktive Komponenten
      mit Patch ist jetzt act, nicht mehr monitor.
    - LLM-Bewertung wird weniger deterministisch (Reasoning-Pfade
      koennen variieren). Cache stabilisiert auf Cache-Key-Ebene.
    - Operator wird haeufiger zur Aktion aufgefordert - defensive
      Default-Linie.
    - Reason-Cap zurueck auf 256 Chars (vorher 200 in Iteration 5),
      weil Reasoning-Kette etwas mehr Platz braucht.
  
  Test-Case-Auswirkung gegen die Standard-5-Group-Suite:
  postgresql auf 10.0.0.5:5432 wird jetzt **act** statt vorher
  monitor (HIGH+exposed+has_fix+not_KEV). Andere vier Cases
  unveraendert.
  
  Spaetere Operator-Override-Moeglichkeit als eigene ADR (v0.10.x+):
  expliziter Server-Flag ``network_exposure: airgapped | restricted
  | open``, der die Listener-Heuristik ueberschreibt. Out-of-Scope
  fuer v0.9.3.

- **``LLM_TOKEN_BUDGET_DAILY``-Default auf 2 Mio Tokens angehoben**
  (vorher 1 Mio). Beobachtete Pass-2-Reality ist ~3x hoeher als
  initiale Schaetzung wegen Reasoning-Tokens. Bei realer Flotte
  (~100 Pass-2-Calls/Tag x ~1500 Tokens) bleibt das immer noch
  guenstig (~$1-2/Monat bei DeepInfra-Preisen).

- **``llm_debug_log``-Tabelle** zur Operator-Inspektion von LLM-
  Request/Response-Bodies pro Job. Schema mit ``job_type``,
  ``job_id``, ``server_id``, ``group_id``, ``model``,
  ``request_body`` (jsonb, gecappt 64 KB), ``response_body``
  (jsonb), ``duration_ms``, ``status``, ``error``, ``created_at``.
  Eviction kombiniert Count-Cap (``LLM_DEBUG_LOG_MAX_ROWS=500``,
  default) und Time-Cap (``LLM_DEBUG_LOG_MAX_AGE_DAYS=14``,
  default) — laeuft als Sub-Tick im Worker alle 10 Minuten. Pro-
  Row-Body-Cap bei 64 KB schuetzt vor Riesen-Responses.
  Realistische Last (3k Findings, ~100 Application-Groups,
  ~10 Server-Context-Cluster, taegliches Re-Eval): ~50-150 neue
  Eintraege/Tag, mit 500-Row-Cap deckt das 3-10 Tage Historie ab.
- Neuer Settings-Sub-Tab unter ``/settings/llm-reviewer`` mit den
  letzten 50 Log-Eintraegen, Drill-down auf vollstaendige
  JSON-Bodies (Request + Response inline expandierbar).

### Migration

- Eine neue Alembic-Migration ``XXXX_block_p_v093.py`` mit zwei
  zusammenhaengenden Schema-Aenderungen:
  - ``add_column`` ``action_type`` (varchar(16) NULL) und
    ``group_kind`` (varchar(20) NULL) auf ``application_groups``,
    plus CheckConstraints auf den erlaubten Werten.
  - Backfill-Update fuer bestehende Groups: ``group_kind`` aus
    ``match_rules`` deterministisch berechnen (``application_bundle``
    wenn ``path_prefixes`` non-empty, sonst ``os_package``).
    ``action_type`` bleibt NULL bis zum naechsten Pass-2-Re-Eval.
  - ``create_table`` fuer ``llm_debug_log`` mit Indizes
    (``created_at``, ``(job_type, created_at DESC)``,
    ``group_id WHERE NOT NULL``).
  - FK-Constraints auf ``llm_jobs.id`` / ``servers.id`` /
    ``application_groups.id`` mit ``ON DELETE SET NULL``.
  - Drei neue Settings-Eintraege fuer Eviction-Konstanten.
  - Downgrade: spiegelbildlich (drop_table fuer llm_debug_log,
    drop_column fuer action_type und group_kind).
- **Keine Schema-Aenderung** am ``Finding`` selbst. Das
  ``mitigate``-Deprecation ist rein Prompt-/Output-Verhaltens-
  Aenderung, der Enum-Wert bleibt in der DB zulaessig fuer
  historische Daten.

### Unchanged (bewusst)

- Backend-Validatoren in ``_validate_pass1_response()`` und
  ``_validate_pass2_response()`` bleiben unveraendert. Die
  Validations-Schichten aus v0.9.0 (ID-Treue, Pattern-Konsistenz,
  Pattern-Generizitaet, Band-Whitelist, NUL-Schutz) sind modell-
  agnostisch und greifen auch bei dem neuen Default-Modell und
  4-Band-Output.
- ``ACTION_REQUIRED_MAP`` bleibt unveraendert. ``mitigate`` wird
  weiter als ``yes`` gemappt fuer historische Daten — bleibt
  konsistent mit der Dashboard-„Action needed"-Card.
- Cache-Logik (``llm_risk_cache``), Worker-Loop, Mode-Flag,
  Token-Budget — alles aus v0.9.0 bleibt. Keine Cache-Invalidation
  durch das Prompt-Update noetig: bestehende Cache-Eintraege
  haben weiterhin gueltige Bewertungen, neue Eintraege ueberschreiben
  natuerlich beim naechsten Cache-Miss.

## [v0.9.2] — 2026-05-20

Bugfix-Release. Schliesst eine Distribution-Luecke aus Block-O (ADR-0022),
die die komplette Block-P-LLM-Pipeline auf produzierten Hosts silently
deaktiviert hat.

### Fixed

- **``lib_host_state.sh`` wird vom Bootstrap-Installer mit ausgeliefert.**
  Die in Block O eingefuehrte Host-State-Collector-Library wurde nie ins
  Whitelist-Set in ``app/views/agent_install.py`` aufgenommen und nie
  vom ``/install.sh``-Template heruntergeladen. Folge auf jedem Host
  ohne manuell kopierte Library: der Agent loggt
  ``Warning: lib_host_state.sh not found next to agent; host_state will
  be omitted``, das Envelope landet ohne ``host_state`` am Backend, die
  Pre-Triage greift Regel 1 (kein Snapshot) und setzt **alle** Findings
  auf ``risk_band=unknown``. Der Block-P-Scan-Ingest-Hook filtert aber
  auf ``risk_band=pending`` und queue't damit nie einen Pass-1-Job —
  die LLM-Pipeline laeuft nicht an, der Worker pollt eine leere Queue.

  Zwei Aenderungen, gemeinsam wirksam:
  - ``_AGENT_FILE_WHITELIST`` um ``lib_host_state.sh`` erweitert.
    ``GET /agent/files/lib_host_state.sh`` liefert jetzt ``200``.
  - ``download_agent_script()`` im ``install.sh.j2``-Template auf einen
    Loop ``(secscan-agent.sh, lib_host_state.sh)`` umgestellt. Beide
    Files landen mit Mode 0755 in ``$SECSCAN_BIN_DIR``.

### Tests

- ``tests/views/test_agent_install.py``:
  - ``test_agent_files_serves_lib_host_state_sh`` verifiziert HTTP 200
    + ``text/x-shellscript`` + identifizierenden Marker.
  - ``test_install_sh_downloads_lib_host_state`` greppt das gerenderte
    Installer-Template auf den Loop-Eintrag — Regression-Schutz, falls
    jemand spaeter wieder nur ``secscan-agent.sh`` allein faehrt.

### Compat

- Operator-Hinweis: bereits installierte Hosts profitieren erst nach
  einem Re-Run von ``/install.sh`` (oder einem manuellen ``scp`` der
  Library). Sobald der naechste Scan mit ``host_state`` ankommt, rechnet
  die Pre-Triage automatisch alle ``unknown``-Findings neu — die werden
  zu ``pending``/``monitor``/``noise`` umsortiert und der Block-P-Hook
  queue't dann den Pass-1-Job.

## [v0.9.1] — 2026-05-20

Bugfix-Release. Behebt einen Liveness/Readiness-Probe-Restart-Loop des
``secscan-llm-worker``-Containers unter k3s/RKE2-Realbedingungen.

### Fixed

- **Healthcheck-Skript ``app/workers/healthcheck.py`` schlankgeschnitten.**
  Das Skript importierte bisher ``app.workers.llm_worker`` und zog damit
  die komplette LLM-Service-Lage mit (``openai``-SDK, ``llm_risk_reviewer``,
  ``group_matcher``, ``llm_cache`` plus alle SQLAlchemy-Tabellen). Auf
  einem ARM64-RKE2-Node mit geteilter CPU lag der Cold-Start-Import-Plus-
  DB-Connect zwischen 4-6 Sekunden — k8s-Default ``timeoutSeconds: 5``
  einer Exec-Probe wurde gerissen, drei Failures = SIGTERM, Pod-Restart
  alle ~90 Sekunden. Das Skript liest jetzt nur ``app.config`` plus eine
  schlanke ``sqlalchemy``-Connection und greift per Raw-SQL auf die
  Heartbeat-Spalte zu. Gemessener Cold-Start fällt auf ~0.6-1.0s, passt
  in jedes Probe-Timeout. **Keine Schema-/Verhaltens-Änderung** —
  exit-Codes, Schwellwerte, Edge-Cases bleiben gleich.

### Tests

- ``tests/workers/test_healthcheck.py`` auf neue Injection-API umgestellt
  (``healthcheck._open_connection`` per ``patch.object`` statt der alten
  ``llm_worker.set_session_factory_for_tests``-Kette).
- Neuer Regressions-Test ``test_healthcheck_does_not_import_llm_worker_module``
  spawnt einen Sub-Process, importiert nur ``app.workers.healthcheck``
  und verifiziert, dass weder ``app.workers.llm_worker`` noch eines der
  ``app.services.llm_*``-Module noch ``openai`` in ``sys.modules``
  landen. Verhindert künftige versehentliche Re-Introduktion des Probleme.

### Compat

- Operator-Hinweis: bestehende k8s-Manifeste muessen **nicht** angepasst
  werden. ``timeoutSeconds: 5`` reicht ab v0.9.1 wieder aus.

## [v0.9.0] — 2026-05-19

Block P (ADR-0023) — LLM-Risk-Reviewer mit Application-Grouping
(Two-Pass) + asynchroner Job-Queue + Mode-Feature-Flag + Settings-Tab.

### Added

- **Two-Pass-LLM-Architektur fuer Final-Risk-Bewertung.** Pass 1
  (`group_detection`) erzeugt aus ungroupierten `pending`-Findings (aus
  Block-O-Pre-Triage) neue `application_groups`-Eintraege mit
  wiederverwendbaren Match-Patterns (`path_prefixes` /
  `pkg_name_exact` / `pkg_name_glob` / `pkg_purl_pattern`). Pass 2
  (`risk_evaluation`) bewertet pro Group das `risk_band` mit
  Server-Kontext (compact-form ohne PIDs/args/timestamps,
  ~2-4K Tokens). LLM-Output ueberschreibt Block-O-Pre-Triage-Bands
  nicht direkt — Pass 2 setzt `Finding.risk_band_source='llm'`,
  Pre-Triage-Loop im Ingest skipt diese Findings beim Re-Ingest.
- **Application-Group-Schicht** als neue Tabelle `application_groups`
  plus FK `Finding.application_group_id` (ON DELETE SET NULL). Group-
  Bewertung wird auf alle enthaltenen Findings als Worst-Case-Band
  vererbt. `worst_finding_id`-Verweis (kein FK — Group ueberlebt
  Finding-Delete).
- **Asynchroner Worker** als eigener Container `secscan-llm-worker`
  (entrypoint `python -m app.workers.llm_worker`, keine eingehenden
  Ports, nur DB-Connect + LLM-Provider-Egress). 2s-Polling auf
  `llm_jobs` mit `SELECT FOR UPDATE SKIP LOCKED`, Dependency-Check
  (Pass-2-Jobs warten via `depends_on` auf Pass-1), Stale-Reaper alle
  60s reset `in_progress`-Jobs aelter als 10 min auf `queued` mit
  exponential backoff (max 3 Attempts → `failed`). Heartbeat alle 10s
  in `settings.llm_worker_heartbeat_at`; Healthcheck-Skript
  `app/workers/healthcheck.py` exit 0/1 abhaengig von < 30s
  Heartbeat-Alter.
- **Feature-Flag `BLOCK_P_LLM_MODE`** (Settings-Spalte mit
  CheckConstraint `off`/`observation`/`live`) fuer stufenweise
  Inbetriebnahme. `observation`-Mode schreibt `would_call`-Marker
  statt echter LLM-Calls — ermoeglicht Cache-Befuellung und
  Cost-Math vor Scharfschaltung.
- **Token-Budget** `SECSCAN_LLM_TOKEN_BUDGET_DAILY` (Default 1M) mit
  00:00-UTC-Reset. Sowohl Pass-1- als auch Pass-2-Verbrauch wird
  verbucht (Pre-Tag-Hotfix nach Security-Auditor-Befund). Bei
  Budget-Erschoepfung: Worker pausiert, einmaliges Audit
  `llm.budget_exhausted` pro Reset-Zyklus.
- **Two-Level-Caching.** Pass-1-Cache *ist* die `application_groups`-
  Library (deterministischer Pattern-Match via `GroupMatcher`-
  Singleton mit `_lock`). Pass-2-Cache als `llm_risk_cache`-Tabelle
  mit SHA256-Key ueber
  `(group_id, group_findings_fp, cve_data_fp, server_context_fp)`,
  TTL 30 Tage + LRU bei > 100K Rows. Server-Context-Fingerprint
  enthaelt KEINE PIDs/args/snapshot_at — stabil zwischen Scans.
- **UI auf Group-Cards.** Findings auf Server-Detail werden nach
  `application_group_id` gruppiert mit Group-Cards (Label,
  Risk-Pill, Findings-Count, Reason-Mono-Box, Worst-Finding-Anker,
  Drill-down-`<details>`). Default-expanded ab `pending` aufwaerts,
  default-collapsed fuer `monitor`/`noise`. Ungroupierte Findings
  landen in „Pending grouping"-Sektion am Ende. `evaluating`-State
  mit Spinner solange Worker arbeitet.
- **Dashboard-Findings-Tabelle** bekommt `Group`-Spalte (zwischen
  Risk und Severity) und `application_group`-Filter-Select.
  Default-Sort bleibt `risk` (DESC).
- **Settings-Tab `/settings/llm-reviewer`.** Zeigt Mode +
  Queue-/Library-/Cache-/Token-Stats + Worker-Liveness.
  Master-Key-gated Mode-Wechsel mit DSGVO-Privacy-Notice (Modal
  mit Confirm-Checkbox) beim Wechsel auf `live`; Re-queue-Backlog-
  Button fuer observation→live-Transition. Audit-Events
  `llm.mode_changed` und `llm.backlog_requeued`.
- **LLM-Output-Validierung strikt:** JSON-Schema (OpenAI-`response_format`
  mode), Label-Regex `^[a-z0-9][a-z0-9_-]{0,63}$`, Vollstaendigkeits-
  Check Pass-1 (jedes Input-Finding in genau einer Group ODER
  `ungrouped`), `risk_band ∈ {escalate,act,mitigate,monitor,noise}` —
  `pending`/`unknown` LLM-verboten via Pydantic-Literal +
  Backend-Set-Check + DB-CheckConstraints (Defense-in-Depth dreifach).
  `worst_finding_id` muss Group-Mitglied sein, `reason` ≤ 256 chars,
  NUL-frei. Pattern-Defensiv-Trim gegen Injection (`/etc/passwd`-
  Pfade technisch erlaubt aber harmlos; `*`-only, `"/"`-allein,
  leerer String, Non-ASCII werden gedroppt).
- **DB-Migrationen 0005 + 0006.** 0005: drei neue Tabellen
  (`application_groups`, `llm_jobs`, `llm_risk_cache`), neue
  Finding-Spalte `application_group_id`, neuer Findings-Index
  `ix_findings_application_group`, drei Settings-Spalten
  (`block_p_llm_mode`, `llm_worker_heartbeat_at`,
  `llm_token_budget_used_today`). 0006: Mini-Migration fuer
  `settings.llm_token_budget_reset_at`-Spalte. Kein Backfill.
- **Audit-Events neu:** `llm.mode_changed`, `llm.budget_exhausted`,
  `llm.jobs_queued`, `llm.job_done`, `llm.job_failed`,
  `llm.job_reaped`, `llm.backlog_requeued`, `risk.llm_group_skipped`.

### Changed

- **ARCHITECTURE.md** §7 (Group-Spalte + Filter), §7a (Server-Detail
  Group-Layer mit `evaluating`-State), §12 (neuer Subabschnitt
  „Risk-Reviewer (Block P, ADR-0023)"), §13 (neue Audit-Actions),
  §17 (sieben neue Out-of-Scope-Punkte).
- **`docker-compose.yml`** mit drittem Service `secscan-llm-worker`
  (depends_on db service_healthy, Healthcheck via Python-Skript,
  keine ports).
- **Block-G-LLM-Wrapper** wird vom Risk-Reviewer-Service mitgenutzt
  (gleicher Provider-Pfad, `AsyncOpenAI`-Pattern).

### Compat-Hinweise

- **MIN_AGENT_VERSION bleibt 0.1.0.** Alte Agents 0.2.0/0.3.0 weiter
  akzeptiert.
- **Default-Mode `off`.** Frische Installationen haben den
  LLM-Reviewer deaktiviert; Operator muss bewusst auf `observation`
  oder `live` schalten (Master-Key-gated).
- **DSGVO-Notice beim live-Mode** zeigt der Settings-Tab als Modal mit
  Confirm-Checkbox. Notice ist UX-Schutz; Master-Key ist die echte
  Backend-Schwelle.

### Tests

- **1477 Tests gruen** (Vorher v0.8.0: 1226; Delta +251 — 33 Phase A
  + 46 Phase B + 21 Phase C + 8 Phase D + 25 Phase E + 13 Phase F +
  105 Phase H). Coverage **91.70 %** (Threshold 85 %).
- **421 adversarial PASS** (Vorher: 326; +95 neue Block-P-Cases:
  Pass-1-Halluzination/Missing/Label-Regex/Pattern-Injection/
  Non-ASCII, Pass-2-Halluzination/Invalid-Band/Worst-Not-In-Group/
  NUL-Reason/Reason-Length, Worker-Race-SKIP-LOCKED 2-of-1 + 5-of-3,
  Worker-Corrupted-Payload, Cache-Key-Collision mit Reihenfolge-
  Sensitivitaet).
- **10 Block-P-E2E-Integration-Tests** (`test_block_p_e2e_observation`,
  `test_block_p_e2e_live`, `test_block_p_mode_switch`) gruen.
- `ruff check` + `ruff format --check` + `mypy app/` (68 source files)
  + `shellcheck agent/*.sh` PASS. Alembic-Roundtrip 0004↔0005↔0006
  PASS gegen Postgres-17. `docker build` + `docker compose up
  --build` startet drei Container alle healthy nach ~30s. Image-Size
  **192 MB** (Delta +1 MB vs. v0.8.0).

### Security-Auditor-Notes

ACCEPTABLE WITH NOTES → SECURITY APPROVED. Alle 10 Pflicht-Punkte
PASS: LLM-Output-Validation strikt, `pending`/`unknown` LLM-verboten
(dreifach: Pydantic-Literal + Set-Check + DB-CheckConstraints),
Worker-Container ohne eingehende Ports, Mode-Wechsel master_key-gated,
Token-Budget-Cap funktioniert (inkl. Pre-Tag-Hotfix Pass-1-Buchung),
`risk_band` hat keinen direkten User-Input-Pfad, Worker-Race mit
SKIP-LOCKED bewiesen, DSGVO-Notice mit Confirm-Checkbox plus
Master-Key-Backend-Gate, Pattern-Defensiv-Trim gegen Injection,
Cache-Key deterministisch und Reihenfolge-sensitiv. Drei optionale
Re-Open-Trigger als Folge-PR-Kandidaten: Worker-Logging auf structlog
umstellen, `ON CONFLICT DO NOTHING` in `_persist_pass1_groups` fuer
Multi-Worker-Skalierung, Setup-Wizard-DSGVO-Notice mit konkreter
Feld-Liste.

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
