# Orchestrator-State

Single source of truth für den Implementierungs-Fortschritt. Wird von der Hauptsession bei jedem Start gelesen und nach jedem Block-Übergang aktualisiert.

## Status

**Block Q geplant — Server-Detail- und Dashboard-Entschlackung, dedizierte Findings-Seite — Spec abgenommen 2026-05-21.** Zielversion v0.10.0, Branch `feat/block-q-slim-down`, Spec [ADR-0025](../decisions/0025-server-detail-and-findings-slim-down.md), Tasks [docs/blocks/Q-slim-down.md](Q-slim-down.md). Auslöser: Operator-Befund 2026-05-21 zu langer Render-Zeit auf `/servers/<id>` (Code-Analyse identifizierte N+1 in `_load_application_groups_for_server`, Eager-Render aller Group-Drill-down-Tabellen, 272 ungroupierte Findings als verstecktes DOM auf einer k3s-Fixture); plus organisatorischer Wunsch Dashboard und Findings-Triage als zwei separate Surfaces zu trennen.

**Was Block Q tut (fünf Punkte, kein neues Feature, reiner Umbau):**

1. **Findings-Modi `gruppiert` und `diff` ersatzlos entfernen.** Code (`compute_diff`, `DiffSection`, `group_findings_by_package`, `PackageGroup`), Templates (`_view_group.html`, `_view_diff.html`), CSV-Mode-Varianten und Tests werden gestrichen. `?mode=group`/`?mode=diff`-URLs werden still ignoriert, rendern den List-Pfad.
2. **Application-Group-Cards default collapsed, Findings via HTMX lazy.** Neuer Endpoint `GET /servers/<id>/groups/<gid>/findings`. Initial-Render reduziert auf 1 GROUP-BY-Counts-Query plus Group-Metadaten plus Worst-Finding-Batch — die heutige Per-Group-Findings-Query-Schleife entfällt.
3. **Pending-Grouping-Sektion gleich behandelt.** Initial-Render = 1 GROUP-BY-Counts-Query nach `risk_band`. Pro Band ein collapsed `<details>` mit Pill plus Count; Findings via Lazy-Endpoint `GET /servers/<id>/findings/pending?risk_band=<band>`.
4. **`active`-Status-Pille aus dem Server-Detail-Header.** Pill-Reihe nur noch für revoked/retired plus auffällige Marker (stale, db veraltet, agent-/trivy-outdated). Settings-Server-Liste behält die Pille (anderer Kontext).
5. **Cross-Server-Findings-Tabelle wandert auf neue `/findings`-Seite.** Neuer Nav-Eintrag neben „Dashboard", Default-State leer (Empty-State mit `total_findings`-Counter), expliziter „Anwenden"-Submit (kein Auto-Submit mehr), klassische nummerierte Pagination mit 50 Findings/Seite. Dashboard verliert die Findings-Section ersatzlos; KPI-Cards, Risk-Band-Pills und Severity-Strip bleiben. KPI-Card-Klicks zeigen jetzt auf `/findings?…`.

**Was Block Q bewusst nicht tut:**

- *Triple-Aggregations-Konsolidierung im Server-Detail-Header.* Die drei `_load_findings()`-Aufrufe in `compute_tendency` + `severity_snapshots_for_server` + `daily_severity_counts_for_server` (drei identische DB-Queries plus drei O(F×50)-Python-Loops über dieselbe Datenbasis) bleiben unberührt — separater Performance-Folge-Block (vermutlich Block R) mit Re-Open-Trigger in ADR-0025.
- *Endless-Scroll auf Findings.* Page-based gewinnt wegen URL-Stabilität, Bookmark-Tauglichkeit und CSV-Scope-Klarheit.
- *Bulk-Ack über Application-Group-Grenzen.* Selection-Scope bleibt auf expandierte Cards beschränkt.
- *Statusänderung an ADR-0018/0020 auf `Superseded by ADR-0025`.* Optionaler Doku-PR nach Block-Q-Merge, nicht Teil des Blocks.
- *Mobile-responsive Findings-Tabelle.* Out-of-scope per ADR-0009.

**Vorgehensweise:**

Phase A (Modi-Ausbau) → Phase B (Group-Cards Lazy) → Phase C (Pending Lazy) → Phase D (Header-Pille) → Phase E (Findings-Seite + Dashboard-Schrumpfung) → Phase F (Spec-Edits) → Phase G (Verifikation, Performance-Bench, CI-Gates). Reviewer ist über Spec-Touchpoints in ARCHITECTURE.md §7 (Server-Detail-Sektion plus neue `/findings`-Erwähnung) plus ADR-0025-Bezug zu informieren.

**Keine Schema-Migration.** Alle Änderungen sind Code/Template/Test/Doku.

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

(keiner — v0.9.3-Patch abgeschlossen 2026-05-20, nächster Block oder Patch per User-Entscheidung)

## Completed

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

## Aktive Blocker

(keine)

## Offene ADR-Wünsche

(keine — ADR-0023 deckt Block P komplett ab. Drei optionale Re-Open-Trigger aus Security-Auditor-Bericht: Worker auf structlog umstellen, `ON CONFLICT DO NOTHING` in `_persist_pass1_groups` fuer Multi-Worker-Skalierung, Setup-Wizard-DSGVO-Notice mit konkreter Feld-Liste. Wenn Implementer eine neue Architektur-Entscheidung braucht, hier eintragen und Spec ergänzen bevor Code geschrieben wird.)

## Update-Konvention

- Beim Block-Start: Status auf "in progress" setzen, Branch-Name notieren.
- Beim Block-Abschluss (nach `reviewer`-Freigabe): Block in "Completed" verschieben mit Datum, nächsten Block als "Aktueller Block" markieren.
- Bei neuen Blockern: in "Aktive Blocker" eintragen mit Datum und Beschreibung.
- Aktive Blocker MÜSSEN aufgelöst sein bevor der Block als completed markiert wird.
