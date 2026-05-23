## ADR-0029 — Parallele LLM-Job-Verarbeitung im Worker (Single-Worker, In-Process-Concurrency)

**Status:** Akzeptiert · **Akzeptiert:** 2026-05-22 · **Datum:** 2026-05-22 · **Block:** U (Implementation, siehe `docs/blocks/U-worker-concurrency.md`) · **Bezug:** Erweitert ADR-0023 (LLM-Risk-Reviewer-Worker-Architektur, Two-Pass, Single-Concurrency-Default). Tangiert ADR-0010 (LLM-Provider-Abstraktion — Client-Lifecycle), ADR-0014 (Token-Cap Best-Effort — Overshoot bleibt akzeptiert), ADR-0028 (Junction-Persistierung — Pass-2-Cache-Race-Behandlung). ADR-0019 (Polling statt SSE) und ADR-0026 (Async-Scan-Ingest) unberührt.

## Kontext

Heutige `_tick()`-Schleife in `app/workers/llm_worker.py` verarbeitet einen LLM-Job pro Loop-Iteration: `_pick_next_job_id()` liefert eine Job-ID via `SELECT FOR UPDATE SKIP LOCKED LIMIT 1`, danach läuft `asyncio.run(_process_live(job_id))` mit einem neuen Event-Loop und einem frisch gebauten `AsyncOpenAI`-Client. Single-Concurrency war für Block P (v0.9.0) eine bewusste Architektur-Entscheidung — der MVP-Worker brauchte keine Parallelität, und Provider-Rate-Limits waren nicht ausgelotet.

Operator-Befund seit v0.9.4 / v0.9.5 / v0.10.0 unter Realbetrieb mit 9 000-Findings-Flotte:

1. **Pass-1-Backlog dominiert die Wallclock.** Nach einem Initial-Scan oder Re-Eval entstehen ~90 Pass-1-Jobs à 100 Findings (siehe v0.9.4-Batching). Bei Single-Concurrency und ~30–60 s LLM-Latenz pro Call bedeutet das 45–90 min Wallclock-Backlog bevor Pass-2 überhaupt starten kann. Der Operator wartet, obwohl die LLM-Provider-API massive Kapazität ungenutzt lässt.
2. **DeepInfra erlaubt deutlich mehr Parallelität pro API-Key** als wir nutzen — in der Praxis >200 gleichzeitige Requests ohne 429-Drosselung. Andere Provider (OpenAI Tier-3/4, lokale vLLM-Setups) ebenso. Wir liegen permanent zwei Größenordnungen unter dem was technisch möglich wäre.
3. **Pass-2-Pipeline ist sequenziell trotz Cache-Hit-Dominanz.** Nach dem ersten Re-Eval ist `llm_risk_cache` zu >95 % befüllt; Cache-Hits brauchen <100 ms, blockieren aber trotzdem den einzigen Pickup-Slot. Bei 200 Server × 5 Groups = 1000 Pass-2-Jobs ist das ~2 min Backlog allein durch Sequenzialität, nicht durch LLM-Latenz.

Multi-Worker-Container (zweiter `secscan-llm-worker`-Pod) wäre ein Skalierungs-Pfad, würde aber verteiltes Rate-Limiting, gemeinsame Budget-Buchhaltung und Multi-Instance-Heartbeat-Logik erfordern — das ist explizit Out-of-Scope laut ARCHITECTURE.md §17 und ADR-0023. Die natürliche nächste Skalierungsstufe ist **In-Process-Concurrency innerhalb des einen Worker-Prozesses**.

Der bestehende Code ist dafür gut vorbereitet: `_do_pass1`, `_do_pass2`, `pass1_detect_groups`, `pass2_evaluate_groups`, `chat_completion_json_with_meta` sind alle bereits `async`. Was fehlt ist ein gemeinsamer Event-Loop und eine `asyncio.Semaphore`-basierte Begrenzung statt der heutigen `asyncio.run`-Pro-Job-Schale.

## Entscheidung

ADR-0029 führt sieben zusammenhängende Änderungen ein, alle innerhalb eines Worker-Prozesses (kein Multi-Container-Scope):

### 1. asyncio + Semaphore, ein Event-Loop pro Worker-Prozess

`main()` wechselt von der synchronen `while not _shutdown: _tick()`-Schleife auf `asyncio.run(_run_async_main())`. `_run_async_main()` baut eine `asyncio.Semaphore(N)` aus dem aktuellen Settings-Wert `llm_worker_job_concurrency` und hält ein `in_flight: set[asyncio.Task]`. Die Sub-Ticks (Stale-Reaper, Debug-Log-Eviction, Feed-Pull-Check, Scan-Ingest-Sub-Tick, Retention-Sweep) laufen synchron *zwischen* den Refill-Iterationen — nicht parallel zu LLM-Tasks. Heartbeat-Daemon-Thread (v0.9.5) bleibt unverändert.

ThreadPoolExecutor wurde verworfen wegen 200-fachem `AsyncOpenAI`-Client-Setup ohne Connection-Reuse und ~50–100 MB RAM-Overhead beim Worst-Case-N=200. Hybrid-Modell (async LLM + Threadpool-DB) wurde verworfen wegen MVP-overdimensioniertem Refactor-Aufwand bei heute durchgängig <50-ms-DB-Sessions.

### 2. Greedy Slot-Refill mit unverändertem Pickup-SQL

Der Dispatcher hält N Slots gefüllt: sobald irgendein Task `done`/`failed` zurückkommt (`asyncio.wait(in_flight, return_when=FIRST_COMPLETED)`), wird sofort der nächste Single-Job-Pickup gemacht. Das bestehende `_pick_next_job_id()`-SQL bleibt **unverändert** (`LIMIT 1 FOR UPDATE SKIP LOCKED`), inklusive Dependency-Check und Pass-2-Sibling-Wait — `SKIP LOCKED` ist concurrency-safe auch innerhalb desselben Prozesses.

Batch-Pickup (`LIMIT N` pro Statement) wurde verworfen: Job-Latency bei neuen Eingängen würde bis zum Batch-Ende stallen, und die Pass-2-Sibling-Wait-Bedingung wird bei N-Pickup komplizierter zu reasonen.

### 3. Settings-Spalte `llm_worker_job_concurrency`

Neue `INT NOT NULL DEFAULT 1` auf der Settings-Singleton-Row mit `CHECK BETWEEN 1 AND 200`. Pydantic-Field-Spiegel in `app/config.py` mit `ge=1, le=200`. Default 1 ist backward-compatible — bestehende Deploys ändern beim Migration-Lauf ihr Verhalten nicht. Operator regelt manuell in `/settings/llm-reviewer` hoch.

Bewusst **eine globale Concurrency** (kein Pass-1/Pass-2-Split): MVP-Vereinfachung. Falls in der Praxis Pass-1-Burst-Last Pass-2-Cache-Hit-Throughput beeinträchtigt, wäre das ein eigener Folge-ADR.

### 4. Hot-Reload alle 30 s, analog Mode-Cache

Der Concurrency-Wert wird im Dispatcher beim Slot-Refill aus dem `_get_mode_throttled`-vergleichbaren Cache gelesen (neue Helper `_get_concurrency_throttled` mit `CONCURRENCY_CHECK_INTERVAL_SEC = 30.0`). Bei Erhöhung füllt der nächste Refill-Zyklus zusätzliche Slots. Bei Senkung werden neue Picks gepausiert bis `len(in_flight) <= N_new`. Operator-Action wirkt binnen <30 s ohne Pod-Restart. Audit-Event `llm.concurrency_changed from=N to=M` einmal pro tatsächlicher Änderung.

### 5. Persistenter `AsyncOpenAI`-Client mit Fingerprint-Detection

Ein gemeinsamer `AsyncOpenAI`-Client für den ganzen Worker-Prozess, der seinen `httpx.AsyncClient`-Connection-Pool über alle Jobs hinweg wiederverwendet. Modul-State `_client` plus `_client_fingerprint: tuple[str, str, str]` über `(base_url, model, sha256(api_key))`. Vor jedem Slot-Refill kurzer Settings-Read → Fingerprint-Vergleich → bei Mismatch alten Client `close()`, neuen bauen, Log-Marker `llm_worker.client_rebuilt reason=fingerprint_changed`.

Wirkung: bei DeepInfra wird die TLS-Connection zu `api.deepinfra.com` wiederverwendet (httpx-Keep-Alive). Statt 200 TLS-Handshakes pro Refill-Wave laufen alle Calls über ~10–20 persistente Connections. Eingesparte Latenz pro Call 50–200 ms, eingesparte CPU im Container 5–15 %. Provider-Wechsel via `/settings/llm` wirkt beim nächsten Refill (binnen <2 s, plus 30 s Concurrency-Cache-Window beim Worst-Case-Timing).

In-flight Jobs bei Provider-Wechsel nutzen den alten Client über ihre Task-Closure-Variable zu Ende — keine Mid-Call-Abrisse.

### 6. DB-Pool-Sizing beim Start aus Concurrency abgeleitet

Im `_get_session_factory()`-Helper wird beim ersten Aufruf der aktuelle `llm_worker_job_concurrency`-Wert gelesen und die Engine mit `pool_size = max(N * 2, 10)`, `max_overflow = N`, `pool_pre_ping = True` gebaut. **Pool-Größe ist nicht hot-reloadable** — das würde Engine-Rebuild erfordern, was MVP-overkill ist. Concurrency-Senkungen innerhalb des einmal-gewählten Pool-Caps sind sofort wirksam; Concurrency-Erhöhungen über den initialen Pool-Cap hinaus erfordern Pod-Restart.

Pool-Größen-Auslegung: ein Pass-1-Job hält pro Slot 1–3 kurze Sessions hintereinander (Pickup, Hydrate, Persist); bei N parallelen Jobs sind die Sessions zeitlich nicht überlappend (Sessions sind je <50 ms), aber Pickup-Session und Persist-Session können kollidieren. `pool_size = 2N` lässt Headroom für Sub-Ticks (Stale-Reaper, Eviction) parallel zu laufenden Job-Sessions. `max_overflow = N` als Sicherheitsnetz für Spike-Last.

### 7. Pass-2-Cache-Store mit `ON CONFLICT (cache_key) DO NOTHING`

Bei parallelen Pass-2-Jobs für dieselbe `(group, server-context)` produzieren beide Jobs denselben `cache_key = SHA256(group_id|group_findings_fp|cve_data_fp|server_context_fp)` und versuchen `INSERT` in `llm_risk_cache`. Heutiges Statement würde am Unique-Constraint failen. Umstellung auf `pg_insert(LLMRiskCache).values(...).on_conflict_do_nothing(index_elements=['cache_key'])`. Semantisch unproblematisch: deterministischer Cache-Key impliziert identische LLM-Antwort, ergo ist „Erster gewinnt, Zweiter verwirft" verlustfrei.

Die separate Eval-Junction `application_group_evaluations` (ADR-0028) ist davon unberührt — die ist per `(group_id, server_id)` partitioniert und nutzt bereits `on_conflict_do_update`.

## Konsequenzen

**Positiv:**

- Pass-1-Backlog-Wallclock bei 9 000-Findings-Flotte sinkt von 45–90 min auf ~5–15 min bei N=20, auf ~2–5 min bei N=200 (LLM-Latenz dominiert, nicht Pickup-Sequenzialität).
- Pass-2-Cache-Hit-Throughput steigt linear mit N — bei 200 Servern × 5 Groups vollständig durch in <15 s.
- Persistenter `AsyncOpenAI`-Client reduziert Worker-Container-CPU spürbar (5–15 %) und Provider-API-Latenz (TLS-Reuse).
- Backward-compat: Default-Concurrency 1 ändert für bestehende Deploys nichts beim Migrations-Lauf. Operator wählt Hochregeln bewusst.
- Provider-Wechsel über `/settings/llm` bleibt im selben UX-Muster wie heute (kein neuer Reload-Button, kein Pod-Restart-Hinweis).

**Negativ / akzeptierte Risiken:**

- **Event-Loop-Stall-Risiko durch sync SQLAlchemy** in Persist-Phasen. Heute sind alle Sessions <50 ms, aber bei N=200 könnten kumulierte Persist-Phasen den Loop blockieren und LLM-Calls warten lassen. **Re-Open-Trigger:** wenn Profiling messbare Stalls zeigt, einzelne Hotspots auf `asyncio.to_thread(...)` umstellen oder Async-SQLAlchemy-Driver (`asyncpg`) evaluieren — eigener Folge-Block, nicht Block U.
- **Token-Budget-Overshoot bei N=200.** Der heutige 60-s-Budget-Cache (v0.9.6) bleibt unverändert. Im Worst-Case kann ein einzelnes Cache-Window mit voller Queue ~5 M Tokens reinpacken bevor der nächste Check den `exhausted`-Marker setzt. Bewusst akzeptiert für MVP — paar Prozent über `daily_limit` ist operativ irrelevant, kein stundenlanger Free-Pass. **Re-Open-Trigger:** wenn der Realbetrieb wiederholt mehr als ~10 % über dem `daily_limit` landet, Folge-ADR mit reserviertem In-Flight-Counter (Pre-Pickup-Budget-Math addiert `estimate_tokens(job)` zur „reservierten" Summe und gibt sie post-Done frei).
- **Debug-Log-Tabelle explodiert** bei N=200 ohne Mitigation (~400 Inserts/min, heute 10-min-Eviction-Cadence und 500-Row-Cap → ~75 s sichtbares Forensik-Fenster, ~80 MB transient zwischen Sweeps). **Mitigation in Block U Phase G** (Sampling 1:10 für Successes, Eviction-Cadence 600 s → 60 s, CTE-DELETE statt `NOT IN`, Default-Anhebung `llm_debug_log_max_rows` 500 → 2000). **Re-Open-Trigger:** status-getrennter Count-Cap (separate Buckets für Success vs. Error) falls Realbetrieb zeigt dass Error-Forensik unter dem Sampling leidet.
- **Logging-Lärm bei N=200.** Per-Job-Phasen-Logs (`pass1_started`, `llm_call_started`, `…_completed`, `…_persist_done`, `cache_lookup`, `cache_hit_applied`, `job_picked`, `job_done`) würden ~5–10 INFO-Lines × N pro Job-Wave erzeugen — unlesbar. **Mitigation in Block U Phase F:** diese Per-Job-Logs werden **komplett entfernt**, strukturierte Per-Job-Inspektion läuft ausschließlich über `llm_debug_log`-Tabelle. Statt dessen alle 30 s ein aggregierter `llm_worker.status`-Snapshot mit `in_flight`, `queued`, `done_30s`, `failed_30s`, `cache_hits_30s`, `budget_pct`, `avg_call_ms`. Fehler/Warnungen bleiben per-Job sichtbar.
- **Pool-Größe nicht hot-reloadable.** Erhöhung der Concurrency über den initialen Pool-Cap hinaus erfordert Pod-Restart. Operator wählt also beim ersten Hochregeln idealerweise das Ziel-N (oder mit Reserve). In der Praxis irrelevant solange Operator die Concurrency nicht in 200-er-Schritten von 1 ausgehend hochfährt.

## Out of Scope (explizit)

- **Multi-Worker-Container.** Zweiter `secscan-llm-worker`-Pod, verteiltes Rate-Limit (Redis), gemeinsame Token-Budget-Buchhaltung über Instanzen, Multi-Instance-Heartbeat. Bleibt out of MVP (ADR-0023 §17, ARCHITECTURE.md §17).
- **Per-Provider-Concurrency-Profile.** Heute eine globale Concurrency unabhängig vom Provider. DeepInfra erlaubt 200+, OpenAI-Tier-1 erlaubt 50, lokale vLLM-Setups je nach GPU. Operator setzt manuell den niedrigsten gemeinsamen Nenner. Falls operativ schmerzhaft: Settings-Tabelle mit Provider-spezifischen Caps als Folge-ADR.
- **Adaptive Concurrency / Auto-Throttle bei 429.** Bei Provider-Rate-Limit-Treffer würde der Worker heute einfach `LLMTimeoutError`/`LLMInvalidResponseError`-Retry-Pfad nutzen. Kein automatisches Hochregeln nach Erfolg, kein automatisches Senken nach 429. Bewusst out of MVP.
- **LLM-Chat-Concurrency** (Block-G-Chat-Surface). Andere Codebase, andere Failure-Modes, andere UX (User wartet synchron). Eigene Folge-ADR falls je nötig.
- **Pass-1/Pass-2-Concurrency-Split.** Eine globale Concurrency reicht für MVP. Falls Pass-1-Burst-Last Pass-2-Cache-Hit-Throughput beeinträchtigt: Folge-ADR.
- **Dynamische DB-Pool-Größen-Anpassung ohne Engine-Rebuild.** Aus dem oben genannten Grund weggelassen.

## Re-Open-Trigger (Zusammenfassung)

1. Event-Loop-Stall durch sync SQLAlchemy unter hoher Concurrency-Last → `asyncio.to_thread` für Hotspots oder Async-Driver.
2. Token-Budget-Overshoot >10 % → reservierter In-Flight-Counter mit Pre-Pickup-Math.
3. Debug-Log-Sampling versteckt zu viele Successes für Error-Korrelation → status-getrennter Count-Cap (separate Buckets Success vs. Error).
4. Pass-1-Burst-Last beeinträchtigt Pass-2-Cache-Hit-Throughput → Per-Pass-Concurrency-Split.
5. 429-Rate-Limit-Treffer häufen sich bei festem N → adaptive Concurrency mit Auto-Throttle.

## Implementations-Verweis

Implementierungs-Plan, Phasen und DoD-Items siehe `docs/blocks/U-worker-concurrency.md`. Block U landet als zusammenhängendes Patch-Release v0.11.0 (kein Hybrid-Modus möglich — die Default-Concurrency 1 macht den Cutover atomar und risikoarm).
