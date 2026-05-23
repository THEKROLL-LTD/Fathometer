# Block U — Parallele LLM-Job-Verarbeitung im Worker

**Spec-Quelle:** [ADR-0029](../decisions/0029-parallel-llm-worker-concurrency.md)
**Branch:** `feat/block-u-worker-concurrency`
**Zielversion:** v0.11.0
**Vorgänger:** Block T (v0.10.x, ADR-0028 Junction). Block R (Async-Ingest, ADR-0026) ist unabhängig und kann vor oder nach Block U landen.
**Status:** Geplant

## Ziel

`secscan-llm-worker` verarbeitet mehrere LLM-Jobs gleichzeitig innerhalb eines einzigen Worker-Prozesses. Konfigurierbar über `settings.llm_worker_job_concurrency ∈ [1, 200]` mit Default 1 (backward-compatible). Persistenter `AsyncOpenAI`-Client mit TLS-Connection-Reuse, Hot-Reload des Concurrency-Werts binnen <30 s, Logging-Refactor mit Status-Snapshot statt Per-Job-Lärm, Debug-Log-Skalierung mit Insert-Sampling und schnellerer Eviction.

**Nicht-Ziele:** Multi-Worker-Container, verteiltes Rate-Limit, Pass-1/Pass-2-Concurrency-Split, adaptive Concurrency, LLM-Chat-Surface — siehe ADR-0029 §Out of Scope.

## Spec-Referenzen (Pflicht-Lektüre)

1. **ADR-0029 komplett** — Architektur-Entscheidung, sieben Punkte, Konsequenzen.
2. **ADR-0023 §Worker-Architektur** und §"Update v0.9.5/v0.9.6" — Heartbeat-Daemon, Mode-/Budget-Cache, Idle-Backoff. Ändert sich teilweise.
3. **ADR-0028 §Pass-2-Persistierung** — Junction-UPSERT, `on_conflict_do_update`. Wird in Phase D als Vorbild für `on_conflict_do_nothing` im Cache-Store referenziert.
4. **`app/workers/llm_worker.py`** komplett — Tick-Loop, Pickup, `_process_live`, Heartbeat, Sub-Ticks. Hauptangriffsfläche.
5. **`app/services/llm_client.py`** — `build_client_from_settings`, URL-Whitelist. Bleibt unverändert; Block U konsumiert nur.
6. **`app/services/llm_cache.py::store`** — Pass-2-Cache-Insert. Phase D ändert ein Statement.
7. **`app/services/llm_debug_log.py`** — `record`, `evict_old`. Phase G ändert beide.
8. **`app/config.py`** Settings-Block-P (`llm_pass1_max_tokens` bis `worker_stale_timeout_min`) — neue Felder reihen sich hier ein.
9. **`app/models.py`** Settings-Modell-Klasse — neue Spalte plus CheckConstraint.
10. **CLAUDE.md §"Test-Konvention — Default vs. On-Demand"** — Verbindlich für jeden Implementer-Agenten.

## Modell-Änderungen

Neue Settings-Spalte (Singleton-Row in `settings`):

| Spalte | Typ | Constraints | Default |
|---|---|---|---|
| `llm_worker_job_concurrency` | `INT NOT NULL` | `CHECK BETWEEN 1 AND 200`, `ck_settings_llm_worker_job_concurrency` | `1` |
| `llm_debug_log_success_sample_rate` | `INT NOT NULL` | `CHECK BETWEEN 1 AND 1000`, `ck_settings_llm_debug_log_success_sample_rate` | `10` |

Keine neue Tabelle, keine FK-Ziele, keine Index-Änderungen. Pydantic-Spiegel in `app/config.py` mit `ge`/`le`.

## Phasen

### Phase A — Schema + Settings

**Dateien:** `alembic/versions/00XX_block_u_worker_concurrency.py` (Nummer = nächste freie nach Block-T-Migration), `app/config.py`, `app/models.py`.

**Upgrade-Pseudocode:**

```python
op.add_column(
    "settings",
    sa.Column("llm_worker_job_concurrency", sa.Integer(), nullable=False, server_default="1"),
)
op.add_column(
    "settings",
    sa.Column("llm_debug_log_success_sample_rate", sa.Integer(), nullable=False, server_default="10"),
)
op.create_check_constraint(
    "ck_settings_llm_worker_job_concurrency",
    "settings",
    "llm_worker_job_concurrency BETWEEN 1 AND 200",
)
op.create_check_constraint(
    "ck_settings_llm_debug_log_success_sample_rate",
    "settings",
    "llm_debug_log_success_sample_rate BETWEEN 1 AND 1000",
)
```

`Setting`-Modell um zwei `Mapped[int]`-Spalten erweitern, `__table_args__` um die zwei `CheckConstraint`-Einträge. `Settings`-Pydantic-Class in `app/config.py` um zwei Felder mit `Field(default=..., ge=..., le=...)` und `SECSCAN_LLM_WORKER_JOB_CONCURRENCY`/`SECSCAN_LLM_DEBUG_LOG_SUCCESS_SAMPLE_RATE`-Env-Var-Override.

`llm_debug_log_max_rows`-Default wird im selben Commit von `500` auf `2000` angehoben (kein Schema-Change, nur Pydantic-Default).

**Tests:**

- `tests/alembic/test_00XX_block_u.py` — Reflection-Schema-Properties (zwei neue Spalten, beide CheckConstraints, Default-Werte stimmen).
- `tests/config/test_settings_concurrency.py` — Pydantic-Bounds (1, 200 PASS; 0, 201 FAIL), Env-Var-Override.

**DoD-A:**

1. Migration-File commit-bar, Upgrade/Downgrade implementiert.
2. `mypy app/config.py app/models.py` PASS.
3. Pure-Unit-Tests grün, neue Tests >= 4 Fälle.
4. **Heavy-Suiten (Alembic-Roundtrip gegen Postgres) ausschließlich auf User-Anweisung** — der Implementer-Agent stoppt mit „A-DoD bis auf Roundtrip grün, User für `pytest -m db_integration` triggern".

### Phase B — Persistenter Async-Client mit Fingerprint-Cache

**Dateien:** `app/workers/llm_worker.py` (Reviewer-/Client-Bau-Sektion ab Zeile ~1475).

Neue Modul-Helper:

```python
_client: AsyncOpenAI | None = None
_client_fingerprint: tuple[str, str, str] | None = None
_client_lock: asyncio.Lock | None = None  # lazy, im async-Kontext gebaut

async def _get_or_build_async_client(session: Session) -> tuple[AsyncOpenAI, str]:
    """Gibt persistenten Client zurück, rebuilt bei Fingerprint-Mismatch.

    Fingerprint = (base_url, model, sha256(api_key_klartext)).
    Bei Mismatch: alten Client `await aclose()`, neuen bauen.
    Log-Marker `llm_worker.client_rebuilt`.
    """
```

`_build_reviewer` bleibt für Tests-Hook (`_reviewer_factory`), wird aber im Live-Pfad durch `_get_or_build_async_client` plus `LLMRiskReviewer(client=...)`-Wrapping ersetzt. `_aclose_reviewer_client` bleibt für Test-Mock-Reviewers; im Live-Pfad wird der persistente Client NICHT pro Job geschlossen.

**Tests:** `tests/workers/test_llm_worker_async_client.py`:

1. Erster Call → Client wird gebaut, Fingerprint gesetzt.
2. Zweiter Call mit unveränderten Settings → derselbe Client-Objekt-ID zurück.
3. Settings-Change `base_url` → Fingerprint mismatch, alter Client `aclose()` aufgerufen, neuer Client.
4. Settings-Change nur `api_key` (gleiches `base_url` + `model`) → Rebuild.
5. Defensive Mock-Reviewer ohne `client`-Attribut → `_aclose_reviewer_client` no-op (Regression-Schutz für Test-Hooks).

**DoD-B:**

1. Helper implementiert, im Live-Pfad eingebaut.
2. Pure-Unit-Tests grün, >= 5 Fälle.
3. `mypy --strict app/workers/llm_worker.py` PASS.

### Phase C — Async-Dispatcher mit Greedy Slot-Refill

**Dateien:** `app/workers/llm_worker.py` (`main()`, `_tick()` → `_run_subticks()`, neuer `_run_async_main()`, neuer `_dispatcher_loop()`).

`main()` wird zu:

```python
def main() -> None:
    logging.basicConfig(...)
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)
    _start_heartbeat_thread()
    log.info("llm_worker.starting worker_id=%s mode=%s", WORKER_ID, _read_mode_safe())
    try:
        asyncio.run(_run_async_main())
    finally:
        _stop_heartbeat_thread(timeout=5.0)
        log.info("llm_worker.shutdown_complete worker_id=%s", WORKER_ID)
```

`_run_async_main()`:

```python
async def _run_async_main() -> None:
    in_flight: set[asyncio.Task] = set()
    cap = _get_concurrency_throttled()
    log.info("llm_worker.dispatcher_started concurrency=%s", cap)
    while not _shutdown:
        _run_subticks()  # synchron — Reaper, Eviction, Feed-Pull, Ingest, Retention
        cap = _get_concurrency_throttled()  # Hot-Reload, max 30s Latenz
        # Greedy Refill bis cap, aber nur picken wenn cap-Senkung erlaubt.
        while not _shutdown and len(in_flight) < cap:
            mode = _get_mode_throttled()
            if mode == "off" or not _budget_ok_throttled():
                break
            job_id = _pick_next_job_id()
            if job_id is None:
                break
            t = asyncio.create_task(_process_one_async(job_id, mode))
            in_flight.add(t)
            t.add_done_callback(in_flight.discard)
        _maybe_emit_status_snapshot(in_flight=len(in_flight), cap=cap)
        if not in_flight:
            await asyncio.sleep(_compute_idle_sleep())  # Backoff wie heute
            continue
        # Mindestens ein Task fertig abwarten, dann sofort refillen.
        done, _ = await asyncio.wait(in_flight, return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            _record_task_completion(t)  # Counter-Increment für Snapshot
    # Shutdown-Drain.
    if in_flight:
        log.info("llm_worker.shutdown_drain in_flight=%s waiting_max_sec=30", len(in_flight))
        try:
            await asyncio.wait_for(
                asyncio.gather(*in_flight, return_exceptions=True),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            log.warning("llm_worker.shutdown_drain_timeout in_flight=%s", len(in_flight))
```

`_process_one_async(job_id, mode)` ist die neue Single-Job-Coroutine: dispatcht zu Observation/Live wie heute, fängt Exceptions ab, ruft `_requeue_or_fail`, ruft `_record_task_completion`.

`_tick()` wird zu `_run_subticks()` (synchron, kein `_get_mode_throttled`-Check, weil Mode/Pickup im Dispatcher-Loop liegen). Heartbeat-Daemon-Thread bleibt unverändert.

Hot-Reload-Implementierung (`_get_concurrency_throttled`): genauso strukturiert wie `_get_mode_throttled`, mit `CONCURRENCY_CHECK_INTERVAL_SEC = 30.0` und Log-Marker `llm_worker.concurrency_changed from=N to=M` bei Wechsel.

Idle-Backoff (`_compute_idle_sleep`): heutige `_idle_sleep_and_backoff`-Logik. Beim erfolgreichen Pickup `_reset_idle_backoff()` wie heute.

**Tests:** `tests/workers/test_llm_worker_dispatcher.py`:

1. N=1 → Verhalten identisch mit heutigem `_tick()` (1 Task aktiv, Refill nach Done).
2. N=5, 10 Jobs in Queue → Dispatcher hält 5 Slots gefüllt bis Queue leer.
3. N=200, 250 Jobs → maximal 200 in_flight, FIFO-ish über `created_at`.
4. Hot-Reload: N=5 → mid-run auf N=10 hoch → nächster Refill nutzt 10 Slots. Auf N=2 runter → keine neuen Picks bis in_flight <= 2.
5. Shutdown-Drain: `_shutdown=True` während 3 in_flight → Dispatcher beendet keine neuen Picks, wartet auf gather mit 30 s-Timeout.
6. Sub-Ticks laufen nicht parallel zu LLM-Tasks (Mock-Reviewer mit `asyncio.Event` blockt, `_run_subticks`-Call-Counter prüfen).
7. Mode=off mid-run → Dispatcher pickt keine neuen Jobs, lässt in_flight zu Ende laufen.
8. Budget-exhausted mid-run → analog: keine neuen Picks, in_flight läuft aus.

**DoD-C:**

1. `main()`, `_run_async_main()`, `_dispatcher_loop()`, `_process_one_async()` implementiert.
2. `_tick` → `_run_subticks` umbenannt, alte Signatur entfernt.
3. Heartbeat-Daemon unangetastet.
4. Pure-Unit-Tests grün, >= 8 Fälle. Tests laufen mit Mock-`_pick_next_job_id`, Mock-Reviewer, Mock-Session-Factory.
5. `mypy --strict app/workers/llm_worker.py` PASS.
6. `ruff check . && ruff format --check .` PASS.

### Phase D — DB-Pool-Sizing + Pass-2-Cache-Conflict

**Dateien:** `app/workers/llm_worker.py::_get_session_factory`, `app/services/llm_cache.py::store`.

**Pool-Sizing:**

```python
def _get_session_factory() -> sessionmaker[Session]:
    global _session_factory
    if _session_factory is None:
        cfg = load_settings()
        n = cfg.llm_worker_job_concurrency
        engine = create_engine(
            cfg.database_url,
            pool_pre_ping=True,
            pool_size=max(n * 2, 10),
            max_overflow=n,
            future=True,
        )
        _session_factory = sessionmaker(...)
    return _session_factory
```

Pool-Größe wird nur beim ersten Aufruf festgelegt — Hot-Reload des Concurrency-Werts ändert die Pool-Größe nicht. Log-Marker `llm_worker.engine_built pool_size=%s max_overflow=%s` einmalig.

**Cache-Conflict** in `app/services/llm_cache.py::store`:

```python
from sqlalchemy.dialects.postgresql import insert as pg_insert

stmt = (
    pg_insert(LLMRiskCache)
    .values(
        cache_key=cache_key,
        group_id=group_id,
        ...
    )
    .on_conflict_do_nothing(index_elements=["cache_key"])
)
session.execute(stmt)
```

ORM-`session.add(entry)` durch `pg_insert` ersetzt. `record_hit` und `lookup` unverändert.

**Tests:** `tests/workers/test_pool_sizing.py` und `tests/services/test_llm_cache_conflict.py`:

1. Pool-Size-Berechnung: N=1 → pool_size=10, max_overflow=1; N=50 → 100, 50; N=200 → 400, 200. (Pure-Unit gegen die Formel-Function.)
2. Engine wird einmalig gebaut, zweiter `_get_session_factory()`-Call gibt selbe Engine-Objekt-ID zurück.
3. Cache-Store mit nicht-existierendem Key → Insert PASS, `lookup` findet Eintrag.
4. Cache-Store mit existierendem Key → kein Error, kein Update, alter Eintrag bleibt.
5. Mock-Session der `IntegrityError` simuliert → Statement wird trotzdem sauber ausgeführt (kein try/except-Wrap nötig dank `on_conflict_do_nothing`).

**DoD-D:**

1. `_get_session_factory` mit Pool-Sizing-Formel.
2. `app/services/llm_cache.py::store` umgestellt.
3. Pure-Unit-Tests grün, >= 5 Fälle.
4. `mypy --strict` PASS.

### Phase E — Settings-UI + Master-Key-Gate

**Dateien:** `app/views/settings.py::llm_reviewer_view`, `app/templates/settings/llm_reviewer.html`, `app/forms.py` (oder wo `LlmReviewerModeForm` lebt).

Neue Concurrency-Card im `/settings/llm-reviewer`-Overview-Tab — analog zur Mode-Card:

- Anzeige: aktueller Wert `current_concurrency`, aktueller `in_flight_count` (aus Status-Snapshot-Cache, akzeptiert 30 s alt).
- Button „Concurrency ändern…" öffnet Modal mit Slider/Input 1..200 plus Master-Key-Bestätigungs-Feld.
- POST-Handler `POST /settings/llm-reviewer/concurrency` validiert Master-Key (`compare_digest` wie Mode-Wechsel), Bounds 1..200, schreibt `settings.llm_worker_job_concurrency`, Audit `llm.concurrency_changed`.
- Live-Wirkung: Worker liest binnen <30 s via `_get_concurrency_throttled` neu.

Status-Snapshot-Auslese im View: einfache Last-Known-Werte aus DB-Query (Status-Snapshot wird nicht in DB persistiert — eine schlanke Lösung ist `len(in_flight)` via Audit-Log-Read der letzten `llm_worker.status`-Events, oder ein simpler Lesepfad auf eine Modul-State-Funktion wenn Web-Container und Worker im selben Prozess wären — sind sie nicht). **MVP-Vereinfachung:** nur den persistierten Settings-Wert anzeigen, kein Live-`in_flight`. Operator schaut für Live-Werte in den Container-Log. Re-Open-Trigger: falls UX schmerzhaft, eine Settings-Status-Table die der Worker alle 30 s schreibt und der View liest.

**Tests:** `tests/views/test_settings_concurrency.py`:

1. GET `/settings/llm-reviewer` zeigt Concurrency-Card mit aktuellem Wert.
2. POST ohne Master-Key → 403.
3. POST mit falschem Master-Key → 403, kein Audit.
4. POST mit Master-Key + N=5 → 302 (Redirect), Settings-Row aktualisiert, Audit-Event mit `from=1 to=5`.
5. POST mit N=0, N=201, N="abc" → 400, Settings unverändert.
6. POST mit N=5 wenn aktueller Wert schon 5 ist → kein Audit (No-Op).

**DoD-E:**

1. Form, View-Handler, Template-Card implementiert.
2. Audit-Event geschrieben.
3. Pure-Unit-Tests grün, >= 6 Fälle.
4. `mypy --strict app/views/settings.py` PASS.

### Phase F — Logging-Refactor (Status-Snapshot statt Per-Job-Lärm)

**Dateien:** `app/workers/llm_worker.py` über alle Pass-1-/Pass-2-Pfade hinweg.

**Komplett entfernen (keine `log.debug`-Demote, sondern Code-Removal):**

- `llm_worker.job_picked` (Zeilen ~588, `_process_job`)
- `llm_worker.job_done` (Zeilen ~625, `_process_job`)
- `llm_worker.pass1_started` (Zeilen ~747)
- `llm_worker.pass2_started` (Zeilen ~1060)
- `llm_worker.llm_call_started` (Zeilen ~758, ~1135 — Pass-1 und Pass-2)
- `llm_worker.llm_call_completed` (Zeilen ~814, ~1210)
- `llm_worker.pass1_persist_done` (Zeilen ~854)
- `llm_worker.pass2_persist_done` (Zeilen ~1291)
- `llm_worker.pass2_cache_lookup` (Zeilen ~1076)
- `llm_worker.pass2_cache_hit_applied` (Zeilen ~1112)
- `llm_worker.pass1_skipped` (Zeilen ~737)
- `llm_worker.pass2_skipped` (Zeilen ~1027, ~1050)

Strukturierte Per-Job-Forensik läuft ausschließlich über `llm_debug_log`-Tabelle (UI `/settings/llm-reviewer/debug-log`).

**Bleibt unverändert (Fehler/Warnungen + Lifecycle):**

- `llm_worker.llm_call_failed` (WARNING)
- `llm_worker.job_failed` (WARNING)
- `llm_worker.job_requeued` (INFO — selten genug, Retry-Spur wertvoll)
- `llm_worker.pass2_started_with_failed_pass1` (WARNING)
- `llm_worker.budget_exhausted` (WARNING)
- `llm_worker.stale_reaped_count` (INFO — nur wenn reaped)
- `llm_worker.debug_log_evicted` (INFO — nur wenn evicted)
- `llm_worker.heartbeat_thread_started/_stopped`
- `llm_worker.mode_changed`
- `llm_worker.tick_failed` (EXCEPTION)
- defensive `…_failed`-Handler

**Neu (im Dispatcher-Loop):**

```python
STATUS_SNAPSHOT_INTERVAL_SEC: float = 30.0
_last_status_at: float = 0.0
_status_counters: dict[str, Any] = {
    "done": 0,
    "failed": 0,
    "cache_hits": 0,
    "durations_ms": [],  # rolling window, capped at last 100
}

def _record_task_completion(task: asyncio.Task) -> None:
    """Aufgerufen vom Dispatcher nach asyncio.wait — incrementiert Counter."""
    result = task.result() if not task.exception() else None
    if task.exception() is not None:
        _status_counters["failed"] += 1
    else:
        _status_counters["done"] += 1
        if isinstance(result, dict):
            if result.get("cache_hit"):
                _status_counters["cache_hits"] += 1
            if (d := result.get("duration_ms")):
                _push_duration(d)

def _maybe_emit_status_snapshot(*, in_flight: int, cap: int) -> None:
    global _last_status_at
    now = time.monotonic()
    if now - _last_status_at < STATUS_SNAPSHOT_INTERVAL_SEC:
        return
    _last_status_at = now
    with get_session() as session:
        queued = session.execute(
            text("SELECT count(*) FROM llm_jobs WHERE status = 'queued'")
        ).scalar() or 0
        row = ensure_settings_row(session)
        budget_pct = int(100 * (row.llm_tokens_used_today or 0) / max(1, row.llm_token_budget_daily))
    avg_ms = (
        int(sum(_status_counters["durations_ms"]) / len(_status_counters["durations_ms"]))
        if _status_counters["durations_ms"] else 0
    )
    log.info(
        "llm_worker.status in_flight=%s/%s queued=%s done_30s=%s failed_30s=%s "
        "cache_hits_30s=%s budget_pct=%s avg_call_ms=%s",
        in_flight, cap, queued,
        _status_counters["done"], _status_counters["failed"],
        _status_counters["cache_hits"], budget_pct, avg_ms,
    )
    _reset_status_counters()
```

**Zusätzliche neue Lifecycle-INFO-Logs:**

- `llm_worker.dispatcher_started concurrency=N` (einmalig in `_run_async_main`)
- `llm_worker.dispatcher_shutdown` (einmalig vor Exit)
- `llm_worker.concurrency_changed from=N to=M` (in `_get_concurrency_throttled`)
- `llm_worker.client_rebuilt reason=fingerprint_changed base_url=… model=…` (in `_get_or_build_async_client`)
- `llm_worker.shutdown_drain in_flight=X waiting_max_sec=30`
- `llm_worker.engine_built pool_size=N max_overflow=M` (in `_get_session_factory`)

**Tests:** `tests/workers/test_llm_worker_logging.py`:

1. Removal-Smoke: `pytest` mit `caplog` über einen mock-Pass-1-Lauf → keine `pass1_started`/`pass1_persist_done`/`llm_call_started`/`llm_call_completed`/`job_picked`/`job_done`-Records.
2. Error-Smoke: Mock-Reviewer wirft `LLMInvalidResponseError` → `llm_call_failed` als WARNING im Caplog.
3. Snapshot-Counter: Mock-Tasks done/failed → `_status_counters` korrekt incrementiert.
4. Snapshot-Reset: nach `_maybe_emit_status_snapshot` sind Counter auf 0.
5. Snapshot-Cadence: zweimal hintereinander aufrufen → nur eine Log-Line, zweiter Aufruf early-return wegen `<30 s`.
6. Snapshot-Format: Log-Line enthält `in_flight=`, `queued=`, `done_30s=`, `failed_30s=`, `cache_hits_30s=`, `budget_pct=`, `avg_call_ms=` als Substrings.
7. Cache-Hit-Counter: Mock-Pass-2 mit `result={"cache_hit": True}` → `cache_hits` incrementiert.
8. Duration-Window: 105 Completions → `durations_ms` cap auf 100, älteste werden gedroppt.

**DoD-F:**

1. 12 Per-Job-Log-Lines entfernt.
2. Status-Snapshot-Helper implementiert, Trigger im Dispatcher-Loop.
3. Counter-Logik plus Reset.
4. Vier neue Lifecycle-Logs.
5. Pure-Unit-Tests grün, >= 8 Fälle.
6. `ruff check . && ruff format --check .` PASS.

### Phase G — Debug-Log-Skalierung für N=200

**Dateien:** `app/services/llm_debug_log.py`, `app/workers/llm_worker.py::_record_pass_debug_log`.

**Vier Änderungen:**

**G.1 — Sampling in `_record_pass_debug_log`:**

```python
def _should_sample_debug_log(job_id: int, job_type: str, status: str, sample_rate: int) -> bool:
    """Returns True wenn die Row geschrieben werden soll.

    - Non-success Status (validation_error, timeout, error) → IMMER True (1:1).
    - Success → True wenn hash(job_id, job_type) % sample_rate == 0.
    - sample_rate=1 → True für alle.
    """
    if status != "success":
        return True
    if sample_rate <= 1:
        return True
    h = abs(hash((int(job_id), job_type)))
    return (h % sample_rate) == 0
```

Im `_record_pass_debug_log`-Handler vor dem Insert: `if not _should_sample_debug_log(job_id, job_type, status, cfg.llm_debug_log_success_sample_rate): return`.

**G.2 — Eviction-Cadence von 600 s auf 60 s:**

`DEBUG_LOG_EVICTION_INTERVAL_SEC: float = 60.0`. Sub-Tick-Aufruf bleibt im `_run_subticks()`-Pfad.

**G.3 — CTE-DELETE statt `NOT IN`:**

In `app/services/llm_debug_log.py::evict_old`:

```python
count_result = session.execute(
    text(
        "DELETE FROM llm_debug_log USING ("
        "  SELECT id FROM llm_debug_log "
        "  ORDER BY created_at DESC, id DESC "
        "  OFFSET :max_rows"
        ") AS to_evict "
        "WHERE llm_debug_log.id = to_evict.id"
    ),
    {"max_rows": cfg.llm_debug_log_max_rows},
)
```

`ORDER BY created_at DESC, id DESC` als Tie-Breaker — `created_at` mit Sub-Sekunden-Kollision kann sonst non-deterministisch sein.

**G.4 — Default-Anhebung `llm_debug_log_max_rows`:**

In `app/config.py`: `Field(default=2000, ge=10, le=100_000)` (vorher 500). Reine Pydantic-Default-Änderung, kein Schema-Touch.

**Tests:** `tests/services/test_llm_debug_log_scaling.py`:

1. Sampling-Determinismus: `_should_sample_debug_log(123, "pass1_group_detection", "success", 10)` gibt für gleichen Input gleichen Output.
2. Sampling-Errors: jeder non-success Status returnt True, unabhängig von job_id und sample_rate.
3. Sampling-Rate=1: 100 verschiedene job_id × success → alle True.
4. Sampling-Rate=10: 1000 verschiedene job_id × success → ~100 True (Toleranz ±20 wegen Hash-Verteilung).
5. CTE-DELETE-SQL: Mock-Session mit `execute`-Spy → SQL-Text enthält `USING (SELECT id FROM llm_debug_log ORDER BY created_at DESC, id DESC OFFSET :max_rows)`.
6. Default-Anhebung: `load_settings().llm_debug_log_max_rows == 2000`.
7. `_record_pass_debug_log` mit `status="success"` und Mock-Sample-Rate=10 das `False` returned → keine `session.add`-Aufruf.
8. `_record_pass_debug_log` mit `status="validation_error"` und Mock-Sample-Rate=10 → Insert passiert (kein Sampling für Errors).

**DoD-G:**

1. Vier Code-Änderungen implementiert.
2. Settings-Spalte `llm_debug_log_success_sample_rate` aus Phase A bereits verfügbar.
3. Pure-Unit-Tests grün, >= 8 Fälle.
4. `mypy --strict app/services/llm_debug_log.py` PASS.

## Test-Konvention (verbindlich)

Erlaubte Quality-Gates: `ruff check`, `ruff format --check`, `mypy app/`, `shellcheck` (falls bash betroffen — Block U ist Python-only), `pytest` Default-Selektion (Pure-Unit mit Mocks/Stubs). Verboten: `db_integration`, `acceptance`, `integration`, `bench`, `bats`, `RUN_E2E`, Docker-Compose-Up, Browser-Tests — keine proaktiven Aufrufe, keine neuen `.bats`-/`.sh`-Test-Dateien. Subagent-Aufrufe für Block-U-Implementer enthalten diese Regel wörtlich.

Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf). Keine `pytest`-Aufrufe ohne Timeout.

**Heavy-Suite-Genehmigung pro Phase:** Phase A Alembic-Roundtrip gegen Postgres, Phase C/D ggf. Async-Dispatcher-Smoke gegen echte DB — der Implementer-Agent stoppt am Phase-Ende mit „Pure-Unit grün, User für `pytest -m db_integration` triggern" anstatt selbst zu starten.

## Reihenfolge & Abhängigkeiten

```
A (Schema+Settings)
 └── B (Persistenter Client) — unabhängig, kann parallel laufen
 └── D (Pool-Sizing + Cache-Conflict)
      └── C (Async-Dispatcher) — braucht A für Settings-Read, B für Client, D für Pool-Größe
           └── F (Logging-Refactor) — braucht C für Dispatcher-Hook, Counter-Increment-Stelle
                └── G (Debug-Log-Skalierung) — braucht A für sample_rate-Setting
                     └── E (Settings-UI) — braucht A für Backend-Spalte, F für Snapshot-Verfügbarkeit
```

Empfohlene Implementer-Reihenfolge: **A → B → D → C → F → G → E**. Jede Phase ist ein eigener Commit auf `feat/block-u-worker-concurrency`. Reviewer-Approval am Ende jeder Phase, security-relevant ist keine (kein neuer Auth-Pfad, Master-Key-Gate für Settings-Change existiert bereits in der Mode-Form als Vorbild).

## Risiken & Mitigation

| Risiko | Mitigation |
|---|---|
| **Event-Loop-Stall durch sync SQLAlchemy** unter N=200 Last | Heute sind alle Sessions <50 ms. Falls Profiling Stalls zeigt: `asyncio.to_thread(...)` für `_persist_pass1_groups`, `_upsert_evaluation`, Hydrate-Phasen. Eigener Folge-Block (siehe ADR-0029 §Re-Open-Trigger). |
| **Token-Budget-Overshoot** | Akzeptiert (ADR-0029 §Konsequenzen). Re-Open: reservierter In-Flight-Counter mit Pre-Pickup-Math. |
| **Debug-Log-Tabelle läuft trotz Phase G voll** | Phase G adressiert das aktiv: Sampling 1:10, 60-s-Cadence, CTE-DELETE, Default 2000 Rows. Re-Open: status-getrennter Cap. |
| **Pool-Erschöpfung** wenn N + Sub-Tick-Sessions kollidieren | `max_overflow = N` als Sicherheitsnetz, `pool_pre_ping = True` defensiv gegen stale Connections. Falls operativ schmerzhaft: `max_overflow` als separates Settings-Field. |
| **Provider-Wechsel mid-flight** | In-flight Jobs nutzen alten Client über Task-Closure zu Ende. Kein Mid-Call-Abriss, kein Stacktrace. |
| **Mode-Wechsel auf `off` mid-flight** | Dispatcher pickt keine neuen Jobs, lässt in_flight zu Ende laufen. Heutige Mode-Cache-Semantik bleibt. |
| **Shutdown-Drain-Timeout (30 s)** | Bei stuck LLM-Call kann Worker-Pod nicht graceful schliessen. Heute ohnehin so (langer LLM-Call blockt `_tick`). 30 s ist großzügig — typischer Pass-1/Pass-2 ist 30–60 s, aber bei N=200 sind die meisten in_flight schon im Persist-Phase und enden in <2 s. Worst-Case-Backstop: K8s `terminationGracePeriodSeconds=60` gibt genug Headroom. |
| **Test-Asyncio-Determinismus** | Pure-Unit-Tests nutzen `pytest-asyncio` mit `@pytest.mark.asyncio` plus `asyncio.Event`-Mocks für Reviewer. `@pytest.mark.timeout(N)` auf alle Dispatcher-Tests gegen Hänger. |
| **Heartbeat-Thread und Async-Loop koexistieren** | Heartbeat-Daemon bleibt synchron mit `time.sleep`-Substitut (`_heartbeat_thread_stop.wait`). Schreibt in eigene Session, keine Event-Loop-Interaktion. Sauber getrennt. |

## NICHT in Block U

- **Multi-Worker-Container** (zweiter Pod, verteiltes Rate-Limit, Redis-Backend). ARCHITECTURE.md §17.
- **Pass-1/Pass-2-Concurrency-Split.** Eine globale Concurrency reicht für MVP.
- **Adaptive Concurrency / 429-Auto-Throttle.** Bei Provider-Drosselung läuft heute Retry-Pfad.
- **LLM-Chat-Concurrency** (Block-G-Surface). Eigene Folge-ADR.
- **Status-Snapshot-Persistierung** (Live-`in_flight`-Anzeige im UI ohne Container-Log-Read). Re-Open in Phase E.
- **Status-getrennter Debug-Log-Cap** (Success-Bucket vs Error-Bucket mit separaten Caps). Re-Open in ADR-0029.
- **Dynamisches DB-Pool-Resize** ohne Engine-Rebuild.
- **Per-Provider-Concurrency-Profile.**
- **`async`-SQLAlchemy / `asyncpg`-Migration.** Falls Phase C Event-Loop-Stalls produziert, eigener Folge-Block.
- **CHANGELOG / STATE.md-Updates** während des Block-Verlaufs. Werden beim Block-Abschluss in einem Commit nachgezogen (ADR-0023-Pattern).

## Cutover & Operator-Impact

Kein Hybrid-Modus, kein Feature-Flag. Migration setzt `llm_worker_job_concurrency = 1` für bestehende Deploys → Verhalten identisch mit heute. Operator regelt manuell via `/settings/llm-reviewer` hoch wenn er den Throughput braucht.

Erwartete Operator-Schritte nach Deploy v0.11.0:

1. `alembic upgrade head` → zwei neue Settings-Spalten mit Default 1 / 10.
2. Pod-Restart `secscan-llm-worker` (neues `main()`, neuer Dispatcher).
3. Optionaler Härtetest: `/settings/llm-reviewer` → Concurrency 5 → Re-Eval triggern → Container-Log nach `llm_worker.status`-Snapshots beobachten.
4. Hochregeln in 5er/10er/50er-Schritten je nach Beobachtung.

**Beobachtungs-Hinweis für `docs/operations.md`:** Status-Snapshot alle 30 s in Container-Log, Felder `in_flight=X/Cap queued=Y done_30s=Z failed_30s=W cache_hits_30s=V budget_pct=P avg_call_ms=…`. Bei `failed_30s` > 0 in mehreren aufeinanderfolgenden Snapshots: `/settings/llm-reviewer/debug-log` aufrufen für Pro-Job-Forensik (Sampling 1:10 für Successes, Errors immer voll).
