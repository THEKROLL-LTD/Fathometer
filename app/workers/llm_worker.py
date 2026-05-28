"""LLM-Risk-Reviewer-Worker fuer Block P (ADR-0023).

Standalone-Python-Prozess (kein Flask-App-Context) der in einem
Endlos-Loop ``llm_jobs`` aus der DB pickt und prozessiert. Drei Modi:

* ``off`` — Worker dreht leer, kein Pickup.
* ``observation`` — Worker pickt, schreibt nur ``would_call``-Marker ins
  ``result``-JSONB. Token-Schaetzung wird gegen das Tages-Budget gebucht
  damit Cost-Math realistisch ist.
* ``live`` — Worker pickt, ruft das LLM, persistiert Group-Daten und
  Pass-2-Result-Cache.

Wichtige Architektur-Eigenschaften:

* **Concurrency-safe Pickup** mit ``SELECT FOR UPDATE SKIP LOCKED``.
* **Dependency-Order**: Pass-2-Jobs warten via ``depends_on`` auf den
  Abschluss eines Pass-1-Parent.
* **Stale-Reaper** alle 60s — ``in_progress``-Jobs mit ``picked_up_at``
  aelter als ``WORKER_STALE_TIMEOUT_MIN`` werden in die Queue zurueck-
  geworfen oder auf ``failed`` gesetzt (bei ``attempts >= MAX_ATTEMPTS``).
* **Heartbeat** alle 10s in ``settings.llm_worker_heartbeat_at`` —
  Healthcheck-Endpoint vergleicht das Alter gegen Schwellwert.
* **Graceful Shutdown** auf ``SIGTERM``/``SIGINT``: Flag wird gesetzt,
  laufender Tick faehrt zu Ende, dann Exit.

Der Worker baut sich seine DB-Engine eigenstaendig aus
``load_settings().database_url`` — kein Flask-Context, keine Blueprints.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import create_engine, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.config import load_settings
from app.models import (
    ApplicationGroup,
    ApplicationGroupEvaluation,
    Finding,
    LLMJob,
    Server,
)
from app.services import llm_budget, llm_debug_log
from app.services.finding_group_inheritance import inherit_group_risk_to_findings
from app.services.group_matcher import GroupMatcher, derive_group_kind
from app.services.llm_cache import lookup, lru_evict_if_needed, record_hit, store
from app.services.llm_client import LlmClient, build_client_from_settings
from app.services.llm_fingerprints import (
    cve_data_fingerprint,
    group_findings_fingerprint,
    make_cache_key,
    server_context_fingerprint,
)
from app.services.llm_risk_reviewer import (
    LLMInvalidResponseError,
    LLMRiskReviewer,
    LLMTimeoutError,
    Pass1Group,
    Pass1Result,
    Pass2Evaluation,
    Pass2Result,
)
from app.services.pass2_enqueue import Pass2Trigger, enqueue_pass2_for_server
from app.settings_service import ensure_settings_row
from app.workers import feed_enrichment

log = logging.getLogger("secscan.llm_worker")


# ---------------------------------------------------------------------------
# Top-Level-Konstanten (Worker-ID, Polling-Intervall, Limits)
# ---------------------------------------------------------------------------


# Worker-Identitaet bleibt konstant ueber den Prozess-Lifetime; alles
# settings-abhaengige holen wir lazy ueber Helper damit der Modul-Import
# nicht an einer fehlenden Env-Var (SECSCAN_ENCRYPTION_KEY) explodiert.
WORKER_ID: str = f"{socket.gethostname()}:{os.getpid()}"
MAX_ATTEMPTS: int = 3
HEARTBEAT_INTERVAL_SEC: float = 10.0
STALE_REAPER_INTERVAL_SEC: float = 60.0
# v0.9.3 (ADR-0023 §"(e) LLM-Debug-Log-Tabelle"): Eviction-Sub-Tick fuer
# `llm_debug_log`. v0.11.0 (Block U Phase G, ADR-0029): Cadence von 600 s auf
# 60 s gesenkt, damit der Count-Cap unter N=200-Last (bis ~12 Inserts/s) den
# Insert-Strom zeitnah deckelt.
DEBUG_LOG_EVICTION_INTERVAL_SEC: float = 60.0
# Block Q (ADR-0024): External-EPSS/KEV-Feed-Pull-Sub-Tick. Alle 10 Minuten
# nachschauen ob ein Pull faellig ist — der Pull selbst laeuft nur 1x pro
# Tag pro Feed (entscheidet ``feed_enrichment_tick`` per Audit-Log).
FEED_PULL_CHECK_INTERVAL_SEC: float = 600.0
# v0.9.6: Idle-CPU-Reduktion. Mode-Wechsel ist Operator-Action; alle 2s die
# Settings-Row zu pollen ist Verschwendung. Cache 30s — Mode-Switch wird also
# binnen <30s wirksam, was operativ vollkommen ausreicht.
MODE_CHECK_INTERVAL_SEC: float = 30.0
# Block U Phase C (ADR-0029 §Entscheidung Punkt 4): Hot-Reload-Cadence fuer
# `settings.llm_worker_job_concurrency`. Analog zum Mode-Cache: Operator-Action
# wirkt binnen <30s ohne Pod-Restart.
CONCURRENCY_CHECK_INTERVAL_SEC: float = 30.0
# Block U Phase C: Cadence fuer aggregierten `llm_worker.status`-Snapshot
# (Phase F fuellt den Helper-Body — hier nur Konstante damit Phase-C-Code
# stabil bleibt wenn Phase F live geht).
STATUS_SNAPSHOT_INTERVAL_SEC: float = 30.0
# Block U Phase C: Shutdown-Drain-Timeout. In-flight Tasks bekommen 30s Zeit
# bis zum harten Exit. Heutiger LLM-Call dauert 30-90s, typische Persist-Phase
# <2s — bei N=200 sind die meisten in_flight schon im Persist-Tail wenn der
# Shutdown faellt. Operativer Backstop: K8s `terminationGracePeriodSeconds=60`.
SHUTDOWN_DRAIN_TIMEOUT_SEC: float = 30.0
# v0.9.6: Budget-Check throttle. Token-Budget aendert sich nur post-LLM-Call
# (via budget_consume) — Idle-Worker sieht keine Aenderung. 60s-Cadence
# bedeutet: bei Budget-Erschoepfung mid-Cycle koennen noch bis zu ~60s lang
# Jobs gepickt werden bevor die Pause greift. Akzeptabel — ein paar Prozent
# ueber dem Daily-Cap ist operativ irrelevant, Hauptsache nicht stundenlang
# overshoot.
BUDGET_CHECK_INTERVAL_SEC: float = 60.0
# v0.9.6: Idle-Backoff. Bei leerer Queue klettert die Sleep-Dauer exponentiell
# von `worker_poll_interval_sec` (2s default) hoch bis zum Cap. Bei jedem
# erfolgreichen Pickup wird der Backoff sofort wieder auf den Default-Poll
# resettet — Job-Latency bleibt damit < 2s sobald die Queue gefuellt wird.
IDLE_BACKOFF_MAX_SEC: float = 30.0
IDLE_BACKOFF_FACTOR: float = 1.5


def _poll_interval() -> float:
    return float(load_settings().worker_poll_interval_sec)


def _stale_timeout_min() -> int:
    return int(load_settings().worker_stale_timeout_min)


# Backwards-compat Module-Konstanten, die nur fuer Tests/Docs sichtbar
# bleiben. Lazily resolved beim ersten Zugriff (Properties auf einem Modul
# sind in CPython nicht direkt machbar; wir nutzen Helper-Aufrufe in der
# Implementation und exportieren die Constants ueber Property-Wrapper im
# `__getattr__`-Hook).
def __getattr__(name: str) -> Any:
    if name == "POLL_INTERVAL":
        return _poll_interval()
    if name == "STALE_TIMEOUT_MIN":
        return _stale_timeout_min()
    raise AttributeError(name)


# Block R (ADR-0026): Scan-Ingest-Retention-Sweep-Cadence (1 Stunde).
SCAN_INGEST_RETENTION_SWEEP_INTERVAL_SEC: float = 3600.0

# TICKET-007: Backstop-Sweep-Cadence fuer den Pass-2-Auto-Trigger (5 min).
# Faengt den Trigger nach falls der Hook im _do_pass1/_requeue_or_fail-Pfad
# aus irgendeinem Grund nicht gefeuert hat (Worker-Crash, DB-Hickup).
PASS2_BACKSTOP_SWEEP_INTERVAL_SEC: float = 300.0

# Modul-State (graceful Shutdown + Cadence-Tracking).
_shutdown: bool = False
# v0.9.5: ``_last_heartbeat_at`` ist Legacy — Heartbeat lebt jetzt im
# Daemon-Thread (siehe `_heartbeat_loop`). Wir behalten die Variable
# fuer Test-Hooks/Backward-Compat, schreiben sie aber nicht mehr im
# `_tick()`.
_last_heartbeat_at: float = 0.0
_last_reaper_at: float = 0.0
_last_debug_log_eviction_at: float = 0.0
_last_feed_pull_check_at: float = 0.0
# Block R (ADR-0026): Letzter Lauf des Scan-Ingest-Retention-Sweeps.
_last_retention_sweep_at: float = 0.0
# TICKET-007: Letzter Lauf des Pass-2-Backstop-Sweeps.
_last_pass2_backstop_sweep_at: float = 0.0

# v0.9.6: Mode-/Budget-Caching + Idle-Backoff. Reduziert die Idle-SQL-Last
# (vorher ~120 Queries/Minute bei leerer Queue) drastisch.
_cached_mode: str | None = None
_mode_cached_at: float = 0.0
_cached_budget_ok: bool = True
_budget_cached_at: float = 0.0
# Aktuelle Sleep-Dauer bei leerer Queue. ``None`` = noch nie idle gewesen
# (oder direkt nach Pickup zurueckgesetzt). Beim ersten Idle-Tick startet
# der Backoff bei ``_poll_interval()``.
_idle_backoff_sec: float | None = None

# Block U Phase C: Hot-Reload-Cache fuer `llm_worker_job_concurrency`.
# Default 1 ist backward-compatible mit Pre-Block-U-Verhalten (1 Task gleich
# alter sync-`_tick()`-Schleife). `None` = Cache noch nie befuellt, naechster
# Read laedt frisch aus der DB.
_cached_concurrency: int | None = None
_concurrency_cached_at: float = 0.0

# v0.9.5: Heartbeat-Daemon-Thread + Stop-Event. Damit der Heartbeat
# unabhaengig vom (potentiell 30-120s blockierenden) LLM-Call im
# `_process_job` weiterlaeuft — sonst kickt die k8s livenessProbe
# (HEARTBEAT_MAX_AGE_SEC=30 in healthcheck.py) den Pod mitten im Call.
_heartbeat_thread: threading.Thread | None = None
_heartbeat_thread_stop: threading.Event = threading.Event()

# Lazy-erzeugte Session-Factory (kein Flask-App-Context).
_session_factory: sessionmaker[Session] | None = None

# Block U Phase B (ADR-0029 §Entscheidung Punkt 2): Persistenter
# ``LlmClient`` mit TLS-Connection-Reuse. Pro Worker-Prozess ein einziger
# Client-Wrapper um ``AsyncOpenAI`` — wird genau dann neu gebaut wenn sich
# ``(base_url, model, sha256(api_key))`` veraendert. Hot-Reload via
# Fingerprint-Cache; bei Mismatch alten Client `await aclose()` aufrufen
# und neuen bauen.
#
# Lock wird lazy im async-Kontext gebaut, weil ``asyncio.Lock()`` zur
# Instanziierung einen laufenden Event-Loop braucht (Python 3.10+).
_cached_client: LlmClient | None = None
_cached_client_fingerprint: tuple[str, str, str] | None = None
_cached_client_lock: asyncio.Lock | None = None


# ---------------------------------------------------------------------------
# Session-Management
# ---------------------------------------------------------------------------


def _compute_pool_sizing(concurrency: int) -> tuple[int, int]:
    """Berechnet ``(pool_size, max_overflow)`` aus der Concurrency.

    Block U Phase D (ADR-0029 §Entscheidung Punkt 3):

    * ``pool_size = max(N * 2, 10)`` — pro in-flight Job rechnen wir mit bis
      zu zwei Sessions (Pickup-Session plus Persist-Session koennen sich
      kurz ueberlappen), plus Sub-Tick-Sessions (Reaper, Eviction, Feed-
      Pull, Ingest, Retention) die im selben Prozess laufen. Untergrenze
      10 fuer den Default-N=1-Fall damit Sub-Ticks Headroom haben.
    * ``max_overflow = N`` — Sicherheitsnetz fuer kurzzeitige Spitzen, z.B.
      Heartbeat-Daemon-Thread oder Status-Snapshot-Read parallel zu allen
      in-flight Jobs.

    Pure-Funktion fuer Testbarkeit — kein DB-/Engine-Bau.
    """
    return max(concurrency * 2, 10), concurrency


def _get_session_factory() -> sessionmaker[Session]:
    """Lazy-baut die Worker-Session-Factory aus ``SECSCAN_DATABASE_URL``.

    Wir wollen genau eine Engine im Worker-Prozess (Connection-Pool wieder-
    verwenden), bauen sie aber lazy damit Tests die Factory per
    :func:`set_session_factory_for_tests` ersetzen koennen, bevor der erste
    Tick laeuft.

    Block U Phase D (ADR-0029 §Entscheidung Punkt 3): Pool-Sizing wird
    einmalig beim ersten Aufruf aus ``cfg.llm_worker_job_concurrency``
    festgelegt. Hot-Reload des Concurrency-Werts veraendert die Pool-Groesse
    NICHT — der Pool ist Engine-Lifetime. Ein Operator-Hochregeln des
    Worker-Concurrency-Settings benoetigt einen Worker-Pod-Restart fuer
    die volle Pool-Auswirkung.
    """
    global _session_factory
    if _session_factory is None:
        cfg = load_settings()
        pool_size, max_overflow = _compute_pool_sizing(cfg.llm_worker_job_concurrency)
        engine = create_engine(
            cfg.database_url,
            pool_pre_ping=True,
            pool_size=pool_size,
            max_overflow=max_overflow,
            future=True,
        )
        log.info(
            "llm_worker.engine_built pool_size=%s max_overflow=%s",
            pool_size,
            max_overflow,
        )
        _session_factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    return _session_factory


def set_session_factory_for_tests(factory: sessionmaker[Session]) -> None:
    """Hilfs-API fuer Tests — uebergibt eine vorgebackene Session-Factory."""
    global _session_factory
    _session_factory = factory


@contextmanager
def get_session() -> Iterator[Session]:
    """Context-Manager mit auto-commit/rollback und close.

    Wirft die Exception weiter — der Tick-Loop faengt sie ab und sleep't.
    """
    factory = _get_session_factory()
    session = factory()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Signal-Handling
# ---------------------------------------------------------------------------


def _signal_handler(signum: int, frame: Any) -> None:
    """Setzt das Shutdown-Flag — der aktuelle Tick faehrt zu Ende."""
    global _shutdown
    log.info("llm_worker.shutdown_requested signum=%s", signum)
    _shutdown = True


def request_shutdown_for_tests() -> None:
    """Test-Hook — setzt das Shutdown-Flag von aussen."""
    global _shutdown
    _shutdown = True


def reset_shutdown_for_tests() -> None:
    """Test-Hook — setzt das Shutdown-Flag zurueck (zwischen Tests)."""
    global _shutdown, _last_heartbeat_at, _last_reaper_at, _last_debug_log_eviction_at
    global _last_feed_pull_check_at, _last_retention_sweep_at, _last_pass2_backstop_sweep_at
    _shutdown = False
    _last_heartbeat_at = 0.0
    _last_reaper_at = 0.0
    _last_debug_log_eviction_at = 0.0
    _last_feed_pull_check_at = 0.0
    _last_retention_sweep_at = 0.0
    _last_pass2_backstop_sweep_at = 0.0
    # v0.9.5: Stop-Event clearen damit Test-Re-Runs den Heartbeat-Thread
    # nicht im Stop-State festhalten.
    _heartbeat_thread_stop.clear()
    # v0.9.6: Mode-/Budget-Cache + Idle-Backoff zwischen Test-Runs zuruecksetzen.
    invalidate_throttle_caches_for_tests()


def invalidate_throttle_caches_for_tests() -> None:
    """Test-Hook — leert die v0.9.6-Throttle-Caches.

    Wird vom autouse-``reset_shutdown_for_tests`` aufgerufen, kann aber auch
    *innerhalb* eines Tests genutzt werden wenn die Test-Logik den Mode oder
    Budget-Zustand mid-test aendert und einen frischen DB-Read im naechsten
    ``_tick()`` braucht (sonst wuerde der Cache noch den alten Wert
    zurueckliefern — siehe ``MODE_CHECK_INTERVAL_SEC = 30s``).
    """
    global _cached_mode, _mode_cached_at, _cached_budget_ok, _budget_cached_at
    global _idle_backoff_sec
    global _cached_concurrency, _concurrency_cached_at
    _cached_mode = None
    _mode_cached_at = 0.0
    _cached_budget_ok = True
    _budget_cached_at = 0.0
    _idle_backoff_sec = None
    # Block U Phase C: Concurrency-Hot-Reload-Cache.
    _cached_concurrency = None
    _concurrency_cached_at = 0.0
    # Block U Phase B: persistenten Client-Cache zwischen Tests resetten.
    # Das Lock-Objekt bleibt None — der naechste async-Aufruf baut es
    # frisch im aktiven Event-Loop.
    reset_client_cache_for_tests()


# ---------------------------------------------------------------------------
# Tick-Loop und Sub-Ticks
# ---------------------------------------------------------------------------


def main() -> None:
    """Worker-Entrypoint (Block U Phase C — ADR-0029).

    Setup laeuft synchron (Logging, Signal-Handler, Heartbeat-Daemon-Thread),
    der eigentliche Dispatcher-Loop laeuft asynchron in
    :func:`_run_async_main`. Der Heartbeat-Daemon (eigener Thread, eigene
    Session) bleibt vom Event-Loop unberuehrt — er startet *vor* und stoppt
    *nach* dem ``asyncio.run()``-Block.
    """
    logging.basicConfig(
        level=load_settings().log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # v0.9.5: Heartbeat-Daemon vor der Tick-Schleife starten — laeuft
    # unabhaengig vom potentiell blockierenden LLM-Call weiter.
    _start_heartbeat_thread()

    log.info(
        "llm_worker.starting worker_id=%s mode=%s poll=%ss stale_timeout_min=%s",
        WORKER_ID,
        _read_mode_safe(),
        _poll_interval(),
        _stale_timeout_min(),
    )

    try:
        asyncio.run(_run_async_main())
    finally:
        # v0.9.5: graceful shutdown — Heartbeat-Thread stoppen + max 5s warten.
        _stop_heartbeat_thread(timeout=5.0)
        log.info("llm_worker.shutdown_complete worker_id=%s", WORKER_ID)


async def _run_async_main() -> None:
    """Async-Dispatcher mit Greedy Slot-Refill (Block U Phase C, ADR-0029).

    Architektur:

    * Genau ein Event-Loop pro Worker-Prozess.
    * ``in_flight: set[asyncio.Task]`` haelt aktuell laufende Job-Coroutinen.
    * Sub-Ticks (Reaper, Eviction, Feed-Pull, Ingest, Retention) laufen
      synchron *zwischen* den Refill-Iterationen — nicht parallel zu
      LLM-Tasks. Heartbeat-Daemon-Thread laeuft separat und schreibt eine
      eigene Session.
    * Greedy Refill: solange Cap nicht erreicht und Mode/Budget/Queue-Pickup
      es zulassen, werden neue Tasks gestartet.
    * Bei voller Queue oder erreichtem Cap wartet der Dispatcher auf
      ``FIRST_COMPLETED`` und refillt sofort.
    * Bei leerer Queue: exponential Idle-Backoff via :func:`_compute_idle_sleep`.
    * Shutdown-Drain: in-flight Tasks bekommen ``SHUTDOWN_DRAIN_TIMEOUT_SEC``
      Zeit zum Beenden, dann WARNING-Log.

    Status-Snapshot- und Counter-Hooks (``_maybe_emit_status_snapshot``,
    ``_record_task_completion``) sind in Phase C als Stubs angelegt und
    werden in Phase F gefuellt.
    """
    in_flight: set[asyncio.Task[Any]] = set()
    cap = _get_concurrency_throttled()
    log.info("llm_worker.dispatcher_started concurrency=%s", cap)

    while not _shutdown:
        # 1) Sub-Ticks (Reaper/Eviction/Feed-Pull/Ingest/Retention) — synchron.
        try:
            _run_subticks()
        except Exception:  # pragma: no cover — Sub-Tick-Sicherheitsnetz
            log.exception("llm_worker.subticks_failed continuing")

        # 2) Concurrency-Cap hot-reloaden (max 30s alt).
        cap = _get_concurrency_throttled()

        # 3) Greedy Slot-Refill bis Cap erreicht, Mode/Budget/Queue-Limit
        #    es erlaubt. Bei Senkung des Cap (in_flight > cap) wird kein
        #    neuer Pickup gemacht — bestehende Tasks laufen bis zum Ende.
        picked_any = False
        while not _shutdown and len(in_flight) < cap:
            mode = _get_mode_throttled()
            if mode == "off":
                break
            if not _budget_ok_throttled():
                break
            job_id = _pick_next_job_id()
            if job_id is None:
                break
            task = asyncio.create_task(_process_one_async(job_id, mode))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)
            picked_any = True

        # Nach erfolgreichem Pickup Idle-Backoff zuruecksetzen — der
        # naechste Idle-Cycle startet wieder bei `_poll_interval()`.
        if picked_any:
            _reset_idle_backoff()

        # 4) Status-Snapshot (Phase F: echte Implementation; hier Stub).
        _maybe_emit_status_snapshot(in_flight=len(in_flight), cap=cap)

        # 5) Wenn keine Tasks laufen, ist die Queue gerade leer (oder Mode/
        #    Budget blockieren). Idle-Sleep statt Busy-Loop.
        if not in_flight:
            sleep_sec = _compute_idle_sleep()
            try:
                await asyncio.sleep(sleep_sec)
            except asyncio.CancelledError:  # pragma: no cover — Shutdown
                break
            continue

        # 6) Mindestens ein Task fertig abwarten, dann sofort refillen.
        try:
            done, _pending = await asyncio.wait(in_flight, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:  # pragma: no cover — Shutdown
            break
        for task in done:
            _record_task_completion(task)

    # Shutdown-Drain: in-flight Tasks bekommen Frist zum sauberen Beenden.
    if in_flight:
        log.info(
            "llm_worker.shutdown_drain in_flight=%s waiting_max_sec=%s",
            len(in_flight),
            SHUTDOWN_DRAIN_TIMEOUT_SEC,
        )
        try:
            await asyncio.wait_for(
                asyncio.gather(*in_flight, return_exceptions=True),
                timeout=SHUTDOWN_DRAIN_TIMEOUT_SEC,
            )
        except TimeoutError:
            log.warning(
                "llm_worker.shutdown_drain_timeout in_flight=%s",
                len(in_flight),
            )
    log.info("llm_worker.dispatcher_shutdown")


def _read_mode_safe() -> str:
    """Liest ``settings.block_p_llm_mode`` defensiv (fallback ``off``)."""
    try:
        with get_session() as session:
            row = ensure_settings_row(session)
            return str(row.block_p_llm_mode or "off")
    except Exception:  # pragma: no cover — DB nicht da
        return "off"


def _get_mode_throttled() -> str:
    """Liest ``settings.block_p_llm_mode`` mit Cache.

    v0.9.6: bei einer Cadence von 2s das Settings-Row zu lesen ist Idle-CPU-
    Verschwendung. Mode-Wechsel ist Operator-Action, ein Cache von 30s ist
    operativ unbedenklich. Defensive Default ``off`` bei DB-Fehler.
    """
    global _cached_mode, _mode_cached_at
    now = time.monotonic()
    if _cached_mode is None or (now - _mode_cached_at) > MODE_CHECK_INTERVAL_SEC:
        try:
            with get_session() as session:
                row = ensure_settings_row(session)
                new_mode = str(row.block_p_llm_mode or "off")
        except Exception:  # pragma: no cover — DB-Hickup
            log.exception("llm_worker.mode_check_failed defaulting_to_off")
            new_mode = "off"
        if new_mode != _cached_mode:
            log.info("llm_worker.mode_changed from=%s to=%s", _cached_mode, new_mode)
        _cached_mode = new_mode
        _mode_cached_at = now
    return _cached_mode


def _budget_ok_throttled() -> bool:
    """Prueft Budget mit Cache + macht den 00:00-UTC-Reset wenn faellig.

    v0.9.6: Token-Budget aendert sich nur post-LLM-Call (via ``budget_consume``)
    — ein Idle-Worker sieht hier keine Aenderung, das Pollen alle 2s ist
    verschwendet. 60s Cache bedeutet: nach Budget-Erschoepfung koennen noch
    bis ~60s lang Jobs gepickt werden. Operativ irrelevant — paar Prozent
    Overshoot, kein stundenlanger Free-Pass.

    Ruft ``maybe_reset_budget`` im selben Throttle-Interval damit der
    00:00-UTC-Reset zuverlaessig binnen 60s greift.
    """
    global _cached_budget_ok, _budget_cached_at
    now = time.monotonic()
    if (now - _budget_cached_at) > BUDGET_CHECK_INTERVAL_SEC:
        try:
            with get_session() as session:
                llm_budget.maybe_reset_budget(session)
                ok = llm_budget.budget_check(session)
                if not ok:
                    # v0.9.5: Budget-Erschoepfung explizit loggen.
                    log.warning("llm_worker.budget_exhausted job_pickup_paused")
                    llm_budget.mark_exhausted_audit_once(session)
                else:
                    log.debug("llm_worker.budget_check_passed")
        except Exception:  # pragma: no cover — DB-Hickup
            log.exception("llm_worker.budget_check_failed defaulting_to_ok")
            ok = True
        _cached_budget_ok = ok
        _budget_cached_at = now
    return _cached_budget_ok


def _compute_idle_sleep() -> float:
    """Berechnet die naechste Idle-Sleep-Dauer und aktualisiert den State.

    Block U Phase C (ADR-0029): die Sleep-Dauer waechst exponentiell um
    ``IDLE_BACKOFF_FACTOR`` pro aufeinanderfolgendem Leer-Pickup, gedeckelt
    durch ``IDLE_BACKOFF_MAX_SEC``. Die Funktion gibt die berechnete Dauer
    *zurueck* — der Caller (Dispatcher-Loop bzw. der Backward-Compat-
    Wrapper :func:`_idle_sleep_and_backoff`) entscheidet selbst ob er
    ``await asyncio.sleep`` oder ``time.sleep`` aufruft.

    Reset via :func:`_reset_idle_backoff` sobald ein Pickup gelingt.
    """
    global _idle_backoff_sec
    if _idle_backoff_sec is None:
        _idle_backoff_sec = _poll_interval()
    else:
        _idle_backoff_sec = min(
            _idle_backoff_sec * IDLE_BACKOFF_FACTOR,
            IDLE_BACKOFF_MAX_SEC,
        )
    return _idle_backoff_sec


def _idle_sleep_and_backoff() -> None:
    """Backward-compat-Wrapper: berechnet Sleep-Dauer und schlaeft synchron.

    Block U Phase C (ADR-0029) entkoppelt Sleep-Berechnung von der Sleep-
    Ausfuehrung — der neue async Dispatcher ruft :func:`_compute_idle_sleep`
    direkt und benutzt ``await asyncio.sleep(...)``. Dieser Wrapper bleibt
    fuer Pure-Unit-Tests (``tests/workers/test_llm_worker.py``) und
    Test-Hooks bestehen, wird im Live-Pfad aber nicht mehr aufgerufen.
    """
    duration = _compute_idle_sleep()
    time.sleep(duration)


def _reset_idle_backoff() -> None:
    """Setzt den Idle-Backoff zurueck — Caller ruft das beim Pickup."""
    global _idle_backoff_sec
    _idle_backoff_sec = None


def _get_concurrency_throttled() -> int:
    """Liest ``settings.llm_worker_job_concurrency`` mit 30s-Cache.

    Block U Phase C (ADR-0029 §Entscheidung Punkt 4): Hot-Reload des
    Concurrency-Werts ohne Pod-Restart. Operator-Action wirkt binnen
    ``CONCURRENCY_CHECK_INTERVAL_SEC`` Sekunden.

    Defensive Defaults bei DB-Hickup:

    * Erster Aufruf ohne erfolgreichen DB-Read: Fallback ``1`` (gleicht
      dem Pre-Block-U-Verhalten).
    * Spaeterer DB-Hickup: behalten den zuletzt-erfolgreich gelesenen Wert.

    Logs einen ``llm_worker.concurrency_changed``-Marker bei tatsaechlicher
    Aenderung — der wird sowohl beim allerersten Read (von "unbekannt" auf
    den Settings-Wert) als auch bei spaeteren Operator-Wechseln getriggert.
    """
    global _cached_concurrency, _concurrency_cached_at
    now = time.monotonic()
    if (
        _cached_concurrency is None
        or (now - _concurrency_cached_at) > CONCURRENCY_CHECK_INTERVAL_SEC
    ):
        try:
            with get_session() as session:
                row = ensure_settings_row(session)
                new_value = int(row.llm_worker_job_concurrency or 1)
        except Exception:  # pragma: no cover — DB-Hickup
            log.exception("llm_worker.concurrency_check_failed keeping_previous")
            new_value = _cached_concurrency if _cached_concurrency is not None else 1
        if new_value != _cached_concurrency:
            log.info(
                "llm_worker.concurrency_changed from=%s to=%s",
                _cached_concurrency,
                new_value,
            )
        _cached_concurrency = new_value
        _concurrency_cached_at = now
    # mypy: nach dem Block ist _cached_concurrency garantiert nicht-None.
    return int(_cached_concurrency)


# ---------------------------------------------------------------------------
# Block U Phase F — Status-Snapshot statt Per-Job-Lärm (ADR-0029 §Punkt 4)
# ---------------------------------------------------------------------------


# Modul-State fuer aggregierte Snapshot-Logs. Ein Snapshot wird alle
# ``STATUS_SNAPSHOT_INTERVAL_SEC`` Sekunden vom Dispatcher emittiert und die
# Counter werden danach zurueckgesetzt. ``durations_ms`` ist ein gleitendes
# Fenster der letzten ``_DURATION_WINDOW_CAP`` LLM-Job-Latenzen — wir lesen
# daraus den 30s-Schnitt fuer den Snapshot.
_last_status_at: float = 0.0
_DURATION_WINDOW_CAP: int = 100
_status_counters: dict[str, Any] = {
    "done": 0,
    "failed": 0,
    "cache_hits": 0,
    "durations_ms": [],
}


def _push_duration(ms: int | float) -> None:
    """Append ``ms`` ans rolling Window; droppt aelteste wenn >Cap."""
    durations: list[int] = _status_counters["durations_ms"]
    durations.append(int(ms))
    if len(durations) > _DURATION_WINDOW_CAP:
        # Slice in-place damit der Cap auch greift wenn z.B. Tests den
        # Counter direkt manipulieren und dann viele Appends folgen.
        del durations[: len(durations) - _DURATION_WINDOW_CAP]


def _reset_status_counters() -> None:
    """Setzt done/failed/cache_hits/durations_ms zurueck nach dem Emit."""
    _status_counters["done"] = 0
    _status_counters["failed"] = 0
    _status_counters["cache_hits"] = 0
    _status_counters["durations_ms"] = []


def _record_task_completion(task: asyncio.Task[Any]) -> None:
    """Incrementiert ``_status_counters`` fuer den Snapshot.

    Wird vom Dispatcher nach ``asyncio.wait(FIRST_COMPLETED)`` fuer jeden
    fertigen Task aufgerufen.

    Achtung: ``task.exception()`` MUSS vor ``task.result()`` aufgerufen
    werden, sonst wuerde ``task.result()`` die Exception erneut werfen.
    """
    exc = task.exception()
    if exc is not None:
        _status_counters["failed"] += 1
        return
    _status_counters["done"] += 1
    result = task.result()
    if isinstance(result, dict):
        if result.get("cache_hit"):
            _status_counters["cache_hits"] += 1
        duration = result.get("duration_ms")
        if duration is not None:
            _push_duration(duration)


def _maybe_emit_status_snapshot(*, in_flight: int, cap: int) -> None:
    """Aggregierter ``llm_worker.status``-Snapshot, alle 30s.

    Liest live aus der DB: ``queued``-Count aus ``llm_jobs`` plus
    Budget-Auslastung aus der Settings-Row. Aggregiert mit den Worker-
    internen Countern (``done``, ``failed``, ``cache_hits``, ``avg_call_ms``)
    und logged genau eine INFO-Line. Anschliessend werden die Counter
    zurueckgesetzt.

    Defensiv: DB-Fehler fuhren NICHT zu einem Crash. Bei Read-Fehler werden
    ``queued`` und ``budget_pct`` auf ``-1`` gesetzt und der Snapshot wird
    trotzdem geloggt (sonst bliebe der Operator ohne Lebenszeichen).
    """
    global _last_status_at
    now = time.monotonic()
    if now - _last_status_at < STATUS_SNAPSHOT_INTERVAL_SEC:
        return
    _last_status_at = now

    queued: int = -1
    budget_pct: int = -1
    try:
        with get_session() as session:
            queued_val = session.execute(
                text("SELECT count(*) FROM llm_jobs WHERE status = 'queued'")
            ).scalar()
            queued = int(queued_val) if queued_val is not None else 0
            row = ensure_settings_row(session)
            tokens_used = int(row.llm_token_budget_used_today or 0)
            # ``llm_token_budget_daily`` lebt im Pydantic-Settings-Layer, nicht
            # in der DB-Row (siehe `app/services/llm_budget.py`).
            budget = max(1, int(load_settings().llm_token_budget_daily or 1))
            budget_pct = int(100 * tokens_used / budget)
            _ = row  # silence linter falls die Row sonst unused waere.
    except Exception:  # pragma: no cover — DB-Hickup darf Worker nicht killen.
        log.warning("llm_worker.status_query_failed", exc_info=True)

    durations: list[int] = _status_counters["durations_ms"]
    avg_ms = int(sum(durations) / len(durations)) if durations else 0
    log.info(
        "llm_worker.status in_flight=%s/%s queued=%s done_30s=%s failed_30s=%s "
        "cache_hits_30s=%s budget_pct=%s avg_call_ms=%s",
        in_flight,
        cap,
        queued,
        _status_counters["done"],
        _status_counters["failed"],
        _status_counters["cache_hits"],
        budget_pct,
        avg_ms,
    )
    _reset_status_counters()


def _run_subticks() -> None:
    """Synchrone Sub-Ticks zwischen den Dispatcher-Refill-Iterationen.

    Block U Phase C (ADR-0029): ersetzt das alte synchrone ``_tick()``.
    Pickup, Mode- und Budget-Check sind nicht mehr Teil der Sub-Ticks —
    die treibt der Async-Dispatcher selbst (siehe :func:`_run_async_main`).

    Sub-Ticks (jeweils mit eigener Cadence-Konstante):

    * Stale-Reaper (60s) — fuer ``llm_jobs`` UND ``scan_ingest_jobs``.
    * Debug-Log-Eviction (600s — Phase G regelt das spaeter auf 60s).
    * External-Feed-Pull-Check (600s; echter Pull max 1x/24h, Block Q).
    * Scan-Ingest-Retention-Sweep (3600s, Block R).
    * Scan-Ingest-Job-Pickup + Process (synchron, lauft parallel zum
      LLM-Mode wie heute — auch bei Mode=off/Budget-Erschoepfung).

    Cadence-Tracking via Modul-Globals (``_last_reaper_at`` etc.). Die
    heutige Logik ist 1:1 uebernommen — nur der Mode/Budget/LLM-Pickup-
    Teil ist herausgenommen.
    """
    global _last_reaper_at, _last_debug_log_eviction_at, _last_feed_pull_check_at
    global _last_retention_sweep_at, _last_pass2_backstop_sweep_at
    now_mono = time.monotonic()

    # Stale-Reaper alle 60s (beide Tabellen: llm_jobs + scan_ingest_jobs).
    if now_mono - _last_reaper_at > STALE_REAPER_INTERVAL_SEC:
        _run_stale_reaper()
        _last_reaper_at = now_mono

    # v0.9.3: Debug-Log-Eviction alle 10 Minuten.
    if now_mono - _last_debug_log_eviction_at > DEBUG_LOG_EVICTION_INTERVAL_SEC:
        _run_debug_log_eviction()
        _last_debug_log_eviction_at = now_mono

    # Block Q (ADR-0024): External-EPSS/KEV-Feed-Pull-Check alle 10 Minuten.
    # Der Tick selbst entscheidet (anhand des Audit-Logs) ob ein Pull
    # tatsaechlich faellig ist — pro Feed max 1 Pull / 24h.
    if now_mono - _last_feed_pull_check_at > FEED_PULL_CHECK_INTERVAL_SEC:
        _run_feed_enrichment_check()
        _last_feed_pull_check_at = now_mono

    # Block R (ADR-0026): Scan-Ingest-Retention-Sweep stündlich.
    if now_mono - _last_retention_sweep_at > SCAN_INGEST_RETENTION_SWEEP_INTERVAL_SEC:
        _run_scan_ingest_retention_sweep_safe()
        _last_retention_sweep_at = now_mono

    # Block R (ADR-0026): Scan-Ingest-Job-Pickup laeuft UNABHAENGIG vom
    # LLM-Mode/Budget — Ingest-Jobs muessen auch verarbeitet werden wenn
    # LLM-Mode='off' oder Token-Budget erschoepft. Synchron in den
    # Sub-Ticks: ein Ingest-Job pro Dispatcher-Iteration. Reicht weil der
    # Async-Dispatcher direkt danach wieder zurueck zum LLM-Refill kommt.
    with get_session() as session:
        scan_ingest_job_id = _pick_next_scan_ingest_job_id(session)
        session.commit()
    if scan_ingest_job_id is not None:
        _process_scan_ingest_job_safe(scan_ingest_job_id)

    # TICKET-007: Pass-2-Backstop-Sweep alle 5 min (Crash-Backstop fuer den
    # _do_pass1/_requeue_or_fail-Hook). Idempotent — bei normalem Betrieb no-op.
    if now_mono - _last_pass2_backstop_sweep_at > PASS2_BACKSTOP_SWEEP_INTERVAL_SEC:
        _run_pass2_backstop_sweep_safe()
        _last_pass2_backstop_sweep_at = now_mono


# ---------------------------------------------------------------------------
# Pass-2-Auto-Trigger (TICKET-007)
# ---------------------------------------------------------------------------


def _maybe_trigger_pass2_after_pass1(*, server_id: int | None, trigger: Pass2Trigger) -> None:
    """Triggert das Pass-2-Enqueue sobald das letzte Pass-1 fuer einen Server
    terminiert (done oder final-failed).

    Sibling-Check: nur wenn KEIN Pass-1-Job (``group_detection``) fuer den
    Server mehr ``queued``/``in_progress`` ist, wird der idempotente Helper
    ``enqueue_pass2_for_server`` gerufen — sonst wartet der Trigger auf die
    Terminierung des letzten Siblings (der dann selbst hier landet).

    Defensiv: jede Exception (DB-Hickup, Helper-Fehler) wird geloggt und
    geschluckt — der Pass-1-Done-/Fail-Pfad darf davon nicht sterben.
    """
    if server_id is None:
        return
    try:
        with get_session() as session:
            pending = session.execute(
                text(
                    """
                    SELECT count(*) FROM llm_jobs
                    WHERE job_type = 'group_detection'
                      AND server_id = :sid
                      AND status IN ('queued', 'in_progress')
                    """
                ),
                {"sid": server_id},
            ).scalar()
            if pending and int(pending) > 0:
                return
            enqueue_pass2_for_server(session, server_id, trigger=trigger)
            session.commit()
    except Exception:  # pragma: no cover — DB-Hickup darf den Worker nicht killen
        log.exception("llm_worker.pass2_trigger_failed server_id=%s", server_id)


def _run_pass2_backstop_sweep_safe() -> None:
    """Crash-Backstop fuer den Pass-2-Trigger.

    Faengt den Trigger ab wenn der Hook im ``_do_pass1``- oder
    ``_requeue_or_fail``-Pfad aus irgendeinem Grund nicht gefeuert hat
    (Worker-Crash zwischen Pass-1-Done und Hook-Aufruf, DB-Hickup).

    Findet Server-IDs mit kuerzlicher Pass-1-Aktivitaet (Performance-Guard:
    ``completed_at`` in den letzten 24 h) und 0 pending Pass-1-Jobs
    (queued + in_progress) und ruft den idempotenten Helper. Bei normaler
    Operation no-op, weil der Hook bereits gefeuert hat und der
    NOT-EXISTS-Guard im Helper greift.
    """
    try:
        with get_session() as session:
            candidate_server_ids = [
                int(row[0])
                for row in session.execute(
                    text(
                        """
                        SELECT DISTINCT server_id FROM llm_jobs
                        WHERE job_type = 'group_detection'
                          AND server_id IS NOT NULL
                          AND completed_at > now() - interval '24 hours'
                        EXCEPT
                        SELECT DISTINCT server_id FROM llm_jobs
                        WHERE job_type = 'group_detection'
                          AND server_id IS NOT NULL
                          AND status IN ('queued', 'in_progress')
                        """
                    )
                ).fetchall()
            ]
            for sid in candidate_server_ids:
                enqueue_pass2_for_server(session, sid, trigger="backstop_sweep")
            session.commit()
    except Exception:  # pragma: no cover — DB-Hickup darf den Worker nicht killen
        log.exception("llm_worker.pass2_backstop_sweep_failed")


# ---------------------------------------------------------------------------
# Pickup
# ---------------------------------------------------------------------------


def _pick_next_job_id() -> int | None:
    """Pickt den naechsten Job mit ``SELECT FOR UPDATE SKIP LOCKED``.

    Returns die Job-ID oder ``None`` wenn die Queue leer ist (oder nur Jobs
    enthaelt deren ``depends_on``-Parent noch nicht ``done`` ist).

    Wir geben bewusst nur die ID zurueck — der Caller laedt das ORM-Objekt
    in einer frischen Session, damit der Pickup-Transaktion-Scope klein
    bleibt und die SKIP-LOCKED-Garantie nicht durch nachgelagerte Reads
    verwaessert wird.

    v0.9.x: Pass-2-Jobs haben zusaetzlich zur ``depends_on``-Schicht eine
    Sibling-Wait-Bedingung — Pass-2 darf nur picken wenn KEIN Pass-1-Job
    fuer denselben ``server_id`` noch in ``queued`` oder ``in_progress``
    haengt. Damit kann Pass-2 nicht starten waehrend Pass-1-Geschwister
    noch laufen (Multi-Worker-zukunftssicher). ``failed`` Pass-1-Siblings
    blockieren NICHT — Pass-2 startet mit dem was an Groups da ist
    (Variante 3: Audit-Event signalisiert dem Operator dass nicht alles
    durch ging — siehe ``_audit_pass2_with_failed_siblings``).
    """
    sql = text(
        """
        WITH job AS (
          SELECT id FROM llm_jobs
          WHERE status = 'queued'
            AND next_attempt_at <= now()
            AND (
              depends_on IS NULL
              OR depends_on IN (SELECT id FROM llm_jobs WHERE status = 'done')
            )
            AND (
              -- Pass-1: kein extra Wait
              job_type = 'group_detection'
              OR (
                -- Pass-2: wartet bis alle Pass-1-Siblings fuer den
                -- selben server_id entweder done oder failed sind.
                job_type = 'risk_evaluation'
                AND NOT EXISTS (
                  SELECT 1 FROM llm_jobs sibling
                  WHERE sibling.job_type = 'group_detection'
                    AND sibling.server_id = llm_jobs.server_id
                    AND sibling.status IN ('queued', 'in_progress')
                )
              )
            )
          ORDER BY created_at
          LIMIT 1
          FOR UPDATE SKIP LOCKED
        )
        UPDATE llm_jobs SET
          status = 'in_progress',
          picked_up_by = :worker_id,
          picked_up_at = now(),
          attempts = attempts + 1
        WHERE id IN (SELECT id FROM job)
        RETURNING id
        """
    )
    with get_session() as session:
        row = session.execute(sql, {"worker_id": WORKER_ID}).fetchone()
        session.commit()
        if row is None:
            return None
        return int(row[0])


# ---------------------------------------------------------------------------
# Job-Processing
# ---------------------------------------------------------------------------


async def _process_one_async(job_id: int, mode: str) -> dict[str, Any] | None:
    """Single-Job-Coroutine fuer den Async-Dispatcher (Block U Phase C).

    Ersetzt das synchrone ``_process_job`` aus Pre-Block-U. Dispatcht zum
    Observation- oder Live-Branch wie bisher, faengt Exceptions ab und
    ruft :func:`_requeue_or_fail`. Bei Erfolg wird ``status='done'``,
    ``completed_at=now()`` und Audit ``llm.job_done`` geschrieben.

    Returns ein Result-Dict (``duration_ms``, optional ``cache_hit``) das
    von Phase F's ``_record_task_completion`` fuer Counter-Increment
    benutzt wird. Bei Fehler returnt die Coroutine ``None`` (die
    Exception wurde intern in ``_requeue_or_fail`` verarbeitet).
    """
    start = time.monotonic()
    try:
        with get_session() as session:
            job = session.get(LLMJob, job_id)
            if job is None:
                log.warning("llm_worker.job_missing job_id=%s", job_id)
                return None
            _audit(
                session,
                "llm.job_picked",
                target_id=str(job.id),
                metadata={"job_type": job.job_type, "mode": mode, "attempts": job.attempts},
            )
            session.commit()

        if mode == "observation":
            # Observation-Mode ist eine sync Funktion (kein LLM-Call) — wir
            # rufen sie direkt im Event-Loop auf. Sub-50-ms-DB-Session,
            # blockt den Loop nicht messbar.
            _process_observation(job_id)
        elif mode == "live":
            # Phase B/C: _process_live ist async und nutzt den persistenten
            # AsyncOpenAI-Client mit TLS-Connection-Reuse.
            await _process_live(job_id)
        else:
            # Defensive: ein "off"-Job wurde gepickt obwohl der Dispatcher-
            # Check das verhindern sollte. Wir requeuen ohne Penalty.
            _requeue(job_id, "mode flipped to off mid-pickup", penalty=False)
            return None

        duration_ms = int((time.monotonic() - start) * 1000)
        cache_hit = False
        with get_session() as session:
            job2 = session.get(LLMJob, job_id)
            if job2 is None:
                return None
            # cache_hit aus job.result fuer Phase-F-Counter ablesen.
            result_payload = job2.result or {}
            if isinstance(result_payload, dict):
                cache_hit = bool(result_payload.get("cache_hit"))
            _audit(
                session,
                "llm.job_done",
                target_id=str(job2.id),
                metadata={"job_type": job2.job_type, "duration_ms": duration_ms},
            )
            session.commit()
        return {"duration_ms": duration_ms, "cache_hit": cache_hit}
    except Exception as exc:
        _requeue_or_fail(job_id, repr(exc))
        return None


def _process_observation(job_id: int) -> None:
    """Observation-Mode: schreibt ``would_call``-Marker, kein LLM-Call.

    Verbucht ``estimate_tokens(job)`` gegen das Tagesbudget, damit der
    Operator in der Observation-Phase realistische Last simuliert sieht.
    """
    with get_session() as session:
        job = session.get(LLMJob, job_id)
        if job is None:
            return
        est = llm_budget.estimate_tokens(job)
        job.status = "done"
        job.completed_at = datetime.now(UTC)
        job.result = {
            "would_call": True,
            "job_type": job.job_type,
            "estimated_tokens": est,
            "mode": "observation",
        }
        session.commit()
        # Budget-Consume erst nach erfolgreichem Status-Update.
        llm_budget.budget_consume(session, est)


async def _process_live(job_id: int) -> None:
    """Live-Mode: dispatcht zum entsprechenden Pass-Handler."""
    with get_session() as session:
        job = session.get(LLMJob, job_id)
        if job is None:
            return
        job_type = job.job_type

    if job_type == "group_detection":
        await _do_pass1(job_id)
    elif job_type == "risk_evaluation":
        await _do_pass2(job_id)
    else:
        raise ValueError(f"unknown job_type: {job_type!r}")


# ---------------------------------------------------------------------------
# Pass 1 — Group-Detection
# ---------------------------------------------------------------------------


async def _aclose_reviewer_client(reviewer: Any) -> None:
    """Schliesst den httpx-Pool des LLM-Clients sauber.

    Ohne explizites ``aclose()`` haengen die TLS-Verbindungen des
    httpx-AsyncClient-Pools im Hintergrund bis zum naechsten GC-Lauf —
    der versucht dann ``AsyncClient.aclose()`` auf einem bereits ge-
    schlossenen ``asyncio.run()``-Event-Loop und wirft
    ``RuntimeError('Event loop is closed')`` in den Container-Log
    (Stacktrace, ~40 Zeilen pro Job, kein Crash aber Resource-Leak).

    Defensiv geschrieben: Mock-Reviewer in Tests haben kein
    ``client``-Attribut — wir tun dann einfach nichts.
    """
    client = getattr(reviewer, "client", None)
    if client is None:
        return
    aclose = getattr(client, "aclose", None)
    if aclose is None:
        return
    try:
        await aclose()
    except Exception:  # pragma: no cover — Best-Effort-Cleanup
        log.debug("llm_worker.client_aclose_failed", exc_info=True)


async def _do_pass1(job_id: int) -> None:
    """Pass 1: LLM detected Groups, Backend persistiert Library + Match-Pass."""
    with get_session() as session:
        job = session.get(LLMJob, job_id)
        if job is None:
            return
        payload = job.payload or {}
        finding_ids = [int(x) for x in (payload.get("finding_ids") or [])]
        findings = list(
            session.execute(select(Finding).where(Finding.id.in_(finding_ids))).scalars().all()
        )
        if not findings:
            # Job ist obsolet (Findings geloescht). Wir markieren ihn done
            # ohne Cache-Eintrag.
            job.status = "done"
            job.completed_at = datetime.now(UTC)
            job.result = {"skipped": True, "reason": "no findings"}
            session.commit()
            return
        job_server_id: int | None = job.server_id

    # Reviewer-Setup ausserhalb der Pickup-Session (Block U Phase B):
    # nutzt persistenten Client mit Connection-Reuse im Live-Pfad. Bei
    # gesetztem ``_reviewer_factory`` (Tests) liefert die Factory einen
    # eigenstaendigen Client den der Caller im ``finally`` aclose-d.
    with get_session() as setup_session:
        reviewer, model_name, owns_client = await _get_reviewer_for_job(setup_session)

    # LLM-Call ausserhalb der DB-Session — sonst halten wir die Connection
    # waehrend der 30-90s LLM-Latenz auf. Block U Phase F (ADR-0029): Per-Job-
    # Lifecycle-Logs entfernt; Forensik laeuft ueber `llm_debug_log`.
    result: Pass1Result
    meta: dict[str, Any]
    # v0.9.x: try/finally schliesst den httpx-Pool des AsyncOpenAI-Clients
    # noch innerhalb des asyncio.run()-Event-Loops — sonst Stacktrace im GC.
    try:
        try:
            result, meta = await reviewer.pass1_detect_groups(findings)
        except LLMInvalidResponseError as exc:
            # v0.9.5: exc.meta enthaelt die echte LLM-Response (raw_content,
            # extracted_json, usage, prompts) — Operator sieht jetzt was das
            # LLM geantwortet hat, auch wenn der Validator wirft.
            log.warning(
                "llm_worker.llm_call_failed job_id=%s job_type=pass1 "
                "error_class=%s error_preview=%.200s",
                job_id,
                type(exc).__name__,
                str(exc),
            )
            _record_pass_debug_log(
                job_id=job_id,
                job_type="pass1_group_detection",
                status="validation_error",
                model=model_name or "-",
                server_id=job_server_id,
                group_id=None,
                meta=getattr(exc, "meta", None),
                error=str(exc),
            )
            raise
        except LLMTimeoutError as exc:
            log.warning(
                "llm_worker.llm_call_failed job_id=%s job_type=pass1 "
                "error_class=%s error_preview=%.200s",
                job_id,
                type(exc).__name__,
                str(exc),
            )
            _record_pass_debug_log(
                job_id=job_id,
                job_type="pass1_group_detection",
                status="timeout",
                model=model_name or "-",
                server_id=job_server_id,
                group_id=None,
                meta=getattr(exc, "meta", None),
                error=str(exc),
            )
            raise
    finally:
        # Block U Phase B: persistenter Client wird *nicht* pro Job
        # geschlossen — nur der Test-Factory-Reviewer.
        if owns_client:
            await _aclose_reviewer_client(reviewer)

    _record_pass_debug_log(
        job_id=job_id,
        job_type="pass1_group_detection",
        status="success",
        model=model_name or "-",
        server_id=job_server_id,
        group_id=None,
        meta=meta,
        error=None,
    )

    with get_session() as session:
        await _persist_pass1_groups(session, finding_ids, result)
        # Mark job done.
        job = session.get(LLMJob, job_id)
        if job is not None:
            job.status = "done"
            job.completed_at = datetime.now(UTC)
            job.result = {
                "groups_count": len(result.groups),
                "ungrouped_count": len(result.ungrouped_finding_ids),
            }
            # Token-Buchung: Pass-1-Verbrauch ist proportional zur Findings-Zahl
            # (vgl. estimate_tokens()). Wir verbuchen die Schaetzung post-Erfolg,
            # damit Tages-Cap auch Pass-1-LLM-Calls einbezieht (Security-Auditor
            # Block-P §1, ADR-0023).
            llm_budget.budget_consume(session, llm_budget.estimate_tokens(job))
            session.commit()

    # TICKET-007 Hook A: Pass-2 enqueuen sobald das letzte Pass-1 fuer diesen
    # Server done ist (Sibling-Check im Helper-Wrapper). Eigene Session, defensiv.
    _maybe_trigger_pass2_after_pass1(server_id=job_server_id, trigger="pass1_completion")


async def _persist_pass1_groups(
    session: Session,
    input_finding_ids: list[int],
    result: Pass1Result,
) -> None:
    """Persistiert Pass-1-Result: Groups (insert/merge) + Finding-Zuordnung.

    Strategie: pro Group-Label suchen wir eine existierende Row; bei Hit
    mergen wir die Match-Patterns (Set-Union, keine Duplikate). Bei Miss
    legen wir eine neue Row an. Anschliessend setzen wir
    ``Finding.application_group_id`` fuer alle vom LLM zugeordneten IDs
    und reloaden den :class:`GroupMatcher`-Singleton damit nachfolgende
    Match-Pässe die neuen Groups sehen.
    """
    for grp in result.groups:
        existing = (
            session.execute(select(ApplicationGroup).where(ApplicationGroup.label == grp.label))
            .scalars()
            .first()
        )
        if existing is None:
            db_grp = ApplicationGroup(
                label=grp.label,
                explanation=grp.explanation,
                path_prefixes=list(grp.path_prefixes),
                pkg_name_exact=list(grp.pkg_name_exact),
                pkg_name_glob=list(grp.pkg_name_glob),
                pkg_purl_pattern=list(grp.pkg_purl_pattern),
                source="llm",
            )
            db_grp.group_kind = derive_group_kind(
                path_prefixes=list(grp.path_prefixes),
                pkg_name_exact=list(grp.pkg_name_exact),
                pkg_purl_pattern=list(grp.pkg_purl_pattern),
                pkg_name_glob=list(grp.pkg_name_glob),
            )
            session.add(db_grp)
            session.flush()
        else:
            db_grp = existing
            db_grp.path_prefixes = _union(db_grp.path_prefixes, grp.path_prefixes)
            db_grp.pkg_name_exact = _union(db_grp.pkg_name_exact, grp.pkg_name_exact)
            db_grp.pkg_name_glob = _union(db_grp.pkg_name_glob, grp.pkg_name_glob)
            db_grp.pkg_purl_pattern = _union(db_grp.pkg_purl_pattern, grp.pkg_purl_pattern)
            if grp.explanation and not db_grp.explanation:
                db_grp.explanation = grp.explanation
            # v0.9.3: ``group_kind`` defensiv ableiten — nur wenn noch NULL
            # damit existierende deterministische Werte erhalten bleiben.
            if db_grp.group_kind is None:
                db_grp.group_kind = derive_group_kind(
                    path_prefixes=list(db_grp.path_prefixes or []),
                    pkg_name_exact=list(db_grp.pkg_name_exact or []),
                    pkg_purl_pattern=list(db_grp.pkg_purl_pattern or []),
                    pkg_name_glob=list(db_grp.pkg_name_glob or []),
                )

        # Findings zuordnen.
        if grp.finding_ids:
            from sqlalchemy import update as sa_update

            session.execute(
                sa_update(Finding)
                .where(Finding.id.in_(grp.finding_ids))
                .values(application_group_id=db_grp.id)
            )

    session.commit()
    # Matcher refreshen damit der naechste Match-Pass die neuen Patterns sieht.
    matcher = GroupMatcher.get()
    matcher.reload(session)

    # Lookup-Helper — fuer Tests/Logging unbenutzt, aber wir referenzieren das
    # `input_finding_ids` damit `mypy --strict` keine unused-Variable-Warnung
    # wirft (Pass-1 droppt obsoleted Findings sauber).
    _ = input_finding_ids


def _union(existing: list[str] | None, incoming: list[str]) -> list[str]:
    """Set-Union mit stabiler Sortierung (Postgres-ARRAY-Equality stabil)."""
    merged = set(existing or [])
    merged.update(incoming)
    return sorted(merged)


# ---------------------------------------------------------------------------
# Pass 2 — Risk-Evaluation
# ---------------------------------------------------------------------------


def _audit_pass2_with_failed_siblings(session: Session, *, job_id: int, server_id: int) -> None:
    """Audit-Event wenn ein Pass-2-Job startet waehrend Pass-1-Siblings
    fuer denselben Server ``failed`` sind.

    v0.9.x: Pass-2 wartet via Pickup-Filter bis alle Pass-1-Siblings
    terminiert sind — failed Siblings blockieren NICHT (sonst wuerde
    Pass-2 nie laufen wenn ein einziger Batch konsequent timeout't).
    Damit Operator trotzdem sieht dass nicht alle Findings groupped
    werden konnten, loggen wir bei Pass-2-Start den failed-Count.
    Die failed Pass-1-Findings werden beim naechsten Re-Ingest erneut
    versucht (sind weiterhin ungrouppt → Block-P-Hook enqueued neue
    Pass-1-Jobs fuer sie).
    """
    failed_ids = [
        int(row[0])
        for row in session.execute(
            text(
                """
                SELECT id FROM llm_jobs
                WHERE job_type = 'group_detection'
                  AND server_id = :sid
                  AND status = 'failed'
                """
            ),
            {"sid": server_id},
        ).fetchall()
    ]
    if not failed_ids:
        return
    log.warning(
        "llm_worker.pass2_started_with_failed_pass1 job_id=%s server_id=%s "
        "failed_pass1_count=%s failed_pass1_ids=%s",
        job_id,
        server_id,
        len(failed_ids),
        failed_ids[:10],
    )
    _audit(
        session,
        "llm.pass2_started_with_failed_pass1",
        target_id=str(job_id),
        metadata={
            "server_id": server_id,
            "failed_pass1_count": len(failed_ids),
            "failed_pass1_ids": failed_ids[:50],
        },
    )


async def _do_pass2(job_id: int) -> None:
    """Pass 2: Risk-Bewertung pro Group, mit Cache-Lookup vor LLM-Call."""
    # Phase 1: Daten + Cache-Key vorbereiten.
    with get_session() as session:
        job = session.get(LLMJob, job_id)
        if job is None:
            return
        payload = job.payload or {}
        group_id = int(payload.get("group_id") or 0)
        server_id = int(payload.get("server_id") or 0)
        if group_id <= 0 or server_id <= 0:
            raise ValueError(f"pass2 payload invalid: {payload!r}")

        # v0.9.x: bei Pass-2-Start audit-loggen ob Pass-1-Siblings fuer
        # den selben Server gescheitert sind. Pass-2 laeuft trotzdem
        # (Variante 3), aber Operator sieht im Audit-Log dass nicht alle
        # Findings groupped werden konnten und vom naechsten Ingest
        # erneut versucht werden muessen.
        _audit_pass2_with_failed_siblings(session, job_id=job_id, server_id=server_id)

        group = session.get(ApplicationGroup, group_id)
        server = session.get(Server, server_id)
        if group is None or server is None:
            job.status = "done"
            job.completed_at = datetime.now(UTC)
            job.result = {"skipped": True, "reason": "group or server missing"}
            session.commit()
            return

        findings = list(
            session.execute(
                select(Finding)
                .where(Finding.application_group_id == group_id)
                .where(Finding.server_id == server_id)
            )
            .scalars()
            .all()
        )
        if not findings:
            job.status = "done"
            job.completed_at = datetime.now(UTC)
            job.result = {"skipped": True, "reason": "no findings in group on server"}
            session.commit()
            return

        gf_fp = group_findings_fingerprint(findings)
        cve_fp = cve_data_fingerprint(findings)
        sv_fp = server_context_fingerprint(server, session=session)
        cache_key = make_cache_key(group.id, gf_fp, cve_fp, sv_fp)

        cached = lookup(session, cache_key)
        if cached is not None:
            record_hit(session, cached)
            _upsert_evaluation(
                session,
                group_id=group_id,
                server_id=server_id,
                risk_band=cached.risk_band,
                reason=cached.reason,
                worst_finding_id=cached.worst_finding_id,
                gf_fp=gf_fp,
                action_type=cached.action_type,
            )
            inherited = inherit_group_risk_to_findings(
                session, group_ids=[group_id], server_id=server_id
            )
            job.status = "done"
            job.completed_at = datetime.now(UTC)
            job.result = {
                "cache_hit": True,
                "risk_band": cached.risk_band,
                "action_type": cached.action_type,
                "findings_inherited": inherited,
            }
            _audit(
                session,
                "llm.cache_hit",
                target_id=str(group.id),
                metadata={"server_id": server_id, "cache_key_prefix": cache_key[:16]},
            )
            session.commit()
            return

        # Cache-Miss: Daten fuer den LLM-Call snapshotten.
        group_label = group.label
        server_id_snapshot = server.id
        group_findings_ids = [int(f.id) for f in findings]

    # Block U Phase B: Reviewer-Setup *ausserhalb* der Pickup-Session,
    # damit wir den async-Helper aufrufen koennen ohne die Session ueber
    # den ``await`` hinweg offen zu halten. Live-Pfad nutzt persistenten
    # Client (kein Per-Job-aclose), Test-Factory-Pfad weiterhin mit
    # eigenstaendigem Client (Caller schliesst).
    with get_session() as setup_session:
        reviewer, model_name, owns_client = await _get_reviewer_for_job(setup_session)

    # Phase 2: LLM-Call ausserhalb der Session.
    # Wir nutzen den Reviewer mit detached-Objekten — eine zweite Session
    # haengen wir nicht an, der `pass2_evaluate_groups`-Helper akzeptiert
    # Session-loese Objekte.
    pass2_result: Pass2Result
    pass2_meta: dict[str, Any]
    # v0.9.x: try/finally schliesst den httpx-Pool des AsyncOpenAI-Clients
    # noch innerhalb des asyncio.run()-Event-Loops — sonst Stacktrace im GC.
    try:
        try:
            with get_session() as detached_session:
                group_re = detached_session.get(ApplicationGroup, group_id)
                server_re = detached_session.get(Server, server_id)
                findings_re = list(
                    detached_session.execute(
                        select(Finding).where(Finding.id.in_(group_findings_ids))
                    )
                    .scalars()
                    .all()
                )
                if group_re is None or server_re is None:
                    raise ValueError(
                        f"pass2 group/server vanished mid-job: "
                        f"group_id={group_id} server_id={server_id}"
                    )
                # Hydrate die Server-Snapshot-Listen damit `_render_pass2_prompt`
                # alle Felder hat (Server hat keine ORM-Relations dafuer).
                _hydrate_server_snapshot(detached_session, server_re)
                pass2_result, pass2_meta = await reviewer.pass2_evaluate_groups(
                    server_re, [(group_re, findings_re)]
                )
        except LLMInvalidResponseError as exc:
            # v0.9.5: meta-Dict aus exc nehmen (siehe Pass-1-Aenderung).
            log.warning(
                "llm_worker.llm_call_failed job_id=%s job_type=pass2 "
                "error_class=%s error_preview=%.200s",
                job_id,
                type(exc).__name__,
                str(exc),
            )
            _record_pass_debug_log(
                job_id=job_id,
                job_type="pass2_risk_evaluation",
                status="validation_error",
                model=model_name or "-",
                server_id=server_id,
                group_id=group_id,
                meta=getattr(exc, "meta", None),
                error=str(exc),
            )
            raise
        except LLMTimeoutError as exc:
            log.warning(
                "llm_worker.llm_call_failed job_id=%s job_type=pass2 "
                "error_class=%s error_preview=%.200s",
                job_id,
                type(exc).__name__,
                str(exc),
            )
            _record_pass_debug_log(
                job_id=job_id,
                job_type="pass2_risk_evaluation",
                status="timeout",
                model=model_name or "-",
                server_id=server_id,
                group_id=group_id,
                meta=getattr(exc, "meta", None),
                error=str(exc),
            )
            raise
    finally:
        # Block U Phase B: persistenten Client *nicht* pro Job schliessen.
        if owns_client:
            await _aclose_reviewer_client(reviewer)

    _record_pass_debug_log(
        job_id=job_id,
        job_type="pass2_risk_evaluation",
        status="success",
        model=model_name or "-",
        server_id=server_id,
        group_id=group_id,
        meta=pass2_meta,
        error=None,
    )

    # Phase 3: Result + Cache schreiben.
    evaluation = _pick_evaluation(pass2_result, group_label)
    if evaluation is None:
        raise LLMInvalidResponseError(
            f"pass2 LLM did not return evaluation for group {group_label!r}"
        )

    with get_session() as session:
        group2 = session.get(ApplicationGroup, group_id)
        inherited = 0
        if group2 is not None:
            _upsert_evaluation(
                session,
                group_id=group_id,
                server_id=server_id,
                risk_band=evaluation.risk_band,
                reason=evaluation.reason,
                worst_finding_id=evaluation.worst_finding_id,
                gf_fp=gf_fp,
                action_type=evaluation.action_type,
            )
            inherited = inherit_group_risk_to_findings(
                session, group_ids=[group_id], server_id=server_id
            )
        store(
            session,
            cache_key=cache_key,
            group_id=group_id,
            group_findings_fp=gf_fp,
            cve_data_fp=cve_fp,
            server_context_fp=sv_fp,
            risk_band=evaluation.risk_band,
            worst_finding_id=evaluation.worst_finding_id,
            reason=evaluation.reason,
            llm_model=model_name,
            action_type=evaluation.action_type,
        )
        job = session.get(LLMJob, job_id)
        if job is not None:
            job.status = "done"
            job.completed_at = datetime.now(UTC)
            job.result = {
                "cache_hit": False,
                "risk_band": evaluation.risk_band,
                "action_type": evaluation.action_type,
                "findings_inherited": inherited,
            }
        session.commit()
        lru_evict_if_needed(session)
        session.commit()

    # Token-Buchung — wir kennen den genauen Verbrauch nicht (kein Streaming-
    # Usage-Hook fuer JSON-Mode), buchen die Schaetzung.
    with get_session() as session:
        # Pseudo-Job um estimate_tokens fuer Pass2 zu bekommen — bei `risk_
        # evaluation` ist die Schaetzung konstant 2000.
        llm_budget.budget_consume(session, 2000)
    _ = server_id_snapshot  # keep linter happy
    _ = inherited  # nur fuer den (entfernten) persist-done-Log gebraucht.


def _record_pass_debug_log(
    *,
    job_id: int,
    job_type: str,
    status: str,
    model: str,
    server_id: int | None,
    group_id: int | None,
    meta: dict[str, Any] | None,
    error: str | None,
) -> None:
    """Schreibt eine ``llm_debug_log``-Row mit (gecappten) Bodies.

    ``meta`` ist das Tuple-Return-Meta-Dict von
    :meth:`LLMRiskReviewer.pass1_detect_groups` /
    :meth:`pass2_evaluate_groups`. ``None`` ist erlaubt — z.B. wenn der
    LLM-Call vor dem Response stirbt (Timeout/Exception in SDK).

    Defensiv geloggt — Debug-Log-Failures duerfen die Job-Pipeline nicht
    killen.

    Block U Phase G (ADR-0029): Success-Calls werden 1:``llm_debug_log_
    success_sample_rate`` herunter-gesampelt, Fehler-Calls bleiben 1:1.
    """
    try:
        cfg = load_settings()
        if not llm_debug_log.should_sample_debug_log(
            job_id=job_id,
            job_type=job_type,
            status=status,
            sample_rate=cfg.llm_debug_log_success_sample_rate,
        ):
            return
        # Request-Body: erste 1KB System-Prompt + erste 8KB User-Prompt, plus
        # Model+max_tokens. Body-Size-Cap im Service wendet zusaetzlich an.
        if meta is not None:
            sys_p = str(meta.get("system_prompt") or "")[:1024]
            usr_p = str(meta.get("user_prompt") or "")[:8192]
            max_t = meta.get("max_tokens")
        else:
            sys_p = ""
            usr_p = ""
            max_t = None
        request_body: dict[str, Any] = {
            "system_prompt": sys_p,
            "user_prompt": usr_p,
            "model": model,
            "max_tokens": max_t,
        }
        response_body: dict[str, Any] | None
        duration_ms = 0
        if meta is not None:
            raw_c = str(meta.get("raw_content") or "")[:32768]
            ext_j = str(meta.get("extracted_json") or "")[:32768]
            reason_f_raw = meta.get("reasoning_field")
            reason_f = str(reason_f_raw)[:16384] if reason_f_raw else None
            response_body = {
                "raw_content": raw_c,
                "extracted_json": ext_j,
                "reasoning_field": reason_f,
                "usage": meta.get("usage"),
                # v0.9.7: finish_reason aus meta persistieren ("stop" / "length"
                # / "content_filter") — hilft die Diagnose ob max_tokens
                # waehrend Reasoning aufgebraucht wurde.
                "finish_reason": meta.get("finish_reason"),
            }
            duration_ms = int(meta.get("duration_ms") or 0)
        else:
            response_body = None

        with get_session() as session:
            job = session.get(LLMJob, job_id)
            llm_debug_log.record(
                session,
                job=job,
                job_type=job_type,
                status=status,
                model=model,
                request_body=request_body,
                response_body=response_body,
                duration_ms=duration_ms,
                server_id=server_id,
                group_id=group_id,
                error=error,
            )
            session.commit()
    except Exception:  # pragma: no cover — DB-Hickup darf den Worker nicht killen
        log.exception("llm_worker.debug_log_insert_failed job_id=%s", job_id)


def _pick_evaluation(result: Pass2Result, group_label: str) -> Pass2Evaluation | None:
    for ev in result.evaluations:
        if ev.group_label == group_label:
            return ev
    return None


def _upsert_evaluation(
    session: Any,
    *,
    group_id: int,
    server_id: int,
    risk_band: str,
    reason: str | None,
    worst_finding_id: int | None,
    gf_fp: str,
    action_type: str | None = None,
) -> None:
    """UPSERT in ``application_group_evaluations`` (ADR-0028, Block T).

    Ersetzt das frühere ``_apply_pass2_to_group``: statt die Eval-Felder
    direkt auf der ``ApplicationGroup``-Row zu setzen (last-write-wins-
    Bug zwischen Servern), wird die ``(group_id, server_id)``-Junction-Row
    per ``pg_insert().on_conflict_do_update()`` atomar geschrieben.

    Bei Cache-Hits aus Pre-v0.9.3-Eintraegen ohne ``action_type`` bleibt
    der Wert ``None`` — die UI ``NULL → 'investigate'``-Abbildung greift
    ohnehin.
    """
    stmt = pg_insert(ApplicationGroupEvaluation).values(
        group_id=group_id,
        server_id=server_id,
        risk_band=risk_band,
        risk_band_reason=reason,
        risk_band_source="llm",
        risk_band_computed_at=datetime.now(UTC),
        worst_finding_id=worst_finding_id,
        group_findings_fingerprint=gf_fp,
        action_type=action_type,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["group_id", "server_id"],
        set_={
            "risk_band": stmt.excluded.risk_band,
            "risk_band_reason": stmt.excluded.risk_band_reason,
            "risk_band_source": stmt.excluded.risk_band_source,
            "risk_band_computed_at": stmt.excluded.risk_band_computed_at,
            "worst_finding_id": stmt.excluded.worst_finding_id,
            "group_findings_fingerprint": stmt.excluded.group_findings_fingerprint,
            "action_type": stmt.excluded.action_type,
        },
    )
    session.execute(stmt)


def _hydrate_server_snapshot(session: Session, server: Server) -> None:
    """Laedt die vier Snapshot-Listen direkt auf das ``server``-Objekt.

    :class:`Server` hat keine ORM-Relations fuer ``listeners`` / ``processes``
    / ``kernel_modules`` / ``services`` (das sind separate Tabellen ohne
    Relation-Eintrag im Model). Der Reviewer-Prompt-Renderer greift via
    ``getattr(server, "listeners", [])`` darauf zu — wir setzen die Listen
    explizit als Attribute auf das ORM-Objekt.
    """
    from app.models import ServerKernelModule, ServerListener, ServerProcess, ServerService

    server.listeners = list(  # type: ignore[attr-defined]
        session.execute(select(ServerListener).where(ServerListener.server_id == server.id))
        .scalars()
        .all()
    )
    server.processes = list(  # type: ignore[attr-defined]
        session.execute(select(ServerProcess).where(ServerProcess.server_id == server.id))
        .scalars()
        .all()
    )
    server.kernel_modules = list(  # type: ignore[attr-defined]
        session.execute(select(ServerKernelModule).where(ServerKernelModule.server_id == server.id))
        .scalars()
        .all()
    )
    server.services = list(  # type: ignore[attr-defined]
        session.execute(select(ServerService).where(ServerService.server_id == server.id))
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------
# Reviewer / Client-Bau
# ---------------------------------------------------------------------------


def _build_reviewer(session: Session) -> tuple[LLMRiskReviewer, str | None]:
    """Baut einen LLMRiskReviewer aus der Settings-Singleton.

    Returns (reviewer, model_name). Tests koennen den Reviewer ueber
    :func:`set_reviewer_factory_for_tests` ersetzen.

    Hinweis (Block U Phase B): im Live-Pfad rufen ``_do_pass1``/
    ``_do_pass2`` stattdessen :func:`_get_reviewer_for_job` auf, was den
    persistenten Client wiederverwendet. ``_build_reviewer`` bleibt fuer
    Test-Hook-Kompatibilitaet und altinterne Aufrufer erhalten — baut bei
    Bedarf einen *neuen*, eigenstaendigen Client (Caller ist dann fuer
    ``_aclose_reviewer_client`` zustaendig).
    """
    if _reviewer_factory is not None:
        result = _reviewer_factory(session)
        # Tests koennen ein Tuple oder bei Bedarf einen Reviewer-Stub liefern.
        return result  # type: ignore[no-any-return]
    settings_row = ensure_settings_row(session)
    cfg = load_settings()
    client = build_client_from_settings(
        settings_row, encryption_key=cfg.encryption_key.get_secret_value()
    )
    return LLMRiskReviewer(client=client), client.model


async def _get_reviewer_for_job(
    session: Session,
) -> tuple[LLMRiskReviewer, str | None, bool]:
    """Live-Pfad-Reviewer-Setup mit persistentem Client (Block U Phase B).

    Returns ``(reviewer, model_name, owns_client_lifecycle)``.

    * ``owns_client_lifecycle=True`` wenn ein Test-Factory-Reviewer
      geliefert wird (Caller ruft ``_aclose_reviewer_client`` im
      ``finally``). Backward-compatible mit bestehenden Tests die
      ``set_reviewer_factory_for_tests`` benutzen.
    * ``owns_client_lifecycle=False`` im Production-Pfad — der
      persistente Client bleibt modul-global cached und wird
      *nicht* pro Job geschlossen. Genau das ist der Punkt von
      Phase B: TLS-Connection-Reuse ueber Job-Grenzen hinweg.
    """
    if _reviewer_factory is not None:
        # Test-Hook: alte Semantik, Caller schliesst den Client.
        reviewer, model_name = _build_reviewer(session)
        return reviewer, model_name, True
    client, model_name = await _get_or_build_async_client(session)
    return LLMRiskReviewer(client=client), model_name, False


_reviewer_factory: Any | None = None


def set_reviewer_factory_for_tests(
    factory: Any | None,
) -> None:
    """Test-Hook: ``factory(session) -> (LLMRiskReviewer, model_name)``."""
    global _reviewer_factory
    _reviewer_factory = factory


# ---------------------------------------------------------------------------
# Block U Phase B — Persistenter Async-Client mit Fingerprint-Cache
# ---------------------------------------------------------------------------


def _compute_client_fingerprint(
    base_url: str, model: str, api_key_plaintext: str
) -> tuple[str, str, str]:
    """Liefert ``(base_url, model, sha256_hex(api_key))``.

    Der API-Key wird *niemals* im Klartext zurueckgegeben oder geloggt —
    nur sein SHA-256-Hex-Digest. Bei leerem Key (Ollama-Localhost-Default)
    hashen wir den leeren String; das ist konsistent und differenziert
    sauber von einem konfigurierten Key.
    """
    import hashlib

    digest = hashlib.sha256(api_key_plaintext.encode("utf-8")).hexdigest()
    return (base_url, model, digest)


async def _get_or_build_async_client(session: Session) -> tuple[LlmClient, str]:
    """Gibt den persistenten ``LlmClient`` zurueck, rebuilt bei Mismatch.

    Fingerprint = ``(base_url, model, sha256_hex(api_key_plaintext))``.

    * Erster Aufruf: Client wird gebaut, Fingerprint gesetzt.
    * Unveraenderte Settings: derselbe Client (Connection-Pool-Reuse).
    * Settings-Aenderung (eines der drei Felder): alter Client wird
      ``await aclose()``-d, neuer Client gebaut.

    Logging-Marker bei Rebuild: ``llm_worker.client_rebuilt``. API-Key
    erscheint *nicht* im Log — nur ``base_url`` und ``model``.

    Returns ``(client, model_name)``. Der ``model_name`` wird vom Caller
    in den ``LLMRiskReviewer``-Konstruktor weiter gereicht (heute
    ueberfluessig weil Reviewer den Client haelt, aber wir folgen der
    bestehenden ``_build_reviewer``-Signatur fuer minimale Aufrufer-
    Anpassung im Live-Pfad).

    Thread-/Coroutine-Sicherheit: ein modul-globales ``asyncio.Lock``
    serialisiert die Rebuild-Section, damit unter Phase-C-Concurrency
    nicht zwei Tasks gleichzeitig einen Rebuild starten.
    """
    global _cached_client, _cached_client_fingerprint, _cached_client_lock

    # Lock lazy im aktuellen Event-Loop bauen. ``asyncio.Lock()``
    # erfordert seit Python 3.10 keinen Loop mehr zur Instanziierung,
    # aber wir bleiben defensiv und bauen ihn beim ersten Async-Aufruf
    # damit das Lock-Objekt sicher zum laufenden Loop gehoert.
    if _cached_client_lock is None:
        _cached_client_lock = asyncio.Lock()

    settings_row = ensure_settings_row(session)
    cfg = load_settings()
    # Klartext-Key entschluesseln um den Fingerprint zu berechnen. Wir
    # lassen den Wert nur so lange im Stack-Frame leben wie noetig und
    # uebergeben ihn nie an Logging.
    plain_key = ""
    if settings_row.llm_api_key_encrypted:
        from app.services.llm_client import decrypt_api_key

        plain_key = decrypt_api_key(
            settings_row.llm_api_key_encrypted,
            cfg.encryption_key.get_secret_value(),
        )
    base_url = settings_row.llm_base_url or ""
    model = settings_row.llm_model or ""
    if not base_url or not model:
        # Konsistent mit ``build_client_from_settings``: ohne Provider-
        # Konfig faellt der Live-Pfad ohnehin frueher (Mode=off oder
        # _read_mode_safe-Default). Wir reichen den Fehler hoch.
        from app.services.llm_client import LlmNotConfiguredError

        raise LlmNotConfiguredError("LLM-Provider noch nicht konfiguriert")

    fingerprint = _compute_client_fingerprint(base_url, model, plain_key)

    async with _cached_client_lock:
        if _cached_client is not None and _cached_client_fingerprint == fingerprint:
            return _cached_client, _cached_client.model
        # Rebuild-Pfad.
        old_client = _cached_client
        if old_client is not None:
            try:
                await old_client.aclose()
            except Exception:  # pragma: no cover — Best-Effort-Cleanup
                log.debug("llm_worker.client_rebuild_aclose_failed", exc_info=True)
        new_client = build_client_from_settings(
            settings_row, encryption_key=cfg.encryption_key.get_secret_value()
        )
        _cached_client = new_client
        _cached_client_fingerprint = fingerprint
        # Niemals den API-Key oder seinen Hash loggen — nur base_url +
        # model + Rebuild-Grund.
        log.info(
            "llm_worker.client_rebuilt reason=fingerprint_changed base_url=%s model=%s",
            base_url,
            model,
        )
        return new_client, new_client.model


def reset_client_cache_for_tests() -> None:
    """Test-Hook — leert den persistenten Client-Cache (Block U Phase B).

    Setzt Client, Fingerprint und Lock zurueck. Schliesst den alten
    Client *nicht* synchron (es gibt keinen laufenden Loop in Pure-Unit-
    Tests); das ist ok, weil Tests den Cache vor *Setup* leeren und der
    GC im Test-Teardown den httpx-Pool aufraeumt.
    """
    global _cached_client, _cached_client_fingerprint, _cached_client_lock
    _cached_client = None
    _cached_client_fingerprint = None
    _cached_client_lock = None


# ---------------------------------------------------------------------------
# Stale-Reaper
# ---------------------------------------------------------------------------


def _run_debug_log_eviction() -> None:
    """Sub-Tick fuer ``llm_debug_log``-Eviction (v0.9.3).

    Wendet Time-Cap (``llm_debug_log_max_age_days``) und Count-Cap
    (``llm_debug_log_max_rows``) an. Defensiv geloggt — DB-Hickup hier
    darf den Worker nicht killen.
    """
    try:
        with get_session() as session:
            time_evicted, count_evicted = llm_debug_log.evict_old(session)
            if time_evicted or count_evicted:
                log.info(
                    "llm_worker.debug_log_evicted time=%s count=%s",
                    time_evicted,
                    count_evicted,
                )
    except Exception:  # pragma: no cover — DB-Hickup
        log.exception("llm_worker.debug_log_eviction_failed")


def _run_feed_enrichment_check() -> None:
    """Sub-Tick fuer External-EPSS/KEV-Feed-Pull (Block Q, ADR-0024).

    Delegiert an :func:`feed_enrichment.feed_enrichment_tick`. Der Tick
    entscheidet selbst (per ``feed_pull_log``-Lookup) ob ein Pull faellig
    ist — wir rufen ihn alle 10 Minuten auf, der echte HTTP-Pull
    passiert max 1x / 24h pro Feed.

    Defensiv try/except: ein DB-Hickup oder ein Bug im Tick darf den
    Worker-Loop nicht killen.
    """
    try:
        with get_session() as session:
            feed_enrichment.feed_enrichment_tick(session)
    except Exception:  # pragma: no cover — DB-/Tick-Failure
        log.exception("llm_worker.feed_enrichment_check_failed")


# ---------------------------------------------------------------------------
# Block R — Scan-Ingest-Sub-Tick-Wrapper
# ---------------------------------------------------------------------------


def _pick_next_scan_ingest_job_id(session: Session) -> int | None:
    """Wrapper: delegiert an scan_ingest_worker._pick_next_scan_ingest_job_id."""
    from app.workers.scan_ingest_worker import (
        _pick_next_scan_ingest_job_id as _siw_pick,
    )

    return _siw_pick(session)


def _process_scan_ingest_job_safe(job_id: int) -> None:
    """Verarbeitet einen Scan-Ingest-Job. Defensiv try/except fuer den Tick-Loop.

    Exception im Worker darf den gesamten llm_worker-Dispatcher-Loop nicht
    killen (Block U Phase C: _run_subticks ist der Caller).
    """
    from app.workers.scan_ingest_worker import (
        _process_scan_ingest_job as _siw_process,
    )

    try:
        _siw_process(job_id, _get_session_factory(), WORKER_ID)
    except Exception:  # pragma: no cover — Sicherheitsnetz fuer den Tick-Loop
        log.exception("llm_worker.scan_ingest_job_failed job_id=%s", job_id)


def _run_scan_ingest_retention_sweep_safe() -> None:
    """Fuehrt den Scan-Ingest-Retention-Sweep aus. Defensiv try/except."""
    from app.workers.scan_ingest_worker import (
        _run_scan_ingest_retention_sweep as _siw_retention,
    )

    try:
        with get_session() as session:
            _siw_retention(session)
            session.commit()
    except Exception:  # pragma: no cover — DB-Hickup
        log.exception("llm_worker.scan_ingest_retention_sweep_failed")


def _run_stale_reaper() -> None:
    """Reset't ``in_progress``-Jobs deren ``picked_up_at`` zu alt ist.

    Zwei Statements:

    1. ``attempts < MAX_ATTEMPTS`` → zurueck auf ``queued`` mit Backoff
       (``next_attempt_at = now() + attempts * 1 minute``).
    2. ``attempts >= MAX_ATTEMPTS`` → ``status = 'failed'``,
       ``error = 'max attempts after stale'``.

    Audit ``llm.job_reaped`` mit Counts.
    """
    timeout_min = _stale_timeout_min()
    with get_session() as session:
        # Step 1: requeue.
        requeued = session.execute(
            text(
                """
                UPDATE llm_jobs
                SET status = 'queued',
                    picked_up_by = NULL,
                    picked_up_at = NULL,
                    next_attempt_at = now() + (attempts * interval '1 minute')
                WHERE status = 'in_progress'
                  AND picked_up_at < now() - make_interval(mins => :mins)
                  AND attempts < :max_attempts
                RETURNING id
                """
            ),
            {"mins": timeout_min, "max_attempts": MAX_ATTEMPTS},
        ).fetchall()
        # Step 2: fail.
        failed = session.execute(
            text(
                """
                UPDATE llm_jobs
                SET status = 'failed',
                    error = 'max attempts after stale'
                WHERE status = 'in_progress'
                  AND picked_up_at < now() - make_interval(mins => :mins)
                  AND attempts >= :max_attempts
                RETURNING id
                """
            ),
            {"mins": timeout_min, "max_attempts": MAX_ATTEMPTS},
        ).fetchall()
        session.commit()
        if requeued or failed:
            # v0.9.5: Stale-Reaper-Count explizit loggen (vorher nur Audit).
            log.info(
                "llm_worker.stale_reaped_count requeued=%s failed=%s",
                len(requeued),
                len(failed),
            )
            _audit(
                session,
                "llm.job_reaped",
                target_id=None,
                metadata={
                    "requeued": [r[0] for r in requeued],
                    "failed": [r[0] for r in failed],
                },
            )
            session.commit()

    # Block R (ADR-0026): Scan-Ingest-Stale-Reaper (zweite Tabelle).
    try:
        from app.workers.scan_ingest_worker import (
            _run_scan_ingest_stale_reaper as _siw_reaper,
        )

        with get_session() as session:
            _siw_reaper(session)
            session.commit()
    except Exception:  # pragma: no cover — DB-Hickup
        log.exception("llm_worker.scan_ingest_stale_reaper_failed")


# ---------------------------------------------------------------------------
# Requeue / Fail
# ---------------------------------------------------------------------------


def _requeue(job_id: int, error: str, *, penalty: bool) -> None:
    """Requeue ohne Attempt-Erhoehung (penalty=False bei system-Faults)."""
    with get_session() as session:
        job = session.get(LLMJob, job_id)
        if job is None:
            return
        backoff_min = max(1, job.attempts) if penalty else 0
        session.execute(
            text(
                """
                UPDATE llm_jobs
                SET status = 'queued',
                    picked_up_by = NULL,
                    picked_up_at = NULL,
                    next_attempt_at = now() + make_interval(mins => :mins),
                    error = :error
                WHERE id = :id
                """
            ),
            {"mins": backoff_min, "error": error[:1024], "id": job_id},
        )
        session.commit()


def _requeue_or_fail(job_id: int, error: str) -> None:
    """Decide between requeue (with backoff) and final fail.

    Pass-1- und Pass-2-Jobs duerfen 3 Versuche haben. Beim Erreichen wird
    ``status='failed'`` gesetzt und Audit ``llm.job_failed`` geschrieben.
    """
    is_timeout_or_llm = any(
        marker in error.lower()
        for marker in (
            "timeout",
            "llminvalidresponse",
            "llmtimeout",
            # v0.9.4: OpenAI-SDK-Fehler (z.B. ``BadRequestError`` bei
            # Context-Window-Ueberschreitung) sollen ebenfalls als
            # LLM-Fehler klassifiziert werden, damit Audit-Metadata und
            # Log-Zeile is_llm=True ausweisen.
            "badrequest",
            "apistatuserror",
        )
    )
    with get_session() as session:
        job = session.get(LLMJob, job_id)
        if job is None:
            return
        if job.attempts >= MAX_ATTEMPTS:
            # TICKET-007 Hook B: server_id/job_type vor dem Commit sichern, der
            # Pass-2-Trigger laeuft danach in eigener Session.
            failed_server_id = job.server_id
            failed_job_type = job.job_type
            job.status = "failed"
            job.error = error[:1024]
            job.completed_at = datetime.now(UTC)
            _audit(
                session,
                "llm.job_failed",
                target_id=str(job.id),
                metadata={
                    "job_type": job.job_type,
                    "attempts": job.attempts,
                    "error_class": _classify_error(error),
                },
            )
            session.commit()
            log.warning(
                "llm_worker.job_failed job_id=%s attempts=%s error=%s",
                job_id,
                job.attempts,
                error[:200],
            )
            # Pass-2 enqueuen wenn ein Pass-1 final failed und keine Pass-1-
            # Siblings mehr laufen (Sibling-Check im Helper-Wrapper).
            if failed_job_type == "group_detection":
                _maybe_trigger_pass2_after_pass1(
                    server_id=failed_server_id, trigger="pass1_final_failed"
                )
            return
        # Requeue mit exponential backoff (attempts * 60s).
        backoff_min = max(1, job.attempts)
        job.status = "queued"
        job.picked_up_by = None
        job.picked_up_at = None
        job.error = error[:1024]
        session.execute(
            text(
                "UPDATE llm_jobs "
                "SET next_attempt_at = now() + make_interval(mins => :mins) "
                "WHERE id = :id"
            ),
            {"mins": backoff_min, "id": job_id},
        )
        session.commit()
        log.info(
            "llm_worker.job_requeued job_id=%s attempts=%s backoff_min=%s is_llm=%s",
            job_id,
            job.attempts,
            backoff_min,
            is_timeout_or_llm,
        )


def _classify_error(error: str) -> str:
    el = error.lower()
    if "llmtimeout" in el or "timeout" in el:
        return "timeout"
    if "llminvalidresponse" in el:
        return "invalid_response"
    # v0.9.4: OpenAI-SDK-Fehlerketten — ``BadRequestError`` (z.B.
    # Context-Window-Ueberschreitung), allgemeines ``APIStatusError``
    # oder die textuelle ``Error code: NNN``-Markierung.
    if "badrequest" in el or "apistatuserror" in el or "error code:" in el:
        return "llm_api_error"
    return "other"


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


def _write_heartbeat() -> None:
    """Schreibt ``settings.llm_worker_heartbeat_at = now()`` (kein Audit-Spam)."""
    try:
        with get_session() as session:
            row = ensure_settings_row(session)
            row.llm_worker_heartbeat_at = datetime.now(UTC)
            session.commit()
    except Exception:  # pragma: no cover — DB-Hickup
        log.exception("llm_worker.heartbeat_failed")


def _heartbeat_loop() -> None:
    """Daemon-Loop der unabhaengig vom Tick alle 10s ``_write_heartbeat()`` ruft.

    v0.9.5: vorher wurde der Heartbeat im ``_tick()`` geschrieben — bei langem
    LLM-Call (60-120s) blockierte ``_tick()`` im ``_process_job``, der Heartbeat
    veraltete und k8s livenessProbe (``failureThreshold=3 x periodSeconds=30``
    = 90s Toleranz, ``HEARTBEAT_MAX_AGE_SEC=30`` in ``healthcheck.py``) killte
    den Pod mitten im LLM-Call → Job blieb in ``in_progress`` haengen bis der
    Stale-Reaper ihn nach 5 Minuten requeued hat.

    Daemon-Flag: stirbt automatisch mit dem Hauptprozess. Stop-Event wird
    parallel via ``_heartbeat_thread_stop.wait(timeout=...)`` abgefragt fuer
    saubere Shutdown-Latency.
    """
    log.info(
        "llm_worker.heartbeat_thread_started interval_sec=%s",
        HEARTBEAT_INTERVAL_SEC,
    )
    while not _heartbeat_thread_stop.is_set():
        try:
            _write_heartbeat()
        except Exception:  # pragma: no cover
            log.exception("llm_worker.heartbeat_thread_write_failed")
        # ``wait`` gibt sofort zurueck wenn Stop-Event gesetzt — saubere
        # Shutdown-Latency (kein time.sleep() das blockt).
        _heartbeat_thread_stop.wait(timeout=HEARTBEAT_INTERVAL_SEC)
    log.info("llm_worker.heartbeat_thread_stopped")


def _start_heartbeat_thread() -> threading.Thread:
    """Startet den Heartbeat-Daemon-Thread (idempotent: returned existing
    wenn schon alive).

    Wird vom ``main()``-Entrypoint und von Tests genutzt.
    """
    global _heartbeat_thread
    if _heartbeat_thread is not None and _heartbeat_thread.is_alive():
        return _heartbeat_thread
    _heartbeat_thread_stop.clear()
    _heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True, name="llm-worker-hb")
    _heartbeat_thread.start()
    return _heartbeat_thread


def _stop_heartbeat_thread(timeout: float = 5.0) -> None:
    """Stoppt den Heartbeat-Thread (Stop-Event + Join). Idempotent."""
    global _heartbeat_thread
    _heartbeat_thread_stop.set()
    t = _heartbeat_thread
    if t is not None and t.is_alive():
        t.join(timeout=timeout)
    _heartbeat_thread = None


# ---------------------------------------------------------------------------
# Audit-Wrapper (kein-Flask-Variante)
# ---------------------------------------------------------------------------


def _audit(
    session: Session,
    action: str,
    *,
    target_id: str | None,
    metadata: dict[str, Any] | None,
) -> None:
    """Schreibt einen Audit-Event mit ``actor='worker'`` (kein Flask-Kontext).

    Lazy-Import damit `app.audit` nicht zum Modul-Import-Zeitpunkt
    Flask hineinzieht — der Worker hat keinen Flask-Context.
    """
    from app.audit import log_event

    try:
        log_event(
            action,
            target_type="llm_job" if action.startswith("llm.job") else "llm",
            target_id=target_id,
            actor="worker",
            session=session,
            metadata=metadata,
        )
    except Exception:  # pragma: no cover — Audit-Fehler darf den Worker nicht killen
        log.exception("llm_worker.audit_failed action=%s", action)


# ---------------------------------------------------------------------------
# Public testing helpers
# ---------------------------------------------------------------------------


# `Pass1Group`/`Pass1Result`/`Pass2Evaluation`/`Pass2Result` und
# `LLMTimeoutError`/`LlmClient` werden im Modul nicht direkt referenziert
# (die Imports machen sie nur fuer Tests verfuegbar) — wir halten sie
# explizit in einem Tuple damit `mypy --strict` keine unused-Imports
# meckert.
_REEXPORTS: tuple[type, ...] = (
    Pass1Group,
    Pass1Result,
    Pass2Evaluation,
    Pass2Result,
    LLMTimeoutError,
    LlmClient,
)


if __name__ == "__main__":  # pragma: no cover — Entrypoint
    main()


__all__ = [
    "HEARTBEAT_INTERVAL_SEC",
    "MAX_ATTEMPTS",
    "STALE_REAPER_INTERVAL_SEC",
    "WORKER_ID",
    "get_session",
    "main",
    "request_shutdown_for_tests",
    "reset_client_cache_for_tests",
    "reset_shutdown_for_tests",
    "set_reviewer_factory_for_tests",
    "set_session_factory_for_tests",
]
