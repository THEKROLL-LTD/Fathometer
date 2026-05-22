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
from sqlalchemy.orm import Session, sessionmaker

from app.config import load_settings
from app.models import ApplicationGroup, Finding, LLMJob, Server
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
# `llm_debug_log`. Wir laufen alle 10 Minuten (analog Stale-Reaper-Cadence).
DEBUG_LOG_EVICTION_INTERVAL_SEC: float = 600.0
# Block Q (ADR-0024): External-EPSS/KEV-Feed-Pull-Sub-Tick. Alle 10 Minuten
# nachschauen ob ein Pull faellig ist — der Pull selbst laeuft nur 1x pro
# Tag pro Feed (entscheidet ``feed_enrichment_tick`` per Audit-Log).
FEED_PULL_CHECK_INTERVAL_SEC: float = 600.0
# v0.9.6: Idle-CPU-Reduktion. Mode-Wechsel ist Operator-Action; alle 2s die
# Settings-Row zu pollen ist Verschwendung. Cache 30s — Mode-Switch wird also
# binnen <30s wirksam, was operativ vollkommen ausreicht.
MODE_CHECK_INTERVAL_SEC: float = 30.0
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

# v0.9.5: Heartbeat-Daemon-Thread + Stop-Event. Damit der Heartbeat
# unabhaengig vom (potentiell 30-120s blockierenden) LLM-Call im
# `_process_job` weiterlaeuft — sonst kickt die k8s livenessProbe
# (HEARTBEAT_MAX_AGE_SEC=30 in healthcheck.py) den Pod mitten im Call.
_heartbeat_thread: threading.Thread | None = None
_heartbeat_thread_stop: threading.Event = threading.Event()

# Lazy-erzeugte Session-Factory (kein Flask-App-Context).
_session_factory: sessionmaker[Session] | None = None


# ---------------------------------------------------------------------------
# Session-Management
# ---------------------------------------------------------------------------


def _get_session_factory() -> sessionmaker[Session]:
    """Lazy-baut die Worker-Session-Factory aus ``SECSCAN_DATABASE_URL``.

    Wir wollen genau eine Engine im Worker-Prozess (Connection-Pool wieder-
    verwenden), bauen sie aber lazy damit Tests die Factory per
    :func:`set_session_factory_for_tests` ersetzen koennen, bevor der erste
    Tick laeuft.
    """
    global _session_factory
    if _session_factory is None:
        cfg = load_settings()
        engine = create_engine(cfg.database_url, pool_pre_ping=True, future=True)
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
    global _last_feed_pull_check_at, _last_retention_sweep_at
    _shutdown = False
    _last_heartbeat_at = 0.0
    _last_reaper_at = 0.0
    _last_debug_log_eviction_at = 0.0
    _last_feed_pull_check_at = 0.0
    _last_retention_sweep_at = 0.0
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
    _cached_mode = None
    _mode_cached_at = 0.0
    _cached_budget_ok = True
    _budget_cached_at = 0.0
    _idle_backoff_sec = None


# ---------------------------------------------------------------------------
# Tick-Loop und Sub-Ticks
# ---------------------------------------------------------------------------


def main() -> None:
    """Worker-Entrypoint — Endlos-Schleife, bricht bei Shutdown-Flag ab."""
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

    while not _shutdown:
        try:
            _tick()
        except Exception:  # pragma: no cover — Tick-Loop-Sicherheit
            log.exception("llm_worker.tick_failed sleeping_and_retrying")
            time.sleep(_poll_interval() * 2)

    # v0.9.5: graceful shutdown — Heartbeat-Thread stoppen + max 5s warten.
    _stop_heartbeat_thread(timeout=5.0)

    log.info("llm_worker.shutdown_complete worker_id=%s", WORKER_ID)


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


def _idle_sleep_and_backoff() -> None:
    """Sleep bei leerer Queue mit exponentieller Backoff bis Cap.

    Bei jedem aufeinanderfolgenden Leer-Pickup steigt die Sleep-Dauer um
    ``IDLE_BACKOFF_FACTOR``, max ``IDLE_BACKOFF_MAX_SEC``. Reset auf
    ``_poll_interval()`` erfolgt im Caller sobald ein Pickup gelingt.
    """
    global _idle_backoff_sec
    if _idle_backoff_sec is None:
        _idle_backoff_sec = _poll_interval()
    else:
        _idle_backoff_sec = min(
            _idle_backoff_sec * IDLE_BACKOFF_FACTOR,
            IDLE_BACKOFF_MAX_SEC,
        )
    time.sleep(_idle_backoff_sec)


def _reset_idle_backoff() -> None:
    """Setzt den Idle-Backoff zurueck — Caller ruft das beim Pickup."""
    global _idle_backoff_sec
    _idle_backoff_sec = None


def _tick() -> None:
    """Einzelne Iteration der Worker-Schleife.

    v0.9.5: der Heartbeat-Block wurde aus dem Tick entfernt — Heartbeat
    laeuft jetzt in einem Daemon-Thread (siehe `_heartbeat_loop`), damit
    er auch wenn `_process_job` 60-120s im LLM-Call blockiert weiter
    tickt und die k8s livenessProbe nicht den Pod kickt.

    v0.9.6: Mode-Check, Budget-Check und Budget-Reset throttled ueber
    Modul-Caches (siehe ``_get_mode_throttled`` und ``_budget_ok_throttled``).
    Bei leerer Queue klettert die Sleep-Dauer exponentiell bis 30s
    (``_idle_sleep_and_backoff``). Reduziert die Idle-SQL-Last drastisch.

    Block R (ADR-0026): Scan-Ingest-Sub-Tick vor LLM-Pickup eingefuegt.
    Ingest-Jobs werden priorisiert — LLM-Pickup nur wenn keine Ingest-Jobs
    warten. Stale-Reaper kennt jetzt beide Tabellen. Retention-Sweep stündlich.
    """
    global _last_reaper_at, _last_debug_log_eviction_at, _last_feed_pull_check_at
    global _last_retention_sweep_at
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

    # Mode-Check (cached 30s).
    mode = _get_mode_throttled()
    if mode == "off":
        # Block R: Scan-Ingest-Sub-Tick laeuft UNABHAENGIG vom LLM-Mode.
        # Ingest-Jobs muessen auch verarbeitet werden wenn LLM-Mode='off'.
        with get_session() as session:
            scan_ingest_job_id = _pick_next_scan_ingest_job_id(session)
            session.commit()
        if scan_ingest_job_id is not None:
            _process_scan_ingest_job_safe(scan_ingest_job_id)
            _reset_idle_backoff()
            return
        _idle_sleep_and_backoff()
        return

    # Budget-Check (cached 60s) — inkludiert maybe_reset_budget.
    if not _budget_ok_throttled():
        # Block R: Scan-Ingest-Sub-Tick laeuft auch bei Budget-Erschoepfung.
        with get_session() as session:
            scan_ingest_job_id = _pick_next_scan_ingest_job_id(session)
            session.commit()
        if scan_ingest_job_id is not None:
            _process_scan_ingest_job_safe(scan_ingest_job_id)
            _reset_idle_backoff()
            return
        _idle_sleep_and_backoff()
        return

    # Block R (ADR-0026): Scan-Ingest-Sub-Tick VOR LLM-Pickup.
    # Ingest-Jobs werden priorisiert damit Agent-Polling-Timeouts (600s)
    # selten greifen. Ein Job pro Tick gleichberechtigt mit LLM-Pickup.
    with get_session() as session:
        scan_ingest_job_id = _pick_next_scan_ingest_job_id(session)
        session.commit()
    if scan_ingest_job_id is not None:
        _process_scan_ingest_job_safe(scan_ingest_job_id)
        _reset_idle_backoff()
        return

    job_id = _pick_next_job_id()
    if job_id is None:
        _idle_sleep_and_backoff()
        return

    # Pickup erfolgreich — Backoff zuruecksetzen, damit der naechste Idle-
    # Cycle wieder bei `_poll_interval()` startet.
    _reset_idle_backoff()
    _process_job(job_id, mode)


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


def _process_job(job_id: int, mode: str) -> None:
    """Dispatcht einen gepickten Job in den Mode-Branch.

    Bei jeder Exception: requeue oder fail. Bei Erfolg: ``status='done'``,
    ``completed_at=now()`` und Audit ``llm.job_done``.
    """
    start = time.monotonic()
    try:
        with get_session() as session:
            job = session.get(LLMJob, job_id)
            if job is None:
                log.warning("llm_worker.job_missing job_id=%s", job_id)
                return
            log.info(
                "llm_worker.job_picked job_id=%s job_type=%s mode=%s attempts=%s",
                job.id,
                job.job_type,
                mode,
                job.attempts,
            )
            _audit(
                session,
                "llm.job_picked",
                target_id=str(job.id),
                metadata={"job_type": job.job_type, "mode": mode, "attempts": job.attempts},
            )
            session.commit()

        if mode == "observation":
            _process_observation(job_id)
        elif mode == "live":
            asyncio.run(_process_live(job_id))
        else:
            # Defensive: ein "off"-Job wurde gepickt obwohl der Tick-Check
            # das verhindern sollte. Wir requeuen ohne Penalty.
            _requeue(job_id, "mode flipped to off mid-tick", penalty=False)
            return

        duration_ms = int((time.monotonic() - start) * 1000)
        with get_session() as session:
            job2 = session.get(LLMJob, job_id)
            if job2 is None:
                return
            _audit(
                session,
                "llm.job_done",
                target_id=str(job2.id),
                metadata={"job_type": job2.job_type, "duration_ms": duration_ms},
            )
            session.commit()
        log.info(
            "llm_worker.job_done job_id=%s duration_ms=%s",
            job_id,
            duration_ms,
        )
    except Exception as exc:
        _requeue_or_fail(job_id, repr(exc))


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


def _usage_tokens(meta: dict[str, Any]) -> tuple[int | None, int | None]:
    """v0.9.5-Helper: (prompt_tokens, completion_tokens) aus meta.usage ziehen.

    Defensiv gegen non-dict usage (kann bei manchen Providern ein
    Pydantic-Model bleiben, das vorher in dict konvertiert wurde — wir
    pruefen trotzdem nochmal isinstance).
    """
    usage = meta.get("usage")
    if not isinstance(usage, dict):
        return None, None
    pt = usage.get("prompt_tokens")
    ct = usage.get("completion_tokens")
    return (int(pt) if isinstance(pt, int) else None, int(ct) if isinstance(ct, int) else None)


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
            log.info(
                "llm_worker.pass1_skipped job_id=%s reason=no_findings",
                job_id,
            )
            return
        # Reviewer-Setup
        reviewer, model_name = _build_reviewer(session)
        job_server_id: int | None = job.server_id

    # v0.9.5: Phasen-Logs damit Operator sieht wo wir im Lifecycle stehen.
    log.info(
        "llm_worker.pass1_started job_id=%s findings_count=%s server_id=%s",
        job_id,
        len(finding_ids),
        job_server_id,
    )

    # LLM-Call ausserhalb der DB-Session — sonst halten wir die Connection
    # waehrend der 30-90s LLM-Latenz auf.
    result: Pass1Result
    meta: dict[str, Any]
    log.info(
        "llm_worker.llm_call_started job_id=%s job_type=pass1 model=%s findings=%s",
        job_id,
        model_name,
        len(finding_ids),
    )
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
        await _aclose_reviewer_client(reviewer)

    pt, ct = _usage_tokens(meta)
    log.info(
        "llm_worker.llm_call_completed job_id=%s job_type=pass1 duration_ms=%s "
        "prompt_tokens=%s completion_tokens=%s reasoning_chars=%s finish_reason=%s",
        job_id,
        meta.get("duration_ms"),
        pt,
        ct,
        len(meta.get("reasoning_field") or ""),
        meta.get("finish_reason"),
    )

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
    # v0.9.5: Persist-Done-Phase-Log nach erfolgreichem Commit.
    log.info(
        "llm_worker.pass1_persist_done job_id=%s groups_count=%s ungrouped_count=%s",
        job_id,
        len(result.groups),
        len(result.ungrouped_finding_ids),
    )


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
            log.info(
                "llm_worker.pass2_skipped job_id=%s reason=group_or_server_missing "
                "group_id=%s server_id=%s",
                job_id,
                group_id,
                server_id,
            )
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
            log.info(
                "llm_worker.pass2_skipped job_id=%s reason=no_findings group_id=%s server_id=%s",
                job_id,
                group_id,
                server_id,
            )
            return

        # v0.9.5: Phasen-Log nach Daten-Hydration.
        log.info(
            "llm_worker.pass2_started job_id=%s group_id=%s group_label=%s "
            "findings_in_group=%s server_id=%s",
            job_id,
            group_id,
            group.label,
            len(findings),
            server_id,
        )

        gf_fp = group_findings_fingerprint(findings)
        cve_fp = cve_data_fingerprint(findings)
        sv_fp = server_context_fingerprint(server, session=session)
        cache_key = make_cache_key(group.id, gf_fp, cve_fp, sv_fp)

        cached = lookup(session, cache_key)
        # v0.9.5: Cache-Lookup-Phase-Log (hit/miss).
        log.info(
            "llm_worker.pass2_cache_lookup job_id=%s cache_key_prefix=%s result=%s",
            job_id,
            cache_key[:16],
            "hit" if cached is not None else "miss",
        )
        if cached is not None:
            record_hit(session, cached)
            _apply_pass2_to_group(
                group,
                risk_band=cached.risk_band,
                reason=cached.reason,
                worst_finding_id=cached.worst_finding_id,
                gf_fp=gf_fp,
                action_type=cached.action_type,
            )
            inherited = inherit_group_risk_to_findings(session, group_ids=[group_id])
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
            log.info(
                "llm_worker.pass2_cache_hit_applied job_id=%s group_id=%s "
                "risk_band=%s action_type=%s findings_inherited=%s",
                job_id,
                group_id,
                cached.risk_band,
                cached.action_type,
                inherited,
            )
            return

        # Cache-Miss: Daten fuer den LLM-Call snapshotten.
        reviewer, model_name = _build_reviewer(session)
        group_label = group.label
        server_id_snapshot = server.id
        group_findings_ids = [int(f.id) for f in findings]

    # Phase 2: LLM-Call ausserhalb der Session.
    # Wir nutzen den Reviewer mit detached-Objekten — eine zweite Session
    # haengen wir nicht an, der `pass2_evaluate_groups`-Helper akzeptiert
    # Session-loese Objekte.
    pass2_result: Pass2Result
    pass2_meta: dict[str, Any]
    log.info(
        "llm_worker.llm_call_started job_id=%s job_type=pass2 model=%s group_id=%s findings=%s",
        job_id,
        model_name,
        group_id,
        len(group_findings_ids),
    )
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
        await _aclose_reviewer_client(reviewer)

    pt2, ct2 = _usage_tokens(pass2_meta)
    log.info(
        "llm_worker.llm_call_completed job_id=%s job_type=pass2 duration_ms=%s "
        "prompt_tokens=%s completion_tokens=%s reasoning_chars=%s finish_reason=%s",
        job_id,
        pass2_meta.get("duration_ms"),
        pt2,
        ct2,
        len(pass2_meta.get("reasoning_field") or ""),
        pass2_meta.get("finish_reason"),
    )

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
            _apply_pass2_to_group(
                group2,
                risk_band=evaluation.risk_band,
                reason=evaluation.reason,
                worst_finding_id=evaluation.worst_finding_id,
                gf_fp=gf_fp,
                action_type=evaluation.action_type,
            )
            inherited = inherit_group_risk_to_findings(session, group_ids=[group_id])
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
    # v0.9.5: Persist-Done-Phase-Log nach Result+Cache+Budget-Commit.
    log.info(
        "llm_worker.pass2_persist_done job_id=%s group_id=%s risk_band=%s "
        "action_type=%s worst_finding_id=%s findings_inherited=%s",
        job_id,
        group_id,
        evaluation.risk_band,
        evaluation.action_type,
        evaluation.worst_finding_id,
        inherited,
    )


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
    """
    try:
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


def _apply_pass2_to_group(
    group: ApplicationGroup,
    *,
    risk_band: str,
    reason: str,
    worst_finding_id: int | None,
    gf_fp: str,
    action_type: str | None = None,
) -> None:
    """Setzt die Bewertungs-Felder auf der ApplicationGroup-Row.

    ``action_type`` ist v0.9.3-Output von Pass 2. Bei Cache-Hits aus Pre-
    v0.9.3-Eintraegen (ohne ``action_type``) bleibt das Feld auf seinem
    Voherwert — wir ueberschreiben es nur wenn ein non-None Wert kommt,
    damit ein alter Cache eine neue LLM-Bewertung nicht zurueck-`None`'d.
    """
    group.risk_band = risk_band
    group.risk_band_reason = reason
    group.risk_band_source = "llm"
    group.risk_band_computed_at = datetime.now(UTC)
    group.worst_finding_id = worst_finding_id
    group.group_findings_fingerprint = gf_fp
    if action_type is not None:
        group.action_type = action_type


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


_reviewer_factory: Any | None = None


def set_reviewer_factory_for_tests(
    factory: Any | None,
) -> None:
    """Test-Hook: ``factory(session) -> (LLMRiskReviewer, model_name)``."""
    global _reviewer_factory
    _reviewer_factory = factory


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

    Exception im Worker darf den gesamten llm_worker._tick() nicht killen.
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
    "reset_shutdown_for_tests",
    "set_reviewer_factory_for_tests",
    "set_session_factory_for_tests",
]
