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


# Modul-State (graceful Shutdown + Cadence-Tracking).
_shutdown: bool = False
_last_heartbeat_at: float = 0.0
_last_reaper_at: float = 0.0
_last_debug_log_eviction_at: float = 0.0

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
    _shutdown = False
    _last_heartbeat_at = 0.0
    _last_reaper_at = 0.0
    _last_debug_log_eviction_at = 0.0


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

    log.info("llm_worker.shutdown_complete worker_id=%s", WORKER_ID)


def _read_mode_safe() -> str:
    """Liest ``settings.block_p_llm_mode`` defensiv (fallback ``off``)."""
    try:
        with get_session() as session:
            row = ensure_settings_row(session)
            return str(row.block_p_llm_mode or "off")
    except Exception:  # pragma: no cover — DB nicht da
        return "off"


def _tick() -> None:
    """Einzelne Iteration der Worker-Schleife."""
    global _last_heartbeat_at, _last_reaper_at, _last_debug_log_eviction_at
    now_mono = time.monotonic()

    # Heartbeat alle 10s.
    if now_mono - _last_heartbeat_at > HEARTBEAT_INTERVAL_SEC:
        _write_heartbeat()
        _last_heartbeat_at = now_mono

    # Stale-Reaper alle 60s.
    if now_mono - _last_reaper_at > STALE_REAPER_INTERVAL_SEC:
        _run_stale_reaper()
        _last_reaper_at = now_mono

    # v0.9.3: Debug-Log-Eviction alle 10 Minuten.
    if now_mono - _last_debug_log_eviction_at > DEBUG_LOG_EVICTION_INTERVAL_SEC:
        _run_debug_log_eviction()
        _last_debug_log_eviction_at = now_mono

    # Budget-Reset pruefen (passiert um 00:00 UTC).
    with get_session() as session:
        llm_budget.maybe_reset_budget(session)

    # Mode-Check — bei `off` kein Pickup.
    with get_session() as session:
        row = ensure_settings_row(session)
        mode = str(row.block_p_llm_mode or "off")

    if mode == "off":
        time.sleep(_poll_interval())
        return

    # Budget-Check — bei Erschoepfung pausieren.
    with get_session() as session:
        if not llm_budget.budget_check(session):
            llm_budget.mark_exhausted_audit_once(session)
            time.sleep(_poll_interval())
            return

    job_id = _pick_next_job_id()
    if job_id is None:
        time.sleep(_poll_interval())
        return

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
        # Reviewer-Setup
        reviewer, model_name = _build_reviewer(session)
        job_server_id: int | None = job.server_id

    # LLM-Call ausserhalb der DB-Session — sonst halten wir die Connection
    # waehrend der 30-90s LLM-Latenz auf.
    result: Pass1Result
    meta: dict[str, Any]
    try:
        result, meta = await reviewer.pass1_detect_groups(findings)
    except LLMInvalidResponseError as exc:
        _record_pass_debug_log(
            job_id=job_id,
            job_type="pass1_group_detection",
            status="validation_error",
            model=model_name or "-",
            server_id=job_server_id,
            group_id=None,
            meta=None,
            error=str(exc),
        )
        raise
    except LLMTimeoutError as exc:
        _record_pass_debug_log(
            job_id=job_id,
            job_type="pass1_group_detection",
            status="timeout",
            model=model_name or "-",
            server_id=job_server_id,
            group_id=None,
            meta=None,
            error=str(exc),
        )
        raise

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
            _apply_pass2_to_group(
                group,
                risk_band=cached.risk_band,
                reason=cached.reason,
                worst_finding_id=cached.worst_finding_id,
                gf_fp=gf_fp,
                action_type=cached.action_type,
            )
            job.status = "done"
            job.completed_at = datetime.now(UTC)
            job.result = {
                "cache_hit": True,
                "risk_band": cached.risk_band,
                "action_type": cached.action_type,
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
    try:
        with get_session() as detached_session:
            group_re = detached_session.get(ApplicationGroup, group_id)
            server_re = detached_session.get(Server, server_id)
            findings_re = list(
                detached_session.execute(select(Finding).where(Finding.id.in_(group_findings_ids)))
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
        _record_pass_debug_log(
            job_id=job_id,
            job_type="pass2_risk_evaluation",
            status="validation_error",
            model=model_name or "-",
            server_id=server_id,
            group_id=group_id,
            meta=None,
            error=str(exc),
        )
        raise
    except LLMTimeoutError as exc:
        _record_pass_debug_log(
            job_id=job_id,
            job_type="pass2_risk_evaluation",
            status="timeout",
            model=model_name or "-",
            server_id=server_id,
            group_id=group_id,
            meta=None,
            error=str(exc),
        )
        raise

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
        if group2 is not None:
            _apply_pass2_to_group(
                group2,
                risk_band=evaluation.risk_band,
                reason=evaluation.reason,
                worst_finding_id=evaluation.worst_finding_id,
                gf_fp=gf_fp,
                action_type=evaluation.action_type,
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
