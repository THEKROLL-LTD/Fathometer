"""Scan-Ingest-Worker-Sub-Tick fuer Block R (ADR-0026, Phase C).

Dieser Sub-Tick wird in `llm_worker._tick()` VOR dem LLM-Pickup aufgerufen.
Er pickt einen Job aus `scan_ingest_jobs`, verarbeitet ihn und setzt Status.

Architektur-Eigenschaften:

* Concurrency-safe Pickup via ``SELECT FOR UPDATE SKIP LOCKED``.
* Atomares UPDATE bei Status='done': payload_gzip wird im gleichen Statement
  auf NULL gesetzt (ADR-0005-Transit-Semantik, ADR-0026 §Bedrohungsmodell).
* Retry-Backoff: ``next_attempt_at = now() + 30s * 2^(attempts-1)`` fuer
  attempts 1, 2 (also 30s, 60s); nach MAX_SCAN_INGEST_ATTEMPTS → failed.
* Stale-Reaper: in_progress-Jobs mit picked_up_at aelter als
  SCAN_INGEST_STALE_TIMEOUT_MIN werden requeued oder auf failed gesetzt.
* Retention-Sweep: done-Jobs mit payload_gzip IS NOT NULL und finished_at
  vor 1h → payload_gzip = NULL (Safety-Net); failed-Jobs nach 24h geloescht.

# DoD-C-On-Demand-Verification:
#
# Die folgenden SQL-Pfade brauchen echte Postgres-Semantik und koennen nicht
# als Pure-Unit-Test verifiziert werden. Sie muessen als ``pytest -m
# db_integration`` vor dem Block-R-Merge laufen:
#
# 1. SELECT FOR UPDATE SKIP LOCKED Concurrency:
#    Zwei Worker-Threads gleichzeitig starten — jeder darf hoechstens einen
#    Job picken. Verifiziere dass picked_up_by unterschiedliche Worker-IDs
#    zeigt.
#
# 2. Atomares UPDATE bei status='done':
#    Nach _process_scan_ingest_job(job_id) direkt:
#      SELECT status, payload_gzip IS NULL AS cleared FROM scan_ingest_jobs
#      WHERE id = :job_id
#    Erwartung: (done, true) — kein Sweep-Lauf zwischendurch.
#
# 3. Stale-Reaper-Requeue:
#    Job auf status='in_progress' setzen, picked_up_at auf
#    now() - interval '6 minutes' setzen (> SCAN_INGEST_STALE_TIMEOUT_MIN=5),
#    attempts=1. _run_scan_ingest_stale_reaper aufrufen.
#    Erwartung: status='queued', next_attempt_at > now().
#
# 4. Stale-Reaper-Fail-nach-Max-Attempts:
#    Wie (3) aber attempts=3 (= MAX_SCAN_INGEST_ATTEMPTS).
#    Erwartung: status='failed'.
#
# 5. Retention-Sweep done-Safety-Net:
#    Job auf status='done' setzen, payload_gzip != NULL, finished_at auf
#    now() - interval '2 hours'. _run_scan_ingest_retention_sweep aufrufen.
#    Erwartung: payload_gzip IS NULL.
#
# 6. Retention-Sweep failed-Delete:
#    Job auf status='failed' setzen, finished_at auf
#    now() - interval '25 hours'. _run_scan_ingest_retention_sweep aufrufen.
#    Erwartung: Zeile geloescht.
#
# 7. on_conflict_do_nothing Partial-Index:
#    Zwei identische Payloads gleichzeitig per enqueue_or_resolve einfuegen.
#    Erwartung: nur ein Job-Row; zweiter Aufruf gibt denselben job_id zurueck.
#
# 8. ValidationError-Pfad:
#    Job mit defektem JSON-Payload einfuegen (z.B. gzip von "{invalid}").
#    _process_scan_ingest_job aufrufen.
#    Erwartung: status='failed', error != NULL, payload_gzip IS NOT NULL
#    (Debugging-Fenster bleibt 24h erhalten).
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Any

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

log = logging.getLogger("secscan.scan_ingest_worker")

# ---------------------------------------------------------------------------
# Modul-Konstanten
# ---------------------------------------------------------------------------

SCAN_INGEST_STALE_TIMEOUT_MIN: int = 5
SCAN_INGEST_RETENTION_INTERVAL_SEC: int = 3600
# Max-Versuche bis ein Job auf 'failed' gesetzt wird. Ueberschreibbar via
# Settings.scan_ingest_max_attempts — Default identisch.
MAX_SCAN_INGEST_ATTEMPTS: int = 3
# Backoff-Basis in Sekunden. next_attempt_at = now() + BASE_BACKOFF_SEC * 2^(attempts-1)
_BACKOFF_BASE_SEC: int = 30
# Error-Truncation-Cap (4 KB, analog zu llm_jobs.error).
_ERROR_MAX_BYTES: int = 4096

# Worker-Identitaet (analog zu llm_worker.WORKER_ID).
_WORKER_ID: str = f"{socket.gethostname()}:{os.getpid()}"


# ---------------------------------------------------------------------------
# Backoff-Berechnung (pure Funktion — unit-testbar)
# ---------------------------------------------------------------------------


def compute_backoff_sec(attempts: int, base_sec: int = _BACKOFF_BASE_SEC) -> int:
    """Berechnet den Retry-Backoff in Sekunden.

    next_attempt_at = now() + compute_backoff_sec(attempts) Sekunden.
    Formel: base_sec * 2^(attempts-1), mindestens base_sec.

    attempts=1 -> 30s
    attempts=2 -> 60s
    attempts=3 -> 120s (aber bei 3 Attempts → failed, wird nicht genutzt)
    """
    if attempts <= 0:
        return base_sec
    return int(base_sec * (2 ** (attempts - 1)))


def truncate_error(error: str, max_bytes: int = _ERROR_MAX_BYTES) -> str:
    """Trunciert einen Error-String auf max_bytes Bytes (UTF-8-safe).

    Wird als `error`-Spalte in `scan_ingest_jobs` gespeichert.
    """
    encoded = error.encode("utf-8")
    if len(encoded) <= max_bytes:
        return error
    # Truncieren auf Byte-Ebene, dann sauber dekodieren.
    return encoded[:max_bytes].decode("utf-8", errors="ignore") + " [truncated]"


def should_fail(attempts: int, max_attempts: int = MAX_SCAN_INGEST_ATTEMPTS) -> bool:
    """True wenn attempts >= max_attempts → Job soll auf 'failed' gesetzt werden."""
    return attempts >= max_attempts


def result_to_jsonb(result: Any) -> dict[str, Any]:
    """Serialisiert ein ScanProcessingResult in ein dict fuer JSONB-Storage.

    Wirft keine Exception — gibt leeres dict zurueck bei unerwarteten Typen.
    """
    try:
        return {
            "scan_id": int(result.scan_id),
            "findings_total": int(result.findings_total),
            "findings_inserted": int(result.findings_inserted),
            "findings_updated": int(result.findings_updated),
            "findings_resolved": int(result.findings_resolved),
            "class_os_pkgs": int(result.class_os_pkgs),
            "class_lang_pkgs": int(result.class_lang_pkgs),
            "class_other": int(result.class_other),
        }
    except (AttributeError, TypeError, ValueError) as exc:
        log.warning("scan_ingest_worker.result_serialization_failed error=%s", exc)
        return {}


# ---------------------------------------------------------------------------
# Pickup
# ---------------------------------------------------------------------------


def _pick_next_scan_ingest_job_id(session: Session) -> int | None:
    """Pickt den naechsten Ingest-Job mit SELECT FOR UPDATE SKIP LOCKED.

    Returns die Job-ID oder None wenn die Queue leer ist.

    SELECT FOR UPDATE SKIP LOCKED stellt sicher dass zwei Worker-Instanzen
    nie denselben Job picken (Concurrency-safe, Standard-PG-Pattern identisch
    zu llm_worker).
    """
    sql = text(
        """
        SELECT id FROM scan_ingest_jobs
        WHERE status = 'queued'
          AND next_attempt_at <= now()
        ORDER BY created_at
        LIMIT 1
        FOR UPDATE SKIP LOCKED
        """
    )
    row = session.execute(sql).fetchone()
    if row is None:
        return None
    return int(row[0])


# ---------------------------------------------------------------------------
# Job-Processing
# ---------------------------------------------------------------------------


def _process_scan_ingest_job(
    job_id: int,
    session_factory: sessionmaker[Session],
    worker_id: str = _WORKER_ID,
) -> None:
    """Verarbeitet einen einzelnen Ingest-Job vollstaendig.

    Ablauf:
    1. Session 1: Job auf in_progress setzen, picked_up_at/by setzen,
       attempts += 1. Sofort committen.
    2. Session 2: process_scan_envelope aufrufen. Bei Erfolg: atomares UPDATE
       (status='done', payload_gzip=NULL, scan_id, result). Kein
       separater Commit im Service.
    3. Bei ValidationError: Session-Rollback, neue Session, status='failed'.
    4. Bei SQLAlchemyError: Rollback, neues Versuch oder failed je nach attempts.
    """
    # --- Schritt 1: Status auf in_progress setzen ---
    with session_factory() as session1:
        try:
            session1.execute(
                text(
                    """
                    UPDATE scan_ingest_jobs
                    SET status        = 'in_progress',
                        picked_up_at  = now(),
                        picked_up_by  = :worker_id,
                        attempts      = attempts + 1
                    WHERE id = :job_id
                    """
                ),
                {"job_id": job_id, "worker_id": worker_id},
            )
            session1.commit()
        except SQLAlchemyError:
            session1.rollback()
            log.exception("scan_ingest_worker.pickup_status_update_failed job_id=%s", job_id)
            return

    # --- Schritt 2: Payload laden + verarbeiten ---
    with session_factory() as session2:
        try:
            from app.models import ScanIngestJob
            from app.models import Server as ServerModel
            from app.services.scan_processing import process_scan_envelope

            job = session2.get(ScanIngestJob, job_id)
            if job is None:
                log.warning("scan_ingest_worker.job_missing job_id=%s", job_id)
                return
            if job.payload_gzip is None:
                log.error(
                    "scan_ingest_worker.job_missing_payload job_id=%s status=%s",
                    job_id,
                    job.status,
                )
                _mark_failed(
                    session_factory,
                    job_id,
                    job.attempts,
                    "payload_gzip is NULL before processing",
                )
                return

            server = session2.get(ServerModel, job.server_id)
            if server is None:
                log.error(
                    "scan_ingest_worker.server_missing job_id=%s server_id=%s",
                    job_id,
                    job.server_id,
                )
                _mark_failed(
                    session_factory,
                    job_id,
                    job.attempts,
                    f"server_id={job.server_id} not found",
                )
                return

            payload_gzip = job.payload_gzip
            attempts_at_pickup = job.attempts

            log.info(
                "scan_ingest_worker.processing job_id=%s server_id=%s attempts=%s payload_bytes=%s",
                job_id,
                job.server_id,
                attempts_at_pickup,
                job.payload_bytes,
            )

            # Service-Aufruf — kein commit im Service.
            proc_result = process_scan_envelope(session2, server, payload_gzip)

            # Atomares UPDATE: status='done', payload_gzip=NULL, scan_id, result.
            result_jsonb = result_to_jsonb(proc_result)
            session2.execute(
                text(
                    """
                    UPDATE scan_ingest_jobs
                    SET status        = 'done',
                        finished_at   = now(),
                        scan_id       = :scan_id,
                        result        = CAST(:result AS jsonb),
                        payload_gzip  = NULL,
                        error         = NULL
                    WHERE id = :job_id
                    """
                ),
                {
                    "job_id": job_id,
                    "scan_id": proc_result.scan_id,
                    "result": _json_dumps(result_jsonb),
                },
            )
            session2.commit()

            log.info(
                "scan_ingest_worker.job_done job_id=%s scan_id=%s findings_total=%s",
                job_id,
                proc_result.scan_id,
                proc_result.findings_total,
            )

        except ValidationError as exc:
            session2.rollback()
            err_str = truncate_error(str(exc))
            log.warning(
                "scan_ingest_worker.validation_error job_id=%s error=%.200s",
                job_id,
                err_str,
            )
            _mark_failed(session_factory, job_id, None, err_str, is_validation=True)

        except SQLAlchemyError as exc:
            session2.rollback()
            err_str = truncate_error(repr(exc))
            log.warning(
                "scan_ingest_worker.sql_error job_id=%s error=%.200s",
                job_id,
                err_str,
            )
            # Attempts erneut auslesen fuer Retry-Entscheidung.
            _retry_or_fail(session_factory, job_id, err_str)

        except Exception as exc:
            session2.rollback()
            err_str = truncate_error(repr(exc))
            log.exception(
                "scan_ingest_worker.unexpected_error job_id=%s error=%.200s",
                job_id,
                err_str,
            )
            _retry_or_fail(session_factory, job_id, err_str)


def _json_dumps(obj: dict[str, Any]) -> str:
    """Serialisiert ein dict als JSON-String fuer Postgres JSONB-Cast."""
    import json as _json

    return _json.dumps(obj)


def _mark_failed(
    session_factory: sessionmaker[Session],
    job_id: int,
    attempts: int | None,
    error: str,
    *,
    is_validation: bool = False,
) -> None:
    """Setzt einen Job auf status='failed' und schreibt Audit-Event."""
    with session_factory() as sess:
        try:
            sess.execute(
                text(
                    """
                    UPDATE scan_ingest_jobs
                    SET status      = 'failed',
                        finished_at = now(),
                        error       = :error
                    WHERE id = :job_id
                    """
                ),
                {"job_id": job_id, "error": truncate_error(error)},
            )
            # Audit-Event schreiben
            _audit_ingest_failed(
                sess,
                job_id=job_id,
                error_class="validation_error" if is_validation else "other",
                error_truncated=error[:256],
            )
            sess.commit()
        except Exception:
            sess.rollback()
            log.exception("scan_ingest_worker.mark_failed_error job_id=%s", job_id)


def _retry_or_fail(
    session_factory: sessionmaker[Session],
    job_id: int,
    error: str,
) -> None:
    """Entscheidet ob der Job requeued oder auf failed gesetzt wird.

    Laedt die aktuelle attempts-Zahl aus der DB um die Entscheidung zu treffen.
    """
    with session_factory() as sess:
        try:
            row = sess.execute(
                text("SELECT attempts FROM scan_ingest_jobs WHERE id = :job_id"),
                {"job_id": job_id},
            ).fetchone()
            if row is None:
                log.warning("scan_ingest_worker.retry_job_missing job_id=%s", job_id)
                return
            attempts = int(row[0])

            if should_fail(attempts):
                sess.execute(
                    text(
                        """
                        UPDATE scan_ingest_jobs
                        SET status      = 'failed',
                            finished_at = now(),
                            error       = :error
                        WHERE id = :job_id
                        """
                    ),
                    {"job_id": job_id, "error": truncate_error(error)},
                )
                _audit_ingest_failed(
                    sess,
                    job_id=job_id,
                    error_class="sql_error",
                    error_truncated=error[:256],
                )
                log.warning(
                    "scan_ingest_worker.job_failed_max_attempts job_id=%s attempts=%s",
                    job_id,
                    attempts,
                )
            else:
                backoff_sec = compute_backoff_sec(attempts)
                sess.execute(
                    text(
                        """
                        UPDATE scan_ingest_jobs
                        SET status           = 'queued',
                            picked_up_by     = NULL,
                            picked_up_at     = NULL,
                            error            = :error,
                            next_attempt_at  = now() + make_interval(secs => :backoff_sec)
                        WHERE id = :job_id
                        """
                    ),
                    {
                        "job_id": job_id,
                        "error": truncate_error(error),
                        "backoff_sec": backoff_sec,
                    },
                )
                log.info(
                    "scan_ingest_worker.job_requeued job_id=%s attempts=%s backoff_sec=%s",
                    job_id,
                    attempts,
                    backoff_sec,
                )
            sess.commit()
        except Exception:
            sess.rollback()
            log.exception("scan_ingest_worker.retry_or_fail_error job_id=%s", job_id)


def _audit_ingest_failed(
    session: Session,
    *,
    job_id: int,
    error_class: str,
    error_truncated: str,
) -> None:
    """Schreibt Audit-Event scan.ingest_failed (Best-Effort)."""
    try:
        from app.audit import log_event

        log_event(
            "scan.ingest_failed",
            target_type="scan_ingest_job",
            target_id=str(job_id),
            metadata={
                "job_id": job_id,
                "error_class": error_class,
                "error_truncated": error_truncated,
            },
            actor="worker",
            session=session,
        )
    except Exception:  # pragma: no cover — Audit darf den Worker nicht killen
        log.exception("scan_ingest_worker.audit_failed job_id=%s", job_id)


# ---------------------------------------------------------------------------
# Stale-Reaper
# ---------------------------------------------------------------------------


def _run_scan_ingest_stale_reaper(session: Session) -> None:
    """Requeued oder failt stale in_progress Ingest-Jobs.

    Zwei UPDATE-Statements analog zu llm_worker._run_stale_reaper:
    1. attempts < MAX_SCAN_INGEST_ATTEMPTS → queued zurueck, next_attempt_at
       mit Backoff.
    2. attempts >= MAX_SCAN_INGEST_ATTEMPTS → failed.
    """
    timeout_min = SCAN_INGEST_STALE_TIMEOUT_MIN
    max_attempts = MAX_SCAN_INGEST_ATTEMPTS

    # Step 1: Requeue.
    requeued = session.execute(
        text(
            """
            UPDATE scan_ingest_jobs
            SET status          = 'queued',
                picked_up_by    = NULL,
                picked_up_at    = NULL,
                next_attempt_at = now() + make_interval(secs => :backoff_sec)
            WHERE status = 'in_progress'
              AND picked_up_at < now() - make_interval(mins => :timeout_min)
              AND attempts < :max_attempts
            RETURNING id
            """
        ),
        {
            "timeout_min": timeout_min,
            "max_attempts": max_attempts,
            # Backoff fuer reaped Jobs: 30s (base, da attempts unbekannt im
            # Batch-Statement; konservativ Basis-Backoff nutzen).
            "backoff_sec": _BACKOFF_BASE_SEC,
        },
    ).fetchall()

    # Step 2: Fail.
    failed = session.execute(
        text(
            """
            UPDATE scan_ingest_jobs
            SET status      = 'failed',
                finished_at = now(),
                error       = 'max attempts after stale'
            WHERE status = 'in_progress'
              AND picked_up_at < now() - make_interval(mins => :timeout_min)
              AND attempts >= :max_attempts
            RETURNING id
            """
        ),
        {"timeout_min": timeout_min, "max_attempts": max_attempts},
    ).fetchall()

    if requeued or failed:
        log.info(
            "scan_ingest_worker.stale_reaped requeued=%s failed=%s",
            len(requeued),
            len(failed),
        )


# ---------------------------------------------------------------------------
# Retention-Sweep
# ---------------------------------------------------------------------------


def _run_scan_ingest_retention_sweep(session: Session) -> None:
    """Retention-Sweep fuer scan_ingest_jobs (stündlich).

    Zwei Operationen:
    1. UPDATE: done-Jobs mit payload_gzip != NULL und finished_at < now()-1h
       → payload_gzip = NULL (Safety-Net fuer crash-resisted Payloads).
    2. DELETE: failed-Jobs mit finished_at < now()-24h (komplette Zeile entfernen).

    ADR-0005-Transit-Ausnahme: Payloads leben max. 24h. Bei sauberem Worker-
    Lauf wird payload_gzip schon im atomaren UPDATE auf NULL gesetzt — dieser
    Sweep ist reines Safety-Net.
    """
    # Safety-Net: done-Jobs mit noch vorhandenem Payload clearen.
    cleared = session.execute(
        text(
            """
            UPDATE scan_ingest_jobs
            SET payload_gzip = NULL
            WHERE status = 'done'
              AND payload_gzip IS NOT NULL
              AND finished_at < now() - interval '1 hour'
            RETURNING id
            """
        )
    ).fetchall()

    # Failed-Jobs nach 24h loeschen (komplette Zeile, inkl. payload_gzip).
    deleted = session.execute(
        text(
            """
            DELETE FROM scan_ingest_jobs
            WHERE status = 'failed'
              AND finished_at < now() - interval '24 hours'
            RETURNING id
            """
        )
    ).fetchall()

    if cleared or deleted:
        log.info(
            "scan_ingest_worker.retention_sweep cleared_payload=%s deleted_rows=%s",
            len(cleared),
            len(deleted),
        )


__all__ = [
    "MAX_SCAN_INGEST_ATTEMPTS",
    "SCAN_INGEST_RETENTION_INTERVAL_SEC",
    "SCAN_INGEST_STALE_TIMEOUT_MIN",
    "_pick_next_scan_ingest_job_id",
    "_process_scan_ingest_job",
    "_run_scan_ingest_retention_sweep",
    "_run_scan_ingest_stale_reaper",
    "compute_backoff_sec",
    "result_to_jsonb",
    "should_fail",
    "truncate_error",
]
