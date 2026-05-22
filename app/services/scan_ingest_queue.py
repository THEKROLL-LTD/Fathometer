"""Ingest-Queue-Service fuer asynchronen Scan-Ingest (ADR-0026, Block R Phase B).

Kapselt den UPSERT-Eintrag in `scan_ingest_jobs` mit Idempotency via
Partial-Unique-Index und Per-Server-Soft-Cap-Pruefung.
"""

from __future__ import annotations

import gzip
import hashlib
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import ScanIngestJob, Server

if TYPE_CHECKING:
    pass

log = structlog.get_logger(__name__)


class QueueFullError(Exception):
    """Wird raised wenn der Per-Server-Soft-Cap ueberschritten wird.

    `current_count` enthaelt die aktuelle Anzahl queued+in_progress Jobs
    fuer den betroffenen Server — wird im 429-Response-Body ausgegeben.
    """

    def __init__(self, current_count: int) -> None:
        super().__init__(f"Queue voll: {current_count} Jobs in Queue/Verarbeitung")
        self.current_count = current_count


def enqueue_or_resolve(
    session: Session,
    server: Server,
    payload_bytes: bytes,
    payload_gzip: bytes,
    *,
    max_queued: int = 50,
) -> tuple[ScanIngestJob, bool]:
    """Fuegt einen Ingest-Job in die Queue ein oder gibt den existierenden Job zurueck.

    Implementiert den Partial-Unique-Index-basierten Idempotency-Mechanismus:
    - Bei Konflikt auf `ux_scan_ingest_jobs_payload_sha256` (status IN
      ('queued','in_progress')) wird kein neuer Job angelegt; stattdessen
      wird der vorhandene Job per Fallback-SELECT ermittelt und zurueckgegeben.
    - Der `was_existing`-Flag steuert ob ein `scan.queued`-Audit-Event emittiert
      wird (nur bei echtem Insert, nicht bei Idempotency-Treffer).

    Soft-Cap-Pruefung laeuft VOR dem Insert — bei Ueberschreitung wird
    `QueueFullError` geraist (ADR-0026 §Bedrohungsmodell DoS-Schutz).

    Args:
        session: Synchrone SQLAlchemy-Session.
        server: Authentifizierter Server.
        payload_bytes: Unkomprimierter Scan-Body (fuer SHA-256 und payload_bytes).
        payload_gzip: Gzip-komprimierter Body fuer Storage in BYTEA.
        max_queued: Per-Server-Soft-Cap (Default 50, aus Settings).

    Returns:
        Tupel `(job, was_existing)`:
        - `job`: Vollstaendig geladenes `ScanIngestJob`-ORM-Objekt.
        - `was_existing`: `True` wenn ein bestehender Job zurueckgegeben wurde
          (kein neues Audit-Event emittieren), `False` bei Neu-Insert.

    Raises:
        QueueFullError: Wenn der Per-Server-Soft-Cap erreicht ist.
        sqlalchemy.exc.SQLAlchemyError: Bei DB-Fehler (kein Retry hier).
    """
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()

    # --- Soft-Cap-Check VOR Insert (ADR-0026 §Bedrohungsmodell) ---
    queued_count: int = session.execute(
        select(func.count()).where(
            ScanIngestJob.server_id == server.id,
            ScanIngestJob.status.in_(["queued", "in_progress"]),
        )
    ).scalar_one()

    if queued_count >= max_queued:
        raise QueueFullError(current_count=queued_count)

    # --- Idempotency-UPSERT via Partial-Unique-Index ---
    # `on_conflict_do_nothing` greift genau dann wenn der partial-unique Index
    # `ux_scan_ingest_jobs_payload_sha256` (WHERE status IN ('queued','in_progress'))
    # einen Konflikt meldet. Bei Konflikt gibt `returning()` None zurueck —
    # wir fallen dann auf einen expliziten SELECT zurueck.
    #
    # Hinweis: `index_elements` muss die Spalte nennen, `index_where` muss
    # die WHERE-Bedingung des Partial-Index exakt wiederholen — nur so matcht
    # Postgres den richtigen Index.
    stmt = (
        pg_insert(ScanIngestJob)
        .values(
            server_id=server.id,
            payload_gzip=payload_gzip,
            payload_sha256=payload_sha256,
            payload_bytes=len(payload_bytes),
            status="queued",
        )
        .on_conflict_do_nothing(
            index_elements=["payload_sha256"],
            index_where=text("status IN ('queued','in_progress')"),
        )
        .returning(ScanIngestJob.id)
    )

    result = session.execute(stmt)
    new_id: int | None = result.scalar_one_or_none()

    if new_id is not None:
        # Echter Insert — neuen Job laden.
        session.flush()
        job = session.get(ScanIngestJob, new_id)
        assert job is not None, f"ScanIngestJob {new_id} gerade inserted, muss existieren"
        log.debug(
            "scan_ingest_queue.enqueued",
            server_id=server.id,
            job_id=job.id,
            payload_sha256=payload_sha256,
            payload_bytes=len(payload_bytes),
        )
        return job, False

    # Konflikt (Idempotency-Treffer) — vorhandenen Job per Fallback-SELECT laden.
    existing_job = session.execute(
        select(ScanIngestJob).where(
            ScanIngestJob.payload_sha256 == payload_sha256,
            ScanIngestJob.status.in_(["queued", "in_progress"]),
        )
    ).scalar_one()

    log.debug(
        "scan_ingest_queue.idempotent_hit",
        server_id=server.id,
        job_id=existing_job.id,
        payload_sha256=payload_sha256,
    )
    return existing_job, True


def compress_payload(payload_bytes: bytes) -> bytes:
    """Gzip-komprimiert den Payload fuer Storage in `payload_gzip` (BYTEA).

    Verwendet Komprimierungslevel 6 (Ausgewogen Geschwindigkeit/Groesse).
    Wird im Edge-Handler aufgerufen wenn der Request NICHT bereits gzip-
    komprimiert war (Content-Encoding: gzip). Wenn der Agent bereits
    gzip-komprimiert sendet, wird der Body-Stream direkt verwendet.
    """
    return gzip.compress(payload_bytes, compresslevel=6)


__all__ = ["QueueFullError", "compress_payload", "enqueue_or_resolve"]
