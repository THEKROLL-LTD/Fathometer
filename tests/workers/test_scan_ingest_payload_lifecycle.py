"""Payload-Lifecycle-Tests fuer scan_ingest_jobs (Block R Phase C, ADR-0026).

Marker: db_integration — testen Postgres-Semantik (interval-Arithmetik, atomares
UPDATE-Verhalten gegen reale Tabelle).

Abgedeckte Garantien aus ADR-0026 §Bedrohungsmodell:
1. **Atomares Payload-Clear bei `done`** — nach `_process_scan_ingest_job` ist
   `payload_gzip IS NULL` direkt nach dem Status-Wechsel (kein zweiter Sweep
   noetig). Das ist die ADR-0005-Transit-Garantie.
2. **Stale-Reaper Requeue + Fail** — Jobs mit `picked_up_at < now() - 5min`
   und `attempts < 3` werden requeued; mit `attempts >= 3` auf failed gesetzt.
3. **Retention-Sweep done-Clear + failed-DELETE** — Safety-Net fuer
   Crash-Reste (done mit payload_gzip != NULL nach >1h) plus 24h-DELETE
   fuer failed-Jobs.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select, text

from app.db import get_session_factory
from app.models import ScanIngestJob
from app.workers.scan_ingest_worker import (
    MAX_SCAN_INGEST_ATTEMPTS,
    _process_scan_ingest_job,
    _run_scan_ingest_retention_sweep,
    _run_scan_ingest_stale_reaper,
)
from tests._helpers import register_test_server

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "trivy" / "ubuntu-22.04-rke2.json"

pytestmark = [pytest.mark.db_integration]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_payload() -> tuple[bytes, bytes]:
    """Baut ein gueltiges Envelope (decompressed + gzipped)."""
    with FIXTURE_PATH.open("rb") as fh:
        trivy_report = json.load(fh)
    envelope = {
        "agent_version": "0.4.0",
        "host": {
            "hostname": "lifecycle-host",
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04.4 LTS",
            "kernel_version": "5.15.0-100-generic",
            "architecture": "x86_64",
        },
        "scan": trivy_report,
    }
    decompressed = json.dumps(envelope).encode("utf-8")
    return decompressed, gzip.compress(decompressed)


def _insert_job(
    session: Any,
    server_id: int,
    *,
    status: str = "queued",
    attempts: int = 0,
    payload_gzip: bytes | None = None,
    picked_up_at: datetime | None = None,
    finished_at: datetime | None = None,
    payload_sha256: str = "0" * 64,
    payload_bytes: int = 1024,
) -> int:
    """Direkter SQL-Insert fuer Lifecycle-Tests."""
    result = session.execute(
        text(
            """
            INSERT INTO scan_ingest_jobs (
                server_id, payload_gzip, payload_sha256, payload_bytes,
                status, attempts, picked_up_at, finished_at
            ) VALUES (
                :server_id, :payload_gzip, :payload_sha256, :payload_bytes,
                :status, :attempts, :picked_up_at, :finished_at
            )
            RETURNING id
            """
        ),
        {
            "server_id": server_id,
            "payload_gzip": payload_gzip,
            "payload_sha256": payload_sha256,
            "payload_bytes": payload_bytes,
            "status": status,
            "attempts": attempts,
            "picked_up_at": picked_up_at,
            "finished_at": finished_at,
        },
    )
    session.commit()
    return int(result.scalar_one())


def _job_state(session: Any, job_id: int) -> dict[str, Any]:
    """Liest Status + Payload-NULL-Flag + Counts direkt aus der DB."""
    row = session.execute(
        text(
            """
            SELECT status,
                   payload_gzip IS NULL AS payload_cleared,
                   scan_id,
                   error,
                   attempts,
                   next_attempt_at,
                   picked_up_by
              FROM scan_ingest_jobs
             WHERE id = :id
            """
        ),
        {"id": job_id},
    ).fetchone()
    return dict(row._mapping) if row is not None else {}


# ---------------------------------------------------------------------------
# 1. Atomares Payload-Clear bei done
# ---------------------------------------------------------------------------


def test_atomic_payload_clear_on_done(db_app: Flask) -> None:
    """Nach erfolgreichem `_process_scan_ingest_job` ist payload_gzip IS NULL
    direkt im selben Status='done'-UPDATE — kein Sweep noetig.

    Verifiziert die ADR-0005-Transit-Garantie: Roh-Body lebt nur bis zum
    Status-Wechsel auf done.
    """
    factory = get_session_factory(db_app)

    with db_app.app_context():
        srv_id, _ = register_test_server(db_app, name="lifecycle-srv")

        _, gzipped = _build_payload()

        setup_sess = factory()
        try:
            job_id = _insert_job(
                setup_sess,
                srv_id,
                status="queued",
                payload_gzip=gzipped,
                payload_bytes=len(gzipped),
                payload_sha256="a" * 64,
            )
        finally:
            setup_sess.close()

        # Worker-Call mit derselben Session-Factory.
        _process_scan_ingest_job(job_id, factory, worker_id="test-worker")

        # Direkt danach (kein Sweep!) muss der Job done + payload cleared sein.
        verify_sess = factory()
        try:
            state = _job_state(verify_sess, job_id)
            assert state["status"] == "done", f"Status nicht done: {state}"
            assert state["payload_cleared"] is True, "payload_gzip NICHT direkt cleared!"
            assert state["scan_id"] is not None, "scan_id muss gesetzt sein bei done"
            assert state["error"] is None, "error muss None sein bei done"
        finally:
            verify_sess.close()


def test_validation_error_keeps_payload_for_debugging(db_app: Flask) -> None:
    """Bei ValidationError bleibt payload_gzip erhalten (24h-Debugging-Fenster).

    Erst Retention-Sweep loescht ihn — der Worker selbst nicht.
    """
    factory = get_session_factory(db_app)

    with db_app.app_context():
        srv_id, _ = register_test_server(db_app, name="lifecycle-srv2")

        # Bewusst defektes JSON als gzipped-Payload.
        bad_payload = b'{"not_an_envelope": true}'
        bad_gzipped = gzip.compress(bad_payload)

        setup_sess = factory()
        try:
            job_id = _insert_job(
                setup_sess,
                srv_id,
                status="queued",
                payload_gzip=bad_gzipped,
                payload_bytes=len(bad_payload),
                payload_sha256="b" * 64,
            )
        finally:
            setup_sess.close()

        _process_scan_ingest_job(job_id, factory, worker_id="test-worker")

        verify_sess = factory()
        try:
            state = _job_state(verify_sess, job_id)
            assert state["status"] == "failed", f"Status nicht failed: {state}"
            assert state["payload_cleared"] is False, "payload_gzip BLEIBT bei failed!"
            assert state["error"] is not None, "error muss gesetzt sein"
        finally:
            verify_sess.close()


# ---------------------------------------------------------------------------
# 2. Stale-Reaper: Requeue + Fail-nach-Max-Attempts
# ---------------------------------------------------------------------------


def test_stale_reaper_requeues_below_max_attempts(db_app: Flask) -> None:
    """Stale in_progress Job mit attempts < 3 wird auf queued zurueckgesetzt."""
    factory = get_session_factory(db_app)

    with db_app.app_context():
        srv_id, _ = register_test_server(db_app, name="stale-srv1")

        # picked_up_at vor >5min, attempts=1 (< 3 → requeue)
        long_ago = datetime.now(UTC) - timedelta(minutes=10)

        setup_sess = factory()
        try:
            job_id = _insert_job(
                setup_sess,
                srv_id,
                status="in_progress",
                attempts=1,
                payload_gzip=b"x" * 100,
                picked_up_at=long_ago,
                payload_sha256="c" * 64,
            )
            # picked_up_by setzen (kommt von realer Pickup-Logik)
            setup_sess.execute(
                text("UPDATE scan_ingest_jobs SET picked_up_by = 'dead-worker' WHERE id = :id"),
                {"id": job_id},
            )
            setup_sess.commit()
        finally:
            setup_sess.close()

        reaper_sess = factory()
        try:
            _run_scan_ingest_stale_reaper(reaper_sess)
            reaper_sess.commit()
        finally:
            reaper_sess.close()

        verify_sess = factory()
        try:
            state = _job_state(verify_sess, job_id)
            assert state["status"] == "queued", f"Status nicht queued: {state}"
            assert state["picked_up_by"] is None
            # next_attempt_at muss in der Zukunft liegen (Backoff)
            assert state["next_attempt_at"] > datetime.now(UTC) - timedelta(seconds=10)
            # Payload bleibt erhalten fuer Retry
            assert state["payload_cleared"] is False
        finally:
            verify_sess.close()


def test_stale_reaper_fails_at_max_attempts(db_app: Flask) -> None:
    """Stale in_progress Job mit attempts >= 3 wird auf failed gesetzt."""
    factory = get_session_factory(db_app)

    with db_app.app_context():
        srv_id, _ = register_test_server(db_app, name="stale-srv2")

        long_ago = datetime.now(UTC) - timedelta(minutes=10)

        setup_sess = factory()
        try:
            job_id = _insert_job(
                setup_sess,
                srv_id,
                status="in_progress",
                attempts=MAX_SCAN_INGEST_ATTEMPTS,
                payload_gzip=b"x" * 100,
                picked_up_at=long_ago,
                payload_sha256="d" * 64,
            )
        finally:
            setup_sess.close()

        reaper_sess = factory()
        try:
            _run_scan_ingest_stale_reaper(reaper_sess)
            reaper_sess.commit()
        finally:
            reaper_sess.close()

        verify_sess = factory()
        try:
            state = _job_state(verify_sess, job_id)
            assert state["status"] == "failed", f"Status nicht failed: {state}"
            assert state["error"] is not None
            # Payload bleibt fuer 24h-Operator-Debugging
            assert state["payload_cleared"] is False
        finally:
            verify_sess.close()


def test_stale_reaper_ignores_recent_in_progress(db_app: Flask) -> None:
    """Junger in_progress Job (< 5min) wird NICHT reaped."""
    factory = get_session_factory(db_app)

    with db_app.app_context():
        srv_id, _ = register_test_server(db_app, name="stale-srv3")

        recent = datetime.now(UTC) - timedelta(minutes=2)

        setup_sess = factory()
        try:
            job_id = _insert_job(
                setup_sess,
                srv_id,
                status="in_progress",
                attempts=1,
                payload_gzip=b"x" * 100,
                picked_up_at=recent,
                payload_sha256="e" * 64,
            )
        finally:
            setup_sess.close()

        reaper_sess = factory()
        try:
            _run_scan_ingest_stale_reaper(reaper_sess)
            reaper_sess.commit()
        finally:
            reaper_sess.close()

        verify_sess = factory()
        try:
            state = _job_state(verify_sess, job_id)
            assert state["status"] == "in_progress", f"Junger Job wurde reaped: {state}"
        finally:
            verify_sess.close()


# ---------------------------------------------------------------------------
# 3. Retention-Sweep: done-payload-Clear + failed-DELETE
# ---------------------------------------------------------------------------


def test_retention_sweep_clears_done_payload_after_1h(db_app: Flask) -> None:
    """Crash-Rest: done-Job mit payload_gzip != NULL und finished_at > 1h
    wird vom Sweep auf payload_gzip = NULL gesetzt (Safety-Net).
    """
    factory = get_session_factory(db_app)

    with db_app.app_context():
        srv_id, _ = register_test_server(db_app, name="retention-srv1")

        long_ago = datetime.now(UTC) - timedelta(hours=2)

        setup_sess = factory()
        try:
            job_id = _insert_job(
                setup_sess,
                srv_id,
                status="done",
                payload_gzip=b"crash-rest" * 50,
                finished_at=long_ago,
                payload_sha256="f" * 64,
            )
        finally:
            setup_sess.close()

        sweep_sess = factory()
        try:
            _run_scan_ingest_retention_sweep(sweep_sess)
            sweep_sess.commit()
        finally:
            sweep_sess.close()

        verify_sess = factory()
        try:
            state = _job_state(verify_sess, job_id)
            assert state["status"] == "done", f"Status sollte done bleiben: {state}"
            assert state["payload_cleared"] is True, "Sweep hat payload nicht cleared!"
        finally:
            verify_sess.close()


def test_retention_sweep_ignores_recent_done_with_payload(db_app: Flask) -> None:
    """Done-Job mit finished_at < 1h wird NICHT vom Sweep angefasst.

    Realistisch: ein done-Job sollte sowieso kein Payload mehr haben — wenn
    er doch eines hat (Crash-Rest) und finished_at jung ist, warten wir bis
    der 1h-TTL abgelaufen ist.
    """
    factory = get_session_factory(db_app)

    with db_app.app_context():
        srv_id, _ = register_test_server(db_app, name="retention-srv2")

        recent = datetime.now(UTC) - timedelta(minutes=30)

        setup_sess = factory()
        try:
            job_id = _insert_job(
                setup_sess,
                srv_id,
                status="done",
                payload_gzip=b"recent-crash-rest" * 50,
                finished_at=recent,
                payload_sha256="0a" * 32,
            )
        finally:
            setup_sess.close()

        sweep_sess = factory()
        try:
            _run_scan_ingest_retention_sweep(sweep_sess)
            sweep_sess.commit()
        finally:
            sweep_sess.close()

        verify_sess = factory()
        try:
            state = _job_state(verify_sess, job_id)
            assert state["payload_cleared"] is False, "Sweep hat zu frueh cleared!"
        finally:
            verify_sess.close()


def test_retention_sweep_deletes_failed_after_24h(db_app: Flask) -> None:
    """Failed-Job mit finished_at > 24h wird vom Sweep komplett geloescht."""
    factory = get_session_factory(db_app)

    with db_app.app_context():
        srv_id, _ = register_test_server(db_app, name="retention-srv3")

        long_ago = datetime.now(UTC) - timedelta(hours=25)

        setup_sess = factory()
        try:
            job_id = _insert_job(
                setup_sess,
                srv_id,
                status="failed",
                payload_gzip=b"to-be-deleted" * 20,
                finished_at=long_ago,
                payload_sha256="0b" * 32,
            )
            setup_sess.execute(
                text("UPDATE scan_ingest_jobs SET error = 'test error' WHERE id = :id"),
                {"id": job_id},
            )
            setup_sess.commit()
        finally:
            setup_sess.close()

        sweep_sess = factory()
        try:
            _run_scan_ingest_retention_sweep(sweep_sess)
            sweep_sess.commit()
        finally:
            sweep_sess.close()

        verify_sess = factory()
        try:
            row = verify_sess.execute(
                select(ScanIngestJob).where(ScanIngestJob.id == job_id)
            ).scalar_one_or_none()
            assert row is None, f"Failed-Job sollte geloescht sein, ist aber noch da: {row}"
        finally:
            verify_sess.close()


def test_retention_sweep_keeps_failed_under_24h(db_app: Flask) -> None:
    """Failed-Job innerhalb 24h-Fenster wird NICHT geloescht (Operator-Debug)."""
    factory = get_session_factory(db_app)

    with db_app.app_context():
        srv_id, _ = register_test_server(db_app, name="retention-srv4")

        recent = datetime.now(UTC) - timedelta(hours=2)

        setup_sess = factory()
        try:
            job_id = _insert_job(
                setup_sess,
                srv_id,
                status="failed",
                payload_gzip=b"debug-this" * 20,
                finished_at=recent,
                payload_sha256="0c" * 32,
            )
        finally:
            setup_sess.close()

        sweep_sess = factory()
        try:
            _run_scan_ingest_retention_sweep(sweep_sess)
            sweep_sess.commit()
        finally:
            sweep_sess.close()

        verify_sess = factory()
        try:
            row = verify_sess.execute(
                select(ScanIngestJob).where(ScanIngestJob.id == job_id)
            ).scalar_one_or_none()
            assert row is not None, "Failed-Job zu frueh geloescht!"
            assert row.payload_gzip is not None, "Payload zu frueh cleared!"
        finally:
            verify_sess.close()
