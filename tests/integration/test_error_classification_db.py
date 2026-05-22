"""Integration-Smokes fuer ``app.workers.llm_worker._requeue_or_fail``.

Diese Tests wurden aus ``tests/workers/test_error_classification.py``
ausgelagert (TICKET-004, Slice 6). Die pure ``_classify_error``-Logik
bleibt DB-frei in der Worker-Test-Datei. Hier verbleiben die Roundtrips
durch ``llm_jobs`` und ``audit_events``: am ``MAX_ATTEMPTS``-Limit muss
ein ``llm.job_failed``-AuditEvent mit dem korrekten ``error_class``-
Metadata-Feld geschrieben werden.

Auto-Markierung als ``db_integration`` (und damit ``acceptance``) erfolgt
ueber ``tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, LLMJob
from app.workers.llm_worker import MAX_ATTEMPTS, _requeue_or_fail
from tests._helpers import register_test_server


def _insert_job(app: Flask, server_id: int, *, attempts: int) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            job = LLMJob(
                job_type="group_detection",
                server_id=server_id,
                payload={"finding_ids": [1, 2, 3]},
                status="in_progress",
                attempts=attempts,
                picked_up_by="worker-test",
                picked_up_at=datetime.now(UTC),
            )
            sess.add(job)
            sess.flush()
            job_id = job.id
            sess.commit()
            return job_id
        finally:
            sess.close()


def _audit_for_job(app: Flask, action: str, job_id: int) -> list[AuditEvent]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            rows = list(
                sess.execute(
                    select(AuditEvent).where(
                        AuditEvent.action == action,
                        AuditEvent.target_id == str(job_id),
                    )
                )
                .scalars()
                .all()
            )
            return rows
        finally:
            sess.close()


def test_requeue_or_fail_audits_llm_api_error_for_badrequest(db_app: Flask) -> None:
    """v0.9.4 Fix 3: BadRequest am MAX_ATTEMPTS → Audit-``llm.job_failed``
    bekommt ``error_class=llm_api_error``."""
    server_id, _ = register_test_server(db_app, name="err-cls-badreq")
    job_id = _insert_job(db_app, server_id, attempts=MAX_ATTEMPTS)

    _requeue_or_fail(job_id, "BadRequestError('Error code: 400 - context_window_exceeded')")

    events = _audit_for_job(db_app, "llm.job_failed", job_id)
    assert len(events) == 1
    meta = events[0].event_metadata
    assert meta is not None
    assert meta["error_class"] == "llm_api_error"


def test_requeue_or_fail_audits_llm_api_error_for_apistatuserror(db_app: Flask) -> None:
    """APIStatusError → ``error_class=llm_api_error``."""
    server_id, _ = register_test_server(db_app, name="err-cls-api")
    job_id = _insert_job(db_app, server_id, attempts=MAX_ATTEMPTS)

    _requeue_or_fail(job_id, "APIStatusError('429 Too Many Requests')")

    events = _audit_for_job(db_app, "llm.job_failed", job_id)
    assert len(events) == 1
    meta = events[0].event_metadata
    assert meta is not None
    assert meta["error_class"] == "llm_api_error"


def test_requeue_or_fail_audits_other_for_unknown(db_app: Flask) -> None:
    """Regression: ein unbekannter Fehler bleibt ``error_class=other``."""
    server_id, _ = register_test_server(db_app, name="err-cls-other")
    job_id = _insert_job(db_app, server_id, attempts=MAX_ATTEMPTS)

    _requeue_or_fail(job_id, "ValueError('something else')")

    events = _audit_for_job(db_app, "llm.job_failed", job_id)
    assert len(events) == 1
    meta = events[0].event_metadata
    assert meta is not None
    assert meta["error_class"] == "other"
