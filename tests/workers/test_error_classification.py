"""Tests fuer ``app.workers.llm_worker._classify_error`` und die
``is_timeout_or_llm``-Markerliste in ``_requeue_or_fail``.

v0.9.4 Fix 3: OpenAI-SDK-Fehler (``BadRequestError``/``APIStatusError``)
sollen als LLM-Fehler erkannt werden — Audit-Metadata bekommt
``error_class=llm_api_error``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, LLMJob
from app.workers.llm_worker import MAX_ATTEMPTS, _classify_error, _requeue_or_fail
from tests._helpers import register_test_server


def test_classify_error_recognizes_badrequest() -> None:
    """BadRequestError-Stringification → ``llm_api_error``."""
    err = "BadRequestError(\"Error code: 400 - {'error': {'message': 'too long'}}\")"
    assert _classify_error(err) == "llm_api_error"


def test_classify_error_recognizes_apistatuserror() -> None:
    """APIStatusError → ``llm_api_error``."""
    assert _classify_error("APIStatusError('rate limit')") == "llm_api_error"


def test_classify_error_recognizes_error_code_marker() -> None:
    """Textuelle ``Error code: NNN``-Marker → ``llm_api_error``."""
    assert _classify_error("Error code: 400 - context_window_exceeded") == "llm_api_error"


def test_classify_error_still_handles_timeout() -> None:
    """Regression: Timeout-Markers haben Vorrang vor llm_api_error."""
    assert _classify_error("LLMTimeoutError(asyncio timeout)") == "timeout"
    assert _classify_error("read timeout") == "timeout"


def test_classify_error_still_handles_invalid_response() -> None:
    """Regression: ``llminvalidresponse`` bleibt ``invalid_response``."""
    assert _classify_error("LLMInvalidResponseError('no choices')") == "invalid_response"


def test_classify_error_other_for_unknown() -> None:
    """Fallback bleibt ``other`` fuer Nicht-LLM-Fehler."""
    assert _classify_error("ConnectionRefusedError") == "other"


# ---------------------------------------------------------------------------
# Integration: _requeue_or_fail mit BadRequest am MAX_ATTEMPTS-Limit
# → Audit-Event ``llm.job_failed`` bekommt ``error_class=llm_api_error``.
# ---------------------------------------------------------------------------


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
