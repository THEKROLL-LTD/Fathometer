"""Block P (ADR-0023) — Modell-Tests fuer `llm_jobs`.

CheckConstraints: job_type, status, attempts >= 0.
FK-Behavior: server_id ON DELETE CASCADE, depends_on ON DELETE SET NULL.
"""

from __future__ import annotations

from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db import get_session_factory
from app.models import LLMJob, Server
from tests._helpers import register_test_server


def _new_job(
    *,
    job_type: str = "group_detection",
    server_id: int | None = None,
    payload: dict[str, Any] | None = None,
    status: str = "queued",
    attempts: int = 0,
    depends_on: int | None = None,
) -> LLMJob:
    return LLMJob(
        job_type=job_type,
        server_id=server_id,
        payload=payload if payload is not None else {"finding_ids": [1, 2, 3]},
        status=status,
        attempts=attempts,
        depends_on=depends_on,
    )


def test_insert_valid_job(db_app: Flask) -> None:
    server_id, _ = register_test_server(db_app, name="srv-job-ok")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            job = _new_job(
                server_id=server_id,
                payload={"finding_ids": [1, 2, 3], "extra": "x"},
            )
            sess.add(job)
            sess.commit()
            row = sess.execute(select(LLMJob).where(LLMJob.id == job.id)).scalar_one()
            assert row.status == "queued"
            assert row.attempts == 0
            assert row.payload == {"finding_ids": [1, 2, 3], "extra": "x"}
            assert row.next_attempt_at is not None
        finally:
            sess.close()


def test_invalid_job_type_fails(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(_new_job(job_type="bogus"))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_invalid_status_fails(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(_new_job(status="bogus"))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_negative_attempts_fails(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(_new_job(attempts=-1))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_server_delete_cascades_to_jobs(db_app: Flask) -> None:
    server_id, _ = register_test_server(db_app, name="srv-job-cascade")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            job = _new_job(server_id=server_id)
            sess.add(job)
            sess.commit()
            jid = job.id

            srv = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            sess.delete(srv)
            sess.commit()

            still = sess.execute(select(LLMJob).where(LLMJob.id == jid)).scalar_one_or_none()
            assert still is None, "Server-Delete sollte zugehoerige Jobs cascaden"
        finally:
            sess.close()


def test_depends_on_self_fk_set_null_on_parent_delete(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            parent = _new_job(job_type="group_detection")
            sess.add(parent)
            sess.flush()
            parent_id = parent.id

            child = _new_job(
                job_type="risk_evaluation",
                depends_on=parent_id,
                payload={"group_id": 1, "server_context_fp": "abc"},
            )
            sess.add(child)
            sess.commit()
            child_id = child.id

            # Parent loeschen → DB-Trigger soll child.depends_on auf NULL
            # setzen. `expire_all` zwingt SQLAlchemy, den ORM-Cache zu
            # invalidieren, sonst sehen wir noch den Vor-Delete-Wert.
            sess.delete(parent)
            sess.commit()
            sess.expire_all()

            reloaded = sess.execute(select(LLMJob).where(LLMJob.id == child_id)).scalar_one()
            assert reloaded.depends_on is None
        finally:
            sess.close()
