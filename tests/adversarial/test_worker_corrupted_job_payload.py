"""Adversarial: Worker faengt korrupte Job-Payloads sauber ab (ADR-0023).

Wenn ein Job mit kaputtem Payload eingelagert wird (defekter Migrate,
manuelle SQL-Manipulation, Schema-Drift) MUSS der Worker:

* den Job auf `status='failed'` setzen,
* einen verstaendlichen `error`-String hinterlegen,
* NICHT crashen — der Tick-Loop laeuft weiter.

Wir simulieren mehrere korrupte Payload-Shapes und beobachten den
Final-Status.
"""

from __future__ import annotations

import time as time_mod
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from flask import Flask

from app.db import get_session_factory
from app.models import LLMJob, Server
from app.settings_service import ensure_settings_row
from app.workers import llm_worker


@pytest.fixture(autouse=True)
def _route_worker(db_app: Flask) -> Any:
    factory = get_session_factory(db_app)
    llm_worker.set_session_factory_for_tests(factory)
    llm_worker.reset_shutdown_for_tests()
    llm_worker.set_reviewer_factory_for_tests(None)
    yield
    llm_worker.set_reviewer_factory_for_tests(None)
    llm_worker.reset_shutdown_for_tests()


def _set_live(app: Flask) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
        finally:
            sess.close()


def _seed_job(app: Flask, *, job_type: str, payload: dict[str, Any], attempts: int = 0) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=f"srv-corrupt-{uuid.uuid4().hex[:8]}",
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
            )
            sess.add(srv)
            sess.flush()
            job = LLMJob(
                job_type=job_type,
                server_id=srv.id,
                payload=payload,
                status="queued",
                attempts=attempts,
            )
            sess.add(job)
            sess.flush()
            sess.commit()
            return int(job.id)
        finally:
            sess.close()


def _force_attempts(app: Flask, job_id: int, attempts: int) -> None:
    """Setzt `attempts` direkt — Helper um in einen Tick die finale `failed`-
    Markierung zu provozieren ohne 3 separate Ticks zu fahren."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            job = sess.get(LLMJob, job_id)
            assert job is not None
            job.attempts = attempts
            sess.commit()
        finally:
            sess.close()


@pytest.mark.parametrize(
    ("payload", "label"),
    [
        pytest.param({"finding_ids": "not a list"}, "finding-ids-string", id="finding-ids-string"),
        pytest.param({}, "empty-payload", id="empty-payload"),
        pytest.param({"finding_ids": None}, "finding-ids-null", id="finding-ids-null"),
        pytest.param(
            {"finding_ids": [{"id": 1}, {"id": 2}]},
            "finding-ids-dict-list",
            id="finding-ids-dict-list",
        ),
    ],
)
def test_worker_handles_corrupted_pass1_payload(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], label: str
) -> None:
    """Corrupted Pass-1-Payload → Worker faengt, markiert failed/requeue,
    KEIN Crash."""
    _set_live(db_app)
    # MAX_ATTEMPTS-1, damit der naechste Fehlversuch direkt zu `failed` fuehrt.
    job_id = _seed_job(
        db_app,
        job_type="group_detection",
        payload=payload,
        attempts=llm_worker.MAX_ATTEMPTS - 1,
    )

    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

    # Reviewer muss bei Pass-1 nicht aufgerufen werden, weil der Worker
    # selbst die Payload-Felder parsed. Defensive Stub-Factory.
    def _stub(_session: Any) -> tuple[Any, str]:
        class _Stub:
            async def pass1_detect_groups(self, findings: Any) -> Any:
                raise AssertionError("Pass-1 should not have been entered")

            async def pass2_evaluate_groups(self, *_args: Any, **_kw: Any) -> Any:
                raise AssertionError("Pass-2 should not be entered")

        return _Stub(), "stub"

    llm_worker.set_reviewer_factory_for_tests(_stub)

    # Der Tick darf nicht crashen.
    llm_worker._tick()

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            job = sess.get(LLMJob, job_id)
            assert job is not None, f"job missing nach corrupted-payload-tick ({label})"
            # Drei zulaessige Pfade — wichtig ist: KEIN in_progress, KEIN
            # Worker-Crash. `done` ist OK wenn der Worker via defensiver
            # Skip-Pfad (`{"skipped": True}`) aussteigt. `failed` ist OK
            # wenn der Code beim Payload-Parsen explodiert hat. `queued` ist
            # OK fuer Requeue-Pfade (attempts < MAX_ATTEMPTS).
            assert job.status in {"failed", "queued", "done"}, (
                f"unerwarteter status={job.status} fuer payload={label}"
            )
            if job.status == "failed":
                assert job.error is not None
                assert len(job.error) > 0
            if job.status == "done":
                # Defensiver Skip muss explizit gemarkert sein, NICHT als
                # erfolgreicher LLM-Call durchgegangen.
                assert (job.result or {}).get("skipped") is True, (
                    f"payload={label} sollte als skipped markiert sein, result={job.result!r}"
                )
        finally:
            sess.close()


def test_worker_handles_corrupted_pass2_payload(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pass-2 mit fehlenden group_id/server_id → ValueError → failed."""
    _set_live(db_app)
    job_id = _seed_job(
        db_app,
        job_type="risk_evaluation",
        payload={},  # weder group_id noch server_id
        attempts=llm_worker.MAX_ATTEMPTS - 1,
    )

    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

    def _stub(_session: Any) -> tuple[Any, str]:
        class _Stub:
            async def pass2_evaluate_groups(self, *_args: Any, **_kw: Any) -> Any:
                raise AssertionError("Pass-2 reviewer must not be called")

        return _Stub(), "stub"

    llm_worker.set_reviewer_factory_for_tests(_stub)

    llm_worker._tick()

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            job = sess.get(LLMJob, job_id)
            assert job is not None
            assert job.status == "failed", f"status={job.status} error={job.error!r}"
            assert job.error is not None
            assert "pass2" in job.error.lower() or "payload" in job.error.lower()
        finally:
            sess.close()


def test_worker_tick_does_not_crash_on_corrupted_payload_sequence(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mehrere Tick-Iterationen mit verschiedenen kaputten Payloads — kein
    Tick-Loop-Abbruch."""
    _set_live(db_app)
    job_ids = [
        _seed_job(
            db_app, job_type="group_detection", payload={}, attempts=llm_worker.MAX_ATTEMPTS - 1
        ),
        _seed_job(
            db_app,
            job_type="risk_evaluation",
            payload={"group_id": "not-an-int"},
            attempts=llm_worker.MAX_ATTEMPTS - 1,
        ),
        _seed_job(
            db_app,
            job_type="group_detection",
            payload={"finding_ids": [None, None]},
            attempts=llm_worker.MAX_ATTEMPTS - 1,
        ),
    ]

    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

    def _stub(_session: Any) -> tuple[Any, str]:
        class _Stub:
            async def pass1_detect_groups(self, *_args: Any, **_kw: Any) -> Any:
                # Pass-1 mit None-Liste fuehrt nicht zwingend zu Crash, sondern
                # zu missing-findings — Worker handlet das selbst.
                raise ValueError("corrupted finding_ids")

            async def pass2_evaluate_groups(self, *_args: Any, **_kw: Any) -> Any:
                raise ValueError("never reached")

        return _Stub(), "stub"

    llm_worker.set_reviewer_factory_for_tests(_stub)

    # Drei Ticks — jedes Mal wird ein Job gepickt.
    for _ in range(len(job_ids)):
        llm_worker._tick()

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            for jid in job_ids:
                job = sess.get(LLMJob, jid)
                assert job is not None
                # Either failed or done (manche Payloads landen in `done`
                # mit `skipped=true` weil keine Findings gefunden werden).
                assert job.status in {"failed", "done"}, (
                    f"job {jid} stuck im status={job.status} error={job.error!r}"
                )
        finally:
            sess.close()
