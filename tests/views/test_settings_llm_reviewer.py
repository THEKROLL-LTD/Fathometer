"""Settings-Tab 'LLM Risk Reviewer' (Block P, Task #15).

DoD:
  - GET zeigt Mode + Stats (Queue-Counts, Library, Token-Budget, Worker).
  - POST Mode-Wechsel ohne Master-Key -> 403/Flash-Error.
  - POST Mode-Wechsel mit korrektem Master-Key -> DB-Update + Audit
    `llm.mode_changed`.
  - POST Re-queue-Backlog setzt would-call-Jobs auf `queued` zurueck +
    Audit `llm.backlog_requeued`.
  - Mode-Wechsel-Modal enthaelt Privacy-Notice (Frontend-Marker).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, LLMJob
from app.settings_service import ensure_settings_row
from tests._helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    DEFAULT_TEST_MASTER_KEY,
    create_admin_user,
    login,
    set_master_key,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _csrf_login(client: FlaskClient) -> None:
    """Login auf einer CSRF-aktiven App. Holt Token vom /login-Form."""
    get_resp = client.get("/login")
    assert get_resp.status_code == 200
    match = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', get_resp.data)
    assert match is not None
    token = match.group(1).decode()
    resp = client.post(
        "/login",
        data={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD,
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.get_data(as_text=True)[:400]


def _csrf_token_from_html(html: str) -> str:
    match = re.search(r'<input[^>]*name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _get_mode(app: Flask) -> str:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            return row.block_p_llm_mode
        finally:
            sess.close()


def _set_mode(app: Flask, mode: str) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = mode
            sess.commit()
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------


def test_llm_reviewer_view_renders_stats(db_app: Flask) -> None:
    """GET liefert Mode + Stats-Cards inkl. Token-Budget und Worker-Status."""
    create_admin_user(db_app)
    set_master_key(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get("/settings/llm-reviewer")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    # Tab-Marker.
    assert 'data-test="llm-reviewer-mode-card"' in body
    assert 'data-test="llm-current-mode"' in body
    # Mode-Default ist "off".
    assert "off" in body
    # Stats-Cards.
    assert 'data-test="llm-queue-stats-card"' in body
    assert 'data-test="llm-library-stats-card"' in body
    assert 'data-test="llm-cache-stats-card"' in body
    assert 'data-test="llm-token-budget-card"' in body
    assert 'data-test="llm-worker-card"' in body


def test_llm_reviewer_view_renders_privacy_notice_in_modal(db_app: Flask) -> None:
    """Privacy-Notice ist im Mode-Wechsel-Modal vorhanden (DSGVO-Hinweis)."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    body = client.get("/settings/llm-reviewer").get_data(as_text=True)
    assert 'data-test="llm-privacy-notice"' in body
    assert "DSGVO" in body or "GDPR" in body


# ---------------------------------------------------------------------------
# POST /mode
# ---------------------------------------------------------------------------


def test_llm_reviewer_mode_change_without_master_key_csrf_off(
    db_app: Flask,
) -> None:
    """Mode-Wechsel ohne Master-Key (Form-Validation greift -> 400)."""
    create_admin_user(db_app)
    set_master_key(db_app)
    client = db_app.test_client()
    login(client)
    # `csrf_enabled_db_app` wuerde CSRF zusaetzlich pruefen; hier in
    # `db_app` ist CSRF off, also faellt der Test auf die Validators-
    # Schicht: `master_key` ist required.
    resp = client.post(
        "/settings/llm-reviewer/mode",
        data={"new_mode": "live", "master_key": ""},
    )
    assert resp.status_code == 400, resp.status_code
    assert _get_mode(db_app) == "off"


def test_llm_reviewer_mode_change_with_wrong_master_key_403(db_app: Flask) -> None:
    """Mode-Wechsel mit falschem Master-Key -> 403, Mode bleibt off."""
    create_admin_user(db_app)
    set_master_key(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.post(
        "/settings/llm-reviewer/mode",
        data={"new_mode": "live", "master_key": "obviously-wrong-key-1234"},
    )
    assert resp.status_code == 403, resp.get_data(as_text=True)[:400]
    assert _get_mode(db_app) == "off"


def test_llm_reviewer_mode_change_succeeds_with_correct_master_key(
    db_app: Flask,
) -> None:
    """Korrekter Master-Key -> Mode-Update + Audit `llm.mode_changed`."""
    create_admin_user(db_app)
    set_master_key(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/mode",
        data={"new_mode": "observation", "master_key": DEFAULT_TEST_MASTER_KEY},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), resp.get_data(as_text=True)[:400]
    assert _get_mode(db_app) == "observation"

    # Audit-Event.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            evt = sess.execute(
                select(AuditEvent)
                .where(AuditEvent.action == "llm.mode_changed")
                .order_by(AuditEvent.ts.desc())
                .limit(1)
            ).scalar_one()
            assert evt.event_metadata is not None
            assert evt.event_metadata.get("from") == "off"
            assert evt.event_metadata.get("to") == "observation"
        finally:
            sess.close()


def test_llm_reviewer_mode_change_same_mode_is_noop(db_app: Flask) -> None:
    """Mode-Wechsel zum aktuellen Wert -> kein Audit, kein DB-Change."""
    create_admin_user(db_app)
    set_master_key(db_app)
    _set_mode(db_app, "observation")
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/mode",
        data={"new_mode": "observation", "master_key": DEFAULT_TEST_MASTER_KEY},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    # Mode bleibt.
    assert _get_mode(db_app) == "observation"
    # Kein neuer Audit-Event.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            evt_count = (
                sess.execute(select(AuditEvent).where(AuditEvent.action == "llm.mode_changed"))
                .scalars()
                .all()
            )
            assert len(evt_count) == 0
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# POST /requeue-backlog
# ---------------------------------------------------------------------------


def _seed_would_call_jobs(app: Flask, count: int) -> list[int]:
    """Legt `count` `done`-Jobs mit `result.would_call=true` an."""
    factory = get_session_factory(app)
    ids: list[int] = []
    with app.app_context():
        sess = factory()
        try:
            for _i in range(count):
                job = LLMJob(
                    job_type="group_detection",
                    payload={"server_id": 1, "findings": []},
                    status="done",
                    attempts=1,
                    next_attempt_at=datetime.now(tz=UTC),
                    result={"would_call": True, "estimated_input_tokens": 100},
                    created_at=datetime.now(tz=UTC),
                    completed_at=datetime.now(tz=UTC),
                )
                sess.add(job)
                sess.flush()
                ids.append(job.id)
            sess.commit()
            return ids
        finally:
            sess.close()


def test_llm_reviewer_requeue_backlog_resets_jobs(db_app: Flask) -> None:
    """Re-queue setzt would_call-Jobs auf `queued`, attempts=0, result=NULL +
    Audit-Event."""
    create_admin_user(db_app)
    set_master_key(db_app)
    _set_mode(db_app, "live")
    job_ids = _seed_would_call_jobs(db_app, count=3)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/requeue-backlog",
        data={"master_key": DEFAULT_TEST_MASTER_KEY},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), resp.get_data(as_text=True)[:400]

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            for jid in job_ids:
                job = sess.get(LLMJob, jid)
                assert job is not None
                assert job.status == "queued"
                assert job.attempts == 0
                assert job.result is None

            evt = sess.execute(
                select(AuditEvent)
                .where(AuditEvent.action == "llm.backlog_requeued")
                .order_by(AuditEvent.ts.desc())
                .limit(1)
            ).scalar_one()
            assert evt.event_metadata is not None
            assert evt.event_metadata.get("count") == 3
        finally:
            sess.close()


def test_llm_reviewer_requeue_backlog_requires_live_mode(db_app: Flask) -> None:
    """Re-queue in `off`/`observation` -> Mode-Error, kein Job-Reset."""
    create_admin_user(db_app)
    set_master_key(db_app)
    _set_mode(db_app, "observation")
    job_ids = _seed_would_call_jobs(db_app, count=2)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/requeue-backlog",
        data={"master_key": DEFAULT_TEST_MASTER_KEY},
        follow_redirects=False,
    )
    # Redirect zurueck mit Flash-Error.
    assert resp.status_code in (302, 303)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            for jid in job_ids:
                job = sess.get(LLMJob, jid)
                assert job is not None
                assert job.status == "done", f"Job {jid} darf nicht re-queued sein"
        finally:
            sess.close()


def test_llm_reviewer_requeue_backlog_wrong_master_key(db_app: Flask) -> None:
    """Re-queue mit falschem Master-Key -> kein Reset."""
    create_admin_user(db_app)
    set_master_key(db_app)
    _set_mode(db_app, "live")
    job_ids = _seed_would_call_jobs(db_app, count=2)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/requeue-backlog",
        data={"master_key": "absolutely-wrong-key-not-the-default"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            for jid in job_ids:
                job = sess.get(LLMJob, jid)
                assert job is not None
                assert job.status == "done"
        finally:
            sess.close()
