"""Block P Phase H Task #19 — E2E Mode-Switch (ADR-0023).

Endlauf:
* off → observation: Audit `llm.mode_changed` mit `{from:"off",to:"observation"}`.
* observation → live: Audit, Worker pickt jetzt echte Calls (Mock).
* live → off: Worker hoert auf zu picken (next tick skippt).
* Mode-Wechsel ohne master_key oder mit falschem → 403, KEIN Audit, Mode bleibt.
"""

from __future__ import annotations

import time as time_mod
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import ApplicationGroup, AuditEvent, Finding, LLMJob
from app.services.group_matcher import GroupMatcher
from app.services.llm_risk_reviewer import (
    Pass1Group,
    Pass1Result,
    Pass2Evaluation,
    Pass2Result,
)
from app.settings_service import ensure_settings_row
from app.workers import llm_worker
from tests._helpers import (
    DEFAULT_TEST_MASTER_KEY,
    create_admin_user,
    login,
    set_master_key,
)
from tests.integration.conftest import MockReviewer

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton() -> Any:
    GroupMatcher._reset_for_tests()
    yield
    GroupMatcher._reset_for_tests()


@pytest.fixture(autouse=True)
def _route_worker(db_app: Flask) -> Any:
    factory = get_session_factory(db_app)
    llm_worker.set_session_factory_for_tests(factory)
    llm_worker.reset_shutdown_for_tests()
    llm_worker.set_reviewer_factory_for_tests(None)
    yield
    llm_worker.set_reviewer_factory_for_tests(None)
    llm_worker.reset_shutdown_for_tests()


def _get_mode(app: Flask) -> str:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return ensure_settings_row(sess).block_p_llm_mode
        finally:
            sess.close()


def _audit_events(app: Flask, action: str) -> list[AuditEvent]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(
                    select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id)
                )
                .scalars()
                .all()
            )
        finally:
            sess.close()


def _switch_mode(client: Any, new_mode: str, master_key: str = DEFAULT_TEST_MASTER_KEY) -> Any:
    return client.post(
        "/settings/llm-reviewer/mode",
        data={"new_mode": new_mode, "master_key": master_key},
        follow_redirects=False,
    )


def _seed_pass1_job(app: Flask) -> int:
    """Legt einen `queued` Pass-1-Job an und liefert die Job-ID zurueck.

    Wird genutzt um zu beweisen dass ein Mode-Wechsel auf off den Worker-
    Pickup blockiert.
    """
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            job = LLMJob(
                job_type="group_detection",
                server_id=None,
                payload={"finding_ids": []},
                status="queued",
            )
            sess.add(job)
            sess.flush()
            sess.commit()
            return int(job.id)
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_mode_switch_full_chain_off_observation_live_off(db_app: Flask) -> None:
    """off → observation → live → off — drei Audits, Mode trackt korrekt."""
    create_admin_user(db_app)
    set_master_key(db_app)
    client = db_app.test_client()
    login(client)

    assert _get_mode(db_app) == "off"

    # off → observation
    r1 = _switch_mode(client, "observation")
    assert r1.status_code in (302, 303)
    assert _get_mode(db_app) == "observation"

    # observation → live
    r2 = _switch_mode(client, "live")
    assert r2.status_code in (302, 303)
    assert _get_mode(db_app) == "live"

    # live → off
    r3 = _switch_mode(client, "off")
    assert r3.status_code in (302, 303)
    assert _get_mode(db_app) == "off"

    events = _audit_events(db_app, "llm.mode_changed")
    assert len(events) == 3
    assert events[0].event_metadata == {"from": "off", "to": "observation"}
    assert events[1].event_metadata == {"from": "observation", "to": "live"}
    assert events[2].event_metadata == {"from": "live", "to": "off"}


def test_mode_switch_without_master_key_blocks_change(db_app: Flask) -> None:
    """Leerer Master-Key → Form-Validator schlaegt fehl (400), kein Mode-Wechsel,
    kein Audit."""
    create_admin_user(db_app)
    set_master_key(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/mode",
        data={"new_mode": "live", "master_key": ""},
    )
    assert resp.status_code == 400
    assert _get_mode(db_app) == "off"
    assert _audit_events(db_app, "llm.mode_changed") == []


def test_mode_switch_with_wrong_master_key_returns_403_no_audit(db_app: Flask) -> None:
    """Falscher Master-Key → 403, Mode bleibt, kein Audit."""
    create_admin_user(db_app)
    set_master_key(db_app)
    client = db_app.test_client()
    login(client)

    resp = _switch_mode(client, "live", master_key="absolutely-wrong-key-1234")
    assert resp.status_code == 403
    assert _get_mode(db_app) == "off"
    assert _audit_events(db_app, "llm.mode_changed") == []


def test_mode_switch_to_off_skips_worker_pickup(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Worker-Tick im off-Mode pickt keinen Job, auch wenn einer queued ist."""
    job_id = _seed_pass1_job(db_app)
    factory = get_session_factory(db_app)

    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

    llm_worker._tick()

    with db_app.app_context():
        sess = factory()
        try:
            job = sess.get(LLMJob, job_id)
            assert job is not None
            assert job.status == "queued", f"job must remain queued in mode=off, got {job.status}"
        finally:
            sess.close()


def test_mode_switch_observation_to_live_changes_worker_behavior(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Observation-Mode markiert nur `would_call`; live-Mode ruft den Mock-LLM."""
    factory = get_session_factory(db_app)
    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

    # Server + ein Finding (ohne Group) anlegen — fuer den Pass-1-Job.
    from app.models import (
        AttackVector,
        FindingClass,
        FindingStatus,
        FindingType,
        Server,
        Severity,
    )

    now = datetime.now(UTC)
    with db_app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "observation"
            row.llm_token_budget_reset_at = now + timedelta(hours=2)
            sess.commit()

            srv = Server(
                name="srv-mode-switch",
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                os_family="ubuntu",
                os_version="24.04",
            )
            sess.add(srv)
            sess.flush()

            finding = Finding(
                server_id=srv.id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key="CVE-2024-55001",
                package_name="openssl",
                installed_version="1.0",
                severity=Severity.HIGH,
                attack_vector=AttackVector.UNKNOWN,
                status=FindingStatus.OPEN,
                is_kev=False,
                first_seen_at=now,
                last_seen_at=now,
                severity_by_provider={"nvd": "high"},
                vendor_status="affected",
            )
            sess.add(finding)
            sess.flush()
            finding_id = finding.id
            server_id = srv.id

            job = LLMJob(
                job_type="group_detection",
                server_id=server_id,
                payload={"finding_ids": [finding_id]},
                status="queued",
            )
            sess.add(job)
            sess.flush()
            obs_job_id = job.id
            sess.commit()
        finally:
            sess.close()

    # 1) Observation-Tick → would_call, kein DB-Group, kein LLM-Call.
    llm_worker._tick()

    with db_app.app_context():
        sess = factory()
        try:
            obs_job = sess.get(LLMJob, obs_job_id)
            assert obs_job is not None
            assert obs_job.status == "done"
            assert (obs_job.result or {}).get("would_call") is True
            assert (obs_job.result or {}).get("mode") == "observation"
            groups = list(sess.execute(select(ApplicationGroup)).scalars().all())
            assert groups == [], "observation must not persist any group"
        finally:
            sess.close()

    # 2) Mode-Switch auf live + Mock-Reviewer + neuer Pass-1-Job.
    pass1 = Pass1Result(
        groups=[
            Pass1Group(
                label="openssl",
                explanation="distro pkg",
                path_prefixes=[],
                pkg_name_exact=["openssl"],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                finding_ids=[finding_id],
            )
        ],
        ungrouped_finding_ids=[],
    )
    pass2 = Pass2Result(
        evaluations=[
            Pass2Evaluation(
                group_label="openssl",
                risk_band="monitor",
                reason="No listener.",
                worst_finding_id=finding_id,
            )
        ]
    )
    mock_reviewer = MockReviewer(pass1_result=pass1, pass2_result=pass2)

    def _factory(_session: Any) -> tuple[Any, str]:
        return mock_reviewer, "mock-model"

    llm_worker.set_reviewer_factory_for_tests(_factory)

    with db_app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            sess.commit()
            job2 = LLMJob(
                job_type="group_detection",
                server_id=server_id,
                payload={"finding_ids": [finding_id]},
                status="queued",
            )
            sess.add(job2)
            sess.flush()
            live_job_id = job2.id
            sess.commit()
        finally:
            sess.close()

    llm_worker._tick()
    assert mock_reviewer.pass1_call_count == 1

    with db_app.app_context():
        sess = factory()
        try:
            live_job = sess.get(LLMJob, live_job_id)
            assert live_job is not None
            assert live_job.status == "done"
            # Cache und Group existieren jetzt.
            grp = sess.execute(
                select(ApplicationGroup).where(ApplicationGroup.label == "openssl")
            ).scalar_one()
            assert grp.source == "llm"
            f = sess.get(Finding, finding_id)
            assert f is not None
            assert f.application_group_id == grp.id
        finally:
            sess.close()
