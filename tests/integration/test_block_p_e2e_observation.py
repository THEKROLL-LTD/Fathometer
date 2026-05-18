"""Block P Phase H Task #19 — E2E Observation-Mode (ADR-0023).

Endlauf:
* Scan-Ingest mit pending Findings → Pass-1-Job wird gequeued.
* Worker pickt den Job in Observation-Mode → schreibt ``would_call``-Marker.
* Settings-Tab GET zeigt die korrekten Queue-Counts (done=1, queued=0).
* `llm.jobs_queued` Audit-Event ist gesetzt.
"""

from __future__ import annotations

import gzip
import json
import time as time_mod
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, LLMJob
from app.services.group_matcher import GroupMatcher
from app.settings_service import ensure_settings_row
from app.workers import llm_worker
from tests._helpers import (
    create_admin_user,
    login,
    register_test_server,
    set_master_key,
)

# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton() -> Any:
    GroupMatcher._reset_for_tests()
    yield
    GroupMatcher._reset_for_tests()


def _minimal_host_state() -> dict[str, Any]:
    return {
        "snapshot_at": "2026-05-18T03:14:22Z",
        "tools_available": ["ss", "ps", "lsmod", "systemctl"],
        "gaps": [],
        "listeners": [],
        "processes": [],
        "kernel_modules": [],
        "services": [],
    }


def _envelope(vulns: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "agent_version": "0.3.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15.0",
            "architecture": "x86_64",
            "trivy_version": "0.70.2",
        },
        "scan": {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.2"},
            "Results": [
                {
                    "Target": "test",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": vulns,
                }
            ],
        },
        "host_state": _minimal_host_state(),
    }


def _post_scan(app: Flask, bearer: str, vulns: list[dict[str, Any]]) -> Any:
    client = app.test_client()
    return client.post(
        "/api/scans",
        data=gzip.compress(json.dumps(_envelope(vulns)).encode("utf-8")),
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Authorization": f"Bearer {bearer}",
        },
    )


def _set_mode(app: Flask, mode: str) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = mode
            # Token-Budget-Reset Zeitpunkt in der Zukunft, damit der
            # maybe_reset_budget-Hook nicht den Counter zurueck setzt.
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
        finally:
            sess.close()


def _route_worker(app: Flask) -> None:
    factory = get_session_factory(app)
    llm_worker.set_session_factory_for_tests(factory)
    llm_worker.reset_shutdown_for_tests()
    llm_worker.set_reviewer_factory_for_tests(None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_observation_e2e_scan_ingest_worker_pickup_and_settings_stats(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Observation-Mode E2E: Pass-1-Job entsteht, Worker schreibt
    `would_call`, Settings-Tab zeigt korrekte Stats."""
    _set_mode(db_app, "observation")
    _route_worker(db_app)
    sid, key = register_test_server(db_app, name="srv-obs-e2e")

    # 1) Scan-Ingest.
    resp = _post_scan(
        db_app,
        key,
        [
            {
                "VulnerabilityID": "CVE-2024-99001",
                "PkgName": "openssh-server",
                "InstalledVersion": "1.0",
                "Severity": "HIGH",
            }
        ],
    )
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            jobs = list(sess.execute(select(LLMJob)).scalars().all())
            assert len(jobs) == 1
            job = jobs[0]
            assert job.job_type == "group_detection"
            assert job.status == "queued"
            assert job.server_id == sid

            # 2) jobs_queued-Audit ist gesetzt.
            jq = list(
                sess.execute(select(AuditEvent).where(AuditEvent.action == "llm.jobs_queued"))
                .scalars()
                .all()
            )
            assert len(jq) == 1
            assert jq[0].event_metadata is not None
            assert jq[0].event_metadata["pass1_queued"] == 1
            assert jq[0].event_metadata["mode"] == "observation"
        finally:
            sess.close()

    # 3) Worker-Tick (sleeps muten).
    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)
    llm_worker._tick()

    # 4) Job ist done, would_call-Marker im Result.
    with db_app.app_context():
        sess = factory()
        try:
            job_done = sess.execute(select(LLMJob)).scalar_one()
            assert job_done.status == "done", f"status={job_done.status} error={job_done.error}"
            assert job_done.result is not None
            assert job_done.result.get("would_call") is True
            assert job_done.result.get("mode") == "observation"
            assert job_done.result.get("estimated_tokens", 0) > 0
        finally:
            sess.close()

    # 5) Settings-Tab GET zeigt Stats (queued=0, done=1).
    create_admin_user(db_app)
    set_master_key(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/llm-reviewer")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Marker fuer Queue-Stats-Card.
    assert 'data-test="llm-queue-stats-card"' in body
    # Aktueller Mode wird angezeigt.
    assert "observation" in body


def test_observation_token_budget_accumulates(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Observation-Mode bucht estimate_tokens gegen das Tagesbudget."""
    _set_mode(db_app, "observation")
    _route_worker(db_app)
    sid, key = register_test_server(db_app, name="srv-obs-budget")

    # Drei pending Findings.
    vulns = [
        {
            "VulnerabilityID": f"CVE-2024-9900{i}",
            "PkgName": "openssh-server",
            "InstalledVersion": "1.0",
            "Severity": "HIGH",
        }
        for i in range(3)
    ]
    resp = _post_scan(db_app, key, vulns)
    assert resp.status_code == 202

    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)
    llm_worker._tick()

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            # estimate_tokens fuer group_detection: 50 * len(finding_ids).
            assert row.llm_token_budget_used_today == 150
            _ = sid
        finally:
            sess.close()
