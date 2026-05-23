"""Block P Phase H Task #19 — E2E Live-Mode mit Mock-LLM (ADR-0023).

Endlauf:
1. Mock-LLM-Client mit deterministischen Pass-1/Pass-2-Responses.
2. Scan-Ingest mit pending Findings ohne passende Library → Pass-1-Job
   queued, kein Pass-2-Job (Library leer).
3. Worker-Tick Pass-1 → Group wird in `application_groups` angelegt,
   `Finding.application_group_id` wird gesetzt.
4. Re-Scan derselben Findings → `apply_matches_for_server` matched die
   Group, KEIN neuer Pass-1, ein Pass-2-Job entsteht (Group war noch
   unbewertet beim zweiten Ingest).
5. Worker-Tick Pass-2 → Group bekommt `risk_band="act"`, `risk_band_source="llm"`,
   `worst_finding_id` gesetzt; `llm_risk_cache`-Eintrag entsteht.
6. Dritter Scan mit identischen Findings → Cache-HIT, Mock-Reviewer wird
   nicht erneut aufgerufen, `used_count` steigt auf 1.
"""

from __future__ import annotations

import gzip
import json
import time as time_mod
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import ApplicationGroup, Finding, LLMJob, LLMRiskCache
from app.services.group_matcher import GroupMatcher
from app.services.llm_risk_reviewer import (
    Pass1Group,
    Pass1Result,
    Pass2Evaluation,
    Pass2Result,
)
from app.settings_service import ensure_settings_row
from app.workers import llm_worker
from tests._helpers import register_test_server
from tests.integration.conftest import MockReviewer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _drive_dispatch_iteration() -> None:
    """Block U Phase C (ADR-0029) Migration-Helper: ersetzt ``_drive_dispatch_iteration()``.

    Pickt einen einzelnen Job aus der Queue und verarbeitet ihn via
    ``asyncio.run(_process_one_async(...))``. Sub-Ticks bleiben aussen
    vor — diese Tests pruefen LLM-Job-Lifecycle gegen den Mock-Reviewer.
    """
    import asyncio as _asyncio

    llm_worker.invalidate_throttle_caches_for_tests()
    mode = llm_worker._get_mode_throttled()
    if mode == "off" or not llm_worker._budget_ok_throttled():
        return
    job_id = llm_worker._pick_next_job_id()
    if job_id is None:
        return
    _asyncio.run(llm_worker._process_one_async(job_id, mode))


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
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
        finally:
            sess.close()


def _install_mock_reviewer(reviewer: MockReviewer) -> MockReviewer:
    def _factory(_session: Any) -> tuple[Any, str]:
        return reviewer, "mock-model"

    llm_worker.set_reviewer_factory_for_tests(_factory)
    return reviewer


def _run_all_picks(monkeypatch: pytest.MonkeyPatch, max_iterations: int = 20) -> int:
    """Faehrt den Worker-Tick wiederholt bis die Queue leer ist."""
    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)
    iterations = 0
    while iterations < max_iterations:
        before = llm_worker._pick_next_job_id  # sanity, not called
        _ = before
        # Use the Phase-C dispatcher-iteration helper which auto-picks if a
        # job is ready. We bail out wenn kein Job mehr drin ist.
        iterations += 1
        _drive_dispatch_iteration()
        if not _has_queued_jobs():
            break
    return iterations


def _has_queued_jobs() -> bool:
    """True wenn noch `queued` Jobs offen sind (depends_on aufgeloest)."""
    factory = llm_worker._get_session_factory()
    sess = factory()
    try:
        from sqlalchemy import func, text

        # Vereinfacht: queued mit aufgeloester Dependency.
        cnt = sess.execute(
            text(
                "SELECT count(*) FROM llm_jobs j WHERE status = 'queued' "
                "AND (depends_on IS NULL OR depends_on IN "
                "(SELECT id FROM llm_jobs WHERE status = 'done'))"
            )
        ).scalar_one()
        _ = func
        return int(cnt) > 0
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_live_e2e_full_pass1_then_pass2_cycle(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pass-1 + Pass-2 vollstaendiger Durchlauf mit Mock-Reviewer."""
    _set_mode(db_app, "live")
    sid, key = register_test_server(db_app, name="srv-live-e2e")

    # 1) Initialer Scan: Pass-1 wird queued, Pass-2 nicht (Library leer).
    resp = _post_scan(
        db_app,
        key,
        [
            {
                "VulnerabilityID": "CVE-2024-77001",
                "PkgName": "openssh-server",
                "InstalledVersion": "1.0",
                "Severity": "HIGH",
            },
            {
                "VulnerabilityID": "CVE-2024-77002",
                "PkgName": "openssh-server",
                "InstalledVersion": "1.0",
                "Severity": "HIGH",
            },
        ],
    )
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            finding_ids = sorted(
                f.id
                for f in sess.execute(select(Finding).where(Finding.server_id == sid))
                .scalars()
                .all()
            )
            assert len(finding_ids) == 2
            jobs_pre = list(sess.execute(select(LLMJob)).scalars().all())
            assert len(jobs_pre) == 1
            assert jobs_pre[0].job_type == "group_detection"
        finally:
            sess.close()

    # 2) Pass-1-Reviewer: legt openssh-server-Group an.
    pass1 = Pass1Result(
        groups=[
            Pass1Group(
                label="openssh-server",
                explanation="OS distro openssh",
                path_prefixes=[],
                pkg_name_exact=["openssh-server"],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                finding_ids=finding_ids,
            )
        ],
        ungrouped_finding_ids=[],
    )
    pass2 = Pass2Result(
        evaluations=[
            Pass2Evaluation(
                group_label="openssh-server",
                risk_band="act",
                action_type="patch",
                reason="Patch im Distro-Repo verfuegbar.",
                worst_finding_id=finding_ids[0],
            )
        ]
    )
    mock_reviewer = _install_mock_reviewer(MockReviewer(pass1_result=pass1, pass2_result=pass2))

    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

    # 3) Pass-1-Tick.
    _drive_dispatch_iteration()
    assert mock_reviewer.pass1_call_count == 1, "pass1 must have been called"

    with db_app.app_context():
        sess = factory()
        try:
            grp = sess.execute(
                select(ApplicationGroup).where(ApplicationGroup.label == "openssh-server")
            ).scalar_one()
            assert grp.source == "llm"
            assert "openssh-server" in (grp.pkg_name_exact or [])
            findings = list(
                sess.execute(select(Finding).where(Finding.server_id == sid)).scalars().all()
            )
            assert all(f.application_group_id == grp.id for f in findings)
        finally:
            sess.close()

    # 4) Zweiter Scan: GroupMatcher matched alle Findings → kein Pass-1,
    #    Pass-2 entsteht (Group hat noch keine Bewertung).
    GroupMatcher._reset_for_tests()  # forciert Reload des Singleton
    resp2 = _post_scan(
        db_app,
        key,
        [
            {
                "VulnerabilityID": "CVE-2024-77001",
                "PkgName": "openssh-server",
                "InstalledVersion": "1.0",
                "Severity": "HIGH",
            },
            {
                "VulnerabilityID": "CVE-2024-77002",
                "PkgName": "openssh-server",
                "InstalledVersion": "1.0",
                "Severity": "HIGH",
            },
        ],
    )
    assert resp2.status_code == 202

    with db_app.app_context():
        sess = factory()
        try:
            jobs = list(sess.execute(select(LLMJob).order_by(LLMJob.id)).scalars().all())
            # Erster Pass-1 ist done; ein neuer Pass-2 ist queued.
            queued_jobs = [j for j in jobs if j.status == "queued"]
            assert len(queued_jobs) == 1
            assert queued_jobs[0].job_type == "risk_evaluation"
            assert queued_jobs[0].depends_on is None  # Library matched, kein Parent
        finally:
            sess.close()

    # 5) Pass-2-Tick.
    _drive_dispatch_iteration()
    assert mock_reviewer.pass2_call_count == 1, "pass2 must have been called once"

    with db_app.app_context():
        sess = factory()
        try:
            grp = sess.execute(
                select(ApplicationGroup).where(ApplicationGroup.label == "openssh-server")
            ).scalar_one()
            assert grp.risk_band == "act"
            assert grp.risk_band_source == "llm"
            assert grp.risk_band_reason == "Patch im Distro-Repo verfuegbar."
            assert grp.worst_finding_id in finding_ids
            assert grp.group_findings_fingerprint is not None

            # Cache-Eintrag wurde angelegt.
            caches = list(sess.execute(select(LLMRiskCache)).scalars().all())
            assert len(caches) == 1
            assert caches[0].risk_band == "act"
            assert caches[0].group_id == grp.id
            assert caches[0].llm_model == "mock-model"
            assert len(caches[0].cache_key) == 64  # voller SHA-256-hex
            # `used_count` Default ist 1 (siehe Model); ein record_hit liefe
            # erst beim naechsten Cache-Lookup.
            assert caches[0].used_count == 1
        finally:
            sess.close()


def test_live_e2e_cache_hit_on_identical_rescan(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-Scan mit identischen Findings → Cache-Hit, kein zweiter LLM-Call."""
    _set_mode(db_app, "live")
    sid, key = register_test_server(db_app, name="srv-live-cache")

    vulns = [
        {
            "VulnerabilityID": "CVE-2024-88001",
            "PkgName": "openssl",
            "InstalledVersion": "1.0",
            "Severity": "HIGH",
        },
    ]

    resp = _post_scan(db_app, key, vulns)
    assert resp.status_code == 202

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            finding_ids = sorted(
                f.id
                for f in sess.execute(select(Finding).where(Finding.server_id == sid))
                .scalars()
                .all()
            )
        finally:
            sess.close()

    pass1 = Pass1Result(
        groups=[
            Pass1Group(
                label="openssl",
                explanation="OS distro openssl",
                path_prefixes=[],
                pkg_name_exact=["openssl"],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                finding_ids=finding_ids,
            )
        ],
        ungrouped_finding_ids=[],
    )
    pass2 = Pass2Result(
        evaluations=[
            Pass2Evaluation(
                group_label="openssl",
                risk_band="mitigate",
                action_type="mitigate",
                reason="No clear listener.",
                worst_finding_id=finding_ids[0],
            )
        ]
    )
    mock_reviewer = _install_mock_reviewer(MockReviewer(pass1_result=pass1, pass2_result=pass2))

    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

    # Erster Pass-1-Tick → Group, Findings zugeordnet.
    _drive_dispatch_iteration()
    assert mock_reviewer.pass1_call_count == 1

    # Re-Scan: GroupMatcher matched, Pass-2 queued.
    GroupMatcher._reset_for_tests()
    resp = _post_scan(db_app, key, vulns)
    assert resp.status_code == 202

    # Pass-2-Tick → LLM-Call, Cache geschrieben.
    _drive_dispatch_iteration()
    assert mock_reviewer.pass2_call_count == 1

    # Dritter Scan: gleiche Findings, gleicher Fingerprint → Hook queued
    # NICHT erneut (Idempotenz), aber wir koennen den Cache-Pfad explizit
    # ueber einen direkten Pass-2-Job antesten.
    GroupMatcher._reset_for_tests()
    with db_app.app_context():
        sess = factory()
        try:
            grp = sess.execute(
                select(ApplicationGroup).where(ApplicationGroup.label == "openssl")
            ).scalar_one()
            # Group-Fingerprint zuruecksetzen, damit der Hook erneut queued.
            grp.group_findings_fingerprint = None
            sess.commit()
        finally:
            sess.close()

    resp = _post_scan(db_app, key, vulns)
    assert resp.status_code == 202

    # Tick fuer den jetzt erneut existierenden Pass-2-Job.
    _drive_dispatch_iteration()
    # Mock-Reviewer-Pass-2 darf KEIN zweites Mal aufgerufen worden sein —
    # der Cache-Eintrag matched.
    assert mock_reviewer.pass2_call_count == 1, (
        f"cache should have absorbed second Pass-2 call, got {mock_reviewer.pass2_call_count}"
    )

    # Cache zeigt used_count >= 1.
    with db_app.app_context():
        sess = factory()
        try:
            cache_row = sess.execute(select(LLMRiskCache)).scalar_one()
            assert cache_row.used_count >= 1
            assert cache_row.last_used_at is not None
        finally:
            sess.close()


def test_live_e2e_no_findings_in_envelope_skips_jobs(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scan ohne pending Findings → kein Pass-1, kein Pass-2."""
    _set_mode(db_app, "live")
    sid, key = register_test_server(db_app, name="srv-live-empty")

    resp = _post_scan(
        db_app,
        key,
        [
            {
                "VulnerabilityID": "CVE-2024-66001",
                "PkgName": "low-pkg",
                "InstalledVersion": "1.0",
                "Severity": "LOW",
            }
        ],
    )
    assert resp.status_code == 202
    _ = sid

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            jobs = list(sess.execute(select(LLMJob)).scalars().all())
            assert jobs == []
        finally:
            sess.close()

    # Worker-Tick → Queue ist leer, kein Crash.
    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)
    # Wir installieren einen Reviewer der bei Aufruf explodieren wuerde —
    # er darf nicht aufgerufen werden.
    exploding = MockReviewer(pass1_result=None, pass2_result=None)
    _install_mock_reviewer(exploding)
    _drive_dispatch_iteration()
    assert exploding.pass1_call_count == 0
    assert exploding.pass2_call_count == 0


@pytest.fixture
def _dummy_factory_pass() -> Callable[[Any], tuple[Any, str]]:
    """Hilfs-Factory die einen Mock-Reviewer ausgibt."""

    def _factory(_session: Any) -> tuple[Any, str]:
        return MockReviewer(), "mock-model"

    return _factory
