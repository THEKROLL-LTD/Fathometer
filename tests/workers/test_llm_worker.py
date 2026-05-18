"""Tests fuer `app.workers.llm_worker` — Block P (ADR-0023) Phase C.

Abgedeckt:

* ``_pick_next_job_id`` mit leerer Queue → None.
* ``_pick_next_job_id`` setzt status=in_progress, picked_up_by/at, attempts+1.
* Concurrency: zwei simultane Picks → genau einer kriegt den Job (SKIP LOCKED).
* Dependency-Check: Pass-2-Job mit ``depends_on`` auf nicht-``done``
  Pass-1-Job wird NICHT gepickt.
* Stale-Reaper resettet ``in_progress``-Jobs zurueck auf ``queued`` mit
  Backoff (und auf ``failed`` bei ``attempts >= MAX_ATTEMPTS``).
* Mode=off: kein Pickup (`_tick` schlaeft).
* Mode=observation: Job wird ``done`` mit ``would_call``-Marker.
* Mode=live mit Mock-Reviewer: Group wird gefuellt, Cache-Eintrag entsteht.
* SIGTERM-Verhalten: ``main()`` bricht ab wenn ``_shutdown`` gesetzt ist.
"""

from __future__ import annotations

import asyncio
import threading
import time as time_mod
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select, text

from app.db import get_session_factory
from app.models import (
    ApplicationGroup,
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    LLMJob,
    LLMRiskCache,
    Server,
    Severity,
)
from app.services.llm_risk_reviewer import (
    Pass1Group,
    Pass1Result,
    Pass2Evaluation,
    Pass2Result,
)
from app.settings_service import ensure_settings_row
from app.workers import llm_worker

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _worker_factory_to_app(db_app: Flask) -> Any:
    """Routet die Worker-Session-Factory auf die `db_app`-Engine."""
    factory = get_session_factory(db_app)
    llm_worker.set_session_factory_for_tests(factory)
    llm_worker.reset_shutdown_for_tests()
    llm_worker.set_reviewer_factory_for_tests(None)
    yield
    llm_worker.set_reviewer_factory_for_tests(None)
    llm_worker.reset_shutdown_for_tests()


def _open_sess(db_app: Flask) -> Any:
    return get_session_factory(db_app)()


def _make_finding(sess: Any, fid: int, server_id: int, **kw: Any) -> Finding:
    now = datetime.now(UTC)
    defaults: dict[str, Any] = {
        "id": fid,
        "server_id": server_id,
        "finding_type": FindingType.VULNERABILITY,
        "finding_class": FindingClass.OS_PKGS,
        "identifier_key": f"CVE-2025-{fid:04d}",
        "package_name": "openssl",
        "installed_version": "1.0",
        "severity": Severity.HIGH,
        "attack_vector": AttackVector.UNKNOWN,
        "status": FindingStatus.OPEN,
        "is_kev": False,
        "first_seen_at": now,
        "last_seen_at": now,
        "severity_by_provider": {"nvd": "high"},
        "vendor_status": "affected",
    }
    defaults.update(kw)
    f = Finding(**defaults)
    sess.add(f)
    return f


def _make_server(sess: Any, sid: int = 1) -> Server:
    s = Server(
        id=sid,
        name=f"srv-{sid}",
        api_key_hash="x" * 64,
        expected_scan_interval_h=24,
        os_family="ubuntu",
        os_version="24.04",
    )
    sess.add(s)
    sess.flush()
    return s


def _make_job(
    sess: Any,
    *,
    job_type: str = "group_detection",
    server_id: int | None = None,
    payload: dict[str, Any] | None = None,
    status: str = "queued",
    depends_on: int | None = None,
    attempts: int = 0,
    picked_up_at: datetime | None = None,
    picked_up_by: str | None = None,
) -> LLMJob:
    job = LLMJob(
        job_type=job_type,
        server_id=server_id,
        payload=payload or {},
        status=status,
        depends_on=depends_on,
        attempts=attempts,
        picked_up_at=picked_up_at,
        picked_up_by=picked_up_by,
    )
    sess.add(job)
    sess.flush()
    return job


# ---------------------------------------------------------------------------
# Pickup
# ---------------------------------------------------------------------------


def test_pick_next_job_empty_queue_returns_none(db_app: Flask) -> None:
    with db_app.app_context():
        assert llm_worker._pick_next_job_id() is None


def test_pick_next_job_marks_in_progress(db_app: Flask) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            server = _make_server(sess)
            job = _make_job(sess, server_id=server.id, payload={"finding_ids": []})
            sess.commit()
            job_id = job.id

            picked = llm_worker._pick_next_job_id()
            assert picked == job_id

            sess.expire_all()
            updated = sess.get(LLMJob, job_id)
            assert updated is not None
            assert updated.status == "in_progress"
            assert updated.attempts == 1
            assert updated.picked_up_by == llm_worker.WORKER_ID
            assert updated.picked_up_at is not None
    finally:
        sess.close()


def test_pick_next_job_concurrent_skip_locked(db_app: Flask) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            server = _make_server(sess)
            _make_job(sess, server_id=server.id, payload={"finding_ids": []})
            sess.commit()
    finally:
        sess.close()

    results: list[int | None] = []
    barrier = threading.Barrier(2)

    def _worker() -> None:
        barrier.wait()
        with db_app.app_context():
            results.append(llm_worker._pick_next_job_id())

    t1 = threading.Thread(target=_worker)
    t2 = threading.Thread(target=_worker)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    non_none = [r for r in results if r is not None]
    assert len(non_none) == 1, f"expected exactly one pick, got {results!r}"


def test_pick_next_job_respects_depends_on(db_app: Flask) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            server = _make_server(sess)
            parent = _make_job(
                sess,
                server_id=server.id,
                payload={"finding_ids": []},
                status="queued",
            )
            sess.commit()
            _make_job(
                sess,
                job_type="risk_evaluation",
                server_id=server.id,
                payload={"group_id": 1, "server_id": server.id},
                depends_on=parent.id,
            )
            sess.commit()

            # Parent ist `queued`, nicht `done` → der Pass-2-Child darf
            # NICHT gepickt werden. Der `queued` Pass-1 Parent darf gepickt
            # werden (er ist der erste in Created-Order).
            picked1 = llm_worker._pick_next_job_id()
            assert picked1 == parent.id
            # Naechster Pickup: depends_on des Pass-2 verlinkt auf den jetzt
            # `in_progress`-Parent → noch immer kein Pickup.
            picked2 = llm_worker._pick_next_job_id()
            assert picked2 is None
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Stale-Reaper
# ---------------------------------------------------------------------------


def test_stale_reaper_requeues_with_backoff(db_app: Flask) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            server = _make_server(sess)
            stale_picked = datetime.now(UTC) - timedelta(minutes=llm_worker.STALE_TIMEOUT_MIN + 1)
            job = _make_job(
                sess,
                server_id=server.id,
                payload={"finding_ids": []},
                status="in_progress",
                attempts=1,
                picked_up_at=stale_picked,
                picked_up_by="ghost",
            )
            sess.commit()
            job_id = job.id

            llm_worker._run_stale_reaper()

            sess.expire_all()
            updated = sess.get(LLMJob, job_id)
            assert updated is not None
            assert updated.status == "queued"
            assert updated.picked_up_at is None
            assert updated.picked_up_by is None
            # Backoff: next_attempt_at sollte in der Zukunft sein.
            now = datetime.now(UTC)
            assert updated.next_attempt_at > now
    finally:
        sess.close()


def test_stale_reaper_fails_after_max_attempts(db_app: Flask) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            server = _make_server(sess)
            stale_picked = datetime.now(UTC) - timedelta(minutes=llm_worker.STALE_TIMEOUT_MIN + 1)
            job = _make_job(
                sess,
                server_id=server.id,
                payload={"finding_ids": []},
                status="in_progress",
                attempts=llm_worker.MAX_ATTEMPTS,
                picked_up_at=stale_picked,
                picked_up_by="ghost",
            )
            sess.commit()
            job_id = job.id

            llm_worker._run_stale_reaper()

            sess.expire_all()
            updated = sess.get(LLMJob, job_id)
            assert updated is not None
            assert updated.status == "failed"
            assert updated.error == "max attempts after stale"
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Mode-Branches im _tick
# ---------------------------------------------------------------------------


def test_tick_mode_off_skips_pickup(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "off"
            sess.commit()
            server = _make_server(sess)
            job = _make_job(sess, server_id=server.id, payload={"finding_ids": []})
            sess.commit()
            job_id = job.id

            # Sleep monkeypatchen damit der Test schnell ist.
            sleeps: list[float] = []
            monkeypatch.setattr(time_mod, "sleep", lambda s: sleeps.append(s))
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: sleeps.append(s))

            llm_worker._tick()

            sess.expire_all()
            updated = sess.get(LLMJob, job_id)
            assert updated is not None
            assert updated.status == "queued"
            assert sleeps  # tick hat geschlafen
    finally:
        sess.close()


def test_tick_observation_marks_would_call(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "observation"
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            server = _make_server(sess)
            job = _make_job(
                sess,
                server_id=server.id,
                payload={"finding_ids": [1, 2, 3]},
            )
            sess.commit()
            job_id = job.id

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            llm_worker._tick()

            sess.expire_all()
            updated = sess.get(LLMJob, job_id)
            assert updated is not None
            assert updated.status == "done"
            assert updated.result is not None
            assert updated.result.get("would_call") is True
            assert updated.result.get("estimated_tokens") == 150  # 50 * 3
            # Budget wurde verbucht.
            row = ensure_settings_row(sess)
            assert row.llm_token_budget_used_today == 150
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Mode=live mit Mock-Reviewer
# ---------------------------------------------------------------------------


class _FakeReviewer:
    """Mock-Reviewer der Pass1/Pass2 ohne LLM-Call beantwortet."""

    def __init__(self, *, pass1: Pass1Result, pass2: Pass2Result) -> None:
        self._pass1 = pass1
        self._pass2 = pass2

    async def pass1_detect_groups(self, findings: Any) -> Pass1Result:
        await asyncio.sleep(0)
        return self._pass1

    async def pass2_evaluate_groups(self, server: Any, groups: Any) -> Pass2Result:
        await asyncio.sleep(0)
        return self._pass2


def test_live_pass1_persists_group_and_assigns_findings(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            server = _make_server(sess)
            f1 = _make_finding(sess, 1001, server.id, package_name="openssl")
            f2 = _make_finding(sess, 1002, server.id, package_name="openssl")
            sess.commit()

            pass1 = Pass1Result(
                groups=[
                    Pass1Group(
                        label="openssl",
                        explanation="OS pkg",
                        path_prefixes=[],
                        pkg_name_exact=["openssl"],
                        pkg_name_glob=[],
                        pkg_purl_pattern=[],
                        finding_ids=[f1.id, f2.id],
                    )
                ],
                ungrouped_finding_ids=[],
            )
            pass2 = Pass2Result(evaluations=[])

            def _factory(_session: Any) -> tuple[Any, str]:
                return _FakeReviewer(pass1=pass1, pass2=pass2), "mock-model"

            llm_worker.set_reviewer_factory_for_tests(_factory)

            job = _make_job(
                sess,
                server_id=server.id,
                payload={"finding_ids": [f1.id, f2.id]},
            )
            sess.commit()
            job_id = job.id

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            llm_worker._tick()

            sess.expire_all()
            updated = sess.get(LLMJob, job_id)
            assert updated is not None
            assert updated.status == "done", f"job status={updated.status} error={updated.error}"

            grp = (
                sess.execute(select(ApplicationGroup).where(ApplicationGroup.label == "openssl"))
                .scalars()
                .first()
            )
            assert grp is not None
            assert "openssl" in (grp.pkg_name_exact or [])

            f1 = sess.get(Finding, 1001)
            f2 = sess.get(Finding, 1002)
            assert f1 is not None and f2 is not None
            assert f1.application_group_id == grp.id
            assert f2.application_group_id == grp.id
    finally:
        sess.close()


def test_live_pass2_writes_cache_and_group_band(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            server = _make_server(sess)
            grp = ApplicationGroup(
                label="openssl",
                explanation="os pkg",
                path_prefixes=[],
                pkg_name_exact=["openssl"],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                source="llm",
            )
            sess.add(grp)
            sess.flush()
            f1 = _make_finding(sess, 2001, server.id, package_name="openssl")
            f1.application_group_id = grp.id
            sess.commit()

            pass1 = Pass1Result(groups=[], ungrouped_finding_ids=[])
            pass2 = Pass2Result(
                evaluations=[
                    Pass2Evaluation(
                        group_label="openssl",
                        risk_band="act",
                        reason="sshd active, patch available",
                        worst_finding_id=f1.id,
                    )
                ]
            )

            def _factory(_session: Any) -> tuple[Any, str]:
                return _FakeReviewer(pass1=pass1, pass2=pass2), "mock-model"

            llm_worker.set_reviewer_factory_for_tests(_factory)

            job = _make_job(
                sess,
                job_type="risk_evaluation",
                server_id=server.id,
                payload={"group_id": grp.id, "server_id": server.id},
            )
            sess.commit()
            job_id = job.id

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            llm_worker._tick()

            sess.expire_all()
            updated_job = sess.get(LLMJob, job_id)
            assert updated_job is not None
            assert updated_job.status == "done", (
                f"job status={updated_job.status} error={updated_job.error}"
            )

            grp = sess.get(ApplicationGroup, grp.id)
            assert grp is not None
            assert grp.risk_band == "act"
            assert grp.risk_band_source == "llm"
            assert grp.risk_band_reason == "sshd active, patch available"

            cache_rows = list(sess.execute(select(LLMRiskCache)).scalars().all())
            assert len(cache_rows) == 1
            assert cache_rows[0].risk_band == "act"
    finally:
        sess.close()


def test_live_pass2_cache_hit_skips_llm_call(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wenn ein passender Cache-Eintrag existiert: kein LLM-Call, Group wird
    aus dem Cache befuellt."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            server = _make_server(sess)
            grp = ApplicationGroup(
                label="openssl",
                explanation="os pkg",
                path_prefixes=[],
                pkg_name_exact=["openssl"],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                source="llm",
            )
            sess.add(grp)
            sess.flush()
            f1 = _make_finding(sess, 3001, server.id, package_name="openssl")
            f1.application_group_id = grp.id
            sess.commit()

            # Cache-Key vor-berechnen damit wir den Hit garantiert haben.
            from app.services.llm_fingerprints import (
                cve_data_fingerprint,
                group_findings_fingerprint,
                make_cache_key,
                server_context_fingerprint,
            )

            findings_list = list(
                sess.execute(select(Finding).where(Finding.id == f1.id)).scalars().all()
            )
            gf_fp = group_findings_fingerprint(findings_list)
            cve_fp = cve_data_fingerprint(findings_list)
            sv_fp = server_context_fingerprint(server, session=sess)
            cache_key = make_cache_key(grp.id, gf_fp, cve_fp, sv_fp)

            cache = LLMRiskCache(
                cache_key=cache_key,
                group_id=grp.id,
                group_findings_fp=gf_fp,
                cve_data_fp=cve_fp,
                server_context_fp=sv_fp,
                risk_band="mitigate",
                worst_finding_id=f1.id,
                reason="cached reason",
                llm_model="mock-model",
            )
            sess.add(cache)
            sess.commit()

            # Reviewer-Factory die explodieren wuerde — ein Hit darf nicht
            # in den LLM-Pfad laufen.
            def _factory_explodes(_session: Any) -> Any:
                raise AssertionError("reviewer must not be built on cache hit")

            llm_worker.set_reviewer_factory_for_tests(_factory_explodes)

            job = _make_job(
                sess,
                job_type="risk_evaluation",
                server_id=server.id,
                payload={"group_id": grp.id, "server_id": server.id},
            )
            sess.commit()
            job_id = job.id

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            llm_worker._tick()

            sess.expire_all()
            updated_job = sess.get(LLMJob, job_id)
            assert updated_job is not None
            assert updated_job.status == "done"
            assert (updated_job.result or {}).get("cache_hit") is True
            grp = sess.get(ApplicationGroup, grp.id)
            assert grp is not None
            assert grp.risk_band == "mitigate"
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------


def test_main_returns_when_shutdown_flag_set(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wenn das Shutdown-Flag VOR dem ersten Tick gesetzt ist, kehrt main()
    sofort zurueck."""
    monkeypatch.setattr(time_mod, "sleep", lambda s: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)
    llm_worker.request_shutdown_for_tests()
    # signal.signal() funktioniert nur im Main-Thread des Main-Interpreters —
    # pytest erfuellt das. Defensiv testen: wir setzen die Handler vorher.
    llm_worker.main()
    # Kein Hang → Test grün.


def test_budget_exhausted_pauses_pickup(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Wenn das Tagesbudget verbraucht ist, pickt der Tick keinen Job."""
    monkeypatch.setenv("SECSCAN_LLM_TOKEN_BUDGET_DAILY", "1000")
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "observation"
            row.llm_token_budget_used_today = 1000  # exact-am-Limit
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            server = _make_server(sess)
            job = _make_job(sess, server_id=server.id, payload={"finding_ids": [1]})
            sess.commit()
            job_id = job.id

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            llm_worker._tick()

            sess.expire_all()
            updated = sess.get(LLMJob, job_id)
            assert updated is not None
            assert updated.status == "queued"
            # Audit-Event sollte einmal geschrieben sein.
            audit_count = sess.execute(
                text("SELECT count(*) FROM audit_events WHERE action = 'llm.budget_exhausted'")
            ).scalar_one()
            assert audit_count == 1
    finally:
        sess.close()
