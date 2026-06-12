"""DB-Integration-Tests fuer ``app.workers.llm_worker``.

Diese Tests wurden aus ``tests/workers/test_llm_worker.py`` ausgelagert
(TICKET-004, Slice 7). Die DB-freien Idle-/Shutdown-/aclose-Tests bleiben
in der Worker-Test-Datei. Hier verbleiben alle Tests, die echte
Postgres-Semantik pruefen:

* ``_pick_next_job_id`` mit leerer Queue / Pickup-Marker / SKIP LOCKED.
* Dependency-Check: Pass-2-Job mit ``depends_on`` auf nicht-``done`` Pass-1.
* Stale-Reaper: Requeue mit Backoff bzw. Fail nach ``MAX_ATTEMPTS``.
* Mode-Branches im ``_tick``: off, observation, live.
* Mode=live: Pass-1-Persistierung von Groups + Findings-Zuordnung.
* Mode=live: Pass-2-Persistierung Cache + Group-Risk-Band + Vererbung.
* Pass-2-Cache-Hit ohne LLM-Call.
* Shutdown/Budget-Pause.
* Validation-Error-Meta im Debug-Log.
* Heartbeat-Thread (Independent-DB-Write + Stop-Event).
* Logging-Smoke fuer Phasen-Marker.
* Mode-/Budget-Throttle-Cache.
* Tick-Idle-Backoff via DB-Settings.
* Pass-2 wartet auf Pass-1-Siblings (queued/in_progress/failed).
* Audit fuer Pass-2 mit failed Pass-1-Siblings.

Auto-Markierung als ``db_integration`` (und damit ``acceptance``) erfolgt
ueber ``tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES``.
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
# Helpers
# ---------------------------------------------------------------------------


def _drive_dispatch_iteration() -> None:
    """Block U Phase C (ADR-0029) Migration-Helper: ersetzt ``_drive_dispatch_iteration()``.

    Pickt synchron einen Job aus der Queue und verarbeitet ihn via
    ``asyncio.run(_process_one_async(...))``. Sub-Ticks (Stale-Reaper,
    Eviction, Feed-Pull, Ingest, Retention) bleiben aussen vor — die Tests
    ueber Sub-Ticks rufen die jeweiligen Helper direkt auf
    (z.B. ``llm_worker._run_stale_reaper()``).
    """
    llm_worker.invalidate_throttle_caches_for_tests()
    mode = llm_worker._get_mode_throttled()
    if mode == "off" or not llm_worker._budget_ok_throttled():
        # Idle-Pfad: Backoff-State updaten damit die alten Idle-Tests
        # (siehe ``test_tick_idle_uses_backoff_sleep``) weiter funktionieren.
        sleep_s = llm_worker._compute_idle_sleep()
        time_mod.sleep(sleep_s)
        return
    job_id = llm_worker._pick_next_job_id()
    if job_id is None:
        sleep_s = llm_worker._compute_idle_sleep()
        time_mod.sleep(sleep_s)
        return
    llm_worker._reset_idle_backoff()
    asyncio.run(llm_worker._process_one_async(job_id, mode))


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

            _drive_dispatch_iteration()

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

            _drive_dispatch_iteration()

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

    async def pass1_detect_groups(self, findings: Any) -> tuple[Pass1Result, dict[str, Any]]:
        await asyncio.sleep(0)
        return self._pass1, {"model": "mock", "duration_ms": 0}

    async def pass2_evaluate_groups(
        self, server: Any, groups: Any, *, fix_lane: str | None = None
    ) -> tuple[Pass2Result, dict[str, Any]]:
        await asyncio.sleep(0)
        return self._pass2, {"model": "mock", "duration_ms": 0}


def test_live_pass1_persists_group_and_assigns_findings(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            row.llm_token_budget_used_today = 0
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            llm_worker.invalidate_throttle_caches_for_tests()
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

            _drive_dispatch_iteration()

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
            row.llm_token_budget_used_today = 0
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            llm_worker.invalidate_throttle_caches_for_tests()
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
            # ADR-0053/TICKET-013: fixed_version gesetzt -> patch-Lane (act ist
            # patch-only, der Job traegt fix_lane=patch).
            f1 = _make_finding(sess, 2001, server.id, package_name="openssl", fixed_version="1.1")
            f1.application_group_id = grp.id
            sess.commit()

            pass1 = Pass1Result(groups=[], ungrouped_finding_ids=[])
            pass2 = Pass2Result(
                evaluations=[
                    Pass2Evaluation(
                        group_label="openssl",
                        risk_band="act",
                        # ADR-0053: kein action_type mehr im LLM-Output.
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
                payload={"group_id": grp.id, "server_id": server.id, "fix_lane": "patch"},
            )
            sess.commit()
            job_id = job.id

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            _drive_dispatch_iteration()

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

            inherited_finding = sess.get(Finding, f1.id)
            assert inherited_finding is not None
            # TICKET-012: Finding erbt Band + Source, aber keinen reason mehr
            # (AI-Assessment ist Group-Level).
            assert inherited_finding.risk_band == "act"
            assert inherited_finding.risk_band_source == "llm"
            assert (updated_job.result or {}).get("findings_inherited") == 1

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
            row.llm_token_budget_used_today = 0
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            llm_worker.invalidate_throttle_caches_for_tests()
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
            # ADR-0053/TICKET-013: f1 hat kein fixed_version -> mitigate-Lane;
            # Cache-Key traegt die Lane als Salt, der Job die fix_lane.
            cache_key = make_cache_key(grp.id, gf_fp, cve_fp, sv_fp, fix_lane="mitigate")

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
                payload={"group_id": grp.id, "server_id": server.id, "fix_lane": "mitigate"},
            )
            sess.commit()
            job_id = job.id

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            asyncio.run(llm_worker._do_pass2(job_id))

            sess.expire_all()
            updated_job = sess.get(LLMJob, job_id)
            assert updated_job is not None
            assert updated_job.status == "done"
            assert (updated_job.result or {}).get("cache_hit") is True
            grp = sess.get(ApplicationGroup, grp.id)
            assert grp is not None
            assert grp.risk_band == "mitigate"
            inherited_finding = sess.get(Finding, f1.id)
            assert inherited_finding is not None
            # TICKET-012: Finding erbt Band + Source, keinen reason (Group-Level).
            assert inherited_finding.risk_band == "mitigate"
            assert inherited_finding.risk_band_source == "llm"
            assert (updated_job.result or {}).get("findings_inherited") == 1
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Budget-Pause
# ---------------------------------------------------------------------------


def test_budget_exhausted_pauses_pickup(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Wenn das Tagesbudget verbraucht ist, pickt der Tick keinen Job."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "observation"
            row.llm_daily_token_cap = 1000
            row.llm_token_budget_used_today = 1000  # exact-am-Limit
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            server = _make_server(sess)
            job = _make_job(sess, server_id=server.id, payload={"finding_ids": [1]})
            sess.commit()
            job_id = job.id

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            _drive_dispatch_iteration()

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


# ---------------------------------------------------------------------------
# v0.9.5 — Meta-Dict im Debug-Log bei Validation-Error
# ---------------------------------------------------------------------------


class _BadReviewer:
    """Reviewer der eine LLMInvalidResponseError MIT meta-Attribut wirft.

    Simuliert den Pass-1-Pfad in dem das LLM eine Response liefert, der
    Backend-Validator sie aber ablehnt (z.B. invalides Label).
    """

    def __init__(self, meta: dict[str, Any]) -> None:
        self._meta = meta

    async def pass1_detect_groups(self, findings: Any) -> tuple[Pass1Result, dict[str, Any]]:
        await asyncio.sleep(0)
        from app.services.llm_risk_reviewer import LLMInvalidResponseError

        raise LLMInvalidResponseError("simulated label regex violation", meta=self._meta)


def test_worker_records_meta_on_validation_error_in_debug_log(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v0.9.5: bei LLMInvalidResponseError muss der Debug-Log raw_content/
    extracted_json aus exc.meta enthalten (vorher: response_body=NULL,
    Operator blind)."""
    from app.models import LLMDebugLog

    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            server = _make_server(sess)
            f1 = _make_finding(sess, 9001, server.id, package_name="openssl")
            sess.commit()

            bad_meta: dict[str, Any] = {
                "raw_content": '{"groups": [{"label": "bad label", ...}]}',
                "extracted_json": '{"groups": [{"label": "bad label"}]}',
                "reasoning_field": None,
                "model": "mock-model",
                "duration_ms": 12345,
                "usage": {"prompt_tokens": 100, "completion_tokens": 50},
                "system_prompt": "SYSTEM",
                "user_prompt": "USER",
                "max_tokens": 4096,
            }

            def _factory(_session: Any) -> tuple[Any, str]:
                return _BadReviewer(meta=bad_meta), "mock-model"

            llm_worker.set_reviewer_factory_for_tests(_factory)

            job = _make_job(
                sess,
                server_id=server.id,
                payload={"finding_ids": [f1.id]},
            )
            sess.commit()
            job_id = job.id

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            _drive_dispatch_iteration()

            sess.expire_all()
            # Job sollte requeued/failed sein (Validator wirft).
            updated = sess.get(LLMJob, job_id)
            assert updated is not None
            assert updated.status in ("queued", "failed")

            # Debug-Log-Row muss existieren und die echte LLM-Response tragen.
            debug_row = (
                sess.execute(select(LLMDebugLog).where(LLMDebugLog.job_id == job_id))
                .scalars()
                .first()
            )
            assert debug_row is not None, "Debug-Log wurde nicht geschrieben"
            assert debug_row.status == "validation_error"
            assert debug_row.response_body is not None
            assert debug_row.response_body.get("raw_content") == bad_meta["raw_content"]
            assert debug_row.response_body.get("extracted_json") == bad_meta["extracted_json"]
            # request_body sollte die Prompts aus meta enthalten.
            assert debug_row.request_body is not None
            assert debug_row.request_body.get("system_prompt") == "SYSTEM"
            assert debug_row.request_body.get("user_prompt") == "USER"
            assert debug_row.duration_ms == 12345
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# v0.9.5 — Heartbeat-Thread (entkoppelt vom Tick)
# ---------------------------------------------------------------------------


def test_heartbeat_thread_writes_while_tick_blocks(db_app: Flask) -> None:
    """v0.9.5: der Daemon-Thread schreibt den Heartbeat unabhaengig davon
    ob der Tick im LLM-Call blockiert."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            # Heartbeat auf "alt" setzen damit wir die Aktualisierung sehen.
            row.llm_worker_heartbeat_at = datetime(2020, 1, 1, tzinfo=UTC)
            sess.commit()
            old_hb = row.llm_worker_heartbeat_at

            # Heartbeat-Interval kurz machen wir nicht — der Thread schreibt
            # initial sofort beim Start. Wir starten, warten kurz, stoppen.
            llm_worker._start_heartbeat_thread()
            try:
                # Daemon-Thread schreibt initial sofort _write_heartbeat().
                # Wir geben ihm 1s um den ersten Write durchzubringen.
                time_mod.sleep(1.0)
                sess.expire_all()
                row2 = ensure_settings_row(sess)
                assert row2.llm_worker_heartbeat_at is not None
                assert row2.llm_worker_heartbeat_at > old_hb
            finally:
                llm_worker._stop_heartbeat_thread(timeout=2.0)
    finally:
        sess.close()


def test_heartbeat_thread_stops_on_event(db_app: Flask) -> None:
    """v0.9.5: Stop-Event triggert sauberen Thread-Exit innerhalb der Wait-Latency."""
    with db_app.app_context():
        t = llm_worker._start_heartbeat_thread()
        assert t.is_alive()
        llm_worker._stop_heartbeat_thread(timeout=2.0)
        # join(timeout) returned → Thread sollte tot sein.
        assert not t.is_alive()


# ---------------------------------------------------------------------------
# Block U Phase F (ADR-0029) — Logging-Refactor: die alten Per-Job-Phasen-
# Marker (pass1_started / llm_call_started / llm_call_completed /
# pass1_persist_done / job_picked / job_done / pass2_started / pass2_persist_
# done / pass1_skipped / pass2_skipped / pass2_cache_lookup /
# pass2_cache_hit_applied) wurden entfernt. Forensik laeuft jetzt
# ausschliesslich ueber ``llm_debug_log`` (UI ``/settings/llm-reviewer/
# debug-log``) plus aggregierte ``llm_worker.status``-Snapshots alle 30s.
#
# Der ehemalige ``test_pass1_logs_phase_markers``-Test wurde in einen
# Negativ-Smoke umgeschrieben: die entfernten Marker DUERFEN NICHT mehr im
# Live-Pass-1-Lauf auftauchen. Der Pure-Unit-Backstop (Source-Check) lebt
# in ``tests/workers/test_llm_worker_logging.py``.
# ---------------------------------------------------------------------------


def test_pass1_does_not_emit_removed_phase_markers(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Block U Phase F Negativ-Smoke: die entfernten Phasen-Marker
    tauchen im Live-Pass-1-Lauf nicht mehr auf.

    Wenn dieser Test gruen ist, war der Logging-Refactor erfolgreich.
    Wenn jemand einen der Marker versehentlich wieder einbaut, faellt
    dieser Test durch und der Source-Check in
    ``tests/workers/test_llm_worker_logging.py`` ebenfalls.
    """
    import logging as _logging

    captured: list[str] = []

    class _Handler(_logging.Handler):
        def emit(self, record: _logging.LogRecord) -> None:
            captured.append(record.getMessage())

    worker_logger = llm_worker.log
    prev_level = worker_logger.level
    prev_disabled = worker_logger.disabled
    worker_logger.setLevel(_logging.DEBUG)
    worker_logger.disabled = False
    handler = _Handler()
    handler.setLevel(_logging.DEBUG)
    worker_logger.addHandler(handler)
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            server = _make_server(sess)
            f1 = _make_finding(sess, 7001, server.id, package_name="openssl")
            sess.commit()

            pass1 = Pass1Result(
                groups=[
                    Pass1Group(
                        label="openssl",
                        explanation=None,
                        path_prefixes=[],
                        pkg_name_exact=["openssl"],
                        pkg_name_glob=[],
                        pkg_purl_pattern=[],
                        finding_ids=[f1.id],
                    )
                ],
                ungrouped_finding_ids=[],
            )

            def _factory(_session: Any) -> tuple[Any, str]:
                return (
                    _FakeReviewer(pass1=pass1, pass2=Pass2Result(evaluations=[])),
                    "mock-model",
                )

            llm_worker.set_reviewer_factory_for_tests(_factory)

            _make_job(sess, server_id=server.id, payload={"finding_ids": [f1.id]})
            sess.commit()

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            _drive_dispatch_iteration()

            messages = " | ".join(captured)
            for removed in (
                "llm_worker.pass1_started",
                "llm_worker.llm_call_started",
                "llm_worker.llm_call_completed",
                "llm_worker.pass1_persist_done",
                "llm_worker.job_picked",
                "llm_worker.job_done",
                "llm_worker.pass1_skipped",
            ):
                assert removed not in messages, (
                    f"Block U Phase F: Marker {removed!r} wurde wieder eingebaut. got: {messages!r}"
                )
    finally:
        worker_logger.removeHandler(handler)
        worker_logger.setLevel(prev_level)
        worker_logger.disabled = prev_disabled
        sess.close()


def test_pass1_logs_failure_marker_on_validation_error(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v0.9.5: bei LLMInvalidResponseError taucht ``llm_call_failed`` im Log auf."""
    import logging as _logging

    captured: list[str] = []

    class _Handler(_logging.Handler):
        def emit(self, record: _logging.LogRecord) -> None:
            captured.append(record.getMessage())

    worker_logger = llm_worker.log
    prev_level = worker_logger.level
    prev_disabled = worker_logger.disabled
    worker_logger.setLevel(_logging.DEBUG)
    worker_logger.disabled = False
    handler = _Handler()
    handler.setLevel(_logging.DEBUG)
    worker_logger.addHandler(handler)
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()
            server = _make_server(sess)
            f1 = _make_finding(sess, 7101, server.id, package_name="openssl")
            sess.commit()

            def _factory(_session: Any) -> tuple[Any, str]:
                return _BadReviewer(meta={"raw_content": "x"}), "mock-model"

            llm_worker.set_reviewer_factory_for_tests(_factory)

            job = _make_job(sess, server_id=server.id, payload={"finding_ids": [f1.id]})
            sess.commit()
            _ = job.id  # touch for linter

            monkeypatch.setattr(time_mod, "sleep", lambda s: None)
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

            _drive_dispatch_iteration()

            messages = " | ".join(captured)
            assert "llm_worker.llm_call_failed" in messages, f"got: {messages!r}"
    finally:
        worker_logger.removeHandler(handler)
        worker_logger.setLevel(prev_level)
        worker_logger.disabled = prev_disabled
        sess.close()


# ---------------------------------------------------------------------------
# v0.9.6: Mode-/Budget-Throttle-Cache
# ---------------------------------------------------------------------------


def test_mode_check_is_cached_30s(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Aufeinanderfolgende ``_get_mode_throttled``-Aufrufe innerhalb des
    Cache-Fensters lesen die DB nicht erneut."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            sess.commit()

            llm_worker.invalidate_throttle_caches_for_tests()

            sql_count = {"n": 0}
            real_ensure = llm_worker.ensure_settings_row

            def _counting_ensure(s: Any) -> Any:
                sql_count["n"] += 1
                return real_ensure(s)

            monkeypatch.setattr(llm_worker, "ensure_settings_row", _counting_ensure)

            assert llm_worker._get_mode_throttled() == "live"
            assert llm_worker._get_mode_throttled() == "live"
            assert llm_worker._get_mode_throttled() == "live"
            assert sql_count["n"] == 1
    finally:
        sess.close()


def test_mode_check_refreshes_after_cache_expiry(db_app: Flask) -> None:
    """Nach Ablauf des Cache-Intervals wird die DB wieder gelesen."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "off"
            sess.commit()

            llm_worker.invalidate_throttle_caches_for_tests()
            assert llm_worker._get_mode_throttled() == "off"

            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            sess.commit()
            # Innerhalb der Cache-Window: noch alter Wert.
            assert llm_worker._get_mode_throttled() == "off"

            # Cache-Window kuenstlich abgelaufen.
            llm_worker._mode_cached_at = (
                llm_worker.time.monotonic() - llm_worker.MODE_CHECK_INTERVAL_SEC - 1
            )
            assert llm_worker._get_mode_throttled() == "live"
    finally:
        sess.close()


def test_budget_check_is_cached_60s(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Budget-Check liest die DB nur alle 60s, nicht pro Tick."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.llm_token_budget_used_today = 0
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()

            llm_worker.invalidate_throttle_caches_for_tests()

            sql_count = {"n": 0}
            real_check = llm_worker.llm_budget.budget_check

            def _counting_check(s: Any) -> bool:
                sql_count["n"] += 1
                return real_check(s)

            monkeypatch.setattr(llm_worker.llm_budget, "budget_check", _counting_check)

            assert llm_worker._budget_ok_throttled() is True
            assert llm_worker._budget_ok_throttled() is True
            assert llm_worker._budget_ok_throttled() is True
            assert sql_count["n"] == 1
    finally:
        sess.close()


def test_tick_idle_uses_backoff_sleep(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """v0.9.6: leere Queue → ``_tick`` schlaeft mit dem Backoff-Wert,
    der ueber aufeinanderfolgende Idle-Ticks waechst."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = "live"
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=2)
            sess.commit()

            sleeps: list[float] = []
            monkeypatch.setattr(llm_worker.time, "sleep", lambda s: sleeps.append(s))
            monkeypatch.setattr(llm_worker, "_poll_interval", lambda: 2.0)

            llm_worker.invalidate_throttle_caches_for_tests()
            _drive_dispatch_iteration()
            _drive_dispatch_iteration()

            assert len(sleeps) == 2
            assert sleeps[0] == 2.0
            assert sleeps[1] == 3.0
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# v0.9.x: Pass-2 wartet auf ALLE Pass-1-Siblings (queued / in_progress)
# ---------------------------------------------------------------------------


def test_pass2_waits_when_pass1_sibling_queued(db_app: Flask) -> None:
    """Pass-2 darf NICHT gepickt werden solange ein Pass-1-Sibling fuer den
    selben server_id noch ``queued`` ist — selbst wenn der ``depends_on``-
    Parent schon ``done`` ist."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            srv = _make_server(sess)
            # Pass-1 #1: done (Parent von Pass-2)
            p1_done = _make_job(
                sess,
                job_type="group_detection",
                server_id=srv.id,
                payload={"finding_ids": [1]},
                status="done",
            )
            # Pass-1 #2: noch queued (Sibling)
            _make_job(
                sess,
                job_type="group_detection",
                server_id=srv.id,
                payload={"finding_ids": [2]},
                status="queued",
            )
            # Pass-2: depends_on auf p1_done → klassische Dependency erfuellt
            _make_job(
                sess,
                job_type="risk_evaluation",
                server_id=srv.id,
                payload={"group_id": 1, "server_id": srv.id},
                status="queued",
                depends_on=p1_done.id,
            )
            sess.commit()

            # Pickup soll Pass-1 #2 (queued) zuerst nehmen, NICHT Pass-2.
            picked = llm_worker._pick_next_job_id()
            assert picked is not None
            sess.expire_all()
            picked_job = sess.get(LLMJob, picked)
            assert picked_job is not None
            assert picked_job.job_type == "group_detection"
    finally:
        sess.close()


def test_pass2_waits_when_pass1_sibling_in_progress(db_app: Flask) -> None:
    """Pass-2 darf NICHT gepickt werden waehrend ein Pass-1-Sibling in
    ``in_progress`` ist (Multi-Worker-Szenario)."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            srv = _make_server(sess)
            p1_done = _make_job(
                sess,
                job_type="group_detection",
                server_id=srv.id,
                payload={"finding_ids": [1]},
                status="done",
            )
            _make_job(
                sess,
                job_type="group_detection",
                server_id=srv.id,
                payload={"finding_ids": [2]},
                status="in_progress",
                picked_up_at=datetime.now(UTC),
                picked_up_by="other-worker:1",
            )
            _make_job(
                sess,
                job_type="risk_evaluation",
                server_id=srv.id,
                payload={"group_id": 1, "server_id": srv.id},
                status="queued",
                depends_on=p1_done.id,
            )
            sess.commit()

            # Pickup soll Pass-2 NICHT picken (Pass-1-Sibling in_progress).
            # Es gibt KEINE anderen Pass-1-Jobs queued → Pickup gibt None.
            picked = llm_worker._pick_next_job_id()
            assert picked is None
    finally:
        sess.close()


def test_pass2_picks_when_pass1_sibling_failed(db_app: Flask) -> None:
    """Pass-2 DARF starten wenn ein Pass-1-Sibling ``failed`` ist (Variante 3:
    Pass-2 laeuft mit dem was an Groups da ist, Audit-Event signalisiert
    den teilweisen Erfolg)."""
    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            srv = _make_server(sess)
            p1_done = _make_job(
                sess,
                job_type="group_detection",
                server_id=srv.id,
                payload={"finding_ids": [1]},
                status="done",
            )
            _make_job(
                sess,
                job_type="group_detection",
                server_id=srv.id,
                payload={"finding_ids": [2]},
                status="failed",
                attempts=3,
            )
            pass2 = _make_job(
                sess,
                job_type="risk_evaluation",
                server_id=srv.id,
                payload={"group_id": 1, "server_id": srv.id},
                status="queued",
                depends_on=p1_done.id,
            )
            sess.commit()

            # Pickup soll Pass-2 jetzt picken.
            picked = llm_worker._pick_next_job_id()
            assert picked == pass2.id
    finally:
        sess.close()


def test_pass2_with_failed_pass1_emits_audit(db_app: Flask) -> None:
    """Wenn Pass-2 startet und failed Pass-1-Siblings existieren, wird
    ``llm.pass2_started_with_failed_pass1`` als Audit-Event geschrieben."""
    from app.models import AuditEvent

    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            srv = _make_server(sess)
            _make_job(
                sess,
                job_type="group_detection",
                server_id=srv.id,
                payload={"finding_ids": [1]},
                status="done",
            )
            _make_job(
                sess,
                job_type="group_detection",
                server_id=srv.id,
                payload={"finding_ids": [2]},
                status="failed",
                attempts=3,
            )
            sess.commit()

            llm_worker._audit_pass2_with_failed_siblings(sess, job_id=999, server_id=srv.id)
            sess.commit()

            events = (
                sess.execute(
                    select(AuditEvent)
                    .where(AuditEvent.action == "llm.pass2_started_with_failed_pass1")
                    .order_by(AuditEvent.id.desc())
                )
                .scalars()
                .all()
            )
            assert len(events) == 1
            assert events[0].event_metadata is not None
            assert events[0].event_metadata.get("failed_pass1_count") == 1
            assert events[0].event_metadata.get("server_id") == srv.id
    finally:
        sess.close()


def test_pass2_without_failed_pass1_no_audit(db_app: Flask) -> None:
    """Wenn KEIN Pass-1-Sibling failed ist, wird KEIN Audit-Event geschrieben."""
    from app.models import AuditEvent

    sess = _open_sess(db_app)
    try:
        with db_app.app_context():
            srv = _make_server(sess)
            _make_job(
                sess,
                job_type="group_detection",
                server_id=srv.id,
                payload={"finding_ids": [1]},
                status="done",
            )
            sess.commit()

            before = (
                sess.execute(
                    select(AuditEvent).where(
                        AuditEvent.action == "llm.pass2_started_with_failed_pass1"
                    )
                )
                .scalars()
                .all()
            )
            llm_worker._audit_pass2_with_failed_siblings(sess, job_id=999, server_id=srv.id)
            sess.commit()
            after = (
                sess.execute(
                    select(AuditEvent).where(
                        AuditEvent.action == "llm.pass2_started_with_failed_pass1"
                    )
                )
                .scalars()
                .all()
            )
            assert len(after) == len(before)
    finally:
        sess.close()
