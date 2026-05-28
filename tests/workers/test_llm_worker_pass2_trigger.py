"""Pure-Unit-Tests fuer den Pass-2-Auto-Trigger im Worker (TICKET-007 Etappe 3).

Mock-Session (kein DB-Roundtrip). ``get_session`` und
``enqueue_pass2_for_server`` werden im ``llm_worker``-Namespace gepatcht.
"""

from __future__ import annotations

import inspect
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.workers import llm_worker


@contextmanager
def _cm(session: Any) -> Iterator[Any]:
    yield session


def _patch_session(monkeypatch: pytest.MonkeyPatch, session: Any) -> None:
    monkeypatch.setattr(llm_worker, "get_session", lambda: _cm(session))


def _patch_enqueue(monkeypatch: pytest.MonkeyPatch, **kw: Any) -> MagicMock:
    mock = MagicMock(**kw)
    monkeypatch.setattr(llm_worker, "enqueue_pass2_for_server", mock)
    return mock


# --- _maybe_trigger_pass2_after_pass1 -------------------------------------


def test_maybe_trigger_skips_when_sibling_queued(monkeypatch: pytest.MonkeyPatch) -> None:
    sess = MagicMock()
    sess.execute.return_value.scalar.return_value = 2  # noch Pass-1 offen
    _patch_session(monkeypatch, sess)
    mock_enq = _patch_enqueue(monkeypatch)
    llm_worker._maybe_trigger_pass2_after_pass1(server_id=1, trigger="pass1_completion")
    mock_enq.assert_not_called()


def test_maybe_trigger_skips_when_sibling_in_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    # Der Sibling-Check zaehlt queued UND in_progress in einem count() -> 1.
    sess = MagicMock()
    sess.execute.return_value.scalar.return_value = 1
    _patch_session(monkeypatch, sess)
    mock_enq = _patch_enqueue(monkeypatch)
    llm_worker._maybe_trigger_pass2_after_pass1(server_id=1, trigger="pass1_completion")
    mock_enq.assert_not_called()


def test_maybe_trigger_enqueues_when_no_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    sess = MagicMock()
    sess.execute.return_value.scalar.return_value = 0
    _patch_session(monkeypatch, sess)
    mock_enq = _patch_enqueue(monkeypatch, return_value=2)
    llm_worker._maybe_trigger_pass2_after_pass1(server_id=7, trigger="pass1_completion")
    mock_enq.assert_called_once_with(sess, 7, trigger="pass1_completion")
    sess.commit.assert_called_once()


def test_maybe_trigger_noop_when_server_id_none(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_enq = _patch_enqueue(monkeypatch)
    # get_session darf gar nicht erst aufgerufen werden.
    monkeypatch.setattr(
        llm_worker,
        "get_session",
        lambda: (_ for _ in ()).throw(AssertionError("get_session should not be called")),
    )
    llm_worker._maybe_trigger_pass2_after_pass1(server_id=None, trigger="pass1_completion")
    mock_enq.assert_not_called()


def test_maybe_trigger_swallows_helper_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    sess = MagicMock()
    sess.execute.return_value.scalar.return_value = 0
    _patch_session(monkeypatch, sess)
    _patch_enqueue(monkeypatch, side_effect=RuntimeError("boom"))
    # Darf NICHT re-raisen.
    llm_worker._maybe_trigger_pass2_after_pass1(server_id=1, trigger="pass1_completion")


# --- _do_pass1 Hook-Wiring -------------------------------------------------


def test_do_pass1_wires_pass2_hook() -> None:
    """_do_pass1 ruft den Pass-2-Trigger am Ende (server_id=job_server_id,
    trigger=pass1_completion). Async-Volltrieb ist nicht pure-unit-bar — daher
    Wiring-Assertion auf den Quelltext."""
    src = inspect.getsource(llm_worker._do_pass1)
    assert "_maybe_trigger_pass2_after_pass1(" in src
    assert 'trigger="pass1_completion"' in src
    assert "server_id=job_server_id" in src


# --- _requeue_or_fail Hook -------------------------------------------------


def _fake_job(*, attempts: int, job_type: str, server_id: int = 5) -> MagicMock:
    job = MagicMock()
    job.id = 99
    job.attempts = attempts
    job.job_type = job_type
    job.server_id = server_id
    return job


def _drive_requeue(monkeypatch: pytest.MonkeyPatch, job: MagicMock) -> MagicMock:
    sess = MagicMock()
    sess.get.return_value = job
    _patch_session(monkeypatch, sess)
    monkeypatch.setattr(llm_worker, "_audit", lambda *a, **kw: None)
    spy = MagicMock()
    monkeypatch.setattr(llm_worker, "_maybe_trigger_pass2_after_pass1", spy)
    return spy


def test_requeue_final_failed_pass1_triggers(monkeypatch: pytest.MonkeyPatch) -> None:
    job = _fake_job(attempts=llm_worker.MAX_ATTEMPTS, job_type="group_detection", server_id=5)
    spy = _drive_requeue(monkeypatch, job)
    llm_worker._requeue_or_fail(99, "some error")
    spy.assert_called_once_with(server_id=5, trigger="pass1_final_failed")


def test_requeue_final_failed_pass2_does_not_trigger(monkeypatch: pytest.MonkeyPatch) -> None:
    job = _fake_job(attempts=llm_worker.MAX_ATTEMPTS, job_type="risk_evaluation")
    spy = _drive_requeue(monkeypatch, job)
    llm_worker._requeue_or_fail(99, "some error")
    spy.assert_not_called()


def test_requeue_non_final_does_not_trigger(monkeypatch: pytest.MonkeyPatch) -> None:
    job = _fake_job(attempts=1, job_type="group_detection")
    spy = _drive_requeue(monkeypatch, job)
    llm_worker._requeue_or_fail(99, "transient error")
    spy.assert_not_called()


# --- _run_pass2_backstop_sweep_safe ----------------------------------------


def test_backstop_sweep_enqueues_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    sess = MagicMock()
    sess.execute.return_value.fetchall.return_value = [(3,), (4,)]
    _patch_session(monkeypatch, sess)
    mock_enq = _patch_enqueue(monkeypatch, return_value=1)
    llm_worker._run_pass2_backstop_sweep_safe()
    assert mock_enq.call_count == 2
    assert {c.args[1] for c in mock_enq.call_args_list} == {3, 4}
    assert all(c.kwargs["trigger"] == "backstop_sweep" for c in mock_enq.call_args_list)


def test_backstop_sweep_no_candidates_no_enqueue(monkeypatch: pytest.MonkeyPatch) -> None:
    """Server mit pending Pass-1 bzw. ohne 24h-Aktivitaet werden bereits in der
    SQL (EXCEPT / 24h-Fenster) herausgefiltert -> leere Kandidatenliste."""
    sess = MagicMock()
    sess.execute.return_value.fetchall.return_value = []
    _patch_session(monkeypatch, sess)
    mock_enq = _patch_enqueue(monkeypatch)
    llm_worker._run_pass2_backstop_sweep_safe()
    mock_enq.assert_not_called()


def test_backstop_sweep_sql_has_24h_window_and_except(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    sess = MagicMock()

    def _exec(sql: Any, *a: Any, **kw: Any) -> Any:
        captured["sql"] = str(sql)
        r = MagicMock()
        r.fetchall.return_value = []
        return r

    sess.execute.side_effect = _exec
    _patch_session(monkeypatch, sess)
    _patch_enqueue(monkeypatch)
    llm_worker._run_pass2_backstop_sweep_safe()
    assert "interval '24 hours'" in captured["sql"]
    assert "EXCEPT" in captured["sql"]


def test_backstop_sweep_swallows_db_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    sess = MagicMock()
    sess.execute.side_effect = RuntimeError("db down")
    _patch_session(monkeypatch, sess)
    _patch_enqueue(monkeypatch)
    # Darf NICHT re-raisen.
    llm_worker._run_pass2_backstop_sweep_safe()


# --- Sub-Tick-Cadence ------------------------------------------------------


def test_subtick_runs_sweep_on_cadence(monkeypatch: pytest.MonkeyPatch) -> None:
    """_run_subticks triggert den Sweep einmal, dann erst wieder nach 300s."""
    llm_worker.reset_shutdown_for_tests()  # setzt _last_pass2_backstop_sweep_at = 0.0
    # Alle anderen Sub-Ticks neutralisieren.
    for name in (
        "_run_stale_reaper",
        "_run_debug_log_eviction",
        "_run_feed_enrichment_check",
        "_run_scan_ingest_retention_sweep_safe",
        "_process_scan_ingest_job_safe",
    ):
        monkeypatch.setattr(llm_worker, name, lambda *a, **kw: None)
    sess = MagicMock()
    monkeypatch.setattr(llm_worker, "_pick_next_scan_ingest_job_id", lambda s: None)
    _patch_session(monkeypatch, sess)
    sweep_spy = MagicMock()
    monkeypatch.setattr(llm_worker, "_run_pass2_backstop_sweep_safe", sweep_spy)

    llm_worker._run_subticks()
    assert sweep_spy.call_count == 1
    # Sofortiger zweiter Lauf: noch innerhalb des 300s-Fensters -> kein Sweep.
    llm_worker._run_subticks()
    assert sweep_spy.call_count == 1
