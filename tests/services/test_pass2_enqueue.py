"""Pure-Unit-Tests fuer ``app/services/pass2_enqueue.py`` (TICKET-007 Etappe 1).

Mock-Session (kein DB-Roundtrip). Die vier ``session.execute``-Aufrufe des
Helpers werden ueber ``side_effect`` in fester Reihenfolge bedient:
  1. affected_groups (``.scalars().all()``)
  2. evaluations (``.scalars().all()``)
  3. aktive Pass-2-Jobs (``.all()`` -> Liste von ``(payload,)``-Tupeln)
  4. OPEN-Findings aller Groups (``.scalars().all()``)
``group_findings_fingerprint`` ist gepatcht (deterministisch), ``log_event``
gepatcht zum Assert.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from app.services.pass2_enqueue import enqueue_pass2_for_server

_FP = "fpcurrent000000"


def _grp(gid: int) -> SimpleNamespace:
    return SimpleNamespace(id=gid)


def _eval(group_id: int, fp: str | None) -> SimpleNamespace:
    return SimpleNamespace(group_id=group_id, group_findings_fingerprint=fp)


def _finding(group_id: int) -> SimpleNamespace:
    return SimpleNamespace(application_group_id=group_id)


def _make_session(
    *,
    groups: list[Any],
    evals: list[Any] | None = None,
    active_pass2: list[int] | None = None,
    findings: list[Any] | None = None,
) -> MagicMock:
    sess = MagicMock()
    results: list[Any] = []

    r_groups = MagicMock()
    r_groups.scalars.return_value.all.return_value = groups
    results.append(r_groups)

    if groups:
        r_evals = MagicMock()
        r_evals.scalars.return_value.all.return_value = evals or []
        results.append(r_evals)

        r_active = MagicMock()
        r_active.all.return_value = [
            ({"group_id": gid, "server_id": 1},) for gid in (active_pass2 or [])
        ]
        results.append(r_active)

        r_findings = MagicMock()
        r_findings.scalars.return_value.all.return_value = findings or []
        results.append(r_findings)

    sess.execute.side_effect = results
    added: list[Any] = []
    sess.add.side_effect = added.append
    sess.added = added  # type: ignore[attr-defined]
    return sess


def _run(session: MagicMock, *, trigger: str = "scan_ingest") -> tuple[int, MagicMock]:
    with (
        patch("app.services.pass2_enqueue.group_findings_fingerprint", return_value=_FP),
        patch("app.services.pass2_enqueue.log_event") as mock_log,
    ):
        count = enqueue_pass2_for_server(session, 1, trigger=trigger)  # type: ignore[arg-type]
    return count, mock_log


# --- Basis ----------------------------------------------------------------


def test_new_group_no_eval_enqueues_one() -> None:
    sess = _make_session(groups=[_grp(10)], evals=[], active_pass2=[], findings=[_finding(10)])
    count, _ = _run(sess)
    assert count == 1
    job = sess.added[0]
    assert job.job_type == "risk_evaluation"
    assert job.payload == {"group_id": 10, "server_id": 1}
    assert getattr(job, "depends_on", None) is None


def test_idempotent_when_active_job_exists() -> None:
    """Zweiter Aufruf (Group hat bereits aktiven Pass-2-Job) -> 0."""
    sess = _make_session(groups=[_grp(10)], active_pass2=[10], findings=[_finding(10)])
    count, _ = _run(sess)
    assert count == 0
    assert sess.added == []


def test_eval_same_fingerprint_skips() -> None:
    sess = _make_session(
        groups=[_grp(10)], evals=[_eval(10, _FP)], active_pass2=[], findings=[_finding(10)]
    )
    count, _ = _run(sess)
    assert count == 0


def test_eval_different_fingerprint_enqueues() -> None:
    sess = _make_session(
        groups=[_grp(10)], evals=[_eval(10, "stale_fp_999999")], findings=[_finding(10)]
    )
    count, _ = _run(sess)
    assert count == 1


def test_group_without_open_findings_skips() -> None:
    sess = _make_session(groups=[_grp(10)], evals=[], active_pass2=[], findings=[])
    count, _ = _run(sess)
    assert count == 0


def test_mixed_groups_select_correctly() -> None:
    """Group 10 neu (enqueue), 11 cached (skip), 12 aktiver Job (skip)."""
    sess = _make_session(
        groups=[_grp(10), _grp(11), _grp(12)],
        evals=[_eval(11, _FP)],
        active_pass2=[12],
        findings=[_finding(10), _finding(11), _finding(12)],
    )
    count, _ = _run(sess)
    assert count == 1
    assert sess.added[0].payload["group_id"] == 10


# --- Audit -----------------------------------------------------------------


def test_trigger_lands_in_audit_metadata() -> None:
    sess = _make_session(groups=[_grp(10)], findings=[_finding(10)])
    count, mock_log = _run(sess, trigger="pass1_completion")
    assert count == 1
    mock_log.assert_called_once()
    kwargs = mock_log.call_args.kwargs
    assert kwargs["metadata"]["trigger"] == "pass1_completion"
    assert kwargs["metadata"]["pass2_queued_count"] == 1
    assert kwargs["metadata"]["server_id"] == 1


def test_no_audit_event_when_zero_enqueued() -> None:
    sess = _make_session(groups=[_grp(10)], evals=[_eval(10, _FP)], findings=[_finding(10)])
    count, mock_log = _run(sess)
    assert count == 0
    mock_log.assert_not_called()


# --- Doppel-Enqueue-Guard --------------------------------------------------


def test_in_progress_pass2_blocks() -> None:
    sess = _make_session(groups=[_grp(10)], active_pass2=[10], findings=[_finding(10)])
    count, _ = _run(sess)
    assert count == 0


def test_queued_pass2_blocks() -> None:
    # active_pass2 modelliert sowohl queued als auch in_progress (Query
    # filtert auf beide Status); hier reicht ein Eintrag fuer Group 10.
    sess = _make_session(groups=[_grp(10)], active_pass2=[10], findings=[_finding(10)])
    count, _ = _run(sess)
    assert count == 0


def test_done_pass2_does_not_block() -> None:
    """Ein alter ``done`` Pass-2-Job taucht im aktiven-Jobs-Query NICHT auf
    (Status-Filter queued/in_progress) -> bei neuem Fingerprint wird enqueued."""
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "old_fp_000000")],
        active_pass2=[],
        findings=[_finding(10)],
    )
    count, _ = _run(sess)
    assert count == 1


def test_no_groups_returns_zero_no_audit() -> None:
    sess = _make_session(groups=[])
    count, mock_log = _run(sess)
    assert count == 0
    mock_log.assert_not_called()
