"""Pure-Unit-Tests fuer ``app/services/pass2_enqueue.py``.

TICKET-007 Etappe 1 (Enqueue-Guard/Fingerprint-Skip) + ADR-0053/TICKET-013
Etappe 4 (Enqueue pro Fix-Lane).

Mock-Session (kein DB-Roundtrip). Die vier ``session.execute``-Aufrufe des
Helpers werden ueber ``side_effect`` in fester Reihenfolge bedient:
  1. affected_groups (``.scalars().all()``)
  2. evaluations (``.scalars().all()``) — jetzt Lane-Rows mit ``fix_lane``
  3. aktive Pass-2-Jobs (``.all()`` -> Liste von ``(payload,)``-Tupeln)
  4. OPEN-Findings aller Groups (``.scalars().all()``)
``group_findings_fingerprint`` ist gepatcht (deterministisch), ``log_event``
gepatcht zum Assert.

Lane-Ableitung: ``fix_lane`` folgt aus ``fixed_version`` — ``patch`` wenn
gesetzt/truthy, sonst ``mitigate`` (``pass2_input_selection.fix_lane_of``).
``group_findings_fingerprint`` wird hier so gepatcht, dass es den
**Lane-Inhalt** widerspiegelt (Side-Effect-Funktion ueber die uebergebene
Finding-Liste), damit Fingerprint-Skip pro Lane testbar ist.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from app.services.pass2_enqueue import enqueue_pass2_for_server

_FP = "fpcurrent000000"


def _grp(gid: int) -> SimpleNamespace:
    return SimpleNamespace(id=gid)


def _eval(group_id: int, fix_lane: str, fp: str | None) -> SimpleNamespace:
    return SimpleNamespace(group_id=group_id, fix_lane=fix_lane, group_findings_fingerprint=fp)


def _finding(
    group_id: int,
    *,
    fixed_version: str | None = "1.2.3",
    finding_class: str = "os-pkgs",
) -> SimpleNamespace:
    """Default ``fixed_version`` gesetzt + ``os-pkgs`` -> Lane ``patch``.

    ADR-0061: die Lane folgt aus ``(finding_class, has_fix)``. ``os-pkgs`` +
    Fix -> ``patch``; ``fixed_version=None`` -> ``mitigate``; ``lang-pkgs`` +
    Fix -> ``upstream`` (per ``finding_class``-Override in den Tests).
    """
    return SimpleNamespace(
        application_group_id=group_id,
        fixed_version=fixed_version,
        finding_class=finding_class,
    )


def _job(group_id: int, *, fix_lane: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {"group_id": group_id, "server_id": 1}
    if fix_lane is not None:
        payload["fix_lane"] = fix_lane
    return payload


def _make_session(
    *,
    groups: list[Any],
    evals: list[Any] | None = None,
    active_jobs: list[dict[str, Any]] | None = None,
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
        r_active.all.return_value = [(p,) for p in (active_jobs or [])]
        results.append(r_active)

        r_findings = MagicMock()
        r_findings.scalars.return_value.all.return_value = findings or []
        results.append(r_findings)

    sess.execute.side_effect = results
    added: list[Any] = []
    sess.add.side_effect = added.append
    sess.added = added  # type: ignore[attr-defined]
    return sess


def _fp_by_lane(findings: list[Any]) -> str:
    """Fingerprint-Stub, der den Lane-Inhalt unterscheidet.

    Patch-Lane (alle ``fixed_version`` truthy) -> ``_FP``; mitigate-Lane ->
    ``fpmitig00000000``; gemischte Liste (sollte beim Enqueue nicht vorkommen,
    da pro Lane aufgerufen) -> stabiler Hash der Lane-Marker.
    """
    has_fix = {bool(f.fixed_version) for f in findings}
    if has_fix == {True}:
        return _FP
    if has_fix == {False}:
        return "fpmitig00000000"
    return "fpmixed000000000"


def _run(
    session: MagicMock,
    *,
    trigger: str = "scan_ingest",
    fp: Any = None,
) -> tuple[int, MagicMock]:
    fp_target = fp if fp is not None else _fp_by_lane
    with (
        patch(
            "app.services.pass2_enqueue.group_findings_fingerprint",
            side_effect=fp_target,
        ),
        patch("app.services.pass2_enqueue.log_event") as mock_log,
    ):
        count = enqueue_pass2_for_server(session, 1, trigger=trigger)  # type: ignore[arg-type]
    return count, mock_log


def _payloads(sess: MagicMock) -> list[dict[str, Any]]:
    return [job.payload for job in sess.added]


# --- Basis: reine Lanes ----------------------------------------------------


def test_new_group_no_eval_pure_patch_enqueues_one() -> None:
    sess = _make_session(groups=[_grp(10)], evals=[], active_jobs=[], findings=[_finding(10)])
    count, _ = _run(sess)
    assert count == 1
    job = sess.added[0]
    assert job.job_type == "risk_evaluation"
    assert job.payload == {"group_id": 10, "server_id": 1, "fix_lane": "patch"}
    assert getattr(job, "depends_on", None) is None


def test_pure_mitigate_group_enqueues_one_mitigate_job() -> None:
    sess = _make_session(
        groups=[_grp(10)],
        evals=[],
        findings=[_finding(10, fixed_version=None), _finding(10, fixed_version=None)],
    )
    count, _ = _run(sess)
    assert count == 1
    assert _payloads(sess) == [{"group_id": 10, "server_id": 1, "fix_lane": "mitigate"}]


def test_pure_patch_group_enqueues_one_patch_job() -> None:
    sess = _make_session(
        groups=[_grp(10)],
        evals=[],
        findings=[_finding(10), _finding(10)],
    )
    count, _ = _run(sess)
    assert count == 1
    assert _payloads(sess) == [{"group_id": 10, "server_id": 1, "fix_lane": "patch"}]


# --- Gemischte Group -> zwei Jobs -----------------------------------------


def test_mixed_group_enqueues_two_jobs_one_per_lane() -> None:
    sess = _make_session(
        groups=[_grp(10)],
        evals=[],
        findings=[_finding(10), _finding(10, fixed_version=None)],
    )
    count, _ = _run(sess)
    assert count == 2
    lanes = {p["fix_lane"] for p in _payloads(sess)}
    assert lanes == {"patch", "mitigate"}
    for p in _payloads(sess):
        assert p["group_id"] == 10
        assert p["server_id"] == 1


def test_empty_lane_produces_no_job() -> None:
    """Reine Patch-Group: die (leere) mitigate-Lane erzeugt keinen Job/Row."""
    sess = _make_session(groups=[_grp(10)], evals=[], findings=[_finding(10)])
    count, _ = _run(sess)
    assert count == 1
    assert all(p["fix_lane"] == "patch" for p in _payloads(sess))


# --- Fingerprint-Skip pro Lane --------------------------------------------


def test_patch_lane_same_fingerprint_skips() -> None:
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", _FP)],
        findings=[_finding(10)],
    )
    count, _ = _run(sess)
    assert count == 0


def test_patch_lane_different_fingerprint_enqueues() -> None:
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", "stale_fp_999999")],
        findings=[_finding(10)],
    )
    count, _ = _run(sess)
    assert count == 1
    assert _payloads(sess)[0]["fix_lane"] == "patch"


def test_mixed_group_only_changed_lane_re_enqueues() -> None:
    """Patch-Lane unveraendert (Fingerprint match) -> kein Job; mitigate-Lane
    fehlt eine Eval-Row -> Job. Genau ein Job."""
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", _FP)],  # patch-Lane bereits aktuell bewertet
        findings=[_finding(10), _finding(10, fixed_version=None)],
    )
    count, _ = _run(sess)
    assert count == 1
    assert _payloads(sess) == [{"group_id": 10, "server_id": 1, "fix_lane": "mitigate"}]


def test_mixed_group_both_lanes_current_skips_both() -> None:
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", _FP), _eval(10, "mitigate", "fpmitig00000000")],
        findings=[_finding(10), _finding(10, fixed_version=None)],
    )
    count, _ = _run(sess)
    assert count == 0


# --- Doppel-Enqueue-Guard pro (group, lane) -------------------------------


def test_active_lane_job_blocks_only_that_lane() -> None:
    """Aktiver patch-Job blockiert die patch-Lane, mitigate-Lane laeuft durch."""
    sess = _make_session(
        groups=[_grp(10)],
        active_jobs=[_job(10, fix_lane="patch")],
        findings=[_finding(10), _finding(10, fixed_version=None)],
    )
    count, _ = _run(sess)
    assert count == 1
    assert _payloads(sess) == [{"group_id": 10, "server_id": 1, "fix_lane": "mitigate"}]


def test_active_jobs_for_both_lanes_block_all() -> None:
    sess = _make_session(
        groups=[_grp(10)],
        active_jobs=[_job(10, fix_lane="patch"), _job(10, fix_lane="mitigate")],
        findings=[_finding(10), _finding(10, fixed_version=None)],
    )
    count, _ = _run(sess)
    assert count == 0
    assert sess.added == []


def test_legacy_job_without_fix_lane_blocks_whole_group() -> None:
    """Alt-Format-Job (ohne fix_lane) blockiert konservativ beide Lanes."""
    sess = _make_session(
        groups=[_grp(10)],
        active_jobs=[_job(10, fix_lane=None)],
        findings=[_finding(10), _finding(10, fixed_version=None)],
    )
    count, _ = _run(sess)
    assert count == 0


# --- Mehrere Groups, gemischt ---------------------------------------------


def test_group_without_open_findings_skips() -> None:
    sess = _make_session(groups=[_grp(10)], evals=[], active_jobs=[], findings=[])
    count, _ = _run(sess)
    assert count == 0


def test_mixed_groups_select_correctly() -> None:
    """Group 10 neu patch (enqueue), 11 cached patch (skip), 12 aktiver Job."""
    sess = _make_session(
        groups=[_grp(10), _grp(11), _grp(12)],
        evals=[_eval(11, "patch", _FP)],
        active_jobs=[_job(12, fix_lane="patch")],
        findings=[_finding(10), _finding(11), _finding(12)],
    )
    count, _ = _run(sess)
    assert count == 1
    assert _payloads(sess)[0]["group_id"] == 10
    assert _payloads(sess)[0]["fix_lane"] == "patch"


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


def test_audit_count_reflects_lane_jobs() -> None:
    sess = _make_session(
        groups=[_grp(10)],
        findings=[_finding(10), _finding(10, fixed_version=None)],
    )
    count, mock_log = _run(sess)
    assert count == 2
    mock_log.assert_called_once()
    assert mock_log.call_args.kwargs["metadata"]["pass2_queued_count"] == 2


def test_no_audit_event_when_zero_enqueued() -> None:
    sess = _make_session(
        groups=[_grp(10)], evals=[_eval(10, "patch", _FP)], findings=[_finding(10)]
    )
    count, mock_log = _run(sess)
    assert count == 0
    mock_log.assert_not_called()


def test_done_pass2_does_not_block() -> None:
    """Ein alter ``done`` Pass-2-Job taucht im aktiven-Jobs-Query NICHT auf
    (Status-Filter queued/in_progress) -> bei neuem Fingerprint wird enqueued."""
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", "old_fp_000000")],
        active_jobs=[],
        findings=[_finding(10)],
    )
    count, _ = _run(sess)
    assert count == 1


def test_no_groups_returns_zero_no_audit() -> None:
    sess = _make_session(groups=[])
    count, mock_log = _run(sess)
    assert count == 0
    mock_log.assert_not_called()
