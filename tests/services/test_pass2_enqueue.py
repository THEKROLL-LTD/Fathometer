"""Pure-unit tests for ``app/services/pass2_enqueue.py``.

TICKET-007 Etappe 1 (enqueue guard / fingerprint skip) + ADR-0053/TICKET-013
Etappe 4 (enqueue per fix-lane) + **TICKET-017 / ADR-0068 Gate 1**: the enqueue
gate now compares the **full** ``make_cache_key`` against the stored eval row's
``cache_key`` (not just ``group_findings_fingerprint``), so a running-kernel
change or a ``host_update_available`` flip re-enqueues even when the OPEN-set is
unchanged.

Mock-Session (no DB roundtrip). The four ``session.execute`` calls of the helper
are served in fixed order via ``side_effect``:
  1. affected_groups (``.scalars().all()``)
  2. evaluations (``.scalars().all()``) — lane rows with ``fix_lane`` + ``cache_key``
  3. active Pass-2 jobs (``.all()`` -> list of ``(payload,)`` tuples)
  4. OPEN findings of all groups (``.scalars().all()``)
In addition ``session.get(Server, server_id)`` is served via ``sess.get`` and
returns a stub ``Server``. ``log_event`` is patched for assertions.

To keep the gate deterministic over ``SimpleNamespace`` stubs, the four
fingerprint/key helpers imported into ``pass2_enqueue`` are patched so the
``cache_key`` of a ``(group, lane)`` is a pure function of
``(group_id, fix_lane, lane-content marker, server-context marker)``. A stored
eval "matches" (and thus skips enqueue) exactly when its ``cache_key`` equals
that computed key — which is precisely the production gate. ``host_update`` /
kernel sensitivity is exercised by changing the marker inputs and asserting the
computed key (and therefore the skip decision) moves with them.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from app.services.pass2_enqueue import enqueue_pass2_for_server

_FP = "fpcurrent000000"
_MITIG_FP = "fpmitig00000000"

# Default server-context marker used when the test does not override it. The
# patched ``server_context_fingerprint`` returns this; bumping it (per-test)
# simulates a running-kernel change.
_DEFAULT_SV_FP = "svctx0000000000"


def _grp(gid: int) -> SimpleNamespace:
    return SimpleNamespace(id=gid)


def _cache_key(group_id: int, lane: str, lane_fp: str, cve_fp: str, sv_fp: str) -> str:
    """Mirror of the production ``make_cache_key`` payload over the stub inputs.

    The real ``make_cache_key`` hashes ``group_id | gf_fp | cve_fp | sv_fp |
    v<version> | lane=<lane>``. We patch ``make_cache_key`` to this same shape so
    a stored ``cache_key`` produced here equals what the gate computes for
    identical inputs — i.e. the no-churn / skip path is exercised exactly.
    """
    payload = f"{group_id}|{lane_fp}|{cve_fp}|{sv_fp}|lane={lane}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _eval(
    group_id: int,
    fix_lane: str,
    cache_key: str | None,
    *,
    gf_fp: str | None = None,
) -> SimpleNamespace:
    """Stored junction row. The **gate** now compares ``cache_key``; the legacy
    ``group_findings_fingerprint`` stays on the row for diagnostics only."""
    return SimpleNamespace(
        group_id=group_id,
        fix_lane=fix_lane,
        group_findings_fingerprint=gf_fp,
        cache_key=cache_key,
    )


def _finding(
    group_id: int,
    *,
    fixed_version: str | None = "1.2.3",
    finding_class: str = "os-pkgs",
    host_update_available: bool | None = None,
) -> SimpleNamespace:
    """Default ``fixed_version`` set + ``os-pkgs`` -> lane ``patch``.

    ADR-0061/0062: the lane follows from ``(finding_class, has_fix,
    host_update_available)``. ``os-pkgs`` + fix -> ``patch``;
    ``fixed_version=None`` -> ``mitigate``.
    """
    return SimpleNamespace(
        application_group_id=group_id,
        fixed_version=fixed_version,
        finding_class=finding_class,
        host_update_available=host_update_available,
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
    server: Any | None = "default",
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
    # TICKET-017: enqueue loads the Server snapshot once via session.get(Server, id).
    sess.get.return_value = SimpleNamespace(id=1) if server == "default" else server
    added: list[Any] = []
    sess.add.side_effect = added.append
    sess.added = added  # type: ignore[attr-defined]
    return sess


def _lane_fp(findings: list[Any]) -> str:
    """``group_findings_fingerprint`` stub — distinguishes lane content."""
    has_fix = {bool(f.fixed_version) for f in findings}
    if has_fix == {True}:
        return _FP
    if has_fix == {False}:
        return _MITIG_FP
    return "fpmixed000000000"


def _cve_fp(findings: list[Any]) -> str:
    """``cve_data_fingerprint`` stub — sensitive to ``host_update_available``.

    TICKET-017: a host_update flip must move the cve fingerprint and therefore
    the cache_key, re-enqueuing even with an unchanged OPEN-set.
    """
    marker = "|".join(
        sorted(f"{bool(f.fixed_version)}:{f.host_update_available}" for f in findings)
    )
    return "cve" + hashlib.sha256(marker.encode("utf-8")).hexdigest()[:13]


def _run(
    session: MagicMock,
    *,
    trigger: str = "scan_ingest",
    sv_fp: str = _DEFAULT_SV_FP,
) -> tuple[int, MagicMock]:
    with (
        patch(
            "app.services.pass2_enqueue.group_findings_fingerprint",
            side_effect=_lane_fp,
        ),
        patch(
            "app.services.pass2_enqueue.cve_data_fingerprint",
            side_effect=_cve_fp,
        ),
        patch(
            "app.services.pass2_enqueue.server_context_fingerprint",
            return_value=sv_fp,
        ),
        patch(
            "app.services.pass2_enqueue.make_cache_key",
            side_effect=lambda gid, gf, cve, sv, fix_lane=None: _cache_key(
                gid, fix_lane or "", gf, cve, sv
            ),
        ),
        patch("app.services.pass2_enqueue.log_event") as mock_log,
    ):
        count = enqueue_pass2_for_server(session, 1, trigger=trigger)  # type: ignore[arg-type]
    return count, mock_log


def _payloads(sess: MagicMock) -> list[dict[str, Any]]:
    return [job.payload for job in sess.added]


def _key_for(
    group_id: int,
    lane: str,
    findings: list[Any],
    *,
    sv_fp: str = _DEFAULT_SV_FP,
) -> str:
    """Compute the cache_key the gate will derive for this (group, lane) state,
    using the same stubs as :func:`_run`. Used to seed a "matching" eval row."""
    return _cache_key(group_id, lane, _lane_fp(findings), _cve_fp(findings), sv_fp)


# --- Basis: pure lanes -----------------------------------------------------


def test_new_group_no_eval_pure_patch_enqueues_one() -> None:
    sess = _make_session(groups=[_grp(10)], evals=[], active_jobs=[], findings=[_finding(10)])
    count, _ = _run(sess)
    assert count == 1, _payloads(sess)
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


# --- Mixed group -> two jobs -----------------------------------------------


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
    """Pure patch group: the (empty) mitigate lane creates no job/row."""
    sess = _make_session(groups=[_grp(10)], evals=[], findings=[_finding(10)])
    count, _ = _run(sess)
    assert count == 1
    assert all(p["fix_lane"] == "patch" for p in _payloads(sess))


# --- TICKET-017 Gate 1: cache_key skip per lane ----------------------------


def test_patch_lane_matching_cache_key_skips() -> None:
    """Stored eval whose full ``cache_key`` matches the computed key -> no churn."""
    findings = [_finding(10)]
    key = _key_for(10, "patch", findings)
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", key)],
        findings=findings,
    )
    count, _ = _run(sess)
    assert count == 0, _payloads(sess)


def test_patch_lane_stale_cache_key_enqueues() -> None:
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", "stale_key_does_not_match")],
        findings=[_finding(10)],
    )
    count, _ = _run(sess)
    assert count == 1
    assert _payloads(sess)[0]["fix_lane"] == "patch"


def test_legacy_null_cache_key_re_enqueues_once() -> None:
    """TICKET-017 self-heal: a legacy row has ``cache_key = NULL`` (!= any
    computed key) and is therefore re-enqueued exactly once on deploy."""
    findings = [_finding(10)]
    sess = _make_session(
        groups=[_grp(10)],
        # NULL cache_key but a matching legacy gf-fingerprint — the OLD gate
        # would have skipped; the NEW gate must NOT.
        evals=[_eval(10, "patch", None, gf_fp=_FP)],
        findings=findings,
    )
    count, _ = _run(sess)
    assert count == 1, _payloads(sess)
    assert _payloads(sess)[0]["fix_lane"] == "patch"


def test_kernel_version_change_re_enqueues() -> None:
    """Running-kernel change flips ``server_context_fingerprint`` -> different
    cache_key -> re-enqueue, even though the OPEN-set is unchanged."""
    findings = [_finding(10)]
    # Stored eval matches the OLD server-context fingerprint.
    old_key = _key_for(10, "patch", findings, sv_fp="svctx_OLD_kernel")
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", old_key)],
        findings=findings,
    )
    # New scan runs with a NEW running kernel -> new server-context fingerprint.
    count, _ = _run(sess, sv_fp="svctx_NEW_kernel")
    assert count == 1, _payloads(sess)
    assert _payloads(sess)[0]["fix_lane"] == "patch"


def test_kernel_unchanged_with_matching_key_does_not_churn() -> None:
    """Same running kernel + same OPEN-set + matching stored key -> no enqueue."""
    findings = [_finding(10)]
    key = _key_for(10, "patch", findings, sv_fp="svctx_STABLE")
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", key)],
        findings=findings,
    )
    count, _ = _run(sess, sv_fp="svctx_STABLE")
    assert count == 0, _payloads(sess)


def test_host_update_flip_re_enqueues() -> None:
    """A ``host_update_available`` flip on a finding moves the cve fingerprint
    (and thus the cache_key) -> re-enqueue with an otherwise unchanged OPEN-set."""
    # Stored eval matches the state where host_update is False/None.
    old_findings = [_finding(10, host_update_available=False)]
    old_key = _key_for(10, "patch", old_findings)
    # New scan: same finding but host_update flipped to True.
    new_findings = [_finding(10, host_update_available=True)]
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", old_key)],
        findings=new_findings,
    )
    count, _ = _run(sess)
    assert count == 1, _payloads(sess)
    assert _payloads(sess)[0]["fix_lane"] == "patch"


def test_host_update_stable_matching_key_does_not_churn() -> None:
    findings = [_finding(10, host_update_available=True)]
    key = _key_for(10, "patch", findings)
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", key)],
        findings=findings,
    )
    count, _ = _run(sess)
    assert count == 0, _payloads(sess)


def test_enqueue_and_worker_compute_identical_key_for_identical_state() -> None:
    """Parity: the key the gate compares against the stored row is exactly the
    key derived from ``make_cache_key(group_id, gf_fp, cve_fp, sv_fp,
    fix_lane=lane)`` over the lane OPEN-set — the same call the worker makes.

    We assert parity behaviorally: seeding the eval with that exact key skips
    (count 0); perturbing any single key input re-enqueues (count 1)."""
    findings = [_finding(10)]
    matching = _key_for(10, "patch", findings)

    # Matching key -> skip.
    sess_match = _make_session(
        groups=[_grp(10)], evals=[_eval(10, "patch", matching)], findings=findings
    )
    assert _run(sess_match)[0] == 0

    # Wrong lane salt baked into the stored key -> mismatch -> enqueue.
    wrong_lane = _cache_key(10, "mitigate", _lane_fp(findings), _cve_fp(findings), _DEFAULT_SV_FP)
    sess_wrong = _make_session(
        groups=[_grp(10)], evals=[_eval(10, "patch", wrong_lane)], findings=findings
    )
    assert _run(sess_wrong)[0] == 1


def test_mixed_group_only_changed_lane_re_enqueues() -> None:
    """Patch lane unchanged (cache_key matches) -> no job; mitigate lane has no
    eval row -> job. Exactly one job."""
    findings = [_finding(10), _finding(10, fixed_version=None)]
    patch_key = _key_for(10, "patch", [_finding(10)])
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", patch_key)],  # patch lane already current
        findings=findings,
    )
    count, _ = _run(sess)
    assert count == 1
    assert _payloads(sess) == [{"group_id": 10, "server_id": 1, "fix_lane": "mitigate"}]


def test_mixed_group_both_lanes_current_skips_both() -> None:
    patch_findings = [_finding(10)]
    mitig_findings = [_finding(10, fixed_version=None)]
    sess = _make_session(
        groups=[_grp(10)],
        evals=[
            _eval(10, "patch", _key_for(10, "patch", patch_findings)),
            _eval(10, "mitigate", _key_for(10, "mitigate", mitig_findings)),
        ],
        findings=[_finding(10), _finding(10, fixed_version=None)],
    )
    count, _ = _run(sess)
    assert count == 0, _payloads(sess)


# --- Double-enqueue guard per (group, lane) --------------------------------


def test_active_lane_job_blocks_only_that_lane() -> None:
    """Active patch job blocks the patch lane, mitigate lane proceeds."""
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
    """Old-format job (no fix_lane) conservatively blocks both lanes."""
    sess = _make_session(
        groups=[_grp(10)],
        active_jobs=[_job(10, fix_lane=None)],
        findings=[_finding(10), _finding(10, fixed_version=None)],
    )
    count, _ = _run(sess)
    assert count == 0


# --- Multiple groups, mixed ------------------------------------------------


def test_group_without_open_findings_skips() -> None:
    sess = _make_session(groups=[_grp(10)], evals=[], active_jobs=[], findings=[])
    count, _ = _run(sess)
    assert count == 0


def test_mixed_groups_select_correctly() -> None:
    """Group 10 new patch (enqueue), 11 cached patch (skip), 12 active job."""
    sess = _make_session(
        groups=[_grp(10), _grp(11), _grp(12)],
        evals=[_eval(11, "patch", _key_for(11, "patch", [_finding(11)]))],
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
    findings = [_finding(10)]
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", _key_for(10, "patch", findings))],
        findings=findings,
    )
    count, mock_log = _run(sess)
    assert count == 0
    mock_log.assert_not_called()


def test_done_pass2_does_not_block() -> None:
    """An old ``done`` Pass-2 job does NOT show in the active-jobs query
    (status filter queued/in_progress) -> with a stale cache_key it enqueues."""
    sess = _make_session(
        groups=[_grp(10)],
        evals=[_eval(10, "patch", "old_key_no_match")],
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
    # No server snapshot is loaded when there are no affected groups.
    sess.get.assert_not_called()
