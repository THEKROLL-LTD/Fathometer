"""Tests fuer `app.services.pass2_input_selection` (TICKET-011, Etappe 1).

Pure-Unit — Finding-Objekte werden detached konstruiert, keine Session.
Abgedeckt: Quoten-Matrix, Overflow (mehr KEV/CRITICAL als Budget),
Determinismus (gleicher/geshuffelter Input -> identische Auswahl und
Reihenfolge), Invariante "0 KEV im Rest", Pfad-Diversitaet, leere und
kleine Gruppen.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Severity,
)
from app.services.llm_fingerprints import group_findings_fingerprint
from app.services.pass2_input_selection import (
    EPSS_QUOTA,
    FIX_LANES,
    PASS2_FINDINGS_BUDGET,
    fix_lane_of,
    partition_by_lane,
    select_pass2_findings,
    triage_sort_key,
)

_BASE_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _mk(
    fid: int,
    *,
    severity: Severity = Severity.MEDIUM,
    epss: float | None = None,
    cvss: float | None = None,
    kev: bool = False,
    fix: str | None = None,
    path: str | None = None,
    package: str = "libfoo",
    first_seen_offset_h: int = 0,
) -> Finding:
    ts = _BASE_TS + timedelta(hours=first_seen_offset_h)
    return Finding(
        id=fid,
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key=f"CVE-2026-{fid:05d}",
        package_name=package,
        installed_version="1.0",
        fixed_version=fix,
        severity=severity,
        attack_vector=AttackVector.UNKNOWN,
        status=FindingStatus.OPEN,
        is_kev=kev,
        cvss_v3_score=cvss,
        epss_score=epss,
        first_seen_at=ts,
        last_seen_at=ts,
        target_path=path,
    )


# ---------------------------------------------------------------------------
# Kleine Gruppen — Budget greift nicht
# ---------------------------------------------------------------------------


def test_empty_input_yields_empty_result() -> None:
    result = select_pass2_findings([])
    assert result.selected == ()
    assert result.selected_ids == frozenset()
    assert result.rest_count == 0
    assert result.rest_severity_counts == ()
    assert result.rest_max_epss is None
    assert result.rest_kev_count == 0


def test_group_at_or_below_budget_is_returned_completely() -> None:
    findings = [_mk(i, severity=Severity.LOW) for i in range(1, PASS2_FINDINGS_BUDGET + 1)]
    result = select_pass2_findings(findings)
    assert result.selected_ids == {f.id for f in findings}
    assert result.rest_count == 0
    assert result.rest_severity_counts == ()


def test_small_group_is_rendered_in_triage_order() -> None:
    f_low = _mk(1, severity=Severity.LOW)
    f_kev = _mk(2, severity=Severity.MEDIUM, kev=True)
    f_high_epss = _mk(3, severity=Severity.MEDIUM, epss=0.9)
    result = select_pass2_findings([f_low, f_high_epss, f_kev])
    assert [f.id for f in result.selected] == [2, 3, 1]


# ---------------------------------------------------------------------------
# Bug-A-Regression: KEV ist immer in der Auswahl
# ---------------------------------------------------------------------------


def test_kev_finding_is_always_selected_in_large_group() -> None:
    # 200 HIGH-Findings mit hohem EPSS/CVSS, ein unscheinbares KEV-LOW
    # tief in der Liste — das KEV MUSS in die Auswahl (Bug A).
    findings = [
        _mk(i, severity=Severity.HIGH, epss=0.5, cvss=8.0, path=f"/usr/lib/x/{i}")
        for i in range(1, 201)
    ]
    findings.append(_mk(999, severity=Severity.LOW, epss=None, cvss=None, kev=True))
    result = select_pass2_findings(findings)
    assert 999 in result.selected_ids
    assert len(result.selected) == PASS2_FINDINGS_BUDGET
    assert result.rest_kev_count == 0


def test_all_critical_are_selected_when_they_fit() -> None:
    criticals = [_mk(i, severity=Severity.CRITICAL) for i in range(1, 11)]
    filler = [_mk(i, severity=Severity.MEDIUM, epss=0.99) for i in range(100, 200)]
    result = select_pass2_findings(criticals + filler)
    assert {f.id for f in criticals} <= result.selected_ids


# ---------------------------------------------------------------------------
# Overflow: Pflicht-Slots allein ueberschreiten das Budget
# ---------------------------------------------------------------------------


def test_mandatory_overflow_cuts_by_epss_desc_kev_first() -> None:
    # 24 KEV + 24 CRITICAL > 32: alle KEV rein (24 < Budget), CRITICAL
    # nach EPSS desc auf die restlichen 8 Slots gekuerzt.
    kevs = [_mk(i, severity=Severity.HIGH, kev=True, epss=i / 100) for i in range(1, 25)]
    crits = [_mk(100 + i, severity=Severity.CRITICAL, epss=i / 100) for i in range(1, 25)]
    result = select_pass2_findings(kevs + crits)
    assert len(result.selected) == PASS2_FINDINGS_BUDGET
    assert {f.id for f in kevs} <= result.selected_ids
    # Die 8 CRITICAL mit dem hoechsten EPSS (117..124).
    expected_crits = {100 + i for i in range(17, 25)}
    assert result.selected_ids - {f.id for f in kevs} == expected_crits


def test_kev_overflow_alone_reports_honest_rest_kev_count() -> None:
    # Mehr KEV als Budget: Invariante "0 KEV im Rest" ist nicht haltbar,
    # das Aggregat traegt den ehrlichen Count statt einer harten 0.
    kevs = [_mk(i, kev=True, epss=i / 1000) for i in range(1, 41)]
    result = select_pass2_findings(kevs)
    assert len(result.selected) == PASS2_FINDINGS_BUDGET
    assert result.rest_kev_count == 40 - PASS2_FINDINGS_BUDGET
    # Gekuerzt wird nach EPSS desc: die niedrigsten EPSS fallen raus.
    assert result.selected_ids == set(range(9, 41))


# ---------------------------------------------------------------------------
# Quoten
# ---------------------------------------------------------------------------


def test_epss_quota_catches_likely_exploited_medium() -> None:
    # Viele HIGH ohne EPSS, ein MEDIUM mit sehr hohem EPSS: die
    # EPSS-Quote holt es rein, obwohl severity_rank es sonst verdraengt.
    highs = [_mk(i, severity=Severity.HIGH, cvss=8.5) for i in range(1, 101)]
    medium_hot = _mk(500, severity=Severity.MEDIUM, epss=0.97)
    result = select_pass2_findings([*highs, medium_hot])
    assert 500 in result.selected_ids


def test_path_quota_selects_worst_per_distinct_path() -> None:
    # 40 Findings auf Pfad A (alle HIGH), je 1 LOW auf Pfaden B und C:
    # die Pfad-Quote garantiert B und C je einen Slot.
    path_a = [_mk(i, severity=Severity.HIGH, cvss=8.0, path="/opt/app-a/lib") for i in range(1, 41)]
    b = _mk(200, severity=Severity.LOW, path="/opt/app-b/lib")
    c = _mk(201, severity=Severity.LOW, path="/opt/app-c/lib")
    result = select_pass2_findings([*path_a, b, c])
    assert 200 in result.selected_ids
    assert 201 in result.selected_ids


def test_path_quota_falls_back_to_package_name() -> None:
    pkg_a = [_mk(i, severity=Severity.HIGH, cvss=8.0, package="pkg-a") for i in range(1, 41)]
    pkg_b = _mk(300, severity=Severity.LOW, package="pkg-b")
    result = select_pass2_findings([*pkg_a, pkg_b])
    assert 300 in result.selected_ids


def test_epss_quota_constant_is_a_quarter_of_budget() -> None:
    assert EPSS_QUOTA == PASS2_FINDINGS_BUDGET // 4


# ---------------------------------------------------------------------------
# Determinismus
# ---------------------------------------------------------------------------


def test_selection_is_deterministic_under_input_shuffle() -> None:
    findings = [
        _mk(
            i,
            severity=list(Severity)[i % 5],
            epss=(i % 7) / 10 if i % 3 else None,
            cvss=5.0 + (i % 5) if i % 4 else None,
            kev=(i % 17 == 0),
            path=f"/srv/app-{i % 9}/lib",
            first_seen_offset_h=i % 11,
        )
        for i in range(1, 121)
    ]
    baseline = select_pass2_findings(findings)
    for seed in (1, 2, 3):
        shuffled = findings[:]
        random.Random(seed).shuffle(shuffled)  # noqa: S311 — Test-Shuffle, kein Krypto
        result = select_pass2_findings(shuffled)
        assert [f.id for f in result.selected] == [f.id for f in baseline.selected]
        assert result.selected_ids == baseline.selected_ids
        assert result.rest_severity_counts == baseline.rest_severity_counts
        assert result.rest_max_epss == baseline.rest_max_epss


def test_selected_render_order_is_triage_order() -> None:
    findings = [
        _mk(i, severity=list(Severity)[i % 5], epss=(i % 5) / 10, kev=(i % 13 == 0))
        for i in range(1, 100)
    ]
    result = select_pass2_findings(findings)
    keys = [triage_sort_key(f) for f in result.selected]
    assert keys == sorted(keys)


def test_duplicate_finding_ids_are_deduped() -> None:
    f = _mk(1, severity=Severity.HIGH)
    result = select_pass2_findings([f, f, _mk(2)])
    assert sorted(int(x.id) for x in result.selected) == [1, 2]


# ---------------------------------------------------------------------------
# Rest-Aggregat
# ---------------------------------------------------------------------------


def test_rest_aggregate_counts_and_max_epss() -> None:
    # Pflicht + Quoten fuellen das Budget; der Rest sind MEDIUM/LOW.
    selected_pool = [
        _mk(i, severity=Severity.CRITICAL, epss=0.5, path=f"/opt/a{i}") for i in range(1, 33)
    ]
    rest_pool = [
        _mk(100 + i, severity=Severity.MEDIUM if i % 2 else Severity.LOW, epss=i / 100)
        for i in range(1, 21)
    ]
    result = select_pass2_findings(selected_pool + rest_pool)
    assert result.rest_count == 20
    counts = dict(result.rest_severity_counts)
    assert counts == {"medium": 10, "low": 10}
    assert result.rest_max_epss == 0.2
    assert result.rest_kev_count == 0


def test_rest_invariant_no_kev_when_kev_fits_budget() -> None:
    findings = [
        _mk(i, severity=Severity.HIGH, epss=0.4, kev=(i <= 5), path=f"/x/{i}")
        for i in range(1, 150)
    ]
    result = select_pass2_findings(findings)
    assert result.rest_kev_count == 0
    assert {1, 2, 3, 4, 5} <= result.selected_ids


def test_rest_fixable_count() -> None:
    selected_pool = [_mk(i, severity=Severity.CRITICAL, epss=0.9) for i in range(1, 33)]
    rest_pool = [
        _mk(100 + i, severity=Severity.LOW, fix="2.0" if i <= 7 else None) for i in range(1, 21)
    ]
    result = select_pass2_findings(selected_pool + rest_pool)
    assert result.rest_fixable_count == 7


# ---------------------------------------------------------------------------
# Fix-Lane (TICKET-013 / ADR-0053): fix_lane_of, partition_by_lane,
# Fix-wird-verfuegbar-Doppel-Invalidation
# ---------------------------------------------------------------------------


def test_fix_lanes_constant() -> None:
    # ADR-0061: dritte Lane ``upstream`` (lang-pkgs-Fix, nicht host-applizierbar).
    assert FIX_LANES == ("patch", "upstream", "mitigate")


def test_fix_lane_of_with_fixed_version_is_patch() -> None:
    f = _mk(1, fix="6.8.0-117.117")
    assert fix_lane_of(f) == "patch"


def test_fix_lane_of_without_fixed_version_is_mitigate() -> None:
    f = _mk(1, fix=None)
    assert fix_lane_of(f) == "mitigate"


def test_fix_lane_of_empty_string_is_mitigate() -> None:
    """Leerer ``fixed_version``-String zaehlt als no-fix (mitigate),
    konsistent zur generierten ``Finding.has_fix``-Spalte
    (``fixed_version IS NOT NULL AND fixed_version <> ''``)."""
    f = _mk(1, fix="")
    assert fix_lane_of(f) == "mitigate"


def test_partition_by_lane_splits_mixed_list() -> None:
    patchable_a = _mk(1, fix="1.2.3")
    patchable_b = _mk(2, fix="4.5.6")
    nofix_a = _mk(3, fix=None)
    nofix_b = _mk(4, fix="")
    buckets = partition_by_lane([patchable_a, nofix_a, patchable_b, nofix_b])
    assert {f.id for f in buckets["patch"]} == {1, 2}
    assert {f.id for f in buckets["mitigate"]} == {3, 4}


def test_partition_by_lane_pure_list_leaves_other_lane_empty() -> None:
    only_patchable = [_mk(i, fix="1.0") for i in range(1, 4)]
    buckets = partition_by_lane(only_patchable)
    assert {f.id for f in buckets["patch"]} == {1, 2, 3}
    assert buckets["mitigate"] == []

    only_nofix = [_mk(i, fix=None) for i in range(1, 4)]
    buckets = partition_by_lane(only_nofix)
    assert buckets["patch"] == []
    assert {f.id for f in buckets["mitigate"]} == {1, 2, 3}


def test_partition_by_lane_always_returns_both_keys_for_empty_input() -> None:
    # ADR-0061: drei Lane-Keys (patch/upstream/mitigate), alle leer.
    buckets = partition_by_lane([])
    assert buckets == {"patch": [], "upstream": [], "mitigate": []}


def test_fix_becomes_available_invalidates_both_lane_fingerprints() -> None:
    """ADR-0053 §Fingerprint, Kern-Szenario: wandert EIN Finding von
    mitigate→patch (Fix wurde verfuegbar), aendern sich BEIDE Lane-
    Fingerprints — mitigate verliert das Finding, patch gewinnt es. Das
    ist der Re-Eval-Trigger, der beide Lanes neu enqueued, ohne
    ``fixed_version`` separat in den Fingerprint aufzunehmen."""
    # Group-OPEN-Set: 2 patchbar, 2 ohne Fix (eins davon wandert spaeter).
    f_patch_1 = _mk(1, fix="1.0")
    f_patch_2 = _mk(2, fix="2.0")
    f_nofix_stay = _mk(3, fix=None)
    f_migrant = _mk(4, fix=None)
    group = [f_patch_1, f_patch_2, f_nofix_stay, f_migrant]

    before = partition_by_lane(group)
    patch_fp_before = group_findings_fingerprint(before["patch"])
    mitigate_fp_before = group_findings_fingerprint(before["mitigate"])
    assert {f.id for f in before["patch"]} == {1, 2}
    assert {f.id for f in before["mitigate"]} == {3, 4}

    # Fix wird fuer Finding 4 verfuegbar → mitigate→patch.
    f_migrant.fixed_version = "9.9.9"

    after = partition_by_lane(group)
    patch_fp_after = group_findings_fingerprint(after["patch"])
    mitigate_fp_after = group_findings_fingerprint(after["mitigate"])
    assert {f.id for f in after["patch"]} == {1, 2, 4}
    assert {f.id for f in after["mitigate"]} == {3}

    # BEIDE Lane-Fingerprints aendern sich — der Doppel-Invalidations-Trigger.
    assert patch_fp_after != patch_fp_before, (patch_fp_before, patch_fp_after)
    assert mitigate_fp_after != mitigate_fp_before, (mitigate_fp_before, mitigate_fp_after)
