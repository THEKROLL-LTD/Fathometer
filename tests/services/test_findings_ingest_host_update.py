# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Block AH (ADR-0062) — Host-Update-Flag-Join im Findings-Ingest.

Pure-Unit-Tests fuer die `target_path`-Join-Logik in `_build_finding_row`:
`host_updates_map[target_path]` setzt die drei neuen Spalten
(`host_update_available`/`owning_package`/`available_version`) bzw. laesst
sie `None` wenn kein Eintrag matcht.

Kein DB-Roundtrip — die Funktion liest nur das parsed Pydantic-Envelope plus
die in-memory `path -> HostUpdateEntry`-Map und gibt ein dict zurueck. Ein
Mini-End-to-End ueber `fix_lane_for(...)` zeigt dass der promotete Eintrag
`patch` ergibt und der nicht-gematchte `mitigate` (ADR-0064; war `upstream`).

Vorlage: `tests/services/test_findings_ingest_cause_mapping.py`
(`_build_rows_from_envelope`-Pattern).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.models import FindingClass
from app.schemas.scan_envelope import Envelope, HostUpdateEntry
from app.services.findings_ingest import _CLASS_MAP, _build_finding_row
from app.services.risk_engine import fix_lane_for

_NOW = datetime(2026, 6, 1, 9, 0, 0, tzinfo=UTC)


def _envelope(*, results: list[dict[str, Any]]) -> Envelope:
    return Envelope.model_validate(
        {
            "agent_version": "0.4.0",
            "host": {
                "os_family": "rocky",
                "os_version": "9.3",
                "os_pretty_name": "Rocky Linux 9.3",
                "kernel_version": "5.14.0",
                "architecture": "x86_64",
                "trivy_version": "0.70.2",
            },
            "scan": {
                "SchemaVersion": 2,
                "Trivy": {"Version": "0.70.2"},
                "Results": results,
            },
        }
    )


def _build_rows(
    env: Envelope,
    *,
    host_updates_map: dict[str, HostUpdateEntry] | None = None,
    host_updates_by_pkg: dict[str, HostUpdateEntry] | None = None,
    server_id: int = 1,
) -> list[dict[str, Any]]:
    """Repliziert die per-Vuln-Schleife aus `ingest_scan`, ohne DB."""
    rows: list[dict[str, Any]] = []
    for result in env.scan.results:
        fc = _CLASS_MAP[result.normalized_class()]
        for vuln in result.vulnerabilities or []:
            rows.append(
                _build_finding_row(
                    server_id=server_id,
                    vuln=vuln,
                    finding_class=fc,
                    target=result.target,
                    result=result,
                    now=_NOW,
                    host_updates_map=host_updates_map,
                    host_updates_by_pkg=host_updates_by_pkg,
                )
            )
    return rows


def _langpkgs_gobinary_result(*, target: str) -> dict[str, Any]:
    """tailscaled gobinary lang-pkgs mit gesetztem FixedVersion (has_fix=True)."""
    return {
        "Target": target,
        "Class": "lang-pkgs",
        "Type": "gobinary",
        "Vulnerabilities": [
            {
                "VulnerabilityID": "CVE-2026-42504",
                "PkgName": "stdlib",
                "InstalledVersion": "v1.23.1",
                "FixedVersion": "v1.23.4",
                "Severity": "HIGH",
                "SeveritySource": "ghsa",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Match: target_path im Map -> drei Spalten gesetzt (Promotion)
# ---------------------------------------------------------------------------


def test_match_sets_all_three_host_update_columns() -> None:
    target = "/usr/bin/tailscaled"
    env = _envelope(results=[_langpkgs_gobinary_result(target=target)])
    host_updates_map = {
        target: HostUpdateEntry.model_validate(
            {
                "path": target,
                "owning_package": "tailscale",
                "available_version": "1.78.1-1",
                "update_available": True,
            }
        )
    }
    rows = _build_rows(env, host_updates_map=host_updates_map)
    assert len(rows) == 1
    row = rows[0]
    # Join-Key ist der effektive target_path.
    assert row["target_path"] == target
    assert row["host_update_available"] is True
    assert row["owning_package"] == "tailscale"
    assert row["available_version"] == "1.78.1-1"


def test_match_with_update_available_false_sets_flag_false() -> None:
    """os-pkgs-Entry mit update_available=False -> Spalte False (nicht None).
    ADR-0066: os-pkgs joinen ueber `pkg_name`, NICHT ueber den Pfad (der
    Distro-`Result.Target` ist kein Binary-Pfad)."""
    target = "rocky 9.3"  # os-pkgs-Result.Target ist der Distro-String.
    env = _envelope(
        results=[
            {
                "Target": target,
                "Class": "os-pkgs",
                "Type": "rocky",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-12345",
                        "PkgName": "curl",
                        "InstalledVersion": "7.76.1",
                        "FixedVersion": "7.76.1-26",
                        "Severity": "HIGH",
                    }
                ],
            }
        ]
    )
    host_updates_by_pkg = {
        "curl": HostUpdateEntry.model_validate(
            {"pkg_name": "curl", "owning_package": "curl", "update_available": False}
        )
    }
    rows = _build_rows(env, host_updates_by_pkg=host_updates_by_pkg)
    assert rows[0]["host_update_available"] is False
    assert rows[0]["owning_package"] == "curl"
    assert rows[0]["available_version"] is None


# ---------------------------------------------------------------------------
# Kein Match / leeres Map -> alle drei None
# ---------------------------------------------------------------------------


def test_no_match_leaves_all_three_columns_none() -> None:
    """target_path nicht im Map (anderer Pfad) -> alle drei Spalten None."""
    env = _envelope(results=[_langpkgs_gobinary_result(target="/usr/bin/tailscaled")])
    host_updates_map = {
        "/usr/bin/somethingelse": HostUpdateEntry.model_validate(
            {"path": "/usr/bin/somethingelse", "update_available": True}
        )
    }
    rows = _build_rows(env, host_updates_map=host_updates_map)
    row = rows[0]
    assert row["host_update_available"] is None
    assert row["owning_package"] is None
    assert row["available_version"] is None


def test_empty_map_leaves_all_three_columns_none() -> None:
    env = _envelope(results=[_langpkgs_gobinary_result(target="/usr/bin/tailscaled")])
    rows = _build_rows(env, host_updates_map={})
    row = rows[0]
    assert row["host_update_available"] is None
    assert row["owning_package"] is None
    assert row["available_version"] is None


def test_none_map_leaves_all_three_columns_none() -> None:
    """host_updates_map=None (Default, alter Agent) -> alle drei None."""
    env = _envelope(results=[_langpkgs_gobinary_result(target="/usr/bin/tailscaled")])
    rows = _build_rows(env, host_updates_map=None)
    row = rows[0]
    assert row["host_update_available"] is None
    assert row["owning_package"] is None
    assert row["available_version"] is None


def test_match_uses_pkg_path_over_result_target_as_join_key() -> None:
    """Walker-Analyzer: target_path = PkgPath (nicht Result.Target). Der
    Host-Update-Join muss ueber denselben effektiven Pfad gehen, sonst matcht
    nichts. Map-Key = PkgPath -> Treffer."""
    pkg_path = "opt/app/venv/lib/python3.12/site-packages/requests-2.28.2.dist-info/METADATA"
    env = _envelope(
        results=[
            {
                "Target": "Python",  # nur Oekosystem-Label
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "PkgPath": pkg_path,
                        "InstalledVersion": "2.28.2",
                        "FixedVersion": "2.31.0",
                        "Severity": "MEDIUM",
                    }
                ],
            }
        ]
    )
    # Map auf den Oekosystem-Target gekeyt -> kein Match.
    rows_no_match = _build_rows(
        env,
        host_updates_map={
            "Python": HostUpdateEntry.model_validate({"path": "Python", "update_available": True})
        },
    )
    assert rows_no_match[0]["host_update_available"] is None
    # Map auf den PkgPath gekeyt -> Match.
    rows_match = _build_rows(
        env,
        host_updates_map={
            pkg_path: HostUpdateEntry.model_validate(
                {"path": pkg_path, "owning_package": "python3-requests", "update_available": True}
            )
        },
    )
    assert rows_match[0]["host_update_available"] is True
    assert rows_match[0]["owning_package"] == "python3-requests"


# ---------------------------------------------------------------------------
# Mini-End-to-End: Row-Flag -> fix_lane_for -> Lane
# ---------------------------------------------------------------------------


def test_promoted_langpkgs_row_yields_patch_via_fix_lane_for() -> None:
    """CVE-2026-42504-Fortsetzung: tailscaled lang-pkgs+fix wird via
    host_update_available=True (Tailscale liefert ein gepatchtes rpm) nach
    `patch` promotet — Kontrast zum Default-Verhalten (ohne Flag -> mitigate,
    ADR-0064)."""
    target = "/usr/bin/tailscaled"
    env = _envelope(results=[_langpkgs_gobinary_result(target=target)])
    host_updates_map = {
        target: HostUpdateEntry.model_validate(
            {
                "path": target,
                "owning_package": "tailscale",
                "available_version": "1.78.1-1",
                "update_available": True,
            }
        )
    }
    row = _build_rows(env, host_updates_map=host_updates_map)[0]

    has_fix = bool(row["fixed_version"])
    assert has_fix is True
    # Mit Flag aus der Row -> patch (Promotion).
    lane = fix_lane_for(row["finding_class"], has_fix, row["host_update_available"])
    assert lane == "patch"

    # Kontrast: Default-Verhalten ohne Flag-Argument -> mitigate (ADR-0064).
    lane_ag = fix_lane_for(row["finding_class"], has_fix)
    assert lane_ag == "mitigate"
    assert row["finding_class"] == FindingClass.LANG_PKGS.value


def test_unmatched_langpkgs_row_yields_mitigate_via_fix_lane_for() -> None:
    """Nicht-gematchtes lang-pkgs+fix-Finding: host_update_available=None ->
    mitigate-Fallback (ADR-0064-Default; war upstream in ADR-0061)."""
    env = _envelope(results=[_langpkgs_gobinary_result(target="/usr/bin/tailscaled")])
    row = _build_rows(env, host_updates_map={})[0]

    has_fix = bool(row["fixed_version"])
    lane = fix_lane_for(row["finding_class"], has_fix, row["host_update_available"])
    assert row["host_update_available"] is None
    assert lane == "mitigate"


# ---------------------------------------------------------------------------
# Block AL (ADR-0066): os-pkgs-Join ueber `package_name` (kein Pfad-Join)
# ---------------------------------------------------------------------------


def _ospkgs_kernel_result() -> dict[str, Any]:
    """installonly-Kernel-Leftover: alter el9_7-Kernel als Trivy-Finding mit
    FixedVersion el9_8 (der laufende Kernel uebererfuellt den Fix -> Stale-FP).
    Result.Target ist der Distro-String, NICHT ein Binary-Pfad."""
    return {
        "Target": "almalinux 9.8",
        "Class": "os-pkgs",
        "Type": "almalinux",
        "Vulnerabilities": [
            {
                "VulnerabilityID": "CVE-2025-12345",
                "PkgName": "kernel",
                "InstalledVersion": "5.14.0-611.54.6.el9_7",
                "FixedVersion": "5.14.0-687.12.1.el9_8",
                "Severity": "HIGH",
            }
        ],
    }


def test_ospkgs_joins_host_update_via_package_name() -> None:
    """os-pkgs-Finding zieht `host_update_available` ueber `package_name` aus
    der pkg-Map (NICHT ueber den Pfad). ADR-0066: `host_update=none` (kein
    dnf-Update) korroboriert den Stale-Artifact-FP."""
    env = _envelope(results=[_ospkgs_kernel_result()])
    host_updates_by_pkg = {
        "kernel": HostUpdateEntry.model_validate(
            {"pkg_name": "kernel", "owning_package": "kernel", "update_available": False}
        )
    }
    rows = _build_rows(env, host_updates_by_pkg=host_updates_by_pkg)
    assert len(rows) == 1
    row = rows[0]
    assert row["package_name"] == "kernel"
    assert row["host_update_available"] is False
    assert row["owning_package"] == "kernel"


def test_ospkgs_does_not_join_via_path_map() -> None:
    """Ein Pfad-gekeyter Eintrag matcht ein os-pkgs-Finding NICHT — os-pkgs
    geht ausschliesslich ueber den Paketnamen-Join (ADR-0066)."""
    env = _envelope(results=[_ospkgs_kernel_result()])
    rows = _build_rows(
        env,
        host_updates_map={
            "almalinux 9.8": HostUpdateEntry.model_validate(
                {"path": "almalinux 9.8", "update_available": True}
            )
        },
    )
    assert rows[0]["host_update_available"] is None
    assert rows[0]["owning_package"] is None


def test_ospkgs_no_entry_leaves_flag_none_forward_compat() -> None:
    """Alter Agent (kein os-pkgs-Eintrag): Kernel-Finding -> host_update=None.
    Der Reviewer faellt auf den reinen Versionsvergleich zurueck (Forward-
    Compat, ADR-0066)."""
    env = _envelope(results=[_ospkgs_kernel_result()])
    rows = _build_rows(env, host_updates_by_pkg={})
    assert rows[0]["host_update_available"] is None


@pytest.mark.parametrize("flag", [True, False, None])
def test_ospkgs_lane_stays_patch_regardless_of_flag(flag: bool | None) -> None:
    """Lane-Invarianz (ADR-0066 DoD): ein os-pkgs+fix-Finding bleibt `patch`
    unabhaengig vom Host-Update-Flag — der os-pkgs-Short-Circuit in
    `fix_lane_for` liegt VOR der Flag-Auswertung. Das Flag ist fuer os-pkgs
    reines Reviewer-Enrichment, kein Lane-Input."""
    env = _envelope(results=[_ospkgs_kernel_result()])
    by_pkg: dict[str, HostUpdateEntry] = {}
    if flag is not None:
        by_pkg = {
            "kernel": HostUpdateEntry.model_validate(
                {"pkg_name": "kernel", "update_available": flag}
            )
        }
    row = _build_rows(env, host_updates_by_pkg=by_pkg)[0]
    has_fix = bool(row["fixed_version"])
    assert has_fix is True
    lane = fix_lane_for(row["finding_class"], has_fix, row["host_update_available"])
    assert lane == "patch"
    assert row["finding_class"] == FindingClass.OS_PKGS.value
