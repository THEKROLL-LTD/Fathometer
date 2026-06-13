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
`patch` ergibt und der nicht-gematchte `upstream` (Single-Source der Lane).

Vorlage: `tests/services/test_findings_ingest_cause_mapping.py`
(`_build_rows_from_envelope`-Pattern).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

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
    """Entry mit update_available=False -> Spalte False (nicht None) —
    der Agent hat das Paket aufgeloest, aber kein Update steht bereit."""
    target = "/usr/bin/curl"
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
    host_updates_map = {
        target: HostUpdateEntry.model_validate(
            {"path": target, "owning_package": "curl", "update_available": False}
        )
    }
    rows = _build_rows(env, host_updates_map=host_updates_map)
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
    `patch` promotet — Kontrast zum AG-Verhalten (ohne Flag -> upstream)."""
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

    # Kontrast: AG-Verhalten ohne Flag-Argument -> upstream.
    lane_ag = fix_lane_for(row["finding_class"], has_fix)
    assert lane_ag == "upstream"
    assert row["finding_class"] == FindingClass.LANG_PKGS.value


def test_unmatched_langpkgs_row_yields_upstream_via_fix_lane_for() -> None:
    """Nicht-gematchtes lang-pkgs+fix-Finding: host_update_available=None ->
    upstream-Fallback (ADR-0061-Default)."""
    env = _envelope(results=[_langpkgs_gobinary_result(target="/usr/bin/tailscaled")])
    row = _build_rows(env, host_updates_map={})[0]

    has_fix = bool(row["fixed_version"])
    lane = fix_lane_for(row["finding_class"], has_fix, row["host_update_available"])
    assert row["host_update_available"] is None
    assert lane == "upstream"
