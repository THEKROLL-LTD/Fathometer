# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Block AL (ADR-0066) — Pass-2-Prompt-Anreicherung gegen Trivy-Stale-Artifact-FP.

Pure-Unit-Tests (reine String-Inspektion des gerenderten Prompts + Validator-
Aufrufe; KEIN LLM-Call, kein DB-Roundtrip). Deckt die ADR-0066-§1-Aenderungen:

* Per-Finding-Zeile traegt ``vulnerable=<version>`` (NULL -> ``vulnerable=n/a``;
  TICKET-017/ADR-0068 renamed ``installed=`` -> ``vulnerable=``).
* Per-Finding-Zeile traegt ``host_update=<available|none>``
  (True -> available, False/None -> none).
* ``_render_host_context`` traegt ``kernel (running): <version>`` wenn gesetzt,
  laesst die Zeile bei NULL weg (kein leerer Marker).
* System-Prompt enthaelt den STALE-ARTIFACT-Correction-Path (Wortlaut-Kern,
  TICKET-017: kernel comparator "at or above" gegen den running kernel).
* ``PASS2_PROMPT_VERSION == 7``.
* Reviewer-Verdikt: ``noise`` besteht die Validierung im patch-Call (Stale-FP
  -> noise); ``act`` bleibt im patch-Call ebenfalls gueltig (fix nicht gebootet).
* Forward-Compat / Regression des konkreten el9_7-Leftover-Falls.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from app.services.llm_prompts import PASS2_PROMPT_VERSION, PASS2_SYSTEM_PROMPT
from app.services.llm_risk_reviewer import LLMRiskReviewer
from tests.services.test_llm_risk_reviewer import _make_group, _MockClient

pytestmark = pytest.mark.usefixtures("app_env")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_finding(
    fid: int,
    *,
    package_name: str = "kernel",
    installed_version: str | None = "5.14.0-611.54.6.el9_7",
    fixed_version: str | None = "5.14.0-687.12.1.el9_8",
    host_update_available: bool | None = None,
    finding_class: FindingClass = FindingClass.OS_PKGS,
) -> Finding:
    now = datetime.now(tz=UTC)
    return Finding(
        id=fid,
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=finding_class,
        identifier_key=f"CVE-2025-{fid:04d}",
        package_name=package_name,
        installed_version=installed_version,
        fixed_version=fixed_version,
        severity=Severity.HIGH,
        attack_vector=AttackVector.NETWORK,
        status=FindingStatus.OPEN,
        is_kev=False,
        first_seen_at=now,
        last_seen_at=now,
        host_update_available=host_update_available,
        severity_by_provider={"nvd": "high"},
        vendor_status="affected",
    )


def _make_server(kernel_version: str | None = "5.14.0-687.15.1.el9_8") -> Server:
    s = Server(
        id=1,
        name="k3s-sv-1",
        api_key_hash="x" * 64,
        expected_scan_interval_h=24,
        os_family="almalinux",
        os_version="9.8",
        os_pretty_name="AlmaLinux 9.8",
        kernel_version=kernel_version,
    )
    s.listeners = []  # type: ignore[attr-defined]
    s.processes = []  # type: ignore[attr-defined]
    s.kernel_modules = []  # type: ignore[attr-defined]
    s.services = []  # type: ignore[attr-defined]
    s.tag_links = []  # type: ignore[attr-defined]
    return s


def _reviewer() -> LLMRiskReviewer:
    return LLMRiskReviewer(client=_MockClient({"evaluations": []}))


def _render(server: Server, findings: list[Finding], *, fix_lane: str = "patch") -> str:
    rv = _reviewer()
    group = _make_group("kernel", [f.id for f in findings])
    return rv._render_pass2_prompt(server, [(group, findings)], fix_lane=fix_lane)


# ---------------------------------------------------------------------------
# PASS2_PROMPT_VERSION
# ---------------------------------------------------------------------------


def test_pass2_prompt_version_is_7() -> None:
    # TICKET-017 / ADR-0068: 6 -> 7 (vulnerable=/fixed= rename + STALE-ARTIFACT
    # kernel-comparator rewrite).
    assert PASS2_PROMPT_VERSION == 7


# ---------------------------------------------------------------------------
# Per-Finding: vulnerable= / host_update= (TICKET-017 rename of installed=)
# ---------------------------------------------------------------------------


def test_per_finding_line_carries_vulnerable_version() -> None:
    f = _make_finding(1, installed_version="5.14.0-611.54.6.el9_7")
    prompt = _render(_make_server(), [f])
    assert "vulnerable=5.14.0-611.54.6.el9_7" in prompt
    # The old role-confusing label is gone.
    assert "installed=" not in prompt


def test_missing_vulnerable_version_renders_na() -> None:
    f = _make_finding(1, installed_version=None)
    prompt = _render(_make_server(), [f])
    assert "vulnerable=n/a" in prompt


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        (True, "host_update=available"),
        (False, "host_update=none"),
        (None, "host_update=none"),
    ],
)
def test_host_update_flag_matrix(flag: bool | None, expected: str) -> None:
    f = _make_finding(1, host_update_available=flag)
    prompt = _render(_make_server(), [f])
    assert expected in prompt
    # Gegenprobe: die jeweils andere Auspraegung darf nicht erscheinen.
    other = "host_update=available" if expected == "host_update=none" else "host_update=none"
    assert other not in prompt


# ---------------------------------------------------------------------------
# Host-Context: kernel (running):
# ---------------------------------------------------------------------------


def test_host_context_renders_running_kernel_when_set() -> None:
    prompt = _render(_make_server(kernel_version="5.14.0-687.15.1.el9_8"), [_make_finding(1)])
    assert "kernel (running): 5.14.0-687.15.1.el9_8" in prompt


def test_host_context_omits_kernel_line_when_null() -> None:
    prompt = _render(_make_server(kernel_version=None), [_make_finding(1)])
    assert "kernel (running):" not in prompt


# ---------------------------------------------------------------------------
# System-Prompt: STALE-ARTIFACT-Correction-Path
# ---------------------------------------------------------------------------


def test_system_prompt_contains_stale_artifact_correction_path() -> None:
    assert "STALE-ARTIFACT" in PASS2_SYSTEM_PROMPT
    assert "stale-artifact false positive" in PASS2_SYSTEM_PROMPT
    # Kern-Aussagen aus ADR-0066 §1 (Zeilenumbrueche zwischen Tokens moeglich,
    # daher Token-weise statt als zusammenhaengender Satz pruefen).
    assert "Three correction paths" in PASS2_SYSTEM_PROMPT
    assert "host_update=none" in PASS2_SYSTEM_PROMPT
    # TICKET-017 / ADR-0068: the kernel comparator wording was rewritten — the
    # model now compares fixed against the running kernel with "at or above"
    # semantics (replaces the old "corroborates" / "NEWER than the running").
    assert "running kernel" in PASS2_SYSTEM_PROMPT
    assert "at or above" in PASS2_SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Reviewer-Verdikt (Validator-Pfad, kein Live-LLM)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_noise_verdict_passes_validation_in_patch_call() -> None:
    """running >= fixed (Stale-FP): das Modell darf `noise` setzen und besteht
    die Validierung im patch-Call (noise ist in jeder Lane gueltig)."""
    server = _make_server(kernel_version="5.14.0-687.15.1.el9_8")
    f = _make_finding(1, host_update_available=False)
    group = _make_group("kernel", [1])
    client = _MockClient(
        {
            "evaluations": [
                {
                    "group_label": "kernel",
                    "risk_band": "noise",
                    "worst_finding_id": 1,
                    "reason": "stale el9_7 kernel leftover; running el9_8 >= fixed; "
                    "host_update=none -> Trivy stale-artifact FP",
                }
            ]
        }
    )
    rv = LLMRiskReviewer(client=client)
    result, _meta = await rv.pass2_evaluate_groups(server, [(group, [f])], fix_lane="patch")
    assert result.evaluations[0].risk_band == "noise"


@pytest.mark.asyncio
async def test_act_verdict_stays_actionable_when_fix_not_yet_booted() -> None:
    """running < fixed (Fix installiert/verfuegbar, aber nicht gebootet): bleibt
    actionable — `act` ist im patch-Call gueltig (kein Stale-FP)."""
    server = _make_server(kernel_version="5.14.0-611.54.6.el9_7")  # alt, < fixed
    f = _make_finding(1, host_update_available=True)
    group = _make_group("kernel", [1])
    client = _MockClient(
        {
            "evaluations": [
                {
                    "group_label": "kernel",
                    "risk_band": "act",
                    "worst_finding_id": 1,
                    "reason": "running kernel < fixed; patch available, apply + reboot",
                }
            ]
        }
    )
    rv = LLMRiskReviewer(client=client)
    result, _meta = await rv.pass2_evaluate_groups(server, [(group, [f])], fix_lane="patch")
    assert result.evaluations[0].risk_band == "act"


# ---------------------------------------------------------------------------
# Regression: der konkrete k3s-sv-1-Fall (alle drei Signale im Prompt)
# ---------------------------------------------------------------------------


def test_concrete_stale_kernel_case_renders_all_three_signals() -> None:
    """el9_7-Kernel-Leftover, laufend el9_8 >= fixed, host_update=none: the
    prompt carries all signals (fixed=, vulnerable=, kernel (running):,
    host_update=none) so the model can derive `noise`. TICKET-017 renamed the
    per-finding labels to vulnerable=/fixed=."""
    server = _make_server(kernel_version="5.14.0-687.15.1.el9_8")
    f = _make_finding(
        1,
        installed_version="5.14.0-611.54.6.el9_7",
        fixed_version="5.14.0-687.12.1.el9_8",
        host_update_available=False,
    )
    prompt = _render(server, [f])
    assert "fixed=5.14.0-687.12.1.el9_8" in prompt
    assert "vulnerable=5.14.0-611.54.6.el9_7" in prompt
    assert "kernel (running): 5.14.0-687.15.1.el9_8" in prompt
    assert "host_update=none" in prompt
