"""Adversarial: Pass-2 `worst_finding_id` muss in der Group sein (ADR-0023).

Wenn der LLM eine ID liefert, die nicht zur betroffenen Group gehoert,
wuerde der Worker beim Persistieren auf einen Finding referenzieren der
gar nicht Teil der Bewertung war. Das ist semantisch eine Halluzination
und MUSS abgewiesen werden.

`null` als `worst_finding_id` ist ausdruecklich erlaubt (kein klarer Worst).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models import (
    ApplicationGroup,
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Severity,
)
from app.services.llm_risk_reviewer import LLMInvalidResponseError, LLMRiskReviewer


class _StubClient:
    def __init__(self) -> None:
        self._sdk = None
        self.model = "stub"


def _f(fid: int) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=fid,
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key=f"CVE-2024-{fid:04d}",
        package_name="pkg",
        installed_version="1.0",
        severity=Severity.HIGH,
        attack_vector=AttackVector.UNKNOWN,
        status=FindingStatus.OPEN,
        is_kev=False,
        first_seen_at=now,
        last_seen_at=now,
        severity_by_provider={"nvd": "high"},
        vendor_status="affected",
    )


def _g() -> ApplicationGroup:
    return ApplicationGroup(
        id=1,
        label="openssl",
        path_prefixes=[],
        pkg_name_exact=[],
        pkg_name_glob=[],
        pkg_purl_pattern=[],
        source="llm",
    )


pytestmark = pytest.mark.usefixtures("app_env")


@pytest.mark.parametrize(
    "bad_worst",
    [
        pytest.param(999, id="completely-unrelated"),
        pytest.param(-1, id="negative"),
        pytest.param(0, id="zero"),
        pytest.param(99999999, id="huge"),
    ],
)
def test_validate_pass2_rejects_worst_finding_not_in_group(bad_worst: int) -> None:
    """Worst-ID nicht in Group → Reject."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "action_type": "patch",
                "worst_finding_id": bad_worst,
                "reason": "x",
            }
        ]
    }
    findings = [_f(1), _f(2), _f(3)]
    with pytest.raises(LLMInvalidResponseError, match="Mitglied"):
        reviewer._validate_pass2_response(payload, [(_g(), findings)])


def test_validate_pass2_rejects_worst_finding_from_other_group() -> None:
    """Worst-ID gehoert zu einer ANDEREN Group — auch das ist verboten."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    g_a = _g()
    g_b = ApplicationGroup(
        id=2,
        label="bash",
        path_prefixes=[],
        pkg_name_exact=[],
        pkg_name_glob=[],
        pkg_purl_pattern=[],
        source="llm",
    )
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "action_type": "patch",
                "worst_finding_id": 5,  # 5 ist in bash-Group, nicht in openssl
                "reason": "x",
            }
        ]
    }
    with pytest.raises(LLMInvalidResponseError, match="Mitglied"):
        reviewer._validate_pass2_response(payload, [(g_a, [_f(1)]), (g_b, [_f(5)])])


def test_validate_pass2_accepts_null_worst_finding() -> None:
    """`null` ist erlaubt — kein klarer Worst."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "monitor",
                "action_type": "watch",
                "worst_finding_id": None,
                "reason": "watch",
            }
        ]
    }
    result = reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])])
    assert result.evaluations[0].worst_finding_id is None


def test_validate_pass2_rejects_non_integer_worst_finding() -> None:
    """String/Boolean als worst_finding_id → Reject."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "action_type": "patch",
                "worst_finding_id": "1",
                "reason": "x",
            }
        ]
    }
    with pytest.raises(LLMInvalidResponseError, match="Integer"):
        reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])])
