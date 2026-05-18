"""Adversarial: Pass-1 lehnt unvollstaendige Antworten ab (ADR-0023).

Jede Input-`finding_id` MUSS entweder in einer Group oder im `ungrouped`-
Array landen. Wenn der LLM Findings einfach vergisst, ist das semantisch
eine Halluzinations-Luecke — `_validate_pass1_response` wirft.
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


pytestmark = pytest.mark.usefixtures("app_env")


def test_validate_pass1_rejects_completely_missing_findings() -> None:
    """3 Findings im Input, LLM antwortet nur fuer 1 — Reject."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    findings = [_f(1), _f(2), _f(3)]
    payload = {
        "groups": [
            {"label": "g", "finding_ids": [1], "match_rules": {}},
        ],
        "ungrouped": [],
    }
    with pytest.raises(LLMInvalidResponseError, match="nicht zugeordnet"):
        reviewer._validate_pass1_response(payload, findings)


def test_validate_pass1_accepts_all_in_ungrouped() -> None:
    """Alle Findings im `ungrouped`-Array — zulaessig, kein Reject."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    findings = [_f(1), _f(2)]
    payload = {
        "groups": [],
        "ungrouped": [1, 2],
    }
    # Darf NICHT werfen.
    result = reviewer._validate_pass1_response(payload, findings)
    assert result.groups == []
    assert sorted(result.ungrouped_finding_ids) == [1, 2]


def test_validate_pass1_rejects_partial_groups_and_partial_ungrouped() -> None:
    """4 Findings; 1 in Group, 2 in ungrouped — 1 fehlt komplett."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    findings = [_f(1), _f(2), _f(3), _f(4)]
    payload = {
        "groups": [
            {"label": "g", "finding_ids": [1], "match_rules": {}},
        ],
        "ungrouped": [2, 3],
    }
    with pytest.raises(LLMInvalidResponseError, match="nicht zugeordnet"):
        reviewer._validate_pass1_response(payload, findings)


def test_validate_pass1_rejects_id_in_group_and_ungrouped() -> None:
    """Eine `finding_id` darf nicht in Group UND ungrouped sein."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    findings = [_f(1), _f(2)]
    payload = {
        "groups": [
            {"label": "g", "finding_ids": [1, 2], "match_rules": {}},
        ],
        "ungrouped": [1],
    }
    with pytest.raises(LLMInvalidResponseError, match="sowohl"):
        reviewer._validate_pass1_response(payload, findings)
