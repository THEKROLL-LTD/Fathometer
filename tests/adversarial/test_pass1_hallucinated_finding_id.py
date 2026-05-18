"""Adversarial: Pass-1 lehnt halluzinierte finding_ids ab (ADR-0023).

Wenn der LLM eine `finding_id` in einer Group meldet, die nicht in der
Input-Liste war, MUSS `_validate_pass1_response` `LLMInvalidResponseError`
werfen — sonst kann die Persistenz-Schicht Findings IDs einer falschen
Group zuordnen.

Parametrisierte Bad-Inputs:
* einzelne halluzinierte ID
* halluzinierte ID gemischt mit echten
* halluzinierte ID im `ungrouped`-Array
* negative IDs (im Schema int erlaubt, im Validator nicht in input_ids)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Severity,
)
from app.services.llm_risk_reviewer import (
    LLMInvalidResponseError,
    LLMRiskReviewer,
)


class _StubClient:
    """Minimaler Stub — `_validate_pass1_response` braucht keinen Client-Call."""

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


@pytest.mark.parametrize(
    ("response_payload", "expected_match"),
    [
        pytest.param(
            {
                "groups": [
                    {"label": "a", "finding_ids": [1, 999], "match_rules": {}},
                ],
                "ungrouped": [],
            },
            "halluzinierte",
            id="single-hallucinated-in-group",
        ),
        pytest.param(
            {
                "groups": [
                    {"label": "a", "finding_ids": [-1], "match_rules": {}},
                ],
                "ungrouped": [],
            },
            "halluzinierte",
            id="negative-id-as-hallucination",
        ),
        pytest.param(
            {
                "groups": [
                    {"label": "a", "finding_ids": [1, 2], "match_rules": {}},
                ],
                "ungrouped": [999],
            },
            "halluzinierte ungrouped",
            id="hallucinated-in-ungrouped",
        ),
        pytest.param(
            {
                "groups": [
                    {"label": "a", "finding_ids": [1, 2, 1000000], "match_rules": {}},
                ],
                "ungrouped": [],
            },
            "halluzinierte",
            id="huge-finding-id",
        ),
    ],
)
def test_validate_pass1_rejects_hallucinated_finding_ids(
    response_payload: dict[str, Any], expected_match: str
) -> None:
    """Halluzinierte finding_ids fuehren zu `LLMInvalidResponseError`."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    findings = [_f(1), _f(2)]
    with pytest.raises(LLMInvalidResponseError, match=expected_match):
        reviewer._validate_pass1_response(response_payload, findings)


def test_validate_pass1_rejects_mixed_real_and_hallucinated() -> None:
    """Echte und halluzinierte IDs gemischt — Validator muss trotzdem ablehnen."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    findings = [_f(1), _f(2), _f(3)]
    payload = {
        "groups": [
            {"label": "a", "finding_ids": [1, 2, 3, 4], "match_rules": {}},
        ],
        "ungrouped": [],
    }
    with pytest.raises(LLMInvalidResponseError, match="halluzinierte"):
        reviewer._validate_pass1_response(payload, findings)
