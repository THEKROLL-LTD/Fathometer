"""Adversarial: Pass-2 lehnt halluzinierte group_labels ab (ADR-0023).

`_validate_pass2_response` muss `group_label` gegen die Input-Group-Liste
matchen. Antwortet der LLM mit einem Label das er sich ausgedacht hat,
darf der Reviewer es NICHT weiter geben — sonst persistiert der Worker
die Bewertung als `worst_finding_id` auf einer falschen Group.
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


def _g(label: str, gid: int = 1) -> ApplicationGroup:
    return ApplicationGroup(
        id=gid,
        label=label,
        explanation=None,
        path_prefixes=[],
        pkg_name_exact=[],
        pkg_name_glob=[],
        pkg_purl_pattern=[],
        source="llm",
    )


pytestmark = pytest.mark.usefixtures("app_env")


@pytest.mark.parametrize(
    "bad_label",
    [
        "ghost-group",
        "opens5l",  # typo
        "k3s-with-suffix",
        "",  # leer
        "completely-unrelated",
    ],
)
def test_validate_pass2_rejects_hallucinated_group_label(bad_label: str) -> None:
    """Label nicht in der Input-Liste → Reject."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": bad_label,
                "risk_band": "act",
                "worst_finding_id": None,
                "reason": "x",
            }
        ]
    }
    with pytest.raises(LLMInvalidResponseError, match=r"halluzinierter|group_label"):
        reviewer._validate_pass2_response(payload, [(_g("openssl"), [_f(1)])])


def test_validate_pass2_rejects_duplicate_group_labels() -> None:
    """Zwei evaluations mit demselben Label sind ein Validierungs-Fehler."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "action_type": "patch",
                "worst_finding_id": None,
                "reason": "x",
            },
            {
                "group_label": "openssl",
                "risk_band": "monitor",
                "action_type": "watch",
                "worst_finding_id": None,
                "reason": "y",
            },
        ]
    }
    with pytest.raises(LLMInvalidResponseError, match="doppelter"):
        reviewer._validate_pass2_response(payload, [(_g("openssl"), [_f(1)])])


def test_validate_pass2_rejects_non_string_label() -> None:
    """Label muss ein String sein — int/None werden geblockt."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": 42,
                "risk_band": "act",
                "worst_finding_id": None,
                "reason": "x",
            }
        ]
    }
    with pytest.raises(LLMInvalidResponseError, match="kein String"):
        reviewer._validate_pass2_response(payload, [(_g("openssl"), [_f(1)])])
