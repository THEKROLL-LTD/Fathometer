"""Adversarial: Pass-2 `reason` muss NUL-frei und <= 256 chars sein (ADR-0023).

NUL-Bytes wuerden in Templates und Audit-Logs Probleme machen
(C-String-Truncation in Tools, Postgres-Text-Spalten erlauben sie zwar,
aber das Audit-JSON serialisiert kaputt).

Reason ueber 256 chars sprengt das ADR-0023-Hardlimit und wuerde die UI-
Card unleserlich machen.
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
from app.services.llm_risk_reviewer import (
    MAX_REASON_LEN,
    LLMInvalidResponseError,
    LLMRiskReviewer,
)


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
    "bad_reason",
    [
        pytest.param("patched\x00; rm -rf /", id="nul-with-shell"),
        pytest.param("\x00", id="lone-nul"),
        pytest.param("safe text\x00", id="trailing-nul"),
        pytest.param("\x00leading", id="leading-nul"),
        pytest.param("middle\x00middle", id="middle-nul"),
    ],
)
def test_validate_pass2_rejects_nul_byte_in_reason(bad_reason: str) -> None:
    """NUL-Byte irgendwo im Reason → Reject."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "action_type": "patch",
                "worst_finding_id": None,
                "reason": bad_reason,
            }
        ]
    }
    with pytest.raises(LLMInvalidResponseError, match="NUL-Byte"):
        reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])])


@pytest.mark.parametrize(
    ("reason_len", "expect_reject"),
    [
        pytest.param(MAX_REASON_LEN + 1, True, id="just-over-limit"),
        pytest.param(MAX_REASON_LEN + 100, True, id="100-over"),
        pytest.param(1024 * 4, True, id="4kib"),
        pytest.param(MAX_REASON_LEN, False, id="exact-limit"),
        pytest.param(MAX_REASON_LEN - 1, False, id="one-under-limit"),
        pytest.param(1, False, id="single-char"),
    ],
)
def test_validate_pass2_reason_length_boundary(reason_len: int, expect_reject: bool) -> None:
    """Genau am Limit OK, ueber dem Limit Reject."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "monitor",
                "action_type": "watch",
                "worst_finding_id": None,
                "reason": "x" * reason_len,
            }
        ]
    }
    if expect_reject:
        with pytest.raises(LLMInvalidResponseError, match=str(MAX_REASON_LEN)):
            reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])])
    else:
        result = reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])])
        assert len(result.evaluations[0].reason) == reason_len


def test_validate_pass2_rejects_non_string_reason() -> None:
    """Reason muss String sein — int/None werden geblockt."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "monitor",
                "action_type": "watch",
                "worst_finding_id": None,
                "reason": 42,
            }
        ]
    }
    with pytest.raises(LLMInvalidResponseError, match="kein String"):
        reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])])
