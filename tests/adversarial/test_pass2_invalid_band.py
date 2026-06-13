"""Adversarial: Pass-2 `risk_band` muss in `VALID_RISK_BANDS` sein (ADR-0023).

`pending` und `unknown` sind explizit verboten — sie sind reine Pre-Triage-
Werte aus Block O. Der LLM darf nur eines aus
`{escalate, act, mitigate, monitor, noise}` liefern.

Doppelte Defense: Pydantic-Literal blockt zwar bereits viele Werte, der
Validator-Pfad pruft aber explizit ueber `VALID_RISK_BANDS`. Beides
testen wir hier zusammen.
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
    VALID_RISK_BANDS,
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


def _g(label: str = "openssl") -> ApplicationGroup:
    return ApplicationGroup(
        id=1,
        label=label,
        path_prefixes=[],
        pkg_name_exact=[],
        pkg_name_glob=[],
        pkg_purl_pattern=[],
        source="llm",
    )


pytestmark = pytest.mark.usefixtures("app_env")


@pytest.mark.parametrize(
    "bad_band",
    [
        pytest.param("pending", id="pending-explicit-veto"),
        pytest.param("unknown", id="unknown-explicit-veto"),
        pytest.param("", id="empty-string"),
        pytest.param("foo", id="completely-foreign"),
        pytest.param("ESCALATE", id="upper-case"),
        pytest.param("escalate ", id="trailing-space"),
        pytest.param("act/now", id="injected-slash"),
        pytest.param("critical", id="alternate-common-name"),
        pytest.param("info", id="another-syslog-style"),
    ],
)
def test_validate_pass2_rejects_invalid_risk_band(bad_band: str) -> None:
    """`risk_band` ausserhalb der Whitelist → Reject."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": bad_band,
                "worst_finding_id": None,
                "reason": "x",
            }
        ]
    }
    with pytest.raises(LLMInvalidResponseError, match="risk_band"):
        reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])])


def test_valid_risk_bands_does_not_contain_pending_or_unknown() -> None:
    """Whitelist-Konstante darf NICHT die Pre-Triage-Werte enthalten."""
    assert "pending" not in VALID_RISK_BANDS
    assert "unknown" not in VALID_RISK_BANDS


@pytest.mark.parametrize("good_band", sorted(VALID_RISK_BANDS))
def test_validate_pass2_accepts_whitelisted_bands(good_band: str) -> None:
    """Jeder Whitelist-Eintrag wird angenommen (ADR-0053: kein action_type mehr).

    Ohne ``fix_lane`` (Uebergangs-Zustand) gilt keine Lane-Restriktion — alle
    Bands sind erlaubt. ``mitigate`` mappt intern auf ``escalate`` (Legacy).
    """
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": good_band,
                "worst_finding_id": None,
                "reason": "x",
            }
        ]
    }
    result = reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])])
    # ``mitigate`` mappt intern auf ``escalate`` (Legacy-Path).
    expected = "escalate" if good_band == "mitigate" else good_band
    assert result.evaluations[0].risk_band == expected


def test_validate_pass2_rejects_act_in_mitigate_lane() -> None:
    """ADR-0053: ``act`` ist patch-only — im mitigate-Call → Reject."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "worst_finding_id": None,
                "reason": "x",
            }
        ]
    }
    with pytest.raises(LLMInvalidResponseError, match="act"):
        reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])], fix_lane="mitigate")


def test_validate_pass2_accepts_act_in_patch_lane() -> None:
    """ADR-0053: ``act`` in der patch-Lane ist gueltig."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "worst_finding_id": None,
                "reason": "x",
            }
        ]
    }
    result = reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])], fix_lane="patch")
    assert result.evaluations[0].risk_band == "act"


@pytest.mark.parametrize("band", ["escalate", "monitor", "noise"])
def test_validate_pass2_accepts_non_act_bands_in_mitigate_lane(band: str) -> None:
    """ADR-0053: mitigate-Lane erlaubt escalate/monitor/noise."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": band,
                "worst_finding_id": None,
                "reason": "x",
            }
        ]
    }
    result = reviewer._validate_pass2_response(payload, [(_g(), [_f(1)])], fix_lane="mitigate")
    assert result.evaluations[0].risk_band == band


# ---------------------------------------------------------------------------
# ADR-0064: die ``upstream``-Lane ist zurueckgenommen und in ``mitigate``
# kollabiert. lang-pkgs-Findings MIT Fix liegen jetzt in der mitigate-Lane;
# ``act`` (patch-only) wird dort weiterhin abgelehnt — abgedeckt von
# ``test_validate_pass2_rejects_act_in_mitigate_lane`` /
# ``test_validate_pass2_accepts_non_act_bands_in_mitigate_lane`` oben. Es gibt
# keine separaten upstream-Lane-Tests mehr.
# ---------------------------------------------------------------------------
