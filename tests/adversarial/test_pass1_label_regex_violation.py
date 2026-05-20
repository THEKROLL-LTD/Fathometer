"""Adversarial: Pass-1 Group-Labels muessen `LABEL_PATTERN` matchen (ADR-0023).

Whitelist: `^[a-z0-9][a-z0-9._-]{0,63}$` — kleinbuchstaben, Ziffern, `._-`,
erstes Zeichen alphanumerisch, max 64 chars. Alles andere → Reject.

v0.9.5: Der Punkt ist Teil der Whitelist (Spec-Quelle:
``docs/blocks/P-evidence/prompt-pass1-final.md`` Z. 63). Distro-Pakete mit
Version im Paketnamen (z.B. ``linux-modules-5.15.0-177-generic``) muessen
zulaessig sein.

Damit der LLM-Reviewer keine Pfad-Traversal/Script-Injection-faehigen
Labels in die UI bringt (Label landet in Cards, Templates, Audit-Metadata).
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


@pytest.mark.parametrize(
    "bad_label",
    [
        pytest.param("K3s Server", id="caps-and-space"),
        pytest.param("k3s server", id="space"),
        pytest.param("k3s/server", id="slash"),
        pytest.param("", id="empty"),
        pytest.param("-leading-dash", id="leading-dash"),
        pytest.param("_leading-underscore", id="leading-underscore"),
        pytest.param("foo<script>", id="script-tag"),
        pytest.param("a" * 65, id="too-long-65"),
        pytest.param("foo bar", id="space-mid"),
        pytest.param("foo:bar", id="colon"),
        pytest.param("foo\x00bar", id="nul-byte"),
        pytest.param("foo\nbar", id="newline"),
        pytest.param("..//etc/passwd", id="path-traversal"),
        pytest.param("fooö", id="non-ascii-umlaut"),
    ],
)
def test_validate_pass1_rejects_label_regex_violation(bad_label: str) -> None:
    """Jeder dieser Labels muss LLMInvalidResponseError werfen."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "groups": [
            {"label": bad_label, "finding_ids": [1], "match_rules": {}},
        ],
        "ungrouped": [],
    }
    with pytest.raises(LLMInvalidResponseError, match="Regex"):
        reviewer._validate_pass1_response(payload, [_f(1)])


@pytest.mark.parametrize(
    "good_label",
    [
        "k3s",
        "openssh-server",
        "a",
        "a" * 64,
        "ubuntu_pkg",
        "0",
        "0abc",
        # v0.9.5: Punkt-haltige Labels (Distro-Pakete mit Version im Namen).
        "linux-modules-5.15.0-177-generic",
        "foo.bar",
        "node.js",
        "lib.so.6",
    ],
)
def test_validate_pass1_accepts_compliant_labels(good_label: str) -> None:
    """Whitelist-konforme Labels werden angenommen."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "groups": [
            {"label": good_label, "finding_ids": [1], "match_rules": {}},
        ],
        "ungrouped": [],
    }
    result = reviewer._validate_pass1_response(payload, [_f(1)])
    assert result.groups[0].label == good_label


def test_label_pattern_accepts_dots() -> None:
    """v0.9.5: Punkt-haltige Labels werden vom Pattern akzeptiert."""
    from app.services.llm_risk_reviewer import LABEL_PATTERN

    assert LABEL_PATTERN.match("linux-modules-5.15.0-177-generic") is not None
    assert LABEL_PATTERN.match("foo.bar") is not None
    assert LABEL_PATTERN.match("a.b.c") is not None


def test_label_pattern_still_rejects_invalid_chars() -> None:
    """v0.9.5: Trotz Punkt-Erweiterung bleiben andere Zeichen verboten."""
    from app.services.llm_risk_reviewer import LABEL_PATTERN

    assert LABEL_PATTERN.match("foo bar") is None  # Space
    assert LABEL_PATTERN.match("FooBar") is None  # Uppercase
    assert LABEL_PATTERN.match("foo!") is None  # Sonderzeichen
    assert LABEL_PATTERN.match("_foo") is None  # leading underscore
    assert LABEL_PATTERN.match(".foo") is None  # leading dot (erstes Zeichen muss alnum)
    assert LABEL_PATTERN.match("-foo") is None  # leading dash


def test_validate_pass1_rejects_duplicate_labels() -> None:
    """Zwei Groups mit demselben Label sind ein Validierungs-Fehler."""
    reviewer = LLMRiskReviewer(client=_StubClient())  # type: ignore[arg-type]
    payload = {
        "groups": [
            {"label": "k3s", "finding_ids": [1], "match_rules": {}},
            {"label": "k3s", "finding_ids": [2], "match_rules": {}},
        ],
        "ungrouped": [],
    }
    with pytest.raises(LLMInvalidResponseError, match="doppeltes"):
        reviewer._validate_pass1_response(payload, [_f(1), _f(2)])
