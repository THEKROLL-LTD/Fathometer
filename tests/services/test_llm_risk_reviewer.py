"""Tests fuer `app.services.llm_risk_reviewer` — Block P (ADR-0023).

Mock-LLM-Client liefert JSON-Strings; wir verifizieren die strikte
Output-Validation:

* Pass 1: Halluzinierte finding_ids, fehlende Input-IDs, Label-Regex-Violations,
  Pattern-Sanitization (NUL/Non-ASCII/Wildcard-only).
* Pass 2: Halluzinierte group_labels, ``risk_band="pending"``/``"unknown"`` → Reject,
  worst_finding_id ausserhalb der Group → Reject, NUL-Reason → Reject,
  Reason > 256 chars → Reject.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app.models import (
    ApplicationGroup,
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from app.services.llm_risk_reviewer import (
    LLMInvalidResponseError,
    LLMRiskReviewer,
)

# ---------------------------------------------------------------------------
# Mock-Client (mimickt das `_sdk.chat.completions.create()`-Interface)
# ---------------------------------------------------------------------------


class _MockSDK:
    def __init__(self, response_payload: dict[str, Any] | str) -> None:
        self._payload = response_payload
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs: Any) -> Any:
        content = json.dumps(self._payload) if isinstance(self._payload, dict) else self._payload
        message = SimpleNamespace(content=content)
        choice = SimpleNamespace(message=message)
        return SimpleNamespace(choices=[choice])


class _MockClient:
    def __init__(self, response_payload: dict[str, Any] | str) -> None:
        self._sdk = _MockSDK(response_payload)
        self.model = "mock-model"


# ---------------------------------------------------------------------------
# Test-Helper
# ---------------------------------------------------------------------------


def _make_finding(
    fid: int,
    *,
    cve: str | None = None,
    package_name: str = "openssl",
    target_path: str | None = None,
    purl: str | None = None,
) -> Finding:
    now = datetime.now(tz=UTC)
    return Finding(
        id=fid,
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key=cve or f"CVE-2024-{fid:04d}",
        package_name=package_name,
        installed_version="1.0",
        severity=Severity.HIGH,
        attack_vector=AttackVector.UNKNOWN,
        status=FindingStatus.OPEN,
        is_kev=False,
        first_seen_at=now,
        last_seen_at=now,
        target_path=target_path,
        package_purl=purl,
        severity_by_provider={"nvd": "high"},
        vendor_status="affected",
    )


def _make_server() -> Server:
    s = Server(
        id=1,
        name="srv-llm-test",
        api_key_hash="x" * 64,
        expected_scan_interval_h=24,
        os_family="ubuntu",
        os_version="24.04",
    )
    s.listeners = []  # type: ignore[attr-defined]
    s.processes = []  # type: ignore[attr-defined]
    s.kernel_modules = []  # type: ignore[attr-defined]
    s.services = []  # type: ignore[attr-defined]
    s.tag_links = []  # type: ignore[attr-defined]
    return s


def _make_group(label: str, finding_ids: list[int], group_id: int = 1) -> ApplicationGroup:
    return ApplicationGroup(
        id=group_id,
        label=label,
        explanation=f"{label} group",
        path_prefixes=[],
        pkg_name_exact=[label],
        pkg_name_glob=[],
        pkg_purl_pattern=[],
        source="llm",
    )


# ---------------------------------------------------------------------------
# Pass 1 — Happy-Path
# ---------------------------------------------------------------------------


pytestmark = pytest.mark.usefixtures("app_env")


@pytest.mark.asyncio
async def test_pass1_happy_path_parses_groups() -> None:
    f1 = _make_finding(1, package_name="openssl")
    f2 = _make_finding(2, package_name="openssl")
    f3 = _make_finding(3, package_name="bash")
    payload = {
        "groups": [
            {
                "label": "openssl",
                "explanation": "OS distro openssl",
                "match_rules": {
                    "path_prefixes": [],
                    "pkg_name_exact": ["openssl"],
                    "pkg_name_glob": [],
                    "pkg_purl_pattern": [],
                },
                "finding_ids": [1, 2],
            },
            {
                "label": "bash",
                "explanation": None,
                "match_rules": {
                    "pkg_name_exact": ["bash"],
                },
                "finding_ids": [3],
            },
        ],
        "ungrouped": [],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    result = await reviewer.pass1_detect_groups([f1, f2, f3])
    labels = [g.label for g in result.groups]
    assert labels == ["openssl", "bash"]
    assert result.ungrouped_finding_ids == []
    assert result.groups[0].pkg_name_exact == ["openssl"]


# ---------------------------------------------------------------------------
# Pass 1 — Halluzinationen und Schema-Verstoesse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pass1_rejects_hallucinated_finding_id() -> None:
    f1 = _make_finding(1)
    payload = {
        "groups": [
            {
                "label": "x",
                "finding_ids": [1, 999],  # 999 nicht im Input
                "match_rules": {},
            },
        ],
        "ungrouped": [],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    with pytest.raises(LLMInvalidResponseError, match="halluzinierte"):
        await reviewer.pass1_detect_groups([f1])


@pytest.mark.asyncio
async def test_pass1_rejects_missing_input_finding() -> None:
    """Findings, die weder in einer Group noch in `ungrouped` landen, sind eine
    Halluzinations-Luecke."""
    f1 = _make_finding(1)
    f2 = _make_finding(2)
    payload = {
        "groups": [
            {"label": "x", "finding_ids": [1], "match_rules": {}},
        ],
        "ungrouped": [],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    with pytest.raises(LLMInvalidResponseError, match="nicht zugeordnet"):
        await reviewer.pass1_detect_groups([f1, f2])


@pytest.mark.asyncio
async def test_pass1_rejects_invalid_label_regex() -> None:
    f1 = _make_finding(1)
    payload = {
        "groups": [
            {"label": "Has-UpperCase", "finding_ids": [1], "match_rules": {}},
        ],
        "ungrouped": [],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    with pytest.raises(LLMInvalidResponseError, match="Regex"):
        await reviewer.pass1_detect_groups([f1])


@pytest.mark.asyncio
async def test_pass1_drops_malicious_path_pattern() -> None:
    """`/etc/passwd`-Pfade sind technisch erlaubt (ASCII, `/`-Start), aber
    `"/"` allein und `"*"` werden gedroppt — Defense-gegen-zu-generische
    Patterns."""
    f1 = _make_finding(1)
    payload = {
        "groups": [
            {
                "label": "tricky",
                "finding_ids": [1],
                "match_rules": {
                    "path_prefixes": ["/", "*", "", "/var/lib/rancher/"],
                    "pkg_name_exact": ["", "*", "real-pkg"],
                    "pkg_name_glob": ["*", "real-*"],
                    "pkg_purl_pattern": ["", "pkg:deb/"],
                },
            },
        ],
        "ungrouped": [],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    result = await reviewer.pass1_detect_groups([f1])
    grp = result.groups[0]
    # Wildcards und Forbidden gestripped:
    assert grp.path_prefixes == ["/var/lib/rancher/"]
    assert grp.pkg_name_exact == ["real-pkg"]
    assert grp.pkg_name_glob == ["real-*"]
    assert grp.pkg_purl_pattern == ["pkg:deb/"]


@pytest.mark.asyncio
async def test_pass1_drops_non_ascii_pattern() -> None:
    f1 = _make_finding(1)
    payload = {
        "groups": [
            {
                "label": "x",
                "finding_ids": [1],
                "match_rules": {
                    "path_prefixes": ["/öäü/path", "/valid/path/"],
                },
            },
        ],
        "ungrouped": [],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    result = await reviewer.pass1_detect_groups([f1])
    assert result.groups[0].path_prefixes == ["/valid/path/"]


@pytest.mark.asyncio
async def test_pass1_rejects_finding_id_in_multiple_groups() -> None:
    f1 = _make_finding(1)
    f2 = _make_finding(2)
    payload = {
        "groups": [
            {"label": "a", "finding_ids": [1, 2], "match_rules": {}},
            {"label": "b", "finding_ids": [2], "match_rules": {}},
        ],
        "ungrouped": [],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    with pytest.raises(LLMInvalidResponseError, match="mehreren Groups"):
        await reviewer.pass1_detect_groups([f1, f2])


# ---------------------------------------------------------------------------
# Pass 2 — Happy-Path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pass2_happy_path() -> None:
    server = _make_server()
    f1 = _make_finding(1)
    f2 = _make_finding(2)
    grp = _make_group("openssl", [1, 2])
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "worst_finding_id": 1,
                "reason": "sshd lauscht auf 0.0.0.0:22. Patch verfuegbar im Distro.",
            },
        ],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    result = await reviewer.pass2_evaluate_groups(server, [(grp, [f1, f2])])
    assert len(result.evaluations) == 1
    e = result.evaluations[0]
    assert e.group_label == "openssl"
    assert e.risk_band == "act"
    assert e.worst_finding_id == 1


# ---------------------------------------------------------------------------
# Pass 2 — Halluzinationen und Schema-Verstoesse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pass2_rejects_hallucinated_group_label() -> None:
    server = _make_server()
    f1 = _make_finding(1)
    grp = _make_group("openssl", [1])
    payload = {
        "evaluations": [
            {
                "group_label": "ghost-group",
                "risk_band": "act",
                "worst_finding_id": None,
                "reason": "hallucinated",
            },
        ],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    with pytest.raises(LLMInvalidResponseError, match="halluzinierter"):
        await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])


@pytest.mark.asyncio
async def test_pass2_rejects_pending_or_unknown_band() -> None:
    server = _make_server()
    f1 = _make_finding(1)
    grp = _make_group("openssl", [1])
    for forbidden in ("pending", "unknown"):
        payload = {
            "evaluations": [
                {
                    "group_label": "openssl",
                    "risk_band": forbidden,
                    "worst_finding_id": None,
                    "reason": "x",
                },
            ],
        }
        reviewer = LLMRiskReviewer(client=_MockClient(payload))
        with pytest.raises(LLMInvalidResponseError, match="risk_band"):
            await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])


@pytest.mark.asyncio
async def test_pass2_rejects_worst_finding_not_in_group() -> None:
    server = _make_server()
    f1 = _make_finding(1)
    grp = _make_group("openssl", [1])
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "worst_finding_id": 999,  # nicht in Group
                "reason": "x",
            },
        ],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    with pytest.raises(LLMInvalidResponseError, match="Mitglied"):
        await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])


@pytest.mark.asyncio
async def test_pass2_rejects_nul_byte_in_reason() -> None:
    server = _make_server()
    f1 = _make_finding(1)
    grp = _make_group("openssl", [1])
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "monitor",
                "worst_finding_id": None,
                "reason": "tricky\x00reason",
            },
        ],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    with pytest.raises(LLMInvalidResponseError, match="NUL-Byte"):
        await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])


@pytest.mark.asyncio
async def test_pass2_rejects_reason_over_256_chars() -> None:
    server = _make_server()
    f1 = _make_finding(1)
    grp = _make_group("openssl", [1])
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "act",
                "worst_finding_id": None,
                "reason": "x" * 300,
            },
        ],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    with pytest.raises(LLMInvalidResponseError, match="256"):
        await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])


@pytest.mark.asyncio
async def test_pass2_accepts_null_worst_finding() -> None:
    """LLM darf `null` als worst_finding_id liefern (keine klare Spitze)."""
    server = _make_server()
    f1 = _make_finding(1)
    grp = _make_group("openssl", [1])
    payload = {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": "monitor",
                "worst_finding_id": None,
                "reason": "watch",
            },
        ],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    result = await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])
    assert result.evaluations[0].worst_finding_id is None


@pytest.mark.asyncio
async def test_invalid_json_response_raises() -> None:
    """Wenn die LLM-Response gar kein JSON ist, kommt InvalidResponse."""
    server = _make_server()
    f1 = _make_finding(1)
    grp = _make_group("openssl", [1])
    reviewer = LLMRiskReviewer(client=_MockClient("not-json-at-all"))
    with pytest.raises(LLMInvalidResponseError, match="JSON"):
        await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])
