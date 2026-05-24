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
    _extract_json_from_response,
    _extract_reasoning,
    chat_completion_json,
    chat_completion_json_with_meta,
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
    result, _meta = await reviewer.pass1_detect_groups([f1, f2, f3])
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
    result, _meta = await reviewer.pass1_detect_groups([f1])
    grp = result.groups[0]
    # Wildcards und Forbidden gestripped; Leading-Slash auf relativ
    # normalisiert (Bugfix 2026-05-24).
    assert grp.path_prefixes == ["var/lib/rancher/"]
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
    result, _meta = await reviewer.pass1_detect_groups([f1])
    # Leading-Slash bei der Persistierung gestrippt (Bugfix 2026-05-24).
    assert result.groups[0].path_prefixes == ["valid/path/"]


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
                "action_type": "patch",
                "worst_finding_id": 1,
                "reason": "sshd lauscht auf 0.0.0.0:22. Patch verfuegbar im Distro.",
            },
        ],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    result, _meta = await reviewer.pass2_evaluate_groups(server, [(grp, [f1, f2])])
    assert len(result.evaluations) == 1
    e = result.evaluations[0]
    assert e.group_label == "openssl"
    assert e.risk_band == "act"
    assert e.action_type == "patch"
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
                "action_type": "patch",
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
                "action_type": "watch",
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
                "action_type": "patch",
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
                "action_type": "watch",
                "worst_finding_id": None,
                "reason": "watch",
            },
        ],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(payload))
    result, _meta = await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])
    assert result.evaluations[0].worst_finding_id is None


# ---------------------------------------------------------------------------
# Bugfix 2026-05-24 (ADR-0023 Nachtrag): Pass2 rendert `path=` pro Finding.
# ---------------------------------------------------------------------------


def test_pass2_prompt_renders_path_for_each_finding() -> None:
    """`_render_pass2_prompt` muss `path=<target_path>` pro Finding-Zeile
    schreiben damit das LLM PROJECT-LOCAL/SYSTEM-BASELINE/ECOSYSTEM-ONLY
    klassifizieren kann."""
    server = _make_server()
    f_proj = _make_finding(
        1, package_name="vite", target_path="AdminLTE-master/node_modules/vite/package.json"
    )
    f_sys = _make_finding(
        2, package_name="urllib3", target_path="usr/lib/python3/dist-packages/urllib3"
    )
    grp = _make_group("adminlte-master", [1, 2])
    reviewer = LLMRiskReviewer(client=_MockClient({"evaluations": []}))
    prompt = reviewer._render_pass2_prompt(server, [(grp, [f_proj, f_sys])])
    assert "path=AdminLTE-master/node_modules/vite/package.json" in prompt
    assert "path=usr/lib/python3/dist-packages/urllib3" in prompt


def test_pass2_prompt_renders_path_n_a_when_target_path_missing() -> None:
    """Fehlender `target_path` muss explizit als `path=n/a` markiert werden,
    damit das LLM nicht auf eine leere Stelle reagiert."""
    server = _make_server()
    f1 = _make_finding(1, package_name="openssl", target_path=None)
    grp = _make_group("openssl", [1])
    reviewer = LLMRiskReviewer(client=_MockClient({"evaluations": []}))
    prompt = reviewer._render_pass2_prompt(server, [(grp, [f1])])
    assert "path=n/a" in prompt


def test_pass2_prompt_truncates_long_paths() -> None:
    """Sehr lange Pfade duerfen den Token-Budget nicht sprengen → Cap 128."""
    server = _make_server()
    long_path = "opt/foo/" + ("a" * 400)
    f1 = _make_finding(1, package_name="x", target_path=long_path)
    grp = _make_group("x", [1])
    reviewer = LLMRiskReviewer(client=_MockClient({"evaluations": []}))
    prompt = reviewer._render_pass2_prompt(server, [(grp, [f1])])
    # 128-Cap → der Pfad steht maximal einmal, abgeschnitten
    assert long_path not in prompt
    assert "path=opt/foo/" + ("a" * (128 - len("opt/foo/"))) in prompt


@pytest.mark.asyncio
async def test_invalid_json_response_raises() -> None:
    """Wenn die LLM-Response gar kein JSON ist, kommt InvalidResponse."""
    server = _make_server()
    f1 = _make_finding(1)
    grp = _make_group("openssl", [1])
    reviewer = LLMRiskReviewer(client=_MockClient("not-json-at-all"))
    with pytest.raises(LLMInvalidResponseError, match="JSON"):
        await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])


# ---------------------------------------------------------------------------
# v0.9.3 — Reasoning-Block-Extraction Tests (ADR-0023 §"(d)").
# ---------------------------------------------------------------------------


class TestExtractJsonFromResponse:
    """Strippt Reasoning-Wrapper, Markdown-Fences und Greedy-Brace-Fallback."""

    def test_strips_harmony_channel(self) -> None:
        content = (
            "<|channel|>analysis<|message|>thinking about the groups<|end|>"
            '{"groups": [], "ungrouped": []}'
        )
        out = _extract_json_from_response(content)
        assert out == '{"groups": [], "ungrouped": []}'

    def test_strips_think_tags(self) -> None:
        content = '<think>let me reason about this</think>\n{"evaluations": []}'
        out = _extract_json_from_response(content)
        assert out.strip() == '{"evaluations": []}'

    def test_strips_reasoning_brackets(self) -> None:
        content = '[REASONING]chain of thought here[/REASONING]{"groups": [], "ungrouped": []}'
        out = _extract_json_from_response(content)
        assert out == '{"groups": [], "ungrouped": []}'

    def test_strips_markdown_fences(self) -> None:
        content = '```json\n{"groups": [], "ungrouped": []}\n```'
        out = _extract_json_from_response(content)
        assert out == '{"groups": [], "ungrouped": []}'

    def test_strips_markdown_fence_no_lang(self) -> None:
        content = '```\n{"groups": [], "ungrouped": []}\n```'
        out = _extract_json_from_response(content)
        assert out == '{"groups": [], "ungrouped": []}'

    def test_fallback_greedy_braces(self) -> None:
        """Garbage prefix + JSON + garbage suffix — Greedy-Brace findet das JSON."""
        content = 'some preamble {"x": 1} trailing garbage'
        out = _extract_json_from_response(content)
        assert out == '{"x": 1}'

    def test_passthrough_clean_json(self) -> None:
        """Bereits cleanes JSON wird unveraendert durchgereicht."""
        content = '{"groups": [], "ungrouped": []}'
        out = _extract_json_from_response(content)
        assert out == content


class TestExtractReasoning:
    """Liest Reasoning-Inhalt aus mehreren Provider-Patterns."""

    def test_reads_direct_reasoning_attribute(self) -> None:
        msg = SimpleNamespace(reasoning="thinking output")
        assert _extract_reasoning(msg) == "thinking output"

    def test_reads_reasoning_content_attribute(self) -> None:
        """DeepSeek-R1 Pattern: ``message.reasoning_content`` als Direct-Attribute."""
        # ``reasoning`` darf nicht existieren, sonst gewinnt das.
        msg = SimpleNamespace(reasoning=None, reasoning_content="r1 thinking")
        assert _extract_reasoning(msg) == "r1 thinking"

    def test_reads_model_extra_reasoning_content(self) -> None:
        """DeepInfra GPT-OSS via OpenAI-SDK: Pydantic-V2 ``model_extra``-Bucket."""
        msg = SimpleNamespace(model_extra={"reasoning_content": "extra-bucket thinking"})
        assert _extract_reasoning(msg) == "extra-bucket thinking"

    def test_reads_thinking_attribute(self) -> None:
        """Anthropic-style ``thinking`` Direct-Attribute."""
        msg = SimpleNamespace(reasoning=None, reasoning_content=None, thinking="anthropic thought")
        assert _extract_reasoning(msg) == "anthropic thought"

    def test_returns_none_when_absent(self) -> None:
        msg = SimpleNamespace()
        assert _extract_reasoning(msg) is None

    def test_returns_none_when_all_empty(self) -> None:
        msg = SimpleNamespace(reasoning="", reasoning_content=None, model_extra={})
        assert _extract_reasoning(msg) is None


# ---------------------------------------------------------------------------
# v0.9.3 — (risk_band, action_type)-Combo-Whitelist Tests.
# ---------------------------------------------------------------------------


def _combo_payload(band: str, action_type: str) -> dict[str, Any]:
    """Baut ein minimales Pass-2-Payload mit der gegebenen Combo."""
    return {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": band,
                "action_type": action_type,
                "worst_finding_id": 1001,
                "reason": "test reason",
            }
        ]
    }


class TestPass2ComboWhitelist:
    """Validator akzeptiert nur die fuenf Whitelist-Combos, sonst Reject."""

    @pytest.mark.parametrize(
        ("band", "action_type"),
        [
            ("escalate", "patch"),
            ("escalate", "mitigate"),
            ("act", "patch"),
            ("monitor", "watch"),
            ("noise", "none"),
        ],
    )
    @pytest.mark.asyncio
    async def test_allowed_combinations_pass(self, band: str, action_type: str) -> None:
        server = _make_server()
        f1 = _make_finding(1001)
        grp = _make_group("openssl", [1001])
        reviewer = LLMRiskReviewer(client=_MockClient(_combo_payload(band, action_type)))
        result, _meta = await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])
        assert len(result.evaluations) == 1
        assert result.evaluations[0].action_type == action_type

    @pytest.mark.parametrize(
        ("band", "action_type"),
        [
            ("escalate", "watch"),
            ("escalate", "none"),
            ("act", "mitigate"),
            ("act", "watch"),
            ("act", "none"),
            ("monitor", "patch"),
            ("monitor", "mitigate"),
            ("monitor", "none"),
            ("noise", "patch"),
            ("noise", "mitigate"),
            ("noise", "watch"),
        ],
    )
    @pytest.mark.asyncio
    async def test_disallowed_combinations_reject(self, band: str, action_type: str) -> None:
        server = _make_server()
        f1 = _make_finding(1001)
        grp = _make_group("openssl", [1001])
        reviewer = LLMRiskReviewer(client=_MockClient(_combo_payload(band, action_type)))
        with pytest.raises(LLMInvalidResponseError, match="unzulaessige"):
            await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])

    @pytest.mark.asyncio
    async def test_invalid_action_type_rejected(self) -> None:
        """``investigate`` ist Pre-Triage-only — LLM darf das nie liefern."""
        server = _make_server()
        f1 = _make_finding(1001)
        grp = _make_group("openssl", [1001])
        payload = _combo_payload("act", "investigate")
        reviewer = LLMRiskReviewer(client=_MockClient(payload))
        with pytest.raises(LLMInvalidResponseError, match="action_type"):
            await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])

    @pytest.mark.asyncio
    async def test_missing_action_type_rejected(self) -> None:
        server = _make_server()
        f1 = _make_finding(1001)
        grp = _make_group("openssl", [1001])
        payload = {
            "evaluations": [
                {
                    "group_label": "openssl",
                    "risk_band": "act",
                    # action_type fehlt
                    "worst_finding_id": 1001,
                    "reason": "test",
                }
            ]
        }
        reviewer = LLMRiskReviewer(client=_MockClient(payload))
        with pytest.raises(LLMInvalidResponseError, match="action_type"):
            await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])


# ---------------------------------------------------------------------------
# v0.9.3 — Legacy-`mitigate`-Band-Mapping (Backward-Compat, ADR-0023).
# ---------------------------------------------------------------------------


class TestLegacyMitigateBandMapping:
    """LLM liefert ``risk_band="mitigate"`` (Iteration-5-Output) → wird auf
    ``escalate`` gemappt; structlog-Warning wird emittiert."""

    @pytest.mark.asyncio
    async def test_legacy_mitigate_band_maps_to_escalate(self) -> None:
        server = _make_server()
        f1 = _make_finding(1001)
        grp = _make_group("openssl", [1001])
        payload = _combo_payload("mitigate", "mitigate")
        reviewer = LLMRiskReviewer(client=_MockClient(payload))
        result, _meta = await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])
        assert result.evaluations[0].risk_band == "escalate"
        # action_type bleibt unveraendert (es war ``mitigate``, das ist
        # eine valide Combo mit dem gemappten ``escalate``-Band).
        assert result.evaluations[0].action_type == "mitigate"

    @pytest.mark.asyncio
    async def test_legacy_mitigate_band_emits_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """structlog-Warning ``llm.legacy_mitigate_band_observed`` muss
        emittiert werden. Wir monkeypatchen den Modul-``log``-Bound-Logger
        damit der Test unabhaengig vom global konfigurierten structlog-State
        funktioniert (``app.logging_setup`` aktiviert in der App-Factory
        ``cache_logger_on_first_use=True``, was ``capture_logs`` umgehen
        kann).
        """
        import app.services.llm_risk_reviewer as reviewer_mod

        captured: list[dict[str, Any]] = []

        class _RecordingLogger:
            def warning(self, event: str, **kwargs: Any) -> None:
                captured.append({"event": event, **kwargs})

            def info(self, *_args: Any, **_kw: Any) -> None: ...
            def debug(self, *_args: Any, **_kw: Any) -> None: ...
            def error(self, *_args: Any, **_kw: Any) -> None: ...

        monkeypatch.setattr(reviewer_mod, "log", _RecordingLogger())

        server = _make_server()
        f1 = _make_finding(1001)
        grp = _make_group("openssl", [1001])
        payload = _combo_payload("mitigate", "mitigate")
        reviewer = LLMRiskReviewer(client=_MockClient(payload))
        await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])

        events = [entry["event"] for entry in captured]
        assert "llm.legacy_mitigate_band_observed" in events, (
            f"Expected warning event not in captured logs: {captured}"
        )
        # Group-Label muss als kwargs mitkommen.
        match = next(e for e in captured if e["event"] == "llm.legacy_mitigate_band_observed")
        assert match.get("group_label") == "openssl"


# ---------------------------------------------------------------------------
# v0.9.3 — Smoke gegen GPT-OSS-Harmony-Wrapper (Mock-basiert).
#
# Verifiziert, dass eine vollstaendige Pass-2-Response, die in einen Harmony-
# Reasoning-Wrapper eingepackt ist und ein ``reasoning_content``-Feld im
# Pydantic-V2-``model_extra``-Bucket fuehrt, den ganzen Reviewer-Pfad
# (Extraction → Validation → Pass2Result) ohne Fehler durchlaeuft.
# ---------------------------------------------------------------------------


class _HarmonyMockSDK:
    """Simuliert DeepInfra-GPT-OSS-Response: Harmony-Wrapper im content,
    Reasoning im ``model_extra``-Bucket der OpenAI-Message-Pydantic-V2-Klasse."""

    def __init__(self, content: str, reasoning: str | None = None) -> None:
        self._content = content
        self._reasoning = reasoning
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **_kwargs: Any) -> Any:
        # ``model_extra`` ist Pydantic-V2-Pattern fuer "extra"-Felder.
        message = SimpleNamespace(
            content=self._content,
            model_extra={"reasoning_content": self._reasoning} if self._reasoning else {},
        )
        choice = SimpleNamespace(message=message)
        usage = SimpleNamespace(prompt_tokens=100, completion_tokens=50, total_tokens=150)
        return SimpleNamespace(choices=[choice], usage=usage)


class _HarmonyMockClient:
    def __init__(self, content: str, reasoning: str | None = None) -> None:
        self._sdk = _HarmonyMockSDK(content, reasoning)
        self.model = "openai/gpt-oss-120b"


class TestGptOssSmokeMockMode:
    """Voller Pass-2-Cycle mit Harmony-Wrapper + Reasoning-Field."""

    @pytest.mark.asyncio
    async def test_full_pass2_with_harmony_reasoning_wrapper(self) -> None:
        server = _make_server()
        f1 = _make_finding(1001)
        grp = _make_group("openssh-server", [1001])
        # Harmony-Wrapper umschliesst valides JSON. Reasoning steckt
        # separat im model_extra-Bucket.
        evaluation_json = (
            '{"evaluations":[{"group_label":"openssh-server","risk_band":"escalate",'
            '"action_type":"patch","worst_finding_id":1001,'
            '"reason":"sshd 0.0.0.0:22 PUBLIC-EXPOSED; KEV CVE-2024-6387 patchable"}]}'
        )
        harmony_content = (
            "<|channel|>analysis<|message|>The openssh-server group has a KEV-listed "
            "CVE and listens on 0.0.0.0 — this matches the escalate+patch combo."
            "<|end|>" + evaluation_json
        )
        reviewer = LLMRiskReviewer(
            client=_HarmonyMockClient(  # type: ignore[arg-type]
                harmony_content, reasoning="chain-of-thought separately captured"
            )
        )
        result, meta = await reviewer.pass2_evaluate_groups(server, [(grp, [f1])])
        # Validation muss ohne Throw durchlaufen.
        assert len(result.evaluations) == 1
        ev = result.evaluations[0]
        assert ev.group_label == "openssh-server"
        assert ev.risk_band == "escalate"
        assert ev.action_type == "patch"
        assert ev.worst_finding_id == 1001
        # Meta muss alle Felder fuer den Debug-Log-Insert mitbringen.
        assert meta["model"] == "openai/gpt-oss-120b"
        assert meta["raw_content"] == harmony_content
        # extracted_json strippt Harmony-Wrapper auf reines JSON.
        assert meta["extracted_json"].startswith("{")
        assert "evaluations" in meta["extracted_json"]
        # Reasoning kommt aus model_extra (DeepInfra-GPT-OSS-Pattern).
        assert meta["reasoning_field"] == "chain-of-thought separately captured"
        # Usage-Dict aus SimpleNamespace gemappt.
        assert meta["usage"] is not None
        assert meta["usage"]["total_tokens"] == 150

    @pytest.mark.asyncio
    async def test_full_pass1_with_harmony_wrapper(self) -> None:
        """Pass-1-Smoke: Harmony-Wrapper + Greedy-Brace-Fallback gemeinsam."""
        f1 = _make_finding(1, package_name="openssl")
        f2 = _make_finding(2, package_name="openssl")
        groups_json = (
            '{"groups":[{"label":"openssl","explanation":"OS distro openssl",'
            '"match_rules":{"pkg_name_exact":["openssl"]},"finding_ids":[1,2]}],'
            '"ungrouped":[]}'
        )
        harmony_content = (
            "<|channel|>analysis<|message|>Grouping by package_name.<|end|>" + groups_json
        )
        reviewer = LLMRiskReviewer(
            client=_HarmonyMockClient(harmony_content)  # type: ignore[arg-type]
        )
        result, meta = await reviewer.pass1_detect_groups([f1, f2])
        assert [g.label for g in result.groups] == ["openssl"]
        assert result.groups[0].finding_ids == [1, 2]
        assert meta["extracted_json"].endswith("}")


# ---------------------------------------------------------------------------
# v0.9.4 — temperature=0 wird im SDK-Call gesetzt
# ---------------------------------------------------------------------------


class _CapturingSDK:
    """Mock-SDK das die `create()`-kwargs aufzeichnet und ein Minimal-Response liefert."""

    def __init__(self, response_payload: dict[str, Any] | str) -> None:
        self._payload = response_payload
        self.calls: list[dict[str, Any]] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs: Any) -> Any:
        self.calls.append(dict(kwargs))
        content = json.dumps(self._payload) if isinstance(self._payload, dict) else self._payload
        message = SimpleNamespace(content=content)
        choice = SimpleNamespace(message=message)
        return SimpleNamespace(choices=[choice], usage=None)


class _CapturingClient:
    def __init__(self, response_payload: dict[str, Any] | str) -> None:
        self._sdk = _CapturingSDK(response_payload)
        self.model = "mock-model"


@pytest.mark.asyncio
async def test_chat_completion_json_with_meta_sets_temperature_zero() -> None:
    """v0.9.4 Fix 2: ``chat_completion_json_with_meta`` MUSS ``temperature=0``
    an das SDK reichen (Spec: P-evidence/prompt-pass{1,2}-final.md)."""
    client = _CapturingClient({"ok": True})
    _parsed, _meta = await chat_completion_json_with_meta(
        client,  # type: ignore[arg-type]
        system_prompt="sys",
        user_prompt="usr",
        schema={},
        max_tokens=100,
    )
    assert len(client._sdk.calls) == 1
    assert client._sdk.calls[0]["temperature"] == 0


@pytest.mark.asyncio
async def test_chat_completion_json_sets_temperature_zero() -> None:
    """Backward-Compat-Wrapper reicht ``temperature=0`` mit weiter."""
    client = _CapturingClient({"ok": True})
    _ = await chat_completion_json(
        client,  # type: ignore[arg-type]
        system_prompt="sys",
        user_prompt="usr",
        schema={},
        max_tokens=100,
    )
    assert client._sdk.calls[0]["temperature"] == 0


# ---------------------------------------------------------------------------
# v0.9.5 — Meta-Dict an LLMInvalidResponseError anhaengen
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pass1_detect_groups_attaches_meta_to_validation_error() -> None:
    """v0.9.5: bei Validation-Error muss exc.meta die echte LLM-Response tragen.

    Vorher: Worker schrieb meta=None in den Debug-Log, Operator sah keine
    Response.
    """
    f1 = _make_finding(1)
    # Invalides Label (Space mittendrin) → triggert Validator-Reject mit
    # vorhandener Response.
    bad_payload = {
        "groups": [
            {"label": "bad label", "finding_ids": [1], "match_rules": {}},
        ],
        "ungrouped": [],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(bad_payload))
    with pytest.raises(LLMInvalidResponseError) as ei:
        await reviewer.pass1_detect_groups([f1])
    exc = ei.value
    assert exc.meta is not None
    assert "raw_content" in exc.meta
    assert exc.meta["raw_content"]  # non-empty
    assert exc.meta["system_prompt"]  # PASS1_SYSTEM_PROMPT
    assert exc.meta["user_prompt"]  # Rendered Findings-Tabelle
    assert "duration_ms" in exc.meta
    # extracted_json sollte ebenfalls da sein (das JSON wurde geparst, nur
    # die Semantik-Validierung schlug fehl).
    assert exc.meta["extracted_json"]


@pytest.mark.asyncio
async def test_pass2_evaluate_groups_attaches_meta_to_validation_error() -> None:
    """v0.9.5: Pass-2-Pendant — Validation-Error trägt meta."""
    f1 = _make_finding(1, package_name="openssl")
    server = _make_server()
    group = _make_group("openssl", [1])

    # Halluzinierter group_label → Validator-Reject mit vorhandener Response.
    bad_payload = {
        "evaluations": [
            {
                "group_label": "does-not-exist",  # nicht im Input
                "risk_band": "act",
                "action_type": "patch",
                "worst_finding_id": 1,
                "reason": "fake",
            },
        ],
    }
    reviewer = LLMRiskReviewer(client=_MockClient(bad_payload))
    with pytest.raises(LLMInvalidResponseError) as ei:
        await reviewer.pass2_evaluate_groups(server, [(group, [f1])])
    exc = ei.value
    assert exc.meta is not None
    assert exc.meta.get("raw_content")
    assert exc.meta.get("system_prompt")
    assert exc.meta.get("user_prompt")
    assert "duration_ms" in exc.meta


# ---------------------------------------------------------------------------
# v0.9.7 — finish_reason capturen + spezifischer Error bei leerem content
# ---------------------------------------------------------------------------


class _FinishReasonSDK:
    """Mock-SDK das einen konfigurierbaren content + finish_reason zurueckgibt."""

    def __init__(self, content: str | None, finish_reason: str) -> None:
        self._content = content
        self._finish_reason = finish_reason
        self.calls: list[dict[str, Any]] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs: Any) -> Any:
        self.calls.append(dict(kwargs))
        message = SimpleNamespace(content=self._content)
        choice = SimpleNamespace(message=message, finish_reason=self._finish_reason)
        return SimpleNamespace(choices=[choice], usage=None)


class _FinishReasonClient:
    def __init__(self, content: str | None, finish_reason: str) -> None:
        self._sdk = _FinishReasonSDK(content, finish_reason)
        self.model = "mock-model"


@pytest.mark.asyncio
async def test_finish_reason_captured_in_meta_on_success() -> None:
    """v0.9.7: ``finish_reason`` MUSS im meta-Dict landen damit der Worker
    es in den Debug-Log schreiben kann."""
    client = _FinishReasonClient(json.dumps({"ok": True}), finish_reason="stop")
    _parsed, meta = await chat_completion_json_with_meta(
        client,  # type: ignore[arg-type]
        system_prompt="sys",
        user_prompt="usr",
        schema={},
        max_tokens=100,
    )
    assert meta["finish_reason"] == "stop"


@pytest.mark.asyncio
async def test_empty_content_with_finish_reason_length_gives_specific_error() -> None:
    """v0.9.7: bei ``finish_reason='length'`` + leerem content soll der
    Fehlertext explizit ``max_tokens-Cap waehrend Reasoning`` erwaehnen
    und meta mitliefern damit der Debug-Log nicht blind bleibt."""
    client = _FinishReasonClient(content=None, finish_reason="length")
    with pytest.raises(LLMInvalidResponseError) as ei:
        await chat_completion_json_with_meta(
            client,  # type: ignore[arg-type]
            system_prompt="sys",
            user_prompt="usr",
            schema={},
            max_tokens=100,
        )
    exc = ei.value
    assert "finish_reason=length" in str(exc)
    assert "max_tokens-Cap" in str(exc)
    assert exc.meta is not None
    assert exc.meta["finish_reason"] == "length"
    assert "duration_ms" in exc.meta


@pytest.mark.asyncio
async def test_empty_content_with_finish_reason_stop_gives_generic_error() -> None:
    """v0.9.7: bei leerem content mit ``finish_reason='stop'`` (also
    "Modell hat sauber beendet, ohne content auszugeben") wird der Provider-
    Quirk-Generic-Error geworfen, ABER trotzdem mit meta."""
    client = _FinishReasonClient(content="", finish_reason="stop")
    with pytest.raises(LLMInvalidResponseError) as ei:
        await chat_completion_json_with_meta(
            client,  # type: ignore[arg-type]
            system_prompt="sys",
            user_prompt="usr",
            schema={},
            max_tokens=100,
        )
    exc = ei.value
    assert "finish_reason='stop'" in str(exc) or "finish_reason=stop" in str(exc)
    assert exc.meta is not None
    assert exc.meta["finish_reason"] == "stop"


@pytest.mark.asyncio
async def test_pass1_attaches_meta_on_empty_content_length_error() -> None:
    """v0.9.7: der ``leeren content``-Pfad muss meta auch durch den Reviewer-
    Wrapper (pass1_detect_groups) sauber weitergeben — exc.meta darf nicht
    durch den try/except in pass1_detect_groups verschluckt werden."""
    f1 = _make_finding(1)
    reviewer = LLMRiskReviewer(
        client=_FinishReasonClient(content=None, finish_reason="length"),  # type: ignore[arg-type]
    )
    with pytest.raises(LLMInvalidResponseError) as ei:
        await reviewer.pass1_detect_groups([f1])
    exc = ei.value
    assert exc.meta is not None
    assert exc.meta["finish_reason"] == "length"
