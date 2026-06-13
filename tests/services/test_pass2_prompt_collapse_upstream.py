"""Pure-Unit-Tests fuer die ADR-0064-Aenderungen am Pass-2-Prompt-Rendering
(Block AK — die ``upstream``-Lane kollabiert in ``mitigate``).

Ergaenzt ``test_llm_risk_reviewer.py`` (das ``_render_pass2_prompt`` nur fuer
Pfad-/Title-/Aggregat-Zeilen prueft) um die Lane-Scope-Texte:

  * Der **mitigate**-Lane-Prompt sagt NICHT mehr "fixed_version is null" (das
    war die ADR-0061-Semantik); stattdessen "NO host-applicable patch" und
    erlaubt explizit ``{escalate, monitor, noise}`` (kein ``act``).
  * Es gibt KEINEN ``upstream``-Lane-Zweig mehr — ``fix_lane='upstream'`` faellt
    auf den Default (alle Bands, kein Lane-Hinweis) zurueck, das Wort wird
    nicht als eigene Lane-Variante gerendert.
  * Der **patch**-Lane-Prompt erlaubt weiter alle vier Bands.
  * ``PASS2_PROMPT_VERSION == 5`` (ADR-0064-Bump, invalidiert alte upstream-
    Reasons).

Reine String-Inspektion des gerenderten Prompts + Validator-Aufrufe; KEIN
LLM-Call, kein DB-Roundtrip.
"""

from __future__ import annotations

import pytest

from app.services.llm_prompts import PASS2_PROMPT_VERSION
from app.services.llm_risk_reviewer import LLMInvalidResponseError, LLMRiskReviewer
from tests.services.test_llm_risk_reviewer import (
    _make_finding,
    _make_group,
    _make_server,
    _MockClient,
)

pytestmark = pytest.mark.usefixtures("app_env")


def _reviewer() -> LLMRiskReviewer:
    return LLMRiskReviewer(client=_MockClient({"evaluations": []}))


# ---------------------------------------------------------------------------
# PASS2_PROMPT_VERSION — ADR-0064-Bump
# ---------------------------------------------------------------------------


def test_pass2_prompt_version_is_5() -> None:
    """ADR-0064 zaehlt die Prompt-Version von 4 auf 5 hoch (invalidiert die
    Eval-Rows mit alter upstream-Semantik beim naechsten Re-Eval)."""
    assert PASS2_PROMPT_VERSION == 5


# ---------------------------------------------------------------------------
# mitigate-Lane-Prompt — ADR-0064-Wortlaut
# ---------------------------------------------------------------------------


def test_mitigate_lane_prompt_no_longer_claims_fixed_version_null() -> None:
    """Der mitigate-Lane-Prompt darf NICHT mehr "fixed_version is null"
    behaupten (ADR-0061-Semantik) — die mitigate-Lane deckt seit ADR-0064 auch
    has-fix lang-pkgs (Upstream-Fix existiert) ab."""
    f1 = _make_finding(1001)
    grp = _make_group("openssl", [1001])
    prompt = _reviewer()._render_pass2_prompt(_make_server(), [(grp, [f1])], fix_lane="mitigate")
    assert "fixed_version is null" not in prompt, (
        f"mitigate-Prompt darf 'fixed_version is null' nicht mehr behaupten:\n{prompt}"
    )


def test_mitigate_lane_prompt_says_no_host_applicable_patch() -> None:
    """Der mitigate-Lane-Prompt formuliert die neue Semantik: kein
    host-applizierbarer Patch (dnf/apt), evtl. existiert ein Upstream-Fix."""
    f1 = _make_finding(1001)
    grp = _make_group("openssl", [1001])
    prompt = _reviewer()._render_pass2_prompt(_make_server(), [(grp, [f1])], fix_lane="mitigate")
    assert "fix_lane: mitigate" in prompt
    assert "host-applicable patch" in prompt, f"neue mitigate-Semantik fehlt:\n{prompt}"
    # act ist patch-only -> nur escalate/monitor/noise.
    assert "{escalate, monitor, noise}" in prompt
    assert "act is " in prompt or "do NOT use" in prompt


def test_mitigate_lane_prompt_mentions_upstream_only_as_finding_level_text() -> None:
    """ "upstream" darf im mitigate-Prompt nur als Fliesstext-Erklaerung
    ("upstream fix"/"upstream rebuild") vorkommen — nicht als eigene Lane-
    Variante (kein 'fix_lane: upstream')."""
    f1 = _make_finding(1001)
    grp = _make_group("openssl", [1001])
    prompt = _reviewer()._render_pass2_prompt(_make_server(), [(grp, [f1])], fix_lane="mitigate")
    assert "fix_lane: upstream" not in prompt, (
        f"'upstream' darf keine eigene Lane-Variante mehr sein:\n{prompt}"
    )


# ---------------------------------------------------------------------------
# patch-Lane-Prompt — unveraendert (alle vier Bands)
# ---------------------------------------------------------------------------


def test_patch_lane_prompt_allows_all_four_bands() -> None:
    f1 = _make_finding(1001)
    grp = _make_group("openssl", [1001])
    prompt = _reviewer()._render_pass2_prompt(_make_server(), [(grp, [f1])], fix_lane="patch")
    assert "fix_lane: patch" in prompt
    assert "{escalate, act, monitor, noise}" in prompt


# ---------------------------------------------------------------------------
# upstream-Lane-Input — kein eigener Zweig mehr (Default-Fallback)
# ---------------------------------------------------------------------------


def test_upstream_fix_lane_input_falls_through_to_default() -> None:
    """ADR-0064: ``fix_lane='upstream'`` ist kein bekannter Wert mehr — der
    Render faellt auf den Default-Zweig (alle vier Bands, kein Lane-Hinweis)
    zurueck und rendert KEINEN mitigate-/patch-Lane-Block.

    (In Produktion gibt es diesen Input nicht mehr; der Test dokumentiert die
    Abwesenheit eines Sonder-Zweigs.)"""
    f1 = _make_finding(1001)
    grp = _make_group("openssl", [1001])
    prompt = _reviewer()._render_pass2_prompt(_make_server(), [(grp, [f1])], fix_lane="upstream")
    assert "fix_lane: mitigate" not in prompt
    assert "fix_lane: patch" not in prompt
    assert "fix_lane: upstream" not in prompt
    # Default-Band-Set (alle vier) in der Return-Zeile.
    assert "{escalate, act, monitor, noise}" in prompt


# ---------------------------------------------------------------------------
# Validator — act-Reject nur fuer mitigate (kein upstream-Input mehr)
# ---------------------------------------------------------------------------


def _payload(band: str) -> dict[str, object]:
    return {
        "evaluations": [
            {
                "group_label": "openssl",
                "risk_band": band,
                "worst_finding_id": 1001,
                "reason": "test reason",
            }
        ]
    }


@pytest.mark.parametrize("band", ["escalate", "monitor", "noise"])
def test_validator_mitigate_accepts_non_act(band: str) -> None:
    f1 = _make_finding(1001)
    grp = _make_group("openssl", [1001])
    result = _reviewer()._validate_pass2_response(
        _payload(band), [(grp, [f1])], fix_lane="mitigate"
    )
    assert result.evaluations[0].risk_band == band


def test_validator_mitigate_rejects_act() -> None:
    """ADR-0064: der act-Reject deckt jetzt die (kollabierte) mitigate-Lane —
    es gibt keinen separaten upstream-Lane-Input mehr, gegen den noch geprueft
    werden muesste."""
    f1 = _make_finding(1001)
    grp = _make_group("openssl", [1001])
    with pytest.raises(LLMInvalidResponseError, match="act"):
        _reviewer()._validate_pass2_response(_payload("act"), [(grp, [f1])], fix_lane="mitigate")
