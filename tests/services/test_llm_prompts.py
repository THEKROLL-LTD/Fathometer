"""Anti-Regression: kritische Regel-Marker muessen in PASS1/PASS2_SYSTEM_PROMPT
enthalten sein.

Wenn jemand den Prompt-Text future-edited und die Marker rausfliegen,
schlaegt das hier sofort an statt erst beim LLM-Test-Lauf.

Die Marker-Quelle ist ``docs/blocks/P-evidence/prompt-pass1-final.md`` und
``prompt-pass2-final.md`` (jeweils §"Wo der Prompt im Code lebt").
"""

from __future__ import annotations

from app.services.llm_prompts import PASS1_SYSTEM_PROMPT, PASS2_SYSTEM_PROMPT


class TestPass1PromptMarkers:
    def test_cross_language_bundles_marker_present(self) -> None:
        assert "CROSS-LANGUAGE BUNDLES" in PASS1_SYSTEM_PROMPT

    def test_multi_path_applications_marker_present(self) -> None:
        assert "MULTI-PATH APPLICATIONS" in PASS1_SYSTEM_PROMPT

    def test_defense_in_depth_marker_present(self) -> None:
        assert "DEFENSE IN DEPTH" in PASS1_SYSTEM_PROMPT

    def test_avoid_over_generic_patterns_marker_present(self) -> None:
        assert "AVOID OVER-GENERIC PATTERNS" in PASS1_SYSTEM_PROMPT

    def test_bundle_purl_marker_present(self) -> None:
        assert "BUNDLE PURLs MUST IDENTIFY THE APPLICATION ITSELF" in PASS1_SYSTEM_PROMPT

    def test_no_hallucination_marker_present(self) -> None:
        assert "NEVER invent finding_ids" in PASS1_SYSTEM_PROMPT


class TestPass2PromptMarkers:
    def test_public_exposed_marker_present(self) -> None:
        assert "PUBLIC-EXPOSED" in PASS2_SYSTEM_PROMPT

    def test_loopback_only_marker_present(self) -> None:
        assert "LOOPBACK-ONLY" in PASS2_SYSTEM_PROMPT

    def test_no_listener_marker_present(self) -> None:
        assert "NO-LISTENER" in PASS2_SYSTEM_PROMPT

    def test_thinking_analyst_marker_present(self) -> None:
        assert "Be a thinking analyst" in PASS2_SYSTEM_PROMPT

    def test_no_tags_signal_marker_present(self) -> None:
        # "Do NOT use any other signal (no tags, no hostnames, ...)"
        assert "no tags" in PASS2_SYSTEM_PROMPT

    def test_combo_whitelist_marker_present(self) -> None:
        assert "Allowed (risk_band, action_type) combinations" in PASS2_SYSTEM_PROMPT

    def test_legacy_bands_forbidden_marker_present(self) -> None:
        # "NEVER use risk_band values "pending", "unknown", or "mitigate" (legacy)."
        assert "pending" in PASS2_SYSTEM_PROMPT
        assert "unknown" in PASS2_SYSTEM_PROMPT
        assert "mitigate" in PASS2_SYSTEM_PROMPT
        assert "legacy" in PASS2_SYSTEM_PROMPT.lower()

    def test_investigate_action_type_forbidden_marker_present(self) -> None:
        # "NEVER use action_type "investigate" (pre-triage-only)."
        assert "investigate" in PASS2_SYSTEM_PROMPT

    def test_path_classification_markers_present(self) -> None:
        # Bugfix 2026-05-24 (ADR-0023 Nachtrag): Pass2 bekommt pro Finding
        # einen `path=` und muss diesen klassifizieren.
        assert "PROJECT-LOCAL" in PASS2_SYSTEM_PROMPT
        assert "SYSTEM-BASELINE" in PASS2_SYSTEM_PROMPT
        assert "ECOSYSTEM-ONLY" in PASS2_SYSTEM_PROMPT
        assert "path=" in PASS2_SYSTEM_PROMPT
        assert "path=n/a" in PASS2_SYSTEM_PROMPT
