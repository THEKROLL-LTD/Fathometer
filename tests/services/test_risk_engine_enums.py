"""Block O Phase A (ADR-0022) — Risk-Engine-Enum- und Konstanten-Smoke."""

from __future__ import annotations

from itertools import pairwise

from app.services.risk_engine import (
    ACTION_REQUIRED_MAP,
    EPSS_PENDING_THRESHOLD,
    RISK_BAND_SORT_RANK,
    ActionRequired,
    RiskBand,
    normalize_vendor_status,
)

# ---------------------------------------------------------------------------
# ACTION_REQUIRED_MAP
# ---------------------------------------------------------------------------


def test_action_required_map_covers_all_bands() -> None:
    """Jeder RiskBand-Wert hat ein Mapping — kein KeyError zur Laufzeit."""
    for band in RiskBand:
        assert band in ACTION_REQUIRED_MAP, f"missing mapping for {band}"
        assert isinstance(ACTION_REQUIRED_MAP[band], ActionRequired)


def test_action_required_yes_for_actionable_bands() -> None:
    """ADR-0022 §Risk-Band-Modell — 5 Bands sind `yes`."""
    for band in (
        RiskBand.ESCALATE,
        RiskBand.ACT,
        RiskBand.MITIGATE,
        RiskBand.PENDING,
        RiskBand.UNKNOWN,
    ):
        assert ACTION_REQUIRED_MAP[band] is ActionRequired.YES


def test_action_required_no_for_passive_bands() -> None:
    """ADR-0022 §Risk-Band-Modell — `monitor` und `noise` sind `no`."""
    assert ACTION_REQUIRED_MAP[RiskBand.MONITOR] is ActionRequired.NO
    assert ACTION_REQUIRED_MAP[RiskBand.NOISE] is ActionRequired.NO


# ---------------------------------------------------------------------------
# RISK_BAND_SORT_RANK
# ---------------------------------------------------------------------------


def test_risk_band_sort_rank_covers_all_bands() -> None:
    for band in RiskBand:
        assert band in RISK_BAND_SORT_RANK


def test_risk_band_sort_rank_strictly_descending() -> None:
    """ADR-0022 §Sort-Order: escalate > act > mitigate > pending > unknown > monitor > noise."""
    ordered_bands = [
        RiskBand.ESCALATE,
        RiskBand.ACT,
        RiskBand.MITIGATE,
        RiskBand.PENDING,
        RiskBand.UNKNOWN,
        RiskBand.MONITOR,
        RiskBand.NOISE,
    ]
    ranks = [RISK_BAND_SORT_RANK[b] for b in ordered_bands]
    for prev, nxt in pairwise(ranks):
        assert prev > nxt, f"Sort-Rank nicht streng monoton fallend: {ranks}"


def test_risk_band_sort_rank_values() -> None:
    """Konkrete Werte aus ADR-0022 — Sanity-Anchor."""
    assert RISK_BAND_SORT_RANK[RiskBand.ESCALATE] == 70
    assert RISK_BAND_SORT_RANK[RiskBand.ACT] == 60
    assert RISK_BAND_SORT_RANK[RiskBand.MITIGATE] == 50
    assert RISK_BAND_SORT_RANK[RiskBand.PENDING] == 40
    assert RISK_BAND_SORT_RANK[RiskBand.UNKNOWN] == 30
    assert RISK_BAND_SORT_RANK[RiskBand.MONITOR] == 20
    assert RISK_BAND_SORT_RANK[RiskBand.NOISE] == 10


# ---------------------------------------------------------------------------
# EPSS_PENDING_THRESHOLD
# ---------------------------------------------------------------------------


def test_epss_pending_threshold_constant() -> None:
    """ADR-0022 §Pre-Triage-Algorithmus: EPSS >= 0.1 triggert pending."""
    assert EPSS_PENDING_THRESHOLD == 0.1


# ---------------------------------------------------------------------------
# normalize_vendor_status
# ---------------------------------------------------------------------------


def test_normalize_vendor_status_known_values() -> None:
    """Whitelist-Werte aus ADR-0022 §vendor_status."""
    assert normalize_vendor_status("affected") == "affected"
    assert normalize_vendor_status("fixed") == "fixed"
    assert normalize_vendor_status("under_investigation") == "investigating"
    assert normalize_vendor_status("will_not_fix") == "will_not_fix"
    assert normalize_vendor_status("end_of_life") == "eol"
    assert normalize_vendor_status("not_affected") == "not_affected"


def test_normalize_vendor_status_case_insensitive() -> None:
    """Trivy schreibt uppercase manchmal — wir normalisieren."""
    assert normalize_vendor_status("WILL_NOT_FIX") == "will_not_fix"
    assert normalize_vendor_status("End_Of_Life") == "eol"
    assert normalize_vendor_status("  affected  ") == "affected"


def test_normalize_vendor_status_unknown_value_to_unknown() -> None:
    """Wert ausserhalb der Whitelist → `unknown` (Forward-Compat)."""
    assert normalize_vendor_status("Foo") == "unknown"
    assert normalize_vendor_status("bar_baz") == "unknown"


def test_normalize_vendor_status_none_or_empty_returns_none() -> None:
    """`None` oder Leer-String → `None` (kein Datensatz)."""
    assert normalize_vendor_status(None) is None
    assert normalize_vendor_status("") is None
