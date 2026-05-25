"""Pure-Unit-Tests fuer ``_assemble_risk_band_sections`` (ADR-0038
Re-Implementation, 2026-05-25).

Prueft die Pure-Funktion die OPEN-Findings in sechs Risk-Band-Slots
einsortiert + pro Slot nach (is_kev DESC, severity ASC, epss DESC NULLS LAST)
sortiert. Kein DB-Zugriff: Finding-Mocks via SimpleNamespace.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.models import Severity
from app.views.server_detail import (
    _RISK_BAND_SECTION_ORDER,
    _assemble_risk_band_sections,
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    risk_band: str | None = "noise",
    is_kev: bool = False,
    severity: Severity = Severity.LOW,
    epss_score: float | None = None,
    fid: int = 1,
) -> SimpleNamespace:
    """Minimaler Finding-Mock fuer die Pure-Funktion.

    Attribute spiegeln die Real-ORM-Felder die ``_assemble_risk_band_sections``
    liest. ``fid`` ist nur ein Identifier fuer Assertions.
    """
    return SimpleNamespace(
        id=fid,
        risk_band=risk_band,
        is_kev=is_kev,
        severity=severity,
        epss_score=epss_score,
    )


def _slot(sections: list[dict[str, Any]], band: str) -> dict[str, Any]:
    for s in sections:
        if s["band"] == band:
            return s
    raise AssertionError(f"Band '{band}' nicht in Sections: {[s['band'] for s in sections]}")


# ---------------------------------------------------------------------------
# Test 1 — sechs Slots in dokumentierter Reihenfolge
# ---------------------------------------------------------------------------


def test_six_slots_in_documented_order() -> None:
    sections = _assemble_risk_band_sections([])
    actual_order = [s["band"] for s in sections]
    assert actual_order == list(_RISK_BAND_SECTION_ORDER), (
        f"Slot-Reihenfolge weicht ab: {actual_order} != {list(_RISK_BAND_SECTION_ORDER)}"
    )


# ---------------------------------------------------------------------------
# Test 2 — alle Slots leer wenn kein Input
# ---------------------------------------------------------------------------


def test_all_slots_empty_when_no_input() -> None:
    sections = _assemble_risk_band_sections([])
    assert len(sections) == 6
    for s in sections:
        assert s["is_empty"] is True
        assert s["findings"] == []
        assert s["total_count"] == 0
        assert s["default_open"] is False


# ---------------------------------------------------------------------------
# Test 3 — Klassifikation: pro Band landet die richtige Findings-Liste
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "band",
    ["escalate", "act", "mitigate", "pending", "monitor", "noise"],
)
def test_finding_with_band_lands_in_matching_slot(band: str) -> None:
    f = _make_finding(risk_band=band, fid=1)
    sections = _assemble_risk_band_sections([f])
    target_slot = _slot(sections, band)
    assert target_slot["total_count"] == 1
    assert target_slot["findings"] == [f]
    for other in sections:
        if other["band"] != band:
            assert other["total_count"] == 0


# ---------------------------------------------------------------------------
# Test 4 — Finding mit risk_band=None landet in PENDING
# ---------------------------------------------------------------------------


def test_finding_with_none_band_lands_in_pending() -> None:
    f = _make_finding(risk_band=None, fid=42)
    sections = _assemble_risk_band_sections([f])
    pending = _slot(sections, "pending")
    assert pending["findings"] == [f]


# ---------------------------------------------------------------------------
# Test 5 — Finding mit unbekanntem risk_band landet in PENDING
# ---------------------------------------------------------------------------


def test_finding_with_unknown_band_lands_in_pending() -> None:
    f = _make_finding(risk_band="totally-bogus-band", fid=99)
    sections = _assemble_risk_band_sections([f])
    pending = _slot(sections, "pending")
    assert pending["findings"] == [f]


# ---------------------------------------------------------------------------
# Test 6 — Sortierung: KEV zuerst innerhalb eines Bands
# ---------------------------------------------------------------------------


def test_kev_findings_sort_first_within_band() -> None:
    non_kev = _make_finding(risk_band="escalate", is_kev=False, fid=1, severity=Severity.HIGH)
    kev = _make_finding(risk_band="escalate", is_kev=True, fid=2, severity=Severity.MEDIUM)
    sections = _assemble_risk_band_sections([non_kev, kev])
    escalate = _slot(sections, "escalate")
    assert [f.id for f in escalate["findings"]] == [2, 1], (
        "KEV-Finding muss VOR non-KEV stehen, auch wenn Severity niedriger"
    )


# ---------------------------------------------------------------------------
# Test 7 — Sortierung: bei gleichem KEV-Status nach Severity
# ---------------------------------------------------------------------------


def test_severity_sorts_within_band_with_same_kev() -> None:
    low = _make_finding(risk_band="act", severity=Severity.LOW, fid=1)
    crit = _make_finding(risk_band="act", severity=Severity.CRITICAL, fid=2)
    medium = _make_finding(risk_band="act", severity=Severity.MEDIUM, fid=3)
    high = _make_finding(risk_band="act", severity=Severity.HIGH, fid=4)
    sections = _assemble_risk_band_sections([low, crit, medium, high])
    act = _slot(sections, "act")
    assert [f.id for f in act["findings"]] == [2, 4, 3, 1], (
        "Severity-Reihenfolge muss CRITICAL > HIGH > MEDIUM > LOW sein"
    )


# ---------------------------------------------------------------------------
# Test 8 — Sortierung: EPSS DESC bei gleichem KEV+Severity
# ---------------------------------------------------------------------------


def test_epss_sorts_desc_within_same_severity() -> None:
    low_epss = _make_finding(risk_band="noise", severity=Severity.LOW, epss_score=0.01, fid=1)
    high_epss = _make_finding(risk_band="noise", severity=Severity.LOW, epss_score=0.85, fid=2)
    no_epss = _make_finding(risk_band="noise", severity=Severity.LOW, epss_score=None, fid=3)
    sections = _assemble_risk_band_sections([low_epss, high_epss, no_epss])
    noise = _slot(sections, "noise")
    # KEV=alle false, Severity=alle LOW → EPSS entscheidet. NULL == 0 in unserem Vergleich.
    assert noise["findings"][0].id == 2, "Hoechster EPSS-Score zuerst"
    # low_epss (0.01) vor no_epss (None ~ 0)
    assert noise["findings"][1].id == 1


# ---------------------------------------------------------------------------
# Test 9 — default_open: ESCALATE wenn nicht leer
# ---------------------------------------------------------------------------


def test_default_open_escalate_when_escalate_nonempty() -> None:
    findings = [
        _make_finding(risk_band="escalate", fid=1),
        _make_finding(risk_band="act", fid=2),
        _make_finding(risk_band="noise", fid=3),
    ]
    sections = _assemble_risk_band_sections(findings)
    for s in sections:
        if s["band"] == "escalate":
            assert s["default_open"] is True
        else:
            assert s["default_open"] is False


# ---------------------------------------------------------------------------
# Test 10 — default_open: erster nicht-leerer Slot wenn ESCALATE leer
# ---------------------------------------------------------------------------


def test_default_open_first_nonempty_when_escalate_empty() -> None:
    findings = [
        _make_finding(risk_band="mitigate", fid=1),
        _make_finding(risk_band="noise", fid=2),
    ]
    sections = _assemble_risk_band_sections(findings)
    # ESCALATE leer, ACT leer -> erster nicht-leerer ist MITIGATE
    for s in sections:
        if s["band"] == "mitigate":
            assert s["default_open"] is True
        else:
            assert s["default_open"] is False


# ---------------------------------------------------------------------------
# Test 11 — default_open: kein Slot wenn alles leer
# ---------------------------------------------------------------------------


def test_default_open_none_when_all_empty() -> None:
    sections = _assemble_risk_band_sections([])
    for s in sections:
        assert s["default_open"] is False


# ---------------------------------------------------------------------------
# Test 12 — is_empty + total_count konsistent
# ---------------------------------------------------------------------------


def test_is_empty_and_total_count_consistent() -> None:
    findings = [_make_finding(risk_band="escalate", fid=i) for i in range(3)]
    sections = _assemble_risk_band_sections(findings)
    escalate = _slot(sections, "escalate")
    assert escalate["total_count"] == 3
    assert escalate["is_empty"] is False
    # Andere Slots: total_count=0, is_empty=True
    for s in sections:
        if s["band"] != "escalate":
            assert s["total_count"] == 0
            assert s["is_empty"] is True


# ---------------------------------------------------------------------------
# Test 13 — Findings-Liste enthaelt die uebergebenen Objekte (kein Filtern)
# ---------------------------------------------------------------------------


def test_findings_list_preserves_inputs() -> None:
    f1 = _make_finding(risk_band="act", fid=1)
    f2 = _make_finding(risk_band="act", fid=2)
    f3 = _make_finding(risk_band="mitigate", fid=3)
    sections = _assemble_risk_band_sections([f1, f2, f3])
    act = _slot(sections, "act")
    mitigate = _slot(sections, "mitigate")
    assert {f.id for f in act["findings"]} == {1, 2}
    assert {f.id for f in mitigate["findings"]} == {3}
