"""Pure-Unit-Tests fuer ``_build_risk_band_sections`` (Block X Phase F, ADR-0038 §6).

Prueft (DoD-Punkt 6, Block X Phase F):
  1.  Sechs Slots in dokumentierter Reihenfolge.
  2.  Alle Slots leer wenn kein Input.
  3.  Group mit evaluation.risk_band='escalate' landet im ESCALATE-Slot.
  4.  Group mit evaluation.risk_band='act' landet im ACT-Slot.
  5.  Groups mit mitigate/pending/monitor/noise landen im jeweiligen Slot (parametrize).
  6.  Group mit evaluation=None landet im PENDING-Slot.
  7.  Group mit evaluation.risk_band='unknown' landet im PENDING-Slot.
  8.  default_open=True auf ESCALATE wenn ESCALATE-Slot nicht leer.
  9.  default_open=True auf erstem nicht-leerem Slot wenn ESCALATE leer.
  10. default_open=True auf PENDING wenn nur pending_grouping_counts > 0.
  11. Kein Slot mit default_open=True wenn alles leer.
  12. pending_count nur im PENDING-Slot gefuellt.
  13. total_count = group-counts + pending_count.
  14. is_empty=True wenn keine Groups und kein pending_count.
  15. is_empty=False wenn mindestens eine Group vorhanden.
  16. is_empty=False wenn nur pending_grouping_counts > 0.
  17. Fehlender count-Key im Entry -> .get('count', 0) faengt ab.
  18. Kombinierter PENDING-Slot: Group mit evaluation.risk_band='pending' UND
      pending_grouping_counts zusammen.

Render-Strategie:
  - Direkter Import von ``_build_risk_band_sections`` + ``_RISK_BAND_SECTION_ORDER``.
  - ``types.SimpleNamespace`` als Evaluation-Mock.
  - Kein DB-Zugriff, kein Flask-App-Context.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.views.server_detail import (
    _RISK_BAND_SECTION_ORDER,
    _build_risk_band_sections,
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_entry(
    risk_band: str | None,
    *,
    count: int = 1,
    group_id: int = 1,
) -> dict[str, Any]:
    """Erstellt einen minimalen Application-Group-Entry fuer Tests.

    ``evaluation=None`` simuliert eine Junction-Row-freie Group (Block T,
    ADR-0028 §UI-bei-Eval-Lucke).
    """
    evaluation = None if risk_band is None else SimpleNamespace(risk_band=risk_band)
    return {
        "group": SimpleNamespace(id=group_id, label=f"group-{group_id}"),
        "evaluation": evaluation,
        "count": count,
        "worst_finding": None,
    }


def _slot(sections: list[dict[str, Any]], band: str) -> dict[str, Any]:
    """Hilfsfunktion: Slot mit passendem band-Wert aus den Sektionen zurueck."""
    for s in sections:
        if s["band"] == band:
            return s
    raise AssertionError(
        f"Band '{band}' nicht in Sections gefunden: {[s['band'] for s in sections]}"
    )


# ---------------------------------------------------------------------------
# Test 1 — Sechs Slots in dokumentierter Reihenfolge
# ---------------------------------------------------------------------------


def test_six_slots_in_documented_order() -> None:
    """_build_risk_band_sections([], {}) liefert sechs Slots in der Reihenfolge
    escalate/act/mitigate/pending/monitor/noise."""
    sections = _build_risk_band_sections([], {})

    assert len(sections) == 6, (
        f"Erwartet 6 Slots, erhalten {len(sections)}: {[s['band'] for s in sections]}"
    )

    bands = [s["band"] for s in sections]
    expected = list(_RISK_BAND_SECTION_ORDER)
    assert bands == expected, f"Slot-Reihenfolge falsch. Erwartet {expected}, erhalten {bands}"


# ---------------------------------------------------------------------------
# Test 2 — Alle Slots leer wenn kein Input
# ---------------------------------------------------------------------------


def test_all_slots_empty_when_no_input() -> None:
    """Alle 6 Slots haben is_empty=True, groups=[], pending_count=0,
    total_count=0, default_open=False bei leerem Input."""
    sections = _build_risk_band_sections([], {})

    for s in sections:
        assert s["is_empty"] is True, (
            f"Slot '{s['band']}' soll is_empty=True haben, ist {s['is_empty']}"
        )
        assert s["groups"] == [], f"Slot '{s['band']}' soll groups=[] haben, ist {s['groups']}"
        assert s["pending_count"] == 0, (
            f"Slot '{s['band']}' soll pending_count=0 haben, ist {s['pending_count']}"
        )
        assert s["total_count"] == 0, (
            f"Slot '{s['band']}' soll total_count=0 haben, ist {s['total_count']}"
        )
        assert s["default_open"] is False, (
            f"Slot '{s['band']}' soll default_open=False haben, ist {s['default_open']}"
        )


# ---------------------------------------------------------------------------
# Test 3 — ESCALATE
# ---------------------------------------------------------------------------


def test_evaluation_risk_band_escalate_lands_in_escalate_slot() -> None:
    """Eine Group mit evaluation.risk_band='escalate' landet im ESCALATE-Slot."""
    entry = _make_entry("escalate")
    sections = _build_risk_band_sections([entry], {})

    escalate = _slot(sections, "escalate")
    assert len(escalate["groups"]) == 1, (
        f"ESCALATE-Slot soll 1 Group haben, hat {len(escalate['groups'])}"
    )

    # Alle anderen Slots sollen leer sein.
    for s in sections:
        if s["band"] != "escalate":
            assert s["groups"] == [], (
                f"Slot '{s['band']}' soll leer sein, hat {len(s['groups'])} Groups"
            )


# ---------------------------------------------------------------------------
# Test 4 — ACT
# ---------------------------------------------------------------------------


def test_evaluation_risk_band_act_lands_in_act_slot() -> None:
    """Eine Group mit evaluation.risk_band='act' landet im ACT-Slot."""
    entry = _make_entry("act")
    sections = _build_risk_band_sections([entry], {})

    act = _slot(sections, "act")
    assert len(act["groups"]) == 1, f"ACT-Slot soll 1 Group haben, hat {len(act['groups'])}"

    for s in sections:
        if s["band"] != "act":
            assert s["groups"] == [], f"Slot '{s['band']}' soll leer sein bei act-only-Input"


# ---------------------------------------------------------------------------
# Test 5 — mitigate/pending/monitor/noise (parametrize)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("band", ["mitigate", "pending", "monitor", "noise"])
def test_evaluation_risk_band_lands_in_correct_slot(band: str) -> None:
    """Group mit evaluation.risk_band=band landet im jeweiligen Slot."""
    entry = _make_entry(band)
    sections = _build_risk_band_sections([entry], {})

    target = _slot(sections, band)
    assert len(target["groups"]) == 1, (
        f"Slot '{band}' soll 1 Group haben, hat {len(target['groups'])}"
    )

    for s in sections:
        if s["band"] != band:
            assert s["groups"] == [], f"Slot '{s['band']}' soll leer sein wenn nur '{band}' belegt"


# ---------------------------------------------------------------------------
# Test 6 — evaluation=None -> PENDING
# ---------------------------------------------------------------------------


def test_evaluation_none_lands_in_pending_slot() -> None:
    """Group mit evaluation=None (Junction-Row fehlt) landet im PENDING-Slot."""
    entry = _make_entry(None)  # evaluation=None
    sections = _build_risk_band_sections([entry], {})

    pending = _slot(sections, "pending")
    assert len(pending["groups"]) == 1, (
        f"PENDING-Slot soll 1 Group haben bei evaluation=None, hat {len(pending['groups'])}"
    )

    for s in sections:
        if s["band"] != "pending":
            assert s["groups"] == [], f"Slot '{s['band']}' soll leer sein bei evaluation=None-Input"


# ---------------------------------------------------------------------------
# Test 7 — Unbekanntes risk_band -> PENDING
# ---------------------------------------------------------------------------


def test_evaluation_unknown_band_lands_in_pending_slot() -> None:
    """Group mit evaluation.risk_band='unknown' (nicht in 6-Slot-Liste) -> PENDING."""
    entry = _make_entry("unknown")
    sections = _build_risk_band_sections([entry], {})

    pending = _slot(sections, "pending")
    assert len(pending["groups"]) == 1, (
        f"PENDING-Slot soll 1 Group bei risk_band='unknown' haben, hat {len(pending['groups'])}"
    )

    escalate = _slot(sections, "escalate")
    assert escalate["groups"] == [], "ESCALATE-Slot soll leer sein bei risk_band='unknown'"


# ---------------------------------------------------------------------------
# Test 8 — default_open auf ESCALATE wenn nicht leer
# ---------------------------------------------------------------------------


def test_default_open_escalate_when_escalate_nonempty() -> None:
    """ESCALATE-Slot hat default_open=True wenn nicht leer; alle anderen False."""
    entry = _make_entry("escalate")
    sections = _build_risk_band_sections([entry], {})

    escalate = _slot(sections, "escalate")
    assert escalate["default_open"] is True, "ESCALATE soll default_open=True haben wenn nicht leer"

    for s in sections:
        if s["band"] != "escalate":
            assert s["default_open"] is False, (
                f"Slot '{s['band']}' soll default_open=False haben wenn ESCALATE belegt"
            )


# ---------------------------------------------------------------------------
# Test 9 — default_open auf erstem nicht-leerem Slot wenn ESCALATE leer
# ---------------------------------------------------------------------------


def test_default_open_first_nonempty_when_escalate_empty() -> None:
    """Kein ESCALATE, aber ACT belegt -> ACT hat default_open=True, andere False."""
    entry = _make_entry("act")
    sections = _build_risk_band_sections([entry], {})

    escalate = _slot(sections, "escalate")
    assert escalate["default_open"] is False, "ESCALATE soll default_open=False haben wenn leer"

    act = _slot(sections, "act")
    assert act["default_open"] is True, (
        "ACT soll default_open=True haben wenn ESCALATE leer und ACT nicht leer"
    )

    for s in sections:
        if s["band"] not in ("escalate", "act"):
            assert s["default_open"] is False, f"Slot '{s['band']}' soll default_open=False haben"


# ---------------------------------------------------------------------------
# Test 10 — default_open PENDING wenn nur pending_grouping_counts > 0
# ---------------------------------------------------------------------------


def test_default_open_pending_when_only_pending_grouping_has_counts() -> None:
    """Kein Application-Group, aber pending_grouping_counts > 0 -> PENDING default_open."""
    sections = _build_risk_band_sections([], {"escalate": 3, "act": 2})

    pending = _slot(sections, "pending")
    assert pending["default_open"] is True, (
        "PENDING soll default_open=True haben wenn nur pending_grouping_counts > 0"
    )

    for s in sections:
        if s["band"] != "pending":
            assert s["default_open"] is False, f"Slot '{s['band']}' soll default_open=False haben"


# ---------------------------------------------------------------------------
# Test 11 — Kein default_open wenn alles leer
# ---------------------------------------------------------------------------


def test_default_open_none_when_everything_empty() -> None:
    """Alle leer -> kein Slot mit default_open=True."""
    sections = _build_risk_band_sections([], {})

    open_slots = [s["band"] for s in sections if s["default_open"]]
    assert open_slots == [], (
        f"Kein Slot soll default_open=True haben wenn alles leer, aber: {open_slots}"
    )


# ---------------------------------------------------------------------------
# Test 12 — pending_count nur im PENDING-Slot gefuellt
# ---------------------------------------------------------------------------


def test_pending_count_only_in_pending_slot() -> None:
    """pending_grouping_counts werden nur im PENDING-Slot als pending_count angezeigt."""
    sections = _build_risk_band_sections([], {"escalate": 5, "act": 3, "pending": 2})

    pending = _slot(sections, "pending")
    assert pending["pending_count"] == 10, (
        f"PENDING-Slot soll pending_count=10 haben (5+3+2), hat {pending['pending_count']}"
    )

    for s in sections:
        if s["band"] != "pending":
            assert s["pending_count"] == 0, (
                f"Slot '{s['band']}' soll pending_count=0 haben, hat {s['pending_count']}"
            )


# ---------------------------------------------------------------------------
# Test 13 — total_count = group-counts + pending_count
# ---------------------------------------------------------------------------


def test_total_count_sums_group_counts_plus_pending() -> None:
    """PENDING-Slot mit 2 Groups (count=3 und count=4) + pending_grouping_counts Summe=5
    -> PENDING.total_count = 12."""
    entries = [
        _make_entry("pending", count=3, group_id=1),
        _make_entry("pending", count=4, group_id=2),
    ]
    sections = _build_risk_band_sections(entries, {"escalate": 3, "act": 2})

    pending = _slot(sections, "pending")
    assert pending["total_count"] == 12, (
        f"PENDING total_count soll 12 sein (3+4 groups + 5 pending), hat {pending['total_count']}"
    )


# ---------------------------------------------------------------------------
# Test 14 — is_empty=True wenn nichts
# ---------------------------------------------------------------------------


def test_is_empty_true_for_no_groups_and_no_pending() -> None:
    """Leerer Input -> alle 6 Slots is_empty=True."""
    sections = _build_risk_band_sections([], {})

    for s in sections:
        assert s["is_empty"] is True, (
            f"Slot '{s['band']}' soll is_empty=True haben bei leerem Input"
        )


# ---------------------------------------------------------------------------
# Test 15 — is_empty=False wenn Group vorhanden
# ---------------------------------------------------------------------------


def test_is_empty_false_for_groups_only() -> None:
    """ACT-Slot mit 1 Group hat is_empty=False; alle anderen True."""
    entry = _make_entry("act")
    sections = _build_risk_band_sections([entry], {})

    act = _slot(sections, "act")
    assert act["is_empty"] is False, f"ACT-Slot soll is_empty=False haben, ist {act['is_empty']}"

    for s in sections:
        if s["band"] != "act":
            assert s["is_empty"] is True, f"Slot '{s['band']}' soll is_empty=True haben"


# ---------------------------------------------------------------------------
# Test 16 — is_empty=False wenn nur pending_grouping_counts > 0
# ---------------------------------------------------------------------------


def test_is_empty_false_for_pending_only() -> None:
    """Nur pending_grouping_counts mit Summe > 0 -> PENDING is_empty=False, andere True."""
    sections = _build_risk_band_sections([], {"monitor": 7})

    pending = _slot(sections, "pending")
    assert pending["is_empty"] is False, (
        "PENDING soll is_empty=False haben wenn pending_grouping_counts > 0"
    )

    for s in sections:
        if s["band"] != "pending":
            assert s["is_empty"] is True, f"Slot '{s['band']}' soll is_empty=True haben"


# ---------------------------------------------------------------------------
# Test 17 — Fehlender count-Key -> kein Crash
# ---------------------------------------------------------------------------


def test_entry_missing_count_key_treated_as_zero() -> None:
    """Entry-Dict ohne count-Key wird als 0 behandelt (.get('count', 0))."""
    entry: dict[str, Any] = {
        "group": SimpleNamespace(id=1, label="no-count"),
        "evaluation": SimpleNamespace(risk_band="monitor"),
        "worst_finding": None,
        # 'count' absichtlich weggelassen
    }
    # Darf nicht crashen.
    sections = _build_risk_band_sections([entry], {})

    monitor = _slot(sections, "monitor")
    assert monitor["total_count"] == 0, (
        f"Monitor total_count soll 0 sein wenn count-Key fehlt, hat {monitor['total_count']}"
    )
    assert monitor["is_empty"] is False, (
        "Monitor soll is_empty=False haben da 1 Group vorhanden (count fehlt -> 0)"
    )


# ---------------------------------------------------------------------------
# Test 18 — Kombinierter PENDING-Slot
# ---------------------------------------------------------------------------


def test_pending_block_card_distribution_combines_with_other_pending_groups() -> None:
    """Eine Group mit evaluation.risk_band='pending' UND pending_grouping_counts ->
    PENDING-Slot hat groups=[...], pending_count=1, total_count=group.count+1."""
    entry = _make_entry("pending", count=5)
    sections = _build_risk_band_sections([entry], {"escalate": 1})

    pending = _slot(sections, "pending")
    assert len(pending["groups"]) == 1, (
        f"PENDING-Slot soll 1 Group haben, hat {len(pending['groups'])}"
    )
    assert pending["pending_count"] == 1, (
        f"PENDING pending_count soll 1 sein, hat {pending['pending_count']}"
    )
    assert pending["total_count"] == 6, (
        f"PENDING total_count soll 6 sein (5 group + 1 pending), hat {pending['total_count']}"
    )
