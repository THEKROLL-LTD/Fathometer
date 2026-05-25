"""Pure-Unit-Tests fuer Risk-Band-Accordion-Markup
``_partials/risk_band_section.html`` + ``servers/_view_groups.html``
(Block X Phase F, ADR-0038 §6).

Prueft (DoD-Punkt 6, Block X Phase F):
  1.  Sechs <details>-Tags in fester Reihenfolge escalate->noise.
  2.  Nur ESCALATE-Slot bekommt open-Attribut wenn ESCALATE nicht leer.
  3.  Erster nicht-leerer Slot offen wenn ESCALATE leer.
  4.  Leere Slots werden nicht gerendert.
  5.  Pending-Grouping-Subblock in PENDING-Slot wenn pending_count > 0.
  6.  Pending-Grouping-Subblock abwesend wenn pending_count == 0.
  7.  Empty-State wenn alle Slots leer.
  8.  sd-risk-band-sections-Wrapper mit data-test="risk-band-sections" present.
  9.  total_count wird im <summary>-Markup gerendert.

Render-Strategie:
  - Option A: ``render_template_string`` mit Source-Read des jeweiligen
    Templates, eigener Jinja-App-Context.
  - Fuer _view_groups.html: risk_band_sections mit minimalen Slot-Dicts,
    groups=[] (kein application_group_card-Include wird ausgefuehrt).
  - Fuer _partials/risk_band_section.html: direkt mit einzelnem section-Dict
    und groups=[] damit keine Card-Includes getriggert werden.
  - Fuer Pending-Subblock-Tests: section.band='pending' + pending_count > 0
    mit groups=[] — nur der Pending-Subblock-Zweig wird gerendert.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from flask import Flask

# ---------------------------------------------------------------------------
# Template-Pfade
# ---------------------------------------------------------------------------

_TEMPLATES_ROOT = Path(__file__).parent.parent.parent / "app" / "templates"
_VIEW_GROUPS_PATH = _TEMPLATES_ROOT / "servers" / "_view_groups.html"
_SECTION_PARTIAL_PATH = _TEMPLATES_ROOT / "_partials" / "risk_band_section.html"

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_empty_slot(band: str, *, default_open: bool = False) -> dict[str, Any]:
    """Erstellt einen leeren Slot-Dict (is_empty=True)."""
    return {
        "band": band,
        "findings": [],
        "total_count": 0,
        "is_empty": True,
        "default_open": default_open,
    }


def _make_nonempty_slot(
    band: str,
    *,
    count: int = 3,
    default_open: bool = False,
) -> dict[str, Any]:
    """Erstellt einen nicht-leeren Slot-Dict (is_empty=False, findings=[]).

    findings=[] intentional: die Finding-Rendering-Schleife in
    risk_band_section.html ueberspringt eine leere Liste, das Accordion-
    Markup (summary, chev, count) wird trotzdem ueber ``not section.is_empty``
    getriggert. Fuer Tests die Accordion-Logik (open/close) pruefen reicht
    das.
    """
    return {
        "band": band,
        "findings": [],
        "total_count": count,
        "is_empty": False,
        "default_open": default_open,
    }


def _all_six_empty_sections() -> list[dict[str, Any]]:
    """Alle sechs Slots leer."""
    bands = ["escalate", "act", "mitigate", "pending", "monitor", "noise"]
    return [_make_empty_slot(b) for b in bands]


def _all_six_sections(open_band: str | None = "escalate") -> list[dict[str, Any]]:
    """Alle sechs Slots nicht leer; open_band bekommt default_open=True."""
    bands = ["escalate", "act", "mitigate", "pending", "monitor", "noise"]
    return [_make_nonempty_slot(b, default_open=(b == open_band)) for b in bands]


def _render_view_groups(
    app: Flask,
    *,
    risk_band_sections: list[dict[str, Any]],
    pending_grouping_counts: dict[str, int] | None = None,
) -> str:
    """Rendert _view_groups.html mit render_template_string."""
    from flask import render_template_string

    source = _VIEW_GROUPS_PATH.read_text(encoding="utf-8")
    server = SimpleNamespace(id=42)
    pgc = pending_grouping_counts or {}
    with app.test_request_context("/servers/42"):
        return render_template_string(
            source,
            risk_band_sections=risk_band_sections,
            pending_grouping_counts=pgc,
            server=server,
        )


def _render_section_partial(
    app: Flask,
    *,
    section: dict[str, Any],
    pending_grouping_counts: dict[str, int] | None = None,
) -> str:
    """Rendert _partials/risk_band_section.html mit render_template_string.

    Nutzt groups=[] im Section-Dict damit kein Card-Include getriggert wird.
    """
    from flask import render_template_string

    source = _SECTION_PARTIAL_PATH.read_text(encoding="utf-8")
    server = SimpleNamespace(id=42)
    pgc = pending_grouping_counts or {}
    with app.test_request_context("/servers/42"):
        return render_template_string(
            source,
            section=section,
            server=server,
            pending_grouping_counts=pgc,
        )


# ===========================================================================
# Test 1 — Sechs <details> in fester Reihenfolge
# ===========================================================================


def test_six_details_in_order(app: Flask) -> None:
    """Render mit allen 6 nicht-leeren Slots -> 6 <details> in Reihenfolge
    escalate -> act -> mitigate -> pending -> monitor -> noise."""
    sections = _all_six_sections(open_band="escalate")
    html = _render_view_groups(app, risk_band_sections=sections)

    expected_order = ["escalate", "act", "mitigate", "pending", "monitor", "noise"]
    positions: list[int] = []
    for band in expected_order:
        marker = f'data-test="risk-band-{band}"'
        assert marker in html, f"'{marker}' fehlt im Output. HTML-Ausschnitt: {html[:1200]!r}"
        positions.append(html.index(marker))

    for i in range(len(positions) - 1):
        assert positions[i] < positions[i + 1], (
            f"Reihenfolge falsch: '{expected_order[i]}' (pos {positions[i]}) "
            f"soll VOR '{expected_order[i + 1]}' (pos {positions[i + 1]}) stehen"
        )


# ===========================================================================
# Test 2 — Nur ESCALATE offen wenn ESCALATE nicht leer
# ===========================================================================


def test_only_escalate_open_when_escalate_nonempty(app: Flask) -> None:
    """ESCALATE default_open=True -> <details ... open> nur auf ESCALATE.
    ACT soll KEIN open-Attribut haben."""
    import re as _re

    # Pruefe ESCALATE mit default_open=True -> open-Attribut im Tag.
    escalate_section = _make_nonempty_slot("escalate", default_open=True)
    escalate_html = _render_section_partial(app, section=escalate_section)
    details_tag_match = _re.search(r"<details\s[^>]*>", escalate_html)
    assert details_tag_match is not None, (
        f"Kein <details>-Tag in ESCALATE-Partial gefunden. HTML: {escalate_html!r}"
    )
    tag_content = details_tag_match.group(0)
    assert " open" in tag_content, (
        f"ESCALATE-<details>-Tag soll 'open'-Attribut haben bei default_open=True. "
        f"Tag: {tag_content!r}"
    )

    # ACT darf kein open haben — rendere ACT-Slot einzeln und pruefen.
    act_section = _make_nonempty_slot("act", default_open=False)
    act_html = _render_section_partial(app, section=act_section)
    act_details_match = _re.search(r"<details\s[^>]*>", act_html)
    if act_details_match:
        act_tag = act_details_match.group(0)
        assert " open" not in act_tag, (
            f"ACT-<details>-Tag soll kein 'open'-Attribut haben. Tag: {act_tag!r}"
        )


# ===========================================================================
# Test 3 — Erster nicht-leerer Slot offen wenn ESCALATE leer
# ===========================================================================


def test_first_nonempty_slot_open_when_escalate_empty(app: Flask) -> None:
    """ESCALATE leer, ACT nicht leer und default_open=True -> ACT hat open."""
    escalate = _make_empty_slot("escalate", default_open=False)
    act = _make_nonempty_slot("act", default_open=True)
    remaining = [_make_empty_slot(b) for b in ["mitigate", "pending", "monitor", "noise"]]
    sections = [escalate, act, *remaining]

    html = _render_view_groups(app, risk_band_sections=sections)

    # ESCALATE soll gar nicht gerendert sein (is_empty=True -> kein <details>).
    assert 'data-test="risk-band-escalate"' not in html, (
        "Leerer ESCALATE-Slot soll nicht gerendert werden"
    )

    # ACT soll mit open gerendert sein.
    import re as _re

    act_partial = _render_section_partial(
        app,
        section=act,
    )
    details_tag_match = _re.search(r"<details\s[^>]+>", act_partial)
    assert details_tag_match is not None, (
        f"Kein <details>-Tag in ACT-Partial gefunden. HTML: {act_partial!r}"
    )
    tag_content = details_tag_match.group(0)
    assert " open" in tag_content, (
        f"ACT-<details>-Tag soll 'open'-Attribut haben bei default_open=True. Tag: {tag_content!r}"
    )


# ===========================================================================
# Test 4 — Leere Slots werden nicht gerendert
# ===========================================================================


def test_empty_slots_not_rendered(app: Flask) -> None:
    """Nur ESCALATE nicht leer -> nur ESCALATE-<details>, kein act/mitigate/etc."""
    escalate = _make_nonempty_slot("escalate", default_open=True)
    rest = [_make_empty_slot(b) for b in ["act", "mitigate", "pending", "monitor", "noise"]]
    sections = [escalate, *rest]

    html = _render_view_groups(app, risk_band_sections=sections)

    assert 'data-test="risk-band-escalate"' in html, "ESCALATE-Slot soll gerendert sein"

    for band in ["act", "mitigate", "pending", "monitor", "noise"]:
        assert f'data-test="risk-band-{band}"' not in html, (
            f"Leerer Slot '{band}' soll NICHT gerendert werden. HTML-Ausschnitt: {html[:600]!r}"
        )


# ===========================================================================
# Test 5 — Empty-State wenn alle Slots leer
# ===========================================================================


def test_empty_state_when_all_slots_empty(app: Flask) -> None:
    """Alle 6 Slots leer -> Empty-State mit sd-empty-block + sd-empty-Klassen.

    Track F hat den Empty-State von DaisyUI card bg-base-200 auf
    sd-empty-block / sd-empty umgebaut.
    """
    sections = _all_six_empty_sections()
    html = _render_view_groups(app, risk_band_sections=sections)

    # Track F: sd-empty-block-Wrapper + sd-empty-Text-Element.
    assert "sd-empty-block" in html, (
        f"'sd-empty-block'-Wrapper fehlt im Empty-State. "
        f"Track F: sd-empty-block ersetzt DaisyUI card bg-base-200. HTML: {html!r}"
    )
    assert "sd-empty" in html, f"'sd-empty'-Klasse fehlt im Empty-State. HTML: {html!r}"
    # Text-Inhalt: Schluessel-Substring genuegt (kein Punkt am Ende im neuen Markup).
    assert "Keine offenen Findings" in html, (
        f"Empty-State-Text 'Keine offenen Findings' fehlt. HTML: {html!r}"
    )

    # Kein <details>-Tag im Output.
    assert "<details" not in html, f"Kein <details>-Tag erwartet bei leerem State. HTML: {html!r}"


# ===========================================================================
# Test 8 — sd-risk-band-sections-Wrapper present
# ===========================================================================


def test_sd_risk_band_sections_wrapper_present(app: Flask) -> None:
    """Output enthaelt data-test='risk-band-sections' wenn mindestens ein Slot belegt.

    Track F: Der Wrapper hat kein eigenes CSS-Klassen-Attribut mehr —
    nur data-test='risk-band-sections' (kein 'sd-risk-band-sections'-CSS-Klasse).
    """
    sections = _all_six_sections(open_band="escalate")
    html = _render_view_groups(app, risk_band_sections=sections)

    assert 'data-test="risk-band-sections"' in html, (
        f"'data-test=\"risk-band-sections\"' fehlt im Output. HTML: {html[:600]!r}"
    )

    # Track F: Der Wrapper-Div hat NUR data-test, keine eigene CSS-Klasse mehr.
    # Wir pruefen dass die <details class="sd-band"> Kinder vorhanden sind.
    assert 'class="sd-band"' in html, (
        f"'class=\"sd-band\"'-Klasse fehlt in den <details>-Kindern. "
        f"Track F hat sd-risk-band-section auf sd-band umbenannt. HTML: {html[:600]!r}"
    )


# ===========================================================================
# Test 9 — total_count wird im <summary>-Markup gerendert
# ===========================================================================


def test_total_count_rendered_in_summary(app: Flask) -> None:
    """Slot mit total_count=42 -> '42' erscheint im <summary>-Markup via sd-band__count.

    Track F hat sd-risk-band-section__count auf sd-band__count umbenannt.
    """
    section = _make_nonempty_slot("act", count=42, default_open=True)
    html = _render_section_partial(app, section=section)

    # Die Section rendert total_count im <summary>-Block.
    assert "42" in html, f"total_count=42 soll als '42' im Output erscheinen. HTML: {html!r}"

    # Track F: Klasse ist jetzt sd-band__count (kein sd-risk-band-section__count mehr).
    assert 'class="sd-band__count"' in html, (
        f"'sd-band__count'-Klasse fehlt im Summary-Markup. "
        f"Track F hat 'sd-risk-band-section__count' auf 'sd-band__count' umbenannt. "
        f"HTML: {html!r}"
    )
