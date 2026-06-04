"""Pure-Unit-Tests fuer Risk-Band-Accordion-Markup
``_partials/risk_band_section.html`` + ``servers/_view_groups.html``
(Block X Phase F, ADR-0038 §6; Block Y Phase A, ADR-0039 §1).

Block Y / ADR-0039: das Template-Vertragstausch fuer den Akkordeon-Header:
  - `risk_band_header_counts` (dict[band, count]) statt `risk_band_sections`.
  - `default_open_band` (str | None) wird vom View vorberechnet.
  - Der Section-Body ist ein Lazy-Slot (Phase C wired hx-get) — keine
    `findings`-Schleife mehr im Initial-Render.

Prueft (DoD-Punkt 6, Block X Phase F + Block Y Phase A):
  1.  Akkordeon-Headers in fester Reihenfolge escalate->noise.
  2.  Nur ESCALATE-Slot bekommt open-Attribut wenn ESCALATE nicht leer.
  3.  Erster nicht-leerer Slot offen wenn ESCALATE leer.
  4.  Leere Slots werden nicht gerendert.
  5.  Empty-State wenn alle Counts 0.
  6.  data-test="risk-band-sections"-Wrapper present.
  7.  total_count wird im <summary>-Markup gerendert.
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


_BANDS_ORDER = ("escalate", "act", "mitigate", "pending", "monitor", "noise")


def _make_nonempty_slot(
    band: str,
    *,
    count: int = 3,
    default_open: bool = False,
) -> dict[str, Any]:
    """Slot-Dict fuer das `_partials/risk_band_section.html`-Partial.

    Block Y / ADR-0039: das Partial konsumiert nur noch `band`, `total_count`,
    `is_empty`, `default_open` — keine `findings`-Schleife mehr.
    """
    return {
        "band": band,
        "total_count": count,
        "is_empty": False,
        "default_open": default_open,
    }


def _empty_header_counts() -> dict[str, int]:
    return dict.fromkeys(_BANDS_ORDER, 0)


def _all_nonempty_header_counts() -> dict[str, int]:
    return dict.fromkeys(_BANDS_ORDER, 3)


def _render_view_groups(
    app: Flask,
    *,
    risk_band_header_counts: dict[str, int],
    default_open_band: str | None = "escalate",
    pending_grouping_counts: dict[str, int] | None = None,
    total_findings_count: int = 0,
) -> str:
    """Rendert _view_groups.html mit render_template_string.

    Block Y / ADR-0039: Vertrag jetzt `risk_band_header_counts` +
    `default_open_band` statt der alten `risk_band_sections`-Liste.
    """
    from flask import render_template_string

    source = _VIEW_GROUPS_PATH.read_text(encoding="utf-8")
    server = SimpleNamespace(id=42)
    pgc = pending_grouping_counts or {}
    with app.test_request_context("/servers/42"):
        return render_template_string(
            source,
            risk_band_header_counts=risk_band_header_counts,
            default_open_band=default_open_band,
            pending_grouping_counts=pgc,
            server=server,
            total_findings_count=total_findings_count,
        )


def _render_section_partial(
    app: Flask,
    *,
    section: dict[str, Any],
    pending_grouping_counts: dict[str, int] | None = None,
) -> str:
    """Rendert _partials/risk_band_section.html mit render_template_string."""
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
    """Render mit allen 6 Bands populated -> 6 <details> in Reihenfolge
    escalate -> act -> mitigate -> pending -> monitor -> noise."""
    counts = _all_nonempty_header_counts()
    html = _render_view_groups(app, risk_band_header_counts=counts, default_open_band="escalate")

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
    """ESCALATE leer (count=0), ACT count>0 mit default_open_band='act' -> ACT hat open."""
    counts = _empty_header_counts()
    counts["act"] = 5

    html = _render_view_groups(app, risk_band_header_counts=counts, default_open_band="act")

    # ESCALATE soll gar nicht gerendert sein (count=0 -> kein <details>).
    assert 'data-test="risk-band-escalate"' not in html, (
        "Leerer ESCALATE-Slot soll nicht gerendert werden"
    )

    # ACT soll mit open gerendert sein.
    import re as _re

    act_partial = _render_section_partial(
        app,
        section=_make_nonempty_slot("act", count=5, default_open=True),
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
    """Nur ESCALATE count>0 -> nur ESCALATE-<details>, kein act/mitigate/etc."""
    counts = _empty_header_counts()
    counts["escalate"] = 3

    html = _render_view_groups(app, risk_band_header_counts=counts, default_open_band="escalate")

    assert 'data-test="risk-band-escalate"' in html, "ESCALATE-Slot soll gerendert sein"

    for band in ["act", "mitigate", "pending", "monitor", "noise"]:
        assert f'data-test="risk-band-{band}"' not in html, (
            f"Leerer Slot '{band}' soll NICHT gerendert werden. HTML-Ausschnitt: {html[:600]!r}"
        )


# ===========================================================================
# Test 5 — Empty-State wenn alle Slots leer
# ===========================================================================


def test_empty_state_when_all_slots_empty(app: Flask) -> None:
    """Alle 6 Bands count=0 -> Empty-State mit sd-empty-block + sd-empty-Klassen.

    Track F hat den Empty-State von DaisyUI card bg-base-200 auf
    sd-empty-block / sd-empty umgebaut.
    """
    counts = _empty_header_counts()
    html = _render_view_groups(app, risk_band_header_counts=counts, default_open_band=None)

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
    counts = _all_nonempty_header_counts()
    html = _render_view_groups(app, risk_band_header_counts=counts, default_open_band="escalate")

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

    # TICKET-009 Etappe 2 (ADR-0044): ackable Bands (hier act) tragen das
    # Per-Band „Acknowledge all"-Hover-Control im Summary.
    assert 'data-test="band-ack-all-act"' in html, (
        f"Hover-Control 'band-ack-all-act' fehlt im Summary-Markup (ADR-0044). HTML: {html!r}"
    )
