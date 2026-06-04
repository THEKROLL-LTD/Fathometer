"""Pure-Unit-Tests fuer das Per-Band „Acknowledge all"-Inline-Confirm-Control
(`_partials/risk_band_section.html`).

TICKET-009-Nachzuegler / ADR-0044-Amendment: das Modal wurde durch einen
Zwei-Zustands-Toggle im `.sd-band__actions`-Slot ersetzt:
  - Ruhe-Zustand: Button `sd-band-ack` (`x-show="!armed"`), `arm()` beim Klick.
  - Armed-Zustand: Confirm-Slot `sd-band-ack-confirm` (`x-show="armed"`) mit
    Frage „Acknowledge <b>N</b> findings?", Confirm-Button (`confirm()`) und
    Cancel-Button (`cancel()`).
KEIN Modal mehr, KEINE Kommentar-Textarea, KEINE Confirm-Checkbox, KEINE
Alpine-`examples`.

Prueft:
  1.  Jedes ackable Band (escalate/act/mitigate/monitor/noise) rendert den
      Rest-Button `data-test="band-ack-all-<band>"`.
  2.  Band `pending`: KEIN Rest-Button, KEIN Confirm-Slot, kein
      `bulkAckBand(`-Scope, kein (totes) Modal.
  3.  Leeres Band (`is_empty=True`): Partial rendert gar nichts.
  4.  Inline-Confirm-Slot: `band-ack-confirm-<band>` mit Yes-Button ("Confirm")
      und No-Button ("Cancel"); die Frage rendert `section.total_count`.
  5.  Toggle: Rest-Button traegt `x-show="!armed"`, Confirm-Slot `x-show="armed"`.
  6.  `@click.prevent.stop` an arm()/confirm()/cancel().
  7.  Negativ: kein `bulk-ack-band-modal`, keine `<textarea>` im Actions-Slot.
  8.  Script-Include `bulk_ack_band.js` in `base_app.html`.

Render-Strategie identisch zu `test_risk_band_accordion.py`: das Partial wird
via `render_template_string` aus dem Datei-Quelltext gerendert, mit einem
`section`-dict + `server`-SimpleNamespace im Kontext.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Template-Pfade
# ---------------------------------------------------------------------------

_TEMPLATES_ROOT = Path(__file__).parent.parent.parent / "app" / "templates"
_SECTION_PARTIAL_PATH = _TEMPLATES_ROOT / "_partials" / "risk_band_section.html"
_BASE_APP_PATH = _TEMPLATES_ROOT / "base_app.html"

# Single Source der ackbaren Bands (identisch zur Schema-Whitelist
# `BULK_ACK_BANDS`, ADR-0044 §(1)).
_ACKABLE_BANDS = ("escalate", "act", "mitigate", "monitor", "noise")


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_section(
    band: str,
    *,
    count: int = 3,
    is_empty: bool = False,
    default_open: bool = False,
) -> dict[str, Any]:
    """Slot-Dict fuer `_partials/risk_band_section.html`."""
    return {
        "band": band,
        "total_count": count,
        "is_empty": is_empty,
        "default_open": default_open,
    }


def _render_section_partial(
    app: Flask,
    *,
    section: dict[str, Any],
) -> str:
    """Rendert `_partials/risk_band_section.html` via render_template_string."""
    from flask import render_template_string

    source = _SECTION_PARTIAL_PATH.read_text(encoding="utf-8")
    server = SimpleNamespace(id=42)
    with app.test_request_context("/servers/42"):
        return render_template_string(
            source,
            section=section,
            server=server,
            pending_grouping_counts={},
        )


# ===========================================================================
# Fall 1 — Rest-Button fuer jedes ackable Band vorhanden
# ===========================================================================


@pytest.mark.parametrize("band", _ACKABLE_BANDS)
def test_ack_all_control_present_for_ackable_band(app: Flask, band: str) -> None:
    """Jedes Band aus escalate/act/mitigate/monitor/noise rendert den
    Rest-Button `band-ack-all-<band>`."""
    html = _render_section_partial(app, section=_make_section(band))

    marker = f'data-test="band-ack-all-{band}"'
    assert marker in html, (
        f"Rest-Button '{marker}' fehlt im Render fuer Band '{band}'. HTML: {html!r}"
    )


# ===========================================================================
# Fall 2 — pending hat kein Control, keinen Confirm-Slot, kein Modal/Scope
# ===========================================================================


def test_pending_band_has_no_control_and_no_scope(app: Flask) -> None:
    """Band `pending`: KEIN ack-all-Control, KEIN Confirm-Slot, KEIN
    Alpine-`bulkAckBand(`-Scope, kein (totes) Modal."""
    html = _render_section_partial(app, section=_make_section("pending"))

    # Das Band wird gerendert (es ist nicht leer) — aber ohne ackable-Affordance.
    assert 'data-test="risk-band-pending"' in html, (
        f"pending-Band soll als <details> gerendert sein. HTML: {html!r}"
    )
    assert 'data-test="band-ack-all-pending"' not in html, (
        f"pending darf KEIN ack-all-Control haben (ADR-0044 §Verworfen e). HTML: {html!r}"
    )
    assert 'data-test="band-ack-confirm-pending"' not in html, (
        f"pending darf KEINEN Inline-Confirm-Slot haben. HTML: {html!r}"
    )
    # Kein Alpine-Scope auf dem Wrapper.
    assert "bulkAckBand(" not in html, (
        f'pending-Wrapper darf keinen x-data="bulkAckBand(...)"-Scope haben. HTML: {html!r}'
    )
    # Modal-Aera vorbei — kein totes Modal-Markup.
    assert "bulk-ack-band-modal" not in html, (
        f"pending darf KEIN (totes) Modal-Markup haben. HTML: {html!r}"
    )


# ===========================================================================
# Fall 3 — leeres Band rendert gar nichts
# ===========================================================================


@pytest.mark.parametrize("band", ("escalate", "noise"))
def test_empty_band_renders_nothing(app: Flask, band: str) -> None:
    """`is_empty=True` -> Partial rendert nur Whitespace, kein <details>,
    kein Control, kein Confirm-Slot."""
    html = _render_section_partial(app, section=_make_section(band, is_empty=True))

    assert html.strip() == "", (
        f"Leeres Band ('{band}', is_empty=True) soll nichts rendern. HTML: {html!r}"
    )
    # Doppelter Schutz: weder details noch Control noch Confirm-Slot.
    assert "<details" not in html, f"Kein <details> bei leerem Band. HTML: {html!r}"
    assert "band-ack-all-" not in html, f"Kein Control bei leerem Band. HTML: {html!r}"
    assert "band-ack-confirm-" not in html, f"Kein Confirm-Slot bei leerem Band. HTML: {html!r}"


# ===========================================================================
# Fall 4 — Inline-Confirm-Slot: Yes/No-Buttons + Count in der Frage
# ===========================================================================


def test_inline_confirm_slot_has_yes_and_no_buttons(app: Flask) -> None:
    """Der Confirm-Slot eines ackablen Bands enthaelt den Slot-Hook, einen
    Confirm-Button ('Confirm') und einen Cancel-Button ('Cancel')."""
    html = _render_section_partial(app, section=_make_section("escalate"))

    assert 'data-test="band-ack-confirm-escalate"' in html, (
        f"Confirm-Slot 'band-ack-confirm-escalate' fehlt. HTML: {html!r}"
    )
    assert 'data-test="band-ack-confirm-yes-escalate"' in html, (
        f"Confirm-Yes-Button fehlt. HTML: {html!r}"
    )
    assert 'data-test="band-ack-confirm-no-escalate"' in html, (
        f"Confirm-No-Button fehlt. HTML: {html!r}"
    )

    # Button-Texte: 'Confirm' fuer yes, 'Cancel' fuer no.
    import re as _re

    yes_match = _re.search(
        r'<button[^>]*data-test="band-ack-confirm-yes-escalate"[^>]*>(.*?)</button>',
        html,
        _re.DOTALL,
    )
    assert yes_match is not None, f"Confirm-Yes-Button-Tag nicht gefunden. HTML: {html!r}"
    assert "Confirm" in yes_match.group(1), (
        f"Confirm-Yes-Button soll Text 'Confirm' tragen. Inhalt: {yes_match.group(1)!r}"
    )

    no_match = _re.search(
        r'<button[^>]*data-test="band-ack-confirm-no-escalate"[^>]*>(.*?)</button>',
        html,
        _re.DOTALL,
    )
    assert no_match is not None, f"Confirm-No-Button-Tag nicht gefunden. HTML: {html!r}"
    assert "Cancel" in no_match.group(1), (
        f"Confirm-No-Button soll Text 'Cancel' tragen. Inhalt: {no_match.group(1)!r}"
    )


def test_inline_confirm_question_renders_total_count(app: Flask) -> None:
    """Die Frage „Acknowledge <b>N</b> findings?" rendert den
    `section.total_count` (hier 42)."""
    html = _render_section_partial(app, section=_make_section("act", count=42))

    assert "Acknowledge <b>42</b> findings?" in html, (
        f"Confirm-Frage soll 'Acknowledge <b>42</b> findings?' mit total_count=42 "
        f"rendern. HTML: {html!r}"
    )
    # Der Frage-Slot traegt die strukturelle Klasse.
    assert "sd-band-ack-confirm__q" in html, (
        f"Frage-Element soll Klasse 'sd-band-ack-confirm__q' tragen. HTML: {html!r}"
    )


# ===========================================================================
# Fall 5 — Toggle: Rest-Button x-show="!armed", Confirm-Slot x-show="armed"
# ===========================================================================


def test_toggle_x_show_armed_flags(app: Flask) -> None:
    """Rest-Button ist nur sichtbar wenn NICHT armed, der Confirm-Slot nur
    wenn armed — der Zwei-Zustands-Toggle haengt an `armed`."""
    import re as _re

    html = _render_section_partial(app, section=_make_section("monitor"))

    # Rest-Button traegt x-show="!armed".
    rest_match = _re.search(
        r'<button[^>]*data-test="band-ack-all-monitor"[^>]*>',
        html,
        _re.DOTALL,
    )
    assert rest_match is not None, f"Rest-Button-Tag nicht gefunden. HTML: {html!r}"
    assert 'x-show="!armed"' in rest_match.group(0), (
        f'Rest-Button soll x-show="!armed" tragen. Tag: {rest_match.group(0)!r}'
    )

    # Confirm-Slot traegt x-show="armed".
    confirm_match = _re.search(
        r'<span[^>]*data-test="band-ack-confirm-monitor"[^>]*>',
        html,
        _re.DOTALL,
    )
    assert confirm_match is not None, f"Confirm-Slot-Tag nicht gefunden. HTML: {html!r}"
    assert 'x-show="armed"' in confirm_match.group(0), (
        f'Confirm-Slot soll x-show="armed" tragen. Tag: {confirm_match.group(0)!r}'
    )


# ===========================================================================
# Fall 6 — @click.prevent.stop an arm()/confirm()/cancel()
# ===========================================================================


def test_arm_button_has_click_prevent_stop(app: Flask) -> None:
    """Der Rest-Button traegt `@click.prevent.stop="arm()"` (bzw. die
    aequivalente `x-on:`-Form) — sonst toggelt der Klick das <details>."""
    html = _render_section_partial(app, section=_make_section("noise"))

    has_at_form = '@click.prevent.stop="arm()"' in html
    has_xon_form = 'x-on:click.prevent.stop="arm()"' in html
    assert has_at_form or has_xon_form, (
        f"Rest-Button soll @click.prevent.stop (oder x-on:-Form) mit arm() tragen. HTML: {html!r}"
    )


def test_confirm_button_has_click_prevent_stop(app: Flask) -> None:
    """Der Confirm-Button traegt `@click.prevent.stop="confirm()"`."""
    html = _render_section_partial(app, section=_make_section("noise"))

    has_at_form = '@click.prevent.stop="confirm()"' in html
    has_xon_form = 'x-on:click.prevent.stop="confirm()"' in html
    assert has_at_form or has_xon_form, (
        f"Confirm-Button soll @click.prevent.stop (oder x-on:-Form) mit confirm() tragen. "
        f"HTML: {html!r}"
    )


def test_cancel_button_has_click_prevent_stop(app: Flask) -> None:
    """Der Cancel-Button traegt `@click.prevent.stop="cancel()"`."""
    html = _render_section_partial(app, section=_make_section("noise"))

    has_at_form = '@click.prevent.stop="cancel()"' in html
    has_xon_form = 'x-on:click.prevent.stop="cancel()"' in html
    assert has_at_form or has_xon_form, (
        f"Cancel-Button soll @click.prevent.stop (oder x-on:-Form) mit cancel() tragen. "
        f"HTML: {html!r}"
    )


# ===========================================================================
# Fall 7 — Negativ: kein Modal, keine Textarea im Actions-Slot
# ===========================================================================


def test_no_modal_and_no_textarea_in_actions(app: Flask) -> None:
    """Die Modal-Aera ist vorbei: weder `bulk-ack-band-modal` noch eine
    Kommentar-`<textarea>` (ADR-0006-Pflichtkommentar-Falle) duerfen im
    Actions-Slot eines ackablen Bands gerendert sein."""
    html = _render_section_partial(app, section=_make_section("act"))

    assert "bulk-ack-band-modal" not in html, (
        f"Kein (totes) Modal-Markup erwartet (Inline-Confirm ersetzt es). HTML: {html!r}"
    )
    assert "<textarea" not in html, (
        f"Keine Kommentar-<textarea> im Inline-Confirm-Flow erwartet. HTML: {html!r}"
    )
    # Auch die alten Modal-Hooks duerfen nicht mehr existieren.
    assert "bulk-ack-band-confirm-check" not in html, (
        f"Confirm-Checkbox-Hook ist Modal-Aera und darf nicht mehr existieren. HTML: {html!r}"
    )
    assert "bulk-ack-band-examples" not in html, (
        f"Examples-Hook ist Modal-Aera und darf nicht mehr existieren. HTML: {html!r}"
    )


# ===========================================================================
# Fall 8 — Script-Include in base_app.html
# ===========================================================================


def test_base_app_includes_bulk_ack_band_js() -> None:
    """`base_app.html` verlinkt `js/bulk_ack_band.js`.

    Raw-Text-Read (wie `tests/views/test_script_load_order.py`) — der
    Script-Pin ist statisches Markup, kein Render-Zustand noetig.
    """
    source = _BASE_APP_PATH.read_text(encoding="utf-8")
    assert "js/bulk_ack_band.js" in source, (
        "base_app.html soll js/bulk_ack_band.js per <script> einbinden."
    )
