"""Pure-Unit-Tests fuer das Per-Band „Acknowledge all"-Hover-Control + Modal
(`_partials/risk_band_section.html` + neues `_partials/bulk_ack_band_modal.html`).

TICKET-009 Etappe 2 / ADR-0044 §(3).

Prueft (Faelle 1-7 der Ticket-Liste):
  1.  Jedes ackable Band (escalate/act/mitigate/monitor/noise) rendert das
      Control `data-test="band-ack-all-<band>"`.
  2.  Band `pending`: KEIN Control, KEIN Modal-Include.
  3.  Leeres Band (`is_empty=True`): Partial rendert gar nichts (kein
      verwaistes Modal).
  4.  Modal-Render: Confirm-Checkbox vorhanden, Kommentar-Feld OHNE
      `required`-Attribut (ADR-0006), kein server-gerendertes Findings-
      Listing (Beispiele kommen aus Alpine `x-for`, nicht aus einer
      Jinja-Schleife).
  5.  Modal liegt AUSSERHALB des `<details>`-Elements (Struktur-Assert).
  6.  `@click.prevent.stop` am Control vorhanden.
  7.  Script-Include `bulk_ack_band.js` in `base_app.html`.

Render-Strategie identisch zu `test_risk_band_accordion.py`: das Partial
wird via `render_template_string` aus dem Datei-Quelltext gerendert, mit
einem `section`-dict + `server`-SimpleNamespace im Kontext.
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
# Fall 1 — Control fuer jedes ackable Band vorhanden
# ===========================================================================


@pytest.mark.parametrize("band", _ACKABLE_BANDS)
def test_ack_all_control_present_for_ackable_band(app: Flask, band: str) -> None:
    """Jedes Band aus escalate/act/mitigate/monitor/noise rendert das
    `band-ack-all-<band>`-Control."""
    html = _render_section_partial(app, section=_make_section(band))

    marker = f'data-test="band-ack-all-{band}"'
    assert marker in html, f"Control '{marker}' fehlt im Render fuer Band '{band}'. HTML: {html!r}"


# ===========================================================================
# Fall 2 — pending hat kein Control und kein Modal
# ===========================================================================


def test_pending_band_has_no_control_and_no_modal(app: Flask) -> None:
    """Band `pending`: KEIN ack-all-Control, KEIN Modal-Include."""
    html = _render_section_partial(app, section=_make_section("pending"))

    # Das Band wird gerendert (es ist nicht leer) — aber ohne ackable-Affordance.
    assert 'data-test="risk-band-pending"' in html, (
        f"pending-Band soll als <details> gerendert sein. HTML: {html!r}"
    )
    assert 'data-test="band-ack-all-pending"' not in html, (
        f"pending darf KEIN ack-all-Control haben (ADR-0044 §Verworfen e). HTML: {html!r}"
    )
    assert 'data-test="bulk-ack-band-modal"' not in html, (
        f"pending darf KEIN Modal-Include haben. HTML: {html!r}"
    )
    # Kein Alpine-Scope auf dem Wrapper.
    assert "bulkAckBand(" not in html, (
        f'pending-Wrapper darf keinen x-data="bulkAckBand(...)"-Scope haben. HTML: {html!r}'
    )


# ===========================================================================
# Fall 3 — leeres Band rendert gar nichts (kein verwaistes Modal)
# ===========================================================================


@pytest.mark.parametrize("band", ("escalate", "noise"))
def test_empty_band_renders_nothing(app: Flask, band: str) -> None:
    """`is_empty=True` -> Partial rendert nur Whitespace, kein <details>,
    kein verwaistes Modal."""
    html = _render_section_partial(app, section=_make_section(band, is_empty=True))

    assert html.strip() == "", (
        f"Leeres Band ('{band}', is_empty=True) soll nichts rendern. HTML: {html!r}"
    )
    # Doppelter Schutz: weder details noch Modal noch Control.
    assert "<details" not in html, f"Kein <details> bei leerem Band. HTML: {html!r}"
    assert "bulk-ack-band-modal" not in html, (
        f"Kein verwaistes Modal bei leerem Band. HTML: {html!r}"
    )
    assert "band-ack-all-" not in html, f"Kein Control bei leerem Band. HTML: {html!r}"


# ===========================================================================
# Fall 4 — Modal: Confirm-Checkbox, Comment ohne required, kein server-Listing
# ===========================================================================


def test_modal_confirm_checkbox_present(app: Flask) -> None:
    """Modal eines ackablen Bands enthaelt die Confirm-Checkbox."""
    html = _render_section_partial(app, section=_make_section("act"))

    assert 'data-test="bulk-ack-band-modal"' in html, (
        f"Modal soll fuer ackables Band gerendert sein. HTML: {html!r}"
    )
    assert 'data-test="bulk-ack-band-confirm-check"' in html, (
        f"Confirm-Checkbox-Hook fehlt im Modal. HTML: {html!r}"
    )


def test_modal_comment_textarea_has_no_required_attr(app: Flask) -> None:
    """ADR-0006: das Kommentar-Feld darf KEIN `required` tragen, aber
    `maxlength="8192"`."""
    import re as _re

    html = _render_section_partial(app, section=_make_section("act"))

    textarea_match = _re.search(r"<textarea\b[^>]*>", html)
    assert textarea_match is not None, f"Keine <textarea> im Modal gefunden. HTML: {html!r}"
    textarea_tag = textarea_match.group(0)

    assert "required" not in textarea_tag, (
        f"Kommentar-Textarea darf KEIN 'required' tragen (ADR-0006). Tag: {textarea_tag!r}"
    )
    assert 'maxlength="8192"' in textarea_tag, (
        f"Kommentar-Textarea soll maxlength=8192 tragen. Tag: {textarea_tag!r}"
    )


def test_modal_examples_come_from_alpine_not_server_listing(app: Flask) -> None:
    """Die Beispiel-Liste darf NICHT server-gerendert sein: der Examples-
    Container nutzt Alpine `x-for`/`<template>`, es gibt keine Jinja-
    Schleife ueber echte Finding-Objekte (kein hartes `<li>` mit echtem
    Identifier-String)."""
    section = _make_section("act")
    html = _render_section_partial(app, section=section)

    # Examples-Container vorhanden.
    assert 'data-test="bulk-ack-band-examples"' in html, (
        f"Examples-Container-Hook fehlt im Modal. HTML: {html!r}"
    )
    # Beispiele kommen aus Alpine `x-for` — der Container nutzt ein
    # <template x-for=...>, nicht eine Jinja-`for`-Schleife mit echten Items.
    assert "x-for=" in html, (
        f"Examples sollen via Alpine x-for kommen (kein server-Listing). HTML: {html!r}"
    )
    # Der Truncation-Hinweis ist ebenfalls Alpine-getrieben (x-text / x-if),
    # kein server-berechneter Count.
    assert 'data-test="bulk-ack-band-truncation"' in html, (
        f"Truncation-Hook fehlt im Modal. HTML: {html!r}"
    )
    # Negativ-Probe: keine konkreten CVE-/Finding-Identifier im Markup —
    # die `section`-Fixture traegt keinerlei Finding-Objekte, also darf auch
    # nichts derartiges erscheinen. Wir pruefen, dass die Liste keine
    # gerenderten <li>-Items mit echtem Textinhalt ausserhalb von
    # x-text-Bindings hat: alle dynamischen Werte haengen an x-text.
    assert "CVE-" not in html, (
        f"Modal darf keine server-gerenderten CVE-Identifier enthalten. HTML: {html!r}"
    )
    assert 'x-text="ex.identifier_key"' in html, (
        f"Beispiel-Identifier soll an Alpine `ex.identifier_key` binden "
        f"(client-side), nicht server-gerendert sein. HTML: {html!r}"
    )


# ===========================================================================
# Fall 5 — Modal liegt AUSSERHALB des <details>
# ===========================================================================


def test_modal_is_sibling_of_details_not_inside(app: Flask) -> None:
    """Das Modal muss als Sibling NACH dem schliessenden `</details>` stehen,
    nicht innerhalb des `<details>...</details>`-Bereichs (sonst versteckt
    ein collapsed <details> das Modal)."""
    html = _render_section_partial(app, section=_make_section("act"))

    details_open = html.index("<details")
    details_close = html.index("</details>")
    modal_pos = html.index('data-test="bulk-ack-band-modal"')

    assert modal_pos > details_close, (
        f"Modal (Pos {modal_pos}) muss NACH dem schliessenden </details> "
        f"(Pos {details_close}) stehen. HTML: {html!r}"
    )
    # Doppelter Schutz: das Modal liegt nicht im Substring zwischen
    # <details ...> und </details>.
    details_block = html[details_open:details_close]
    assert "bulk-ack-band-modal" not in details_block, (
        f"Modal darf nicht INNERHALB des <details>-Blocks liegen. "
        f"<details>-Block: {details_block!r}"
    )


# ===========================================================================
# Fall 6 — @click.prevent.stop am Control
# ===========================================================================


def test_control_has_click_prevent_stop(app: Flask) -> None:
    """Das Control traegt `@click.prevent.stop="openModal()"` (bzw. die
    aequivalente `x-on:click.prevent.stop`-Form) — sonst toggelt der Klick
    das <details>."""
    html = _render_section_partial(app, section=_make_section("noise"))

    has_at_form = '@click.prevent.stop="openModal()"' in html
    has_xon_form = 'x-on:click.prevent.stop="openModal()"' in html
    assert has_at_form or has_xon_form, (
        f"Control soll @click.prevent.stop (oder x-on:click.prevent.stop) "
        f"mit openModal() tragen. HTML: {html!r}"
    )


# ===========================================================================
# Fall 7 — Script-Include in base_app.html
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
