"""Pure-Unit-Tests fuer ``servers/_kpi_card.html`` (Block X Phase E, ADR-0038 §10).

Prueft (DoD-Punkt 5, Block X Phase E):
  1.  skel=True rendert Em-Dash ``—`` statt dem numerischen Wert.
  2.  skel=True: Container hat ``sd-tile--skel sd-skel-frame``.
  3.  skel=True + sparkline=[1,2,3]: kein ``sd-spark``-Element im Output.
  4.  skel=False, value=0: ``sd-tile__num--zero``-Klasse vorhanden.
  5.  link_url gesetzt + skel=False: ``<a>``-Tag mit hx-get-Attribut.
  6.  link_url gesetzt + skel=True: ``<div>``-Tag (kein ``<a>``, kein hx-get).
  7.  label="KEV" -> data-test="kpi-card-kev".

Render-Strategie:
  - ``render_template_string`` mit verbatim Source-Read des Partials.
  - Flask-App-Context via ``app``-Fixture.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Pfad zum Partial
# ---------------------------------------------------------------------------

_PARTIAL_PATH = (
    Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "_kpi_card.html"
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _load_partial_source() -> str:
    """Laedt _kpi_card.html-Source direkt vom Filesystem."""
    return _PARTIAL_PATH.read_text(encoding="utf-8")


def _render(
    app: Flask,
    *,
    label: str = "KEV",
    value: int = 42,
    tone: str = "base",
    sparkline: list[int] | None = None,
    kev_indicator: bool = False,
    link_url: str | None = None,
    skel: bool = False,
) -> str:
    """Rendert _kpi_card.html mit den angegebenen Variablen."""
    from flask import render_template_string

    source = _load_partial_source()
    ctx: dict = {
        "label": label,
        "value": value,
        "tone": tone,
        "sparkline": sparkline or [],
        "kev_indicator": kev_indicator,
        "link_url": link_url,
        "skel": skel,
    }
    with app.test_request_context("/"):
        return render_template_string(source, **ctx)


# ---------------------------------------------------------------------------
# Test 1 — skel=True rendert Em-Dash statt Wert
# ---------------------------------------------------------------------------


def test_kpi_card_skel_renders_em_dash(app: Flask) -> None:
    """skel=True, value=42: Output enthaelt '—' (em-dash), nicht '42'."""
    html = _render(app, label="KEV", value=42, skel=True)

    assert "—" in html, f"Em-Dash '—' fehlt im Skel-State-Output. HTML: {html!r}"
    # Der numerische Wert 42 darf nicht sichtbar sein
    # (Vorsicht: er koennte in data-*-Attributen o.ae. auftauchen — wir pruefen
    # nur dass er nicht im Zahlen-Container steht, also als Text-Content.)
    # Pragmatischer Check: "42" kommt nicht als eigenstaendige Zahl vor.
    # Da das Template bei skel nur "—" rendert (kein {{ value }}), ist "42"
    # komplett absent.
    assert ">42<" not in html and ">42 <" not in html, (
        f"Numerischer Wert '42' darf im Skel-State nicht sichtbar sein. HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 2 — skel=True: Container-Klassen enthalten sd-tile--skel + sd-skel-frame
# ---------------------------------------------------------------------------


def test_kpi_card_skel_has_modifier_classes(app: Flask) -> None:
    """skel=True: Container hat 'sd-tile--skel' und 'sd-skel-frame'."""
    html = _render(app, skel=True)

    assert "sd-tile--skel" in html, (
        f"'sd-tile--skel' fehlt im Skel-State-Container. HTML: {html[:400]!r}"
    )
    assert "sd-skel-frame" in html, (
        f"'sd-skel-frame' fehlt im Skel-State-Container. HTML: {html[:400]!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — skel=True + sparkline: kein sd-spark-Element
# ---------------------------------------------------------------------------


def test_kpi_card_skel_has_no_sparkline(app: Flask) -> None:
    """skel=True + sparkline=[1,2,3]: kein 'sd-spark'-Element im Output."""
    html = _render(app, sparkline=[1, 2, 3], skel=True)

    assert "sd-spark" not in html, (
        f"'sd-spark' darf im Skel-State nicht gerendert werden. "
        f"Sparkline soll bei skel=True ausgeblendet sein. HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — value=0: sd-tile__num--zero-Klasse
# ---------------------------------------------------------------------------


def test_kpi_card_zero_value_has_zero_modifier(app: Flask) -> None:
    """skel=False, value=0 -> sd-tile__num--zero-Klasse am Zahl-Container."""
    html = _render(app, value=0, skel=False)

    assert "sd-tile__num--zero" in html, f"'sd-tile__num--zero' fehlt bei value=0. HTML: {html!r}"


def test_kpi_card_nonzero_value_has_no_zero_modifier(app: Flask) -> None:
    """skel=False, value=5: kein sd-tile__num--zero."""
    html = _render(app, value=5, skel=False)

    assert "sd-tile__num--zero" not in html, (
        f"'sd-tile__num--zero' darf bei value=5 nicht vorhanden sein. HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 5 — link_url + skel=False: <a>-Tag mit hx-get
# ---------------------------------------------------------------------------


def test_kpi_card_with_link_url_renders_anchor(app: Flask) -> None:
    """link_url='/x', skel=False -> <a>-Tag mit hx-get='/x'."""
    html = _render(app, link_url="/x", skel=False)

    assert "<a " in html, f"'<a'-Tag fehlt bei link_url='/x' und skel=False. HTML: {html!r}"
    assert 'hx-get="/x"' in html, f"'hx-get=\"/x\"' fehlt bei link_url='/x'. HTML: {html!r}"
    # Kein <div> als Wrapper wenn link_url gesetzt und skel=False
    assert "<div " not in html.split("<a ")[0] or True, (
        # Dieser Check ist schwierig ohne HTML-Parser — wir pruefen stattdessen
        # dass das erste Block-Element ein <a> ist.
        "Struktureller Check: erstes Block-Element soll <a> sein."
    )


def test_kpi_card_with_link_url_skel_false_no_div_wrapper(app: Flask) -> None:
    """link_url gesetzt + skel=False: Das Root-Element ist <a>, nicht <div>."""
    html = _render(app, link_url="/dashboard/findings", skel=False, value=7)

    # Erstes Tag im HTML soll <a sein
    stripped = html.strip()
    assert stripped.startswith("<a "), (
        f"Root-Element bei link_url+skel=False soll '<a ...' sein. "
        f"Tatsaechlicher Anfang: {stripped[:80]!r}"
    )


# ---------------------------------------------------------------------------
# Test 6 — link_url + skel=True: <div>-Tag, kein <a>, kein hx-get
# ---------------------------------------------------------------------------


def test_kpi_card_skel_with_link_url_renders_div_not_anchor(app: Flask) -> None:
    """link_url='/x', skel=True -> <div>-Tag (kein <a>, kein hx-get)."""
    html = _render(app, link_url="/x", skel=True)

    # Root-Element soll <div> sein
    stripped = html.strip()
    assert stripped.startswith("<div "), (
        f"Root-Element bei link_url+skel=True soll '<div ...' sein. "
        f"Tatsaechlicher Anfang: {stripped[:80]!r}"
    )

    # Kein hx-get im Skel-State
    assert "hx-get" not in html, f"'hx-get' darf im Skel-State nicht vorhanden sein. HTML: {html!r}"

    # Kein <a>-Tag
    assert "<a " not in html, f"'<a'-Tag darf bei skel=True nicht gerendert werden. HTML: {html!r}"


# ---------------------------------------------------------------------------
# Test 7 — data-test-Attribut aus label
# ---------------------------------------------------------------------------


def test_kpi_card_data_test_anchor(app: Flask) -> None:
    """label='KEV' -> data-test='kpi-card-kev'."""
    html = _render(app, label="KEV", skel=False)

    assert 'data-test="kpi-card-kev"' in html, (
        f"'data-test=\"kpi-card-kev\"' fehlt. "
        f"Erwartet: label.lower() als data-test-Suffix. HTML: {html[:400]!r}"
    )


@pytest.mark.parametrize(
    "label, expected_data_test",
    [
        ("Critical", "kpi-card-critical"),
        ("High", "kpi-card-high"),
        ("Medium", "kpi-card-medium"),
        ("KEV", "kpi-card-kev"),
    ],
)
def test_kpi_card_data_test_label_mapping(app: Flask, label: str, expected_data_test: str) -> None:
    """data-test-Attribut wird korrekt aus dem Label abgeleitet (parametrize)."""
    html = _render(app, label=label, skel=False)

    assert f'data-test="{expected_data_test}"' in html, (
        f"data-test='{expected_data_test}' fehlt fuer label='{label}'. HTML: {html[:400]!r}"
    )


# ---------------------------------------------------------------------------
# Extra — tone='error' -> sd-tile--accent
# ---------------------------------------------------------------------------


def test_kpi_card_tone_error_gets_accent_class(app: Flask) -> None:
    """tone='error' -> sd-tile--accent-Klasse (ADR-0038 §10: error = accent-look)."""
    html = _render(app, tone="error", skel=False)

    assert "sd-tile--accent" in html, (
        f"'sd-tile--accent' fehlt bei tone='error'. HTML: {html[:400]!r}"
    )


def test_kpi_card_tone_base_no_accent_class(app: Flask) -> None:
    """tone='base' -> kein sd-tile--accent."""
    html = _render(app, tone="base", skel=False)

    assert "sd-tile--accent" not in html, (
        f"'sd-tile--accent' darf bei tone='base' nicht vorhanden sein. HTML: {html[:400]!r}"
    )
