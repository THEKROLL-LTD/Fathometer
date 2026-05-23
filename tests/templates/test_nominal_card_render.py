"""Pure-Unit Template-Smoke-Tests fuer dashboard/_nominal_card.html.

Block W Phase D.

Prueft:
- [nominal]-Label ist im Render vorhanden (englisch).
- / N hosts-Format wird korrekt gerendert.
- Sub-Counter-Format: N monitor · N noise · N unknown (englisch).
- stat--safe-Klasse ist gesetzt (Color-Doctrine: kein cyan fuer Nominal).
- id="nominal-card" fuer Phase-F-OOB-Target.

ADR-0033 Color-Reduction-Rule: stat--safe traegt kein Cyan (kein stat--alarm).
"""

from __future__ import annotations

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}

_DEFAULT_NOMINAL_DATA = {
    "monitor_count": 7,
    "hosts_total": 10,
    "monitor": 15,
    "noise": 8,
    "unknown": 3,
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _render_nominal_card(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    card_data: dict | None = None,
) -> str:
    """Rendert dashboard/_nominal_card.html mit Mock-Daten."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    data = card_data if card_data is not None else _DEFAULT_NOMINAL_DATA

    with app.test_request_context("/"):
        template = app.jinja_env.get_template("dashboard/_nominal_card.html")
        html = template.render(nominal_card_data=data)
    return html


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_nominal_card_renders_nominal_label(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render enthaelt das 'nominal'-Label mit Brackets (englisch, ADR-0033 Sprach-Policy).

    Das Template rendert die Brackets als separate <span class="bracket">-Elemente:
    <span class="bracket">[</span>nominal<span class="bracket">]</span>
    """
    html = _render_nominal_card(app, monkeypatch)

    # Das Template rendert Brackets als separate Spans — wir pruefen auf
    # den Text 'nominal' und die bracket-Spans separat.
    assert "nominal" in html, (
        "Text 'nominal' fehlt im Nominal-Card-Render. "
        "ADR-0033 Sprach-Policy: englische Strings auf redesignten Surfaces. "
        f"HTML-Ausschnitt: {html[:400]}"
    )
    # Brackets als span.bracket (Template-Pattern: <span class="bracket">[</span>)
    assert 'class="bracket"' in html, (
        f"bracket-Spans fehlen fuer [ und ] Zeichen. HTML-Ausschnitt: {html[:400]}"
    )


def test_nominal_card_shows_hosts_total(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render zeigt '/ N hosts'-Format mit dem korrekten Wert."""
    data = {**_DEFAULT_NOMINAL_DATA, "hosts_total": 42}
    html = _render_nominal_card(app, monkeypatch, data)

    assert "42" in html, f"hosts_total '42' fehlt im Render. HTML: {html[:600]}"
    assert "hosts" in html, "Label 'hosts' fehlt im '/ N hosts'-Format"


def test_nominal_card_sub_counter_format(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sub-Zeile zeigt N monitor · N noise · N unknown (englisch)."""
    data = {**_DEFAULT_NOMINAL_DATA, "monitor": 15, "noise": 8, "unknown": 3}
    html = _render_nominal_card(app, monkeypatch, data)

    assert "monitor" in html, "Label 'monitor' fehlt in Sub-Counter"
    assert "noise" in html, "Label 'noise' fehlt in Sub-Counter"
    assert "unknown" in html, "Label 'unknown' fehlt in Sub-Counter"
    assert "15" in html, f"monitor-Count '15' fehlt. HTML: {html[:600]}"
    assert "8" in html, f"noise-Count '8' fehlt. HTML: {html[:600]}"
    assert "3" in html, f"unknown-Count '3' fehlt. HTML: {html[:600]}"


def test_nominal_card_no_scan_beam_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nominal-Card hat stat--safe, aber KEIN stat--alarm (Color-Doctrine).

    ADR-0033 Color-Reduction-Rule: nur 'escalate' traegt cyan.
    Nominal-Card ist gedaempft (grau), kein Scan-Beam.
    """
    html = _render_nominal_card(app, monkeypatch)

    assert "stat--safe" in html, (
        "Klasse 'stat--safe' fehlt auf der Nominal-Card. "
        "ADR-0033: Nominal-Card ist stat--safe (kein Cyan)."
    )
    assert "stat--alarm" not in html, (
        "Klasse 'stat--alarm' darf NICHT auf der Nominal-Card vorkommen. "
        "ADR-0033 Color-Doctrine: nur escalate-State traegt cyan. "
        "Nominal-Card ist gedaempft."
    )


def test_nominal_card_has_id_nominal_card(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrapper hat id='nominal-card' fuer Phase-F-OOB-Target."""
    html = _render_nominal_card(app, monkeypatch)

    assert 'id="nominal-card"' in html, (
        "id='nominal-card' fehlt am Wrapper-Element. "
        "Wird in Phase F als OOB-Swap-Target benoetigt. "
        f"HTML-Ausschnitt: {html[:400]}"
    )


def test_nominal_card_monitor_count_rendered(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """monitor_count ist als grosse Hauptzahl im stat__num sichtbar."""
    data = {**_DEFAULT_NOMINAL_DATA, "monitor_count": 17}
    html = _render_nominal_card(app, monkeypatch, data)

    assert "17" in html, f"monitor_count '17' fehlt im Render. HTML: {html[:600]}"


def test_nominal_card_zero_counts_no_crash(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Karte rendert korrekt wenn alle Counts 0 sind (kein Crash)."""
    data = {
        "monitor_count": 0,
        "hosts_total": 0,
        "monitor": 0,
        "noise": 0,
        "unknown": 0,
    }
    html = _render_nominal_card(app, monkeypatch, data)

    assert 'id="nominal-card"' in html, "Card-Wrapper fehlt bei Null-Counts"
    assert "nominal" in html, "Text 'nominal' fehlt bei Null-Counts"


def test_nominal_card_no_scan_flash_spans(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nominal-Card hat keine scan-flash-Spans (keine Scan-Animation).

    Die Action-Card hat scan-flash (stat--alarm + Scan-Beam).
    Die Nominal-Card (stat--safe) ist bewusst ohne Animation.
    """
    html = _render_nominal_card(app, monkeypatch)

    # Die Nominal-Card selbst soll keine scan-flash-Spans enthalten —
    # sie hat keine Scan-Beam-Animation per ADR-0033 Color-Doctrine.
    assert 'class="scan-flash"' not in html, (
        "Nominal-Card darf keine scan-flash-Spans enthalten "
        "(ADR-0033: nur stat--alarm traegt Scan-Beam-Animation). "
        f"HTML-Ausschnitt: {html[:600]}"
    )
