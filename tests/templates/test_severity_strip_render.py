"""Pure-Unit Template-Smoke-Tests fuer dashboard/_severity_strip.html.

Block W Phase E.

Prueft:
- Genau 4 Items in der Reihenfolge critical, high, medium, low
  via data-test-Attribute.
- critical-Item traegt severity__item--crit-Klasse (ADR-0033 Color-Doctrine).
- Bar-Width ist max-normalisiert (style="width: {pct}%").
- count=0 -> Bar hat width: 0%.
- Wrapper-ID ist 'severity-strip' (Phase-F-OOB-Target).

Render-Pattern: Flask-App mit test_request_context + jinja_env.get_template().
_MOCK_MANIFEST verhindert Manifest-Lookup auf Disk.
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

_SEVERITY_ORDER = ("critical", "high", "medium", "low")

_DEFAULT_SEVERITY_COUNTS: dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 3,
    "low": 1,
    "max_count": 10,
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _render_severity_strip(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    severity_counts: dict[str, int] | None = None,
) -> str:
    """Rendert dashboard/_severity_strip.html mit Mock-Daten."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    counts = severity_counts if severity_counts is not None else _DEFAULT_SEVERITY_COUNTS

    with app.test_request_context("/"):
        template = app.jinja_env.get_template("dashboard/_severity_strip.html")
        html = template.render(severity_counts=counts)
    return html


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_severity_strip_renders_4_items(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render enthaelt genau 4 Items in der Reihenfolge critical, high, medium, low.

    Items werden via data-test-Attribut identifiziert.
    """
    html = _render_severity_strip(app, monkeypatch)

    for sev in _SEVERITY_ORDER:
        marker = f'data-test="severity-{sev}"'
        assert marker in html, (
            f"data-test='severity-{sev}' fehlt im Render. HTML-Ausschnitt: {html[:600]}"
        )

    # Reihenfolge: jeder Marker muss vor dem naechsten erscheinen.
    positions = [html.index(f'data-test="severity-{s}"') for s in _SEVERITY_ORDER]
    assert positions == sorted(positions), (
        f"Severity-Items sind nicht in Design-Reihenfolge (critical > high > medium > low). "
        f"Gefundene Positionen: {dict(zip(_SEVERITY_ORDER, positions, strict=False))}"
    )


def test_severity_critical_has_crit_modifier(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """critical-Item traegt severity__item--crit (ADR-0033: nur critical bekommt Cyan)."""
    html = _render_severity_strip(app, monkeypatch)

    assert "severity__item--crit" in html, (
        "severity__item--crit fehlt im Render. "
        "ADR-0033 Color-Doctrine: nur critical traegt --accent (cyan). "
        f"HTML-Ausschnitt: {html[:600]}"
    )


def test_severity_bar_width_normalized_to_max(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bar-Width ist max-normalisiert: critical=10, max_count=10 -> 100%; high=5 -> 50%."""
    counts = {
        "critical": 10,
        "high": 5,
        "medium": 2,
        "low": 1,
        "max_count": 10,
    }
    html = _render_severity_strip(app, monkeypatch, counts)

    # critical (10/10 = 100%).
    assert "width: 100%" in html, (
        f"critical-Bar muss 'width: 100%' haben (10/10*100=100%). HTML: {html[:800]}"
    )
    # high (5/10 = 50%).
    assert "width: 50%" in html, (
        f"high-Bar muss 'width: 50%' haben (5/10*100=50%). HTML: {html[:800]}"
    )


def test_severity_bar_width_zero_when_count_zero(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """count=0 -> Bar hat width: 0% (kein negativer oder leerer Wert)."""
    counts = {
        "critical": 10,
        "high": 0,
        "medium": 0,
        "low": 0,
        "max_count": 10,
    }
    html = _render_severity_strip(app, monkeypatch, counts)

    assert "width: 0%" in html, f"Bei count=0 muss 'width: 0%' erscheinen. HTML: {html[:800]}"


def test_severity_bar_width_all_zero_uses_max_count_1(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn alle Counts 0 und max_count=1 (Division-by-Zero-Schutz) -> alle Bars 0%."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "max_count": 1,  # Schutzwert aus _load_severity_counts
    }
    html = _render_severity_strip(app, monkeypatch, counts)

    # Alle 4 Bars muessen 0% sein.
    zero_count = html.count("width: 0%")
    assert zero_count == 4, (
        f"Erwartet 4x 'width: 0%' bei allen-null-Counts, erhalten: {zero_count}. HTML: {html[:800]}"
    )


def test_severity_strip_has_id_for_oob(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrapper-Section hat id='severity-strip' (Phase-F-OOB-Target, ADR-0036)."""
    html = _render_severity_strip(app, monkeypatch)

    assert 'id="severity-strip"' in html, (
        "id='severity-strip' fehlt am Wrapper-Element. "
        "Wird in Phase F als OOB-Swap-Target fuer /_partials/dashboard/kpis benoetigt. "
        f"HTML-Ausschnitt: {html[:400]}"
    )


def test_severity_strip_renders_severity_labels(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Alle 4 Severity-Label-Texte sind im Render vorhanden."""
    html = _render_severity_strip(app, monkeypatch)

    for label in _SEVERITY_ORDER:
        assert label in html, (
            f"Label '{label}' fehlt im Severity-Strip-Render. HTML-Ausschnitt: {html[:600]}"
        )
