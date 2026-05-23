"""Pure-Unit-Tests fuer das fathometer_logo-Jinja-Macro.

Block W Phase B / ADR-0033 §1.

Prueft:
- Macro rendert ein <svg>-Element mit aria-label="Fathometer".
- Default-Klasse ist "topbar__logo".
- Custom-Klasse wird korrekt auf dem SVG gesetzt.
- SVG enthaelt Elemente mit Sweep-Animation-Klasse (topbar__logo-sweep).
- SVG enthaelt Elemente mit Echo-Pulse-Klasse (topbar__logo-echo).

Render-Pattern:
  app.jinja_env.from_string('{% from "_macros.html" import fathometer_logo %}{{ fathometer_logo() }}')
  innerhalb von app.test_request_context("/").
"""

from __future__ import annotations

import pytest
from flask import Flask

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}


def _render_logo(app: Flask, monkeypatch: pytest.MonkeyPatch) -> str:
    """Rendert das fathometer_logo-Macro mit Default-Klasse (topbar__logo)."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    source = '{% from "_macros.html" import fathometer_logo %}{{ fathometer_logo() }}'
    with app.test_request_context("/"):
        template = app.jinja_env.from_string(source)
        return template.render()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_fathometer_logo_macro_renders_svg(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fathometer_logo() rendert ein <svg>-Element."""
    html = _render_logo(app, monkeypatch)

    assert "<svg" in html, f"fathometer_logo() muss ein <svg>-Element rendern. Output: {html[:200]}"


def test_fathometer_logo_macro_aria_label(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fathometer_logo()-SVG hat aria-label='Fathometer'."""
    html = _render_logo(app, monkeypatch)

    assert 'aria-label="Fathometer"' in html, (
        f"aria-label='Fathometer' fehlt auf dem SVG-Element. Output: {html[:300]}"
    )


def test_fathometer_logo_macro_default_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fathometer_logo() ohne Parameter hat class='topbar__logo' auf dem SVG."""
    html = _render_logo(app, monkeypatch)

    assert 'class="topbar__logo"' in html, (
        f"Default-Klasse 'topbar__logo' fehlt auf dem SVG. Output: {html[:300]}"
    )


def test_fathometer_logo_macro_custom_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fathometer_logo('login__logo') -> SVG hat class='login__logo' (Custom-Klasse)."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    source = '{% from "_macros.html" import fathometer_logo %}{{ fathometer_logo("login__logo") }}'
    with app.test_request_context("/"):
        template = app.jinja_env.from_string(source)
        html = template.render()

    assert 'class="login__logo"' in html, (
        f"Custom-Klasse 'login__logo' fehlt auf dem SVG. Output: {html[:300]}"
    )
    # Default-Klasse darf nicht vorhanden sein wenn Custom-Klasse gesetzt
    assert 'class="topbar__logo"' not in html, (
        "Default-Klasse 'topbar__logo' darf nicht vorhanden sein wenn Custom-Klasse gesetzt"
    )


def test_fathometer_logo_has_sweep_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SVG enthaelt Element mit class='topbar__logo-sweep' (Sweep-Animation-CSS-Hook)."""
    html = _render_logo(app, monkeypatch)

    assert "topbar__logo-sweep" in html, (
        f"Sweep-Klasse 'topbar__logo-sweep' fehlt im SVG-Markup. Output: {html[:500]}"
    )


def test_fathometer_logo_has_echo_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SVG enthaelt Element mit class='topbar__logo-echo' (Echo-Pulse-Animation-CSS-Hook)."""
    html = _render_logo(app, monkeypatch)

    assert "topbar__logo-echo" in html, (
        f"Echo-Klasse 'topbar__logo-echo' fehlt im SVG-Markup. Output: {html[:500]}"
    )


def test_fathometer_logo_has_sweep_and_pulse_classes(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kombinierter Test: SVG enthaelt BEIDE Animations-Klassen (Sweep + Echo)."""
    html = _render_logo(app, monkeypatch)

    assert "topbar__logo-sweep" in html and "topbar__logo-echo" in html, (
        f"Sweep- UND Echo-Klassen muessen beide vorhanden sein. "
        f"topbar__logo-sweep={'topbar__logo-sweep' in html}, "
        f"topbar__logo-echo={'topbar__logo-echo' in html}. "
        f"Output: {html[:500]}"
    )


def test_fathometer_logo_svg_has_role_img(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SVG hat role='img' fuer korrekte ARIA-Semantik."""
    html = _render_logo(app, monkeypatch)

    assert 'role="img"' in html, f"role='img' fehlt auf dem SVG-Element. Output: {html[:300]}"


def test_fathometer_logo_contains_accent_color(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SVG-Sweep-Nadel und Echo-Dot verwenden var(--accent) (ADR-0033 Color-Doctrine)."""
    html = _render_logo(app, monkeypatch)

    assert "var(--accent)" in html, (
        "Sweep-Nadel/-Dot soll 'var(--accent)' als Farbe haben (ADR-0033 Color-Reduction-Rule)"
    )
