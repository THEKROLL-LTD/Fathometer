"""Pure-Unit-Tests fuer das scan_chars-Macro in app/templates/_macros.html.

Block W Phase D.

Prueft:
- scan_chars("abc") -> mindestens 3 scan-flash-Spans (ein Span pro Char).
- scan_chars(42)    -> 2 scan-flash-Spans (ein Span pro Ziffer).
- visually-hidden-Span mit Volltext fuer Screenreader-Zugaenglichkeit.
- Jeder scan-flash-Span hat aria-hidden="true".

ADR-0033: scan-chars-Macro ist Foundation fuer die Sonar-Return-Visual-Language
auf der Action-Card. Accessibility-Anforderung: Screenreader soll den Volltext
lesen, nicht jeden Char einzeln.
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

# Minimales Test-Template das das Macro importiert und aufruft.
_MACRO_TEST_TEMPLATE = """\
{% from "_macros.html" import scan_chars %}
{{ scan_chars(value) }}
"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _render_scan_chars(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    value: str | int,
) -> str:
    """Rendert scan_chars(value) via Jinja-Template-String."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/"):
        tmpl = app.jinja_env.from_string(_MACRO_TEST_TEMPLATE)
        html = tmpl.render(value=value)
    return html


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_scan_chars_macro_splits_chars(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_chars('abc') erzeugt mindestens 3 scan-flash-Spans (einen pro Char)."""
    html = _render_scan_chars(app, monkeypatch, "abc")

    count = html.count('class="scan-flash"')
    assert count >= 3, (
        f"scan_chars('abc') muss mindestens 3 scan-flash-Spans erzeugen (a, b, c), "
        f"hat {count} erzeugt. HTML: {html}"
    )


def test_scan_chars_macro_handles_integer(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_chars(42) erzeugt exakt 2 scan-flash-Spans (Ziffern 4 und 2)."""
    html = _render_scan_chars(app, monkeypatch, 42)

    count = html.count('class="scan-flash"')
    assert count >= 2, (
        f"scan_chars(42) muss mindestens 2 scan-flash-Spans erzeugen (4, 2), "
        f"hat {count} erzeugt. HTML: {html}"
    )
    # Die Ziffern muessen im Render sichtbar sein.
    assert "4" in html and "2" in html, (
        f"Ziffern '4' und '2' fehlen im scan_chars(42)-Render. HTML: {html}"
    )


def test_scan_chars_macro_has_visually_hidden_full_text(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """visually-hidden-Span mit Volltext fuer Screenreader.

    Screenreader soll den Volltext lesen, nicht jeden Char einzeln.
    Der Span muss class="visually-hidden" und den Volltext enthalten.
    """
    html = _render_scan_chars(app, monkeypatch, "abc")

    assert 'class="visually-hidden"' in html, (
        "visually-hidden-Span fehlt. Screenreader wuerde jeden Buchstaben einzeln vorlesen. "
        f"HTML: {html}"
    )
    assert "abc" in html, (
        f"Volltext 'abc' fehlt im Render (sollte in visually-hidden-Span stehen). HTML: {html}"
    )


def test_scan_chars_spans_have_aria_hidden(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jeder scan-flash-Span hat aria-hidden='true'.

    Die Einzel-Char-Spans sollen von Screenreadern uebersprungen werden —
    der Volltext kommt aus dem visually-hidden-Span.
    """
    html = _render_scan_chars(app, monkeypatch, "abc")

    assert 'aria-hidden="true"' in html, (
        "aria-hidden='true' fehlt auf den scan-flash-Spans. "
        "Screenreader wuerde sonst die Char-Spans zusaetzlich zum visually-hidden-Volltext vorlesen. "
        f"HTML: {html}"
    )


def test_scan_chars_macro_integer_visually_hidden(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_chars(42) hat visually-hidden-Span mit '42' fuer Screenreader."""
    html = _render_scan_chars(app, monkeypatch, 42)

    assert 'class="visually-hidden"' in html, (
        f"visually-hidden-Span fehlt bei scan_chars(42). HTML: {html}"
    )
    assert "42" in html, (
        f"Volltext '42' fehlt (sollte in visually-hidden-Span stehen). HTML: {html}"
    )


def test_scan_chars_macro_wrapped_in_scan_chars_container(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_chars-Ausgabe ist in einem scan-chars-Container-Element gewrappt."""
    html = _render_scan_chars(app, monkeypatch, "test")

    assert 'class="scan-chars"' in html, (
        "scan-chars-Container-Klasse fehlt im Macro-Output. "
        "dashboard_scan_sync.js braucht diesen Container als Anker. "
        f"HTML: {html}"
    )


def test_scan_chars_macro_space_rendered(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_chars('a b') rendert den Space ohne Crash (Space -> non-breaking or regular space)."""
    html = _render_scan_chars(app, monkeypatch, "a b")

    # Kein Crash und mindestens 3 Spans (a, space, b).
    count = html.count('class="scan-flash"')
    assert count >= 3, (
        f"scan_chars('a b') muss mindestens 3 Spans erzeugen (a, space, b), "
        f"hat {count} erzeugt. HTML: {html}"
    )


def test_scan_chars_macro_empty_string(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_chars('') rendert ohne Crash und erzeugt 0 scan-flash-Spans."""
    html = _render_scan_chars(app, monkeypatch, "")

    # Kein Crash ist die Hauptanforderung.
    # Bei leerem String keine scan-flash-Spans (Schleife ueber leeren String).
    count = html.count('class="scan-flash"')
    assert count == 0, (
        f"scan_chars('') soll 0 scan-flash-Spans erzeugen, hat {count} erzeugt. HTML: {html}"
    )
