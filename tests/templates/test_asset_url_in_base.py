"""Template-Smoke-Tests fuer asset_url-Tags in base.html und base_app.html.

Block W / ADR-0032 — Phase A.

Prueft:
- `base.html` enthaelt nach Render den gehashten CSS-Link-Tag.
- `base_app.html` enthaelt nach Render den gehashten CSS-Link-Tag.
- Beide Templates rendern alle drei Asset-Typen (CSS + 2x JS) via asset_url.

Mock-Strategie:
  `app._asset_manifest` (Modul-State) wird via monkeypatch auf ein bekanntes
  Test-Dict gesetzt, bevor der Render stattfindet. `_asset_url` liest den
  gecachten State und muss keine Disk-Operation durchfuehren.

Render-Pattern:
  `flask.render_template` im `app.test_request_context("/")` — identisch
  zum Production-Pfad, Flask-WTF-CSRF und Flask-Login sind initialisiert.
  Kein eingeloggter User: `current_user.is_authenticated == False` ->
  kein Profil-Dropdown, keine Sidebar-DB-Calls.
"""

from __future__ import annotations

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Manifest-Konstanten fuer alle Tests
# ---------------------------------------------------------------------------

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}

_EXPECTED_CSS_LINK = "/static/dist/css/app.abc123.css"
_EXPECTED_VENDOR_JS = "/static/dist/js/vendor.def456.js"
_EXPECTED_APP_JS = "/static/dist/js/app.ghi789.js"


# ---------------------------------------------------------------------------
# base.html
# ---------------------------------------------------------------------------


def test_base_html_renders_asset_url_link_tag(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """base.html enthaelt den gehashten CSS-Link nach Render mit Mock-Manifest.

    Prueft dass `asset_url('css/app.css')` im Template aufgerufen wird und
    den Wert aus dem Manifest aufloest — nicht den unverhashten Fallback-Pfad.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template("base.html")

    assert _EXPECTED_CSS_LINK in html, (
        f"Erwartet '{_EXPECTED_CSS_LINK}' in base.html, aber nicht gefunden. "
        f"asset_url('css/app.css') muss den Hash-Wert aus dem Manifest nehmen."
    )


def test_base_html_renders_all_three_asset_url_tags(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """base.html enthaelt nach Render CSS-Link + beide JS-Script-Tags mit Hashes."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template("base.html")

    assert _EXPECTED_CSS_LINK in html, (
        f"css/app.css-Hash fehlt in base.html: {_EXPECTED_CSS_LINK!r}"
    )
    assert _EXPECTED_VENDOR_JS in html, (
        f"js/vendor.js-Hash fehlt in base.html: {_EXPECTED_VENDOR_JS!r}"
    )
    assert _EXPECTED_APP_JS in html, f"js/app.js-Hash fehlt in base.html: {_EXPECTED_APP_JS!r}"


# ---------------------------------------------------------------------------
# base_app.html
# ---------------------------------------------------------------------------


def test_base_app_html_renders_asset_url_link_tag(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """base_app.html enthaelt den gehashten CSS-Link nach Render mit Mock-Manifest.

    base_app.html inkludiert layout/_header.html, sidebar/_search.html und
    sidebar/_server_list.html. Mit unauthentiziertem User werden Sidebar-
    DB-Calls durch den Context-Processor uebersprungen (liefert leeres dict).
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "base_app.html",
            sidebar_servers=[],
            filter_tags=[],
            active_server_id=None,
        )

    assert _EXPECTED_CSS_LINK in html, (
        f"Erwartet '{_EXPECTED_CSS_LINK}' in base_app.html, aber nicht gefunden. "
        f"asset_url('css/app.css') muss den Hash-Wert aus dem Manifest nehmen."
    )


def test_base_app_html_renders_all_three_asset_url_tags(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """base_app.html enthaelt nach Render CSS-Link + beide JS-Script-Tags mit Hashes."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "base_app.html",
            sidebar_servers=[],
            filter_tags=[],
            active_server_id=None,
        )

    assert _EXPECTED_CSS_LINK in html, (
        f"css/app.css-Hash fehlt in base_app.html: {_EXPECTED_CSS_LINK!r}"
    )
    assert _EXPECTED_VENDOR_JS in html, (
        f"js/vendor.js-Hash fehlt in base_app.html: {_EXPECTED_VENDOR_JS!r}"
    )
    assert _EXPECTED_APP_JS in html, f"js/app.js-Hash fehlt in base_app.html: {_EXPECTED_APP_JS!r}"


# ---------------------------------------------------------------------------
# Regressions-Sicherung: unverhashte Fallback-Pfade tauchen nicht auf
# ---------------------------------------------------------------------------


def test_base_html_does_not_use_unhashed_css_path_when_manifest_present(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn Manifest gesetzt ist, darf der unverhashte Pfad nicht im Output stehen.

    Dieser Test schlaegt fehl wenn asset_url immer den Fallback-Pfad
    zurueckgibt (z.B. weil _asset_manifest nicht korrekt gelesen wird).
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template("base.html")

    # Hash-Pfad muss vorhanden sein.
    assert "dist/css/app.abc123.css" in html, (
        "Hash-Pfad 'dist/css/app.abc123.css' fehlt im Render-Output."
    )
    # Der exakte unverhashte Pfad '/static/dist/css/app.css"' darf nicht
    # als href-Wert vorkommen (als Teil des Hash-Namens ist 'app.css' OK).
    assert '/static/dist/css/app.css"' not in html, (
        "Unverhashter Fallback-Pfad '/static/dist/css/app.css' wurde gerendert, "
        "obwohl das Manifest einen Hash-Pfad enthaelt. Manifest-Lookup defekt."
    )
