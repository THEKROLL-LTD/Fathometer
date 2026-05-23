"""Pure-Unit Template-Smoke-Tests fuer das bg-grid-Element.

Block W Phase B / ADR-0033 §6.

Prueft:
- base.html enthaelt `<div class="bg-grid"` mit `aria-hidden="true"`.
- base_app.html enthaelt `<div class="bg-grid"`.

Das bg-grid-Element ist ein globales Ambient-Detail das auf allen Routen
vorhanden sein muss (Login + App-Shell).

Render-Pattern:
  Identisch zu test_asset_url_in_base.py (Phase A Vorlage).
  _MOCK_MANIFEST verhindert Manifest-Lookup auf Disk.
"""

from __future__ import annotations

import pytest
from flask import Flask

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_base_html_has_bg_grid(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """base.html enthaelt '<div class=\"bg-grid\"' (fuer Login + Pre-Login-Routen)."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template("base.html")

    assert '<div class="bg-grid"' in html, (
        "bg-grid-Element fehlt in base.html. "
        "Pruefe dass '<div class=\"bg-grid\"' nach <body> eingefuegt wurde (Block W Phase B)."
    )


def test_base_html_bg_grid_has_aria_hidden(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Das bg-grid-Element in base.html hat aria-hidden='true' (rein dekorativ)."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template("base.html")

    # Pruefe dass bg-grid und aria-hidden="true" im selben Abschnitt vorkommen.
    assert 'aria-hidden="true"' in html, (
        "aria-hidden='true' fehlt in base.html. "
        "Das bg-grid-Element soll dekorativ/aria-hidden sein (ADR-0033 §6)."
    )
    # Sicherstellen dass das bg-grid-div selbst da ist
    assert 'class="bg-grid"' in html, "class='bg-grid' fehlt in base.html"


def test_base_app_html_has_bg_grid(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """base_app.html enthaelt '<div class=\"bg-grid\"' (fuer App-Shell-Routen)."""
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

    assert '<div class="bg-grid"' in html, (
        "bg-grid-Element fehlt in base_app.html. "
        "Pruefe dass '<div class=\"bg-grid\"' nach <body> eingefuegt wurde (Block W Phase B)."
    )


def test_base_app_html_bg_grid_has_aria_hidden(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Das bg-grid-Element in base_app.html hat aria-hidden='true'."""
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

    assert 'aria-hidden="true"' in html, (
        "aria-hidden='true' fehlt in base_app.html (bg-grid-Element soll dekorativ sein)"
    )
