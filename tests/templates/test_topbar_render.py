"""Pure-Unit Template-Smoke-Tests fuer den neuen Topbar (_header.html).

Block W Phase B.

Prueft:
- Wordmark "Fathometer" und Subline "CVE Intelligence" sind im Render.
- Nav-Items "Dashboard" und "Findings" sind vorhanden.
- Profile-Avatar zeigt die ersten 2 Buchstaben des Username uppercased.
- Active-Nav-Klasse wird korrekt gesetzt (endpoint-basiert).

Render-Pattern:
  Flask-App mit test_request_context.
  current_user wird als Mock-Objekt injiziert (kein Login-Manager notig).
  _MOCK_MANIFEST verhindert Manifest-Lookup auf Disk.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Fixtures / Hilfsfunktionen
# ---------------------------------------------------------------------------

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}


def _render_header(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    *,
    username: str = "admin",
    path: str = "/",
    endpoint: str = "dashboard.index",
) -> str:
    """Rendert layout/_header.html mit einem Mock-User im Request-Context."""

    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    # Mock-User mit is_authenticated=True
    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_user.username = username

    with app.test_request_context(path):
        # flask_login.current_user ist ein LocalProxy — wir setzen ihn ueber
        # den Jinja-Global, damit das Template ihn sieht.
        app.jinja_env.globals["current_user"] = mock_user

        # request.endpoint wird im Test-Request-Context nicht automatisch
        # gesetzt; wir rendern mit einem Wrapper, der den Endpoint simuliert.
        from flask import request as flask_request

        # Override endpoint im Request-Context
        flask_request.environ["werkzeug.request"] = flask_request
        # Setze endpoint direkt ueber Adapter
        flask_request.url_rule = MagicMock()
        flask_request.url_rule.endpoint = endpoint

        # Template via Jinja-Env direkt laden
        template = app.jinja_env.get_template("layout/_header.html")
        html = template.render(
            current_user=mock_user,
            request=flask_request,
        )
    return html


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_topbar_renders_fathometer_wordmark(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_header.html enthaelt 'Fathometer'-Wordmark und 'CVE Intelligence'-Subline."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_user.username = "admin"

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "layout/_header.html",
            current_user=mock_user,
        )

    assert "Fathometer" in html, (
        f"Wordmark 'Fathometer' fehlt im Topbar-Render. HTML-Laenge: {len(html)}"
    )
    assert "CVE Intelligence" in html, (
        f"Subline 'CVE Intelligence' fehlt im Topbar-Render. HTML-Laenge: {len(html)}"
    )


def test_topbar_renders_nav_items(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_header.html enthaelt Nav-Links 'Dashboard' und 'Findings' fuer eingeloggten User."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_user.username = "admin"

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "layout/_header.html",
            current_user=mock_user,
        )

    assert "Dashboard" in html, "Nav-Item 'Dashboard' fehlt im Topbar-Render fuer eingeloggten User"
    assert "Findings" in html, "Nav-Item 'Findings' fehlt im Topbar-Render fuer eingeloggten User"


def test_topbar_renders_profile_avatar_initials(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Avatar zeigt die ersten 2 Buchstaben des Username uppercased.

    Username 'admin' -> Avatar 'AD'.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_user.username = "admin"

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "layout/_header.html",
            current_user=mock_user,
        )

    assert "AD" in html, "Avatar-Initialen 'AD' (Username 'admin'[:2].upper()) fehlen im Render"


def test_topbar_renders_profile_avatar_other_username(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Avatar-Initialen aus einem anderen Username: 'operator' -> 'OP'."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_user.username = "operator"

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "layout/_header.html",
            current_user=mock_user,
        )

    assert "OP" in html, "Avatar-Initialen 'OP' (Username 'operator'[:2].upper()) fehlen im Render"


def test_topbar_renders_fathometer_logo_svg(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_header.html enthaelt das SVG-Logo mit aria-label='Fathometer'."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_user.username = "admin"

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "layout/_header.html",
            current_user=mock_user,
        )

    assert "<svg" in html, "SVG-Element fehlt im Topbar-Render"
    assert 'aria-label="Fathometer"' in html, (
        "aria-label='Fathometer' auf dem SVG fehlt im Topbar-Render"
    )


def test_topbar_no_nav_for_unauthenticated_user(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kein Nav/Profile-Dropdown fuer unauthentifizierten User."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    mock_user = MagicMock()
    mock_user.is_authenticated = False

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "layout/_header.html",
            current_user=mock_user,
        )

    # Nav-Items sollen fuer unauthentifizierte User nicht gerendert werden
    assert "topbar__navitem" not in html, (
        "Nav-Items duerften fuer unauthentifizierten User nicht gerendert werden"
    )


def test_topbar_active_nav_dashboard_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auf dem Dashboard-Pfad '/' traegt der Dashboard-Nav-Item die Active-Klasse."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_user.username = "admin"

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "layout/_header.html",
            current_user=mock_user,
        )

    assert "topbar__navitem--active" in html, (
        "Active-Klasse 'topbar__navitem--active' fehlt auf dem Dashboard-Pfad '/'"
    )
