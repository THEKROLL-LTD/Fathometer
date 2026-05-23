"""Pure-Unit Template-Smoke-Tests fuer das Profile-Dropdown (_profile_dropdown.html).

Block W Phase B / ADR-0033 Sprach-Policy.

Prueft:
- Englische Strings: 'Logged in as', Username, 'Settings', 'Audit', 'Logout'.
- Logout ist ein <form method="post"> (kein <a>-Link).
- CSRF-Token-Input ist vorhanden (csrf_token()-Helper).
- Kein alter Deutsch-String ('Angemeldet als').

Render-Pattern:
  render_template("layout/_profile_dropdown.html", current_user=mock_user)
  innerhalb von app.test_request_context("/").
  WTF_CSRF_ENABLED=False im Test, damit csrf_token() ohne DB-Session
  einen Dummy-Wert liefert.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from flask import Flask

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}


def _render_dropdown(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    username: str = "admin",
) -> str:
    """Rendert _profile_dropdown.html mit Mock-User."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_user.username = username

    # CSRF deaktivieren damit csrf_token() ohne Session-Backend funktioniert
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_request_context("/"):
        from flask import render_template

        html = render_template(
            "layout/_profile_dropdown.html",
            current_user=mock_user,
        )
    return html


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_profile_dropdown_logged_in_as_english(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropdown enthaelt englischen String 'Logged in as'."""
    html = _render_dropdown(app, monkeypatch, username="admin")

    assert "Logged in as" in html, (
        f"Englischer String 'Logged in as' fehlt im Profile-Dropdown. HTML: {html[:500]}"
    )


def test_profile_dropdown_shows_username(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropdown zeigt den aktuellen Username."""
    html = _render_dropdown(app, monkeypatch, username="admin")

    assert "admin" in html, "Username 'admin' fehlt im Profile-Dropdown"


def test_profile_dropdown_has_settings(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropdown enthaelt 'Settings'-Link."""
    html = _render_dropdown(app, monkeypatch)

    assert "Settings" in html, "Englischer String 'Settings' fehlt im Profile-Dropdown"


def test_profile_dropdown_has_audit(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropdown enthaelt 'Audit'-Link."""
    html = _render_dropdown(app, monkeypatch)

    assert "Audit" in html, "Englischer String 'Audit' fehlt im Profile-Dropdown"


def test_profile_dropdown_has_logout(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropdown enthaelt 'Logout'-Element."""
    html = _render_dropdown(app, monkeypatch)

    assert "Logout" in html, "Englischer String 'Logout' fehlt im Profile-Dropdown"


def test_profile_dropdown_logout_is_post_form(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logout ist ein <form method=\"post\"> (kein <a>-Link — CSRF-Schutz per Design).

    Prueft:
    1. Es gibt ein <form method="post"> im Dropdown.
    2. Das Logout-Element ist ein <button type="submit">, kein <a>-Logout-Link.
    """
    html = _render_dropdown(app, monkeypatch)

    assert 'method="post"' in html, (
        "Logout-Form muss method='post' haben (CSRF-Schutz — kein <a>-Link erlaubt)"
    )
    # Logout soll als Submit-Button in einer Form vorliegen
    assert 'type="submit"' in html, (
        "Logout muss als <button type='submit'> in einer POST-Form vorhanden sein"
    )
    # Die Form darf kein GET sein (wuerde CSRF-Schutz aufheben)
    assert 'method="get"' not in html.lower(), (
        "Logout-Form darf nicht method='get' haben (CSRF-Schutz)"
    )


def test_profile_dropdown_has_csrf_token_input(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logout-Form enthaelt ein csrf_token-Hidden-Input."""
    html = _render_dropdown(app, monkeypatch)

    assert 'name="csrf_token"' in html, (
        "CSRF-Token-Input 'name=\"csrf_token\"' fehlt im Logout-Form"
    )


def test_profile_dropdown_no_german_strings(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kein alter Deutsch-String 'Angemeldet als' im Dropdown (ADR-0033 Sprach-Policy)."""
    html = _render_dropdown(app, monkeypatch)

    assert "Angemeldet als" not in html, (
        "Alter Deutsch-String 'Angemeldet als' noch im Profile-Dropdown — "
        "muss durch 'Logged in as' ersetzt sein (ADR-0033)"
    )
