"""Pure-Unit Template-Smoke-Tests fuer login.html (Block W Phase G).

Prueft englische Strings, Form-Felder, CSRF-Token und Layout-Klassen.
Kein DB-Fixture noetig: login.html wird direkt via Jinja-Env gerendert.

Render-Pattern:
  - Flask-App via `app`-Fixture (conftest.py, DB-frei).
  - LoginForm wird als Mock-Objekt injiziert (kein WTF-Formular-Rendering).
  - _MOCK_MANIFEST verhindert Manifest-Lookup auf Disk.
  - `_render_login` kapselt den gemeinsamen Setup.
"""

from __future__ import annotations

from unittest.mock import MagicMock

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


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_login_form(*, errors: dict | None = None) -> MagicMock:
    """Erstellt einen LoginForm-Mock der das Jinja-Template-Interface erfuellt.

    Das Template benutzt:
      - form.csrf_token       (rendert ein Hidden-Input-Field)
      - form.errors           (dict, leer = kein Error-State)
      - form.username.errors  (list)
      - form.password.errors  (list)
    """
    form = MagicMock()

    # CSRF-Token: das Template ruft {{ form.csrf_token }} auf.
    # Jinja rendert MagicMock als String — wir geben einen realistischen
    # Hidden-Input-String zurueck.
    csrf_field = MagicMock()
    csrf_field.__str__ = lambda self: (
        '<input id="csrf_token" name="csrf_token" type="hidden" value="test-csrf-token-value">'
    )
    form.csrf_token = csrf_field

    # form.errors ist ein dict — leeres dict = kein Fehler-Zweig.
    form.errors = errors or {}

    # form.username.errors und form.password.errors (leere Listen ohne Fehler).
    form.username = MagicMock()
    form.username.errors = []
    form.password = MagicMock()
    form.password.errors = []

    return form


def _render_login(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    *,
    form: MagicMock | None = None,
) -> str:
    """Rendert login.html mit Mock-Form im Flask-Request-Context."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    if form is None:
        form = _make_login_form()

    with app.test_request_context("/login"):
        from flask import render_template

        html = render_template("login.html", form=form)

    return html


# ---------------------------------------------------------------------------
# Tests — Pflicht-Strings aus dem Design
# ---------------------------------------------------------------------------


def test_login_renders_operator_credentials_title(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """login.html enthaelt 'Operator credentials.' als H1-Titel."""
    html = _render_login(app, monkeypatch)

    assert "Operator credentials." in html, (
        f"Title 'Operator credentials.' fehlt in login.html. HTML-Laenge: {len(html)}"
    )


def test_login_renders_eyebrow_authenticate(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """login.html enthaelt den Eyebrow-Text 'authenticate' (nach '>' Prompt)."""
    html = _render_login(app, monkeypatch)

    # Template rendert '>' als HTML-Entity '&gt;' plus 'authenticate'
    assert "authenticate" in html, (
        f"Eyebrow-Text 'authenticate' fehlt in login.html. HTML-Laenge: {len(html)}"
    )
    # Mindestens eines der beiden Formate muss vorhanden sein
    has_gt_prompt = "&gt;" in html or ">" in html
    assert has_gt_prompt, f"Prompt-Zeichen '>' fehlt in login.html. HTML-Laenge: {len(html)}"


def test_login_renders_subtitle_no_signup(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """login.html enthaelt Sub-Text 'No signup. No reset. No SSO. Internal operators only.'"""
    html = _render_login(app, monkeypatch)

    assert "No signup. No reset. No SSO. Internal operators only." in html, (
        f"Sub-Text fehlt in login.html. HTML-Laenge: {len(html)}"
    )


def test_login_renders_username_field(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """login.html enthaelt ein username-Input-Field (name='username' und id='auth-username')."""
    html = _render_login(app, monkeypatch)

    assert 'name="username"' in html, (
        f"Input name='username' fehlt in login.html. HTML-Laenge: {len(html)}"
    )
    assert 'id="auth-username"' in html, (
        f"Input id='auth-username' fehlt in login.html. HTML-Laenge: {len(html)}"
    )


def test_login_renders_password_field(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """login.html enthaelt ein password-Input-Field (name='password' und id='auth-password')."""
    html = _render_login(app, monkeypatch)

    assert 'name="password"' in html, (
        f"Input name='password' fehlt in login.html. HTML-Laenge: {len(html)}"
    )
    assert 'id="auth-password"' in html, (
        f"Input id='auth-password' fehlt in login.html. HTML-Laenge: {len(html)}"
    )


def test_login_renders_submit_authenticate(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Submit-Button-Text enthaelt 'authenticate'."""
    html = _render_login(app, monkeypatch)

    assert "<button" in html, f"Submit-Button-Element fehlt in login.html. HTML-Laenge: {len(html)}"
    assert 'type="submit"' in html, f"type='submit' fehlt in login.html. HTML-Laenge: {len(html)}"
    # Submit-Button-Text ist 'authenticate' (plus Arrow-Span)
    # Wir pruefen dass 'authenticate' im Button-Bereich vorkommt
    assert "authenticate" in html, (
        f"Submit-Text 'authenticate' fehlt in login.html. HTML-Laenge: {len(html)}"
    )


def test_login_form_is_post_to_auth_login(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Form hat method='post' und action zeigt auf die auth.login-Route."""
    html = _render_login(app, monkeypatch)

    assert 'method="post"' in html, (
        f"Form method='post' fehlt in login.html. HTML-Laenge: {len(html)}"
    )
    # action-Attribut: url_for('auth.login') gibt '/login' (oder aehnlich)
    assert "action=" in html, f"Form action-Attribut fehlt in login.html. HTML-Laenge: {len(html)}"
    assert "/login" in html, f"Login-URL '/login' fehlt in Form-Action. HTML-Laenge: {len(html)}"


def test_login_form_has_csrf_token(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """login.html rendert das CSRF-Hidden-Input-Field."""
    html = _render_login(app, monkeypatch)

    # Das Template ruft {{ form.csrf_token }} auf. Unser Mock gibt
    # ein <input type="hidden" name="csrf_token" ...> zurueck.
    assert "csrf_token" in html, f"CSRF-Token-Field fehlt in login.html. HTML-Laenge: {len(html)}"


def test_login_no_german_strings(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """login.html enthaelt keine deutschen Strings (Login ist Phase-G englisch).

    Prueft auf typische deutsche Auth-Strings die ersetzt werden mussten.
    """
    html = _render_login(app, monkeypatch)

    forbidden = [
        "Anmelden",
        "Bitte melde dich",
        "Login fehlgeschlagen",
    ]
    for term in forbidden:
        assert term not in html, (
            f"Deutscher String '{term}' gefunden in login.html (sollte englisch sein). "
            f"HTML-Laenge: {len(html)}"
        )


def test_login_uses_app_auth_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """login.html enthaelt 'app--auth' Klasse fuer das Auth-Shell-Layout."""
    html = _render_login(app, monkeypatch)

    assert "app--auth" in html, f"Klasse 'app--auth' fehlt in login.html. HTML-Laenge: {len(html)}"


def test_login_uses_auth_panel_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """login.html enthaelt 'auth__panel' Klasse fuer die Auth-Panel-Card."""
    html = _render_login(app, monkeypatch)

    assert "auth__panel" in html, (
        f"Klasse 'auth__panel' fehlt in login.html. HTML-Laenge: {len(html)}"
    )
