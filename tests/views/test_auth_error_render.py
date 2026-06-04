"""Pure-Unit Template-Smoke-Tests fuer den Error-State in login.html (Block W Phase G).

Prueft:
- Ohne Fehler: Status-Line zeigt Hint 'enter credentials to proceed.'
- Mit Flash-Error: Status-Line zeigt '[access denied]'
- Flash-Message-Text erscheint im Status-Bereich

Render-Pattern:
  Flask-App via `app`-Fixture (conftest.py, DB-frei).
  Flash-Messages werden via flask.get_flashed_messages() injiziert —
  dazu aktivieren wir den Session-Stack im Test-Request-Context.
  _MOCK_MANIFEST verhindert Manifest-Lookup auf Disk.
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
    """Erstellt einen LoginForm-Mock ohne Form-Errors."""
    form = MagicMock()

    csrf_field = MagicMock()
    csrf_field.__str__ = lambda self: (
        '<input id="csrf_token" name="csrf_token" type="hidden" value="test-csrf-token-value">'
    )
    form.csrf_token = csrf_field

    form.errors = errors or {}
    form.username = MagicMock()
    form.username.errors = []
    form.password = MagicMock()
    form.password.errors = []

    return form


def _render_login_with_flash(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    *,
    flash_messages: list[tuple[str, str]] | None = None,
    form: MagicMock | None = None,
) -> str:
    """Rendert login.html mit optionalen Flash-Messages im Request-Context.

    Flash-Messages werden in die Session eingelagert, damit
    get_flashed_messages() sie im Template findet.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    if form is None:
        form = _make_login_form()

    with app.test_client() as client:
        with client.session_transaction() as sess:
            if flash_messages:
                # Flask speichert Flash-Messages als '_flashes' in der Session.
                # Format: list[(category, message)]
                sess["_flashes"] = flash_messages

        with app.test_request_context("/login"):
            # Flask-Flash-Messages werden aus der Session gelesen.
            # Im Test-Context brauchen wir die App-Context-Push damit
            # get_flashed_messages() funktioniert. Wir simulieren das
            # indem wir die Messages direkt via flask.flash() einfuegen.
            from flask import flash, render_template

            if flash_messages:
                for category, message in flash_messages:
                    flash(message, category)

            html = render_template("login.html", form=form)

    return html


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_login_renders_empty_status_when_no_error(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Idle-State (kein Flash-Error, keine Form-Errors): `.auth__status`-Div ist
    leer und reserviert nur Layout-Platz via `min-height: 14px`.

    Drift-Fix 2026-05-23: das Template hatte einen hardcoded Default-Hint
    `enter credentials to proceed.` der nicht im Design steht (docs/design/
    login.jsx Z. 121-127 rendert im Idle-State `null`, also leer). Hint
    entfernt — Status-Div bleibt leer im Idle.
    """
    html = _render_login_with_flash(app, monkeypatch)

    # Idle: kein hardcoded Hint-Text mehr
    assert "enter credentials to proceed" not in html, (
        f"Default-Hint 'enter credentials to proceed' soll entfernt sein (Drift-Fix). "
        f"Idle-State rendert nur die leere .auth__status-Div als Layout-Reserve. "
        f"HTML-Laenge: {len(html)}"
    )
    # Im Idle-State darf der Error-Zweig nicht auftreten
    assert "auth__status--error" not in html, (
        f"CSS-Klasse 'auth__status--error' erscheint faelschlicherweise ohne Fehler-State. "
        f"HTML-Laenge: {len(html)}"
    )
    # Die `auth__status`-Wrapper-Div muss aber da sein (Layout-Reserve)
    assert 'class="auth__status"' in html, (
        f".auth__status-Wrapper-Div fehlt — wird fuer die `min-height: 14px`-"
        f"Layout-Reserve benoetigt. HTML-Laenge: {len(html)}"
    )


def test_login_renders_access_denied_on_flash_error(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mit Flash-Error-Message zeigt die Status-Line den Error-State.

    Template-Logik: wenn _flash_errors nicht leer -> auth__status--error Zweig.
    Das Template rendert '[' und ']' als separate Spans mit CSS-Klasse 'bracket',
    der Textinhalt 'access denied' ist separat (kein [access denied] als String).
    """
    html = _render_login_with_flash(
        app,
        monkeypatch,
        flash_messages=[("error", "Login failed.")],
    )

    assert "auth__status--error" in html, (
        f"CSS-Klasse 'auth__status--error' fehlt bei Flash-Error. HTML-Laenge: {len(html)}"
    )
    assert "access denied" in html, (
        f"Text 'access denied' fehlt bei Flash-Error. HTML-Laenge: {len(html)}"
    )
    # Hint-Text (vorher hardcoded) ist generell entfernt — auch im Error-State darf er nicht stehen
    assert "enter credentials to proceed" not in html, (
        f"Hint-Text wurde entfernt und darf nirgendwo erscheinen. HTML-Laenge: {len(html)}"
    )


def test_login_access_denied_includes_flash_message(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Die Flash-Message-Text wird im Status-Bereich nach 'access denied' gerendert.

    Template-Logik: _flash_errors wird als '· {message}' nach 'access denied' ausgegeben.
    """
    flash_msg = "Ungueltige Anmeldedaten."
    html = _render_login_with_flash(
        app,
        monkeypatch,
        flash_messages=[("error", flash_msg)],
    )

    assert "access denied" in html, (
        f"Text 'access denied' fehlt bei Flash-Error. HTML-Laenge: {len(html)}"
    )
    assert flash_msg in html, (
        f"Flash-Message-Text '{flash_msg}' fehlt im Status-Bereich. HTML-Laenge: {len(html)}"
    )


def test_login_renders_access_denied_on_warning_flash(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auch Flash-Kategorie 'warning' triggert den Error-State (auth__status--error).

    Template filtert nach category 'in' ['error', 'warning'].
    """
    html = _render_login_with_flash(
        app,
        monkeypatch,
        flash_messages=[("warning", "Account gesperrt.")],
    )

    assert "auth__status--error" in html, (
        f"CSS-Klasse 'auth__status--error' fehlt bei Flash-Warning. HTML-Laenge: {len(html)}"
    )
    assert "access denied" in html, (
        f"Text 'access denied' fehlt bei Flash-Warning. HTML-Laenge: {len(html)}"
    )


def test_login_info_flash_does_not_trigger_access_denied(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flash-Kategorie 'info' triggert NICHT den '[access denied]'-Zweig.

    Das Template filtert nur 'error' und 'warning' als Fehlerkategorien.
    """
    html = _render_login_with_flash(
        app,
        monkeypatch,
        flash_messages=[("info", "Sitzung abgelaufen.")],
    )

    # 'info'-Flash soll keinen access-denied-State ausloesen
    assert "auth__status--error" not in html, (
        f"CSS-Klasse 'auth__status--error' erscheint faelschlicherweise bei 'info'-Flash. "
        f"HTML-Laenge: {len(html)}"
    )
    # Idle-State: kein hardcoded Hint-Text mehr (Drift-Fix 2026-05-23)
    assert "enter credentials to proceed" not in html, (
        f"Default-Hint wurde entfernt und darf bei 'info'-Flash nicht erscheinen. "
        f"HTML-Laenge: {len(html)}"
    )
