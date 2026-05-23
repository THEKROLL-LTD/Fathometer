"""Pure-Unit Smoke-Tests: Server-Detail-Template rendert noch korrekt nach Block W Phase G.

Phase 1 hat Server-Detail als Dual-Stack (Tailwind+DaisyUI) belassen.
Server-Detail-Redesign ist explizit als Nicht-Ziel von Block W definiert.

Dieser Test verifiziert:
- servers/detail.html existiert und ist Jinja-parsbar.
- Das Template kann geladen werden ohne Crash.
- Kein Template-Syntax-Fehler durch Phase-G-Aenderungen.

Render-Strategie:
  servers/detail.html hat viele Variablen-Abhaengigkeiten (server, findings, etc.)
  Der Template-Existenz-Load-Smoke prueft nur ob Jinja das Template parsen kann.
  Ein vollstaendiger Render wuerde zu viel Mock-Kontext brauchen; das waere
  Test-Overhead der keinen Mehrwert gegenueber dem Existenz-Check bietet.
  Bei konkreten View-Regressions gibt es bereits test_server_detail.py.
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_server_detail_template_can_be_loaded(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """servers/detail.html kann ohne Crash geladen werden (Jinja-Parse-Smoke).

    Phase G haette servers/detail.html NICHT aendern sollen (Server-Detail-
    Redesign ist explizit Nicht-Ziel von Block W, siehe W-redesign-phase-1.md
    §Nicht-Ziele).

    Dieser Test stellt sicher dass keine Jinja-Syntax-Fehler eingefuehrt wurden.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/servers/1"):
        # get_template() parst das Template vollstaendig.
        # Bei Jinja-Syntax-Errors wirft es TemplateSyntaxError.
        template = app.jinja_env.get_template("servers/detail.html")

    assert template is not None, (
        "servers/detail.html konnte nicht geladen werden. "
        "Phase G haette dieses Template NICHT aendern sollen."
    )


def test_server_detail_template_extends_correct_base(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """servers/detail.html nutzt noch das korrekte Base-Template.

    Das Template extendiert '_partial_shell.html' (hx_partial) oder 'base_app.html'.
    Beide sind Dual-Stack-Templates — verifiziert dass kein ungueltiges Base
    eingefuehrt wurde.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    # Template-Source direkt lesen um das extends-Statement zu pruefen
    with app.test_request_context("/servers/1"):
        source, _, _ = app.jinja_env.loader.get_source(  # type: ignore[union-attr]
            app.jinja_env,
            "servers/detail.html",
        )

    # Das Template soll eines der korrekten Base-Templates nutzen
    valid_bases = ["_partial_shell.html", "base_app.html"]
    has_valid_base = any(base in source for base in valid_bases)

    assert has_valid_base, (
        f"servers/detail.html nutzt kein gueltiges Base-Template. "
        f"Geprueft: {valid_bases}. "
        f"Erste 200 Zeichen: {source[:200]!r}"
    )


def test_server_detail_template_has_server_variable_reference(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """servers/detail.html referenziert noch die `server`-Variable.

    Smoke-Check: Template ist unversehrt und nutzt noch die erwarteten
    View-Variablen (kein vollstaendiger Umschreibung durch Phase G).
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/servers/1"):
        source, _, _ = app.jinja_env.loader.get_source(  # type: ignore[union-attr]
            app.jinja_env,
            "servers/detail.html",
        )

    assert "server" in source, (
        f"servers/detail.html referenziert die `server`-Variable nicht mehr. "
        f"Template scheint veraendert zu sein. "
        f"Erste 300 Zeichen: {source[:300]!r}"
    )


def test_server_detail_template_has_findings_variable_reference(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """servers/detail.html referenziert noch findings-bezogene Variablen."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/servers/1"):
        source, _, _ = app.jinja_env.loader.get_source(  # type: ignore[union-attr]
            app.jinja_env,
            "servers/detail.html",
        )

    # Das Template nutzt findings (Flat-Modus) oder groups (Group-Modus)
    has_findings_ref = "findings" in source or "groups" in source
    assert has_findings_ref, (
        f"servers/detail.html hat keine Referenz auf 'findings' oder 'groups'. "
        f"Template scheint wesentlich veraendert. "
        f"Erste 300 Zeichen: {source[:300]!r}"
    )
