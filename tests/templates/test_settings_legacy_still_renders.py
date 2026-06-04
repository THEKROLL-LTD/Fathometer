"""Pure-Unit Smoke-Tests: Settings-Templates rendern noch korrekt nach Block W Phase G.

Phase 1 hat Settings als Dual-Stack (Tailwind+DaisyUI) belassen.
Diese Smoke-Tests verifizieren dass die Legacy-Surfaces nicht broken wurden:
- Settings-Content-Templates (Partials ohne extends) lassen sich rendern.
- DaisyUI/Tailwind-Indikatoren sind noch vorhanden.
- Kein Template-Render-Crash durch Phase-G-Aenderungen.

Render-Pattern:
  Settings-Content-Templates sind KEINE vollstaendigen Seiten (kein extends).
  Sie werden direkt via app.jinja_env.get_template + render() geladen.
  Mock-Kontext wird minimal gehalten (nur was das Template direkt braucht).
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
# Helpers
# ---------------------------------------------------------------------------


def _make_csrf_form() -> MagicMock:
    """Erstellt einen Mock fuer ein einfaches CSRF-Only-Form."""
    form = MagicMock()
    csrf_field = MagicMock()
    csrf_field.__str__ = lambda self: (
        '<input id="csrf_token" name="csrf_token" type="hidden" value="test-token">'
    )
    form.csrf_token = csrf_field
    return form


def _render_settings_partial(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    template_name: str,
    context: dict,
) -> str:
    """Rendert ein Settings-Partial-Template direkt (ohne extends-Kette).

    Settings-Content-Templates (z.B. settings/servers.html, settings/llm_reviewer.html)
    nutzen kein 'extends' — sie sind reine Content-Fragmente.
    Sie werden hier direkt mit einem Jinja-Env-Lookup gerendert.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/settings"):
        template = app.jinja_env.get_template(template_name)
        html = template.render(**context)

    return html


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_settings_template_servers_can_be_loaded(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """settings/servers.html kann ohne Crash geladen und gerendert werden.

    Das Template ist ein Content-Partial (kein extends), braucht aber
    `servers`, `revoke_form`, `retire_form` als Kontext.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    # Minimaler Mock-Kontext: leere Server-Liste
    context = {
        "servers": [],
        "revoke_form": _make_csrf_form(),
        "retire_form": _make_csrf_form(),
    }

    with app.test_request_context("/settings"):
        template = app.jinja_env.get_template("settings/servers.html")
        html = template.render(**context)

    assert html is not None, "settings/servers.html rendert None"
    assert len(html) > 0, "settings/servers.html rendert leeren String"


def test_settings_servers_template_uses_s_layer(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """settings/servers.html nutzt die s-*-Schicht (Block AD), kein DaisyUI mehr.

    Nach dem Block-AD-Restyling traegt die Server-Liste das s-*-Markup
    (settings__title, s-section, s-empty) und KEINE DaisyUI-Komponenten-Klassen
    (card/btn/badge/table) mehr.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    context = {
        "servers": [],
        "revoke_form": _make_csrf_form(),
        "retire_form": _make_csrf_form(),
    }

    with app.test_request_context("/settings"):
        template = app.jinja_env.get_template("settings/servers.html")
        html = template.render(**context)

    # s-*-Schicht-Indikatoren vorhanden.
    assert "settings__title" in html
    assert "s-section" in html
    # DaisyUI/Tailwind-Komponenten-Klassen abwesend.
    for forbidden in ('class="card', 'class="btn', "badge badge", "table-zebra"):
        assert forbidden not in html, f"DaisyUI-Rest in servers.html: {forbidden}"


def test_settings_llm_reviewer_template_can_be_loaded(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """settings/llm_reviewer.html kann ohne Crash geladen werden (Template-Existenz-Smoke).

    Das Template erfordert viele Kontext-Variablen — wir pruefen nur
    dass es existiert und loadbar ist, nicht den vollen Render.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/settings/llm-reviewer"):
        # Nur laden, nicht rendern — verifiziert dass das Template existiert
        # und Jinja es parsen kann (keine Syntax-Errors).
        template = app.jinja_env.get_template("settings/llm_reviewer.html")

    assert template is not None, (
        "settings/llm_reviewer.html konnte nicht geladen werden. "
        "Phase G haette dieses Template NICHT aendern sollen."
    )


def test_settings_master_key_template_can_be_loaded(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """settings/master_key.html kann ohne Crash geladen werden (Template-Existenz-Smoke)."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/settings/master-key"):
        template = app.jinja_env.get_template("settings/master_key.html")

    assert template is not None, (
        "settings/master_key.html konnte nicht geladen werden. "
        "Phase G haette dieses Template NICHT aendern sollen."
    )


def test_settings_nav_template_can_be_rendered(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """settings/_nav.html rendert ohne Crash (Settings-Navigation Smoke).

    _nav.html ist ein Include-Partial ohne extends — direkt renderbar.
    Braucht einen `active_tab`-Kontext-Wert oder ist ohne tolerant.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/settings"):
        template = app.jinja_env.get_template("settings/_nav.html")
        html = template.render(active_tab="servers")

    assert html is not None, "settings/_nav.html rendert None"
    assert len(html) > 0, "settings/_nav.html rendert leeren String"
    # Nav enthaelt typischerweise Settings-Link-Texte
    assert "settings" in html.lower() or "Settings" in html, (
        f"Settings-Nav enthaelt keinen 'Settings'-Text. HTML-Laenge: {len(html)}"
    )
