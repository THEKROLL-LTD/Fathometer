"""Pure-Unit Template-Tests: Server-Settings Inline-Create-UI (Block Z, Phase B, ADR-0040).

Verifiziert dass `servers/settings.html` zwei neue Inline-Anlage-Felder rendert
(Tag + Group) und dabei:
  - die `data-test`-Hooks vorhanden sind,
  - die HTML5-`form="…"`-Sub-Form-Kopplung (`group-create-form` / `tag-create-form`)
    auf Inputs und Buttons gesetzt ist,
  - die versteckten Sub-Forms mit CSRF-Token existieren,
  - die bestehenden "aus existierenden auswählen"-Pfade unverändert sind
    (Negativ-Regression: `tag-add-select` + `settings-group-select`).

Render-Strategie:
  Wie `tests/views/test_server_settings.py` wird der `show`-Handler via
  `func.__wrapped__` direkt aufgerufen (umgeht `@login_required` ohne
  Auth-Bypass). DB-Zugriffe (`_load_server_with_settings`, `_all_tags`,
  `_all_groups`) werden gestubbt. Das echte Flask-Jinja rendert das Template
  inklusive der echten `ServerGroupCreateForm`/`ServerTagCreateForm` aus
  `_render_settings`. Kein DB-Zugriff, kein db_integration-Marker.
"""

from __future__ import annotations

import types
from typing import Any

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Helpers — Mock-Objekte
# ---------------------------------------------------------------------------


def _make_server(
    *,
    id: int = 42,
    name: str = "test-host.example.com",
    group_id: int | None = None,
    expected_scan_interval_h: int = 24,
) -> types.SimpleNamespace:
    """Minimales Server-Mock-Objekt fuer Settings-Render."""
    return types.SimpleNamespace(
        id=id,
        name=name,
        group_id=group_id,
        expected_scan_interval_h=expected_scan_interval_h,
        revoked_at=None,
        retired_at=None,
        tag_links=[],
        group=None,
    )


# ---------------------------------------------------------------------------
# Fixture: App mit CSRF aktiviert (CSRF-Token-Render-Test braucht echtes Token)
# ---------------------------------------------------------------------------


@pytest.fixture
def csrf_app(app_env: None) -> Flask:
    """App mit aktiviertem CSRF und TESTING=True.

    CSRF bleibt aktiv, damit `hidden_tag()` ein echtes `csrf_token`-Input
    rendert (sonst rendert WTForms kein CSRF-Feld).
    """
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=True, SECRET_KEY="test-secret")
    return flask_app


# ---------------------------------------------------------------------------
# Render-Helper
# ---------------------------------------------------------------------------


def _render(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    *,
    server: Any,
    server_id: int = 42,
) -> str:
    """Ruft show.__wrapped__ mit gemockten Dependencies auf und rendert das Template."""
    from app.views.server_settings import show

    inner = getattr(show, "__wrapped__", show)
    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings._all_tags", list)
    monkeypatch.setattr("app.views.server_settings._all_groups", list)

    with app.test_request_context(f"/servers/{server_id}/settings/"):
        result = inner(server_id=server_id)

    assert isinstance(result, str), f"show() muss einen String zurueckgeben, got: {type(result)}"
    return result


# ===========================================================================
# 1. Tag-Inline-Create-Input + Submit gerendert (data-test-Hooks)
# ===========================================================================


def test_tag_inline_create_controls_rendered(
    csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Template rendert das Tag-Inline-Eingabefeld + Submit-Button."""
    html = _render(csrf_app, monkeypatch, server=_make_server())
    assert 'data-test="tag-inline-create-input"' in html, (
        f"tag-inline-create-input fehlt. Output-Auszug: {html[:400]!r}"
    )
    assert 'data-test="tag-inline-create-submit"' in html, (
        f"tag-inline-create-submit fehlt. Output-Auszug: {html[:400]!r}"
    )


# ===========================================================================
# 2. Group-Inline-Create-Input + Submit gerendert (data-test-Hooks)
# ===========================================================================


def test_group_inline_create_controls_rendered(
    csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Template rendert das Group-Inline-Eingabefeld + Submit-Button."""
    html = _render(csrf_app, monkeypatch, server=_make_server())
    assert 'data-test="group-inline-create-input"' in html, (
        f"group-inline-create-input fehlt. Output-Auszug: {html[:400]!r}"
    )
    assert 'data-test="group-inline-create-submit"' in html, (
        f"group-inline-create-submit fehlt. Output-Auszug: {html[:400]!r}"
    )


# ===========================================================================
# 3. form="…"-Kopplung auf Tag-Controls korrekt
# ===========================================================================


def test_tag_inline_create_form_attribute(csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tag-Inline-Input + Button tragen form="tag-create-form"."""
    html = _render(csrf_app, monkeypatch, server=_make_server())
    # Mindestens zweimal: einmal am Input, einmal am Button.
    assert html.count('form="tag-create-form"') >= 2, (
        f'form="tag-create-form" muss auf Input UND Button stehen. '
        f"Treffer: {html.count('form=' + chr(34) + 'tag-create-form' + chr(34))}"
    )


# ===========================================================================
# 4. form="…"-Kopplung auf Group-Controls korrekt
# ===========================================================================


def test_group_inline_create_form_attribute(
    csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Group-Inline-Input + Button tragen form="group-create-form"."""
    html = _render(csrf_app, monkeypatch, server=_make_server())
    assert html.count('form="group-create-form"') >= 2, (
        f'form="group-create-form" muss auf Input UND Button stehen. '
        f"Treffer: {html.count('form=' + chr(34) + 'group-create-form' + chr(34))}"
    )


# ===========================================================================
# 5. Hidden-Sub-Forms existieren und enthalten CSRF-Token
# ===========================================================================


def test_hidden_subforms_present_with_csrf(
    csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Versteckte Sub-Forms group-create-form + tag-create-form existieren mit CSRF-Token."""
    html = _render(csrf_app, monkeypatch, server=_make_server())
    assert 'id="group-create-form"' in html, "Hidden-Sub-Form group-create-form fehlt"
    assert 'id="tag-create-form"' in html, "Hidden-Sub-Form tag-create-form fehlt"
    # hidden_tag() rendert ein csrf_token-Input (CSRF ist in dieser Fixture aktiv).
    assert "csrf_token" in html, (
        f"Kein csrf_token im Output — hidden_tag() hat kein CSRF-Feld gerendert. "
        f"Output-Auszug: {html[:300]!r}"
    )


# ===========================================================================
# 6. Negativ-Regression: bestehende Auswahl-Pfade unveraendert
# ===========================================================================


def test_existing_select_paths_unchanged(csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Bestehende 'aus existierenden auswaehlen'-Pfade bleiben vorhanden."""
    html = _render(csrf_app, monkeypatch, server=_make_server())
    assert 'data-test="tag-add-select"' in html, (
        "Bestehender tag-add-select-Pfad fehlt — Inline-Create darf ihn nicht ersetzen."
    )
    assert 'data-test="settings-group-select"' in html, (
        "Bestehender settings-group-select-Pfad fehlt — Inline-Create darf ihn nicht ersetzen."
    )
    assert 'data-test="tag-add-submit"' in html, "Bestehender tag-add-submit-Button fehlt."


# ===========================================================================
# 7. CSS-Wrapper-Klasse sd-inline-create vorhanden
# ===========================================================================


def test_inline_create_wrapper_class(csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Beide Inline-Create-Zeilen sind in .sd-inline-create gewrappt (zweimal)."""
    html = _render(csrf_app, monkeypatch, server=_make_server())
    assert html.count('class="sd-inline-create"') == 2, (
        f"Erwartet genau zwei sd-inline-create-Wrapper (Tag + Group), "
        f"gefunden: {html.count('class=' + chr(34) + 'sd-inline-create' + chr(34))}"
    )
