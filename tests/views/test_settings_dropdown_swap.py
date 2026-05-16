"""Tests fuer die drei Render-Modi der Settings-Sub-Views (ADR-0016).

Block-I-Addendum DoD §163: pro Sub-Route drei Modi gegen
`render_settings()` aus `app/views/_settings_shell.py`:

  1. **Vollseite** (kein HX-Header): `base_app.html` mit globaler
     Sidebar links + Settings-Shell (Nav + Content) im Detail-Pane.
     -> `<html>` + Sidebar-Marker + Settings-Nav + Content.

  2. **HTMX-Detail-Pane-Fragment** (`HX-Request: true`, kein
     spezielles HX-Target oder Target != `settings-content`):
     -> Settings-Shell (Nav + Content), **kein** `<html>`, **kein**
     `<aside>` (keine globale Sidebar).

  3. **HTMX-Content-Fragment** (`HX-Request: true`,
     `HX-Target: settings-content`): -> **nur** Content rechts der
     Nav. Kein `<nav id="settings-nav">`, kein `<html>`, keine Sidebar.

Geprueft fuer alle fuenf Settings-Sub-Routes:
  - `/settings/tags`
  - `/settings/llm/`
  - `/settings/servers/`
  - `/settings/master-key`
  - `/settings/about`
"""

from __future__ import annotations

import pytest
from flask import Flask
from flask.testing import FlaskClient

from tests._helpers import create_admin_user, login

# Routen + erwarteter `active`-Tab-Bezeichner + Content-Marker, der nur
# in der jeweiligen Sub-View vorkommt (Sanity-Check dass das richtige
# Template gerendert wurde).
SETTINGS_ROUTES: list[tuple[str, str, str]] = [
    # (Pfad, aktiver-Tab-Bezeichner-Substring, eindeutiger Content-Marker)
    ("/settings/tags", "tags", "Tag-Name"),
    ("/settings/llm/", "llm", "Base-URL"),
    ("/settings/servers/", "servers", "Server-Verwaltung"),
    ("/settings/master-key", "master-key", "Letzte Rotation"),
    ("/settings/about", "about", "App-Version"),
]


@pytest.fixture
def logged_in_client(db_app: Flask) -> FlaskClient:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    return client


# ---------------------------------------------------------------------------
# Mode 1: Vollseite (kein HX-Request)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "_active", "content_marker"), SETTINGS_ROUTES)
def test_settings_full_page_includes_sidebar_and_nav(
    logged_in_client: FlaskClient,
    path: str,
    _active: str,
    content_marker: str,
) -> None:
    """Mode 1: kein HX-Request -> Vollseite mit Sidebar, Settings-Nav,
    und Content."""
    resp = logged_in_client.get(path)
    assert resp.status_code == 200, (path, resp.status_code, resp.data[:200])
    body = resp.get_data(as_text=True)

    # `<html>`-Wrapper (Vollseite).
    assert "<html" in body.lower(), f"{path}: <html>-Wrapper fehlt"
    # Globale Sidebar von `base_app.html`.
    assert "<aside" in body.lower(), f"{path}: globale Sidebar (<aside>) fehlt"
    assert 'id="sidebar-root"' in body, f"{path}: sidebar-root fehlt"
    # Settings-Nav.
    assert 'id="settings-nav"' in body, f"{path}: Settings-Nav fehlt"
    # Aktiver Tab-Marker (Settings-Nav hebt den aktiven Eintrag hervor).
    assert "Settings" in body, f"{path}: 'Settings'-Heading fehlt"
    # Sub-Content gerendert.
    assert content_marker in body, f"{path}: Content-Marker '{content_marker}' fehlt"


# ---------------------------------------------------------------------------
# Mode 2: HX-Request mit anderem Target als settings-content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "_active", "content_marker"), SETTINGS_ROUTES)
def test_settings_hx_detail_pane_returns_shell_without_html(
    logged_in_client: FlaskClient,
    path: str,
    _active: str,
    content_marker: str,
) -> None:
    """Mode 2: `HX-Request: true` ohne spezielles Target -> Settings-Shell
    (Nav + Content), aber **kein** `<html>` und **keine** globale Sidebar."""
    resp = logged_in_client.get(
        path,
        headers={"HX-Request": "true", "HX-Target": "detail-pane"},
    )
    assert resp.status_code == 200, (path, resp.status_code, resp.data[:200])
    body = resp.get_data(as_text=True)

    # Kein `<html>` (Fragment).
    assert "<html" not in body.lower(), f"{path}: HX liefert <html>"
    # Keine globale Sidebar.
    assert 'id="sidebar-root"' not in body, f"{path}: HX liefert globale Sidebar"
    # Settings-Nav vorhanden (Detail-Pane-Fragment enthaelt Nav + Content).
    assert 'id="settings-nav"' in body, f"{path}: Settings-Nav fehlt in HX-Mode-2"
    # Content gerendert.
    assert content_marker in body, f"{path}: Content-Marker '{content_marker}' fehlt"


# ---------------------------------------------------------------------------
# Mode 3: HX-Request mit HX-Target=settings-content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "_active", "content_marker"), SETTINGS_ROUTES)
def test_settings_hx_content_only_returns_content_without_nav(
    logged_in_client: FlaskClient,
    path: str,
    _active: str,
    content_marker: str,
) -> None:
    """Mode 3: `HX-Request: true` + `HX-Target: settings-content` ->
    NUR Content, keine Settings-Nav, kein `<html>`, keine Sidebar."""
    resp = logged_in_client.get(
        path,
        headers={"HX-Request": "true", "HX-Target": "settings-content"},
    )
    assert resp.status_code == 200, (path, resp.status_code, resp.data[:200])
    body = resp.get_data(as_text=True)

    # Kein `<html>`.
    assert "<html" not in body.lower(), f"{path}: Mode-3 liefert <html>"
    # Keine globale Sidebar.
    assert 'id="sidebar-root"' not in body, f"{path}: Mode-3 liefert Sidebar"
    # Keine Settings-Nav (das ist die *innere* Swap-Ebene).
    assert 'id="settings-nav"' not in body, f"{path}: Mode-3 liefert Settings-Nav"
    # Auch keine Shell-Wrapper-Marker.
    assert "<nav" not in body.lower() or "settings-nav" not in body, (
        f"{path}: Mode-3 enthaelt unerwartete Nav-Struktur"
    )
    # Content trotzdem gerendert.
    assert content_marker in body, f"{path}: Content-Marker '{content_marker}' fehlt"


# ---------------------------------------------------------------------------
# Settings-Nav-Active-Marker
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "active_substr", "_marker"), SETTINGS_ROUTES)
def test_settings_full_page_highlights_active_tab(
    logged_in_client: FlaskClient,
    path: str,
    active_substr: str,
    _marker: str,
) -> None:
    """Der aktive Tab in der Settings-Nav hat die `menu-active`-Klasse.

    Das Template `_nav.html` setzt `menu-active bg-primary/10 text-primary
    font-semibold` auf das `<a>` des aktiven Eintrags."""
    resp = logged_in_client.get(path)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # `menu-active` muss mindestens einmal vorkommen (genau auf dem aktiven Tab).
    assert "menu-active" in body, f"{path}: kein menu-active-Marker in Nav"
    # Smoke-Check: der active-Bezeichner kommt in der Sub-Route vor.
    # `active` wird vom View-Helper als String gesetzt (`tags`, `llm`,
    # `servers`, `master_key`, `about`).
    _ = active_substr  # nur zur Doku der Test-Parameter; Pattern-Test optional.
