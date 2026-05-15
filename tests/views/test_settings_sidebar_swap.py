"""Tests fuer den HTMX-Sidebar-Tab-Swap der Settings-Views (Block I, §7a).

Erwartung pro Settings-View:
  * Ohne HX-Header -> volle Seite (Sidebar `<aside>` vorhanden, `<html>`).
  * Mit `HX-Request: true` -> nur Detail-Pane-Fragment (`_partial_shell.html`),
    keine `<html>`/`<aside>`.

Geprueft fuer:
  * /settings/tags             (settings.tags_list)
  * /settings/servers/         (servers.list_servers)
  * /settings/llm/             (llm_settings.show)
  * /audit/                    (audit.list_events)
  * /findings/search           (search.search)
"""

from __future__ import annotations

import pytest
from flask import Flask
from flask.testing import FlaskClient

from tests._helpers import create_admin_user, login

SETTINGS_PATHS: list[str] = [
    "/settings/tags",
    "/settings/servers/",
    "/settings/llm/",
    "/audit/",
    "/findings/search",
]


@pytest.fixture
def logged_in_client(db_app: Flask) -> FlaskClient:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    return client


@pytest.mark.parametrize("path", SETTINGS_PATHS)
def test_settings_full_page_includes_sidebar(logged_in_client: FlaskClient, path: str) -> None:
    resp = logged_in_client.get(path)
    assert resp.status_code == 200, (path, resp.status_code, resp.data[:200])
    body = resp.get_data(as_text=True)
    assert "<html" in body.lower(), f"{path}: kein <html>-Wrapper"
    assert "<aside" in body.lower(), f"{path}: keine Sidebar"
    assert 'id="sidebar-root"' in body, f"{path}: sidebar-root fehlt"
    assert 'id="detail-pane"' in body, f"{path}: detail-pane fehlt"


@pytest.mark.parametrize("path", SETTINGS_PATHS)
def test_settings_hx_request_returns_fragment_only(
    logged_in_client: FlaskClient, path: str
) -> None:
    resp = logged_in_client.get(path, headers={"HX-Request": "true"})
    assert resp.status_code == 200, (path, resp.status_code, resp.data[:200])
    body = resp.get_data(as_text=True)
    assert "<html" not in body.lower(), f"{path}: HX liefert <html>"
    assert "<aside" not in body.lower(), f"{path}: HX liefert <aside>"
    assert 'id="sidebar-root"' not in body, f"{path}: HX liefert Sidebar-Root"
