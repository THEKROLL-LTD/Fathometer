"""Tests fuer `GET /settings` -> `/settings/servers/` (ADR-0016 Klaerung).

Das Block-I-Addendum hatte zunaechst `Tags` als Default-Sub-Tab; der
User-Wunsch war Server-Verwaltung. Die Implementierung redirectet daher
auf `servers.list_servers`.

Routen:
  - `GET /settings/` ohne Login -> 302 auf `/login`.
  - `GET /settings/` mit Login -> 302 auf `/settings/servers/`.
  - `GET /settings/` mit `follow_redirects=True` -> 200 mit
    Server-Verwaltungs-Markup.
"""

from __future__ import annotations

from flask import Flask

from tests._helpers import create_admin_user, login


def test_settings_index_redirects_to_login_when_anonymous(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/settings/", follow_redirects=False)
    assert resp.status_code == 302, resp.status_code
    location = resp.headers.get("Location", "")
    assert "/login" in location, location


def test_settings_index_redirects_to_servers_for_logged_in_user(
    db_app: Flask,
) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/", follow_redirects=False)
    assert resp.status_code == 302, resp.status_code
    location = resp.headers.get("Location", "")
    assert location.endswith("/settings/servers/"), location
    # Explizit NICHT `/settings/tags` — User-Klaerung.
    assert "/settings/tags" not in location


def test_settings_index_follow_redirects_renders_servers_page(
    db_app: Flask,
) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/", follow_redirects=True)
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    # Server-Verwaltung enthaelt die Settings-Nav mit "Server-Verwaltung"-
    # Eintrag und einen Marker fuer den aktiven Tab.
    assert "Server management" in body
    # Settings-Nav muss da sein.
    assert 'id="settings-nav"' in body or "settings-nav" in body


def test_settings_index_without_trailing_slash_also_redirects(
    db_app: Flask,
) -> None:
    """Flask redirected `/settings` -> `/settings/` (trailing slash) per
    Default. Wir verifizieren, dass dieser Doppel-Redirect am Ende auf
    `/settings/servers/` landet."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings", follow_redirects=True)
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    assert "Server management" in body
