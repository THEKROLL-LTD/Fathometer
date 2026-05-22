"""Tests fuer den Sidebar-HTMX-Polling-Endpoint `GET /_partials/sidebar`
(ADR-0019, Block L).

Der Sidebar-Wrapper `base_app.html` rendert `sidebar/_server_list.html`
beim Full-Page-Render selbst. Fuers HTMX-Polling hat Block L eine
schmale Route gebaut, die DASSELBE Partial ohne Page-Shell liefert,
damit ein `hx-get="/_partials/sidebar"` direkt gegen sie pollen kann.

Was hier getestet wird:

  * Auth-Wand: ohne Login -> Redirect zum Login (302).
  * Mit Login: 200, enthaelt `id="server-list"`, KEIN `<html>`-Wrapper.
  * Polling-Trigger ist auf dem `<ul>`-Container gesetzt.
  * Tag-Filter persistiert in der eigenen `hx-get`-URL des Containers.
"""

from __future__ import annotations

import re

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import Server, ServerTag, Tag
from tests._helpers import create_admin_user, login


def _create_server(app: Flask, *, name: str, tags: list[str] | None = None) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            if tags:
                for tag_name in tags:
                    tag = sess.execute(select(Tag).where(Tag.name == tag_name)).scalar_one_or_none()
                    if tag is None:
                        tag = Tag(name=tag_name, color="#6b7280")
                        sess.add(tag)
                        sess.flush()
                    sess.add(ServerTag(server_id=sid, tag_id=tag.id))
            sess.commit()
            return sid
        finally:
            sess.close()


_LIST_OPEN_RE = re.compile(r'<ul id="server-list"[^>]*>', re.DOTALL)


def _extract_list_open_tag(body: str) -> str:
    match = _LIST_OPEN_RE.search(body)
    assert match is not None, (
        f'`<ul id="server-list" ...>`-Opener nicht im Body gefunden. '
        f"Erste 400 Bytes: {body[:400]!r}"
    )
    return match.group(0)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_sidebar_partial_without_login_redirects(db_app: Flask) -> None:
    """`@login_required` ist Pflicht — ein anonymer GET landet auf /login."""
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/_partials/sidebar", follow_redirects=False)
    assert resp.status_code in (301, 302), resp.status_code
    assert "/login" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# Markup
# ---------------------------------------------------------------------------


def test_sidebar_partial_returns_server_list_marker(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="srv-sidebar-1")
    client = db_app.test_client()
    login(client)

    resp = client.get("/_partials/sidebar")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    assert 'id="server-list"' in body, body[:400]


def test_sidebar_partial_is_fragment_only(db_app: Flask) -> None:
    """Kein `<html>`/`<head>`/`<body>`-Wrapper in der Polling-Antwort."""
    create_admin_user(db_app)
    _create_server(db_app, name="srv-sidebar-fragment")
    client = db_app.test_client()
    login(client)

    resp = client.get("/_partials/sidebar")
    body_lower = resp.get_data(as_text=True).lower()
    assert "<html" not in body_lower, body_lower[:400]
    assert "<head>" not in body_lower, body_lower[:400]
    assert "<head " not in body_lower, body_lower[:400]
    assert "<body" not in body_lower, body_lower[:400]


def test_sidebar_partial_has_polling_trigger(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="srv-sidebar-trigger")
    client = db_app.test_client()
    login(client)

    resp = client.get("/_partials/sidebar")
    list_tag = _extract_list_open_tag(resp.get_data(as_text=True))
    assert "hx-trigger=\"every 10s [document.visibilityState === 'visible']\"" in list_tag, list_tag
    assert 'hx-target="this"' in list_tag, list_tag
    assert 'hx-swap="outerHTML"' in list_tag, list_tag


def test_sidebar_partial_disinherits_polling_attrs(db_app: Flask) -> None:
    """`hx-disinherit="*"` ist Pflicht auf dem `<ul id="server-list">`.

    Die Polling-Attribute (`hx-target="this"`, `hx-swap="outerHTML"`) sind
    PRIVAT fuer den Container — ohne `hx-disinherit="*"` erben alle
    `<a hx-get>`-Klicks in den `<li>`-Zeilen das `hx-swap="outerHTML"`
    und ersetzen den Klick-Ziel-Container (`#detail-pane`) komplett,
    statt nur dessen `innerHTML` zu swappen. Folge: `<main id="detail-pane">`
    verschwindet aus dem DOM, der Scroll-Container fehlt und die
    Server-Detail-Sektion (Findings-Tabelle) landet unterhalb des
    sichtbaren Bereichs ohne Scroll-Moeglichkeit."""
    create_admin_user(db_app)
    _create_server(db_app, name="srv-sidebar-disinherit")
    client = db_app.test_client()
    login(client)

    resp = client.get("/_partials/sidebar")
    list_tag = _extract_list_open_tag(resp.get_data(as_text=True))
    assert 'hx-disinherit="*"' in list_tag, list_tag


def test_sidebar_partial_renders_existing_servers(db_app: Flask) -> None:
    """Sanity: ein vorhandener Server taucht in der Liste auf."""
    create_admin_user(db_app)
    _create_server(db_app, name="srv-visible-in-sidebar")
    client = db_app.test_client()
    login(client)

    resp = client.get("/_partials/sidebar")
    body = resp.get_data(as_text=True)
    assert "srv-visible-in-sidebar" in body, body[:400]


def test_sidebar_partial_renders_empty_state_when_no_servers(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/_partials/sidebar")
    body = resp.get_data(as_text=True)
    assert 'data-empty="no_servers"' in body, body[:400]


# ---------------------------------------------------------------------------
# Filter-Persistenz im hx-get der Sidebar-Liste
# ---------------------------------------------------------------------------


def test_sidebar_partial_preserves_tag_filter_in_hx_get(db_app: Flask) -> None:
    """`?tag=prod` muss im `hx-get`-Attribut des `<ul>`-Containers
    persistieren — analog zur Pane-URL, damit Polling den Tag-Filter
    nicht verliert."""
    create_admin_user(db_app)
    _create_server(db_app, name="srv-prod", tags=["prod"])
    _create_server(db_app, name="srv-staging", tags=["staging"])
    client = db_app.test_client()
    login(client)

    resp = client.get("/_partials/sidebar?tag=prod")
    list_tag = _extract_list_open_tag(resp.get_data(as_text=True))
    assert "tag=prod" in list_tag, list_tag
