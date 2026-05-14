"""Tests fuer `/servers/<id>` und Tag-Add/Remove (Block D).

Deckt Detail-View, 404-Pfad, HTMX-Tag-Editor (Add/Remove inkl. Audit-
Events und CSRF-Schutz) ab.
"""

from __future__ import annotations

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, Server, ServerTag, Tag
from tests._helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin_user, login

# ---------------------------------------------------------------------------
# Setup-Helper
# ---------------------------------------------------------------------------


def _create_server(app: Flask, name: str = "srv-detail") -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _create_tag(app: Flask, name: str = "prod", color: str = "#6b7280") -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            tag = sess.execute(select(Tag).where(Tag.name == name)).scalar_one_or_none()
            if tag is None:
                tag = Tag(name=name, color=color)
                sess.add(tag)
                sess.flush()
            tid = tag.id
            sess.commit()
            return tid
        finally:
            sess.close()


def _audit_actions(app: Flask) -> list[str]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return [e.action for e in sess.execute(select(AuditEvent)).scalars().all()]
        finally:
            sess.close()


def _server_tags(app: Flask, server_id: int) -> list[str]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            links = (
                sess.execute(select(ServerTag).where(ServerTag.server_id == server_id))
                .scalars()
                .all()
            )
            tags: list[str] = []
            for link in links:
                tag = sess.execute(select(Tag).where(Tag.id == link.tag_id)).scalar_one()
                tags.append(tag.name)
            return tags
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Auth/Show
# ---------------------------------------------------------------------------


def test_detail_redirects_when_not_logged_in(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    client = db_app.test_client()
    resp = client.get(f"/servers/{sid}", follow_redirects=False)
    assert resp.status_code in (301, 302), resp.status_code
    assert "/login" in resp.headers.get("Location", "")


def test_detail_shows_server_for_admin(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-visible")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    assert "srv-visible" in body


def test_detail_returns_404_for_unknown_server(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/servers/999999")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tag-Add
# ---------------------------------------------------------------------------


def test_add_existing_tag_succeeds_and_audits(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    _create_tag(db_app, name="prod")

    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), resp.status_code
    assert "prod" in _server_tags(db_app, sid)
    assert "server.tag.added" in _audit_actions(db_app)


def test_add_nonexistent_tag_does_nothing(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "ghost"},
        follow_redirects=False,
    )
    # Redirect oder 200 (HTMX), aber kein DB-Insert und kein Audit.
    assert resp.status_code in (200, 302, 303)
    assert _server_tags(db_app, sid) == []
    assert "server.tag.added" not in _audit_actions(db_app)


def test_add_tag_with_invalid_regex_rejected(db_app: Flask) -> None:
    """Eingabe `Foo Bar` matched TAG_NAME_REGEX nicht — nichts wird geschrieben."""
    create_admin_user(db_app)
    sid = _create_server(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "Foo Bar"},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 302, 303)
    assert _server_tags(db_app, sid) == []
    assert "server.tag.added" not in _audit_actions(db_app)


def test_add_existing_tag_twice_is_idempotent(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)

    r1 = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        follow_redirects=False,
    )
    r2 = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        follow_redirects=False,
    )
    assert r1.status_code in (200, 302, 303)
    assert r2.status_code in (200, 302, 303)
    # Tag-Mapping bleibt 1x.
    assert _server_tags(db_app, sid) == ["prod"]
    # Audit-Event nur einmal.
    actions = _audit_actions(db_app)
    assert actions.count("server.tag.added") == 1


def test_add_tag_lowercases_input(db_app: Flask) -> None:
    """Input `PROD` wird auf `prod` normalisiert."""
    create_admin_user(db_app)
    sid = _create_server(db_app)
    _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "PROD"},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 302, 303)
    assert "prod" in _server_tags(db_app, sid)


# ---------------------------------------------------------------------------
# Tag-Remove
# ---------------------------------------------------------------------------


def test_remove_tag_succeeds_and_audits(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    tid = _create_tag(db_app, name="prod")

    # Erst Tag setzen.
    client = db_app.test_client()
    login(client)
    client.post(f"/servers/{sid}/tags/add", data={"tag_name": "prod"})
    assert "prod" in _server_tags(db_app, sid)

    resp = client.post(f"/servers/{sid}/tags/{tid}/remove", follow_redirects=False)
    assert resp.status_code in (200, 302, 303)
    assert _server_tags(db_app, sid) == []
    assert "server.tag.removed" in _audit_actions(db_app)


def test_remove_nonexistent_link_is_safe(db_app: Flask) -> None:
    """Tag existiert, ist aber dem Server nicht zugewiesen → no-op."""
    create_admin_user(db_app)
    sid = _create_server(db_app)
    tid = _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)
    resp = client.post(f"/servers/{sid}/tags/{tid}/remove", follow_redirects=False)
    assert resp.status_code in (200, 302, 303)
    assert "server.tag.removed" not in _audit_actions(db_app)


# ---------------------------------------------------------------------------
# HTMX-Pfad
# ---------------------------------------------------------------------------


def test_add_tag_with_htmx_header_returns_fragment(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        headers={"HX-Request": "true"},
    )
    # HTMX-Response: 200 + HTML-Fragment (kein Redirect).
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    # Fragment beginnt mit `tag-editor-wrap`-Container.
    assert "tag-editor-wrap" in body
    # Kein vollstaendiges `<html`-Dokument.
    assert "<html" not in body.lower()


def test_remove_tag_with_htmx_header_returns_fragment(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    tid = _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)
    # Erst zuweisen.
    client.post(f"/servers/{sid}/tags/add", data={"tag_name": "prod"})

    resp = client.post(
        f"/servers/{sid}/tags/{tid}/remove",
        headers={"HX-Request": "true"},
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "tag-editor-wrap" in body
    assert "<html" not in body.lower()


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


def test_add_tag_without_csrf_token_is_rejected(csrf_enabled_db_app: Flask) -> None:
    """Bei aktivem CSRF-Schutz muss der POST ohne Token abgewiesen werden."""
    create_admin_user(csrf_enabled_db_app)
    sid = _create_server(csrf_enabled_db_app)
    _create_tag(csrf_enabled_db_app, name="prod")

    client = csrf_enabled_db_app.test_client()
    # Login via Form — der Form-Endpoint zieht den Token aus der GET-Seite,
    # was wir manuell tun muessen.
    login_get = client.get("/login")
    assert login_get.status_code == 200
    # Token extrahieren.
    import re

    match = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', login_get.data)
    assert match is not None, "csrf_token nicht im /login-Form gefunden"
    token = match.group(1).decode()

    resp_login = client.post(
        "/login",
        data={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD,
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert resp_login.status_code == 302, resp_login.get_data(as_text=True)[:400]

    # Add-Request OHNE Token — sollte abgewiesen werden (Redirect mit Flash
    # oder 400). Implementer-Code: bei ungueltigem CSRF gibt es einen
    # Redirect mit Flash-Message. Wir akzeptieren beide vernuenftigen
    # Verhaltensweisen, schliessen aber definitiv den Success-Pfad aus.
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303, 400), resp.get_data(as_text=True)[:400]
    # DB ist NICHT veraendert worden.
    assert _server_tags(csrf_enabled_db_app, sid) == []
    assert "server.tag.added" not in _audit_actions(csrf_enabled_db_app)
