"""Tests fuer die Master-Key-Rotations-View (ADR-0016 / §8-Spec-Luecke).

Routen:
  - `GET  /settings/master-key`        — Rotations-UI rendern.
  - `POST /settings/master-key/rotate` — Rotation ausfuehren.

DoD-Aspekte aus dem Block-I-Addendum:
  - CSRF zwingend (POST ohne CSRF -> 400).
  - Erfolgreiche Rotation aendert `settings.master_key_hash`.
  - Audit-Event `master_key.rotated` mit `metadata.hash_prefix` (8 Zeichen).
  - Audit-Event-Metadata enthaelt NICHT den Klartext-Master-Key.
  - Klartext-Master-Key wird genau **einmalig** nach Rotation angezeigt.
  - Alte Server-Keys bleiben gueltig nach der Rotation (Server-Key-Hash
    ist nicht vom Master-Key abgeleitet — siehe ARCHITECTURE.md §8).
"""

from __future__ import annotations

from typing import Any

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app.auth import hash_master_key, verify_server_key
from app.db import get_session_factory
from app.models import AuditEvent, Server
from app.settings_service import get_settings_row
from tests._helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    DEFAULT_TEST_MASTER_KEY,
    create_admin_user,
    register_test_server,
    set_master_key,
)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _login_with_csrf(client: FlaskClient) -> None:
    """Login gegen die CSRF-aktive App. Holt zuerst den Token aus dem
    `/login`-GET-Form und schickt ihn im POST mit."""
    import re

    get_resp = client.get("/login")
    assert get_resp.status_code == 200, get_resp.status_code
    match = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', get_resp.data)
    assert match is not None, "csrf_token nicht im /login-Form gefunden"
    token = match.group(1).decode()
    resp = client.post(
        "/login",
        data={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD,
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, (resp.status_code, resp.get_data(as_text=True)[:400])


def _get_master_key_hash(app: Flask) -> str | None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = get_settings_row(sess)
            return row.master_key_hash
        finally:
            sess.close()


def _last_rotation_audit(app: Flask) -> AuditEvent | None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            stmt = (
                select(AuditEvent)
                .where(AuditEvent.action == "master_key.rotated")
                .order_by(AuditEvent.ts.desc())
                .limit(1)
            )
            return sess.execute(stmt).scalar_one_or_none()
        finally:
            sess.close()


def _csrf_token_from_html(html: str) -> str:
    """Sucht das `csrf_token`-Hidden-Input. Wirft AssertionError wenn fehlend."""
    import re

    match = re.search(r'<input[^>]*name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match is not None, "csrf_token-Input fehlt im Render"
    return match.group(1)


# ---------------------------------------------------------------------------
# GET /settings/master-key
# ---------------------------------------------------------------------------


def test_master_key_view_redirects_when_not_logged_in(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/settings/master-key", follow_redirects=False)
    assert resp.status_code == 302, resp.status_code
    assert "/login" in resp.headers.get("Location", ""), resp.headers


def test_master_key_view_renders_for_logged_in_user(
    csrf_enabled_db_app: Flask,
) -> None:
    """CSRF-aktiver Pfad: das gerenderte HTML enthaelt einen
    `csrf_token`-Hidden-Input. Klartext-Key wird im Default-Render NICHT
    angezeigt (`new_master_key=None`)."""
    create_admin_user(csrf_enabled_db_app)
    set_master_key(csrf_enabled_db_app)
    client = csrf_enabled_db_app.test_client()
    _login_with_csrf(client)

    resp = client.get("/settings/master-key")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    # csrf_token-Input vorhanden.
    assert 'name="csrf_token"' in body, "CSRF-Token fehlt im Render"
    # Klartext-Key-Container existiert nicht im Default-Render.
    assert 'id="new-master-key"' not in body, (
        "Klartext-Key darf ohne Rotation nicht angezeigt werden"
    )
    # Header-Text ist vorhanden.
    assert "Master-Key" in body
    # "noch nie" Fallback ODER Datums-Markup — eines von beiden.
    # Setup-Datum wird via `_last_master_key_rotation_at` ueber
    # `setup_completed_at` ausgefuellt; sollte daher nicht "noch nie" zeigen.
    # Beide Faelle akzeptabel — wir asserten nur dass der "Letzte Rotation"-
    # Block existiert.
    assert "Letzte Rotation" in body


# ---------------------------------------------------------------------------
# POST /settings/master-key/rotate
# ---------------------------------------------------------------------------


def test_master_key_rotate_without_csrf_returns_400(
    csrf_enabled_db_app: Flask,
) -> None:
    """POST ohne CSRF-Token -> 400 (View setzt explizit `make_response(..., 400)`)."""
    create_admin_user(csrf_enabled_db_app)
    set_master_key(csrf_enabled_db_app)
    client = csrf_enabled_db_app.test_client()
    _login_with_csrf(client)
    # Bewusst kein CSRF-Token mitgeben.
    resp = client.post("/settings/master-key/rotate", data={})
    assert resp.status_code == 400, (resp.status_code, resp.get_data(as_text=True)[:400])


def test_master_key_rotate_with_csrf_succeeds_and_shows_new_key(
    csrf_enabled_db_app: Flask,
) -> None:
    """POST mit CSRF-Token: 200, Response enthaelt den neuen Klartext-Key
    genau einmal in einem `<code id="new-master-key">`-Block."""
    create_admin_user(csrf_enabled_db_app)
    set_master_key(csrf_enabled_db_app)
    client = csrf_enabled_db_app.test_client()
    _login_with_csrf(client)

    # Erst GET fuer CSRF-Token.
    get_resp = client.get("/settings/master-key")
    csrf = _csrf_token_from_html(get_resp.get_data(as_text=True))

    resp = client.post(
        "/settings/master-key/rotate",
        data={"csrf_token": csrf},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    # Klartext-Code-Block existiert mit der `id`.
    assert 'id="new-master-key"' in body, "Klartext-Master-Key-Container fehlt"

    # Extrahiere den Klartext-Key aus dem `<code>`-Block.
    import re

    m = re.search(
        r'<code\s+id="new-master-key"[^>]*>([^<]+)</code>',
        body,
    )
    assert m is not None, "Master-Key-Klartext nicht im Code-Block"
    plain_key = m.group(1).strip()
    # `generate_master_key()` -> `token_urlsafe(32)` -> ~43 Zeichen.
    assert 20 < len(plain_key) < 80, f"Klartext-Key-Laenge ungewoehnlich: {len(plain_key)}"


def test_master_key_rotate_changes_stored_hash(
    csrf_enabled_db_app: Flask,
) -> None:
    create_admin_user(csrf_enabled_db_app)
    set_master_key(csrf_enabled_db_app)
    client = csrf_enabled_db_app.test_client()
    _login_with_csrf(client)

    old_hash = _get_master_key_hash(csrf_enabled_db_app)
    assert old_hash is not None and old_hash == hash_master_key(DEFAULT_TEST_MASTER_KEY)

    get_resp = client.get("/settings/master-key")
    csrf = _csrf_token_from_html(get_resp.get_data(as_text=True))

    resp = client.post(
        "/settings/master-key/rotate",
        data={"csrf_token": csrf},
    )
    assert resp.status_code == 200

    new_hash = _get_master_key_hash(csrf_enabled_db_app)
    assert new_hash is not None
    assert new_hash != old_hash
    # SHA-256-Hex.
    assert len(new_hash) == 64
    assert all(c in "0123456789abcdef" for c in new_hash)


def test_master_key_rotate_writes_audit_event_with_hash_prefix(
    csrf_enabled_db_app: Flask,
) -> None:
    create_admin_user(csrf_enabled_db_app)
    set_master_key(csrf_enabled_db_app)
    client = csrf_enabled_db_app.test_client()
    _login_with_csrf(client)

    get_resp = client.get("/settings/master-key")
    csrf = _csrf_token_from_html(get_resp.get_data(as_text=True))

    resp = client.post(
        "/settings/master-key/rotate",
        data={"csrf_token": csrf},
    )
    assert resp.status_code == 200

    event = _last_rotation_audit(csrf_enabled_db_app)
    assert event is not None, "Audit-Event master_key.rotated fehlt"
    assert event.action == "master_key.rotated"
    metadata = event.event_metadata or {}
    assert "hash_prefix" in metadata, metadata
    assert isinstance(metadata["hash_prefix"], str)
    assert len(metadata["hash_prefix"]) == 8


def test_master_key_rotate_audit_metadata_has_no_plaintext_key(
    csrf_enabled_db_app: Flask,
) -> None:
    """Sicherheits-Gegen-Test: das Audit-Event-Metadata-Dict enthaelt
    weder den Klartext-Key noch den vollen SHA-256-Hash.

    Der View speichert ausschliesslich `metadata={"hash_prefix": new_hash[:8]}`.
    Wir verifizieren das durch Substring-Inspektion gegen den Klartext und
    gegen den 64-Zeichen-Hex-Hash."""
    create_admin_user(csrf_enabled_db_app)
    set_master_key(csrf_enabled_db_app)
    client = csrf_enabled_db_app.test_client()
    _login_with_csrf(client)

    get_resp = client.get("/settings/master-key")
    csrf = _csrf_token_from_html(get_resp.get_data(as_text=True))

    resp = client.post(
        "/settings/master-key/rotate",
        data={"csrf_token": csrf},
    )
    body = resp.get_data(as_text=True)
    import re

    m = re.search(
        r'<code\s+id="new-master-key"[^>]*>([^<]+)</code>',
        body,
    )
    assert m is not None
    plain_key = m.group(1).strip()
    full_hash = hash_master_key(plain_key)

    event = _last_rotation_audit(csrf_enabled_db_app)
    assert event is not None
    metadata: dict[str, Any] = event.event_metadata or {}

    # Audit-Metadata darf weder Klartext noch vollen Hash enthalten.
    serialized = repr(metadata)
    assert plain_key not in serialized, "KLARTEXT-Master-Key in Audit-Metadata!"
    assert full_hash not in serialized, "Voller Hash in Audit-Metadata — nur Prefix erlaubt"

    # `target_id` und `comment` ebenfalls Plain-Free.
    assert plain_key not in (event.target_id or "")
    assert plain_key not in (event.comment or "")


# ---------------------------------------------------------------------------
# Server-Keys bleiben gueltig
# ---------------------------------------------------------------------------


def test_master_key_rotation_does_not_invalidate_existing_server_keys(
    csrf_enabled_db_app: Flask,
) -> None:
    """Kritisches Invariante (ARCHITECTURE.md §8): die Rotation des
    Master-Keys aendert KEINE Server-Key-Hashes. Wir registrieren einen
    Server via ORM, fuehren die Rotation durch und verifizieren, dass
    der Server-Key-Hash unveraendert ist und der Klartext-Key weiterhin
    verifiziert."""
    create_admin_user(csrf_enabled_db_app)
    set_master_key(csrf_enabled_db_app)

    # Server mit bekanntem Klartext-Key anlegen.
    server_id, plain_server_key = register_test_server(
        csrf_enabled_db_app, name="srv-before-rotation"
    )

    # Hash vor Rotation merken.
    factory = get_session_factory(csrf_enabled_db_app)
    with csrf_enabled_db_app.app_context():
        sess = factory()
        try:
            srv = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            old_server_hash = srv.api_key_hash
        finally:
            sess.close()

    # Rotation.
    client = csrf_enabled_db_app.test_client()
    _login_with_csrf(client)
    get_resp = client.get("/settings/master-key")
    csrf = _csrf_token_from_html(get_resp.get_data(as_text=True))
    resp = client.post(
        "/settings/master-key/rotate",
        data={"csrf_token": csrf},
    )
    assert resp.status_code == 200

    # Server-Key-Hash unveraendert.
    with csrf_enabled_db_app.app_context():
        sess = factory()
        try:
            srv2 = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            assert srv2.api_key_hash == old_server_hash
            # Klartext-Server-Key verifiziert weiterhin.
            assert verify_server_key(srv2.api_key_hash, plain_server_key)
        finally:
            sess.close()


def test_master_key_rotate_redirects_when_not_logged_in(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.post(
        "/settings/master-key/rotate",
        data={"csrf_token": "irrelevant"},
        follow_redirects=False,
    )
    # Ohne Login zuerst Redirect, dann CSRF-Check.
    assert resp.status_code in (302, 400, 401), resp.status_code
    if resp.status_code == 302:
        assert "/login" in resp.headers.get("Location", "")
