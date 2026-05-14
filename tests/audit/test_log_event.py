"""Unit-Tests fuer `app.audit.log_event`.

DoD aus `docs/blocks/B-models.md`:
- log_event schreibt korrekte Spalten (actor, actor_user_id, action,
  target_type, target_id, comment, metadata).
- Ohne Request-Context wird `actor` automatisch auf "system" gesetzt.
- Mit eingeloggtem User landet `actor_user_id` korrekt aus `current_user`.
- Metadata roundtrip durch JSONB.
"""

from __future__ import annotations

from flask import Flask
from sqlalchemy import select

from app.audit import log_event
from app.db import get_session_factory
from app.models import AuditEvent, User
from tests._helpers import create_admin_user

# ---------------------------------------------------------------------------
# Spalten-Roundtrip.
# ---------------------------------------------------------------------------


def test_log_event_writes_all_columns(db_app: Flask) -> None:
    """Aufruf ohne Request-Context -> `actor='system'`, alle Felder gesetzt."""
    factory = get_session_factory(db_app)
    s = factory()
    try:
        event = log_event(
            "test.action",
            "tag",
            42,
            comment="hi",
            metadata={"k": "v", "n": 7},
            session=s,
        )
        s.commit()
        assert event.id is not None
    finally:
        s.close()

    # Read-back mit frischer Session.
    s2 = factory()
    try:
        row = s2.execute(select(AuditEvent)).scalar_one()
        assert row.action == "test.action"
        assert row.target_type == "tag"
        assert row.target_id == "42", row.target_id  # String-Coercion erwartet.
        assert row.comment == "hi"
        assert row.event_metadata == {"k": "v", "n": 7}, row.event_metadata
        assert row.actor == "system", row.actor
        assert row.actor_user_id is None
        assert row.ts is not None
    finally:
        s2.close()


def test_log_event_target_id_none_is_persisted_as_null(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    s = factory()
    try:
        log_event("test.no_target", "system", None, session=s)
        s.commit()
    finally:
        s.close()

    s2 = factory()
    try:
        row = s2.execute(select(AuditEvent)).scalar_one()
        assert row.target_id is None
    finally:
        s2.close()


def test_log_event_string_target_id_passthrough(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    s = factory()
    try:
        log_event("test.str_target", "server", "abc-123", session=s)
        s.commit()
    finally:
        s.close()

    s2 = factory()
    try:
        row = s2.execute(select(AuditEvent)).scalar_one()
        assert row.target_id == "abc-123"
    finally:
        s2.close()


# ---------------------------------------------------------------------------
# Auto-Capture aus `current_user`.
# ---------------------------------------------------------------------------


def test_log_event_uses_authenticated_user_as_actor(db_app: Flask) -> None:
    """Im Request-Context mit eingeloggtem User: `actor` = username, `actor_user_id` = id."""
    uid = create_admin_user(db_app)

    # Wir loggen via /login ein und feuern dann log_event aus einer Test-Route.
    @db_app.route("/__test/audit", methods=["POST"])
    def _emit() -> str:  # pyright: ignore[reportUnusedFunction]
        from app.db import get_session

        sess = get_session()
        log_event("test.from_view", "thing", uid, session=sess)
        sess.commit()
        return "ok"

    client = db_app.test_client()
    # Login durchfuehren.
    from tests._helpers import login

    login(client)

    resp = client.post("/__test/audit")
    assert resp.status_code == 200, resp.data[:200]

    factory = get_session_factory(db_app)
    s = factory()
    try:
        rows = (
            s.execute(select(AuditEvent).where(AuditEvent.action == "test.from_view"))
            .scalars()
            .all()
        )
        assert len(rows) == 1, rows
        ev = rows[0]
        # Username = "admin" (siehe tests/_helpers.py).
        assert ev.actor == "admin", ev.actor
        assert ev.actor_user_id == uid, (ev.actor_user_id, uid)
    finally:
        s.close()


def test_log_event_explicit_actor_overrides_current_user(db_app: Flask) -> None:
    """`actor=...` als Argument schlaegt die Auto-Capture aus `current_user`."""
    create_admin_user(db_app)

    @db_app.route("/__test/audit_override", methods=["POST"])
    def _emit() -> str:  # pyright: ignore[reportUnusedFunction]
        from app.db import get_session

        sess = get_session()
        log_event(
            "test.override",
            "thing",
            None,
            actor="external-script",
            actor_id=None,
            session=sess,
        )
        sess.commit()
        return "ok"

    client = db_app.test_client()
    from tests._helpers import login

    login(client)

    resp = client.post("/__test/audit_override")
    assert resp.status_code == 200, resp.data[:200]

    factory = get_session_factory(db_app)
    s = factory()
    try:
        rows = (
            s.execute(select(AuditEvent).where(AuditEvent.action == "test.override"))
            .scalars()
            .all()
        )
        assert len(rows) == 1
        ev = rows[0]
        assert ev.actor == "external-script"
        # `actor_user_id` muss explizit als None ankommen, NICHT aus current_user gezogen werden.
        assert ev.actor_user_id is None, ev.actor_user_id
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Metadata-Edge-Cases.
# ---------------------------------------------------------------------------


def test_log_event_metadata_none_roundtrip(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    s = factory()
    try:
        log_event("test.nometa", "x", None, session=s)
        s.commit()
    finally:
        s.close()

    s2 = factory()
    try:
        row = s2.execute(select(AuditEvent)).scalar_one()
        assert row.event_metadata is None
    finally:
        s2.close()


def test_log_event_metadata_nested_dict_roundtrip(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    s = factory()
    try:
        meta = {"ip": "10.0.0.1", "ids": [1, 2, 3], "nested": {"a": True, "b": None}}
        log_event("test.meta", "x", 1, metadata=meta, session=s)
        s.commit()
    finally:
        s.close()

    s2 = factory()
    try:
        row = s2.execute(select(AuditEvent)).scalar_one()
        assert row.event_metadata == {
            "ip": "10.0.0.1",
            "ids": [1, 2, 3],
            "nested": {"a": True, "b": None},
        }
    finally:
        s2.close()


# ---------------------------------------------------------------------------
# Defensive: gleichzeitig actor und actor_id setzen.
# ---------------------------------------------------------------------------


def test_log_event_explicit_actor_and_actor_id(db_app: Flask) -> None:
    """Beide Felder explizit gesetzt -> exakt durchgereicht."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        s = factory()
        try:
            # User anlegen, damit FK valide ist.
            from app.auth import hash_password

            u = User(username="manual", password_hash=hash_password("x" * 16))
            s.add(u)
            s.flush()
            log_event("test.both", "y", 99, actor="manual", actor_id=u.id, session=s)
            s.commit()
            uid = u.id
        finally:
            s.close()

    s2 = factory()
    try:
        row = s2.execute(select(AuditEvent).where(AuditEvent.action == "test.both")).scalar_one()
        assert row.actor == "manual"
        assert row.actor_user_id == uid
    finally:
        s2.close()
