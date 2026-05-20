"""Unit-Tests fuer `app.audit.log_event` ohne DB.

Verifiziert via MagicMock-Session:

- `log_event` ruft `session.add(AuditEvent(...))` mit den korrekten Spalten.
- Ohne Request-Context wird `actor` automatisch auf "system" gesetzt.
- Mit `actor`/`actor_id`-Argumenten werden diese explizit durchgereicht und
  schlagen die Auto-Capture aus `current_user` (wenn vorhanden).
- Metadata wird unveraendert in `AuditEvent.event_metadata` durchgereicht.
- `target_id=None` bleibt None; `target_id=int` wird zu `str` coerced;
  `target_id=str` bleibt String.
- Wenn ein User authentisiert ist (Flask-Login `current_user`), werden
  `actor` und `actor_user_id` aus `current_user.username`/`.id` gezogen.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from flask import Flask

from app.audit import log_event
from app.models import AuditEvent


def _capture_added_event(session: MagicMock) -> AuditEvent:
    """Liefert das letzte AuditEvent-Argument das an `session.add(...)` ging."""
    assert session.add.call_count == 1, session.add.call_args_list
    obj = session.add.call_args[0][0]
    assert isinstance(obj, AuditEvent)
    return obj


# ---------------------------------------------------------------------------
# Spalten-Roundtrip ohne Request-Context.
# ---------------------------------------------------------------------------


def test_log_event_writes_all_columns_without_request_context() -> None:
    """Aufruf ohne Flask-Request-Context -> `actor='system'`, alle Felder gesetzt."""
    session = MagicMock()
    metadata: dict[str, Any] = {"k": "v", "n": 7}

    event = log_event(
        "test.action",
        "tag",
        42,
        comment="hi",
        metadata=metadata,
        session=session,
    )

    added = _capture_added_event(session)
    assert added is event
    assert added.action == "test.action"
    assert added.target_type == "tag"
    assert added.target_id == "42"  # int → str-Coercion erwartet.
    assert added.comment == "hi"
    assert added.event_metadata == {"k": "v", "n": 7}
    assert added.actor == "system"
    assert added.actor_user_id is None
    # `session.flush()` muss aufgerufen worden sein damit `event.id` gesetzt
    # ist (die Mock-Variante hat keine echte FK, aber wir verifizieren den
    # Lifecycle-Call).
    session.flush.assert_called_once()


def test_log_event_target_id_none_is_persisted_as_null() -> None:
    session = MagicMock()
    log_event("test.no_target", "system", None, session=session)
    added = _capture_added_event(session)
    assert added.target_id is None


def test_log_event_string_target_id_passthrough() -> None:
    session = MagicMock()
    log_event("test.str_target", "server", "abc-123", session=session)
    added = _capture_added_event(session)
    assert added.target_id == "abc-123"


# ---------------------------------------------------------------------------
# Explizite Actor-Argumente schlagen Auto-Capture.
# ---------------------------------------------------------------------------


def test_log_event_explicit_actor_and_actor_id_passthrough() -> None:
    """Beide Felder explizit gesetzt -> exakt durchgereicht (kein Auto-Capture)."""
    session = MagicMock()
    log_event(
        "test.both",
        "y",
        99,
        actor="manual",
        actor_id=123,
        session=session,
    )
    added = _capture_added_event(session)
    assert added.actor == "manual"
    assert added.actor_user_id == 123


def test_log_event_explicit_actor_overrides_authenticated_user(app: Flask) -> None:
    """`actor=...` Argument schlaegt Auto-Capture aus `current_user`.

    Wir simulieren einen authentisierten User via `app_env`-Flask-Context
    plus `flask_login.current_user`-Patch. Wenn das Argument `actor` aber
    explizit gesetzt ist, ignoriert der Code den `current_user`-Path.
    """
    session = MagicMock()
    fake_user = MagicMock()
    fake_user.is_authenticated = True
    fake_user.username = "alice"
    fake_user.id = 7

    with app.test_request_context("/"), patch("app.audit.current_user", fake_user):
        log_event(
            "test.override",
            "thing",
            None,
            actor="external-script",
            actor_id=None,
            session=session,
        )

    added = _capture_added_event(session)
    assert added.actor == "external-script"
    # `actor_user_id` muss explizit als None ankommen, NICHT aus current_user
    # gezogen werden — der Auto-Capture-Pfad ist via `resolved_actor is None`
    # gated, und der ist hier nicht None.
    assert added.actor_user_id is None


# ---------------------------------------------------------------------------
# Auto-Capture aus `current_user` (Request-Context + Login).
# ---------------------------------------------------------------------------


def test_log_event_uses_authenticated_user_as_actor(app: Flask) -> None:
    """Im Request-Context mit `current_user.is_authenticated=True`:

    `actor` = username, `actor_user_id` = id.
    """
    session = MagicMock()
    fake_user = MagicMock()
    fake_user.is_authenticated = True
    fake_user.username = "admin"
    fake_user.id = 42

    with app.test_request_context("/"), patch("app.audit.current_user", fake_user):
        log_event("test.from_view", "thing", 42, session=session)

    added = _capture_added_event(session)
    assert added.actor == "admin"
    assert added.actor_user_id == 42


def test_log_event_uses_system_when_user_is_unauthenticated(app: Flask) -> None:
    """Request-Context aber `is_authenticated=False` -> actor='system'."""
    session = MagicMock()
    fake_user = MagicMock()
    fake_user.is_authenticated = False
    # username/id sind irrelevant — der Code-Pfad wird nicht erreicht.

    with app.test_request_context("/"), patch("app.audit.current_user", fake_user):
        log_event("test.anon", "thing", 1, session=session)

    added = _capture_added_event(session)
    assert added.actor == "system"
    assert added.actor_user_id is None


# ---------------------------------------------------------------------------
# Metadata-Edge-Cases.
# ---------------------------------------------------------------------------


def test_log_event_metadata_none_roundtrip() -> None:
    session = MagicMock()
    log_event("test.nometa", "x", None, session=session)
    added = _capture_added_event(session)
    assert added.event_metadata is None


def test_log_event_metadata_nested_dict_passthrough() -> None:
    session = MagicMock()
    meta = {"ip": "10.0.0.1", "ids": [1, 2, 3], "nested": {"a": True, "b": None}}
    log_event("test.meta", "x", 1, metadata=meta, session=session)
    added = _capture_added_event(session)
    assert added.event_metadata == meta
