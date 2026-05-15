"""Tests fuer `notify_conversations_for_scan` aus `app.services.llm_update_hook`.

Verifiziert:
- Aktive Conversation bekommt eine System-Message angehaengt mit Update-Text.
- Audit-Event `llm.conversation_update_hook` mit metadata gesetzt.
- Archive-Conversation wird ignoriert.
- Server ohne aktive Conversation => no-op.
- Mehrere aktive Conversations => Message wird an alle angehaengt.
- `changed_count=0` (Block-E-Limit) korrekt im Text.
- `new=0, resolved=0, changed=0` => no-op (return 0).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.models import (
    AuditEvent,
    LlmConversation,
    LlmConversationStatus,
    LlmMessage,
    LlmMessageRole,
    Server,
)
from app.services.llm_update_hook import notify_conversations_for_scan


def _make_server(session: Any, name: str = "u-srv") -> Server:
    srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
    session.add(srv)
    session.flush()
    return srv


def _make_conv(
    session: Any,
    server_id: int,
    *,
    status: LlmConversationStatus = LlmConversationStatus.ACTIVE,
) -> LlmConversation:
    ts = datetime.now(tz=UTC)
    conv = LlmConversation(
        server_id=server_id,
        started_at=ts,
        last_message_at=ts,
        model="m",
        status=status,
        findings_snapshot_at=ts,
    )
    session.add(conv)
    session.flush()
    return conv


def _messages_for(session: Any, conv_id: int) -> list[LlmMessage]:
    return list(
        session.execute(
            select(LlmMessage)
            .where(LlmMessage.conversation_id == conv_id)
            .order_by(LlmMessage.id.asc())
        )
        .scalars()
        .all()
    )


def _audit_events_for(session: Any, action: str) -> list[AuditEvent]:
    return list(
        session.execute(select(AuditEvent).where(AuditEvent.action == action)).scalars().all()
    )


# ---------------------------------------------------------------------------


def test_single_active_conversation_gets_system_message(db_session: Any) -> None:
    srv = _make_server(db_session)
    conv = _make_conv(db_session, srv.id)
    db_session.commit()

    n = notify_conversations_for_scan(
        db_session, srv.id, new_count=5, resolved_count=2, changed_count=0
    )
    db_session.commit()

    assert n == 1
    msgs = _messages_for(db_session, conv.id)
    assert len(msgs) == 1
    assert msgs[0].role == LlmMessageRole.SYSTEM
    # Inhalt mit Counts.
    assert "5" in msgs[0].content
    assert "2" in msgs[0].content


def test_update_hook_writes_audit_event(db_session: Any) -> None:
    srv = _make_server(db_session)
    conv = _make_conv(db_session, srv.id)
    db_session.commit()

    notify_conversations_for_scan(db_session, srv.id, new_count=3, resolved_count=1)
    db_session.commit()

    events = _audit_events_for(db_session, "llm.conversation_update_hook")
    assert len(events) == 1
    ev = events[0]
    assert ev.target_type == "llm_conversation"
    assert ev.target_id == str(conv.id)
    assert ev.event_metadata is not None
    assert ev.event_metadata["server_id"] == srv.id
    assert ev.event_metadata["new"] == 3
    assert ev.event_metadata["resolved"] == 1
    assert ev.event_metadata["changed"] == 0


def test_archived_conversations_are_not_touched(db_session: Any) -> None:
    srv = _make_server(db_session)
    archived = _make_conv(db_session, srv.id, status=LlmConversationStatus.ARCHIVED)
    db_session.commit()

    n = notify_conversations_for_scan(db_session, srv.id, new_count=5, resolved_count=0)
    db_session.commit()

    assert n == 0
    msgs = _messages_for(db_session, archived.id)
    assert msgs == []
    # Audit darf nicht ausgeloest werden.
    assert _audit_events_for(db_session, "llm.conversation_update_hook") == []


def test_no_active_conversation_is_no_op(db_session: Any) -> None:
    srv = _make_server(db_session)
    db_session.commit()

    n = notify_conversations_for_scan(db_session, srv.id, new_count=10, resolved_count=2)
    db_session.commit()

    assert n == 0
    assert _audit_events_for(db_session, "llm.conversation_update_hook") == []


def test_multiple_active_conversations_get_message_each(db_session: Any) -> None:
    srv = _make_server(db_session)
    conv_a = _make_conv(db_session, srv.id)
    conv_b = _make_conv(db_session, srv.id)
    db_session.commit()

    n = notify_conversations_for_scan(db_session, srv.id, new_count=2, resolved_count=1)
    db_session.commit()

    assert n == 2
    assert len(_messages_for(db_session, conv_a.id)) == 1
    assert len(_messages_for(db_session, conv_b.id)) == 1
    assert len(_audit_events_for(db_session, "llm.conversation_update_hook")) == 2


def test_changed_count_zero_block_e_limit_reflected_in_text(db_session: Any) -> None:
    srv = _make_server(db_session)
    conv = _make_conv(db_session, srv.id)
    db_session.commit()

    notify_conversations_for_scan(
        db_session, srv.id, new_count=4, resolved_count=2, changed_count=0
    )
    db_session.commit()

    msgs = _messages_for(db_session, conv.id)
    assert len(msgs) == 1
    text = msgs[0].content
    # Block-E-Limit: 0 veraendert ist im Text reflektiert.
    assert "0" in text


def test_zero_deltas_is_noop(db_session: Any) -> None:
    """new=0, resolved=0, changed=0 sollte gar nichts tun."""
    srv = _make_server(db_session)
    conv = _make_conv(db_session, srv.id)
    db_session.commit()

    n = notify_conversations_for_scan(
        db_session, srv.id, new_count=0, resolved_count=0, changed_count=0
    )
    db_session.commit()

    assert n == 0
    assert _messages_for(db_session, conv.id) == []


def test_other_servers_active_conversations_are_not_affected(db_session: Any) -> None:
    """Ein Update fuer Server A darf keine Messages an Conversations fuer Server B haengen."""
    srv_a = _make_server(db_session, name="srv-a")
    srv_b = _make_server(db_session, name="srv-b")
    conv_b = _make_conv(db_session, srv_b.id)
    db_session.commit()

    n = notify_conversations_for_scan(db_session, srv_a.id, new_count=3, resolved_count=1)
    db_session.commit()

    assert n == 0
    assert _messages_for(db_session, conv_b.id) == []
