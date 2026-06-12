# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Block AE (ADR-0055) — Pure-Unit-Modell-Tests fuer den Group-Chat.

Verifiziert die ORM-Konfiguration ohne DB-Verbindung: Enum-DB-Werte
(lowercase-Strings), Relationship-Cascade (`delete-orphan`), `order_by` der
Messages und `__all__`-Praesenz aller drei Symbole.

Die DB-Semantik (UNIQUE-Constraint, CASCADE-Delete, Alembic-Roundtrip) steht
als db_integration beim User an — hier wird ausschliesslich die ORM-Metadata
introspektiert.
"""

from __future__ import annotations

import app.models as models
from app.models import (
    CHAT_MESSAGE_ROLE_ENUM_NAME,
    ChatMessageRole,
    GroupChatConversation,
    GroupChatMessage,
)


def test_chat_message_role_db_values_are_lowercase() -> None:
    """Der DB-Wert ist der lowercase-String, nicht der Enum-Name."""
    assert ChatMessageRole.SYSTEM.value == "system"
    assert ChatMessageRole.USER.value == "user"
    assert ChatMessageRole.ASSISTANT.value == "assistant"
    assert {m.value for m in ChatMessageRole} == {"system", "user", "assistant"}


def test_chat_message_role_enum_name_constant() -> None:
    assert CHAT_MESSAGE_ROLE_ENUM_NAME == "chat_message_role"


def test_role_column_uses_native_enum_with_value_callable() -> None:
    """Die `role`-Spalte nutzt den nativen Postgres-Enum mit lowercase-Werten."""
    role_col = GroupChatMessage.__table__.c.role
    enum_type = role_col.type
    assert enum_type.name == "chat_message_role"  # type: ignore[attr-defined]
    assert enum_type.native_enum is True  # type: ignore[attr-defined]
    # values_callable rendert die lowercase-Werte, nicht die Enum-Namen — der
    # native Postgres-Enum bekommt die DB-Strings, nicht SYSTEM/USER/ASSISTANT.
    assert list(enum_type.enums) == ["system", "user", "assistant"]  # type: ignore[attr-defined]


def test_messages_relationship_cascade_is_delete_orphan() -> None:
    rel = GroupChatConversation.__mapper__.relationships["messages"]
    assert rel.cascade.delete_orphan is True
    assert rel.cascade.delete is True
    # passive_deletes laesst die DB-seitige CASCADE die Arbeit machen.
    assert rel.passive_deletes is True


def test_messages_relationship_order_by_created_at_then_id() -> None:
    rel = GroupChatConversation.__mapper__.relationships["messages"]
    order_cols = [str(expr) for expr in rel.order_by]
    assert order_cols == [
        "group_chat_messages.created_at",
        "group_chat_messages.id",
    ]


def test_conversation_unique_constraint_on_server_and_group() -> None:
    """Genau eine Konversation pro (server_id, application_group_id)."""
    from sqlalchemy import UniqueConstraint

    uniques = [
        c for c in GroupChatConversation.__table__.constraints if isinstance(c, UniqueConstraint)
    ]
    cols = {tuple(col.name for col in uc.columns) for uc in uniques}
    assert ("server_id", "application_group_id") in cols


def test_conversation_fk_columns_and_ondelete() -> None:
    """server_id Integer, application_group_id BigInteger, beide ON DELETE CASCADE."""
    table = GroupChatConversation.__table__
    server_fk = next(iter(table.c.server_id.foreign_keys))
    group_fk = next(iter(table.c.application_group_id.foreign_keys))
    assert server_fk.column.table.name == "servers"
    assert server_fk.ondelete == "CASCADE"
    assert group_fk.column.table.name == "application_groups"
    assert group_fk.ondelete == "CASCADE"
    # application_group_id muss BigInteger sein (PK von application_groups ist
    # BigInteger) — ein Integer-FK wuerde den PK-Typ verfehlen.
    assert table.c.application_group_id.type.__class__.__name__ == "BigInteger"


def test_message_conversation_fk_ondelete_cascade() -> None:
    fk = next(iter(GroupChatMessage.__table__.c.conversation_id.foreign_keys))
    assert fk.column.table.name == "group_chat_conversations"
    assert fk.ondelete == "CASCADE"


def test_message_lookup_index_present() -> None:
    idx = {i.name: [c.name for c in i.columns] for i in GroupChatMessage.__table__.indexes}
    assert "ix_group_chat_messages_conversation" in idx
    assert idx["ix_group_chat_messages_conversation"] == [
        "conversation_id",
        "created_at",
        "id",
    ]


def test_nullable_token_columns() -> None:
    table = GroupChatMessage.__table__
    assert table.c.prompt_tokens.nullable is True
    assert table.c.completion_tokens.nullable is True
    assert table.c.content.nullable is False


def test_all_symbols_exported() -> None:
    for name in ("ChatMessageRole", "GroupChatConversation", "GroupChatMessage"):
        assert name in models.__all__
