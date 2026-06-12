# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""block_ae_group_chat — Per-Group AI-Chat-Schema (ADR-0055, Block AE).

ADR-0055 fuehrt einen fokussierten LLM-Chat pro ``(server, application_group)``
wieder ein (kehrt ADR-0050 teilweise um — der server-weite Chat bleibt
verworfen). Diese Migration ist rein **additiv**: zwei neue Tabellen und ein
neuer Enum, kein Eingriff in Bestands-Schema.

Erzeugt:

* Enum ``chat_message_role`` (``system``/``user``/``assistant``).
* ``group_chat_conversations`` — genau eine Konversation pro
  ``(server_id, application_group_id)`` (``UNIQUE``-Constraint). Der eingefrorene
  Findings-Snapshot lebt im persistierten System-Prompt (erste Message);
  ``findings_snapshot_at`` haelt nur den Zeitpunkt fuer Debug/Audit. Kein
  Findings-Bridge-Table (ADR-0055 §Neu).
* ``group_chat_messages`` — Chat-Verlauf, FK CASCADE auf die Konversation,
  Lookup-Index ``(conversation_id, created_at, id)``.

FK-Typen folgen der Repo-Konvention (``ApplicationGroupEvaluation``/
``LLMDebugLog``): ``server_id`` ist ``Integer`` (``servers.id`` ist Integer),
``application_group_id`` ist ``BigInteger`` (``application_groups.id`` ist
BigInteger — ein Integer-FK wuerde den PK-Typ verfehlen).

``downgrade()`` droppt die Tabellen child -> parent und danach den Enum mit
``checkfirst=False`` — exakt das Muster aus ``0017_remove_llm_chat``.

Revision ID: 0023_block_ae_group_chat
Revises: 0022_fix_lane_evaluation
Create Date: 2026-06-11
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0023_block_ae_group_chat"
down_revision: str | None = "0022_fix_lane_evaluation"
branch_labels: str | None = None
depends_on: str | None = None

# Enum — ``create_type=False`` haelt das ORM vom Auto-Create/-Drop ab;
# create()/drop() werden hier explizit gesteuert (Muster aus 0017).
_CHAT_MSG_ROLE = postgresql.ENUM(
    "system", "user", "assistant", name="chat_message_role", create_type=False
)


def upgrade() -> None:
    bind = op.get_bind()

    # Enum zuerst anlegen — die Message-Tabelle referenziert ihn.
    _CHAT_MSG_ROLE.create(bind, checkfirst=False)

    # group_chat_conversations (parent).
    op.create_table(
        "group_chat_conversations",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "application_group_id",
            sa.BigInteger(),
            sa.ForeignKey("application_groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_message_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("findings_snapshot_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "server_id",
            "application_group_id",
            name="uq_group_chat_conversations_server_group",
        ),
    )

    # group_chat_messages (child).
    op.create_table(
        "group_chat_messages",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "conversation_id",
            sa.BigInteger(),
            sa.ForeignKey("group_chat_conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", _CHAT_MSG_ROLE, nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("prompt_tokens", sa.Integer()),
        sa.Column("completion_tokens", sa.Integer()),
    )
    op.create_index(
        "ix_group_chat_messages_conversation",
        "group_chat_messages",
        ["conversation_id", "created_at", "id"],
    )


def downgrade() -> None:
    bind = op.get_bind()

    # Tabellen child -> parent droppen (FK-Reihenfolge). Der Index faellt mit
    # der Tabelle.
    op.drop_index("ix_group_chat_messages_conversation", table_name="group_chat_messages")
    op.drop_table("group_chat_messages")
    op.drop_table("group_chat_conversations")

    # Chat-exklusiven Enum droppen.
    _CHAT_MSG_ROLE.drop(bind, checkfirst=False)
