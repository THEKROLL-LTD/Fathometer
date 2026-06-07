"""remove_llm_chat - Server-weites AI-Assessment-Chat-Feature entfernen (ADR-0048).

ADR-0048: Das interaktive "Request AI assessment"-Chat-Feature auf der
Server-Detail-Seite wird ersatzlos entfernt (UI/Prompts/Routes/Services/Tests).
Diese Migration droppt die drei Chat-Tabellen und die zwei zugehoerigen
Postgres-Enums, die in `0002_initial_schema` angelegt wurden:

* ``llm_conversation_findings`` (Bridge: Conversation x Finding-Snapshot)
* ``llm_messages`` (Chat-Verlauf)
* ``llm_conversations`` (Conversation-Kopf)
* Enum ``llm_message_role`` (``system``/``user``/``assistant``)
* Enum ``llm_conversation_status`` (``active``/``archived``)

Die geteilte LLM-Provider-Config (`settings.llm_base_url`/`llm_model`/
`llm_api_key_encrypted`/`llm_daily_token_cap`/`llm_provider_name`) bleibt
unangetastet — sie wird weiterhin vom LLM-Risk-Reviewer (Block P) genutzt.

`downgrade()` rekonstruiert Tabellen und Enums byte-getreu aus der
`0002`-DDL (leer, kein Daten-Restore — die Conversation-Daten sind beim
Upgrade verloren).

Revision ID: 0017_remove_llm_chat
Revises: 0016_block_aa_add_primary_url
Create Date: 2026-06-07
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0017_remove_llm_chat"
down_revision: str | None = "0016_block_aa_add_primary_url"
branch_labels: str | None = None
depends_on: str | None = None

# Enums — exakt wie in 0002 benannt. ``create_type=False`` haelt das ORM
# vom Auto-Create/-Drop ab; create()/drop() werden hier explizit gesteuert.
_LLM_CONV_STATUS = postgresql.ENUM(
    "active", "archived", name="llm_conversation_status", create_type=False
)
_LLM_MSG_ROLE = postgresql.ENUM(
    "system", "user", "assistant", name="llm_message_role", create_type=False
)
# Bereits existierender ``severity``-Enum (in 0002 erzeugt, NICHT hier gedroppt)
# — nur fuer den Bridge-Table-Recreate im downgrade() referenziert.
_SEVERITY = postgresql.ENUM(name="severity", create_type=False)


def upgrade() -> None:
    bind = op.get_bind()

    # Tabellen child -> parent droppen (FK-Reihenfolge).
    op.drop_table("llm_conversation_findings")
    op.drop_table("llm_messages")
    op.drop_table("llm_conversations")

    # Chat-exklusive Enums droppen.
    for enum_type in (_LLM_MSG_ROLE, _LLM_CONV_STATUS):
        enum_type.drop(bind, checkfirst=False)


def downgrade() -> None:
    bind = op.get_bind()

    # Enums wiederherstellen.
    for enum_type in (_LLM_CONV_STATUS, _LLM_MSG_ROLE):
        enum_type.create(bind, checkfirst=False)

    # llm_conversations (parent zuerst).
    op.create_table(
        "llm_conversations",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "started_at",
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
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column(
            "status",
            _LLM_CONV_STATUS,
            nullable=False,
            server_default=sa.text("'active'::llm_conversation_status"),
        ),
        sa.Column("findings_snapshot_at", sa.DateTime(timezone=True), nullable=False),
    )

    # llm_messages.
    op.create_table(
        "llm_messages",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "conversation_id",
            sa.BigInteger(),
            sa.ForeignKey("llm_conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", _LLM_MSG_ROLE, nullable=False),
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

    # llm_conversation_findings (Bridge).
    op.create_table(
        "llm_conversation_findings",
        sa.Column(
            "conversation_id",
            sa.BigInteger(),
            sa.ForeignKey("llm_conversations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "finding_id",
            sa.BigInteger(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("severity_at_send", _SEVERITY, nullable=False),
        sa.Column("cvss_v3_score_at_send", sa.Float()),
        sa.Column("epss_score_at_send", sa.Float()),
        sa.Column("is_kev_at_send", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
