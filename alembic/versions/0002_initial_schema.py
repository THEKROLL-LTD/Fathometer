"""initial_schema — alle Tabellen, Enums, Indizes und Generated-Columns aus
ARCHITECTURE.md §5.

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-14
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None


# Enum-Definitionen — als Modul-Variablen, damit upgrade und downgrade sie
# konsistent referenzieren.
_SEVERITY = postgresql.ENUM(
    "critical", "high", "medium", "low", "unknown", name="severity", create_type=False
)
_FINDING_TYPE = postgresql.ENUM(
    "vulnerability", "secret", "misconfig", name="finding_type", create_type=False
)
_FINDING_CLASS = postgresql.ENUM(
    "os-pkgs", "lang-pkgs", "other", name="finding_class", create_type=False
)
_FINDING_STATUS = postgresql.ENUM(
    "open", "acknowledged", "resolved", name="finding_status", create_type=False
)
_ATTACK_VECTOR = postgresql.ENUM(
    "network",
    "adjacent",
    "local",
    "physical",
    "unknown",
    name="attack_vector",
    create_type=False,
)
_LLM_CONV_STATUS = postgresql.ENUM(
    "active", "archived", name="llm_conversation_status", create_type=False
)
_LLM_MSG_ROLE = postgresql.ENUM(
    "system", "user", "assistant", name="llm_message_role", create_type=False
)


def upgrade() -> None:
    bind = op.get_bind()

    # 1) Enums erzeugen.
    for enum_type in (
        _SEVERITY,
        _FINDING_TYPE,
        _FINDING_CLASS,
        _FINDING_STATUS,
        _ATTACK_VECTOR,
        _LLM_CONV_STATUS,
        _LLM_MSG_ROLE,
    ):
        enum_type.create(bind, checkfirst=False)

    # 2) users.
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # 3) servers.
    op.create_table(
        "servers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("api_key_hash", sa.String(128), nullable=False),
        sa.Column(
            "expected_scan_interval_h", sa.Integer(), nullable=False, server_default="24"
        ),
        sa.Column("last_scan_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.Column("os_family", sa.String(32)),
        sa.Column("os_version", sa.String(64)),
        sa.Column("os_pretty_name", sa.String(256)),
        sa.Column("kernel_version", sa.String(128)),
        sa.Column("architecture", sa.String(16)),
        sa.Column("agent_version", sa.String(32)),
        sa.Column("trivy_db_version", sa.String(64)),
        sa.Column("trivy_db_updated_at", sa.DateTime(timezone=True)),
    )

    # 4) scans.
    op.create_table(
        "scans",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("agent_version", sa.String(32)),
        sa.Column("trivy_scanner_version", sa.String(32)),
        sa.Column("trivy_db_version", sa.String(64)),
        sa.Column("trivy_db_updated_at", sa.DateTime(timezone=True)),
        sa.Column("os_family", sa.String(32)),
        sa.Column("os_version", sa.String(64)),
        sa.Column("os_pretty_name", sa.String(256)),
        sa.Column("kernel_version", sa.String(128)),
        sa.Column("architecture", sa.String(16)),
    )

    # 5) tags + server_tags.
    op.create_table(
        "tags",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(32), nullable=False, unique=True),
        sa.Column("color", sa.String(7), nullable=False, server_default="#6b7280"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_table(
        "server_tags",
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "tag_id",
            sa.Integer(),
            sa.ForeignKey("tags.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    # 6) findings — inkl. Generated-Column `has_fix`.
    op.create_table(
        "findings",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("finding_type", _FINDING_TYPE, nullable=False),
        sa.Column("finding_class", _FINDING_CLASS, nullable=False),
        sa.Column("identifier_key", sa.String(128), nullable=False),
        sa.Column("package_name", sa.String(256), nullable=False),
        sa.Column("installed_version", sa.String(256)),
        sa.Column("fixed_version", sa.String(256)),
        sa.Column("severity", _SEVERITY, nullable=False),
        sa.Column("title", sa.String(512)),
        sa.Column("description", sa.Text()),
        sa.Column("cvss_v3_score", sa.Float()),
        sa.Column("cvss_v3_vector", sa.String(256)),
        sa.Column("epss_score", sa.Float()),
        sa.Column("epss_percentile", sa.Float()),
        sa.Column("is_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_added_at", sa.DateTime(timezone=True)),
        sa.Column("cwe_ids", sa.ARRAY(sa.String(16))),
        sa.Column(
            "attack_vector",
            _ATTACK_VECTOR,
            nullable=False,
            server_default=sa.text("'unknown'::attack_vector"),
        ),
        sa.Column("references", sa.ARRAY(sa.Text())),
        sa.Column(
            "has_fix",
            sa.Boolean(),
            sa.Computed("fixed_version IS NOT NULL AND fixed_version <> ''", persisted=True),
            nullable=False,
        ),
        sa.Column(
            "status",
            _FINDING_STATUS,
            nullable=False,
            server_default=sa.text("'open'::finding_status"),
        ),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column(
            "acknowledged_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "server_id",
            "finding_type",
            "identifier_key",
            "package_name",
            name="uq_findings_natural_key",
        ),
        sa.CheckConstraint(
            "cvss_v3_score IS NULL OR (cvss_v3_score >= 0.0 AND cvss_v3_score <= 10.0)",
            name="ck_findings_cvss_range",
        ),
        sa.CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0.0 AND epss_score <= 1.0)",
            name="ck_findings_epss_range",
        ),
        sa.CheckConstraint(
            "epss_percentile IS NULL OR (epss_percentile >= 0.0 AND epss_percentile <= 1.0)",
            name="ck_findings_epss_percentile_range",
        ),
    )

    op.create_index(
        "ix_findings_server_status", "findings", ["server_id", "status"]
    )
    op.create_index("ix_findings_identifier_key", "findings", ["identifier_key"])
    op.create_index(
        "ix_findings_kev_open",
        "findings",
        ["is_kev"],
        postgresql_where=sa.text("is_kev = true"),
    )
    op.create_index(
        "ix_findings_epss_open",
        "findings",
        [sa.text("epss_score DESC NULLS LAST")],
        postgresql_where=sa.text("status = 'open'"),
    )
    op.create_index(
        "ix_findings_package_open",
        "findings",
        ["package_name", "server_id"],
        postgresql_where=sa.text("status = 'open'"),
    )

    # 7) finding_notes.
    op.create_table(
        "finding_notes",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.BigInteger(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("author", sa.String(64), nullable=False),
        sa.Column(
            "author_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
    )

    # 8) llm_conversations.
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

    # 9) llm_messages.
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

    # 10) llm_conversation_findings (Bridge).
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
        sa.Column(
            "is_kev_at_send", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )

    # 11) audit_events.
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.String(128)),
        sa.Column("comment", sa.Text()),
        sa.Column("metadata", postgresql.JSONB()),
    )
    op.create_index(
        "ix_audit_events_ts_desc", "audit_events", [sa.text("ts DESC")]
    )

    # 12) settings — Singleton via Check-Constraint id=1.
    op.create_table(
        "settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "severity_threshold",
            _SEVERITY,
            nullable=False,
            server_default=sa.text("'high'::severity"),
        ),
        sa.Column(
            "stale_threshold_h", sa.Integer(), nullable=False, server_default="48"
        ),
        sa.Column(
            "stale_trivy_db_threshold_h",
            sa.Integer(),
            nullable=False,
            server_default="30",
        ),
        sa.Column(
            "default_theme",
            sa.String(8),
            nullable=False,
            server_default="auto",
        ),
        sa.Column("master_key_hash", sa.String(255)),
        sa.Column("llm_provider_name", sa.String(64)),
        sa.Column("llm_base_url", sa.String(256)),
        sa.Column("llm_api_key_encrypted", sa.LargeBinary()),
        sa.Column("llm_model", sa.String(128)),
        sa.Column(
            "llm_daily_token_cap",
            sa.Integer(),
            nullable=False,
            server_default="1000000",
        ),
        sa.Column("setup_completed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("id = 1", name="ck_settings_singleton"),
        sa.CheckConstraint(
            "default_theme IN ('light', 'dark', 'auto')", name="ck_settings_theme"
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()

    op.drop_table("settings")

    op.drop_index("ix_audit_events_ts_desc", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_table("llm_conversation_findings")
    op.drop_table("llm_messages")
    op.drop_table("llm_conversations")

    op.drop_table("finding_notes")

    op.drop_index("ix_findings_package_open", table_name="findings")
    op.drop_index("ix_findings_epss_open", table_name="findings")
    op.drop_index("ix_findings_kev_open", table_name="findings")
    op.drop_index("ix_findings_identifier_key", table_name="findings")
    op.drop_index("ix_findings_server_status", table_name="findings")
    op.drop_table("findings")

    op.drop_table("server_tags")
    op.drop_table("tags")

    op.drop_table("scans")
    op.drop_table("servers")
    op.drop_table("users")

    for enum_type in (
        _LLM_MSG_ROLE,
        _LLM_CONV_STATUS,
        _ATTACK_VECTOR,
        _FINDING_STATUS,
        _FINDING_CLASS,
        _FINDING_TYPE,
        _SEVERITY,
    ):
        enum_type.drop(bind, checkfirst=False)
