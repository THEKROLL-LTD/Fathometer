"""block_p_v093 — ADR-0023 §"Update v0.9.3".

Konsolidierte Migration fuer den v0.9.3-Patch auf Block P:

1. ``application_groups`` bekommt ``action_type`` (varchar 16, nullable) und
   ``group_kind`` (varchar 20, nullable) plus zwei CheckConstraints.
2. Backfill: ``group_kind`` wird deterministisch aus den vorhandenen
   ``match_rules`` (``path_prefixes`` non-empty? → ``application_bundle``;
   sonst ``os_package``) gesetzt.
3. ``llm_risk_cache`` bekommt ``action_type`` (varchar 16, nullable) plus
   CheckConstraint.
4. Neue Tabelle ``llm_debug_log`` (id, job_type, job_id, server_id,
   group_id, model, request_body, response_body, duration_ms, status,
   error, created_at) mit drei Indizes und einer Status-Whitelist.

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-20
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ---- application_groups: action_type + group_kind --------------------
    op.add_column(
        "application_groups",
        sa.Column("action_type", sa.String(16), nullable=True),
    )
    op.add_column(
        "application_groups",
        sa.Column("group_kind", sa.String(20), nullable=True),
    )
    op.create_check_constraint(
        "ck_application_groups_action_type",
        "application_groups",
        "action_type IS NULL OR action_type IN "
        "('patch','mitigate','watch','none','investigate')",
    )
    op.create_check_constraint(
        "ck_application_groups_group_kind",
        "application_groups",
        "group_kind IS NULL OR group_kind IN ('application_bundle','os_package')",
    )

    # ---- Backfill group_kind ---------------------------------------------
    op.execute(
        text(
            """
            UPDATE application_groups
            SET group_kind = CASE
                WHEN array_length(path_prefixes, 1) > 0 THEN 'application_bundle'
                ELSE 'os_package'
            END
            WHERE group_kind IS NULL
            """
        )
    )

    # ---- llm_risk_cache: action_type -------------------------------------
    op.add_column(
        "llm_risk_cache",
        sa.Column("action_type", sa.String(16), nullable=True),
    )
    op.create_check_constraint(
        "ck_llm_risk_cache_action_type",
        "llm_risk_cache",
        "action_type IS NULL OR action_type IN ('patch','mitigate','watch','none')",
    )

    # ---- llm_debug_log (neue Tabelle) ------------------------------------
    op.create_table(
        "llm_debug_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, nullable=False),
        sa.Column("job_type", sa.String(32), nullable=False),
        sa.Column(
            "job_id",
            sa.BigInteger(),
            sa.ForeignKey("llm_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "group_id",
            sa.BigInteger(),
            sa.ForeignKey("application_groups.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("model", sa.String(64), nullable=False),
        sa.Column("request_body", postgresql.JSONB(), nullable=False),
        sa.Column("response_body", postgresql.JSONB(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('success','failed','timeout','validation_error')",
            name="ck_llm_debug_log_status",
        ),
    )
    op.create_index(
        "ix_llm_debug_log_created", "llm_debug_log", ["created_at"]
    )
    op.create_index(
        "ix_llm_debug_log_job_type", "llm_debug_log", ["job_type", "created_at"]
    )
    op.create_index(
        "ix_llm_debug_log_group",
        "llm_debug_log",
        ["group_id"],
        postgresql_where=sa.text("group_id IS NOT NULL"),
    )


def downgrade() -> None:
    # llm_debug_log first (no other deps).
    op.drop_index("ix_llm_debug_log_group", table_name="llm_debug_log")
    op.drop_index("ix_llm_debug_log_job_type", table_name="llm_debug_log")
    op.drop_index("ix_llm_debug_log_created", table_name="llm_debug_log")
    op.drop_table("llm_debug_log")

    # llm_risk_cache action_type.
    op.drop_constraint(
        "ck_llm_risk_cache_action_type", "llm_risk_cache", type_="check"
    )
    op.drop_column("llm_risk_cache", "action_type")

    # application_groups action_type + group_kind.
    op.drop_constraint(
        "ck_application_groups_group_kind", "application_groups", type_="check"
    )
    op.drop_constraint(
        "ck_application_groups_action_type", "application_groups", type_="check"
    )
    op.drop_column("application_groups", "group_kind")
    op.drop_column("application_groups", "action_type")
