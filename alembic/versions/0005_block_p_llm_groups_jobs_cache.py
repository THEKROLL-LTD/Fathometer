"""block_p_llm_groups_jobs_cache — ADR-0023.

Drei neue Tabellen plus FK + Index auf bestehende `findings`-Tabelle plus
drei neue Spalten auf der Singleton-`settings`-Zeile.

Neue Tabellen:

- `application_groups` — Owner-Application-Group mit Match-Patterns
  (ARRAY-Spalten) und Bewertung (risk_band & co.). UNIQUE auf `label`.
- `llm_jobs` — asynchrone Job-Queue, drei Indizes (Pickup-, Stale-,
  Server-Partial-Indizes). Self-FK `depends_on -> llm_jobs.id`.
- `llm_risk_cache` — Pass-2-Result-Cache mit SHA256-PK (64 chars). FK
  auf `application_groups.id ON DELETE CASCADE`.

Neue Spalte auf `findings`:

- `application_group_id` — FK auf `application_groups.id ON DELETE SET
  NULL`. Plus Index `ix_findings_application_group` fuer Drill-down.

Neue Spalten auf `settings` (Singleton):

- `block_p_llm_mode` (default `'off'`, CheckConstraint).
- `llm_worker_heartbeat_at` (nullable).
- `llm_token_budget_used_today` (BigInteger, default `0`,
  CheckConstraint `>= 0`).

Kein Backfill — die `application_group_id`-Spalte bleibt initial NULL fuer
alle bestehenden Findings; Pass 1 fuellt das spaeter.

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-18
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ---- application_groups -------------------------------------------------
    op.create_table(
        "application_groups",
        sa.Column("id", sa.BigInteger(), primary_key=True, nullable=False),
        sa.Column("label", sa.String(64), nullable=False, unique=True),
        sa.Column("explanation", sa.String(512), nullable=True),
        sa.Column(
            "path_prefixes",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("ARRAY[]::text[]"),
        ),
        sa.Column(
            "pkg_name_exact",
            postgresql.ARRAY(sa.String(256)),
            nullable=False,
            server_default=sa.text("ARRAY[]::varchar[]"),
        ),
        sa.Column(
            "pkg_name_glob",
            postgresql.ARRAY(sa.String(256)),
            nullable=False,
            server_default=sa.text("ARRAY[]::varchar[]"),
        ),
        sa.Column(
            "pkg_purl_pattern",
            postgresql.ARRAY(sa.String(512)),
            nullable=False,
            server_default=sa.text("ARRAY[]::varchar[]"),
        ),
        sa.Column("risk_band", sa.String(16), nullable=True),
        sa.Column("risk_band_reason", sa.String(256), nullable=True),
        sa.Column("risk_band_source", sa.String(16), nullable=True),
        sa.Column("risk_band_computed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("worst_finding_id", sa.BigInteger(), nullable=True),
        sa.Column("group_findings_fingerprint", sa.String(16), nullable=True),
        sa.Column(
            "source",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'llm'"),
        ),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "risk_band IS NULL OR risk_band IN "
            "('escalate','act','mitigate','monitor','noise')",
            name="ck_application_groups_band",
        ),
        sa.CheckConstraint(
            "source IN ('llm','manual')",
            name="ck_application_groups_source",
        ),
    )

    # ---- llm_jobs -----------------------------------------------------------
    op.create_table(
        "llm_jobs",
        sa.Column("id", sa.BigInteger(), primary_key=True, nullable=False),
        sa.Column("job_type", sa.String(32), nullable=False),
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column(
            "depends_on",
            sa.BigInteger(),
            sa.ForeignKey("llm_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'queued'"),
        ),
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("picked_up_by", sa.String(128), nullable=True),
        sa.Column("picked_up_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "job_type IN ('group_detection','risk_evaluation')",
            name="ck_llm_jobs_type",
        ),
        sa.CheckConstraint(
            "status IN ('queued','in_progress','done','failed')",
            name="ck_llm_jobs_status",
        ),
        sa.CheckConstraint("attempts >= 0", name="ck_llm_jobs_attempts"),
    )
    op.create_index(
        "ix_llm_jobs_pickup",
        "llm_jobs",
        ["status", "next_attempt_at"],
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.create_index(
        "ix_llm_jobs_stale",
        "llm_jobs",
        ["status", "picked_up_at"],
        postgresql_where=sa.text("status = 'in_progress'"),
    )
    op.create_index(
        "ix_llm_jobs_server",
        "llm_jobs",
        ["server_id", "status"],
    )

    # ---- llm_risk_cache -----------------------------------------------------
    op.create_table(
        "llm_risk_cache",
        sa.Column("cache_key", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "group_id",
            sa.BigInteger(),
            sa.ForeignKey("application_groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("group_findings_fp", sa.String(16), nullable=False),
        sa.Column("cve_data_fp", sa.String(16), nullable=False),
        sa.Column("server_context_fp", sa.String(16), nullable=False),
        sa.Column("risk_band", sa.String(16), nullable=False),
        sa.Column("worst_finding_id", sa.BigInteger(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("llm_model", sa.String(64), nullable=True),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "used_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "last_used_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "risk_band IN ('escalate','act','mitigate','monitor','noise')",
            name="ck_llm_risk_cache_band",
        ),
    )
    op.create_index("ix_llm_risk_cache_lru", "llm_risk_cache", ["last_used_at"])
    op.create_index("ix_llm_risk_cache_group", "llm_risk_cache", ["group_id"])

    # ---- findings.application_group_id --------------------------------------
    op.add_column(
        "findings",
        sa.Column("application_group_id", sa.BigInteger(), nullable=True),
    )
    op.create_foreign_key(
        "fk_findings_application_group_id",
        "findings",
        "application_groups",
        ["application_group_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_findings_application_group",
        "findings",
        ["application_group_id"],
    )

    # ---- settings: Block-P-Felder ------------------------------------------
    # Drei neue Spalten auf der Singleton-Row. `server_default` ist
    # noetig damit bestehende Zeilen (id=1) sofort einen gueltigen Wert
    # bekommen — wir setzen NOT NULL fuer Mode und Token-Budget.
    op.add_column(
        "settings",
        sa.Column(
            "block_p_llm_mode",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'off'"),
        ),
    )
    op.add_column(
        "settings",
        sa.Column(
            "llm_worker_heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "settings",
        sa.Column(
            "llm_token_budget_used_today",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.create_check_constraint(
        "ck_settings_block_p_llm_mode",
        "settings",
        "block_p_llm_mode IN ('off', 'observation', 'live')",
    )
    op.create_check_constraint(
        "ck_settings_llm_token_budget_used_today_nonneg",
        "settings",
        "llm_token_budget_used_today >= 0",
    )


def downgrade() -> None:
    # ---- settings: Block-P-Felder zurueck -----------------------------------
    op.drop_constraint(
        "ck_settings_llm_token_budget_used_today_nonneg",
        "settings",
        type_="check",
    )
    op.drop_constraint(
        "ck_settings_block_p_llm_mode",
        "settings",
        type_="check",
    )
    op.drop_column("settings", "llm_token_budget_used_today")
    op.drop_column("settings", "llm_worker_heartbeat_at")
    op.drop_column("settings", "block_p_llm_mode")

    # ---- findings.application_group_id zurueck -----------------------------
    # Reihenfolge: Index, FK, Spalte. Vorher die FK, sonst meckert Postgres
    # ueber den abhaengigen Constraint.
    op.drop_index("ix_findings_application_group", table_name="findings")
    op.drop_constraint(
        "fk_findings_application_group_id",
        "findings",
        type_="foreignkey",
    )
    op.drop_column("findings", "application_group_id")

    # ---- llm_risk_cache zurueck (FK auf application_groups) ----------------
    op.drop_index("ix_llm_risk_cache_group", table_name="llm_risk_cache")
    op.drop_index("ix_llm_risk_cache_lru", table_name="llm_risk_cache")
    op.drop_table("llm_risk_cache")

    # ---- llm_jobs zurueck ---------------------------------------------------
    op.drop_index("ix_llm_jobs_server", table_name="llm_jobs")
    op.drop_index("ix_llm_jobs_stale", table_name="llm_jobs")
    op.drop_index("ix_llm_jobs_pickup", table_name="llm_jobs")
    op.drop_table("llm_jobs")

    # ---- application_groups zurueck ----------------------------------------
    op.drop_table("application_groups")
