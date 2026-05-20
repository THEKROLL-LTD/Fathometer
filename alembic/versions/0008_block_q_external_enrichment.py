"""block_q_external_enrichment — ADR-0024 §"Neue DB-Tabellen".

Phase 1 von Block Q (External EPSS/KEV Enrichment). Legt die drei
Server-Side-Feed-Tabellen an, in die der neue ``feed_enrichment``-
Worker-Sub-Tick die taeglichen EPSS- und CISA-KEV-Pulls persistiert:

1. ``epss_scores`` — PK ``cve_id``, ``epss_score``+``epss_percentile``
   (beide [0.0, 1.0] per Check-Constraint), ``updated_at``.
2. ``cisa_kev_catalog`` — PK ``cve_id``, Vendor-/Produkt-/Aktions-
   Felder, ``date_added`` (NOT NULL), ``due_date`` (nullable),
   ``known_ransomware`` (NOT NULL DEFAULT FALSE).
3. ``feed_pull_log`` — BIGSERIAL-PK, Audit pro Pull mit Status-
   Whitelist (``epss``/``cisa_kev``) und Index auf (feed_name,
   started_at DESC) fuer den "letzter Pull pro Feed"-Lookup.

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-21
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ---- epss_scores -----------------------------------------------------
    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.String(32), primary_key=True, nullable=False),
        sa.Column("epss_score", sa.Float(), nullable=False),
        sa.Column("epss_percentile", sa.Float(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "epss_score >= 0.0 AND epss_score <= 1.0 "
            "AND epss_percentile >= 0.0 AND epss_percentile <= 1.0",
            name="ck_epss_scores_range",
        ),
    )

    # ---- cisa_kev_catalog ------------------------------------------------
    op.create_table(
        "cisa_kev_catalog",
        sa.Column("cve_id", sa.String(32), primary_key=True, nullable=False),
        sa.Column("vendor_project", sa.String(256), nullable=True),
        sa.Column("product", sa.String(256), nullable=True),
        sa.Column("vulnerability_name", sa.String(512), nullable=True),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("short_description", sa.Text(), nullable=True),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column(
            "known_ransomware",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ---- feed_pull_log ---------------------------------------------------
    op.create_table(
        "feed_pull_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, nullable=False),
        sa.Column("feed_name", sa.String(32), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("row_count", sa.Integer(), nullable=True),
        sa.Column("bytes_downloaded", sa.BigInteger(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "feed_name IN ('epss', 'cisa_kev')",
            name="ck_feed_pull_log_name",
        ),
    )
    op.create_index(
        "ix_feed_pull_log_feed_started",
        "feed_pull_log",
        ["feed_name", sa.text("started_at DESC")],
    )


def downgrade() -> None:
    # Reverse-Reihenfolge zum upgrade().
    op.drop_index("ix_feed_pull_log_feed_started", table_name="feed_pull_log")
    op.drop_table("feed_pull_log")
    op.drop_table("cisa_kev_catalog")
    op.drop_table("epss_scores")
