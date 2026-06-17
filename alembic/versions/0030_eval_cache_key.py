"""eval_cache_key — TICKET-017 / ADR-0068 Gate 1.

Adds a nullable ``cache_key VARCHAR(64)`` column to
``application_group_evaluations``. The enqueue gate
(``pass2_enqueue.enqueue_pass2_for_server``) compares this full
``make_cache_key`` against the stored row instead of only
``group_findings_fingerprint``, so a change to any reviewer-load-bearing
host/CVE input (running kernel, ``host_update_available``,
installed/fixed version) re-enqueues evaluation.

Existing rows get ``cache_key = NULL``; the gate treats NULL as a mismatch
and re-enqueues every group once after deploy (self-heal, ADR-0068).

Upgrade: ``ADD COLUMN cache_key VARCHAR(64) NULL`` (no rewrite).

Downgrade: ``DROP COLUMN cache_key`` (documented, accepted data loss of the
persisted cache key; the column is purely a gate optimization and is
recomputed on the next enqueue/worker run).

Revision ID: 0030_eval_cache_key
Revises: 0029_widen_reason_text
Create Date: 2026-06-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0030_eval_cache_key"
down_revision: str | None = "0029_widen_reason_text"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "application_group_evaluations",
        sa.Column("cache_key", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("application_group_evaluations", "cache_key")
