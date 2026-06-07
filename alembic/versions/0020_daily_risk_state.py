"""daily_risk_state - ADR-0035-Addendum: materialisierter Tages-Heartbeat.

Neue Tabelle `daily_risk_state` (PK `(server_id, day)`, Index auf `day`) fuer
den TD-013-Vollausbau "Vergangenheit einfrieren, heute live" (ADR-0035-
Addendum 2026-06-07).

Die Tabelle haelt pro `(server_id, day)` das eingefrorene Tages-Aggregat der
am Tagesende praesenten Findings (`dominant_risk_band`, `max_severity`,
`kev_count`, `had_scan`). Vergangene Tage sind unveraenderlich — ein
Worker-Sub-Tick (`finalize_pending_days`) finalisiert per Anti-Join-UPSERT
alle fehlenden Paare im Fenster `[today-30, gestern]`. Der heutige Tag wird im
Read-Path live aggregiert und NICHT hier persistiert.

`max_severity`/`dominant_risk_band` sind bewusst lockere Strings (kein
nativer PG-Enum) — die Tabelle ist ein Visual-Snapshot, keine Audit-Quelle.

Migration-Strategie:
- Tabelle ist nach der Migration leer; der erste Worker-Finalize-Lauf
  (= Deploy-Backfill) fuellt die 29 frozen Cells pro Server.
- ON DELETE CASCADE: Server loeschen entfernt die zugehoerigen Snapshots.

Downgrade: erst Index droppen, dann Tabelle.

Revision ID: 0020_daily_risk_state
Revises: 0019_triage_idx_include_id
Create Date: 2026-06-07
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0020_daily_risk_state"
down_revision: str | None = "0019_triage_idx_include_id"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "daily_risk_state",
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("dominant_risk_band", sa.String(16), nullable=True),
        sa.Column("max_severity", sa.String(16), nullable=True),
        sa.Column("kev_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "had_scan",
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
        sa.PrimaryKeyConstraint("server_id", "day"),
    )
    op.create_index("ix_daily_risk_state_day", "daily_risk_state", ["day"])


def downgrade() -> None:
    op.drop_index("ix_daily_risk_state_day", "daily_risk_state")
    op.drop_table("daily_risk_state")
