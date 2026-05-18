"""block_p_token_reset_at — ergaenze `settings.llm_token_budget_reset_at`.

Phase A der Block-P-Implementierung hat die Token-Budget-Felder
(`llm_token_budget_used_today`, `llm_worker_heartbeat_at`,
`block_p_llm_mode`) angelegt, aber NICHT den Reset-Zeitpunkt — er kam
erst in Phase C (Worker + Budget) hinzu. Diese Mini-Migration ergaenzt
die fehlende Spalte mit `server_default = now()`, sodass bestehende
Singleton-Rows sofort einen verarbeitbaren Wert bekommen (Worker
faellt beim ersten Tick in `maybe_reset_budget` und setzt das Feld auf
morgen 00:00 UTC).

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-18
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "settings",
        sa.Column(
            "llm_token_budget_reset_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_column("settings", "llm_token_budget_reset_at")
