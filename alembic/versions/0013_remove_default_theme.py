"""remove_default_theme - ADR-0031: Theme-Switcher entfernt.

Das `default_theme`-Feld und der zugehoerige Check-Constraint
`ck_settings_theme` werden aus der Settings-Singleton-Row entfernt.
Das Theme ist ab sofort statisch auf "dark" fixiert (`<html data-theme="dark">`).

Revision ID: 0013_remove_default_theme
Revises: 0012_block_u_worker
Create Date: 2026-05-23
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0013_remove_default_theme"
down_revision: str | None = "0012_block_u_worker"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Erst Constraint entfernen, dann Spalte.
    op.drop_constraint("ck_settings_theme", "settings", type_="check")
    op.drop_column("settings", "default_theme")


def downgrade() -> None:
    # Spalte mit `auto`-Default restaurieren; bestehende Zeilen bekommen
    # den server_default. Daten-Verlust: der zur Upgrade-Zeit gespeicherte
    # Wert ist unwiederbringlich weg — das ist akzeptabel (toter Code).
    op.add_column(
        "settings",
        sa.Column(
            "default_theme",
            sa.String(length=8),
            nullable=False,
            server_default="auto",
        ),
    )
    op.create_check_constraint(
        "ck_settings_theme",
        "settings",
        "default_theme IN ('light', 'dark', 'auto')",
    )
