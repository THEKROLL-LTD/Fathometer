"""block_w_server_groups - ADR-0034: Host-Group-Datenmodell.

Neue Tabelle `server_groups` (id PK, name UNIQUE+CHECK, position INT,
created_at TIMESTAMPTZ) und Spalte `servers.group_id` (nullable FK mit
ON DELETE SET NULL). Index `ix_servers_group_id` fuer Sidebar-Filter-Query.

Migration-Strategie:
- Bestehende Server bekommen `group_id = NULL` (DEFAULT-Verhalten von ADD
  COLUMN ohne server_default) — kein Backfill, keine Downtime.
- Tabelle ist nach der Migration leer. CRUD-UI kommt in einem spaeterer Block.
- ON DELETE SET NULL: Gruppe loeschen -> Server fallen in "ungrouped"-Bucket
  zurueck ohne Datenverlust.

Downgrade: erst Index droppen, dann Spalte + FK, dann Tabelle.

Revision ID: 0014_block_w_server_groups
Revises: 0013_remove_default_theme
Create Date: 2026-05-23
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0014_block_w_server_groups"
down_revision: str | None = "0013_remove_default_theme"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "server_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("name", name="uq_server_groups_name"),
        sa.CheckConstraint(
            "length(trim(name)) > 0 AND length(name) <= 64",
            name="ck_server_groups_name_length",
        ),
        sa.CheckConstraint(
            "name ~ '^[A-Za-z0-9 _.-]+$'",
            name="ck_server_groups_name_charset",
        ),
    )
    op.add_column(
        "servers",
        sa.Column(
            "group_id",
            sa.Integer(),
            sa.ForeignKey("server_groups.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_servers_group_id", "servers", ["group_id"])


def downgrade() -> None:
    op.drop_index("ix_servers_group_id", "servers")
    op.drop_column("servers", "group_id")
    op.drop_table("server_groups")
