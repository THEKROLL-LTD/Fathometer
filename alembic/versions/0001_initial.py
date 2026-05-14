"""initial — leerer Baseline-Revision-Stub fuer Block A.

Block B fuegt die echten Tabellen hinzu (users, servers, scans, ...).

Revision ID: 0001
Revises:
Create Date: 2026-05-14
"""

from __future__ import annotations

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """No-op — Block B liefert das erste reale Schema."""
    pass


def downgrade() -> None:
    """No-op."""
    pass
