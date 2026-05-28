"""block_aa_add_primary_url - findings.primary_url persistieren (ADR-0041).

Block AA (ADR-0041): Die Trivy-`PrimaryURL` (Aquasec-/NVD-/Vendor-Direktlink)
wird im Envelope-Schema (`TrivyVulnerability.primary_url`) bereits validiert
(HttpUrl, http(s)-Whitelist, NUL-Schutz, `MAX_REF_URL_LENGTH=2048`), aber im
Ingest-Mapper bisher nicht in die DB geschrieben. Diese Migration ergaenzt die
Spalte; der Mapper (`_build_finding_row`) und der `ON CONFLICT DO UPDATE`-Block
fuellen sie ab dem naechsten Re-Ingest.

Idempotent: kein Backfill, kein Server-Side-Default. Bestands-Findings bleiben
`NULL`, bis der naechste Scan des jeweiligen Servers die Spalte fuellt.

Revision ID: 0016_block_aa_add_primary_url
Revises: 0015_findings_covering_idx
Create Date: 2026-05-28
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0016_block_aa_add_primary_url"
down_revision: str | None = "0015_findings_covering_idx"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("primary_url", sa.String(length=2048), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "primary_url")
