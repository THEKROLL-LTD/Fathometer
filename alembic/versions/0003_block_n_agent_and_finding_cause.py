"""block_n_agent_and_finding_cause — ADR-0021.

Zwei Spalten auf `servers`:
- `trivy_version` (`String(32)`, nullable) — zuletzt beobachtete Trivy-CLI-Version.
- `agent_version_seen_at` (`DateTime(timezone=True)`, nullable) — Zeitstempel
  des letzten Envelope-Empfangs.

(Die Spalte `agent_version` existiert bereits aus Migration 0002.)

Fuenf Spalten auf `findings`:
- `package_purl` (`String(512)`) — Trivy `Vulnerability.PkgIdentifier.PURL`.
- `target_path` (`String(512)`) — Trivy `Result.Target` (Datei-Pfad bei
  lang-pkgs, Distro-Marker bei os-pkgs).
- `result_type` (`String(64)`) — Trivy `Result.Type` (`ubuntu`, `gobinary`, ...).
- `severity_source` (`String(64)`) — Trivy `Vulnerability.SeveritySource`.
- `vendor_ids` (`ARRAY(String(128))`) — Trivy `Vulnerability.VendorIDs`.

Alle Spalten nullable, kein Backfill — bestehende Findings ziehen sich beim
naechsten Scan via UPSERT auf Re-Ingest selbst nach.

UNIQUE-Constraint `uq_findings_natural_key` bleibt unveraendert (ADR-0011
`@target`-Suffix im `package_name` waehrend der Re-Ingest-Konsolidierung).

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-18
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "servers",
        sa.Column("trivy_version", sa.String(32), nullable=True),
    )
    op.add_column(
        "servers",
        sa.Column(
            "agent_version_seen_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.add_column(
        "findings",
        sa.Column("package_purl", sa.String(512), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("target_path", sa.String(512), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("result_type", sa.String(64), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("severity_source", sa.String(64), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "vendor_ids",
            postgresql.ARRAY(sa.String(128)),
            nullable=True,
        ),
    )


def downgrade() -> None:
    # Reihenfolge umgekehrt zum Upgrade — sauberer Roll-Back.
    op.drop_column("findings", "vendor_ids")
    op.drop_column("findings", "severity_source")
    op.drop_column("findings", "result_type")
    op.drop_column("findings", "target_path")
    op.drop_column("findings", "package_purl")
    op.drop_column("servers", "agent_version_seen_at")
    op.drop_column("servers", "trivy_version")
