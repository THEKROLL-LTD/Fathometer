"""drop_findings_risk_band_reason - TICKET-012 / ADR-0054.

Entfernt die Per-Finding-Spalte ``findings.risk_band_reason``. Das
AI-Assessment ist ausschliesslich Group-Level
(``application_group_evaluations.risk_band_reason``); der per Finding
vererbte Group-Reason war irrefuehrend (beschrieb das *worst finding* der
Group, nicht das einzelne Finding — siehe TICKET-012). Die Schreibseite
(``finding_group_inheritance``, ``scan_processing``) und die UI-Anzeige
wurden mitentfernt; die Spalte ist damit toter Ballast.

Group-Level bleibt unangetastet: ``ApplicationGroupEvaluation.risk_band_reason``
ist eine andere Tabelle und wird hier nicht beruehrt.

Downgrade fuegt die Spalte als nullable ``String(256)`` ohne Backfill wieder
ein — die historischen Reason-Werte sind verloren (offensichtlicher
Spalten-Drop-Fall, kein verlustfreier Roundtrip moeglich).

Revision ID: 0021_drop_findings_risk_band_reason
Revises: 0020_daily_risk_state
Create Date: 2026-06-11
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0021_drop_findings_risk_band_reason"
down_revision: str | None = "0020_daily_risk_state"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.drop_column("findings", "risk_band_reason")


def downgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("risk_band_reason", sa.String(256), nullable=True),
    )
