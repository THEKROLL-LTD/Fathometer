"""widen_reason_text — TICKET-016 / ADR-0065.

Aendert ``application_group_evaluations.risk_band_reason`` von
``VARCHAR(256)`` auf ``TEXT`` (unbegrenzt), damit die volle LLM-Begruendung
gespeichert werden kann (TD-021).

Upgrade: ``ALTER COLUMN … TYPE TEXT`` (Postgres: in-place bei
Vergrößerung, kein Rewrite-Risiko).

Downgrade: ``ALTER COLUMN … TYPE VARCHAR(256)`` mit ``USING LEFT(…, 256)``.
Hinweis: Reasons >256 Zeichen werden beim Downgrade still auf 256
abgeschnitten; der Daten-Verlust ist dokumentiert und akzeptiert
(Operator kann danach ``upgrade head`` wiederholen).

Revision ID: 0029_widen_reason_text
Revises: 0028_collapse_upstream_lane
Create Date: 2026-06-14
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0029_widen_reason_text"
down_revision: str | None = "0028_collapse_upstream_lane"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "application_group_evaluations"
_COLUMN = "risk_band_reason"


def upgrade() -> None:
    op.execute(
        f"ALTER TABLE {_TABLE} ALTER COLUMN {_COLUMN} TYPE TEXT"
    )


def downgrade() -> None:
    # Bei Werten >256 wuerde Postgres sonst einen Fehler werfen.
    # LEFT(…, 256) truncates still — dokumentierter Daten-Verlust.
    op.execute(
        f"ALTER TABLE {_TABLE} ALTER COLUMN {_COLUMN} TYPE VARCHAR(256) "
        f"USING LEFT({_COLUMN}, 256)"
    )
