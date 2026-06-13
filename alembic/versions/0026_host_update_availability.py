"""host_update_availability — ADR-0062 (Block AH).

Drei neue nullable Finding-Spalten fuer das autoritative Host-Update-Flag:

* ``host_update_available`` (Boolean, nullable) — der Agent loest pro
  Binary-Pfad das besitzende OS-Paket auf und meldet, ob mit den aktuell
  konfigurierten Repos ein host-applizierbares Update bereitsteht. ``True``
  promotet ein lang-pkgs-Finding in ``fix_lane_for`` von ``upstream`` nach
  ``patch``. ``NULL`` = Agent zu alt / Paket nicht aufgeloest -> konservativ
  ``upstream`` (ADR-0061-Default, kein Hard-Break).
* ``owning_package`` (String(256), nullable) — reine UI-Anzeige.
* ``available_version`` (String(256), nullable) — reine UI-Anzeige.

**Reiner nullable-Add, KEIN Eval-Rebuild** (im Gegensatz zu Migration 0025).
Bestehende Findings bekommen ``host_update_available = NULL``, das in der
Lane-Ableitung exakt auf ``upstream`` faellt — also das unveraenderte
AG-/ADR-0061-Verhalten. Es gibt daher KEINE Lane-Churn und keinen Grund die
``application_group_evaluations``-Rows zu leeren: die Lane eines Findings
flippt erst, wenn ein NEUER Scan den Flag liefert. Dieser Scan aendert ohnehin
den Group-/Lane-Fingerprint (neue Spaltenwerte fliessen in die organische
Re-Eval via ``llm_risk_cache``-Pfad ein) — kein PASS2-Prompt-Bump noetig, der
Prompt-Text bleibt unveraendert.

Downgrade droppt die drei Spalten (offensichtlicher, akzeptierter Datenverlust
des Host-Update-Flags — es wird beim naechsten Scan ohnehin neu gemeldet).

Revision ID: 0026_host_update_availability
Revises: 0025_upstream_fix_lane
Create Date: 2026-06-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0026_host_update_availability"
down_revision: str | None = "0025_upstream_fix_lane"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "findings"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column("host_update_available", sa.Boolean(), nullable=True),
    )
    op.add_column(
        _TABLE,
        sa.Column("owning_package", sa.String(length=256), nullable=True),
    )
    op.add_column(
        _TABLE,
        sa.Column("available_version", sa.String(length=256), nullable=True),
    )


def downgrade() -> None:
    op.drop_column(_TABLE, "available_version")
    op.drop_column(_TABLE, "owning_package")
    op.drop_column(_TABLE, "host_update_available")
