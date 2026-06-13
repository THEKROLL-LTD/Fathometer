"""collapse_upstream_lane — ADR-0064 (Block AK, Phase P1).

Nimmt die dritte Fix-Lane ``upstream`` aus ADR-0061 (Migration 0025) wieder
zurueck: sie kollabiert in ``mitigate``. Die Information "ein Fix existiert
upstream" ist seither **Finding-Level-Enrichment** (``Finding.fixed_version``
an der einzelnen Row), KEINE eigene Lane — die Operator-Aktion ist in beiden
Faellen identisch ("auf dem Host gibt es jetzt keinen Patch, mitigieren").

Diese Migration verengt den CHECK ``ck_app_group_evals_fix_lane`` von
``IN ('patch','mitigate','upstream')`` zurueck auf ``IN ('patch','mitigate')``.

**Kein Daten-Backfill, Drop & Rebuild** (analog ADR-0061 / Migration 0025): die
Lane-Partition aendert sich (lang-pkgs+Fix wandert von ``upstream`` zurueck nach
``mitigate``) und bestehende ``upstream``-Rows wuerden den neuen 2-Wert-CHECK
verletzen. Die Rows werden geleert; Pass-2 fuellt die Junction beim naechsten
regulaeren Scan jedes Servers via ``llm_risk_cache``-Pfad neu auf (einmaliger
Cache-Miss durch den ``PASS2_PROMPT_VERSION``-Bump 4->5, danach Hits).

PK/Index unveraendert — ``fix_lane`` ist bereits PK-Bestandteil (Migration
0022), die Aenderung betrifft nur die CHECK-Wertemenge.

Downgrade leert die Rows erneut und recreated den CHECK auf
``IN ('patch','mitigate','upstream')`` (Stand nach Migration 0025).

Revision ID: 0028_collapse_upstream_lane
Revises: 0027_upstream_check_cache
Create Date: 2026-06-13
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0028_collapse_upstream_lane"
down_revision: str | None = "0027_upstream_check_cache"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "application_group_evaluations"


def upgrade() -> None:
    # Drop & Rebuild, kein Backfill (ADR-0064): die Lane-Partition aendert sich
    # (lang-pkgs+Fix wandert von upstream zurueck nach mitigate); Bestands-
    # ``upstream``-Rows wuerden den engeren 2-Wert-CHECK verletzen. Pass-2
    # fuellt organisch neu (PASS2_PROMPT_VERSION-Bump erzwingt Cache-Miss).
    op.execute(f"DELETE FROM {_TABLE}")

    op.drop_constraint("ck_app_group_evals_fix_lane", _TABLE, type_="check")
    op.create_check_constraint(
        "ck_app_group_evals_fix_lane",
        _TABLE,
        "fix_lane IN ('patch','mitigate')",
    )


def downgrade() -> None:
    # Rows leeren und die dritte Lane (Stand Migration 0025) wieder zulassen.
    # Pass-2 fuellt nach erneutem Upgrade neu.
    op.execute(f"DELETE FROM {_TABLE}")

    op.drop_constraint("ck_app_group_evals_fix_lane", _TABLE, type_="check")
    op.create_check_constraint(
        "ck_app_group_evals_fix_lane",
        _TABLE,
        "fix_lane IN ('patch','mitigate','upstream')",
    )
