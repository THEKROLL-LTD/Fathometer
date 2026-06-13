"""upstream_fix_lane — ADR-0061 (Block AG).

Dritte Fix-Lane ``upstream`` fuer lang-pkgs-Findings mit Fix. lang-pkgs-Fixes
(gobinary/jar/node-pkg ...) sind NICHT host-applizierbar: die ``fixed_version``
ist ein Dependency-/Toolchain-Stand, der einen Upstream-Rebuild braucht, kein
``dnf/apt upgrade``. Diese Migration erweitert den CHECK
``ck_app_group_evals_fix_lane`` von ``IN ('patch','mitigate')`` auf
``IN ('patch','mitigate','upstream')``.

**Kein Daten-Backfill, Drop & Rebuild** (analog ADR-0053 / Migration 0022): die
Lane-Partition aendert sich (lang-pkgs+Fix wandert von ``patch`` nach
``upstream``), bestehende Eval-Rows sind nach der Logik-Aenderung ohnehin neu zu
berechnen. Die Rows werden geleert; Pass-2 fuellt die Junction beim naechsten
regulaeren Scan jedes Servers via ``llm_risk_cache``-Pfad neu auf (einmaliger
Cache-Miss durch ``PASS2_PROMPT_VERSION``-Bump, danach Hits).

PK/Index unveraendert — ``fix_lane`` ist bereits PK-Bestandteil (Migration
0022), die Erweiterung betrifft nur die CHECK-Wertemenge.

Downgrade leert die Rows erneut (upstream-Rows wuerden den 2-Wert-CHECK
verletzen), droppt und recreated den CHECK auf ``IN ('patch','mitigate')``.

Revision ID: 0025_upstream_fix_lane
Revises: 0024_reviewer_chat_model_split
Create Date: 2026-06-13
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0025_upstream_fix_lane"
down_revision: str | None = "0024_reviewer_chat_model_split"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "application_group_evaluations"


def upgrade() -> None:
    # Drop & Rebuild, kein Backfill (ADR-0061 §Schema/Migration): die
    # Lane-Partition aendert sich, Bestands-Rows sind neu zu berechnen.
    op.execute(f"DELETE FROM {_TABLE}")

    op.drop_constraint("ck_app_group_evals_fix_lane", _TABLE, type_="check")
    op.create_check_constraint(
        "ck_app_group_evals_fix_lane",
        _TABLE,
        "fix_lane IN ('patch','mitigate','upstream')",
    )


def downgrade() -> None:
    # Rows leeren: upstream-Rows wuerden den engeren 2-Wert-CHECK verletzen.
    # Pass-2 fuellt nach erneutem Upgrade neu.
    op.execute(f"DELETE FROM {_TABLE}")

    op.drop_constraint("ck_app_group_evals_fix_lane", _TABLE, type_="check")
    op.create_check_constraint(
        "ck_app_group_evals_fix_lane",
        _TABLE,
        "fix_lane IN ('patch','mitigate')",
    )
