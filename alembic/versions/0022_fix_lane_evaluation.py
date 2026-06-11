"""fix_lane_evaluation — ADR-0053 / TICKET-013 (Etappe 1).

Pass-2 bewertet ab jetzt pro Fix-Lane statt pro Group: ``application_group_evaluations``
bekommt eine dritte PK-Spalte ``fix_lane`` (`patch` / `mitigate`), womit bis zu
zwei Eval-Rows pro ``(group_id, server_id)`` existieren — eine fuer die
patchbaren (``fixed_version IS NOT NULL``) und eine fuer die nicht-patchbaren
(``fixed_version IS NULL``) OPEN-Findings einer Group auf einem Server.

``fix_lane`` ist eine deterministische Partition aus ``Finding.fixed_version``,
kein LLM-Output und keine persistierte Finding-Spalte. PK wird
``(group_id, server_id, fix_lane)``; der Lookup-Index ``ix_app_group_evals_server``
wird auf ``(server_id, fix_lane, risk_band)`` erweitert; CHECK
``ck_app_group_evals_fix_lane`` erzwingt ``fix_lane IN ('patch','mitigate')``.
``ck_app_group_evals_action_type`` bleibt unveraendert — der ab Etappe 5
abgeleitete ``action_type`` erfuellt die Whitelist weiterhin.

**Kein Daten-Backfill** (analog ADR-0028 §Migration "Drop & Rebuild"): bestehende
Eval-Rows tragen kein ``fix_lane`` und sind nach der Logik-Aenderung ohnehin neu
zu berechnen (Group-Level-Worst war moeglicherweise ein patchbares Finding,
das fuer die mitigate-Lane nichts aussagt). Die Rows werden geleert; Pass-2
fuellt die Junction beim naechsten regulaeren Scan jedes Servers via
``llm_risk_cache``-Pfad neu auf (einmaliger Cache-Miss pro
``(group, server, lane)`` durch Lane-Salt + Prompt-Version-Bump, danach Hits).

Downgrade baut den Zustand vor 0022 zurueck (Rows bleiben leer): Index zurueck
auf ``(server_id, risk_band)``, CHECK + ``fix_lane``-Spalte gedroppt, PK zurueck
auf ``(group_id, server_id)``.

Revision ID: 0022_fix_lane_evaluation
Revises: 0021_drop_finding_reason
Create Date: 2026-06-11
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0022_fix_lane_evaluation"
down_revision: str | None = "0021_drop_finding_reason"
branch_labels: str | None = None
depends_on: str | None = None

_TABLE = "application_group_evaluations"
_PK = "application_group_evaluations_pkey"


def upgrade() -> None:
    # ---- Drop & Rebuild, kein Backfill (ADR-0053 §Schema) -------------------
    # Bestands-Rows tragen kein fix_lane und sind nach der Logik-Aenderung neu
    # zu berechnen. Leeren, damit die NOT-NULL-PK-Spalte ohne server_default
    # haltbar ist und keine fix_lane-losen Rows den neuen PK verletzen.
    op.execute(f"DELETE FROM {_TABLE}")

    # Alten 2-Spalten-PK droppen, bevor die dritte PK-Spalte ergaenzt wird.
    op.drop_constraint(_PK, _TABLE, type_="primary")

    # fix_lane: NOT NULL ist auf der nun leeren Tabelle ohne server_default
    # haltbar (keine Bestands-Rows zu fuellen).
    op.add_column(
        _TABLE,
        sa.Column("fix_lane", sa.String(8), nullable=False),
    )

    # Neuer Composite-PK inkl. fix_lane.
    op.create_primary_key(_PK, _TABLE, ["group_id", "server_id", "fix_lane"])

    op.create_check_constraint(
        "ck_app_group_evals_fix_lane",
        _TABLE,
        "fix_lane IN ('patch','mitigate')",
    )

    # Lookup-Index um die Lane-Komponente erweitern (Server-Detail-Pfad
    # filtert/gruppiert jetzt pro Lane).
    op.drop_index("ix_app_group_evals_server", table_name=_TABLE)
    op.create_index(
        "ix_app_group_evals_server",
        _TABLE,
        ["server_id", "fix_lane", "risk_band"],
    )


def downgrade() -> None:
    # Rows leeren: ohne fix_lane sind die Lane-getrennten Rows nicht eindeutig
    # auf den 2-Spalten-PK zurueckfuehrbar (zwei Lanes kollidieren auf
    # (group_id, server_id)). Pass-2 fuellt nach erneutem Upgrade neu.
    op.execute(f"DELETE FROM {_TABLE}")

    op.drop_index("ix_app_group_evals_server", table_name=_TABLE)
    op.create_index(
        "ix_app_group_evals_server",
        _TABLE,
        ["server_id", "risk_band"],
    )

    op.drop_constraint("ck_app_group_evals_fix_lane", _TABLE, type_="check")
    op.drop_constraint(_PK, _TABLE, type_="primary")
    op.drop_column(_TABLE, "fix_lane")
    op.create_primary_key(_PK, _TABLE, ["group_id", "server_id"])
