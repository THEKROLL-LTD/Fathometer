"""application_group_evaluations — ADR-0028 §"Migration".

Junction-Tabelle fuer per-(group, server)-Bewertungen. Trennt die fleet-
weite Group-Identitaet (`application_groups`) von der server-abhaengigen
Eval (last-write-wins-Bug aus ADR-0023 / TICKET-002 wird damit behoben).

Sieben Eval-Spalten werden ersatzlos aus `application_groups` entfernt
(``risk_band``, ``risk_band_reason``, ``risk_band_source``,
``risk_band_computed_at``, ``worst_finding_id``, ``group_findings_fingerprint``,
``action_type``). Zwei CheckConstraints (``ck_application_groups_band``,
``ck_application_groups_action_type``) wandern in die Junction-Tabelle.

**Kein Daten-Backfill** (ADR-0028 §Migration "Drop & Rebuild"): bestehende
Eval-Werte sind last-write-wins-falsch, eine Replikation auf alle
Junction-Rows pro Server wuerde den Fehler in N Zeilen vervielfaeltigen.
Pass-2 fuellt die Junction beim naechsten regulaeren Scan jedes Servers
via ``llm_risk_cache``-Hit nahezu kostenlos neu auf.

Schema (`application_group_evaluations`):

- group_id BIGINT FK application_groups.id ON DELETE CASCADE — Composite-PK.
- server_id INT FK servers.id ON DELETE CASCADE — Composite-PK.
- risk_band VARCHAR(16) NOT NULL CHECK IN ('escalate','act','mitigate','monitor','noise').
- risk_band_reason VARCHAR(256) NULL.
- risk_band_source VARCHAR(16) NOT NULL CHECK IN ('llm','manual').
- risk_band_computed_at TIMESTAMPTZ NOT NULL DEFAULT now().
- worst_finding_id BIGINT NULL (KEIN FK — Group-Eval ueberlebt Finding-Deletes).
- group_findings_fingerprint VARCHAR(16) NULL — fuer Pass-2-Skip-Logik.
- action_type VARCHAR(16) NULL CHECK IN ('patch','mitigate','watch','none','investigate').

Drei Indizes:

- Composite-PK auf (group_id, server_id).
- ix_app_group_evals_server: (server_id, risk_band) — Server-Detail-Path.
- ix_app_group_evals_worst_finding: partial auf worst_finding_id WHERE NOT NULL.

Revision ID: 0011_app_group_evals
Revises: 0010_scan_ingest_jobs
Create Date: 2026-05-22

Hinweis: Revision-ID ist auf 20 Zeichen gekuerzt (vorher
``0011_application_group_evaluations`` = 35 Zeichen), weil
``alembic_version.version_num`` ein ``VARCHAR(32)`` ist.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011_app_group_evals"
down_revision: str | None = "0010_scan_ingest_jobs"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ---- Neue Junction-Tabelle ---------------------------------------------
    op.create_table(
        "application_group_evaluations",
        sa.Column(
            "group_id",
            sa.BigInteger(),
            sa.ForeignKey("application_groups.id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("risk_band", sa.String(16), nullable=False),
        sa.Column("risk_band_reason", sa.String(256), nullable=True),
        sa.Column(
            "risk_band_source",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'llm'"),
        ),
        sa.Column(
            "risk_band_computed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("worst_finding_id", sa.BigInteger(), nullable=True),
        sa.Column("group_findings_fingerprint", sa.String(16), nullable=True),
        sa.Column("action_type", sa.String(16), nullable=True),
        sa.CheckConstraint(
            "risk_band IN ('escalate','act','mitigate','monitor','noise')",
            name="ck_app_group_evals_band",
        ),
        sa.CheckConstraint(
            "risk_band_source IN ('llm','manual')",
            name="ck_app_group_evals_source",
        ),
        sa.CheckConstraint(
            "action_type IS NULL OR action_type IN "
            "('patch','mitigate','watch','none','investigate')",
            name="ck_app_group_evals_action_type",
        ),
    )

    # Server-spezifischer Lookup-Index: Server-Detail-Pfad
    # (_load_application_groups_for_server) und Fleet-Aggregate.
    op.create_index(
        "ix_app_group_evals_server",
        "application_group_evaluations",
        ["server_id", "risk_band"],
    )

    # Partial-Index fuer Worst-Finding-UI-Render-Pfad.
    op.create_index(
        "ix_app_group_evals_worst_finding",
        "application_group_evaluations",
        ["worst_finding_id"],
        postgresql_where=sa.text("worst_finding_id IS NOT NULL"),
    )

    # ---- Eval-Spalten aus application_groups entfernen ---------------------
    # CheckConstraints zuerst (sonst kollidieren sie mit den Drop-Column-Statements
    # weil sie auf die Spalten referenzieren).
    op.drop_constraint("ck_application_groups_band", "application_groups", type_="check")
    op.drop_constraint("ck_application_groups_action_type", "application_groups", type_="check")

    op.drop_column("application_groups", "risk_band")
    op.drop_column("application_groups", "risk_band_reason")
    op.drop_column("application_groups", "risk_band_source")
    op.drop_column("application_groups", "risk_band_computed_at")
    op.drop_column("application_groups", "worst_finding_id")
    op.drop_column("application_groups", "group_findings_fingerprint")
    op.drop_column("application_groups", "action_type")


def downgrade() -> None:
    # Reverse: Eval-Spalten zurueck auf application_groups, Daten bleiben LEER
    # (ADR-0028 §Migration: der Cut wird beim Upgrade hingenommen; ein
    # Rollback erlaubt das Schema zurueckzubauen, aber bestehende Eval-
    # Daten kommen nicht zurueck — Pass-2 muss sie nach erneutem Upgrade
    # wieder befuellen).
    op.add_column(
        "application_groups",
        sa.Column("risk_band", sa.String(16), nullable=True),
    )
    op.add_column(
        "application_groups",
        sa.Column("risk_band_reason", sa.String(256), nullable=True),
    )
    op.add_column(
        "application_groups",
        sa.Column("risk_band_source", sa.String(16), nullable=True),
    )
    op.add_column(
        "application_groups",
        sa.Column("risk_band_computed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "application_groups",
        sa.Column("worst_finding_id", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "application_groups",
        sa.Column("group_findings_fingerprint", sa.String(16), nullable=True),
    )
    op.add_column(
        "application_groups",
        sa.Column("action_type", sa.String(16), nullable=True),
    )
    op.create_check_constraint(
        "ck_application_groups_band",
        "application_groups",
        "risk_band IS NULL OR risk_band IN ('escalate','act','mitigate','monitor','noise')",
    )
    op.create_check_constraint(
        "ck_application_groups_action_type",
        "application_groups",
        "action_type IS NULL OR action_type IN ('patch','mitigate','watch','none','investigate')",
    )

    op.drop_index(
        "ix_app_group_evals_worst_finding",
        table_name="application_group_evaluations",
    )
    op.drop_index(
        "ix_app_group_evals_server",
        table_name="application_group_evaluations",
    )
    op.drop_table("application_group_evaluations")
