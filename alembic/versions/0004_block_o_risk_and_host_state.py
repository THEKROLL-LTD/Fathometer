"""block_o_risk_and_host_state — ADR-0022.

Vier neue Tabellen fuer den Host-Snapshot (truncate+insert pro Server):

- `server_listeners(server_id, proto, port, addr, process, pid)`
- `server_processes(server_id, pid, user, comm, args)`
- `server_kernel_modules(server_id, name)`
- `server_services(server_id, name)`

Eine neue Spalte auf `servers`:

- `host_state_snapshot_at` — Zeitstempel des letzten Snapshot-Updates.

Sechs neue Spalten auf `findings` (Risk-Engine + Vendor-Severity):

- `risk_band` — `escalate`/`act`/`mitigate`/`pending`/`unknown`/`monitor`/`noise`.
- `risk_band_reason` — Begruendungs-String, max 256 Chars.
- `risk_band_source` — `engine`/`llm`/`manual`, default `engine`.
- `risk_band_computed_at` — Zeitstempel der letzten Engine-Auswertung.
- `severity_by_provider` — JSONB-Map `provider -> severity_label`.
- `vendor_status` — Normalisiertes Trivy-Status-Feld, max 32 Chars.

Plus zwei Indizes auf `findings.risk_band`:

- `ix_findings_risk_band_open` (partial `WHERE status = 'open'`).
- `ix_findings_server_risk_band` (server_id, risk_band).

Kein Backfill — Werte werden beim naechsten Scan-Ingest gesetzt. Bestehende
Findings bleiben mit `risk_band = NULL` bis zum naechsten Scan; UI rendert
in diesem Fall einen "pending pre-triage"-Hint (siehe ADR-0022).

Revision ID: 0004_block_o
Revises: 0003
Create Date: 2026-05-18
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ---- Snapshot-Tabellen --------------------------------------------------
    op.create_table(
        "server_listeners",
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("proto", sa.String(8), primary_key=True, nullable=False),
        sa.Column("port", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("addr", sa.String(64), primary_key=True, nullable=False),
        sa.Column("process", sa.String(64), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "port >= 0 AND port <= 65535",
            name="ck_server_listeners_port_range",
        ),
    )
    op.create_index(
        "ix_server_listeners_port",
        "server_listeners",
        ["server_id", "port"],
    )

    op.create_table(
        "server_processes",
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("pid", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("user", sa.String(32), nullable=True),
        sa.Column("comm", sa.String(64), nullable=True),
        sa.Column("args", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_server_processes_comm",
        "server_processes",
        ["server_id", "comm"],
    )

    op.create_table(
        "server_kernel_modules",
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("name", sa.String(64), primary_key=True, nullable=False),
    )

    op.create_table(
        "server_services",
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("name", sa.String(128), primary_key=True, nullable=False),
    )

    # ---- servers.host_state_snapshot_at ------------------------------------
    op.add_column(
        "servers",
        sa.Column(
            "host_state_snapshot_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # ---- findings — sechs neue Spalten --------------------------------------
    op.add_column(
        "findings",
        sa.Column("risk_band", sa.String(16), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("risk_band_reason", sa.String(256), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("risk_band_source", sa.String(16), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "risk_band_computed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "findings",
        sa.Column("severity_by_provider", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("vendor_status", sa.String(32), nullable=True),
    )

    # ---- findings.risk_band-Indizes -----------------------------------------
    op.create_index(
        "ix_findings_risk_band_open",
        "findings",
        ["risk_band"],
        postgresql_where=sa.text("status = 'open'"),
    )
    op.create_index(
        "ix_findings_server_risk_band",
        "findings",
        ["server_id", "risk_band"],
    )


def downgrade() -> None:
    # Reihenfolge spiegelbildlich: erst Indizes, dann Spalten, dann Tabellen.
    op.drop_index("ix_findings_server_risk_band", table_name="findings")
    op.drop_index("ix_findings_risk_band_open", table_name="findings")

    op.drop_column("findings", "vendor_status")
    op.drop_column("findings", "severity_by_provider")
    op.drop_column("findings", "risk_band_computed_at")
    op.drop_column("findings", "risk_band_source")
    op.drop_column("findings", "risk_band_reason")
    op.drop_column("findings", "risk_band")

    op.drop_column("servers", "host_state_snapshot_at")

    op.drop_table("server_services")
    op.drop_table("server_kernel_modules")
    op.drop_index("ix_server_processes_comm", table_name="server_processes")
    op.drop_table("server_processes")
    op.drop_index("ix_server_listeners_port", table_name="server_listeners")
    op.drop_table("server_listeners")
