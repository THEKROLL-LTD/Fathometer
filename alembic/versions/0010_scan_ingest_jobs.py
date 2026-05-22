"""scan_ingest_jobs — ADR-0026 §"Schema-Aenderungen".

Neue Tabelle `scan_ingest_jobs` als asynchrone Ingest-Queue fuer POST
/api/scans. Ermoeglicht den Fast-Path: HTTP-Handler antwortet <1s mit 202
+ job_id; die eigentliche Verarbeitung (Findings-UPSERT, Pre-Triage,
Group-Matching, LLM-Queueing) laeuft im secscan-llm-worker als Sub-Tick.

Spalten:
- id BIGSERIAL PK — Job-ID, wird im 202-Response-Body zurueckgegeben.
- server_id INT FK servers.id ON DELETE CASCADE NOT NULL.
- payload_gzip BYTEA NULL — gzip-komprimierter Decompressed-Body fuer
  Transit-Speicher. Wird atomar mit status='done' auf NULL gesetzt
  (ADR-0026 §Bedrohungsmodell). STORAGE EXTERNAL: kein Toast-Compress,
  da der Body bereits gzip-komprimiert ist.
- payload_sha256 CHAR(64) NOT NULL — SHA-256-Hex Idempotency-Key.
- payload_bytes INT NOT NULL — Decompressed-Groesse fuer Audit/Diagnose.
- status VARCHAR(16) DEFAULT 'queued' CHECK IN (queued/in_progress/done/failed).
- attempts INT DEFAULT 0 CHECK >= 0.
- next_attempt_at TIMESTAMPTZ DEFAULT now() — Pickup-Gate fuer Retry-Backoff.
- picked_up_by VARCHAR(128) NULL — Worker-ID fuer Stale-Detection.
- picked_up_at TIMESTAMPTZ NULL.
- result JSONB NULL — Counts bei status='done'.
- error TEXT NULL — Validation-/SQL-Error (max 4 KB, truncated).
- created_at TIMESTAMPTZ NOT NULL DEFAULT now() — FIFO-Ordering.
- finished_at TIMESTAMPTZ NULL — Ende der Verarbeitung fuer Retention-Sweep.
- scan_id BIGINT NULL FK scans.id ON DELETE SET NULL — Pointer auf erzeugten Scan.

Vier Indizes:
- ix_scan_ingest_jobs_pickup: Partial auf status='queued', (next_attempt_at, created_at).
- ix_scan_ingest_jobs_stale: Partial auf status='in_progress', (picked_up_at,).
- ix_scan_ingest_jobs_server: (server_id, status) fuer Status-Endpoint-Lookups.
- ux_scan_ingest_jobs_payload_sha256: Partial Unique auf status IN ('queued','in_progress').

Revision ID: 0010_scan_ingest_jobs
Revises: 0008
Create Date: 2026-05-22
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010_scan_ingest_jobs"
down_revision: str | None = "0008"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ---- scan_ingest_jobs ---------------------------------------------------
    op.create_table(
        "scan_ingest_jobs",
        sa.Column("id", sa.BigInteger(), primary_key=True, nullable=False),
        sa.Column(
            "server_id",
            sa.Integer(),
            sa.ForeignKey("servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("payload_gzip", sa.LargeBinary(), nullable=True),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("payload_bytes", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'queued'"),
        ),
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("picked_up_by", sa.String(128), nullable=True),
        sa.Column("picked_up_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "scan_id",
            sa.BigInteger(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "status IN ('queued','in_progress','done','failed')",
            name="ck_scan_ingest_jobs_status",
        ),
        sa.CheckConstraint(
            "attempts >= 0",
            name="ck_scan_ingest_jobs_attempts",
        ),
    )

    # Storage-Hint: payload_gzip ist bereits gzip-komprimiert — Toast-Compression
    # wuerde den Body erneut komprimieren und dabei Verarbeitungszeit verschwenden.
    # EXTERNAL speichert den Wert out-of-line ohne Kompression (ADR-0026 §Begruendung).
    op.execute("ALTER TABLE scan_ingest_jobs ALTER COLUMN payload_gzip SET STORAGE EXTERNAL")

    # Pickup-Index: heisseste Query — Worker pollt alle N Sekunden.
    # Partial auf status='queued' haelt den Index klein.
    op.create_index(
        "ix_scan_ingest_jobs_pickup",
        "scan_ingest_jobs",
        ["next_attempt_at", "created_at"],
        postgresql_where=sa.text("status = 'queued'"),
    )

    # Stale-Reaper-Index: findet in_progress-Jobs die laenger als 5 Min laufen.
    op.create_index(
        "ix_scan_ingest_jobs_stale",
        "scan_ingest_jobs",
        ["picked_up_at"],
        postgresql_where=sa.text("status = 'in_progress'"),
    )

    # Server-Status-Index: fuer GET /api/scans/jobs/<id> (server_id-Scoping) und
    # Per-Server-Soft-Cap-Check (COUNT WHERE server_id=? AND status IN (...)).
    op.create_index(
        "ix_scan_ingest_jobs_server",
        "scan_ingest_jobs",
        ["server_id", "status"],
    )

    # Partial-Unique-Index: verhindert Doppel-Queue desselben Payloads waehrend
    # er noch in Bearbeitung ist. Erlaubt Re-Upload nach done (z.B. 24h spaeter).
    # Nicht als UniqueConstraint sondern als Index, weil Postgres partial unique
    # constraints nur ueber partial unique indexes unterstuetzt.
    op.create_index(
        "ux_scan_ingest_jobs_payload_sha256",
        "scan_ingest_jobs",
        ["payload_sha256"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued','in_progress')"),
    )


def downgrade() -> None:
    # Reverse-Reihenfolge zum upgrade() — Indizes zuerst, dann Tabelle.
    # Storage-Hint braucht kein explizites Drop (geht mit der Tabelle weg).
    op.drop_index(
        "ux_scan_ingest_jobs_payload_sha256",
        table_name="scan_ingest_jobs",
    )
    op.drop_index(
        "ix_scan_ingest_jobs_server",
        table_name="scan_ingest_jobs",
    )
    op.drop_index(
        "ix_scan_ingest_jobs_stale",
        table_name="scan_ingest_jobs",
    )
    op.drop_index(
        "ix_scan_ingest_jobs_pickup",
        table_name="scan_ingest_jobs",
    )
    op.drop_table("scan_ingest_jobs")
