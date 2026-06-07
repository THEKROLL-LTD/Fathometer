"""triage_idx_include_id - id in die INCLUDE-Liste des Triage-Index.

Folgebefund aus EXPLAIN (ANALYZE, BUFFERS) nach Migration 0018
(scripts/perf/explain_server_detail.sql, 2026-06-07, Server mit 25.9k offenen
Findings):

Migration 0018 hat `ix_findings_server_open_triage` angelegt, aber nur Q7
(_tendency_quick, nutzt `count(*)`) wurde tatsaechlich Index-Only-Scan
(15.138 -> 207 Buffer). Q1/Q3/Q4/Q5 blieben beim alten `ix_findings_server_
status` + Bitmap-Heap-Scan (15.138 Buffer) haengen.

Grund: ein Postgres-B-Tree-Index speichert den Heap-TID, NICHT den
Spaltenwert `id`. Die Aggregate verwenden `count(findings.id)` (und der
Two-Step-Triage-Pfad `select(Finding.id) … LIMIT 10`) — beide brauchen den
`id`-WERT, der ohne INCLUDE nur aus dem Heap kommt. Damit faellt der Index-
Only-Scan weg und der Planner bleibt beim Heap-Scan.

Loesung: `id` als erste INCLUDE-Spalte aufnehmen. Dann liefert der Index
`id` ohne Heap-Zugriff, und:
  - Q1/Q3/Q4/Q5 (`count(id)` / GROUP BY) werden Index-Only (~200 statt
    15.138 Buffer, wie Q7),
  - der Two-Step-Triage-Endpoint sortiert Step 1 (`select(id) ORDER BY …
    LIMIT 10`) ueber schmale Index-Tupel statt 14.027 fette Heap-Rows.

`id` ist BIGINT (8 Byte) — der Index waechst um ~8 Byte je Eintrag, bei
~26k offenen Rows/Server vernachlaessigbar.

Umsetzung: DROP + CREATE (kein In-Place-Alter fuer INCLUDE moeglich). Analog
0015/0018 ohne `postgresql_concurrently` — kurze SHARE-Lock-Phase bei ~33k
Rows/Server vertretbar. Fuer Hot-Online: manuell
`DROP INDEX CONCURRENTLY` + `CREATE INDEX CONCURRENTLY` ausserhalb Alembic,
dann `alembic stamp 0019_triage_idx_include_id`.

Revision ID: 0019_triage_idx_include_id
Revises: 0018_findings_open_triage_idx
Create Date: 2026-06-07
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0019_triage_idx_include_id"
down_revision: str | None = "0018_findings_open_triage_idx"
branch_labels: str | None = None
depends_on: str | None = None


_INDEX_NAME = "ix_findings_server_open_triage"
_TABLE = "findings"
_KEY_COLS = ["server_id", "risk_band"]
_WHERE = sa.text("status = 'open'")
# v2: `id` als erste INCLUDE-Spalte (Index-Only fuer count(id) / select(id)).
_INCLUDE_V2 = [
    "id",
    "application_group_id",
    "first_seen_at",
    "is_kev",
    "severity",
    "epss_score",
]
# v1 (Migration 0018) — ohne `id`.
_INCLUDE_V1 = [
    "application_group_id",
    "first_seen_at",
    "is_kev",
    "severity",
    "epss_score",
]


def upgrade() -> None:
    op.drop_index(_INDEX_NAME, table_name=_TABLE)
    op.create_index(
        _INDEX_NAME,
        _TABLE,
        _KEY_COLS,
        postgresql_include=_INCLUDE_V2,
        postgresql_where=_WHERE,
    )


def downgrade() -> None:
    op.drop_index(_INDEX_NAME, table_name=_TABLE)
    op.create_index(
        _INDEX_NAME,
        _TABLE,
        _KEY_COLS,
        postgresql_include=_INCLUDE_V1,
        postgresql_where=_WHERE,
    )
