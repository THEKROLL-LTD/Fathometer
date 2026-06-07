"""findings_server_open_triage_idx - Partial-Covering-Index fuer Server-Detail.

Befund aus EXPLAIN (ANALYZE, BUFFERS) gegen die echte DB (2026-06-07,
`scripts/perf/explain_server_detail.sql`, Test-Server mit 25.907 offenen /
33.612 Findings total):

Die heissen Server-Detail-Widget-Queries sind am DB-Layer warm zwar schnell
(40-66 ms), lesen aber pro Aufruf ~15.138 Buffer (~118 MB) als **Bitmap Heap
Scan** ueber *alle* offenen Findings des Servers — obwohl sie nur 1-2 Spalten
brauchen:

  Q3 _risk_band_header_counts        GROUP BY risk_band            15.138 Buf
  Q4 _load_server_band_aggregates    GROUP BY risk_band + filter   15.138 Buf
  Q5 _load_application_groups (Cnt)  GROUP BY application_group_id 15.138 Buf
  Q7 _tendency_quick                 first_seen_at-Buckets         15.138 Buf
  Q1 triage_band_fragment COUNT      count WHERE server+open+band   8.939 Buf

Auf **kaltem Cache** (`shared read` statt `shared hit`) wird daraus Disk-I/O
im Mehrsekundenbereich — das erklaert die beobachteten "teilweise sehr lang"
ladenden Widgets.

Loesung: EIN konsolidierter Partial-Covering-Index. Key `(server_id,
risk_band)`, `INCLUDE` ueber die Projektions-/Sort-/Filter-Spalten der
Aggregate und Listen, partial `WHERE status = 'open'` (der mit Abstand
haeufigste Praedikat-Wert auf der Server-Detail-View). Die obigen Queries
laufen damit als **Index-Only Scan** (~150 Buffer statt 15.138 — Faktor ~100
weniger I/O, kalt wie warm) und Q1/Q2/Q6 bekommen einen schlanken gefilterten
Scan als Eingang statt eines BitmapAnd ueber zwei Indizes.

INCLUDE-Spalten:
- application_group_id : Q4-FILTER (app_group IS NULL) + Q5-GROUP BY
- first_seen_at        : Q7-Zeitfenster-Buckets
- is_kev, severity, epss_score : Sort-Keys der Triage-/Group-Listen (Q2/Q6)

Hinweis Redundanz: `ix_findings_server_risk_band (server_id, risk_band)` wird
durch diesen Index funktional abgedeckt (gleiche Key-Prefix). Das Droppen ist
bewusst NICHT Teil dieser Migration — erst nach EXPLAIN-Gegenmessung auf der
echten DB entscheiden (separater Change), um keinen genutzten Plan zu
zerschiessen.

Kein `postgresql_concurrently` (analog Migration 0015): Alembic-Default-
Transaktion vertraegt das nicht; die SHARE-Lock-Phase ist bei ~33k Rows/Server
im einstelligen Sekundenbereich vertretbar. Fuer einen Hot-Online-Deploy:
manuell `CREATE INDEX CONCURRENTLY ix_findings_server_open_triage ...`
ausserhalb von Alembic anlegen, dann diese Migration mit
`alembic stamp 0018_findings_open_triage_idx` als angewendet markieren.

Revision ID: 0018_findings_open_triage_idx
Revises: 0017_remove_llm_chat
Create Date: 2026-06-07
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0018_findings_open_triage_idx"
down_revision: str | None = "0017_remove_llm_chat"
branch_labels: str | None = None
depends_on: str | None = None


_INDEX_NAME = "ix_findings_server_open_triage"
_TABLE = "findings"
_KEY_COLS = ["server_id", "risk_band"]
_INCLUDE_COLS = [
    "application_group_id",
    "first_seen_at",
    "is_kev",
    "severity",
    "epss_score",
]


def upgrade() -> None:
    op.create_index(
        _INDEX_NAME,
        _TABLE,
        _KEY_COLS,
        postgresql_include=_INCLUDE_COLS,
        postgresql_where=sa.text("status = 'open'"),
    )


def downgrade() -> None:
    op.drop_index(_INDEX_NAME, table_name=_TABLE)
