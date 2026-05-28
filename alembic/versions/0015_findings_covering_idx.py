"""findings_covering_idx - Covering-Index fuer Server-Detail-Aggregate.

Befund aus pyinstrument-Profiling (2026-05-27): `_build_server_daily_sql` in
`app/services/severity_history.py` dominiert die Server-Detail-Render-Zeit
mit ~22 s (cold cache) bzw. ~2 s (warm cache) bei 10k Findings pro Server.

EXPLAIN-ANALYZE-Plan zeigt einen Seq Scan ueber die komplette `findings`-
Tabelle, obwohl bereits `ix_findings_server_status` und `ix_findings_server_risk_band`
existieren. Grund: bei Single-User-Setups mit ~2-3 Servern ist die `server_id`-
Filter-Selektivitaet ~50 % — bei dieser Selektivitaet ist ein Index-Scan
mit Heap-Fetches teurer als ein Full-Seq-Scan, weshalb der Planner zu Recht
Seq Scan waehlt.

Loesung: Covering Index mit `INCLUDE` ueber die Spalten die der Aggregat-
Pfad braucht (`severity`, `first_seen_at`, `acknowledged_at`, `resolved_at`,
`kev_added_at`). Postgres kann dann einen **Index-Only Scan** ausfuehren —
es muss die Heap-Seiten gar nicht mehr anfassen (die Visibility-Map muss
nach VACUUM aktuell sein, was bei einem laufenden Autovacuum kein Problem
ist).

Groessenordnung:
- Heap-Row: ~500-2000 Byte (viele TEXT-Spalten: title, description, references)
- Index-Eintrag: ~40 Byte (server_id:4, severity:4, 4x timestamptz:32)
- Verhaeltnis: ~50x kleiner → 50x weniger I/O fuer den 50%-Filter-Scan

Erwartete Wirkung: `_build_server_daily_sql` von ~2 s auf < 200 ms (warm),
zusammen mit JIT-Off (separate Cluster-Config, kein Migration-Scope) auf
< 100 ms.

Wichtige Non-Goals dieser Migration:
- JIT-Threshold-Tuning: gehoert in die CNPG-`Cluster.spec.postgresql.parameters`
  (siehe `docs/operations.md`-Folge-PR), nicht in eine Schema-Migration.
- Query-Rewrite auf Per-Finding-Day-Expansion: separater Code-Change, im
  Backlog vermerken.
- Daily-Pre-Aggregations-Tabelle: bereits als TD-013 dokumentiert,
  langfristige Loesung wenn die Flotte > 50 Server / 100k Findings erreicht.

Revision ID: 0015_findings_covering_idx
Revises: 0014_block_w_server_groups
Create Date: 2026-05-27
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0015_findings_covering_idx"
down_revision: str | None = "0014_block_w_server_groups"
branch_labels: str | None = None
depends_on: str | None = None


# Index-Name: `ix_findings_server_covering` — folgt der etablierten
# `ix_<table>_<purpose>`-Konvention der bestehenden Findings-Indizes.
_INDEX_NAME = "ix_findings_server_covering"
_TABLE = "findings"
_KEY_COLS = ["server_id"]
_INCLUDE_COLS = [
    "severity",
    "first_seen_at",
    "acknowledged_at",
    "resolved_at",
    "kev_added_at",
]


def upgrade() -> None:
    # `postgresql_include` produziert `CREATE INDEX ... ON findings (server_id)
    # INCLUDE (severity, first_seen_at, acknowledged_at, resolved_at,
    # kev_added_at)`. SQLAlchemy 2.x / Alembic >= 1.10 unterstuetzen das nativ.
    #
    # Kein `postgresql_concurrently=True`: Alembic-Default-Transaktion vertraegt
    # das nicht; bei Single-User-Setup mit kurzer Tabelle (~10k Rows/Server)
    # ist die ACCESS-EXCLUSIVE-Lock-Phase im einstelligen Sekundenbereich
    # voellig vertretbar. Falls in Zukunft ein Hot-Online-Deploy benoetigt
    # wird: separate manuelle `CREATE INDEX CONCURRENTLY` ausserhalb von Alembic.
    op.create_index(
        _INDEX_NAME,
        _TABLE,
        _KEY_COLS,
        postgresql_include=_INCLUDE_COLS,
    )


def downgrade() -> None:
    op.drop_index(_INDEX_NAME, table_name=_TABLE)
