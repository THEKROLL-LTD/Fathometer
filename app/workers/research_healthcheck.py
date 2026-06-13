# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Healthcheck-Skript fuer den ``fathometer-research-worker``-Container (P5).

Variante von ``app.workers.healthcheck`` fuer den separaten Research-Worker:
liest ``settings.research_worker_heartbeat_at`` statt ``llm_worker_heartbeat_at``
und exit'et 0 (healthy) oder 1 (unhealthy). Aufruf:
``python -m app.workers.research_healthcheck``.

**Bewusst minimaler Import-Footprint** (wie ``healthcheck.py``): nur
``app.config`` plus eine schlanke ``sqlalchemy``-Connection, Spalte per Raw-SQL.
Die Heartbeat-Cadence im Worker ist ``HEARTBEAT_INTERVAL_SEC = 10`` — der
Schwellwert hier ist 30s (zwei verpasste Schreibvorgaenge gelten noch als
gesund). Die ``_is_alive``-Entscheidungslogik wird aus ``healthcheck`` geteilt,
damit es nur eine Quelle fuer die Alters-Schwellwert-Semantik gibt.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime

from sqlalchemy import Connection, create_engine, text

from app.config import load_settings
from app.workers.healthcheck import _is_alive

HEARTBEAT_MAX_AGE_SEC: int = 30


def _open_connection() -> Connection:
    """Baut eine kurzlebige DB-Connection (patchbar in Tests)."""
    cfg = load_settings()
    engine = create_engine(cfg.database_url, future=True, pool_pre_ping=False)
    return engine.connect()


def main() -> int:
    """Healthcheck-Hauptfunktion.

    Returns ``0`` wenn ``research_worker_heartbeat_at`` juenger als
    ``HEARTBEAT_MAX_AGE_SEC`` Sekunden ist, sonst ``1``.
    """
    try:
        conn = _open_connection()
        try:
            row = conn.execute(
                text("SELECT research_worker_heartbeat_at FROM settings WHERE id = 1")
            ).first()
        finally:
            conn.close()
    except Exception as exc:  # defensiv — DB nicht erreichbar etc.
        print(f"research_healthcheck: db_error {type(exc).__name__}", file=sys.stderr)
        return 1

    hb = row[0] if row is not None else None
    if hb is None:
        print("research_healthcheck: no_heartbeat_yet", file=sys.stderr)
        return 1

    now = datetime.now(tz=UTC)
    if not _is_alive(hb, now, HEARTBEAT_MAX_AGE_SEC):
        hb_aware = hb if hb.tzinfo is not None else hb.replace(tzinfo=UTC)
        age = now - hb_aware
        print(
            f"research_healthcheck: heartbeat_stale age_sec={age.total_seconds():.0f}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
