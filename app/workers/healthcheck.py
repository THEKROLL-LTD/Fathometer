# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Healthcheck-Skript fuer den ``fathometer-llm-worker``-Container.

Wird vom Compose-Healthcheck-Eintrag und von den k8s-Liveness/Readiness-
Probes aufgerufen (``python -m app.workers.healthcheck``). Liest die
Singleton-``settings``-Zeile per Raw-SQL, prueft das Alter von
``llm_worker_heartbeat_at`` und exit'et 0 (healthy) oder 1 (unhealthy).

**Bewusst minimaler Import-Footprint** (v0.9.1): das Skript laeuft als
eigenes kurzlebiges Python-Process bei jeder Probe — die kombinierte
Import-Last von ``openai``-SDK, Pydantic-v2-Schemas und ORM-Tabellen
sprengt unter ARM64-RKE2-Realbedingungen das Default-``timeoutSeconds: 5``
einer k8s-Exec-Probe (gemessen 4-6s Cold-Start). Wir importieren deshalb
ausschliesslich ``app.config`` (pydantic-settings) plus eine schlanke
``sqlalchemy``-Connection und lesen die Spalte per Raw-SQL.

Heartbeat-Cadence im Worker ist ``HEARTBEAT_INTERVAL_SEC = 10`` (siehe
``app.workers.llm_worker``). Der Schwellwert hier ist mit 30s deutlich
groesser — zwei verpasste Schreibvorgaenge gelten noch als gesund,
erst der dritte loest unhealthy aus.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import Connection, create_engine, text

from app.config import load_settings

HEARTBEAT_MAX_AGE_SEC: int = 30


def _is_alive(heartbeat_at: datetime | None, now: datetime, max_age_sec: int) -> bool:
    """Reine Heartbeat-Alter-Entscheidung.

    Returns ``True`` wenn ``heartbeat_at`` nicht ``None`` ist und nicht
    aelter als ``max_age_sec`` Sekunden gegenueber ``now``. Tz-naive
    Heartbeats werden defensiv als UTC interpretiert (Migration/Backfill-
    Edge-Case).
    """
    if heartbeat_at is None:
        return False
    if heartbeat_at.tzinfo is None:
        heartbeat_at = heartbeat_at.replace(tzinfo=UTC)
    age = now - heartbeat_at
    return age <= timedelta(seconds=max_age_sec)


def _open_connection() -> Connection:
    """Baut eine kurzlebige DB-Connection.

    Eigene Funktion damit Tests sie patchen koennen (`patch.object`).
    `pool_pre_ping=False` weil die Connection sofort genutzt wird —
    ein Ping waere zusaetzlicher Roundtrip ohne Nutzen.
    """
    cfg = load_settings()
    engine = create_engine(cfg.database_url, future=True, pool_pre_ping=False)
    return engine.connect()


def main() -> int:
    """Healthcheck-Hauptfunktion.

    Returns:
        ``0`` wenn der Worker-Heartbeat juenger als ``HEARTBEAT_MAX_AGE_SEC``
        Sekunden ist, sonst ``1``.
    """
    try:
        conn = _open_connection()
        try:
            row = conn.execute(
                text("SELECT llm_worker_heartbeat_at FROM settings WHERE id = 1")
            ).first()
        finally:
            conn.close()
    except Exception as exc:  # defensiv — DB nicht erreichbar etc.
        print(f"healthcheck: db_error {type(exc).__name__}", file=sys.stderr)
        return 1

    hb = row[0] if row is not None else None
    if hb is None:
        print("healthcheck: no_heartbeat_yet", file=sys.stderr)
        return 1

    now = datetime.now(tz=UTC)
    if not _is_alive(hb, now, HEARTBEAT_MAX_AGE_SEC):
        # Defensiv auf UTC anheben fuer das Log-Format — _is_alive selbst
        # ist tz-tolerant.
        hb_aware = hb if hb.tzinfo is not None else hb.replace(tzinfo=UTC)
        age = now - hb_aware
        print(
            f"healthcheck: heartbeat_stale age_sec={age.total_seconds():.0f}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
