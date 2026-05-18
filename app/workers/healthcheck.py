"""Healthcheck-Skript fuer den ``secscan-llm-worker``-Container.

Wird vom ``docker-compose``-``healthcheck.test``-Eintrag aufgerufen
(``python -m app.workers.healthcheck``). Liest die Singleton-``settings``-
Zeile aus der DB, prueft das Alter von ``llm_worker_heartbeat_at`` gegen
einen festen Schwellwert (``HEARTBEAT_MAX_AGE_SEC``) und beendet sich mit
``exit(0)`` (healthy) oder ``exit(1)`` (unhealthy).

**Wichtige Eigenschaften:**

* Kein Flask-App-Context — der Worker-Container hat keine eingehenden
  HTTP-Ports (ARCHITECTURE.md §9). Der Check ist ein reiner DB-Read.
* Wiederverwendung der Worker-Session-Factory aus
  ``app.workers.llm_worker`` — damit nutzen Healthcheck und Worker
  exakt dieselbe Engine-Konfiguration (``SECSCAN_DATABASE_URL``).
* Defensiv: jede unerwartete Exception wird als unhealthy
  (``exit(1)``) gewertet und kurz nach STDERR geloggt — der Worker
  selbst hat sein eigenes Logging, hier reicht ein knapper One-Liner.

Heartbeat-Cadence im Worker ist ``HEARTBEAT_INTERVAL_SEC = 10`` (siehe
``app.workers.llm_worker``). Der Schwellwert hier ist mit 30s deutlich
groesser — zwei verpasste Schreibvorgaenge gelten noch als gesund,
erst der dritte loest unhealthy aus. Compose-Retries (3 x 30s)
multiplizieren sich darauf; ein toter Worker wird also erst nach
ca. 120-150s als unhealthy markiert. Das ist akzeptabel — der
Stale-Reaper im Worker selbst arbeitet ohnehin auf einer feineren
Zeitachse.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta

from app.settings_service import ensure_settings_row
from app.workers.llm_worker import get_session

# Worker schreibt alle 10s einen Heartbeat (HEARTBEAT_INTERVAL_SEC im Worker).
# 30s erlaubt zwei verpasste Schreibvorgaenge — der dritte gilt als unhealthy.
HEARTBEAT_MAX_AGE_SEC: int = 30


def main() -> int:
    """Healthcheck-Hauptfunktion.

    Returns:
        ``0`` wenn der Worker-Heartbeat juenger als ``HEARTBEAT_MAX_AGE_SEC``
        Sekunden ist, sonst ``1``.
    """
    try:
        with get_session() as session:
            row = ensure_settings_row(session)
            hb = row.llm_worker_heartbeat_at
    except Exception as exc:  # defensiv — DB nicht erreichbar etc.
        print(f"healthcheck: db_error {type(exc).__name__}", file=sys.stderr)
        return 1

    if hb is None:
        print("healthcheck: no_heartbeat_yet", file=sys.stderr)
        return 1

    # Tz-naive Werte koennen aus aelteren Migrationen kommen — defensiv
    # auf UTC anheben, damit der subtract nicht crasht.
    if hb.tzinfo is None:
        hb = hb.replace(tzinfo=UTC)

    age = datetime.now(tz=UTC) - hb
    if age > timedelta(seconds=HEARTBEAT_MAX_AGE_SEC):
        print(
            f"healthcheck: heartbeat_stale age_sec={age.total_seconds():.0f}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
