# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Sysline-Context-Service (Block W Phase F, ADR-0036).

Baut den Status-Dict fuer die ``sysline``-Sektion des Dashboards:
  - ``last_scan_ago``    : humanisierte Zeit seit dem letzten Scan aller Server.
  - ``epss_feed_status`` : "synced" / "stale" / "never".
  - ``kev_feed_status``  : "synced" / "stale" / "never".
  - ``worker_status``    : "healthy" / "down" / None (wenn LLM-Mode == 'off').

Pure-Unit-testbar: ``build_sysline_context`` akzeptiert einen optionalen
``_now``-Parameter. Tests koennen eine feste ``datetime`` uebergeben statt
``datetime.now(UTC)`` aufzurufen.

Alle DB-Zugriffe gehen ausschliesslich ueber ORM-Selects (kein ``text()``
ohne Bind-Parameter). Ergebnis-Dict ist immer vollstaendig (alle 4 Keys
vorhanden, niemals KeyError im Template).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import FeedPullLog, Server, Setting

# Schwellwerte
_STALE_HOURS = 24  # Feed gilt als "stale" wenn letzter Success > 24h alt
_WORKER_ALIVE_SECONDS = 30  # Worker gilt als "healthy" wenn Heartbeat < 30s alt


def _humanize_scan_ago(delta_seconds: float) -> str:
    """Formatiere eine Sekunden-Differenz als kurze Englisch-Phrase.

    Schwellen gemaess Block-Spec:
      < 3600 s  (1h)  ->  "Nm"
      < 86400 s (24h) ->  "Nh"
      sonst           ->  "Nd"
    """
    if delta_seconds < 3600:
        minutes = max(1, int(delta_seconds // 60))
        return f"{minutes}m"
    if delta_seconds < 86400:
        hours = max(1, int(delta_seconds // 3600))
        return f"{hours}h"
    days = max(1, int(delta_seconds // 86400))
    return f"{days}d"


def _feed_status(
    sess: Session,
    feed_name: str,
    now: datetime,
    stale_threshold: timedelta,
) -> str:
    """Liefert 'synced' | 'stale' | 'never' fuer einen Feed.

    Sucht den juengsten erfolgreichen FeedPullLog-Eintrag fuer ``feed_name``.
    Ein Eintrag gilt als erfolgreich wenn ``status = 'success'`` und
    ``completed_at IS NOT NULL``.
    """
    stmt = select(func.max(FeedPullLog.completed_at)).where(
        FeedPullLog.feed_name == feed_name,
        FeedPullLog.status == "success",
        FeedPullLog.completed_at.is_not(None),
    )
    last_success: datetime | None = sess.execute(stmt).scalar()
    if last_success is None:
        return "never"
    if last_success.tzinfo is None:
        last_success = last_success.replace(tzinfo=UTC)
    if (now - last_success) < stale_threshold:
        return "synced"
    return "stale"


def build_sysline_context(
    sess: Session,
    *,
    _now: datetime | None = None,
) -> dict[str, Any]:
    """Baut den Sysline-Context-Dict.

    Liefert immer alle vier Schluessel:
      ``last_scan_ago``    : str | None
      ``epss_feed_status`` : "synced" | "stale" | "never"
      ``kev_feed_status``  : "synced" | "stale" | "never"
      ``worker_status``    : "healthy" | "down" | None

    Argumente:
      sess  -- aktive SQLAlchemy-Session.
      _now  -- Zeitbasis fuer Alters-Berechnungen. Wenn None wird
               ``datetime.now(UTC)`` verwendet. Nur fuer Tests.
    """
    now = _now if _now is not None else datetime.now(tz=UTC)
    stale_threshold = timedelta(hours=_STALE_HOURS)

    # --- last_scan_ago ---------------------------------------------------------
    last_scan_stmt = select(func.max(Server.last_scan_at))
    last_scan_at: datetime | None = sess.execute(last_scan_stmt).scalar()

    last_scan_ago: str | None = None
    if last_scan_at is not None:
        if last_scan_at.tzinfo is None:
            last_scan_at = last_scan_at.replace(tzinfo=UTC)
        delta_seconds = (now - last_scan_at).total_seconds()
        if delta_seconds >= 0:
            last_scan_ago = _humanize_scan_ago(delta_seconds)
        # Wenn delta negativ (Clock-Skew): last_scan_ago bleibt None.

    # --- Feed-Status -----------------------------------------------------------
    epss_status = _feed_status(sess, "epss", now, stale_threshold)
    kev_status = _feed_status(sess, "cisa_kev", now, stale_threshold)

    # --- Worker-Status ---------------------------------------------------------
    # Settings-Singleton laden (id = 1).
    settings_stmt = select(Setting).where(Setting.id == 1)
    setting: Setting | None = sess.execute(settings_stmt).scalar_one_or_none()

    worker_status: str | None = None
    if setting is not None:
        llm_mode = setting.block_p_llm_mode or "off"
        if llm_mode != "off":
            heartbeat = setting.llm_worker_heartbeat_at
            if heartbeat is None:
                worker_status = "down"
            else:
                if heartbeat.tzinfo is None:
                    heartbeat = heartbeat.replace(tzinfo=UTC)
                age = (now - heartbeat).total_seconds()
                worker_status = "healthy" if age < _WORKER_ALIVE_SECONDS else "down"
        # llm_mode == 'off' -> worker_status bleibt None

    return {
        "last_scan_ago": last_scan_ago,
        "epss_feed_status": epss_status,
        "kev_feed_status": kev_status,
        "worker_status": worker_status,
    }


__all__ = ["build_sysline_context"]
