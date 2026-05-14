"""Stale-Detection-Helper fuer Dashboard und Server-Detail.

ARCHITECTURE.md §14:
- **Server-Stale**: `now() - last_scan_at > expected_scan_interval_h` (in
  Stunden). Wenn `last_scan_at` NULL ist (Server registriert, aber noch nie
  Scan empfangen), gilt der Server ebenfalls als stale.
- **Trivy-DB-Stale**: `now() - trivy_db_updated_at > stale_db_threshold_h`.
  Default 30h aus den Settings. Bei NULL: stale.

Beide Helfer sind reine Read-Only-Funktionen und schreiben nichts in die DB.
Der `now`-Parameter ist injizierbar, damit Tests deterministisch sein
koennen.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from app.settings_service import get_settings_row

if TYPE_CHECKING:
    from app.models import Server

# Fallback-Werte falls die Settings-Row nicht erreichbar ist. Entsprechen den
# Defaults aus der Migration / §14.
_FALLBACK_TRIVY_DB_STALE_H: int = 30
_FALLBACK_SERVER_STALE_H: int = 48


def _resolve_now(now: datetime | None) -> datetime:
    """Stellt sicher dass `now` ein tz-aware UTC-Wert ist."""
    if now is None:
        return datetime.now(tz=UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now


def _ensure_aware(value: datetime) -> datetime:
    """Naive datetimes als UTC interpretieren — defensive Behandlung."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def is_stale(server: Server, now: datetime | None = None) -> bool:
    """`True` wenn der Server als stale gilt.

    Stale-Kriterium:
    - `last_scan_at` ist NULL **und** der Server ist nicht retired
      (retired Server sollen nicht permanent in "Aufmerksamkeit noetig"
      auftauchen — sie sind absichtlich abgemeldet), **oder**
    - `now - last_scan_at > expected_scan_interval_h Stunden`.

    Revoked Server werden weiterhin als stale gewertet, sofern sie nicht
    auch retired sind — das ist ein gewollter Hinweis, dass der Key kaputt
    ist.
    """
    if server.retired_at is not None:
        return False

    current = _resolve_now(now)
    last = server.last_scan_at
    if last is None:
        return True

    threshold = timedelta(hours=server.expected_scan_interval_h)
    return (current - _ensure_aware(last)) > threshold


def is_db_stale(
    server: Server,
    now: datetime | None = None,
    threshold_h: int | None = None,
) -> bool:
    """`True` wenn die Trivy-DB des Servers als veraltet gilt.

    `threshold_h` ueberschreibt den Settings-Wert (vor allem fuer Tests).
    Ohne Override wird der Wert aus `settings.stale_trivy_db_threshold_h`
    gezogen; faellt das aus, wird auf `_FALLBACK_TRIVY_DB_STALE_H` (30h)
    zurueckgegriffen.

    Wie bei `is_stale` gilt: retired Server werden nicht angemeckert.
    """
    if server.retired_at is not None:
        return False

    effective_h = threshold_h if threshold_h is not None else _load_db_threshold_h()
    current = _resolve_now(now)
    updated = server.trivy_db_updated_at
    if updated is None:
        return True

    return (current - _ensure_aware(updated)) > timedelta(hours=effective_h)


def get_db_stale_threshold_h() -> int:
    """Public-Helper: liefert die aktuelle DB-Stale-Schwelle in Stunden.

    Wird vom Template gebraucht, falls dort eigene `is_older_than_h`-
    Aufrufe noetig sind (Konsistenz zwischen View-Logik und Anzeige).
    """
    return _load_db_threshold_h()


def get_server_stale_default_h() -> int:
    """Liefert den globalen Server-Stale-Default aus den Settings."""
    try:
        row = get_settings_row()
    except Exception:  # pragma: no cover — DB-down edge case
        return _FALLBACK_SERVER_STALE_H
    return int(row.stale_threshold_h or _FALLBACK_SERVER_STALE_H)


def _load_db_threshold_h() -> int:
    try:
        row = get_settings_row()
    except Exception:  # pragma: no cover — DB-down edge case
        return _FALLBACK_TRIVY_DB_STALE_H
    return int(row.stale_trivy_db_threshold_h or _FALLBACK_TRIVY_DB_STALE_H)


__all__ = [
    "get_db_stale_threshold_h",
    "get_server_stale_default_h",
    "is_db_stale",
    "is_stale",
]
