# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Semver-Vergleichs-Helper fuer Agent-/Trivy-Versions-Indikatoren.

ADR-0021 (Block N) fuehrt UI-Pills fuer veraltete Agents, veraltete Trivy-
Binaries und veraltete Trivy-DBs ein. Die Heuristik fuer "veraltet" lebt
hier zentral, damit sowohl Server-Detail als auch Sidebar denselben Check
benutzen.

Wichtige Heuristik (siehe Block-Brief Task #2):
- `version_lt(None, X)` ist `True` — eine unbekannte Agent-Version wird
  konservativ als "update required" behandelt.
- `version_lt("nonsense", X)` ist `True` — gleiche Heuristik fuer
  unparsebare Strings.
- `version_lt(a, None)` ist `False` — ohne Referenz keine Vergleichbarkeit.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from packaging.version import InvalidVersion, Version

from app.config import Settings

if TYPE_CHECKING:
    from app.models import Server


def version_lt(a: str | None, b: str | None) -> bool:
    """`True` wenn ``a`` semantisch kleiner als ``b`` ist.

    None oder unparsebare Strings auf der linken Seite gelten als "unbekannt"
    und damit als "veraltet". Auf der rechten Seite hat None den Effekt
    "keine Referenz, kein Vergleich".
    """
    if b is None:
        return False
    if a is None:
        return True
    try:
        return Version(a) < Version(b)
    except InvalidVersion:
        return True


def is_agent_outdated(server: Server) -> bool:
    """`True` wenn der Server eine Agent-Version unter `MIN_AGENT_VERSION` meldet."""
    return version_lt(server.agent_version, Settings.MIN_AGENT_VERSION)


def is_trivy_outdated(server: Server) -> bool:
    """`True` wenn die zuletzt beobachtete Trivy-Version unter `MIN_TRIVY_VERSION` liegt."""
    return version_lt(server.trivy_version, Settings.MIN_TRIVY_VERSION)


def is_trivy_db_outdated(server: Server, *, now: datetime | None = None) -> bool:
    """`True` wenn die Trivy-DB aelter als `TRIVY_DB_STALE_THRESHOLD_DAYS` ist.

    Wenn `trivy_db_updated_at` `None` ist, gilt das ebenfalls als veraltet —
    wir haben in dem Fall ja keinerlei Beleg dafuer, dass die DB jung ist.
    """
    if server.trivy_db_updated_at is None:
        return True
    current = now or datetime.now(tz=UTC)
    db_ts = server.trivy_db_updated_at
    if db_ts.tzinfo is None:
        db_ts = db_ts.replace(tzinfo=UTC)
    threshold = timedelta(days=Settings.TRIVY_DB_STALE_THRESHOLD_DAYS)
    return (current - db_ts) > threshold


__all__ = [
    "is_agent_outdated",
    "is_trivy_db_outdated",
    "is_trivy_outdated",
    "version_lt",
]
