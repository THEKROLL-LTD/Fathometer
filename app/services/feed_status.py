# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Read-Side-Service fuer den Feed-Status (Block Q Phase 4, ADR-0024).

Liefert pro Feed (``epss``, ``cisa_kev``) den letzten erfolgreichen Pull
und ob er stale ist (>7 Tage alt). Wird von der LLM-Settings-View
genutzt um die Two-Liner-Anzeige zu rendern (siehe ADR-0024
§"Feed-Freshness-Anzeige im UI").
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.models import FeedPullLog

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


# Stale-Threshold laut ADR-0024 §"Geklaerte Design-Entscheidungen" Punkt 5.
STALE_THRESHOLD_DAYS: int = 7

# Feeds die wir kennen — Reihenfolge bestimmt UI-Render-Reihenfolge.
KNOWN_FEEDS: tuple[str, ...] = ("epss", "cisa_kev")


@dataclass(frozen=True, slots=True)
class FeedStatus:
    """Status-Snapshot eines einzelnen Feeds.

    ``last_pull_started_at`` ist der juengste Pull-Versuch jeglichen
    Status. ``last_success_at`` und die anderen ``*_at_last_success``-
    Felder beziehen sich auf den juengsten ``success``-Pull.
    """

    feed_name: str
    last_success_at: datetime | None
    last_success_row_count: int | None
    last_attempt_at: datetime | None
    last_attempt_status: str | None  # 'running' | 'success' | 'failed' | None
    last_attempt_error: str | None
    is_stale: bool


def _newest_log(
    session: Session, feed_name: str, *, status: str | None = None
) -> FeedPullLog | None:
    """Holt den juengsten ``feed_pull_log``-Eintrag pro Feed (optional Status-Filter)."""
    stmt = select(FeedPullLog).where(FeedPullLog.feed_name == feed_name)
    if status is not None:
        stmt = stmt.where(FeedPullLog.status == status)
    stmt = stmt.order_by(FeedPullLog.started_at.desc()).limit(1)
    return session.execute(stmt).scalar_one_or_none()


def get_feed_status(session: Session, feed_name: str, *, now: datetime | None = None) -> FeedStatus:
    """Liefert den Status eines einzelnen Feeds."""
    now = now or datetime.now(UTC)

    last_success = _newest_log(session, feed_name, status="success")
    last_attempt = _newest_log(session, feed_name)

    success_ts = last_success.completed_at or last_success.started_at if last_success else None
    is_stale = success_ts is None or (now - success_ts) > timedelta(days=STALE_THRESHOLD_DAYS)

    return FeedStatus(
        feed_name=feed_name,
        last_success_at=success_ts,
        last_success_row_count=last_success.row_count if last_success else None,
        last_attempt_at=last_attempt.started_at if last_attempt else None,
        last_attempt_status=last_attempt.status if last_attempt else None,
        last_attempt_error=last_attempt.error_message if last_attempt else None,
        is_stale=is_stale,
    )


def get_all_feed_statuses(session: Session, *, now: datetime | None = None) -> list[FeedStatus]:
    """Liefert die Status-Snapshots fuer alle bekannten Feeds in stabiler Reihenfolge."""
    return [get_feed_status(session, name, now=now) for name in KNOWN_FEEDS]


__all__ = [
    "KNOWN_FEEDS",
    "STALE_THRESHOLD_DAYS",
    "FeedStatus",
    "get_all_feed_statuses",
    "get_feed_status",
]
