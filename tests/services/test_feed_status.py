"""Unit-Tests fuer ``feed_status`` (Block Q Phase 4, ADR-0024).

Read-Side-Service der den juengsten Pull pro Feed liefert und die
Stale-Schwelle (7 Tage) auswertet. Tests mit MagicMock-Session.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

from app.services.feed_status import (
    KNOWN_FEEDS,
    STALE_THRESHOLD_DAYS,
    FeedStatus,
    get_all_feed_statuses,
    get_feed_status,
)


def _log_stub(
    *,
    started_at: datetime,
    completed_at: datetime | None = None,
    status: str = "success",
    row_count: int | None = 100,
    error_message: str | None = None,
) -> Any:
    stub = MagicMock()
    stub.started_at = started_at
    stub.completed_at = completed_at
    stub.status = status
    stub.row_count = row_count
    stub.error_message = error_message
    return stub


def _session_with_logs(success: Any | None, latest: Any | None) -> MagicMock:
    """Baut MagicMock-Session, die in dieser Reihenfolge zurueckgibt:

    Service-Code ruft ``_newest_log(status='success')`` zuerst, dann
    ``_newest_log()`` ohne Filter — wir steuern beide Aufrufe ueber
    ``execute(...).scalar_one_or_none()`` mit ``side_effect``.
    """
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.side_effect = [success, latest]
    return session


def test_constants() -> None:
    assert STALE_THRESHOLD_DAYS == 7
    assert KNOWN_FEEDS == ("epss", "cisa_kev")


# ---------------------------------------------------------------------------
# Single feed status
# ---------------------------------------------------------------------------


def test_get_feed_status_fresh_success() -> None:
    now = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)
    log = _log_stub(
        started_at=now - timedelta(hours=2),
        completed_at=now - timedelta(hours=1),
        status="success",
        row_count=247_382,
    )
    session = _session_with_logs(success=log, latest=log)

    status = get_feed_status(session, "epss", now=now)

    assert status.feed_name == "epss"
    assert status.last_success_at == now - timedelta(hours=1)
    assert status.last_success_row_count == 247_382
    assert status.last_attempt_status == "success"
    assert status.last_attempt_error is None
    assert status.is_stale is False


def test_get_feed_status_stale_when_success_older_than_7_days() -> None:
    now = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)
    log = _log_stub(
        started_at=now - timedelta(days=8),
        completed_at=now - timedelta(days=8),
        status="success",
        row_count=247_000,
    )
    session = _session_with_logs(success=log, latest=log)

    status = get_feed_status(session, "epss", now=now)

    assert status.is_stale is True
    assert status.last_success_at == now - timedelta(days=8)


def test_get_feed_status_never_pulled() -> None:
    now = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)
    session = _session_with_logs(success=None, latest=None)

    status = get_feed_status(session, "epss", now=now)

    assert status.last_success_at is None
    assert status.last_success_row_count is None
    assert status.last_attempt_at is None
    assert status.last_attempt_status is None
    assert status.is_stale is True  # nie gepullt = stale


def test_get_feed_status_recent_failure_after_old_success() -> None:
    """Last attempt war fail, letzter erfolgreicher Pull liegt zurueck."""
    now = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)
    success = _log_stub(
        started_at=now - timedelta(days=2),
        completed_at=now - timedelta(days=2),
        status="success",
        row_count=247_000,
    )
    failure = _log_stub(
        started_at=now - timedelta(hours=2),
        completed_at=None,
        status="failed",
        row_count=None,
        error_message="HTTPStatusError: 503",
    )
    session = _session_with_logs(success=success, latest=failure)

    status = get_feed_status(session, "epss", now=now)

    assert status.last_success_at == now - timedelta(days=2)
    assert status.last_attempt_status == "failed"
    assert status.last_attempt_error == "HTTPStatusError: 503"
    assert status.is_stale is False  # Letzter Erfolg ist <7d alt


def test_get_feed_status_borderline_exactly_7_days_not_stale() -> None:
    now = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)
    log = _log_stub(
        started_at=now - timedelta(days=7),
        completed_at=now - timedelta(days=7),
        status="success",
    )
    session = _session_with_logs(success=log, latest=log)

    status = get_feed_status(session, "epss", now=now)

    # Genau 7 Tage = NICHT stale (Threshold ist >7).
    assert status.is_stale is False


def test_get_feed_status_uses_started_at_when_completed_at_missing() -> None:
    """Edge-Case: success-Log ohne completed_at — wir fallen auf started_at zurueck."""
    now = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)
    log = _log_stub(
        started_at=now - timedelta(hours=3),
        completed_at=None,
        status="success",
    )
    session = _session_with_logs(success=log, latest=log)

    status = get_feed_status(session, "epss", now=now)

    assert status.last_success_at == now - timedelta(hours=3)
    assert status.is_stale is False


# ---------------------------------------------------------------------------
# All-feeds bulk lookup
# ---------------------------------------------------------------------------


def test_get_all_feed_statuses_returns_list_in_known_order() -> None:
    now = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)
    epss_log = _log_stub(started_at=now, completed_at=now, status="success", row_count=1000)
    kev_log = _log_stub(started_at=now, completed_at=now, status="success", row_count=1500)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.side_effect = [
        epss_log,
        epss_log,
        kev_log,
        kev_log,
    ]

    statuses = get_all_feed_statuses(session, now=now)

    assert len(statuses) == 2
    assert statuses[0].feed_name == "epss"
    assert statuses[1].feed_name == "cisa_kev"
    assert statuses[0].last_success_row_count == 1000
    assert statuses[1].last_success_row_count == 1500


def test_feed_status_is_dataclass_frozen() -> None:
    s = FeedStatus(
        feed_name="epss",
        last_success_at=None,
        last_success_row_count=None,
        last_attempt_at=None,
        last_attempt_status=None,
        last_attempt_error=None,
        is_stale=True,
    )
    import dataclasses

    import pytest

    with pytest.raises(dataclasses.FrozenInstanceError):
        s.feed_name = "kev"  # type: ignore[misc]
