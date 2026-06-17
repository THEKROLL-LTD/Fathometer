"""TICKET-018 (d) — `_load_last_failed_ingest` pure-unit query-logic tests.

`server_detail._load_last_failed_ingest(sess, server)` surfaces the newest
``scan_ingest_jobs`` row with ``status='failed'`` that finished AFTER the
server's last successful scan (``Server.last_scan_at``) — a still-unresolved
failure. It then reads the ``error_class`` from the matching
``scan.ingest_failed`` audit event metadata.

These tests exercise the post-query branching (None-vs-dict, supersession,
error_class extraction) with a fake session that returns canned ``.first()``
rows in call order — no real DB. The SQL itself is exercised separately by the
db_integration suite (forbidden here); this covers the Python decision logic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

from app.models import Server
from app.views.server_detail import _load_last_failed_ingest


class _FakeResult:
    """Stand-in for a SQLAlchemy Result; `.first()` returns a preset row."""

    def __init__(self, row: Any) -> None:
        self._row = row

    def first(self) -> Any:
        return self._row


class _FakeSession:
    """Returns queued `_FakeResult`s in order for successive `execute()` calls."""

    def __init__(self, rows: list[Any]) -> None:
        self._rows = list(rows)
        self.execute_count = 0

    def execute(self, _stmt: Any) -> _FakeResult:
        row = self._rows[self.execute_count] if self.execute_count < len(self._rows) else None
        self.execute_count += 1
        return _FakeResult(row)


def _server(*, last_scan_at: datetime | None) -> Server:
    """A duck-typed Server stub — `_load_last_failed_ingest` reads only `.id`
    and `.last_scan_at`, so a SimpleNamespace satisfies the runtime contract."""
    return cast("Server", SimpleNamespace(id=7, last_scan_at=last_scan_at))


def _job_row(job_id: int, finished_at: datetime | None) -> SimpleNamespace:
    return SimpleNamespace(id=job_id, finished_at=finished_at)


def _audit_row(metadata: Any) -> SimpleNamespace:
    return SimpleNamespace(event_metadata=metadata)


_FAILED_AT = datetime(2026, 6, 17, 12, 0, tzinfo=UTC)


def test_returns_dict_when_failure_is_newer_than_last_scan() -> None:
    """A failed job finished after the last successful scan -> banner data."""
    sess = _FakeSession(
        [
            _job_row(27, _FAILED_AT),
            _audit_row({"error_class": "validation_error"}),
        ]
    )
    server = _server(last_scan_at=datetime(2026, 6, 16, 0, 0, tzinfo=UTC))

    result = _load_last_failed_ingest(sess, server)

    assert result is not None
    assert result["job_id"] == 27
    assert result["failed_at"] == _FAILED_AT
    assert result["error_class"] == "validation_error"


def test_returns_dict_when_no_prior_successful_scan() -> None:
    """No `last_scan_at` (server never ingested) -> failure is surfaced."""
    sess = _FakeSession(
        [
            _job_row(5, _FAILED_AT),
            _audit_row({"error_class": "host_state_parse_failed"}),
        ]
    )
    server = _server(last_scan_at=None)

    result = _load_last_failed_ingest(sess, server)

    assert result is not None
    assert result["job_id"] == 5
    assert result["error_class"] == "host_state_parse_failed"


def test_returns_none_when_no_failed_job() -> None:
    """No failed job row at all -> None (banner hidden)."""
    sess = _FakeSession([None])
    server = _server(last_scan_at=None)

    assert _load_last_failed_ingest(sess, server) is None


def test_returns_none_when_failure_superseded_by_newer_scan() -> None:
    """A failure older than (or equal to) the last successful scan is resolved."""
    sess = _FakeSession([_job_row(27, _FAILED_AT)])
    # Last successful scan is NEWER than the failure -> superseded.
    server = _server(last_scan_at=datetime(2026, 6, 18, 0, 0, tzinfo=UTC))

    assert _load_last_failed_ingest(sess, server) is None


def test_returns_none_when_failure_equals_last_scan() -> None:
    """Boundary: failed_at == last_scan_at counts as superseded (<=)."""
    sess = _FakeSession([_job_row(27, _FAILED_AT)])
    server = _server(last_scan_at=_FAILED_AT)

    assert _load_last_failed_ingest(sess, server) is None


def test_error_class_none_when_no_audit_event() -> None:
    """A failure with no matching audit event -> dict with error_class=None."""
    sess = _FakeSession([_job_row(9, _FAILED_AT), None])
    server = _server(last_scan_at=None)

    result = _load_last_failed_ingest(sess, server)

    assert result is not None
    assert result["job_id"] == 9
    assert result["error_class"] is None


def test_error_class_none_when_metadata_not_a_dict() -> None:
    """Defensive: non-dict audit metadata yields error_class=None, not a crash."""
    sess = _FakeSession([_job_row(9, _FAILED_AT), _audit_row("not-a-dict")])
    server = _server(last_scan_at=None)

    result = _load_last_failed_ingest(sess, server)

    assert result is not None
    assert result["error_class"] is None


def test_error_class_none_when_metadata_value_not_a_string() -> None:
    """A non-string `error_class` in metadata is ignored (defensive typing)."""
    sess = _FakeSession([_job_row(9, _FAILED_AT), _audit_row({"error_class": 123})])
    server = _server(last_scan_at=None)

    result = _load_last_failed_ingest(sess, server)

    assert result is not None
    assert result["error_class"] is None
