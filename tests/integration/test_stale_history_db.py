"""Integration-Smokes fuer `app/services/stale_history.py` gegen echte
Postgres-DB.

Diese Tests wurden aus `tests/services/test_stale_history.py` ausgelagert
(TICKET-004, Slice 3). Pure-Aggregation (`_compute_stale_counts`) ist DB-
frei testbar; hier verbleibt der End-to-End-Round-Trip plus der
Performance-Mini-Bench (`@bench`, default deselektiert).

Auto-Markierung als `db_integration` (und damit `acceptance`) erfolgt
ueber `tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES`.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from sqlalchemy import insert, select

from app.db import get_session_factory
from app.models import Scan, Server
from app.services.stale_history import daily_stale_server_counts

FIXED_NOW = datetime(2026, 5, 15, 12, 0, tzinfo=UTC)


def _add_server(
    app: Flask,
    *,
    name: str,
    interval_h: int = 24,
    created_at: datetime | None = None,
    retired_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=interval_h,
                retired_at=retired_at,
                revoked_at=revoked_at,
            )
            if created_at is not None:
                srv.created_at = created_at
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _add_scan(app: Flask, *, server_id: int, received_at: datetime) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            scan = Scan(server_id=server_id, received_at=received_at)
            sess.add(scan)
            sess.commit()
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Round-Trip-Smoke
# ---------------------------------------------------------------------------


def test_daily_stale_server_counts_round_trip_db_load(db_app: Flask) -> None:
    """End-to-end: Wrapper laedt Server+Scans und delegiert an Pure-Aggregator."""
    sid = _add_server(
        db_app,
        name="db-stale-mix",
        interval_h=24,
        created_at=FIXED_NOW - timedelta(days=100),
    )
    # Letzter Scan vor 50h -> stale (Schwelle 48h).
    _add_scan(db_app, server_id=sid, received_at=FIXED_NOW - timedelta(hours=50))

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_stale_server_counts(sess, days=50, now=FIXED_NOW)
        finally:
            sess.close()
    assert len(out) == 50
    # Heute: stale.
    assert out[-1] == 1


# ---------------------------------------------------------------------------
# Performance-Mini-Bench
# ---------------------------------------------------------------------------


@pytest.mark.bench
def test_bench_200_servers_50_days_under_100ms(db_app: Flask) -> None:
    """200 Server * 50 Tage < 100 ms (Block M, ADR-0020)."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.execute(
                insert(Server),
                [
                    {
                        "name": f"bench-srv-{i:03d}",
                        "api_key_hash": "x" * 64,
                        "expected_scan_interval_h": 24,
                    }
                    for i in range(200)
                ],
            )
            sess.commit()

            server_ids = list(sess.execute(select(Server.id)).scalars().all())
            scan_rows = []
            for sid in server_ids:
                for d in range(5):
                    scan_rows.append(
                        {
                            "server_id": sid,
                            "received_at": FIXED_NOW - timedelta(days=d * 7),
                        }
                    )
            sess.execute(insert(Scan), scan_rows)
            sess.commit()

            t0 = time.perf_counter()
            out = daily_stale_server_counts(sess, days=50, now=FIXED_NOW)
            elapsed = time.perf_counter() - t0
        finally:
            sess.close()

    assert len(out) == 50
    assert elapsed < 0.1, f"daily_stale_server_counts zu langsam: {elapsed:.3f}s (> 100 ms)"
