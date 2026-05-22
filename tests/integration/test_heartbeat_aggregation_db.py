"""Integration-Smokes fuer `app/services/heartbeat_aggregation.py` gegen echte
Postgres-DB.

Diese Tests wurden aus `tests/services/test_heartbeat_aggregation.py`
ausgelagert (TICKET-004, Slice 3). Die Pure-Aggregation
(`_aggregate_one_server`) ist DB-frei testbar; hier verbleibt der
End-to-End-Round-Trip fuer `heartbeat_for_server` / `heartbeats_for_servers`
plus der Performance-Sanity-Test.

Auto-Markierung als `db_integration` (und damit `acceptance`) erfolgt
ueber `tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES`.
"""

from __future__ import annotations

import time
from datetime import UTC, date, datetime, timedelta

from flask import Flask

from app.db import get_session_factory
from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Scan,
    Server,
    Severity,
)
from app.services.heartbeat_aggregation import (
    heartbeat_for_server,
    heartbeats_for_servers,
)

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


def _create_server(app: Flask, name: str = "hb-srv") -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _create_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    severity: Severity,
    first_seen_at: datetime,
    resolved_at: datetime | None = None,
    is_kev: bool = False,
    package_name: str = "pkg",
    status: FindingStatus = FindingStatus.OPEN,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key=identifier_key,
                package_name=package_name,
                installed_version="1.0",
                severity=severity,
                status=status,
                is_kev=is_kev,
                first_seen_at=first_seen_at,
                last_seen_at=first_seen_at,
                resolved_at=resolved_at,
                attack_vector=AttackVector.UNKNOWN,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def _create_scan(app: Flask, *, server_id: int, received_at: datetime) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            s = Scan(server_id=server_id, received_at=received_at)
            sess.add(s)
            sess.flush()
            sid = s.id
            sess.commit()
            return sid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Round-Trip-Smokes
# ---------------------------------------------------------------------------


def test_heartbeat_for_server_round_trip_db_load(db_app: Flask) -> None:
    """End-to-end: Wrapper laedt Findings+Scans und delegiert an Pure-Aggregator."""
    sid = _create_server(db_app, name="db-hb-1")
    fseen = FIXED_NOW - timedelta(days=2)
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="DB-HB-1",
        severity=Severity.HIGH,
        first_seen_at=fseen,
        is_kev=True,
    )
    _create_scan(db_app, server_id=sid, received_at=fseen)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            cells = heartbeat_for_server(sess, sid, days=5, now=FIXED_NOW)
        finally:
            sess.close()
    assert len(cells) == 5
    assert cells[-1].day == date(2026, 5, 15)
    assert cells[-1].max_severity == Severity.HIGH
    assert cells[-1].kev_count == 1
    # Tag der first_seen muss had_scan=True haben.
    by_day = {c.day: c for c in cells}
    assert by_day[fseen.date()].had_scan is True


def test_heartbeats_for_servers_batch_round_trip(db_app: Flask) -> None:
    """Batch-Variante liefert Dict mit allen IDs, auch fuer Server ohne Daten."""
    sid_a = _create_server(db_app, name="batch-a")
    sid_b = _create_server(db_app, name="batch-b")
    sid_c = _create_server(db_app, name="batch-c")
    _create_finding(
        db_app,
        server_id=sid_a,
        identifier_key="CVE-BATCH",
        severity=Severity.MEDIUM,
        first_seen_at=FIXED_NOW - timedelta(days=2),
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = heartbeats_for_servers(sess, [sid_a, sid_b, sid_c], days=10, now=FIXED_NOW)
        finally:
            sess.close()
    assert set(out.keys()) == {sid_a, sid_b, sid_c}
    assert all(len(cells) == 10 for cells in out.values())
    for sid in (sid_b, sid_c):
        assert all(c.max_severity is None for c in out[sid]), out[sid]
    assert out[sid_a][-1].max_severity == Severity.MEDIUM


def test_heartbeats_for_servers_empty_list_returns_empty_dict(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = heartbeats_for_servers(sess, [], days=5, now=FIXED_NOW)
        finally:
            sess.close()
    assert out == {}


# ---------------------------------------------------------------------------
# Performance-Sanity
# ---------------------------------------------------------------------------


def test_performance_50_servers_50_days_under_200ms(db_app: Flask) -> None:
    """Sanity-Check: Batch-Heartbeat fuer 50 Server x 50 Tage in <200ms."""
    sids: list[int] = []
    base = FIXED_NOW - timedelta(days=10)
    for i in range(50):
        sid = _create_server(db_app, name=f"perf-srv-{i:02d}")
        sids.append(sid)
        _create_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-PERF-A-{i}",
            severity=Severity.HIGH,
            first_seen_at=base,
            package_name=f"pkg-a-{i}",
        )
        _create_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-PERF-B-{i}",
            severity=Severity.MEDIUM,
            first_seen_at=base,
            is_kev=True,
            package_name=f"pkg-b-{i}",
        )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            t0 = time.perf_counter()
            out = heartbeats_for_servers(sess, sids, days=50, now=FIXED_NOW)
            elapsed = time.perf_counter() - t0
        finally:
            sess.close()
    assert len(out) == 50
    assert elapsed < 0.2, f"Heartbeat-Aggregation zu langsam: {elapsed * 1000:.1f}ms"
