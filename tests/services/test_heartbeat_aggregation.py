"""Tests fuer den Heartbeat-Aggregations-Service (Block I).

Deckt:
  * Tag-Liste-Form (`days` Eintraege, aelteste zuerst, today zuletzt).
  * Server ohne Findings/Scans -> alle Cells leer (`max_severity=None`).
  * Hoechste Severity pro Tag.
  * KEV-Counter unabhaengig von `max_severity`.
  * Carry-Forward an Tagen ohne Scan (Finding bleibt offen).
  * Resolved-Findings verschwinden ab `resolved_at`-Tag.
  * `heartbeats_for_servers` Batch liefert dict mit allen Server-IDs.
  * `now`-Injection (Test-Determinismus).
  * Performance: 50 Server x 50 Tage <200ms.
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
    DailyStatus,
    heartbeat_for_server,
    heartbeats_for_servers,
)

# ---------------------------------------------------------------------------
# Setup-Helpers
# ---------------------------------------------------------------------------

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
# Tag-Liste / leerer Server
# ---------------------------------------------------------------------------


def test_heartbeat_returns_days_cells_for_server_without_findings(db_app: Flask) -> None:
    sid = _create_server(db_app, name="empty-srv")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            cells = heartbeat_for_server(sess, sid, days=50, now=FIXED_NOW)
        finally:
            sess.close()

    assert len(cells) == 50, f"erwartet 50 Cells, bekommen {len(cells)}"
    # Aelteste zuerst, heute zuletzt.
    assert cells[0].day == date(2026, 5, 15) - timedelta(days=49)
    assert cells[-1].day == date(2026, 5, 15)
    for c in cells:
        assert c.max_severity is None, c
        assert c.kev_count == 0, c
        assert c.had_scan is False, c


def test_heartbeat_for_server_returns_dailystatus_instances(db_app: Flask) -> None:
    sid = _create_server(db_app, name="type-check-srv")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            cells = heartbeat_for_server(sess, sid, days=3, now=FIXED_NOW)
        finally:
            sess.close()
    assert all(isinstance(c, DailyStatus) for c in cells), cells


# ---------------------------------------------------------------------------
# Hoechste Severity pro Tag
# ---------------------------------------------------------------------------


def test_max_severity_picked_per_day(db_app: Flask) -> None:
    """Vier Findings unterschiedlicher Severity -> CRITICAL ist max."""
    sid = _create_server(db_app, name="max-sev-srv")
    base = FIXED_NOW - timedelta(days=5)
    for ik, sev in [
        ("CVE-LOW", Severity.LOW),
        ("CVE-MED", Severity.MEDIUM),
        ("CVE-HIGH", Severity.HIGH),
        ("CVE-CRIT", Severity.CRITICAL),
    ]:
        _create_finding(
            db_app,
            server_id=sid,
            identifier_key=ik,
            severity=sev,
            first_seen_at=base,
            package_name=f"pkg-{ik}",
        )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            cells = heartbeat_for_server(sess, sid, days=10, now=FIXED_NOW)
        finally:
            sess.close()

    # Alle Tage ab Tag-5 vor heute (inkl. heute) muessen max=CRITICAL haben.
    today = FIXED_NOW.date()
    for c in cells:
        if c.day >= base.date():
            assert c.max_severity == Severity.CRITICAL, (c.day, c)
        else:
            assert c.max_severity is None, c
    assert cells[-1].day == today


# ---------------------------------------------------------------------------
# KEV-Counter separat von max_severity
# ---------------------------------------------------------------------------


def test_kev_count_independent_of_max_severity(db_app: Flask) -> None:
    """KEV-Finding mit LOW-Severity erhoeht kev_count, beeinflusst aber
    `max_severity` nur entsprechend seiner Severity."""
    sid = _create_server(db_app, name="kev-srv")
    base = FIXED_NOW - timedelta(days=3)
    # 1 KEV-Finding LOW + 1 Nicht-KEV HIGH
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-KEV-LOW",
        severity=Severity.LOW,
        first_seen_at=base,
        is_kev=True,
        package_name="pkg-kev",
    )
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-NONKEV-HIGH",
        severity=Severity.HIGH,
        first_seen_at=base,
        package_name="pkg-high",
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            cells = heartbeat_for_server(sess, sid, days=5, now=FIXED_NOW)
        finally:
            sess.close()

    # An den Tagen ab `base` muss max=HIGH und kev_count=1 sein.
    for c in cells:
        if c.day >= base.date():
            assert c.max_severity == Severity.HIGH, c
            assert c.kev_count == 1, c
        else:
            assert c.max_severity is None
            assert c.kev_count == 0


# ---------------------------------------------------------------------------
# had_scan / Carry-Forward
# ---------------------------------------------------------------------------


def test_carry_forward_on_days_without_scan(db_app: Flask) -> None:
    """Finding bleibt an Tagen ohne Scan offen -> max_severity weiterhin gesetzt."""
    sid = _create_server(db_app, name="carry-srv")
    fseen = FIXED_NOW - timedelta(days=4)
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-CARRY",
        severity=Severity.HIGH,
        first_seen_at=fseen,
        package_name="pkg",
    )
    # Nur ein Scan am Tag von first_seen.
    _create_scan(db_app, server_id=sid, received_at=fseen)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            cells = heartbeat_for_server(sess, sid, days=6, now=FIXED_NOW)
        finally:
            sess.close()

    by_day = {c.day: c for c in cells}
    scan_day = fseen.date()
    assert by_day[scan_day].had_scan is True
    assert by_day[scan_day].max_severity == Severity.HIGH

    # Folgetage haben keinen Scan, aber das Finding ist weiter offen.
    for offset in range(1, 4):
        d = scan_day + timedelta(days=offset)
        c = by_day[d]
        assert c.had_scan is False, c
        assert c.max_severity == Severity.HIGH, c


# ---------------------------------------------------------------------------
# Resolved Findings tauchen ab resolved_at-Tag nicht mehr in max_severity auf
# ---------------------------------------------------------------------------


def test_resolved_finding_drops_out_after_resolved_at(db_app: Flask) -> None:
    sid = _create_server(db_app, name="resolved-srv")
    fseen = FIXED_NOW - timedelta(days=4)
    resolved = FIXED_NOW - timedelta(days=2)
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-RES",
        severity=Severity.CRITICAL,
        first_seen_at=fseen,
        resolved_at=resolved,
        status=FindingStatus.RESOLVED,
        package_name="pkg",
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            cells = heartbeat_for_server(sess, sid, days=6, now=FIXED_NOW)
        finally:
            sess.close()

    by_day = {c.day: c for c in cells}
    # An Tagen vor `resolved.date()` war das Finding offen.
    day_before = resolved.date() - timedelta(days=1)
    assert by_day[day_before].max_severity == Severity.CRITICAL
    assert by_day[fseen.date()].max_severity == Severity.CRITICAL
    # An `resolved.date()` ist `resolved (12:00) <= end_of_day (23:59:59)` -
    # das Finding gilt bereits als resolved -> max_severity zurueck auf None.
    assert by_day[resolved.date()].max_severity is None
    # Auch am Folgetag bleibt es weg.
    assert by_day[resolved.date() + timedelta(days=1)].max_severity is None


# ---------------------------------------------------------------------------
# Batch-Variante
# ---------------------------------------------------------------------------


def test_heartbeats_for_servers_returns_dict_with_all_ids(db_app: Flask) -> None:
    sid_a = _create_server(db_app, name="batch-a")
    sid_b = _create_server(db_app, name="batch-b")
    sid_c = _create_server(db_app, name="batch-c")
    # Nur sid_a hat ein Finding.
    _create_finding(
        db_app,
        server_id=sid_a,
        identifier_key="CVE-BATCH",
        severity=Severity.MEDIUM,
        first_seen_at=FIXED_NOW - timedelta(days=2),
        package_name="pkg",
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
    # Server b/c haben in jedem Cell None.
    for sid in (sid_b, sid_c):
        assert all(c.max_severity is None for c in out[sid]), out[sid]
    # Server a hat MEDIUM ab Tag-2 vor heute.
    a_last = out[sid_a][-1]
    assert a_last.max_severity == Severity.MEDIUM


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
# `now`-Injection
# ---------------------------------------------------------------------------


def test_now_parameter_pins_end_day(db_app: Flask) -> None:
    sid = _create_server(db_app, name="now-srv")
    factory = get_session_factory(db_app)
    pinned = datetime(2026, 5, 15, 0, 0, 0, tzinfo=UTC)
    with db_app.app_context():
        sess = factory()
        try:
            cells = heartbeat_for_server(sess, sid, days=3, now=pinned)
        finally:
            sess.close()
    assert cells[-1].day == date(2026, 5, 15)
    assert cells[0].day == date(2026, 5, 13)


# ---------------------------------------------------------------------------
# Performance-Sanity: 50 Server x 50 Tage Aggregation unter 200ms
# ---------------------------------------------------------------------------


def test_performance_50_servers_50_days_under_200ms(db_app: Flask) -> None:
    """Sanity-Check: Batch-Heartbeat fuer 50 Server x 50 Tage in <200ms.

    Wir schaffen pro Server zwei Findings (eines davon KEV) — etwa der
    realistische MVP-Fuellstand. Falls die Aggregation O(n^2) waere, wuerde
    das hier sichtbar werden.
    """
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


# ---------------------------------------------------------------------------
# Acknowledged-Findings zaehlen weiter als "vorhanden"
# ---------------------------------------------------------------------------


def test_acknowledged_finding_still_counted(db_app: Flask) -> None:
    """Ein acknowledged Finding ist nach §7a noch nicht weg — die Heartbeat-
    Bar zeigt weiterhin die Severity (Frontend macht die Differenzierung)."""
    sid = _create_server(db_app, name="ack-srv")
    fseen = FIXED_NOW - timedelta(days=2)
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-ACK",
        severity=Severity.HIGH,
        first_seen_at=fseen,
        status=FindingStatus.ACKNOWLEDGED,
        package_name="pkg-ack",
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            cells = heartbeat_for_server(sess, sid, days=5, now=FIXED_NOW)
        finally:
            sess.close()
    assert cells[-1].max_severity == Severity.HIGH
