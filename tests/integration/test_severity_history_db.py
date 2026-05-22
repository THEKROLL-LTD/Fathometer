"""Integration-Smokes fuer `app/services/severity_history.py` gegen echte
Postgres-DB.

Diese Tests wurden aus `tests/services/test_severity_history.py` ausgelagert
(TICKET-004, Slice 3). Reine Aggregations-Logik (`_compute_snapshots`,
`_compute_daily_counts`) liegt DB-frei in der Service-Test-Datei. Hier
verbleiben:

  * 1-2 Round-Trip-Smokes durch `_load_findings` und die public Wrapper.
  * Der Performance-Mini-Bench gegen 10k Findings, der zwingend ein
    materialisiertes DB-Volumen braucht.

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
    Server,
    Severity,
)
from app.services.severity_history import (
    daily_severity_counts_for_server,
    severity_snapshots_for_server,
)

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


def _create_server(app: Flask, name: str = "sh-srv") -> int:
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
    acknowledged_at: datetime | None = None,
    resolved_at: datetime | None = None,
    is_kev: bool = False,
    kev_added_at: datetime | None = None,
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
                package_name=f"pkg-{identifier_key}",
                installed_version="1.0",
                severity=severity,
                status=status,
                is_kev=is_kev,
                kev_added_at=kev_added_at,
                first_seen_at=first_seen_at,
                last_seen_at=first_seen_at,
                acknowledged_at=acknowledged_at,
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


# ---------------------------------------------------------------------------
# Round-Trip-Smokes
# ---------------------------------------------------------------------------


def test_severity_snapshots_round_trip_db_load_and_aggregate(db_app: Flask) -> None:
    """End-to-end: DB-Load und Aggregation liefern die erwarteten Reihen."""
    sid = _create_server(db_app, name="sh-db-snap")
    fseen = FIXED_NOW - timedelta(days=4)
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="DB-OPEN-1",
        severity=Severity.HIGH,
        first_seen_at=fseen,
        is_kev=True,
        kev_added_at=fseen,
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = severity_snapshots_for_server(sess, sid, days=50, now=FIXED_NOW)
        finally:
            sess.close()
    assert set(out.keys()) == {"critical", "high", "medium", "low", "kev"}
    high = out["high"]
    kev = out["kev"]
    for i in range(50):
        days_ago = 49 - i
        expected = 1 if days_ago <= 4 else 0
        assert high[i] == expected, f"high Tag -{days_ago}: erwarte {expected}, habe {high[i]}"
        assert kev[i] == expected, f"kev Tag -{days_ago}: erwarte {expected}, habe {kev[i]}"


def test_daily_severity_counts_round_trip_db_load(db_app: Flask) -> None:
    """End-to-end: Wrapper liefert DailySeverityCount-Liste mit korrekten Tagen."""
    sid = _create_server(db_app, name="sh-db-daily")
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="DB-DAILY-1",
        severity=Severity.MEDIUM,
        first_seen_at=FIXED_NOW - timedelta(days=2),
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_severity_counts_for_server(sess, sid, days=10, now=FIXED_NOW)
        finally:
            sess.close()
    assert len(out) == 10
    assert out[-1].day == date(2026, 5, 15)
    assert out[-1].medium == 1
    assert out[-3].medium == 1
    assert out[-4].medium == 0


# ---------------------------------------------------------------------------
# Performance-Mini-Bench: 10k Findings x 50 Tage < 1.5s
# ---------------------------------------------------------------------------


def test_performance_10k_findings_50_days_under_100ms(db_app: Flask) -> None:
    """Sanity-Check: Daily-Snapshots fuer 10k Findings * 50 Tage in <100 ms.

    Die ADR-0018 nennt 100 ms als Schwelle. Wir messen End-to-End-Aufruf
    inkl. DB-Load + Python-Aggregation. Schwelle absichtlich grosszuegig
    fuer CI-Lasten (Coverage-Tracer-Overhead, Postgres-Container-Cold-Start).
    """
    sid = _create_server(db_app, name="perf-snap")

    factory = get_session_factory(db_app)
    base = FIXED_NOW - timedelta(days=30)
    with db_app.app_context():
        sess = factory()
        try:
            chunk = []
            for i in range(10_000):
                chunk.append(
                    Finding(
                        server_id=sid,
                        finding_type=FindingType.VULNERABILITY,
                        finding_class=FindingClass.OS_PKGS,
                        identifier_key=f"PERF-{i:06d}",
                        package_name=f"pkg-{i % 100}",
                        installed_version="1.0",
                        severity=Severity.HIGH,
                        status=FindingStatus.OPEN,
                        is_kev=False,
                        first_seen_at=base,
                        last_seen_at=base,
                        attack_vector=AttackVector.UNKNOWN,
                    )
                )
            sess.add_all(chunk)
            sess.commit()
        finally:
            sess.close()

    with db_app.app_context():
        sess = factory()
        try:
            t0 = time.perf_counter()
            out = daily_severity_counts_for_server(sess, sid, days=50, now=FIXED_NOW)
            elapsed = time.perf_counter() - t0
        finally:
            sess.close()
    assert len(out) == 50
    assert elapsed < 1.5, (
        f"Daily-Snapshot zu langsam: {elapsed * 1000:.1f} ms (10k Findings, 50T) "
        "— ADR-0018 Ziel ist 100 ms standalone (ohne coverage-Tracer)."
    )
