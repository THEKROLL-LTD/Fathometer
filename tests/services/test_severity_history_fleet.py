"""Unit-Tests fuer `daily_severity_counts_fleet` (Block M, ADR-0020).

Geprueft werden:
- Leere Flotte: alle 50 Tageswerte = 0.
- Nur OPEN-Findings: konstante Sparkline ab dem `first_seen_at`-Tag.
- Gemischt OPEN/ack/resolved: Bucket-Counts korrekt pro Tag.
- KEV-Sub-Bucket: 2 KEV + 3 non-KEV im OPEN -> `kev=2`, `total=5`.
- Performance-Mini-Bench: 50k Findings * 50 Tage < 200 ms.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest
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
from app.services.severity_history import daily_severity_counts_fleet

FIXED_NOW = datetime(2026, 5, 15, 12, 0, tzinfo=UTC)


def _create_server(app: Flask, name: str) -> int:
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


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    severity: Severity = Severity.HIGH,
    first_seen_at: datetime = FIXED_NOW,
    acknowledged_at: datetime | None = None,
    resolved_at: datetime | None = None,
    is_kev: bool = False,
    status: FindingStatus = FindingStatus.OPEN,
) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key=identifier_key,
                package_name="openssl",
                installed_version="1.0",
                severity=severity,
                status=status,
                is_kev=is_kev,
                first_seen_at=first_seen_at,
                last_seen_at=first_seen_at,
                acknowledged_at=acknowledged_at,
                resolved_at=resolved_at,
                attack_vector=AttackVector.UNKNOWN,
            )
            sess.add(f)
            sess.commit()
        finally:
            sess.close()


def test_empty_fleet_returns_all_zero(db_app: Flask) -> None:
    """Keine Findings -> alle vier Buckets mit 50 Nullen."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_severity_counts_fleet(sess, days=50, now=FIXED_NOW)
        finally:
            sess.close()

    assert set(out.keys()) == {"total", "kev", "critical", "high"}
    for key, vals in out.items():
        assert len(vals) == 50, f"{key}: len != 50"
        assert all(v == 0 for v in vals), f"{key}: erwartet alle 0"


def test_only_open_findings_constant_sparkline(db_app: Flask) -> None:
    """Drei OPEN-HIGH-Findings ab Tag -10: konstant 3 ab Tag -10, davor 0."""
    sid = _create_server(db_app, "fleet-open")
    fseen = FIXED_NOW - timedelta(days=10)
    for i in range(3):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"OPEN-{i}",
            severity=Severity.HIGH,
            first_seen_at=fseen,
        )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_severity_counts_fleet(sess, days=50, now=FIXED_NOW)
        finally:
            sess.close()

    # Index 0 = Tag -49, Index 49 = heute.
    for i in range(50):
        days_ago = 49 - i
        expected = 3 if days_ago <= 10 else 0
        assert out["total"][i] == expected, (
            f"total Tag-{days_ago}: erwartet {expected}, got {out['total'][i]}"
        )
        assert out["high"][i] == expected, (
            f"high Tag-{days_ago}: erwartet {expected}, got {out['high'][i]}"
        )
    assert all(v == 0 for v in out["kev"])
    assert all(v == 0 for v in out["critical"])


def test_mixed_lifecycle_buckets_correct_per_day(db_app: Flask) -> None:
    """Lifecycle-Test: Open seit -10, ack vor 5 Tagen.

    Tag -10..-5: zaehlt (OPEN), Tag -5..heute: zaehlt nicht.
    """
    sid = _create_server(db_app, "fleet-mixed")
    fseen = FIXED_NOW - timedelta(days=10)
    ack_at = FIXED_NOW - timedelta(days=5)
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="MIX-1",
        severity=Severity.CRITICAL,
        first_seen_at=fseen,
        acknowledged_at=ack_at,
        status=FindingStatus.ACKNOWLEDGED,
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_severity_counts_fleet(sess, days=50, now=FIXED_NOW)
        finally:
            sess.close()

    # Index 0 = Tag -49, Index 49 = heute.
    # Tag -10..-6: gilt als OPEN, Tag-5 und juenger nicht mehr (ack_at <= EOD).
    for i in range(50):
        days_ago = 49 - i
        if 6 <= days_ago <= 10:
            assert out["total"][i] == 1, f"Tag-{days_ago}: total=1 erwartet"
            assert out["critical"][i] == 1, f"Tag-{days_ago}: critical=1 erwartet"
        else:
            assert out["total"][i] == 0, f"Tag-{days_ago}: total=0 erwartet"
            assert out["critical"][i] == 0, f"Tag-{days_ago}: critical=0 erwartet"


def test_kev_sub_bucket_counts_kev_subset(db_app: Flask) -> None:
    """2 KEV + 3 non-KEV im OPEN: `kev=2`, `total=5` am Ende."""
    sid = _create_server(db_app, "fleet-kev")
    fseen = FIXED_NOW - timedelta(days=2)
    for i in range(2):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"KEV-{i}",
            severity=Severity.CRITICAL,
            first_seen_at=fseen,
            is_kev=True,
        )
    for i in range(3):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"NOKEV-{i}",
            severity=Severity.HIGH,
            first_seen_at=fseen,
            is_kev=False,
        )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_severity_counts_fleet(sess, days=50, now=FIXED_NOW)
        finally:
            sess.close()

    assert out["total"][-1] == 5
    assert out["kev"][-1] == 2
    assert out["critical"][-1] == 2
    assert out["high"][-1] == 3


@pytest.mark.bench
def test_bench_50k_findings_under_200ms(db_app: Flask) -> None:
    """Mini-Bench: 50k Findings * 50 Tage < 200 ms (Block M, ADR-0020)."""
    sid = _create_server(db_app, "bench-srv")
    factory = get_session_factory(db_app)
    fseen = FIXED_NOW - timedelta(days=20)
    with db_app.app_context():
        sess = factory()
        try:
            # Bulk-Insert via direkter Connection — sonst dauert das ewig.
            from sqlalchemy import insert

            insert_stmt = insert(Finding)
            sess.execute(
                insert_stmt,
                [
                    {
                        "server_id": sid,
                        "finding_type": FindingType.VULNERABILITY.value,
                        "finding_class": FindingClass.OS_PKGS.value,
                        "identifier_key": f"BENCH-{i:06d}",
                        "package_name": "openssl",
                        "installed_version": "1.0",
                        "severity": (
                            Severity.CRITICAL.value
                            if i % 5 == 0
                            else (Severity.HIGH.value if i % 5 == 1 else Severity.MEDIUM.value)
                        ),
                        "status": FindingStatus.OPEN.value,
                        "is_kev": (i % 11 == 0),
                        "first_seen_at": fseen,
                        "last_seen_at": fseen,
                        "attack_vector": AttackVector.UNKNOWN.value,
                    }
                    for i in range(50_000)
                ],
            )
            sess.commit()

            t0 = time.perf_counter()
            out = daily_severity_counts_fleet(sess, days=50, now=FIXED_NOW)
            elapsed = time.perf_counter() - t0
        finally:
            sess.close()

    assert len(out["total"]) == 50
    assert elapsed < 0.2, f"daily_severity_counts_fleet zu langsam: {elapsed:.3f}s (> 200 ms)"
