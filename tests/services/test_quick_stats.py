"""Tests fuer den Quick-Stats-Service (Block I).

Deckt:
  * Leere Flotte -> (0,0,0,0,0).
  * Severity-/KEV-Counter aggregieren korrekt.
  * Acknowledged/Resolved Findings zaehlen nicht in `total_open`.
  * Tag-Filter (OR) zaehlt nur Findings auf passenden Servern.
  * Tag-Filter mit unbekanntem Tag -> alles 0.
  * Stale-Counter: Server mit veraltetem `last_scan_at`.
  * Retired/Revoked Server zaehlen nicht in `stale_servers`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Flask

from app.db import get_session_factory
from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    ServerTag,
    Severity,
    Tag,
)
from app.services.quick_stats import QuickStats, get_quick_stats

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Setup-Helpers
# ---------------------------------------------------------------------------


def _create_server(
    app: Flask,
    *,
    name: str,
    last_scan_at: datetime | None = None,
    expected_scan_interval_h: int = 24,
    retired_at: datetime | None = None,
    revoked_at: datetime | None = None,
    tags: list[str] | None = None,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=expected_scan_interval_h,
                last_scan_at=last_scan_at,
                retired_at=retired_at,
                revoked_at=revoked_at,
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id

            if tags:
                from sqlalchemy import select

                for tn in tags:
                    tag = sess.execute(select(Tag).where(Tag.name == tn)).scalar_one_or_none()
                    if tag is None:
                        tag = Tag(name=tn, color="#6b7280")
                        sess.add(tag)
                        sess.flush()
                    sess.add(ServerTag(server_id=sid, tag_id=tag.id))
            sess.commit()
            return sid
        finally:
            sess.close()


def _add_findings(
    app: Flask,
    *,
    server_id: int,
    n_open_high: int = 0,
    n_open_critical: int = 0,
    n_open_kev: int = 0,
    n_acknowledged_high: int = 0,
    n_resolved_critical: int = 0,
) -> None:
    """Massen-Insert von Findings. Identifier-Keys werden eindeutig generiert."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            ctr = 0

            def _f(
                sev: Severity,
                status: FindingStatus,
                is_kev: bool,
            ) -> Finding:
                nonlocal ctr
                ctr += 1
                return Finding(
                    server_id=server_id,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key=f"CVE-QS-{server_id}-{ctr}",
                    package_name=f"pkg-{ctr}",
                    installed_version="1.0",
                    severity=sev,
                    status=status,
                    is_kev=is_kev,
                    attack_vector=AttackVector.UNKNOWN,
                )

            for _ in range(n_open_high):
                sess.add(_f(Severity.HIGH, FindingStatus.OPEN, False))
            for _ in range(n_open_critical):
                sess.add(_f(Severity.CRITICAL, FindingStatus.OPEN, False))
            for _ in range(n_open_kev):
                # KEV-Counter zaehlt unabhaengig — wir machen HIGH+KEV
                sess.add(_f(Severity.HIGH, FindingStatus.OPEN, True))
            for _ in range(n_acknowledged_high):
                sess.add(_f(Severity.HIGH, FindingStatus.ACKNOWLEDGED, False))
            for _ in range(n_resolved_critical):
                f = _f(Severity.CRITICAL, FindingStatus.RESOLVED, False)
                f.resolved_at = datetime.now(tz=UTC)
                sess.add(f)
            sess.commit()
        finally:
            sess.close()


def _session(app: Flask):
    factory = get_session_factory(app)
    return factory()


# ---------------------------------------------------------------------------
# Empty fleet
# ---------------------------------------------------------------------------


def test_quick_stats_empty_fleet_returns_zeros(db_app: Flask) -> None:
    with db_app.app_context():
        sess = _session(db_app)
        try:
            qs = get_quick_stats(sess, now=FIXED_NOW)
        finally:
            sess.close()
    assert qs == QuickStats(0, 0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def test_quick_stats_aggregates_open_severity_and_kev(db_app: Flask) -> None:
    sid = _create_server(db_app, name="qs-srv-1", last_scan_at=FIXED_NOW)
    _add_findings(
        db_app,
        server_id=sid,
        n_open_high=20,
        n_open_critical=5,
        n_open_kev=10,  # zaehlen auch als open (HIGH)
        n_acknowledged_high=3,
        n_resolved_critical=2,
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            qs = get_quick_stats(sess, now=FIXED_NOW)
        finally:
            sess.close()
    # open: 20 high + 5 crit + 10 kev(high) = 35
    assert qs.total_open == 35, qs
    assert qs.kev_open == 10, qs
    assert qs.critical_open == 5, qs
    assert qs.high_open == 30, qs  # 20 + 10 kev(high)


def test_quick_stats_acknowledged_and_resolved_not_in_open(db_app: Flask) -> None:
    sid = _create_server(db_app, name="qs-srv-ack", last_scan_at=FIXED_NOW)
    _add_findings(
        db_app,
        server_id=sid,
        n_acknowledged_high=5,
        n_resolved_critical=3,
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            qs = get_quick_stats(sess, now=FIXED_NOW)
        finally:
            sess.close()
    assert qs.total_open == 0
    assert qs.high_open == 0
    assert qs.critical_open == 0
    assert qs.kev_open == 0


# ---------------------------------------------------------------------------
# Tag-Filter (OR)
# ---------------------------------------------------------------------------


def test_quick_stats_tag_filter_restricts_to_matching_servers(db_app: Flask) -> None:
    sid_prod = _create_server(db_app, name="qs-prod", last_scan_at=FIXED_NOW, tags=["prod"])
    sid_staging = _create_server(
        db_app, name="qs-staging", last_scan_at=FIXED_NOW, tags=["staging"]
    )
    _add_findings(db_app, server_id=sid_prod, n_open_high=4, n_open_critical=1)
    _add_findings(db_app, server_id=sid_staging, n_open_high=10, n_open_critical=10)

    with db_app.app_context():
        sess = _session(db_app)
        try:
            qs_prod = get_quick_stats(sess, filter_tags=["prod"], now=FIXED_NOW)
        finally:
            sess.close()
    # Nur prod-Server zaehlen.
    assert qs_prod.total_open == 5, qs_prod
    assert qs_prod.high_open == 4, qs_prod
    assert qs_prod.critical_open == 1, qs_prod


def test_quick_stats_tag_filter_nonexistent_tag_returns_zeros(db_app: Flask) -> None:
    sid = _create_server(db_app, name="qs-srv", tags=["prod"], last_scan_at=FIXED_NOW)
    _add_findings(db_app, server_id=sid, n_open_high=3)

    with db_app.app_context():
        sess = _session(db_app)
        try:
            qs = get_quick_stats(sess, filter_tags=["does-not-exist"], now=FIXED_NOW)
        finally:
            sess.close()
    assert qs == QuickStats(0, 0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Stale-Counter
# ---------------------------------------------------------------------------


def test_quick_stats_stale_servers_counts_overdue(db_app: Flask) -> None:
    # Frischer Server (kein Stale).
    _create_server(
        db_app,
        name="qs-fresh",
        last_scan_at=FIXED_NOW - timedelta(hours=2),
        expected_scan_interval_h=24,
    )
    # Stale-Server: last_scan vor 50h, Intervall 24h.
    _create_server(
        db_app,
        name="qs-stale",
        last_scan_at=FIXED_NOW - timedelta(hours=50),
        expected_scan_interval_h=24,
    )
    # Server ohne Scan -> stale.
    _create_server(db_app, name="qs-never-scanned", last_scan_at=None)

    with db_app.app_context():
        sess = _session(db_app)
        try:
            qs = get_quick_stats(sess, now=FIXED_NOW)
        finally:
            sess.close()
    assert qs.stale_servers == 2, qs


def test_quick_stats_retired_or_revoked_server_not_stale(db_app: Flask) -> None:
    # Retired Server mit altem Scan -> ignoriert.
    _create_server(
        db_app,
        name="qs-retired",
        last_scan_at=FIXED_NOW - timedelta(hours=200),
        retired_at=FIXED_NOW - timedelta(days=10),
    )
    # Revoked Server -> ebenfalls aus dem Stale-Counter draussen
    # (Service filtert auf `retired_at IS NULL AND revoked_at IS NULL`).
    _create_server(
        db_app,
        name="qs-revoked",
        last_scan_at=FIXED_NOW - timedelta(hours=200),
        revoked_at=FIXED_NOW - timedelta(days=1),
    )

    with db_app.app_context():
        sess = _session(db_app)
        try:
            qs = get_quick_stats(sess, now=FIXED_NOW)
        finally:
            sess.close()
    assert qs.stale_servers == 0, qs
