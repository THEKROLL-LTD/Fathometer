"""Unit-Tests fuer `count_kev_events_50d()` (Block K, ADR-0018).

Setup laut DoD:
  - F1: `kev_added_at` vor 30 Tagen -> zaehlt.
  - F2: `kev_added_at` vor 90 Tagen -> zaehlt NICHT (ausserhalb 50d).
  - F3: neu ingestet mit `is_kev=True` vor 5 Tagen, kein `kev_added_at` ->
        zaehlt (first_seen_at >= now-50d AND is_kev).

Erwartung: Counter == 2.
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
    Severity,
)
from app.services.severity_history import count_kev_events_50d

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


def _create_server(app: Flask, name: str = "kev-srv") -> int:
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
    first_seen_at: datetime,
    is_kev: bool,
    kev_added_at: datetime | None = None,
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
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                is_kev=is_kev,
                kev_added_at=kev_added_at,
                first_seen_at=first_seen_at,
                last_seen_at=first_seen_at,
                attack_vector=AttackVector.UNKNOWN,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def test_count_kev_events_50d_matches_spec(db_app: Flask) -> None:
    """ADR-0018-Beispielsetup -> Counter == 2."""
    sid = _create_server(db_app, name="kev-spec")
    # F1 — kev_added_at vor 30 Tagen -> zaehlt.
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="F1-NEW-KEV-30D",
        first_seen_at=FIXED_NOW - timedelta(days=60),
        is_kev=True,
        kev_added_at=FIXED_NOW - timedelta(days=30),
    )
    # F2 — kev_added_at vor 90 Tagen -> zaehlt NICHT.
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="F2-OLD-KEV-90D",
        first_seen_at=FIXED_NOW - timedelta(days=120),
        is_kev=True,
        kev_added_at=FIXED_NOW - timedelta(days=90),
    )
    # F3 — frisch ingestet vor 5 Tagen, is_kev=True, kein kev_added_at.
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="F3-FRESH-KEV-5D",
        first_seen_at=FIXED_NOW - timedelta(days=5),
        is_kev=True,
        kev_added_at=None,
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            count = count_kev_events_50d(sess, sid, now=FIXED_NOW)
        finally:
            sess.close()
    assert count == 2, f"erwarte 2, habe {count}"


def test_count_kev_events_50d_empty_server(db_app: Flask) -> None:
    """Server ohne KEV-Findings -> 0."""
    sid = _create_server(db_app, name="kev-empty")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            count = count_kev_events_50d(sess, sid, now=FIXED_NOW)
        finally:
            sess.close()
    assert count == 0


def test_count_kev_events_50d_ignores_non_kev_recent(db_app: Flask) -> None:
    """Frische Findings ohne `is_kev=True` zaehlen nicht."""
    sid = _create_server(db_app, name="kev-nonkev")
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="NONKEV-FRESH",
        first_seen_at=FIXED_NOW - timedelta(days=2),
        is_kev=False,
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            count = count_kev_events_50d(sess, sid, now=FIXED_NOW)
        finally:
            sess.close()
    assert count == 0


def test_count_kev_events_50d_distinct_finding_ids(db_app: Flask) -> None:
    """Ein Finding mit `kev_added_at` UND `first_seen_at` im Fenster zaehlt nur 1x."""
    sid = _create_server(db_app, name="kev-distinct")
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="BOTH-CONDITIONS",
        first_seen_at=FIXED_NOW - timedelta(days=10),
        is_kev=True,
        kev_added_at=FIXED_NOW - timedelta(days=8),
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            count = count_kev_events_50d(sess, sid, now=FIXED_NOW)
        finally:
            sess.close()
    assert count == 1
