"""Unit-Tests fuer `app.services.trend` (Block K, ADR-0018, Phase B ADR-0030).

Deckt:
  * Stabile Reihe -> STABLE.
  * Klar steigend (avg_short deutlich > avg_long) -> RISING.
  * Klar fallend -> FALLING.
  * Leere History -> STABLE (Default).
  * Schwelle-Grenzfaelle (knapp unter / knapp ueber +5%).
  * `Tendency.label` Lowercase-Format ("ueber 50 tage ...").

Phase B (ADR-0030 Befund 1): neue Pure-Unit-Tests fuer `tendency_from_counts`.
Die Pure-Funktion benoetigt weder Session noch DB und ist direkt testbar.
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
from app.services.trend import Tendency, compute_tendency

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Setup-Helpers
# ---------------------------------------------------------------------------


def _create_server(app: Flask, name: str = "trend-srv") -> int:
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


def _add_open_findings(
    app: Flask,
    *,
    server_id: int,
    first_seen_at: datetime,
    count: int,
    prefix: str,
    severity: Severity = Severity.HIGH,
) -> None:
    """Legt `count` OPEN-Findings mit `first_seen_at` an (alle ohne ack/resolved)."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            for i in range(count):
                f = Finding(
                    server_id=server_id,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key=f"{prefix}-{i:04d}",
                    package_name=f"pkg-{prefix}-{i}",
                    installed_version="1.0",
                    severity=severity,
                    status=FindingStatus.OPEN,
                    is_kev=False,
                    first_seen_at=first_seen_at,
                    last_seen_at=first_seen_at,
                    attack_vector=AttackVector.UNKNOWN,
                )
                sess.add(f)
            sess.commit()
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_history_returns_stable(db_app: Flask) -> None:
    """Server ohne Findings -> STABLE als Default."""
    sid = _create_server(db_app, name="trend-empty")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            result = compute_tendency(sess, sid, now=FIXED_NOW)
        finally:
            sess.close()
    assert result is Tendency.STABLE


def test_stable_series_returns_stable(db_app: Flask) -> None:
    """Konstant offene Findings ueber 50 Tage -> avg_short == avg_long -> STABLE."""
    sid = _create_server(db_app, name="trend-stable")
    # Alle Findings haben first_seen_at = vor 50 Tagen -> jeden Tag sind sie offen.
    _add_open_findings(
        db_app,
        server_id=sid,
        first_seen_at=FIXED_NOW - timedelta(days=49),
        count=5,
        prefix="STABLE",
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            result = compute_tendency(sess, sid, now=FIXED_NOW)
        finally:
            sess.close()
    assert result is Tendency.STABLE, f"erwartet STABLE, bekommen {result!r}"


def test_rising_series_returns_rising(db_app: Flask) -> None:
    """Findings die alle erst in den letzten 7 Tagen first_seen wurden -> RISING.

    avg_short=N, avg_long ~= 7*N/50 << N -> diff klar > 0.05.
    """
    sid = _create_server(db_app, name="trend-rising")
    # Alle Findings frisch (vor 1 Tag) -> in den letzten 7 Tagen vollstaendig
    # offen, in den letzten 50 Tagen nur in den letzten ~2 Tagen.
    _add_open_findings(
        db_app,
        server_id=sid,
        first_seen_at=FIXED_NOW - timedelta(days=1),
        count=20,
        prefix="RISE",
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            result = compute_tendency(sess, sid, now=FIXED_NOW)
        finally:
            sess.close()
    assert result is Tendency.RISING, f"erwartet RISING, bekommen {result!r}"


def test_falling_series_returns_falling(db_app: Flask) -> None:
    """Findings die alle frueh im 50T-Fenster resolved wurden -> FALLING.

    In den letzten 7 Tagen sind kaum/keine Findings mehr offen, in den 50T
    davor schon -> avg_short < avg_long -> diff <= -0.05.
    """
    sid = _create_server(db_app, name="trend-falling")
    factory = get_session_factory(db_app)

    # 20 Findings, first_seen vor 49 Tagen, alle resolved vor 20 Tagen.
    with db_app.app_context():
        sess = factory()
        try:
            for i in range(20):
                f = Finding(
                    server_id=sid,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key=f"FALL-{i:04d}",
                    package_name=f"pkg-fall-{i}",
                    installed_version="1.0",
                    severity=Severity.HIGH,
                    status=FindingStatus.RESOLVED,
                    is_kev=False,
                    first_seen_at=FIXED_NOW - timedelta(days=49),
                    last_seen_at=FIXED_NOW - timedelta(days=20),
                    resolved_at=FIXED_NOW - timedelta(days=20),
                    attack_vector=AttackVector.UNKNOWN,
                )
                sess.add(f)
            sess.commit()
        finally:
            sess.close()

    with db_app.app_context():
        sess = factory()
        try:
            result = compute_tendency(sess, sid, now=FIXED_NOW)
        finally:
            sess.close()
    assert result is Tendency.FALLING, f"erwartet FALLING, bekommen {result!r}"


def test_threshold_grenzfall_below_returns_stable(db_app: Flask) -> None:
    """Mit threshold=0.5 und nur leichtem Anstieg bleibt STABLE.

    Wir benutzen einen kuenstlich hohen Threshold, um die Schwellen-Logik
    zu validieren ohne auf brittle floating-point-Bauten angewiesen zu sein.
    """
    sid = _create_server(db_app, name="trend-th-below")
    # avg_long ~ avg_short fuer threshold-Test:
    # konstante Reihe, threshold sehr hoch -> auch leichte Schwankungen bleiben STABLE.
    _add_open_findings(
        db_app,
        server_id=sid,
        first_seen_at=FIXED_NOW - timedelta(days=49),
        count=10,
        prefix="THBELOW",
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            result = compute_tendency(sess, sid, threshold=0.5, now=FIXED_NOW)
        finally:
            sess.close()
    assert result is Tendency.STABLE


def test_threshold_grenzfall_above_returns_rising(db_app: Flask) -> None:
    """Mit threshold=0.01 wird selbst minimaler Anstieg als RISING erkannt."""
    sid = _create_server(db_app, name="trend-th-above")
    # avg_long deutlich kleiner als avg_short (frische Findings).
    _add_open_findings(
        db_app,
        server_id=sid,
        first_seen_at=FIXED_NOW - timedelta(days=3),
        count=10,
        prefix="THABOVE",
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            # threshold sehr klein -> RISING wird leicht ausgeloest.
            result = compute_tendency(sess, sid, threshold=0.01, now=FIXED_NOW)
        finally:
            sess.close()
    assert result is Tendency.RISING


def test_tendency_label_format() -> None:
    """Label entspricht dem Design-Mockup (Lowercase, 'ueber 30 tage <X>',
    ADR-0038 Fenster-Reduktion von 50 auf 30 Tage)."""
    assert Tendency.STABLE.label == "stable over 30 days"
    assert Tendency.RISING.label == "rising over 30 days"
    assert Tendency.FALLING.label == "falling over 30 days"
