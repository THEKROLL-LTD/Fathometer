"""Block Q Phase 1 (ADR-0024) — Modell-Tests fuer EPSS/KEV/Audit-Log.

ORM-Round-Trip pro Modell: Insert, Query, PK-Duplicate, CheckConstraint-
Violation. Verifiziert SQLAlchemy-Defaults (``known_ransomware=False``,
``server_default=now()``) und die Whitelist-Constraints (EPSS-Range,
``feed_name``).
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db import get_session_factory
from app.models import CisaKevCatalog, EpssScore, FeedPullLog

# ---------------------------------------------------------------------------
# EpssScore
# ---------------------------------------------------------------------------


def test_epss_score_insert_and_query(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                EpssScore(
                    cve_id="CVE-2024-6387",
                    epss_score=0.42,
                    epss_percentile=0.97,
                )
            )
            sess.commit()
            row = sess.execute(
                select(EpssScore).where(EpssScore.cve_id == "CVE-2024-6387")
            ).scalar_one()
            assert row.epss_score == pytest.approx(0.42)
            assert row.epss_percentile == pytest.approx(0.97)
            assert row.updated_at is not None
        finally:
            sess.close()


def test_epss_score_duplicate_pk_fails(db_app: Flask) -> None:
    """Zweimal selbe ``cve_id`` direkt rein → PK-Verletzung."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(EpssScore(cve_id="CVE-2024-1111", epss_score=0.1, epss_percentile=0.1))
            sess.commit()
            sess.add(EpssScore(cve_id="CVE-2024-1111", epss_score=0.2, epss_percentile=0.2))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_epss_score_check_constraint_violation_above_one(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(EpssScore(cve_id="CVE-2024-2222", epss_score=1.5, epss_percentile=0.5))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_epss_score_check_constraint_violation_negative_percentile(
    db_app: Flask,
) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(EpssScore(cve_id="CVE-2024-3333", epss_score=0.5, epss_percentile=-0.01))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


# ---------------------------------------------------------------------------
# CisaKevCatalog
# ---------------------------------------------------------------------------


def test_kev_insert_and_query(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                CisaKevCatalog(
                    cve_id="CVE-2024-6387",
                    vendor_project="OpenBSD",
                    product="OpenSSH",
                    vulnerability_name="regreSSHion",
                    date_added=date(2024, 7, 1),
                    short_description="Race condition in sshd.",
                    required_action="Patch.",
                    due_date=date(2024, 7, 22),
                    known_ransomware=False,
                )
            )
            sess.commit()
            row = sess.execute(
                select(CisaKevCatalog).where(CisaKevCatalog.cve_id == "CVE-2024-6387")
            ).scalar_one()
            assert row.vendor_project == "OpenBSD"
            assert row.due_date == date(2024, 7, 22)
            assert row.known_ransomware is False
        finally:
            sess.close()


def test_kev_default_known_ransomware_false(db_app: Flask) -> None:
    """ORM-Default: bei nicht gesetztem ``known_ransomware`` → False."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                CisaKevCatalog(
                    cve_id="CVE-2024-7777",
                    date_added=date(2024, 5, 1),
                )
            )
            sess.commit()
            row = sess.execute(
                select(CisaKevCatalog).where(CisaKevCatalog.cve_id == "CVE-2024-7777")
            ).scalar_one()
            assert row.known_ransomware is False
        finally:
            sess.close()


def test_kev_date_added_required(db_app: Flask) -> None:
    """``date_added`` ist NOT NULL."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                CisaKevCatalog(
                    cve_id="CVE-2024-8888",
                    date_added=None,  # type: ignore[arg-type]
                )
            )
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_kev_due_date_nullable(db_app: Flask) -> None:
    """``due_date`` ist nullable; Insert ohne Wert ist legal."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                CisaKevCatalog(
                    cve_id="CVE-2024-9999",
                    date_added=date(2024, 1, 5),
                    due_date=None,
                )
            )
            sess.commit()
            row = sess.execute(
                select(CisaKevCatalog).where(CisaKevCatalog.cve_id == "CVE-2024-9999")
            ).scalar_one()
            assert row.due_date is None
        finally:
            sess.close()


def test_kev_duplicate_pk_fails(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(CisaKevCatalog(cve_id="CVE-2024-1234", date_added=date(2024, 1, 1)))
            sess.commit()
            sess.add(CisaKevCatalog(cve_id="CVE-2024-1234", date_added=date(2024, 1, 2)))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


# ---------------------------------------------------------------------------
# FeedPullLog
# ---------------------------------------------------------------------------


def test_feed_pull_log_insert_running(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            entry = FeedPullLog(feed_name="epss", status="running")
            sess.add(entry)
            sess.commit()
            assert entry.id is not None
            assert entry.started_at is not None
            assert entry.completed_at is None
            assert entry.row_count is None
        finally:
            sess.close()


def test_feed_pull_log_update_to_success(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            entry = FeedPullLog(feed_name="cisa_kev", status="running")
            sess.add(entry)
            sess.commit()
            entry.status = "success"
            entry.completed_at = datetime.now(UTC)
            entry.row_count = 1423
            entry.bytes_downloaded = 987_654
            sess.commit()

            reloaded = sess.execute(
                select(FeedPullLog).where(FeedPullLog.id == entry.id)
            ).scalar_one()
            assert reloaded.status == "success"
            assert reloaded.row_count == 1423
            assert reloaded.bytes_downloaded == 987_654
            assert reloaded.completed_at is not None
        finally:
            sess.close()


def test_feed_pull_log_unknown_feed_name_fails(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(FeedPullLog(feed_name="foo", status="running"))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_feed_pull_log_error_message_persists(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            entry = FeedPullLog(
                feed_name="epss",
                status="failed",
                error_message="HTTP 503: Service Unavailable",
                completed_at=datetime.now(UTC),
            )
            sess.add(entry)
            sess.commit()
            reloaded = sess.execute(
                select(FeedPullLog).where(FeedPullLog.id == entry.id)
            ).scalar_one()
            assert reloaded.error_message == "HTTP 503: Service Unavailable"
            assert reloaded.status == "failed"
        finally:
            sess.close()
