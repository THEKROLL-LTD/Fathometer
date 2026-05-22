"""Integration-Smokes fuer `app/services/csv_export.py` gegen echte Postgres-DB.

Diese Tests wurden aus `tests/services/test_csv_export.py` ausgelagert
(TICKET-004, Slice 1). Sie pruefen bewusst das Zusammenspiel von
`stream_audit_csv` / `stream_findings_csv` mit einer echten SQLAlchemy-Session
und ORM-Iteration — gehoeren also in die `db_integration`-Suite und werden im
Default-Pytest-Lauf via Auto-Marker (`tests/conftest.py`) deselektiert.

Reine Logik-/Streaming-/Spalten-Tests verbleiben DB-frei in
`tests/services/test_csv_export.py`.

psycopg-Connection-Pool-Cleanup-Reihenfolge ist unter `filterwarnings = error`
flaky beim Aufeinanderfolgen vieler DB-Tests (siehe auch
`tests/adversarial/test_csv_injection.py`). Die `ResourceWarning` kommt aus
dem GC, nicht aus unseren Helpers, und ist KEIN echter Test-Failure.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    AttackVector,
    AuditEvent,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from app.services.csv_export import (
    AUDIT_CSV_COLUMNS,
    FINDINGS_CSV_COLUMNS,
    stream_audit_csv,
    stream_findings_csv,
)
from app.services.findings_query import FindingsFilter

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

_BASE_TS = datetime(2026, 5, 13, 9, 0, tzinfo=UTC)


def _add_audit_event(
    app: Flask,
    *,
    actor: str,
    action: str,
    target_id: str | None = None,
    comment: str | None = None,
) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            sess.add(
                AuditEvent(
                    actor=actor,
                    action=action,
                    target_type="finding",
                    target_id=target_id,
                    comment=comment,
                )
            )
            sess.commit()
        finally:
            sess.close()


def _create_server(app: Flask, name: str) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
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
    package_name: str = "openssl",
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
                severity=Severity.HIGH,
                attack_vector=AttackVector.UNKNOWN,
                status=FindingStatus.OPEN,
                first_seen_at=_BASE_TS,
                last_seen_at=_BASE_TS,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def test_stream_audit_csv_yields_filtered_events(db_app: Flask) -> None:
    _add_audit_event(db_app, actor="admin", action="finding.acknowledged", target_id="1")
    _add_audit_event(db_app, actor="admin", action="finding.reopened", target_id="2")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            stmt = select(AuditEvent).where(AuditEvent.action == "finding.acknowledged")
            result = b"".join(stream_audit_csv(sess, filter_query=stmt)).decode("utf-8")
        finally:
            sess.close()

    lines = result.strip().split("\r\n")
    assert lines[0] == ",".join(AUDIT_CSV_COLUMNS)
    body = "\r\n".join(lines[1:])
    assert "finding.acknowledged" in body
    assert "finding.reopened" not in body


def test_stream_findings_csv_global_export_all_servers(db_app: Flask) -> None:
    sid1 = _create_server(db_app, "srv-csv-1")
    sid2 = _create_server(db_app, "srv-csv-2")
    _add_finding(db_app, server_id=sid1, identifier_key="CVE-2024-EX001")
    _add_finding(db_app, server_id=sid2, identifier_key="CVE-2024-EX002")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            result = b"".join(
                stream_findings_csv(sess, server_id=None, filter_obj=FindingsFilter(status="open"))
            ).decode("utf-8")
        finally:
            sess.close()

    lines = result.strip().split("\r\n")
    assert lines[0] == ",".join(FINDINGS_CSV_COLUMNS)
    body = "\r\n".join(lines[1:])
    assert "CVE-2024-EX001" in body
    assert "CVE-2024-EX002" in body
    assert "srv-csv-1" in body
    assert "srv-csv-2" in body


def test_stream_findings_csv_with_server_id_filters(db_app: Flask) -> None:
    sid1 = _create_server(db_app, "srv-csv-a")
    sid2 = _create_server(db_app, "srv-csv-b")
    _add_finding(db_app, server_id=sid1, identifier_key="CVE-2024-FX001")
    _add_finding(db_app, server_id=sid2, identifier_key="CVE-2024-FX002")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            result = b"".join(
                stream_findings_csv(sess, server_id=sid1, filter_obj=FindingsFilter(status="open"))
            ).decode("utf-8")
        finally:
            sess.close()

    assert "CVE-2024-FX001" in result
    assert "CVE-2024-FX002" not in result
