"""Unit-Tests fuer den Cross-Server-CSV-Export (Block M, ADR-0020).

Geprueft werden:
- 5 Findings auf 3 Servern -> 6 Zeilen (1 Header + 5 Daten), Server-Spalte.
- Server-Name `=cmd|...` bekommt `'`-Prefix (OWASP-Formula-Injection).
- Filter `?q=openssh` filtert vor dem Export.
"""

from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO

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
from app.schemas.dashboard_filter import DashboardFilter
from app.services.csv_export import (
    FINDINGS_CSV_COLUMNS_CROSS,
    stream_findings_csv_cross_server,
)

_BASE_TS = datetime(2026, 5, 15, 12, 0, tzinfo=UTC)


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
    package_name: str = "openssl",
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
                package_name=package_name,
                installed_version="1.0",
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                is_kev=False,
                first_seen_at=_BASE_TS,
                last_seen_at=_BASE_TS,
                attack_vector=AttackVector.UNKNOWN,
            )
            sess.add(f)
            sess.commit()
        finally:
            sess.close()


def _collect_csv(stream_generator: object) -> list[list[str]]:
    """Sammelt CSV-Bytes zu einer Zeilenliste."""
    import csv

    buf = StringIO()
    for chunk in stream_generator:  # type: ignore[attr-defined]
        buf.write(chunk.decode("utf-8"))
    buf.seek(0)
    return list(csv.reader(buf))


def test_five_findings_three_servers_six_rows_with_server_column(db_app: Flask) -> None:
    """5 Findings auf 3 Servern -> Header + 5 Datenzeilen, Server-Spalte korrekt."""
    sid_a = _create_server(db_app, "srv-a")
    sid_b = _create_server(db_app, "srv-b")
    sid_c = _create_server(db_app, "srv-c")
    _add_finding(db_app, server_id=sid_a, identifier_key="CVE-A-1")
    _add_finding(db_app, server_id=sid_a, identifier_key="CVE-A-2")
    _add_finding(db_app, server_id=sid_b, identifier_key="CVE-B-1")
    _add_finding(db_app, server_id=sid_c, identifier_key="CVE-C-1")
    _add_finding(db_app, server_id=sid_c, identifier_key="CVE-C-2")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            stream = stream_findings_csv_cross_server(sess, DashboardFilter())
            rows = _collect_csv(stream)
        finally:
            sess.close()

    assert rows[0] == FINDINGS_CSV_COLUMNS_CROSS
    assert len(rows) == 6
    # Server-Spalte (Index 0) muss eine der drei Server-Namen enthalten.
    server_col_values = {row[0] for row in rows[1:]}
    assert server_col_values == {"srv-a", "srv-b", "srv-c"}


def test_formula_injection_server_name_gets_prefix(db_app: Flask) -> None:
    """Server-Name `=cmd|...` bekommt `'`-Prefix in der Server-Spalte (OWASP)."""
    sid = _create_server(db_app, "=cmd|'/c calc'!A1")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-INJECT")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            stream = stream_findings_csv_cross_server(sess, DashboardFilter())
            rows = _collect_csv(stream)
        finally:
            sess.close()

    assert len(rows) == 2
    # Erste Datenzeile, erste Spalte ist Server-Name -> muss mit `'` beginnen.
    assert rows[1][0].startswith("'="), f"erwartet '`-Prefix vor `=cmd|`, got {rows[1][0]!r}"


def test_q_filter_applies_before_export(db_app: Flask) -> None:
    """`?q=openssh` filtert vor dem Export — nur openssh-Findings landen drin."""
    sid = _create_server(db_app, "srv-q")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-O-1", package_name="openssh-server")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-O-2", package_name="openssh-client")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-C-1", package_name="curl")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            stream = stream_findings_csv_cross_server(sess, DashboardFilter(q="openssh"))
            rows = _collect_csv(stream)
        finally:
            sess.close()

    # 1 Header + 2 Datenzeilen (nur openssh-*).
    assert len(rows) == 3
    pkg_idx = FINDINGS_CSV_COLUMNS_CROSS.index("package_name")
    packages = {row[pkg_idx] for row in rows[1:]}
    assert packages == {"openssh-server", "openssh-client"}
