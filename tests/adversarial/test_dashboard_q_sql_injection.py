"""Adversarial: `/?q=' OR 1=1--` (Block M, ADR-0020).

ARCHITECTURE.md §10. Das `q`-Feld wird in `list_findings_cross_server` per
`ilike(f"%{q}%")` gefiltert — SQLAlchemy bindet den Parameter, der String
geht NIE direkt ins SQL. Diese Suite verifiziert:

- Klassische SQLi-Payloads liefern Status 200 ohne SQL-Error.
- Der Treffer ist 0 (kein Wildcard-Match gegen alle Findings).
- DB ist nach dem Request unveraendert.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from flask import Flask
from sqlalchemy import select

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
from tests._helpers import create_admin_user, login


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


def _add_finding(app: Flask, *, server_id: int, identifier_key: str) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            now = datetime.now(tz=UTC)
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key=identifier_key,
                package_name="openssl",
                installed_version="1.0",
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                is_kev=False,
                first_seen_at=now,
                last_seen_at=now,
                attack_vector=AttackVector.UNKNOWN,
            )
            sess.add(f)
            sess.commit()
        finally:
            sess.close()


_SQLI_PAYLOADS: list[str] = [
    "' OR 1=1--",
    "' OR '1'='1",
    "'; DROP TABLE findings;--",
    "'; SELECT * FROM users;--",
    "%' OR '1'='1",
    "'/**/OR/**/1=1--",
    "' UNION SELECT NULL--",
    "\\'; DROP TABLE findings;--",
    "1' AND SLEEP(5)--",
]


@pytest.mark.parametrize("payload", _SQLI_PAYLOADS)
def test_q_sql_injection_does_not_match_or_crash(db_app: Flask, payload: str) -> None:
    """SQLi-Payload im `q`-Feld -> 200, kein Match, kein SQL-Error."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name=f"sqli-{abs(hash(payload)) % 10_000}")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SAFE-100")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SAFE-200")
    client = db_app.test_client()
    login(client)

    resp = client.get("/", query_string={"q": payload})
    assert resp.status_code == 200, (
        f"q={payload!r}: erwartet 200, got {resp.status_code}: "
        f"{resp.get_data(as_text=True)[:200]!r}"
    )
    body = resp.get_data(as_text=True)
    body_lower = body.lower()
    for marker in ("sqlalchemy.exc", "programmingerror", "operationalerror"):
        assert marker not in body_lower, f"q={payload!r}: SQL-Error-Marker '{marker}' im Body"

    # Pruefe: keine Findings sind durch Wildcard-Bypass durchgekommen.
    # Findings-Section vorhanden, aber `findings-empty` Marker oder die Such-
    # term-Treffer fehlen.
    section_start = body.find('data-test="dashboard-findings-section"')
    section = body[section_start:]
    # Da die Payload kein gueltiger Substring der CVE-IDs/Pakete/Server-Namen
    # ist, muessen wir den Empty-Marker sehen, NICHT die beiden Findings.
    assert "CVE-SAFE-100" not in section, f"q={payload!r}: `OR 1=1`-Bypass — alle Findings sichtbar"
    assert "CVE-SAFE-200" not in section
    assert 'data-test="findings-empty"' in section


def test_q_sql_injection_db_unchanged(db_app: Flask) -> None:
    """End-to-End: DB nach SQLi-Payload unveraendert."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="sqli-db-check")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-PRE-001")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-PRE-002")
    client = db_app.test_client()
    login(client)
    resp = client.get("/", query_string={"q": "'; DROP TABLE findings;--"})
    assert resp.status_code == 200

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            rows = (
                sess.execute(select(Finding.identifier_key).where(Finding.server_id == sid))
                .scalars()
                .all()
            )
        finally:
            sess.close()
    assert set(rows) == {"CVE-PRE-001", "CVE-PRE-002"}, rows
