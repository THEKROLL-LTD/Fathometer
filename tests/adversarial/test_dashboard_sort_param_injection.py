"""Adversarial: Dashboard-`?sort=`-/`?dir=`-Parameter (Block M, ADR-0020).

ARCHITECTURE.md §10 + ADR-0020 (Sort-Keys: Whitelist-only). `DashboardFilter`
validiert `sort` und `dir` gegen Whitelist-Literal-Mengen, das ORDER BY
benutzt `_SORT_COLUMNS_CROSS` als statisches dict[str, Column]-Mapping —
User-Strings fliessen NIE direkt in SQL.

Diese Suite verifiziert das Verhalten aus User-Sicht: bei einem garbage-
oder injection-Payload faellt der View auf den Default `sev`/`desc` zurueck,
liefert 200 und keinen SQL-Error.
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


_BAD_SORT_VALUES: list[str] = [
    "DROP TABLE findings",
    "'; DROP TABLE findings;--",
    "<script>alert(1)</script>",
    "cve OR 1=1",
    "../../etc/passwd",
    "",
    " ",
    "epsss",  # typo, gueltig waere `epss`
    "first seen",
    "\x00cve",
    "cve\nDROP TABLE",
    "a" * 1024,
    "cve/**/UNION/**/SELECT",
    "1 OR 1=1",
    "id, (SELECT password FROM users)",
]


_BAD_DIR_VALUES: list[str] = [
    "'; DROP TABLE findings;--",
    "<script>",
    "ASC; --",
    "",
    " ",
    "asc desc",
    "desc1",
    "a" * 256,
    "\x00asc",
    "DESC OR 1=1",
]


@pytest.mark.parametrize("bad_sort", _BAD_SORT_VALUES)
def test_dashboard_sort_param_invalid_falls_back_to_default(db_app: Flask, bad_sort: str) -> None:
    """`/?sort=<garbage>` -> Default `sev`/`desc`, 200, kein SQL-Error."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name=f"sort-adv-{abs(hash(bad_sort)) % 10_000}")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-ADV-SORT")
    client = db_app.test_client()
    login(client)

    resp = client.get("/", query_string={"sort": bad_sort})
    assert resp.status_code == 200, (
        f"sort={bad_sort!r}: erwartet 200, bekommen {resp.status_code}; "
        f"body: {resp.get_data(as_text=True)[:200]!r}"
    )
    body = resp.get_data(as_text=True).lower()
    for marker in ("sqlalchemy.exc", "programmingerror", "operationalerror"):
        assert marker not in body, f"sort={bad_sort!r}: SQL-Error-Marker '{marker}' im Body"


@pytest.mark.parametrize("bad_dir", _BAD_DIR_VALUES)
def test_dashboard_dir_param_invalid_falls_back_to_default(db_app: Flask, bad_dir: str) -> None:
    """`/?dir=<garbage>` -> Default `desc`, 200, kein SQL-Error."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name=f"dir-adv-{abs(hash(bad_dir)) % 10_000}")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-ADV-DIR")
    client = db_app.test_client()
    login(client)
    resp = client.get("/", query_string={"dir": bad_dir})
    assert resp.status_code == 200, f"dir={bad_dir!r}: bekam {resp.status_code}"
    body = resp.get_data(as_text=True).lower()
    for marker in ("sqlalchemy.exc", "programmingerror", "operationalerror"):
        assert marker not in body, f"dir={bad_dir!r}: SQL-Error-Marker '{marker}' im Body"


def test_dashboard_sort_payload_does_not_modify_database(db_app: Flask) -> None:
    """End-to-End: Findings sind nach SQLi-Payload immer noch unveraendert."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="dashboard-sqli-e2e")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SAFE-1")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SAFE-2")
    client = db_app.test_client()
    login(client)

    resp = client.get(
        "/",
        query_string={
            "sort": "'; DROP TABLE findings;--",
            "dir": "'; DROP TABLE users;--",
        },
    )
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
    assert set(rows) == {"CVE-SAFE-1", "CVE-SAFE-2"}, rows
