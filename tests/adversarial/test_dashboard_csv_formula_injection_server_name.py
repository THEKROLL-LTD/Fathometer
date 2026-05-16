"""Adversarial: CSV-Formula-Injection in der Server-Spalte (Block M, ADR-0020).

ARCHITECTURE.md §10 + Block F (`_harden_against_formula`). Excel/LibreOffice
interpretieren Zell-Werte mit `=`/`+`/`-`/`@`/`\\t`/`\\r` als Formel; ein
boeswillig gewaehlter Server-Name koennte beim Oeffnen der CSV in Excel
Schadcode triggern. Mitigation: `'`-Prefix vor solchen Zellen.

Diese Suite verifiziert: Server-Namen, die mit einem Trigger-Zeichen
beginnen, bekommen im Cross-Server-CSV-Export (`/findings/export.csv`
ohne `server_id`) ein fuehrendes Apostroph.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from io import StringIO

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


_TRIGGER_NAMES: list[str] = [
    "=cmd|'/c calc'!A1",
    "+1+1",
    "-7-7",
    "@SUM(A1:A9)",
    "\tprefix-tab",
    "\rprefix-cr",
]


@pytest.mark.parametrize("server_name", _TRIGGER_NAMES)
def test_csv_server_column_gets_apostrophe_prefix(db_app: Flask, server_name: str) -> None:
    """Server-Name mit Trigger-Zeichen bekommt `'`-Prefix in der Server-Spalte."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name=server_name)
    _add_finding(db_app, server_id=sid, identifier_key="CVE-INJ-1")
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/export.csv")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
    assert resp.mimetype == "text/csv"
    body = resp.get_data(as_text=True)
    rows = list(csv.reader(StringIO(body)))
    assert len(rows) >= 2, f"erwartet >= 2 Zeilen (Header + Daten), got {len(rows)}"
    # Erste Datenzeile, erste Spalte ist Server.
    server_cell = rows[1][0]
    assert server_cell.startswith("'"), (
        f"Server-Name {server_name!r} ohne `'`-Prefix in CSV-Server-Spalte: "
        f"{server_cell!r} — OWASP-Formula-Injection-Mitigation greift nicht"
    )
    # Der Trigger-Charakter folgt direkt hinter dem Apostroph.
    assert server_cell[1:2] == server_name[0:1] or server_cell[1:].startswith(
        server_name.lstrip()
    ), f"Apostroph nicht vor dem Trigger-Zeichen: {server_cell!r}"


def test_csv_normal_server_name_unchanged(db_app: Flask) -> None:
    """Normale Server-Namen ohne Trigger-Zeichen bleiben unveraendert."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="normal-srv-prod")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-NORM-1")
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/export.csv")
    body = resp.get_data(as_text=True)
    rows = list(csv.reader(StringIO(body)))
    server_cell = rows[1][0]
    assert server_cell == "normal-srv-prod", server_cell
    # Kein zusaetzlicher Apostroph.
    assert not server_cell.startswith("'")
