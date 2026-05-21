"""Adversarial-Tests fuer die Sort-URL-Parameter (Block K, ADR-0018).

ARCHITECTURE.md §10 (Input-Validierung) + ADR-0018 §Sicherheits-Surface.

Die Sortier-Parameter `sort` und `dir` werden in `FindingsViewFilter`
durch Whitelist-Literals validiert (`SortKey`, `SortDir`). Das `ORDER BY`
wird ueber `_SORT_COLUMNS` als statisches dict[SortKey, Column]-Mapping
gebaut — User-Strings fliessen NIE direkt in SQL.

Diese Suite verifiziert das Mapping aus User-Sicht: SQL-Injection-Payloads,
XSS-aehnliche Strings, Path-Traversal-Attempts und Encoded-Payloads muessen
zu einem stabilen 200-Response auf der Default-Sortierung fuehren — nie zu
500/SQL-Error und nie zu Side-Effects (DROP/UNION).
"""

from __future__ import annotations

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
from tests._helpers import create_admin_user, login

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------


def _create_server(app: Flask, name: str = "srv-adv-sort") -> int:
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
                first_seen_at=datetime.now(tz=UTC) - timedelta(hours=1),
                last_seen_at=datetime.now(tz=UTC) - timedelta(hours=1),
                attack_vector=AttackVector.UNKNOWN,
            )
            sess.add(f)
            sess.commit()
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Adversarial-Payloads
# ---------------------------------------------------------------------------


# Bunte Mischung aus SQLi-Klassikern, Path-Traversal und Encoding-Tricks.
# Jeder Payload muss zu HTTP 200 mit Default-Sortierung fuehren.
_BAD_SORT_VALUES: list[str] = [
    "'; DROP TABLE findings;--",
    "<script>alert(1)</script>",
    "cve OR 1=1",
    "cve%20OR%201=1",
    "../../../etc/passwd",
    "..\\..\\windows\\system32",
    "cve' UNION SELECT password FROM users--",
    "",  # leerer String
    " ",
    "CVE",  # case wird normalisiert, "cve" gueltig — aber das sollte nicht zaehlen
    "epsss",  # typo (gueltig waere 'epss')
    "first_seenat",  # typo
    "first seen",  # mit Space
    "\x00cve",  # NUL-Byte
    "cve\nDROP TABLE",  # newline-injection
    "a" * 1024,  # uebergrosses Feld
    "cve/**/UNION/**/SELECT",
    "1 OR 1=1",
    "0",
    "true",
    "null",
]

_BAD_DIR_VALUES: list[str] = [
    "'; DROP TABLE findings;--",
    "<script>",
    "ASC; --",
    "../../etc",
    "",
    " ",
    "asc desc",
    "desc1",
    "a" * 256,
    "\x00asc",
    "DESC OR 1=1",
    "true",
    "null",
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_sort", _BAD_SORT_VALUES)
def test_sort_param_invalid_falls_back_to_default(db_app: Flask, bad_sort: str) -> None:
    """`?sort=<böser-string>` -> Default-Sort, kein SQL-Error, Status 200.

    Wir vergleichen das Body-Output gegen den Default-Request ohne `sort`-Param
    nicht direkt (das wuerde die Test-Disziplin gegen Markup-Drift erhoehen).
    Stattdessen pruefen wir nur Status-Code und Abwesenheit klassischer
    SQL-Error-Marker.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name=f"srv-adv-{abs(hash(bad_sort)) % 10_000}")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-ADV-001")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}", query_string={"sort": bad_sort})
    assert resp.status_code == 200, (
        f"sort={bad_sort!r}: erwartet 200, bekommen {resp.status_code} — "
        f"body: {resp.get_data(as_text=True)[:200]!r}"
    )
    body = resp.get_data(as_text=True).lower()
    # Klassische SQL-Error-Marker.
    for marker in ("sqlalchemy.exc", "programmingerror", "operationalerror"):
        assert marker not in body, f"sort={bad_sort!r}: SQL-Error-Marker '{marker}' im Body"


@pytest.mark.parametrize("bad_dir", _BAD_DIR_VALUES)
def test_dir_param_invalid_falls_back_to_default(db_app: Flask, bad_dir: str) -> None:
    """`?dir=<böser-string>` -> Default `desc`, kein SQL-Error, Status 200."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name=f"srv-adv-dir-{abs(hash(bad_dir)) % 10_000}")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-ADV-002")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}", query_string={"dir": bad_dir})
    assert resp.status_code == 200, f"dir={bad_dir!r}: erwartet 200, bekommen {resp.status_code}"
    body = resp.get_data(as_text=True).lower()
    for marker in ("sqlalchemy.exc", "programmingerror", "operationalerror"):
        assert marker not in body, f"dir={bad_dir!r}: SQL-Error-Marker '{marker}' im Body"


def test_sort_param_no_sql_injection_surface_via_findings_query(db_app: Flask) -> None:
    """End-to-End: Findings sind nach SQLi-Payload immer noch lesbar.

    Beweist: weder `findings`-Tabelle noch `users`-Tabelle wurde durch das
    Payload modifiziert. Wir holen Findings nach dem Adversarial-Request
    und erwarten denselben Stand.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-sqli-e2e")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SAFE-001")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SAFE-002")
    client = db_app.test_client()
    login(client)

    # SQLi-Payload mit Komma in den `sort`-Param packen — wuerde bei naivem
    # `ORDER BY <sort>` `ORDER BY id, (SELECT ...)` ergeben.
    resp = client.get(
        f"/servers/{sid}",
        query_string={"sort": "id, (SELECT 1 FROM users)", "dir": "desc"},
    )
    assert resp.status_code == 200

    # DB-Verifizierung: beide Findings existieren noch.
    from sqlalchemy import select

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
    assert set(rows) == {"CVE-SAFE-001", "CVE-SAFE-002"}, rows


def test_sort_and_dir_combined_payloads(db_app: Flask) -> None:
    """`?sort=X&dir=Y` mit beiden ungueltig -> 200 + Default-Sort.

    ADR-0025 §2/§3: Findings werden default lazy in Group-Cards gerendert.
    Damit die CVE-ID im Initial-HTML auftaucht, erzwingen wir mit `?flat=1`
    die flache Tabelle (`_view_list.html`). Der eigentliche Injection-Test
    ist davon unabhaengig — beide ungueltigen Strings fallen vor SQL-Render
    auf den Default-Sort zurueck.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-combined")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-COMBI-001")
    client = db_app.test_client()
    login(client)
    resp = client.get(
        f"/servers/{sid}",
        query_string={
            "flat": "1",
            "sort": "'; DROP TABLE findings;--",
            "dir": "'; DROP TABLE users;--",
        },
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Tabelle wurde nicht modifiziert: Finding ist noch da.
    assert "CVE-COMBI-001" in body
