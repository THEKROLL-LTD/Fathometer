"""Block O (ADR-0022): Findings-Query / Sort / Filter mit `risk_band`.

Direct-Service-Tests (kein HTTP-Roundtrip noetig), weil die Sort-Logik
in `app/services/findings_query.py` lebt. Verifiziert:

  - `?risk_band=pending` filtert auf genau diesen Band.
  - `?action_required=yes` filtert auf alle fuenf Yes-Baender.
  - Default-Sort `risk` zeigt escalate/act/mitigate/pending vor unknown
    vor monitor vor noise.
  - Sort-Header-Klick auf Risk toggelt asc/desc.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Flask

from app.db import get_session, get_session_factory
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
from app.services.findings_query import list_findings_cross_server
from tests._helpers import create_admin_user, login


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _seed(app: Flask, *, server_name: str, findings: list[tuple[str, str | None]]) -> int:
    """Seedet einen Server mit Findings (identifier_key, risk_band). Returns server_id."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=server_name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=_now(),
            )
            sess.add(srv)
            sess.flush()
            srv_id = srv.id
            for ident, band in findings:
                f = Finding(
                    server_id=srv_id,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key=ident,
                    package_name="openssl",
                    installed_version="1.0",
                    severity=Severity.HIGH,
                    status=FindingStatus.OPEN,
                    is_kev=False,
                    attack_vector=AttackVector.UNKNOWN,
                    first_seen_at=_now(),
                    last_seen_at=_now(),
                    risk_band=band,
                )
                sess.add(f)
            sess.commit()
            return srv_id
        finally:
            sess.close()


def test_list_findings_cross_server_filter_risk_band(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed(
        db_app,
        server_name="srv-rb",
        findings=[
            ("CVE-PENDING", "pending"),
            ("CVE-NOISE", "noise"),
            ("CVE-MONITOR", "monitor"),
        ],
    )
    with db_app.app_context():
        sess = get_session()
        filt = DashboardFilter(risk_band="pending")
        results, total = list_findings_cross_server(sess, filt)
        assert total == 1
        assert [f.identifier_key for f in results] == ["CVE-PENDING"]


def test_list_findings_cross_server_filter_action_required_yes(db_app: Flask) -> None:
    """`action_required=yes` filtert auf alle fuenf Yes-Baender."""
    create_admin_user(db_app)
    _seed(
        db_app,
        server_name="srv-ar",
        findings=[
            ("CVE-ESCALATE", "escalate"),
            ("CVE-ACT", "act"),
            ("CVE-MITIGATE", "mitigate"),
            ("CVE-PENDING", "pending"),
            ("CVE-UNKNOWN", "unknown"),
            ("CVE-MONITOR", "monitor"),
            ("CVE-NOISE", "noise"),
        ],
    )
    with db_app.app_context():
        sess = get_session()
        filt = DashboardFilter(action_required="yes")
        results, total = list_findings_cross_server(sess, filt)
        assert total == 5
        idents = {f.identifier_key for f in results}
        assert idents == {
            "CVE-ESCALATE",
            "CVE-ACT",
            "CVE-MITIGATE",
            "CVE-PENDING",
            "CVE-UNKNOWN",
        }


def test_list_findings_cross_server_default_sort_is_risk_desc(db_app: Flask) -> None:
    """Default-Sort `risk` zeigt escalate/act/mitigate vor pending vor
    unknown vor monitor vor noise."""
    create_admin_user(db_app)
    _seed(
        db_app,
        server_name="srv-sort",
        findings=[
            ("CVE-NOISE", "noise"),
            ("CVE-PENDING", "pending"),
            ("CVE-ESCALATE", "escalate"),
            ("CVE-ACT", "act"),
            ("CVE-MITIGATE", "mitigate"),
            ("CVE-MONITOR", "monitor"),
            ("CVE-UNKNOWN", "unknown"),
        ],
    )
    with db_app.app_context():
        sess = get_session()
        filt = DashboardFilter()  # default sort=risk, dir=desc
        results, _ = list_findings_cross_server(sess, filt, sort=filt.sort, dir=filt.dir)
        order = [f.identifier_key for f in results]
        # escalate(70), act(60), mitigate(50), pending(40), unknown(30),
        # monitor(20), noise(10).
        expected = [
            "CVE-ESCALATE",
            "CVE-ACT",
            "CVE-MITIGATE",
            "CVE-PENDING",
            "CVE-UNKNOWN",
            "CVE-MONITOR",
            "CVE-NOISE",
        ]
        assert order == expected, f"got {order}"


def test_list_findings_cross_server_sort_risk_asc_reverses(db_app: Flask) -> None:
    """`sort=risk&dir=asc` kehrt die Reihenfolge um (noise zuerst)."""
    create_admin_user(db_app)
    _seed(
        db_app,
        server_name="srv-sort-asc",
        findings=[
            ("CVE-NOISE", "noise"),
            ("CVE-PENDING", "pending"),
            ("CVE-ESCALATE", "escalate"),
        ],
    )
    with db_app.app_context():
        sess = get_session()
        filt = DashboardFilter(sort="risk", dir="asc")
        results, _ = list_findings_cross_server(sess, filt, sort=filt.sort, dir=filt.dir)
        order = [f.identifier_key for f in results]
        assert order == ["CVE-NOISE", "CVE-PENDING", "CVE-ESCALATE"]


def test_dashboard_view_default_sort_risk_renders_escalate_first(db_app: Flask) -> None:
    """Smoke-Test: Default-Sort auf dem View liefert escalate-Pill zuerst
    in der Tabelle."""
    create_admin_user(db_app)
    _seed(
        db_app,
        server_name="srv-view-sort",
        findings=[
            ("CVE-NOISE", "noise"),
            ("CVE-ESCALATE", "escalate"),
        ],
    )
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)
    # In der Tabelle sollte CVE-ESCALATE vor CVE-NOISE auftauchen.
    section = body[body.find('data-test="dashboard-findings-section"') :]
    esc = section.find("CVE-ESCALATE")
    noise = section.find("CVE-NOISE")
    assert esc > 0 and noise > 0
    assert esc < noise, f"escalate({esc}) muss vor noise({noise}) erscheinen"
