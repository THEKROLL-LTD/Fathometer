"""Block O (ADR-0022) §UI-Redesign: Dashboard Risk-KPI-Strip.

Drei Tier:
  1. Action-Required-Cards (yes/no).
  2. Sieben Risk-Band-Pills (escalate -> noise).
  3. Severity-Strip (CRITICAL/HIGH/MEDIUM/LOW, ohne Klick-Filter).

Plus: `?action_required=yes` und `?risk_band=pending` filtern die Tabelle.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

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


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _create_server(app: Flask, *, name: str) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=_now(),
            )
            sess.add(srv)
            sess.flush()
            srv_id = srv.id
            sess.commit()
            return srv_id
        finally:
            sess.close()


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    severity: Severity = Severity.HIGH,
    risk_band: str | None = None,
    status: FindingStatus = FindingStatus.OPEN,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            now = _now()
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key=identifier_key,
                package_name="openssl",
                installed_version="1.0",
                severity=severity,
                status=status,
                is_kev=False,
                attack_vector=AttackVector.UNKNOWN,
                first_seen_at=now,
                last_seen_at=now,
                risk_band=risk_band,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def test_dashboard_kpi_counter_three_servers_different_bands(db_app: Flask) -> None:
    """3 Server mit unterschiedlichen Bands -> Counter korrekt.

    Server A: 1 pending-Finding -> action_required=yes
    Server B: 2 noise-Findings -> action_required=no
    Server C: 1 monitor + 1 escalate -> action_required=yes (escalate dominiert)
    """
    create_admin_user(db_app)
    sid_a = _create_server(db_app, name="srv-a")
    sid_b = _create_server(db_app, name="srv-b")
    sid_c = _create_server(db_app, name="srv-c")

    _add_finding(db_app, server_id=sid_a, identifier_key="CVE-A-1", risk_band="pending")
    _add_finding(db_app, server_id=sid_b, identifier_key="CVE-B-1", risk_band="noise")
    _add_finding(db_app, server_id=sid_b, identifier_key="CVE-B-2", risk_band="noise")
    _add_finding(db_app, server_id=sid_c, identifier_key="CVE-C-1", risk_band="monitor")
    _add_finding(
        db_app,
        server_id=sid_c,
        identifier_key="CVE-C-2",
        risk_band="escalate",
        severity=Severity.CRITICAL,
    )

    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    # 2 Server haben einen Yes-Band-Finding (A, C). 1 Server hat nur No-Bands (B).
    yes_card = re.search(
        r'data-test="action-required-card-yes".*?<span[^>]*>\s*(\d+)\s*</span>',
        body,
        re.DOTALL,
    )
    assert yes_card is not None, "Action-needed-Card mit Server-Count fehlt"
    assert yes_card.group(1) == "2", (
        f"Action-needed-Card sollte 2 Server zeigen, got {yes_card.group(1)}"
    )

    no_card = re.search(
        r'data-test="action-required-card-no".*?<span[^>]*>\s*(\d+)\s*</span>',
        body,
        re.DOTALL,
    )
    assert no_card is not None
    assert no_card.group(1) == "1", f"Safe-Card sollte 1 Server zeigen, got {no_card.group(1)}"

    # Yes-Sub-Counter: escalate=1, pending=1 (act/mitigate/unknown=0).
    assert 'data-test="action-card-yes-sub-escalate"' in body
    assert 'data-test="action-card-yes-sub-pending"' in body
    # 0-Counter werden NICHT gerendert (Card filtert >0).
    assert 'data-test="action-card-yes-sub-act"' not in body

    # Risk-Band-Pills: alle 7 vorhanden, mit korrekten Counts.
    # Wir verifizieren escalate-Count=1, noise-Count=2.
    pending_pill = re.search(
        r'data-test="risk-band-pill-noise".*?tabular-nums">\s*(\d+)\s*</span>',
        body,
        re.DOTALL,
    )
    assert pending_pill is not None
    assert pending_pill.group(1) == "2"


def test_findings_action_required_yes_filter_filters_table(db_app: Flask) -> None:
    """`/findings?action_required=yes` filtert die Tabelle auf yes-Bands.

    Block Q (ADR-0025): Filter ist von `/` auf `/findings` umgezogen.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-filter")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-PENDING", risk_band="pending")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-NOISE", risk_band="noise")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-MONITOR", risk_band="monitor")
    client = db_app.test_client()
    login(client)
    body = client.get("/findings?action_required=yes").get_data(as_text=True)

    section_start = body.find('data-test="findings-table-section"')
    assert section_start >= 0, "Findings-Tabelle muss bei aktiv. Filter gerendert sein"
    section = body[section_start:]
    assert "CVE-PENDING" in section
    assert "CVE-NOISE" not in section
    assert "CVE-MONITOR" not in section


def test_findings_action_required_no_filter_filters_table(db_app: Flask) -> None:
    """`/findings?action_required=no` filtert auf monitor/noise."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-no-filter")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-PENDING", risk_band="pending")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-NOISE", risk_band="noise")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-MONITOR", risk_band="monitor")
    client = db_app.test_client()
    login(client)
    body = client.get("/findings?action_required=no").get_data(as_text=True)
    section = body[body.find('data-test="findings-table-section"') :]
    assert "CVE-NOISE" in section
    assert "CVE-MONITOR" in section
    assert "CVE-PENDING" not in section


def test_findings_risk_band_filter_pending(db_app: Flask) -> None:
    """`/findings?risk_band=pending` filtert auf genau diesen Band."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-rb-filter")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-PENDING", risk_band="pending")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-ESCALATE", risk_band="escalate")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-NOISE", risk_band="noise")
    client = db_app.test_client()
    login(client)
    body = client.get("/findings?risk_band=pending").get_data(as_text=True)
    section = body[body.find('data-test="findings-table-section"') :]
    assert "CVE-PENDING" in section
    assert "CVE-ESCALATE" not in section
    assert "CVE-NOISE" not in section


def test_dashboard_severity_strip_no_click_filter(db_app: Flask) -> None:
    """Severity-Strip rendert ohne `<a>`-Wrapper (kein Klick-Filter)."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-strip")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-S-1",
        severity=Severity.CRITICAL,
        risk_band="pending",
    )
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)
    assert 'data-test="dashboard-severity-strip"' in body
    # Severity-Strip-Items sind <span>, KEIN <a> mit hx-get.
    crit_link = re.search(
        r'<a[^>]*data-test="severity-strip-critical"',
        body,
    )
    assert crit_link is None, "Severity-Strip-Items duerfen keine Klick-Links sein"
    # Critical-Count = 1 (das Finding oben).
    crit_block = re.search(
        r'data-test="severity-strip-critical".*?tabular-nums[^>]*>\s*(\d+)\s*</span>',
        body,
        re.DOTALL,
    )
    assert crit_block is not None
    assert crit_block.group(1) == "1"


def test_dashboard_action_yes_active_highlights_card(db_app: Flask) -> None:
    """Wenn `?action_required=yes` aktiv ist, hat die yes-Card einen
    `ring-2`-Akzent (is_active)."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-active")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-A", risk_band="pending")
    client = db_app.test_client()
    login(client)
    body = client.get("/?action_required=yes").get_data(as_text=True)
    # yes-Card hat `ring-2` (is_active).
    yes_block = re.search(
        r'data-test="action-required-card-yes"[^>]*>',
        body,
    )
    # Suche die Klassen aufm Wrapper-<a>.
    wrapper = re.search(
        r'<a[^>]*data-test="action-required-card-yes"[^>]*>',
        body,
        re.DOTALL,
    )
    assert wrapper is not None
    assert "ring-2" in wrapper.group(0), (
        f"Active yes-Card sollte ring-2 haben, got {wrapper.group(0)!r}"
    )
    # no-Card NICHT active.
    wrapper_no = re.search(
        r'<a[^>]*data-test="action-required-card-no"[^>]*>',
        body,
        re.DOTALL,
    )
    assert wrapper_no is not None
    assert "ring-2" not in wrapper_no.group(0)
    _ = yes_block  # nur fuer mypy-Klarheit
