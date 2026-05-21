"""Tests fuer das Dashboard `/` (Block M / Block Q, ADR-0020 / ADR-0025).

Block M hatte die Cross-Server-Findings-Tabelle als Triage-Surface auf
das Dashboard gestellt. Block Q (ADR-0025) hat diese Tabelle wieder
ausgelagert auf eine dedizierte `/findings`-Seite — das Dashboard zeigt
seitdem nur noch:

  - die KPI-Strip (Action-Required-Cards, Risk-Band-Pills, Severity-Strip)
    aus Block O (ADR-0022).
  - keinen Findings-Tabellen-Render mehr, keine Filter-Bar im Pane.

Die Sidebar (Block I, `base_app.html`) bleibt mit Quick-Stats-Counter und
Server-Liste unangetastet — die wird in `test_sidebar_layout.py` geprueft,
nicht hier.

Findings-Tabelle / Filter-/Sort-/Pagination-Verhalten ist auf
`tests/views/test_findings_index.py` und
`tests/services/test_findings_query_cross.py` umgezogen.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

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
    ServerTag,
    Severity,
    Tag,
)
from tests._helpers import create_admin_user, login

# ---------------------------------------------------------------------------
# Setup-Helper
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _create_server(
    app: Flask,
    *,
    name: str,
    last_scan_at: datetime | None = None,
    expected_scan_interval_h: int = 24,
    retired_at: datetime | None = None,
    revoked_at: datetime | None = None,
    trivy_db_updated_at: datetime | None = None,
    tags: list[str] | None = None,
) -> int:
    """Legt einen Server inkl. Tags direkt via ORM an, liefert die ID."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=expected_scan_interval_h,
                last_scan_at=last_scan_at if last_scan_at is not None else _now(),
                retired_at=retired_at,
                revoked_at=revoked_at,
                trivy_db_updated_at=trivy_db_updated_at,
            )
            sess.add(srv)
            sess.flush()
            srv_id = srv.id

            if tags:
                for tag_name in tags:
                    tag = sess.execute(select(Tag).where(Tag.name == tag_name)).scalar_one_or_none()
                    if tag is None:
                        tag = Tag(name=tag_name, color="#6b7280")
                        sess.add(tag)
                        sess.flush()
                    sess.add(ServerTag(server_id=srv_id, tag_id=tag.id))

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
    status: FindingStatus = FindingStatus.OPEN,
    is_kev: bool = False,
    package_name: str = "openssl",
    title: str | None = None,
) -> int:
    """Legt ein Finding direkt via ORM an."""
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
                package_name=package_name,
                installed_version="1.0",
                severity=severity,
                status=status,
                is_kev=is_kev,
                title=title,
                attack_vector=AttackVector.UNKNOWN,
                first_seen_at=now,
                last_seen_at=now,
                acknowledged_at=now if status == FindingStatus.ACKNOWLEDGED else None,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Auth-Pfad
# ---------------------------------------------------------------------------


def test_dashboard_redirects_when_not_logged_in(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302), resp.status_code
    assert "/login" in resp.headers.get("Location", "")


def test_dashboard_renders_empty_state_when_no_servers(db_app: Flask) -> None:
    """Die Sidebar zeigt den `no_servers`-Empty-State, wenn die Flotte leer
    ist. ADR-0025 (Block Q): Findings-Section ist nicht mehr im Dashboard.
    """
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    assert 'data-empty="no_servers"' in body, body[:600]
    # Block Q (ADR-0025): KEIN Findings-Section-Marker mehr im Dashboard.
    assert 'data-test="dashboard-findings-section"' not in body
    assert 'data-test="sort-header-server"' not in body


# ---------------------------------------------------------------------------
# KPI-Cards mit Sparklines (Block M)
# ---------------------------------------------------------------------------


def test_dashboard_renders_risk_kpi_strip(db_app: Flask) -> None:
    """Block O (ADR-0022): Drei-Tier-KPI-Strip ersetzt die Block-M-Sparkline-
    Cards. Zwei Action-Required-Cards links, sieben Risk-Band-Pills rechts,
    Severity-Strip darunter."""
    create_admin_user(db_app)
    _create_server(db_app, name="kpi-srv-1")
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)

    # Tier 1: zwei Action-Required-Cards.
    assert 'data-test="action-required-card-yes"' in body
    assert 'data-test="action-required-card-no"' in body

    # Tier 2: sieben Risk-Band-Pills.
    for band in ("escalate", "act", "mitigate", "pending", "unknown", "monitor", "noise"):
        assert f'data-test="risk-band-pill-{band}"' in body, (
            f"Risk-Band-Pill `{band}` fehlt im Markup"
        )

    # Tier 3: Severity-Strip.
    for sev in ("critical", "high", "medium", "low"):
        assert f'data-test="severity-strip-{sev}"' in body, (
            f"Severity-Strip-Item `{sev}` fehlt im Markup"
        )


# ---------------------------------------------------------------------------
# KPI-Card-Links auf `/findings`
# ---------------------------------------------------------------------------


def test_dashboard_action_required_cards_link_to_findings_view(db_app: Flask) -> None:
    """Block Q (ADR-0025): Action-Required-Cards linken auf `/findings` mit
    `?action_required=yes|no` als Query. KEIN HTMX-Swap mehr.

    Risk-Band-Pills linken analog auf `/findings?risk_band=<band>`.
    """
    create_admin_user(db_app)
    _create_server(db_app, name="kpi-click-srv")
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    # Action-needed-Card linkt auf /findings?action_required=yes.
    yes_card = re.search(
        r'<a[^>]*data-test="action-required-card-yes"[^>]*>',
        body,
        re.DOTALL,
    )
    assert yes_card is not None
    yes_tag = yes_card.group(0)
    assert "/findings?action_required=yes" in yes_tag, yes_tag
    # ADR-0025: Full-Page-Nav, kein HTMX-Swap.
    assert "hx-get=" not in yes_tag, yes_tag
    assert "#findings-section" not in yes_tag, yes_tag

    # Safe-Card linkt auf /findings?action_required=no.
    no_card = re.search(
        r'<a[^>]*data-test="action-required-card-no"[^>]*>',
        body,
        re.DOTALL,
    )
    assert no_card is not None
    assert "/findings?action_required=no" in no_card.group(0)

    # Risk-Band-Pill (Pending) linkt auf /findings?risk_band=pending.
    pending_pill = re.search(
        r'<a[^>]*data-test="risk-band-pill-pending"[^>]*>',
        body,
        re.DOTALL,
    )
    assert pending_pill is not None
    pp_tag = pending_pill.group(0)
    assert "/findings?risk_band=pending" in pp_tag, pp_tag
    assert "hx-get=" not in pp_tag, pp_tag


def test_dashboard_severity_strip_has_no_click_filter(db_app: Flask) -> None:
    """Block O (ADR-0022): Severity-Strip ist KEIN Filter — nur Display."""
    create_admin_user(db_app)
    _create_server(db_app, name="sev-strip-srv")
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    # Severity-Strip-Marker existiert.
    assert 'data-test="dashboard-severity-strip"' in body
    # Keine <a>-Wrapper um die Severity-Strip-Items.
    crit_block = re.search(
        r'<a[^>]*data-test="severity-strip-critical"[^>]*>',
        body,
        re.DOTALL,
    )
    assert crit_block is None, "Severity-Strip darf kein Klick-Filter sein"


# ---------------------------------------------------------------------------
# Negative Markup-Asserts: keine Attention-Section, kein Platzhalter
# ---------------------------------------------------------------------------


def test_dashboard_no_attention_section(db_app: Flask) -> None:
    """ADR-0020: Die alte Aufmerksamkeits-Sektion (`_attention.html`)
    existiert nicht mehr."""
    create_admin_user(db_app)
    sid = _create_server(
        db_app,
        name="att-srv",
        last_scan_at=_now() - timedelta(hours=50),
        expected_scan_interval_h=24,
    )
    _add_finding(db_app, server_id=sid, identifier_key="CVE-ATT", is_kev=True)
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    # Der gesamte Pane (zwischen `dashboard-pane`-Open und Ende der Section)
    # darf den alten Attention-Header NICHT enthalten.
    assert "Aufmerksamkeit noetig" not in body, (
        "Attention-Sektion sollte mit Block M (ADR-0020) entfallen sein"
    )
    assert "KEV-betroffen" not in body
    # Der Sidebar-DB-Stale-Bucket ist ebenfalls weg.
    assert "Trivy-DB veraltet" not in body


def test_dashboard_no_platzhalter(db_app: Flask) -> None:
    """ADR-0020: kein dashed-border-Platzhalter-Block ("Hier kommt
    spaeter ein Widget-Bereich") mehr im Pane."""
    create_admin_user(db_app)
    _create_server(db_app, name="placeholder-srv")
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    assert "Platzhalter" not in body
    # `border-dashed` darf nicht im Dashboard-Pane-Block selbst auftauchen.
    pane_start = body.find('id="dashboard-pane"')
    pane_end = body.find("</div>\n\n    </main>", pane_start)
    if pane_end == -1:
        pane_end = body.find("</main>", pane_start)
    pane_section = body[pane_start:pane_end] if pane_start >= 0 else ""
    assert "border-dashed" not in pane_section, (
        "Dashed-Border-Platzhalter ist mit Block M (ADR-0020) entfallen"
    )


# ---------------------------------------------------------------------------
# /findings/search → 404
# ---------------------------------------------------------------------------


def test_dashboard_search_route_404(db_app: Flask) -> None:
    """`GET /findings/search` → 404 (Block M, ADR-0020 ersatzlos entfernt)."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/findings/search")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# CSV-Export Cross-Server
# ---------------------------------------------------------------------------


def test_dashboard_csv_export_cross_server_uses_filter(db_app: Flask) -> None:
    """`/findings/export.csv?q=openssh` → CSV mit `Server`-Spalte und gefiltert."""
    create_admin_user(db_app)
    sid_a = _create_server(db_app, name="csv-srv-a")
    sid_b = _create_server(db_app, name="csv-srv-b")
    _add_finding(db_app, server_id=sid_a, identifier_key="CVE-OS-1", package_name="openssh-server")
    _add_finding(db_app, server_id=sid_b, identifier_key="CVE-OS-2", package_name="openssh-client")
    _add_finding(db_app, server_id=sid_a, identifier_key="CVE-CURL", package_name="curl")
    client = db_app.test_client()
    login(client)
    resp = client.get("/findings/export.csv?q=openssh")

    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    body = resp.get_data(as_text=True)
    # Header-Zeile beginnt mit `Server` (Cross-Server-Mode).
    first_line = body.splitlines()[0]
    assert first_line.startswith("Server,"), first_line
    # Nur openssh-Findings (gefiltert).
    assert "openssh-server" in body
    assert "openssh-client" in body
    assert "curl" not in body
    # Server-Namen sind in der ersten Spalte.
    assert "csv-srv-a" in body
    assert "csv-srv-b" in body


# ---------------------------------------------------------------------------
# Bulk-Acknowledge cross-server
# ---------------------------------------------------------------------------


def test_dashboard_bulk_ack_cross_server(db_app: Flask) -> None:
    """`POST /api/findings/bulk-acknowledge` akzeptiert `finding_ids`
    quer ueber mehrere Server (Endpoint aus Block F, hier nur Smoke)."""
    create_admin_user(db_app)
    sid_a = _create_server(db_app, name="bulk-srv-a")
    sid_b = _create_server(db_app, name="bulk-srv-b")
    fid_a = _add_finding(db_app, server_id=sid_a, identifier_key="CVE-BULK-A")
    fid_b = _add_finding(db_app, server_id=sid_b, identifier_key="CVE-BULK-B")
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": [fid_a, fid_b], "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 2
    assert body["applied"] is True
    # Cross-Server: `server_count` muss 2 sein.
    assert body["server_count"] == 2

    # Beide Findings stehen jetzt auf ACK.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            for fid in (fid_a, fid_b):
                f = sess.execute(select(Finding).where(Finding.id == fid)).scalar_one()
                assert f.status == FindingStatus.ACKNOWLEDGED
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# View-Context-Vertrag
# ---------------------------------------------------------------------------


def test_dashboard_pane_context_complete(db_app: Flask) -> None:
    """Dashboard-Pane (post-Block-Q) zeigt nur noch die KPI-Strip.

    Wir koennen den Context nicht direkt inspizieren, ohne den View aus-
    zufuehren — daher pruefen wir Markup-Marker, die genau dann existieren,
    wenn die jeweilige Variable im Template gesetzt ist. ADR-0025: keine
    Findings-Tabelle/Filter-Bar/Bulk-Ack-Modal mehr im Pane.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="ctx-srv")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-CTX-1")
    client = db_app.test_client()
    login(client)
    body = client.get("/", headers={"HX-Request": "true"}).get_data(as_text=True)

    # `risk_kpis` -> Action-Required-Cards + Risk-Band-Pills + Severity-Strip.
    assert 'data-test="action-required-card-yes"' in body
    assert 'data-test="action-required-card-no"' in body
    assert 'data-test="risk-band-pill-pending"' in body
    assert 'data-test="dashboard-severity-strip"' in body

    # ADR-0025 (Block Q): KEINE Findings-Tabelle/Filter-Bar/Bulk-Ack-Modal
    # mehr im Dashboard.
    assert 'data-test="dashboard-findings-section"' not in body
    assert 'data-test="findings-filter-bar"' not in body
    assert 'data-test="sort-header-server"' not in body
    assert 'data-test="bulk-ack-modal"' not in body
    assert 'data-test="truncation-notice"' not in body

    # `attention` darf weiterhin NICHT da sein (ADR-0020).
    assert "Aufmerksamkeit noetig" not in body
