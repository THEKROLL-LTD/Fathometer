"""Tests fuer das Dashboard `/` (Block M, ADR-0020).

Block M hat die Dashboard-Pane-Struktur komplett umgebaut:

  - Quick-Stats sind zu KPI-Cards mit 50-Tage-Sparklines geworden
    (`_kpi_card.html` mit `link_url`-Parameter, Tasks #9/#9a).
  - Cross-Server-Findings-Tabelle als Triage-Surface ersetzt die alte
    Server-Card-Grid und die abgeschaffte `/findings/search`-View.
  - Filter-Bar wandert in die Findings-Section (Hybrid-Auto-Submit, ohne
    `Anwenden`-Button).
  - Aufmerksamkeits-Sektion und Platzhalter sind ersatzlos entfernt.

Die Sidebar (Block I, `base_app.html`) bleibt mit Quick-Stats-Counter und
Server-Liste unangetastet — die wird in `test_sidebar_layout.py` geprueft,
nicht hier.
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
    """Die Sidebar zeigt weiterhin den `no_servers`-Empty-State, wenn die
    Flotte leer ist. Im Dashboard-Pane selbst wird die Findings-Section
    mit einem dedizierten Empty-State (`data-test="findings-empty"`)
    angezeigt."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    assert 'data-empty="no_servers"' in body, body[:600]
    # Findings-Section ist auch ohne Server vorhanden (mit Empty-Inhalt).
    assert 'data-test="dashboard-findings-section"' in body


# ---------------------------------------------------------------------------
# KPI-Cards mit Sparklines (Block M)
# ---------------------------------------------------------------------------


def test_dashboard_renders_kpi_cards_with_sparklines(db_app: Flask) -> None:
    """Fuenf KPI-Card-Instanzen aus `_kpi_card.html` mit jeweils einer
    SVG-Sparkline-Markup-Sektion (auch wenn flat/leer)."""
    create_admin_user(db_app)
    _create_server(db_app, name="kpi-srv-1")
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)

    # Fuenf Card-Marker — siehe `dashboard/_kpi_cards.html`.
    expected = ("total_open", "kev", "critical", "high", "stale_server")
    for label in expected:
        assert f'data-test="kpi-card-{label}"' in body, (
            f"KPI-Card-Marker `kpi-card-{label}` fehlt im Markup"
        )

    # Jede KPI-Card hat ein eigenes `<svg>` (Sparkline oder leerer Container).
    # Wir zaehlen die Card-Container per Marker und stellen sicher, dass
    # mindestens fuenf `<svg ` im Markup auftauchen — Sidebar-Sparklines gibt
    # es im Pane nicht, Header-Logo-SVGs sind im Pane ebenfalls nicht.
    svg_count = body.count("<svg")
    assert svg_count >= 5, f"Erwartet >= 5 SVG-Tags fuer Sparklines, gefunden: {svg_count}"


# ---------------------------------------------------------------------------
# Findings-Tabelle mit Server-Spalte + Tag-Pills
# ---------------------------------------------------------------------------


def test_dashboard_renders_findings_table_with_server_column(db_app: Flask) -> None:
    """`data-test="sort-header-server"` im Header; pro Row Server-Name +
    Tag-Pills (Block M, Task #10)."""
    create_admin_user(db_app)
    sid_prod = _create_server(db_app, name="srv-prod", tags=["prod"])
    sid_web = _create_server(db_app, name="srv-web", tags=["web"])
    _add_finding(db_app, server_id=sid_prod, identifier_key="CVE-2024-0001")
    _add_finding(db_app, server_id=sid_web, identifier_key="CVE-2024-0002")
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    # Server-Sort-Header vorhanden.
    assert 'data-test="sort-header-server"' in body
    # Server-Namen in Tabelle.
    assert "srv-prod" in body
    assert "srv-web" in body
    # Tag-Pills (`#prod`, `#web`) — escaped Form (`#` ist nicht reserviert).
    assert "#prod" in body
    assert "#web" in body


# ---------------------------------------------------------------------------
# Q-Filter
# ---------------------------------------------------------------------------


def test_dashboard_filter_q_matches_cve_identifier(db_app: Flask) -> None:
    """`?q=CVE-2024-6387` → exakt diese CVE in der Tabelle."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="q-srv-cve")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-6387")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-9999")
    client = db_app.test_client()
    login(client)
    body = client.get("/?q=CVE-2024-6387").get_data(as_text=True)

    # Findings-Tabelle: 6387 vorhanden, 9999 nicht.
    # Wir suchen explizit in der dashboard-findings-section.
    section_start = body.find('data-test="dashboard-findings-section"')
    assert section_start >= 0
    section = body[section_start:]
    assert "CVE-2024-6387" in section
    assert "CVE-2024-9999" not in section


def test_dashboard_filter_q_matches_package_substring(db_app: Flask) -> None:
    """`?q=openssh` matched mehrere Findings."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="q-srv-pkg")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-A", package_name="openssh-server")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-B", package_name="openssh-client")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-C", package_name="curl")
    client = db_app.test_client()
    login(client)
    body = client.get("/?q=openssh").get_data(as_text=True)

    section_start = body.find('data-test="dashboard-findings-section"')
    section = body[section_start:]
    assert "openssh-server" in section
    assert "openssh-client" in section
    # `curl` ist in der Tabelle nicht zu finden (Findings-Section).
    # Wir suchen das Finding selbst (CVE-C) anstatt `curl`, weil `curl`
    # potenziell in Skripten/Footer auftauchen koennte.
    assert "CVE-C" not in section


def test_dashboard_filter_q_matches_server_name(db_app: Flask) -> None:
    """`?q=edge-02` matched alle Findings auf dem Server."""
    create_admin_user(db_app)
    sid_edge = _create_server(db_app, name="edge-02")
    sid_core = _create_server(db_app, name="core-01")
    _add_finding(db_app, server_id=sid_edge, identifier_key="CVE-EDGE-1")
    _add_finding(db_app, server_id=sid_edge, identifier_key="CVE-EDGE-2")
    _add_finding(db_app, server_id=sid_core, identifier_key="CVE-CORE-1")
    client = db_app.test_client()
    login(client)
    body = client.get("/?q=edge-02").get_data(as_text=True)

    section_start = body.find('data-test="dashboard-findings-section"')
    section = body[section_start:]
    assert "CVE-EDGE-1" in section
    assert "CVE-EDGE-2" in section
    assert "CVE-CORE-1" not in section


# ---------------------------------------------------------------------------
# Status-Filter
# ---------------------------------------------------------------------------


def test_dashboard_filter_status_acknowledged_only_changes_table(
    db_app: Flask,
) -> None:
    """KPI-Counter bleiben OPEN; Tabelle nur ACK (ADR-0020 Sparkline-Semantik:
    KPI-Counter sind filter-unabhaengig OPEN-Counter)."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="ack-srv")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-OPEN-1")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-ACK-1",
        status=FindingStatus.ACKNOWLEDGED,
    )
    client = db_app.test_client()
    login(client)
    body = client.get("/?status=acknowledged").get_data(as_text=True)

    section_start = body.find('data-test="dashboard-findings-section"')
    section = body[section_start:]
    # Nur das ACK-Finding in der Tabelle.
    assert "CVE-ACK-1" in section
    assert "CVE-OPEN-1" not in section

    # KPI-Counter zeigt weiter den OPEN-Counter (TOTAL OPEN). Es gibt 1 OPEN-
    # Finding in der Flotte; die Card muss den Wert `1` rendern.
    # Wir parsen das aus dem `total_open`-Card-Block.
    total_open_match = re.search(
        r'data-test="kpi-card-total_open".*?font-mono text-2xl[^>]*>(\d+)<',
        body,
        re.DOTALL,
    )
    assert total_open_match is not None, "TOTAL OPEN KPI-Card nicht gefunden"
    assert total_open_match.group(1) == "1", (
        f"TOTAL OPEN sollte 1 zeigen (filter-unabhaengig OPEN-Counter), "
        f"got {total_open_match.group(1)}"
    )


# ---------------------------------------------------------------------------
# Sort
# ---------------------------------------------------------------------------


def test_dashboard_filter_sort_by_server_asc(db_app: Flask) -> None:
    """`sort=server&dir=asc` → Server-Reihenfolge alphabetisch."""
    create_admin_user(db_app)
    sid_c = _create_server(db_app, name="charlie")
    sid_a = _create_server(db_app, name="alpha")
    sid_b = _create_server(db_app, name="bravo")
    _add_finding(db_app, server_id=sid_c, identifier_key="CVE-C")
    _add_finding(db_app, server_id=sid_a, identifier_key="CVE-A")
    _add_finding(db_app, server_id=sid_b, identifier_key="CVE-B")
    client = db_app.test_client()
    login(client)
    body = client.get("/?sort=server&dir=asc").get_data(as_text=True)

    # Tabelle ausschneiden.
    section_start = body.find('data-test="dashboard-findings-section"')
    section = body[section_start:]

    # Reihenfolge: alpha vor bravo vor charlie (data-server-id-Reihenfolge).
    a_pos = section.find("alpha")
    b_pos = section.find("bravo")
    c_pos = section.find("charlie")
    assert 0 < a_pos < b_pos < c_pos, (
        f"Erwartet alphabetisch, got alpha={a_pos} bravo={b_pos} charlie={c_pos}"
    )


# ---------------------------------------------------------------------------
# KPI-Card-Klick setzt Filter
# ---------------------------------------------------------------------------


def test_dashboard_kpi_card_click_sets_filter(db_app: Flask) -> None:
    """Card-`hx-get` setzt den richtigen Query-String fuer den entsprechenden
    Filter (KEV-, Severity-, Stale-Cards)."""
    create_admin_user(db_app)
    _create_server(db_app, name="kpi-click-srv")
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    # `data-test` kommt nach `hx-get` im Macro — wir suchen die Card-`<a>`
    # neutral und extrahieren das gesamte Opening-Tag.
    kev_card_block = re.search(
        r'<a[^>]*data-test="kpi-card-kev"[^>]*>',
        body,
        re.DOTALL,
    )
    assert kev_card_block is not None, "KEV-Card nicht als <a> gerendert"
    kev_tag = kev_card_block.group(0)
    assert "kev_only=1" in kev_tag, f"KEV-Card hx-get setzt nicht kev_only=1: {kev_tag!r}"
    assert "#findings-section" in kev_tag, kev_tag

    # CRITICAL-Card.
    crit_block = re.search(
        r'<a[^>]*data-test="kpi-card-critical"[^>]*>',
        body,
        re.DOTALL,
    )
    assert crit_block is not None
    assert "severity=critical" in crit_block.group(0)

    # STALE-Card.
    stale_block = re.search(
        r'<a[^>]*data-test="kpi-card-stale_server"[^>]*>',
        body,
        re.DOTALL,
    )
    assert stale_block is not None
    assert "stale_only=1" in stale_block.group(0)


def test_dashboard_kpi_total_open_card_resets_filter(db_app: Flask) -> None:
    """Total-Card `link_url` = `/#findings-section` (kein Filter-Query)."""
    create_admin_user(db_app)
    _create_server(db_app, name="kpi-reset-srv")
    client = db_app.test_client()
    login(client)
    body = client.get("/?severity=critical").get_data(as_text=True)

    total_block = re.search(
        r'<a[^>]*data-test="kpi-card-total_open"[^>]*>',
        body,
        re.DOTALL,
    )
    assert total_block is not None, "TOTAL-OPEN-Card nicht als <a>"
    tag = total_block.group(0)
    # `href`/`hx-get` zeigen auf `/` mit `#findings-section` — kein Query-Param.
    assert 'href="/#findings-section"' in tag, tag
    assert 'hx-get="/#findings-section"' in tag, tag
    # Kein Severity-Filter im Reset-Link.
    assert "severity=" not in tag


# ---------------------------------------------------------------------------
# Truncation-Notice
# ---------------------------------------------------------------------------


def test_dashboard_truncation_notice_when_total_exceeds_limit(db_app: Flask) -> None:
    """250 Findings → `data-test="truncation-notice"` enthaelt `50 weitere`.

    Hartes Limit ist 200 (siehe `_build_pane_context()`), Truncation-Block
    rendert `findings_total - len(findings)` = 50.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="bulk-srv")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            for i in range(250):
                f = Finding(
                    server_id=sid,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key=f"CVE-2024-{i:05d}",
                    package_name="openssl",
                    installed_version="1.0",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.OPEN,
                    is_kev=False,
                    attack_vector=AttackVector.UNKNOWN,
                    first_seen_at=_now(),
                    last_seen_at=_now(),
                )
                sess.add(f)
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    assert 'data-test="truncation-notice"' in body
    # Text-Inhalt prueft Anzahl "50 weitere".
    notice_match = re.search(
        r'data-test="truncation-notice"[^>]*>(.*?)</div>',
        body,
        re.DOTALL,
    )
    assert notice_match is not None
    assert "50 weitere" in notice_match.group(1)
    # CSV-Truncation-Link existiert.
    assert 'data-test="truncation-csv-link"' in body


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
# HX-Partial-Swap-Marker / Sort-Header-Target
# ---------------------------------------------------------------------------


def test_dashboard_hx_partial_swap_findings_section_via_hx_select(
    db_app: Flask,
) -> None:
    """Sort-Header `<th>`-Anker setzen `hx-target="#findings-section"` +
    `hx-select="#findings-section"` — der Filter-/Sort-Klick swappt nur
    das Sub-Tree, nicht den ganzen Pane (ADR-0020 Filter-Submit-Verhalten)."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="hx-srv")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SORT-1")
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    # Wir suchen den `sort-header-server`-Block und pruefen die HTMX-Attribute.
    sort_block = re.search(
        r'data-test="sort-header-server">.*?</th>',
        body,
        re.DOTALL,
    )
    assert sort_block is not None
    block = sort_block.group(0)
    assert 'hx-target="#findings-section"' in block
    assert 'hx-select="#findings-section"' in block
    assert 'hx-push-url="true"' in block


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
    """`_build_pane_context()` liefert alle Block-M-Variablen.

    Wir koennen den Context nicht direkt inspizieren, ohne den View aus-
    zufuehren — daher pruefen wir Markup-Marker, die genau dann existieren,
    wenn die jeweilige Variable im Template gesetzt ist.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="ctx-srv")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-CTX-1")
    client = db_app.test_client()
    login(client)
    body = client.get("/", headers={"HX-Request": "true"}).get_data(as_text=True)

    # `view_filter` -> Sort-Header und Filter-Bar-Echo.
    assert 'data-test="sort-header-server"' in body  # view_filter.sort/dir benutzt
    assert 'data-test="findings-filter-bar"' in body  # view_filter im Filter-Echo
    # `findings` -> Tabelle gerendert oder Empty-State.
    assert "CVE-CTX-1" in body or 'data-test="findings-empty"' in body, body[:500]
    # `findings_total` -> Truncation-Logik (kein Notice bei nur 1 Finding).
    assert 'data-test="truncation-notice"' not in body
    # `kpi_sparklines` + `stale_sparkline` -> KPI-Cards.
    assert 'data-test="kpi-card-total_open"' in body
    assert 'data-test="kpi-card-stale_server"' in body
    # `bulk_form` + `csrf_form` -> Bulk-Ack-Modal-Marker.
    assert 'data-test="bulk-ack-modal"' in body
    # `attention` darf NICHT mehr da sein.
    assert "Aufmerksamkeit noetig" not in body


# ---------------------------------------------------------------------------
# Filter-Persistenz / Reset-Link / Active-Badge
# ---------------------------------------------------------------------------


def test_dashboard_filter_is_active_marker_shown(db_app: Flask) -> None:
    """`?q=openssh` aktiviert den `filter.is_active`-Badge."""
    create_admin_user(db_app)
    _create_server(db_app, name="active-srv")
    client = db_app.test_client()
    login(client)
    body = client.get("/?q=openssh").get_data(as_text=True)
    assert "gefiltert" in body
    # Reset-Link in der Filter-Bar.
    assert 'data-test="filter-reset"' in body


def test_dashboard_empty_filter_no_filtered_badge(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="empty-flt-srv")
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)
    assert "gefiltert" not in body
    assert 'data-test="filter-reset"' not in body
