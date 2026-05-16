"""View-Tests fuer das Server-Detail-Redesign (Block K, ADR-0018).

Deckt die neuen Sektionen ab:
  * Header / HeaderStats — Tendenz-Label, 4 KPI-Sparklines.
  * Lebenszeichen — HeartbeatLarge + 4-Spalten-Meta-Grid.
  * Severity-Trend — StackedBarChart + Legende.
  * FindingsTable — sortierbare Spalten-Header (`aria-sort`).
  * Sort-URL-Params — `?sort=cvss&dir=desc` veraendert die Reihenfolge.
  * Status-Pill-Reihe — `stale` und `db veraltet`.
  * CSV-Export — Mode `gruppiert` / `diff`.

Tests gegen Filter-Bar-UI-Elemente sind absichtlich nicht in dieser Datei
— die Filter-Bar wurde entfernt (ADR-0018). URL-Param-Filter-Tests
(`?severity=high`, `?status=acknowledged` etc.) bleiben in
`test_server_detail.py`, weil das Filter-Schema selbst erhalten ist.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

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
# Setup-Helpers
# ---------------------------------------------------------------------------


def _create_server(
    app: Flask,
    *,
    name: str = "srv-redesign",
    last_scan_at: datetime | None = None,
    trivy_db_updated_at: datetime | None = None,
    expected_scan_interval_h: int = 24,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=expected_scan_interval_h,
                last_scan_at=last_scan_at,
                trivy_db_updated_at=trivy_db_updated_at,
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
    severity: Severity = Severity.HIGH,
    finding_class: FindingClass = FindingClass.OS_PKGS,
    status: FindingStatus = FindingStatus.OPEN,
    is_kev: bool = False,
    epss_score: float | None = None,
    cvss_v3_score: float | None = None,
    first_seen_at: datetime | None = None,
) -> int:
    factory = get_session_factory(app)
    fseen = first_seen_at or datetime(2026, 5, 1, 10, 0, tzinfo=UTC)
    with app.app_context():
        sess = factory()
        try:
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=finding_class,
                identifier_key=identifier_key,
                package_name=package_name,
                installed_version="1.0",
                severity=severity,
                cvss_v3_score=cvss_v3_score,
                epss_score=epss_score,
                is_kev=is_kev,
                attack_vector=AttackVector.UNKNOWN,
                status=status,
                first_seen_at=fseen,
                last_seen_at=fseen,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Header / HeaderStats / Tendenz / Sparklines
# ---------------------------------------------------------------------------


def test_detail_renders_tendency_label(db_app: Flask) -> None:
    """Header enthaelt einen der drei Tendenz-Strings (`ueber 50 tage ...`)."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-tendency")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    found = (
        "über 50 tage stabil" in body
        or "über 50 tage steigend" in body
        or "über 50 tage fallend" in body
    )
    assert found, "Kein Tendenz-Label im Header gefunden"


def test_detail_renders_kpi_sparklines(db_app: Flask) -> None:
    """Vier KPI-Kacheln (KEV/Critical/High/Medium) mit Sparkline-SVG.

    Wir pruefen die Eyebrow-Labels (`KEV`, `Critical`, `High`, `Medium`) plus
    das Vorhandensein der `aria-label="<label> Verlauf"` aus _kpi_card.html.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-kpis")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-K-001")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Eyebrow-Labels im KPI-Card-Markup.
    for label in ("KEV", "Critical", "High", "Medium"):
        assert f">{label}<" in body, f"KPI-Label '{label}' fehlt im Markup"
    # SVG-Marker pro Karte ueber das aria-label.
    for label in ("KEV", "Critical", "High", "Medium"):
        assert f'aria-label="{label} Verlauf' in body or (
            f'aria-label="{label} keine History' in body
        ), f"SVG-aria-label fuer '{label}' fehlt"


def test_detail_renders_heartbeat_large(db_app: Flask) -> None:
    """Lebenszeichen-Sektion mit Meta-Grid und SVG-Heartbeat."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-hb")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Vier Eyebrow-Labels im Meta-Grid.
    for label in ("Erwarteter Intervall", "Letzter Scan", "Trivy-DB", "KEV-Ereignisse"):
        assert label in body, f"Meta-Grid-Label '{label}' fehlt"
    # Heartbeat-SVG (von _heartbeat_large.html erzeugt) traegt das aria-label
    # "Heartbeat letzte <N> Tage".
    assert "Heartbeat letzte 50 Tage" in body, "Heartbeat-SVG-Markierung fehlt"


def test_detail_renders_trend_section(db_app: Flask) -> None:
    """Severity-Trend-Sektion: StackedBarChart-SVG + Legende mit 'sigma kumulativ'."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-trend")
    # Mindestens 1 Finding, damit die Legende mit Totals gerendert wird.
    _add_finding(db_app, server_id=sid, identifier_key="CVE-T-001")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # SVG aus _stacked_bar_chart.html.
    assert "Severity Trend ueber 50 Tage" in body, "Stacked-Bar-Chart-aria-label fehlt"
    # Legende mit Sigma-Hinweis (Template traegt griechisches sigma).
    assert "σ kumulativ" in body, "Legend-Sigma-Hinweis fehlt"  # noqa: RUF001


# ---------------------------------------------------------------------------
# Sortierbare Findings-Tabelle
# ---------------------------------------------------------------------------


_ROW_RE = re.compile(r"CVE-SORT-\d+")


def test_detail_table_supports_sort_by_column_desc(db_app: Flask) -> None:
    """`?sort=cvss&dir=desc` -> Reihenfolge hoechster CVSS zuerst."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-sort-desc")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SORT-001", cvss_v3_score=3.0)
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SORT-002", cvss_v3_score=9.5)
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SORT-003", cvss_v3_score=6.0)
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?sort=cvss&dir=desc")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    order = _ROW_RE.findall(body)
    # Erstes Vorkommen jeder ID lokalisieren (Tabellen-Reihen).
    first_idx = {}
    for cve in order:
        if cve not in first_idx:
            first_idx[cve] = len(first_idx)
    # Erwartete Reihenfolge nach CVSS desc: 002 (9.5) -> 003 (6.0) -> 001 (3.0).
    assert first_idx["CVE-SORT-002"] < first_idx["CVE-SORT-003"], f"Reihenfolge: {first_idx}"
    assert first_idx["CVE-SORT-003"] < first_idx["CVE-SORT-001"], f"Reihenfolge: {first_idx}"


def test_detail_table_supports_sort_by_column_asc(db_app: Flask) -> None:
    """`?sort=cvss&dir=asc` -> Reihenfolge niedrigster CVSS zuerst."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-sort-asc")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SORT-001", cvss_v3_score=3.0)
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SORT-002", cvss_v3_score=9.5)
    _add_finding(db_app, server_id=sid, identifier_key="CVE-SORT-003", cvss_v3_score=6.0)
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?sort=cvss&dir=asc")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    order = _ROW_RE.findall(body)
    first_idx = {}
    for cve in order:
        if cve not in first_idx:
            first_idx[cve] = len(first_idx)
    # CVSS asc: 001 (3.0) -> 003 (6.0) -> 002 (9.5).
    assert first_idx["CVE-SORT-001"] < first_idx["CVE-SORT-003"], f"Reihenfolge: {first_idx}"
    assert first_idx["CVE-SORT-003"] < first_idx["CVE-SORT-002"], f"Reihenfolge: {first_idx}"


def test_detail_table_renders_sort_indicator(db_app: Flask) -> None:
    """`aria-sort` markiert aktive Spalte, andere haben `aria-sort="none"`."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-sort-aria")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-AR-001", cvss_v3_score=5.0)
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?sort=cvss&dir=desc")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Sortierbare Spalten: cve/pkg/epss/cvss/sev/status/first_seen — 7 Header.
    descending_count = body.count('aria-sort="descending"')
    ascending_count = body.count('aria-sort="ascending"')
    none_count = body.count('aria-sort="none"')
    assert descending_count == 1, f"erwartet 1 descending header, habe {descending_count}"
    assert ascending_count == 0
    # 6 weitere sortierbare Header in none-State.
    assert none_count == 6, f"erwartet 6 none-Header, habe {none_count}"


# ---------------------------------------------------------------------------
# Toolbar: Bulk-Ack-Button
# ---------------------------------------------------------------------------


def test_detail_bulk_ack_button_has_disabled_binding(db_app: Flask) -> None:
    """Bulk-Ack-Toolbar-Button hat Alpine-Disabled-Binding fuer leere Auswahl."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-bulk")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-B-001")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # data-test-Marker aus _findings_section.html.
    assert 'data-test="bulk-ack-toolbar"' in body, "Bulk-Ack-Toolbar-Button-Marker fehlt"
    # Alpine-Disabled-Binding: `:disabled="(window.__detailSelected || []).length === 0"`.
    assert ':disabled="(window.__detailSelected || []).length === 0"' in body, (
        "Alpine-Disabled-Binding fuer Bulk-Ack-Button fehlt"
    )


# ---------------------------------------------------------------------------
# Status-Pill-Reihe (active + stale + db veraltet)
# ---------------------------------------------------------------------------


def test_detail_status_pill_shows_stale_when_scan_stale(db_app: Flask) -> None:
    """Server mit `last_scan_at` aelter als `expected_scan_interval_h` -> stale-Pill."""
    create_admin_user(db_app)
    # Letzter Scan vor 48h, expected_scan_interval_h=24 -> stale.
    stale_scan = datetime.now(tz=UTC) - timedelta(hours=48)
    sid = _create_server(
        db_app,
        name="srv-stale-scan",
        last_scan_at=stale_scan,
        expected_scan_interval_h=24,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # active-Pill und stale-Pill nebeneinander.
    assert ">active<" in body
    assert (
        ">\n            stale\n          <" in body
        or ">stale<" in body
        or ("stale\n          </span>" in body)
    ), "stale-Pill fehlt"


def test_detail_status_pill_shows_db_veraltet_when_db_stale(db_app: Flask) -> None:
    """Server mit `trivy_db_updated_at` > 7 Tage -> db-veraltet-Pill.

    Das Template `detail.html` nutzt eine 168h-Schwelle (= 7 Tage) fuer das
    db-veraltet-Marker — hardcoded in detail.html.
    """
    create_admin_user(db_app)
    db_old = datetime.now(tz=UTC) - timedelta(days=10)
    sid = _create_server(
        db_app,
        name="srv-stale-db",
        last_scan_at=datetime.now(tz=UTC) - timedelta(hours=1),
        trivy_db_updated_at=db_old,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "db veraltet" in body, "db-veraltet-Pill fehlt im Markup"


# ---------------------------------------------------------------------------
# CSV-Export-Modi (Block K)
# ---------------------------------------------------------------------------


def test_csv_export_mode_grouped_includes_group_column(db_app: Flask) -> None:
    """`mode=gruppiert` -> Spalte `Group` in der CSV, Sortierung nach Package."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-csv-group")
    # Zwei Findings auf unterschiedlichen Paketen — `gruppiert` sortiert
    # primaer nach package_name asc.
    _add_finding(db_app, server_id=sid, identifier_key="CVE-G-001", package_name="zlib")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-G-002", package_name="alpine-base")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/findings/export.csv?server_id={sid}&mode=gruppiert")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Header-Zeile enthaelt `Group` als erste Spalte.
    first_line = body.splitlines()[0]
    assert first_line.startswith("Group,"), f"Header-Zeile: {first_line!r}"
    # Body-Zeilen sind nach Paket sortiert: alpine-base vor zlib.
    pos_alpine = body.find("alpine-base")
    pos_zlib = body.find("zlib")
    assert pos_alpine != -1 and pos_zlib != -1, body[:400]
    assert pos_alpine < pos_zlib, "gruppiert-Mode: alpine-base muss vor zlib stehen"


def test_csv_export_mode_diff_includes_diffstatus_column(db_app: Flask) -> None:
    """`mode=diff` -> Spalte `DiffStatus`."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-csv-diff")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/findings/export.csv?server_id={sid}&mode=diff")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    first_line = body.splitlines()[0]
    assert first_line.startswith("DiffStatus,"), f"Header-Zeile: {first_line!r}"


def test_csv_export_mode_diff_no_previous_scan_emits_notice(db_app: Flask) -> None:
    """Server ohne vorherigen Scan -> Hinweis-Zeile als erste Body-Zeile."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-csv-diff-empty")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/findings/export.csv?server_id={sid}&mode=diff")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    lines = body.splitlines()
    assert len(lines) >= 2, f"erwartet Header + Hinweis-Zeile, habe {lines}"
    # Erste Body-Zeile enthaelt den Hinweis.
    assert "Kein vorheriger Scan zum Vergleich" in lines[1], f"Body-Zeile 1: {lines[1]!r}"
