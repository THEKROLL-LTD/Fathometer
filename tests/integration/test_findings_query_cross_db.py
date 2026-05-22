"""Integration-Smokes fuer `list_findings_cross_server` gegen echte Postgres-DB.

Diese Tests wurden aus `tests/services/test_findings_query_cross.py` ausgelagert
(TICKET-004, Slice 2). Sie pruefen Cross-Server-Filter-/Sort-Semantik mit
JOIN auf `Server.name`, ILIKE-Suche, stale-Server-Filter und Limit/Total-Count.
Sie sind ohne echte DB nicht sinnvoll testbar — Mocks auf
SQLAlchemy-Session-Internals sind explizit verboten (TICKET-004 Leitplanke 3).

Sie laufen via Auto-Marker (`tests/conftest.py`) als `db_integration`-Suite
und werden im Default-Pytest-Lauf deselektiert.

Geprueft werden (Block M, ADR-0020):
- Leerer Filter -> alle OPEN-Findings ueber alle Server, §15-Default-Sort.
- `q` matcht exakte CVE-ID auf `identifier_key`.
- `q` matcht Substring auf `package_name`.
- `q` matcht Substring auf `Server.name` (via JOIN).
- `kev_only=True` filtert KEV-Findings.
- `stale_only=True` filtert auf Findings stale Server.
- Truncation: 250 Findings x Limit 200 -> 200 Items + total_count = 250.
- `sort="server", dir="asc"` liefert alphabetische Server-Reihenfolge.
"""

from __future__ import annotations

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
from app.schemas.dashboard_filter import DashboardFilter
from app.services.findings_query import list_findings_cross_server

_BASE_TS = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _create_server(
    app: Flask,
    *,
    name: str,
    interval_h: int = 24,
    last_scan_at: datetime | None = None,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=interval_h,
                last_scan_at=last_scan_at,
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
    status: FindingStatus = FindingStatus.OPEN,
    is_kev: bool = False,
    title: str | None = None,
    first_seen_offset_h: int = 0,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            ts = _BASE_TS + timedelta(hours=first_seen_offset_h)
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
                first_seen_at=ts,
                last_seen_at=ts,
                attack_vector=AttackVector.UNKNOWN,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_filter_returns_all_open_findings_sorted(db_app: Flask) -> None:
    """Default-Filter: alle OPEN-Findings sortiert per §15."""
    sid_a = _create_server(db_app, name="alpha")
    sid_b = _create_server(db_app, name="beta")
    _add_finding(db_app, server_id=sid_a, identifier_key="CVE-2024-1111", severity=Severity.LOW)
    _add_finding(
        db_app,
        server_id=sid_b,
        identifier_key="CVE-2024-2222",
        severity=Severity.CRITICAL,
    )
    # Resolved-Finding darf nicht im OPEN-Default auftauchen.
    _add_finding(
        db_app,
        server_id=sid_a,
        identifier_key="CVE-2024-3333",
        severity=Severity.HIGH,
        status=FindingStatus.RESOLVED,
    )

    filt = DashboardFilter()
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            results, total = list_findings_cross_server(sess, filt)
        finally:
            sess.close()

    keys = [f.identifier_key for f in results]
    # Default-Sort `sev,desc`: CRITICAL kommt vor LOW.
    assert keys == ["CVE-2024-2222", "CVE-2024-1111"]
    assert total == 2


def test_q_matches_exact_cve_identifier(db_app: Flask) -> None:
    """`q=CVE-2024-6387` matcht den exakten Identifier-Key."""
    sid = _create_server(db_app, name="srv-cve")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-6387")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-9999")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            filt = DashboardFilter(q="CVE-2024-6387")
            results, total = list_findings_cross_server(sess, filt)
        finally:
            sess.close()

    assert total == 1
    assert results[0].identifier_key == "CVE-2024-6387"


def test_q_matches_package_substring(db_app: Flask) -> None:
    """`q=openssh` matcht Substring auf `package_name`."""
    sid = _create_server(db_app, name="srv-pkg")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-A",
        package_name="openssh-server",
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-B",
        package_name="openssh-client",
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-C",
        package_name="curl",
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            filt = DashboardFilter(q="openssh")
            results, total = list_findings_cross_server(sess, filt)
        finally:
            sess.close()

    assert total == 2
    assert {f.package_name for f in results} == {"openssh-server", "openssh-client"}


def test_q_matches_server_name_substring(db_app: Flask) -> None:
    """`q=edge-02` matcht alle Findings des Servers via JOIN."""
    sid_edge = _create_server(db_app, name="edge-02")
    sid_core = _create_server(db_app, name="core-01")
    _add_finding(db_app, server_id=sid_edge, identifier_key="CVE-2024-EDGE-1")
    _add_finding(db_app, server_id=sid_edge, identifier_key="CVE-2024-EDGE-2")
    _add_finding(db_app, server_id=sid_core, identifier_key="CVE-2024-CORE-1")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            filt = DashboardFilter(q="edge-02")
            results, total = list_findings_cross_server(sess, filt)
        finally:
            sess.close()

    assert total == 2
    assert all(f.identifier_key.startswith("CVE-2024-EDGE-") for f in results)


def test_kev_only_filters_kev_findings(db_app: Flask) -> None:
    """`kev_only=True` liefert nur Findings mit `is_kev=True`."""
    sid = _create_server(db_app, name="srv-kev")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-X", is_kev=True)
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-Y", is_kev=False)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            filt = DashboardFilter(kev_only=True)
            results, total = list_findings_cross_server(sess, filt)
        finally:
            sess.close()

    assert total == 1
    assert results[0].identifier_key == "CVE-2024-X"
    assert results[0].is_kev is True


def test_stale_only_filters_findings_on_stale_servers(db_app: Flask) -> None:
    """`stale_only=True`: nur Findings, deren Server stale ist."""
    fixed_now = datetime(2026, 5, 15, 12, 0, tzinfo=UTC)
    # Fresh: vor 1 Stunde, interval 24h.
    sid_fresh = _create_server(
        db_app,
        name="srv-fresh",
        interval_h=24,
        last_scan_at=fixed_now - timedelta(hours=1),
    )
    # Stale: vor 100 Stunden, interval 24h.
    sid_stale = _create_server(
        db_app,
        name="srv-stale",
        interval_h=24,
        last_scan_at=fixed_now - timedelta(hours=100),
    )
    _add_finding(db_app, server_id=sid_fresh, identifier_key="CVE-FRESH")
    _add_finding(db_app, server_id=sid_stale, identifier_key="CVE-STALE")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            filt = DashboardFilter(stale_only=True)
            results, total = list_findings_cross_server(sess, filt, now=fixed_now)
        finally:
            sess.close()

    assert total == 1
    assert results[0].identifier_key == "CVE-STALE"


def test_stale_only_no_stale_servers_returns_empty(db_app: Flask) -> None:
    """`stale_only=True` ohne stale Server: leeres Resultat, kein Crash."""
    fixed_now = datetime(2026, 5, 15, 12, 0, tzinfo=UTC)
    sid = _create_server(db_app, name="all-fresh", interval_h=24, last_scan_at=fixed_now)
    _add_finding(db_app, server_id=sid, identifier_key="CVE-OK")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            results, total = list_findings_cross_server(
                sess, DashboardFilter(stale_only=True), now=fixed_now
            )
        finally:
            sess.close()

    assert results == []
    assert total == 0


def test_limit_truncates_results_but_total_is_exact(db_app: Flask) -> None:
    """250 Findings x Limit 200 -> 200 zurueck, `total_count = 250`."""
    sid = _create_server(db_app, name="srv-bulk")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            # Bulk-Insert via ORM-Session — schneller als 250 commit-Schleifen.
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
                    first_seen_at=_BASE_TS,
                    last_seen_at=_BASE_TS,
                    attack_vector=AttackVector.UNKNOWN,
                )
                sess.add(f)
            sess.commit()

            results, total = list_findings_cross_server(sess, DashboardFilter(), limit=200)
        finally:
            sess.close()

    assert len(results) == 200
    assert total == 250


def test_sort_server_asc_orders_alphabetically(db_app: Flask) -> None:
    """`sort="server", dir="asc"` sortiert die Findings nach Server.name."""
    sid_charlie = _create_server(db_app, name="charlie")
    sid_alpha = _create_server(db_app, name="alpha")
    sid_bravo = _create_server(db_app, name="bravo")
    _add_finding(db_app, server_id=sid_charlie, identifier_key="CVE-C")
    _add_finding(db_app, server_id=sid_alpha, identifier_key="CVE-A")
    _add_finding(db_app, server_id=sid_bravo, identifier_key="CVE-B")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            results, _ = list_findings_cross_server(
                sess, DashboardFilter(), sort="server", dir="asc"
            )
            # Server-Namen ueber die Server-Relation aufloesen.
            order = [f.server.name for f in results]
        finally:
            sess.close()

    assert order == ["alpha", "bravo", "charlie"]
