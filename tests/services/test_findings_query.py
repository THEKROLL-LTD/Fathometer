"""Unit-Tests fuer den Findings-Query-Service (Block E).

Geprueft werden:
- Default-Sortierung gemaess ARCHITECTURE.md §15:
  KEV desc, EPSS desc nulls last, CVSS desc nulls last, Severity-Rank desc,
  first_seen_at asc.
- Class-Toggle (`both` -> OS oben, `os-pkgs` / `lang-pkgs` filtern korrekt).
- Status- / KEV- / Severity-Min- / Search-Filter.
- `limit`-Cap.
- `count_findings` ignoriert den Status-Filter.

Findings werden direkt via ORM angelegt — kompakter als der Ingest-Pfad und
deckt genau die Sort-/Filter-Semantik ab, die Block E garantiert.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Severity,
)
from app.schemas.dashboard_filter import DashboardFilter
from app.services.findings_query import (
    FindingsFilter,
    count_findings,
    list_findings,
    list_findings_cross_server,
)
from tests._helpers import register_test_server

# ---------------------------------------------------------------------------
# Fixture-Helpers
# ---------------------------------------------------------------------------


_BASE_TS = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _make_finding(
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
    title: str | None = None,
    first_seen_offset_h: int = 0,
) -> Finding:
    """Erzeugt eine Finding-Instanz mit sinnvollen Defaults."""
    ts = _BASE_TS + timedelta(hours=first_seen_offset_h)
    return Finding(
        server_id=server_id,
        finding_type=FindingType.VULNERABILITY,
        finding_class=finding_class,
        identifier_key=identifier_key,
        package_name=package_name,
        installed_version="1.0.0",
        fixed_version=None,
        severity=severity,
        title=title,
        description=None,
        cvss_v3_score=cvss_v3_score,
        epss_score=epss_score,
        is_kev=is_kev,
        attack_vector=AttackVector.UNKNOWN,
        status=status,
        first_seen_at=ts,
        last_seen_at=ts,
    )


def _persist(app: Flask, findings: list[Finding]) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            for f in findings:
                sess.add(f)
            sess.commit()
        finally:
            sess.close()


def _session(app: Flask) -> Any:
    """Liefert eine neue ORM-Session — die App muss aktiver Context sein."""
    factory = get_session_factory(app)
    return factory()


# ---------------------------------------------------------------------------
# Default-Sort §15
# ---------------------------------------------------------------------------


def test_default_sort_puts_kev_first(db_app: Flask) -> None:
    """KEV-Findings stehen vor non-KEV (desc), unabhaengig von EPSS/CVSS."""
    sid, _ = register_test_server(db_app, name="srv-sort-kev")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-1001",
                is_kev=False,
                epss_score=0.99,
                cvss_v3_score=10.0,
                severity=Severity.CRITICAL,
            ),
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-1002",
                is_kev=True,
                epss_score=0.01,
                cvss_v3_score=4.0,
                severity=Severity.LOW,
            ),
        ],
    )
    filt = FindingsFilter(finding_class="os-pkgs")
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows = list_findings(sess, sid, filt)
        finally:
            sess.close()

    assert [f.identifier_key for f in rows] == ["CVE-2026-1002", "CVE-2026-1001"]
    assert rows[0].is_kev is True


def test_default_sort_epss_desc_with_nulls_last(db_app: Flask) -> None:
    """Bei gleicher KEV-Stufe: hoechstes EPSS zuerst, NULL-EPSS zuletzt."""
    sid, _ = register_test_server(db_app, name="srv-sort-epss")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-2001", epss_score=None, cvss_v3_score=9.0
            ),
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-2002", epss_score=0.8, cvss_v3_score=5.0
            ),
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-2003", epss_score=0.3, cvss_v3_score=5.0
            ),
        ],
    )
    filt = FindingsFilter(finding_class="os-pkgs")
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows = list_findings(sess, sid, filt)
        finally:
            sess.close()

    keys = [f.identifier_key for f in rows]
    # EPSS 0.8 > 0.3 > None.
    assert keys == ["CVE-2026-2002", "CVE-2026-2003", "CVE-2026-2001"]


def test_default_sort_cvss_after_epss(db_app: Flask) -> None:
    """Bei gleicher EPSS-Stufe entscheidet CVSS desc nulls last."""
    sid, _ = register_test_server(db_app, name="srv-sort-cvss")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-3001", epss_score=0.5, cvss_v3_score=6.0
            ),
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-3002", epss_score=0.5, cvss_v3_score=9.0
            ),
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-3003", epss_score=0.5, cvss_v3_score=None
            ),
        ],
    )
    filt = FindingsFilter(finding_class="os-pkgs")
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows = list_findings(sess, sid, filt)
        finally:
            sess.close()
    assert [f.identifier_key for f in rows] == [
        "CVE-2026-3002",
        "CVE-2026-3001",
        "CVE-2026-3003",
    ]


def test_default_sort_severity_rank_tiebreaker(db_app: Flask) -> None:
    """Bei gleicher CVSS/EPSS sortiert die Severity-Rank-CASE-Expr.

    CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN.
    """
    sid, _ = register_test_server(db_app, name="srv-sort-sev")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-4001",
                severity=Severity.LOW,
                cvss_v3_score=None,
                epss_score=None,
                first_seen_offset_h=0,
            ),
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-4002",
                severity=Severity.CRITICAL,
                cvss_v3_score=None,
                epss_score=None,
                first_seen_offset_h=1,
            ),
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-4003",
                severity=Severity.MEDIUM,
                cvss_v3_score=None,
                epss_score=None,
                first_seen_offset_h=2,
            ),
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-4004",
                severity=Severity.HIGH,
                cvss_v3_score=None,
                epss_score=None,
                first_seen_offset_h=3,
            ),
        ],
    )
    filt = FindingsFilter(finding_class="os-pkgs")
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows = list_findings(sess, sid, filt)
        finally:
            sess.close()
    assert [f.severity for f in rows] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
    ]


def test_class_both_puts_os_pkgs_before_lang_pkgs(db_app: Flask) -> None:
    """`class=both` setzt OS-Findings VOR Lang-Findings, ueber KEV hinaus."""
    sid, _ = register_test_server(db_app, name="srv-class-both")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-5001",
                package_name="libfoo",
                finding_class=FindingClass.LANG_PKGS,
                is_kev=True,
                epss_score=0.99,
                cvss_v3_score=9.5,
                severity=Severity.CRITICAL,
            ),
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-5002",
                package_name="openssl",
                finding_class=FindingClass.OS_PKGS,
                is_kev=False,
                epss_score=0.05,
                cvss_v3_score=5.0,
                severity=Severity.MEDIUM,
            ),
        ],
    )
    filt = FindingsFilter(finding_class="both")
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows = list_findings(sess, sid, filt)
        finally:
            sess.close()
    # OS-Finding zuerst, obwohl es kein KEV ist und niedriger CVSS hat.
    assert rows[0].finding_class == FindingClass.OS_PKGS
    assert rows[0].identifier_key == "CVE-2026-5002"


# ---------------------------------------------------------------------------
# Class-/Status-/KEV-/Severity-Filter
# ---------------------------------------------------------------------------


def test_class_os_pkgs_filters_correctly(db_app: Flask) -> None:
    sid, _ = register_test_server(db_app, name="srv-cls-os")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-6001",
                package_name="openssl",
                finding_class=FindingClass.OS_PKGS,
            ),
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-6002",
                package_name="libfoo",
                finding_class=FindingClass.LANG_PKGS,
            ),
        ],
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows_os = list_findings(sess, sid, FindingsFilter(finding_class="os-pkgs"))
            rows_lang = list_findings(sess, sid, FindingsFilter(finding_class="lang-pkgs"))
        finally:
            sess.close()
    assert [f.identifier_key for f in rows_os] == ["CVE-2026-6001"]
    assert [f.identifier_key for f in rows_lang] == ["CVE-2026-6002"]


def test_status_acknowledged_shows_only_ack(db_app: Flask) -> None:
    sid, _ = register_test_server(db_app, name="srv-status-ack")
    _persist(
        db_app,
        [
            _make_finding(server_id=sid, identifier_key="CVE-2026-7001", status=FindingStatus.OPEN),
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-7002", status=FindingStatus.ACKNOWLEDGED
            ),
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-7003", status=FindingStatus.RESOLVED
            ),
        ],
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows = list_findings(
                sess,
                sid,
                FindingsFilter(status="acknowledged", finding_class="os-pkgs"),
            )
        finally:
            sess.close()
    assert [f.identifier_key for f in rows] == ["CVE-2026-7002"]


def test_severity_min_filters(db_app: Flask) -> None:
    """`severity_min=high` zeigt CRITICAL+HIGH, nicht MEDIUM/LOW."""
    sid, _ = register_test_server(db_app, name="srv-sevmin")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-8001", severity=Severity.CRITICAL
            ),
            _make_finding(server_id=sid, identifier_key="CVE-2026-8002", severity=Severity.HIGH),
            _make_finding(server_id=sid, identifier_key="CVE-2026-8003", severity=Severity.MEDIUM),
            _make_finding(server_id=sid, identifier_key="CVE-2026-8004", severity=Severity.LOW),
        ],
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows = list_findings(
                sess,
                sid,
                FindingsFilter(severity_min=Severity.HIGH, finding_class="os-pkgs"),
            )
        finally:
            sess.close()
    keys = {f.identifier_key for f in rows}
    assert keys == {"CVE-2026-8001", "CVE-2026-8002"}


def test_kev_only_filters_to_kev(db_app: Flask) -> None:
    sid, _ = register_test_server(db_app, name="srv-kevonly")
    _persist(
        db_app,
        [
            _make_finding(server_id=sid, identifier_key="CVE-2026-9001", is_kev=False),
            _make_finding(server_id=sid, identifier_key="CVE-2026-9002", is_kev=True),
        ],
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows = list_findings(sess, sid, FindingsFilter(kev_only=True, finding_class="os-pkgs"))
        finally:
            sess.close()
    assert [f.identifier_key for f in rows] == ["CVE-2026-9002"]


def test_search_substring_case_insensitive(db_app: Flask) -> None:
    """Substring-Suche matched case-insensitive auf identifier/package/title."""
    sid, _ = register_test_server(db_app, name="srv-search")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-1100",
                package_name="openssl",
                title="OpenSSL Buffer Overflow",
            ),
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-1101",
                package_name="nginx",
                title="Nothing fancy",
            ),
        ],
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            # Match auf package_name, andere Schreibweise.
            rows_pkg = list_findings(
                sess, sid, FindingsFilter(search="OPENSSL", finding_class="os-pkgs")
            )
            # Match auf title-Substring.
            rows_title = list_findings(
                sess, sid, FindingsFilter(search="buffer", finding_class="os-pkgs")
            )
            # Kein Match.
            rows_none = list_findings(
                sess, sid, FindingsFilter(search="apache", finding_class="os-pkgs")
            )
        finally:
            sess.close()
    assert [f.identifier_key for f in rows_pkg] == ["CVE-2026-1100"]
    assert [f.identifier_key for f in rows_title] == ["CVE-2026-1100"]
    assert rows_none == []


def test_limit_caps_results(db_app: Flask) -> None:
    sid, _ = register_test_server(db_app, name="srv-limit")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid,
                identifier_key=f"CVE-2026-12{idx:02d}",
                first_seen_offset_h=idx,
            )
            for idx in range(5)
        ],
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            rows = list_findings(sess, sid, FindingsFilter(finding_class="os-pkgs"), limit=2)
        finally:
            sess.close()
    assert len(rows) == 2


# ---------------------------------------------------------------------------
# count_findings
# ---------------------------------------------------------------------------


def test_count_findings_ignores_status_filter(db_app: Flask) -> None:
    """Status-Counts ueber alle Status, unabhaengig vom Filter-Status."""
    sid, _ = register_test_server(db_app, name="srv-counts")
    _persist(
        db_app,
        [
            _make_finding(server_id=sid, identifier_key="CVE-2026-1501", status=FindingStatus.OPEN),
            _make_finding(server_id=sid, identifier_key="CVE-2026-1502", status=FindingStatus.OPEN),
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-1503", status=FindingStatus.ACKNOWLEDGED
            ),
            _make_finding(
                server_id=sid, identifier_key="CVE-2026-1504", status=FindingStatus.RESOLVED
            ),
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-1505",
                status=FindingStatus.OPEN,
                is_kev=True,
            ),
        ],
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            # Filter mit status=acknowledged darf das Count-Ergebnis NICHT
            # einschraenken.
            counts = count_findings(
                sess, sid, FindingsFilter(status="acknowledged", finding_class="os-pkgs")
            )
        finally:
            sess.close()

    assert counts["open"] == 3
    assert counts["acknowledged"] == 1
    assert counts["resolved"] == 1
    assert counts["total"] == 5
    assert counts["kev_open"] == 1


def test_count_findings_respects_class_filter(db_app: Flask) -> None:
    """`finding_class` filtert die Counts; nur OS-Findings werden gezaehlt."""
    sid, _ = register_test_server(db_app, name="srv-counts-cls")
    _persist(
        db_app,
        [
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-1601",
                finding_class=FindingClass.OS_PKGS,
            ),
            _make_finding(
                server_id=sid,
                identifier_key="CVE-2026-1602",
                finding_class=FindingClass.LANG_PKGS,
            ),
        ],
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            counts = count_findings(sess, sid, FindingsFilter(finding_class="os-pkgs"))
        finally:
            sess.close()
    assert counts["total"] == 1


# ---------------------------------------------------------------------------
# Block Q (ADR-0025 §(5)) — Cross-Server-Pagination
# ---------------------------------------------------------------------------


def test_cross_server_offset_pagination(db_app: Flask) -> None:
    """DoD E.1: klassische Offset/Limit-Pagination in `list_findings_cross_server`.

    75 OPEN-Findings ueber 3 Server. `limit=50, offset=0` -> 50 Treffer,
    `limit=50, offset=50` -> 25 Treffer. `total_count` bleibt in beiden
    Faellen bei 75 (gilt fuer den vollen gefilterten Satz, nicht fuer
    die aktuelle Seite). Optional: pruefen dass die ersten 50 und die
    letzten 25 disjunkt sind und zusammen alle 75 ergeben — Sort ist
    deterministisch via `identifier_key.asc()`-Tiebreak.
    """
    sid_a, _ = register_test_server(db_app, name="page-srv-a")
    sid_b, _ = register_test_server(db_app, name="page-srv-b")
    sid_c, _ = register_test_server(db_app, name="page-srv-c")
    server_ids = (sid_a, sid_b, sid_c)

    findings = [
        _make_finding(
            server_id=server_ids[i % 3],
            identifier_key=f"CVE-2024-{i + 1:04d}",  # CVE-2024-0001..0075
            severity=Severity.MEDIUM,
        )
        for i in range(75)
    ]
    _persist(db_app, findings)

    with db_app.app_context():
        sess = _session(db_app)
        try:
            page1, total1 = list_findings_cross_server(sess, DashboardFilter(), limit=50, offset=0)
            page2, total2 = list_findings_cross_server(sess, DashboardFilter(), limit=50, offset=50)
        finally:
            sess.close()

    assert len(page1) == 50, f"Seite 1 sollte 50 Treffer haben, hat {len(page1)}"
    assert len(page2) == 25, f"Seite 2 sollte 25 Treffer haben, hat {len(page2)}"
    assert total1 == 75, f"total_count Seite 1 = {total1}, erwartet 75"
    assert total2 == 75, f"total_count Seite 2 = {total2}, erwartet 75"

    ids1 = {f.identifier_key for f in page1}
    ids2 = {f.identifier_key for f in page2}
    assert ids1.isdisjoint(ids2), "Seite 1 und Seite 2 duerfen keine Findings teilen"
    assert len(ids1 | ids2) == 75, "Vereinigung beider Seiten muss alle 75 Findings sein"


def test_persist_smoke(db_app: Flask) -> None:
    """Smoke: ORM-Insert klappt und Reload findet die Reihe."""
    sid, _ = register_test_server(db_app, name="srv-smoke")
    _persist(
        db_app,
        [_make_finding(server_id=sid, identifier_key="CVE-2026-9999")],
    )
    with db_app.app_context():
        sess = _session(db_app)
        try:
            row = sess.execute(
                select(Finding).where(Finding.identifier_key == "CVE-2026-9999")
            ).scalar_one()
        finally:
            sess.close()
    assert row.server_id == sid
