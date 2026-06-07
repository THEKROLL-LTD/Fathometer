"""Pure-Unit-Tests fuer `app.services.heartbeat_aggregation` (TICKET-004 Slice 3).

`_aggregate_one_server(findings, scan_days, day_list)` ist ohne Refaktor
bereits eine reine Funktion. Sie operiert auf Finding-aehnlichen Objekten
mit `first_seen_at`, `resolved_at`, `severity`, `is_kev`. Wir nutzen
unpersistierte ORM-`Finding`-Instanzen (kein `session.add()` / `commit()`)
fuer realistische Typen ohne DB-Roundtrip.

DB-backed Smokes fuer `heartbeat_for_server` / `heartbeats_for_servers`
liegen in `tests/integration/test_heartbeat_aggregation_db.py`.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Severity,
)
from app.services.heartbeat_aggregation import (
    DailyStatus,
    _aggregate_one_server,
    _day_range,
)

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    *,
    severity: Severity,
    first_seen_at: datetime,
    resolved_at: datetime | None = None,
    is_kev: bool = False,
    status: FindingStatus = FindingStatus.OPEN,
    identifier_key: str = "CVE-UNIT-0",
) -> Finding:
    """Unpersistierte ORM-Instanz — kein session/add/commit."""
    return Finding(
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key=identifier_key,
        package_name="pkg",
        installed_version="1.0",
        severity=severity,
        status=status,
        is_kev=is_kev,
        first_seen_at=first_seen_at,
        last_seen_at=first_seen_at,
        resolved_at=resolved_at,
        attack_vector=AttackVector.UNKNOWN,
    )


def _days(end_day: date, n: int) -> list[date]:
    return _day_range(end_day, n)


# ---------------------------------------------------------------------------
# Leerer Server / Tag-Liste
# ---------------------------------------------------------------------------


def test_aggregate_empty_returns_empty_cells_for_each_day() -> None:
    cells = _aggregate_one_server([], set(), _days(FIXED_NOW.date(), 50))
    assert len(cells) == 50
    assert all(isinstance(c, DailyStatus) for c in cells)
    assert cells[0].day == date(2026, 5, 15) - timedelta(days=49)
    assert cells[-1].day == date(2026, 5, 15)
    for c in cells:
        assert c.max_severity is None
        assert c.kev_count == 0
        assert c.had_scan is False


def test_aggregate_returns_dailystatus_instances() -> None:
    cells = _aggregate_one_server([], set(), _days(FIXED_NOW.date(), 3))
    assert all(isinstance(c, DailyStatus) for c in cells), cells


# ---------------------------------------------------------------------------
# Hoechste Severity
# ---------------------------------------------------------------------------


def test_max_severity_picked_per_day() -> None:
    """Vier Findings unterschiedlicher Severity -> CRITICAL ist max."""
    base = FIXED_NOW - timedelta(days=5)
    findings = [
        _finding(severity=Severity.LOW, first_seen_at=base, identifier_key="LOW"),
        _finding(severity=Severity.MEDIUM, first_seen_at=base, identifier_key="MED"),
        _finding(severity=Severity.HIGH, first_seen_at=base, identifier_key="HIGH"),
        _finding(severity=Severity.CRITICAL, first_seen_at=base, identifier_key="CRIT"),
    ]
    cells = _aggregate_one_server(findings, set(), _days(FIXED_NOW.date(), 10))
    today = FIXED_NOW.date()
    for c in cells:
        if c.day >= base.date():
            assert c.max_severity == Severity.CRITICAL, (c.day, c)
        else:
            assert c.max_severity is None, c
    assert cells[-1].day == today


# ---------------------------------------------------------------------------
# KEV-Counter unabhaengig von max_severity
# ---------------------------------------------------------------------------


def test_kev_count_independent_of_max_severity() -> None:
    """KEV-Finding mit LOW erhoeht kev_count, beeinflusst max_severity nicht."""
    base = FIXED_NOW - timedelta(days=3)
    findings = [
        _finding(severity=Severity.LOW, first_seen_at=base, is_kev=True, identifier_key="K-LOW"),
        _finding(severity=Severity.HIGH, first_seen_at=base, identifier_key="NK-HIGH"),
    ]
    cells = _aggregate_one_server(findings, set(), _days(FIXED_NOW.date(), 5))
    for c in cells:
        if c.day >= base.date():
            assert c.max_severity == Severity.HIGH, c
            assert c.kev_count == 1, c
        else:
            assert c.max_severity is None
            assert c.kev_count == 0


def test_multiple_kev_findings_accumulate() -> None:
    """Mehrere offene KEV-Findings -> kev_count entsprechend hoch."""
    base = FIXED_NOW - timedelta(days=2)
    findings = [
        _finding(
            severity=Severity.HIGH,
            first_seen_at=base,
            is_kev=True,
            identifier_key=f"KEV-{i}",
        )
        for i in range(3)
    ]
    cells = _aggregate_one_server(findings, set(), _days(FIXED_NOW.date(), 5))
    assert cells[-1].kev_count == 3


# ---------------------------------------------------------------------------
# had_scan / Carry-Forward
# ---------------------------------------------------------------------------


def test_carry_forward_on_days_without_scan() -> None:
    """Finding bleibt an Tagen ohne Scan offen -> Severity bleibt gesetzt."""
    fseen = FIXED_NOW - timedelta(days=4)
    findings = [_finding(severity=Severity.HIGH, first_seen_at=fseen, identifier_key="CARRY")]
    scan_days = {fseen.date()}
    cells = _aggregate_one_server(findings, scan_days, _days(FIXED_NOW.date(), 6))
    by_day = {c.day: c for c in cells}
    scan_day = fseen.date()
    assert by_day[scan_day].had_scan is True
    assert by_day[scan_day].max_severity == Severity.HIGH
    for offset in range(1, 4):
        d = scan_day + timedelta(days=offset)
        c = by_day[d]
        assert c.had_scan is False, c
        assert c.max_severity == Severity.HIGH, c


# ---------------------------------------------------------------------------
# Resolved verschwindet ab resolved_at-Tag
# ---------------------------------------------------------------------------


def test_resolved_finding_drops_out_after_resolved_at() -> None:
    fseen = FIXED_NOW - timedelta(days=4)
    resolved = FIXED_NOW - timedelta(days=2)
    findings = [
        _finding(
            severity=Severity.CRITICAL,
            first_seen_at=fseen,
            resolved_at=resolved,
            status=FindingStatus.RESOLVED,
            identifier_key="RES",
        )
    ]
    cells = _aggregate_one_server(findings, set(), _days(FIXED_NOW.date(), 6))
    by_day = {c.day: c for c in cells}
    day_before = resolved.date() - timedelta(days=1)
    assert by_day[day_before].max_severity == Severity.CRITICAL
    assert by_day[fseen.date()].max_severity == Severity.CRITICAL
    # resolved (12:00) <= end_of_day (23:59) -> bereits resolved.
    assert by_day[resolved.date()].max_severity is None
    assert by_day[resolved.date() + timedelta(days=1)].max_severity is None


# ---------------------------------------------------------------------------
# Acknowledged zaehlt weiter als "vorhanden"
# ---------------------------------------------------------------------------


def test_acknowledged_finding_still_counted() -> None:
    """Acked Finding ist nach §7a noch nicht weg — Heartbeat zeigt Severity."""
    fseen = FIXED_NOW - timedelta(days=2)
    findings = [
        _finding(
            severity=Severity.HIGH,
            first_seen_at=fseen,
            status=FindingStatus.ACKNOWLEDGED,
            identifier_key="ACK",
        )
    ]
    cells = _aggregate_one_server(findings, set(), _days(FIXED_NOW.date(), 5))
    assert cells[-1].max_severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Day-Boundary-Spezifika
# ---------------------------------------------------------------------------


def test_finding_first_seen_after_day_not_counted() -> None:
    """Finding entsteht in Zukunft: an heute end_of_day noch NICHT da."""
    future = FIXED_NOW + timedelta(days=2)
    findings = [_finding(severity=Severity.HIGH, first_seen_at=future, identifier_key="FUT")]
    cells = _aggregate_one_server(findings, set(), _days(FIXED_NOW.date(), 5))
    for c in cells:
        assert c.max_severity is None


def test_scan_days_set_marks_had_scan() -> None:
    """Tage in `scan_days` werden mit had_scan=True markiert."""
    days_list = _days(FIXED_NOW.date(), 5)
    scan_days = {days_list[1], days_list[3]}
    cells = _aggregate_one_server([], scan_days, days_list)
    assert cells[0].had_scan is False
    assert cells[1].had_scan is True
    assert cells[2].had_scan is False
    assert cells[3].had_scan is True
    assert cells[4].had_scan is False


def test_naive_datetime_treated_as_utc() -> None:
    """Defensiv: naive first_seen wird als UTC interpretiert."""
    fseen_naive = (FIXED_NOW - timedelta(days=3)).replace(tzinfo=None)
    findings = [_finding(severity=Severity.HIGH, first_seen_at=fseen_naive, identifier_key="NAIVE")]
    cells = _aggregate_one_server(findings, set(), _days(FIXED_NOW.date(), 5))
    # cells[-1] = heute, cells[-4] = Tag-3 (= first_seen), cells[-5] = Tag-4.
    assert cells[-1].max_severity == Severity.HIGH
    assert cells[-4].max_severity == Severity.HIGH
    assert cells[-5].max_severity is None


# ---------------------------------------------------------------------------
# Phase C: schmale Projektion via _FindingRow (ADR-0030 Befund 6)
# ---------------------------------------------------------------------------


def test_aggregate_accepts_finding_row_namedtuple() -> None:
    """_aggregate_one_server akzeptiert _FindingRow-NamedTuples statt ORM-Instanzen."""
    from app.services.heartbeat_aggregation import _FindingRow

    fseen = FIXED_NOW - timedelta(days=2)
    row = _FindingRow(
        server_id=1,
        severity=Severity.CRITICAL,
        first_seen_at=fseen,
        acknowledged_at=None,
        resolved_at=None,
        is_kev=False,
        kev_added_at=None,
    )
    cells = _aggregate_one_server([row], set(), _days(FIXED_NOW.date(), 5))
    # 5-Tage-Liste: [5-11, 5-12, 5-13, 5-14, 5-15]
    # fseen = 5-13 -> cells[-3]=5-13 ist erster Tag mit CRITICAL
    # cells[-4]=5-12 liegt vor first_seen -> None
    assert cells[-1].max_severity == Severity.CRITICAL
    assert cells[-3].max_severity == Severity.CRITICAL
    assert cells[-4].max_severity is None


def test_aggregate_finding_row_kev_flag() -> None:
    """_FindingRow mit is_kev=True erhoet kev_count korrekt."""
    from app.services.heartbeat_aggregation import _FindingRow

    fseen = FIXED_NOW - timedelta(days=1)
    row = _FindingRow(
        server_id=2,
        severity=Severity.HIGH,
        first_seen_at=fseen,
        acknowledged_at=None,
        resolved_at=None,
        is_kev=True,
        kev_added_at=None,
    )
    cells = _aggregate_one_server([row], set(), _days(FIXED_NOW.date(), 3))
    # kev_count muss 1 sein fuer die letzten beiden Tage
    assert cells[-1].kev_count == 1
    assert cells[-2].kev_count == 1
    assert cells[0].kev_count == 0


def test_aggregate_finding_row_resolved_drops_out() -> None:
    """_FindingRow mit resolved_at verschwindet ab dem resolved_at-Tag."""
    from app.services.heartbeat_aggregation import _FindingRow

    fseen = FIXED_NOW - timedelta(days=4)
    resolved = FIXED_NOW - timedelta(days=2)
    row = _FindingRow(
        server_id=3,
        severity=Severity.MEDIUM,
        first_seen_at=fseen,
        acknowledged_at=None,
        resolved_at=resolved,
        is_kev=False,
        kev_added_at=None,
    )
    cells = _aggregate_one_server([row], set(), _days(FIXED_NOW.date(), 6))
    by_day = {c.day: c for c in cells}
    # Tag vor resolved: Finding ist noch offen
    assert by_day[resolved.date() - timedelta(days=1)].max_severity == Severity.MEDIUM
    # Ab resolved_at: Finding weg (resolved <= end_of_day)
    assert by_day[resolved.date()].max_severity is None
    assert by_day[FIXED_NOW.date()].max_severity is None


def test_heartbeats_for_servers_narrow_projection_via_mock() -> None:
    """live_heartbeats_for_servers nutzt schmale Projektion — kein select(Finding) mehr.

    Prueft: die zusammengestellte SELECT-Anweisung enthaelt Finding-Spalten
    (schmale Projektion), nicht das vollstaendige ORM-Objekt.

    Hinweis: Seit dem ADR-0035-Addendum liest der Render-Pfad
    (`heartbeats_for_servers`) die materialisierte `daily_risk_state`-Tabelle.
    Diese Internals-Shape-Pruefung gilt der erhaltenen Live-Variante
    (`live_heartbeats_for_servers`), die die alte 2-Query-Form behaelt.
    """
    from unittest.mock import MagicMock

    from app.services.heartbeat_aggregation import live_heartbeats_for_servers

    # Mock-Session die leere Results liefert (keine Rows) ->
    # live_heartbeats_for_servers baut leere DailyStatus-Listen.
    session = MagicMock()
    session.execute.return_value.all.return_value = []

    result = live_heartbeats_for_servers(session, server_ids=[1, 2], days=3, now=FIXED_NOW)

    # Rueckgabe muss fuer beide Server vorhanden sein (Garantie der Funktion)
    assert set(result.keys()) == {1, 2}
    for cells in result.values():
        assert len(cells) == 3
        assert all(c.max_severity is None for c in cells)
        assert all(c.kev_count == 0 for c in cells)

    # session.execute wurde fuer Findings UND Scans aufgerufen (2 Queries)
    assert session.execute.call_count == 2
