"""Pure-Unit-Tests fuer `app.services.severity_history` (TICKET-004 Slice 3).

Die Aggregations-Logik (`_compute_snapshots`, `_compute_daily_counts`) ist
durch eine kleine Service-DI-Aenderung als Modul-Funktion extrahiert; sie
operiert ausschliesslich auf `_FindingRow`-Listen und Tages-Listen. Damit
sind die Range-/Lifecycle-/KEV-Tests DB-frei ausfuehrbar.

DB-backed Smokes fuer `_load_findings` und das Round-Trip-Verhalten der
public Wrapper liegen in `tests/integration/test_severity_history_db.py`.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from app.models import Severity
from app.services.severity_history import (
    DailySeverityCount,
    _compute_daily_counts,
    _compute_snapshots,
    _FindingRow,
)

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(
    *,
    severity: Severity,
    first_seen_at: datetime,
    acknowledged_at: datetime | None = None,
    resolved_at: datetime | None = None,
    is_kev: bool = False,
    kev_added_at: datetime | None = None,
) -> _FindingRow:
    return _FindingRow(
        severity=severity,
        first_seen_at=first_seen_at,
        acknowledged_at=acknowledged_at,
        resolved_at=resolved_at,
        kev_added_at=kev_added_at,
        is_kev=is_kev,
    )


def _day_list(end_day: date, days: int) -> list[date]:
    return [end_day - timedelta(days=days - 1 - i) for i in range(days)]


# ---------------------------------------------------------------------------
# _compute_snapshots
# ---------------------------------------------------------------------------


def test_snapshots_empty_rows_returns_zero_lists() -> None:
    out = _compute_snapshots([], _day_list(FIXED_NOW.date(), 50))
    assert set(out.keys()) == {"critical", "high", "medium", "low", "kev"}
    for key, values in out.items():
        assert len(values) == 50, f"{key}: erwarte 50 Eintraege"
        assert all(v == 0 for v in values), f"{key}: alle Nullen erwartet"


def test_snapshots_only_open_findings_counts_correctly() -> None:
    """Drei OPEN-HIGH-Findings ab Tag-10 -> an Tag-10..0 jeweils 3, davor 0."""
    fseen = FIXED_NOW - timedelta(days=10)
    rows = [_row(severity=Severity.HIGH, first_seen_at=fseen) for _ in range(3)]

    out = _compute_snapshots(rows, _day_list(FIXED_NOW.date(), 50))
    high = out["high"]
    for i in range(50):
        days_ago = 49 - i
        if days_ago <= 10:
            assert high[i] == 3, f"Tag -{days_ago}: erwarte 3, habe {high[i]}"
        else:
            assert high[i] == 0, f"Tag -{days_ago}: erwarte 0, habe {high[i]}"
    assert all(v == 0 for v in out["critical"])
    assert all(v == 0 for v in out["medium"])
    assert all(v == 0 for v in out["low"])
    assert all(v == 0 for v in out["kev"])


def test_snapshots_acknowledged_finding_drops_out_from_day() -> None:
    """Ack vor 5 Tagen: an Tagen <-5 zaehlt, ab Tag-5 nicht mehr."""
    fseen = FIXED_NOW - timedelta(days=10)
    ack_at = FIXED_NOW - timedelta(days=5)
    rows = [_row(severity=Severity.CRITICAL, first_seen_at=fseen, acknowledged_at=ack_at)]

    out = _compute_snapshots(rows, _day_list(FIXED_NOW.date(), 50))
    crit = out["critical"]
    for i in range(50):
        days_ago = 49 - i
        if days_ago <= 10 and days_ago > 5:
            assert crit[i] == 1, f"Tag -{days_ago}: erwarte 1, habe {crit[i]}"
        elif days_ago <= 5:
            assert crit[i] == 0, f"Tag -{days_ago}: nach ack erwarte 0"
        else:
            assert crit[i] == 0, f"Tag -{days_ago}: vor first_seen erwarte 0"


def test_snapshots_resolved_finding_drops_out_from_day() -> None:
    """Resolved vor 3 Tagen -> ab Tag-3 nicht mehr gezaehlt."""
    fseen = FIXED_NOW - timedelta(days=15)
    res_at = FIXED_NOW - timedelta(days=3)
    rows = [_row(severity=Severity.MEDIUM, first_seen_at=fseen, resolved_at=res_at)]

    out = _compute_snapshots(rows, _day_list(FIXED_NOW.date(), 50))
    med = out["medium"]
    for i in range(50):
        days_ago = 49 - i
        if 3 < days_ago <= 15:
            assert med[i] == 1, f"Tag -{days_ago}: erwarte 1"
        else:
            assert med[i] == 0, f"Tag -{days_ago}: erwarte 0"


def test_snapshots_kev_open_counter() -> None:
    """`"kev"`-Bucket im Snapshot ist OPEN-KEV-Stand, nicht Event-Counter."""
    rows = [
        _row(
            severity=Severity.HIGH,
            first_seen_at=FIXED_NOW - timedelta(days=4),
            is_kev=True,
            kev_added_at=FIXED_NOW - timedelta(days=4),
        )
    ]
    out = _compute_snapshots(rows, _day_list(FIXED_NOW.date(), 50))
    kev = out["kev"]
    for i in range(50):
        days_ago = 49 - i
        if days_ago <= 4:
            assert kev[i] == 1, f"Tag -{days_ago}: erwarte 1 OPEN-KEV"
        else:
            assert kev[i] == 0


# ---------------------------------------------------------------------------
# _compute_daily_counts
# ---------------------------------------------------------------------------


def test_daily_counts_returns_dailyseveritycount_records() -> None:
    out = _compute_daily_counts([], _day_list(FIXED_NOW.date(), 50))
    assert len(out) == 50
    assert all(isinstance(d, DailySeverityCount) for d in out)
    assert out[0].day == date(2026, 5, 15) - timedelta(days=49)
    assert out[-1].day == date(2026, 5, 15)
    for d in out:
        assert (d.critical, d.high, d.medium, d.low, d.kev) == (0, 0, 0, 0, 0)


def test_daily_counts_kev_event_only_on_event_day() -> None:
    """`kev` im DailySeverityCount ist Event-Zaehler — nicht OPEN-Stand."""
    kev_at = FIXED_NOW - timedelta(days=10)
    rows = [
        _row(
            severity=Severity.HIGH,
            first_seen_at=FIXED_NOW - timedelta(days=30),
            is_kev=True,
            kev_added_at=kev_at,
        ),
        _row(severity=Severity.HIGH, first_seen_at=FIXED_NOW - timedelta(days=20)),
    ]
    out = _compute_daily_counts(rows, _day_list(FIXED_NOW.date(), 50))
    by_day = {d.day: d for d in out}
    assert by_day[kev_at.date()].kev == 1
    for d in out:
        if d.day != kev_at.date():
            assert d.kev == 0, f"Tag {d.day}: erwarte kev=0, habe {d.kev}"


def test_daily_counts_mixed_lifecycle() -> None:
    """OPEN, ack, resolved gemischt -> Tages-Counts spiegeln Lifecycle."""
    rows = [
        # F1: HIGH, first_seen Tag-20, OPEN (lebt bis heute).
        _row(severity=Severity.HIGH, first_seen_at=FIXED_NOW - timedelta(days=20)),
        # F2: CRITICAL, first_seen Tag-15, acknowledged Tag-7.
        _row(
            severity=Severity.CRITICAL,
            first_seen_at=FIXED_NOW - timedelta(days=15),
            acknowledged_at=FIXED_NOW - timedelta(days=7),
        ),
        # F3: MEDIUM, first_seen Tag-10, resolved Tag-3.
        _row(
            severity=Severity.MEDIUM,
            first_seen_at=FIXED_NOW - timedelta(days=10),
            resolved_at=FIXED_NOW - timedelta(days=3),
        ),
    ]
    out = _compute_daily_counts(rows, _day_list(FIXED_NOW.date(), 50))
    by_day = {d.day: d for d in out}
    today = FIXED_NOW.date()

    d18 = by_day[today - timedelta(days=18)]
    assert d18.high == 1
    assert d18.critical == 0
    assert d18.medium == 0

    d8 = by_day[today - timedelta(days=8)]
    assert d8.high == 1, f"Tag -8 erwarte high=1, habe {d8.high}"
    assert d8.critical == 1, f"Tag -8 erwarte crit=1, habe {d8.critical}"
    assert d8.medium == 1, f"Tag -8 erwarte med=1, habe {d8.medium}"

    d5 = by_day[today - timedelta(days=5)]
    assert d5.high == 1
    assert d5.critical == 0
    assert d5.medium == 1

    dtoday = by_day[today]
    assert dtoday.high == 1
    assert dtoday.critical == 0
    assert dtoday.medium == 0


def test_daily_counts_unknown_severity_is_excluded() -> None:
    """UNKNOWN-Findings sollen in keinem Severity-Bucket auftauchen."""
    rows = [
        _row(severity=Severity.UNKNOWN, first_seen_at=FIXED_NOW - timedelta(days=5)),
    ]
    out = _compute_daily_counts(rows, _day_list(FIXED_NOW.date(), 50))
    for d in out:
        assert d.critical == 0 and d.high == 0 and d.medium == 0 and d.low == 0


def test_daily_counts_kev_event_outside_window_ignored() -> None:
    """KEV-Event vor Fenster-Start zaehlt nicht im Event-Bucket."""
    rows = [
        _row(
            severity=Severity.HIGH,
            first_seen_at=FIXED_NOW - timedelta(days=200),
            is_kev=True,
            kev_added_at=FIXED_NOW - timedelta(days=200),
        )
    ]
    out = _compute_daily_counts(rows, _day_list(FIXED_NOW.date(), 50))
    for d in out:
        assert d.kev == 0
