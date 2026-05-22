"""Pure-Unit-Tests fuer `app.services.stale_history` (TICKET-004 Slice 3).

`_compute_stale_counts` ist die Aggregations-Schleife extrahiert als Modul-
Funktion; sie operiert ausschliesslich auf `_ServerRow`-Listen (Scans
sortiert ASC) und einer Tages-Liste. Damit sind die Aktiv-/Retire-/
Threshold-Tests DB-frei ausfuehrbar.

DB-backed Smokes inkl. Performance-Bench liegen in
`tests/integration/test_stale_history_db.py`.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from app.services.stale_history import _compute_stale_counts, _ServerRow

FIXED_NOW = datetime(2026, 5, 15, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(
    *,
    id: int = 1,
    interval_h: int = 24,
    created_at: datetime,
    retired_at: datetime | None = None,
    revoked_at: datetime | None = None,
    scans: list[datetime] | None = None,
) -> _ServerRow:
    return _ServerRow(
        id=id,
        interval_h=interval_h,
        created_at=created_at,
        retired_at=retired_at,
        revoked_at=revoked_at,
        scans=sorted(scans or []),
    )


def _day_list(end_day: date, days: int) -> list[date]:
    return [end_day - timedelta(days=days - 1 - i) for i in range(days)]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_all_servers_fresh_returns_all_zero() -> None:
    """Server mit taeglich frischem Scan: alle 50 Werte = 0."""
    scans = [FIXED_NOW - timedelta(days=d, hours=1) for d in range(60)]
    rows = [
        _row(
            id=1,
            interval_h=24,
            created_at=FIXED_NOW - timedelta(days=100),
            scans=scans,
        )
    ]
    out = _compute_stale_counts(rows, _day_list(FIXED_NOW.date(), 50))
    assert len(out) == 50
    assert all(v == 0 for v in out), f"erwartet alle 0, got {out}"


def test_retire_mid_window_drops_from_count_after_retire() -> None:
    """Server retired Tag -20: zaehlt an Tag -19..heute nicht mehr."""
    retire_at = FIXED_NOW - timedelta(days=20)
    rows = [
        _row(
            id=1,
            interval_h=24,
            created_at=FIXED_NOW - timedelta(days=100),
            retired_at=retire_at,
            scans=[FIXED_NOW - timedelta(days=30)],
        )
    ]
    out = _compute_stale_counts(rows, _day_list(FIXED_NOW.date(), 50))
    # Heute (Index 49): retired (out=0).
    assert out[-1] == 0, f"heute: erwartet 0 (retired), got {out[-1]}"
    # Tag -25 (Index 24): vor Retire, kein Scan seit Tag-30 -> stale.
    assert out[49 - 25] == 1, f"Tag-25: erwartet 1 (stale, nicht retired), got {out[49 - 25]}"
    # Tag -19 (nach Retire): out=0.
    assert out[49 - 19] == 0, "Tag-19: erwartet 0 (retired)"
    # Tag -45 (vor Scan): kein Scan im Fenster -> stale.
    assert out[49 - 45] == 1, "Tag-45: erwartet 1 (kein Scan im Fenster)"


def test_revoke_mid_window_drops_from_count_after_revoke() -> None:
    """Revoke verhaelt sich identisch zu Retire."""
    revoke_at = FIXED_NOW - timedelta(days=10)
    rows = [
        _row(
            id=1,
            interval_h=24,
            created_at=FIXED_NOW - timedelta(days=100),
            revoked_at=revoke_at,
            scans=[FIXED_NOW - timedelta(days=30)],
        )
    ]
    out = _compute_stale_counts(rows, _day_list(FIXED_NOW.date(), 50))
    assert out[-1] == 0, "heute: erwartet 0 (revoked)"
    assert out[49 - 9] == 0, "Tag-9: erwartet 0 (nach revoke)"
    assert out[49 - 11] == 1, "Tag-11: erwartet 1 (stale, vor revoke)"


def test_weekly_interval_stale_after_14_days_with_factor_2() -> None:
    """Interval 168h: Stale-Schwelle = 2 x 168h = 336h = 14 Tage."""
    rows = [
        _row(
            id=1,
            interval_h=168,
            created_at=FIXED_NOW - timedelta(days=100),
            scans=[FIXED_NOW - timedelta(days=16)],
        )
    ]
    out = _compute_stale_counts(rows, _day_list(FIXED_NOW.date(), 50))
    # Heute: Differenz ~16.5d > 14d -> stale.
    assert out[-1] == 1, f"erwartet 1 stale heute, got {out[-1]}"
    # Tag -15: Differenz ~0.5d -> nicht stale.
    assert out[49 - 15] == 0, f"Tag-15: erwartet 0, got {out[49 - 15]}"
    # Tag -1: Differenz ~15.5d > 14d -> stale.
    assert out[49 - 1] == 1, f"Tag-1: erwartet 1, got {out[49 - 1]}"
    # Tag -16: am Scan-Tag, Scan ~11h59min vor end_of_day -> nicht stale.
    assert out[49 - 16] == 0, "Tag-16: erwartet 0 (Scan am selben Tag)"
    # Tag -17: vor Scan -> stale.
    assert out[49 - 17] == 1, "Tag-17: erwartet 1"


def test_server_created_30d_ago_no_scan_counts_from_day_30() -> None:
    """Server vor 30 Tagen erstellt, kein Scan: ab Tag-30 aktiv + stale."""
    rows = [
        _row(
            id=1,
            interval_h=24,
            created_at=FIXED_NOW - timedelta(days=30),
            scans=[],
        )
    ]
    out = _compute_stale_counts(rows, _day_list(FIXED_NOW.date(), 50))
    for i in range(50):
        days_ago = 49 - i
        if days_ago > 30:
            assert out[i] == 0, f"Tag-{days_ago}: erwartet 0 (noch nicht aktiv)"
        else:
            assert out[i] == 1, f"Tag-{days_ago}: erwartet 1 (aktiv + stale)"
