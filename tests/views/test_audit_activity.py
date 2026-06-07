"""Pure-Unit-Tests fuer den 24h-Aktivitaets-Strip (`_compute_activity`).

Audit-Redesign (Style-Adoption Audit.jsx): der Header-Strip zeigt ein 48-
Bucket-Histogramm der Event-Anzahl ueber die letzten 24h. Der Peak-Bucket
traegt das einzige Cyan-Signal (`audit__bar--peak`). Diese Tests pinnen die
Bucketing-, Peak- und Hoehen-Logik der reinen Helfer-Funktion (keine DB).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.views.audit_view import (
    _ACTIVITY_BUCKETS,
    _ACTIVITY_MIN_PCT,
    _compute_activity,
)

_NOW = datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)


def test_empty_input_yields_flat_zero_histogram() -> None:
    res = _compute_activity([], _NOW)
    assert res["total"] == 0
    assert res["max"] == 0
    assert len(res["bars"]) == _ACTIVITY_BUCKETS
    assert all(b["count"] == 0 for b in res["bars"])
    assert all(b["height_pct"] == 0 for b in res["bars"])
    # Kein Peak bei leerer Eingabe — kein Bucket traegt Cyan.
    assert not any(b["peak"] for b in res["bars"])


def test_event_lands_in_correct_bucket_and_counts() -> None:
    # 24h-Fenster, 48 Buckets => 30min pro Bucket. Ein Event 70min vor `now`
    # liegt im Bucket-Index 45 (start = now-24h; (24h-70min)/30min = 45.66 -> 45).
    ts = _NOW - timedelta(minutes=70)
    res = _compute_activity([ts, ts, ts], _NOW)
    assert res["total"] == 3
    assert res["max"] == 3
    assert res["bars"][45]["count"] == 3
    assert res["bars"][45]["peak"] is True
    # Genau ein Peak.
    assert sum(1 for b in res["bars"] if b["peak"]) == 1


def test_out_of_window_events_are_ignored() -> None:
    too_old = _NOW - timedelta(hours=25)
    future = _NOW + timedelta(minutes=5)
    inside = _NOW - timedelta(hours=1)
    res = _compute_activity([too_old, future, inside], _NOW)
    assert res["total"] == 1


def test_peak_is_first_maximum_only() -> None:
    # Zwei Buckets mit je 2 Events (Index 0 und 47), Rest 0. Peak = erster.
    b0 = _NOW - timedelta(hours=24) + timedelta(minutes=1)  # Bucket 0
    b47 = _NOW - timedelta(minutes=1)  # letzter Bucket
    res = _compute_activity([b0, b0, b47, b47], _NOW)
    assert res["max"] == 2
    peaks = [i for i, b in enumerate(res["bars"]) if b["peak"]]
    assert peaks == [0]


def test_height_pct_normalized_to_peak_with_floor() -> None:
    # Peak-Bucket: 10 Events -> 100%. Kleiner Bucket: 1 Event -> floor.
    peak_ts = _NOW - timedelta(minutes=15)  # letzter Bucket
    small_ts = _NOW - timedelta(hours=23)  # frueher Bucket
    res = _compute_activity([peak_ts] * 10 + [small_ts], _NOW)
    peak_bar = next(b for b in res["bars"] if b["peak"])
    assert peak_bar["height_pct"] == 100
    small_bar = next(b for b in res["bars"] if 0 < b["count"] < 10)
    # 1/10 -> 10%, aber mindestens der Floor.
    assert small_bar["height_pct"] == max(_ACTIVITY_MIN_PCT, 10)


def test_naive_timestamps_treated_as_utc() -> None:
    naive = (_NOW - timedelta(hours=1)).replace(tzinfo=None)
    res = _compute_activity([naive], _NOW.replace(tzinfo=None))
    assert res["total"] == 1
