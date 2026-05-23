"""Pure-Unit-Tests fuer `tendency_from_counts` (Phase B, ADR-0030 Befund 1).

`tendency_from_counts` ist eine Pure-Funktion ohne Session-Abhaengigkeit.
Sie operiert ausschliesslich auf einer bereits berechneten `DailySeverityCount`-
Liste — kein DB-Fixture noetig, kein Mock erforderlich.

Deckt:
  * Leere Liste -> STABLE.
  * Konstante Reihe -> STABLE.
  * Ansteigende Reihe (letzte 7 Tage deutlich hoeher) -> RISING.
  * Fallende Reihe (letzte 7 Tage nahe 0) -> FALLING.
  * Hoher threshold -> selbst starker Anstieg bleibt STABLE.
  * Konsistenz mit dem compute_tendency-Wrapper (Patch-Test, kein echter DB-Call).
"""

from __future__ import annotations

from datetime import date, timedelta
from unittest.mock import MagicMock, patch

from app.services.severity_history import DailySeverityCount
from app.services.trend import Tendency, compute_tendency, tendency_from_counts

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_counts(
    totals: list[int],
    *,
    start_day: date | None = None,
) -> list[DailySeverityCount]:
    """Erzeugt eine `DailySeverityCount`-Liste aus einer Tagessummen-Liste.

    Alle Counts laufen als HIGH-Findings — critical/medium/low/kev bleiben 0.
    Damit koennen wir die Tendency-Logik direkt testen ohne DB oder Session.
    """
    if start_day is None:
        start_day = date(2026, 1, 1)
    return [
        DailySeverityCount(
            day=start_day + timedelta(days=i),
            critical=0,
            high=total,
            medium=0,
            low=0,
            kev=0,
        )
        for i, total in enumerate(totals)
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_tendency_from_counts_empty_returns_stable() -> None:
    """Leere Counts-Liste -> STABLE als Default (kein Crash)."""
    result = tendency_from_counts([])
    assert result is Tendency.STABLE


def test_tendency_from_counts_stable_series() -> None:
    """Konstant offene Findings ueber 50 Tage -> avg_short == avg_long -> STABLE.

    Bei konstantem Verlauf ist avg_short == avg_long -> diff = 0 < threshold.
    """
    counts = _make_counts([5] * 50)
    result = tendency_from_counts(counts)
    assert result is Tendency.STABLE, f"erwartet STABLE, bekommen {result!r}"


def test_tendency_from_counts_rising_pattern() -> None:
    """Neuere Tage haben viel hoehere Counts -> avg_short >> avg_long -> RISING.

    Konfiguration: Tage 1-43 haben 0 Findings, Tage 44-50 haben je 100.
    avg_short = 100, avg_long = (0*43 + 100*7) / 50 = 14.
    diff = (100 - 14) / max(14, 1) = 86/14 ~ 6.14 >> 0.05 -> RISING.
    """
    totals = [0] * 43 + [100] * 7  # 50 Tage gesamt
    counts = _make_counts(totals)
    result = tendency_from_counts(counts)
    assert result is Tendency.RISING, f"erwartet RISING, bekommen {result!r}"


def test_tendency_from_counts_falling_pattern() -> None:
    """Fruehe Tage haben hohe Counts, letzte 7 Tage nahe 0 -> FALLING.

    Konfiguration: Tage 1-43 haben je 100 Findings, Tage 44-50 haben 0.
    avg_short = 0, avg_long = (100*43 + 0*7) / 50 = 86.
    diff = (0 - 86) / 86 = -1.0 << -0.05 -> FALLING.
    """
    totals = [100] * 43 + [0] * 7  # 50 Tage gesamt
    counts = _make_counts(totals)
    result = tendency_from_counts(counts)
    assert result is Tendency.FALLING, f"erwartet FALLING, bekommen {result!r}"


def test_tendency_from_counts_high_threshold_keeps_stable() -> None:
    """Sehr hoher threshold -> selbst starker Anstieg bleibt STABLE.

    Mit threshold=10.0 (1000%) ist selbst diff=6.14 kleiner als 10.0
    -> STABLE.
    """
    totals = [0] * 43 + [100] * 7
    counts = _make_counts(totals)
    result = tendency_from_counts(counts, threshold=10.0)
    assert result is Tendency.STABLE, f"erwartet STABLE bei threshold=10.0, bekommen {result!r}"


def test_tendency_from_counts_consistent_with_compute_tendency_wrapper() -> None:
    """tendency_from_counts liefert dasselbe Ergebnis wie compute_tendency
    wenn beide denselben Counts-Datensatz erhalten.

    Beweist, dass compute_tendency als duenner Wrapper korrekt delegiert.
    Kein echter DB-Call: daily_severity_counts_for_server wird gepatcht.
    """
    totals = [0] * 43 + [100] * 7
    counts = _make_counts(totals)

    # Direkte Pure-Funktion (kein Patch noetig).
    direct = tendency_from_counts(counts)

    # Wrapper-Pfad via Patch (kein echter DB-Aufruf).
    with patch(
        "app.services.trend.daily_severity_counts_for_server",
        return_value=counts,
    ):
        mock_sess = MagicMock()
        wrapped = compute_tendency(mock_sess, server_id=1)

    assert direct == wrapped, (
        f"tendency_from_counts={direct!r} != compute_tendency(patched)={wrapped!r}"
    )


def test_tendency_from_counts_only_high_contributes() -> None:
    """Nur `high`-Counts werden in die Tagessumme eingerechnet; kev fliesst raus.

    DailySeverityCount hat zusaetzlich `kev`-Feld das im Tendency-Stack
    bewusst nicht einfliesst (analog zum Stacked-Chart — UNKNOWN auch raus).
    """
    # 50 Tage mit high=0 aber kev=100 -> totals alle 0 -> STABLE.
    counts = [
        DailySeverityCount(
            day=date(2026, 1, 1) + timedelta(days=i), critical=0, high=0, medium=0, low=0, kev=100
        )
        for i in range(50)
    ]
    result = tendency_from_counts(counts)
    assert result is Tendency.STABLE, "kev-Feld darf nicht in die Tagessumme einfliessen"
