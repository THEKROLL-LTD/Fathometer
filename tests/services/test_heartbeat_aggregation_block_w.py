"""Block-W-Erweiterungen fuer `app.services.heartbeat_aggregation` (ADR-0035).

Tests fuer:
  - `dominant_risk_band`-Reduce in `_aggregate_one_server`
  - Risk-Band-Ranking: escalate > act > mitigate > pending > monitor > noise > unknown
  - Null-Handling wenn alle risk_band=None
  - `heartbeats_for_servers` Default-days=30 Garantie

Diese Tests ergaenzen `tests/services/test_heartbeat_aggregation.py` ohne
es zu duplizieren.
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
    _RISK_BAND_RANK,
    _aggregate_one_server,
    _day_range,
    _FindingRow,
    heartbeats_for_servers,
)

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_with_risk_band(
    *,
    severity: Severity = Severity.HIGH,
    first_seen_at: datetime,
    resolved_at: datetime | None = None,
    risk_band: str | None = None,
    identifier_key: str = "CVE-W-0",
) -> Finding:
    """Unpersistierte ORM-Instanz mit risk_band-Feld."""
    f = Finding(
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key=identifier_key,
        package_name="pkg",
        installed_version="1.0",
        severity=severity,
        status=FindingStatus.OPEN,
        is_kev=False,
        first_seen_at=first_seen_at,
        last_seen_at=first_seen_at,
        resolved_at=resolved_at,
        attack_vector=AttackVector.UNKNOWN,
    )
    # risk_band ist kein ctor-Arg bei Finding; wir setzen es direkt.
    f.risk_band = risk_band  # type: ignore[assignment]
    return f


def _row(
    *,
    risk_band: str | None,
    first_seen_at: datetime,
    resolved_at: datetime | None = None,
    server_id: int = 1,
    severity: Severity = Severity.HIGH,
) -> _FindingRow:
    return _FindingRow(
        server_id=server_id,
        severity=severity,
        first_seen_at=first_seen_at,
        acknowledged_at=None,
        resolved_at=resolved_at,
        is_kev=False,
        kev_added_at=None,
        risk_band=risk_band,
    )


def _days(n: int = 5) -> list[date]:
    return _day_range(FIXED_NOW.date(), n)


# ---------------------------------------------------------------------------
# Risk-Band-Rank-Tabelle
# ---------------------------------------------------------------------------


def test_risk_band_rank_escalate_is_highest() -> None:
    """escalate hat den hoechsten Rank (7) gemaess ADR-0035."""
    assert _RISK_BAND_RANK["escalate"] == 7, _RISK_BAND_RANK


def test_risk_band_rank_ordering() -> None:
    """Vollstaendige Ordnung: escalate > act > mitigate > pending > monitor > noise > unknown."""
    order = ["escalate", "act", "mitigate", "pending", "monitor", "noise", "unknown"]
    ranks = [_RISK_BAND_RANK[b] for b in order]
    assert ranks == sorted(ranks, reverse=True), (
        f"Falscher Rank: {list(zip(order, ranks, strict=True))}"
    )


# ---------------------------------------------------------------------------
# dominant_risk_band: escalate beats all anderen
# ---------------------------------------------------------------------------


def test_dominant_risk_band_escalate_beats_act() -> None:
    """Wenn escalate und act am selben Tag aktiv, dominant_risk_band == 'escalate'."""
    base = FIXED_NOW - timedelta(days=2)
    rows_typed = [
        _FindingRow(
            server_id=1,
            severity=Severity.HIGH,
            first_seen_at=base,
            acknowledged_at=None,
            resolved_at=None,
            is_kev=False,
            kev_added_at=None,
            risk_band="act",
        ),
        _FindingRow(
            server_id=1,
            severity=Severity.HIGH,
            first_seen_at=base,
            acknowledged_at=None,
            resolved_at=None,
            is_kev=False,
            kev_added_at=None,
            risk_band="escalate",
        ),
    ]
    cells = _aggregate_one_server(rows_typed, set(), _days(5))
    today_cell = cells[-1]
    assert today_cell.dominant_risk_band == "escalate", (
        f"escalate soll act dominieren, got {today_cell.dominant_risk_band!r}"
    )


def test_dominant_risk_band_with_none_findings() -> None:
    """Wenn alle risk_band=None, ist dominant_risk_band=None."""
    base = FIXED_NOW - timedelta(days=1)
    rows = [
        _FindingRow(
            server_id=1,
            severity=Severity.HIGH,
            first_seen_at=base,
            acknowledged_at=None,
            resolved_at=None,
            is_kev=False,
            kev_added_at=None,
            risk_band=None,
        ),
    ]
    cells = _aggregate_one_server(rows, set(), _days(3))
    assert cells[-1].dominant_risk_band is None, (
        f"Alle risk_band=None -> dominant_risk_band muss None sein, got {cells[-1].dominant_risk_band!r}"
    )


def test_dominant_risk_band_no_findings_at_all() -> None:
    """Kein Finding -> dominant_risk_band=None fuer jeden Tag."""
    cells = _aggregate_one_server([], set(), _days(5))
    for c in cells:
        assert c.dominant_risk_band is None, (
            f"Tag {c.day}: erwartet None, got {c.dominant_risk_band!r}"
        )


def test_dominant_risk_band_severity_order() -> None:
    """Vollstaendige Ordnung: escalate > act > mitigate > pending > monitor > noise > unknown.

    Pro Test-Iteration wird ein 'schwaecher'-er Band plus 'starker' Band kombiniert;
    der Starkere gewinnt immer.
    """
    base = FIXED_NOW - timedelta(days=1)
    ordered = ["escalate", "act", "mitigate", "pending", "monitor", "noise", "unknown"]
    for i in range(len(ordered) - 1):
        stronger = ordered[i]
        weaker = ordered[i + 1]
        rows = [
            _FindingRow(
                server_id=1,
                severity=Severity.HIGH,
                first_seen_at=base,
                acknowledged_at=None,
                resolved_at=None,
                is_kev=False,
                kev_added_at=None,
                risk_band=stronger,
            ),
            _FindingRow(
                server_id=1,
                severity=Severity.HIGH,
                first_seen_at=base,
                acknowledged_at=None,
                resolved_at=None,
                is_kev=False,
                kev_added_at=None,
                risk_band=weaker,
            ),
        ]
        cells = _aggregate_one_server(rows, set(), _days(3))
        assert cells[-1].dominant_risk_band == stronger, (
            f"{stronger!r} soll {weaker!r} dominieren, got {cells[-1].dominant_risk_band!r}"
        )


def test_dominant_risk_band_mixed_none_and_real() -> None:
    """risk_band=None Findings werden uebersprungen; echte Bands gewinnen."""
    base = FIXED_NOW - timedelta(days=1)
    rows = [
        _FindingRow(
            server_id=1,
            severity=Severity.HIGH,
            first_seen_at=base,
            acknowledged_at=None,
            resolved_at=None,
            is_kev=False,
            kev_added_at=None,
            risk_band=None,
        ),
        _FindingRow(
            server_id=1,
            severity=Severity.HIGH,
            first_seen_at=base,
            acknowledged_at=None,
            resolved_at=None,
            is_kev=False,
            kev_added_at=None,
            risk_band="monitor",
        ),
    ]
    cells = _aggregate_one_server(rows, set(), _days(3))
    assert cells[-1].dominant_risk_band == "monitor", (
        f"'monitor' soll None ueberwiegen, got {cells[-1].dominant_risk_band!r}"
    )


def test_dominant_risk_band_resolved_finding_excluded() -> None:
    """Ein resolved Finding traegt nicht zur dominant_risk_band bei."""
    base = FIXED_NOW - timedelta(days=3)
    resolved_at = FIXED_NOW - timedelta(days=1)
    rows = [
        _FindingRow(
            server_id=1,
            severity=Severity.HIGH,
            first_seen_at=base,
            acknowledged_at=None,
            resolved_at=resolved_at,
            is_kev=False,
            kev_added_at=None,
            risk_band="escalate",
        ),
    ]
    cells = _aggregate_one_server(rows, set(), _days(5))
    # Heute (cells[-1]): Finding wurde 1 Tag vor heute resolved -> nicht mehr aktiv
    assert cells[-1].dominant_risk_band is None, (
        f"Resolved Finding darf heute kein dominant_risk_band setzen, "
        f"got {cells[-1].dominant_risk_band!r}"
    )
    # 2 Tage vor heute (cells[-3]): Finding war noch aktiv
    assert cells[-3].dominant_risk_band == "escalate", (
        f"Finding war vor resolved_at aktiv, got {cells[-3].dominant_risk_band!r}"
    )


# ---------------------------------------------------------------------------
# heartbeats_for_servers — Default days=30
# ---------------------------------------------------------------------------


def test_heartbeats_for_servers_default_days_30() -> None:
    """Bei Default-Aufruf (days=30) hat das Resultat 30 Tage statt 50."""
    from unittest.mock import MagicMock

    session = MagicMock()
    session.execute.return_value.all.return_value = []

    result = heartbeats_for_servers(session, server_ids=[1], now=FIXED_NOW)

    assert len(result[1]) == 30, f"Default-Aufruf muss 30 Tage liefern, got {len(result[1])}"


def test_heartbeats_for_servers_explicit_days_override() -> None:
    """Explizites days-Argument wird beachtet."""
    from unittest.mock import MagicMock

    session = MagicMock()
    session.execute.return_value.all.return_value = []

    result = heartbeats_for_servers(session, server_ids=[1], days=7, now=FIXED_NOW)
    assert len(result[1]) == 7, f"days=7, got {len(result[1])}"


def test_heartbeats_for_servers_dominant_risk_band_in_dailystatus() -> None:
    """DailyStatus-Instanzen haben das dominant_risk_band-Feld."""
    from unittest.mock import MagicMock

    session = MagicMock()
    session.execute.return_value.all.return_value = []

    result = heartbeats_for_servers(session, server_ids=[42], days=3, now=FIXED_NOW)
    for cell in result[42]:
        assert hasattr(cell, "dominant_risk_band"), (
            f"DailyStatus muss dominant_risk_band-Feld haben: {cell!r}"
        )
        assert cell.dominant_risk_band is None  # keine Findings -> None


def test_heartbeats_for_servers_empty_ids() -> None:
    """Leere ID-Liste -> leeres Dict ohne DB-Call."""
    from unittest.mock import MagicMock

    session = MagicMock()
    result = heartbeats_for_servers(session, server_ids=[], days=30, now=FIXED_NOW)
    assert result == {}
    session.execute.assert_not_called()
