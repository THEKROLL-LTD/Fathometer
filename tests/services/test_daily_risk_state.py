"""Pure-Unit-Tests fuer `app.services.daily_risk_state` (ADR-0035-Addendum).

Materialisierter `daily_risk_state`-Read-/Write-Pfad ("Vergangenheit
einfrieren, heute live", TD-013). Diese Datei deckt die DB-frei testbaren
Anteile ab:

* CASE-Rank<->Value-Map-Helper als Pure-Functions (kompilierbar / korrektes
  Mapping, Reverse-Roundtrip, Severity-+1-Offset, NULL-Band-Behandlung).
* `today_live_aggregate`-Dict-Vollstaendigkeit via Mock-Session.
* `heartbeats_for_servers`-Read-Path-Assembly/Merge/Gap-Fill via Mock-Session.

Der **Paritaets-Test** (SQL == Python-Oracle) braucht echte Postgres-Semantik
und liegt — `db_integration`-markiert, NICHT in der Default-Suite — in
`tests/integration/test_daily_risk_state_db.py`.

Die SQL-Expression-Helper werden hier gegen die SQLAlchemy-PostgreSQL-Dialect
*kompiliert* (`str(expr.compile(dialect=postgresql.dialect()))`), nicht gegen
eine echte DB ausgefuehrt — das ist eine reine String-/Struktur-Pruefung.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from sqlalchemy import column, literal
from sqlalchemy.dialects import postgresql

from app.models import Severity
from app.services.daily_risk_state import (
    _rank_to_band_expr,
    _rank_to_severity_expr,
    _risk_band_rank_expr,
    _severity_rank_expr,
    today_live_aggregate,
)
from app.services.heartbeat_aggregation import (
    _RISK_BAND_RANK,
    _SEVERITY_RANK,
    DailyStatus,
)

FIXED_NOW = datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)


def _compile(expr: Any) -> str:
    """Kompiliert eine SQLAlchemy-Expression gegen den PostgreSQL-Dialect."""
    return str(expr.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))


# ---------------------------------------------------------------------------
# (A) CASE-Rank-Helper — Risk-Band-Mapping (Pure / kompilierbar)
# ---------------------------------------------------------------------------


def test_risk_band_rank_expr_compiles_and_maps_all_bands() -> None:
    """`_risk_band_rank_expr` kompiliert und enthaelt jeden Band->Rang-Zweig."""
    sql = _compile(_risk_band_rank_expr(column("risk_band")))
    assert sql.upper().startswith("CASE")
    # Jeder Band-String und sein Rang muessen im kompilierten CASE auftauchen.
    for band, rank in _RISK_BAND_RANK.items():
        assert band in sql, (band, sql)
        assert str(rank) in sql, (rank, sql)
    # Else-Zweig (NULL/unbekannt) -> 0.
    assert "ELSE 0" in sql.upper()


def test_rank_to_band_expr_compiles_and_reverse_maps() -> None:
    """Reverse-Map kompiliert; Rang 0 (else) -> NULL, sonst kanonischer String."""
    sql = _compile(_rank_to_band_expr(column("rk")))
    assert sql.upper().startswith("CASE")
    for band, rank in _RISK_BAND_RANK.items():
        assert band in sql, (band, sql)
        assert str(rank) in sql, (rank, sql)
    # Else-Zweig liefert NULL (Rang 0 -> dominant_risk_band None).
    assert "ELSE NULL" in sql.upper()


def test_risk_band_rank_roundtrip_is_bijective() -> None:
    """rank(band) -> band ist fuer alle bekannten Bands eine Identitaet.

    Wir simulieren das Mapping mit den reinen Python-Dicts, die die SQL-CASE-
    Zweige 1:1 spiegeln (`_RISK_BAND_RANK` + Reverse). Das ist der Kern der
    Parity-Garantie: die SQL-CASE-Ausdruecke werden aus exakt diesen Dicts
    gebaut.
    """
    reverse = {rank: band for band, rank in _RISK_BAND_RANK.items()}
    # Bijektiv: kein Rang doppelt vergeben.
    assert len(reverse) == len(_RISK_BAND_RANK)
    for band, rank in _RISK_BAND_RANK.items():
        assert reverse[rank] == band
    # Rang 0 (else) ist in der Reverse-Map NICHT vorhanden -> NULL/None.
    assert 0 not in reverse


# ---------------------------------------------------------------------------
# (B) CASE-Rank-Helper — Severity-Mapping mit +1-Offset (scharfe Kante #1)
# ---------------------------------------------------------------------------


def test_severity_rank_expr_uses_plus_one_offset() -> None:
    """Severity-Rang ist +1 verschoben — UNKNOWN(0) wird zu 1, nicht 0.

    Damit "keine Findings" (MAX liefert 0/NULL) von "nur-unknown-Findings"
    (MAX liefert 1) unterscheidbar bleibt (Implementer-Kante #1).
    """
    sql = _compile(_severity_rank_expr(column("severity")))
    assert sql.upper().startswith("CASE")
    # UNKNOWN hat Python-Rang 0 -> SQL-Wert 0+1 = 1.
    assert _SEVERITY_RANK[Severity.UNKNOWN] == 0
    assert "unknown" in sql
    # CRITICAL hat Python-Rang 4 -> SQL-Wert 5.
    for sev, rank in _SEVERITY_RANK.items():
        assert sev.value in sql, (sev, sql)
        assert str(rank + 1) in sql, (sev, rank, sql)
    # Else-Zweig 0 reserviert fuer "kein Finding praesent".
    assert "ELSE 0" in sql.upper()


def test_rank_to_severity_expr_reverses_plus_one_offset() -> None:
    """Reverse-Map matcht gegen (rank+1); Rang 0/NULL -> NULL (kein Finding)."""
    sql = _compile(_rank_to_severity_expr(column("rk")))
    for sev, rank in _SEVERITY_RANK.items():
        assert sev.value in sql, (sev, sql)
        assert str(rank + 1) in sql, (sev, sql)
    # Kein expliziter Zweig fuer den Wert 0 -> faellt in ELSE NULL.
    assert "ELSE NULL" in sql.upper()


def test_severity_rank_offset_separates_unknown_from_no_finding() -> None:
    """Kernaussage der Kante #1 auf Mapping-Ebene.

    - "kein Finding praesent": MAX(case else 0) -> 0 -> Reverse matcht keinen
      Zweig (kleinster Zweig ist rank+1 = 1) -> NULL -> max_severity=None.
    - "nur unknown praesent": MAX -> 1 -> Reverse matcht UNKNOWN.value.
    Wir bilden das mit den reinen Dicts nach.
    """
    shifted = {sev.value: rank + 1 for sev, rank in _SEVERITY_RANK.items()}
    reverse = {v: k for k, v in shifted.items()}
    # 0 ist NICHT in der Reverse-Map -> kein Finding -> None.
    assert 0 not in reverse
    # 1 ist die unknown-Severity (Offset machte aus Rang 0 den Wert 1).
    assert reverse[1] == Severity.UNKNOWN.value


# ---------------------------------------------------------------------------
# (C) today_live_aggregate — Dict-Vollstaendigkeit via Mock-Session
# ---------------------------------------------------------------------------


def _agg_row(server_id: int, band: str | None, sev: str | None, kev: int) -> SimpleNamespace:
    """Eine Zeile der Findings-GROUP-BY-Query (today_live_aggregate)."""
    return SimpleNamespace(
        server_id=server_id,
        dominant_risk_band=band,
        max_severity=sev,
        kev_count=kev,
    )


def _make_session(agg_rows: list[Any], scan_rows: list[tuple[int]]) -> MagicMock:
    """Mock-Session: erste execute = Findings-Agg, zweite = Scans-heute."""
    findings_result = MagicMock()
    findings_result.all.return_value = agg_rows
    scans_result = MagicMock()
    scans_result.all.return_value = scan_rows
    session = MagicMock()
    session.execute.side_effect = [findings_result, scans_result]
    return session


def test_today_live_aggregate_every_server_in_result() -> None:
    """Jeder uebergebene server_id taucht im Result auf — auch ohne Findings."""
    # Nur Server 1 hat ein Agg-Result; Server 2 und 3 keins.
    session = _make_session(
        agg_rows=[_agg_row(1, "act", "high", 2)],
        scan_rows=[(1,)],
    )
    out = today_live_aggregate(session, [1, 2, 3], now=FIXED_NOW)

    assert set(out.keys()) == {1, 2, 3}, out
    today = FIXED_NOW.date()
    # Server 1: vollstaendiges Aggregat.
    assert out[1] == DailyStatus(
        day=today,
        max_severity=Severity.HIGH,
        kev_count=2,
        had_scan=True,
        dominant_risk_band="act",
    )
    # Server 2/3: leeres Aggregat aber praesent, day == today.
    for sid in (2, 3):
        assert out[sid].day == today
        assert out[sid].max_severity is None
        assert out[sid].kev_count == 0
        assert out[sid].dominant_risk_band is None
        assert out[sid].had_scan is False


def test_today_live_aggregate_day_is_today() -> None:
    """`day` ist exakt der heutige Tag (nicht gestern/morgen)."""
    session = _make_session(agg_rows=[], scan_rows=[])
    out = today_live_aggregate(session, [42], now=FIXED_NOW)
    assert out[42].day == date(2026, 6, 7)


def test_today_live_aggregate_had_scan_from_scan_query() -> None:
    """had_scan kommt aus der zweiten (Scan-)Query, unabhaengig von Findings."""
    session = _make_session(
        agg_rows=[_agg_row(7, None, None, 0)],  # Findings-Row ohne Severity
        scan_rows=[(7,)],  # aber heute gescannt
    )
    out = today_live_aggregate(session, [7], now=FIXED_NOW)
    assert out[7].had_scan is True
    assert out[7].max_severity is None
    assert out[7].dominant_risk_band is None


def test_today_live_aggregate_empty_server_list_returns_empty() -> None:
    """Leere server_ids -> leeres Dict, kein execute."""
    session = MagicMock()
    out = today_live_aggregate(session, [], now=FIXED_NOW)
    assert out == {}
    session.execute.assert_not_called()


def test_today_live_aggregate_null_risk_band_but_severity_set() -> None:
    """Kante #2: band=None, aber max_severity/kev gesetzt — unabhaengig."""
    session = _make_session(
        agg_rows=[_agg_row(5, None, "critical", 3)],
        scan_rows=[(5,)],
    )
    out = today_live_aggregate(session, [5], now=FIXED_NOW)
    assert out[5].dominant_risk_band is None
    assert out[5].max_severity == Severity.CRITICAL
    assert out[5].kev_count == 3


# ---------------------------------------------------------------------------
# (D) heartbeats_for_servers — Read-Path-Assembly / Merge / Gap-Fill
# ---------------------------------------------------------------------------


def _frozen_row(
    server_id: int,
    day: date,
    band: str | None,
    sev: str | None,
    kev: int,
    had_scan: bool,
) -> SimpleNamespace:
    """Eine Zeile der frozen-`daily_risk_state`-Query."""
    return SimpleNamespace(
        server_id=server_id,
        day=day,
        dominant_risk_band=band,
        max_severity=sev,
        kev_count=kev,
        had_scan=had_scan,
    )


def test_read_path_assembly_merge_and_gap_fill(monkeypatch: Any) -> None:
    """frozen-Rows (mit Luecken) + live-today -> exakt `days` Cells je Server.

    Aufbau (days=5, today=2026-06-07):
      day_list = [06-03, 06-04, 06-05, 06-06, 06-07(today)]
      frozen[Server 1] hat NUR 06-04 und 06-06 -> 06-03 und 06-05 sind Luecken.
      today-Cell kommt aus dem (gemockten) today_live_aggregate.
    """
    from app.services import heartbeat_aggregation

    today = FIXED_NOW.date()
    d3 = today - timedelta(days=4)  # 06-03
    d4 = today - timedelta(days=3)  # 06-04
    d5 = today - timedelta(days=2)  # 06-05
    d6 = today - timedelta(days=1)  # 06-06

    # Frozen-Query liefert nur 2 der 4 Vergangenheits-Tage (Luecken d3, d5).
    frozen_result = MagicMock()
    frozen_result.all.return_value = [
        _frozen_row(1, d4, "act", "high", 0, True),
        _frozen_row(1, d6, "escalate", "critical", 2, True),
    ]
    session = MagicMock()
    session.execute.return_value = frozen_result

    # today_live_aggregate mocken — wird intern (lokaler Import) aufgerufen.
    today_cell = DailyStatus(
        day=today,
        max_severity=Severity.MEDIUM,
        kev_count=1,
        had_scan=True,
        dominant_risk_band="mitigate",
    )
    monkeypatch.setattr(
        "app.services.daily_risk_state.today_live_aggregate",
        lambda sess, ids, now=None: {1: today_cell},
    )

    out = heartbeat_aggregation.heartbeats_for_servers(session, [1], days=5, now=FIXED_NOW)

    assert set(out.keys()) == {1}
    cells = out[1]
    assert len(cells) == 5
    # Datums-Reihenfolge aeltester-zuerst.
    assert [c.day for c in cells] == [d3, d4, d5, d6, today]
    # Luecken (d3, d5) sind None-DailyStatus.
    by_day = {c.day: c for c in cells}
    for gap in (d3, d5):
        assert by_day[gap].max_severity is None
        assert by_day[gap].dominant_risk_band is None
        assert by_day[gap].kev_count == 0
        assert by_day[gap].had_scan is False
    # Vorhandene frozen-Cells korrekt gemerged.
    assert by_day[d4].dominant_risk_band == "act"
    assert by_day[d4].max_severity == Severity.HIGH
    assert by_day[d6].dominant_risk_band == "escalate"
    assert by_day[d6].max_severity == Severity.CRITICAL
    assert by_day[d6].kev_count == 2
    # Letzte Cell ist die today-Cell aus dem Live-Aggregat.
    assert cells[-1] is today_cell
    assert cells[-1].day == today
    assert cells[-1].dominant_risk_band == "mitigate"


def test_read_path_every_server_in_dict_even_without_frozen(monkeypatch: Any) -> None:
    """Jeder server_id im Dict; Server ohne frozen-Rows -> alle Past-Cells None."""
    from app.services import heartbeat_aggregation

    today = FIXED_NOW.date()
    frozen_result = MagicMock()
    frozen_result.all.return_value = []  # gar keine frozen-Rows
    session = MagicMock()
    session.execute.return_value = frozen_result

    # today-Aggregat liefert nur fuer Server 1 etwas, Server 2 fehlt -> Fallback.
    monkeypatch.setattr(
        "app.services.daily_risk_state.today_live_aggregate",
        lambda sess, ids, now=None: {
            1: DailyStatus(
                day=today,
                max_severity=Severity.LOW,
                kev_count=0,
                had_scan=True,
                dominant_risk_band="monitor",
            )
        },
    )

    out = heartbeat_aggregation.heartbeats_for_servers(session, [1, 2], days=3, now=FIXED_NOW)

    assert set(out.keys()) == {1, 2}
    for sid in (1, 2):
        assert len(out[sid]) == 3
        # Past-Cells (erste 2) sind None-Status.
        for past in out[sid][:-1]:
            assert past.max_severity is None
            assert past.dominant_risk_band is None
    # Server 1 today aus Live-Aggregat.
    assert out[1][-1].dominant_risk_band == "monitor"
    # Server 2 today: Fallback None-Cell (today_live_aggregate hatte keinen Eintrag).
    assert out[2][-1].max_severity is None
    assert out[2][-1].day == today


def test_read_path_empty_server_list_returns_empty() -> None:
    """Leere server_ids -> leeres Dict (Frueh-Return, kein execute)."""
    from app.services import heartbeat_aggregation

    session = MagicMock()
    out = heartbeat_aggregation.heartbeats_for_servers(session, [], days=30, now=FIXED_NOW)
    assert out == {}
    session.execute.assert_not_called()


def test_read_path_window_size_matches_days(monkeypatch: Any) -> None:
    """Kante #5: jede Server-Liste hat exakt `days` Cells (hier days=30)."""
    from app.services import heartbeat_aggregation

    today = FIXED_NOW.date()
    frozen_result = MagicMock()
    frozen_result.all.return_value = []
    session = MagicMock()
    session.execute.return_value = frozen_result
    monkeypatch.setattr(
        "app.services.daily_risk_state.today_live_aggregate",
        lambda sess, ids, now=None: {},
    )

    out = heartbeat_aggregation.heartbeats_for_servers(session, [1], days=30, now=FIXED_NOW)
    cells = out[1]
    assert len(cells) == 30
    # aeltester Tag = today-29, letzter = today.
    assert cells[0].day == today - timedelta(days=29)
    assert cells[-1].day == today
    # Streng monoton steigende Tage, keine Duplikate.
    days = [c.day for c in cells]
    assert days == sorted(days)
    assert len(set(days)) == 30


# Silence linter falls `literal`/`date`-Imports nur indirekt genutzt werden.
_ = (literal, date)
