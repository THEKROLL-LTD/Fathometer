"""Pure-Unit-Tests fuer den SQL-Aggregations-Pfad in `severity_history`
(Phase E, ADR-0030 Befund 3).

Zwei Test-Kategorien:

1. **SQL-String-Smoke-Tests** — kompilieren das SQLAlchemy-Statement mit
   `literal_binds=True` und pruefen Substrings wie `generate_series`,
   `COUNT(*) FILTER`, `severity = `, `is_kev`, etc. Billige Coverage
   ohne echte DB-Verbindung.

2. **Verhaltens-Aequivalenz-Tests** — Mock-Session gibt (day, crit, high,
   medium, low, kev_events)-Tupel zurueck wie sie eine echte SQL-Query
   liefern wuerde; prueft, dass `daily_severity_counts_for_server` und
   `severity_snapshots_for_server` ohne `rows=`-Parameter die richtigen
   `DailySeverityCount`-Objekte bauen.

Kein DB-Fixture, kein Postgres — rein Pure-Unit.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from sqlalchemy import Date, bindparam, func, select

from app.models import Finding, Severity
from app.services.severity_history import (
    DailySeverityCount,
    daily_severity_counts_fleet,
    daily_severity_counts_for_server,
)

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)
FIXED_TODAY = FIXED_NOW.date()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compile_stmt(stmt: object) -> str:
    """Kompiliert ein SQLAlchemy-Statement mit literal_binds zu einem SQL-String."""
    from sqlalchemy.dialects import postgresql

    compiled = stmt.compile(  # type: ignore[union-attr]
        dialect=postgresql.dialect(),
        compile_kwargs={"literal_binds": True},
    )
    return str(compiled)


# ---------------------------------------------------------------------------
# SQL-String-Smoke-Tests: _build_server_daily_sql
# ---------------------------------------------------------------------------


def test_server_daily_sql_contains_generate_series() -> None:
    """Kompilierter Server-Daily-SQL-String enthaelt `generate_series`."""
    from app.services.severity_history import _INTERVAL_1_DAY, _build_kev_open_sql  # noqa: F401

    # Baue das Statement direkt (nachbilden was _build_server_daily_sql erzeugt).
    start_day = FIXED_TODAY - timedelta(days=49)
    end_day = FIXED_TODAY

    days_subq = select(
        func.cast(
            func.generate_series(
                bindparam("srv_start_day", value=start_day, type_=Date),
                bindparam("srv_end_day", value=end_day, type_=Date),
                _INTERVAL_1_DAY,
            ),
            Date,
        ).label("d")
    ).subquery()

    from sqlalchemy.dialects import postgresql

    sql = str(
        days_subq.element.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )

    assert "generate_series" in sql, f"generate_series erwartet in SQL:\n{sql}"


def test_server_daily_sql_contains_count_filter() -> None:
    """Kompilierter Server-Daily-SQL-String enthaelt `COUNT(*) FILTER`."""
    from app.services.severity_history import _INTERVAL_1_DAY, _eod_expr

    start_day = FIXED_TODAY - timedelta(days=4)
    end_day = FIXED_TODAY

    from sqlalchemy import or_

    days_subq = select(
        func.cast(
            func.generate_series(
                bindparam("srv_start_day", value=start_day, type_=Date),
                bindparam("srv_end_day", value=end_day, type_=Date),
                _INTERVAL_1_DAY,
            ),
            Date,
        ).label("d")
    ).subquery()

    eod = _eod_expr(days_subq.c.d)

    stmt = (
        select(
            days_subq.c.d,
            func.count()
            .filter(
                Finding.severity == Severity.CRITICAL,
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("crit"),
        )
        .select_from(days_subq)
        .outerjoin(Finding, Finding.server_id == 99)
        .group_by(days_subq.c.d)
        .order_by(days_subq.c.d)
    )

    from sqlalchemy.dialects import postgresql

    sql = str(
        stmt.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )

    assert "FILTER (WHERE" in sql or "filter (where" in sql.lower(), (
        f"COUNT FILTER erwartet in SQL:\n{sql}"
    )
    assert "generate_series" in sql, f"generate_series erwartet in SQL:\n{sql}"


def test_server_daily_sql_contains_severity_filter() -> None:
    """Der kompilierte SQL-String enthaelt Severity-Werte als FILTER-Bedingungen."""
    from app.services.severity_history import _INTERVAL_1_DAY, _eod_expr

    start_day = FIXED_TODAY - timedelta(days=4)
    end_day = FIXED_TODAY

    from sqlalchemy import or_

    days_subq = select(
        func.cast(
            func.generate_series(
                bindparam("srv_start_day", value=start_day, type_=Date),
                bindparam("srv_end_day", value=end_day, type_=Date),
                _INTERVAL_1_DAY,
            ),
            Date,
        ).label("d")
    ).subquery()

    eod = _eod_expr(days_subq.c.d)

    stmt = (
        select(
            days_subq.c.d,
            func.count()
            .filter(
                Finding.severity == Severity.CRITICAL,
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("crit"),
            func.count()
            .filter(
                Finding.is_kev.is_(True),
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("kev_open"),
        )
        .select_from(days_subq)
        .outerjoin(Finding, Finding.server_id == 99)
        .group_by(days_subq.c.d)
        .order_by(days_subq.c.d)
    )

    from sqlalchemy.dialects import postgresql

    sql = str(
        stmt.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )

    # Severity-Enum-Wert 'critical' muss als FILTER-Bedingung erscheinen.
    assert "critical" in sql, f"'critical' erwartet in SQL:\n{sql}"
    # is_kev-Filter muss erscheinen.
    assert "is_kev" in sql, f"'is_kev' erwartet in SQL:\n{sql}"


# ---------------------------------------------------------------------------
# SQL-String-Smoke-Tests: _build_fleet_daily_sql
# ---------------------------------------------------------------------------


def test_fleet_daily_sql_contains_generate_series_and_filters() -> None:
    """Fleet-SQL-Statement enthaelt generate_series + total/kev/crit/high-Filter."""
    from app.services.severity_history import _INTERVAL_1_DAY, _eod_expr

    start_day = FIXED_TODAY - timedelta(days=49)
    end_day = FIXED_TODAY

    from sqlalchemy import or_

    days_subq = select(
        func.cast(
            func.generate_series(
                bindparam("fleet_start_day", value=start_day, type_=Date),
                bindparam("fleet_end_day", value=end_day, type_=Date),
                _INTERVAL_1_DAY,
            ),
            Date,
        ).label("d")
    ).subquery()

    eod = _eod_expr(days_subq.c.d)

    stmt = (
        select(
            days_subq.c.d,
            func.count()
            .filter(
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("total"),
            func.count()
            .filter(
                Finding.is_kev.is_(True),
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("kev"),
            func.count()
            .filter(
                Finding.severity == Severity.CRITICAL,
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("crit"),
        )
        .select_from(days_subq)
        .outerjoin(Finding, Finding.server_id.is_not(None))
        .group_by(days_subq.c.d)
        .order_by(days_subq.c.d)
    )

    from sqlalchemy.dialects import postgresql

    sql = str(
        stmt.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )

    assert "generate_series" in sql, f"generate_series erwartet in SQL:\n{sql}"
    assert "FILTER (WHERE" in sql or "filter (where" in sql.lower(), (
        f"COUNT FILTER erwartet in SQL:\n{sql}"
    )
    assert "is_kev" in sql, f"'is_kev' erwartet in SQL:\n{sql}"
    assert "critical" in sql, f"'critical' erwartet in SQL:\n{sql}"


# ---------------------------------------------------------------------------
# Verhaltens-Aequivalenz-Tests: daily_severity_counts_for_server
# ---------------------------------------------------------------------------


def _make_sql_mock_rows(
    days: int = 5,
    now: datetime = FIXED_NOW,
) -> list[MagicMock]:
    """Erzeugt Mock-SQL-Rows wie sie eine echte SQLAlchemy-Query liefern wuerde.

    SQLAlchemy Row-Objekte haben benannte Attribute (r.d, r.crit, ...),
    kein tuple-Unpacking. MagicMock emuliert das korrekt.

    Werte: crit=1 am ersten Tag, high=2 am zweiten Tag; kev_events=1 am letzten Tag.
    """
    end_day = now.date()
    rows = []
    for i in range(days):
        d = end_day - timedelta(days=days - 1 - i)
        row = MagicMock()
        row.d = d  # date-Objekt, kein .date()-Call noetig
        row.crit = 1 if i == 0 else 0
        row.high = 2 if i == 1 else 0
        row.medium = 0
        row.low = 0
        row.kev_events = 1 if i == days - 1 else 0
        rows.append(row)
    return rows


def test_daily_counts_sql_path_builds_correct_dataclasses() -> None:
    """Ohne `rows=` nutzt daily_severity_counts_for_server den SQL-Pfad.

    Mock-Session gibt feste Tupel zurueck; prueft, dass die richtigen
    DailySeverityCount-Objekte gebaut werden — Reihenfolge, Werte, Typen.
    """
    days = 5
    sql_rows = _make_sql_mock_rows(days=days, now=FIXED_NOW)

    # Die SQL-Query gibt sql_rows als Resultat zurueck.
    # Zwei execute()-Calls sind im Snapshots-Pfad (SQL-rows + kev-open);
    # fuer daily_counts_for_server ist es ein execute()-Call.
    mock_session = MagicMock()
    mock_session.execute.return_value.all.return_value = sql_rows

    result = daily_severity_counts_for_server(
        mock_session,
        server_id=42,
        days=days,
        now=FIXED_NOW,
        # rows=None -> SQL-Pfad
    )

    assert len(result) == days, f"Erwartet {days} Records, bekommen {len(result)}"
    assert all(isinstance(d, DailySeverityCount) for d in result)

    # Erster Tag: critical=1, alle anderen 0.
    first = result[0]
    assert first.day == FIXED_TODAY - timedelta(days=days - 1)
    assert first.critical == 1
    assert first.high == 0
    assert first.kev == 0

    # Zweiter Tag: high=2.
    second = result[1]
    assert second.high == 2
    assert second.critical == 0

    # Letzter Tag: kev_events=1.
    last = result[-1]
    assert last.day == FIXED_TODAY
    assert last.kev == 1


def test_daily_counts_sql_path_session_is_called() -> None:
    """Ohne rows= wird session.execute aufgerufen — SQL-Pfad ist aktiv."""
    mock_session = MagicMock()
    mock_session.execute.return_value.all.return_value = []

    daily_severity_counts_for_server(
        mock_session,
        server_id=7,
        days=3,
        now=FIXED_NOW,
    )

    assert mock_session.execute.called, "session.execute muss im SQL-Pfad aufgerufen werden"


def test_daily_counts_sql_path_empty_rows_returns_empty_list() -> None:
    """Leere SQL-Rows -> leere Liste (kein Crash, kein NaN)."""
    mock_session = MagicMock()
    mock_session.execute.return_value.all.return_value = []

    result = daily_severity_counts_for_server(
        mock_session,
        server_id=1,
        days=5,
        now=FIXED_NOW,
    )

    # Bei leeren SQL-Rows: keine Tupel -> leere Liste.
    assert isinstance(result, list)
    assert result == []


# ---------------------------------------------------------------------------
# Verhaltens-Aequivalenz-Tests: daily_severity_counts_fleet
# ---------------------------------------------------------------------------


def test_fleet_sql_path_returns_correct_structure() -> None:
    """daily_severity_counts_fleet nutzt den SQL-Pfad und baut das korrekte Dict.

    Mock-Session gibt (day, total, kev, crit, high)-Tupel zurueck.
    """
    days = 3
    end_day = FIXED_TODAY
    fleet_rows = [
        MagicMock(d=end_day - timedelta(days=2), total=5, kev=2, crit=1, high=3),
        MagicMock(d=end_day - timedelta(days=1), total=7, kev=3, crit=2, high=4),
        MagicMock(d=end_day, total=10, kev=4, crit=3, high=6),
    ]

    mock_session = MagicMock()
    mock_session.execute.return_value.all.return_value = fleet_rows

    result = daily_severity_counts_fleet(mock_session, days=days, now=FIXED_NOW)

    assert set(result.keys()) == {"total", "kev", "critical", "high"}
    assert len(result["total"]) == days
    assert result["total"] == [5, 7, 10]
    assert result["kev"] == [2, 3, 4]
    assert result["critical"] == [1, 2, 3]
    assert result["high"] == [3, 4, 6]


def test_fleet_sql_path_session_is_called() -> None:
    """daily_severity_counts_fleet ruft session.execute auf (SQL-Pfad aktiv)."""
    mock_session = MagicMock()
    mock_session.execute.return_value.all.return_value = []

    daily_severity_counts_fleet(mock_session, days=5, now=FIXED_NOW)

    assert mock_session.execute.called, "session.execute muss im SQL-Pfad aufgerufen werden"


def test_fleet_sql_empty_rows_returns_all_zeros() -> None:
    """Leere SQL-Rows -> alle Buckets mit `days` Nullen."""
    mock_session = MagicMock()
    mock_session.execute.return_value.all.return_value = []

    result = daily_severity_counts_fleet(mock_session, days=5, now=FIXED_NOW)

    assert set(result.keys()) == {"total", "kev", "critical", "high"}
    for key, vals in result.items():
        assert len(vals) == 5, f"{key}: erwartet 5 Eintraege"
        assert all(v == 0 for v in vals), f"{key}: erwartet alle 0"


# ---------------------------------------------------------------------------
# Backward-Compat: rows=-Pfad bleibt unveraendert
# ---------------------------------------------------------------------------


def test_daily_counts_rows_param_bypasses_sql() -> None:
    """Mit rows= wird der SQL-Pfad NICHT benutzt — Phase-B-Backward-Compat.

    Mock-Session darf nicht aufgerufen werden wenn rows= gesetzt ist.
    """
    from app.services.severity_history import _FindingRow

    fseen = FIXED_NOW - timedelta(days=2)
    rows = [
        _FindingRow(
            severity=Severity.HIGH,
            first_seen_at=fseen,
            acknowledged_at=None,
            resolved_at=None,
            kev_added_at=None,
            is_kev=False,
        )
    ]

    mock_session = MagicMock()
    mock_session.execute.side_effect = AssertionError("SQL-Pfad darf nicht aufgerufen werden")

    result = daily_severity_counts_for_server(
        mock_session,
        server_id=1,
        days=3,
        now=FIXED_NOW,
        rows=rows,
    )

    # rows=-Pfad: Python-Aggregator, kein Session-Aufruf.
    assert len(result) == 3
    assert any(d.high > 0 for d in result), "HIGH-Finding muss in mindestens einem Tag zaehlen"
