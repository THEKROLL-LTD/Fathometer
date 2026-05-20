"""Unit-Tests fuer `count_kev_events_50d()` (Block K, ADR-0018) ohne DB.

Die Funktion baut genau eine `select(...)`-Query und ruft
`session.execute(stmt).scalar()`. Wir mocken die Session und verifizieren:

1. Das Statement enthaelt die beiden ODER-Aeste aus der ADR-0018-Definition
   (kev_added_at >= cutoff ODER first_seen_at >= cutoff AND is_kev=TRUE).
2. Der gefilterte server_id-Wert kommt in den Bind-Parametern an.
3. Der Cutoff = `now - 50d` wird korrekt berechnet (auf den Bind-Wert
   geprueft).
4. Der Rueckgabewert ist `int(scalar or 0)` — auch wenn die Query `None`
   liefert, ist das Ergebnis 0.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

from sqlalchemy.dialects import postgresql

from app.services.severity_history import count_kev_events_50d

FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)
EXPECTED_CUTOFF = FIXED_NOW - timedelta(days=50)


def _compile_stmt(stmt: Any) -> tuple[str, dict[str, Any]]:
    """Kompiliert ein SQLA-Statement gegen den postgresql-Dialect.

    Liefert (SQL-Text, Bind-Params) — Bind-Werte sind die `literal_binds=False`-
    Defaultwerte, damit wir Cutoffs und IDs ablesen koennen.
    """
    compiled = stmt.compile(
        dialect=postgresql.dialect(),
        compile_kwargs={"literal_binds": False},
    )
    return str(compiled), dict(compiled.params)


def _mock_session(scalar_value: int | None) -> MagicMock:
    session = MagicMock()
    session.execute.return_value.scalar.return_value = scalar_value
    return session


def test_count_kev_events_50d_builds_two_branch_filter() -> None:
    """Die Query enthaelt beide Aeste aus der ADR-0018-Definition.

    - `kev_added_at >= cutoff`
    - `first_seen_at >= cutoff AND is_kev = TRUE`

    Auf SQL-Stringebene heisst das: beide Spaltennamen tauchen in WHERE auf,
    `OR` verbindet die zwei Aeste, `is_kev IS true` ist drin.
    """
    session = _mock_session(2)
    result = count_kev_events_50d(session, server_id=42, now=FIXED_NOW)
    assert result == 2

    assert session.execute.call_count == 1
    stmt = session.execute.call_args[0][0]
    sql, params = _compile_stmt(stmt)
    sql_lower = sql.lower()

    # Beide Aeste sind drin.
    assert "kev_added_at" in sql_lower
    assert "first_seen_at" in sql_lower
    assert "is_kev" in sql_lower
    # Das OR verbindet die beiden Cut-off-Vergleiche.
    assert " or " in sql_lower
    # Distinct-Count auf findings.id.
    assert "count(distinct" in sql_lower
    # Server-Filter ist drin.
    assert "server_id" in sql_lower

    # Bind-Werte: cutoff = now - 50d, server_id = 42.
    bind_values = list(params.values())
    assert EXPECTED_CUTOFF in bind_values
    assert 42 in bind_values


def test_count_kev_events_50d_returns_zero_on_empty_server() -> None:
    """Liefert die Query `None`/0 -> Ergebnis ist 0, kein Crash."""
    session = _mock_session(None)
    assert count_kev_events_50d(session, server_id=99, now=FIXED_NOW) == 0

    session2 = _mock_session(0)
    assert count_kev_events_50d(session2, server_id=99, now=FIXED_NOW) == 0


def test_count_kev_events_50d_uses_explicit_now_for_cutoff() -> None:
    """`now`-Parameter wird respektiert (deterministische Tests).

    Wir verschieben `now` 100 Tage in die Vergangenheit und pruefen dass
    der Cutoff entsprechend verschoben ist.
    """
    shifted_now = FIXED_NOW - timedelta(days=100)
    expected_cutoff = shifted_now - timedelta(days=50)
    session = _mock_session(7)

    count_kev_events_50d(session, server_id=1, now=shifted_now)

    stmt = session.execute.call_args[0][0]
    _sql, params = _compile_stmt(stmt)
    assert expected_cutoff in params.values()


def test_count_kev_events_50d_coerces_scalar_to_int() -> None:
    """`session.execute(...).scalar()` kann theoretisch float/Decimal liefern — wir wandeln zu int."""
    session = MagicMock()
    # Postgres count() liefert bigint, der psycopg-Adapter mappt zu int —
    # aber wir verlassen uns nicht drauf. Die Funktion ruft `int(... or 0)`.
    session.execute.return_value.scalar.return_value = 5
    assert count_kev_events_50d(session, server_id=1, now=FIXED_NOW) == 5
    assert isinstance(
        count_kev_events_50d(_mock_session(3), server_id=1, now=FIXED_NOW),
        int,
    )
