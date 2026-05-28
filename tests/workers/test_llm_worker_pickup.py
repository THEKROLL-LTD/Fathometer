"""Pure-Unit-Tests fuer die Pickup-SQL-Struktur (TICKET-007 Etappe 2).

Die *Semantik* des Pickups (failed Pass-1-Sibling blockt Pass-2 nicht mehr,
queued Sibling blockt, nur-done Siblings erlauben Pickup) ist eine
Postgres-SQL-Eigenschaft und gehoert in eine db_integration-Suite
(User-Gate, siehe TICKET-007 DoD #10 Operator-Smoke). Hier wird ohne DB
nur die SQL-*Struktur* gegen Drift abgesichert:

- der Sibling-Wait (`NOT EXISTS ... status IN ('queued','in_progress')`)
  ist vorhanden — er ist die alleinige Gate-Bedingung fuer Pass-2, nachdem
  TICKET-007 das `depends_on` auf Pass-2-Jobs gestrichen hat,
- die `depends_on`-Klausel beginnt weiterhin mit `depends_on IS NULL OR …`,
  sodass die jetzt durchweg `NULL`-wertigen Pass-2-Jobs den Gate immer
  passieren (Bug A: failed Pass-1-Parent kann nicht mehr blockieren).

Capture-Pattern: `_pick_next_job_id` baut die SQL lokal und reicht sie an
`session.execute(sql, params)`. Wir mocken `get_session`, fangen das
`TextClause`-Argument ab und pruefen `str(sql)`.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from app.workers import llm_worker


def _capture_pickup_sql(monkeypatch: pytest.MonkeyPatch) -> str:
    captured: dict[str, Any] = {}

    class _FakeSession:
        def __enter__(self) -> _FakeSession:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def execute(self, sql: Any, params: Any = None) -> Any:
            captured["sql"] = sql
            result = MagicMock()
            result.fetchone.return_value = None
            return result

        def commit(self) -> None:
            return None

    monkeypatch.setattr(llm_worker, "get_session", lambda: _FakeSession())
    llm_worker._pick_next_job_id()
    return str(captured["sql"])


def test_pickup_sql_has_sibling_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    sql = _capture_pickup_sql(monkeypatch)
    assert "risk_evaluation" in sql
    assert "NOT EXISTS" in sql
    assert "group_detection" in sql
    assert "('queued', 'in_progress')" in sql or "('queued','in_progress')" in sql


def test_pickup_sql_depends_on_clause_allows_null(monkeypatch: pytest.MonkeyPatch) -> None:
    sql = _capture_pickup_sql(monkeypatch)
    # `depends_on IS NULL` ist die erste Alternative — Pass-2-Jobs ohne
    # depends_on (TICKET-007) passieren die Klausel immer.
    assert "depends_on IS NULL" in sql
