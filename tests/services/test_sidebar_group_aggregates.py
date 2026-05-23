"""Pure-Unit-Tests fuer `app.services.sidebar_group_aggregates` (Block W, ADR-0034).

`group_counts(session)` ist eine reine Service-Funktion die eine Session nimmt
und ein Dict zurueckgibt. Wir mocken die Session so, dass `.execute().all()`
eine kontrollierte Tuple-Liste liefert — kein Postgres-Roundtrip.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.services.sidebar_group_aggregates import group_counts


def _make_row(
    group_id: int | None, server_count: int, escalate_count: int, act_count: int
) -> MagicMock:
    """Simuliert eine SQLAlchemy-Row mit den erwarteten Spalten."""
    row = MagicMock()
    row.group_id = group_id
    row.server_count = server_count
    row.escalate_count = escalate_count
    row.act_count = act_count
    return row


def _make_session(rows: list[MagicMock]) -> MagicMock:
    """Stub-Session die exakt `rows` als `.execute().all()` zurueckgibt."""
    session = MagicMock()
    session.execute.return_value.all.return_value = rows
    return session


# ---------------------------------------------------------------------------
# Basis-Verhalten
# ---------------------------------------------------------------------------


def test_group_counts_returns_dict_with_int_keys() -> None:
    """Typische Ausgabe: Dict mit int-Keys und korrekten Aggregat-Werten."""
    rows = [
        _make_row(group_id=1, server_count=3, escalate_count=2, act_count=1),
        _make_row(group_id=2, server_count=5, escalate_count=0, act_count=4),
    ]
    session = _make_session(rows)

    result = group_counts(session)

    assert isinstance(result, dict), "Rueckgabe muss ein Dict sein"
    assert 1 in result, "group_id=1 muss im Dict sein"
    assert 2 in result, "group_id=2 muss im Dict sein"

    assert result[1] == {"escalate": 2, "act": 1, "hosts": 3}, result[1]
    assert result[2] == {"escalate": 0, "act": 4, "hosts": 5}, result[2]


def test_group_counts_handles_null_bucket() -> None:
    """Server ohne group_id (NULL) werden unter Key None aggregiert."""
    rows = [
        _make_row(group_id=None, server_count=7, escalate_count=3, act_count=2),
        _make_row(group_id=1, server_count=2, escalate_count=0, act_count=0),
    ]
    session = _make_session(rows)

    result = group_counts(session)

    assert None in result, "NULL-Gruppe muss unter Key None stehen"
    assert result[None] == {"escalate": 3, "act": 2, "hosts": 7}, result[None]
    assert result[1] == {"escalate": 0, "act": 0, "hosts": 2}, result[1]


def test_group_counts_empty_db() -> None:
    """Leere DB (keine Server, keine Findings) -> leeres Dict."""
    session = _make_session([])

    result = group_counts(session)

    assert result == {}, f"Erwartetes leeres Dict, got {result!r}"


def test_group_counts_only_escalate_act_count() -> None:
    """Nur Findings mit risk_band in ('escalate', 'act') zaehlen fuer die Counts.

    Das wird durch den DB-Query sichergestellt; der Test verifiziert, dass
    der Service die DB-Spalten 1:1 durchreicht und kein eigenes Filtering macht.
    Wenn die DB (via Mock) nur escalate/act-Counts liefert, spiegelt das Resultat
    diese exakt wider.
    """
    # Simuliert: Group 5 hat 10 Server, 3 escalate, 2 act, der Rest ist ignoriert.
    rows = [
        _make_row(group_id=5, server_count=10, escalate_count=3, act_count=2),
    ]
    session = _make_session(rows)

    result = group_counts(session)

    assert result[5]["escalate"] == 3, "escalate-Count muss 3 sein"
    assert result[5]["act"] == 2, "act-Count muss 2 sein"
    assert result[5]["hosts"] == 10, "hosts-Count muss 10 sein"
    # Kein weiterer Key ausser escalate/act/hosts
    assert set(result[5].keys()) == {"escalate", "act", "hosts"}, result[5]


def test_group_counts_multiple_groups_all_zero_counts() -> None:
    """Gruppen ohne Findings haben escalate=0, act=0, hosts=N."""
    rows = [
        _make_row(group_id=10, server_count=4, escalate_count=0, act_count=0),
        _make_row(group_id=20, server_count=1, escalate_count=0, act_count=0),
    ]
    session = _make_session(rows)

    result = group_counts(session)

    assert len(result) == 2
    assert result[10] == {"escalate": 0, "act": 0, "hosts": 4}
    assert result[20] == {"escalate": 0, "act": 0, "hosts": 1}


def test_group_counts_only_null_group() -> None:
    """Nur ungrouped Server (alle group_id=None) — kein int-Key im Result."""
    rows = [
        _make_row(group_id=None, server_count=12, escalate_count=5, act_count=3),
    ]
    session = _make_session(rows)

    result = group_counts(session)

    assert list(result.keys()) == [None], f"Nur None-Key erwartet, got {list(result.keys())}"
    assert result[None]["hosts"] == 12
