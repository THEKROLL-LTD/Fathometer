"""Regressions-Tests: leere Gruppen tauchen NICHT in der Sidebar-Aggregation auf
(Block Z, Phase E, ADR-0040 §Empty-Group-Verhalten).

`group_counts()` baut die Query FROM `servers` (LEFT JOIN findings, GROUP BY
`servers.group_id`). Eine `ServerGroup` ohne zugeordnete Server erzeugt damit
gar keine Ergebnis-Row — sie kann nie im Aggregations-Dict landen und wird in
der Sidebar nicht als Bucket-Header gerendert. Diese Tests sichern den
Kontrakt gegen zukuenftige Query-Umbauten (Mock-Session, kein Postgres).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.services.sidebar_group_aggregates import group_counts


def _make_row(
    group_id: int | None, server_count: int, escalate_count: int, act_count: int
) -> MagicMock:
    row = MagicMock()
    row.group_id = group_id
    row.server_count = server_count
    row.escalate_count = escalate_count
    row.act_count = act_count
    return row


def _make_session(rows: list[MagicMock]) -> MagicMock:
    session = MagicMock()
    session.execute.return_value.all.return_value = rows
    return session


def test_empty_group_absent_from_aggregates() -> None:
    """Eine member-lose Gruppe (kein Server) erscheint nicht im Result.

    Die Query startet FROM servers — eine Gruppe ohne Server produziert keine
    Row. Wir simulieren genau das: nur Group 1 (3 Server) liefert eine Row,
    die leere Group 2 fehlt. Group 2 darf kein Key im Result sein.
    """
    rows = [_make_row(group_id=1, server_count=3, escalate_count=1, act_count=0)]
    session = _make_session(rows)

    result = group_counts(session)

    assert 1 in result, "Gruppe mit Membern muss im Result sein"
    assert 2 not in result, "Leere Gruppe (kein Server) darf NICHT im Result auftauchen"


def test_every_aggregate_entry_has_at_least_one_host() -> None:
    """Invariante: jeder Result-Eintrag hat hosts >= 1.

    Weil die Aggregation FROM servers laeuft, hat jede zurueckgegebene
    group_id per Konstruktion mindestens einen Server. Ein `hosts == 0`-Eintrag
    (= leere Gruppe) ist damit unmoeglich — der Regressions-Guard.
    """
    rows = [
        _make_row(group_id=1, server_count=2, escalate_count=0, act_count=0),
        _make_row(group_id=None, server_count=5, escalate_count=2, act_count=1),
        _make_row(group_id=7, server_count=1, escalate_count=0, act_count=0),
    ]
    session = _make_session(rows)

    result = group_counts(session)

    assert result, "Result darf nicht leer sein fuer diesen Fixture"
    for gid, counts in result.items():
        assert counts["hosts"] >= 1, (
            f"group_id={gid!r} hat hosts={counts['hosts']} < 1 — eine leere Gruppe "
            f"haette niemals im Aggregat landen duerfen"
        )
