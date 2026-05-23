"""Pure-Unit-Tests fuer `app.services.sidebar_risk_counts`.

Testet `escalate_act_counts_by_server` mit einer Mock-Session die
GROUP-BY-Row-Tuples zurueckliefert — kein DB-Roundtrip.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.services.sidebar_risk_counts import escalate_act_counts_by_server


def _make_session(rows: list[tuple[int, str, int]]) -> MagicMock:
    """Erstellt eine Mock-Session deren `.execute().all()` die uebergebenen Rows liefert.

    Jede Row ist ein (server_id, risk_band, n)-Tuple das via Attribut-Zugriff
    (`row.server_id`, `row.risk_band`, `row.n`) gelesen wird.
    """
    session = MagicMock()

    row_objects = []
    for server_id, risk_band, n in rows:
        row = MagicMock()
        row.server_id = server_id
        row.risk_band = risk_band
        row.n = n
        row_objects.append(row)

    session.execute.return_value.all.return_value = row_objects
    return session


# ---------------------------------------------------------------------------
# Leere server_ids — kein DB-Roundtrip
# ---------------------------------------------------------------------------


def test_empty_server_ids_returns_empty_dict_without_query() -> None:
    session = MagicMock()
    result = escalate_act_counts_by_server(session, [])
    assert result == {}
    session.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Mehrere Server mit gemischten Baendern
# ---------------------------------------------------------------------------


def test_mixed_bands_multiple_servers() -> None:
    """Drei Server: S1 hat escalate+act, S2 nur escalate, S3 nur act."""
    rows = [
        (1, "escalate", 5),
        (1, "act", 2),
        (2, "escalate", 3),
        (3, "act", 7),
    ]
    session = _make_session(rows)
    result = escalate_act_counts_by_server(session, [1, 2, 3])

    assert result[1] == {"escalate": 5, "act": 2}
    assert result[2] == {"escalate": 3}
    assert result[3] == {"act": 7}


def test_server_without_findings_not_in_result() -> None:
    """Server ohne OPEN-Findings in escalate/act taucht im Dict nicht auf."""
    rows: list[tuple[int, str, int]] = [
        (1, "escalate", 1),
    ]
    session = _make_session(rows)
    result = escalate_act_counts_by_server(session, [1, 99])

    assert 1 in result
    # Server 99 hat keine Findings — fehlt im Result
    assert 99 not in result
    # Aufrufer muss .get(99, {}) handhaben
    assert result.get(99, {}) == {}


# ---------------------------------------------------------------------------
# Nur ein Band gesetzt
# ---------------------------------------------------------------------------


def test_only_escalate_band_set() -> None:
    """Nur escalate-Findings, kein act — result hat nur 'escalate'-Key."""
    rows = [(7, "escalate", 10)]
    session = _make_session(rows)
    result = escalate_act_counts_by_server(session, [7])

    assert result[7] == {"escalate": 10}
    assert "act" not in result[7]


def test_only_act_band_set() -> None:
    """Nur act-Findings, kein escalate — result hat nur 'act'-Key."""
    rows = [(42, "act", 4)]
    session = _make_session(rows)
    result = escalate_act_counts_by_server(session, [42])

    assert result[42] == {"act": 4}
    assert "escalate" not in result[42]


# ---------------------------------------------------------------------------
# Session.execute wird genau einmal aufgerufen
# ---------------------------------------------------------------------------


def test_single_query_executed() -> None:
    """Die Funktion macht genau eine DB-Query."""
    rows = [(1, "escalate", 2)]
    session = _make_session(rows)
    escalate_act_counts_by_server(session, [1])
    session.execute.assert_called_once()


# ---------------------------------------------------------------------------
# alarm_count-Semantik — Hilfsfunktion analog zum View-Code testen
# ---------------------------------------------------------------------------


def test_alarm_count_derivable_from_result() -> None:
    """alarm_count = Anzahl Server mit escalate > 0 (View-Logik, nicht Service)."""
    rows = [
        (1, "escalate", 3),  # -> alarm
        (2, "act", 2),  # -> kein alarm (nur act)
        (3, "escalate", 1),  # -> alarm
    ]
    session = _make_session(rows)
    server_ids = [1, 2, 3]
    result = escalate_act_counts_by_server(session, server_ids)

    alarm_count = sum(1 for sid in server_ids if result.get(sid, {}).get("escalate", 0) > 0)
    assert alarm_count == 2
