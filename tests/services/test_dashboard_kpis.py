"""Pure-Unit-Tests fuer app/services/dashboard_kpis.py (Block W Phase D).

Deckt:
  * _load_action_needed_card_data: Band-Summen, Server-Count, hosts_total.
  * _load_nominal_card_data: monitor_count-Berechnung, Band-Summen.

Kein echter DB-Zugriff — Mock-Session mit Fake-Scalar-Returns.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.services.dashboard_kpis import (
    _load_action_needed_card_data,
    _load_nominal_card_data,
)

# ---------------------------------------------------------------------------
# Helper — Mock-Session die scalar() = N liefert (fuer hosts_total-Query).
# ---------------------------------------------------------------------------


def _mock_session_with_scalar(scalar_value: int) -> MagicMock:
    """Session deren execute().scalar() den uebergebenen Wert zurueckgibt."""
    sess = MagicMock()
    result = MagicMock()
    result.scalar.return_value = scalar_value
    sess.execute.return_value = result
    return sess


# ---------------------------------------------------------------------------
# _load_action_needed_card_data
# ---------------------------------------------------------------------------


def test_load_action_needed_card_data_basic() -> None:
    """Basisfall: definierte Server- und Finding-Counts -> korrekte Output-Keys.

    Setup:
      Server 1 (aktiv): escalate=3, act=1, pending=2 -> action-relevant
      Server 2 (aktiv): monitor=5, noise=2           -> nicht action-relevant
      hosts_total = 10 (aus DB-Query)
    """
    risk_bands_by_server = {
        1: {
            "escalate": 3,
            "act": 1,
            "pending": 2,
            "monitor": 0,
            "noise": 0,
            "unknown": 0,
            "mitigate": 0,
        },
        2: {
            "escalate": 0,
            "act": 0,
            "pending": 0,
            "monitor": 5,
            "noise": 2,
            "unknown": 0,
            "mitigate": 0,
        },
    }
    active_server_ids = {1, 2}
    sess = _mock_session_with_scalar(10)

    result = _load_action_needed_card_data(sess, risk_bands_by_server, active_server_ids)

    assert result["server_count"] == 1, (
        f"Erwartet server_count=1 (nur Server 1 hat action-Bands), erhalten: {result['server_count']}"
    )
    assert result["hosts_total"] == 10, (
        f"Erwartet hosts_total=10 (aus DB-Query), erhalten: {result['hosts_total']}"
    )
    assert result["escalate"] == 3, (
        f"Erwartet escalate=3 (nur Server 1), erhalten: {result['escalate']}"
    )
    assert result["act"] == 1, f"Erwartet act=1 (nur Server 1), erhalten: {result['act']}"
    assert result["pending"] == 2, (
        f"Erwartet pending=2 (nur Server 1), erhalten: {result['pending']}"
    )


def test_load_action_needed_card_data_multiple_action_servers() -> None:
    """Mehrere Server mit action-Bands werden korrekt summiert."""
    risk_bands_by_server = {
        1: {
            "escalate": 5,
            "act": 0,
            "pending": 0,
            "monitor": 0,
            "noise": 0,
            "unknown": 0,
            "mitigate": 0,
        },
        2: {
            "escalate": 2,
            "act": 3,
            "pending": 1,
            "monitor": 0,
            "noise": 0,
            "unknown": 0,
            "mitigate": 0,
        },
        3: {
            "escalate": 0,
            "act": 0,
            "pending": 0,
            "monitor": 4,
            "noise": 0,
            "unknown": 0,
            "mitigate": 0,
        },
    }
    active_server_ids = {1, 2, 3}
    sess = _mock_session_with_scalar(3)

    result = _load_action_needed_card_data(sess, risk_bands_by_server, active_server_ids)

    assert result["server_count"] == 2, (
        f"Erwartet server_count=2 (Server 1 + 2), erhalten: {result['server_count']}"
    )
    assert result["escalate"] == 7, f"Erwartet escalate=5+2=7, erhalten: {result['escalate']}"
    assert result["act"] == 3, f"Erwartet act=3, erhalten: {result['act']}"
    assert result["pending"] == 1, f"Erwartet pending=1, erhalten: {result['pending']}"


def test_load_action_needed_card_data_empty_db() -> None:
    """Leere DB: keine Server, keine Findings -> alle Counts 0, hosts_total 0."""
    sess = _mock_session_with_scalar(0)

    result = _load_action_needed_card_data(sess, {}, set())

    assert result["server_count"] == 0, (
        f"Erwartet server_count=0 bei leerer DB, erhalten: {result['server_count']}"
    )
    assert result["hosts_total"] == 0, (
        f"Erwartet hosts_total=0 bei leerer DB, erhalten: {result['hosts_total']}"
    )
    assert result["escalate"] == 0, f"Erwartet escalate=0, erhalten: {result['escalate']}"
    assert result["act"] == 0, f"Erwartet act=0, erhalten: {result['act']}"
    assert result["pending"] == 0, f"Erwartet pending=0, erhalten: {result['pending']}"


def test_load_action_needed_card_data_revoked_server_excluded() -> None:
    """Revoked Server (nicht in active_server_ids) darf nicht mitgezaehlt werden."""
    risk_bands_by_server = {
        1: {
            "escalate": 5,
            "act": 0,
            "pending": 0,
            "monitor": 0,
            "noise": 0,
            "unknown": 0,
            "mitigate": 0,
        },
        # Server 2 ist revoked — hat Findings in risk_bands_by_server aber nicht in active_server_ids.
        2: {
            "escalate": 3,
            "act": 2,
            "pending": 0,
            "monitor": 0,
            "noise": 0,
            "unknown": 0,
            "mitigate": 0,
        },
    }
    active_server_ids = {1}  # Server 2 ist revoked
    sess = _mock_session_with_scalar(1)

    result = _load_action_needed_card_data(sess, risk_bands_by_server, active_server_ids)

    assert result["server_count"] == 1, (
        f"Revoked Server 2 darf nicht mitgezaehlt werden, erwartet server_count=1, erhalten: {result['server_count']}"
    )
    assert result["escalate"] == 5, (
        f"Nur aktiver Server 1: escalate=5, erhalten: {result['escalate']}"
    )
    assert result["act"] == 0, f"Nur aktiver Server 1: act=0, erhalten: {result['act']}"


def test_load_action_needed_card_data_returns_expected_keys() -> None:
    """Output-Dict hat exakt die erwarteten Keys."""
    sess = _mock_session_with_scalar(5)
    result = _load_action_needed_card_data(sess, {}, set())

    expected_keys = {"server_count", "hosts_total", "escalate", "act", "pending"}
    assert set(result.keys()) == expected_keys, (
        f"Erwartete Keys: {expected_keys}, erhalten: {set(result.keys())}"
    )


# ---------------------------------------------------------------------------
# _load_nominal_card_data
# ---------------------------------------------------------------------------


def test_load_nominal_card_data_basic() -> None:
    """Basisfall: action_server_count=3, hosts_total=10 -> monitor_count=7."""
    risk_bands_by_server = {
        1: {
            "escalate": 0,
            "act": 0,
            "pending": 0,
            "monitor": 3,
            "noise": 1,
            "unknown": 2,
            "mitigate": 0,
        },
        2: {
            "escalate": 0,
            "act": 0,
            "pending": 0,
            "monitor": 2,
            "noise": 4,
            "unknown": 0,
            "mitigate": 0,
        },
    }
    active_server_ids = {1, 2}
    sess = MagicMock()  # _load_nominal_card_data macht keinen eigenen DB-Zugriff im Basispfad

    result = _load_nominal_card_data(
        sess,
        risk_bands_by_server,
        active_server_ids,
        hosts_total=10,
        action_server_count=3,
    )

    assert result["monitor_count"] == 7, (
        f"Erwartet monitor_count=10-3=7, erhalten: {result['monitor_count']}"
    )
    assert result["hosts_total"] == 10, (
        f"Erwartet hosts_total=10 (Durchreichung), erhalten: {result['hosts_total']}"
    )
    assert result["monitor"] == 5, f"Erwartet monitor=3+2=5, erhalten: {result['monitor']}"
    assert result["noise"] == 5, f"Erwartet noise=1+4=5, erhalten: {result['noise']}"
    assert result["unknown"] == 2, f"Erwartet unknown=2, erhalten: {result['unknown']}"


def test_load_nominal_card_data_handles_zero_hosts() -> None:
    """hosts_total=0 -> monitor_count=0 (kein negativer Wert via max(0,...))."""
    sess = MagicMock()

    result = _load_nominal_card_data(
        sess,
        risk_bands_by_server={},
        active_server_ids=set(),
        hosts_total=0,
        action_server_count=0,
    )

    assert result["monitor_count"] == 0, (
        f"Erwartet monitor_count=0 bei hosts_total=0, erhalten: {result['monitor_count']}"
    )
    assert result["hosts_total"] == 0, f"Erwartet hosts_total=0, erhalten: {result['hosts_total']}"


def test_load_nominal_card_data_monitor_count_never_negative() -> None:
    """monitor_count ist nie negativ (action_server_count > hosts_total Edge-Case)."""
    sess = MagicMock()

    # Pathologischer Fall: action_server_count > hosts_total
    result = _load_nominal_card_data(
        sess,
        risk_bands_by_server={},
        active_server_ids=set(),
        hosts_total=2,
        action_server_count=5,
    )

    assert result["monitor_count"] == 0, (
        f"monitor_count darf nicht negativ sein, erwartet 0, erhalten: {result['monitor_count']}"
    )


def test_load_nominal_card_data_empty_risk_bands() -> None:
    """Keine Findings -> monitor/noise/unknown alle 0."""
    sess = MagicMock()

    result = _load_nominal_card_data(
        sess,
        risk_bands_by_server={},
        active_server_ids={1, 2},
        hosts_total=5,
        action_server_count=2,
    )

    assert result["monitor"] == 0, f"Erwartet monitor=0, erhalten: {result['monitor']}"
    assert result["noise"] == 0, f"Erwartet noise=0, erhalten: {result['noise']}"
    assert result["unknown"] == 0, f"Erwartet unknown=0, erhalten: {result['unknown']}"
    assert result["monitor_count"] == 3, (
        f"Erwartet monitor_count=5-2=3, erhalten: {result['monitor_count']}"
    )


def test_load_nominal_card_data_returns_expected_keys() -> None:
    """Output-Dict hat exakt die erwarteten Keys."""
    sess = MagicMock()
    result = _load_nominal_card_data(
        sess,
        risk_bands_by_server={},
        active_server_ids=set(),
        hosts_total=0,
        action_server_count=0,
    )

    expected_keys = {"monitor_count", "hosts_total", "monitor", "noise", "unknown"}
    assert set(result.keys()) == expected_keys, (
        f"Erwartete Keys: {expected_keys}, erhalten: {set(result.keys())}"
    )


# ---------------------------------------------------------------------------
# _load_triage_counts — Phase E
# ---------------------------------------------------------------------------


def _mock_session_with_rows(rows: list) -> MagicMock:
    """Session deren execute().all() die uebergebenen Zeilen zurueckgibt."""
    sess = MagicMock()
    result = MagicMock()
    result.all.return_value = rows
    sess.execute.return_value = result
    return sess


def _make_triage_row(risk_band: str | None, cnt: int) -> MagicMock:
    """Fake-DB-Row mit .risk_band und .cnt Attributen."""
    row = MagicMock()
    row.risk_band = risk_band
    row.cnt = cnt
    return row


def test_load_triage_counts_standalone_mode_returns_7_buckets() -> None:
    """Standalone-Modus: DB liefert Rows -> output hat genau die 7 Design-Buckets.

    Reihenfolge muss escalate, act, mitigate, pending, monitor, noise, unknown sein.
    """
    from app.services.dashboard_kpis import _load_triage_counts

    rows = [
        _make_triage_row("escalate", 3),
        _make_triage_row("act", 1),
        _make_triage_row("mitigate", 5),
        _make_triage_row("pending", 2),
        _make_triage_row("monitor", 7),
        _make_triage_row("noise", 4),
        _make_triage_row("unknown", 0),
    ]
    sess = _mock_session_with_rows(rows)

    result = _load_triage_counts(sess)

    expected_keys = ("escalate", "act", "mitigate", "pending", "monitor", "noise", "unknown")
    assert list(result.keys()) == list(expected_keys), (
        f"Erwartete Reihenfolge: {list(expected_keys)}, erhalten: {list(result.keys())}"
    )
    assert result["escalate"] == 3, f"Erwartet escalate=3, erhalten: {result['escalate']}"
    assert result["act"] == 1, f"Erwartet act=1, erhalten: {result['act']}"
    assert result["mitigate"] == 5, f"Erwartet mitigate=5, erhalten: {result['mitigate']}"
    assert result["monitor"] == 7, f"Erwartet monitor=7, erhalten: {result['monitor']}"


def test_load_triage_counts_missing_bands_default_to_zero() -> None:
    """Standalone: DB liefert nur escalate=5 -> alle anderen Buckets sind 0."""
    from app.services.dashboard_kpis import _load_triage_counts

    rows = [_make_triage_row("escalate", 5)]
    sess = _mock_session_with_rows(rows)

    result = _load_triage_counts(sess)

    assert result["escalate"] == 5, f"Erwartet escalate=5, erhalten: {result['escalate']}"
    assert result["act"] == 0, f"Erwartet act=0 (fehlend -> default 0), erhalten: {result['act']}"
    assert result["mitigate"] == 0, f"Erwartet mitigate=0, erhalten: {result['mitigate']}"
    assert result["pending"] == 0, f"Erwartet pending=0, erhalten: {result['pending']}"
    assert result["monitor"] == 0, f"Erwartet monitor=0, erhalten: {result['monitor']}"
    assert result["noise"] == 0, f"Erwartet noise=0, erhalten: {result['noise']}"
    assert result["unknown"] == 0, f"Erwartet unknown=0, erhalten: {result['unknown']}"


def test_load_triage_counts_unknown_risk_band_falls_in_unknown_bucket() -> None:
    """Standalone: risk_band=None oder unbekannter String -> landet in 'unknown'."""
    from app.services.dashboard_kpis import _load_triage_counts

    # None-Band: kein kanonischer Bucket-Name -> unknown
    rows_none = [_make_triage_row(None, 8)]
    sess_none = _mock_session_with_rows(rows_none)
    result_none = _load_triage_counts(sess_none)

    assert result_none["unknown"] == 8, (
        f"risk_band=None muss in 'unknown'-Bucket fallen, erhalten: {result_none['unknown']}"
    )
    assert result_none["escalate"] == 0, (
        f"escalate muss 0 sein wenn nur None-Band vorliegt, erhalten: {result_none['escalate']}"
    )

    # Unbekannter String-Band -> ebenfalls unknown
    rows_unknown = [_make_triage_row("future_band_xyz", 3)]
    sess_unknown = _mock_session_with_rows(rows_unknown)
    result_unknown = _load_triage_counts(sess_unknown)

    assert result_unknown["unknown"] == 3, (
        f"Unbekannter Band 'future_band_xyz' muss in 'unknown' landen, "
        f"erhalten: {result_unknown['unknown']}"
    )


def test_load_triage_counts_derived_mode_no_db_call() -> None:
    """Abgeleiteter Modus (risk_bands_by_server gesetzt) -> DB wird NICHT aufgerufen."""
    from app.services.dashboard_kpis import _load_triage_counts

    risk_bands_by_server = {
        1: {
            "escalate": 2,
            "act": 1,
            "mitigate": 0,
            "pending": 3,
            "monitor": 0,
            "noise": 0,
            "unknown": 0,
        },
        2: {
            "escalate": 1,
            "act": 0,
            "mitigate": 4,
            "pending": 0,
            "monitor": 5,
            "noise": 2,
            "unknown": 1,
        },
    }
    active_server_ids = {1, 2}
    sess = MagicMock()  # Kein execute() erwartet

    result = _load_triage_counts(
        sess,
        risk_bands_by_server=risk_bands_by_server,
        active_server_ids=active_server_ids,
    )

    (
        sess.execute.assert_not_called(),
        "execute() wurde aufgerufen obwohl risk_bands_by_server gesetzt war",
    )

    # Korrekte Summierung aus den Pro-Server-Aggregaten.
    assert result["escalate"] == 3, f"escalate: 2+1=3, erhalten: {result['escalate']}"
    assert result["act"] == 1, f"act: 1+0=1, erhalten: {result['act']}"
    assert result["mitigate"] == 4, f"mitigate: 0+4=4, erhalten: {result['mitigate']}"
    assert result["pending"] == 3, f"pending: 3+0=3, erhalten: {result['pending']}"
    assert result["monitor"] == 5, f"monitor: 0+5=5, erhalten: {result['monitor']}"
    assert result["noise"] == 2, f"noise: 0+2=2, erhalten: {result['noise']}"
    assert result["unknown"] == 1, f"unknown: 0+1=1, erhalten: {result['unknown']}"


# ---------------------------------------------------------------------------
# _load_severity_counts — Phase E
# ---------------------------------------------------------------------------


def _make_severity_row(severity: str | None, cnt: int) -> MagicMock:
    """Fake-DB-Row mit .severity und .cnt Attributen."""
    row = MagicMock()
    row.severity = severity
    row.cnt = cnt
    return row


def test_load_severity_counts_basic() -> None:
    """Basisfall: DB liefert critical=5, high=3 -> output hat critical=5, high=3, medium=0, low=0, max_count=5."""
    from app.services.dashboard_kpis import _load_severity_counts

    rows = [
        _make_severity_row("critical", 5),
        _make_severity_row("high", 3),
    ]
    sess = _mock_session_with_rows(rows)

    result = _load_severity_counts(sess)

    assert result["critical"] == 5, f"Erwartet critical=5, erhalten: {result['critical']}"
    assert result["high"] == 3, f"Erwartet high=3, erhalten: {result['high']}"
    assert result["medium"] == 0, f"Erwartet medium=0 (fehlend -> 0), erhalten: {result['medium']}"
    assert result["low"] == 0, f"Erwartet low=0 (fehlend -> 0), erhalten: {result['low']}"
    assert result["max_count"] == 5, (
        f"Erwartet max_count=5 (max von critical=5), erhalten: {result['max_count']}"
    )


def test_load_severity_counts_all_zero_max_count_is_1() -> None:
    """Leere DB (alle Counts 0) -> max_count=1 (Schutz gegen Division-by-Zero im Template)."""
    from app.services.dashboard_kpis import _load_severity_counts

    sess = _mock_session_with_rows([])  # Keine Findings

    result = _load_severity_counts(sess)

    assert result["critical"] == 0, f"Erwartet critical=0, erhalten: {result['critical']}"
    assert result["high"] == 0, f"Erwartet high=0, erhalten: {result['high']}"
    assert result["medium"] == 0, f"Erwartet medium=0, erhalten: {result['medium']}"
    assert result["low"] == 0, f"Erwartet low=0, erhalten: {result['low']}"
    assert result["max_count"] == 1, (
        f"Erwartet max_count=1 bei allen-null (Division-by-Zero-Schutz), "
        f"erhalten: {result['max_count']}"
    )


def test_load_severity_counts_returns_5_keys() -> None:
    """Output-Dict hat exakt die erwarteten 5 Keys: critical, high, medium, low, max_count."""
    from app.services.dashboard_kpis import _load_severity_counts

    sess = _mock_session_with_rows([])

    result = _load_severity_counts(sess)

    expected_keys = {"critical", "high", "medium", "low", "max_count"}
    assert set(result.keys()) == expected_keys, (
        f"Erwartete Keys: {expected_keys}, erhalten: {set(result.keys())}"
    )
