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
