"""Pure-Unit-Tests fuer Block-W-Phase-D-Context-Keys in `app/views/dashboard.py`.

Prueft:
  - `_build_pane_context` liefert `action_needed_card_data`-Key.
  - `_build_pane_context` liefert `nominal_card_data`-Key.
  - `action_needed_card_data` hat die erwarteten Keys.
  - `nominal_card_data` hat die erwarteten Keys.

Kein echter DB-Zugriff — Mock-Session mit Fake-Result-Sets.
Nutzt dasselbe Mock-Pattern wie test_dashboard_phase_d.py.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

from app.views.dashboard import _build_pane_context

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_row(**kwargs: int | str) -> Any:
    """Einfacher Namespace der Attribut-Zugriffe auf kwargs weiterleitet."""
    obj = MagicMock()
    for key, value in kwargs.items():
        setattr(obj, key, value)
    return obj


def _build_mock_session_for_pane_context(
    *,
    hosts_total: int = 5,
    risk_bands_by_server: dict | None = None,
) -> MagicMock:
    """Baut eine Mock-Session die alle Queries in _build_pane_context bedient.

    _build_pane_context ruft folgende Queries auf:
      1. _load_servers  -> scalars().unique().all() -> []
      2. _load_open_aggregates -> .all()            -> [] (Aggregat-Rows)
      3. _load_risk_kpi_counters:
           a. Findings-Row  -> .one()               -> _make_row(...)
           b. active-Server -> .scalar()            -> hosts_total
      4. _load_action_needed_card_data:
           hosts_total-Query -> .scalar()           -> hosts_total

    Wir simulieren alle execute()-Calls in der richtigen Reihenfolge via side_effect.
    """
    # Findings-Row fuer _load_risk_kpi_counters (alle Counts 0).
    findings_row = _make_row(
        rb_escalate=0,
        rb_act=0,
        rb_mitigate=0,
        rb_pending=0,
        rb_unknown=0,
        rb_monitor=0,
        rb_noise=0,
        sev_critical=0,
        sev_high=0,
        sev_medium=0,
        sev_low=0,
    )

    # Result fuer _load_servers (scalars().unique().all() -> leere Liste).
    server_result = MagicMock()
    server_result.scalars.return_value.unique.return_value.all.return_value = []

    # Result fuer _load_open_aggregates (.all() -> leere Liste).
    aggregates_result = MagicMock()
    aggregates_result.all.return_value = []

    # Result fuer _load_risk_kpi_counters Findings-Query (.one() -> findings_row).
    findings_result = MagicMock()
    findings_result.one.return_value = findings_row

    # Result fuer aktive-Server-Count in _load_risk_kpi_counters (.scalar() -> hosts_total).
    active_count_result = MagicMock()
    active_count_result.scalar.return_value = hosts_total

    # Result fuer hosts_total in _load_action_needed_card_data (.scalar() -> hosts_total).
    action_hosts_result = MagicMock()
    action_hosts_result.scalar.return_value = hosts_total

    sess = MagicMock()
    sess.execute.side_effect = [
        server_result,  # _load_servers
        aggregates_result,  # _load_open_aggregates
        findings_result,  # _load_risk_kpi_counters: Findings-Query
        active_count_result,  # _load_risk_kpi_counters: aktive-Server-Count
        action_hosts_result,  # _load_action_needed_card_data: hosts_total
    ]
    return sess


def _now() -> datetime:
    return datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_build_pane_context_includes_action_needed_card_data_key() -> None:
    """_build_pane_context liefert 'action_needed_card_data' im Context-Dict."""
    from app.schemas.dashboard_filter import DashboardFilter

    sess = _build_mock_session_for_pane_context()
    filt = DashboardFilter()

    ctx = _build_pane_context(sess, filt, _now())

    assert "action_needed_card_data" in ctx, (
        f"Key 'action_needed_card_data' fehlt im Context-Dict. Vorhandene Keys: {list(ctx.keys())}"
    )
    assert isinstance(ctx["action_needed_card_data"], dict), (
        f"action_needed_card_data soll ein dict sein, ist: {type(ctx['action_needed_card_data'])}"
    )


def test_build_pane_context_includes_nominal_card_data_key() -> None:
    """_build_pane_context liefert 'nominal_card_data' im Context-Dict."""
    from app.schemas.dashboard_filter import DashboardFilter

    sess = _build_mock_session_for_pane_context()
    filt = DashboardFilter()

    ctx = _build_pane_context(sess, filt, _now())

    assert "nominal_card_data" in ctx, (
        f"Key 'nominal_card_data' fehlt im Context-Dict. Vorhandene Keys: {list(ctx.keys())}"
    )
    assert isinstance(ctx["nominal_card_data"], dict), (
        f"nominal_card_data soll ein dict sein, ist: {type(ctx['nominal_card_data'])}"
    )


def test_action_needed_card_data_has_expected_keys() -> None:
    """action_needed_card_data enthaelt exakt die erwarteten Keys.

    Erwartet: server_count, hosts_total, escalate, act, pending.
    """
    from app.schemas.dashboard_filter import DashboardFilter

    sess = _build_mock_session_for_pane_context()
    filt = DashboardFilter()

    ctx = _build_pane_context(sess, filt, _now())

    card_data = ctx["action_needed_card_data"]
    expected_keys = {"server_count", "hosts_total", "escalate", "act", "pending"}

    assert set(card_data.keys()) == expected_keys, (
        f"action_needed_card_data hat falsche Keys.\n"
        f"Erwartet: {expected_keys}\n"
        f"Erhalten:  {set(card_data.keys())}"
    )


def test_nominal_card_data_has_expected_keys() -> None:
    """nominal_card_data enthaelt exakt die erwarteten Keys.

    Erwartet: monitor_count, hosts_total, monitor, noise, unknown.
    """
    from app.schemas.dashboard_filter import DashboardFilter

    sess = _build_mock_session_for_pane_context()
    filt = DashboardFilter()

    ctx = _build_pane_context(sess, filt, _now())

    card_data = ctx["nominal_card_data"]
    expected_keys = {"monitor_count", "hosts_total", "monitor", "noise", "unknown"}

    assert set(card_data.keys()) == expected_keys, (
        f"nominal_card_data hat falsche Keys.\n"
        f"Erwartet: {expected_keys}\n"
        f"Erhalten:  {set(card_data.keys())}"
    )


def test_action_needed_card_data_values_are_ints() -> None:
    """Alle Werte in action_needed_card_data sind Integers."""
    from app.schemas.dashboard_filter import DashboardFilter

    sess = _build_mock_session_for_pane_context(hosts_total=7)
    filt = DashboardFilter()

    ctx = _build_pane_context(sess, filt, _now())

    card_data = ctx["action_needed_card_data"]
    for key, value in card_data.items():
        assert isinstance(value, int), (
            f"action_needed_card_data['{key}'] soll int sein, ist {type(value)}: {value!r}"
        )


def test_nominal_card_data_values_are_ints() -> None:
    """Alle Werte in nominal_card_data sind Integers."""
    from app.schemas.dashboard_filter import DashboardFilter

    sess = _build_mock_session_for_pane_context(hosts_total=7)
    filt = DashboardFilter()

    ctx = _build_pane_context(sess, filt, _now())

    card_data = ctx["nominal_card_data"]
    for key, value in card_data.items():
        assert isinstance(value, int), (
            f"nominal_card_data['{key}'] soll int sein, ist {type(value)}: {value!r}"
        )


def test_nominal_card_data_hosts_total_matches_action_card() -> None:
    """nominal_card_data.hosts_total stimmt mit action_needed_card_data.hosts_total ueberein.

    Beide Cards zeigen denselben Fleet-Gesamtwert — er wird einmalig berechnet
    und an _load_nominal_card_data weitergereicht.
    """
    from app.schemas.dashboard_filter import DashboardFilter

    sess = _build_mock_session_for_pane_context(hosts_total=12)
    filt = DashboardFilter()

    ctx = _build_pane_context(sess, filt, _now())

    action_total = ctx["action_needed_card_data"]["hosts_total"]
    nominal_total = ctx["nominal_card_data"]["hosts_total"]

    assert action_total == nominal_total, (
        f"hosts_total muss in beiden Cards identisch sein. "
        f"action_needed_card_data.hosts_total={action_total}, "
        f"nominal_card_data.hosts_total={nominal_total}"
    )


def test_context_still_has_risk_kpis_key() -> None:
    """risk_kpis-Key bleibt im Context fuer Rueckwaerts-Kompat mit alten Tests."""
    from app.schemas.dashboard_filter import DashboardFilter

    sess = _build_mock_session_for_pane_context()
    filt = DashboardFilter()

    ctx = _build_pane_context(sess, filt, _now())

    assert "risk_kpis" in ctx, (
        "Key 'risk_kpis' fehlt — wird noch fuer Rueckwaerts-Kompat behalten "
        f"(Kommentar in dashboard.py). Vorhandene Keys: {list(ctx.keys())}"
    )
