"""Drift-Regression: Initial-Render vs. OOB-Batch-Render (TICKET-005 Schritt 1).

Schuetzt das Single-Source-Partial-Pattern aus CLAUDE.md §HTMX-OOB-Single-
Source-Pattern: beide Pfade muessen strukturell identisches Markup erzeugen.
"""

from __future__ import annotations

import re
from datetime import date, timedelta
from unittest.mock import MagicMock

from flask import Flask, render_template

# ---------------------------------------------------------------------------
# Helper — keine `.value`-Mocks (Defekt 1 aus TICKET-005). `dominant_risk_band`
# ist `str | None`, kein Enum.
# ---------------------------------------------------------------------------

BASE_DATE = date(2026, 5, 24)

# 4 Mapping-Klassen ueber 30 Cells verteilen — escalate, act, monitor, None.
_BAND_CYCLE: tuple[str | None, ...] = ("escalate", "act", "monitor", None)


def _make_cell(
    day: date, dominant_risk_band: str | None = None, had_scan: bool = True
) -> MagicMock:
    """Minimal-Mock eines DailyStatus-Objekts (str | None, kein Enum)."""
    cell = MagicMock()
    cell.day = day
    cell.had_scan = had_scan
    cell.dominant_risk_band = dominant_risk_band
    return cell


def _make_server(server_id: int) -> MagicMock:
    """Minimal-Mock eines Server-Objekts.

    Liest Felder die `_server_row.html` benoetigt: id, name, os, kernel,
    arch, tag_links (Liste mit .tag.name).
    """
    srv = MagicMock()
    srv.id = server_id
    srv.name = f"host-{server_id}"
    srv.os = "ubuntu"
    srv.kernel = "6.8.0"
    srv.arch = "x86_64"
    srv.group_id = None
    srv.tag_links = []
    return srv


def _make_30_cells(server_id: int) -> list[MagicMock]:
    """30 Cells mit verteilten Bands + abwechselndem had_scan."""
    cells: list[MagicMock] = []
    for i in range(30):
        day = BASE_DATE - timedelta(days=29 - i)
        band = _BAND_CYCLE[(i + server_id) % len(_BAND_CYCLE)]
        had_scan = (i % 3) != 0  # gemischt
        cells.append(_make_cell(day, dominant_risk_band=band, had_scan=had_scan))
    return cells


def _render_initial(
    app: Flask, server: MagicMock, cells: list[MagicMock], risk: dict[str, int]
) -> str:
    """Initial-Render via `sidebar/_server_row.html`."""
    with app.test_request_context("/"):
        return render_template(
            "sidebar/_server_row.html",
            server=server,
            cells=cells,
            risk=risk,
            is_active=False,
        )


def _render_oob(
    app: Flask,
    servers: list[MagicMock],
    heartbeats: dict[int, list[MagicMock]],
    risk_counts: dict[int, dict[str, int]],
) -> str:
    """OOB-Render via `_partials/sidebar_batch_oob.html`."""
    with app.test_request_context("/"):
        return render_template(
            "_partials/sidebar_batch_oob.html",
            batch_servers=servers,
            batch_heartbeats=heartbeats,
            batch_risk_counts=risk_counts,
        )


# ---------------------------------------------------------------------------
# Drift-Asserts
# ---------------------------------------------------------------------------


def test_drift_heartbeat_id_present_in_both_paths(app: Flask) -> None:
    """ID `sidebar-host-{N}-heartbeat` existiert in Initial- und OOB-Pfad."""
    server_a = _make_server(7)
    server_b = _make_server(42)
    cells_a = _make_30_cells(7)
    cells_b = _make_30_cells(42)
    risk_a = {"escalate": 4, "act": 1}
    risk_b = {"escalate": 0, "act": 2}

    initial_a = _render_initial(app, server_a, cells_a, risk_a)
    initial_b = _render_initial(app, server_b, cells_b, risk_b)
    oob = _render_oob(
        app,
        [server_a, server_b],
        {7: cells_a, 42: cells_b},
        {7: risk_a, 42: risk_b},
    )

    assert 'id="sidebar-host-7-heartbeat"' in initial_a, (
        f"Initial-Pfad fehlt Heartbeat-Anker fuer Server 7: {initial_a[:500]}"
    )
    assert 'id="sidebar-host-42-heartbeat"' in initial_b, (
        f"Initial-Pfad fehlt Heartbeat-Anker fuer Server 42: {initial_b[:500]}"
    )
    assert 'id="sidebar-host-7-heartbeat"' in oob, (
        f"OOB-Pfad fehlt Heartbeat-Anker fuer Server 7: {oob[:500]}"
    )
    assert 'id="sidebar-host-42-heartbeat"' in oob, (
        f"OOB-Pfad fehlt Heartbeat-Anker fuer Server 42: {oob[:500]}"
    )


def test_drift_counts_id_present_in_both_paths(app: Flask) -> None:
    """ID `sidebar-host-{N}-counts` existiert in Initial- und OOB-Pfad."""
    server_a = _make_server(7)
    server_b = _make_server(42)
    cells_a = _make_30_cells(7)
    cells_b = _make_30_cells(42)
    risk_a = {"escalate": 4, "act": 1}
    risk_b = {"escalate": 0, "act": 2}

    initial_a = _render_initial(app, server_a, cells_a, risk_a)
    initial_b = _render_initial(app, server_b, cells_b, risk_b)
    oob = _render_oob(
        app,
        [server_a, server_b],
        {7: cells_a, 42: cells_b},
        {7: risk_a, 42: risk_b},
    )

    assert 'id="sidebar-host-7-counts"' in initial_a, (
        f"Initial-Pfad fehlt Counts-Anker fuer Server 7: {initial_a[:500]}"
    )
    assert 'id="sidebar-host-42-counts"' in initial_b, (
        f"Initial-Pfad fehlt Counts-Anker fuer Server 42: {initial_b[:500]}"
    )
    assert 'id="sidebar-host-7-counts"' in oob, (
        f"OOB-Pfad fehlt Counts-Anker fuer Server 7: {oob[:500]}"
    )
    assert 'id="sidebar-host-42-counts"' in oob, (
        f"OOB-Pfad fehlt Counts-Anker fuer Server 42: {oob[:500]}"
    )


def test_drift_exactly_30_ticks_per_server_in_both_paths(app: Flask) -> None:
    """Beide Pfade rendern genau 30 `host__beat-tick` pro Server."""
    server_a = _make_server(7)
    server_b = _make_server(42)
    cells_a = _make_30_cells(7)
    cells_b = _make_30_cells(42)
    risk_a = {"escalate": 4, "act": 1}
    risk_b = {"escalate": 0, "act": 2}

    initial_a = _render_initial(app, server_a, cells_a, risk_a)
    initial_b = _render_initial(app, server_b, cells_b, risk_b)
    oob = _render_oob(
        app,
        [server_a, server_b],
        {7: cells_a, 42: cells_b},
        {7: risk_a, 42: risk_b},
    )

    # Initial: 30 pro Server
    assert initial_a.count("host__beat-tick") == 30, (
        f"Initial-A: 30 Ticks erwartet, got {initial_a.count('host__beat-tick')}"
    )
    assert initial_b.count("host__beat-tick") == 30, (
        f"Initial-B: 30 Ticks erwartet, got {initial_b.count('host__beat-tick')}"
    )
    # OOB enthaelt beide Server: 60 Ticks gesamt
    assert oob.count("host__beat-tick") == 60, (
        f"OOB: 60 Ticks erwartet (2x30), got {oob.count('host__beat-tick')}"
    )


def test_drift_no_old_host_beat_cell_schema_anywhere(app: Flask) -> None:
    """Altes `host__beat__cell`-Klassen-Schema darf in keinem Pfad vorkommen."""
    server = _make_server(7)
    cells = _make_30_cells(7)
    risk = {"escalate": 4, "act": 1}

    initial = _render_initial(app, server, cells, risk)
    oob = _render_oob(app, [server], {7: cells}, {7: risk})

    assert "host__beat__cell" not in initial, (
        f"Initial-Pfad enthaelt totes Klassen-Schema host__beat__cell: {initial[:500]}"
    )
    assert "host__beat__cell" not in oob, (
        f"OOB-Pfad enthaelt totes Klassen-Schema host__beat__cell: {oob[:500]}"
    )


def test_drift_data_day_values_identical_between_paths(app: Flask) -> None:
    """`data-day`-Reihenfolge und -Werte sind im Initial- und OOB-Pfad gleich."""
    server = _make_server(7)
    cells = _make_30_cells(7)
    risk = {"escalate": 4, "act": 1}

    initial = _render_initial(app, server, cells, risk)
    oob = _render_oob(app, [server], {7: cells}, {7: risk})

    pattern = re.compile(r'data-day="([^"]+)"')
    initial_days = pattern.findall(initial)
    oob_days = pattern.findall(oob)

    assert len(initial_days) == 30, f"Initial: 30 data-day erwartet, got {len(initial_days)}"
    assert len(oob_days) == 30, f"OOB: 30 data-day erwartet, got {len(oob_days)}"
    assert initial_days == oob_days, (
        f"data-day-Reihenfolge driftet:\n initial={initial_days}\n oob={oob_days}"
    )


def test_drift_oob_path_has_hx_swap_oob_initial_does_not(app: Flask) -> None:
    """OOB-Pfad hat `hx-swap-oob`-Attribute auf beiden Anker-IDs, Initial nicht."""
    server = _make_server(7)
    cells = _make_30_cells(7)
    risk = {"escalate": 4, "act": 1}

    initial = _render_initial(app, server, cells, risk)
    oob = _render_oob(app, [server], {7: cells}, {7: risk})

    # OOB-Pfad: beide Targets vorhanden
    assert 'hx-swap-oob="outerHTML:#sidebar-host-7-heartbeat"' in oob, (
        f"OOB fehlt Heartbeat-Swap-Attribut: {oob[:500]}"
    )
    assert 'hx-swap-oob="outerHTML:#sidebar-host-7-counts"' in oob, (
        f"OOB fehlt Counts-Swap-Attribut: {oob[:500]}"
    )

    # Initial-Pfad: kein hx-swap-oob ueberhaupt
    assert "hx-swap-oob" not in initial, (
        f"Initial-Pfad darf KEIN hx-swap-oob enthalten: {initial[:500]}"
    )


def test_drift_only_beat_tick_schema_used_in_both_paths(app: Flask) -> None:
    """Beide Pfade verwenden ausschliesslich `host__beat-tick beat--*`."""
    server = _make_server(7)
    cells = _make_30_cells(7)
    risk = {"escalate": 4, "act": 1}

    initial = _render_initial(app, server, cells, risk)
    oob = _render_oob(app, [server], {7: cells}, {7: risk})

    # Mindestens eine der 4 Klassen muss vorkommen (Cells haben echte Bands)
    for path_name, html in [("initial", initial), ("oob", oob)]:
        present = [
            cls for cls in ("beat--alarm", "beat--warn", "beat--ok", "beat--unknown") if cls in html
        ]
        assert present, f"{path_name}-Pfad enthaelt keine beat--* Klasse: {html[:500]}"
