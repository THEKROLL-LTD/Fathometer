"""ID-Anker und OOB-Conditional-Flag fuer Heartbeat- und Counts-Partial.

Schuetzt CLAUDE.md §HTMX-OOB-Single-Source-Pattern Punkt 2 (ID-Konvention):
- Initial-Render setzt die IDs immer.
- OOB-Render zusaetzlich `hx-swap-oob="outerHTML:#<id>"`.
- Skeleton-Pfad traegt die ID ebenfalls (damit der erste OOB-Swap-Zyklus trifft).
"""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock

from flask import Flask, render_template


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
    srv = MagicMock()
    srv.id = server_id
    return srv


# ---------------------------------------------------------------------------
# Heartbeat-Bar: ID + Conditional OOB-Attribut
# ---------------------------------------------------------------------------


def test_heartbeat_initial_render_has_id_and_no_oob(app: Flask) -> None:
    """`_heartbeat_bar.html` mit `oob_swap=false` hat ID und KEIN hx-swap-oob."""
    server = _make_server(42)
    cells = [_make_cell(date(2026, 5, 24), dominant_risk_band="escalate")]
    with app.test_request_context("/"):
        html = render_template(
            "sidebar/_heartbeat_bar.html",
            server=server,
            cells=cells,
            oob_swap=False,
        )

    assert 'id="sidebar-host-42-heartbeat"' in html, (
        f"Initial-Heartbeat fehlt ID-Anker: {html[:500]}"
    )
    assert "hx-swap-oob" not in html, f"Initial-Heartbeat darf KEIN hx-swap-oob haben: {html[:500]}"


def test_heartbeat_oob_render_has_id_and_swap_attribute(app: Flask) -> None:
    """`_heartbeat_bar.html` mit `oob_swap=true` hat ID und das Swap-Attribut."""
    server = _make_server(42)
    cells = [_make_cell(date(2026, 5, 24), dominant_risk_band="escalate")]
    with app.test_request_context("/"):
        html = render_template(
            "sidebar/_heartbeat_bar.html",
            server=server,
            cells=cells,
            oob_swap=True,
        )

    assert 'id="sidebar-host-42-heartbeat"' in html, f"OOB-Heartbeat fehlt ID-Anker: {html[:500]}"
    assert 'hx-swap-oob="outerHTML:#sidebar-host-42-heartbeat"' in html, (
        f"OOB-Heartbeat fehlt Swap-Attribut: {html[:500]}"
    )


def test_heartbeat_skeleton_path_has_id_anchor(app: Flask) -> None:
    """Skeleton-Pfad (cells=[]) traegt die Anker-ID — erster OOB-Swap muss treffen."""
    server = _make_server(42)
    with app.test_request_context("/"):
        html = render_template(
            "sidebar/_heartbeat_bar.html",
            server=server,
            cells=[],
            oob_swap=False,
        )

    assert 'id="sidebar-host-42-heartbeat"' in html, (
        f"Skeleton-Heartbeat fehlt ID-Anker (erster OOB-Swap wuerde verpuffen): {html[:500]}"
    )


# ---------------------------------------------------------------------------
# Counts-Partial: ID + Conditional OOB-Attribut
# ---------------------------------------------------------------------------


def test_counts_initial_render_has_id_and_no_oob(app: Flask) -> None:
    """`_counts.html` mit `oob_swap=false` hat ID und KEIN hx-swap-oob."""
    server = _make_server(42)
    risk = {"escalate": 3, "act": 1}
    with app.test_request_context("/"):
        html = render_template(
            "sidebar/_counts.html",
            server=server,
            risk=risk,
            is_loading=False,
            oob_swap=False,
        )

    assert 'id="sidebar-host-42-counts"' in html, f"Initial-Counts fehlt ID-Anker: {html[:500]}"
    assert "hx-swap-oob" not in html, f"Initial-Counts darf KEIN hx-swap-oob haben: {html[:500]}"


def test_counts_oob_render_has_id_and_swap_attribute(app: Flask) -> None:
    """`_counts.html` mit `oob_swap=true` hat ID und das Swap-Attribut."""
    server = _make_server(42)
    risk = {"escalate": 3, "act": 1}
    with app.test_request_context("/"):
        html = render_template(
            "sidebar/_counts.html",
            server=server,
            risk=risk,
            is_loading=False,
            oob_swap=True,
        )

    assert 'id="sidebar-host-42-counts"' in html, f"OOB-Counts fehlt ID-Anker: {html[:500]}"
    assert 'hx-swap-oob="outerHTML:#sidebar-host-42-counts"' in html, (
        f"OOB-Counts fehlt Swap-Attribut: {html[:500]}"
    )
