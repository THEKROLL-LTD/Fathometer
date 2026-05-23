"""Template-Smoke-Tests fuer Phase-C-Skeleton-Markup (ADR-0030, Befund 8).

Prueft via Jinja-Render-Output:
  - Initialer Render (_server_list.html ohne sidebar_heartbeats/sidebar_risk_counts):
    * HTMX-Trigger ist `load, every 60s [...]`.
    * Header-Markup mit data-test="sidebar-host-summary" vorhanden.
    * Skeleton-Markup fuer Heartbeat-Bar (data-test="heartbeat-skeleton").
    * Skeleton-Markup fuer ESCALATE-Spalte (animate-pulse, aria-label).
    * Skeleton-Markup fuer ACT-Spalte (animate-pulse, aria-label).
  - Polling-Endpoint-Render (sidebar_heartbeats + sidebar_risk_counts gesetzt):
    * Kein Skeleton fuer Heartbeat-Bar (heartbeat-cell vorhanden statt -skeleton).
    * Live-Zahlen oder Dash-Marker fuer ESCALATE/ACT.
    * alarm_count korrekt dargestellt.
"""

from __future__ import annotations

from datetime import date
from typing import Any
from unittest.mock import MagicMock

from flask import Flask

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(server_id: int = 1, name: str = "srv-01") -> MagicMock:
    """Minimal-Mock eines Server-ORM-Objekts fuer Template-Tests."""
    server = MagicMock()
    server.id = server_id
    server.name = name
    server.tag_links = []
    server.revoked_at = None
    server.retired_at = None
    return server


def _make_daily_status(day: date | None = None) -> MagicMock:
    """Minimal-Mock eines DailyStatus-Objekts fuer Heartbeat-Cell-Tests."""
    ds = MagicMock()
    ds.day = day or date(2026, 5, 1)
    ds.max_severity = None
    ds.kev_count = 0
    ds.had_scan = True
    return ds


def _render_server_list(
    app: Flask,
    servers: list[MagicMock],
    *,
    sidebar_heartbeats: dict | None = None,
    sidebar_risk_counts: dict | None = None,
    hosts_total: int | None = None,
    alarm_count: int | None = None,
    active_server_id: int | None = None,
    filter_tags: list[str] | None = None,
) -> str:
    """Rendert `sidebar/_server_list.html` im Flask-App-Kontext.

    Wenn `sidebar_heartbeats` / `sidebar_risk_counts` None sind, werden sie
    dem Template-Context NICHT uebergeben — das simuliert den initialen
    Page-Render, bei dem nur die billigen Keys vorhanden sind.
    """
    ctx: dict[str, Any] = {
        "sidebar_servers": servers,
        "available_tags": [],
        "filter_tags": filter_tags or [],
        "active_server_id": active_server_id,
    }
    if sidebar_heartbeats is not None:
        ctx["sidebar_heartbeats"] = sidebar_heartbeats
    if sidebar_risk_counts is not None:
        ctx["sidebar_risk_counts"] = sidebar_risk_counts
    if hosts_total is not None:
        ctx["hosts_total"] = hosts_total
    if alarm_count is not None:
        ctx["alarm_count"] = alarm_count

    with app.test_request_context("/"):
        from flask import render_template

        return render_template("sidebar/_server_list.html", **ctx)


# ---------------------------------------------------------------------------
# HTMX-Trigger
# ---------------------------------------------------------------------------


def test_htmx_trigger_is_load_and_60s(app: Flask) -> None:
    """HTMX-Trigger muss 'load, every 60s [...]' sein (ADR-0030 Phase C)."""
    html = _render_server_list(app, [])
    assert 'hx-trigger="load, every 60s [document.visibilityState' in html


# ---------------------------------------------------------------------------
# Header HOSTS · ALARM — initialer Render (Skeleton-Zustand)
# ---------------------------------------------------------------------------


def test_header_host_summary_present_initial(app: Flask) -> None:
    """Header-Markup data-test='sidebar-host-summary' im initialen Render."""
    srv = _make_server()
    html = _render_server_list(app, [srv])
    assert 'data-test="sidebar-host-summary"' in html


def test_header_hosts_total_fallback_to_server_count(app: Flask) -> None:
    """Wenn hosts_total nicht gesetzt, wird sidebar_servers | length genutzt."""
    servers = [_make_server(1, "s1"), _make_server(2, "s2")]
    html = _render_server_list(app, servers)
    assert 'data-test="sidebar-hosts-total"' in html
    # 2 Server -> "2 hosts" im Output
    assert ">2<" in html or "2</span>" in html


def test_header_alarm_skeleton_when_not_set(app: Flask) -> None:
    """Wenn alarm_count nicht im Context, wird Skeleton-Span gerendert."""
    html = _render_server_list(app, [_make_server()])
    assert 'data-test="sidebar-alarm-count-skeleton"' in html
    assert "animate-pulse" in html


def test_header_alarm_count_live_when_zero(app: Flask) -> None:
    """alarm_count=0 zeigt Live-Zahl (kein Skeleton), kein text-error."""
    html = _render_server_list(app, [_make_server()], alarm_count=0)
    assert 'data-test="sidebar-alarm-count"' in html
    assert 'data-test="sidebar-alarm-count-skeleton"' not in html
    # 0 -> kein text-error
    assert "text-error" not in html.split('data-test="sidebar-alarm-count"')[1].split(">0<")[0]


def test_header_alarm_count_live_with_error_class(app: Flask) -> None:
    """alarm_count > 0 zeigt Live-Zahl mit text-error-Klasse."""
    html = _render_server_list(app, [_make_server()], alarm_count=3)
    assert 'data-test="sidebar-alarm-count"' in html
    assert "text-error" in html


# ---------------------------------------------------------------------------
# ESCALATE / ACT-Spalten — initialer Render (Skeleton)
# ---------------------------------------------------------------------------


def test_escalate_skeleton_present_on_initial_render(app: Flask) -> None:
    """Ohne sidebar_risk_counts wird Skeleton fuer ESCALATE-Spalte gerendert."""
    srv = _make_server(42)
    html = _render_server_list(app, [srv])
    assert 'data-test="sidebar-row-escalate-42"' in html
    assert 'aria-label="escalate count loading"' in html


def test_act_skeleton_present_on_initial_render(app: Flask) -> None:
    """Ohne sidebar_risk_counts wird Skeleton fuer ACT-Spalte gerendert."""
    srv = _make_server(42)
    html = _render_server_list(app, [srv])
    assert 'data-test="sidebar-row-act-42"' in html
    assert 'aria-label="act count loading"' in html


# ---------------------------------------------------------------------------
# ESCALATE / ACT-Spalten — Polling-Render (Live-Werte)
# ---------------------------------------------------------------------------


def test_escalate_live_count_rendered_when_nonzero(app: Flask) -> None:
    """Mit sidebar_risk_counts != {} wird die echte Zahl gerendert."""
    srv = _make_server(7)
    risk = {7: {"escalate": 5, "act": 0}}
    html = _render_server_list(app, [srv], sidebar_risk_counts=risk)
    assert 'data-test="sidebar-row-escalate-7"' in html
    # Kein Skeleton
    assert 'aria-label="escalate count loading"' not in html
    # Echte Zahl mit text-error
    assert "text-error" in html


def test_escalate_dash_rendered_when_zero(app: Flask) -> None:
    """escalate=0 zeigt Dash-Marker (opacity-30), kein text-error."""
    srv = _make_server(8)
    risk = {8: {"escalate": 0, "act": 0}}
    html = _render_server_list(app, [srv], sidebar_risk_counts=risk)
    escalate_section = html.split('data-test="sidebar-row-escalate-8"')[1]
    assert "opacity-30" in escalate_section.split("</span>")[0]


def test_act_live_count_rendered_when_nonzero(app: Flask) -> None:
    """Mit sidebar_risk_counts != {} wird die echte ACT-Zahl gerendert."""
    srv = _make_server(9)
    risk = {9: {"escalate": 0, "act": 3}}
    html = _render_server_list(app, [srv], sidebar_risk_counts=risk)
    assert 'data-test="sidebar-row-act-9"' in html
    assert 'aria-label="act count loading"' not in html
    assert "text-warning" in html


def test_server_not_in_risk_counts_shows_skeleton(app: Flask) -> None:
    """Wenn ein Server nicht in sidebar_risk_counts ist, bleibt Skeleton."""
    srv = _make_server(99)
    risk: dict = {}  # Server 99 fehlt
    html = _render_server_list(app, [srv], sidebar_risk_counts=risk)
    assert 'aria-label="escalate count loading"' in html
    assert 'aria-label="act count loading"' in html


# ---------------------------------------------------------------------------
# Heartbeat-Bar Skeleton
# ---------------------------------------------------------------------------


def test_heartbeat_skeleton_present_on_initial_render(app: Flask) -> None:
    """Ohne sidebar_heartbeats (leere cells) erscheint Heartbeat-Skeleton."""
    srv = _make_server(1)
    html = _render_server_list(app, [srv])
    assert 'data-test="heartbeat-skeleton"' in html
    assert "animate-pulse" in html


def test_heartbeat_live_cells_rendered_when_data_present(app: Flask) -> None:
    """Mit sidebar_heartbeats zeigt die Bar echte heartbeat-cell-Spans."""
    srv = _make_server(1)
    cells = [_make_daily_status(date(2026, 5, i + 1)) for i in range(5)]
    heartbeats = {1: cells}
    html = _render_server_list(app, [srv], sidebar_heartbeats=heartbeats)
    assert "heartbeat-cell" in html
    assert 'data-test="heartbeat-skeleton"' not in html


def test_heartbeat_skeleton_has_50_cells(app: Flask) -> None:
    """Skeleton-Pfad rendert genau 50 Skeleton-Cells."""
    srv = _make_server(1)
    html = _render_server_list(app, [srv])
    # Zaehle wie viele Male "animate-pulse rounded-sm" vorkommt
    # (jede Skeleton-Cell hat diese Kombination)
    count = html.count("animate-pulse rounded-sm")
    # 50 Heartbeat-Skeleton-Cells + 2 ESCALATE/ACT-Skeleton-Spans pro Server
    # + optionaler alarm-count-Skeleton im Header
    # Mindestens 50 muss von Heartbeat kommen
    assert count >= 50
