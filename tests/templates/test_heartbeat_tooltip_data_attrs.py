"""TICKET-005 Batch 2 — neue data-* Attribute am Heartbeat-Tick.

Verifiziert: kein `title=` mehr, `data-day`/`data-band`/`data-had-scan` in
jedem Live-Tick gesetzt; Skeleton-Pfad bleibt frei von band/had-scan-Attrs.
"""

from __future__ import annotations

from datetime import date

from flask import Flask

from tests.templates.test_heartbeat_30_ticks import (
    BASE_DATE,
    _make_30_cells,
    _make_cell,
    _render_heartbeat_bar,
)

# ---------------------------------------------------------------------------
# Live-Pfad: kein title=, alle data-* gesetzt
# ---------------------------------------------------------------------------


def test_heartbeat_live_path_has_no_title_attribute(app: Flask) -> None:
    """Browser-Native-Tooltip raus — `title="` darf im Live-Markup nicht vorkommen."""
    cells = _make_30_cells(risk_band="escalate")
    html = _render_heartbeat_bar(app, cells)

    assert 'title="' not in html, (
        f"Live-Pfad darf kein title='…'-Attribut mehr setzen: {html[:500]}"
    )


def test_heartbeat_live_path_data_day_in_every_tick(app: Flask) -> None:
    """data-day ist in jedem der 30 Live-Ticks gesetzt."""
    cells = _make_30_cells(risk_band="escalate")
    html = _render_heartbeat_bar(app, cells)

    count = html.count('data-day="')
    assert count == 30, f"Erwartet 30x data-day, got {count}: {html[:500]}"


def test_heartbeat_live_path_data_band_in_every_tick(app: Flask) -> None:
    """data-band ist in jedem der 30 Live-Ticks gesetzt."""
    cells = _make_30_cells(risk_band="escalate")
    html = _render_heartbeat_bar(app, cells)

    count = html.count('data-band="')
    assert count == 30, f"Erwartet 30x data-band, got {count}: {html[:500]}"


def test_heartbeat_live_path_data_had_scan_in_every_tick(app: Flask) -> None:
    """data-had-scan ist in jedem der 30 Live-Ticks gesetzt."""
    cells = _make_30_cells(risk_band="escalate")
    html = _render_heartbeat_bar(app, cells)

    count = html.count('data-had-scan="')
    assert count == 30, f"Erwartet 30x data-had-scan, got {count}: {html[:500]}"


# ---------------------------------------------------------------------------
# data-band: echter String aus dominant_risk_band, KEIN "none"-Default
# ---------------------------------------------------------------------------


def test_heartbeat_data_band_contains_escalate(app: Flask) -> None:
    """Cell mit dominant_risk_band='escalate' → data-band='escalate' im Markup."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="escalate")]
    html = _render_heartbeat_bar(app, cells)

    assert 'data-band="escalate"' in html, f"data-band='escalate' erwartet: {html}"


def test_heartbeat_data_band_contains_act(app: Flask) -> None:
    """Cell mit dominant_risk_band='act' → data-band='act' im Markup."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="act")]
    html = _render_heartbeat_bar(app, cells)

    assert 'data-band="act"' in html, f"data-band='act' erwartet: {html}"


def test_heartbeat_data_band_none_renders_empty_string(app: Flask) -> None:
    """Cell mit dominant_risk_band=None → data-band='' (leer), NICHT 'none'."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band=None)]
    html = _render_heartbeat_bar(app, cells)

    assert 'data-band=""' in html, f"data-band='' (leerer String) bei None-Band erwartet: {html}"
    assert 'data-band="none"' not in html, (
        f"Alter 'none'-Default darf NICHT mehr im Markup auftauchen: {html}"
    )


# ---------------------------------------------------------------------------
# data-had-scan: "1" oder "0"
# ---------------------------------------------------------------------------


def test_heartbeat_data_had_scan_true_renders_1(app: Flask) -> None:
    """had_scan=True → data-had-scan='1'."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="escalate", had_scan=True)]
    html = _render_heartbeat_bar(app, cells)

    assert 'data-had-scan="1"' in html, f"data-had-scan='1' erwartet: {html}"


def test_heartbeat_data_had_scan_false_renders_0(app: Flask) -> None:
    """had_scan=False → data-had-scan='0'."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band=None, had_scan=False)]
    html = _render_heartbeat_bar(app, cells)

    assert 'data-had-scan="0"' in html, f"data-had-scan='0' erwartet: {html}"


def test_heartbeat_data_had_scan_mixed_fixture_has_both(app: Flask) -> None:
    """Gemischte Cells (had_scan True/False) → Markup enthält beide Varianten."""
    cells = [
        _make_cell(date(2026, 5, 14), dominant_risk_band="escalate", had_scan=True),
        _make_cell(date(2026, 5, 15), dominant_risk_band=None, had_scan=False),
    ]
    html = _render_heartbeat_bar(app, cells)

    assert 'data-had-scan="1"' in html, f"Mix-Fixture: data-had-scan='1' fehlt: {html}"
    assert 'data-had-scan="0"' in html, f"Mix-Fixture: data-had-scan='0' fehlt: {html}"


# ---------------------------------------------------------------------------
# Skeleton-Pfad: keine band/had-scan-Attribute
# ---------------------------------------------------------------------------


def test_heartbeat_skeleton_path_has_no_data_band(app: Flask) -> None:
    """Skeleton-Cells haben kein data-band-Attribut (nur Live-Ticks tragen es)."""
    html = _render_heartbeat_bar(app, [])

    assert 'data-band="' not in html, f"Skeleton-Pfad darf kein data-band setzen: {html[:500]}"


def test_heartbeat_skeleton_path_has_no_data_had_scan(app: Flask) -> None:
    """Skeleton-Cells haben kein data-had-scan-Attribut."""
    html = _render_heartbeat_bar(app, [])

    assert 'data-had-scan="' not in html, (
        f"Skeleton-Pfad darf kein data-had-scan setzen: {html[:500]}"
    )
