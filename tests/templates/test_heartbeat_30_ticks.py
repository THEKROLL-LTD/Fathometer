"""Template-Smoke-Tests fuer Heartbeat-Bar mit 30 Ticks (Block W, ADR-0035).

Prueft:
  - Live-Pfad rendert genau 30 `host__beat-tick`-Elemente.
  - Skeleton-Pfad rendert genau 30 Skeleton-Cells mit `host__beat-tick--skel`.
  - dominant_risk_band-Mapping: 'escalate' -> 'beat--alarm', etc.
"""

from __future__ import annotations

from datetime import date, timedelta
from unittest.mock import MagicMock

from flask import Flask

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_cell(
    day: date, dominant_risk_band: str | None = None, had_scan: bool = True
) -> MagicMock:
    """Minimal-Mock eines DailyStatus-Objekts."""
    cell = MagicMock()
    cell.day = day
    cell.had_scan = had_scan
    # dominant_risk_band kann ein Enum-Objekt oder None sein.
    # Das Template macht: band = cell.dominant_risk_band.value if cell.dominant_risk_band else None
    if dominant_risk_band is None:
        cell.dominant_risk_band = None
    else:
        rb_mock = MagicMock()
        rb_mock.value = dominant_risk_band
        cell.dominant_risk_band = rb_mock
    return cell


def _render_heartbeat_bar(app: Flask, cells: list | None) -> str:
    """Rendert `sidebar/_heartbeat_bar.html` mit den gegebenen Cells.

    `cells=None` oder `cells=[]` triggert den Skeleton-Pfad.
    """
    from flask import render_template

    with app.test_request_context("/"):
        return render_template("sidebar/_heartbeat_bar.html", cells=cells)


BASE_DATE = date(2026, 5, 15)


def _make_30_cells(risk_band: str | None = None) -> list[MagicMock]:
    """30 Mock-Cells fuer den Live-Pfad."""
    return [
        _make_cell(BASE_DATE - timedelta(days=29 - i), dominant_risk_band=risk_band)
        for i in range(30)
    ]


# ---------------------------------------------------------------------------
# 30-Ticks-Live-Pfad
# ---------------------------------------------------------------------------


def test_heartbeat_bar_renders_exactly_30_ticks(app: Flask) -> None:
    """Live-Pfad mit 30 Cells rendert genau 30 host__beat-tick-Elemente."""
    cells = _make_30_cells()
    html = _render_heartbeat_bar(app, cells)

    tick_count = html.count("host__beat-tick")
    assert tick_count == 30, f"Erwartet 30 host__beat-tick-Elemente, got {tick_count}: {html[:500]}"


def test_heartbeat_bar_live_path_has_no_skeleton_class(app: Flask) -> None:
    """Live-Pfad darf keine Skeleton-Klasse haben."""
    cells = _make_30_cells()
    html = _render_heartbeat_bar(app, cells)

    assert "host__beat--skel" not in html, (
        f"Live-Pfad darf kein 'host__beat--skel' enthalten: {html[:500]}"
    )


def test_heartbeat_bar_live_path_has_aria_label(app: Flask) -> None:
    """Live-Pfad hat `aria-label='30-day heartbeat'`."""
    cells = _make_30_cells()
    html = _render_heartbeat_bar(app, cells)

    assert "30-day heartbeat" in html, f"aria-label='30-day heartbeat' erwartet: {html[:500]}"


# ---------------------------------------------------------------------------
# 30-Ticks-Skeleton-Pfad
# ---------------------------------------------------------------------------


def test_heartbeat_bar_skeleton_path_renders_30_skel_cells(app: Flask) -> None:
    """Skeleton-Pfad (cells=[]) rendert 30 Skeleton-Cells."""
    html = _render_heartbeat_bar(app, [])

    skel_count = html.count("host__beat-tick--skel")
    assert skel_count == 30, (
        f"Erwartet 30 host__beat-tick--skel-Cells, got {skel_count}: {html[:500]}"
    )


def test_heartbeat_bar_skeleton_path_has_probe(app: Flask) -> None:
    """Skeleton-Pfad hat den Scan-Probe-Beam (`host__beat__probe`)."""
    html = _render_heartbeat_bar(app, [])

    assert "host__beat__probe" in html, (
        f"Skeleton-Pfad braucht host__beat__probe-Beam: {html[:500]}"
    )


def test_heartbeat_bar_skeleton_path_data_test_marker(app: Flask) -> None:
    """Skeleton-Pfad hat `data-test='heartbeat-skeleton'` fuer Test-Queries."""
    html = _render_heartbeat_bar(app, [])

    assert 'data-test="heartbeat-skeleton"' in html, (
        f"data-test='heartbeat-skeleton' erwartet: {html[:500]}"
    )


def test_heartbeat_bar_skeleton_path_none_cells(app: Flask) -> None:
    """cells=None (statt leere Liste) triggert ebenfalls den Skeleton-Pfad."""
    html = _render_heartbeat_bar(app, None)

    # Jinja's `{% if cells %}` evaluiert None als Falsey.
    assert "host__beat-tick--skel" in html, f"cells=None soll Skeleton zeigen: {html[:500]}"


# ---------------------------------------------------------------------------
# dominant_risk_band -> CSS-Klassen-Mapping (ADR-0035 §Frontend-Mapping)
# ---------------------------------------------------------------------------


def test_heartbeat_bar_dominant_risk_band_escalate_to_alarm(app: Flask) -> None:
    """dominant_risk_band='escalate' -> beat--alarm-Klasse."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="escalate")]
    html = _render_heartbeat_bar(app, cells)

    assert "beat--alarm" in html, f"'escalate' soll 'beat--alarm' ergeben: {html}"


def test_heartbeat_bar_dominant_risk_band_act_to_warn(app: Flask) -> None:
    """dominant_risk_band='act' -> beat--warn-Klasse."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="act")]
    html = _render_heartbeat_bar(app, cells)

    assert "beat--warn" in html, f"'act' soll 'beat--warn' ergeben: {html}"


def test_heartbeat_bar_dominant_risk_band_mitigate_to_warn(app: Flask) -> None:
    """dominant_risk_band='mitigate' -> beat--warn-Klasse."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="mitigate")]
    html = _render_heartbeat_bar(app, cells)

    assert "beat--warn" in html, f"'mitigate' soll 'beat--warn' ergeben: {html}"


def test_heartbeat_bar_dominant_risk_band_monitor_to_ok(app: Flask) -> None:
    """dominant_risk_band='monitor' -> beat--ok-Klasse."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="monitor")]
    html = _render_heartbeat_bar(app, cells)

    assert "beat--ok" in html, f"'monitor' soll 'beat--ok' ergeben: {html}"


def test_heartbeat_bar_dominant_risk_band_pending_to_ok(app: Flask) -> None:
    """dominant_risk_band='pending' -> beat--ok-Klasse."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="pending")]
    html = _render_heartbeat_bar(app, cells)

    assert "beat--ok" in html, f"'pending' soll 'beat--ok' ergeben: {html}"


def test_heartbeat_bar_dominant_risk_band_noise_to_ok(app: Flask) -> None:
    """dominant_risk_band='noise' -> beat--ok-Klasse."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="noise")]
    html = _render_heartbeat_bar(app, cells)

    assert "beat--ok" in html, f"'noise' soll 'beat--ok' ergeben: {html}"


def test_heartbeat_bar_dominant_risk_band_unknown_to_unknown(app: Flask) -> None:
    """dominant_risk_band='unknown' -> beat--unknown-Klasse."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band="unknown")]
    html = _render_heartbeat_bar(app, cells)

    assert "beat--unknown" in html, f"'unknown' soll 'beat--unknown' ergeben: {html}"


def test_heartbeat_bar_dominant_risk_band_none_to_ok(app: Flask) -> None:
    """dominant_risk_band=None (kein Finding) -> beat--ok-Klasse (nominal)."""
    cells = [_make_cell(BASE_DATE, dominant_risk_band=None)]
    html = _render_heartbeat_bar(app, cells)

    assert "beat--ok" in html, f"None-Band (kein Finding) soll 'beat--ok' ergeben: {html}"


def test_heartbeat_bar_data_day_attribute_present(app: Flask) -> None:
    """Live-Cells haben `data-day`-Attribut mit ISO-Datum."""
    cells = [_make_cell(date(2026, 5, 10), dominant_risk_band=None)]
    html = _render_heartbeat_bar(app, cells)

    assert 'data-day="2026-05-10"' in html, f"data-day='2026-05-10' erwartet: {html}"
