"""Drift-Regression: Initial-Render-Skeleton vs. Fragment-Response.

Schuetzt das Single-Source-Partial-Pattern aus CLAUDE.md §HTMX-OOB-Single-
Source-Pattern fuer die drei OOB-faehigen Block-Y-Fragmente:

  - **KPI-Tiles** (`#sd-tiles`) — Initial-Render und Sparklines-Fragment-
    Response inkludieren beide `_kpi_card.html` und rendern dieselben vier
    Cards (KEV/Critical/High/Medium). Drift zwischen den Pfaden wuerde
    bedeuten, dass HTMX-Swap das Markup-Schema bricht.
  - **Heartbeat** (`#sd-heartbeat`) — Initial-Render rendert das
    `_heartbeat_large.html`-Partial im `--skel`-Modus, Fragment-Response
    rendert dasselbe Partial mit Live-Cells. Identische ID, identische
    30-Tick-Anzahl, identische `data-test`-Marker.
  - **Severity-Trend** (`#sd-trend`) — analog: identisches Partial
    (`_stacked_bar_chart.html`), 30 Columns im Skeleton, 30 Columns im
    Live-Render.

Begruendung: Block-W-Heartbeat-Bug (CLAUDE.md §HTMX-OOB-Single-Source-
Pattern) — wenn Skeleton- und Live-Pfad strukturell auseinanderlaufen
(unterschiedliche CSS-Klassen, fehlende IDs, andere Tick-Anzahl), bricht
HTMX-Swap stillschweigend und der Operator sieht entweder das Skeleton
oder gar nichts. Diese Tests erkennen jeden zukuenftigen Drift bevor er
in Produktion sichtbar wird.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from flask import Flask, render_template

# ---------------------------------------------------------------------------
# Fixtures / Helper
# ---------------------------------------------------------------------------

BASE_DATE = date(2026, 5, 24)


def _make_server(server_id: int = 7, *, scanned: bool = True) -> MagicMock:
    """Minimal-Mock eines Server-Objekts fuer die Fragment-Templates."""
    srv = MagicMock()
    srv.id = server_id
    srv.name = f"host-{server_id}"
    if scanned:
        srv.host_state_snapshot_at = datetime(2026, 5, 24, 12, 0, tzinfo=UTC)
    else:
        srv.host_state_snapshot_at = None
    return srv


def _make_heartbeat_cell(
    day: date, dominant_risk_band: str | None = "nominal", had_scan: bool = True
) -> MagicMock:
    """Minimal-Mock eines DailyStatus-Objekts."""
    cell = MagicMock()
    cell.day = day
    cell.had_scan = had_scan
    cell.dominant_risk_band = dominant_risk_band
    return cell


def _make_30_heartbeat_cells() -> list[MagicMock]:
    """30 Heartbeat-Cells mit variierenden Bands (escalate/act/nominal/None)."""
    bands: tuple[str | None, ...] = ("escalate", "act", "nominal", None)
    cells: list[MagicMock] = []
    for i in range(30):
        day = BASE_DATE - timedelta(days=29 - i)
        cells.append(_make_heartbeat_cell(day, dominant_risk_band=bands[i % len(bands)]))
    return cells


def _make_trend_day(
    d: date, *, c: int = 1, h: int = 2, m: int = 3, low: int = 4, kev: int = 0
) -> MagicMock:
    """Minimal-Mock eines DailySeverityCount-Objekts."""
    day = MagicMock()
    day.day = d
    day.critical = c
    day.high = h
    day.medium = m
    day.low = low
    day.kev = kev
    return day


def _make_30_trend_days() -> list[MagicMock]:
    return [_make_trend_day(BASE_DATE - timedelta(days=29 - i)) for i in range(30)]


def _quick_counts() -> dict[str, int]:
    return {
        "total_all": 42,
        "total_open": 18,
        "kev_open": 2,
        "critical_open": 3,
        "high_open": 5,
        "medium_open": 6,
        "low_open": 4,
    }


def _sparklines() -> dict[str, list[int]]:
    return {
        "kev": [
            0,
            1,
            2,
            1,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
        ],
        "critical": [3] * 30,
        "high": [5] * 30,
        "medium": [6] * 30,
    }


def _tendency_stub() -> MagicMock:
    t = MagicMock()
    t.label = "stable"
    return t


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


def _render_kpi_initial(app: Flask, counts: dict[str, int]) -> str:
    """Initial-Render-Skeleton aus `detail.html` (sd-tiles-Block, Z. 286-307).

    Eigenstaendig nachgebildet — wir koennen `detail.html` nicht isoliert
    rendern (haengt am vollen `show()`-Kontext); die Card-Struktur ist
    aber stabil und 1:1 mit `_partials/sparklines_fragment.html`.
    """
    with app.test_request_context("/"):
        return render_template(
            "test_helpers/_kpi_tiles_initial_skeleton.html",
            quick_counts=counts,
        )


def _render_kpi_fragment(
    app: Flask, counts: dict[str, int], sparklines: dict[str, list[int]]
) -> str:
    with app.test_request_context("/"):
        return render_template(
            "servers/_partials/sparklines_fragment.html",
            quick_counts=counts,
            sparklines=sparklines,
        )


def _render_heartbeat_initial(app: Flask, server: MagicMock) -> str:
    """Initial-Skeleton aus `detail.html` Z. 320-333 — `#sd-heartbeat`-Wrapper
    + entweder Empty-State oder `_heartbeat_large.html` mit `skel=True`."""
    with app.test_request_context("/"):
        return render_template(
            "test_helpers/_heartbeat_initial_skeleton.html",
            server=server,
        )


def _render_heartbeat_fragment(app: Flask, server: MagicMock, cells: list[MagicMock]) -> str:
    with app.test_request_context("/"):
        return render_template(
            "servers/_partials/heartbeat_fragment.html",
            server=server,
            cells=cells,
        )


def _render_trend_initial(app: Flask) -> str:
    """Initial-Skeleton aus `detail.html` Z. 350-357 — `#sd-trend`-Wrapper +
    `_stacked_bar_chart.html` mit `skel=True`."""
    with app.test_request_context("/"):
        return render_template(
            "test_helpers/_trend_initial_skeleton.html",
        )


def _render_trend_fragment(app: Flask, days: list[MagicMock]) -> str:
    with app.test_request_context("/"):
        return render_template(
            "servers/_partials/trend_fragment.html",
            trend_data=days,
            tendency=_tendency_stub(),
        )


# ---------------------------------------------------------------------------
# Test-Helper-Templates dynamisch erzeugen (eigener Loader-Path)
# ---------------------------------------------------------------------------

# Die Initial-Render-Skeletons sind in `detail.html` eingebettet und nicht
# isoliert renderbar (siehe Kommentar in `_render_kpi_initial`). Statt das
# komplette `detail.html` zu mocken erzeugen wir kleine Test-Templates die
# das identische Markup wie der jeweilige `detail.html`-Block enthalten und
# include-en dieselben Partials wie der Echt-Pfad. Damit testen wir genau
# das Single-Source-Pattern: ein und dasselbe Partial im Skeleton- und
# Fragment-Pfad muss strukturell gleich rendern.

_KPI_INITIAL_TEMPLATE = """\
<div class="sd-tiles" id="sd-tiles">
  {% with label='KEV', value=quick_counts.kev_open | default(0), tone='error',
          sparkline=[], kev_indicator=true %}
    {% include "servers/_kpi_card.html" %}
  {% endwith %}
  {% with label='Critical', value=quick_counts.critical_open | default(0), tone='error',
          sparkline=[], kev_indicator=false %}
    {% include "servers/_kpi_card.html" %}
  {% endwith %}
  {% with label='High', value=quick_counts.high_open | default(0), tone='warning',
          sparkline=[], kev_indicator=false %}
    {% include "servers/_kpi_card.html" %}
  {% endwith %}
  {% with label='Medium', value=quick_counts.medium_open | default(0), tone='accent',
          sparkline=[], kev_indicator=false %}
    {% include "servers/_kpi_card.html" %}
  {% endwith %}
</div>
"""

_HEARTBEAT_INITIAL_TEMPLATE = """\
<div id="sd-heartbeat">
  {% if server.host_state_snapshot_at is none %}
    <div class="sd-heartbeat-frame sd-heartbeat-frame--empty" data-test="heartbeat-empty">
      <p class="sd-empty">— noch nie gescannt</p>
    </div>
  {% else %}
    {% with cells=[], skel=True %}
      {% include "servers/_heartbeat_large.html" %}
    {% endwith %}
  {% endif %}
</div>
"""

_TREND_INITIAL_TEMPLATE = """\
<div id="sd-trend">
  {% with days_data=[], skel=True %}
    {% include "servers/_stacked_bar_chart.html" %}
  {% endwith %}
</div>
"""


@pytest.fixture(autouse=True)
def _register_test_helper_templates(app: Flask) -> None:
    """Registriert die drei Initial-Skeleton-Helper-Templates im Jinja-Loader.

    Wir koennen die Skeletons nicht 1:1 aus `detail.html` rendern (das
    Template haengt am vollen `show()`-Kontext), aber wir kopieren das exakte
    Skeleton-Markup (siehe `_KPI_INITIAL_TEMPLATE`/etc.) und includen
    dieselben Partials wie der Echt-Pfad. Drift zwischen Skeleton- und
    Fragment-Render erkennen wir damit zuverlaessig.
    """
    from jinja2 import ChoiceLoader, DictLoader

    helpers = DictLoader(
        {
            "test_helpers/_kpi_tiles_initial_skeleton.html": _KPI_INITIAL_TEMPLATE,
            "test_helpers/_heartbeat_initial_skeleton.html": _HEARTBEAT_INITIAL_TEMPLATE,
            "test_helpers/_trend_initial_skeleton.html": _TREND_INITIAL_TEMPLATE,
        }
    )
    if app.jinja_loader is not None:
        app.jinja_loader = ChoiceLoader([helpers, app.jinja_loader])
    else:
        app.jinja_loader = helpers


# ---------------------------------------------------------------------------
# Drift-Tests: KPI-Tiles
# ---------------------------------------------------------------------------


def test_kpi_tiles_drift_initial_vs_fragment(app: Flask) -> None:
    """Initial-Skeleton und Sparklines-Fragment teilen ID, Card-Anzahl und
    `data-test`-Marker pro Tile."""
    counts = _quick_counts()
    initial = _render_kpi_initial(app, counts)
    fragment = _render_kpi_fragment(app, counts, _sparklines())

    # Beide Pfade haben den Wrapper-DIV mit ID.
    assert 'id="sd-tiles"' in initial, f"Initial fehlt #sd-tiles: {initial[:300]}"
    assert 'id="sd-tiles"' in fragment, f"Fragment fehlt #sd-tiles: {fragment[:300]}"

    # Beide Pfade rendern vier Tiles mit identischen data-test-Markern.
    expected_markers = [
        'data-test="kpi-card-kev"',
        'data-test="kpi-card-critical"',
        'data-test="kpi-card-high"',
        'data-test="kpi-card-medium"',
    ]
    for marker in expected_markers:
        assert marker in initial, f"Initial fehlt {marker}: {initial[:500]}"
        assert marker in fragment, f"Fragment fehlt {marker}: {fragment[:500]}"

    # Beide Pfade enthalten genau vier Tile-Wrapper. data-test="kpi-card-…"
    # ist exklusiv am aeusseren Tile-Element gesetzt (siehe `_kpi_card.html`)
    # und ein robuster Zaehler, der nicht mit Sub-Elementen
    # (`sd-tile__label`, `sd-tile__num`) kollidiert.
    initial_tile_count = len(re.findall(r'data-test="kpi-card-', initial))
    fragment_tile_count = len(re.findall(r'data-test="kpi-card-', fragment))
    assert initial_tile_count == 4, f"Initial: 4 Tiles erwartet, got {initial_tile_count}"
    assert fragment_tile_count == 4, f"Fragment: 4 Tiles erwartet, got {fragment_tile_count}"


def test_kpi_card_skel_class_only_when_sparkline_empty(app: Flask) -> None:
    """`_kpi_card.html` setzt `sd-tile--skel sd-skel-frame` nur wenn `skel=True`.

    Im Initial-Render-Skeleton sind die Sparklines leer (`sparkline=[]`),
    aber der `skel`-Flag ist NICHT gesetzt — also rendert die Card mit
    Zahlen, aber ohne `--skel`-Modifier. Das ist by-design (Phase A): die
    KPIs zeigen sofort ihre Zahl, nur die Sparkline-Bars erscheinen erst
    nach dem Fragment-Swap.
    """
    initial = _render_kpi_initial(app, _quick_counts())
    fragment = _render_kpi_fragment(app, _quick_counts(), _sparklines())

    # Weder Initial noch Fragment setzen --skel auf den Tiles (Phase-A-Design).
    assert "sd-tile--skel" not in initial, (
        f"Initial-Render setzt --skel obwohl nicht erwartet: {initial[:500]}"
    )
    assert "sd-tile--skel" not in fragment, (
        f"Fragment setzt --skel obwohl nicht erwartet: {fragment[:500]}"
    )

    # Fragment-Pfad rendert die Sparkline-Bars (sd-spark__bar) — Initial nicht.
    assert "sd-spark__bar" not in initial, (
        f"Initial-Render rendert Sparkline-Bars obwohl sparkline=[]: {initial[:500]}"
    )
    assert "sd-spark__bar" in fragment, f"Fragment fehlt Sparkline-Bars: {fragment[:500]}"


# ---------------------------------------------------------------------------
# Drift-Tests: Heartbeat
# ---------------------------------------------------------------------------


def test_heartbeat_drift_initial_vs_fragment(app: Flask) -> None:
    """Initial-Skeleton (skel=True) und Fragment-Response (live cells) teilen
    den `#sd-heartbeat`-Wrapper, das `_heartbeat_large.html`-Partial und die
    30-Tick-Anzahl."""
    server = _make_server(scanned=True)
    cells = _make_30_heartbeat_cells()

    initial = _render_heartbeat_initial(app, server)
    fragment = _render_heartbeat_fragment(app, server, cells)

    # Wrapper-ID in beiden Pfaden.
    assert 'id="sd-heartbeat"' in initial, f"Initial fehlt #sd-heartbeat: {initial[:300]}"
    assert 'id="sd-heartbeat"' in fragment, f"Fragment fehlt #sd-heartbeat: {fragment[:300]}"

    # Beide Pfade rendern 30 `<button … class="sd-heartbeat__tick …">`-
    # Elemente. Auf das oeffnende Tag matchen, sonst zaehlt der zweite
    # Modifier-Klassenname (z.B. `sd-heartbeat__tick--skel`) doppelt.
    initial_tick_count = len(re.findall(r'<button[^>]*class="sd-heartbeat__tick', initial))
    fragment_tick_count = len(re.findall(r'<button[^>]*class="sd-heartbeat__tick', fragment))
    assert initial_tick_count == 30, f"Initial: 30 Ticks erwartet, got {initial_tick_count}"
    assert fragment_tick_count == 30, f"Fragment: 30 Ticks erwartet, got {fragment_tick_count}"

    # Beide nutzen das identische data-test-Marker am Frame.
    assert 'data-test="heartbeat-frame"' in initial, (
        f"Initial fehlt heartbeat-frame-Marker: {initial[:500]}"
    )
    assert 'data-test="heartbeat-frame"' in fragment, (
        f"Fragment fehlt heartbeat-frame-Marker: {fragment[:500]}"
    )

    # Skeleton-Modifier nur im Initial, NICHT im Fragment.
    assert "sd-heartbeat__tick--skel" in initial, f"Initial fehlt --skel-Modifier: {initial[:500]}"
    assert "sd-heartbeat__tick--skel" not in fragment, (
        f"Fragment hat --skel-Modifier obwohl live-cells: {fragment[:500]}"
    )

    # Fragment-Pfad rendert `data-day`/`data-band` auf jedem Tick — Initial nicht.
    fragment_data_day_count = fragment.count("data-day=")
    assert fragment_data_day_count == 30, (
        f"Fragment: 30 data-day-Attribute erwartet, got {fragment_data_day_count}"
    )
    assert "data-day=" not in initial, (
        f"Initial-Skeleton hat data-day obwohl skel=True: {initial[:500]}"
    )


def test_heartbeat_drift_empty_state_consistent(app: Flask) -> None:
    """Never-scanned-Server: Initial-Render und Fragment-Response liefern
    beide den `--empty`-State mit `data-test="heartbeat-empty"`-Marker."""
    server = _make_server(scanned=False)

    initial = _render_heartbeat_initial(app, server)
    fragment = _render_heartbeat_fragment(app, server, cells=[])

    assert 'data-test="heartbeat-empty"' in initial, (
        f"Initial fehlt Empty-State-Marker: {initial[:500]}"
    )
    assert 'data-test="heartbeat-empty"' in fragment, (
        f"Fragment fehlt Empty-State-Marker: {fragment[:500]}"
    )
    # Beide haben den `--empty`-Modifier.
    assert "sd-heartbeat-frame--empty" in initial, f"Initial fehlt --empty: {initial[:500]}"
    assert "sd-heartbeat-frame--empty" in fragment, f"Fragment fehlt --empty: {fragment[:500]}"
    # Kein Tick im Empty-State.
    assert "sd-heartbeat__tick" not in initial, f"Initial-Empty rendert Ticks: {initial[:500]}"
    assert "sd-heartbeat__tick" not in fragment, f"Fragment-Empty rendert Ticks: {fragment[:500]}"


# ---------------------------------------------------------------------------
# Drift-Tests: Severity-Trend
# ---------------------------------------------------------------------------


def test_trend_drift_initial_vs_fragment(app: Flask) -> None:
    """Initial-Skeleton (skel=True, 30 leere Cols) und Fragment (live Cols)
    teilen den `#sd-trend`-Wrapper und die 30-Column-Anzahl."""
    days = _make_30_trend_days()

    initial = _render_trend_initial(app)
    fragment = _render_trend_fragment(app, days)

    assert 'id="sd-trend"' in initial, f"Initial fehlt #sd-trend: {initial[:300]}"
    assert 'id="sd-trend"' in fragment, f"Fragment fehlt #sd-trend: {fragment[:300]}"

    # Auf das oeffnende `<div class="sd-trend-col` matchen, sonst zaehlt der
    # zweite Modifier-Klassenname (`sd-trend-col--skel`) doppelt.
    initial_col_count = len(re.findall(r'<div[^>]*class="sd-trend-col', initial))
    fragment_col_count = len(re.findall(r'<div[^>]*class="sd-trend-col', fragment))
    assert initial_col_count == 30, f"Initial: 30 Cols erwartet, got {initial_col_count}"
    assert fragment_col_count == 30, f"Fragment: 30 Cols erwartet, got {fragment_col_count}"

    # Beide nutzen das identische data-test-Marker am Frame.
    assert 'data-test="severity-trend-frame"' in initial, (
        f"Initial fehlt trend-frame-Marker: {initial[:500]}"
    )
    assert 'data-test="severity-trend-frame"' in fragment, (
        f"Fragment fehlt trend-frame-Marker: {fragment[:500]}"
    )

    # Skeleton-Modifier nur im Initial.
    assert "sd-trend-col--skel" in initial, f"Initial fehlt --skel-Modifier: {initial[:500]}"
    assert "sd-trend-col--skel" not in fragment, (
        f"Fragment hat --skel-Modifier obwohl live-data: {fragment[:500]}"
    )
    assert "sd-skel-frame" in initial, f"Initial fehlt sd-skel-frame: {initial[:500]}"
    assert "sd-skel-frame" not in fragment, (
        f"Fragment hat sd-skel-frame obwohl live-data: {fragment[:500]}"
    )

    # Fragment hat data-day auf jeder Col — Initial nicht.
    assert fragment.count("data-day=") == 30, (
        f"Fragment: 30 data-day erwartet, got {fragment.count('data-day=')}"
    )
    assert "data-day=" not in initial, (
        f"Initial-Skeleton hat data-day obwohl skel=True: {initial[:500]}"
    )


def test_trend_fragment_emits_tendency_oob_swap(app: Flask) -> None:
    """Fragment-Response emittiert den `#sd-stats-delta`-OOB-Swap-Span — der
    Tendency-Wert im Header wird durch die Live-30-Tage-Aggregation
    ueberschrieben (Single-Source-Wahrheit)."""
    fragment = _render_trend_fragment(app, _make_30_trend_days())
    assert 'id="sd-stats-delta"' in fragment, f"Fragment fehlt OOB-Span: {fragment[:500]}"
    assert 'hx-swap-oob="outerHTML"' in fragment, (
        f"Fragment fehlt OOB-Swap-Attribut: {fragment[:500]}"
    )
