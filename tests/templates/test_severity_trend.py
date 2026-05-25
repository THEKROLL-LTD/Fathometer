"""Pure-Unit-Tests fuer ``servers/_stacked_bar_chart.html`` und Severity-Trend-Toggle
in ``servers/detail.html`` (Block X Phase E, ADR-0038 §5).

Prueft (DoD-Punkt 5, Block X Phase E):
  1.  Range-Toggle in detail.html hat genau drei Buttons: '24h', '7T', '30T'.
      Kein '50T'-Button mehr vorhanden.
  2.  Range-Toggle-Container hat ``class="sd-trend-range"``.
  3.  Skeleton-State (skel=True): 30 ``sd-trend-col--skel``-Divs,
      Container hat ``sd-skel-frame``.
  4.  Live-Pfad (skel=False): 30 days_data -> 30 ``sd-trend-col``-Divs (ohne --skel).
  5.  Severity-Segmente haben korrekte Modifier-Klassen (--critical, --high,
      --medium, --low).
  6.  ``data-test="severity-trend-frame"``-Anker im Output.
  7.  detail.html-Source enthaelt ``trendRange: '30T'`` (nicht ``'50T'``).

Render-Strategie:
  - Source-Read via ``Path(...).read_text()`` fuer Tests 1, 2, 7 (Substring-Check).
  - ``render_template_string`` mit Partial-Source fuer Tests 3, 4, 5, 6.
  - ``types.SimpleNamespace`` als Daten-Mock.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from types import SimpleNamespace

from flask import Flask

# ---------------------------------------------------------------------------
# Pfade
# ---------------------------------------------------------------------------

_DETAIL_PATH = Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "detail.html"
_PARTIAL_PATH = (
    Path(__file__).parent.parent.parent
    / "app"
    / "templates"
    / "servers"
    / "_stacked_bar_chart.html"
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _load_detail_source() -> str:
    """Laedt detail.html-Source direkt vom Filesystem."""
    return _DETAIL_PATH.read_text(encoding="utf-8")


def _load_partial_source() -> str:
    """Laedt _stacked_bar_chart.html-Source direkt vom Filesystem."""
    return _PARTIAL_PATH.read_text(encoding="utf-8")


def _make_day(
    day: date,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    kev: int = 0,
) -> SimpleNamespace:
    """Minimal-Mock eines DailySeverityCount-Objekts."""
    return SimpleNamespace(
        day=day,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        kev=kev,
    )


def _make_30_days(
    critical: int = 2,
    high: int = 3,
    medium: int = 1,
    low: int = 4,
    kev: int = 0,
) -> list[SimpleNamespace]:
    """30 Mock-Days fuer den Live-Pfad."""
    return [
        _make_day(
            date(2026, 4, 1) if i == 0 else date(2026, 3, 1 + i),
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            kev=kev,
        )
        for i in range(30)
    ]


def _render_trend(app: Flask, *, days_data: list[SimpleNamespace], skel: bool = False) -> str:
    """Rendert _stacked_bar_chart.html via render_template_string."""
    from flask import render_template_string

    source = _load_partial_source()
    with app.test_request_context("/"):
        return render_template_string(source, days_data=days_data, skel=skel)


# ---------------------------------------------------------------------------
# Test 1 — Range-Toggle hat drei Buttons, kein 50T
# ---------------------------------------------------------------------------


def test_range_toggle_has_three_buttons_no_50t() -> None:
    """detail.html Range-Toggle enthaelt '24h', '7T', '30T' — kein '50T' als Button-Wert."""
    source = _load_detail_source()

    # Die drei erlaubten Werte muessen als Button-Texte / Alpine-Attribut-Werte
    # im Source auftauchen.
    for expected in ("24h", "7T", "30T"):
        assert expected in source, (
            f"Range-Toggle-Wert '{expected}' fehlt in detail.html. "
            f"Pflicht-Reihenfolge: [24h, 7T, 30T]."
        )

    # '50T' darf nicht mehr als Button-Wert oder Alpine-Attribut vorkommen.
    # Kommentar-Zeilen werden ausgefiltert (beginnen mit '{#' oder enden auf '#}').
    non_comment_lines = [
        line
        for line in source.splitlines()
        if not line.strip().startswith("{#") and not line.strip().startswith("#")
    ]
    non_comment_source = "\n".join(non_comment_lines)

    # '50T' als Button-Text oder trendRange-Wert darf im nicht-Kommentar-Code nicht vorkommen.
    # Pruefe ob '50T' als Python-Listenitem (['24h', '7T', '50T']) oder Button-@click auftaucht.
    assert "'50T'" not in non_comment_source, (
        f"'50T' ist noch als Jinja-Listenwert oder Alpine-Attribut in detail.html. "
        f"Phase E hat '50T' aus dem Range-Toggle entfernt (ADR-0038 §5). "
        f"Kontext: {[line for line in non_comment_lines if '50T' in line]}"
    )

    # Ebenfalls kein '50 Tage' / '50 days' als Lebenszeichen-Label.
    assert "50 Tage" not in non_comment_source, (
        "'50 Tage' noch in detail.html (ausserhalb von Kommentaren). "
        "Lebenszeichen-Label soll '30 Tage' sein."
    )
    assert "50 days" not in non_comment_source, (
        "'50 days' noch in detail.html (ausserhalb von Kommentaren). "
        "Lebenszeichen-Label soll '30 days' sein."
    )


# ---------------------------------------------------------------------------
# Test 2 — Range-Toggle-Container hat sd-trend-range
# ---------------------------------------------------------------------------


def test_range_toggle_uses_sd_trend_range_class() -> None:
    """Range-Toggle-Container hat ``class="sd-trend-range"``.

    Track E hat den Range-Toggle in _stacked_bar_chart.html integriert
    (nicht mehr direkt in detail.html). Der Test prueft den Partial-Source.
    """
    # Track E: Toggle ist jetzt Teil des Partials, nicht von detail.html.
    partial_source = _load_partial_source()

    assert 'class="sd-trend-range"' in partial_source, (
        "'class=\"sd-trend-range\"' fehlt in _stacked_bar_chart.html. "
        "Track E hat den Range-Toggle in das Partial integriert. "
        "Range-Toggle-Container soll sd-trend-range-Klasse verwenden."
    )


# ---------------------------------------------------------------------------
# Test 3 — Skeleton-State: 30 skel-Cols, sd-skel-frame
# ---------------------------------------------------------------------------


def test_trend_skel_state_renders_30_skel_cols(app: Flask) -> None:
    """skel=True rendert 30 sd-trend-col--skel-Divs, Container hat sd-skel-frame."""
    html = _render_trend(app, days_data=[], skel=True)

    skel_count = html.count("sd-trend-col--skel")
    assert skel_count == 30, (
        f"Erwartet 30 sd-trend-col--skel-Divs bei skel=True, gefunden {skel_count}. "
        f"HTML-Ausschnitt: {html[:600]!r}"
    )

    assert "sd-skel-frame" in html, (
        f"Skel-Container soll 'sd-skel-frame'-Klasse haben. HTML: {html[:400]!r}"
    )

    # Keine Live-Trend-Cols bei Skel
    assert '"sd-trend-col"' not in html, (
        f"Skel-State darf keine Live-'sd-trend-col'-Divs enthalten. HTML: {html[:600]!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Live: 30 days_data -> 30 sd-trend-col-Divs
# ---------------------------------------------------------------------------


def test_trend_live_renders_one_col_per_day(app: Flask) -> None:
    """skel=False mit 30 days_data rendert 30 sd-trend-col-Divs (ohne --skel)."""
    days_data = _make_30_days(critical=1, high=0, medium=0, low=0)
    html = _render_trend(app, days_data=days_data, skel=False)

    # sd-trend-col zaehlen — class="sd-trend-col" mit Leerzeichen oder Anzeichen.
    # Die Col-Divs haben class="sd-trend-col" und data-day="...".
    col_count = html.count('"sd-trend-col"')
    assert col_count == 30, (
        f"Erwartet 30 'sd-trend-col'-Divs (class=\"sd-trend-col\"), gefunden {col_count}. "
        f"HTML-Ausschnitt: {html[:800]!r}"
    )

    # Kein --skel im Live-Pfad
    assert "sd-trend-col--skel" not in html, (
        f"Live-Pfad darf kein 'sd-trend-col--skel' enthalten. HTML: {html[:600]!r}"
    )


# ---------------------------------------------------------------------------
# Test 5 — Segmente haben Severity-Modifier-Klassen
# ---------------------------------------------------------------------------


def test_trend_segments_use_severity_modifiers(app: Flask) -> None:
    """Render mit allen vier Severity-Werten > 0 erzeugt alle vier --<sev>-Segmente."""
    day_with_all = _make_day(date(2026, 5, 24), critical=2, high=3, medium=1, low=4, kev=0)
    html = _render_trend(app, days_data=[day_with_all], skel=False)

    for modifier in ("critical", "high", "medium", "low"):
        cls = f"sd-trend-seg--{modifier}"
        assert cls in html, (
            f"'{cls}' fehlt im Segment-Output. "
            f"Severity-Modifier '{modifier}' soll als Span-Klasse vorhanden sein. "
            f"HTML: {html!r}"
        )


def test_trend_segments_skip_zero_severity(app: Flask) -> None:
    """Segmente mit Wert 0 werden nicht gerendert (kein leeres Span im Output)."""
    day_only_critical = _make_day(date(2026, 5, 24), critical=5, high=0, medium=0, low=0)
    html = _render_trend(app, days_data=[day_only_critical], skel=False)

    assert "sd-trend-seg--critical" in html, (
        f"sd-trend-seg--critical fehlt obwohl critical=5. HTML: {html!r}"
    )
    for zero_sev in ("high", "medium", "low"):
        cls = f"sd-trend-seg--{zero_sev}"
        assert cls not in html, (
            f"'{cls}' ist im Output obwohl {zero_sev}=0. "
            f"Null-Segmente sollen nicht gerendert werden. HTML: {html!r}"
        )


# ---------------------------------------------------------------------------
# Test 6 — data-test="severity-trend-frame"
# ---------------------------------------------------------------------------


def test_trend_frame_data_test_anchor_present(app: Flask) -> None:
    """Output enthaelt data-test="severity-trend-frame"."""
    html = _render_trend(app, days_data=[], skel=False)

    assert 'data-test="severity-trend-frame"' in html, (
        f"'data-test=\"severity-trend-frame\"' fehlt im Output. HTML: {html[:400]!r}"
    )


# ---------------------------------------------------------------------------
# Test 7 — detail.html enthaelt trendRange: '30T'
# ---------------------------------------------------------------------------


def test_alpine_trend_range_default_30t() -> None:
    """detail.html-Source enthaelt ``trendRange: '30T'`` (nicht ``'50T'``)."""
    source = _load_detail_source()

    if "trendRange" in source:
        ctx_start = source.find("trendRange")
        ctx = source[max(0, ctx_start - 50) : ctx_start + 80]
        assert "trendRange: '30T'" in source, (
            f"'trendRange: '30T'' fehlt in detail.html. "
            f"Default-Range soll '30T' sein (Phase E, ADR-0038 §5). "
            f"Relevanter Source-Ausschnitt: {ctx!r}"
        )
    else:
        raise AssertionError("'trendRange' komplett absent in detail.html.")

    # Sicherheits-Check: kein 50T-Default
    assert "trendRange: '50T'" not in source, (
        "'trendRange: '50T'' ist noch in detail.html. Phase E soll '30T' als Default setzen."
    )
