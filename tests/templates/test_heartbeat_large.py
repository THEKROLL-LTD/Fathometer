"""Pure-Unit-Tests fuer ``servers/_heartbeat_large.html`` (Block X Phase E, ADR-0035 + ADR-0038 §5).

Prueft (DoD-Punkt 5, Block X Phase E):
  1.  Live-Pfad mit 30 Cells rendert genau 30 ``sd-heartbeat__tick``-Spans.
  2.  Band-Mapping: dominant_risk_band='escalate' -> ``--escalate``.
  3.  Band-Mapping: dominant_risk_band='act' -> ``--act``.
  4.  Band-Mapping: 'mitigate'|'monitor'|'noise'|'pending' -> ``--nominal`` (parametrize).
  5.  Band-Mapping: None -> ``--unknown``.
  6.  Band-Mapping: 'unknown' (String) -> ``--unknown``.
  7.  Skeleton-State: 30 ``sd-heartbeat__tick--skel``-Spans, kein data-Band/day/had-scan,
      Container hat ``sd-skel-frame``.
  8.  Live-Ticks haben data-day, data-band, data-had-scan-Attribute.
  9.  Legende enthaelt vier sd-legend-swatch-Elemente in Reihenfolge
      escalate/act/nominal/unknown.
  10. ``data-test="heartbeat-frame"``-Anker ist im Output.

Render-Strategie:
  - ``_render_heartbeat_large()`` nutzt ``render_template_string`` mit verbatim
    Source-Read des Partials (kein ``{% extends %}``).
  - ``types.SimpleNamespace`` als Daten-Mock.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Pfad zum Partial
# ---------------------------------------------------------------------------

_PARTIAL_PATH = (
    Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "_heartbeat_large.html"
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _load_partial_source() -> str:
    """Laedt _heartbeat_large.html-Source direkt vom Filesystem."""
    return _PARTIAL_PATH.read_text(encoding="utf-8")


def _make_cell(
    day: date,
    dominant_risk_band: str | None = None,
    had_scan: bool = True,
) -> SimpleNamespace:
    """Minimal-Mock eines DailyStatus-Objekts fuer Template-Render."""
    return SimpleNamespace(day=day, dominant_risk_band=dominant_risk_band, had_scan=had_scan)


def _make_30_cells(band: str | None = None) -> list[SimpleNamespace]:
    """30 Mock-Cells fuer den Live-Pfad."""
    return [
        _make_cell(date(2026, 5, 1) if i == 0 else date(2026, 4, 1 + i), dominant_risk_band=band)
        for i in range(30)
    ]


def _render(app: Flask, *, cells: list[SimpleNamespace], skel: bool = False) -> str:
    """Rendert _heartbeat_large.html mit ``cells`` + ``skel``."""
    from flask import render_template_string

    source = _load_partial_source()
    with app.test_request_context("/"):
        return render_template_string(source, cells=cells, skel=skel)


# ---------------------------------------------------------------------------
# Test 1 — 30 Ticks bei 30 Live-Cells
# ---------------------------------------------------------------------------


def test_heartbeat_renders_30_ticks_when_cells_present(app: Flask) -> None:
    """Live-Pfad mit 30 Cells rendert genau 30 ``sd-heartbeat__tick``-Spans."""
    cells = _make_30_cells()
    html = _render(app, cells=cells, skel=False)

    # Manche Ticks koennten "--escalate" etc. direkt ohne Leerzeichen folgen,
    # daher breiter Match ueber den spezifischeren Klassen-String:
    all_ticks = html.count('"sd-heartbeat__tick sd-heartbeat__tick--')
    assert all_ticks == 30, (
        f"Erwartet 30 sd-heartbeat__tick--<band>-Spans, gefunden {all_ticks}. "
        f"HTML-Ausschnitt: {html[:600]!r}"
    )


# ---------------------------------------------------------------------------
# Tests 2 + 3 — Band-Mapping fuer 'escalate' und 'act'
# ---------------------------------------------------------------------------


def test_band_mapping_escalate(app: Flask) -> None:
    """dominant_risk_band='escalate' -> sd-heartbeat__tick--escalate."""
    cells = [_make_cell(date(2026, 5, 1), dominant_risk_band="escalate")]
    html = _render(app, cells=cells)

    assert "sd-heartbeat__tick--escalate" in html, (
        f"'escalate' soll 'sd-heartbeat__tick--escalate' erzeugen. HTML: {html!r}"
    )
    assert "sd-heartbeat__tick--act" not in html, (
        f"'escalate' darf kein '--act' erzeugen. HTML: {html!r}"
    )


def test_band_mapping_act(app: Flask) -> None:
    """dominant_risk_band='act' -> sd-heartbeat__tick--act."""
    cells = [_make_cell(date(2026, 5, 1), dominant_risk_band="act")]
    html = _render(app, cells=cells)

    assert "sd-heartbeat__tick--act" in html, (
        f"'act' soll 'sd-heartbeat__tick--act' erzeugen. HTML: {html!r}"
    )
    assert "sd-heartbeat__tick--escalate" not in html, (
        f"'act' darf kein '--escalate' erzeugen. HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — 'mitigate'|'monitor'|'noise'|'pending' -> nominal (parametrize)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("band", ["mitigate", "monitor", "noise", "pending"])
def test_band_mapping_nominal_for_mitigate_monitor_noise_pending(app: Flask, band: str) -> None:
    """'mitigate'|'monitor'|'noise'|'pending' -> sd-heartbeat__tick--nominal."""
    cells = [_make_cell(date(2026, 5, 1), dominant_risk_band=band)]
    html = _render(app, cells=cells)

    assert "sd-heartbeat__tick--nominal" in html, (
        f"Band '{band}' soll '--nominal' erzeugen. HTML: {html!r}"
    )
    # Weder --escalate noch --act noch --unknown darf auftreten.
    for wrong in ("--escalate", "--act", "--unknown", "--skel"):
        assert f"sd-heartbeat__tick{wrong}" not in html, (
            f"Band '{band}': unerwartete Klasse '--{wrong.lstrip('-')}' im HTML. HTML: {html!r}"
        )


# ---------------------------------------------------------------------------
# Test 5 — None -> unknown
# ---------------------------------------------------------------------------


def test_band_mapping_unknown_when_none(app: Flask) -> None:
    """dominant_risk_band=None -> sd-heartbeat__tick--unknown."""
    cells = [_make_cell(date(2026, 5, 1), dominant_risk_band=None)]
    html = _render(app, cells=cells)

    assert "sd-heartbeat__tick--unknown" in html, (
        f"None-Band soll '--unknown' erzeugen. HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 6 — 'unknown' (String) -> unknown
# ---------------------------------------------------------------------------


def test_band_mapping_unknown_for_string_unknown(app: Flask) -> None:
    """dominant_risk_band='unknown' (String) -> sd-heartbeat__tick--unknown.

    Per ADR-0035-Mapping zaehlt der Backend-explizite 'unknown'-String genauso
    wie None als unbekannter Zustand — beide rendern --unknown.
    """
    cells = [_make_cell(date(2026, 5, 1), dominant_risk_band="unknown")]
    html = _render(app, cells=cells)

    assert "sd-heartbeat__tick--unknown" in html, (
        f"Band-String 'unknown' muss --unknown rendern (Spec ADR-0035). HTML: {html!r}"
    )
    assert "sd-heartbeat__tick--nominal" not in html, (
        f"Band-String 'unknown' darf NICHT auf --nominal fallen. HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 7 — Skeleton-State
# ---------------------------------------------------------------------------


def test_skel_state_renders_30_skel_ticks(app: Flask) -> None:
    """Skeleton-State (skel=True) rendert 30 sd-heartbeat__tick--skel-Spans.

    Kein data-band/data-day/data-had-scan auf Skel-Ticks.
    Container hat sd-skel-frame.
    """
    cells = _make_30_cells()  # cells irrelevant bei skel=True
    html = _render(app, cells=cells, skel=True)

    # 30 Skel-Ticks
    skel_count = html.count("sd-heartbeat__tick--skel")
    assert skel_count == 30, (
        f"Erwartet 30 sd-heartbeat__tick--skel-Spans bei skel=True, gefunden {skel_count}. "
        f"HTML-Ausschnitt: {html[:600]!r}"
    )

    # Keine data-band/data-day/data-had-scan auf Skel-Ticks
    assert "data-band=" not in html, (
        f"Skel-State darf kein data-band-Attribut haben. HTML: {html[:600]!r}"
    )
    assert "data-day=" not in html, (
        f"Skel-State darf kein data-day-Attribut haben. HTML: {html[:600]!r}"
    )
    assert "data-had-scan=" not in html, (
        f"Skel-State darf kein data-had-scan-Attribut haben. HTML: {html[:600]!r}"
    )

    # Container hat sd-skel-frame
    assert "sd-skel-frame" in html, (
        f"Skel-Container soll 'sd-skel-frame'-Klasse haben. HTML: {html[:400]!r}"
    )

    # Keine Live-Band-Klassen
    for live_cls in ("--escalate", "--act", "--nominal", "--unknown"):
        assert f"sd-heartbeat__tick{live_cls}" not in html, (
            f"Skel-State darf kein '{live_cls}' in Tick-Klassen haben. HTML: {html[:600]!r}"
        )


# ---------------------------------------------------------------------------
# Test 8 — Live-Ticks haben data-Attribute
# ---------------------------------------------------------------------------


def test_live_ticks_have_data_attributes(app: Flask) -> None:
    """Live-Pfad (skel=False) mit 1 Cell: Tick hat data-day, data-band, data-had-scan."""
    target_day = date(2026, 5, 24)
    cells = [_make_cell(target_day, dominant_risk_band="escalate", had_scan=True)]
    html = _render(app, cells=cells, skel=False)

    assert f'data-day="{target_day.isoformat()}"' in html, (
        f"data-day='{target_day.isoformat()}' fehlt im Live-Tick. HTML: {html!r}"
    )
    assert 'data-band="escalate"' in html, (
        f"data-band='escalate' fehlt im Live-Tick. HTML: {html!r}"
    )
    assert 'data-had-scan="1"' in html, (
        f"data-had-scan='1' fehlt im Live-Tick (had_scan=True). HTML: {html!r}"
    )


def test_live_ticks_had_scan_false_renders_zero(app: Flask) -> None:
    """had_scan=False -> data-had-scan='0'."""
    cells = [_make_cell(date(2026, 5, 24), dominant_risk_band=None, had_scan=False)]
    html = _render(app, cells=cells, skel=False)

    assert 'data-had-scan="0"' in html, (
        f"data-had-scan='0' fehlt bei had_scan=False. HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 9 — Legende hat vier Swatches in Reihenfolge
# ---------------------------------------------------------------------------


def test_legend_has_four_swatches(app: Flask) -> None:
    """Legende enthaelt vier sd-legend-swatch-Elemente in Design-Reihenfolge
    unknown -> nominal -> act -> escalate (Schweregrad aufsteigend, von links
    nach rechts gelesen). Siehe docs/design/ServerDetail.jsx Z. 358-363."""
    cells = _make_30_cells()
    html = _render(app, cells=cells)

    # Gesamtanzahl der Swatches
    swatch_count = html.count("sd-legend-swatch sd-legend-swatch--")
    assert swatch_count == 4, (
        f"Erwartet 4 sd-legend-swatch--<band>-Elemente, gefunden {swatch_count}. "
        f"HTML (Legende): {html!r}"
    )

    # Reihenfolge: unknown -> nominal -> act -> escalate (Design-treu).
    expected_order = ["--unknown", "--nominal", "--act", "--escalate"]
    positions = []
    for swatch in expected_order:
        full = f"sd-legend-swatch{swatch}"
        assert full in html, f"'{full}' fehlt in der Legende. HTML: {html!r}"
        positions.append(html.index(full))

    for i in range(len(positions) - 1):
        assert positions[i] < positions[i + 1], (
            f"Legenden-Reihenfolge falsch: '{expected_order[i]}' (pos {positions[i]}) "
            f"soll VOR '{expected_order[i + 1]}' (pos {positions[i + 1]}) stehen."
        )


# ---------------------------------------------------------------------------
# Test 10 — data-test="heartbeat-frame"-Anker
# ---------------------------------------------------------------------------


def test_heartbeat_frame_data_test_anchor_present(app: Flask) -> None:
    """Output enthaelt data-test="heartbeat-frame"."""
    cells = _make_30_cells()
    html = _render(app, cells=cells)

    assert 'data-test="heartbeat-frame"' in html, (
        f"'data-test=\"heartbeat-frame\"' fehlt im Output. HTML-Ausschnitt: {html[:400]!r}"
    )
