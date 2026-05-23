"""Pure-Unit Template-Smoke-Tests fuer dashboard/_triage_row.html.

Block W Phase E.

Prueft:
- Genau 7 Cells in der Design-Reihenfolge (escalate, act, mitigate, pending,
  monitor, noise, unknown) via data-test-Attribute.
- escalate/act tragen triage__cell--accent wenn count > 0.
- Kein triage__cell--accent wenn count == 0.
- Jede Cell-href enthaelt risk_band=<bucket>-Query-Param.
- count=0 -> triage__cell-num--zero-Klasse.
- Wrapper-ID ist 'triage-row' (Phase-F-OOB-Target).

Render-Pattern: Flask-App mit test_request_context + jinja_env.get_template().
_MOCK_MANIFEST verhindert Manifest-Lookup auf Disk.
"""

from __future__ import annotations

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}

_DESIGN_ORDER = ("escalate", "act", "mitigate", "pending", "monitor", "noise", "unknown")

_DEFAULT_TRIAGE_COUNTS: dict[str, int] = {
    "escalate": 5,
    "act": 3,
    "mitigate": 2,
    "pending": 1,
    "monitor": 7,
    "noise": 4,
    "unknown": 0,
}

_ALL_ZERO_TRIAGE_COUNTS: dict[str, int] = dict.fromkeys(_DESIGN_ORDER, 0)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _render_triage_row(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    triage_counts: dict[str, int] | None = None,
) -> str:
    """Rendert dashboard/_triage_row.html mit Mock-Daten."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    counts = triage_counts if triage_counts is not None else _DEFAULT_TRIAGE_COUNTS

    with app.test_request_context("/"):
        template = app.jinja_env.get_template("dashboard/_triage_row.html")
        html = template.render(triage_counts=counts)
    return html


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_triage_row_renders_7_cells_in_design_order(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render enthaelt genau 7 Cells in der Design-Reihenfolge via data-test-Attribut.

    Reihenfolge: escalate, act, mitigate, pending, monitor, noise, unknown.
    """
    html = _render_triage_row(app, monkeypatch)

    # Alle 7 data-test-Marker muessen vorhanden sein.
    for bucket in _DESIGN_ORDER:
        marker = f'data-test="triage-cell-{bucket}"'
        assert marker in html, (
            f"data-test='triage-cell-{bucket}' fehlt im Render. HTML-Ausschnitt: {html[:600]}"
        )

    # Reihenfolge pruefen: jeder Marker muss vor dem naechsten erscheinen.
    positions = [html.index(f'data-test="triage-cell-{b}"') for b in _DESIGN_ORDER]
    assert positions == sorted(positions), (
        f"Triage-Cells sind nicht in Design-Reihenfolge. "
        f"Gefundene Positionen (Bucket: Pos): {dict(zip(_DESIGN_ORDER, positions, strict=False))}"
    )


def test_triage_cell_accent_class_when_escalate_count_positive(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """escalate-Cell hat triage__cell--accent wenn count > 0 (ADR-0033 Color-Doctrine)."""
    counts = {**_ALL_ZERO_TRIAGE_COUNTS, "escalate": 5}
    html = _render_triage_row(app, monkeypatch, counts)

    # Die escalate-Cell muss triage__cell--accent tragen.
    # Wir suchen nach dem spezifischen data-test-Attribut und pruefen ob
    # triage__cell--accent in der Naehe auftaucht (innerhalb der Cell-Struktur).
    # Einfachster Ansatz: accent-Klasse muss global im HTML sein.
    assert "triage__cell--accent" in html, (
        "triage__cell--accent fehlt bei escalate=5 (count > 0). "
        "ADR-0033: escalate/act koennen accent tragen wenn count > 0."
    )


def test_triage_cell_accent_class_when_act_count_positive(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """act-Cell hat triage__cell--accent wenn count > 0 (ADR-0033 Color-Doctrine)."""
    counts = {**_ALL_ZERO_TRIAGE_COUNTS, "act": 7}
    html = _render_triage_row(app, monkeypatch, counts)

    assert "triage__cell--accent" in html, (
        "triage__cell--accent fehlt bei act=7 (count > 0). "
        "ADR-0033: escalate/act koennen accent tragen wenn count > 0."
    )


def test_triage_cell_no_accent_when_count_zero(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keine triage__cell--accent wenn alle Counts 0 sind."""
    html = _render_triage_row(app, monkeypatch, _ALL_ZERO_TRIAGE_COUNTS)

    assert "triage__cell--accent" not in html, (
        "triage__cell--accent darf nicht erscheinen wenn alle Counts 0 sind. "
        f"HTML-Ausschnitt: {html[:600]}"
    )


def test_triage_cell_links_to_findings_with_risk_band(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jede Cell-href enthaelt risk_band=<bucket>-Query-Param (ADR-0022)."""
    html = _render_triage_row(app, monkeypatch)

    for bucket in _DESIGN_ORDER:
        # url_for('findings.index', risk_band=bucket) muss im href stehen.
        assert f"risk_band={bucket}" in html, (
            f"href fuer Bucket '{bucket}' enthaelt 'risk_band={bucket}' nicht. "
            f"HTML-Ausschnitt: {html[:800]}"
        )


def test_triage_cell_zero_class_when_count_zero(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """count=0 -> triage__cell-num--zero-Klasse am Num-Element."""
    # unknown=0, alle anderen haben positive Counts.
    counts = {**_DEFAULT_TRIAGE_COUNTS, "unknown": 0}
    html = _render_triage_row(app, monkeypatch, counts)

    assert "triage__cell-num--zero" in html, (
        f"triage__cell-num--zero fehlt bei count=0. HTML-Ausschnitt: {html[:600]}"
    )


def test_triage_cell_no_zero_class_when_count_positive(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """count > 0 -> kein triage__cell-num--zero an dieser Cell."""
    # Alle Counts positiv -> keine --zero-Klasse irgendwo.
    counts = dict.fromkeys(_DESIGN_ORDER, 1)
    html = _render_triage_row(app, monkeypatch, counts)

    assert "triage__cell-num--zero" not in html, (
        "triage__cell-num--zero darf nicht erscheinen wenn alle Counts > 0 sind. "
        f"HTML-Ausschnitt: {html[:600]}"
    )


def test_triage_section_has_id_for_oob(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrapper-Section hat id='triage-row' (Phase-F-OOB-Target, ADR-0036)."""
    html = _render_triage_row(app, monkeypatch)

    assert 'id="triage-row"' in html, (
        "id='triage-row' fehlt am Wrapper-Element. "
        "Wird in Phase F als OOB-Swap-Target fuer /_partials/dashboard/kpis benoetigt. "
        f"HTML-Ausschnitt: {html[:400]}"
    )
