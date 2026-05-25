"""Pure-Unit-Tests fuer ``_partials/action_required_pill.html`` (Block X Phase G, ADR-0038 §G1).

Prueft (DoD-Punkt 7, Block X Phase G):
  1.  Pill rendert bei escalate-only (yes_subcounts={'escalate': 3}).
  2.  Pill rendert bei act-only (yes_subcounts={'act': 2}).
  3.  Pill rendert bei escalate + act kombiniert.
  4.  Pill rendert NICHT bei pending-only.
  5.  Pill rendert NICHT bei unknown-only.
  6.  Pill rendert NICHT bei yes_subcounts={} + snapshot_missing=False.
  7.  Pill rendert NICHT bei monitor/noise-only (kein Safe-Pill, Spec §G1).
  8.  Pill rendert update-agent-Variante bei snapshot_missing=True + kein Alert.
  9.  Alert hat Vorrang vor update-agent wenn escalate > 0 + snapshot_missing=True.
  10. Scan-Chars-Markup im Alert-Output: scan-chars-Container + scan-flash-Spans.
  11. Pill nutzt sd-status-pill-Klasse, KEIN badge-Tailwind-Markup.
  12. Tooltip listet Sub-Counter in Band-Reihenfolge (escalate · act · mitigate).

Render-Strategie:
  - ``render_template_string`` mit verbatim-Source von
    ``_partials/action_required_pill.html``.
  - Flask-Loader muss ``_macros.html`` finden — daher wird
    ``app.jinja_env.from_string`` nach Source-Read verwendet statt
    ``render_template_string``, damit Macro-Import via Flask-Template-Loader
    aufgeloest wird.
  - Keine DB, keine externen Services.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask

# ---------------------------------------------------------------------------
# Pfad zum Partial
# ---------------------------------------------------------------------------

_PARTIAL_PATH = (
    Path(__file__).parent.parent.parent
    / "app"
    / "templates"
    / "_partials"
    / "action_required_pill.html"
)


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _load_partial_source() -> str:
    """Laedt action_required_pill.html-Source direkt vom Filesystem."""
    return _PARTIAL_PATH.read_text(encoding="utf-8")


def _render_pill(
    app: Flask,
    *,
    yes_subcounts: dict[str, int] | None = None,
    no_subcounts: dict[str, int] | None = None,
    snapshot_missing: bool = False,
) -> str:
    """Rendert action_required_pill.html via Flask-Jinja-Env (Macro-Import benoetigt Loader).

    Verwendet app.jinja_env.from_string damit ``{% from "_macros.html" import ... %}``
    ueber den echten Flask-Template-Loader aufgeloest wird.
    """
    source = _load_partial_source()
    ctx: dict[str, object] = {
        "yes_subcounts": yes_subcounts or {},
        "no_subcounts": no_subcounts or {},
        "snapshot_missing": snapshot_missing,
        # yes_count / no_count werden im Pill-Template nicht direkt genutzt
        # (nur yes_subcounts.get()), aber wir uebergeben sie sicherheitshalber.
        "yes_count": sum((yes_subcounts or {}).values()),
        "no_count": sum((no_subcounts or {}).values()),
    }
    with app.test_request_context("/"):
        tmpl = app.jinja_env.from_string(source)
        return tmpl.render(**ctx)


# ===========================================================================
# Test 1 — escalate-only rendert Pill
# ===========================================================================


def test_pill_renders_when_escalate_only(app: Flask) -> None:
    """Render mit escalate=3: data-test='action-required-pill-needed' + sd-status-pill-Klasse."""
    html = _render_pill(app, yes_subcounts={"escalate": 3})

    assert 'data-test="action-required-pill-needed"' in html, (
        f"Pill muss bei escalate=3 rendern (action-required-pill-needed fehlt). HTML: {html!r}"
    )
    # Track G: Pill nutzt sd-status-pill (kein --alert-Modifier mehr; Variante ist eine Klasse).
    assert "sd-status-pill" in html, f"sd-status-pill-Klasse fehlt bei escalate=3. HTML: {html!r}"


# ===========================================================================
# Test 2 — act-only rendert Pill
# ===========================================================================


def test_pill_renders_when_act_only(app: Flask) -> None:
    """Render mit act=2: Pill rendert."""
    html = _render_pill(app, yes_subcounts={"act": 2})

    assert 'data-test="action-required-pill-needed"' in html, (
        f"Pill muss bei act=2 rendern. HTML: {html!r}"
    )
    assert "sd-status-pill" in html, f"sd-status-pill fehlt bei act=2. HTML: {html!r}"


# ===========================================================================
# Test 3 — escalate + act kombiniert rendert Pill
# ===========================================================================


def test_pill_renders_when_escalate_and_act(app: Flask) -> None:
    """Render mit escalate=1 + act=2: Pill rendert."""
    html = _render_pill(app, yes_subcounts={"escalate": 1, "act": 2})

    assert 'data-test="action-required-pill-needed"' in html, (
        f"Pill muss bei escalate=1+act=2 rendern. HTML: {html!r}"
    )
    assert "sd-status-pill" in html, f"sd-status-pill fehlt bei escalate=1+act=2. HTML: {html!r}"


# ===========================================================================
# Test 4 — pending-only: Pill rendert NICHT
# ===========================================================================


def test_pill_does_not_render_when_pending_only(app: Flask) -> None:
    """Render mit pending=5: kein Pill-Markup (weder needed noch update-agent)."""
    html = _render_pill(app, yes_subcounts={"pending": 5}, snapshot_missing=False)

    assert 'data-test="action-required-pill-needed"' not in html, (
        f"pending-only darf KEINE action-required-pill-needed rendern. HTML: {html!r}"
    )
    assert 'data-test="action-required-pill-update-agent"' not in html, (
        f"pending-only darf KEINE update-agent-Pill rendern. HTML: {html!r}"
    )
    # Sicherheitsnetz: kein pill-data-test-Anker irgendwelcher Art
    assert 'data-test="action-required-pill' not in html, (
        f"pending-only darf KEIN action-required-pill-Markup rendern. HTML: {html!r}"
    )


# ===========================================================================
# Test 5 — unknown-only: Pill rendert NICHT
# ===========================================================================


def test_pill_does_not_render_when_unknown_only(app: Flask) -> None:
    """Render mit unknown=3: kein Pill-Markup."""
    html = _render_pill(app, yes_subcounts={"unknown": 3}, snapshot_missing=False)

    assert 'data-test="action-required-pill' not in html, (
        f"unknown-only darf KEIN action-required-pill-Markup rendern. HTML: {html!r}"
    )


# ===========================================================================
# Test 6 — leere subcounts + snapshot_missing=False: Pill rendert NICHT
# ===========================================================================


def test_pill_does_not_render_when_all_zero(app: Flask) -> None:
    """Render mit yes_subcounts={} + snapshot_missing=False: kein Markup."""
    html = _render_pill(app, yes_subcounts={}, no_subcounts={}, snapshot_missing=False)

    assert 'data-test="action-required-pill' not in html, (
        f"Leere Subcounts + snapshot_missing=False: kein Pill-Markup erwartet. HTML: {html!r}"
    )


# ===========================================================================
# Test 7 — monitor/noise-only: Pill rendert NICHT (kein 'Safe'-Pill, Spec §G1)
# ===========================================================================


def test_pill_does_not_render_when_only_monitor_noise(app: Flask) -> None:
    """Render mit no_subcounts={monitor:5, noise:10}, yes_subcounts={}: kein Pill.

    Spec §G1: kein 'Safe'-Pill mehr — Server wirkt visuell ruhig.
    """
    html = _render_pill(
        app,
        yes_subcounts={},
        no_subcounts={"monitor": 5, "noise": 10},
        snapshot_missing=False,
    )

    assert 'data-test="action-required-pill' not in html, (
        f"monitor/noise-only darf KEIN action-required-pill-Markup rendern. "
        f"Kein Safe-Pill laut Spec §G1. HTML: {html!r}"
    )
    # Explizit: keine safe-Variante
    assert "sd-status-pill--safe" not in html, (
        f"sd-status-pill--safe darf nicht rendern (entfernt in Block X). HTML: {html!r}"
    )


# ===========================================================================
# Test 8 — snapshot_missing=True + kein Alert: update-agent-Pill
# ===========================================================================


def test_pill_renders_update_agent_when_snapshot_missing_and_no_alert(app: Flask) -> None:
    """Render mit snapshot_missing=True + yes_subcounts={}: update-agent-Pill rendert."""
    html = _render_pill(app, yes_subcounts={}, snapshot_missing=True)

    assert 'data-test="action-required-pill-update-agent"' in html, (
        f"update-agent-Pill muss bei snapshot_missing=True + kein Alert rendern. HTML: {html!r}"
    )
    assert 'data-test="action-required-pill-needed"' not in html, (
        f"action-required-pill-needed darf bei kein-Alert + snapshot_missing NICHT rendern. "
        f"HTML: {html!r}"
    )


# ===========================================================================
# Test 9 — Alert hat Vorrang vor update-agent
# ===========================================================================


def test_pill_renders_needed_when_alert_and_snapshot_missing(app: Flask) -> None:
    """Render mit escalate=1 + snapshot_missing=True: action-required-pill-needed, NICHT update-agent."""
    html = _render_pill(app, yes_subcounts={"escalate": 1}, snapshot_missing=True)

    assert 'data-test="action-required-pill-needed"' in html, (
        f"action-required-pill-needed fehlt bei escalate=1 + snapshot_missing=True. HTML: {html!r}"
    )
    assert 'data-test="action-required-pill-update-agent"' not in html, (
        f"update-agent-Pill darf bei Alert-Vorrang NICHT rendern. HTML: {html!r}"
    )


# ===========================================================================
# Test 10 — Scan-Chars-Markup im Alert-Output
# ===========================================================================


def test_pill_contains_scan_chars_markup(app: Flask) -> None:
    """Bei Alert: Output enthaelt scan-chars-Container + mindestens einen scan-flash-Span.

    Der Text 'action needed' muss als Per-Char-Spans zerlegt sein.
    """
    html = _render_pill(app, yes_subcounts={"escalate": 1})

    assert 'class="scan-chars"' in html, (
        f"scan-chars-Container fehlt im Alert-Output. HTML: {html!r}"
    )
    assert 'class="scan-flash"' in html, (
        f"scan-flash-Spans fehlen im Alert-Output (Per-Char-Zerlegung). HTML: {html!r}"
    )
    # 'action needed' hat 13 Zeichen (inkl. Leerzeichen) -> mindestens 13 scan-flash-Spans
    # (Leerzeichen wird als &nbsp; oder Space gerendert, daher >= 13).
    flash_count = html.count('class="scan-flash"')
    assert flash_count >= 13, (
        f"'action needed' (13 Chars) muss >= 13 scan-flash-Spans erzeugen, "
        f"hat {flash_count} erzeugt. HTML: {html!r}"
    )


# ===========================================================================
# Test 11 — sd-status-pill-Klasse statt Tailwind-badge
# ===========================================================================


def test_pill_uses_sd_status_pill_class_not_tailwind_badge(app: Flask) -> None:
    """Bei Alert: Output enthaelt sd-status-pill-Klasse, KEIN badge badge-sm badge-error."""
    html = _render_pill(app, yes_subcounts={"act": 1})

    assert "sd-status-pill" in html, f"sd-status-pill-Klasse fehlt im Alert-Output. HTML: {html!r}"
    # Alte Tailwind-DaisyUI-Klassen duerfen nicht mehr vorkommen.
    assert "badge badge-sm badge-error" not in html, (
        f"Alte Tailwind-Klasse 'badge badge-sm badge-error' ist noch im Output. "
        f"Block X Phase G erfordert sd-status-pill. HTML: {html!r}"
    )
    assert "badge-sm" not in html, (
        f"Tailwind 'badge-sm' noch im Output (Block X Phase G: sd-status-pill). HTML: {html!r}"
    )


# ===========================================================================
# Test 12 — Tooltip listet Sub-Counter in Band-Reihenfolge
# ===========================================================================


def test_pill_tooltip_lists_sub_counters_in_band_order(app: Flask) -> None:
    """Tooltip-title enthaelt '2 escalate · 1 act · 5 mitigate' in Reihenfolge."""
    html = _render_pill(app, yes_subcounts={"escalate": 2, "act": 1, "mitigate": 5})

    # Tooltip als title-Attribut suchen
    assert "2 escalate" in html, f"'2 escalate' fehlt im Tooltip-title. HTML: {html!r}"
    assert "1 act" in html, f"'1 act' fehlt im Tooltip-title. HTML: {html!r}"
    assert "5 mitigate" in html, f"'5 mitigate' fehlt im Tooltip-title. HTML: {html!r}"

    # Reihenfolge: escalate vor act vor mitigate
    pos_escalate = html.index("2 escalate")
    pos_act = html.index("1 act")
    pos_mitigate = html.index("5 mitigate")

    assert pos_escalate < pos_act, (
        f"'escalate' (pos {pos_escalate}) muss VOR 'act' (pos {pos_act}) stehen. HTML: {html!r}"
    )
    assert pos_act < pos_mitigate, (
        f"'act' (pos {pos_act}) muss VOR 'mitigate' (pos {pos_mitigate}) stehen. HTML: {html!r}"
    )

    # Trennzeichen · zwischen den Eintraegen
    assert " · " in html, f"' · '-Trennzeichen zwischen Sub-Countern fehlt. HTML: {html!r}"
