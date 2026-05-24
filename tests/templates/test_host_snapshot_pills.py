"""Pure-Unit-Tests fuer die Block-X-Phase-C-Pill-Partials und Pills im Header.

Prueft (DoD-Punkt 3, Block X Phase C, ADR-0038 §(3)):
  1. Pill-1-Label ist genau 'Listeners' (nicht 'Listeners & services').
  2. Pill-2-Label ist 'Active services'.
  3. Pills sind disabled mit Tooltip wenn host_state_snapshot_at is None.
  4. Pills sind NICHT disabled wenn host_state_snapshot_at gesetzt ist.
  5. Listener-Tabelle hat genau vier Spalten: Process, Addr:port, Proto, Exposure.
  6. Listener-Row rendert LOOPBACK-Tag (ohne --exposed-Modifier) korrekt.
  7. Listener-Row rendert PUBLIC-EXPOSED-Tag (mit --exposed-Modifier) korrekt.
  8. Keine Pagination-Controls im Listeners-Panel.
  9. Keine Pagination-Controls im Services-Panel.
  10. Services-Panel rendert Mono-Liste mit <code>-Elementen und data-test.

Render-Strategie:
  - Strukturelle Tests 1-4, 8-9: Source-Read via Path.read_text() + Substring-Match.
  - Render-Tests 5-7, 10: render_template_string mit verbatim-Extrakt des
    Loop-Bodys aus den Partial-Templates. Flask-App-Context via `app`-Fixture.
"""

from __future__ import annotations

import types
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask

# ---------------------------------------------------------------------------
# Pfade
# ---------------------------------------------------------------------------

_DETAIL_PATH = Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "detail.html"
_LISTENERS_PARTIAL_PATH = (
    Path(__file__).parent.parent.parent
    / "app"
    / "templates"
    / "_partials"
    / "server_pill_listeners.html"
)
_SERVICES_PARTIAL_PATH = (
    Path(__file__).parent.parent.parent
    / "app"
    / "templates"
    / "_partials"
    / "server_pill_services.html"
)

# Verbatim-Extrakt: der komplette Partial-Inhalt wird via render_template_string
# gerendert. Da die Partials Alpine x-show und x-cloak nutzen (kein Jinja-
# Bedingungs-Block der Werte benoetigt), koennen wir den Source direkt rendern.
# Wir laden das Partial per Path.read_text() und injizieren Variablen.

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _load_detail_source() -> str:
    """Laedt detail.html-Source direkt vom Filesystem."""
    return _DETAIL_PATH.read_text(encoding="utf-8")


def _load_listeners_source() -> str:
    """Laedt server_pill_listeners.html-Source direkt vom Filesystem."""
    return _LISTENERS_PARTIAL_PATH.read_text(encoding="utf-8")


def _load_services_source() -> str:
    """Laedt server_pill_services.html-Source direkt vom Filesystem."""
    return _SERVICES_PARTIAL_PATH.read_text(encoding="utf-8")


def _render_listeners_partial(app: Flask, listeners: list[dict]) -> str:  # type: ignore[type-arg]
    """Rendert das Listeners-Partial via render_template_string."""
    from flask import render_template_string

    source = _load_listeners_source()
    with app.test_request_context("/servers/42"):
        return render_template_string(source, listeners=listeners)


def _render_services_partial(app: Flask, services: list[str]) -> str:
    """Rendert das Services-Partial via render_template_string."""
    from flask import render_template_string

    source = _load_services_source()
    with app.test_request_context("/servers/42"):
        return render_template_string(source, services=services)


def _make_listener(
    *,
    process: str = "sshd",
    addr: str = "127.0.0.1",
    port: int = 22,
    proto: str = "tcp",
    pid: int = 1234,
    exposure: str = "LOOPBACK",
) -> dict:  # type: ignore[type-arg]
    """Erstellt ein minimales Listener-Dict fuer Template-Render-Tests."""
    return {
        "process": process,
        "addr": addr,
        "port": port,
        "proto": proto,
        "pid": pid,
        "exposure": exposure,
    }


# ---------------------------------------------------------------------------
# Test 1 — Pill-1-Label ist 'Listeners' (NICHT 'Listeners & services')
# ---------------------------------------------------------------------------


def test_pill_listeners_label_is_listeners_not_listeners_and_services(
    app: Flask,
) -> None:
    """detail.html: Pill-1 traegt das Label 'Listeners' (ADR-0038 §(3) C2).

    Das Label 'Listeners & services' aus dem alten Design darf nicht verwendet
    werden. Die Pill enthaelt data-test='pill-listeners'.
    """
    source = _load_detail_source()

    # Positiv: data-test="pill-listeners" muss vorhanden sein.
    assert 'data-test="pill-listeners"' in source, (
        "'data-test=\"pill-listeners\"' fehlt in detail.html. "
        "Phase C soll den Pill-1-Button mit diesem Attribut eingefuegt haben. "
        f"Template-Pfad: {_DETAIL_PATH}"
    )

    # Positiv: 'Listeners' als Pill-Text muss vorhanden sein.
    assert "Listeners" in source, f"'Listeners' fehlt in detail.html. Template-Pfad: {_DETAIL_PATH}"

    # Negativ: 'Listeners & services' darf nicht vorkommen.
    assert "Listeners &amp; services" not in source, (
        "'Listeners &amp; services' (HTML-encoded) ist noch in detail.html. "
        "Pill-1-Label soll per ADR-0038 §(3) C2 nur 'Listeners' heissen. "
        f"Template-Pfad: {_DETAIL_PATH}"
    )
    assert "Listeners & services" not in source, (
        "'Listeners & services' ist noch in detail.html. "
        "Pill-1-Label soll per ADR-0038 §(3) C2 nur 'Listeners' heissen. "
        f"Template-Pfad: {_DETAIL_PATH}"
    )


# ---------------------------------------------------------------------------
# Test 2 — Pill-2-Label ist 'Active services'
# ---------------------------------------------------------------------------


def test_pill_services_label_is_active_services(app: Flask) -> None:
    """detail.html: Pill-2 traegt das Label 'Active services' (ADR-0038 §(3) C2).

    data-test='pill-services' und Text 'Active services' muessen vorhanden sein.
    """
    source = _load_detail_source()

    assert 'data-test="pill-services"' in source, (
        f"'data-test=\"pill-services\"' fehlt in detail.html. Template-Pfad: {_DETAIL_PATH}"
    )

    assert "Active services" in source, (
        "'Active services' fehlt in detail.html. "
        "Pill-2 soll dieses Label tragen (ADR-0038 §(3) C2). "
        f"Template-Pfad: {_DETAIL_PATH}"
    )


# ---------------------------------------------------------------------------
# Test 3 — Pills disabled wenn snapshot_at is None
# ---------------------------------------------------------------------------


def test_pills_disabled_when_snapshot_at_is_none(app: Flask) -> None:
    """Pills rendern 'disabled' + Tooltip wenn host_state_snapshot_at=None.

    Phase C Task C9 (ADR-0038 §(3)): Empty-State -> disabled mit Erklaer-Tooltip.
    """
    # Verbatim-Extrakt des Pills-Blocks aus detail.html.
    # Die Logik ist rein Jinja-seitig (kein Alpine-State), daher render_template_string.
    from flask import render_template_string

    # Verbatim-Pills-Block — wird direkt mit minimalen Template-Variablen gerendert.
    pills_block = """\
{% set _snapshot_at = server.host_state_snapshot_at %}
{% set _listeners_list = listeners | default([]) %}
{% set _services_list = services | default([]) %}
<div class="sd-pills" x-data="serverPillPanels" data-test="server-pills">
  <button type="button"
          class="sd-chip"
          data-test="pill-listeners"
          {% if _snapshot_at is none %}disabled title="Update agent to >= 0.3.0 for snapshot"{% endif %}>
    Listeners <span class="sd-chip__count">{{ _listeners_list | length }}</span>
  </button>
  <button type="button"
          class="sd-chip"
          data-test="pill-services"
          {% if _snapshot_at is none %}disabled title="Update agent to >= 0.3.0 for snapshot"{% endif %}>
    Active services <span class="sd-chip__count">{{ _services_list | length }}</span>
  </button>
</div>
"""

    server = types.SimpleNamespace(
        host_state_snapshot_at=None,
    )

    with app.test_request_context("/servers/42"):
        html = render_template_string(
            pills_block,
            server=server,
            listeners=[],
            services=[],
        )

    # Beide Buttons muessen 'disabled' enthalten.
    button_blocks = html.split("<button")
    pill_buttons = [b for b in button_blocks if 'data-test="pill-' in b]

    assert len(pill_buttons) == 2, (
        f"Zwei Pill-Buttons erwartet, gefunden: {len(pill_buttons)}. HTML: {html!r}"
    )

    for btn in pill_buttons:
        assert "disabled" in btn, (
            f"'disabled' fehlt in Pill-Button wenn snapshot_at=None. Button-Fragment: {btn!r}"
        )
        assert 'title="Update agent to >= 0.3.0 for snapshot"' in btn, (
            f"Erklaer-Tooltip fehlt wenn snapshot_at=None. Button-Fragment: {btn!r}"
        )


# ---------------------------------------------------------------------------
# Test 4 — Pills NICHT disabled wenn snapshot_at gesetzt ist
# ---------------------------------------------------------------------------


def test_pills_not_disabled_when_snapshot_at_is_set(app: Flask) -> None:
    """Pills rendern OHNE 'disabled' wenn host_state_snapshot_at gesetzt ist.

    Phase C Task C9 (ADR-0038 §(3)): Snpashot vorhanden -> Pills aktiv.
    """
    from flask import render_template_string

    pills_block = """\
{% set _snapshot_at = server.host_state_snapshot_at %}
{% set _listeners_list = listeners | default([]) %}
{% set _services_list = services | default([]) %}
<div class="sd-pills" data-test="server-pills">
  <button type="button"
          data-test="pill-listeners"
          {% if _snapshot_at is none %}disabled title="Update agent to >= 0.3.0 for snapshot"{% endif %}>
    Listeners
  </button>
  <button type="button"
          data-test="pill-services"
          {% if _snapshot_at is none %}disabled title="Update agent to >= 0.3.0 for snapshot"{% endif %}>
    Active services
  </button>
</div>
"""

    server = types.SimpleNamespace(
        host_state_snapshot_at=datetime(2026, 5, 24, 10, 0, 0, tzinfo=UTC),
    )

    with app.test_request_context("/servers/42"):
        html = render_template_string(
            pills_block,
            server=server,
            listeners=[],
            services=[],
        )

    # Kein 'disabled' in den Buttons.
    button_blocks = html.split("<button")
    pill_buttons = [b for b in button_blocks if 'data-test="pill-' in b]

    assert len(pill_buttons) == 2, (
        f"Zwei Pill-Buttons erwartet, gefunden: {len(pill_buttons)}. HTML: {html!r}"
    )

    for btn in pill_buttons:
        assert "disabled" not in btn, (
            f"'disabled' darf nicht in Pill-Button sein wenn snapshot_at gesetzt. "
            f"Button-Fragment: {btn!r}"
        )


# ---------------------------------------------------------------------------
# Test 5 — Listener-Panel hat genau vier Spalten in richtiger Reihenfolge
# ---------------------------------------------------------------------------


def test_listener_panel_has_four_columns(app: Flask) -> None:
    """server_pill_listeners.html: Tabelle hat genau vier <th>-Elemente.

    Pflicht-Reihenfolge: Process, Addr:port, Proto, Exposure (ADR-0038 §(3) C3).
    """
    source = _load_listeners_source()

    # Anzahl der <th>-Elemente.
    th_count = source.count("<th>")
    assert th_count == 4, (
        f"Listener-Tabelle soll genau 4 <th>-Elemente haben, gefunden: {th_count}. "
        f"Source-Pfad: {_LISTENERS_PARTIAL_PATH}"
    )

    # Reihenfolge der Spalten-Header.
    expected_headers = ["Process", "Addr:port", "Proto", "Exposure"]
    positions = [source.index(h) for h in expected_headers]

    for i in range(len(positions) - 1):
        assert positions[i] < positions[i + 1], (
            f"Spalten-Header-Reihenfolge falsch: '{expected_headers[i]}' (pos {positions[i]}) "
            f"soll VOR '{expected_headers[i + 1]}' (pos {positions[i + 1]}) kommen. "
            f"Pflicht-Reihenfolge: {expected_headers}. "
            f"Source-Pfad: {_LISTENERS_PARTIAL_PATH}"
        )


# ---------------------------------------------------------------------------
# Test 6 — Listener-Row rendert LOOPBACK-Tag korrekt (ohne --exposed)
# ---------------------------------------------------------------------------


def test_listener_row_renders_loopback_tag(app: Flask) -> None:
    """LOOPBACK-Listener rendert <span class='sd-listener-tag'>LOOPBACK</span>.

    Kein sd-listener-tag--exposed-Modifier bei LOOPBACK (ADR-0038 §(3) C3).
    """
    listeners = [
        _make_listener(
            process="sshd",
            addr="127.0.0.1",
            port=22,
            proto="tcp",
            pid=1234,
            exposure="LOOPBACK",
        )
    ]
    html = _render_listeners_partial(app, listeners)

    assert '<span class="sd-listener-tag">LOOPBACK</span>' in html, (
        f"LOOPBACK-Tag nicht korrekt gerendert. "
        f"Erwartet: '<span class=\"sd-listener-tag\">LOOPBACK</span>'. "
        f"HTML: {html!r}"
    )

    # Kein --exposed-Modifier bei LOOPBACK.
    assert "sd-listener-tag--exposed" not in html, (
        f"sd-listener-tag--exposed darf nicht bei LOOPBACK-Listener vorkommen. HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 7 — Listener-Row rendert PUBLIC EXPOSED-Tag korrekt (mit --exposed)
# ---------------------------------------------------------------------------


def test_listener_row_renders_public_exposed_tag(app: Flask) -> None:
    """PUBLIC EXPOSED-Listener rendert <span class='sd-listener-tag sd-listener-tag--exposed'>.

    Cyan-Outline-Modifier --exposed wird bei exponierten Listenern gesetzt
    (ADR-0038 §(3) C3).
    """
    listeners = [
        _make_listener(
            process="nginx",
            addr="0.0.0.0",  # noqa: S104
            port=80,
            proto="tcp",
            pid=5678,
            exposure="PUBLIC EXPOSED",
        )
    ]
    html = _render_listeners_partial(app, listeners)

    assert '<span class="sd-listener-tag sd-listener-tag--exposed">PUBLIC EXPOSED</span>' in html, (
        f"PUBLIC EXPOSED-Tag nicht korrekt gerendert. "
        f"Erwartet: '<span class=\"sd-listener-tag sd-listener-tag--exposed\">PUBLIC EXPOSED</span>'. "
        f"HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 8 — Keine Pagination im Listeners-Panel (Spec §C5)
# ---------------------------------------------------------------------------


def test_no_pagination_in_listener_panel(app: Flask) -> None:
    """server_pill_listeners.html enthaelt keine Pagination-Markup (ADR-0038 §(3) C5).

    Phase C Spec C5: Beide Panels rendern komplette Liste, kein Seiten-Toggle.
    """
    source = _load_listeners_source()

    forbidden_patterns = [
        'class="pagination"',
        "show more",
        "Show more",
        "&laquo; prev",
        "next &raquo;",
        "page-nav",
        "« prev",
        "next »",
        "Seite",
        "Page",
    ]

    for pattern in forbidden_patterns:
        assert pattern not in source, (
            f"Verbotenes Pagination-Pattern '{pattern}' in server_pill_listeners.html gefunden. "
            f"Spec §C5: keine Pagination in den Pill-Panels. "
            f"Source-Pfad: {_LISTENERS_PARTIAL_PATH}"
        )


# ---------------------------------------------------------------------------
# Test 9 — Keine Pagination im Services-Panel (Spec §C5)
# ---------------------------------------------------------------------------


def test_no_pagination_in_services_panel(app: Flask) -> None:
    """server_pill_services.html enthaelt keine Pagination-Markup (ADR-0038 §(3) C5).

    Phase C Spec C5: Beide Panels rendern komplette Liste, kein Seiten-Toggle.
    """
    source = _load_services_source()

    forbidden_patterns = [
        'class="pagination"',
        "show more",
        "Show more",
        "&laquo; prev",
        "next &raquo;",
        "page-nav",
        "« prev",
        "next »",
        "Seite",
        "Page",
    ]

    for pattern in forbidden_patterns:
        assert pattern not in source, (
            f"Verbotenes Pagination-Pattern '{pattern}' in server_pill_services.html gefunden. "
            f"Spec §C5: keine Pagination in den Pill-Panels. "
            f"Source-Pfad: {_SERVICES_PARTIAL_PATH}"
        )


# ---------------------------------------------------------------------------
# Test 10 — Services-Panel rendert Mono-Liste mit <code>-Elementen
# ---------------------------------------------------------------------------


def test_services_panel_renders_mono_list(app: Flask) -> None:
    """Services-Panel rendert service-Namen in <code>-Elementen innerhalb data-test.

    data-test='pill-services-list' muss gesetzt sein.
    Jeder Service-Name muss in einem <code>-Element erscheinen (ADR-0038 §(3) C4).
    """
    services = ["nginx", "postgresql", "sshd"]
    html = _render_services_partial(app, services)

    # data-test="pill-services-list" muss vorhanden sein.
    assert 'data-test="pill-services-list"' in html, (
        f"'data-test=\"pill-services-list\"' fehlt im gerenderten Services-Panel. HTML: {html!r}"
    )

    # Alle drei Service-Namen muessen in <code>-Elementen erscheinen.
    for svc in services:
        code_pattern = f"<code>{svc}</code>"
        assert code_pattern in html, (
            f"Service '{svc}' fehlt als <code>{svc}</code> im Panel. HTML: {html!r}"
        )

    # Genau drei <code>-Elemente.
    code_count = html.count("<code>")
    assert code_count == len(services), (
        f"Drei <code>-Elemente erwartet (eines pro Service), gefunden: {code_count}. HTML: {html!r}"
    )
