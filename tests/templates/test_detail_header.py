"""Pure-Unit-Tests fuer den Header-Abschnitt von servers/detail.html (Block X Phase A).

Prueft:
  1. OS-Zeile enthaelt kein 'letzter scan' mehr (Phase A Task A1).
  2. Sysline rendert die drei Segmente in dokumentierter Reihenfolge:
     expected interval · last scan · trivy-db.
  3. Sysline-Segment 2 zeigt 'never' wenn server.last_scan_at=None.
  4. Sysline-Segment 3 zeigt 'unknown' wenn server.trivy_db_updated_at=None.
  5. <time>-Elemente mit datetime- und title-Attributen korrekt gerendert.
  6. Altes <dl class="grid grid-cols-2 md:grid-cols-4"> und KEV-/Intervall-Labels
     sind aus dem Template entfernt (Phase A Task A2).
  7. Hashtag-Zeile (tag_links-Loop) ist in Phase A noch vorhanden (Phase B
     entfernt sie erst).

Render-Strategie:
  - Sysline-Tests 2-5: `render_template_string` mit dem verbatim-Markup aus
    dem Template. Der Flask-App-Context stellt den `relative_time`-Filter
    bereit. Ein `types.SimpleNamespace`-Mock stellt das server-Objekt.
  - Strukturelle Tests 1, 6, 7: Template-Source direkt lesen und
    Substring-Checks (wie test_server_detail_legacy_still_renders.py).
"""

from __future__ import annotations

import types
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask

# ---------------------------------------------------------------------------
# Konstanten + Pfade
# ---------------------------------------------------------------------------

_TEMPLATE_PATH = (
    Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "detail.html"
)

# Verbatim sysline-Markup aus detail.html (Z. 127-139).
# Wird via render_template_string gerendert — kein extends, kein includes.
_SYSLINE_TEMPLATE = """\
<div class="sd-sysline">
  <span class="sd-sysline__seg">
    <span class="sd-sysline__prompt">&gt;</span> expected interval <b>{{ server.expected_scan_interval_h }} h</b>
  </span>
  <span class="sd-sysline__sep">&middot;</span>
  <span class="sd-sysline__seg">
    last scan <b>{% if server.last_scan_at %}<time datetime="{{ server.last_scan_at.isoformat() }}" title="{{ server.last_scan_at.strftime('%Y-%m-%d %H:%M %Z') }}">{{ server.last_scan_at | relative_time }}</time>{% else %}never{% endif %}</b>
  </span>
  <span class="sd-sysline__sep">&middot;</span>
  <span class="sd-sysline__seg">
    trivy-db <b>{% if server.trivy_db_updated_at %}<time datetime="{{ server.trivy_db_updated_at.isoformat() }}" title="{{ server.trivy_db_updated_at.strftime('%Y-%m-%d %H:%M %Z') }}">{{ server.trivy_db_updated_at | relative_time }}</time>{% else %}unknown{% endif %}</b>
  </span>
</div>
"""

# OS-Zeile Markup aus detail.html (Z. 118-126) — fuer Render-Pruefung.
_OS_LINE_TEMPLATE = """\
<p class="font-mono text-xs opacity-60 mt-2">
  {% if server.os_pretty_name %}{{ server.os_pretty_name }}{% endif %}
  {% if server.kernel_version %}
    {% if server.os_pretty_name %}<span class="opacity-30 mx-2">·</span>{% endif %}{{ server.kernel_version }}
  {% endif %}
  {% if server.architecture %}
    {% if server.os_pretty_name or server.kernel_version %}<span class="opacity-30 mx-2">·</span>{% endif %}{{ server.architecture }}
  {% endif %}
</p>
"""

# Hashtag-Zeile Markup aus detail.html (Z. 140-155) — fuer Source-Pruefung.
_TAG_LINKS_MARKER = "font-mono text-xs mt-2 flex flex-wrap gap-x-3 gap-y-1"
_TAG_LINKS_LOOP_MARKER = "server.tag_links"
_TAG_LINK_HASH_MARKER = "#{{ link.tag.name }}"


# ---------------------------------------------------------------------------
# Helper: minimal server-Mock
# ---------------------------------------------------------------------------


def _make_server(
    *,
    expected_scan_interval_h: int = 24,
    last_scan_at: datetime | None = None,
    trivy_db_updated_at: datetime | None = None,
    os_pretty_name: str | None = "Ubuntu 24.04.2 LTS",
    kernel_version: str | None = "6.8.0-58-generic",
    architecture: str | None = "x86_64",
    tag_links: list | None = None,
) -> types.SimpleNamespace:
    """Erstellt ein minimales server-Mock-Objekt fuer Template-Renders."""
    return types.SimpleNamespace(
        id=42,
        name="test-host.example.com",
        expected_scan_interval_h=expected_scan_interval_h,
        last_scan_at=last_scan_at,
        trivy_db_updated_at=trivy_db_updated_at,
        os_pretty_name=os_pretty_name,
        kernel_version=kernel_version,
        architecture=architecture,
        tag_links=tag_links if tag_links is not None else [],
        revoked_at=None,
        retired_at=None,
        agent_version=None,
        trivy_version=None,
        host_state_snapshot_at=None,
    )


# ---------------------------------------------------------------------------
# Helper: Template-Source laden
# ---------------------------------------------------------------------------


def _load_template_source() -> str:
    """Laedt detail.html-Source direkt vom Filesystem."""
    return _TEMPLATE_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Helper: sysline und OS-Zeile rendern
# ---------------------------------------------------------------------------


def _render_sysline(app: Flask, server: types.SimpleNamespace) -> str:
    """Rendert das verbatim sysline-Markup via render_template_string.

    Flask-App-Context stellt den `relative_time`-Filter bereit.
    """
    from flask import render_template_string

    with app.test_request_context("/servers/42"):
        return render_template_string(_SYSLINE_TEMPLATE, server=server)


def _render_os_line(app: Flask, server: types.SimpleNamespace) -> str:
    """Rendert die verbatim OS-Zeile via render_template_string."""
    from flask import render_template_string

    with app.test_request_context("/servers/42"):
        return render_template_string(_OS_LINE_TEMPLATE, server=server)


# ---------------------------------------------------------------------------
# Test 1 — OS-Zeile enthaelt kein 'letzter scan'
# ---------------------------------------------------------------------------


def test_os_line_omits_letzter_scan(app: Flask) -> None:
    """OS-Zeile (Z. ~118-126) darf kein 'letzter scan' enthalten.

    Phase A Task A1 hat 'letzter scan' aus der OS-Zeile entfernt —
    dieser Wert wandert in die neue Sysline. Der String-Check prueft
    sowohl die Template-Source (Regression bei kuenftigem Umbau)
    als auch den gerendertenOS-Zeilen-Output.
    """
    # Source-Level-Check: 'letzter scan' darf in der OS-Zeile nicht vorkommen.
    source = _load_template_source()
    # Der alte Code hatte innerhalb des <p class="font-mono text-xs …">-Blocks
    # einen 'letzter scan'-Eintrag. Einfache String-Suche genfuegt —
    # 'letzter scan' ist deutsch und nur im alten Kontext vorgekommen.
    assert "letzter scan" not in source, (
        "'letzter scan' ist noch im Template-Source vorhanden. "
        "Phase A Task A1 soll diesen String aus der OS-Zeile entfernt haben. "
        f"Vorkommen in Source: {source.count('letzter scan')}x"
    )

    # Render-Check: auch der gerenderte OS-Zeilen-Output enthaelt keinen
    # deutschen 'letzter scan'-String.
    server = _make_server(
        last_scan_at=datetime(2026, 5, 20, 10, 0, 0, tzinfo=UTC),
    )
    html = _render_os_line(app, server)
    assert "letzter scan" not in html, (
        f"OS-Zeile darf kein 'letzter scan' rendern. OS-Zeilen-HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 2 — Sysline rendert drei Segmente in dokumentierter Reihenfolge
# ---------------------------------------------------------------------------


def test_sysline_renders_three_segments_in_documented_order(app: Flask) -> None:
    """Sysline rendert expected interval · last scan · trivy-db in dieser Reihenfolge.

    Prueft:
    - class="sd-sysline" ist im Output.
    - Index(expected interval) < Index(last scan) < Index(trivy-db).
    - expected_scan_interval_h-Wert (24) erscheint im Output.
    - sd-sysline__prompt, sd-sysline__seg, sd-sysline__sep sind als
      Klassen-Strings im Output.
    """
    server = _make_server(
        expected_scan_interval_h=24,
        last_scan_at=datetime(2026, 5, 20, 10, 0, 0, tzinfo=UTC),
        trivy_db_updated_at=datetime(2026, 5, 21, 8, 0, 0, tzinfo=UTC),
    )
    html = _render_sysline(app, server)

    # Wrapper-Klasse
    assert 'class="sd-sysline"' in html, f"class='sd-sysline' fehlt im Render. HTML: {html!r}"

    # Segment-Klassen
    for cls in ("sd-sysline__seg", "sd-sysline__sep", "sd-sysline__prompt"):
        assert cls in html, f"Klasse '{cls}' fehlt im Sysline-Render. HTML: {html[:400]!r}"

    # interval-Wert sichtbar
    assert "24" in html, f"expected_scan_interval_h=24 fehlt im Render. HTML: {html!r}"
    assert " h" in html, f"' h'-Einheit fehlt im Render. HTML: {html!r}"

    # Reihenfolge: expected interval < last scan < trivy-db
    idx_interval = html.index("expected interval")
    idx_last_scan = html.index("last scan")
    idx_trivy_db = html.index("trivy-db")

    assert idx_interval < idx_last_scan, (
        f"'expected interval' soll vor 'last scan' kommen. "
        f"idx_interval={idx_interval}, idx_last_scan={idx_last_scan}"
    )
    assert idx_last_scan < idx_trivy_db, (
        f"'last scan' soll vor 'trivy-db' kommen. "
        f"idx_last_scan={idx_last_scan}, idx_trivy_db={idx_trivy_db}"
    )


# ---------------------------------------------------------------------------
# Test 3 — last_scan_at=None rendert 'never'
# ---------------------------------------------------------------------------


def test_sysline_last_scan_renders_never_when_null(app: Flask) -> None:
    """server.last_scan_at=None -> Sysline-Segment 2 enthaelt 'never'.

    Kein <time>-Element darf fuer last_scan gerendert werden wenn None.
    """
    server = _make_server(
        last_scan_at=None,
        trivy_db_updated_at=datetime(2026, 5, 21, 8, 0, 0, tzinfo=UTC),
    )
    html = _render_sysline(app, server)

    assert "never" in html, f"'never' fehlt wenn last_scan_at=None. HTML: {html!r}"

    # Kein <time>-Element fuer last_scan wenn None.
    # Vorsicht: trivy_db_updated_at ist gesetzt -> ein <time> ist OK.
    # Wir pruefen: der 'last scan'-Kontext enthaelt kein <time>.
    # Strategie: extrahiere den Substring zwischen 'last scan' und 'trivy-db'.
    idx_last_scan = html.index("last scan")
    idx_trivy_db = html.index("trivy-db")
    last_scan_segment = html[idx_last_scan:idx_trivy_db]

    assert "<time" not in last_scan_segment, (
        f"<time>-Element darf nicht im last-scan-Segment erscheinen wenn "
        f"last_scan_at=None. Segment: {last_scan_segment!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — trivy_db_updated_at=None rendert 'unknown'
# ---------------------------------------------------------------------------


def test_sysline_trivy_db_renders_unknown_when_null(app: Flask) -> None:
    """server.trivy_db_updated_at=None -> Sysline-Segment 3 enthaelt 'unknown'.

    Kein <time>-Element darf fuer trivy-db gerendert werden wenn None.
    """
    server = _make_server(
        last_scan_at=datetime(2026, 5, 20, 10, 0, 0, tzinfo=UTC),
        trivy_db_updated_at=None,
    )
    html = _render_sysline(app, server)

    assert "unknown" in html, f"'unknown' fehlt wenn trivy_db_updated_at=None. HTML: {html!r}"

    # Kein <time>-Element fuer trivy-db wenn None.
    # Extrahiere den Substring ab 'trivy-db'.
    idx_trivy_db = html.index("trivy-db")
    trivy_segment = html[idx_trivy_db:]

    assert "<time" not in trivy_segment, (
        f"<time>-Element darf nicht im trivy-db-Segment erscheinen wenn "
        f"trivy_db_updated_at=None. Segment: {trivy_segment!r}"
    )


# ---------------------------------------------------------------------------
# Test 5 — <time>-Elemente mit isoformat() datetime und strftime() title
# ---------------------------------------------------------------------------


def test_sysline_time_tooltip_uses_iso_and_strftime(app: Flask) -> None:
    """Beide Timestamps gesetzt -> zwei <time datetime=...>-Elemente mit
    passendem title='%Y-%m-%d %H:%M %Z'-Format.

    ADR-0038 verlangt Tooltips mit absolutem Zeitstempel auf <time>-Elementen.
    """
    ts_scan = datetime(2026, 5, 20, 10, 30, 0, tzinfo=UTC)
    ts_trivy = datetime(2026, 5, 21, 8, 15, 0, tzinfo=UTC)

    server = _make_server(
        last_scan_at=ts_scan,
        trivy_db_updated_at=ts_trivy,
    )
    html = _render_sysline(app, server)

    # Zwei <time>-Elemente
    time_count = html.count("<time ")
    assert time_count == 2, (
        f"Zwei <time>-Elemente erwartet (last_scan + trivy_db), "
        f"gefunden: {time_count}. HTML: {html!r}"
    )

    # datetime-Attribute mit ISO-Format
    assert f'datetime="{ts_scan.isoformat()}"' in html, (
        f"datetime='{ts_scan.isoformat()}' fehlt im Render. HTML: {html!r}"
    )
    assert f'datetime="{ts_trivy.isoformat()}"' in html, (
        f"datetime='{ts_trivy.isoformat()}' fehlt im Render. HTML: {html!r}"
    )

    # title-Attribute mit strftime-Format '%Y-%m-%d %H:%M %Z'
    expected_title_scan = ts_scan.strftime("%Y-%m-%d %H:%M %Z")
    expected_title_trivy = ts_trivy.strftime("%Y-%m-%d %H:%M %Z")

    assert f'title="{expected_title_scan}"' in html, (
        f"title='{expected_title_scan}' fehlt im last_scan-time-Element. HTML: {html!r}"
    )
    assert f'title="{expected_title_trivy}"' in html, (
        f"title='{expected_title_trivy}' fehlt im trivy_db-time-Element. HTML: {html!r}"
    )


# ---------------------------------------------------------------------------
# Test 6 — altes dl-Meta-Grid ist entfernt
# ---------------------------------------------------------------------------


def test_dl_meta_grid_removed(app: Flask) -> None:
    """Das alte <dl class="grid grid-cols-2 md:grid-cols-4 gap-4 ...">-Element
    und seine deutschen Labels sind aus detail.html entfernt (Phase A Task A2).

    Negativ-Test-Vorsicht: 'trivy-db' (lowercase) ist Teil der neuen Sysline.
    Daher wird die Original-Casing aus dem alten <dl> geprueft:
    'Trivy-DB' (capital T+D), 'KEV-Ereignisse', 'Erwarteter Intervall'.
    """
    source = _load_template_source()

    # grid grid-cols-2 md:grid-cols-4 — das alte DL-Grid-Markup
    assert "grid-cols-2 md:grid-cols-4" not in source, (
        "'grid-cols-2 md:grid-cols-4' ist noch im Template-Source. "
        "Das alte <dl>-Meta-Grid soll in Phase A entfernt worden sein. "
        f"Vorkommen: {source.count('grid-cols-2 md:grid-cols-4')}x"
    )

    # Alte deutsche Labels aus dem <dl>-Block (Gross-/Kleinschreibung wie im alten Code)
    old_labels = [
        "KEV-Ereignisse",
        "Erwarteter Intervall",
    ]
    for label in old_labels:
        assert label not in source, (
            f"Altes Label '{label}' ist noch im Template-Source. "
            f"Das alte <dl>-Meta-Grid soll in Phase A entfernt worden sein. "
            f"Vorkommen: {source.count(label)}x"
        )

    # 'KEV-Ereignisse · 50T' als zusammengesetztes Label
    assert "50T" not in source or "KEV-Ereignisse" not in source, (
        "'KEV-Ereignisse · 50T'-Label aus dem alten <dl> ist noch vorhanden. "
        "Phase A Task A2 soll dieses Label entfernt haben."
    )

    # '<dt>Trivy-DB</dt>' war ein <dt>-Label im alten Grid.
    # 'Trivy-DB' kann im Template-Source als Badge-Tooltip-Text vorkommen —
    # daher prueft dieser Check explizit das <dt>-Wrapping, nicht blossen
    # Substring-Match. Die neue Sysline verwendet 'trivy-db' (lowercase).
    assert "<dt>Trivy-DB</dt>" not in source, (
        "'<dt>Trivy-DB</dt>' ist noch im Template-Source. "
        "Das war ein <dt>-Label im alten Meta-Grid. "
        "Hinweis: 'trivy-db' (lowercase) in der neuen Sysline ist OK."
    )


# ---------------------------------------------------------------------------
# Test 7 — Hashtag-Zeile ist in Phase A noch vorhanden
# ---------------------------------------------------------------------------


def test_hashtag_zeile_still_renders_in_phase_a(app: Flask) -> None:
    """Phase A entfernt die Tag-Hashtag-Zeile NICHT (das ist erst Phase B).

    Prueft, dass das tag_links-Loop-Markup noch im Template-Source vorhanden
    ist. Sichert: Implementer hat in Phase A nicht versehentlich Phase-B-
    Markup mit entfernt.

    Geprueft werden:
    - Das server.tag_links-Conditional im Source.
    - Der Hashtag-Link-Loop (#{{ link.tag.name }}).
    - Die font-mono text-xs mt-2 flex flex-wrap-Klassen der Hashtag-<p>.
    """
    source = _load_template_source()

    assert _TAG_LINKS_LOOP_MARKER in source, (
        f"'{_TAG_LINKS_LOOP_MARKER}' fehlt im Template-Source. "
        "Die Hashtag-Zeile wird erst in Phase B entfernt — "
        "Phase A darf dieses Markup nicht anfassen. "
        f"Template-Pfad: {_TEMPLATE_PATH}"
    )

    assert _TAG_LINK_HASH_MARKER in source, (
        f"'{_TAG_LINK_HASH_MARKER}' fehlt im Template-Source. "
        "Das Hashtag-Link-Markup soll in Phase A noch vorhanden sein. "
        f"Template-Pfad: {_TEMPLATE_PATH}"
    )

    assert _TAG_LINKS_MARKER in source, (
        f"'font-mono text-xs mt-2 flex flex-wrap'-Klassen der Hashtag-<p> "
        f"fehlen im Template-Source. Phase A entfernt die Hashtag-Zeile nicht. "
        f"Template-Pfad: {_TEMPLATE_PATH}"
    )
