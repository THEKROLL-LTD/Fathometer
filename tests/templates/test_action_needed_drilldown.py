"""Pure-Unit-Tests fuer das Drilldown-Tabellen-Markup in
``servers/_action_needed_section.html`` (Block X Phase D, ADR-0038 §(4) D2-D3).

Prueft (DoD-Punkt 4, Block X):
  1.  Workflow-Card-Body nutzt ``class="workflow-card__drilldown"`` (keine
      DaisyUI ``table-xs``-Klassen mehr).
  2.  Tabellen-Header hat drei Spalten in dokumentierter Reihenfolge:
      Group -> Worst Finding -> Reason.
  3.  Group-Spalte rendert Link als ``<a href="#group-<id>">``.
  4.  Worst-Finding-Spalte rendert den ``identifier_key``-String.
  5.  Worst-Finding-Spalte rendert ``<span class="opacity-50">—</span>``
      wenn ``worst_finding=None``.
  6.  Reason-Spalte rendert ``risk_band_reason``-String.
  7.  Reason-Spalte rendert Em-Dash-Span wenn ``evaluation=None``.
  8.  Reason-String wird HTML-escaped (kein ``|safe``-Leak).
  9.  Sub-Line (``data-test="…-sublist"``) ist entfernt.
  10. Sub-Line fehlt auch wenn ``show_labels=False``.
  11. Kein Pagination-Stub bei <= 25 Groups.
  12. Pagination-Stub rendert wenn 26 Groups vorhanden.
  13. Seitenanzahl-Berechnung fuer mehrere Laengen (parametrize).
  14. Beide Pagination-Buttons haben ``disabled``-Attribut.

Render-Strategie:
  - ``_load_template_source()`` fuer reine Source-Level-Substring-Checks.
  - ``flask.render_template_string`` mit verbatim-Extrakt des Card-Body-
    Loops fuer dynamisch gerendertes HTML. Da ``_action_needed_section.html``
    kein ``{% extends %}`` nutzt, wird es direkt gerendert.
  - ``types.SimpleNamespace`` als Daten-Mock (kein DB-Zugriff).
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Pfade
# ---------------------------------------------------------------------------

_TEMPLATE_PATH = (
    Path(__file__).parent.parent.parent
    / "app"
    / "templates"
    / "servers"
    / "_action_needed_section.html"
)


# ---------------------------------------------------------------------------
# Helper: Template-Source laden
# ---------------------------------------------------------------------------


def _load_template_source() -> str:
    """Laedt _action_needed_section.html-Source direkt vom Filesystem."""
    return _TEMPLATE_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Helper: Fixtures konstruieren
# ---------------------------------------------------------------------------


def _make_single_entry_card(
    *,
    card_id: str = "escalate-distro-patch",
    show_labels: bool = True,
    group_id: int = 1,
    group_label: str = "k3s",
    group_kind: str = "os_package",
    identifier_key: str | None = "CVE-2024-1234",
    risk_band_reason: str | None = "vendor (redhat) severity HIGH",
) -> dict:  # type: ignore[type-arg]
    """Erstellt eine minimale action_section-Card mit einem Group-Eintrag."""
    worst_finding = (
        SimpleNamespace(identifier_key=identifier_key) if identifier_key is not None else None
    )
    evaluation = (
        SimpleNamespace(risk_band_reason=risk_band_reason) if risk_band_reason is not None else None
    )
    return {
        "id": card_id,
        "label": "ESCALATE · Distro patchen",
        "variant": "escalate-distro",
        "filter": ("escalate", "patch", "os_package"),
        "count": 1,
        "show_labels": show_labels,
        "groups": [
            {
                "group": SimpleNamespace(id=group_id, label=group_label, group_kind=group_kind),
                "evaluation": evaluation,
                "worst_finding": worst_finding,
                "count": 5,
            }
        ],
    }


def _make_pagination_card(num_groups: int, card_id: str = "escalate-distro-patch") -> dict:  # type: ignore[type-arg]
    """Erstellt eine Card mit `num_groups` Group-Eintraegen fuer Pagination-Tests."""
    groups = [
        {
            "group": SimpleNamespace(id=i, label=f"group-{i}", group_kind="os_package"),
            "evaluation": SimpleNamespace(risk_band_reason=None),
            "worst_finding": None,
            "count": 1,
        }
        for i in range(num_groups)
    ]
    return {
        "id": card_id,
        "label": "ESCALATE · Distro patchen",
        "variant": "escalate-distro",
        "filter": ("escalate", "patch", "os_package"),
        "count": num_groups,
        "show_labels": True,
        "groups": groups,
    }


# ---------------------------------------------------------------------------
# Helper: Template rendern
# ---------------------------------------------------------------------------


def _render_section(app: Flask, action_sections: list) -> str:  # type: ignore[type-arg]
    """Rendert _action_needed_section.html via render_template_string.

    Da das Template kein ``{% extends %}`` hat, kann es direkt gerendert
    werden. Der Flask-App-Context wird fuer Jinja-Autoescaping benoetigt.
    """
    from flask import render_template_string

    source = _load_template_source()
    with app.test_request_context("/servers/42"):
        return render_template_string(source, action_sections=action_sections)


# ===========================================================================
# Drilldown-Tabellen-Tests (1-8)
# ===========================================================================


def test_drilldown_table_uses_workflow_card_class(app: Flask) -> None:
    """Card-Body-Tabelle hat class="workflow-card__drilldown".

    DaisyUI-Klassen ``table table-xs w-full`` duerfen NICHT mehr vorkommen
    (ADR-0038 Phase D2 — Umstieg auf eigene CSS-Klassen).
    """
    card = _make_single_entry_card()
    html = _render_section(app, [card])

    assert 'class="workflow-card__drilldown"' in html, (
        f"'class=\"workflow-card__drilldown\"' fehlt im gerenderten HTML. "
        f"Phase D2 soll diese Klasse eingefuehrt haben. HTML (Ausschnitt): {html[:600]!r}"
    )

    # DaisyUI-Klassen duerfen nicht mehr vorhanden sein.
    assert "table-xs" not in html, (
        f"'table-xs' (DaisyUI) ist noch im gerenderten HTML. "
        f"Phase D2 soll auf 'workflow-card__drilldown' gewechselt haben. HTML: {html[:600]!r}"
    )


def test_drilldown_table_has_three_columns_in_documented_order(app: Flask) -> None:
    """Drilldown-Tabelle hat genau drei <th>-Tags in Reihenfolge Group -> Worst Finding -> Reason.

    ADR-0038 Phase D2: dokumentierte Spalten-Reihenfolge ist verbindlich.
    """
    card = _make_single_entry_card()
    html = _render_section(app, [card])

    # Anzahl der <th>-Elemente exakt drei.
    # Hinweis: ``html.count("<th")`` wuerde auch ``<thead>`` treffen — daher
    # ``</th>`` zaehlen (kein False-Positive von ``<thead>``).
    th_count = html.count("</th>")
    assert th_count == 3, (
        f"Drilldown-Tabelle soll genau 3 <th>-Elemente haben, gefunden: {th_count}. "
        f"HTML (Ausschnitt): {html[:800]!r}"
    )

    # Reihenfolge via Substring-Index-Vergleich.
    expected_order = ["Group", "Worst Finding", "Reason"]
    positions = []
    for header in expected_order:
        assert header in html, (
            f"Spalten-Header '{header}' fehlt im Drilldown-HTML. HTML: {html[:800]!r}"
        )
        positions.append(html.index(header))

    for i in range(len(positions) - 1):
        assert positions[i] < positions[i + 1], (
            f"Spalten-Reihenfolge falsch: '{expected_order[i]}' (pos {positions[i]}) "
            f"soll VOR '{expected_order[i + 1]}' (pos {positions[i + 1]}) kommen. "
            f"Pflicht-Reihenfolge: {expected_order}."
        )


def test_drilldown_row_renders_group_label_as_anchor(app: Flask) -> None:
    """Group-Spalte rendert <a href="#group-<id>">label</a> mit data-test-Attribut.

    Pattern: anchor-link auf die Group-Sektion der Seite,
    ``data-test="action-card-<id>-row"`` auf der <tr>.
    """
    card = _make_single_entry_card(card_id="escalate-distro-patch", group_id=1, group_label="k3s")
    html = _render_section(app, [card])

    # Anchor-Link auf group-ID.
    assert 'href="#group-1"' in html, (
        f"'href=\"#group-1\"' fehlt in der Group-Spalte. HTML: {html!r}"
    )
    assert "k3s" in html, f"'k3s' (Group-Label) fehlt im gerenderten HTML. HTML: {html!r}"

    # data-test auf <tr>.
    assert 'data-test="action-card-escalate-distro-patch-row"' in html, (
        f"'data-test=\"action-card-escalate-distro-patch-row\"' fehlt im <tr>. HTML: {html!r}"
    )


def test_drilldown_row_renders_worst_finding_identifier(app: Flask) -> None:
    """Worst-Finding-Spalte zeigt den identifier_key-String.

    CVE-ID muss in der zweiten Tabellen-Spalte erscheinen.
    """
    card = _make_single_entry_card(identifier_key="CVE-2024-1234")
    html = _render_section(app, [card])

    assert "CVE-2024-1234" in html, (
        f"'CVE-2024-1234' fehlt im gerenderten HTML. "
        f"worst_finding.identifier_key soll in der zweiten Spalte stehen. HTML: {html!r}"
    )

    # Em-Dash-Fallback darf bei gesetztem worst_finding NICHT vorkommen.
    # (Vorsicht: Reason-Spalte hat einen eigenen Em-Dash-Fallback — wir pruefen
    # nur ob der identifier_key vorhanden ist, nicht ob Em-Dash komplett fehlt.)
    assert "CVE-2024-1234" in html, (
        f"identifier_key='CVE-2024-1234' soll im HTML sichtbar sein. HTML: {html!r}"
    )


def test_drilldown_row_renders_em_dash_when_worst_finding_missing(app: Flask) -> None:
    """Worst-Finding-Spalte rendert <span class="opacity-50">—</span> wenn worst_finding=None.

    ADR-0038 Phase D2: Em-Dash als Placeholder bei fehlendem Worst-Finding.
    """
    card = _make_single_entry_card(identifier_key=None)
    html = _render_section(app, [card])

    assert '<span class="opacity-50">—</span>' in html, (
        f"Em-Dash-Span '<span class=\"opacity-50\">—</span>' fehlt bei worst_finding=None. "
        f"HTML: {html!r}"
    )


def test_drilldown_row_renders_risk_band_reason(app: Flask) -> None:
    """Reason-Spalte zeigt evaluation.risk_band_reason-String.

    Der Reason-Text soll sichtbar im HTML erscheinen (auto-escaped, kein ``|safe``).
    """
    reason_text = "vendor (redhat) severity HIGH"
    card = _make_single_entry_card(risk_band_reason=reason_text)
    html = _render_section(app, [card])

    assert reason_text in html, (
        f"risk_band_reason='{reason_text}' fehlt im gerenderten HTML. "
        f"Reason-Spalte soll diesen String zeigen. HTML: {html!r}"
    )


def test_drilldown_row_em_dash_when_reason_missing(app: Flask) -> None:
    """Reason-Spalte rendert <span class="opacity-50">—</span> wenn evaluation=None.

    ADR-0038 Phase D2: Em-Dash bei fehlender Junction-Eval.
    """
    # evaluation=None wird durch risk_band_reason=None erzeugt —
    # aber der Template-Check ist ``entry.evaluation and entry.evaluation.risk_band_reason``.
    # Wir setzen evaluation komplett auf None via dem _make_single_entry_card-Helper.
    card = {
        "id": "escalate-distro-patch",
        "label": "ESCALATE · Distro patchen",
        "variant": "escalate-distro",
        "filter": ("escalate", "patch", "os_package"),
        "count": 1,
        "show_labels": True,
        "groups": [
            {
                "group": SimpleNamespace(id=1, label="k3s", group_kind="os_package"),
                "evaluation": None,
                "worst_finding": SimpleNamespace(identifier_key="CVE-2024-1234"),
                "count": 5,
            }
        ],
    }
    html = _render_section(app, [card])

    assert '<span class="opacity-50">—</span>' in html, (
        f"Em-Dash-Span '<span class=\"opacity-50\">—</span>' fehlt bei evaluation=None. "
        f"HTML: {html!r}"
    )


def test_drilldown_reason_is_autoescaped_xss_payload(app: Flask) -> None:
    """risk_band_reason mit XSS-Payload wird HTML-escaped.

    Jinja-Autoescaping muss ``<script>alert(1)</script>`` zu
    ``&lt;script&gt;alert(1)&lt;/script&gt;`` escapen.
    Kein ``|safe`` darf die Escaping-Kette unterbrechen (ADR-0038 §Sicherheit).
    """
    xss_payload = "<script>alert(1)</script>"
    card = _make_single_entry_card(risk_band_reason=xss_payload)
    html = _render_section(app, [card])

    # Rohes Script-Tag darf NICHT im Output sein.
    assert "<script>alert(1)</script>" not in html, (
        f"XSS-Payload '<script>alert(1)</script>' ist UNESCAPED im HTML! "
        f"Jinja-Autoescaping muss greifen. Kein '|safe' auf risk_band_reason. HTML: {html!r}"
    )

    # Escaped-Version muss vorhanden sein.
    assert "&lt;script&gt;" in html, (
        f"'&lt;script&gt;' (HTML-escaped) fehlt im Output. "
        f"Jinja-Autoescaping hat nicht gegriffen. HTML: {html!r}"
    )


# ===========================================================================
# Sub-Line-Removal-Tests (9-10)
# ===========================================================================


def test_no_sublist_data_test_in_output(app: Flask) -> None:
    """Output enthaelt kein data-test="action-card-<id>-sublist"-Attribut.

    Phase D2 hat die Sub-Line der Group-Labels entfernt — sie wird durch
    die Group-Spalte der Drilldown-Tabelle ersetzt.
    """
    card = _make_single_entry_card(card_id="escalate-distro-patch", show_labels=True)
    html = _render_section(app, [card])

    assert 'data-test="action-card-escalate-distro-patch-sublist"' not in html, (
        f"'data-test=\"action-card-escalate-distro-patch-sublist\"' ist noch im HTML. "
        f"Phase D2 soll die Sub-Line entfernt haben. HTML: {html!r}"
    )

    # Generischer Check: kein -sublist-Anker mehr.
    assert "-sublist" not in html, (
        f"'-sublist'-Pattern noch im HTML. Sub-Line-Markup soll komplett entfernt sein. "
        f"HTML: {html!r}"
    )

    # '+N more'-Pattern darf nicht vorkommen.
    assert "+N more" not in html, (
        f"'+N more' noch im HTML. Altes Sub-Line-Pattern soll entfernt sein. HTML: {html!r}"
    )
    # Variante mit echter Zahl ebenfalls nicht.
    assert re.search(r"\+\d+ more", html) is None, (
        f"'+<N> more'-Pattern (mit Zahl) noch im HTML. HTML: {html!r}"
    )


def test_no_sublist_when_show_labels_false(app: Flask) -> None:
    """Output enthaelt kein Sublist-Markup auch wenn show_labels=False.

    Unabhaengig vom show_labels-Flag darf kein Sub-Line-Markup mehr rendern.
    """
    card = _make_single_entry_card(card_id="act-distro-patch", show_labels=False)
    html = _render_section(app, [card])

    assert "-sublist" not in html, (
        f"'-sublist'-Pattern noch im HTML bei show_labels=False. HTML: {html!r}"
    )

    assert re.search(r"\+\d+ more", html) is None, (
        f"'+<N> more'-Pattern noch im HTML bei show_labels=False. HTML: {html!r}"
    )


# ===========================================================================
# Pagination-Stub-Tests (11-14)
# ===========================================================================


def test_no_pagination_stub_when_25_groups_or_fewer(app: Flask) -> None:
    """Kein Pagination-Stub bei genau 25 Groups (Grenzwert).

    Pagination-Footer soll erst ab > 25 Groups erscheinen (Spec D3).
    """
    card = _make_pagination_card(num_groups=25)
    html = _render_section(app, [card])

    assert 'data-test="action-card-escalate-distro-patch-pagination"' not in html, (
        f"Pagination-Stub darf bei 25 Groups NICHT rendern. HTML: {html[:800]!r}"
    )

    assert "workflow-card__pagination" not in html, (
        f"'workflow-card__pagination' darf bei <= 25 Groups nicht im HTML sein. HTML: {html[:800]!r}"
    )


def test_pagination_stub_renders_when_26_groups(app: Flask) -> None:
    """Pagination-Stub rendert bei genau 26 Groups.

    Prueft alle Pflicht-Elemente aus Spec D3:
    - ``data-test="action-card-<id>-pagination"``
    - Text "Seite 1 von 2"
    - ``class="workflow-card__pagination"``
    - Zwei <button> mit disabled
    - aria-label="Previous page" und aria-label="Next page"
    """
    card = _make_pagination_card(num_groups=26)
    html = _render_section(app, [card])

    # Pagination-Container vorhanden.
    assert 'data-test="action-card-escalate-distro-patch-pagination"' in html, (
        f"'data-test=\"action-card-escalate-distro-patch-pagination\"' fehlt bei 26 Groups. "
        f"HTML: {html[:1000]!r}"
    )

    assert 'class="workflow-card__pagination"' in html, (
        f"'class=\"workflow-card__pagination\"' fehlt bei 26 Groups. HTML: {html[:1000]!r}"
    )

    # Seiten-Text: 26 Groups / 25 pro Seite = 2 Seiten (1 Rest).
    assert "Seite 1 von 2" in html, f"'Seite 1 von 2' fehlt bei 26 Groups. HTML: {html!r}"

    # Beide disabled Buttons.
    assert 'aria-label="Previous page"' in html, (
        f"'aria-label=\"Previous page\"' fehlt im Pagination-Stub. HTML: {html!r}"
    )
    assert 'aria-label="Next page"' in html, (
        f"'aria-label=\"Next page\"' fehlt im Pagination-Stub. HTML: {html!r}"
    )


@pytest.mark.parametrize(
    "num_groups, expected_text",
    [
        (50, "Seite 1 von 2"),  # 50 // 25 = 2, kein Rest -> genau 2 Seiten
        (51, "Seite 1 von 3"),  # 51 // 25 = 2 + 1 Rest -> 3 Seiten
        (100, "Seite 1 von 4"),  # 100 // 25 = 4, kein Rest -> genau 4 Seiten
        (101, "Seite 1 von 5"),  # 101 // 25 = 4 + 1 Rest -> 5 Seiten
    ],
)
def test_pagination_total_pages_calculation(
    app: Flask, num_groups: int, expected_text: str
) -> None:
    """Gesamtseitenanzahl wird korrekt berechnet (parametrize).

    Formel: ``ceil(num_groups / 25)``.
    """
    card = _make_pagination_card(num_groups=num_groups)
    html = _render_section(app, [card])

    assert expected_text in html, (
        f"'{expected_text}' fehlt bei {num_groups} Groups. "
        f"Pagination-Seiten-Berechnung inkorrekt. HTML (letzter Teil): {html[-600:]!r}"
    )


def test_pagination_buttons_are_disabled_stub(app: Flask) -> None:
    """Beide Pagination-Buttons haben das disabled-Attribut bei 30 Groups.

    Der Stub ist statisch (echte Pagination kommt in einem Folge-PR) —
    beide Buttons muessen deswegen immer disabled sein.
    """
    card = _make_pagination_card(num_groups=30)
    html = _render_section(app, [card])

    # Pagination-Container suchen.
    assert 'data-test="action-card-escalate-distro-patch-pagination"' in html, (
        f"Pagination-Container fehlt bei 30 Groups. HTML: {html[:800]!r}"
    )

    # Beide Buttons muessen disabled enthalten — wir pruefen via substring.
    # Das Template setzt ``disabled`` auf beiden <button>-Elementen.
    # Strategie: extrahiere den Pagination-Block und zaehle disabled.
    pag_start = html.index('data-test="action-card-escalate-distro-patch-pagination"')
    pag_block = html[pag_start:]

    disabled_count = pag_block.count("disabled")
    assert disabled_count >= 2, (
        f"Beide Pagination-Buttons muessen 'disabled' haben, "
        f"gefunden: {disabled_count}x 'disabled' im Pagination-Block. "
        f"Block: {pag_block[:400]!r}"
    )
