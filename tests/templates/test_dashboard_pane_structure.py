"""Pure-Unit Template-Smoke-Tests fuer die Dashboard-Pane-Struktur (Block W Phase F).

Prueft:
  - `_detail_pane.html` hat hx-trigger="every 60s [document.visibilityState === 'visible']".
  - `_detail_pane.html` hat hx-swap="none" auf #dashboard-pane.
  - `_detail_pane.html` hat hx-get="/_partials/dashboard/kpis".
  - `_action_needed_card.html` outer wrapper hat hx-preserve="true".
  - `_detail_pane.html` inkludiert _sysline.html.

Test-Strategie: direktes Lesen der Template-Dateien als Text (grep-aequivalent).
Dieses Pattern vermeidet das Aufsetzen eines vollen Template-Render-Kontexts fuer
Templates die andere Templates mit url_for() includen. Prueft statische Markup-
Attribute die sich nicht dynamisch aendern.

ADR-0036: Polling-Pattern mit hx-preserve + OOB-Swaps.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Template-Root bestimmen
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent.parent
_TEMPLATE_ROOT = _REPO_ROOT / "app" / "templates" / "dashboard"


def _read_template(filename: str) -> str:
    """Liest eine Template-Datei als String."""
    path = _TEMPLATE_ROOT / filename
    assert path.exists(), (
        f"Template-Datei '{path}' existiert nicht. Wurde die Datei angelegt? (Block W Phase F)"
    )
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# _detail_pane.html — Polling-Pattern (ADR-0036)
# ---------------------------------------------------------------------------


def test_dashboard_pane_polling_cadence_60s() -> None:
    """_detail_pane.html hat exakt das erwartete hx-trigger-Attribut (ADR-0036).

    Polling-Cadence: 60s, nur wenn Tab sichtbar (visibilityState === 'visible').
    """
    html = _read_template("_detail_pane.html")

    expected_trigger = "every 60s [document.visibilityState === 'visible']"
    assert expected_trigger in html, (
        f"hx-trigger='{expected_trigger}' fehlt in _detail_pane.html. "
        "ADR-0036: Polling-Cadence ist 60s, nur bei sichtbarem Tab. "
        f"Template-Inhalt (erste 600 Zeichen): {html[:600]}"
    )


def test_dashboard_pane_hx_swap_none() -> None:
    """_detail_pane.html hat hx-swap='none' auf #dashboard-pane.

    hx-swap='none' bedeutet: der Pane selbst wird nicht ersetzt,
    nur OOB-Fragmente werden von HTMX applied (ADR-0036).
    """
    html = _read_template("_detail_pane.html")

    assert 'hx-swap="none"' in html, (
        "hx-swap='none' fehlt in _detail_pane.html. "
        "ADR-0036: Pane-Trigger darf den Pane nicht ersetzen — "
        "nur OOB-Fragmente werden angewendet. "
        f"Template-Inhalt (erste 600 Zeichen): {html[:600]}"
    )


def test_dashboard_pane_hx_get_kpis_endpoint() -> None:
    """_detail_pane.html hat hx-get='/_partials/dashboard/kpis'.

    Dieser Endpoint liefert die konsolidierten OOB-Fragmente (ADR-0036).
    """
    html = _read_template("_detail_pane.html")

    assert 'hx-get="/_partials/dashboard/kpis"' in html, (
        "hx-get='/_partials/dashboard/kpis' fehlt in _detail_pane.html. "
        "ADR-0036: Dashboard pollt diesen Endpoint alle 60s. "
        f"Template-Inhalt (erste 600 Zeichen): {html[:600]}"
    )


def test_dashboard_pane_has_dashboard_pane_id() -> None:
    """_detail_pane.html hat id='dashboard-pane' auf dem Trigger-Element."""
    html = _read_template("_detail_pane.html")

    assert 'id="dashboard-pane"' in html, (
        "id='dashboard-pane' fehlt in _detail_pane.html. "
        "Das Trigger-Element braucht diese ID fuer HTMX-Targeting. "
        f"Template-Inhalt (erste 600 Zeichen): {html[:600]}"
    )


def test_dashboard_pane_includes_sysline() -> None:
    """_detail_pane.html inkludiert _sysline.html (Phase F, ADR-0036).

    Sysline ist neues Element in Phase F — das Include muss im Pane vorhanden sein.
    """
    html = _read_template("_detail_pane.html")

    assert "_sysline.html" in html, (
        "_sysline.html-Include fehlt in _detail_pane.html. "
        "Block W Phase F: Sysline wird in den Detail-Pane eingebunden. "
        f"Template-Inhalt (erste 800 Zeichen): {html[:800]}"
    )


# ---------------------------------------------------------------------------
# _action_needed_card.html — hx-preserve (ADR-0036)
# ---------------------------------------------------------------------------


def test_action_needed_card_has_hx_preserve() -> None:
    """_action_needed_card.html outer wrapper hat hx-preserve='true'.

    Dieser Wrapper (#action-needed-card) traegt hx-preserve='true' damit
    HTMX ihn beim OOB-Swap nicht ersetzt. So laeuft die Scan-Beam-Animation
    (CSS ::before/.stat--alarm) kontinuierlich ohne Neustart (ADR-0036).
    """
    html = _read_template("_action_needed_card.html")

    assert 'hx-preserve="true"' in html, (
        "hx-preserve='true' fehlt auf dem Wrapper in _action_needed_card.html. "
        "ADR-0036: Wrapper muss hx-preserve='true' tragen damit die Scan-Beam-"
        "Animation beim OOB-Swap nicht neugestartet wird. "
        f"Template-Inhalt (erste 600 Zeichen): {html[:600]}"
    )


def test_action_needed_card_has_id_action_needed_card() -> None:
    """_action_needed_card.html Wrapper hat id='action-needed-card'.

    Diese ID ist das hx-preserve-Target und der OOB-Anchor (ADR-0036).
    """
    html = _read_template("_action_needed_card.html")

    assert 'id="action-needed-card"' in html, (
        "id='action-needed-card' fehlt in _action_needed_card.html. "
        "Diese ID ist der hx-preserve-Identifier und das OOB-Anchor-Element. "
        f"Template-Inhalt (erste 600 Zeichen): {html[:600]}"
    )


# ---------------------------------------------------------------------------
# OOB-Target-IDs in _detail_pane.html
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target_id",
    [
        "dashboard-last-refresh",
        "dashboard-eyebrow",
    ],
)
def test_dashboard_pane_has_oob_target_ids(target_id: str) -> None:
    """_detail_pane.html enthaelt alle fuer OOB-Swaps benoetigen IDs."""
    html = _read_template("_detail_pane.html")

    assert f'id="{target_id}"' in html, (
        f"id='{target_id}' fehlt in _detail_pane.html. "
        f"Diese ID ist ein OOB-Swap-Target aus dem /_partials/dashboard/kpis-Endpoint. "
        f"Template-Inhalt (erste 800 Zeichen): {html[:800]}"
    )
