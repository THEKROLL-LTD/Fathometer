"""Pure-Unit-Tests: Legacy-Dashboard-Partials wurden in Block W Phase D geloescht.

Verifiziert:
- app/templates/dashboard/_kpi_cards.html existiert nicht mehr.
- app/templates/_partials/action_required_card.html existiert nicht mehr.
- Kein Template oder View importiert / inkludiert '_kpi_cards' noch.
- Kein Template oder View importiert / inkludiert 'action_required_card'.

Hinweis: risk_band_pill.html wird NICHT geprueft — wird noch von
Findings-/Servers-Surfaces genutzt, Loesung kommt in einem spaeteren Block.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# Projekt-Root
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent.parent

_TEMPLATES_DIR = _REPO_ROOT / "app" / "templates"
_VIEWS_DIR = _REPO_ROOT / "app" / "views"


# ---------------------------------------------------------------------------
# Datei-Existenz-Tests
# ---------------------------------------------------------------------------


def test_kpi_cards_template_deleted() -> None:
    """app/templates/dashboard/_kpi_cards.html darf nicht mehr existieren.

    Diese Datei wurde in Block W Phase D durch Action-Card + Nominal-Card ersetzt.
    """
    target = _TEMPLATES_DIR / "dashboard" / "_kpi_cards.html"
    assert not target.exists(), (
        f"Legacy-Template {target} existiert noch — muss in Phase D geloescht worden sein. "
        "DoD-D Item 1: grep auf '_kpi_cards' soll nichts liefern."
    )


def test_action_required_card_template_deleted() -> None:
    """app/templates/_partials/action_required_card.html darf nicht mehr existieren.

    Diese Datei wurde in Block W Phase D durch die neue Action-Needed-Card ersetzt.
    """
    target = _TEMPLATES_DIR / "_partials" / "action_required_card.html"
    assert not target.exists(), (
        f"Legacy-Template {target} existiert noch — muss in Phase D geloescht worden sein. "
        "DoD-D Item 1."
    )


# ---------------------------------------------------------------------------
# Import-Site-Tests (kein Include mehr im Codebase)
# ---------------------------------------------------------------------------


def _grep_for_pattern(pattern: str) -> list[str]:
    """Sucht rekursiv in app/templates/ und app/views/ nach dem Muster.

    Gibt alle gefundenen Zeilen als Liste zurueck.
    Leere Liste = kein Fund = erwartet.
    """
    result = subprocess.run(
        ["grep", "-rn", pattern, str(_TEMPLATES_DIR), str(_VIEWS_DIR)],
        capture_output=True,
        text=True,
    )
    # grep liefert returncode=1 wenn kein Treffer — das ist OK.
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return lines


def test_no_imports_of_kpi_cards() -> None:
    """Kein Template oder View referenziert noch '_kpi_cards'.

    DoD-D Item 1: grep -rn '_kpi_cards' app/templates/ app/views/ liefert nichts.
    """
    hits = _grep_for_pattern("_kpi_cards")
    assert not hits, (
        "Referenzen auf '_kpi_cards' gefunden — muss in Phase D bereinigt werden:\n"
        + "\n".join(hits)
    )


def test_no_imports_of_action_required_card() -> None:
    """Kein Template oder View referenziert noch 'action_required_card'.

    DoD-D Item 1: grep -rn 'action_required_card' app/templates/ app/views/ liefert nichts.
    """
    hits = _grep_for_pattern("action_required_card")
    assert not hits, (
        "Referenzen auf 'action_required_card' gefunden — muss in Phase D bereinigt werden:\n"
        + "\n".join(hits)
    )


# ---------------------------------------------------------------------------
# Negativ-Test: risk_band_pill.html soll NOCH existieren
# ---------------------------------------------------------------------------


def test_risk_band_pill_still_exists() -> None:
    """risk_band_pill.html soll in Phase D noch existieren.

    Wird von Findings- und Servers-Surfaces genutzt.
    Loesung kommt in einem spaeteren Block — NICHT in Phase D loeschen.
    """
    target = _TEMPLATES_DIR / "_partials" / "risk_band_pill.html"
    assert target.exists(), (
        f"risk_band_pill.html wurde versehentlich geloescht ({target}). "
        "Wird noch von anderen Surfaces benutzt — Loesung kommt in einem spaeteren Block."
    )
