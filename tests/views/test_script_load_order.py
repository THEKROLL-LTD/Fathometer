"""Regression-Test fuer die Script-Lade-Reihenfolge in `base_app.html`.

Hintergrund: Alpine v3 startet aus dem `defer`-Kontext SOFORT (weil
`document.readyState === 'interactive'` zum Script-Eval-Zeitpunkt) und
feuert `alpine:init` synchron. Wenn `alpinejs.cdn.min.js` vor den App-
Skripten geladen wird, die `window.bulkAckIds`, `window.sidebarSearch`,
`window.staleTick`, ...
registrieren, dann scannt Alpine den DOM bevor diese Factories existieren.
Folge: `x-data="bulkAckIds(...)"` und alle anderen Komponenten werden mit
leerem Scope initialisiert, was sich als Bulk-Ack-Modal-Visibility ohne
funktionierendes Cancel ("comment/busy/canApply is not defined") aeussert.

Dieser Test stellt sicher, dass Alpine NACH allen Factory-Skripten
referenziert wird — gleiche Regel wie in `base.html` (siehe Kommentar
dort).

ADR-0019: `js/sse.js` ist zu `js/stale.js` umbenannt — die einzige
Komponente die hier bleibt ist `staleTick()`. `dashboardSse` ist
mit Block L entfernt.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_APP = REPO_ROOT / "app" / "templates" / "base_app.html"
BASE = REPO_ROOT / "app" / "templates" / "base.html"

ALPINE_MARKER = "js/vendor.js"
# Block W Addendum 2026-05-23: Alpine + HTMX kommen nicht mehr via CDN
# sondern via dem esbuild-Bundle vendor.js (ADR-0032 Phase 2 vorgezogen).
# Die Lade-Reihenfolge-Invariante bleibt identisch: alle window-Factory-
# Skripte muessen VOR vendor.js geladen werden — sonst sind die Factories
# beim Alpine-DOM-Scan noch nicht registriert.

# Pro Template: nur Skripte pruefen die das Template tatsaechlich verlinkt.
# `base.html` ist die Pre-Auth-Shell (Setup/Login) und braucht weder
# Sidebar- noch sse_highlight-Skripte; `base_app.html` ist die volle
# App-Shell mit Sidebar.
FACTORY_SCRIPTS_BY_TEMPLATE = {
    "base_app.html": [
        "js/bulk_ack.js",
        "js/stale.js",
        "js/sidebar.js",
        "js/sse_highlight.js",
        "js/llm_settings.js",
    ],
    "base.html": [
        "js/bulk_ack.js",
        "js/stale.js",
    ],
}


def _position(html: str, needle: str) -> int:
    idx = html.find(needle)
    if idx == -1:
        raise AssertionError(f"Script-Pin {needle!r} nicht im Template gefunden.")
    return idx


@pytest.mark.parametrize("template", [BASE_APP, BASE])
def test_alpine_loads_after_all_factory_scripts(template: Path) -> None:
    """Alpine darf erst NACH allen `window.*`-Factory-Skripten kommen."""
    html = template.read_text(encoding="utf-8")
    alpine_pos = _position(html, ALPINE_MARKER)
    for script in FACTORY_SCRIPTS_BY_TEMPLATE[template.name]:
        script_pos = _position(html, script)
        assert script_pos < alpine_pos, (
            f"{template.name}: {script!r} (Pos {script_pos}) muss "
            f"vor Alpine (Pos {alpine_pos}) geladen werden — sonst sind "
            f"die window-Factories beim DOM-Scan noch nicht registriert."
        )


def test_base_app_loads_factory_scripts() -> None:
    """Sanity: alle erwarteten Factory-Skripte sind in `base_app.html` verlinkt."""
    html = BASE_APP.read_text(encoding="utf-8")
    for script in FACTORY_SCRIPTS_BY_TEMPLATE["base_app.html"]:
        assert script in html, f"{script!r} fehlt in base_app.html."
