"""Pure-Unit-Tests fuer den JS-Anteil von Phase A0 (Block X).

Prueft:
- server_detail.js exportiert die drei dokumentierten Funktionen.
- server_detail.js registriert Alpine.data('serverPillPanels', …) fuer
  Phase-C-Pills (Phase-A0-Vorarbeit).
- app.js importiert initServerDetailModule aus server_detail.js und verwendet
  die Funktion tatsaechlich (nicht nur importiert).
- app.js haengt initServerDetailModule an htmx:afterSettle und verwendet
  .sd-detail-root als Selektor (Pane-Swap-Kompatibilitaet).
- server_detail.js enthaelt keine Tailwind/DaisyUI-Klassennamen
  (ADR-0032 — Block W hat Tailwind vollstaendig verbannt).
"""

from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Pfad-Basis
# ---------------------------------------------------------------------------

_JS_SRC = Path(__file__).resolve().parent.parent.parent / "frontend" / "src" / "js"
_SERVER_DETAIL_JS = _JS_SRC / "server_detail.js"
_APP_JS = _JS_SRC / "app.js"


# ---------------------------------------------------------------------------
# Test 1: server_detail.js exportiert die drei Pflicht-Funktionen
# ---------------------------------------------------------------------------


def test_server_detail_js_exports_setup_functions() -> None:
    """server_detail.js enthaelt die drei export-function-Signaturen.

    Verifiziert via Substring-Match (kein JS-Parser notwendig). Die drei
    Exporte sind das oeffentliche API das app.js und Phase-C-Templates
    benoetigen.
    """
    assert _SERVER_DETAIL_JS.exists(), f"server_detail.js fehlt: {_SERVER_DETAIL_JS}"

    js_text = _SERVER_DETAIL_JS.read_text(encoding="utf-8")

    expected_exports = [
        "export function setupScanFlashSync(",
        "export function setupServerDetailHeartbeatTip(",
        "export function initServerDetailModule(",
    ]

    for signature in expected_exports:
        assert signature in js_text, (
            f"Export-Signatur fehlt in server_detail.js: '{signature}'. "
            f"A0-3 unvollstaendig oder Funktion umbenannt."
        )


# ---------------------------------------------------------------------------
# Test 2: server_detail.js registriert Alpine-Component serverPillPanels
# ---------------------------------------------------------------------------


def test_server_detail_js_registers_pill_panels_alpine_component() -> None:
    """server_detail.js ruft Alpine.data('serverPillPanels', …) auf.

    Phase C bindet <div x-data="serverPillPanels"> — wenn die Registration
    hier fehlt, laden die Pills leer. Substring-Match auf den genauen
    Alpine.data-Aufruf.
    """
    assert _SERVER_DETAIL_JS.exists(), f"server_detail.js fehlt: {_SERVER_DETAIL_JS}"

    js_text = _SERVER_DETAIL_JS.read_text(encoding="utf-8")

    alpine_registration = "Alpine.data('serverPillPanels',"

    assert alpine_registration in js_text, (
        f"Alpine.data-Registrierung fehlt: erwartet '{alpine_registration}' "
        f"in server_detail.js. Phase-C-Pills koennen nicht binden."
    )


# ---------------------------------------------------------------------------
# Test 3: app.js importiert initServerDetailModule und verwendet es
# ---------------------------------------------------------------------------


def test_app_js_imports_server_detail_module() -> None:
    """app.js importiert initServerDetailModule aus './server_detail.js' und verwendet die Funktion.

    Verifiziert zwei Bedingungen:
    1. Das Import-Statement ist vorhanden (kein toter Import).
    2. Der Name 'initServerDetailModule' taucht ausserhalb des Import-Statements
       ein zweites Mal auf (tatsaechliche Verwendung, nicht nur Import-Alias).
    """
    assert _APP_JS.exists(), f"app.js fehlt: {_APP_JS}"

    js_text = _APP_JS.read_text(encoding="utf-8")

    import_statement = "from './server_detail.js'"
    assert import_statement in js_text, (
        f"Import-Statement fehlt in app.js: erwartet '{import_statement}'. "
        f"A0-4 wurde moeglicherweise nicht ausgefuehrt."
    )

    # initServerDetailModule muss mindestens zweimal vorkommen:
    # einmal im Import-Statement, einmal beim tatsaechlichen Aufruf.
    occurrences = js_text.count("initServerDetailModule")
    assert occurrences >= 2, (
        f"'initServerDetailModule' taucht nur {occurrences}x in app.js auf. "
        f"Erwartet mindestens 2 (einmal im Import, einmal beim Aufruf). "
        f"Wird die Funktion auch tatsaechlich aufgerufen?"
    )


# ---------------------------------------------------------------------------
# Test 4: app.js haengt Init-Hook an htmx:afterSettle mit .sd-detail-root
# ---------------------------------------------------------------------------


def test_app_js_hooks_htmx_after_settle_for_server_detail() -> None:
    """app.js registriert einen htmx:afterSettle-Listener der .server-detail als Selektor nutzt.

    Pane-Swap-Kompatibilitaet: initServerDetailModule muss nur auf neu
    eingefuegte Detail-Pane-Wurzeln angewandt werden, nicht auf beliebige
    HTMX-Swaps. Beides muss in app.js vorhanden sein.

    Block X Track A: Wrapper-Klasse von .sd-detail-root auf .server-detail
    umbenannt (Track G hat app.js entsprechend aktualisiert).
    """
    assert _APP_JS.exists(), f"app.js fehlt: {_APP_JS}"

    js_text = _APP_JS.read_text(encoding="utf-8")

    assert "htmx:afterSettle" in js_text, (
        "Event-Name 'htmx:afterSettle' fehlt in app.js. "
        "Der HTMX-Hook fuer Server-Detail-Init ist nicht registriert."
    )

    assert ".server-detail" in js_text, (
        "Selektor '.server-detail' fehlt in app.js. "
        "initServerDetailModule muss gezielt auf die Detail-Pane-Wurzel "
        "angewandt werden (nicht auf beliebige Elemente). "
        "(Block X Track A: Umbenennung von .sd-detail-root auf .server-detail)"
    )


# ---------------------------------------------------------------------------
# Test 5: server_detail.js enthaelt keine Tailwind/DaisyUI-Klassennamen
# ---------------------------------------------------------------------------


# Ban-Liste typischer Tailwind/DaisyUI-Klassen-Praefixe (ADR-0032).
# String-Lookup — kein Regex notwendig da die Praefixe eindeutig sind.
_TAILWIND_BAN_LIST = [
    "bg-",
    "text-base-",
    "daisy-",
    "btn-primary",
    "btn-secondary",
    "btn-ghost",
    "p-",
    "m-",
    "flex-",
    "grid-cols-",
    "rounded-",
    "border-",
    "ring-",
    "shadow-",
    "hover:bg-",
    "hover:text-",
    "focus:ring-",
    "dark:",
    "lg:",
    "md:",
    "sm:",
    "xl:",
]


def test_server_detail_js_no_tailwind_class_references() -> None:
    """server_detail.js enthaelt keine Tailwind- oder DaisyUI-Klassennamen.

    ADR-0032 — Block W hat Tailwind/DaisyUI vollstaendig verbannt. Wenn ein
    Implementer versehentlich einen 'bg-base-200'- oder 'btn-primary'-String
    einbaut, faengt dieser Test es fruehzeitig ab.

    Pruefstrategie: Ban-Liste von typischen Praefix-Mustern wird als Substring
    in js_text gesucht. String-Literals in Klassennamen-Strings sind das
    wahrscheinlichste Einfallstor.
    """
    assert _SERVER_DETAIL_JS.exists(), f"server_detail.js fehlt: {_SERVER_DETAIL_JS}"

    js_text = _SERVER_DETAIL_JS.read_text(encoding="utf-8")

    # Kommentare entfernen (// Zeilen-Kommentare und /* */ Bloecke),
    # damit Erwaehnungen in Kommentaren nicht falsch positiv ausloesen.
    # Einzeilige Kommentare (// bis Zeilenende).
    js_no_line_comments = re.sub(r"//[^\n]*", "", js_text)
    # Block-Kommentare (/* … */).
    js_clean = re.sub(r"/\*.*?\*/", "", js_no_line_comments, flags=re.DOTALL)

    violations = [prefix for prefix in _TAILWIND_BAN_LIST if prefix in js_clean]

    assert not violations, (
        f"server_detail.js enthaelt Tailwind/DaisyUI-Klassennamen-Praefixe "
        f"(ADR-0032 verletzt): {violations}"
    )
