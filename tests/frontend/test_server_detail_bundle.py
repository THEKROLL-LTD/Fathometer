"""Pure-Unit-Tests fuer den CSS-Bundle-Anteil von Phase A0 (Block X).

Prueft:
- server-detail.css existiert im Source-Tree und enthaelt die erwarteten
  Sentinel-Klassen (1:1-Port-Verifikation).
- app.css importiert server-detail.css in der dokumentierten Source-Order
  (nach auth.css, vor legacy-shim.css).
- Der _asset_url-Helper loest css/app.css korrekt auf einen gehashten Pfad auf
  (Mock-Manifest, analog tests/test_asset_manifest.py).
- Alle var(--token)-Referenzen in server-detail.css sind in tokens.css
  definiert (Token-Drift-Frueherkennung).
- Keine Hex-Farbwerte in server-detail.css ausserhalb von Header-Kommentaren
  (ADR-0033 Token-only-Policy).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Pfad-Basis
# ---------------------------------------------------------------------------

_FRONTEND_SRC = Path(__file__).resolve().parent.parent.parent / "frontend" / "src"
_CSS_COMPONENTS = _FRONTEND_SRC / "css" / "components"
_SERVER_DETAIL_CSS = _CSS_COMPONENTS / "server-detail.css"
_APP_CSS = _FRONTEND_SRC / "css" / "app.css"
_TOKENS_CSS = _FRONTEND_SRC / "css" / "tokens.css"


# ---------------------------------------------------------------------------
# Test 1: server-detail.css existiert und enthaelt Sentinel-Klassen
# ---------------------------------------------------------------------------


def test_server_detail_css_lives_in_bundled_app_css() -> None:
    """server-detail.css existiert und enthaelt die Sentinel-Klassen .sd-status-pill und .sd-chip.

    Verifikation des 1:1-Ports aus docs/design/server-detail.css: diese zwei
    Klassen-Namen sind stabile Ankerpunkte — sie werden in Phase C von den
    Alpine-Pills verwendet und duerfen nicht umbenannt werden.
    """
    assert _SERVER_DETAIL_CSS.exists(), (
        f"server-detail.css nicht gefunden unter: {_SERVER_DETAIL_CSS}"
    )

    css_text = _SERVER_DETAIL_CSS.read_text(encoding="utf-8")

    assert ".sd-status-pill" in css_text, (
        "Sentinel-Klasse '.sd-status-pill' fehlt in server-detail.css — "
        "1:1-Port aus docs/design/server-detail.css onkorrekt oder Klasse umbenannt."
    )
    assert ".sd-chip" in css_text, (
        "Sentinel-Klasse '.sd-chip' fehlt in server-detail.css — "
        "1:1-Port aus docs/design/server-detail.css inkorrekt oder Klasse umbenannt."
    )


# ---------------------------------------------------------------------------
# Test 2: app.css importiert server-detail.css in korrekter Source-Order
# ---------------------------------------------------------------------------


def test_server_detail_css_imported_in_app_css() -> None:
    """app.css enthaelt @import fuer server-detail.css, positioniert nach auth.css und vor legacy-shim.css.

    Source-Order ist semantisch relevant: server-detail.css muss die
    Foundation-Imports (tokens, globale Klassen) bereits in der Cascade haben,
    und legacy-shim.css darf server-detail.css nicht ueberschreiben.
    """
    assert _APP_CSS.exists(), f"app.css nicht gefunden unter: {_APP_CSS}"

    app_css_text = _APP_CSS.read_text(encoding="utf-8")

    server_detail_import = '@import "./components/server-detail.css"'

    assert server_detail_import in app_css_text, (
        f"Erwartet '{server_detail_import}' in app.css, aber nicht gefunden. "
        f"A0-2 wurde moeglicherweise nicht ausgefuehrt."
    )

    # Position-Verifikation via Index-Vergleich
    idx_server_detail = app_css_text.index(server_detail_import)

    # auth.css-Import ist "@import "./components/auth.css""
    auth_import_full = '@import "./components/auth.css"'
    assert auth_import_full in app_css_text, (
        f"Erwartet '{auth_import_full}' in app.css fuer Source-Order-Pruefung."
    )
    idx_auth = app_css_text.index(auth_import_full)

    # legacy-shim.css-Import
    legacy_import_full = '@import "./components/legacy-shim.css"'
    assert legacy_import_full in app_css_text, (
        f"Erwartet '{legacy_import_full}' in app.css fuer Source-Order-Pruefung."
    )
    idx_legacy = app_css_text.index(legacy_import_full)

    assert idx_auth < idx_server_detail, (
        f"Source-Order-Verletzung: server-detail.css (pos {idx_server_detail}) "
        f"muss NACH auth.css (pos {idx_auth}) importiert werden."
    )
    assert idx_server_detail < idx_legacy, (
        f"Source-Order-Verletzung: server-detail.css (pos {idx_server_detail}) "
        f"muss VOR legacy-shim.css (pos {idx_legacy}) importiert werden."
    )


# ---------------------------------------------------------------------------
# Test 3: _asset_url loest css/app.css auf gehashten Pfad auf (Mock-Manifest)
# ---------------------------------------------------------------------------


def test_manifest_resolves_app_css_to_hashed_filename(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_asset_url gibt den gehashten Pfad aus einem Mock-Manifest zurueck.

    Verifiziert den Manifest-Lookup-Pfad aus app/__init__.py (analog
    tests/test_asset_manifest.py). Relevant fuer DoD-Punkt 0: der neue
    CSS-Bundle-Inhalt muss ueber _asset_url im Jinja-Template aufloesbarsein.

    Strategie: Mock-Manifest direkt als Cache-Wert setzen (Double-Checked-
    Locking ueberspringt den Disk-Zugriff wenn _asset_manifest is not None).
    """
    import app as app_module

    mock_manifest = {"css/app.css": "css/app.deadbeef.css"}
    monkeypatch.setattr(app_module, "_asset_manifest", mock_manifest)
    monkeypatch.delenv("SECSCAN_ENV", raising=False)

    with app.test_request_context("/"):
        result = app_module._asset_url("css/app.css")

    assert result == "/static/dist/css/app.deadbeef.css", (
        f"Erwartet '/static/dist/css/app.deadbeef.css', got: {result!r}"
    )


# ---------------------------------------------------------------------------
# Test 4: Alle var(--token)-Referenzen in server-detail.css sind in tokens.css
# ---------------------------------------------------------------------------


def test_server_detail_css_uses_only_existing_tokens() -> None:
    """Jede var(--token)-Referenz in server-detail.css muss in tokens.css definiert sein.

    Faengt Drift: wenn ein Token in tokens.css geloescht oder umbenannt wird,
    schlaegt dieser Test fehl und nennt die fehlenden Token-Namen explizit.
    Ausnahme: var(--*) in Kommentaren (Wildcard-Notation im Datei-Header).
    """
    assert _SERVER_DETAIL_CSS.exists(), f"server-detail.css fehlt: {_SERVER_DETAIL_CSS}"
    assert _TOKENS_CSS.exists(), f"tokens.css fehlt: {_TOKENS_CSS}"

    css_text = _SERVER_DETAIL_CSS.read_text(encoding="utf-8")
    tokens_text = _TOKENS_CSS.read_text(encoding="utf-8")

    # Extrahiere alle var(--name)-Referenzen aus dem CSS (keine Wildcards / Sternchen).
    # Pattern: var( gefolgt von -- gefolgt von mindestens einem Buchstaben,
    # dann beliebig viele [a-z0-9-], abgeschlossen durch ).
    used_tokens: set[str] = set(re.findall(r"var\(--([a-z][a-z0-9-]*)\)", css_text))

    # Extrahiere definierte Token-Namen aus tokens.css.
    # Pattern: --name: (mit Doppelpunkt) an beliebiger Stelle.
    defined_tokens: set[str] = set(re.findall(r"--([a-z][a-z0-9-]+)\s*:", tokens_text))

    missing = sorted(used_tokens - defined_tokens)

    assert not missing, (
        f"server-detail.css referenziert {len(missing)} undefinierte Token(s) "
        f"die in tokens.css fehlen:\n" + "\n".join(f"  var(--{t})" for t in missing)
    )


# ---------------------------------------------------------------------------
# Test 5: Keine Hex-Farbliterale in server-detail.css (ADR-0033)
# ---------------------------------------------------------------------------


def test_server_detail_css_no_raw_hex_colors() -> None:
    """server-detail.css enthaelt keine rohen Hex-Farbwerte (#RGB / #RRGGBB / #RRGGBBAA).

    ADR-0033 Token-only-Policy: alle Farben kommen aus var(--token). Ausnahmen:
    - rgba()/rgb()-Aufrufe sind erlaubt (fuer die TODO(token)-markierten
      Transparenz-Varianten die noch keinen exakten Token haben).
    - Kommentar-Zeilen (beginnen nach optionalem Whitespace mit //) oder
      Kommentar-Bloecke (/* … */) werden aus der Pruefung ausgeschlossen.

    Strategie: gesamten CSS-Text von /* */-Kommentar-Bloecken bereinigen,
    dann auf #[0-9A-Fa-f]{3,8} pruefen.
    """
    assert _SERVER_DETAIL_CSS.exists(), f"server-detail.css fehlt: {_SERVER_DETAIL_CSS}"

    css_text = _SERVER_DETAIL_CSS.read_text(encoding="utf-8")

    # Kommentar-Bloecke (/* … */) entfernen — diese koennen legitim Hex-Werte
    # wie "#RRGGBB" als Dokumentation enthalten.
    css_no_comments = re.sub(r"/\*.*?\*/", "", css_text, flags=re.DOTALL)

    # Hex-Farbliterale suchen: # gefolgt von 3, 4, 6 oder 8 Hex-Ziffern,
    # die NICHT von weiteren Hex-Ziffern oder Buchstaben gefolgt werden
    # (Word-Boundary-Aequivalent).
    hex_pattern = re.compile(r"#[0-9A-Fa-f]{3,8}(?![0-9A-Fa-f])")
    matches = hex_pattern.findall(css_no_comments)

    assert not matches, (
        f"server-detail.css enthaelt {len(matches)} rohe Hex-Farbliteral(e) "
        f"ausserhalb von Kommentaren (ADR-0033 Token-only-Policy verletzt):\n"
        + "\n".join(f"  {m}" for m in matches)
    )
