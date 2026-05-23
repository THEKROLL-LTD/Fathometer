"""Pure-Unit-Tests fuer den Asset-Manifest-Loader und _asset_url-Helper.

Block W / ADR-0032 — Phase A.

Deckt:
- `_asset_url` gibt den gemappten, gehashten Pfad aus dem Mock-Manifest zurueck.
- `_asset_url` wirft RuntimeError bei fehlendem Key in Production-Mode.
- `_asset_url` faellt in Dev-Mode auf den unverhashten Pfad zurueck.
- `_load_asset_manifest` gibt leeres dict zurueck wenn Manifest-Datei fehlt.

Strategie fuer den Manifest-Cache:
  Das Modul haelt `app._asset_manifest` als None|dict-Global. Da der echte
  manifest.json auf Disk existiert, wird er beim ersten `_load_asset_manifest()`-
  Aufruf geladen und gecacht. Alle Tests, die einen bestimmten Manifest-Inhalt
  benoetigen, setzen den Cache via `monkeypatch.setattr(app_module, "_asset_manifest",
  {...})` BEVOR sie `_asset_url` aufrufen — so wird der Disk-Zugriff komplett
  uebersprungen (Double-Checked-Locking prueft `is not None` zuerst).

  Fuer den "fehlende Datei"-Test wird der Cache auf None (Miss-Zustand) gesetzt
  und `Path.exists` via monkeypatch auf `False` umgebogen.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# _load_asset_manifest — Verhalten bei fehlender Datei
# ---------------------------------------------------------------------------


def test_load_asset_manifest_missing_file_returns_empty_dict(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn manifest.json nicht existiert, gibt _load_asset_manifest {} zurueck.

    Strategie: Cache auf None setzen (erzwingt Disk-Pfad) und `Path.exists`
    via Patch auf False setzen (simuliert fehlende Datei ohne Filesystem-
    Aenderung).
    """
    import app as app_module

    # Cache-Miss erzwingen: None setzt den Cache zurueck.
    monkeypatch.setattr(app_module, "_asset_manifest", None)
    # `manifest_path.exists()` soll False zurueckgeben.
    with patch.object(Path, "exists", return_value=False):
        result = app_module._load_asset_manifest()

    assert result == {}, f"Erwartet leeres dict bei fehlender manifest.json, got: {result!r}"


# ---------------------------------------------------------------------------
# _asset_url — Mapping-Pfad (Key im Manifest vorhanden)
# ---------------------------------------------------------------------------


def test_asset_url_returns_hashed_filename_from_manifest(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_asset_url gibt den gehashten Pfad aus dem Manifest zurueck.

    Mock-Manifest: {"css/app.css": "css/app.abc123.css"}.
    Erwartet: url_for("static", filename="dist/css/app.abc123.css")
    = "/static/dist/css/app.abc123.css".
    """
    import app as app_module

    mock_manifest = {"css/app.css": "css/app.abc123.css"}
    monkeypatch.setattr(app_module, "_asset_manifest", mock_manifest)
    monkeypatch.delenv("SECSCAN_ENV", raising=False)

    with app.test_request_context("/"):
        result = app_module._asset_url("css/app.css")

    assert result == "/static/dist/css/app.abc123.css", (
        f"Erwartet '/static/dist/css/app.abc123.css', got: {result!r}"
    )


def test_asset_url_all_three_manifest_keys(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_asset_url mappt alle drei Build-Outputs korrekt.

    Stellt sicher, dass css/app.css, js/vendor.js und js/app.js
    alle korrekt aus dem Manifest aufgeloest werden.
    """
    import app as app_module

    mock_manifest = {
        "css/app.css": "css/app.abc123.css",
        "js/vendor.js": "js/vendor.def456.js",
        "js/app.js": "js/app.ghi789.js",
    }
    monkeypatch.setattr(app_module, "_asset_manifest", mock_manifest)
    monkeypatch.delenv("SECSCAN_ENV", raising=False)

    with app.test_request_context("/"):
        css_url = app_module._asset_url("css/app.css")
        vendor_url = app_module._asset_url("js/vendor.js")
        app_url = app_module._asset_url("js/app.js")

    assert css_url == "/static/dist/css/app.abc123.css", f"css: {css_url!r}"
    assert vendor_url == "/static/dist/js/vendor.def456.js", f"vendor: {vendor_url!r}"
    assert app_url == "/static/dist/js/app.ghi789.js", f"app: {app_url!r}"


# ---------------------------------------------------------------------------
# _asset_url — Error-Pfad: fehlendes Manifest-Key in Production
# ---------------------------------------------------------------------------


def test_asset_url_missing_key_raises_in_production(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_asset_url wirft RuntimeError wenn Key fehlt und SECSCAN_ENV != "dev".

    Leeres Manifest simuliert fehlerhaften Build (npm run build nicht
    ausgefuehrt oder Manifest unvollstaendig).
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", {})
    monkeypatch.setenv("SECSCAN_ENV", "production")

    with (
        app.test_request_context("/"),
        pytest.raises(RuntimeError, match=r"kein Mapping fuer 'css/app\.css'"),
    ):
        app_module._asset_url("css/app.css")


# ---------------------------------------------------------------------------
# _asset_url — Dev-Fallback bei fehlendem Key
# ---------------------------------------------------------------------------


def test_asset_url_missing_key_falls_back_in_dev(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_asset_url faellt in Dev-Mode (SECSCAN_ENV=dev) auf den unverhashten Pfad zurueck.

    Wenn das Manifest leer ist und SECSCAN_ENV=dev gesetzt ist, gibt _asset_url
    url_for("static", filename="dist/css/app.css") zurueck (ohne Hash).
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", {})
    monkeypatch.setenv("SECSCAN_ENV", "dev")

    with app.test_request_context("/"):
        result = app_module._asset_url("css/app.css")

    assert result == "/static/dist/css/app.css", (
        f"Erwartet '/static/dist/css/app.css' (Dev-Fallback ohne Hash), got: {result!r}"
    )


def test_asset_url_missing_key_falls_back_when_env_unset(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_asset_url faellt zurueck wenn SECSCAN_ENV nicht gesetzt ist.

    Default in _asset_url ist "dev" (os.environ.get("SECSCAN_ENV", "dev")),
    daher ist ein fehlender Key ohne SECSCAN_ENV ein Dev-Fallback (kein Fehler).
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", {})
    monkeypatch.delenv("SECSCAN_ENV", raising=False)

    with app.test_request_context("/"):
        result = app_module._asset_url("css/app.css")

    assert result == "/static/dist/css/app.css", (
        f"Dev-Fallback erwartet '/static/dist/css/app.css', got: {result!r}"
    )


def test_asset_url_dev_fallback_all_three_keys(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dev-Fallback funktioniert fuer alle drei Build-Output-Schluesseln."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", {})
    monkeypatch.setenv("SECSCAN_ENV", "dev")

    with app.test_request_context("/"):
        css_url = app_module._asset_url("css/app.css")
        vendor_url = app_module._asset_url("js/vendor.js")
        app_js_url = app_module._asset_url("js/app.js")

    assert css_url == "/static/dist/css/app.css", f"css: {css_url!r}"
    assert vendor_url == "/static/dist/js/vendor.js", f"vendor: {vendor_url!r}"
    assert app_js_url == "/static/dist/js/app.js", f"app: {app_js_url!r}"
