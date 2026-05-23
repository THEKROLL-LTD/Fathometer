"""Pure-Unit Template-Smoke-Tests fuer den Footer (_footer.html).

Block W Phase B.

Prueft:
- Bei secscan_version="v0.12.0" enthaelt der Output "v0.12.0" und
  einen Link auf ...releases/tag/v0.12.0.
- Bei secscan_version="dev" zeigt der Version-Link die Basis-Repo-URL
  (kein "releases/tag/vdev").
- GitHub-Icon-Link auf https://github.com/THEKROLL-LTD/fathometer vorhanden.
- Tagline "thekroll ltd" rechts vorhanden.
- docs-Link auf README vorhanden.

Render-Pattern:
  render_template("layout/_footer.html", secscan_version="v0.12.0")
  innerhalb von app.test_request_context("/").
"""

from __future__ import annotations

import pytest
from flask import Flask

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}

_REPO_BASE_URL = "https://github.com/THEKROLL-LTD/fathometer"


def _render_footer(app: Flask, monkeypatch: pytest.MonkeyPatch, version: str) -> str:
    """Rendert _footer.html mit gegebenem secscan_version."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/"):
        from flask import render_template

        return render_template("layout/_footer.html", secscan_version=version)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_footer_renders_version_string_present(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bei secscan_version='v0.12.0' enthaelt der Footer die Versionsnummer und Releases-URL.

    HINWEIS: Die Template-Implementierung hat einen bekannten Bug:
    das Template baut die URL als 'releases/tag/v' ~ _ver, wobei _ver='v0.12.0' ist.
    Das ergibt 'releases/tag/vv0.12.0' (doppeltes 'v').
    Dieser Test prueft lediglich dass '0.12.0' im Output vorhanden ist (als Smoke-Test).
    Der Bug ist in test_footer_release_url_contains_version_without_double_v dokumentiert.
    """
    html = _render_footer(app, monkeypatch, "v0.12.0")

    assert "0.12.0" in html, f"Versionsnummer '0.12.0' fehlt im Footer-Render. HTML: {html[:500]}"
    assert "releases/tag/" in html, (
        f"Releases-URL-Fragment 'releases/tag/' fehlt im Footer-Render. HTML: {html[:500]}"
    )


def test_footer_renders_dev_fallback_link(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bei secscan_version='dev' zeigt der Link die Basis-Repo-URL, kein releases/tag/vdev."""
    html = _render_footer(app, monkeypatch, "dev")

    # "dev"-Version soll keinen Releases-URL generieren
    assert "releases/tag/vdev" not in html, (
        "Bei 'dev'-Version darf kein 'releases/tag/vdev'-Link erscheinen"
    )
    # Stattdessen soll die Basis-URL vorhanden sein
    assert _REPO_BASE_URL in html, (
        f"Basis-Repo-URL '{_REPO_BASE_URL}' fehlt im Footer bei 'dev'-Version"
    )


def test_footer_renders_github_icon_link(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub-Icon-Link auf https://github.com/THEKROLL-LTD/fathometer vorhanden."""
    html = _render_footer(app, monkeypatch, "v0.12.0")

    assert _REPO_BASE_URL in html, f"GitHub-Link '{_REPO_BASE_URL}' fehlt im Footer-Render"
    # Icon-Link hat class="footer__link--icon"
    assert "footer__link--icon" in html, (
        "GitHub-Icon-Link-Klasse 'footer__link--icon' fehlt im Footer-Render"
    )


def test_footer_renders_docs_link(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """docs-Link auf GitHub README vorhanden."""
    html = _render_footer(app, monkeypatch, "v0.12.0")

    assert "fathometer#readme" in html, "docs-Link auf fathometer#readme fehlt im Footer-Render"
    assert "docs" in html, "Text 'docs' fehlt im Footer-Render"


def test_footer_renders_tagline(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Footer-Tagline 'thekroll ltd · human intent. machine precision.' ist vorhanden."""
    html = _render_footer(app, monkeypatch, "v0.12.0")

    assert "thekroll ltd" in html, "Tagline 'thekroll ltd' fehlt im Footer-Render"
    assert "human intent. machine precision." in html, (
        "Tagline 'human intent. machine precision.' fehlt im Footer-Render"
    )


def test_footer_renders_github_text(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Footer enthaelt 'github' als sichtbaren Link-Text."""
    html = _render_footer(app, monkeypatch, "v0.12.0")

    assert "github" in html, "Text 'github' fehlt im Footer-Render"


def test_footer_release_url_contains_version_without_double_v(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Releases-URL hat kein doppeltes 'v' (z.B. nicht releases/tag/vv0.12.0).

    secscan_version='v0.12.0' -> URL endet auf '/releases/tag/v0.12.0'
    (kein '/releases/tag/vv0.12.0').

    IMPLEMENTIERUNGS-BUG ERKANNT: _footer.html baut die URL als
    'releases/tag/v' ~ _ver. Wenn _ver='v0.12.0' (mit 'v'-Prefix aus dem
    Context-Processor), entsteht 'releases/tag/vv0.12.0'.
    Loesungsoptionen:
    a) Template: 'releases/tag/' ~ _ver (ohne hardcoded 'v').
    b) Context-Processor: secscan_version ohne fuehrendes 'v' liefern,
       Template rendert 'v{{ secscan_version }}' fuer Display, URL baut
       'releases/tag/v{{ secscan_version }}'.
    """
    html = _render_footer(app, monkeypatch, "v0.12.0")

    assert "releases/tag/vv" not in html, (
        "BUG: Releases-URL enthaelt doppeltes 'v' (releases/tag/vv...) — "
        "Bug im _footer.html: Template haengt 'v' vor secscan_version='v0.12.0' -> 'vv0.12.0'. "
        "Fix: Template-Zeile 27: 'releases/tag/' ~ _ver (ohne hartekodietes 'v')."
    )
    assert "releases/tag/v0.12.0" in html, (
        "Releases-URL 'releases/tag/v0.12.0' fehlt im Footer-Render"
    )
