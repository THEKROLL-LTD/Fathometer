"""Pure-Unit Template-Smoke-Tests fuer dashboard/_sysline.html (Block W Phase F).

Prueft:
  - last_scan: rendert "last scan Nm ago"-Format.
  - last_scan=None: rendert "never" (Default-Text).
  - epss-feed: Label + Status-Wert.
  - kev-feed: Label vorhanden.
  - worker: Label + Status-Wert (oder "off" wenn None).
  - Accent-Prompt '>' (sysline__prompt-Klasse).
  - id='sysline' fuer OOB-Swap (ADR-0036).

Render-Pattern: Flask-App mit test_request_context + jinja_env.get_template().
_MOCK_MANIFEST verhindert Manifest-Lookup auf Disk.
"""

from __future__ import annotations

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}

_DEFAULT_SYSLINE = {
    "last_scan_ago": "3m",
    "epss_feed_status": "synced",
    "kev_feed_status": "synced",
    "worker_status": "healthy",
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _render_sysline(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    sysline: dict | None = None,
) -> str:
    """Rendert dashboard/_sysline.html mit Mock-Daten."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    data = sysline if sysline is not None else _DEFAULT_SYSLINE

    with app.test_request_context("/"):
        template = app.jinja_env.get_template("dashboard/_sysline.html")
        html = template.render(sysline=data)
    return html


# ---------------------------------------------------------------------------
# last_scan-Feld
# ---------------------------------------------------------------------------


def test_sysline_renders_last_scan_field(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render enthaelt 'last scan', den Wert und 'ago'.

    Template-Markup: 'last scan <b>3m ago</b>'
    """
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "last_scan_ago": "3m"})

    assert "last scan" in html, f"Label 'last scan' fehlt im Sysline-Render. HTML: {html[:400]}"
    assert "3m" in html, f"Wert '3m' fuer last_scan_ago fehlt. HTML: {html[:400]}"
    assert "ago" in html, f"'ago' fehlt nach dem last_scan_ago-Wert. HTML: {html[:400]}"


def test_sysline_renders_last_scan_never_when_none(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """last_scan_ago=None -> 'never' wird gerendert (Default-Text).

    Template-Logik: {% if sysline.last_scan_ago %}...{% else %}never{% endif %}
    """
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "last_scan_ago": None})

    assert "never" in html, f"'never' fehlt wenn last_scan_ago=None. HTML: {html[:400]}"
    # "ago" sollte nicht vorhanden sein wenn never gerendert wird
    # (Das Template zeigt "ago" nur wenn last_scan_ago vorhanden ist)
    assert "ago" not in html, (
        f"'ago' darf nicht erscheinen wenn last_scan_ago=None und 'never' gerendert wird. "
        f"HTML: {html[:400]}"
    )


def test_sysline_last_scan_shows_value_not_never_when_set(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """last_scan_ago='2h' -> '2h' sichtbar, 'never' nicht vorhanden."""
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "last_scan_ago": "2h"})

    assert "2h" in html, f"Wert '2h' fehlt. HTML: {html[:400]}"
    assert "never" not in html, (
        f"'never' darf nicht vorhanden sein wenn last_scan_ago='2h'. HTML: {html[:400]}"
    )


# ---------------------------------------------------------------------------
# epss-feed-Feld
# ---------------------------------------------------------------------------


def test_sysline_renders_epss_feed_field(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render enthaelt 'epss-feed' Label und den Status-Wert."""
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "epss_feed_status": "synced"})

    assert "epss-feed" in html, f"Label 'epss-feed' fehlt im Sysline-Render. HTML: {html[:400]}"
    assert "synced" in html, f"epss_feed_status-Wert 'synced' fehlt. HTML: {html[:400]}"


def test_sysline_renders_epss_feed_stale(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """epss_feed_status='stale' -> 'stale' wird gerendert."""
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "epss_feed_status": "stale"})

    assert "stale" in html, f"'stale' fehlt fuer epss_feed_status='stale'. HTML: {html[:400]}"


def test_sysline_renders_epss_feed_never(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """epss_feed_status='never' -> 'never' wird gerendert."""
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "epss_feed_status": "never"})

    assert "never" in html, f"'never' fehlt fuer epss_feed_status='never'. HTML: {html[:400]}"


# ---------------------------------------------------------------------------
# kev-feed-Feld
# ---------------------------------------------------------------------------


def test_sysline_renders_kev_feed_field(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render enthaelt 'kev-feed' Label und den Status-Wert."""
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "kev_feed_status": "stale"})

    assert "kev-feed" in html, f"Label 'kev-feed' fehlt im Sysline-Render. HTML: {html[:400]}"
    assert "stale" in html, f"kev_feed_status-Wert 'stale' fehlt. HTML: {html[:400]}"


# ---------------------------------------------------------------------------
# worker-Feld
# ---------------------------------------------------------------------------


def test_sysline_renders_worker_field(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Render enthaelt 'worker' Label und den Status-Wert."""
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "worker_status": "healthy"})

    assert "worker" in html, f"Label 'worker' fehlt im Sysline-Render. HTML: {html[:400]}"
    assert "healthy" in html, f"worker_status-Wert 'healthy' fehlt. HTML: {html[:400]}"


def test_sysline_renders_worker_off_when_none(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """worker_status=None -> 'off' wird gerendert (llm_mode='off').

    Template-Logik: {{ sysline.worker_status if sysline.worker_status is not none else 'off' }}
    """
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "worker_status": None})

    assert "worker" in html, f"Label 'worker' fehlt wenn worker_status=None. HTML: {html[:400]}"
    assert "off" in html, f"'off' soll gerendert werden wenn worker_status=None. HTML: {html[:400]}"


def test_sysline_renders_worker_down(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """worker_status='down' -> 'down' wird gerendert."""
    html = _render_sysline(app, monkeypatch, {**_DEFAULT_SYSLINE, "worker_status": "down"})

    assert "down" in html, f"'down' fehlt fuer worker_status='down'. HTML: {html[:400]}"


# ---------------------------------------------------------------------------
# Strukturelle Elemente — Prompt, ID, Separator
# ---------------------------------------------------------------------------


def test_sysline_has_accent_prompt(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sysline enthaelt den '>' Accent-Prompt (Klasse sysline__prompt).

    Das Template rendert: <span class="sysline__prompt">&gt;</span>
    &gt; ist HTML-Entity fuer '>'.
    """
    html = _render_sysline(app, monkeypatch)

    assert "sysline__prompt" in html, (
        "Klasse 'sysline__prompt' fehlt im Sysline-Render. "
        "Accent-Prompt '>' ist das Terminal-Brand-Element. HTML: {html[:400]}"
    )
    # &gt; ist die HTML-Entity fuer '>' — Jinja autoescaped
    assert "&gt;" in html, (
        f"'&gt;' (HTML-Entity fuer '>') fehlt im Sysline-Render. "
        f"Template rendert den Prompt als: <span class='sysline__prompt'>&gt;</span>. "
        f"HTML: {html[:400]}"
    )


def test_sysline_has_id_for_oob(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sysline-Wrapper hat id='sysline' fuer OOB-Swap-Target (ADR-0036).

    Der OOB-Response-Endpoint ersetzt dieses Element bei jedem Polling-Tick.
    """
    html = _render_sysline(app, monkeypatch)

    assert 'id="sysline"' in html, (
        "id='sysline' fehlt am Wrapper-Element. "
        "Wird als OOB-Swap-Target benoetigt (ADR-0036 §Endpoint-Response-Skizze). "
        f"HTML-Ausschnitt: {html[:400]}"
    )


def test_sysline_has_sysline_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sysline-Wrapper hat class='sysline' (CSS-Styling)."""
    html = _render_sysline(app, monkeypatch)

    assert 'class="sysline"' in html, (
        f"class='sysline' fehlt am Wrapper-Element. HTML-Ausschnitt: {html[:400]}"
    )


def test_sysline_has_pipe_separators(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sysline enthaelt Pipe-Separatoren zwischen den Feldern (sysline__sep-Klasse)."""
    html = _render_sysline(app, monkeypatch)

    assert "sysline__sep" in html, (
        "Klasse 'sysline__sep' (Pipe-Separator zwischen Feldern) fehlt. "
        f"HTML-Ausschnitt: {html[:400]}"
    )


def test_sysline_all_four_fields_present(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Alle 4 Felder sind im Render sichtbar: last scan, epss-feed, kev-feed, worker."""
    html = _render_sysline(app, monkeypatch)

    for field_label in ("last scan", "epss-feed", "kev-feed", "worker"):
        assert field_label in html, (
            f"Feld-Label '{field_label}' fehlt im Sysline-Render. "
            "Die Sysline soll 4 Felder enthalten (ADR-0036). "
            f"HTML-Ausschnitt: {html[:600]}"
        )
