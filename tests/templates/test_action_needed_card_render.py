"""Pure-Unit Template-Smoke-Tests fuer dashboard/_action_needed_card.html.

Block W Phase D.

Prueft:
- scan_chars-Macro splitet Zahl-Chars in individuelle scan-flash-Spans.
- Brackets-Wrapping ([action needed]).
- CTA-Link fuehrt auf /findings?risk_band=escalate.
- Sub-Counter-Format: N escalate · N act · N pending.
- Wrapper hat id="action-needed-card" fuer Phase-F-OOB-Target.

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

_DEFAULT_CARD_DATA = {
    "server_count": 42,
    "hosts_total": 100,
    "escalate": 7,
    "act": 3,
    "pending": 12,
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _render_action_card(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    card_data: dict | None = None,
) -> str:
    """Rendert dashboard/_action_needed_card.html mit Mock-Daten."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    data = card_data if card_data is not None else _DEFAULT_CARD_DATA

    with app.test_request_context("/"):
        template = app.jinja_env.get_template("dashboard/_action_needed_card.html")
        html = template.render(action_needed_card_data=data)
    return html


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_action_needed_card_uses_scan_chars_macro(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_chars(42) splittet die Zahl in mindestens 2 scan-flash-Spans.

    42 hat 2 Ziffern -> mindestens 2 <span class="scan-flash">-Spans in stat__num.
    """
    html = _render_action_card(app, monkeypatch, {**_DEFAULT_CARD_DATA, "server_count": 42})

    # scan_chars(42) muss mindestens 2 scan-flash-Spans generieren (eine pro Ziffer).
    scan_flash_count = html.count('class="scan-flash"')
    assert scan_flash_count >= 2, (
        f"scan_chars(42) muss mindestens 2 scan-flash-Spans erzeugen (eine pro Ziffer), "
        f"hat {scan_flash_count} erzeugt. HTML-Laenge: {len(html)}"
    )


def test_action_needed_card_single_digit_has_scan_flash(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_chars(5) erzeugt mindestens 1 scan-flash-Span."""
    html = _render_action_card(app, monkeypatch, {**_DEFAULT_CARD_DATA, "server_count": 5})

    assert 'class="scan-flash"' in html, "scan_chars(5) muss mindestens 1 scan-flash-Span erzeugen"


def test_action_needed_card_brackets_wrapped(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """[action needed]-Label hat scan-flash-Bracket-Spans fuer [ und ]."""
    html = _render_action_card(app, monkeypatch)

    # Der Wrapper muss explizite bracket-Spans enthalten.
    assert 'class="bracket scan-flash"' in html, (
        "Bracket-Spans mit class='bracket scan-flash' fehlen im Action-Card-Render. "
        f"HTML-Ausschnitt: {html[:500]}"
    )


def test_action_needed_card_label_text_present(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Der Text 'action needed' ist im Render vorhanden (als scan-chars oder direkt)."""
    html = _render_action_card(app, monkeypatch)

    # scan_chars("action needed") rendert jeden Buchstaben einzeln in Spans,
    # aber auch einen visually-hidden-Span mit dem Volltext.
    assert "action needed" in html, (
        "Text 'action needed' fehlt im Render (sollte in visually-hidden-Span stehen)"
    )


def test_action_needed_card_cta_links_to_findings_escalate(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Triage-CTA-Link fuehrt auf /findings?risk_band=escalate."""
    html = _render_action_card(app, monkeypatch)

    # url_for('findings.index', risk_band='escalate') muss im href enthalten sein.
    assert "risk_band=escalate" in html, (
        f"CTA-Link muss '?risk_band=escalate' enthalten. HTML-Ausschnitt: {html[:800]}"
    )


def test_action_needed_card_sub_counter_format(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sub-Zeile zeigt N escalate · N act · N pending mit den korrekten Werten."""
    data = {**_DEFAULT_CARD_DATA, "escalate": 7, "act": 3, "pending": 12}
    html = _render_action_card(app, monkeypatch, data)

    assert "7" in html, f"Escalate-Count '7' fehlt in Sub-Counter. HTML: {html[:600]}"
    assert "escalate" in html, "Label 'escalate' fehlt in Sub-Counter"
    assert "3" in html, f"Act-Count '3' fehlt in Sub-Counter. HTML: {html[:600]}"
    assert "act" in html, "Label 'act' fehlt in Sub-Counter"
    assert "12" in html, f"Pending-Count '12' fehlt in Sub-Counter. HTML: {html[:600]}"
    assert "pending" in html, "Label 'pending' fehlt in Sub-Counter"


def test_action_needed_card_has_id_action_needed_card(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrapper hat id='action-needed-card' fuer Phase-F-OOB-Target."""
    html = _render_action_card(app, monkeypatch)

    assert 'id="action-needed-card"' in html, (
        "id='action-needed-card' fehlt am Wrapper-Element. "
        "Dieses ID wird in Phase F als OOB-Target benoetigt. "
        f"HTML-Ausschnitt: {html[:400]}"
    )


def test_action_needed_card_has_stat_alarm_class(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrapper hat class='stat stat--alarm' (Color-Doctrine: nur escalate traegt cyan)."""
    html = _render_action_card(app, monkeypatch)

    assert "stat--alarm" in html, (
        "Klasse 'stat--alarm' fehlt. Die Action-Card muss stat--alarm tragen "
        "(ADR-0033 Color-Doctrine: nur escalate / alarm-State traegt cyan)."
    )


def test_action_needed_card_has_stat_num_id(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stat__num hat id='action-needed-num' fuer Phase-F-OOB-Partial-Update."""
    html = _render_action_card(app, monkeypatch)

    assert 'id="action-needed-num"' in html, (
        "id='action-needed-num' fehlt — wird in Phase F als OOB-Update-Target benoetigt."
    )


def test_action_needed_card_hosts_total_rendered(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """hosts_total-Wert ist im Render als '/ N hosts' sichtbar."""
    data = {**_DEFAULT_CARD_DATA, "hosts_total": 99}
    html = _render_action_card(app, monkeypatch, data)

    assert "99" in html, f"hosts_total '99' fehlt im Render. HTML: {html[:600]}"
    assert "hosts" in html, "Label 'hosts' fehlt im Render"


def test_action_needed_card_zero_counts(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Karte rendert korrekt wenn alle Counts 0 sind (kein Crash)."""
    data = {
        "server_count": 0,
        "hosts_total": 5,
        "escalate": 0,
        "act": 0,
        "pending": 0,
    }
    html = _render_action_card(app, monkeypatch, data)

    assert 'id="action-needed-card"' in html, "Card-Wrapper fehlt bei Null-Counts"
    assert "action needed" in html, "Label fehlt bei Null-Counts"
