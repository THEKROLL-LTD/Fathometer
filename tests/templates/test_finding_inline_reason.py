"""Pure-Unit-Tests fuer ``_partials/group_findings_table.html`` (Block X Phase G3/G4, ADR-0038 §G3/§G4).

Prueft (DoD-Punkt 7, Block X Phase G):
  1.  Finding-Zeile rendert als <details class="sd-finding">, KEIN <tr>.
  2.  Finding-Zeile hat data-test="group-finding-row-<id>".
  3.  Inline-Reason rendert wenn f.risk_band_reason truthy.
  4.  Inline-Reason rendert NICHT wenn f.risk_band_reason=None.
  5.  Inline-Reason rendert NICHT wenn f.risk_band_reason="" (leer, falsy).
  6.  KRITISCH (G4-Sicherheit): risk_band_reason wird HTML-escaped (kein |safe).
  7.  Wrapper ist <div class="sd-findings-stack">.
  8.  Output enthaelt KEIN <table>, <thead>, <tr > Markup.
  9.  KEV-Badge rendert in der Summary wenn f.is_kev=True.

Render-Strategie:
  - ``app.jinja_env.get_template()`` fuer das Partial (Macro-Import via
    Flask-Template-Loader aufgeloest).
  - ``types.SimpleNamespace`` als Finding-Mock (kein DB-Zugriff).
  - Fehlende Attribute auf dem Namespace werden defensiv via getattr(f, x, None)
    in Macros aufgeloest — daher minimaler Mock genuegt.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Template-Pfad (fuer Source-Read)
# ---------------------------------------------------------------------------

_PARTIAL_PATH = (
    Path(__file__).parent.parent.parent
    / "app"
    / "templates"
    / "_partials"
    / "group_findings_table.html"
)

# Mock fuer Asset-Manifest (verhindert Disk-Lookup durch app._asset_manifest)
_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    finding_id: int = 42,
    identifier_key: str = "CVE-2024-1234",
    risk_band_reason: str | None = "vendor (redhat) severity HIGH",
    is_kev: bool = False,
    title: str | None = "OpenSSL Buffer Overflow",
    package_name: str | None = "openssl",
    finding_class: str | None = "os_package",
    installed_version: str | None = "3.0.2-0ubuntu1.12",
    fixed_version: str | None = "3.0.2-0ubuntu1.13",
    epss_score: float | None = 0.12,
    cvss_v3_score: float | None = 7.5,
    status: str | None = "open",
    severity: str | None = "high",
) -> SimpleNamespace:
    """Minimaler Finding-Mock fuer Template-Render."""
    return SimpleNamespace(
        id=finding_id,
        identifier_key=identifier_key,
        risk_band_reason=risk_band_reason,
        is_kev=is_kev,
        title=title,
        package_name=package_name,
        finding_class=finding_class,
        installed_version=installed_version,
        fixed_version=fixed_version,
        epss_score=epss_score,
        cvss_v3_score=cvss_v3_score,
        status=status,
        severity=severity,
    )


def _render_findings_table(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    findings: list[SimpleNamespace],
) -> str:
    """Rendert group_findings_table.html via Flask-Template-Loader."""
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    with app.test_request_context("/servers/1"):
        template = app.jinja_env.get_template("_partials/group_findings_table.html")
        return template.render(findings=findings)


# ===========================================================================
# Test 1 — Finding-Zeile ist <details>, KEIN <tr>
# ===========================================================================


def test_finding_row_renders_as_details_not_tr(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Render mit 1 Finding: Output enthaelt <details class="sd-finding" und id="finding-42".

    KEIN <tr id="finding-42"> (alter Markup-Stil).
    """
    finding = _make_finding(finding_id=42)
    html = _render_findings_table(app, monkeypatch, [finding])

    assert '<details class="sd-finding"' in html, (
        f"'<details class=\"sd-finding\"' fehlt im Output. HTML: {html!r}"
    )
    assert 'id="finding-42"' in html, f"'id=\"finding-42\"' fehlt im Output. HTML: {html!r}"
    assert '<tr id="finding-42"' not in html, (
        f"Altes '<tr id=\"finding-42\">' ist noch im Output (Block X G3 entfernt <tr>). "
        f"HTML: {html!r}"
    )


# ===========================================================================
# Test 2 — Finding-Zeile hat data-test-Anker
# ===========================================================================


def test_finding_row_has_data_test_anchor(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Output enthaelt data-test="group-finding-row-42"."""
    finding = _make_finding(finding_id=42)
    html = _render_findings_table(app, monkeypatch, [finding])

    assert 'data-test="group-finding-row-42"' in html, (
        f"'data-test=\"group-finding-row-42\"' fehlt im Output. HTML: {html!r}"
    )


# ===========================================================================
# Test 3 — Inline-Reason rendert wenn risk_band_reason truthy
# ===========================================================================


def test_inline_reason_rendered_when_risk_band_reason_set(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Render mit f.risk_band_reason='vendor (redhat) severity HIGH':
    Output enthaelt KI-Bewertung-Eyebrow + Reason-Text + sd-finding__reason-Klasse.
    """
    reason_text = "vendor (redhat) severity HIGH"
    finding = _make_finding(risk_band_reason=reason_text)
    html = _render_findings_table(app, monkeypatch, [finding])

    assert "KI-Bewertung" in html, (
        f"'KI-Bewertung'-Eyebrow fehlt bei gesetztem risk_band_reason. HTML: {html!r}"
    )
    assert reason_text in html, f"Reason-Text '{reason_text}' fehlt im Output. HTML: {html!r}"
    assert "sd-finding__reason" in html, (
        f"'sd-finding__reason'-Klasse fehlt bei gesetztem risk_band_reason. HTML: {html!r}"
    )
    assert "sd-finding__body" in html, (
        f"'sd-finding__body'-Klasse fehlt bei gesetztem risk_band_reason. HTML: {html!r}"
    )


# ===========================================================================
# Test 4 — Inline-Reason rendert NICHT wenn risk_band_reason=None
# ===========================================================================


def test_inline_reason_not_rendered_when_risk_band_reason_none(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Render mit f.risk_band_reason=None: kein sd-finding__body, kein KI-Bewertung."""
    finding = _make_finding(risk_band_reason=None)
    html = _render_findings_table(app, monkeypatch, [finding])

    assert "sd-finding__body" not in html, (
        f"'sd-finding__body' darf bei risk_band_reason=None NICHT rendern. HTML: {html!r}"
    )
    assert "KI-Bewertung" not in html, (
        f"'KI-Bewertung'-Eyebrow darf bei risk_band_reason=None NICHT rendern. HTML: {html!r}"
    )


# ===========================================================================
# Test 5 — Inline-Reason rendert NICHT wenn risk_band_reason="" (leer)
# ===========================================================================


def test_inline_reason_not_rendered_when_risk_band_reason_empty(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Render mit f.risk_band_reason='' (leer, falsy): kein Reason-Block.

    Jinja ``{%- if f.risk_band_reason -%}`` muss leeren String als falsy behandeln.
    """
    finding = _make_finding(risk_band_reason="")
    html = _render_findings_table(app, monkeypatch, [finding])

    assert "sd-finding__body" not in html, (
        f"'sd-finding__body' darf bei risk_band_reason='' NICHT rendern. HTML: {html!r}"
    )
    assert "KI-Bewertung" not in html, (
        f"'KI-Bewertung'-Eyebrow darf bei risk_band_reason='' NICHT rendern. HTML: {html!r}"
    )


# ===========================================================================
# Test 6 — KRITISCH: risk_band_reason ist HTML-escaped (kein |safe)
# ===========================================================================


def test_inline_reason_is_html_escaped_against_xss_payload(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KRITISCH (G4-Sicherheit): risk_band_reason mit XSS-Payload wird HTML-escaped.

    Jinja-Autoescape muss '<script>alert(1)</script>' zu
    '&lt;script&gt;alert(1)&lt;/script&gt;' escapen.
    Kein |safe darf die Escaping-Kette unterbrechen (ADR-0038 §G4).
    """
    xss_payload = "<script>alert(1)</script>"
    finding = _make_finding(risk_band_reason=xss_payload)
    html = _render_findings_table(app, monkeypatch, [finding])

    # Rohes Script-Tag darf NICHT im Output sein.
    assert "<script>alert(1)</script>" not in html, (
        f"XSS-Payload '<script>alert(1)</script>' ist UNESCAPED im Output! "
        f"Jinja-Autoescape muss greifen. Kein '|safe' auf risk_band_reason erlaubt "
        f"(ADR-0038 §G4). HTML: {html!r}"
    )
    # Escaped-Version muss vorhanden sein.
    assert "&lt;script&gt;" in html, (
        f"'&lt;script&gt;' (HTML-escaped) fehlt im Output. "
        f"Jinja-Autoescape hat nicht gegriffen. HTML: {html!r}"
    )


# ===========================================================================
# Test 7 — Wrapper ist sd-findings-stack
# ===========================================================================


def test_finding_uses_sd_findings_stack_wrapper(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Render mit 2+ Findings: Wrapper ist <div class='sd-findings-stack'>."""
    findings = [
        _make_finding(finding_id=1, identifier_key="CVE-2024-0001"),
        _make_finding(finding_id=2, identifier_key="CVE-2024-0002"),
    ]
    html = _render_findings_table(app, monkeypatch, findings)

    assert '<div class="sd-findings-stack">' in html, (
        f"'<div class=\"sd-findings-stack\">' fehlt als Wrapper bei 2+ Findings. HTML: {html!r}"
    )


# ===========================================================================
# Test 8 — kein <table>, <thead>, <tr > im Output
# ===========================================================================


def test_no_table_tr_markup_in_output(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Output enthaelt KEIN <table, <thead, <tr  (Block X G3: <table> -> <details>-Stack)."""
    findings = [_make_finding(finding_id=42)]
    html = _render_findings_table(app, monkeypatch, findings)

    assert "<table" not in html, (
        f"'<table' darf nach Block X G3 NICHT im Output sein (Umstieg auf <details>). "
        f"HTML: {html!r}"
    )
    assert "<thead" not in html, (
        f"'<thead' darf nach Block X G3 NICHT im Output sein. HTML: {html!r}"
    )
    # '<tr ' mit Leerzeichen — defensiv gegen Table-Reste
    assert "<tr " not in html, (
        f"'<tr ' (mit Leerzeichen) darf nach Block X G3 NICHT im Output sein. HTML: {html!r}"
    )


# ===========================================================================
# Test 9 — KEV-Badge rendert in der Summary wenn is_kev=True
# ===========================================================================


def test_kev_finding_renders_kev_badge_in_summary(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Render mit f.is_kev=True: Output enthaelt KEV-Badge-Markup.

    Das kev_badge-Macro rendert <span ...>KEV</span> bei is_kev=True.
    """
    finding = _make_finding(is_kev=True)
    html = _render_findings_table(app, monkeypatch, [finding])

    # kev_badge(is_kev=True) rendert 'KEV' in einem Badge-Span
    assert "KEV" in html, (
        f"'KEV'-Text fehlt bei is_kev=True. kev_badge-Macro muss KEV-Badge rendern. HTML: {html!r}"
    )
    # Alternativ per Klasse pruefe: badge-error wird bei KEV-Badge genutzt
    # (gemaess _macros.html Z. 139: badge-error + ring-1)
    assert "badge-error" in html, (
        f"'badge-error'-Klasse fehlt bei is_kev=True (kev_badge rendert badge-error). "
        f"HTML: {html!r}"
    )
