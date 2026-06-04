"""Pure-Unit-Tests fuer ``_partials/group_findings_table.html`` (Block X Phase
G3/G4 + Block AA, ADR-0038 §G3/§G4 + ADR-0041).

Block AA (ADR-0041): der aufgeklappte Body kommt jetzt aus dem Single-Source-
Partial ``_partials/finding_inline_body.html`` und rendert IMMER (AI-Reason
oder Pending-Fallback + Action-Button + Description/Primary/References/Notes).
Die frueheren "kein Body wenn reason None"-Asserts sind damit hinfaellig —
stattdessen pruefen wir hier den Summary-Markup-Vertrag und die Reason-
Darstellung. Der volle Body-Vertrag liegt in ``test_finding_inline_body.py``.

Render-Strategie:
  - ``app.jinja_env.get_template()`` fuer das Wrapper-Partial.
  - ``types.SimpleNamespace`` als Finding-Mock (kein DB-Zugriff).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from flask import Flask

from app.forms import AcknowledgeForm, CSRFOnlyForm, NoteForm, ReopenForm
from app.models import FindingStatus

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}


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
    status: FindingStatus = FindingStatus.OPEN,
    severity: str | None = "high",
    description: str | None = None,
    primary_url: str | None = None,
    references: list[str] | None = None,
    notes: list[Any] | None = None,
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
        description=description,
        primary_url=primary_url,
        references=references,
        notes=notes if notes is not None else [],
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
        return template.render(
            findings=findings,
            note_form=NoteForm(),
            csrf_form=CSRFOnlyForm(),
            ack_form=AcknowledgeForm(),
            reopen_form=ReopenForm(),
        )


def test_finding_row_renders_as_details_not_tr(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    finding = _make_finding(finding_id=42)
    html = _render_findings_table(app, monkeypatch, [finding])
    assert '<details class="sd-finding"' in html
    assert 'id="finding-42"' in html
    assert '<tr id="finding-42"' not in html


def test_finding_row_has_data_test_anchor(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    finding = _make_finding(finding_id=42)
    html = _render_findings_table(app, monkeypatch, [finding])
    assert 'data-test="group-finding-row-42"' in html


def test_inline_reason_rendered_when_risk_band_reason_set(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    reason_text = "vendor (redhat) severity HIGH"
    finding = _make_finding(risk_band_reason=reason_text)
    html = _render_findings_table(app, monkeypatch, [finding])
    assert "AI assessment" in html
    assert reason_text in html
    assert "sd-finding__body" in html
    assert "sd-ai-text" in html


def test_body_renders_pending_fallback_when_reason_none(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Block AA: bei risk_band_reason=None rendert der Body trotzdem — mit
    Pending-Fallback-Hint statt der KI-Bewertung."""
    finding = _make_finding(risk_band_reason=None)
    html = _render_findings_table(app, monkeypatch, [finding])
    assert "sd-finding__body" in html
    assert "pass 2" in html
    assert "sd-ai-text--pending" in html


def test_body_renders_pending_fallback_when_reason_empty(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _make_finding(risk_band_reason="")
    html = _render_findings_table(app, monkeypatch, [finding])
    assert "sd-finding__body" in html
    assert "sd-ai-text--pending" in html


def test_inline_reason_is_html_escaped_against_xss_payload(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    xss_payload = "<script>alert(1)</script>"
    finding = _make_finding(risk_band_reason=xss_payload)
    html = _render_findings_table(app, monkeypatch, [finding])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_finding_uses_sd_findings_stack_wrapper(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    findings = [
        _make_finding(finding_id=1, identifier_key="CVE-2024-0001"),
        _make_finding(finding_id=2, identifier_key="CVE-2024-0002"),
    ]
    html = _render_findings_table(app, monkeypatch, findings)
    assert '<div class="sd-findings-stack">' in html


def test_kev_finding_renders_kev_badge_in_summary(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _make_finding(is_kev=True)
    html = _render_findings_table(app, monkeypatch, [finding])
    assert "KEV" in html
    assert "badge-error" in html
