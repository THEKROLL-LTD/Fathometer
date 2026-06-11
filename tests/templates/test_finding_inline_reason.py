"""Pure-Unit-Tests fuer ``_partials/group_findings_table.html`` (Block X Phase
G3/G4 + Block AA, ADR-0038 §G3/§G4 + ADR-0041).

Block AA (ADR-0041): der aufgeklappte Body kommt aus dem Single-Source-
Partial ``_partials/finding_inline_body.html``. Geprueft wird hier der
Summary-Markup-Vertrag (details-Row, sd-findings-stack, KEV-Badge) plus die
TICKET-012-Regression: KEINE Per-Finding-AI-Box mehr im Body. Der volle
Body-Vertrag liegt in ``test_finding_inline_body.py``.

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


def test_no_ai_assessment_box_in_group_body(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """TICKET-012: der Group-Drilldown-Body rendert KEINE Per-Finding-AI-Box
    (weder Reason noch Pending-Fallback) — das Assessment lebt nur auf der
    Application-Group-Card."""
    finding = _make_finding(finding_id=42)
    html = _render_findings_table(app, monkeypatch, [finding])
    # Body rendert weiterhin (Action-Button), aber ohne AI-Box.
    assert "sd-finding__body" in html
    assert "AI assessment" not in html
    assert "sd-ai-text--pending" not in html
    assert "finding-reason-pending-" not in html


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
