"""Adversarial XSS-Tests fuer ``_partials/finding_inline_body.html`` (Block AA,
ADR-0041 §Audit / ADR-0038 §G4).

Double-Defense: Pydantic verhindert non-http(s)-URLs schon beim Ingest, das
Template re-checkt defensiv. Description/References/Primary-URL/Reason werden
ausschliesslich autoescaped gerendert (kein |safe). Notes laufen ueber
markdown_safe (nh3-Whitelist).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from flask import Flask

from app.forms import AcknowledgeForm, CSRFOnlyForm, NoteForm, ReopenForm
from app.models import FindingStatus


def _finding(**over: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "id": 1,
        "identifier_key": "CVE-2024-0001",
        "risk_band_reason": None,
        "status": FindingStatus.OPEN,
        "description": None,
        "primary_url": None,
        "references": None,
        "notes": [],
    }
    base.update(over)
    return SimpleNamespace(**base)


def _render(app: Flask, finding: SimpleNamespace) -> str:
    with app.test_request_context("/servers/1"):
        template = app.jinja_env.get_template("_partials/finding_inline_body.html")
        return template.render(
            finding=finding,
            note_form=NoteForm(),
            csrf_form=CSRFOnlyForm(),
            ack_form=AcknowledgeForm(),
            reopen_form=ReopenForm(),
        )


def test_description_script_is_autoescaped(app: Flask) -> None:
    html = _render(app, _finding(description="<script>alert('x')</script>"))
    assert "<script>alert('x')</script>" not in html
    assert "&lt;script&gt;" in html


def test_description_img_onerror_autoescaped(app: Flask) -> None:
    html = _render(app, _finding(description='<img src=x onerror="alert(1)">'))
    assert "<img src=x onerror=" not in html
    assert "&lt;img" in html


def test_reference_with_script_attr_filtered(app: Flask) -> None:
    """Eine Reference die kein http(s)-Prefix hat (z.B. mit eingebettetem
    Markup) wird vom Template-Filter verworfen — Double-Defense."""
    html = _render(app, _finding(references=['"><script>alert(1)</script>']))
    assert "<script>alert(1)</script>" not in html
    # Kein References-Block, weil das einzige Item gefiltert wurde.
    assert "sd-finding__refs-block" not in html


def test_primary_url_javascript_filtered(app: Flask) -> None:
    html = _render(app, _finding(primary_url="javascript:alert(document.cookie)"))
    assert "javascript:alert" not in html
    assert "sd-finding__primary-block" not in html


def test_reason_script_autoescaped(app: Flask) -> None:
    html = _render(app, _finding(risk_band_reason="<script>steal()</script>"))
    assert "<script>steal()</script>" not in html
    assert "&lt;script&gt;" in html
