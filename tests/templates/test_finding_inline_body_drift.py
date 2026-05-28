"""Single-Source-Drift-Test fuer den Inline-Finding-Body (Block AA, ADR-0041 +
CLAUDE.md §HTMX-OOB-Single-Source-Pattern).

Garantiert, dass alle Listen-Templates denselben Body aus
``_partials/finding_inline_body.html`` beziehen — kein hand-gerolltes
Duplikat-Markup, das auseinanderdriften koennte. Zwei Ebenen:

  1. Source-Level: jedes Wrapper-Template includet das Single-Source-Partial
     und enthaelt KEINEN inline-kopierten Reason-Body mehr.
  2. Render-Level: derselbe Finding liefert in Group-Drilldown und Triage-
     Queue strukturell identisches Body-Markup.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from flask import Flask

from app.forms import AcknowledgeForm, CSRFOnlyForm, NoteForm, ReopenForm
from app.models import FindingStatus

_TPL_DIR = Path(__file__).parent.parent.parent / "app" / "templates"

_WRAPPERS = [
    "_partials/group_findings_table.html",
    "servers/_partials/triage_findings_page.html",
    "_partials/bucket_findings_table.html",
    "_partials/pending_bucket_findings_table.html",
]


def test_all_wrappers_include_single_source_partial() -> None:
    for rel in _WRAPPERS:
        src = (_TPL_DIR / rel).read_text(encoding="utf-8")
        assert "_partials/finding_inline_body.html" in src, (
            f"{rel} includet das Single-Source-Body-Partial nicht"
        )


def test_no_wrapper_has_inline_reason_duplicate() -> None:
    """Kein Wrapper darf den alten inline-kopierten Reason-Body fuehren."""
    for rel in _WRAPPERS:
        src = (_TPL_DIR / rel).read_text(encoding="utf-8")
        assert "bucket-finding__body" not in src, f"{rel} hat altes bucket-finding__body-Markup"
        # Reason-Text direkt am f-Objekt (alter inline-Body) darf nicht mehr da sein.
        assert "{{ f.risk_band_reason }}" not in src, (
            f"{rel} rendert risk_band_reason noch inline statt via Partial"
        )


def _finding() -> SimpleNamespace:
    return SimpleNamespace(
        id=42,
        identifier_key="CVE-2024-0042",
        title="Boom",
        package_name="openssl",
        installed_version="1.0.0",
        fixed_version="1.0.1",
        epss_score=0.5,
        cvss_v3_score=7.5,
        severity="high",
        is_kev=False,
        risk_band_reason="reason text here",
        status=FindingStatus.OPEN,
        description="A description.",
        primary_url="https://avd.aquasec.com/x",
        references=["https://nvd.nist.gov/a"],
        notes=[],
    )


def _body_slice(html: str) -> str:
    start = html.index('<div class="sd-finding__body"')
    end = html.index("</details>", start)
    return html[start:end].strip()


def test_group_and_triage_render_identical_body(app: Flask) -> None:
    f = _finding()
    with app.test_request_context("/servers/1"):
        forms = {
            "note_form": NoteForm(),
            "csrf_form": CSRFOnlyForm(),
            "ack_form": AcknowledgeForm(),
            "reopen_form": ReopenForm(),
        }
        group_html = app.jinja_env.get_template("_partials/group_findings_table.html").render(
            findings=[f], **forms
        )
        triage_html = app.jinja_env.get_template(
            "servers/_partials/triage_findings_page.html"
        ).render(
            findings=[f],
            server=SimpleNamespace(id=1),
            band="escalate",
            page=1,
            total=1,
            total_pages=1,
            has_prev=False,
            has_next=False,
            **forms,
        )
    assert _body_slice(group_html) == _body_slice(triage_html), (
        "Body-Markup driftet zwischen Group-Drilldown und Triage-Queue"
    )
