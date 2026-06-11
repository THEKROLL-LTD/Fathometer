"""Pure-Unit-Tests fuer ``_partials/finding_inline_body.html`` (Block AA, ADR-0041).

Single-Source-Inline-Body: Action-Button, Beschreibung, Quelle (Primary-URL),
References, Notes-Thread + Ack-/Reopen-Modal. Render direkt via
Flask-Template-Loader mit vollem Form-Kontext, kein DB-Roundtrip.

TICKET-012: Die Per-Finding-"AI assessment"-Box ist entfernt — das Assessment
ist ein Group-Level-Wert und wird nur noch auf der Application-Group-Card
gerendert. Die Tests hier pruefen die Abwesenheit der AI-Box im Finding-Body.

Sicherheit: description/references/primary_url NIE mit |safe.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from flask import Flask

from app.forms import AcknowledgeForm, CSRFOnlyForm, NoteForm, ReopenForm
from app.models import FindingStatus


def _finding(
    *,
    fid: int = 4711,
    identifier_key: str = "CVE-2018-1121",
    status: FindingStatus = FindingStatus.OPEN,
    description: str | None = "procps-ng local privilege escalation in top.",
    primary_url: str | None = "https://avd.aquasec.com/nvd/cve-2018-1121",
    references: list[str] | None = None,
    notes: list[Any] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=fid,
        identifier_key=identifier_key,
        status=status,
        description=description,
        primary_url=primary_url,
        references=references
        if references is not None
        else [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1121",
            "https://ubuntu.com/security/CVE-2018-1121",
        ],
        notes=notes if notes is not None else [],
    )


def _render_body(app: Flask, finding: SimpleNamespace) -> str:
    with app.test_request_context("/servers/1"):
        template = app.jinja_env.get_template("_partials/finding_inline_body.html")
        return template.render(
            finding=finding,
            note_form=NoteForm(),
            csrf_form=CSRFOnlyForm(),
            ack_form=AcknowledgeForm(),
            reopen_form=ReopenForm(),
        )


# --- AI-Box absent + Action-Button -----------------------------------------


def test_no_ai_assessment_box_in_body(app: Flask) -> None:
    """TICKET-012: keine Per-Finding-AI-Box mehr — weder Reason noch Pending."""
    html = _render_body(app, _finding(status=FindingStatus.OPEN))
    assert "AI assessment" not in html
    assert "sd-ai-text--pending" not in html
    assert "finding-reason-pending-" not in html


def test_ack_button_for_open(app: Flask) -> None:
    html = _render_body(app, _finding(status=FindingStatus.OPEN))
    assert "Acknowledge" in html
    assert "Re-open" not in html


def test_reopen_button_for_acknowledged(app: Flask) -> None:
    html = _render_body(app, _finding(status=FindingStatus.ACKNOWLEDGED))
    assert "Re-open" in html
    assert "ackOpen = true" not in html  # statt dessen reopenOpen
    assert "reopenOpen = true" in html


def test_action_button_has_data_test(app: Flask) -> None:
    html = _render_body(app, _finding(fid=99))
    assert 'data-test="finding-action-btn-99"' in html
    assert "sd-finding__action-btn" in html


# --- Description -----------------------------------------------------------


def test_description_rendered_when_present(app: Flask) -> None:
    html = _render_body(app, _finding(description="A clear description text."))
    assert "Description" in html
    assert "A clear description text." in html
    assert "sd-finding__desc" in html


def test_no_description_block_when_absent(app: Flask) -> None:
    html = _render_body(app, _finding(description=None))
    assert "sd-finding__desc-block" not in html


# --- Primary-URL -----------------------------------------------------------


def test_primary_url_rendered_when_present(app: Flask) -> None:
    html = _render_body(app, _finding(primary_url="https://avd.aquasec.com/x"))
    assert "Source" in html
    assert 'href="https://avd.aquasec.com/x"' in html
    assert 'rel="noopener noreferrer"' in html
    assert 'target="_blank"' in html


def test_no_primary_block_when_absent(app: Flask) -> None:
    html = _render_body(app, _finding(primary_url=None))
    assert "sd-finding__primary-block" not in html


def test_non_http_primary_url_filtered(app: Flask) -> None:
    html = _render_body(app, _finding(primary_url="javascript:alert(1)"))
    assert "sd-finding__primary-block" not in html
    assert "javascript:alert" not in html


# --- References ------------------------------------------------------------


def test_references_list_rendered(app: Flask) -> None:
    refs = ["https://nvd.nist.gov/a", "https://ubuntu.com/b"]
    html = _render_body(app, _finding(references=refs))
    assert "References (2)" in html
    for url in refs:
        assert f'href="{url}"' in html
    assert html.count('rel="noopener noreferrer"') >= 2


def test_references_count_excludes_non_http(app: Flask) -> None:
    refs = ["https://nvd.nist.gov/a", "javascript:alert(1)", "ftp://x/y", "https://ubuntu.com/b"]
    html = _render_body(app, _finding(references=refs))
    assert "References (2)" in html
    assert "javascript:alert" not in html
    assert "ftp://x/y" not in html


def test_no_refs_block_when_empty(app: Flask) -> None:
    html = _render_body(app, _finding(references=[]))
    assert "sd-finding__refs-block" not in html


# --- Notes -----------------------------------------------------------------


def test_notes_thread_included(app: Flask) -> None:
    html = _render_body(app, _finding())
    assert "notes-thread-4711" in html
    assert "Notes" in html


# --- IDs / structure -------------------------------------------------------


def test_body_data_test_id_present(app: Flask) -> None:
    html = _render_body(app, _finding(fid=4711))
    assert 'data-test="finding-body-4711"' in html
