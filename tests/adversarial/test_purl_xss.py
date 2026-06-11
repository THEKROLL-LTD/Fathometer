"""Block N (ADR-0021) / Block AA (ADR-0041) — Adversarial: XSS-Payloads in
Finding-Feldern werden im Server-Detail-Render escaped.

Zwei Verteidigungs-Linien:
1. Pydantic-Validator akzeptiert nur druckbares ASCII fuer PURL — ein
   Payload mit Non-ASCII landet bereits in der Vuln-Reject-Bahn.
2. ASCII-Payloads wie `<script>alert(1)</script>` koennen durchkommen
   (sind valides ASCII). Aber das Template muss sie escaped rendern —
   kein rohes `<script>` im HTML.

Block AA (ADR-0041): der `?flat=1`-Flat-Pfad und das `data-purl`-Attribut sind
entfernt; `package_purl` wird in keinem Finding-Template mehr gerendert. Linie 2
prueft daher jetzt Pure-Unit gegen das Group-Drilldown-Markup
(`group_findings_table.html`) anhand eines in der Summary gerenderten Feldes
(`package_name`) — kein DB-Roundtrip noetig.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from flask import Flask
from pydantic import ValidationError

from app.forms import AcknowledgeForm, CSRFOnlyForm, NoteForm, ReopenForm
from app.models import FindingStatus
from app.schemas.scan_envelope import TrivyPkgIdentifier


def test_purl_non_ascii_xss_payload_rejected_by_validator() -> None:
    """Non-ASCII (Unicode) im PURL: Pydantic verwirft die Vuln."""
    payload = "pkg:deb/ubuntu/<script>alert(1)</script>‮@1.0"
    with pytest.raises(ValidationError):
        TrivyPkgIdentifier.model_validate({"PURL": payload})


def test_finding_field_xss_payload_renders_escaped(app: Flask) -> None:
    """ASCII-`<script>`-Payload in einem gerenderten Finding-Feld
    (package_name) wird vom Group-Drilldown-Markup autoescaped — kein rohes
    `<script>` im HTML (Block AA, ADR-0041 / ADR-0038 §G4)."""
    payload = "<script>alert(1)</script>"
    finding = SimpleNamespace(
        id=7,
        identifier_key="CVE-2026-77001",
        is_kev=False,
        title="evil",
        package_name=payload,
        finding_class="os_package",
        installed_version="1.0",
        fixed_version=None,
        epss_score=None,
        cvss_v3_score=None,
        status=FindingStatus.OPEN,
        severity="critical",
        description=None,
        primary_url=None,
        references=None,
        notes=[],
    )
    with app.test_request_context("/servers/1"):
        template = app.jinja_env.get_template("_partials/group_findings_table.html")
        body = template.render(
            findings=[finding],
            note_form=NoteForm(),
            csrf_form=CSRFOnlyForm(),
            ack_form=AcknowledgeForm(),
            reopen_form=ReopenForm(),
        )

    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
