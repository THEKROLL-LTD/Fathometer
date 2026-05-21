"""Block N (ADR-0021) — Adversarial: PURL mit XSS-Payload wird im UI escaped.

Zwei Verteidigungs-Linien:
1. Pydantic-Validator akzeptiert nur druckbares ASCII fuer PURL — ein
   Payload mit Non-ASCII landet bereits in der Vuln-Reject-Bahn.
2. ASCII-Payloads wie `<script>alert(1)</script>` koennen durchkommen
   (sind valides ASCII). Aber das Template muss sie escaped rendern —
   kein rohes `<script>` im HTML.

Dieser Test deckt Linie 2 ab: ein syntaktisch valides ASCII-PURL mit
HTML-Tags wird im `data-purl`-Attribut escaped, niemals roh.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from flask import Flask
from pydantic import ValidationError

from app.db import get_session_factory
from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from app.schemas.scan_envelope import TrivyPkgIdentifier
from tests._helpers import create_admin_user, login


def test_purl_non_ascii_xss_payload_rejected_by_validator() -> None:
    """Non-ASCII (Unicode) im PURL: Pydantic verwirft die Vuln."""
    payload = "pkg:deb/ubuntu/<script>alert(1)</script>‮@1.0"
    with pytest.raises(ValidationError):
        TrivyPkgIdentifier.model_validate({"PURL": payload})


def test_purl_ascii_xss_payload_renders_escaped(db_app: Flask) -> None:
    """ASCII-PURL mit `<script>` passiert den Validator — UI muss escapen."""
    payload = "pkg:deb/ubuntu/<script>alert(1)</script>@1.0"
    # Validator-Check zuerst: PURL ist druckbares ASCII, also valide.
    assert TrivyPkgIdentifier.model_validate({"PURL": payload}).purl == payload

    create_admin_user(db_app)
    factory = get_session_factory(db_app)
    now = datetime.now(tz=UTC)
    with db_app.app_context():
        sess = factory()
        try:
            srv = Server(name="srv-xss", api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            f = Finding(
                server_id=sid,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key="CVE-2026-77001",
                package_name="evil",
                installed_version="1.0",
                severity=Severity.CRITICAL,
                attack_vector=AttackVector.UNKNOWN,
                status=FindingStatus.OPEN,
                first_seen_at=now,
                last_seen_at=now,
                result_type="ubuntu",
                target_path=None,
                vendor_ids=None,
                package_purl=payload,
                severity_source="ubuntu",
            )
            sess.add(f)
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)
    # ADR-0025 §2/§3: Server-Detail rendert Findings default lazy
    # (Application-Group-Cards collapsed). `?flat=1` erzwingt den flachen
    # Tabellen-Pfad — sonst landet das `data-purl`-Attribut nicht im Initial-HTML.
    body = client.get(f"/servers/{sid}?flat=1").get_data(as_text=True)

    # Rohes `<script>` mit Klammern darf NIE im Markup auftauchen — Jinja
    # escaped es zu `&lt;script&gt;`.
    assert "<script>alert(1)</script>" not in body
    # Aber die escaped Form muss da sein (PURL wird im data-purl-Attribut
    # gerendert; Jinja-Autoescape macht daraus &lt;script&gt;).
    assert "&lt;script&gt;" in body or "&amp;lt;script" in body
