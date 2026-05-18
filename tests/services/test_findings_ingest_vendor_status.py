"""Block O Phase B (ADR-0022) — Vendor-Status + Provider-Severity-Map im Ingest.

Cases (Block-O-Brief Task #5 DoD):
* Trivy `Status="will_not_fix"` → Finding `vendor_status="will_not_fix"`.
* Trivy `Status="end_of_life"` → `vendor_status="eol"`.
* Trivy `Status="Foobar"` → `vendor_status="unknown"`.
* Trivy `Status=None` (kein Feld) → `vendor_status=None`.
* Trivy `VendorSeverity={"nvd":"high","ubuntu":"medium"}` → 1:1 persistiert.
* Trivy `VendorSeverity={"nvd":3,"ubuntu":2}` (Integer-Variante) →
  `{"nvd":"high","ubuntu":"medium"}` durch Envelope-Pre-Validator normalisiert.
* Re-Ingest mit jetzt fehlenden Feldern → Spalten auf NULL.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import Finding, Server
from app.schemas.scan_envelope import Envelope
from app.services.findings_ingest import ingest_scan


def _envelope(*, vulns: list[dict[str, Any]]) -> Envelope:
    return Envelope.model_validate(
        {
            "agent_version": "0.3.0",
            "host": {
                "os_family": "ubuntu",
                "os_version": "22.04",
                "os_pretty_name": "Ubuntu 22.04",
                "kernel_version": "5.15.0",
                "architecture": "x86_64",
                "trivy_version": "0.70.2",
            },
            "scan": {
                "SchemaVersion": 2,
                "Trivy": {"Version": "0.70.2"},
                "Results": [
                    {
                        "Target": "srv (ubuntu 22.04)",
                        "Class": "os-pkgs",
                        "Type": "ubuntu",
                        "Vulnerabilities": vulns,
                    }
                ],
            },
        }
    )


def _create_server(app: Flask, name: str) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _ingest(app: Flask, server_id: int, env: Envelope) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            ingest_scan(srv, env, session=sess, now=datetime.now(tz=UTC))
            sess.commit()
        finally:
            sess.close()


def _findings(app: Flask, server_id: int) -> list[Finding]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(select(Finding).where(Finding.server_id == server_id)).scalars().all()
            )
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# vendor_status — Normalisierung
# ---------------------------------------------------------------------------


def test_vendor_status_will_not_fix(db_app: Flask) -> None:
    sid = _create_server(db_app, "srv-wnf")
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10001",
                "PkgName": "openssl",
                "InstalledVersion": "3.0.2",
                "Severity": "HIGH",
                "Status": "will_not_fix",
            }
        ]
    )
    _ingest(db_app, sid, env)
    rows = _findings(db_app, sid)
    assert len(rows) == 1
    assert rows[0].vendor_status == "will_not_fix"


def test_vendor_status_end_of_life_normalized_to_eol(db_app: Flask) -> None:
    sid = _create_server(db_app, "srv-eol")
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10002",
                "PkgName": "curl",
                "InstalledVersion": "7.0",
                "Severity": "MEDIUM",
                "Status": "end_of_life",
            }
        ]
    )
    _ingest(db_app, sid, env)
    rows = _findings(db_app, sid)
    assert rows[0].vendor_status == "eol"


def test_vendor_status_foobar_normalized_to_unknown(db_app: Flask) -> None:
    sid = _create_server(db_app, "srv-foobar")
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10003",
                "PkgName": "wget",
                "InstalledVersion": "1.21",
                "Severity": "LOW",
                "Status": "Foobar",
            }
        ]
    )
    _ingest(db_app, sid, env)
    rows = _findings(db_app, sid)
    assert rows[0].vendor_status == "unknown"


def test_vendor_status_missing_field_is_none(db_app: Flask) -> None:
    sid = _create_server(db_app, "srv-no-status")
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10004",
                "PkgName": "bash",
                "InstalledVersion": "5.0",
                "Severity": "MEDIUM",
            }
        ]
    )
    _ingest(db_app, sid, env)
    rows = _findings(db_app, sid)
    assert rows[0].vendor_status is None


# ---------------------------------------------------------------------------
# severity_by_provider — String + Integer-Varianten
# ---------------------------------------------------------------------------


def test_vendor_severity_string_variant_persisted(db_app: Flask) -> None:
    """Trivy schreibt `VendorSeverity` als lowercase-Strings → 1:1 persistiert."""
    sid = _create_server(db_app, "srv-vs-str")
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10005",
                "PkgName": "openssh-server",
                "InstalledVersion": "9.0",
                "Severity": "HIGH",
                "VendorSeverity": {"nvd": "high", "ubuntu": "medium"},
            }
        ]
    )
    _ingest(db_app, sid, env)
    rows = _findings(db_app, sid)
    assert rows[0].severity_by_provider == {"nvd": "high", "ubuntu": "medium"}


def test_vendor_severity_integer_variant_normalized(db_app: Flask) -> None:
    """Trivy schreibt VendorSeverity als Integer (interner Code) → mapped via INT_MAP."""
    sid = _create_server(db_app, "srv-vs-int")
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10006",
                "PkgName": "glibc",
                "InstalledVersion": "2.35",
                "Severity": "HIGH",
                # Integer-Variante: 3=high, 2=medium, 4=critical, 1=low.
                "VendorSeverity": {"nvd": 3, "ubuntu": 2},
            }
        ]
    )
    _ingest(db_app, sid, env)
    rows = _findings(db_app, sid)
    assert rows[0].severity_by_provider == {"nvd": "high", "ubuntu": "medium"}


def test_vendor_severity_missing_is_none(db_app: Flask) -> None:
    """Kein `VendorSeverity` im Envelope → Spalte ist None."""
    sid = _create_server(db_app, "srv-vs-none")
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10007",
                "PkgName": "perl",
                "InstalledVersion": "5.34",
                "Severity": "LOW",
            }
        ]
    )
    _ingest(db_app, sid, env)
    rows = _findings(db_app, sid)
    assert rows[0].severity_by_provider is None


# ---------------------------------------------------------------------------
# Re-Ingest: fehlendes Feld -> NULL (Quelle der Wahrheit = aktueller Scan)
# ---------------------------------------------------------------------------


def test_re_ingest_drops_vendor_status_and_severity_map_when_missing(db_app: Flask) -> None:
    sid = _create_server(db_app, "srv-reingest-drop")
    env1 = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10008",
                "PkgName": "rsync",
                "InstalledVersion": "3.2",
                "Severity": "MEDIUM",
                "Status": "will_not_fix",
                "VendorSeverity": {"nvd": "medium", "ubuntu": "low"},
            }
        ]
    )
    _ingest(db_app, sid, env1)
    rows1 = _findings(db_app, sid)
    assert rows1[0].vendor_status == "will_not_fix"
    assert rows1[0].severity_by_provider == {"nvd": "medium", "ubuntu": "low"}

    # Zweiter Scan ohne Status und ohne VendorSeverity.
    env2 = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10008",
                "PkgName": "rsync",
                "InstalledVersion": "3.2",
                "Severity": "MEDIUM",
            }
        ]
    )
    _ingest(db_app, sid, env2)
    rows2 = _findings(db_app, sid)
    assert len(rows2) == 1
    assert rows2[0].vendor_status is None
    assert rows2[0].severity_by_provider is None
