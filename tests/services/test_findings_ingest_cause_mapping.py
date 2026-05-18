"""Block N (ADR-0021) — Ursachen-Felder schreiben in Findings (Task #4b).

Cases (Block-Brief Task #4b DoD):
* os-pkgs (ubuntu) mit voller `PkgIdentifier.PURL` → Finding hat alle
  fuenf Cause-Felder + `package_name="openssl"` (ADR-0011 fuer os-pkgs:
  ohne `@target`-Suffix).
* lang-pkgs gobinary mit `Result.Target="usr/local/bin/kubelet"` →
  `target_path="usr/local/bin/kubelet"`, `result_type="gobinary"`,
  `package_name="golang.org/x/net@usr/local/bin/kubelet"` (Uebergangsformat).
* Re-Ingest identisch → UPSERT, kein Duplikat, kein `IntegrityError`.
* Re-Ingest mit jetzt fehlendem `SeveritySource` → Spalte auf NULL gesetzt.
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


def _envelope(*, results: list[dict[str, Any]]) -> Envelope:
    return Envelope.model_validate(
        {
            "agent_version": "0.2.0",
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
                "Results": results,
            },
        }
    )


def _create_server(app: Flask, name: str = "srv-cause") -> int:
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
# os-pkgs ubuntu
# ---------------------------------------------------------------------------


def test_os_pkgs_ubuntu_writes_all_five_cause_fields(db_app: Flask) -> None:
    sid = _create_server(db_app, name="srv-os")
    env = _envelope(
        results=[
            {
                "Target": "srv-os (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-12345",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.2-0ubuntu1.10",
                        "Severity": "HIGH",
                        "PkgIdentifier": {
                            "PURL": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04",
                            "UID": "abc-uid-1",
                        },
                        "SeveritySource": "ubuntu",
                        "VendorIDs": ["USN-1234-1"],
                    }
                ],
            }
        ]
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        srv = sess.execute(select(Server).where(Server.id == sid)).scalar_one()
        ingest_scan(srv, env, session=sess)
        sess.commit()
        sess.close()

    rows = _findings(db_app, sid)
    assert len(rows) == 1
    f = rows[0]
    # ADR-0011: os-pkgs hat KEINEN `@target`-Suffix im package_name.
    assert f.package_name == "openssl"
    assert (
        f.package_purl == "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04"
    )
    assert f.target_path == "srv-os (ubuntu 22.04)"
    assert f.result_type == "ubuntu"
    assert f.severity_source == "ubuntu"
    assert f.vendor_ids == ["USN-1234-1"]


# ---------------------------------------------------------------------------
# lang-pkgs gobinary
# ---------------------------------------------------------------------------


def test_lang_pkgs_gobinary_uses_target_suffix_and_target_path(db_app: Flask) -> None:
    sid = _create_server(db_app, name="srv-lang")
    env = _envelope(
        results=[
            {
                "Target": "usr/local/bin/kubelet",
                "Class": "lang-pkgs",
                "Type": "gobinary",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-67890",
                        "PkgName": "golang.org/x/net",
                        "InstalledVersion": "v0.17.0",
                        "Severity": "MEDIUM",
                        "PkgIdentifier": {"PURL": "pkg:golang/golang.org/x/net@v0.17.0"},
                        "SeveritySource": "ghsa",
                    }
                ],
            }
        ]
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        srv = sess.execute(select(Server).where(Server.id == sid)).scalar_one()
        ingest_scan(srv, env, session=sess)
        sess.commit()
        sess.close()

    rows = _findings(db_app, sid)
    assert len(rows) == 1
    f = rows[0]
    # ADR-0011-Uebergangsformat: `<pkg>@<target>` im package_name.
    assert f.package_name == "golang.org/x/net@usr/local/bin/kubelet"
    assert f.target_path == "usr/local/bin/kubelet"
    assert f.result_type == "gobinary"
    assert f.severity_source == "ghsa"
    assert f.package_purl == "pkg:golang/golang.org/x/net@v0.17.0"


# ---------------------------------------------------------------------------
# Re-Ingest: UPSERT
# ---------------------------------------------------------------------------


def _ingest(db_app: Flask, server_id: int, env: Envelope) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            srv = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            ingest_scan(srv, env, session=sess, now=datetime.now(tz=UTC))
            sess.commit()
        finally:
            sess.close()


def test_re_ingest_identical_no_duplicates(db_app: Flask) -> None:
    sid = _create_server(db_app, name="srv-reingest")
    env = _envelope(
        results=[
            {
                "Target": "srv-reingest (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-77001",
                        "PkgName": "curl",
                        "InstalledVersion": "7.81.0",
                        "Severity": "HIGH",
                        "SeveritySource": "nvd",
                    }
                ],
            }
        ]
    )
    _ingest(db_app, sid, env)
    _ingest(db_app, sid, env)
    rows = _findings(db_app, sid)
    assert len(rows) == 1
    assert rows[0].severity_source == "nvd"


def test_re_ingest_drops_severity_source_when_missing(db_app: Flask) -> None:
    """Quelle der Wahrheit ist der aktuelle Scan — fehlendes Feld → NULL."""
    sid = _create_server(db_app, name="srv-reingest-null")
    env1 = _envelope(
        results=[
            {
                "Target": "srv-reingest-null (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-77002",
                        "PkgName": "wget",
                        "InstalledVersion": "1.21.2",
                        "Severity": "MEDIUM",
                        "SeveritySource": "nvd",
                        "VendorIDs": ["USN-9999-1"],
                    }
                ],
            }
        ]
    )
    _ingest(db_app, sid, env1)
    rows1 = _findings(db_app, sid)
    assert rows1[0].severity_source == "nvd"
    assert rows1[0].vendor_ids == ["USN-9999-1"]

    # Zweiter Scan: SeveritySource und VendorIDs sind weg.
    env2 = _envelope(
        results=[
            {
                "Target": "srv-reingest-null (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-77002",
                        "PkgName": "wget",
                        "InstalledVersion": "1.21.2",
                        "Severity": "MEDIUM",
                    }
                ],
            }
        ]
    )
    _ingest(db_app, sid, env2)
    rows2 = _findings(db_app, sid)
    assert len(rows2) == 1
    assert rows2[0].severity_source is None
    assert rows2[0].vendor_ids is None
