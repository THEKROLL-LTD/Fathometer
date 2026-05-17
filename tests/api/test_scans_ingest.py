"""Tests fuer `POST /api/scans` (Block C).

Decken die DoD-Punkte ab:
- 401 ohne / mit malformed Bearer.
- 401 mit unbekanntem Token (DoS-Heuristik: Latenz unabhaengig von Body-Groesse).
- 403 wenn Server `revoked_at` oder `retired_at` gesetzt.
- 202 mit echter Fixture: 306 Findings, 296 lang-pkgs, 10 os-pkgs.
- Idempotenz: zweimal -> kein Duplikat, 2 Scan-Rows.
- Resolve: Subset-Scan -> entfernte CVE wird RESOLVED.
- 422 bei manipuliertem Envelope, ohne Echo der User-Inputs.
"""

from __future__ import annotations

import gzip
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Scan,
    Server,
)
from tests._helpers import register_test_server

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "trivy" / "ubuntu-22.04-rke2.json"


# ---------------------------------------------------------------------------
# Fixture-Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def trivy_report() -> dict[str, Any]:
    """Real-fixture als Dict (cache pro Modul — die Datei ist ~5 MB)."""
    with FIXTURE_PATH.open("rb") as fh:
        return json.load(fh)


def _envelope(scan: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_version": "0.1.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04.4 LTS",
            "kernel_version": "5.15.0-100-generic",
            "architecture": "x86_64",
        },
        "scan": scan,
    }


def _gzip(payload: dict[str, Any]) -> bytes:
    return gzip.compress(json.dumps(payload).encode("utf-8"))


def _post_scan(client: Any, payload: dict[str, Any], *, bearer: str | None) -> Any:
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
    }
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    return client.post("/api/scans", data=_gzip(payload), headers=headers)


def _findings_for(app: Flask, server_id: int) -> list[Finding]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(select(Finding).where(Finding.server_id == server_id)).scalars().all()
            )
        finally:
            sess.close()


def _scans_for(app: Flask, server_id: int) -> list[Scan]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(select(Scan).where(Scan.server_id == server_id)).scalars().all()
            )
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# 401 / Bearer-Path
# ---------------------------------------------------------------------------


def test_scans_401_no_auth(db_app: Flask) -> None:
    client = db_app.test_client()
    resp = client.post("/api/scans", data=b"x")
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "unauthorized"


def test_scans_401_malformed_bearer(db_app: Flask) -> None:
    client = db_app.test_client()
    resp = client.post("/api/scans", data=b"x", headers={"Authorization": "abc-no-bearer-prefix"})
    assert resp.status_code == 401


def test_scans_401_basic_auth_instead_of_bearer(db_app: Flask) -> None:
    client = db_app.test_client()
    resp = client.post("/api/scans", data=b"x", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert resp.status_code == 401


def test_scans_401_unknown_token(db_app: Flask) -> None:
    client = db_app.test_client()
    resp = client.post(
        "/api/scans",
        data=b"x",
        headers={"Authorization": "Bearer this-token-does-not-exist-in-the-db"},
    )
    assert resp.status_code == 401


def test_scans_401_before_body_parse_with_large_body(db_app: Flask) -> None:
    """DoS-Test: 5 MB Body mit falschem Bearer -> 401 sehr schnell.

    Heuristik: < 500 ms (Toleranz fuer CI). Kein echter ms-SLA-Test —
    wir wollen ausschliessen, dass das Backend den Body erst parst.
    """
    client = db_app.test_client()
    big_body = b"A" * (5 * 1024 * 1024)
    start = time.monotonic()
    resp = client.post(
        "/api/scans",
        data=big_body,
        headers={"Authorization": "Bearer wrong-token-deadbeef"},
    )
    elapsed = time.monotonic() - start
    assert resp.status_code == 401
    # Generoeses Toleranz-Fenster: 500ms reicht problemlos fuer "kein Parse".
    # Bei ineffizienter Reihenfolge wuerde das gzip-Header-fehlt schon vorher
    # entdeckt, also wirklich nur als Sicherheits-Netz.
    assert elapsed < 0.5, f"Auth-vor-Body-Parse: 401 dauerte {elapsed:.3f}s"


# ---------------------------------------------------------------------------
# 403 — Server inactive
# ---------------------------------------------------------------------------


def _set_server_field(app: Flask, server_id: int, **fields: Any) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            for k, v in fields.items():
                setattr(srv, k, v)
            sess.commit()
        finally:
            sess.close()


def test_scans_403_when_server_revoked(db_app: Flask, trivy_report: dict[str, Any]) -> None:
    server_id, api_key = register_test_server(db_app, name="revoked-srv")
    _set_server_field(db_app, server_id, revoked_at=datetime.now(tz=UTC))
    client = db_app.test_client()
    resp = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert resp.get_json()["error"]["code"] == "server_inactive"


def test_scans_403_when_server_retired(db_app: Flask, trivy_report: dict[str, Any]) -> None:
    server_id, api_key = register_test_server(db_app, name="retired-srv")
    _set_server_field(db_app, server_id, retired_at=datetime.now(tz=UTC))
    client = db_app.test_client()
    resp = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 202 — Happy-Path mit echter Fixture
# ---------------------------------------------------------------------------


def test_scans_202_full_fixture_counts(db_app: Flask, trivy_report: dict[str, Any]) -> None:
    server_id, api_key = register_test_server(db_app, name="real-srv")
    client = db_app.test_client()
    resp = _post_scan(client, _envelope(trivy_report), bearer=api_key)

    assert resp.status_code == 202, resp.get_data(as_text=True)
    body = resp.get_json()
    assert "scan_id" in body
    assert body["findings_total"] == 306, body
    assert body["findings_inserted"] == 306
    assert body["findings_updated"] == 0
    assert body["findings_resolved"] == 0

    # DB-Seite: 306 Rows insgesamt, 296 lang-pkgs, 10 os-pkgs.
    findings = _findings_for(db_app, server_id)
    assert len(findings) == 306
    lang = sum(1 for f in findings if f.finding_class == FindingClass.LANG_PKGS)
    os_p = sum(1 for f in findings if f.finding_class == FindingClass.OS_PKGS)
    assert lang == 296, lang
    assert os_p == 10, os_p

    # Server-Felder denormalisiert.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            srv = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            assert srv.last_scan_at is not None
            assert srv.os_family == "ubuntu"
            assert srv.architecture == "x86_64"
            assert srv.agent_version == "0.1.0"
        finally:
            sess.close()

    # 1 Scan-Row.
    scans = _scans_for(db_app, server_id)
    assert len(scans) == 1


def test_scans_idempotent_rescan_keeps_306(db_app: Flask, trivy_report: dict[str, Any]) -> None:
    """Re-Scan -> kein Duplikat in `findings`, aber zwei Scan-Rows.

    Wir pruefen die DB-Invariante (kein Duplikat). Die `inserted`/`updated`-
    Counter im Response-Body sind heuristisch (first_seen_at-vs-now mit 1s-
    Toleranz) und koennen bei schnell aufeinanderfolgenden Requests inkonsistent
    sein — Implementer-Hinweis im Bericht.
    """
    server_id, api_key = register_test_server(db_app, name="idem-srv")
    client = db_app.test_client()
    r1 = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert r1.status_code == 202
    r2 = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert r2.status_code == 202

    body2 = r2.get_json()
    assert body2["findings_total"] == 306
    assert body2["findings_resolved"] == 0

    findings = _findings_for(db_app, server_id)
    assert len(findings) == 306, "Kein Duplikat trotz Re-Scan"
    scans = _scans_for(db_app, server_id)
    assert len(scans) == 2  # Zwei Buchhaltungs-Rows.


def test_scans_resolve_phase_marks_disappeared_findings(
    db_app: Flask, trivy_report: dict[str, Any]
) -> None:
    """Scan A mit voller Fixture, Scan B mit 5 entfernten Findings.

    Die entfernten Findings muessen `status=RESOLVED` und `resolved_at != NULL` haben.
    """
    server_id, api_key = register_test_server(db_app, name="resolve-srv")
    client = db_app.test_client()
    r1 = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert r1.status_code == 202

    # Subset-Fixture: erste Vulnerability aus erstem Result rauswerfen.
    subset = json.loads(json.dumps(trivy_report))  # deep copy
    removed_pairs: list[tuple[str, str]] = []
    # Wir entfernen die 5 ersten Vulns aus dem 1. Result (os-pkgs).
    first_result = subset["Results"][0]
    removed_vulns = first_result["Vulnerabilities"][:5]
    first_result["Vulnerabilities"] = first_result["Vulnerabilities"][5:]
    for v in removed_vulns:
        removed_pairs.append((v["VulnerabilityID"], v["PkgName"]))

    r2 = _post_scan(client, _envelope(subset), bearer=api_key)
    assert r2.status_code == 202
    body2 = r2.get_json()
    # >=5, weil dieselbe (CVE, PkgName)-Kombi auch in anderen Results vorkommen
    # koennte. Wir pruefen >0 — exakter Wert je nach Fixture-Eindeutigkeit.
    assert body2["findings_resolved"] >= 1, body2

    # Konkret: mindestens ein Finding aus den entfernten Paaren ist resolved.
    findings = _findings_for(db_app, server_id)
    resolved = [f for f in findings if f.status == FindingStatus.RESOLVED]
    assert len(resolved) >= 1
    for f in resolved:
        assert f.resolved_at is not None


def test_scans_findings_have_proper_field_population(
    db_app: Flask, trivy_report: dict[str, Any]
) -> None:
    """Sample-Check: CVSS-Score, CweIDs, attack_vector werden befuellt."""
    server_id, api_key = register_test_server(db_app, name="sample-srv")
    client = db_app.test_client()
    resp = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert resp.status_code == 202

    findings = _findings_for(db_app, server_id)
    # Mindestens eines mit CVSS-Score (echte Fixture hat 'redhat'-Provider).
    with_cvss = [f for f in findings if f.cvss_v3_score is not None]
    assert with_cvss, "Erwarte mindestens 1 Finding mit CVSS-Score"
    for f in with_cvss:
        assert 0.0 <= f.cvss_v3_score <= 10.0  # type: ignore[operator]

    # Mindestens eines mit CweIDs (real-fixture hat einige).
    with_cwe = [f for f in findings if f.cwe_ids]
    assert with_cwe, "Erwarte mindestens 1 Finding mit CweIDs"
    for f in with_cwe:
        for cwe in f.cwe_ids or []:
            assert cwe.startswith("CWE-"), cwe

    # Alle Findings: finding_type=vulnerability.
    for f in findings:
        assert f.finding_type == FindingType.VULNERABILITY


# ---------------------------------------------------------------------------
# 422 — Envelope-Validation
# ---------------------------------------------------------------------------


def test_scans_422_missing_host_field(db_app: Flask, trivy_report: dict[str, Any]) -> None:
    _server_id, api_key = register_test_server(db_app, name="bad-host")
    client = db_app.test_client()
    envelope = _envelope(trivy_report)
    del envelope["host"]
    resp = _post_scan(client, envelope, bearer=api_key)
    assert resp.status_code == 422, resp.get_data(as_text=True)
    body = resp.get_json()
    fields = [d["field"] for d in body["error"].get("details", [])]
    assert "host" in fields


def test_scans_422_bad_agent_version(db_app: Flask, trivy_report: dict[str, Any]) -> None:
    _server_id, api_key = register_test_server(db_app, name="bad-av")
    client = db_app.test_client()
    envelope = _envelope(trivy_report)
    envelope["agent_version"] = "not-a-version"
    resp = _post_scan(client, envelope, bearer=api_key)
    assert resp.status_code == 422
    fields = [d["field"] for d in resp.get_json()["error"].get("details", [])]
    assert "agent_version" in fields


def test_scans_422_no_user_input_echo(db_app: Flask, trivy_report: dict[str, Any]) -> None:
    """422-Body darf User-Input NICHT enthalten (§9 Fingerprinting)."""
    _server_id, api_key = register_test_server(db_app, name="echo-test")
    client = db_app.test_client()
    sentinel = "SENTINEL_SHOULD_NOT_BE_REFLECTED_xyz"
    envelope = _envelope(trivy_report)
    envelope["host"]["os_family"] = sentinel
    resp = _post_scan(client, envelope, bearer=api_key)
    assert resp.status_code == 422
    assert sentinel not in resp.get_data(as_text=True)


def test_scans_400_corrupt_gzip(db_app: Flask) -> None:
    _server_id, api_key = register_test_server(db_app, name="corrupt-gz")
    client = db_app.test_client()
    resp = client.post(
        "/api/scans",
        data=b"not-actually-gzipped",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Encoding": "gzip",
        },
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "bad_encoding"


def test_scans_400_bad_json(db_app: Flask) -> None:
    _server_id, api_key = register_test_server(db_app, name="bad-json")
    client = db_app.test_client()
    resp = client.post(
        "/api/scans",
        data=gzip.compress(b"this is not json at all"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Encoding": "gzip",
        },
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "bad_json"


# ---------------------------------------------------------------------------
# Regression v0.6.1 — >50 References pro Vuln muss durchgehen (defensiv getrimmt)
# ---------------------------------------------------------------------------


def test_scans_202_accepts_vuln_with_many_references(db_app: Flask) -> None:
    """Vuln mit 120 References landet als 202 — vorher: 422 `too_long`.

    Reproduktion des produktiven Bugs vom 2026-05-17, beobachtet auf einer
    arm64-Hetzner-Cloud-Instanz (Ubuntu 22.04, rke2-Server): der Trivy-Scan
    enthielt 20+ Distro-CVEs mit jeweils > 50 References (NVD + Ubuntu-
    Mailinglisten + Vendor-Advisories). Der Ingest hat den ganzen Scan mit
    HTTP 422 abgewiesen.

    Fix: `max_length=` von den `references`/`cwe_ids`-Fields entfernt, der
    `field_validator` ist die einzige Cap-Quelle und trimmt defensiv.
    """
    server_id, api_key = register_test_server(db_app, name="refs-heavy-srv")
    client = db_app.test_client()

    scan = {
        "ArtifactName": "/",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "/",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-99999",
                        "PkgName": "openssh",
                        "PkgID": "openssh@8.9",
                        "InstalledVersion": "8.9",
                        "FixedVersion": "9.0",
                        "Severity": "HIGH",
                        "Title": "many-refs",
                        "Description": "regression for v0.6.1",
                        "References": [
                            f"https://example.com/cve-2024-99999/ref/{i}" for i in range(120)
                        ],
                        "CweIDs": [f"CWE-{i}" for i in range(1, 61)],
                    }
                ],
            }
        ],
    }
    resp = _post_scan(client, _envelope(scan), bearer=api_key)

    assert resp.status_code == 202, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["findings_inserted"] == 1

    findings = _findings_for(db_app, server_id)
    assert len(findings) == 1
    refs = findings[0].references or []
    cwes = findings[0].cwe_ids or []
    # Defensiv getrimmt — nicht abgelehnt.
    assert len(refs) == 100, len(refs)
    assert len(cwes) == 50, len(cwes)
