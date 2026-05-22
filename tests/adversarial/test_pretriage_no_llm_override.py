# block_r_sync_to_async — Phase G migriert (siehe docs/blocks/R-async-ingest.md §Phase G).
# LLM-Override-Schutz wandert in Worker-Sub-Tick bei Async-Cutover; Phase G passt an.
"""Adversarial: LLM-gesetzte Risk-Bands ueberleben Re-Ingest.

Block O, ADR-0022 §Re-Evaluation:

> Findings mit `risk_band_source == "llm"` werden vom Caller (Ingest-Loop in
> `app/api/scans.py`) NICHT erneut von `pretriage()` evaluiert. Die LLM-
> Entscheidung (Block P) ist authoritativer als die deterministische
> Pre-Triage und darf nicht stillschweigend ueberschrieben werden.

Konkret muss gelten:
  * `finding.risk_band` bleibt unveraendert.
  * `finding.risk_band_source` bleibt `"llm"`.
  * `finding.risk_band_reason` bleibt unveraendert.
  * `finding.risk_band_computed_at` bleibt unveraendert.
  * Field-Level-Invarianten bleiben auch nach Re-Ingest erhalten.

Plus: in einer Mischmenge engine+llm muss die Pre-Triage genau die
engine-Findings re-evaluieren und die llm-Findings unangetastet lassen.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from typing import Any

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import Finding
from tests._helpers import register_test_server, run_scan_synchronously

# ---------------------------------------------------------------------------
# Envelope-Builder (analog `tests/api/test_scans_risk_pretriage.py`).
# ---------------------------------------------------------------------------


def _minimal_host_state() -> dict[str, Any]:
    return {
        "snapshot_at": "2026-05-18T03:14:22Z",
        "tools_available": ["ss", "ps"],
        "gaps": [],
        "listeners": [],
        "processes": [],
        "kernel_modules": [],
        "services": [],
    }


def _envelope(vulns: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "agent_version": "0.3.0",
        "host": {
            "hostname": "pretriage-test-host",
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
                    "Target": "ubuntu",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": vulns,
                }
            ],
        },
        "host_state": _minimal_host_state(),
    }


def _post(client: Any, payload: dict[str, Any], *, bearer: str) -> Any:
    return client.post(
        "/api/scans",
        data=gzip.compress(json.dumps(payload).encode("utf-8")),
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Authorization": f"Bearer {bearer}",
        },
    )


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


def _set_llm_band(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    band: str,
    reason: str,
    computed_at: datetime,
) -> int:
    """Markiert ein Finding als LLM-bewertet (Block-P-Simulation)."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            f = sess.execute(
                select(Finding).where(
                    Finding.server_id == server_id,
                    Finding.identifier_key == identifier_key,
                )
            ).scalar_one()
            f.risk_band = band
            f.risk_band_source = "llm"
            f.risk_band_reason = reason
            f.risk_band_computed_at = computed_at
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Test 1: single Finding mit risk_band_source="llm" -> unveraendert nach Re-Ingest.
# ---------------------------------------------------------------------------


def test_llm_act_band_not_overwritten_on_reingest(db_app: Flask) -> None:
    """`risk_band="act"` mit `risk_band_source="llm"` ueberlebt Re-Ingest:
    keine Feld-Aenderung.

    Pre-Triage wuerde fuer LOW-Severity ohne KEV/EPSS sonst `noise` setzen —
    der LLM-Override hat Vorrang und darf nicht abgewertet werden.
    """
    sid, key = register_test_server(db_app, name="srv-adv-llm-keep")
    client = db_app.test_client()

    vulns = [
        {
            "VulnerabilityID": "CVE-2024-50001",
            "PkgName": "llm-keep-pkg",
            "InstalledVersion": "1.0",
            "Severity": "LOW",
        }
    ]

    # Initialer Ingest setzt das Finding auf `noise` (engine).
    r1 = run_scan_synchronously(db_app, client, key, _envelope(vulns))
    assert r1["status_code"] == 202, r1.get("response_body", "")[:200]
    assert r1["job_status"] == "done", f"Worker hat nicht done erreicht: {r1}"

    fixed_ts = datetime(2026, 5, 18, 3, 14, 22, tzinfo=UTC)
    fid = _set_llm_band(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-50001",
        band="act",
        reason="LLM determined act",
        computed_at=fixed_ts,
    )

    # Re-Ingest mit identischen Daten — LLM-Band muss stehen bleiben.
    r2 = run_scan_synchronously(db_app, client, key, _envelope(vulns))
    assert r2["status_code"] == 202, r2.get("response_body", "")[:200]
    assert r2["job_status"] == "done", f"Worker hat nicht done erreicht: {r2}"

    findings = _findings(db_app, sid)
    assert len(findings) == 1, "Re-Ingest darf keine Duplikate erzeugen."
    f = findings[0]
    assert f.id == fid

    # Felder unveraendert.
    assert f.risk_band == "act", f"risk_band wurde ueberschrieben: {f.risk_band}"
    assert f.risk_band_source == "llm", f"risk_band_source wurde umgesetzt: {f.risk_band_source}"
    assert f.risk_band_reason == "LLM determined act", (
        f"risk_band_reason wurde ueberschrieben: {f.risk_band_reason!r}"
    )
    assert f.risk_band_computed_at == fixed_ts, (
        f"risk_band_computed_at wurde ueberschrieben: {f.risk_band_computed_at}"
    )


# ---------------------------------------------------------------------------
# Test 2: gemischte Menge engine + llm — nur engine wird re-evaluiert.
# ---------------------------------------------------------------------------


def test_mixed_engine_and_llm_only_engine_reevaluated(db_app: Flask) -> None:
    """Zwei Findings am gleichen Server:
      * `engine_finding`: Severity LOW, soll von Pre-Triage in `noise` bleiben.
      * `llm_finding`: vorher manuell auf `risk_band="act"` / `source="llm"`.

    Re-Ingest mit Severity-Upgrade des engine-Findings (LOW -> HIGH) muss:
      * engine_finding -> Band wechselt auf `pending` (HIGH-Trigger).
      * llm_finding -> alles unveraendert.
    """
    sid, key = register_test_server(db_app, name="srv-adv-mixed")
    client = db_app.test_client()

    vulns_initial = [
        {
            "VulnerabilityID": "CVE-2024-60001",
            "PkgName": "engine-pkg",
            "InstalledVersion": "1.0",
            "Severity": "LOW",
        },
        {
            "VulnerabilityID": "CVE-2024-60002",
            "PkgName": "llm-pkg",
            "InstalledVersion": "1.0",
            "Severity": "LOW",
        },
    ]

    r1 = run_scan_synchronously(db_app, client, key, _envelope(vulns_initial))
    assert r1["status_code"] == 202, r1.get("response_body", "")[:200]
    assert r1["job_status"] == "done", f"Worker hat nicht done erreicht: {r1}"

    # `CVE-2024-60002` zur LLM-Entscheidung promovieren.
    fixed_ts = datetime(2026, 5, 18, 3, 14, 22, tzinfo=UTC)
    llm_fid = _set_llm_band(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-60002",
        band="act",
        reason="LLM final: exposed and exploitable",
        computed_at=fixed_ts,
    )

    assert llm_fid > 0

    # Re-Ingest: engine-Vuln wird zu HIGH eskaliert; LLM-Vuln gleich.
    vulns_reingest = [
        {
            "VulnerabilityID": "CVE-2024-60001",
            "PkgName": "engine-pkg",
            "InstalledVersion": "1.0",
            "Severity": "HIGH",  # promoviert -> pending erwartet
        },
        {
            "VulnerabilityID": "CVE-2024-60002",
            "PkgName": "llm-pkg",
            "InstalledVersion": "1.0",
            "Severity": "LOW",
        },
    ]
    r2 = run_scan_synchronously(db_app, client, key, _envelope(vulns_reingest))
    assert r2["status_code"] == 202, r2.get("response_body", "")[:200]
    assert r2["job_status"] == "done", f"Worker hat nicht done erreicht: {r2}"

    findings_post = {f.identifier_key: f for f in _findings(db_app, sid)}
    assert len(findings_post) == 2

    # Engine-Finding wurde re-evaluiert auf `pending`.
    engine_f = findings_post["CVE-2024-60001"]
    assert engine_f.risk_band == "pending", (
        f"Engine-Finding sollte auf 'pending' eskaliert sein, ist: {engine_f.risk_band}"
    )
    assert engine_f.risk_band_source == "engine"

    # LLM-Finding ist unveraendert.
    llm_f = findings_post["CVE-2024-60002"]
    assert llm_f.risk_band == "act"
    assert llm_f.risk_band_source == "llm"
    assert llm_f.risk_band_reason == "LLM final: exposed and exploitable"
    assert llm_f.risk_band_computed_at == fixed_ts
