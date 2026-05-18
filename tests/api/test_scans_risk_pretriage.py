"""Block O Phase C Task #8 — Pre-Triage-Aufruf im Ingest.

Cases:
* Vollstaendiger Ingest mit Snapshot → alle Findings haben
  `risk_band ∈ {noise, monitor, pending, unknown}`, `risk_band_source="engine"`,
  `risk_band_computed_at` gesetzt.
* Re-Ingest mit identischem Snapshot + identischen Findings → keine
  `risk.band_changed`-Audits, Bands unveraendert.
* Re-Ingest mit Trivy-DB-Update das ein CVE jetzt KEV-listet → Finding
  wechselt von `noise`/`monitor` auf `pending`, Audit `risk.band_changed`.
* Ingest ohne `host_state` → alle Findings haben `risk_band="unknown"`,
  Reason enthaelt "host snapshot missing".
* Finding mit `risk_band_source="llm"` und `risk_band="act"` (manuell gesetzt)
  → Re-Ingest ueberschreibt das NICHT, kein `risk.band_changed`, Counter zaehlt `act`.
"""

from __future__ import annotations

import gzip
import json
from typing import Any

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, Finding
from tests._helpers import register_test_server

# ---------------------------------------------------------------------------
# Envelope-Builder
# ---------------------------------------------------------------------------


def _minimal_host_state() -> dict[str, Any]:
    return {
        "snapshot_at": "2026-05-18T03:14:22Z",
        "tools_available": ["ss", "ps", "lsmod", "systemctl"],
        "gaps": [],
        "listeners": [],
        "processes": [],
        "kernel_modules": [],
        "services": [],
    }


def _envelope(
    *,
    agent_version: str = "0.3.0",
    host_state: dict[str, Any] | None = None,
    vulns: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if vulns is None:
        vulns = [
            {
                "VulnerabilityID": "CVE-2024-00001",
                "PkgName": "openssl",
                "InstalledVersion": "1.1.1",
                "Severity": "LOW",
            }
        ]
    env: dict[str, Any] = {
        "agent_version": agent_version,
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
                    "Target": "test-target",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": vulns,
                }
            ],
        },
    }
    if host_state is not None:
        env["host_state"] = host_state
    return env


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


def _audit_events(app: Flask, action: str) -> list[AuditEvent]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(select(AuditEvent).where(AuditEvent.action == action)).scalars().all()
            )
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
# Cases
# ---------------------------------------------------------------------------


def test_full_ingest_with_snapshot_assigns_engine_bands(db_app: Flask) -> None:
    _sid, key = register_test_server(db_app, name="srv-pre-bands")
    client = db_app.test_client()

    vulns = [
        # LOW + no EPSS + no KEV → noise.
        {
            "VulnerabilityID": "CVE-2024-00001",
            "PkgName": "low-pkg",
            "InstalledVersion": "1.0",
            "Severity": "LOW",
        },
        # MEDIUM + low EPSS → monitor.
        {
            "VulnerabilityID": "CVE-2024-00002",
            "PkgName": "mid-pkg",
            "InstalledVersion": "1.0",
            "Severity": "MEDIUM",
        },
        # HIGH → pending.
        {
            "VulnerabilityID": "CVE-2024-00003",
            "PkgName": "high-pkg",
            "InstalledVersion": "1.0",
            "Severity": "HIGH",
        },
    ]
    resp = _post(client, _envelope(host_state=_minimal_host_state(), vulns=vulns), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    findings = _findings(db_app, _sid)
    assert len(findings) == 3
    by_id = {f.identifier_key: f for f in findings}
    assert by_id["CVE-2024-00001"].risk_band == "noise"
    assert by_id["CVE-2024-00002"].risk_band == "monitor"
    assert by_id["CVE-2024-00003"].risk_band == "pending"

    for f in findings:
        assert f.risk_band_source == "engine"
        assert f.risk_band_computed_at is not None
        assert f.risk_band in {"noise", "monitor", "pending", "unknown"}

    # `risk.pretriage_evaluated`-Event genau einmal.
    evals = _audit_events(db_app, action="risk.pretriage_evaluated")
    assert len(evals) == 1
    meta = evals[0].event_metadata
    assert meta is not None
    counters = meta["counters"]
    assert counters["noise"] == 1
    assert counters["monitor"] == 1
    assert counters["pending"] == 1


def test_re_ingest_identical_no_band_change_audits(db_app: Flask) -> None:
    _sid, key = register_test_server(db_app, name="srv-pre-stable")
    client = db_app.test_client()

    vulns = [
        {
            "VulnerabilityID": "CVE-2024-10001",
            "PkgName": "stable-pkg",
            "InstalledVersion": "1.0",
            "Severity": "LOW",
        }
    ]
    payload = _envelope(host_state=_minimal_host_state(), vulns=vulns)

    resp1 = _post(client, payload, bearer=key)
    assert resp1.status_code == 202

    # Initialer Wechsel `None -> noise` ist ein band_changed-Event.
    changes_1 = _audit_events(db_app, action="risk.band_changed")
    assert len(changes_1) == 1
    assert changes_1[0].event_metadata is not None
    assert changes_1[0].event_metadata["from"] is None
    assert changes_1[0].event_metadata["to"] == "noise"

    # Zweiter Ingest mit identischen Daten — keine zusaetzlichen band_changed.
    resp2 = _post(client, payload, bearer=key)
    assert resp2.status_code == 202

    changes_2 = _audit_events(db_app, action="risk.band_changed")
    assert len(changes_2) == 1  # gleich geblieben

    findings = _findings(db_app, _sid)
    assert len(findings) == 1
    assert findings[0].risk_band == "noise"


def test_re_ingest_with_kev_promotion_emits_band_changed(db_app: Flask) -> None:
    _sid, key = register_test_server(db_app, name="srv-pre-kev")
    client = db_app.test_client()

    base_vuln = {
        "VulnerabilityID": "CVE-2024-20001",
        "PkgName": "kev-pkg",
        "InstalledVersion": "1.0",
        "Severity": "LOW",
    }

    # Erster Ingest — LOW, kein KEV → noise.
    resp1 = _post(
        client, _envelope(host_state=_minimal_host_state(), vulns=[base_vuln]), bearer=key
    )
    assert resp1.status_code == 202

    findings = _findings(db_app, _sid)
    assert len(findings) == 1
    assert findings[0].risk_band == "noise"

    # Zweiter Ingest — gleiche CVE, jetzt KEV-Hint. Trivy-DB-Update simuliert.
    kev_vuln: dict[str, Any] = dict(base_vuln)
    kev_vuln["IsKEV"] = True
    kev_vuln["CISAKEVDateAdded"] = "2024-06-01T00:00:00Z"

    resp2 = _post(client, _envelope(host_state=_minimal_host_state(), vulns=[kev_vuln]), bearer=key)
    assert resp2.status_code == 202

    findings = _findings(db_app, _sid)
    assert len(findings) == 1
    assert findings[0].risk_band == "pending"
    assert findings[0].is_kev is True

    # Zwei band_changed-Audits gesamt: None→noise und noise→pending.
    changes = _audit_events(db_app, action="risk.band_changed")
    # `from`-Werte: erstes Event None, zweites "noise".
    transitions = [(c.event_metadata["from"], c.event_metadata["to"]) for c in changes]
    assert (None, "noise") in transitions
    assert ("noise", "pending") in transitions


def test_ingest_without_host_state_assigns_unknown(db_app: Flask) -> None:
    _sid, key = register_test_server(db_app, name="srv-pre-no-snap")
    client = db_app.test_client()

    vulns = [
        {
            "VulnerabilityID": "CVE-2024-30001",
            "PkgName": "anything",
            "InstalledVersion": "1.0",
            "Severity": "HIGH",
        }
    ]
    resp = _post(client, _envelope(agent_version="0.2.0", host_state=None, vulns=vulns), bearer=key)
    assert resp.status_code == 202

    findings = _findings(db_app, _sid)
    assert len(findings) == 1
    f = findings[0]
    assert f.risk_band == "unknown"
    assert f.risk_band_source == "engine"
    assert f.risk_band_reason is not None
    assert "host snapshot missing" in f.risk_band_reason


def test_llm_band_not_overwritten_by_re_ingest(db_app: Flask) -> None:
    """Block-P-Simulation: Finding traegt `risk_band_source="llm"` + `risk_band="act"`.
    Re-Ingest darf das NICHT ueberschreiben, kein `risk.band_changed`, Counter `act`.
    """
    _sid, key = register_test_server(db_app, name="srv-pre-llm-keep")
    client = db_app.test_client()

    vulns = [
        {
            "VulnerabilityID": "CVE-2024-40001",
            "PkgName": "llm-pkg",
            "InstalledVersion": "1.0",
            "Severity": "LOW",  # Pre-Triage wuerde sonst `noise` setzen.
        }
    ]

    # Erster Ingest: setzt das Finding auf `noise` (engine).
    resp1 = _post(client, _envelope(host_state=_minimal_host_state(), vulns=vulns), bearer=key)
    assert resp1.status_code == 202

    # Manuell auf LLM-`act` setzen (Block-P-Simulation).
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            f = sess.execute(select(Finding).where(Finding.server_id == _sid)).scalar_one()
            f.risk_band = "act"
            f.risk_band_source = "llm"
            f.risk_band_reason = "LLM final: exposed sshd, patch available"
            sess.commit()
        finally:
            sess.close()

    # Audit-Events-Snapshot vor dem zweiten Ingest.
    before = _audit_events(db_app, action="risk.band_changed")
    before_count = len(before)

    # Zweiter Ingest — Pre-Triage muss `act` stehen lassen.
    resp2 = _post(client, _envelope(host_state=_minimal_host_state(), vulns=vulns), bearer=key)
    assert resp2.status_code == 202

    findings = _findings(db_app, _sid)
    assert len(findings) == 1
    f2 = findings[0]
    assert f2.risk_band == "act"
    assert f2.risk_band_source == "llm"
    assert f2.risk_band_reason == "LLM final: exposed sshd, patch available"

    # Keine zusaetzlichen band_changed-Events fuer dieses Finding.
    after = _audit_events(db_app, action="risk.band_changed")
    assert len(after) == before_count

    # Counter im pretriage_evaluated-Event zaehlt das LLM-`act` mit.
    evals = _audit_events(db_app, action="risk.pretriage_evaluated")
    last_eval = evals[-1]
    assert last_eval.event_metadata is not None
    counters = last_eval.event_metadata["counters"]
    assert counters.get("act") == 1
