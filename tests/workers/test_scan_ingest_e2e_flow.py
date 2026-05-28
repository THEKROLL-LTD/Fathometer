"""End-to-End-Smoke fuer den Async-Ingest-Flow (Block R, ADR-0026).

Marker: db_integration — testet HTTP-Edge → Worker-Pickup gegen die echte
Test-Postgres-DB. KEIN Docker-Compose-Start — das wird separat im
Operator-Smoke ausgefuehrt.

Verifiziert die beiden Schritte aus dem Operator-Cutover-Plan:
1. POST /api/scans → 202 + job_id binnen <1s.
2. Worker-Tick verarbeitet den Job → status='done' + Counts in `result`.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.config import Settings
from app.db import get_session_factory
from app.models import AuditEvent, ScanIngestJob
from app.workers.scan_ingest_worker import (
    _pick_next_scan_ingest_job_id,
    _process_scan_ingest_job,
)
from tests._helpers import register_test_server

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "trivy" / "ubuntu-22.04-rke2.json"

pytestmark = [pytest.mark.db_integration]


def _gzip_envelope(envelope: dict[str, Any]) -> bytes:
    return gzip.compress(json.dumps(envelope).encode("utf-8"))


def _build_envelope(hostname: str = "e2e-host") -> dict[str, Any]:
    with FIXTURE_PATH.open("rb") as fh:
        trivy_report = json.load(fh)
    return {
        "agent_version": "0.4.0",
        "host": {
            "hostname": hostname,
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04.4 LTS",
            "kernel_version": "5.15.0-100-generic",
            "architecture": "x86_64",
        },
        "scan": trivy_report,
    }


@pytest.fixture
def async_db_app(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """db_app mit aktiviertem async-Flag (analog test_scans_async_edge.py)."""
    settings: Settings = db_app.config["SECSCAN_SETTINGS"]
    monkeypatch.setattr(settings, "scan_ingest_async", True)
    return db_app


def test_full_async_flow_post_to_done(async_db_app: Flask) -> None:
    """End-to-End: POST → Worker → Status-Endpoint, alles im Async-Pfad.

    Operator-Smoke-Equivalent ohne Docker — die HTTP-Schicht (Edge + Status)
    laeuft im Flask-Test-Client gegen die echte Postgres-DB, der Worker-Tick
    laeuft direkt im Test-Thread.
    """
    factory = get_session_factory(async_db_app)
    client = async_db_app.test_client()

    with async_db_app.app_context():
        _srv_id, api_key = register_test_server(async_db_app, name="e2e-server")

    # --- 1. Edge: POST /api/scans → 202 + job_id ---
    envelope = _build_envelope()
    body = _gzip_envelope(envelope)
    started = datetime.now(UTC)

    resp = client.post(
        "/api/scans",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        },
    )
    edge_latency_ms = (datetime.now(UTC) - started).total_seconds() * 1000

    assert resp.status_code == 202, f"Erwartet 202, bekommen {resp.status_code}: {resp.data}"
    payload = resp.get_json()
    assert payload["status"] == "queued"
    assert isinstance(payload["job_id"], int)
    job_id = payload["job_id"]

    # Edge-Latenz sollte deutlich unter 1s sein (Operator-Erwartung).
    assert edge_latency_ms < 1000, f"Edge zu langsam: {edge_latency_ms:.0f}ms"

    # --- 1b. Audit-Event scan.queued vorhanden ---
    with async_db_app.app_context():
        sess = factory()
        try:
            queued_events = list(
                sess.execute(select(AuditEvent).where(AuditEvent.action == "scan.queued")).scalars()
            )
            assert len(queued_events) == 1, f"Erwartet 1 scan.queued, bekommen {len(queued_events)}"
            evt = queued_events[0]
            assert evt.actor == "e2e-server"
            meta = evt.event_metadata or {}
            assert meta.get("job_id") == job_id
            assert "payload_sha256" in meta
            assert meta.get("payload_bytes") > 0
        finally:
            sess.close()

    # --- 2. Worker: Pickup + Verarbeitung ---
    with async_db_app.app_context():
        pick_sess = factory()
        try:
            picked = _pick_next_scan_ingest_job_id(pick_sess)
            pick_sess.commit()
        finally:
            pick_sess.close()

    assert picked == job_id, f"Worker hat den falschen Job gepickt: {picked} vs {job_id}"

    _process_scan_ingest_job(job_id, factory, worker_id="e2e-worker")

    # --- 3. DB-State direkt verifizieren ---
    with async_db_app.app_context():
        verify_sess = factory()
        try:
            job = verify_sess.get(ScanIngestJob, job_id)
            assert job is not None
            assert job.status == "done", f"Worker hat nicht done erreicht: {job.status} {job.error}"
            assert job.payload_gzip is None, "Payload-Clear bei done verletzt!"
            assert job.scan_id is not None
            assert job.result is not None
            assert job.result["findings_total"] > 0  # echter Trivy-Fixture hat Findings

            # Audit scan.ingested vom Worker
            ingested = list(
                verify_sess.execute(
                    select(AuditEvent).where(AuditEvent.action == "scan.ingested")
                ).scalars()
            )
            assert len(ingested) == 1
            assert ingested[0].actor == "e2e-server"
        finally:
            verify_sess.close()
