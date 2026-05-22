"""Block N (ADR-0021) — Adversarial: `agent_version='0.0.1'` wird mit 400 abgelehnt.

Audit-Event `agent.rejected_outdated` wird mit `server_id` in der DB
geschrieben. KEIN stilles 202 mit veraltetem Agent — sonst koennte ein
Operator nicht zwischen "alles ok" und "Agent-Update faellig" unterscheiden.
"""

from __future__ import annotations

import gzip
import json
from typing import Any

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent
from tests._helpers import register_test_server


def _envelope(agent_version: str) -> dict[str, Any]:
    return {
        "agent_version": agent_version,
        "host": {
            "hostname": "outdated-agent-host",
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15.0",
            "architecture": "x86_64",
        },
        "scan": {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.2"},
            "Results": [],
        },
    }


def test_outdated_agent_version_rejected_with_400(db_app: Flask) -> None:
    sid, key = register_test_server(db_app, name="srv-too-old")
    client = db_app.test_client()
    resp = client.post(
        "/api/scans",
        data=gzip.compress(json.dumps(_envelope("0.0.1")).encode("utf-8")),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        },
    )
    assert resp.status_code == 400, resp.get_data(as_text=True)[:300]
    body = resp.get_json()
    # Async-Fast-Path (seit v0.12.0 einziger Pfad) liefert flat error-Format:
    # {"error": "agent_outdated"}. Vor v0.12.0 war der Sync-Pfad mit nested
    # {"error": {"code": ..., "message": ...}} aktiv — der ist entfernt.
    assert body == {"error": "agent_outdated"}, body

    # Audit-Event geschrieben — mit `server_id` und Metadata.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            events = list(
                sess.execute(
                    select(AuditEvent).where(AuditEvent.action == "agent.rejected_outdated")
                )
                .scalars()
                .all()
            )
        finally:
            sess.close()
    assert len(events) == 1, events
    ev = events[0]
    assert str(ev.target_id) == str(sid)
    assert ev.target_type == "server"
