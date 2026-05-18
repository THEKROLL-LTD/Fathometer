"""Block N (ADR-0021) — `POST /api/scans` mit `host.trivy_version` und
Agent-Version-Gate.

Cases (Task #4 DoD):
* Envelope mit `host.trivy_version="0.70.2"` → Server-Feld gesetzt nach Ingest,
  `agent_version_seen_at` ist gesetzt.
* Envelope ohne `host.trivy_version` → Forward-Compat: Feld bleibt None,
  Ingest erfolgreich.
* Envelope mit `agent_version="0.0.5"` (unter `MIN_AGENT_VERSION`) → 400,
  Audit-Event `agent.rejected_outdated` mit `server_id` in der DB.
* Envelope mit `agent_version="0.2.0"` → 202.
* Reihenfolge: Request ohne Bearer-Header bekommt 401, auch wenn der Body
  einen ungueltigen `agent_version`-Wert haette.
"""

from __future__ import annotations

import gzip
import json
from typing import Any

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, Server
from tests._helpers import register_test_server


def _envelope(
    *,
    agent_version: str = "0.2.0",
    trivy_version: str | None = "0.70.2",
) -> dict[str, Any]:
    host: dict[str, Any] = {
        "os_family": "ubuntu",
        "os_version": "22.04",
        "os_pretty_name": "Ubuntu 22.04",
        "kernel_version": "5.15.0",
        "architecture": "x86_64",
    }
    if trivy_version is not None:
        host["trivy_version"] = trivy_version
    return {
        "agent_version": agent_version,
        "host": host,
        "scan": {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.2"},
            "Results": [
                {
                    "Target": "test-target",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-12345",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        },
    }


def _post(client: Any, payload: dict[str, Any], *, bearer: str | None) -> Any:
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
    }
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    return client.post(
        "/api/scans",
        data=gzip.compress(json.dumps(payload).encode("utf-8")),
        headers=headers,
    )


def _server(app: Flask, sid: int) -> Server:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return sess.execute(select(Server).where(Server.id == sid)).scalar_one()
        finally:
            sess.close()


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


# ---------------------------------------------------------------------------
# Envelope mit/ohne `trivy_version`
# ---------------------------------------------------------------------------


def test_envelope_with_trivy_version_sets_server_field(db_app: Flask) -> None:
    sid, key = register_test_server(db_app, name="srv-with-trivy")
    client = db_app.test_client()

    resp = _post(client, _envelope(trivy_version="0.70.2"), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    srv = _server(db_app, sid)
    assert srv.trivy_version == "0.70.2"
    assert srv.agent_version == "0.2.0"
    assert srv.agent_version_seen_at is not None


def test_envelope_without_trivy_version_keeps_field_none(db_app: Flask) -> None:
    """Forward-Compat: Agent v0.1.0 schickt das Feld nicht — Ingest bleibt erfolgreich."""
    sid, key = register_test_server(db_app, name="srv-no-trivy")
    client = db_app.test_client()

    resp = _post(client, _envelope(trivy_version=None, agent_version="0.1.0"), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    srv = _server(db_app, sid)
    assert srv.trivy_version is None
    assert srv.agent_version == "0.1.0"
    assert srv.agent_version_seen_at is not None


# ---------------------------------------------------------------------------
# Agent-Version-Gate
# ---------------------------------------------------------------------------


def test_envelope_below_min_agent_version_rejected_400(db_app: Flask) -> None:
    sid, key = register_test_server(db_app, name="srv-old-agent")
    client = db_app.test_client()

    resp = _post(client, _envelope(agent_version="0.0.5"), bearer=key)
    assert resp.status_code == 400, resp.get_data(as_text=True)[:300]
    body = resp.get_json()
    assert body["error"]["code"] == "agent_outdated"
    assert "0.0.5" in body["error"]["message"]

    # Audit-Event geschrieben.
    events = _audit_events(db_app, action="agent.rejected_outdated")
    assert len(events) == 1
    ev = events[0]
    # `target_id` ist String(128) im Audit-Modell — verglichen als str.
    assert str(ev.target_id) == str(sid)
    assert ev.target_type == "server"


def test_envelope_with_current_agent_version_accepted(db_app: Flask) -> None:
    """Smoke: aktueller Agent → 202 wie bisher."""
    _sid, key = register_test_server(db_app, name="srv-current-agent")
    client = db_app.test_client()
    resp = _post(client, _envelope(agent_version="0.2.0"), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]


# ---------------------------------------------------------------------------
# Auth vor Body-Parse — 401 hat Vorrang vor 400 (ADR-0021 Task #4)
# ---------------------------------------------------------------------------


def test_no_bearer_returns_401_even_with_outdated_agent_version(db_app: Flask) -> None:
    """Ohne Bearer-Header: 401 zuerst, auch wenn der Body sonst 400 ergeben wuerde."""
    client = db_app.test_client()
    # Kein Server registriert; Auth-Layer muss vor Body-Parse abbrechen.
    resp = _post(client, _envelope(agent_version="0.0.1"), bearer=None)
    assert resp.status_code == 401, resp.get_data(as_text=True)[:300]
    # KEIN audit-event `agent.rejected_outdated` — die Pruefung passiert
    # erst nach Auth.
    events = _audit_events(db_app, action="agent.rejected_outdated")
    assert events == []
