# ruff: noqa: S104
"""Block O Phase C Task #7 — Snapshot-Persist im Ingest.

Cases:
* Envelope mit komplettem `host_state` → vier Snapshot-Tabellen befuellt,
  `Server.host_state_snapshot_at` gesetzt, Audit-Event `host_state.snapshot_received`.
* Envelope ohne `host_state` (alter Agent) → keine Snapshot-Tabellen-Aenderung,
  kein Crash, Pre-Triage faellt auf `snapshot_available=False`.
* Re-Ingest mit anderem Snapshot → alte Snapshot-Daten weg, neue da.
* Envelope mit `gaps=["kernel_modules"]` + leerer Modul-Liste → Modul-Tabelle
  leer, Audit-Event traegt `gaps=["kernel_modules"]`.
* Listener-Dedup: zwei identische `(proto, addr, port)`-Eintraege → 1 Row.
* Process-Dedup: zwei Eintraege mit gleicher PID → 1 Row.
* Snapshot-Persist-Fehler-Pfad: monkeypatch wirft `SQLAlchemyError` →
  Audit `host_state.parse_failed`, Findings-Ingest laeuft trotzdem,
  Pre-Triage liefert `unknown`.
"""

from __future__ import annotations

import gzip
import json
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session_factory
from app.models import (
    AuditEvent,
    Finding,
    Server,
    ServerKernelModule,
    ServerListener,
    ServerProcess,
    ServerService,
)
from tests._helpers import register_test_server

# ---------------------------------------------------------------------------
# Envelope-Builder
# ---------------------------------------------------------------------------


def _full_host_state() -> dict[str, Any]:
    return {
        "snapshot_at": "2026-05-18T03:14:22Z",
        "tools_available": ["ss", "ps", "lsmod", "systemctl"],
        "gaps": [],
        "listeners": [
            {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd", "pid": 1234},
            {
                "proto": "tcp",
                "addr": "127.0.0.1",
                "port": 5432,
                "process": "postgres",
                "pid": 5678,
            },
        ],
        "processes": [
            {"pid": 1234, "user": "root", "comm": "sshd", "args": "/usr/sbin/sshd -D"},
            {"pid": 5678, "user": "postgres", "comm": "postgres", "args": "/usr/lib/postgresql"},
        ],
        "kernel_modules": ["ext4", "nf_conntrack", "overlay"],
        "services": ["sshd.service", "postgresql.service"],
    }


def _envelope(
    *,
    agent_version: str = "0.3.0",
    host_state: dict[str, Any] | None = None,
    cve_severity: str = "LOW",
    cve_id: str = "CVE-2024-12345",
) -> dict[str, Any]:
    env: dict[str, Any] = {
        "agent_version": agent_version,
        "host": {
            "hostname": "host-state-test",
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
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": cve_id,
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "Severity": cve_severity,
                        }
                    ],
                }
            ],
        },
    }
    if host_state is not None:
        env["host_state"] = host_state
    return env


def _post(client: Any, payload: dict[str, Any], *, bearer: str) -> Any:
    """Wrapper: sendet POST und triggert den Worker synchron (seit v0.12.0
    ist Async der einzige Pfad — der Test braucht den DB-State nach dem
    Verarbeiten, nicht nach dem Edge-Insert).
    """
    resp = client.post(
        "/api/scans",
        data=gzip.compress(json.dumps(payload).encode("utf-8")),
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Authorization": f"Bearer {bearer}",
        },
    )
    if resp.status_code == 202:
        body = resp.get_json() or {}
        job_id = body.get("job_id")
        if isinstance(job_id, int):
            from app.db import get_session_factory
            from app.workers.scan_ingest_worker import _process_scan_ingest_job

            factory = get_session_factory(client.application)
            _process_scan_ingest_job(job_id, factory, worker_id="test-sync")
    return resp


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


def _count_in_table(app: Flask, model: type, server_id: int) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return len(
                list(
                    sess.execute(select(model).where(model.server_id == server_id)).scalars().all()
                )
            )
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def test_envelope_with_complete_host_state_fills_four_tables(db_app: Flask) -> None:
    sid, key = register_test_server(db_app, name="srv-snap-full")
    client = db_app.test_client()

    resp = _post(client, _envelope(host_state=_full_host_state()), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    assert _count_in_table(db_app, ServerListener, sid) == 2
    assert _count_in_table(db_app, ServerProcess, sid) == 2
    assert _count_in_table(db_app, ServerKernelModule, sid) == 3
    assert _count_in_table(db_app, ServerService, sid) == 2

    srv = _server(db_app, sid)
    assert srv.host_state_snapshot_at is not None

    events = _audit_events(db_app, action="host_state.snapshot_received")
    assert len(events) == 1
    meta = events[0].event_metadata
    assert meta is not None
    assert meta["listener_count"] == 2
    assert meta["process_count"] == 2
    assert "ss" in meta["tools_available"]
    assert meta["gaps"] == []


def test_envelope_without_host_state_no_snapshot_changes(db_app: Flask) -> None:
    """Alter Agent (kein host_state) — Tabellen bleiben leer, Pre-Triage → unknown."""
    sid, key = register_test_server(db_app, name="srv-no-snap")
    client = db_app.test_client()

    resp = _post(client, _envelope(agent_version="0.2.0", host_state=None), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    assert _count_in_table(db_app, ServerListener, sid) == 0
    assert _count_in_table(db_app, ServerProcess, sid) == 0
    assert _count_in_table(db_app, ServerKernelModule, sid) == 0
    assert _count_in_table(db_app, ServerService, sid) == 0

    srv = _server(db_app, sid)
    assert srv.host_state_snapshot_at is None

    # Kein snapshot_received-Event geschrieben.
    assert _audit_events(db_app, action="host_state.snapshot_received") == []

    # Pre-Triage hat alle Findings auf `unknown` gesetzt.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            findings = list(
                sess.execute(select(Finding).where(Finding.server_id == sid)).scalars().all()
            )
            assert len(findings) == 1
            assert findings[0].risk_band == "unknown"
            assert findings[0].risk_band_source == "engine"
        finally:
            sess.close()


def test_re_ingest_with_different_snapshot_replaces_data(db_app: Flask) -> None:
    sid, key = register_test_server(db_app, name="srv-snap-reingest")
    client = db_app.test_client()

    # Erster Ingest mit Full-State.
    resp1 = _post(client, _envelope(host_state=_full_host_state()), bearer=key)
    assert resp1.status_code == 202

    # Zweiter Ingest mit minimalem Snapshot.
    minimal_state = {
        "snapshot_at": "2026-05-19T10:00:00Z",
        "tools_available": ["ss"],
        "gaps": ["processes", "kernel_modules", "services"],
        "listeners": [
            {"proto": "tcp", "addr": "0.0.0.0", "port": 80, "process": "nginx", "pid": 999},
        ],
        "processes": [],
        "kernel_modules": [],
        "services": [],
    }
    resp2 = _post(client, _envelope(host_state=minimal_state), bearer=key)
    assert resp2.status_code == 202, resp2.get_data(as_text=True)[:300]

    # Alte Daten weg, neue da.
    assert _count_in_table(db_app, ServerListener, sid) == 1
    assert _count_in_table(db_app, ServerProcess, sid) == 0
    assert _count_in_table(db_app, ServerKernelModule, sid) == 0
    assert _count_in_table(db_app, ServerService, sid) == 0

    # Listener-Inhalt: der neue, nicht der alte.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            listeners = list(
                sess.execute(select(ServerListener).where(ServerListener.server_id == sid))
                .scalars()
                .all()
            )
            assert len(listeners) == 1
            assert listeners[0].port == 80
            assert listeners[0].process == "nginx"
        finally:
            sess.close()


def test_envelope_with_gaps_module_list_empty_audit_carries_gaps(db_app: Flask) -> None:
    sid, key = register_test_server(db_app, name="srv-snap-gaps")
    client = db_app.test_client()

    state = _full_host_state()
    state["gaps"] = ["kernel_modules"]
    state["kernel_modules"] = []

    resp = _post(client, _envelope(host_state=state), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    assert _count_in_table(db_app, ServerKernelModule, sid) == 0

    events = _audit_events(db_app, action="host_state.snapshot_received")
    assert len(events) == 1
    meta = events[0].event_metadata
    assert meta is not None
    assert meta["gaps"] == ["kernel_modules"]


def test_listener_dedup_collapses_identical_keys(db_app: Flask) -> None:
    sid, key = register_test_server(db_app, name="srv-snap-listen-dup")
    client = db_app.test_client()

    state = _full_host_state()
    # Zwei identische (tcp, 0.0.0.0, 22, sshd, pid=1234)-Eintraege.
    state["listeners"] = [
        {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd", "pid": 1234},
        {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd", "pid": 1234},
    ]
    state["processes"] = []
    state["kernel_modules"] = []
    state["services"] = []

    resp = _post(client, _envelope(host_state=state), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    assert _count_in_table(db_app, ServerListener, sid) == 1


def test_process_dedup_on_pid(db_app: Flask) -> None:
    sid, key = register_test_server(db_app, name="srv-snap-proc-dup")
    client = db_app.test_client()

    state = _full_host_state()
    state["listeners"] = []
    state["processes"] = [
        {"pid": 1234, "user": "root", "comm": "sshd", "args": "/usr/sbin/sshd"},
        # Zweiter Eintrag mit gleicher PID — wird gedroppt (Truncate+Insert,
        # zweiter waere im DB-PK-Konflikt).
        {"pid": 1234, "user": "root", "comm": "sshd-other", "args": "noise"},
    ]
    state["kernel_modules"] = []
    state["services"] = []

    resp = _post(client, _envelope(host_state=state), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    assert _count_in_table(db_app, ServerProcess, sid) == 1


def test_snapshot_persist_error_path_findings_still_ingested(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`persist_host_state` wirft SQLAlchemyError → Audit `host_state.parse_failed`,
    Findings-Ingest laeuft trotzdem, Pre-Triage liefert `unknown`."""
    sid, key = register_test_server(db_app, name="srv-snap-fail")
    client = db_app.test_client()

    def _boom(*args: Any, **kwargs: Any) -> None:
        raise SQLAlchemyError("synthetic persist failure")

    # Seit v0.12.0 (Async-only) lebt persist_host_state im Worker-Service-Pfad,
    # nicht mehr inline im Edge-Handler.
    monkeypatch.setattr("app.services.scan_processing.persist_host_state", _boom)

    resp = _post(client, _envelope(host_state=_full_host_state()), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    # Audit-Event geschrieben.
    fails = _audit_events(db_app, action="host_state.parse_failed")
    assert len(fails) == 1
    meta = fails[0].event_metadata
    assert meta is not None
    assert "synthetic" in meta["error"]

    # Findings-Ingest hat trotzdem stattgefunden — Finding existiert.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            findings = list(
                sess.execute(select(Finding).where(Finding.server_id == sid)).scalars().all()
            )
            assert len(findings) == 1
            # Pre-Triage faellt auf `snapshot_available=False` zurueck → unknown.
            assert findings[0].risk_band == "unknown"
        finally:
            sess.close()
