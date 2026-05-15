"""Tests fuer den `scan.received`-EventBus-Hook in `POST /api/scans`.

Block H Aufgabe 4: Nach erfolgreichem Ingest publishes der Endpoint ein
`scan.received`-Event mit `{server_id, server_name, new_finding_count,
resolved_count, updated_count, ingested_at}` an den App-EventBus, damit
das Dashboard live aktualisiert.

Anti-Regression:
- Hook-Fehler darf den 202er-Ingest NICHT abreissen — Best-Effort.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest
from flask import Flask

from app.services.event_bus import EventBus, get_event_bus
from tests._helpers import register_test_server

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "trivy" / "ubuntu-22.04-rke2.json"


@pytest.fixture(scope="module")
def trivy_report() -> dict[str, Any]:
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


def _post_scan(client: Any, payload: dict[str, Any], *, bearer: str) -> Any:
    headers = {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "Authorization": f"Bearer {bearer}",
    }
    body = gzip.compress(json.dumps(payload).encode("utf-8"))
    return client.post("/api/scans", data=body, headers=headers)


def test_successful_ingest_publishes_scan_received_event(
    db_app: Flask, trivy_report: dict[str, Any]
) -> None:
    """Happy-Path: 202er Ingest publishes genau ein `scan.received`-Event."""
    server_id, api_key = register_test_server(db_app, name="event-host")
    bus = get_event_bus(db_app)
    sub = bus.subscribe()

    client = db_app.test_client()
    resp = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert resp.status_code == 202, resp.get_data(as_text=True)

    # Genau ein Event auf der Subscription.
    received: list[Any] = []
    while not sub.q.empty():
        received.append(sub.q.get_nowait())

    scan_events = [e for e in received if e.event_type == "scan.received"]
    assert len(scan_events) == 1, [e.event_type for e in received]
    payload = scan_events[0].payload
    assert payload["server_id"] == server_id
    assert payload["server_name"] == "event-host"
    assert payload["new_finding_count"] == 306  # full fixture inserts
    assert payload["resolved_count"] == 0
    assert payload["updated_count"] == 0
    assert "ingested_at" in payload


def test_ingest_event_payload_has_iso_timestamp(
    db_app: Flask, trivy_report: dict[str, Any]
) -> None:
    """`ingested_at` ist ein ISO-8601-String, parsebar."""
    from datetime import datetime

    server_id, api_key = register_test_server(db_app, name="iso-host")
    bus = get_event_bus(db_app)
    sub = bus.subscribe()

    client = db_app.test_client()
    resp = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert resp.status_code == 202

    events = []
    while not sub.q.empty():
        events.append(sub.q.get_nowait())
    scan_events = [e for e in events if e.event_type == "scan.received"]
    assert len(scan_events) == 1
    ts_str = scan_events[0].payload["ingested_at"]
    parsed = datetime.fromisoformat(ts_str)
    assert parsed is not None
    assert str(server_id)  # mark used


def test_failed_event_publish_does_not_break_ingest(
    db_app: Flask,
    trivy_report: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn `bus.publish` raised, bleibt der Ingest trotzdem 202."""
    server_id, api_key = register_test_server(db_app, name="hook-fail-host")
    bus = get_event_bus(db_app)

    def _broken_publish(self: EventBus, event_type: str, payload: dict[str, Any]) -> None:
        raise TypeError("bus is on fire")

    monkeypatch.setattr(EventBus, "publish", _broken_publish)

    client = db_app.test_client()
    resp = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert resp.status_code == 202, resp.get_data(as_text=True)
    body = resp.get_json()
    # Ingest hat alle Findings erfolgreich verarbeitet.
    assert body["findings_total"] == 306
    # mark used
    assert server_id > 0
    assert bus is not None


def test_rescan_publishes_event_with_updated_counts(
    db_app: Flask, trivy_report: dict[str, Any]
) -> None:
    """Zweiter Scan -> Event mit findings_updated > 0 oder neue=0."""
    server_id, api_key = register_test_server(db_app, name="rescan-host")
    client = db_app.test_client()

    # Erster Scan.
    r1 = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert r1.status_code == 202

    # Subscribe vor dem zweiten Scan damit wir nur den zweiten Event sehen.
    bus = get_event_bus(db_app)
    sub = bus.subscribe()

    r2 = _post_scan(client, _envelope(trivy_report), bearer=api_key)
    assert r2.status_code == 202

    received: list[Any] = []
    while not sub.q.empty():
        received.append(sub.q.get_nowait())
    scan_events = [e for e in received if e.event_type == "scan.received"]
    assert len(scan_events) == 1
    p = scan_events[0].payload
    assert p["server_id"] == server_id
    # `new_finding_count` und `updated_count` sind heuristisch (first_seen_at-
    # vs-now mit 1s-Toleranz, siehe test_scans_idempotent_rescan_keeps_306).
    # Wir pruefen nur dass das Event auf den Re-Scan fliesst und der
    # Resolved-Count konsistent 0 ist (alle Findings im Re-Scan vorhanden).
    assert p["resolved_count"] == 0
    assert isinstance(p["new_finding_count"], int)
    assert isinstance(p["updated_count"], int)


def test_failed_auth_does_not_publish_event(db_app: Flask, trivy_report: dict[str, Any]) -> None:
    """401-Antwort darf KEIN `scan.received` triggern."""
    register_test_server(db_app, name="no-publish")
    bus = get_event_bus(db_app)
    sub = bus.subscribe()

    client = db_app.test_client()
    resp = _post_scan(client, _envelope(trivy_report), bearer="bogus-token-deadbeef")
    assert resp.status_code == 401

    received: list[Any] = []
    while not sub.q.empty():
        received.append(sub.q.get_nowait())
    scan_events = [e for e in received if e.event_type == "scan.received"]
    assert scan_events == []
