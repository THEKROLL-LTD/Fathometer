"""Tests fuer den asynchronen Fast-Path von POST /api/scans (Block R Phase B).

Marker: db_integration — braucht echte Postgres-Semantik fuer den
`on_conflict_do_nothing`-Partial-Index-Match auf
`ux_scan_ingest_jobs_payload_sha256`.

Abgedeckte Faelle:
1. Happy-Path: gueltiger Envelope -> 202 + job_id + scan.queued-Audit.
2. Auth-Fail 401 (Bearer fehlt/falsch) — vor Feature-Flag-Branch.
3. Agent outdated -> 400 agent_outdated + Audit agent.rejected_outdated.
4. Queue full -> 429 queue_full (50 queued Jobs vorab, dann 51ster Call).
5. Idempotency: zwei identische Bodies -> selber job_id, nur ein Audit-Event.
6. Pre-Validation-Schemafehler (parametrize): 400 not_an_object / missing_*.
7. Decompress-Limit: gzip-Bomb > 100 MB -> 413 (vor Feature-Flag-Branch).
8. Wrong-Server-Status: revoked/retired -> 403 (vor Feature-Flag-Branch).
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
from app.models import AuditEvent, ScanIngestJob, Server
from tests._helpers import register_test_server

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "trivy" / "ubuntu-22.04-rke2.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_envelope(
    agent_version: str = "0.1.0",
    hostname: str = "testhost",
    scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Baut ein minimales gueltiges Envelope."""
    if scan is None:
        with FIXTURE_PATH.open("rb") as fh:
            trivy_report = json.load(fh)
        scan = trivy_report
    return {
        "agent_version": agent_version,
        "host": {
            "hostname": hostname,
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04.4 LTS",
            "kernel_version": "5.15.0-100-generic",
            "architecture": "x86_64",
        },
        "scan": scan,
    }


def _gzip_envelope(envelope: dict[str, Any]) -> bytes:
    return gzip.compress(json.dumps(envelope).encode("utf-8"))


def _post_scan(
    client: Any,
    payload_bytes: bytes,
    bearer: str | None,
) -> Any:
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
    }
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    return client.post("/api/scans", data=payload_bytes, headers=headers)


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


def _ingest_jobs(app: Flask, server_id: int) -> list[ScanIngestJob]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(select(ScanIngestJob).where(ScanIngestJob.server_id == server_id))
                .scalars()
                .all()
            )
        finally:
            sess.close()


@pytest.fixture
def async_db_app(db_app: Flask) -> Flask:
    """Alias auf ``db_app``. Seit v0.12.0 ist Async der einzige Pfad —
    das frueher hier gesetzte `scan_ingest_async`-Flag existiert nicht mehr.
    Wir behalten den Fixture-Namen aus Lesbarkeitsgruenden (Tests sagen
    explizit „async-Pfad")."""
    return db_app


# ---------------------------------------------------------------------------
# 1. Happy-Path
# ---------------------------------------------------------------------------


def test_happy_path_returns_202_with_job_id(
    async_db_app: Flask,
) -> None:
    """Gueltiger Envelope -> 202 + job_id in JSON + scan.queued-Audit."""
    server_id, key = register_test_server(async_db_app, "happy-server")
    client = async_db_app.test_client()

    envelope = _build_envelope()
    resp = _post_scan(client, _gzip_envelope(envelope), bearer=key)

    assert resp.status_code == 202
    body = resp.get_json()
    assert "job_id" in body
    assert body["status"] == "queued"

    # Job in DB
    jobs = _ingest_jobs(async_db_app, server_id)
    assert len(jobs) == 1
    assert jobs[0].id == body["job_id"]
    assert jobs[0].status == "queued"
    assert jobs[0].server_id == server_id

    # Audit-Event
    events = _audit_events(async_db_app, "scan.queued")
    assert len(events) == 1
    assert events[0].event_metadata["job_id"] == body["job_id"]
    assert "payload_sha256" in events[0].event_metadata
    assert events[0].event_metadata["payload_bytes"] > 0


# ---------------------------------------------------------------------------
# 2. Auth-Fail 401 (passiert VOR Feature-Flag-Branch)
# ---------------------------------------------------------------------------


def test_auth_fail_missing_bearer(async_db_app: Flask) -> None:
    """Kein Bearer-Token -> 401, kein Body-Read."""
    client = async_db_app.test_client()
    resp = client.post(
        "/api/scans",
        data=b"irrelevant",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_auth_fail_unknown_bearer(async_db_app: Flask) -> None:
    """Unbekannter Bearer -> 401."""
    client = async_db_app.test_client()
    envelope = _build_envelope()
    resp = _post_scan(client, _gzip_envelope(envelope), bearer="totally-wrong-key")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 3. Agent outdated -> 400
# ---------------------------------------------------------------------------


def test_agent_outdated_returns_400(async_db_app: Flask) -> None:
    """Agent-Version unter MIN_AGENT_VERSION -> 400 agent_outdated + Audit."""
    _server_id, key = register_test_server(async_db_app, "old-agent-server")
    client = async_db_app.test_client()

    # 0.0.1 ist immer kleiner als MIN_AGENT_VERSION (0.1.0)
    envelope = _build_envelope(agent_version="0.0.1")
    resp = _post_scan(client, _gzip_envelope(envelope), bearer=key)

    assert resp.status_code == 400
    body = resp.get_json()
    assert body.get("error") == "agent_outdated"

    events = _audit_events(async_db_app, "agent.rejected_outdated")
    assert len(events) == 1
    assert events[0].event_metadata["agent_version"] == "0.0.1"


# ---------------------------------------------------------------------------
# 4. Queue full -> 429
# ---------------------------------------------------------------------------


def test_queue_full_returns_429(async_db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Bei Soft-Cap-Ueberschreitung -> 429 queue_full."""
    settings: Settings = async_db_app.config["FM_SETTINGS"]
    # Sehr kleinen Cap setzen damit wir ihn leicht fuellen koennen.
    monkeypatch.setattr(settings, "max_queued_ingest_jobs", 2)

    server_id, key = register_test_server(async_db_app, "queue-full-server")

    # 2 Jobs direkt per ORM einfuegen (simuliert volle Queue).
    factory = get_session_factory(async_db_app)
    with async_db_app.app_context():
        sess = factory()
        try:
            for i in range(2):
                job = ScanIngestJob(
                    server_id=server_id,
                    payload_gzip=gzip.compress(b"x"),
                    payload_sha256="a" * 63 + str(i),
                    payload_bytes=1,
                    status="queued",
                )
                sess.add(job)
            sess.commit()
        finally:
            sess.close()

    client = async_db_app.test_client()
    envelope = _build_envelope()
    resp = _post_scan(client, _gzip_envelope(envelope), bearer=key)

    assert resp.status_code == 429
    body = resp.get_json()
    assert body.get("error") == "queue_full"
    assert body.get("queued") == 2


# ---------------------------------------------------------------------------
# 5. Idempotency: identischer Body -> selber job_id, nur ein Audit-Event
# ---------------------------------------------------------------------------


def test_idempotency_same_body_returns_same_job_id(async_db_app: Flask) -> None:
    """Zwei identische Uploads -> derselbe job_id, nur ein scan.queued-Event."""
    server_id, key = register_test_server(async_db_app, "idem-server")
    client = async_db_app.test_client()

    envelope = _build_envelope()
    gzipped = _gzip_envelope(envelope)

    resp1 = _post_scan(client, gzipped, bearer=key)
    assert resp1.status_code == 202
    job_id_1 = resp1.get_json()["job_id"]

    resp2 = _post_scan(client, gzipped, bearer=key)
    assert resp2.status_code == 202
    job_id_2 = resp2.get_json()["job_id"]

    assert job_id_1 == job_id_2

    # Nur ein Job in der DB.
    jobs = _ingest_jobs(async_db_app, server_id)
    assert len(jobs) == 1

    # Nur ein Audit-Event (Idempotency-Schutz).
    events = _audit_events(async_db_app, "scan.queued")
    assert len(events) == 1


# ---------------------------------------------------------------------------
# 6. Pre-Validation-Schemafehler (parametrize)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_body, expected_error",
    [
        # not_an_object: JSON-Array statt Objekt
        (b"[]", "not_an_object"),
        # missing_agent_version: agent_version fehlt
        (
            json.dumps(
                {
                    "host": {"hostname": "x"},
                    "scan": {},
                }
            ).encode(),
            "missing_agent_version",
        ),
        # missing_agent_version: agent_version ist zu lang (>32 Zeichen)
        (
            json.dumps(
                {
                    "agent_version": "x" * 33,
                    "host": {"hostname": "x"},
                    "scan": {},
                }
            ).encode(),
            "missing_agent_version",
        ),
        # missing_host: host fehlt komplett
        (
            json.dumps(
                {
                    "agent_version": "0.1.0",
                    "scan": {},
                }
            ).encode(),
            "missing_host",
        ),
        # missing_host: host ist kein dict
        (
            json.dumps(
                {
                    "agent_version": "0.1.0",
                    "host": "not-a-dict",
                    "scan": {},
                }
            ).encode(),
            "missing_host",
        ),
        # missing_scan: scan ist kein dict
        (
            json.dumps(
                {
                    "agent_version": "0.1.0",
                    "host": {"os_family": "ubuntu"},
                    "scan": "not-a-dict",
                }
            ).encode(),
            "missing_scan",
        ),
    ],
    ids=[
        "not_an_object",
        "missing_agent_version_absent",
        "missing_agent_version_too_long",
        "missing_host_absent",
        "missing_host_not_dict",
        "missing_scan",
    ],
)
def test_pre_validation_errors(
    async_db_app: Flask,
    bad_body: bytes,
    expected_error: str,
) -> None:
    """Pre-Validation-Fehler -> 400 mit entsprechendem error-Wert."""
    _server_id, key = register_test_server(async_db_app, f"preval-{expected_error}-server")
    client = async_db_app.test_client()

    gzipped = gzip.compress(bad_body)
    resp = _post_scan(client, gzipped, bearer=key)

    assert resp.status_code == 400
    body = resp.get_json()
    assert body.get("error") == expected_error


# ---------------------------------------------------------------------------
# 7. Decompress-Limit: gzip-Bomb > 100 MB -> 413 (vor Feature-Flag-Branch)
# ---------------------------------------------------------------------------


def test_decompress_limit_returns_413(
    async_db_app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """gzip-Bomb die den Decompress-Limit ueberschreitet -> 413."""
    # Limit auf 1 Byte senken damit wir keinen echten 100-MB-Body brauchen.
    settings: Settings = async_db_app.config["FM_SETTINGS"]
    monkeypatch.setattr(settings, "max_decompressed_mb", 1)

    _server_id, key = register_test_server(async_db_app, "bomb-server")
    client = async_db_app.test_client()

    # Komprimierter Body der nach Dekomprimierung >1 MB ergibt.
    big_body = b"x" * (2 * 1024 * 1024)
    compressed = gzip.compress(big_body)

    resp = _post_scan(client, compressed, bearer=key)
    assert resp.status_code == 413


# ---------------------------------------------------------------------------
# 8. Wrong-Server-Status: revoked/retired -> 403 (vor Feature-Flag-Branch)
# ---------------------------------------------------------------------------


def test_revoked_server_returns_403(
    async_db_app: Flask,
) -> None:
    """Revoked Server -> 403 server_inactive."""
    server_id, key = register_test_server(async_db_app, "revoked-server")

    factory = get_session_factory(async_db_app)
    with async_db_app.app_context():
        sess = factory()
        try:
            srv = sess.get(Server, server_id)
            assert srv is not None
            srv.revoked_at = datetime.now(tz=UTC)
            sess.commit()
        finally:
            sess.close()

    client = async_db_app.test_client()
    envelope = _build_envelope()
    resp = _post_scan(client, _gzip_envelope(envelope), bearer=key)

    assert resp.status_code == 403


def test_retired_server_returns_403(
    async_db_app: Flask,
) -> None:
    """Retired Server -> 403 server_inactive."""
    server_id, key = register_test_server(async_db_app, "retired-server")

    factory = get_session_factory(async_db_app)
    with async_db_app.app_context():
        sess = factory()
        try:
            srv = sess.get(Server, server_id)
            assert srv is not None
            srv.retired_at = datetime.now(tz=UTC)
            sess.commit()
        finally:
            sess.close()

    client = async_db_app.test_client()
    envelope = _build_envelope()
    resp = _post_scan(client, _gzip_envelope(envelope), bearer=key)

    assert resp.status_code == 403
