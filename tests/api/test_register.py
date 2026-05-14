"""Tests fuer `POST /api/register` (Block C).

Decken die DoD-Punkte ab:
- 201 mit gueltigem Master-Key, `api_key` in Response, Klartext NICHT in DB.
- Audit-Event `server.registered` bzw. `server.register.failed` geschrieben.
- 401 bei falschem Master-Key, generische Fehlermeldung.
- 422 bei ungueltigem `name`-Pattern / `expected_scan_interval_h`-Range.
- 409 bei duplizierten Namen.
- Rate-Limit greift (Default 10/minute).
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, Server
from tests._helpers import DEFAULT_TEST_MASTER_KEY, set_master_key

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app_with_master_key(db_app: Flask) -> Flask:
    """db_app mit gesetztem Master-Key."""
    set_master_key(db_app, DEFAULT_TEST_MASTER_KEY)
    return db_app


def _post_register(client: Any, **overrides: Any) -> Any:
    body: dict[str, Any] = {
        "master_key": DEFAULT_TEST_MASTER_KEY,
        "name": "prod-web-01",
        "expected_scan_interval_h": 24,
    }
    body.update(overrides)
    return client.post("/api/register", json=body)


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


def _server_count(app: Flask) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return len(sess.execute(select(Server)).scalars().all())
        finally:
            sess.close()


def _server_by_name(app: Flask, name: str) -> Server | None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return sess.execute(select(Server).where(Server.name == name)).scalar_one_or_none()
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Happy-Path
# ---------------------------------------------------------------------------


def test_register_201_happy_path(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = _post_register(client, name="prod-web-01")

    assert resp.status_code == 201, resp.get_data(as_text=True)
    body = resp.get_json()
    assert "api_key" in body, body
    assert "server_id" in body, body
    assert "scan_endpoint" in body, body
    assert isinstance(body["api_key"], str) and len(body["api_key"]) >= 32

    # DB-Seite: Server existiert, Hash ist SHA-256(Klartext), Klartext nicht in DB.
    srv = _server_by_name(app_with_master_key, "prod-web-01")
    assert srv is not None
    expected_hash = hashlib.sha256(body["api_key"].encode("utf-8")).hexdigest()
    assert srv.api_key_hash == expected_hash, "api_key_hash muss SHA-256(Klartext) sein"
    assert body["api_key"] not in srv.api_key_hash


def test_register_audit_event_written(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = _post_register(client, name="audit-test")
    assert resp.status_code == 201

    events = _audit_events(app_with_master_key, "server.registered")
    assert len(events) >= 1
    last = events[-1]
    assert last.target_type == "server"
    # target_id ist die numerische Server-ID als String.
    assert last.target_id is not None and last.target_id.isdigit()
    assert last.event_metadata is not None
    assert last.event_metadata.get("name") == "audit-test"


# ---------------------------------------------------------------------------
# 401 — Master-Key falsch
# ---------------------------------------------------------------------------


def test_register_401_wrong_master_key(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = _post_register(client, master_key="WRONG-KEY-x" * 4)
    assert resp.status_code == 401, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["error"]["code"] == "unauthorized"
    # Generische Message — kein Hint ob Name oder Key falsch.
    msg = body["error"]["message"].lower()
    assert "name" not in msg, msg
    assert _server_count(app_with_master_key) == 0


def test_register_401_writes_failed_audit_event(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = _post_register(client, master_key="WRONG-KEY-x" * 4, name="should-not-exist")
    assert resp.status_code == 401

    events = _audit_events(app_with_master_key, "server.register.failed")
    assert len(events) >= 1


def test_register_401_when_no_master_key_setup(db_app: Flask) -> None:
    """Wenn kein Master-Key in der DB ist, schlaegt jede Registrierung fehl."""
    client = db_app.test_client()
    resp = _post_register(client, master_key=DEFAULT_TEST_MASTER_KEY)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 422 — Validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "",  # leer
        "a" * 65,  # 65 > max 64
        "bad/name",  # slash
        "bad\\name",  # backslash
        "bad\x00name",  # NUL
        "bad!name",  # exclamation
        "bad?name",  # question
        "тест",  # cyrillic
    ],
)
def test_register_422_invalid_name(app_with_master_key: Flask, name: str) -> None:
    client = app_with_master_key.test_client()
    resp = _post_register(client, name=name)
    assert resp.status_code == 422, (name, resp.get_data(as_text=True))
    body = resp.get_json()
    assert body["error"]["code"] == "validation_error"
    fields = [d["field"] for d in body["error"].get("details", [])]
    assert "name" in fields, fields


@pytest.mark.parametrize("interval", [0, -1, 745, 10000])
def test_register_422_invalid_interval(app_with_master_key: Flask, interval: int) -> None:
    client = app_with_master_key.test_client()
    resp = _post_register(client, expected_scan_interval_h=interval)
    assert resp.status_code == 422, (interval, resp.get_data(as_text=True))
    body = resp.get_json()
    fields = [d["field"] for d in body["error"].get("details", [])]
    assert "expected_scan_interval_h" in fields, fields


def test_register_422_missing_required_field(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = client.post("/api/register", json={"master_key": DEFAULT_TEST_MASTER_KEY})
    assert resp.status_code == 422
    body = resp.get_json()
    fields = [d["field"] for d in body["error"].get("details", [])]
    assert "name" in fields


def test_register_400_non_object_body(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = client.post("/api/register", data="not-json", content_type="application/json")
    assert resp.status_code == 400


def test_register_pydantic_no_input_echo(app_with_master_key: Flask) -> None:
    """422-Antwort darf den User-Input NICHT zurueckspiegeln (§9 Fingerprinting)."""
    client = app_with_master_key.test_client()
    sentinel = "ATTACKER_INPUT_SENTINEL_xyz"
    resp = client.post(
        "/api/register",
        json={
            "master_key": DEFAULT_TEST_MASTER_KEY,
            "name": sentinel + "/badchar",
            "expected_scan_interval_h": 24,
        },
    )
    assert resp.status_code == 422
    raw = resp.get_data(as_text=True)
    assert sentinel not in raw, "Pydantic-Input-Echo: 422 darf User-Input nicht reflektieren"


# ---------------------------------------------------------------------------
# 409 — Duplikat
# ---------------------------------------------------------------------------


def test_register_409_duplicate_name(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp1 = _post_register(client, name="dup-server")
    assert resp1.status_code == 201
    resp2 = _post_register(client, name="dup-server")
    assert resp2.status_code == 409, resp2.get_data(as_text=True)
    body = resp2.get_json()
    assert body["error"]["code"] == "name_conflict"

    # Nur 1 Server in DB.
    assert _server_count(app_with_master_key) == 1


# ---------------------------------------------------------------------------
# Rate-Limit
# ---------------------------------------------------------------------------


def test_register_rate_limit_kicks_in(app_with_master_key: Flask) -> None:
    """Default-Limit ist `10/minute` aus den Settings."""
    client = app_with_master_key.test_client()

    # 10 erlaubte Calls (mit falschem Key, damit kein Name-Konflikt entsteht).
    saw_429 = False
    for i in range(20):
        resp = _post_register(client, master_key=f"wrong-key-iteration-{i}-" + "x" * 16)
        if resp.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "Rate-Limit muss nach ~10 Versuchen 429 liefern"
