"""Tests fuer `POST /api/keys/rotate` (Block C)."""

from __future__ import annotations

import gzip
import json
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, Setting
from tests._helpers import (
    DEFAULT_TEST_MASTER_KEY,
    register_test_server,
    set_master_key,
)


@pytest.fixture
def app_with_master_key(db_app: Flask) -> Flask:
    set_master_key(db_app, DEFAULT_TEST_MASTER_KEY)
    return db_app


def _rotate(client: Any, **body: Any) -> Any:
    return client.post("/api/keys/rotate", json=body)


def _audit_actions(app: Flask) -> list[str]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return [e.action for e in sess.execute(select(AuditEvent)).scalars().all()]
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# 401 / 422 / 404 — Negative
# ---------------------------------------------------------------------------


def test_rotate_401_wrong_master_key(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = _rotate(client, target="master", current_master_key="WRONG-" + "x" * 32)
    assert resp.status_code == 401, resp.get_data(as_text=True)


def test_rotate_422_missing_server_id_for_server_target(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = _rotate(client, target="server", current_master_key=DEFAULT_TEST_MASTER_KEY)
    assert resp.status_code == 422
    fields = [d["field"] for d in resp.get_json()["error"].get("details", [])]
    # Pydantic-Model-Validator-Fehler landet als "(root)" oder "server_id".
    assert any(f in ("server_id", "(root)") for f in fields), fields


def test_rotate_404_unknown_server_id(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = _rotate(
        client,
        target="server",
        server_id=999999,
        current_master_key=DEFAULT_TEST_MASTER_KEY,
    )
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == "not_found"


def test_rotate_422_invalid_target(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = _rotate(client, target="other", current_master_key=DEFAULT_TEST_MASTER_KEY)
    assert resp.status_code == 422


def test_rotate_400_non_object_body(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()
    resp = client.post("/api/keys/rotate", data="garbage", content_type="application/json")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 200 — Master-Rotation
# ---------------------------------------------------------------------------


def test_rotate_master_changes_hash(app_with_master_key: Flask) -> None:
    client = app_with_master_key.test_client()

    # Hash vorher festhalten.
    factory = get_session_factory(app_with_master_key)
    with app_with_master_key.app_context():
        sess = factory()
        try:
            row_before = sess.execute(select(Setting).where(Setting.id == 1)).scalar_one()
            old_hash = row_before.master_key_hash
        finally:
            sess.close()

    resp = _rotate(client, target="master", current_master_key=DEFAULT_TEST_MASTER_KEY)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["target"] == "master"
    new_master = body["new_key"]
    assert isinstance(new_master, str) and len(new_master) >= 32

    with app_with_master_key.app_context():
        sess = factory()
        try:
            row_after = sess.execute(select(Setting).where(Setting.id == 1)).scalar_one()
            assert row_after.master_key_hash != old_hash
        finally:
            sess.close()

    # Audit-Event geschrieben.
    assert "key.rotated.master" in _audit_actions(app_with_master_key)


def test_rotate_master_invalidates_old_key_for_register(
    app_with_master_key: Flask,
) -> None:
    """Nach Master-Rotation: alter Key macht `/api/register` 401."""
    client = app_with_master_key.test_client()
    r1 = _rotate(client, target="master", current_master_key=DEFAULT_TEST_MASTER_KEY)
    assert r1.status_code == 200
    new_master = r1.get_json()["new_key"]

    # Alter Key fuer /api/register: 401.
    resp_old = client.post(
        "/api/register",
        json={
            "master_key": DEFAULT_TEST_MASTER_KEY,
            "name": "after-rotate",
            "expected_scan_interval_h": 24,
        },
    )
    assert resp_old.status_code == 401, resp_old.get_data(as_text=True)

    # Neuer Key: 201.
    resp_new = client.post(
        "/api/register",
        json={
            "master_key": new_master,
            "name": "with-new-master",
            "expected_scan_interval_h": 24,
        },
    )
    assert resp_new.status_code == 201, resp_new.get_data(as_text=True)


# ---------------------------------------------------------------------------
# 200 — Server-Rotation
# ---------------------------------------------------------------------------


def test_rotate_server_changes_api_key(app_with_master_key: Flask) -> None:
    server_id, old_api_key = register_test_server(app_with_master_key, name="srv-rotate")
    client = app_with_master_key.test_client()

    resp = _rotate(
        client,
        target="server",
        server_id=server_id,
        current_master_key=DEFAULT_TEST_MASTER_KEY,
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["target"] == "server"
    assert body["server_id"] == server_id
    new_api_key = body["new_key"]
    assert new_api_key != old_api_key

    # Alter Key -> 401 auf /api/scans.
    envelope = {
        "agent_version": "0.1.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15",
            "architecture": "x86_64",
        },
        "scan": {"SchemaVersion": 2, "Results": []},
    }
    payload = gzip.compress(json.dumps(envelope).encode("utf-8"))
    resp_old = client.post(
        "/api/scans",
        data=payload,
        headers={
            "Authorization": f"Bearer {old_api_key}",
            "Content-Encoding": "gzip",
        },
    )
    assert resp_old.status_code == 401

    # Neuer Key -> 202.
    resp_new = client.post(
        "/api/scans",
        data=payload,
        headers={
            "Authorization": f"Bearer {new_api_key}",
            "Content-Encoding": "gzip",
        },
    )
    assert resp_new.status_code == 202

    assert "key.rotated.server" in _audit_actions(app_with_master_key)
