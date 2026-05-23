"""Tests fuer den First-Boot-Wizard `/setup`.

DoD aus `docs/blocks/B-models.md` -> Tests-Sektion:
- Wizard-Step-Reihenfolge wird erzwungen.
- Master-Key wird genau einmal angezeigt (zweiter GET liefert denselben Key
  aus der Session — der Implementer hat sich bewusst dafuer entschieden, dass
  ein User nach Page-Reload nicht den Key verliert. Erst nach `confirmed`-POST
  wird der Klartext aus der Session entfernt).
- Nach `setup_completed_at` werden alle `/setup`-Routen auf `/login` gelocked.
"""

from __future__ import annotations

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, Setting, User
from app.settings_service import is_setup_completed


@pytest.fixture
def fresh_client(db_app: Flask) -> FlaskClient:
    """Frischer Client gegen die leere migrierte DB (kein Admin, kein Setup)."""
    return db_app.test_client()


# ---------------------------------------------------------------------------
# Step-Reihenfolge.
# ---------------------------------------------------------------------------


def test_step1_get_renders_form(fresh_client: FlaskClient) -> None:
    resp = fresh_client.get("/setup/step1")
    assert resp.status_code == 200, resp.status_code
    body = resp.get_data(as_text=True)
    assert "username" in body.lower(), body[:200]


def test_step2_get_without_step1_redirects_to_step1(fresh_client: FlaskClient) -> None:
    resp = fresh_client.get("/setup/step2", follow_redirects=False)
    assert resp.status_code == 302, resp.status_code
    assert "/setup/step1" in resp.headers["Location"]


def test_step3_get_without_step1_redirects_to_step1(fresh_client: FlaskClient) -> None:
    resp = fresh_client.get("/setup/step3", follow_redirects=False)
    assert resp.status_code == 302, resp.status_code
    assert "/setup/step1" in resp.headers["Location"]


def test_step3_after_only_step1_redirects_to_step2(fresh_client: FlaskClient) -> None:
    fresh_client.post(
        "/setup/step1",
        data={"username": "admin", "password": "x" * 16, "password_confirm": "x" * 16},
    )
    resp = fresh_client.get("/setup/step3", follow_redirects=False)
    assert resp.status_code == 302, resp.status_code
    assert "/setup/step2" in resp.headers["Location"]


def test_setup_index_redirects_to_required_step(fresh_client: FlaskClient) -> None:
    resp = fresh_client.get("/setup/", follow_redirects=False)
    assert resp.status_code == 302, resp.status_code
    assert "/setup/step1" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Step 1.
# ---------------------------------------------------------------------------


def test_step1_post_valid_creates_user_and_redirects(
    db_app: Flask, fresh_client: FlaskClient
) -> None:
    resp = fresh_client.post(
        "/setup/step1",
        data={"username": "admin", "password": "x" * 16, "password_confirm": "x" * 16},
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.status_code
    assert "/setup/step2" in resp.headers["Location"]

    factory = get_session_factory(db_app)
    s = factory()
    try:
        user = s.execute(select(User).where(User.username == "admin")).scalar_one_or_none()
        assert user is not None, "User wurde nicht angelegt"
        # Hash darf nicht das Klartext-Passwort sein.
        assert "x" * 16 not in user.password_hash
        assert user.password_hash.startswith("$argon2"), user.password_hash[:20]
    finally:
        s.close()


def test_step1_post_password_mismatch_rerenders(db_app: Flask, fresh_client: FlaskClient) -> None:
    resp = fresh_client.post(
        "/setup/step1",
        data={
            "username": "admin",
            "password": "x" * 16,
            "password_confirm": "y" * 16,
        },
        follow_redirects=False,
    )
    # Re-Render, kein Redirect.
    assert resp.status_code == 200, resp.status_code

    factory = get_session_factory(db_app)
    s = factory()
    try:
        user = s.execute(select(User).where(User.username == "admin")).scalar_one_or_none()
        assert user is None, "User darf bei Mismatch nicht angelegt sein"
    finally:
        s.close()


def test_step1_already_done_redirects_forward(fresh_client: FlaskClient) -> None:
    fresh_client.post(
        "/setup/step1",
        data={"username": "admin", "password": "x" * 16, "password_confirm": "x" * 16},
    )
    # Zweiter GET auf step1 leitet auf step2 weiter.
    resp = fresh_client.get("/setup/step1", follow_redirects=False)
    assert resp.status_code == 302, resp.status_code
    assert "/setup/step2" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Step 2 — Master-Key.
# ---------------------------------------------------------------------------


def _do_step1(client: FlaskClient) -> None:
    r = client.post(
        "/setup/step1",
        data={"username": "admin", "password": "x" * 16, "password_confirm": "x" * 16},
    )
    assert r.status_code == 302


def test_step2_get_shows_master_key(fresh_client: FlaskClient) -> None:
    _do_step1(fresh_client)
    resp = fresh_client.get("/setup/step2")
    assert resp.status_code == 200, resp.status_code
    # `master_key` wird ans Template gegeben — wir verifizieren, dass ein
    # ~43-Zeichen-Base64URL-Token im Body steht (token_urlsafe(32) -> ~43 Zeichen).
    body = resp.get_data(as_text=True)
    # Wenigstens ein zusammenhaengender token_urlsafe-aehnlicher String.
    import re

    matches = re.findall(r"[A-Za-z0-9_-]{40,60}", body)
    assert matches, f"Kein Master-Key-Format im Body: {body[:400]}"


def test_step2_get_twice_returns_same_master_key(fresh_client: FlaskClient) -> None:
    """Zweiter GET zeigt den gleichen Key — dieser bleibt in der Server-Session
    bis er per `confirmed`-POST gehasht und entfernt wird.
    """
    _do_step1(fresh_client)

    r1 = fresh_client.get("/setup/step2")
    r2 = fresh_client.get("/setup/step2")
    assert r1.status_code == 200 and r2.status_code == 200

    import re

    keys1 = set(re.findall(r"[A-Za-z0-9_-]{40,60}", r1.get_data(as_text=True)))
    keys2 = set(re.findall(r"[A-Za-z0-9_-]{40,60}", r2.get_data(as_text=True)))
    overlap = keys1 & keys2
    assert overlap, (
        f"GET2 sollte denselben Master-Key zeigen wie GET1; keys1={keys1}, keys2={keys2}"
    )


def test_step2_post_without_confirmed_rerenders(db_app: Flask, fresh_client: FlaskClient) -> None:
    _do_step1(fresh_client)
    fresh_client.get("/setup/step2")
    resp = fresh_client.post("/setup/step2", data={})
    assert resp.status_code == 200, resp.status_code

    # `master_key_hash` darf noch nicht gesetzt sein.
    factory = get_session_factory(db_app)
    s = factory()
    try:
        row = s.execute(select(Setting).where(Setting.id == 1)).scalar_one_or_none()
        if row is not None:
            assert row.master_key_hash is None
    finally:
        s.close()


def test_step2_post_confirmed_stores_hash_and_clears_session(
    db_app: Flask, fresh_client: FlaskClient
) -> None:
    _do_step1(fresh_client)

    # Master-Key generieren lassen.
    r_get = fresh_client.get("/setup/step2")
    assert r_get.status_code == 200

    resp = fresh_client.post("/setup/step2", data={"confirmed": "y"}, follow_redirects=False)
    assert resp.status_code == 302, (resp.status_code, resp.data[:200])
    assert "/setup/step3" in resp.headers["Location"]

    # Settings-Row enthaelt master_key_hash, NICHT den Klartext.
    factory = get_session_factory(db_app)
    s = factory()
    try:
        row = s.execute(select(Setting).where(Setting.id == 1)).scalar_one()
        assert row.master_key_hash is not None
        # SHA-256-Hex = 64 Zeichen.
        assert len(row.master_key_hash) == 64, row.master_key_hash
    finally:
        s.close()

    # Session enthaelt den Klartext nicht mehr.
    with fresh_client.session_transaction() as sess:
        assert "setup_pending_master_key" not in sess, list(sess.keys())


# ---------------------------------------------------------------------------
# Step 3 — Abschluss.
# ---------------------------------------------------------------------------


def _do_step1_and_step2(client: FlaskClient) -> None:
    _do_step1(client)
    client.get("/setup/step2")
    r = client.post("/setup/step2", data={"confirmed": "y"})
    assert r.status_code == 302


def test_step3_post_completes_setup(db_app: Flask, fresh_client: FlaskClient) -> None:
    _do_step1_and_step2(fresh_client)
    resp = fresh_client.post(
        "/setup/step3",
        data={
            "severity_threshold": "medium",
            "stale_threshold_h": "24",
            "stale_trivy_db_threshold_h": "12",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, (resp.status_code, resp.data[:200])
    assert "/login" in resp.headers["Location"]

    factory = get_session_factory(db_app)
    s = factory()
    try:
        row = s.execute(select(Setting).where(Setting.id == 1)).scalar_one()
        assert row.setup_completed_at is not None
        assert row.severity_threshold.value == "medium"
        assert row.stale_threshold_h == 24
        assert row.stale_trivy_db_threshold_h == 12

        # Audit: `setup.completed` ist da.
        events = s.execute(
            select(AuditEvent.action).where(
                AuditEvent.action.in_(["setup.completed", "setup.defaults_set"])
            )
        ).all()
        actions = {row[0] for row in events}
        assert "setup.completed" in actions and "setup.defaults_set" in actions, actions
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Lock nach Abschluss.
# ---------------------------------------------------------------------------


def test_setup_routes_locked_after_completion(db_app: Flask, fresh_client: FlaskClient) -> None:
    _do_step1_and_step2(fresh_client)
    fresh_client.post(
        "/setup/step3",
        data={
            "severity_threshold": "high",
            "stale_threshold_h": "48",
            "stale_trivy_db_threshold_h": "30",
        },
    )
    # Sanity-Check.
    factory = get_session_factory(db_app)
    s = factory()
    try:
        assert is_setup_completed(s) is True
    finally:
        s.close()

    # Frischer Client (saubere Session) — Setup-Wizard muss komplett gesperrt sein.
    other = db_app.test_client()
    for path in ("/setup/", "/setup/step1", "/setup/step2", "/setup/step3"):
        resp = other.get(path, follow_redirects=False)
        assert resp.status_code == 302, (path, resp.status_code)
        assert "/login" in resp.headers["Location"], (path, resp.headers["Location"])
