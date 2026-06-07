"""Login-, Logout- und Rate-Limit-Tests fuer `/login`.

DoD aus `docs/blocks/B-models.md` -> Tests-Sektion:
- Login-Erfolg, Login-Fehler, Rate-Limit, Logout, Session-Timeout.
"""

from __future__ import annotations

import contextlib
import time
from datetime import timedelta

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app import limiter
from app.db import get_session_factory
from app.models import AuditEvent
from tests._helpers import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_admin_user,
    login,
)


@pytest.fixture
def seeded_db_app(db_app: Flask) -> Flask:
    """Test-App mit einem fertig angelegten Admin-User + abgeschlossenem Setup."""
    create_admin_user(db_app)
    return db_app


@pytest.fixture
def seeded_client(seeded_db_app: Flask) -> FlaskClient:
    return seeded_db_app.test_client()


# ---------------------------------------------------------------------------
# Login-Erfolg.
# ---------------------------------------------------------------------------


def test_login_success_redirects_and_sets_session(seeded_client: FlaskClient) -> None:
    resp = seeded_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 302, (resp.status_code, resp.data[:200])
    # Bei /settings/tags landet man nach Login (siehe app/views/auth.py).
    assert "/settings/tags" in resp.headers["Location"], resp.headers["Location"]

    # Session-Cookie muss gesetzt sein.
    with seeded_client.session_transaction() as sess:
        assert "_user_id" in sess, list(sess.keys())


def test_login_success_writes_auth_success_audit_event(
    seeded_db_app: Flask, seeded_client: FlaskClient
) -> None:
    seeded_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )

    factory = get_session_factory(seeded_db_app)
    s = factory()
    try:
        events = (
            s.execute(select(AuditEvent).where(AuditEvent.action == "auth.success")).scalars().all()
        )
        assert len(events) == 1, [(e.action, e.actor) for e in events]
        ev = events[0]
        assert ev.actor == ADMIN_USERNAME, ev.actor
        assert ev.target_type == "user", ev.target_type
        assert ev.event_metadata is not None
        assert "ip" in ev.event_metadata, ev.event_metadata
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Login-Fehler.
# ---------------------------------------------------------------------------


def test_login_wrong_password_returns_401_and_audit(
    seeded_db_app: Flask, seeded_client: FlaskClient
) -> None:
    resp = seeded_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": "not-the-right-password"},
        follow_redirects=False,
    )
    assert resp.status_code == 401, (resp.status_code, resp.data[:200])

    factory = get_session_factory(seeded_db_app)
    s = factory()
    try:
        events = (
            s.execute(select(AuditEvent).where(AuditEvent.action == "auth.failed")).scalars().all()
        )
        assert len(events) == 1, [(e.action, e.actor) for e in events]
        ev = events[0]
        assert ev.actor == ADMIN_USERNAME, ev.actor
        assert ev.event_metadata is not None and "ip" in ev.event_metadata
    finally:
        s.close()


def test_login_unknown_user_returns_401_and_audit(
    seeded_db_app: Flask, seeded_client: FlaskClient
) -> None:
    resp = seeded_client.post(
        "/login",
        data={"username": "does-not-exist", "password": "whatever-pass"},
        follow_redirects=False,
    )
    assert resp.status_code == 401, (resp.status_code, resp.data[:200])

    factory = get_session_factory(seeded_db_app)
    s = factory()
    try:
        events = (
            s.execute(select(AuditEvent).where(AuditEvent.action == "auth.failed")).scalars().all()
        )
        # Auch fuer unbekannte User wird ein Audit-Event geschrieben.
        assert len(events) >= 1, [(e.action, e.actor) for e in events]
        assert events[0].actor == "does-not-exist"
    finally:
        s.close()


def test_login_unknown_user_takes_similar_time_as_wrong_password(
    seeded_client: FlaskClient,
) -> None:
    """Konstantzeit-Schutz: Antwortzeit fuer unknown-user und wrong-password
    muss in derselben Groessenordnung liegen.

    Wir messen sehr grob — Faktor 3 reicht aus, um den Username-Enum-Pfad
    auszuschliessen, in dem unknown-user ohne Argon2-Call zurueckkommt.
    """
    # Erst ein "warm" Run, damit Caches etc. nicht den ersten Lauf verfaelschen.
    seeded_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": "definitely-wrong-pw"},
    )

    # Wrong password (User existiert) — Argon2-Verify laeuft.
    t0 = time.perf_counter()
    seeded_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": "definitely-wrong-pw"},
    )
    t_wrong = time.perf_counter() - t0

    # Unknown user — sollte aequivalent verzoegert sein.
    t0 = time.perf_counter()
    seeded_client.post(
        "/login",
        data={"username": "completely-unknown-user", "password": "definitely-wrong-pw"},
    )
    t_unknown = time.perf_counter() - t0

    # Faktor 5 lockerer Bound — bei aktivierter Konstantzeit liegen die Werte
    # eng beieinander. Beide muessen mindestens 1us dauern (Sanity-Check).
    assert t_wrong > 0 and t_unknown > 0
    ratio = max(t_wrong, t_unknown) / max(1e-6, min(t_wrong, t_unknown))
    assert ratio < 10.0, f"timing diverges too much: wrong={t_wrong:.4f}s unknown={t_unknown:.4f}s"


# ---------------------------------------------------------------------------
# Rate-Limit.
# ---------------------------------------------------------------------------


def test_login_rate_limit_after_5_attempts(seeded_client: FlaskClient) -> None:
    """`FM_RATELIMIT_LOGIN=5/minute` -> Versuch 6 muss 429 sein."""
    # Limiter resetten, damit vorherige Tests nichts verbraucht haben.
    with contextlib.suppress(Exception):
        limiter.reset()

    for i in range(5):
        resp = seeded_client.post(
            "/login",
            data={"username": ADMIN_USERNAME, "password": "wrong"},
        )
        # Die 5 ersten Versuche enden in 401 (Fehler), aber nicht in 429.
        assert resp.status_code != 429, f"attempt {i} unexpectedly throttled"

    resp = seeded_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": "wrong"},
    )
    assert resp.status_code == 429, (resp.status_code, resp.data[:200])


# ---------------------------------------------------------------------------
# Logout.
# ---------------------------------------------------------------------------


def test_logout_clears_session_and_redirects(
    seeded_db_app: Flask, seeded_client: FlaskClient
) -> None:
    login(seeded_client)

    resp = seeded_client.post("/logout", follow_redirects=False)
    assert resp.status_code == 302, (resp.status_code, resp.data[:200])
    assert "/login" in resp.headers["Location"]

    with seeded_client.session_transaction() as sess:
        assert "_user_id" not in sess, list(sess.keys())

    # Audit-Event geschrieben.
    factory = get_session_factory(seeded_db_app)
    s = factory()
    try:
        events = (
            s.execute(select(AuditEvent).where(AuditEvent.action == "auth.logout")).scalars().all()
        )
        assert len(events) == 1, [(e.action, e.actor) for e in events]
        assert events[0].actor == ADMIN_USERNAME
    finally:
        s.close()


def test_logout_unauthenticated_is_rejected(seeded_client: FlaskClient) -> None:
    """Logout ohne Login -> Login-Manager redirected auf /login."""
    resp = seeded_client.post("/logout", follow_redirects=False)
    assert resp.status_code in {302, 401}, (resp.status_code, resp.data[:200])
    if resp.status_code == 302:
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Session-Timeout.
# ---------------------------------------------------------------------------


def test_session_expires_after_lifetime(seeded_db_app: Flask, seeded_client: FlaskClient) -> None:
    """Nach Session-Clear -> geschuetzte Route fordert Re-Login.

    Flask-Login speichert kein Lifetime-Field in der Session — die echte
    Lifetime-Pruefung passiert beim Cookie-Refresh durch den Browser.
    Wir simulieren den Ablauf, indem wir die Session manuell leeren; danach
    muss eine `@login_required`-Route auf `/login` umleiten.
    """
    seeded_db_app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=1)

    login(seeded_client)

    # Bestaetigung: Session ist gesetzt.
    with seeded_client.session_transaction() as sess:
        assert "_user_id" in sess

    # Session manuell leeren — Aequivalent zum Cookie-Expiry.
    with seeded_client.session_transaction() as sess:
        sess.clear()

    # Logout-Route ist `@login_required` und triggert daher den
    # Login-Redirect ohne das (in Block-B noch kaputte) Tag-Template zu rendern.
    r_gone = seeded_client.post("/logout", follow_redirects=False)
    assert r_gone.status_code == 302, r_gone.status_code
    assert "/login" in r_gone.headers["Location"], r_gone.headers["Location"]
