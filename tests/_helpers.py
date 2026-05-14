"""Test-Helpers fuer Block-B-Suites.

Halten View-Tests klein: Setup-Wizard durchklicken, Admin-User anlegen,
Login durchfuehren, etc. Alle Helper greifen nur ueber die oeffentlichen
App-APIs (kein direktes Patching von Implementer-Details).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask
    from flask.testing import FlaskClient


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "correct horse battery staple"


def complete_setup(client: FlaskClient) -> None:
    """Klickt das Setup-Wizard durch, damit der Setup-Guard die Tests durchlaesst.

    Erzeugt einen `admin`-User mit `ADMIN_PASSWORD`. Verwendet nur die
    HTTP-Routen — keine direkten DB-Zugriffe.
    """
    # Step 1.
    r1 = client.post(
        "/setup/step1",
        data={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD,
            "password_confirm": ADMIN_PASSWORD,
        },
        follow_redirects=False,
    )
    assert r1.status_code == 302, (r1.status_code, r1.data[:200])
    # Step 2 — GET (Key anzeigen) und POST (Bestaetigung).
    r2_get = client.get("/setup/step2")
    assert r2_get.status_code == 200, r2_get.status_code
    r2 = client.post("/setup/step2", data={"confirmed": "y"}, follow_redirects=False)
    assert r2.status_code == 302, (r2.status_code, r2.data[:200])
    # Step 3 — Defaults setzen.
    r3 = client.post(
        "/setup/step3",
        data={
            "severity_threshold": "high",
            "stale_threshold_h": "48",
            "stale_trivy_db_threshold_h": "30",
            "default_theme": "auto",
        },
        follow_redirects=False,
    )
    assert r3.status_code == 302, (r3.status_code, r3.data[:200])


def create_admin_user(
    app: Flask, username: str = ADMIN_USERNAME, password: str = ADMIN_PASSWORD
) -> int:
    """Legt einen Admin-User direkt via ORM an und schliesst das Setup ab.

    Schneller als `complete_setup` und ohne Session-State-Abhaengigkeit.
    Liefert die User-ID zurueck.
    """
    from datetime import UTC, datetime

    from sqlalchemy import select

    from app.auth import hash_password
    from app.db import get_session_factory
    from app.models import User
    from app.settings_service import ensure_settings_row

    factory = get_session_factory(app)
    # `hash_password` greift ueber `current_app` auf die Argon2-Settings zu;
    # daher muss der Aufruf in einem App-Context laufen.
    with app.app_context():
        sess = factory()
        try:
            existing = sess.execute(
                select(User).where(User.username == username)
            ).scalar_one_or_none()
            if existing is not None:
                uid = existing.id
            else:
                user = User(username=username, password_hash=hash_password(password))
                sess.add(user)
                sess.flush()
                uid = user.id
            row = ensure_settings_row(sess)
            row.setup_completed_at = datetime.now(tz=UTC)
            sess.commit()
            return uid
        finally:
            sess.close()


def login(
    client: FlaskClient, username: str = ADMIN_USERNAME, password: str = ADMIN_PASSWORD
) -> None:
    """Loggt einen User via `/login` ein. Erwartet erfolgreichen Login (302)."""
    resp = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )
    assert resp.status_code == 302, (resp.status_code, resp.data[:200])


__all__ = [
    "ADMIN_PASSWORD",
    "ADMIN_USERNAME",
    "complete_setup",
    "create_admin_user",
    "login",
]
