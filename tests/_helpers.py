"""Test-Helpers fuer Block-B-Suites.

Halten View-Tests klein: Setup-Wizard durchklicken, Admin-User anlegen,
Login durchfuehren, etc. Alle Helper greifen nur ueber die oeffentlichen
App-APIs (kein direktes Patching von Implementer-Details).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

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


# Block-C-Helpers ---------------------------------------------------------


DEFAULT_TEST_MASTER_KEY = "test-master-key-32-bytes-minimum-entropy-aaa"


def set_master_key(app: Flask, plain_master_key: str = DEFAULT_TEST_MASTER_KEY) -> None:
    """Setzt den Master-Key direkt via ORM (SHA-256-Hash) ohne Setup-Wizard.

    Wird von Block-C-Tests benutzt, die `/api/register` und `/api/keys/rotate`
    testen — wir brauchen Kontrolle ueber den Klartext-Master-Key, den der
    Wizard aber nur einmalig generiert.
    """
    from app.auth import hash_master_key
    from app.db import get_session_factory
    from app.settings_service import ensure_settings_row

    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            row.master_key_hash = hash_master_key(plain_master_key)
            sess.commit()
        finally:
            sess.close()


def register_test_server(
    app: Flask,
    name: str = "testhost",
    *,
    interval_h: int = 24,
) -> tuple[int, str]:
    """Legt einen Server direkt via ORM an, gibt `(server_id, plain_api_key)` zurueck.

    Bewusst nicht via HTTP — manche Tests wollen den Klartext-Key bereits
    haben bevor irgendwelche Limiter triggern.
    """
    from app.auth import generate_server_key, hash_server_key
    from app.db import get_session_factory
    from app.models import Server

    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            plain = generate_server_key()
            srv = Server(
                name=name,
                api_key_hash=hash_server_key(plain),
                expected_scan_interval_h=interval_h,
            )
            sess.add(srv)
            sess.flush()
            srv_id = srv.id
            sess.commit()
            return (srv_id, plain)
        finally:
            sess.close()


def run_scan_synchronously(
    app: Flask,
    client: Any,
    bearer: str,
    envelope: dict[str, Any] | bytes,
) -> dict[str, Any]:
    """Async-Scan-Ingest deterministisch in einem Aufruf durchziehen.

    Seit v0.12.0 ist Async der einzige Pfad: ``POST /api/scans`` antwortet
    202 + ``job_id``, die Verarbeitung laeuft im Worker-Sub-Tick. Tests die
    UI-Render oder Folge-State (Pre-Triage, Inheritance, Findings-DB)
    asserten brauchen einen synchronen Sweep — diese Helper-Funktion
    laesst genau das laufen:

      1. POST /api/scans (gzipped) → 202 mit job_id.
      2. ``_process_scan_ingest_job`` direkt im Test-Thread aufrufen.
      3. Job-State aus ``scan_ingest_jobs`` zurueckgeben (status, scan_id,
         result-JSONB, error).

    Args:
        app: Flask-App (typisch ``db_app``).
        client: Flask-Test-Client.
        bearer: Plain-Text-API-Key des Servers.
        envelope: Entweder ein dict (wird intern gzip-komprimiert) oder
                  rohe Bytes (werden 1:1 gesendet — Test-Edge-Cases).

    Returns:
        Dict mit Keys ``status_code`` (HTTP), ``job_id``, ``job_status``,
        ``job_result``, ``job_error``, ``scan_id`` (falls done),
        ``response_body`` (raw 202-JSON).

    Raises:
        AssertionError: wenn POST nicht 202 zurueckgibt.
    """
    import gzip
    import json

    from app.db import get_session_factory
    from app.models import ScanIngestJob
    from app.workers.scan_ingest_worker import _process_scan_ingest_job

    if isinstance(envelope, bytes):
        body = envelope
    else:
        body = gzip.compress(json.dumps(envelope).encode("utf-8"))

    resp = client.post(
        "/api/scans",
        data=body,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        },
    )
    if resp.status_code != 202:
        return {
            "status_code": resp.status_code,
            "response_body": resp.get_data(as_text=True),
            "job_id": None,
            "job_status": None,
            "job_result": None,
            "job_error": None,
            "scan_id": None,
        }

    payload = resp.get_json() or {}
    job_id = int(payload["job_id"])

    factory = get_session_factory(app)
    _process_scan_ingest_job(job_id, factory, worker_id="test-sync")

    verify_sess = factory()
    try:
        job = verify_sess.get(ScanIngestJob, job_id)
        if job is None:
            return {
                "status_code": 202,
                "response_body": resp.get_data(as_text=True),
                "job_id": job_id,
                "job_status": None,
                "job_result": None,
                "job_error": "job vanished after pickup",
                "scan_id": None,
            }
        return {
            "status_code": 202,
            "response_body": resp.get_data(as_text=True),
            "job_id": job_id,
            "job_status": job.status,
            "job_result": dict(job.result) if job.result else None,
            "job_error": job.error,
            "scan_id": job.scan_id,
        }
    finally:
        verify_sess.close()


__all__ = [
    "ADMIN_PASSWORD",
    "ADMIN_USERNAME",
    "DEFAULT_TEST_MASTER_KEY",
    "complete_setup",
    "create_admin_user",
    "login",
    "register_test_server",
    "run_scan_synchronously",
    "set_master_key",
]
