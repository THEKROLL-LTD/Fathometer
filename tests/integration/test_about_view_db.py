"""Tests fuer die About-View (`GET /settings/about`, ADR-0016).

DoD-Punkte:
  - Login-required.
  - Version-Strings: `app_version`, `build_revision`, `alembic_revision`,
    `python_version`, `flask_version`, `sqlalchemy_version`.
  - `build_revision == "dev"` wenn `SECSCAN_BUILD_REVISION` nicht gesetzt.
  - `alembic_revision` matched Hex-Pattern `[a-f0-9]+` oder `"unknown"`.
  - Secret-Leak-Gegen-Test: weder Env-Var-Namen noch DB-Spalten-Namen mit
    Geheimnissen erscheinen im Render.
"""

from __future__ import annotations

import os
import re

import pytest
from flask import Flask

from tests._helpers import create_admin_user, login


def test_about_redirects_when_not_logged_in(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/settings/about", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers.get("Location", "")


def test_about_renders_for_logged_in_user(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/about")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]


def test_about_contains_all_required_version_labels(db_app: Flask) -> None:
    """Die DD/DL-Liste enthaelt die Labels fuer alle 6 Versions-Strings."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/about")
    body = resp.get_data(as_text=True)

    # Wir verifizieren die *Anzeige*-Labels aus `about.html`. Die Kontext-
    # Keys (`app_version` etc.) werden hier nicht direkt im HTML benutzt
    # — stattdessen `{{ about.app_version }}` mit lesbarem Label.
    for label in (
        "App version",
        "Build revision",
        "DB schema",
        "Python",
        "Flask",
        "SQLAlchemy",
    ):
        assert label in body, f"Label '{label}' fehlt im About-Render"


def test_about_build_revision_defaults_to_dev(db_app: Flask) -> None:
    """Ohne `SECSCAN_BUILD_REVISION`-ENV ist `build_revision == "dev"`.

    Die `_clean_environment`-Fixture (siehe `tests/conftest.py`) stellt
    sicher, dass die Env nicht aus dem Host blutet — wir muessen daher
    nicht eigens via monkeypatch deleten."""
    if "SECSCAN_BUILD_REVISION" in os.environ:
        pytest.skip("SECSCAN_BUILD_REVISION ist im Host-Env gesetzt")
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/about")
    body = resp.get_data(as_text=True)

    # `Build-Revision` Label und der Wert "dev" sollen beide auftauchen.
    # Wir matchen das per Regex auf die `<dt>Build-Revision</dt><dd ...>dev</dd>`-
    # Struktur (Template rendert `<dt>` + `<dd class="font-mono">dev</dd>`).
    m = re.search(r"Build revision</dt>\s*<dd[^>]*>([^<]+)</dd>", body)
    assert m is not None, "Build-Revision-DD nicht gefunden"
    assert m.group(1).strip() == "dev", m.group(0)


def test_about_alembic_revision_matches_hex_or_unknown(db_app: Flask) -> None:
    """`alembic_revision` ist entweder ein Hex-String oder "unknown".

    Die Test-DB ist via Fixture migriert -> Wert sollte Hex sein."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/about")
    body = resp.get_data(as_text=True)

    m = re.search(r"DB-Schema[^<]*</dt>\s*<dd[^>]*>([^<]+)</dd>", body)
    assert m is not None, "DB-Schema-DD nicht gefunden"
    value = m.group(1).strip()
    assert re.fullmatch(r"[a-f0-9]+|unknown", value), f"Unerwarteter Wert: {value!r}"


def test_about_response_does_not_leak_secret_envs(db_app: Flask) -> None:
    """Sicherheits-Gegen-Test: weder die Namen sensibler Env-Vars noch
    der Klartext eines konkreten Secrets darf in der Response auftauchen."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/about")
    body = resp.get_data(as_text=True)

    forbidden = [
        "SECSCAN_ENCRYPTION_KEY",
        "SECSCAN_SECRET_KEY",
        "master_key_hash",
        "llm_api_key_encrypted",
        "password_hash",
    ]
    for token in forbidden:
        assert token not in body, f"Geheimnis-Marker '{token}' im About-Render!"


def test_about_response_does_not_leak_actual_secret_values(db_app: Flask) -> None:
    """Sicherheits-Sentinel: das vorher gesetzte `SECSCAN_SECRET_KEY` aus
    `db_app_env`-Fixture (`test-secret-key-not-used-in-prod`) darf nicht
    in der Response auftauchen — egal ob via Env oder DB-Spalte.

    Falls jemand die About-View versehentlich um `os.environ` erweitert,
    schlaegt dieser Test sofort an."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/about")
    body = resp.get_data(as_text=True)
    # `SECSCAN_SECRET_KEY`-Wert aus der Fixture darf nicht auftauchen.
    assert "test-secret-key-not-used-in-prod" not in body


def test_about_renders_app_version_value(db_app: Flask) -> None:
    """Smoke-Test: `about.app_version` wird gerendert (entweder die
    installierte Version oder `"unknown"` falls Metadata fehlt)."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/about")
    body = resp.get_data(as_text=True)

    m = re.search(r"App-Version</dt>\s*<dd[^>]*>([^<]+)</dd>", body)
    assert m is not None
    value = m.group(1).strip()
    # Entweder semver-aehnlich (z.B. 0.1.0) oder "unknown".
    assert value == "unknown" or re.match(r"[0-9]", value), f"Unerwartet: {value!r}"


def test_about_build_revision_uses_env_when_set(db_app: Flask) -> None:
    """Wenn `SECSCAN_BUILD_REVISION` gesetzt ist, taucht der Wert im
    Build-Revision-Feld auf.

    Der View liest `os.environ.get("SECSCAN_BUILD_REVISION", "dev")` zur
    Request-Zeit (siehe `settings.py::about_view`). Wir setzen
    `os.environ` direkt (statt monkeypatch) und raeumen explizit auf —
    monkeypatch erzeugte in dieser Test-Konfiguration einen
    Connection-Pool-Hang.
    """
    sentinel = "abc1234-canary"
    prev = os.environ.get("SECSCAN_BUILD_REVISION")
    os.environ["SECSCAN_BUILD_REVISION"] = sentinel
    try:
        create_admin_user(db_app)
        client = db_app.test_client()
        login(client)
        resp = client.get("/settings/about")
        body = resp.get_data(as_text=True)

        m = re.search(r"Build revision</dt>\s*<dd[^>]*>([^<]+)</dd>", body)
        assert m is not None
        value = m.group(1).strip()
        assert value == sentinel, value
    finally:
        if prev is None:
            os.environ.pop("SECSCAN_BUILD_REVISION", None)
        else:
            os.environ["SECSCAN_BUILD_REVISION"] = prev
