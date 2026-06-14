"""Block N (ADR-0021) — Smoke-Tests fuer die drei Bootstrap-Installer-Routes.

Die volle Test-Runde (Inhaltsstruktur, Adversarial, ETag-Roundtrip) kommt
in Phase D durch den test-writer; hier nur Implementations-begleitende
Smoke-Tests fuer die Tasks #5, #6, #7.
"""

from __future__ import annotations

import json

from flask import Flask


def test_agent_version_returns_json_shape(db_app: Flask) -> None:
    """Task #5 — `GET /agent/version` liefert das erwartete JSON ohne Auth."""
    client = db_app.test_client()
    resp = client.get("/agent/version")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    assert resp.mimetype == "application/json"
    data = json.loads(resp.get_data(as_text=True))
    assert set(data.keys()) == {
        "current_agent_version",
        "min_agent_version",
        "recommended_trivy_version",
        "min_trivy_version",
        "trivy_release_url_template",
    }
    assert data["current_agent_version"] == "0.8.0"
    assert data["min_agent_version"] == "0.1.0"
    assert data["recommended_trivy_version"] == "0.71.0"
    assert data["min_trivy_version"] == "0.70.0"
    assert "{version}" in data["trivy_release_url_template"]
    assert "{arch}" in data["trivy_release_url_template"]


def test_agent_files_serves_whitelisted_scripts(db_app: Flask) -> None:
    """Task #6 — `GET /agent/files/fathometer-agent.sh` liefert das Skript."""
    client = db_app.test_client()
    resp = client.get("/agent/files/fathometer-agent.sh")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    assert resp.mimetype == "text/x-shellscript"
    body = resp.get_data(as_text=True)
    assert "AGENT_VERSION=" in body

    resp2 = client.get("/agent/files/fathometer-register.sh")
    assert resp2.status_code == 200
    body2 = resp2.get_data(as_text=True)
    assert "fathometer-register.sh" in body2


def test_agent_files_rejects_non_whitelisted_names(db_app: Flask) -> None:
    """Task #6 — Whitelist haert gegen unbekannte Namen und Traversal."""
    client = db_app.test_client()
    # Nicht in der Whitelist (auch wenn die Datei existiert).
    assert client.get("/agent/files/install.sh").status_code == 404
    # Path-Traversal — Werkzeug normalisiert auf die nackte Route ohne
    # Slash; `/agent/files/../../etc/passwd` matcht die Route ueberhaupt
    # nicht und bekommt 404 vom Router. Wir testen mehrere Varianten.
    for path in (
        "/agent/files/../../etc/passwd",
        "/agent/files/..%2f..%2fetc%2fpasswd",
        "/agent/files/fathometer-agent.sh/../fathometer-register.sh",
        "/agent/files/fathometer-agent",
        "/agent/files/FATHOMETER-AGENT.SH",  # case-sensitive Whitelist
    ):
        resp = client.get(path)
        assert resp.status_code == 404, (path, resp.status_code)


def test_install_sh_renders_with_backend_url(db_app: Flask) -> None:
    """Task #7 — `GET /install.sh` rendert das Template mit eingebackener URL."""
    client = db_app.test_client()
    resp = client.get("/install.sh")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    assert resp.mimetype == "text/x-shellscript"
    body = resp.get_data(as_text=True)
    assert body.startswith("#!/usr/bin/env bash")
    # Die Template-Variablen sind aufgeloest (kein Jinja-Marker uebrig).
    assert "{{" not in body
    assert "}}" not in body
    # Eingebackene Konstanten.
    assert "0.71.0" in body  # RECOMMENDED_TRIVY_VERSION
    assert "0.8.0" in body  # CURRENT_AGENT_VERSION
    # Backend-URL ist gesetzt (Fallback auf request.host_url im Test-Setup).
    assert "http://" in body or "https://" in body
