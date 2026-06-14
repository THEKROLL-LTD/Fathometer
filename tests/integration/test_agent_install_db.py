"""Block N (ADR-0021) — Vollstaendige View-Tests fuer die drei Bootstrap-
Installer-Routes (Tasks #5, #6, #7).

Ergaenzt die existierenden Smoke-Tests in `test_agent_install_smoke.py`
um:
* Negativ-Pfade fuer `/agent/files/` (Whitelist, weiterer Traversal).
* `/agent/version` ohne Auth (PUBLIC) → 200.
* `/install.sh` Body-Inhalt (RECOMMENDED_TRIVY_VERSION, AGENT_VERSION,
  Backend-URL).
* Content-Length und Caching-Header.

Smoke-Tests im Schwester-File bleiben bestehen — die zwei Files ueberlappen
bewusst minimal, damit sowohl der Phase-A-Implementer-Brief als auch
Phase D pro Subagenten klar nachvollziehbar ist.
"""

from __future__ import annotations

from flask import Flask

# ---------------------------------------------------------------------------
# /agent/version — JSON-Endpoint
# ---------------------------------------------------------------------------


def test_agent_version_returns_all_expected_keys(db_app: Flask) -> None:
    client = db_app.test_client()
    resp = client.get("/agent/version")
    assert resp.status_code == 200
    data = resp.get_json()
    assert set(data.keys()) == {
        "current_agent_version",
        "min_agent_version",
        "recommended_trivy_version",
        "min_trivy_version",
        "trivy_release_url_template",
    }


def test_agent_version_endpoint_is_public(db_app: Flask) -> None:
    """ADR-0021: drei Endpoints sind ohne Auth/Session erreichbar (PUBLIC_PATHS)."""
    # Brandneue Client-Instanz, keine Cookies, kein CSRF.
    client = db_app.test_client()
    resp = client.get("/agent/version")
    # WICHTIG: nicht 302 (auf Login redirected), nicht 401, sondern 200.
    assert resp.status_code == 200, (
        f"Got {resp.status_code} (location={resp.headers.get('Location')!r})"
    )


def test_agent_version_has_cache_header(db_app: Flask) -> None:
    client = db_app.test_client()
    resp = client.get("/agent/version")
    cache = resp.headers.get("Cache-Control", "")
    assert "max-age" in cache


# ---------------------------------------------------------------------------
# /agent/files/<name> — Whitelist
# ---------------------------------------------------------------------------


def test_agent_files_serves_fathometer_agent_sh(db_app: Flask) -> None:
    client = db_app.test_client()
    resp = client.get("/agent/files/fathometer-agent.sh")
    assert resp.status_code == 200
    assert resp.mimetype == "text/x-shellscript"
    body = resp.get_data(as_text=True)
    assert 'AGENT_VERSION="0.8.0"' in body


def test_agent_files_serves_fathometer_register_sh(db_app: Flask) -> None:
    client = db_app.test_client()
    resp = client.get("/agent/files/fathometer-register.sh")
    assert resp.status_code == 200
    assert resp.mimetype == "text/x-shellscript"
    body = resp.get_data(as_text=True)
    # Datei-Header oder Skript-Marker; das Register-Skript identifiziert
    # sich im Header.
    assert "fathometer-register.sh" in body or "fathometer-register" in body


def test_agent_files_serves_lib_host_state_sh(db_app: Flask) -> None:
    """v0.9.2: ``lib_host_state.sh`` muss ueber die Whitelist erreichbar sein.

    Begruendung: der Bootstrap-Installer laedt diese Library neben
    ``fathometer-agent.sh`` herunter. Fehlt sie auf dem Host, ist ``host_state``
    im Envelope leer → Pre-Triage liefert ``risk_band=unknown`` → die
    komplette Block-P-LLM-Pipeline wird silently disabled.
    """
    client = db_app.test_client()
    resp = client.get("/agent/files/lib_host_state.sh")
    assert resp.status_code == 200
    assert resp.mimetype == "text/x-shellscript"
    body = resp.get_data(as_text=True)
    # Identifizierender Marker aus dem Datei-Header.
    assert "lib_host_state.sh" in body


def test_agent_files_install_sh_not_in_whitelist(db_app: Flask) -> None:
    """`install.sh` ist ein eigenes Endpoint, NICHT ueber `/agent/files/`."""
    client = db_app.test_client()
    resp = client.get("/agent/files/install.sh")
    assert resp.status_code == 404


def test_agent_files_unknown_name_404(db_app: Flask) -> None:
    client = db_app.test_client()
    for path in (
        "/agent/files/random.sh",
        "/agent/files/foo",
        "/agent/files/FATHOMETER-AGENT.SH",  # case-sensitive Whitelist
        "/agent/files/fathometer-agent",  # ohne .sh
    ):
        resp = client.get(path)
        assert resp.status_code == 404, (path, resp.status_code)


def test_agent_files_traversal_returns_404(db_app: Flask) -> None:
    """Werkzeug normalisiert traversal — wir sehen entweder 404 vom Router
    oder 404 von der Whitelist. Niemals 200 oder 5xx."""
    client = db_app.test_client()
    for path in (
        "/agent/files/../../etc/passwd",
        "/agent/files/..%2f..%2fetc%2fpasswd",
        "/agent/files/fathometer-agent.sh/../fathometer-register.sh",
    ):
        resp = client.get(path)
        assert resp.status_code == 404, (path, resp.status_code)


# ---------------------------------------------------------------------------
# /install.sh — Jinja-Render
# ---------------------------------------------------------------------------


def test_install_sh_returns_shellscript(db_app: Flask) -> None:
    client = db_app.test_client()
    resp = client.get("/install.sh")
    assert resp.status_code == 200
    assert resp.mimetype == "text/x-shellscript"
    body = resp.get_data(as_text=True)
    assert body.startswith("#!/usr/bin/env bash")


def test_install_sh_contains_recommended_trivy_version(db_app: Flask) -> None:
    client = db_app.test_client()
    body = client.get("/install.sh").get_data(as_text=True)
    assert 'RECOMMENDED_TRIVY_VERSION="0.71.0"' in body
    assert 'MIN_TRIVY_VERSION="0.70.0"' in body
    assert 'CURRENT_AGENT_VERSION="0.8.0"' in body


def test_install_sh_has_resolved_backend_url(db_app: Flask) -> None:
    """Keine Jinja-Marker mehr im Body — alle Variablen sind aufgeloest."""
    client = db_app.test_client()
    body = client.get("/install.sh").get_data(as_text=True)
    assert "{{" not in body
    assert "{%" not in body
    # `FM_URL` ist auf eine echte URL gerendert (Test-Setup: host_url-
    # Fallback).
    assert 'FM_URL="http' in body


def test_install_sh_downloads_lib_host_state(db_app: Flask) -> None:
    """v0.9.2: das Installer-Template muss ``lib_host_state.sh`` neben
    ``fathometer-agent.sh`` in dasselbe Bin-Directory legen.

    Ohne diesen Download fehlt die Library auf dem Host → Agent sendet
    kein ``host_state`` → Pre-Triage faellt auf ``risk_band=unknown``,
    Block-P-LLM-Pipeline ist deaktiviert. Regression-Schutz fuer diese
    stille Distribution-Luecke.
    """
    client = db_app.test_client()
    body = client.get("/install.sh").get_data(as_text=True)
    # Download-URL muss im Skript stehen — wir greppen auf den Filename,
    # nicht auf die volle URL (host-portion variiert nach Umgebung).
    assert "lib_host_state.sh" in body
    # Beide Files muessen ueber den Loop iteriert werden (sichert die
    # gemeinsame Install-Logik ab).
    assert "fathometer-agent.sh lib_host_state.sh" in body


def test_install_sh_is_public(db_app: Flask) -> None:
    """Kein Auth, kein 302 auf /login, kein 401."""
    client = db_app.test_client()
    resp = client.get("/install.sh")
    assert resp.status_code == 200
    # Kein Setup-Wizard-Redirect (ADR-0021: `/install.sh` in
    # `_SETUP_EXEMPT_PREFIXES`).
    assert "setup" not in (resp.headers.get("Location") or "")
