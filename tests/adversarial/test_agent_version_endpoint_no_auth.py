"""Block N (ADR-0021) — Adversarial: `/agent/version` ist PUBLIC.

Der Installer muss `/agent/version` *vor* dem Master-Key-Prompt aufrufen
koennen, um die Recommended-Trivy-Version zu lernen. Wenn die Route aus
Versehen hinter dem Setup-Guard oder Login-Wall landet (302 → /login),
haengt der Installer.
"""

from __future__ import annotations

from flask import Flask


def test_agent_version_no_auth_returns_200(db_app: Flask) -> None:
    """Frischer Client, keine Cookies — Route antwortet sofort mit 200."""
    client = db_app.test_client()
    resp = client.get("/agent/version")
    assert resp.status_code == 200, (
        f"Got {resp.status_code} (Location={resp.headers.get('Location')!r}) — "
        "/agent/version muss PUBLIC sein (ADR-0021)."
    )
    # Kein 302 auf /login oder /setup.
    assert "Location" not in resp.headers or "/login" not in (resp.headers.get("Location") or "")


def test_agent_version_redirect_free(db_app: Flask) -> None:
    """Auch mit `follow_redirects=False`: erstes Response ist direkt 200, kein 3xx."""
    client = db_app.test_client()
    resp = client.get("/agent/version", follow_redirects=False)
    assert resp.status_code == 200


def test_install_sh_public_too(db_app: Flask) -> None:
    """Schwester-Endpoint — gleicher Public-Garant gilt fuer `/install.sh`."""
    client = db_app.test_client()
    resp = client.get("/install.sh", follow_redirects=False)
    assert resp.status_code == 200
