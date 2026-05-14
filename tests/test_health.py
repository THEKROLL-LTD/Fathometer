"""Smoke-Tests fuer die Health- und Readiness-Endpoints."""

from __future__ import annotations

from flask.testing import FlaskClient


def test_readyz_returns_200_with_ready_status(client: FlaskClient) -> None:
    response = client.get("/readyz")
    assert response.status_code == 200, response.status_code
    payload = response.get_json()
    assert payload is not None, response.data
    # `/readyz` muss ein Status-Feld liefern, das die Bereitschaft signalisiert.
    assert payload.get("status") == "ready", payload


def test_healthz_returns_503_when_db_unreachable(client: FlaskClient) -> None:
    """DB-URL im Test ist absichtlich unerreichbar (127.0.0.1:1) -> 503."""
    response = client.get("/healthz")
    assert response.status_code == 503, response.status_code
    payload = response.get_json()
    assert payload is not None, response.data
    assert payload.get("status") != "ok", payload
