"""Tests fuer das Theme-Cookie-Handling (light/dark/auto).

Die App-Factory registriert einen `before_request`-Hook, der `g.theme`
basierend auf dem `theme`-Cookie setzt. Invalide Werte werden auf `auto`
normalisiert.
"""

from __future__ import annotations

import pytest
from flask import Flask, g, jsonify
from flask.testing import FlaskClient
from flask.wrappers import Response


@pytest.fixture
def app_with_probe(app: Flask) -> Flask:
    """Erweitert die Test-App um eine `/__probe`-Route, die `g.theme` zurueckgibt."""

    @app.get("/__probe")
    def _probe() -> Response:
        return jsonify({"theme": getattr(g, "theme", None)})

    return app


@pytest.fixture
def probe_client(app_with_probe: Flask) -> FlaskClient:
    return app_with_probe.test_client()


def test_no_cookie_defaults_to_auto(probe_client: FlaskClient) -> None:
    response = probe_client.get("/__probe")
    assert response.status_code == 200, response.status_code
    payload = response.get_json()
    assert payload == {"theme": "auto"}, payload


def test_dark_cookie_is_preserved(probe_client: FlaskClient) -> None:
    probe_client.set_cookie("theme", "dark")
    response = probe_client.get("/__probe")
    assert response.status_code == 200, response.status_code
    assert response.get_json() == {"theme": "dark"}, response.get_json()


def test_light_cookie_is_preserved(probe_client: FlaskClient) -> None:
    probe_client.set_cookie("theme", "light")
    response = probe_client.get("/__probe")
    assert response.status_code == 200, response.status_code
    assert response.get_json() == {"theme": "light"}, response.get_json()


def test_invalid_cookie_normalises_to_auto(probe_client: FlaskClient) -> None:
    probe_client.set_cookie("theme", "hackerman")
    response = probe_client.get("/__probe")
    assert response.status_code == 200, response.status_code
    assert response.get_json() == {"theme": "auto"}, response.get_json()


def test_invalid_cookie_is_overwritten_in_response(probe_client: FlaskClient) -> None:
    """`after_request` schreibt ein normalisiertes `theme=auto`-Cookie zurueck."""
    probe_client.set_cookie("theme", "hackerman")
    response = probe_client.get("/__probe")
    # Flask-Testclient: Set-Cookie-Header inspizieren.
    set_cookie_headers = response.headers.getlist("Set-Cookie")
    assert any("theme=auto" in h for h in set_cookie_headers), set_cookie_headers
