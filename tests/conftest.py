"""Globale pytest-Fixtures.

Stellt die App-Factory in einem isolierten Environment bereit. Detaillierte
Tests schreibt der `test-writer`-Agent.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from flask import Flask
from flask.testing import FlaskClient


@pytest.fixture
def app_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Setzt die minimal noetigen Env-Vars fuer `create_app()`."""
    monkeypatch.setenv("SECSCAN_ENCRYPTION_KEY", "x" * 32)
    monkeypatch.setenv("SECSCAN_SECRET_KEY", "test-secret-key-not-used-in-prod")
    monkeypatch.setenv(
        "SECSCAN_DATABASE_URL",
        # Bewusst nicht erreichbar — Healthz darf scheitern, andere Tests
        # rufen die DB nicht direkt auf.
        "postgresql+psycopg://test:test@127.0.0.1:1/test",
    )
    monkeypatch.setenv("SECSCAN_LOG_LEVEL", "WARNING")
    yield


@pytest.fixture
def app(app_env: None) -> Flask:
    """Erzeugt eine Test-App-Instanz pro Test."""
    # Lazy-Import damit Env-Setup vor `load_settings()` laeuft.
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Flask-Testclient fuer HTTP-Smoke-Tests."""
    return app.test_client()


@pytest.fixture(autouse=True)
def _clean_environment() -> Iterator[None]:
    """Stellt sicher, dass keine Test-Vars in nachfolgende Tests bluten."""
    snapshot = dict(os.environ)
    yield
    # Restore — monkeypatch macht das eigentlich selbst, das hier ist
    # Defense-in-Depth fuer Tests die `os.environ` direkt manipulieren.
    for key in list(os.environ.keys()):
        if key not in snapshot:
            del os.environ[key]
    for key, value in snapshot.items():
        os.environ[key] = value
