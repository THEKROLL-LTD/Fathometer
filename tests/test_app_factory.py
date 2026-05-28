"""Smoke-Tests fuer die App-Factory `app.create_app`.

Prueft die Cross-Cutting-Defaults aus Block A:
- Settings werden geladen (Pflicht-Env-Var `SECSCAN_ENCRYPTION_KEY`).
- `MAX_CONTENT_LENGTH` ist 64 MB Default bzw. ueberschreibbar.
- Jinja-Autoescape ist aktiv.
- Fehlende Pflicht-Env-Var fuehrt zu `SystemExit`.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from flask import Flask


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    """Stellt sicher, dass keine `SECSCAN_*`-Vars aus dem Host-Env durchschlagen."""
    # Pflicht- und optionale Settings entfernen, um deterministischen Ausgang zu garantieren.
    for key in (
        "SECSCAN_ENCRYPTION_KEY",
        "SECSCAN_SECRET_KEY",
        "SECSCAN_DATABASE_URL",
        "SECSCAN_MAX_BODY_MB",
        "SECSCAN_LOG_LEVEL",
    ):
        monkeypatch.delenv(key, raising=False)
    yield monkeypatch


def test_create_app_returns_flask_instance(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SECSCAN_ENCRYPTION_KEY", "x" * 32)
    clean_env.setenv("SECSCAN_DATABASE_URL", "postgresql+psycopg://test:test@127.0.0.1:1/test")

    from app import create_app

    app = create_app()
    assert isinstance(app, Flask), type(app)


def test_default_max_content_length_is_64_mb(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SECSCAN_ENCRYPTION_KEY", "x" * 32)
    clean_env.setenv("SECSCAN_DATABASE_URL", "postgresql+psycopg://test:test@127.0.0.1:1/test")

    from app import create_app

    app = create_app()
    assert app.config["MAX_CONTENT_LENGTH"] == 64 * 1024 * 1024, app.config["MAX_CONTENT_LENGTH"]


def test_jinja_autoescape_is_enabled(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SECSCAN_ENCRYPTION_KEY", "x" * 32)
    clean_env.setenv("SECSCAN_DATABASE_URL", "postgresql+psycopg://test:test@127.0.0.1:1/test")

    from app import create_app

    app = create_app()
    assert app.jinja_env.autoescape is True, app.jinja_env.autoescape


def test_max_body_mb_override_applies(clean_env: pytest.MonkeyPatch) -> None:
    """Override via `SECSCAN_MAX_BODY_MB` muss bis zu `MAX_CONTENT_LENGTH` durchschlagen."""
    clean_env.setenv("SECSCAN_ENCRYPTION_KEY", "x" * 32)
    clean_env.setenv("SECSCAN_DATABASE_URL", "postgresql+psycopg://test:test@127.0.0.1:1/test")
    clean_env.setenv("SECSCAN_MAX_BODY_MB", "5")

    from app import create_app

    app = create_app()
    assert app.config["MAX_CONTENT_LENGTH"] == 5 * 1024 * 1024, app.config["MAX_CONTENT_LENGTH"]


def test_missing_encryption_key_refuses_start(clean_env: pytest.MonkeyPatch) -> None:
    """Ohne `SECSCAN_ENCRYPTION_KEY` darf die App nicht starten."""
    # Bewusst keinen Key setzen.
    clean_env.setenv("SECSCAN_DATABASE_URL", "postgresql+psycopg://test:test@127.0.0.1:1/test")

    from app import create_app

    with pytest.raises(SystemExit):
        create_app()


def test_too_short_encryption_key_refuses_start(clean_env: pytest.MonkeyPatch) -> None:
    """Key unter 32 Zeichen ist auch unzureichend."""
    clean_env.setenv("SECSCAN_ENCRYPTION_KEY", "tooshort")
    clean_env.setenv("SECSCAN_DATABASE_URL", "postgresql+psycopg://test:test@127.0.0.1:1/test")

    from app import create_app

    with pytest.raises(SystemExit):
        create_app()
