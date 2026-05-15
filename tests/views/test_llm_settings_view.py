"""View-Tests fuer `/settings/llm` und `/settings/llm/test-connection`.

Deckt ergaenzend zu `tests/services/test_llm_provider_switch.py`:
- GET rendert die Form mit Presets.
- POST mit ungueltiger base_url -> 400 + Fehler-Render.
- /test-connection ohne Settings -> 400.
- /test-connection mit Settings + gemocktem `LlmClient.test_connection` ->
  Erfolg-JSON.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from flask import Flask

from app.db import get_session_factory
from app.models import Setting
from app.services.llm_client import ConnectionTestResult, encrypt_api_key
from tests._helpers import create_admin_user, login


def _seed_settings(
    app: Flask,
    *,
    base_url: str | None,
    model: str | None,
    api_key_enc: bytes | None = None,
) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = sess.get(Setting, 1)
            if row is None:
                row = Setting(id=1)
                sess.add(row)
            row.llm_base_url = base_url
            row.llm_model = model
            row.llm_provider_name = "test"
            row.llm_daily_token_cap = 1_000_000
            row.llm_api_key_encrypted = api_key_enc
            sess.commit()
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# GET /settings/llm/
# ---------------------------------------------------------------------------


def test_get_settings_page_renders_form(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app, base_url=None, model=None)

    client = db_app.test_client()
    login(client)

    resp = client.get("/settings/llm/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "base_url" in body.lower() or "base-url" in body.lower()


def test_get_settings_page_requires_login(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/settings/llm/")
    assert resp.status_code in (302, 401)


# ---------------------------------------------------------------------------
# POST /settings/llm/ — invalid form
# ---------------------------------------------------------------------------


def test_post_settings_invalid_base_url_returns_400(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app, base_url=None, model=None)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "test",
            "base_url": "http://evil.com",  # not https, not localhost
            "api_key": "",
            "model": "deepseek-ai/DeepSeek-V3",
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_post_settings_missing_model_returns_400(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app, base_url=None, model=None)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "test",
            "base_url": "https://api.openai.com/v1",
            "api_key": "",
            "model": "",  # required
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_post_settings_invalid_provider_name_returns_400(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app, base_url=None, model=None)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "Has Spaces!",  # invalid pattern
            "base_url": "https://api.openai.com/v1",
            "api_key": "",
            "model": "deepseek-ai/DeepSeek-V3",
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /settings/llm/test-connection
# ---------------------------------------------------------------------------


def test_test_connection_without_settings_returns_400(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app, base_url=None, model=None)

    client = db_app.test_client()
    login(client)

    resp = client.post("/settings/llm/test-connection")
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["success"] is False
    assert body["error"] == "llm_not_configured"


def test_test_connection_with_settings_success(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_admin_user(db_app)
    enc = encrypt_api_key("dummy", "x" * 32)
    _seed_settings(
        db_app,
        base_url="https://api.deepinfra.com/v1/openai",
        model="deepseek-ai/DeepSeek-V3",
        api_key_enc=enc,
    )

    # `LlmClient.test_connection` mocken -> Erfolg.
    from app.services import llm_client as llm_client_mod

    async def _mock_test_connection(self: Any) -> ConnectionTestResult:
        return ConnectionTestResult(
            success=True, latency_ms=123, model="deepseek-ai/DeepSeek-V3", error=None
        )

    async def _mock_aclose(self: Any) -> None:
        return None

    monkeypatch.setattr(llm_client_mod.LlmClient, "test_connection", _mock_test_connection)
    monkeypatch.setattr(llm_client_mod.LlmClient, "aclose", _mock_aclose)

    client = db_app.test_client()
    login(client)

    resp = client.post("/settings/llm/test-connection")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["success"] is True
    assert body["latency_ms"] == 123
    assert body["model"] == "deepseek-ai/DeepSeek-V3"
    assert body["error"] is None


def test_test_connection_failure(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    create_admin_user(db_app)
    enc = encrypt_api_key("bad", "x" * 32)
    _seed_settings(
        db_app,
        base_url="https://api.deepinfra.com/v1/openai",
        model="deepseek-ai/DeepSeek-V3",
        api_key_enc=enc,
    )

    from app.services import llm_client as llm_client_mod

    async def _mock_test_connection(self: Any) -> ConnectionTestResult:
        return ConnectionTestResult(
            success=False, latency_ms=42, model=None, error="AuthError: invalid key"
        )

    async def _mock_aclose(self: Any) -> None:
        return None

    monkeypatch.setattr(llm_client_mod.LlmClient, "test_connection", _mock_test_connection)
    monkeypatch.setattr(llm_client_mod.LlmClient, "aclose", _mock_aclose)

    client = db_app.test_client()
    login(client)

    resp = client.post("/settings/llm/test-connection")
    assert resp.status_code == 200  # success-Feld unterscheidet, nicht der HTTP-Status
    body = resp.get_json()
    assert body["success"] is False
    assert body["error"] is not None


def test_test_connection_requires_login(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app, base_url=None, model=None)
    client = db_app.test_client()
    resp = client.post("/settings/llm/test-connection")
    assert resp.status_code in (302, 401)


# ---------------------------------------------------------------------------
# POST /settings/llm/ — Happy-Path mit allen Feldern
# ---------------------------------------------------------------------------


def test_post_settings_persists_all_fields(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app, base_url=None, model=None)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "deepinfra",
            "base_url": "https://api.deepinfra.com/v1/openai",
            "api_key": "sk-new-key-value",
            "model": "deepseek-ai/DeepSeek-V3",
            "daily_token_cap": "500000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            row = sess.get(Setting, 1)
            assert row is not None
            assert row.llm_provider_name == "deepinfra"
            assert row.llm_base_url == "https://api.deepinfra.com/v1/openai"
            assert row.llm_model == "deepseek-ai/DeepSeek-V3"
            assert row.llm_daily_token_cap == 500000
            assert row.llm_api_key_encrypted is not None
            assert len(row.llm_api_key_encrypted) > 0
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Rate-Limit (Block H): POST /settings/llm/test-connection ist 60/hour begrenzt.
# ---------------------------------------------------------------------------


def test_test_connection_rate_limit_60_per_hour_returns_429_on_61st(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """61. POST in derselben Stunde gegen `/settings/llm/test-connection` -> 429."""
    from app import limiter

    create_admin_user(db_app)
    enc = encrypt_api_key("dummy", "x" * 32)
    _seed_settings(
        db_app,
        base_url="https://api.deepinfra.com/v1/openai",
        model="deepseek-ai/DeepSeek-V3",
        api_key_enc=enc,
    )

    # `LlmClient.test_connection` mocken — sonst wuerde der echte SDK
    # gegen die DeepInfra-URL gehen.
    from app.services import llm_client as llm_client_mod

    async def _mock_test_connection(self: Any) -> ConnectionTestResult:
        return ConnectionTestResult(
            success=True, latency_ms=1, model="deepseek-ai/DeepSeek-V3", error=None
        )

    async def _mock_aclose(self: Any) -> None:
        return None

    monkeypatch.setattr(llm_client_mod.LlmClient, "test_connection", _mock_test_connection)
    monkeypatch.setattr(llm_client_mod.LlmClient, "aclose", _mock_aclose)

    limiter.reset()

    client = db_app.test_client()
    login(client)

    # 60 erfolgreiche POSTs.
    for n in range(60):
        resp = client.post("/settings/llm/test-connection")
        assert resp.status_code == 200, (n, resp.get_data(as_text=True))

    # Der 61. POST trifft das Limit.
    resp_over = client.post("/settings/llm/test-connection")
    assert resp_over.status_code == 429, resp_over.get_data(as_text=True)


# Mark unused import for ruff
_ = AsyncMock
