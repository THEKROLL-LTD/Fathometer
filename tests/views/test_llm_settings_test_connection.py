"""Pure-Unit-Tests fuer ``test_connection`` — Doppel-Probe (ADR-0057 §4).

Block AF. DB-FREI: ``get_session``/``get_settings_row`` im View-Modul gepatcht,
``build_client_from_settings`` an der Quelle (``app.services.llm_client``)
gepatcht — der Probe-Pfad importiert es lazy von dort. Kein echter Provider-Call.

Deckt:
- 2-Teil-Objekt ``{reviewer, chat}`` mit je ``{success, latency_ms, model, error}``.
- ``400 llm_not_configured`` wenn ``base_url`` fehlt.
- Reviewer-Teil ``not_configured`` wenn ``llm_reviewer_model`` None ist (kein Call).
- Error-Code-Mapping (``model_not_found`` / ``provider_error``).
- Key-/Exception-Leak-Regression: kein API-Key und kein roher Exception-Text
  in der Response-JSON.

Live-Provider-Doppelprobe steht beim User an (db_integration/integration).
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from flask import Flask

import app.services.llm_client as llm_client_mod
import app.views.llm_settings as views
from app.services.llm_client import ConnectionTestResult


class _SpySettingRow:
    def __init__(
        self,
        *,
        base_url: str | None = "https://api.deepinfra.com/v1/openai",
        reviewer_model: str | None = "openai/gpt-oss-120b",
        chat_model: str = "deepseek-ai/DeepSeek-V4-Flash",
        api_key_encrypted: bytes | None = b"enc-blob",
    ) -> None:
        self.llm_base_url = base_url
        self.llm_reviewer_model = reviewer_model
        self.llm_chat_model = chat_model
        self.llm_api_key_encrypted = api_key_encrypted


class _FakeClient:
    """Mock-``LlmClient`` mit konfigurierbarem ``test_connection``-Ergebnis."""

    def __init__(self, model: str, result: ConnectionTestResult) -> None:
        self._model = model
        self._result = result
        self.closed = False

    @property
    def model(self) -> str:
        return self._model

    async def test_connection(self) -> ConnectionTestResult:
        return self._result

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture
def nodb_app(app: Flask) -> Flask:
    from app import limiter

    app.config.update(TESTING=True, LOGIN_DISABLED=True, WTF_CSRF_ENABLED=False)
    with contextlib.suppress(Exception):
        limiter.reset()
    return app


def _patch_session(monkeypatch: pytest.MonkeyPatch, row: _SpySettingRow) -> None:
    monkeypatch.setattr(views, "get_session", lambda: object())
    monkeypatch.setattr(views, "get_settings_row", lambda _s=None: row)


def _patch_build(
    monkeypatch: pytest.MonkeyPatch,
    *,
    per_model: dict[str, ConnectionTestResult],
) -> dict[str, list[str]]:
    """Patcht ``build_client_from_settings`` an der Quelle.

    ``per_model`` mappt das effektiv genutzte Modell auf das Probe-Ergebnis.
    Returnt ein Dict mit dem ``calls``-Log (die je Probe genutzten Modelle).
    """
    log: dict[str, list[str]] = {"calls": []}

    def _fake_build(
        setting: Any, *, encryption_key: str, model_override: str | None = None
    ) -> _FakeClient:
        effective = model_override or setting.llm_reviewer_model
        log["calls"].append(effective)
        result = per_model[effective]
        return _FakeClient(effective, result)

    monkeypatch.setattr(llm_client_mod, "build_client_from_settings", _fake_build)
    return log


def _ok(model: str) -> ConnectionTestResult:
    return ConnectionTestResult(success=True, latency_ms=200, model=model, error=None)


def _fail(error: str) -> ConnectionTestResult:
    return ConnectionTestResult(success=False, latency_ms=10, model=None, error=error)


# ---------------------------------------------------------------------------
# 2-Teil-Objekt, beide Modelle geprobt
# ---------------------------------------------------------------------------


def test_two_part_result_both_models_probed(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Beide Modelle werden geprobt; Response traegt reviewer + chat Teile."""
    row = _SpySettingRow()
    _patch_session(monkeypatch, row)
    log = _patch_build(
        monkeypatch,
        per_model={
            "openai/gpt-oss-120b": _ok("openai/gpt-oss-120b"),
            "deepseek-ai/DeepSeek-V4-Flash": _ok("deepseek-ai/DeepSeek-V4-Flash"),
        },
    )

    resp = nodb_app.test_client().post("/settings/llm/test-connection")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()

    assert set(body.keys()) == {"reviewer", "chat"}, body
    for part in (body["reviewer"], body["chat"]):
        assert set(part.keys()) == {"success", "latency_ms", "model", "error"}, part

    assert body["reviewer"]["success"] is True
    assert body["reviewer"]["latency_ms"] == 200
    assert body["chat"]["success"] is True
    # Beide Modelle wurden tatsaechlich geprobt.
    assert "openai/gpt-oss-120b" in log["calls"]
    assert "deepseek-ai/DeepSeek-V4-Flash" in log["calls"]


# ---------------------------------------------------------------------------
# 400 wenn base_url fehlt
# ---------------------------------------------------------------------------


def test_400_when_base_url_missing(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fehlende base_url (gemeinsamer Gate) -> 400 llm_not_configured."""
    row = _SpySettingRow(base_url=None)
    _patch_session(monkeypatch, row)
    # build darf gar nicht aufgerufen werden.
    log = _patch_build(monkeypatch, per_model={})

    resp = nodb_app.test_client().post("/settings/llm/test-connection")
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert resp.get_json()["error"] == "llm_not_configured"
    assert log["calls"] == [], "Kein Provider-Call ohne base_url erwartet"


# ---------------------------------------------------------------------------
# Reviewer-Teil not_configured wenn reviewer_model None
# ---------------------------------------------------------------------------


def test_reviewer_not_configured_when_reviewer_model_none(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``llm_reviewer_model`` None -> Reviewer-Teil ``not_configured`` (kein Call);
    Chat-Teil wird trotzdem regulaer geprobt."""
    row = _SpySettingRow(reviewer_model=None)
    _patch_session(monkeypatch, row)
    log = _patch_build(
        monkeypatch,
        per_model={"deepseek-ai/DeepSeek-V4-Flash": _ok("deepseek-ai/DeepSeek-V4-Flash")},
    )

    resp = nodb_app.test_client().post("/settings/llm/test-connection")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()

    assert body["reviewer"]["success"] is False
    assert body["reviewer"]["error"] == "not_configured"
    assert body["reviewer"]["latency_ms"] is None
    # Chat-Teil wurde geprobt und ist erfolgreich.
    assert body["chat"]["success"] is True
    # Nur das Chat-Modell wurde tatsaechlich gebaut/geprobt.
    assert log["calls"] == ["deepseek-ai/DeepSeek-V4-Flash"], log["calls"]


# ---------------------------------------------------------------------------
# Error-Code-Mapping
# ---------------------------------------------------------------------------


def test_error_code_model_not_found(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """404/not-found-Provider-Fehler -> Error-Code ``model_not_found``."""
    row = _SpySettingRow()
    _patch_session(monkeypatch, row)
    _patch_build(
        monkeypatch,
        per_model={
            "openai/gpt-oss-120b": _ok("openai/gpt-oss-120b"),
            "deepseek-ai/DeepSeek-V4-Flash": _fail("NotFoundError: The model does not exist (404)"),
        },
    )

    resp = nodb_app.test_client().post("/settings/llm/test-connection")
    body = resp.get_json()
    assert body["chat"]["success"] is False
    assert body["chat"]["error"] == "model_not_found", body["chat"]
    # Bei Fehler traegt ``model`` den versuchten Modellnamen.
    assert body["chat"]["model"] == "deepseek-ai/DeepSeek-V4-Flash"


def test_error_code_provider_error_fallback(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unspezifischer Provider-Fehler -> Fallback-Code ``provider_error``."""
    row = _SpySettingRow()
    _patch_session(monkeypatch, row)
    _patch_build(
        monkeypatch,
        per_model={
            "openai/gpt-oss-120b": _fail("APIConnectionError: connection reset by peer"),
            "deepseek-ai/DeepSeek-V4-Flash": _ok("deepseek-ai/DeepSeek-V4-Flash"),
        },
    )

    resp = nodb_app.test_client().post("/settings/llm/test-connection")
    body = resp.get_json()
    assert body["reviewer"]["success"] is False
    assert body["reviewer"]["error"] == "provider_error", body["reviewer"]


# ---------------------------------------------------------------------------
# Key-/Exception-Leak-Regression
# ---------------------------------------------------------------------------


def test_no_api_key_or_raw_exception_in_response(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Weder API-Key noch roher Exception-Text duerfen in der Response-JSON
    auftauchen — nur maschinen-lesbare Error-Codes (ADR-0057 §4)."""
    secret_key_fragment = "sk-super-secret-key-abc123"
    raw_exc = f"AuthenticationError: invalid api_key {secret_key_fragment} rejected by provider"

    row = _SpySettingRow()
    _patch_session(monkeypatch, row)
    _patch_build(
        monkeypatch,
        per_model={
            "openai/gpt-oss-120b": _fail(raw_exc),
            "deepseek-ai/DeepSeek-V4-Flash": _fail(raw_exc),
        },
    )

    resp = nodb_app.test_client().post("/settings/llm/test-connection")
    raw_body = resp.get_data(as_text=True)

    assert secret_key_fragment not in raw_body, "API-Key-Fragment im Response-Body geleakt!"
    assert "AuthenticationError" not in raw_body, "Roher Exception-Class-Name geleakt!"
    assert "rejected by provider" not in raw_body, "Roher Exception-Text geleakt!"

    body = resp.get_json()
    # Auth-Fehler wird auf den kurzen Code gemappt.
    assert body["reviewer"]["error"] == "auth_error", body["reviewer"]
    assert body["chat"]["error"] == "auth_error", body["chat"]
