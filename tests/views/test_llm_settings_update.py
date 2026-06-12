"""Pure-Unit-Tests fuer ``app.views.llm_settings`` — Reviewer-/Chat-Modell-Split.

Block AF / ADR-0057. DB-FREI: ``get_session``/``get_settings_row``/``log_event``
werden im View-Modul-Namespace gepatcht (Spy-Session statt echtem Postgres).
Auth via ``LOGIN_DISABLED=True``, CSRF aus, Limiter neutralisiert.

Deckt:
- ``update()`` persistiert **beide** Modelle auf die Setting-Row.
- ``llm.provider_changed`` feuert bei Reviewer- **oder** Chat-Modell-Aenderung.
- ``changed_fields`` enthaelt ``reviewer_model`` + ``chat_model``.
- No-Op (kein Modell/keine base_url geaendert) feuert **kein** provider_changed.
- Audit-Metadata traegt old/new fuer beide Modelle.
- Default-Konstanten + Presets fuehren beide Modelle.

Die Persistenz-Roundtrip-Variante gegen echtes Postgres steht beim User an
(db_integration ``tests/integration/test_llm_settings_view_db.py``).
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from flask import Flask

import app.views.llm_settings as views


class _SpySettingRow:
    """Stand-in fuer eine ``Setting``-Row mit den im View beruehrten Feldern."""

    def __init__(
        self,
        *,
        base_url: str | None = "https://api.deepinfra.com/v1/openai",
        reviewer_model: str | None = "openai/gpt-oss-120b",
        chat_model: str = "deepseek-ai/DeepSeek-V4-Flash",
    ) -> None:
        self.llm_provider_name: str | None = "deepinfra"
        self.llm_base_url = base_url
        self.llm_reviewer_model = reviewer_model
        self.llm_chat_model = chat_model
        self.llm_daily_token_cap = 1_000_000
        self.llm_api_key_encrypted: bytes | None = None


class _SpySession:
    def __init__(self) -> None:
        self.commit_count = 0

    def commit(self) -> None:
        self.commit_count += 1


@pytest.fixture
def nodb_app(app: Flask) -> Flask:
    from app import limiter

    app.config.update(TESTING=True, LOGIN_DISABLED=True, WTF_CSRF_ENABLED=False)
    with contextlib.suppress(Exception):
        limiter.reset()
    return app


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    row: _SpySettingRow,
    events: list[dict[str, Any]],
) -> _SpySession:
    """Patcht Session/Settings-Row-Loader/log_event im View-Modul."""
    sess = _SpySession()
    monkeypatch.setattr(views, "get_session", lambda: sess)
    monkeypatch.setattr(views, "get_settings_row", lambda _s=None: row)

    def _spy_log_event(event_type: str, **kwargs: Any) -> None:
        events.append({"event_type": event_type, **kwargs})

    monkeypatch.setattr(views, "log_event", _spy_log_event)
    return sess


def _post(app: Flask, **over: str) -> Any:
    base = {
        "provider_name": "deepinfra",
        "base_url": "https://api.deepinfra.com/v1/openai",
        "api_key": "",
        "reviewer_model": "openai/gpt-oss-120b",
        "chat_model": "deepseek-ai/DeepSeek-V4-Flash",
        "daily_token_cap": "1000000",
    }
    base.update(over)
    return app.test_client().post("/settings/llm/", data=base, follow_redirects=False)


# ---------------------------------------------------------------------------
# Persistenz beider Modelle
# ---------------------------------------------------------------------------


def test_update_persists_both_models(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """``update()`` schreibt reviewer_model + chat_model auf die Setting-Row."""
    row = _SpySettingRow(reviewer_model="old/reviewer", chat_model="old/chat")
    events: list[dict[str, Any]] = []
    sess = _patch(monkeypatch, row=row, events=events)

    resp = _post(
        nodb_app,
        reviewer_model="new/reviewer-model",
        chat_model="new/chat-model",
    )
    assert resp.status_code == 302, resp.get_data(as_text=True)
    assert row.llm_reviewer_model == "new/reviewer-model"
    assert row.llm_chat_model == "new/chat-model"
    assert sess.commit_count == 1


# ---------------------------------------------------------------------------
# provider_changed — feuert bei Reviewer- ODER Chat-Aenderung
# ---------------------------------------------------------------------------


def test_provider_changed_fires_on_reviewer_model_change(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nur das Reviewer-Modell aendert sich -> llm.provider_changed feuert."""
    row = _SpySettingRow(reviewer_model="old/reviewer", chat_model="stable/chat")
    events: list[dict[str, Any]] = []
    _patch(monkeypatch, row=row, events=events)

    resp = _post(nodb_app, reviewer_model="new/reviewer", chat_model="stable/chat")
    assert resp.status_code == 302

    types = [e["event_type"] for e in events]
    assert "llm.provider_changed" in types, types


def test_provider_changed_fires_on_chat_model_change(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nur das Chat-Modell aendert sich -> llm.provider_changed feuert."""
    row = _SpySettingRow(reviewer_model="stable/reviewer", chat_model="old/chat")
    events: list[dict[str, Any]] = []
    _patch(monkeypatch, row=row, events=events)

    resp = _post(nodb_app, reviewer_model="stable/reviewer", chat_model="new/chat")
    assert resp.status_code == 302

    types = [e["event_type"] for e in events]
    assert "llm.provider_changed" in types, types


def test_provider_changed_metadata_carries_old_new_for_both_models(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit-Metadata des provider_changed-Events traegt old/new fuer beide Modelle."""
    row = _SpySettingRow(reviewer_model="old/reviewer", chat_model="old/chat")
    events: list[dict[str, Any]] = []
    _patch(monkeypatch, row=row, events=events)

    _post(nodb_app, reviewer_model="new/reviewer", chat_model="new/chat")

    pc = next(e for e in events if e["event_type"] == "llm.provider_changed")
    meta = pc["metadata"]
    assert meta["old_reviewer_model"] == "old/reviewer", meta
    assert meta["new_reviewer_model"] == "new/reviewer", meta
    assert meta["old_chat_model"] == "old/chat", meta
    assert meta["new_chat_model"] == "new/chat", meta


# ---------------------------------------------------------------------------
# changed_fields — enthaelt beide Modelle
# ---------------------------------------------------------------------------


def test_changed_fields_contains_both_models(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``settings.updated``-Event listet reviewer_model + chat_model in ``fields``."""
    row = _SpySettingRow()
    events: list[dict[str, Any]] = []
    _patch(monkeypatch, row=row, events=events)

    _post(nodb_app)

    updated = next(e for e in events if e["event_type"] == "settings.updated")
    fields = updated["metadata"]["fields"]
    assert "reviewer_model" in fields, fields
    assert "chat_model" in fields, fields


# ---------------------------------------------------------------------------
# No-Op — kein provider_changed
# ---------------------------------------------------------------------------


def test_no_op_does_not_fire_provider_changed(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unveraenderte base_url + beide Modelle -> KEIN provider_changed.

    (``settings.updated`` feuert weiterhin — nur der Provider-Wechsel-Marker
    bleibt aus, mit ``provider_changed: False`` in der Metadata.)
    """
    row = _SpySettingRow(
        base_url="https://api.deepinfra.com/v1/openai",
        reviewer_model="openai/gpt-oss-120b",
        chat_model="deepseek-ai/DeepSeek-V4-Flash",
    )
    events: list[dict[str, Any]] = []
    _patch(monkeypatch, row=row, events=events)

    # Exakt die bestehenden Werte erneut posten.
    resp = _post(
        nodb_app,
        base_url="https://api.deepinfra.com/v1/openai",
        reviewer_model="openai/gpt-oss-120b",
        chat_model="deepseek-ai/DeepSeek-V4-Flash",
    )
    assert resp.status_code == 302

    types = [e["event_type"] for e in events]
    assert "llm.provider_changed" not in types, types
    updated = next(e for e in events if e["event_type"] == "settings.updated")
    assert updated["metadata"]["provider_changed"] is False


# ---------------------------------------------------------------------------
# Default-Konstanten + Presets
# ---------------------------------------------------------------------------


def test_default_model_constants() -> None:
    """Beide Default-Konstanten haben die ADR-0057-Werte."""
    assert views.DEFAULT_REVIEWER_MODEL == "openai/gpt-oss-120b"
    assert views.DEFAULT_CHAT_MODEL == "deepseek-ai/DeepSeek-V4-Flash"


def test_presets_carry_both_models() -> None:
    """Jeder Preset traegt reviewer_model + chat_model (Provider-Tab Preset-Apply)."""
    assert views.LLM_PRESETS, "mindestens ein Preset erwartet"
    for preset in views.LLM_PRESETS:
        assert preset["reviewer_model"] == views.DEFAULT_REVIEWER_MODEL, preset
        assert preset["chat_model"] == views.DEFAULT_CHAT_MODEL, preset
        assert "base_url" in preset, preset
