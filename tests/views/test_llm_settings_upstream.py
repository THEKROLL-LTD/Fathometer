"""Pure-Unit-/Mock-Tests fuer ``llm_settings.update_upstream`` (Block AI-2, ADR-0063, P1).

DB-frei: ``get_session``/``get_settings_row`` werden im ``llm_settings``-Modul-
Namespace gepatcht (Fake-Setting-Row mit Attribut-Mutation), ``log_event`` wird
gespy't. ``encrypt_api_key`` bleibt der echte Fernet-Encrypt (wir verifizieren,
dass das Secret NICHT als Klartext landet und tatsaechlich verschluesselt wird).
Auth via ``LOGIN_DISABLED``, CSRF aus.

Voller DB-Roundtrip (Commit gegen Postgres) ist db_integration und steht beim
User an — hier NICHT dupliziert.
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from flask import Flask

import app.views.llm_settings as ls
from app.services.llm_client import decrypt_api_key


class _FakeSettingRow:
    """Mutierbares Setting-Surrogat — die View setzt Attribute direkt."""

    def __init__(self) -> None:
        # Provider-Felder (vom Re-Render-Pfad gelesen).
        self.llm_provider_name = "DeepInfra"
        self.llm_base_url = "https://api.deepinfra.com/v1/openai"
        self.llm_reviewer_model = "openai/gpt-oss-120b"
        self.llm_chat_model = "deepseek-ai/DeepSeek-V4-Flash"
        self.llm_daily_token_cap = 1_000_000
        self.llm_api_key_encrypted: bytes | None = b"existing"
        # Upstream-Felder.
        self.upstream_check_enabled = False
        self.upstream_search_backend: str | None = None
        self.upstream_search_base_url: str | None = None
        self.upstream_search_username: str | None = None
        self.llm_research_model: str | None = None
        self.upstream_search_api_key_encrypted: bytes | None = None
        self.upstream_search_password_encrypted: bytes | None = None


class _FakeSession:
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
    monkeypatch: pytest.MonkeyPatch, *, row: _FakeSettingRow, sess: _FakeSession
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    def _spy_log(action: str, **kw: Any) -> None:
        events.append({"action": action, **kw})

    monkeypatch.setattr(ls, "get_session", lambda: sess)
    monkeypatch.setattr(ls, "get_settings_row", lambda _s=None: row)
    monkeypatch.setattr(ls, "log_event", _spy_log)
    return events


def _enc_key(app: Flask) -> str:
    from typing import cast

    from app.config import Settings

    return cast(Settings, app.config["FM_SETTINGS"]).encryption_key.get_secret_value()


# ---------------------------------------------------------------------------
# Persist-Pfad
# ---------------------------------------------------------------------------


def test_persists_plain_fields(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    row = _FakeSettingRow()
    sess = _FakeSession()
    events = _patch(monkeypatch, row=row, sess=sess)

    resp = nodb_app.test_client().post(
        "/settings/llm/upstream",
        data={
            "upstream_check_enabled": "y",
            "upstream_search_backend": "searxng",
            "upstream_search_base_url": "https://searx.internal/search",
            "upstream_search_username": "scanbot",
            "llm_research_model": "deepseek-ai/DeepSeek-V4-Flash",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.data
    assert row.upstream_check_enabled is True
    assert row.upstream_search_backend == "searxng"
    assert row.upstream_search_base_url == "https://searx.internal/search"
    assert row.upstream_search_username == "scanbot"
    assert row.llm_research_model == "deepseek-ai/DeepSeek-V4-Flash"
    assert sess.commit_count == 1
    assert [e["action"] for e in events] == ["upstream_check.configured"]


def test_secret_is_encrypted_not_plaintext(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """API-Key + SearXNG-Passwort landen Fernet-verschluesselt, nie als Klartext."""
    row = _FakeSettingRow()
    sess = _FakeSession()
    _patch(monkeypatch, row=row, sess=sess)
    secret_key = "super-secret-search-key"
    secret_pw = "searx-basic-pw"

    resp = nodb_app.test_client().post(
        "/settings/llm/upstream",
        data={
            "upstream_check_enabled": "y",
            "upstream_search_backend": "searxng",
            "upstream_search_base_url": "https://searx.internal/search",
            "upstream_search_api_key": secret_key,
            "upstream_search_password": secret_pw,
        },
    )
    assert resp.status_code == 302, resp.data
    enc_key_blob = row.upstream_search_api_key_encrypted
    enc_pw_blob = row.upstream_search_password_encrypted
    assert isinstance(enc_key_blob, bytes) and enc_key_blob, (
        "Key muss verschluesselt persistiert sein"
    )
    assert isinstance(enc_pw_blob, bytes) and enc_pw_blob
    # Klartext darf NICHT in der gespeicherten Spalte stehen.
    assert secret_key.encode() not in enc_key_blob
    assert secret_pw.encode() not in enc_pw_blob
    # Roundtrip: Fernet entschluesselt wieder den Klartext.
    enc_key = _enc_key(nodb_app)
    assert decrypt_api_key(enc_key_blob, enc_key) == secret_key
    assert decrypt_api_key(enc_pw_blob, enc_key) == secret_pw


def test_empty_secret_keeps_existing_value(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _FakeSettingRow()
    row.upstream_search_api_key_encrypted = b"old-encrypted-blob"
    sess = _FakeSession()
    _patch(monkeypatch, row=row, sess=sess)

    nodb_app.test_client().post(
        "/settings/llm/upstream",
        data={
            "upstream_check_enabled": "y",
            "upstream_search_backend": "tavily",
            "upstream_search_base_url": "https://api.tavily.com",
            "upstream_search_api_key": "",  # leer -> behalten
        },
    )
    assert row.upstream_search_api_key_encrypted == b"old-encrypted-blob"


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_audit_lists_changed_fields_never_plaintext_secret(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _FakeSettingRow()
    sess = _FakeSession()
    events = _patch(monkeypatch, row=row, sess=sess)
    secret = "leak-me-if-you-dare"

    nodb_app.test_client().post(
        "/settings/llm/upstream",
        data={
            "upstream_check_enabled": "y",
            "upstream_search_backend": "serper",
            "upstream_search_base_url": "https://google.serper.dev",
            "upstream_search_api_key": secret,
        },
    )
    assert len(events) == 1
    ev = events[0]
    assert ev["action"] == "upstream_check.configured"
    meta = ev["metadata"]
    # Feldname ist gelistet ...
    assert "upstream_search_api_key" in meta["fields"]
    assert "upstream_search_backend" in meta["fields"]
    assert meta["backend"] == "serper"
    assert meta["enabled"] is True
    # ... aber NIE der Klartext-Wert irgendwo in den Metadaten.
    import json

    blob = json.dumps(meta)
    assert secret not in blob, f"Klartext-Secret im Audit-Metadata-Blob: {blob}"


def test_audit_no_secret_field_when_secret_empty(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _FakeSettingRow()
    sess = _FakeSession()
    events = _patch(monkeypatch, row=row, sess=sess)

    nodb_app.test_client().post(
        "/settings/llm/upstream",
        data={
            "upstream_check_enabled": "y",
            "upstream_search_backend": "searxng",
            "upstream_search_base_url": "https://searx.internal",
        },
    )
    meta = events[0]["metadata"]
    assert "upstream_search_api_key" not in meta["fields"]
    assert "upstream_search_password" not in meta["fields"]


# ---------------------------------------------------------------------------
# Defense-in-Depth Backend-Whitelist
# ---------------------------------------------------------------------------


def test_invalid_backend_rejected_at_form_level(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein unbekanntes Backend wird bereits vom Form verworfen -> 400, kein Commit."""
    row = _FakeSettingRow()
    sess = _FakeSession()
    events = _patch(monkeypatch, row=row, sess=sess)

    resp = nodb_app.test_client().post(
        "/settings/llm/upstream",
        data={"upstream_check_enabled": "y", "upstream_search_backend": "evilbackend"},
    )
    assert resp.status_code == 400, resp.data
    assert sess.commit_count == 0
    assert events == [], "kein Audit-Event bei Validierungsfehler"


def test_validation_error_renders_400_without_persist(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ungueltige base_url -> 400, Felder bleiben unveraendert, kein Commit."""
    row = _FakeSettingRow()
    sess = _FakeSession()
    _patch(monkeypatch, row=row, sess=sess)

    resp = nodb_app.test_client().post(
        "/settings/llm/upstream",
        data={
            "upstream_check_enabled": "y",
            "upstream_search_backend": "searxng",
            "upstream_search_base_url": "http://evil.example.com/search",
        },
    )
    assert resp.status_code == 400, resp.data
    assert sess.commit_count == 0
    assert row.upstream_check_enabled is False, "kein Persist bei Validierungsfehler"
