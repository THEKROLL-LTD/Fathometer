"""View-Tests fuer den Provider-Wechsel-Hook in `app.views.llm_settings`.

Verifiziert ARCHITECTURE.md §12 und ADR-0006:
- Aenderung von `base_url` ODER `model` archiviert alle aktiven Conversations.
- Aenderung nur von `daily_token_cap` (oder `provider_name`) archiviert NICHT.
- Audit-Event `llm.provider_changed` mit `metadata.archived_conversations`.
- Audit-Event `settings.updated` wird IMMER geschrieben.
- Mehrere aktive Conversations (auf verschiedenen Servern) -> alle archiviert.

CSRF ist im `db_app` deaktiviert (siehe conftest). Login wird via Helper
gemacht.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    AuditEvent,
    LlmConversation,
    LlmConversationStatus,
    Server,
    Setting,
)
from tests._helpers import create_admin_user, login

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_settings(
    app: Flask,
    *,
    base_url: str | None = "https://api.deepinfra.com/v1/openai",
    model: str | None = "deepseek-ai/DeepSeek-V3",
    provider_name: str = "deepinfra",
    cap: int = 1_000_000,
) -> None:
    """Setzt eine Settings-Zeile mit gegebenem Provider-State."""
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
            row.llm_provider_name = provider_name
            row.llm_daily_token_cap = cap
            sess.commit()
        finally:
            sess.close()


def _seed_server(app: Flask, name: str) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _seed_conversation(
    app: Flask, server_id: int, *, model: str = "deepseek-ai/DeepSeek-V3"
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            ts = datetime.now(tz=UTC)
            conv = LlmConversation(
                server_id=server_id,
                started_at=ts,
                last_message_at=ts,
                model=model,
                status=LlmConversationStatus.ACTIVE,
                findings_snapshot_at=ts,
            )
            sess.add(conv)
            sess.flush()
            cid = conv.id
            sess.commit()
            return cid
        finally:
            sess.close()


def _get_conv(app: Flask, conv_id: int) -> LlmConversation:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return sess.execute(
                select(LlmConversation).where(LlmConversation.id == conv_id)
            ).scalar_one()
        finally:
            sess.close()


def _audit(app: Flask, action: str) -> list[AuditEvent]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(select(AuditEvent).where(AuditEvent.action == action)).scalars().all()
            )
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Provider-Wechsel (base_url)
# ---------------------------------------------------------------------------


def test_base_url_change_archives_active_conversations(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app)
    sid = _seed_server(db_app, "srv-1")
    cid = _seed_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "openai",
            "base_url": "https://api.openai.com/v1",  # changed
            "api_key": "",
            "model": "deepseek-ai/DeepSeek-V3",
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.get_data(as_text=True)[:300]

    conv = _get_conv(db_app, cid)
    assert conv.status == LlmConversationStatus.ARCHIVED

    events = _audit(db_app, "llm.provider_changed")
    assert len(events) == 1
    md = events[0].event_metadata
    assert md is not None
    assert cid in md["archived_conversations"]
    assert md["old_base_url"] == "https://api.deepinfra.com/v1/openai"
    assert md["new_base_url"] == "https://api.openai.com/v1"


def test_model_change_archives_active_conversations(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app)
    sid = _seed_server(db_app, "srv-1")
    cid = _seed_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "deepinfra",
            "base_url": "https://api.deepinfra.com/v1/openai",
            "api_key": "",
            "model": "mistralai/Mistral-7B",  # changed
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.get_data(as_text=True)[:300]

    conv = _get_conv(db_app, cid)
    assert conv.status == LlmConversationStatus.ARCHIVED

    events = _audit(db_app, "llm.provider_changed")
    assert len(events) == 1
    md = events[0].event_metadata
    assert md is not None
    assert md["old_model"] == "deepseek-ai/DeepSeek-V3"
    assert md["new_model"] == "mistralai/Mistral-7B"


def test_cap_only_change_keeps_conversations_active(db_app: Flask) -> None:
    """Nur Cap-Aenderung darf nicht archivieren und keinen `provider_changed` Event."""
    create_admin_user(db_app)
    _seed_settings(db_app)
    sid = _seed_server(db_app, "srv-1")
    cid = _seed_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "deepinfra",
            "base_url": "https://api.deepinfra.com/v1/openai",  # same
            "api_key": "",
            "model": "deepseek-ai/DeepSeek-V3",  # same
            "daily_token_cap": "500000",  # changed
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.get_data(as_text=True)[:300]

    conv = _get_conv(db_app, cid)
    assert conv.status == LlmConversationStatus.ACTIVE

    # KEIN provider_changed-Event.
    assert _audit(db_app, "llm.provider_changed") == []
    # Aber settings.updated MUSS geschrieben sein.
    upd = _audit(db_app, "settings.updated")
    assert len(upd) == 1
    md = upd[0].event_metadata
    assert md is not None
    assert md["provider_changed"] is False


def test_provider_name_only_change_keeps_conversations_active(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_settings(db_app)
    sid = _seed_server(db_app, "srv-1")
    cid = _seed_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "deepinfra-renamed",  # changed
            "base_url": "https://api.deepinfra.com/v1/openai",
            "api_key": "",
            "model": "deepseek-ai/DeepSeek-V3",
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302

    conv = _get_conv(db_app, cid)
    assert conv.status == LlmConversationStatus.ACTIVE
    assert _audit(db_app, "llm.provider_changed") == []


def test_multiple_active_conversations_all_archived(db_app: Flask) -> None:
    """Provider-Wechsel mit Conversations auf verschiedenen Servern -> alle archiviert."""
    create_admin_user(db_app)
    _seed_settings(db_app)
    sid_a = _seed_server(db_app, "srv-a")
    sid_b = _seed_server(db_app, "srv-b")
    sid_c = _seed_server(db_app, "srv-c")
    cid_a = _seed_conversation(db_app, sid_a)
    cid_b = _seed_conversation(db_app, sid_b)
    cid_c = _seed_conversation(db_app, sid_c)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "openai",
            "base_url": "https://api.openai.com/v1",  # changed
            "api_key": "",
            "model": "gpt-4o-mini",  # changed too
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302

    for cid in (cid_a, cid_b, cid_c):
        conv = _get_conv(db_app, cid)
        assert conv.status == LlmConversationStatus.ARCHIVED, cid

    events = _audit(db_app, "llm.provider_changed")
    assert len(events) == 1
    md = events[0].event_metadata
    assert md is not None
    assert set(md["archived_conversations"]) == {cid_a, cid_b, cid_c}


def test_settings_updated_audit_always_written(db_app: Flask) -> None:
    """Auch bei reinem Provider-Name-Update wird `settings.updated` geloggt."""
    create_admin_user(db_app)
    _seed_settings(db_app)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "deepinfra",
            "base_url": "https://api.deepinfra.com/v1/openai",
            "api_key": "",
            "model": "deepseek-ai/DeepSeek-V3",
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302

    upd = _audit(db_app, "settings.updated")
    assert len(upd) == 1
    md = upd[0].event_metadata
    assert md is not None
    assert "fields" in md
    assert "provider_changed" in md


def test_archived_conversations_are_not_touched_again(db_app: Flask) -> None:
    """Bereits archivierte Conversations sollten nicht in `archived_conversations` auftauchen."""
    create_admin_user(db_app)
    _seed_settings(db_app)
    sid = _seed_server(db_app, "srv-1")
    cid_active = _seed_conversation(db_app, sid)
    cid_archived = _seed_conversation(db_app, sid)

    # cid_archived manuell auf ARCHIVED setzen.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            conv = sess.execute(
                select(LlmConversation).where(LlmConversation.id == cid_archived)
            ).scalar_one()
            conv.status = LlmConversationStatus.ARCHIVED
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "openai",
            "base_url": "https://api.openai.com/v1",
            "api_key": "",
            "model": "gpt-4o-mini",
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302

    events = _audit(db_app, "llm.provider_changed")
    assert len(events) == 1
    md: Any = events[0].event_metadata
    archived = md["archived_conversations"]
    assert cid_active in archived
    assert cid_archived not in archived


def test_api_key_change_alone_does_not_trigger_provider_changed(db_app: Flask) -> None:
    """Aenderung des API-Keys (selbe base_url + model) ist KEIN Provider-Wechsel.

    Begruendung aus ARCHITECTURE.md §12: nur `base_url`/`model` -> archiviert,
    Key-Rotation ist explizit kein Trigger.
    """
    create_admin_user(db_app)
    _seed_settings(db_app)
    sid = _seed_server(db_app, "srv-1")
    cid = _seed_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm/",
        data={
            "provider_name": "deepinfra",
            "base_url": "https://api.deepinfra.com/v1/openai",
            "api_key": "new-key-value",  # changed
            "model": "deepseek-ai/DeepSeek-V3",
            "daily_token_cap": "1000000",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302

    conv = _get_conv(db_app, cid)
    assert conv.status == LlmConversationStatus.ACTIVE
    assert _audit(db_app, "llm.provider_changed") == []
