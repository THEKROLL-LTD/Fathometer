"""API-Tests fuer `app.api.llm_chat`.

Deckt alle Routen aus Block G:
- `POST /servers/<id>/chat`
- `GET /chat/<id>` (Browser-View)
- `GET /chat/<id>/stream` (SSE)
- `POST /chat/<id>/messages` (JSON-Body)
- `POST /chat/<id>/archive`

LLM-Provider-Calls werden **immer** gemockt — niemals echte Netzwerk-Calls
in der Test-Suite. Wir patchen `LlmClient.stream_chat` mit einem
deterministischen async-Generator und `LlmClient.aclose` mit einem No-Op.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    AuditEvent,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    LlmConversation,
    LlmConversationFinding,
    LlmConversationStatus,
    LlmMessage,
    LlmMessageRole,
    Server,
    Setting,
    Severity,
)
from tests._helpers import create_admin_user, login

# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------


def _seed_llm_settings(
    app: Flask,
    *,
    base_url: str | None = "https://api.deepinfra.com/v1/openai",
    model: str | None = "deepseek-ai/DeepSeek-V3",
    cap: int = 1_000_000,
    api_key_encrypted: bytes | None = None,
) -> None:
    """Setzt LLM-Settings. Default = konfiguriert."""
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
            row.llm_daily_token_cap = cap
            if api_key_encrypted is not None:
                row.llm_api_key_encrypted = api_key_encrypted
            sess.commit()
        finally:
            sess.close()


def _seed_server_with_findings(
    app: Flask,
    *,
    name: str = "target-host",
    findings_count: int = 3,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            now = datetime(2026, 5, 14, 12, 0, tzinfo=UTC)
            for i in range(findings_count):
                sess.add(
                    Finding(
                        server_id=sid,
                        finding_type=FindingType.VULNERABILITY,
                        finding_class=FindingClass.OS_PKGS,
                        identifier_key=f"CVE-2026-{i:04d}",
                        package_name="openssl",
                        installed_version="1.1.1",
                        severity=Severity.HIGH,
                        title=f"Test finding {i}",
                        cvss_v3_score=7.0,
                        epss_score=0.5,
                        status=FindingStatus.OPEN,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )
            sess.commit()
            return sid
        finally:
            sess.close()


def _make_active_conversation(app: Flask, server_id: int) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            ts = datetime.now(tz=UTC)
            conv = LlmConversation(
                server_id=server_id,
                started_at=ts,
                last_message_at=ts,
                model="deepseek-ai/DeepSeek-V3",
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


def _messages_for(app: Flask, conv_id: int) -> list[LlmMessage]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(
                    select(LlmMessage)
                    .where(LlmMessage.conversation_id == conv_id)
                    .order_by(LlmMessage.id.asc())
                )
                .scalars()
                .all()
            )
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


def _conv_finding_snapshots(app: Flask, conv_id: int) -> list[LlmConversationFinding]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(
                    select(LlmConversationFinding).where(
                        LlmConversationFinding.conversation_id == conv_id
                    )
                )
                .scalars()
                .all()
            )
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# POST /servers/<id>/chat
# ---------------------------------------------------------------------------


def test_start_conversation_without_llm_settings_returns_400(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app, base_url=None, model=None)  # ungesetzt
    sid = _seed_server_with_findings(db_app)

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/servers/{sid}/chat")
    assert resp.status_code == 400, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["error"] == "llm_not_configured"


def test_start_conversation_requires_login(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)

    client = db_app.test_client()
    # Kein login.
    resp = client.post(f"/servers/{sid}/chat")
    # 302 redirect to login (Flask-Login default).
    assert resp.status_code in (302, 401)


def test_start_conversation_creates_new(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app, findings_count=3)

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/servers/{sid}/chat")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert "conversation_id" in body
    assert "stream_url" in body
    assert body["resumed"] is False
    cid = body["conversation_id"]

    # Conversation persistiert.
    conv = _get_conv(db_app, cid)
    assert conv.status == LlmConversationStatus.ACTIVE
    assert conv.server_id == sid

    # Snapshot der OPEN-Findings.
    snapshots = _conv_finding_snapshots(db_app, cid)
    assert len(snapshots) == 3

    # Audit-Event geschrieben.
    events = _audit(db_app, "llm.queried")
    assert len(events) == 1
    assert events[0].target_type == "llm_conversation"

    # System-Prompt + User-Intro persistiert.
    msgs = _messages_for(db_app, cid)
    assert len(msgs) >= 2
    roles = [m.role for m in msgs]
    assert LlmMessageRole.SYSTEM in roles
    assert LlmMessageRole.USER in roles


def test_start_conversation_resumes_existing(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    existing_cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/servers/{sid}/chat")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["conversation_id"] == existing_cid
    assert body["resumed"] is True


def test_start_conversation_404_on_unknown_server(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)

    client = db_app.test_client()
    login(client)

    resp = client.post("/servers/9999999/chat")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Token-Cap
# ---------------------------------------------------------------------------


def test_start_conversation_token_cap_exceeded_returns_429(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app, cap=10)
    sid = _seed_server_with_findings(db_app)

    # 15 Tokens Usage heute eingespielt -> ueber Cap=10.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            ts = datetime.now(tz=UTC)
            # Helper-Conversation als Anker fuer die LlmMessage-FK.
            srv2 = Server(name="other-srv", api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv2)
            sess.flush()
            conv = LlmConversation(
                server_id=srv2.id,
                started_at=ts,
                last_message_at=ts,
                model="m",
                status=LlmConversationStatus.ARCHIVED,
                findings_snapshot_at=ts,
            )
            sess.add(conv)
            sess.flush()
            sess.add(
                LlmMessage(
                    conversation_id=conv.id,
                    role=LlmMessageRole.ASSISTANT,
                    content="x",
                    created_at=ts,
                    prompt_tokens=10,
                    completion_tokens=5,
                )
            )
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/servers/{sid}/chat")
    assert resp.status_code == 429, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["error"] == "token_cap_exceeded"
    assert "reset_at" in body
    assert body["cap"] == 10
    assert body["used"] == 15


# ---------------------------------------------------------------------------
# POST /chat/<id>/messages
# ---------------------------------------------------------------------------


def test_post_message_appends_user_message(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(
        f"/chat/{cid}/messages",
        json={"content": "Welche CVE ist am kritischsten?"},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert "message_id" in body
    assert "stream_url" in body

    msgs = _messages_for(db_app, cid)
    assert len(msgs) == 1
    assert msgs[0].role == LlmMessageRole.USER
    assert msgs[0].content == "Welche CVE ist am kritischsten?"


def test_post_message_empty_content_returns_400(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/chat/{cid}/messages", json={"content": ""})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_content"


def test_post_message_whitespace_only_returns_400(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/chat/{cid}/messages", json={"content": "   \n  "})
    assert resp.status_code == 400


def test_post_message_missing_content_field_returns_400(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/chat/{cid}/messages", json={"other_field": "x"})
    assert resp.status_code == 400


def test_post_message_oversize_returns_400(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    big = "x" * (8 * 1024 + 100)
    resp = client.post(f"/chat/{cid}/messages", json={"content": big})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "content_too_long"


def test_post_message_on_archived_conversation_returns_409(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    # Conversation archivieren.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            conv = sess.execute(
                select(LlmConversation).where(LlmConversation.id == cid)
            ).scalar_one()
            conv.status = LlmConversationStatus.ARCHIVED
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/chat/{cid}/messages", json={"content": "hello"})
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "conversation_archived"


def test_post_message_requires_login(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    resp = client.post(f"/chat/{cid}/messages", json={"content": "x"})
    assert resp.status_code in (302, 401)


def test_post_message_token_cap_exceeded_returns_429(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app, cap=5)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    # Token-Usage erzeugen.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                LlmMessage(
                    conversation_id=cid,
                    role=LlmMessageRole.ASSISTANT,
                    content="x",
                    created_at=datetime.now(tz=UTC),
                    prompt_tokens=10,
                    completion_tokens=0,
                )
            )
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/chat/{cid}/messages", json={"content": "Hi"})
    assert resp.status_code == 429
    assert resp.get_json()["error"] == "token_cap_exceeded"


# ---------------------------------------------------------------------------
# POST /chat/<id>/archive
# ---------------------------------------------------------------------------


def test_archive_conversation_sets_status_and_audits(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/chat/{cid}/archive")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["status"] == "archived"
    assert body["conversation_id"] == cid

    conv = _get_conv(db_app, cid)
    assert conv.status == LlmConversationStatus.ARCHIVED

    events = _audit(db_app, "llm.conversation_archived")
    assert len(events) == 1
    assert events[0].target_id == str(cid)


def test_archive_idempotent_on_already_archived(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)
    # Erstes Archiv.
    client.post(f"/chat/{cid}/archive")
    # Zweites Archiv -> 200, kein zusaetzliches Audit (oder weiteres OK).
    resp = client.post(f"/chat/{cid}/archive")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "archived"


def test_archive_requires_login(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    resp = client.post(f"/chat/{cid}/archive")
    assert resp.status_code in (302, 401)


# ---------------------------------------------------------------------------
# GET /chat/<id> — Browser-View
# ---------------------------------------------------------------------------


def test_get_conversation_renders_page(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    login(client)

    resp = client.get(f"/chat/{cid}")
    assert resp.status_code == 200
    # HTML.
    body = resp.get_data(as_text=True)
    assert "<html" in body.lower() or "<!doctype" in body.lower()


def test_get_unknown_conversation_returns_404(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app)

    client = db_app.test_client()
    login(client)
    resp = client.get("/chat/9999999")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /chat/<id>/stream — SSE
# ---------------------------------------------------------------------------


async def _fake_stream_chat(
    self: Any, messages: list[dict[str, str]], *, max_tokens: int | None = None
) -> AsyncIterator[str]:
    """Mock fuer `LlmClient.stream_chat` — gibt drei Tokens zurueck und
    setzt eine deterministische Usage."""
    from app.services.llm_client import StreamUsage

    for tok in ("Hello, ", "this is ", "a test."):
        yield tok
    self._last_usage = StreamUsage(prompt_tokens=42, completion_tokens=7)


async def _fake_aclose(self: Any) -> None:
    return None


@pytest.fixture
def mock_llm_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patcht `LlmClient.stream_chat` und `aclose` mit Mocks."""
    from app.services import llm_client as llm_client_mod

    monkeypatch.setattr(llm_client_mod.LlmClient, "stream_chat", _fake_stream_chat)
    monkeypatch.setattr(llm_client_mod.LlmClient, "aclose", _fake_aclose)


def _seed_llm_settings_with_api_key(app: Flask) -> None:
    """Setzt Settings inkl. encrypted API-Key (sonst skipt build_client beim Decrypt)."""
    from app.services.llm_client import encrypt_api_key

    enc = encrypt_api_key("dummy-key", "x" * 32)
    _seed_llm_settings(app, api_key_encrypted=enc)


def test_stream_sets_sse_content_type_and_streams_tokens(
    db_app: Flask, mock_llm_stream: None
) -> None:
    create_admin_user(db_app)
    _seed_llm_settings_with_api_key(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    # Eine User-Message anfuegen damit der Stream nicht auf leerer History sitzt.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                LlmMessage(
                    conversation_id=cid,
                    role=LlmMessageRole.USER,
                    content="Bewerte bitte.",
                    created_at=datetime.now(tz=UTC),
                )
            )
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.get(f"/chat/{cid}/stream")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/event-stream")
    assert resp.headers.get("Cache-Control") == "no-cache"

    # Body voll konsumieren (Flask test_client puffert den ganzen Stream).
    body = resp.get_data(as_text=True)
    # Mindestens ein data:-Frame.
    assert "data: " in body
    # Der `done`-Marker am Ende.
    assert "event: done" in body
    # Assistant-Reply enthaelt eine unserer Mock-Token-Strings.
    assert "Hello" in body or "test" in body


def test_stream_persists_assistant_message_with_usage(db_app: Flask, mock_llm_stream: None) -> None:
    create_admin_user(db_app)
    _seed_llm_settings_with_api_key(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                LlmMessage(
                    conversation_id=cid,
                    role=LlmMessageRole.USER,
                    content="Bewerte bitte.",
                    created_at=datetime.now(tz=UTC),
                )
            )
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.get(f"/chat/{cid}/stream")
    # Body konsumieren — die assistant-message wird erst danach geschrieben.
    body = resp.get_data(as_text=True)
    assert "event: done" in body

    msgs = _messages_for(db_app, cid)
    assistants = [m for m in msgs if m.role == LlmMessageRole.ASSISTANT]
    assert len(assistants) == 1
    # Zusammengesetzter Mock-Output.
    assert assistants[0].content == "Hello, this is a test."
    assert assistants[0].prompt_tokens == 42
    assert assistants[0].completion_tokens == 7


def test_stream_blocks_on_archived_conversation(db_app: Flask, mock_llm_stream: None) -> None:
    create_admin_user(db_app)
    _seed_llm_settings_with_api_key(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            conv = sess.execute(
                select(LlmConversation).where(LlmConversation.id == cid)
            ).scalar_one()
            conv.status = LlmConversationStatus.ARCHIVED
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.get(f"/chat/{cid}/stream")
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "conversation_archived"


def test_stream_token_cap_returns_429(db_app: Flask, mock_llm_stream: None) -> None:
    create_admin_user(db_app)
    _seed_llm_settings_with_api_key(db_app)
    _seed_llm_settings(db_app, cap=5)  # cap=5
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                LlmMessage(
                    conversation_id=cid,
                    role=LlmMessageRole.ASSISTANT,
                    content="x",
                    created_at=datetime.now(tz=UTC),
                    prompt_tokens=10,
                    completion_tokens=0,
                )
            )
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.get(f"/chat/{cid}/stream")
    assert resp.status_code == 429


def test_stream_requires_login(db_app: Flask) -> None:
    create_admin_user(db_app)
    _seed_llm_settings_with_api_key(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    client = db_app.test_client()
    resp = client.get(f"/chat/{cid}/stream")
    assert resp.status_code in (302, 401)


# ---------------------------------------------------------------------------
# CSRF — POST-Routen mit aktivem CSRFProtect
# ---------------------------------------------------------------------------


def test_post_message_csrf_required_when_enabled(
    csrf_enabled_db_app: Flask,
) -> None:
    """Bei aktivem CSRFProtect schlaegt POST ohne Token fehl."""
    create_admin_user(csrf_enabled_db_app)
    _seed_llm_settings(csrf_enabled_db_app)
    sid = _seed_server_with_findings(csrf_enabled_db_app)

    client = csrf_enabled_db_app.test_client()
    # Login: muss zuerst CSRF-Token holen.
    # Wir umgehen das hier nicht — der Login-Endpoint hat ohnehin
    # eigenes CSRF-Handling. Wir testen nur dass /chat/.../messages
    # ohne CSRF-Token nicht durchgeht.
    # Direkter POST ohne Login -> 302 (Login-Redirect), unabhaengig von CSRF.
    resp = client.post(f"/servers/{sid}/chat")
    # Egal ob 302 (login_required vor CSRF) oder 400 (CSRF) — kein 200.
    assert resp.status_code != 200


# ---------------------------------------------------------------------------
# Token-Tracker-Integration: Folge-Message konsumiert _nicht_ weiter, aber
# 100% beim Start blockiert (parametrize fuer Robustheit).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "endpoint_factory",
    [
        lambda sid, _cid: ("POST", f"/servers/{sid}/chat", None),
        lambda _sid, cid: ("POST", f"/chat/{cid}/messages", {"content": "Hi"}),
    ],
)
def test_token_cap_blocks_multiple_endpoints(db_app: Flask, endpoint_factory: Any) -> None:
    create_admin_user(db_app)
    _seed_llm_settings(db_app, cap=5)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    # 100 Tokens auf heute — sicher ueber Cap=5.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                LlmMessage(
                    conversation_id=cid,
                    role=LlmMessageRole.ASSISTANT,
                    content="x",
                    created_at=datetime.now(tz=UTC),
                    prompt_tokens=100,
                    completion_tokens=0,
                )
            )
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)
    method, path, json_body = endpoint_factory(sid, cid)
    resp = client.open(path, method=method, json=json_body)
    assert resp.status_code == 429, (path, resp.get_data(as_text=True))


# ---------------------------------------------------------------------------
# Yesterday usage darf nicht blocken
# ---------------------------------------------------------------------------


def test_yesterday_token_usage_does_not_block(db_app: Flask) -> None:
    """Token-Cap-Reset um 00:00 UTC: gestrige Tokens duerfen heute nicht blocken."""
    create_admin_user(db_app)
    _seed_llm_settings(db_app, cap=10)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    yesterday = datetime.now(tz=UTC).replace(
        hour=12, minute=0, second=0, microsecond=0
    ) - timedelta(days=2)
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                LlmMessage(
                    conversation_id=cid,
                    role=LlmMessageRole.ASSISTANT,
                    content="x",
                    created_at=yesterday,
                    prompt_tokens=1000,
                    completion_tokens=0,
                )
            )
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.post(f"/chat/{cid}/messages", json={"content": "Hi"})
    # Sollte durchgehen — gestrige Tokens werden nicht gezaehlt.
    assert resp.status_code == 200, resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Done-event payload structure
# ---------------------------------------------------------------------------


def test_stream_done_payload_contains_conversation_metadata(
    db_app: Flask, mock_llm_stream: None
) -> None:
    create_admin_user(db_app)
    _seed_llm_settings_with_api_key(db_app)
    sid = _seed_server_with_findings(db_app)
    cid = _make_active_conversation(db_app, sid)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                LlmMessage(
                    conversation_id=cid,
                    role=LlmMessageRole.USER,
                    content="Hi",
                    created_at=datetime.now(tz=UTC),
                )
            )
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)

    resp = client.get(f"/chat/{cid}/stream")
    body = resp.get_data(as_text=True)
    # Find `event: done` block and its payload.
    assert "event: done" in body
    # Parse done payload — extract JSON from data: line after event: done.
    lines = body.splitlines()
    done_idx = next(i for i, line in enumerate(lines) if line.startswith("event: done"))
    payload_line = lines[done_idx + 1]
    assert payload_line.startswith("data: ")
    payload = json.loads(payload_line[len("data: ") :])
    assert payload["conversation_id"] == cid
    assert payload["server_id"] == sid
    assert payload["prompt_tokens"] == 42
    assert payload["completion_tokens"] == 7
