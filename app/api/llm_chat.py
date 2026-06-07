"""LLM-Chat-API: Conversation-Start, Streaming, Folge-Messages, Archive.

Routen (Browser-facing, Login-Pflicht, CSRF auf POST):

- `POST /servers/<server_id>/chat`
    Startet eine neue Conversation oder springt zur aktiven. Snapshot der
    OPEN-Findings in `llm_conversation_findings`. Audit `llm.queried`.
    Token-Tracker-Check (429 bei `blocked`). Antwort: JSON
    `{conversation_id, stream_url}`.

- `GET /chat/<conversation_id>/stream`
    Server-Sent-Events (`text/event-stream`). Stream nimmt den
    *letzten* User-Turn aus `llm_messages`, schickt die kumulierte
    Historie an den LLM-Provider und sendet Token-Deltas als
    `data: <delta>\\n\\n`-Events. Bei Stream-Ende: `event: done` mit
    `data: {prompt_tokens, completion_tokens}` JSON.

- `POST /chat/<conversation_id>/messages`
    Haengt eine neue User-Message an. JSON-Body `{content}`. Token-Cap
    erneut pruefen. Antwort: `{message_id, stream_url}`.

- `POST /chat/<conversation_id>/archive`
    Conversation auf `archived` setzen. Audit `llm.conversation_archived`.

Anti-Patterns vermieden:
- KEIN Pflicht-Kommentar (ADR-0006).
- KEIN Function-Calling/Tools (ADR-0002).
- KEINE Modellwahl pro Conversation (nur `Setting.llm_model`).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any, cast

import structlog
from flask import (
    Blueprint,
    Response,
    abort,
    jsonify,
    request,
    stream_with_context,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import select

from app import csrf, limiter
from app.audit import log_event
from app.config import Settings
from app.db import get_session
from app.models import (
    Finding,
    FindingStatus,
    LlmConversation,
    LlmConversationFinding,
    LlmConversationStatus,
    LlmMessage,
    LlmMessageRole,
    Server,
    ServerTag,
)
from app.services.llm_client import (
    LlmNotConfiguredError,
    build_client_from_settings,
)
from app.services.llm_prompt import (
    build_system_prompt,
    build_user_prompt_intro,
)
from app.services.llm_token_tracker import get_today_usage
from app.settings_service import get_settings_row

log = structlog.get_logger(__name__)

llm_chat_bp = Blueprint("llm_chat", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_error(status: int, code: str, message: str, **extra: Any) -> tuple[Response, int]:
    body: dict[str, Any] = {"error": code, "message": message}
    body.update(extra)
    resp: Response = jsonify(body)
    return resp, status


def _load_server(server_id: int) -> Server:
    sess = get_session()
    server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one_or_none()
    if server is None:
        abort(404)
    return server


def _load_conversation(conv_id: int) -> LlmConversation:
    sess = get_session()
    conv = sess.execute(
        select(LlmConversation).where(LlmConversation.id == conv_id)
    ).scalar_one_or_none()
    if conv is None:
        abort(404)
    return conv


def _server_tags(server_id: int) -> list[Any]:
    """Lade die Tag-Objekte fuer einen Server (fuer den Prompt-Builder)."""
    sess = get_session()
    rows = sess.execute(select(ServerTag).where(ServerTag.server_id == server_id)).scalars().all()
    return [link.tag for link in rows if link.tag is not None]


def _open_findings(server_id: int) -> list[Finding]:
    sess = get_session()
    return list(
        sess.execute(
            select(Finding).where(
                Finding.server_id == server_id,
                Finding.status == FindingStatus.OPEN,
            )
        )
        .scalars()
        .all()
    )


def _active_conversation_for(server_id: int) -> LlmConversation | None:
    sess = get_session()
    return (
        sess.execute(
            select(LlmConversation)
            .where(
                LlmConversation.server_id == server_id,
                LlmConversation.status == LlmConversationStatus.ACTIVE,
            )
            .order_by(LlmConversation.started_at.desc())
        )
        .scalars()
        .first()
    )


def _check_token_cap() -> tuple[Response, int] | None:
    """Liefert 429 wenn Cap ueberschritten, sonst None."""
    sess = get_session()
    usage = get_today_usage(sess)
    if usage.blocked:
        return _json_error(
            429,
            "token_cap_exceeded",
            "Daily token cap reached. Reset at 00:00 UTC.",
            reset_at=usage.reset_at.isoformat(),
            used=usage.used,
            cap=usage.cap,
        )
    return None


# ---------------------------------------------------------------------------
# POST /servers/<id>/chat — Conversation starten / springen
# ---------------------------------------------------------------------------


@llm_chat_bp.post("/servers/<int:server_id>/chat")
@login_required
@limiter.limit("30/minute")
def start_conversation(server_id: int) -> Any:
    """Startet (oder findet) eine aktive Conversation fuer den Server."""
    cap_resp = _check_token_cap()
    if cap_resp is not None:
        return cap_resp

    server = _load_server(server_id)
    sess = get_session()
    settings_row = get_settings_row(sess)

    if not settings_row.llm_base_url or not settings_row.llm_model:
        return _json_error(
            400,
            "llm_not_configured",
            "LLM provider is not configured yet. See /settings/llm.",
        )

    existing = _active_conversation_for(server_id)
    if existing is not None:
        return jsonify(
            {
                "conversation_id": existing.id,
                "stream_url": url_for("llm_chat.stream", conversation_id=existing.id),
                "resumed": True,
            }
        )

    findings = _open_findings(server_id)
    tags = _server_tags(server_id)
    now = datetime.now(tz=UTC)

    conv = LlmConversation(
        server_id=server_id,
        started_at=now,
        last_message_at=now,
        model=settings_row.llm_model,
        status=LlmConversationStatus.ACTIVE,
        findings_snapshot_at=now,
    )
    sess.add(conv)
    sess.flush()

    # Snapshot der OPEN-Findings inkl. Trivy-Metriken zum Zeitpunkt.
    for f in findings:
        sess.add(
            LlmConversationFinding(
                conversation_id=conv.id,
                finding_id=f.id,
                severity_at_send=f.severity,
                cvss_v3_score_at_send=f.cvss_v3_score,
                epss_score_at_send=f.epss_score,
                is_kev_at_send=f.is_kev,
            )
        )

    # System-Prompt und User-Intro persistieren.
    system_prompt = build_system_prompt(server, findings, tags)
    user_intro = build_user_prompt_intro(server)

    sess.add(
        LlmMessage(
            conversation_id=conv.id,
            role=LlmMessageRole.SYSTEM,
            content=system_prompt,
            created_at=now,
        )
    )
    sess.add(
        LlmMessage(
            conversation_id=conv.id,
            role=LlmMessageRole.USER,
            content=user_intro,
            created_at=now,
        )
    )

    log_event(
        "llm.queried",
        target_type="llm_conversation",
        target_id=conv.id,
        metadata={
            "server_id": server_id,
            "model": settings_row.llm_model,
            "findings_count": len(findings),
        },
        session=sess,
    )
    sess.commit()

    return jsonify(
        {
            "conversation_id": conv.id,
            "stream_url": url_for("llm_chat.stream", conversation_id=conv.id),
            "resumed": False,
        }
    )


# ---------------------------------------------------------------------------
# POST /chat/<id>/messages — Folge-User-Nachricht
# ---------------------------------------------------------------------------


@llm_chat_bp.post("/chat/<int:conversation_id>/messages")
@login_required
@limiter.limit("30/minute")
def post_message(conversation_id: int) -> Any:
    cap_resp = _check_token_cap()
    if cap_resp is not None:
        return cap_resp

    conv = _load_conversation(conversation_id)
    if conv.status != LlmConversationStatus.ACTIVE:
        return _json_error(409, "conversation_archived", "Conversation is archived.")

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _json_error(400, "invalid_body", "JSON object expected")
    content = body.get("content")
    if not isinstance(content, str) or not content.strip():
        return _json_error(400, "invalid_content", "Field 'content' required")
    # Hartes Cap pro User-Turn — 8 KB wie Notes (siehe forms.NOTE_TEXT_MAX_LEN).
    content = content.strip()
    if len(content) > 8 * 1024:
        return _json_error(400, "content_too_long", "User message > 8 KB")

    sess = get_session()
    now = datetime.now(tz=UTC)
    msg = LlmMessage(
        conversation_id=conv.id,
        role=LlmMessageRole.USER,
        content=content,
        created_at=now,
    )
    sess.add(msg)
    conv.last_message_at = now
    sess.flush()

    log_event(
        "llm.queried",
        target_type="llm_conversation",
        target_id=conv.id,
        metadata={"server_id": conv.server_id, "model": conv.model, "turn": "followup"},
        session=sess,
    )
    sess.commit()

    return jsonify(
        {
            "message_id": msg.id,
            "stream_url": url_for("llm_chat.stream", conversation_id=conv.id),
        }
    )


# ---------------------------------------------------------------------------
# GET /chat/<id>/stream — SSE-Stream
# ---------------------------------------------------------------------------


def _collect_history(conv: LlmConversation) -> list[dict[str, str]]:
    """Sammelt alle Messages der Conversation (chronologisch) fuer den Provider."""
    sess = get_session()
    rows = list(
        sess.execute(
            select(LlmMessage)
            .where(LlmMessage.conversation_id == conv.id)
            .order_by(LlmMessage.created_at.asc(), LlmMessage.id.asc())
        )
        .scalars()
        .all()
    )
    return [{"role": m.role.value, "content": m.content} for m in rows]


async def _run_stream(
    history: list[dict[str, str]],
    settings_row: Any,
    encryption_key: str,
) -> Any:
    """Async-Generator-Helfer fuer den Stream — separat zum Type-Check."""
    client = build_client_from_settings(settings_row, encryption_key=encryption_key)
    try:
        async for delta in client.stream_chat(history):
            yield ("delta", delta)
        yield (
            "usage",
            {
                "prompt_tokens": client.last_usage.prompt_tokens,
                "completion_tokens": client.last_usage.completion_tokens,
            },
        )
    finally:
        await client.aclose()


def _sse_payload(event: str, data: str) -> bytes:
    """SSE-Frame: optional `event:`-Zeile + `data:`-Zeile + Leerzeile."""
    out = ""
    if event != "message":
        out += f"event: {event}\n"
    # `data:` darf keine eingebetteten Newlines haben — wir teilen auf.
    for line in data.splitlines() or [""]:
        out += f"data: {line}\n"
    out += "\n"
    return out.encode("utf-8")


@llm_chat_bp.get("/chat/<int:conversation_id>/stream")
@login_required
@limiter.limit("60/hour")
def stream(conversation_id: int) -> Response:
    """SSE-Endpoint — Token-Deltas vom LLM-Provider."""
    cap_check = _check_token_cap()
    if cap_check is not None:
        resp, status = cap_check
        resp.status_code = status
        return resp

    conv = _load_conversation(conversation_id)
    if conv.status != LlmConversationStatus.ACTIVE:
        resp_err: Response = jsonify({"error": "conversation_archived"})
        resp_err.status_code = 409
        return resp_err

    history = _collect_history(conv)
    sess = get_session()
    settings_row = get_settings_row(sess)
    if not settings_row.llm_base_url or not settings_row.llm_model:
        resp_err = jsonify({"error": "llm_not_configured"})
        resp_err.status_code = 400
        return resp_err

    from flask import current_app

    app_settings = cast(Settings, current_app.config["FM_SETTINGS"])
    encryption_key = app_settings.encryption_key.get_secret_value()

    conv_id = conv.id
    server_id = conv.server_id
    conv_model = conv.model

    def _generate() -> Any:
        """Sync-Wrapper um den async Generator. Sammelt das Assistant-Reply
        und persistiert es am Ende als `assistant`-Message inkl. Usage."""
        loop = asyncio.new_event_loop()
        assistant_chunks: list[str] = []
        prompt_tokens: int | None = None
        completion_tokens: int | None = None
        try:
            agen = _run_stream(history, settings_row, encryption_key).__aiter__()
            while True:
                try:
                    kind, payload = loop.run_until_complete(agen.__anext__())
                except StopAsyncIteration:
                    break
                if kind == "delta":
                    delta_str = cast(str, payload)
                    assistant_chunks.append(delta_str)
                    yield _sse_payload("message", delta_str)
                elif kind == "usage":
                    usage_obj = cast(dict[str, int | None], payload)
                    prompt_tokens = usage_obj.get("prompt_tokens")
                    completion_tokens = usage_obj.get("completion_tokens")
        except LlmNotConfiguredError:
            yield _sse_payload("error", json.dumps({"error": "llm_not_configured"}))
        except Exception as exc:  # pragma: no cover — Provider-Fehler werden geloggt
            log.warning("llm_chat.stream_failed", error=type(exc).__name__)
            yield _sse_payload("error", json.dumps({"error": "provider_error"}))
        finally:
            import contextlib

            with contextlib.suppress(Exception):  # pragma: no cover
                loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

        # Persistenz: Assistant-Message + Usage-Counts (eigene Session,
        # weil Flask die Request-Session bereits geschlossen hat sobald
        # der Generator schwebt). Wir nutzen die App-Engine direkt.
        from sqlalchemy.orm import Session as SAOrmSession

        from app.db import get_engine

        engine = get_engine(current_app._get_current_object())  # type: ignore[attr-defined]
        with SAOrmSession(bind=engine, expire_on_commit=False) as worker_sess:
            assistant_text = "".join(assistant_chunks)
            now = datetime.now(tz=UTC)
            worker_sess.add(
                LlmMessage(
                    conversation_id=conv_id,
                    role=LlmMessageRole.ASSISTANT,
                    content=assistant_text,
                    created_at=now,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                )
            )
            conv_row = worker_sess.execute(
                select(LlmConversation).where(LlmConversation.id == conv_id)
            ).scalar_one()
            conv_row.last_message_at = now
            worker_sess.commit()

        done_payload = json.dumps(
            {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "conversation_id": conv_id,
                "server_id": server_id,
                "model": conv_model,
            }
        )
        yield _sse_payload("done", done_payload)

    resp = Response(stream_with_context(_generate()), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"  # Falls hinter nginx
    return resp


# ---------------------------------------------------------------------------
# POST /chat/<id>/archive
# ---------------------------------------------------------------------------


@llm_chat_bp.get("/chat/<int:conversation_id>")
@login_required
def show_conversation(conversation_id: int) -> Any:
    """Browser-View fuer eine Conversation (Chat-UI)."""
    from flask import render_template

    conv = _load_conversation(conversation_id)
    server = _load_server(conv.server_id)
    sess = get_session()
    messages = list(
        sess.execute(
            select(LlmMessage)
            .where(LlmMessage.conversation_id == conv.id)
            .order_by(LlmMessage.created_at.asc(), LlmMessage.id.asc())
        )
        .scalars()
        .all()
    )
    token_usage = get_today_usage(sess)
    return render_template(
        "chat/conversation.html",
        server=server,
        conversation=conv,
        messages=messages,
        token_usage=token_usage,
        stream_url=url_for("llm_chat.stream", conversation_id=conv.id),
        post_message_url=url_for("llm_chat.post_message", conversation_id=conv.id),
        archive_url=url_for("llm_chat.archive_conversation", conversation_id=conv.id),
    )


@llm_chat_bp.post("/chat/<int:conversation_id>/archive")
@login_required
def archive_conversation(conversation_id: int) -> Any:
    conv = _load_conversation(conversation_id)
    if conv.status == LlmConversationStatus.ARCHIVED:
        return jsonify({"conversation_id": conv.id, "status": "archived"})
    sess = get_session()
    conv.status = LlmConversationStatus.ARCHIVED
    log_event(
        "llm.conversation_archived",
        target_type="llm_conversation",
        target_id=conv.id,
        metadata={"server_id": conv.server_id, "actor": getattr(current_user, "username", None)},
        session=sess,
    )
    sess.commit()
    return jsonify({"conversation_id": conv.id, "status": "archived"})


# CSRF-Exempt nur fuer den GET-SSE-Stream (kein POST — CSRFProtect rueht GETs
# ohnehin nicht an). Die POST-Routen werden vom globalen CSRFProtect gedeckt.
csrf.exempt(stream)


__all__ = ["llm_chat_bp"]
