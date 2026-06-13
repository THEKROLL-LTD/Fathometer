# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Per-Group-LLM-Chat-Blueprint (ADR-0055, Block AE).

Fokussierter LLM-Chat pro ``(Server, Application-Group)``. Einstieg
ausschliesslich ueber den "Help"-Button pro Group-Row in den
Operator-Workflows (ADR-0055 Entscheidung). Es gibt **keinen** server-weiten
Chat mehr (ADR-0050 bleibt verworfen).

Vier Browser-facing Routen (Login-Pflicht, CSRF auf POST, ``flask-limiter``):

- ``GET  /servers/<sid>/groups/<gid>/chat``
    Rendert die Chat-Sub-View (``#detail-pane-content``-Swap bei HX-Request,
    Vollseite sonst). Zeigt die bestehende Konversation (Messages
    ``role != system``) oder einen Empty-State mit ``CHAT_SUGGESTIONS``-Chips.
    **Legt nichts an.**

- ``POST /servers/<sid>/groups/<gid>/chat/messages``
    Haengt eine User-Message an. Existiert keine Konversation -> Lazy-Create:
    Host-Snapshot + Group-Findings + Worst/Reason/Lane laden, System-Prompt
    via :func:`build_group_system_prompt` bauen und mit System- + User-Message
    persistieren (``findings_snapshot_at=now``, ``model=Setting.llm_chat_model``).
    Existiert sie -> nur User-Message anhaengen (KEIN neuer Snapshot). Antwort:
    User-Bubble-Partial + ``stream_url``. ``400 llm_not_configured`` wenn der
    Provider fehlt.

- ``GET  /servers/<sid>/groups/<gid>/chat/stream``
    Server-Sent-Events (``text/event-stream``). Kumulierte Historie an den
    Provider, Token-Deltas als ``data:``-Frames, ``event: done`` am Ende.
    Assistant-Message + Usage werden nach Stream-Ende in einer **frischen**
    DB-Session persistiert (Muster aus dem entfernten ``llm_chat.stream``).
    **KEIN** ``llm_budget``-Aufruf (ADR-0055 Entscheidung 4).

- ``POST /servers/<sid>/groups/<gid>/chat/new``
    Loescht die Konversation unwiderruflich (CASCADE auf die Messages).
    Antwort: Empty-State-Partial.

Gemeinsamer 404-Guard (alle Routen): der Server existiert + ist aktiv (nicht
revoked/retired) **und** die Group hat OPEN-Findings auf genau diesem Server —
exakt die ``group_findings_fragment``-Semantik. Deckt Cross-Server- und
Cross-Group-IDOR ab.

Anti-Patterns vermieden:
- KEIN Function-Calling/Tools (ADR-0002).
- KEINE Modellwahl pro Konversation (nur ``Setting.llm_chat_model``).
- KEIN ``llm_budget``-Aufruf (ADR-0055 Entscheidung 4).
- Niemals API-Key in Logs/SSE-Fehlerframes (generischer ``event: error``).

Template-Variablen-Vertrag (fuer frontend-implementer, Phase 4) siehe
:func:`_render_chat_view` und :func:`_user_bubble_partial`.
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
    current_app,
    jsonify,
    render_template,
    request,
    stream_with_context,
    url_for,
)
from flask_login import login_required
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as SAOrmSession
from sqlalchemy.orm import selectinload

from app import limiter
from app.config import Settings
from app.db import get_engine, get_session
from app.forms import CSRFOnlyForm
from app.models import (
    ChatMessageRole,
    Finding,
    FindingStatus,
    GroupChatConversation,
    GroupChatMessage,
    Server,
    ServerTag,
)
from app.services.group_chat_prompt import (
    CHAT_SUGGESTIONS,
    GROUP_CHAT_FINDINGS_BUDGET,
    FindingsAggregate,
    build_group_system_prompt,
)
from app.services.llm_client import (
    LlmNotConfiguredError,
    build_client_from_settings,
)
from app.services.pass2_input_selection import SelectionResult, select_pass2_findings
from app.settings_service import get_settings_row
from app.views.server_detail import (
    _load_application_groups_for_server,
    _load_host_snapshot,
)

log = structlog.get_logger(__name__)

group_chat_bp = Blueprint(
    "group_chat",
    __name__,
    url_prefix="/servers/<int:sid>/groups/<int:gid>/chat",
)

# Hartes Cap pro User-Turn — 8 KB analog Notes (siehe alter llm_chat.post_message).
_USER_MSG_MAX = 8 * 1024


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_error(status: int, code: str, message: str, **extra: Any) -> tuple[Response, int]:
    body: dict[str, Any] = {"error": code, "message": message}
    body.update(extra)
    resp: Response = jsonify(body)
    return resp, status


def _load_active_server_with_tags(sid: int) -> Server:
    """Lade den Server inkl. eager-geladener Tags oder 404.

    Tags werden eager geladen, weil :func:`build_group_system_prompt` sie
    ueber ``server.tag_links`` liest (der Builder macht keine DB-Queries).
    Revoked/retired Server liefern 404 — der Chat ist nur fuer aktive Hosts.
    """
    sess = get_session()
    server = sess.execute(
        select(Server)
        .options(selectinload(Server.tag_links).selectinload(ServerTag.tag))
        .where(Server.id == sid)
    ).scalar_one_or_none()
    if server is None:
        abort(404)
    if server.revoked_at is not None or server.retired_at is not None:
        abort(404)
    return server


def _group_open_findings(sid: int, gid: int) -> list[Finding]:
    """OPEN-Findings der Group auf genau diesem Server (volle ORM-Objekte).

    Exakt die ``group_findings_fragment``-Semantik: ``server_id == sid AND
    application_group_id == gid AND status == OPEN``. Leeres Ergebnis -> die
    Group existiert auf diesem Server nicht (oder hat keine offenen Findings)
    -> der Aufrufer liefert 404 (Cross-Server/Cross-Group-IDOR-Schutz).
    """
    sess = get_session()
    return list(
        sess.execute(
            select(Finding).where(
                Finding.server_id == sid,
                Finding.application_group_id == gid,
                Finding.status == FindingStatus.OPEN,
            )
        )
        .scalars()
        .all()
    )


def _guard_or_404(sid: int, gid: int) -> tuple[Server, list[Finding]]:
    """Gemeinsamer 404-Guard: aktiver Server + Group mit OPEN-Findings hier.

    Liefert das geladene Server-Objekt und die OPEN-Findings der Group zurueck,
    damit der Aufrufer sie ohne zweite Query weiterverwenden kann.
    """
    server = _load_active_server_with_tags(sid)
    findings = _group_open_findings(sid, gid)
    if not findings:
        abort(404)
    return server, findings


def _conversation_for(sid: int, gid: int) -> GroupChatConversation | None:
    """Die (hoechstens eine) Konversation fuer ``(server, group)`` oder None."""
    sess = get_session()
    return sess.execute(
        select(GroupChatConversation).where(
            GroupChatConversation.server_id == sid,
            GroupChatConversation.application_group_id == gid,
        )
    ).scalar_one_or_none()


def _visible_messages(conv: GroupChatConversation | None) -> list[GroupChatMessage]:
    """Messages der Konversation fuer die Anzeige (chronologisch, ohne System).

    Die System-Message traegt den eingefrorenen Snapshot-Prompt — sie wird dem
    Operator nicht angezeigt, nur user/assistant.
    """
    if conv is None:
        return []
    sess = get_session()
    rows = list(
        sess.execute(
            select(GroupChatMessage)
            .where(GroupChatMessage.conversation_id == conv.id)
            .order_by(GroupChatMessage.created_at.asc(), GroupChatMessage.id.asc())
        )
        .scalars()
        .all()
    )
    return [m for m in rows if m.role != ChatMessageRole.SYSTEM]


def _group_context(sid: int, gid: int) -> dict[str, Any]:
    """Worst-Finding + Reason + Lane + group_label fuer eine konkrete Group.

    Reuse von :func:`_load_application_groups_for_server`: aus dem Lane-Kontrakt
    der Ziel-Group wird die Lane mit der hoechsten Urgency (erste Lane nach der
    eingebauten Sortierung; ``lanes`` ist patch-zuerst, aber die Eval-Bands
    sind nicht garantiert sortiert) gewaehlt. Wir nehmen die Lane mit Eval-Row
    falls vorhanden, sonst die erste Lane. Worst-Finding/Reason kommen aus
    dieser Lane.

    Rueckgabe-Keys: ``group_label`` (str), ``lane`` (str | None),
    ``worst_finding`` (Row | None), ``reason`` (str | None).
    """
    sess = get_session()
    groups = _load_application_groups_for_server(sess, sid)
    target = next((g for g in groups if int(g["group"].id) == gid), None)
    if target is None:
        # Defensive: der 404-Guard hat OPEN-Findings garantiert, aber falls die
        # Group-Metadaten fehlen, liefern wir einen leeren Kontext.
        return {"group_label": str(gid), "lane": None, "worst_finding": None, "reason": None}
    grp = target["group"]
    label = getattr(grp, "label", None) or str(gid)
    lanes = target["lanes"]
    chosen = next((ln for ln in lanes if ln.get("evaluation") is not None), None)
    if chosen is None and lanes:
        chosen = lanes[0]
    lane_name: str | None = None
    worst: Any = None
    reason: str | None = None
    if chosen is not None:
        lane_name = chosen.get("fix_lane")
        worst = chosen.get("worst_finding")
        ev = chosen.get("evaluation")
        reason = getattr(ev, "risk_band_reason", None) if ev is not None else None
    return {
        "group_label": str(label),
        "lane": lane_name,
        "worst_finding": worst,
        "reason": reason,
    }


def _provider_configured() -> bool:
    """True wenn ``llm_base_url`` UND ``llm_chat_model`` gesetzt sind.

    Der Modell-Teil ist durch den ``server_default`` von ``llm_chat_model``
    faktisch immer truthy — das eigentliche „nicht konfiguriert" ist die
    fehlende ``llm_base_url`` (der geteilte Provider-Gate).
    """
    sess = get_session()
    row = get_settings_row(sess)
    return bool(row.llm_base_url and row.llm_chat_model)


def _select_for_chat(findings: list[Finding]) -> SelectionResult:
    """Deterministische Findings-Selektion fuer den Chat-Snapshot (ADR-0058).

    Wiederverwendet die getestete Pass-2-Heuristik (alle KEV/CRITICAL als
    Pflicht-Slots, dann EPSS-/Pfad-Quote, Rest als Aggregat), aber mit dem
    kleineren Chat-Budget ``GROUP_CHAT_FINDINGS_BUDGET`` — der Snapshot wird pro
    Turn erneut gesendet, ein 745-Findings-Dump ist nicht tragbar.
    """
    return select_pass2_findings(findings, budget=GROUP_CHAT_FINDINGS_BUDGET)


def _aggregate_from_selection(selection: SelectionResult) -> FindingsAggregate | None:
    """``FindingsAggregate`` aus dem ``SelectionResult`` (oder ``None``).

    ``None`` wenn nichts gekuerzt wurde (``rest_count == 0``) — dann braucht der
    Prompt keine Aggregat-Zeile und das UI keinen Hinweis.
    """
    if selection.rest_count <= 0:
        return None
    return FindingsAggregate(
        rest_count=selection.rest_count,
        severity_counts=selection.rest_severity_counts,
        max_epss=selection.rest_max_epss,
        fixable_count=selection.rest_fixable_count,
        kev_count=selection.rest_kev_count,
    )


def _chat_findings_context(findings: list[Finding]) -> dict[str, Any]:
    """Banner-Kontext fuer das Template (ADR-0058).

    ``findings_total``/``findings_shown``/``findings_truncated`` beschreiben die
    aktuelle Selektion. Bewusst eine **Live-Preview** der aktuellen OPEN-
    Findings — der eingefrorene Snapshot kann nach einem Re-Scan leicht
    abweichen (gleiche Staleness-Doktrin wie ADR-0055).
    """
    selection = _select_for_chat(findings)
    shown = len(selection.selected)
    return {
        "findings_total": shown + selection.rest_count,
        "findings_shown": shown,
        "findings_truncated": selection.rest_count > 0,
    }


def _render_chat_view(
    server: Server,
    sid: int,
    gid: int,
    conv: GroupChatConversation | None,
    findings: list[Finding],
) -> str:
    """Rendert die Chat-Sub-View (HX-Fragment oder Vollseite).

    Template-Variablen-Vertrag fuer ``servers/group_chat.html`` (Phase 4):

      - ``server``: Server-ORM (mit eager-geladenen Tags).
      - ``sid`` / ``gid``: ints fuer url_for in den Endpoints.
      - ``group_label``: str — Anzeigelabel der Group.
      - ``lane``: str | None — Fix-Lane der gewaehlten Lane (``patch``/``mitigate``).
      - ``worst_finding``: Projektions-Row | None (``.identifier_key``/``.title``).
      - ``reason``: str | None — Scanner/Risk-Reviewer-Reason.
      - ``messages``: list[GroupChatMessage] — bestehende user/assistant-Bubbles
        (chronologisch, ``role != system``); leer -> Empty-State rendern.
      - ``suggestions``: list[ChatSuggestion] — ``CHAT_SUGGESTIONS`` (Empty-State-
        Chips; ``.label`` sichtbar, ``.prompt`` via ``data-prompt`` ans LLM).
      - ``conversation``: GroupChatConversation | None.
      - ``csrf_form``: CSRFOnlyForm — CSRF-Token fuer die POST-Forms.
      - ``hx_partial``: bool — HX-Request -> Detail-Pane-Fragment.
      - ``findings_total`` / ``findings_shown`` / ``findings_truncated``
        (ADR-0058): Banner-Kontext fuer den gelben „nur die X wichtigsten von N
        Findings"-Hinweis; ``findings_truncated`` gated den Hinweis.
      - URL-Endpoints (url_for): ``group_chat.post_message``,
        ``group_chat.stream``, ``group_chat.new_chat`` (je mit ``sid``/``gid``),
        ``server_detail.show`` (Back-Link).
    """
    ctx = _group_context(sid, gid)
    hx_request = request.headers.get("HX-Request") == "true"
    findings_ctx = _chat_findings_context(findings)
    return render_template(
        "servers/group_chat.html",
        server=server,
        sid=sid,
        gid=gid,
        group_label=ctx["group_label"],
        lane=ctx["lane"],
        worst_finding=ctx["worst_finding"],
        reason=ctx["reason"],
        messages=_visible_messages(conv),
        suggestions=CHAT_SUGGESTIONS,
        conversation=conv,
        csrf_form=CSRFOnlyForm(),
        hx_partial=hx_request,
        **findings_ctx,
    )


def _user_bubble_partial(message: GroupChatMessage, sid: int, gid: int) -> str:
    """Rendert eine einzelne User-Bubble + ``stream_url`` (POST-Response).

    Single-Source-Bubble-Partial ``servers/_partials/group_chat_message.html``
    (Phase 4) — dasselbe Markup wie der Initial-Render (``group_chat.html``
    inkludiert exakt diesen Pfad). Variablen-Vertrag:

      - ``message``: GroupChatMessage (``.role``/``.content``).
      - ``stream_url``: str — EventSource-Ziel fuer die Assistant-Antwort.
    """
    return render_template(
        "servers/_partials/group_chat_message.html",
        message=message,
        stream_url=url_for("group_chat.stream", sid=sid, gid=gid),
    )


# ---------------------------------------------------------------------------
# GET /chat — Sub-View (rendert, legt nichts an)
# ---------------------------------------------------------------------------


@group_chat_bp.get("")
@login_required
@limiter.limit("120/minute")
def show(sid: int, gid: int) -> str:
    """GET /servers/<sid>/groups/<gid>/chat — rendert die Chat-Sub-View."""
    server, findings = _guard_or_404(sid, gid)
    conv = _conversation_for(sid, gid)
    return _render_chat_view(server, sid, gid, conv, findings)


# ---------------------------------------------------------------------------
# POST /chat/messages — User-Message anhaengen (+ Lazy-Create)
# ---------------------------------------------------------------------------


def _upstream_verdict_for_snapshot(sess: Any, sid: int, gid: int, settings_row: Any) -> Any | None:
    """Das (gecachte) Upstream-Check-Verdikt fuer den Chat-Snapshot (ADR-0063
    §Integration).

    Reuse des AI-2-State-Lookups (server-seitige Worst-Upstream-Finding-
    Ableitung → Seed → Cache-Zeile). Nur **abgeschlossene** Verdikte
    (``status == 'done'``, egal ob TTL-frisch) gehen in den Snapshot;
    ``queued``/``running``/``error``/idle → ``None`` (kein Block). Beratend und
    friert mit dem Snapshot ein (ADR-0055-Semantik: ein spaeterer Re-Check
    aendert eine laufende Konversation nicht — „New Chat" zieht den frischen
    Stand). Lokaler Import haelt den Modul-Import-Graphen schlank.
    """
    from app.services.upstream_check_state import STATE_DONE, lookup_state_for_group
    from app.services.upstream_research import is_upstream_check_configured

    if not is_upstream_check_configured(settings_row):
        return None
    state = lookup_state_for_group(sess, sid, gid, configured=True)
    row = state.row
    if row is not None and getattr(row, "status", None) == STATE_DONE:
        return row
    return None


@group_chat_bp.post("/messages")
@login_required
@limiter.limit("30/minute")
def post_message(sid: int, gid: int) -> Any:
    """POST /messages — User-Message anhaengen; ggf. Konversation lazy anlegen."""
    server, findings = _guard_or_404(sid, gid)

    if not _provider_configured():
        return _json_error(
            400,
            "llm_not_configured",
            "LLM provider is not configured yet. See /settings/llm.",
        )

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _json_error(400, "invalid_body", "JSON object expected")
    content = body.get("content")
    if not isinstance(content, str) or not content.strip():
        return _json_error(400, "invalid_content", "Field 'content' required")
    content = content.strip()
    if len(content) > _USER_MSG_MAX:
        return _json_error(400, "content_too_long", "User message > 8 KB")

    sess = get_session()
    settings_row = get_settings_row(sess)
    now = datetime.now(tz=UTC)
    conv = _conversation_for(sid, gid)

    if conv is None:
        # Lazy-Create + Snapshot: System-Prompt einfrieren (ADR-0055 §3).
        # Findings-Budget (ADR-0058): nur die wichtigsten an das LLM, Rest als
        # Aggregat — der Snapshot wird pro Turn re-gesendet.
        ctx = _group_context(sid, gid)
        selection = _select_for_chat(findings)
        system_prompt = build_group_system_prompt(
            server=server,
            group_label=ctx["group_label"],
            lane=ctx["lane"],
            worst_finding=ctx["worst_finding"],
            reason=ctx["reason"],
            host_snapshot=_load_host_snapshot(sess, sid),
            group_findings=list(selection.selected),
            findings_aggregate=_aggregate_from_selection(selection),
            upstream_verdict=_upstream_verdict_for_snapshot(sess, sid, gid, settings_row),
        )
        conv = GroupChatConversation(
            server_id=sid,
            application_group_id=gid,
            model=settings_row.llm_chat_model,
            created_at=now,
            last_message_at=now,
            findings_snapshot_at=now,
        )
        sess.add(conv)
        sess.flush()
        sess.add(
            GroupChatMessage(
                conversation_id=conv.id,
                role=ChatMessageRole.SYSTEM,
                content=system_prompt,
                created_at=now,
            )
        )

    # User-Message anhaengen (Create- und Resume-Pfad). KEIN neuer Snapshot bei
    # Resume — der eingefrorene System-Prompt bleibt unveraendert.
    user_msg = GroupChatMessage(
        conversation_id=conv.id,
        role=ChatMessageRole.USER,
        content=content,
        created_at=now,
    )
    sess.add(user_msg)
    conv.last_message_at = now
    sess.flush()
    sess.commit()

    bubble_html = _user_bubble_partial(user_msg, sid, gid)
    resp: Response = jsonify(
        {
            "message_id": user_msg.id,
            "stream_url": url_for("group_chat.stream", sid=sid, gid=gid),
            "bubble_html": bubble_html,
        }
    )
    return resp


# ---------------------------------------------------------------------------
# GET /chat/stream — SSE
# ---------------------------------------------------------------------------


def _collect_history(conv_id: int) -> list[dict[str, str]]:
    """Kumulierte Historie (system + user + assistant, chronologisch)."""
    sess = get_session()
    rows = list(
        sess.execute(
            select(GroupChatMessage)
            .where(GroupChatMessage.conversation_id == conv_id)
            .order_by(GroupChatMessage.created_at.asc(), GroupChatMessage.id.asc())
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
    """Async-Generator-Helfer: Deltas + finaler Usage-Block."""
    client = build_client_from_settings(
        settings_row,
        encryption_key=encryption_key,
        model_override=settings_row.llm_chat_model,
    )
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
    """SSE-Frame: optional ``event:``-Zeile + ``data:``-Zeilen + Leerzeile.

    ``data:`` darf keine eingebetteten Newlines tragen — wir splitten auf
    mehrere ``data:``-Zeilen (SSE-Spec).
    """
    out = ""
    if event != "message":
        out += f"event: {event}\n"
    for line in data.splitlines() or [""]:
        out += f"data: {line}\n"
    out += "\n"
    return out.encode("utf-8")


def _persist_assistant(
    conv_id: int,
    chunks: list[str],
    prompt_tokens: int | None,
    completion_tokens: int | None,
) -> None:
    """Persistiert die Assistant-Message + Usage in einer **frischen** Session.

    Wird nach Stream-Ende aufgerufen, wenn Flask die Request-Session bereits
    geschlossen hat (der Generator schwebt ueber das Request-Ende hinaus). Wir
    binden direkt an die App-Engine.
    """
    engine = get_engine(current_app._get_current_object())  # type: ignore[attr-defined]
    with SAOrmSession(bind=engine, expire_on_commit=False) as worker_sess:
        now = datetime.now(tz=UTC)
        worker_sess.add(
            GroupChatMessage(
                conversation_id=conv_id,
                role=ChatMessageRole.ASSISTANT,
                content="".join(chunks),
                created_at=now,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )
        )
        conv_row = worker_sess.execute(
            select(GroupChatConversation).where(GroupChatConversation.id == conv_id)
        ).scalar_one_or_none()
        if conv_row is not None:
            conv_row.last_message_at = now
        worker_sess.commit()


@group_chat_bp.get("/stream")
@login_required
@limiter.limit("60/hour")
def stream(sid: int, gid: int) -> Response:
    """SSE-Endpoint — Token-Deltas vom LLM-Provider (kein Token-Cap)."""
    _server, _findings = _guard_or_404(sid, gid)
    conv = _conversation_for(sid, gid)
    if conv is None:
        resp_err: Response = jsonify({"error": "no_conversation"})
        resp_err.status_code = 404
        return resp_err

    sess = get_session()
    settings_row = get_settings_row(sess)
    if not settings_row.llm_base_url or not settings_row.llm_chat_model:
        resp_err = jsonify({"error": "llm_not_configured"})
        resp_err.status_code = 400
        return resp_err

    history = _collect_history(conv.id)
    app_settings = cast(Settings, current_app.config["FM_SETTINGS"])
    encryption_key = app_settings.encryption_key.get_secret_value()
    conv_id = conv.id

    def _generate() -> Any:
        """Sync-Wrapper um den async Generator. Sammelt das Assistant-Reply und
        persistiert es am Ende als ``assistant``-Message inkl. Usage."""
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
            # Generischer Fehler-Frame — niemals Exception-Text mit potentiell
            # sensiblen SDK-Headern/Key-Fragmenten ins SSE oder Log leaken.
            log.warning("group_chat.stream_failed", error=type(exc).__name__)
            yield _sse_payload("error", json.dumps({"error": "provider_error"}))
        finally:
            import contextlib

            with contextlib.suppress(Exception):  # pragma: no cover
                loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

        # Persistenz nach Stream-Ende in frischer Session (ADR-0055 §2).
        _persist_assistant(conv_id, assistant_chunks, prompt_tokens, completion_tokens)

        done_payload = json.dumps(
            {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "conversation_id": conv_id,
            }
        )
        yield _sse_payload("done", done_payload)

    resp = Response(stream_with_context(_generate()), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"  # Falls hinter nginx
    return resp


# ---------------------------------------------------------------------------
# POST /chat/new — Konversation loeschen (CASCADE)
# ---------------------------------------------------------------------------


@group_chat_bp.post("/new")
@login_required
@limiter.limit("30/minute")
def new_chat(sid: int, gid: int) -> str:
    """POST /new — Konversation unwiderruflich loeschen, Empty-State zurueck.

    Loeschung trifft genau die ``(server, group)``-Konversation. CASCADE/
    ``delete-orphan`` raeumt die Messages mit ab.
    """
    server, findings = _guard_or_404(sid, gid)
    sess = get_session()
    sess.execute(
        delete(GroupChatConversation).where(
            GroupChatConversation.server_id == sid,
            GroupChatConversation.application_group_id == gid,
        )
    )
    sess.commit()
    return _render_chat_view(server, sid, gid, None, findings)


# Der GET-SSE-Stream ist CSRF-irrelevant (CSRFProtect rueht GETs nicht an); die
# POST-Routen werden vom globalen CSRFProtect gedeckt.

__all__ = ["group_chat_bp"]
