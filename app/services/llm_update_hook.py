"""Update-Hook: bei neuem Scan System-Message an aktive Conversations anhaengen.

ARCHITECTURE.md §12 ("Update-Verhalten bei neuen Scans"):

> Wenn waehrend eine Conversation `active` ist ein neuer Scan reinkommt
> und Findings auf dem zugehoerigen Server hinzukommen oder
> verschwinden, haengen wir automatisch eine `system`-Message an:
> "Update: 2 neue Findings, 1 resolved, …". So bleibt der Chat aktuell,
> ohne dass der User neu starten muss.

API: `notify_conversations_for_scan(session, server_id, *, new=..., resolved=..., changed=0)`.
Wird nach erfolgreichem `findings_ingest.ingest_scan` aufgerufen (Hook).
Im MVP wird `changed_count` immer `0` uebergeben, weil Block E keine
Delta-Erkennung fuer veraenderte Findings hat.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import log_event
from app.models import LlmConversation, LlmConversationStatus, LlmMessage, LlmMessageRole
from app.services.llm_prompt import build_update_system_note

log = structlog.get_logger(__name__)


def notify_conversations_for_scan(
    session: Session,
    server_id: int,
    *,
    new_count: int,
    resolved_count: int,
    changed_count: int = 0,
    now: datetime | None = None,
) -> int:
    """Haengt eine System-Update-Message an alle aktiven Conversations.

    Returns die Anzahl der Conversations, denen wir eine Message angehaengt
    haben. Wenn weder neue noch resolved Findings vorliegen, passiert nichts.

    Audit-Event `llm.conversation_update_hook` pro betroffene Conversation
    mit `{server_id, new, resolved, changed}` als metadata.
    """
    if new_count == 0 and resolved_count == 0 and changed_count == 0:
        return 0

    ts = now or datetime.now(tz=UTC)

    conversations = list(
        session.execute(
            select(LlmConversation).where(
                LlmConversation.server_id == server_id,
                LlmConversation.status == LlmConversationStatus.ACTIVE,
            )
        )
        .scalars()
        .all()
    )

    if not conversations:
        return 0

    body = build_update_system_note(
        new_count=new_count,
        resolved_count=resolved_count,
        changed_count=changed_count,
    )

    for conv in conversations:
        msg = LlmMessage(
            conversation_id=conv.id,
            role=LlmMessageRole.SYSTEM,
            content=body,
            created_at=ts,
        )
        session.add(msg)
        conv.last_message_at = ts
        log_event(
            "llm.conversation_update_hook",
            target_type="llm_conversation",
            target_id=conv.id,
            metadata={
                "server_id": server_id,
                "new": new_count,
                "resolved": resolved_count,
                "changed": changed_count,
            },
            session=session,
        )

    session.flush()
    log.info(
        "llm.update_hook.applied",
        server_id=server_id,
        conversations=len(conversations),
        new=new_count,
        resolved=resolved_count,
    )
    return len(conversations)


__all__ = ["notify_conversations_for_scan"]
