"""Audit-Log-Helper.

Zentrale Funktion `log_event(...)` schreibt einen `audit_events`-Eintrag in
die DB. Wenn ein eingeloggter User vorhanden ist (`flask_login.current_user`
ist authenticated), wird `actor`/`actor_user_id` automatisch befuellt.
Aufrufer koennen `actor_id` explizit setzen — z.B. fuer System-Events oder
fuer Login-Failed (kein eingeloggter User).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog
from flask import has_request_context
from flask_login import current_user
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import AuditEvent

if TYPE_CHECKING:
    pass

log = structlog.get_logger(__name__)


def log_event(
    action: str,
    target_type: str,
    target_id: str | int | None = None,
    *,
    comment: str | None = None,
    metadata: dict[str, Any] | None = None,
    actor: str | None = None,
    actor_id: int | None = None,
    session: Session | None = None,
) -> AuditEvent:
    """Schreibt einen Audit-Event.

    - `action`: kurzer Bezeichner aus dem in ARCHITECTURE.md §13 definierten
      Vokabular (z.B. `auth.success`, `auth.failed`, `setup.completed`,
      `tag.created`).
    - `target_type` / `target_id`: identifiziert das Objekt, auf das sich der
      Event bezieht (z.B. `("server", "42")`).
    - `comment`: freier Text, niemals Pflicht-Feld (siehe ADR-0006).
    - `metadata`: zusaetzlicher JSON-Kontext (z.B. IP-Adresse, betroffene
      Finding-IDs bei Bulk-Aktionen).
    - `actor` / `actor_id`: bei Bedarf manuell setzen; sonst wird automatisch
      aus `current_user` gezogen.

    Liefert den persistierten Event zurueck (kein Commit, der Caller
    entscheidet ueber Transaction-Bounds — die per-Request-Session committet
    am Ende des Requests von alleine, sofern nichts geworfen wurde).
    """
    sess = session if session is not None else get_session()

    resolved_actor = actor
    resolved_actor_id = actor_id

    if (
        resolved_actor is None
        and has_request_context()
        and getattr(current_user, "is_authenticated", False)
    ):
        resolved_actor = getattr(current_user, "username", None)
        resolved_actor_id = getattr(current_user, "id", None)

    if resolved_actor is None:
        resolved_actor = "system"

    event = AuditEvent(
        actor=resolved_actor,
        actor_user_id=resolved_actor_id,
        action=action,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        comment=comment,
        event_metadata=metadata,
    )
    sess.add(event)
    sess.flush()

    log.info(
        "audit.logged",
        action=action,
        target_type=target_type,
        target_id=event.target_id,
    )
    return event


__all__ = ["log_event"]
