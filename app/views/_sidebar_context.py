"""Sidebar-Context-Builder fuer Block-I-View-Routes.

Die Views aus Block D/E/F sollen bei vollem Request (kein HX-Request)
zusammen mit ihrem Detail-Pane-Inhalt die Sidebar rendern. Damit das
DRY bleibt, sammelt dieses Modul die Sidebar-Variablen einmal.

Variablen-Vertrag (siehe `base_app.html`):
  - quick_stats        : QuickStats
  - sidebar_servers    : list[Server]  (mit eager-loaded tag_links/tag)
  - sidebar_heartbeats : dict[int, list[DailyStatus]]
  - available_tags     : list[Tag]
  - filter_tags        : list[str]
  - active_server_id   : int | None  (vom View gesetzt)

Zusaetzlich stellt dieses Modul den HTMX-Polling-Endpoint
`GET /_partials/sidebar` bereit (ADR-0019): dasselbe Sidebar-Markup
ohne Page-Shell, das `base_app.html` per `hx-get` alle 10s nachzieht.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Blueprint, render_template, request
from flask_login import login_required
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import get_session
from app.models import Server, ServerTag, Tag
from app.services.heartbeat_aggregation import heartbeats_for_servers
from app.services.quick_stats import get_quick_stats


def build_sidebar_context(
    filter_tags: list[str] | None = None,
    days: int = 50,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Sammelt alle Variablen die `base_app.html` fuer die Sidebar braucht.

    Argumente:
      `filter_tags` — aktive Tag-Filter (OR), optional.
      `days`        — Heartbeat-Fenster in Tagen (Default 50).
      `now`         — Test-Zeitpunkt; sonst `datetime.now(UTC)`.

    Rueckgabe: dict mit den oben definierten Keys. `active_server_id`
    wird vom aufrufenden View selbst gesetzt.
    """
    sess = get_session()
    current = now if now is not None else datetime.now(tz=UTC)
    tags = filter_tags or []

    server_stmt = (
        select(Server)
        .options(selectinload(Server.tag_links).selectinload(ServerTag.tag))
        .order_by(Server.retired_at.isnot(None), Server.name.asc())
    )
    servers = list(sess.execute(server_stmt).scalars().unique().all())

    available_tags = list(sess.execute(select(Tag).order_by(Tag.name)).scalars().all())

    heartbeats = heartbeats_for_servers(
        sess,
        [srv.id for srv in servers],
        days=days,
        now=current,
    )
    quick_stats = get_quick_stats(sess, filter_tags=tags or None, now=current)

    return {
        "quick_stats": quick_stats,
        "sidebar_servers": servers,
        "sidebar_heartbeats": heartbeats,
        "available_tags": available_tags,
        "filter_tags": tags,
        "active_server_id": None,
    }


def is_hx_request(request: Any) -> bool:
    """Kleiner Helper: True wenn der Request HTMX-getriggert ist.

    `request` ist `flask.request`; wir nehmen `Any` damit der Helper auch
    in Tests mit Mock-Requests genutzt werden kann.
    """
    return bool(request.headers.get("HX-Request") == "true")


sidebar_partials_bp = Blueprint("sidebar_partials", __name__)


@sidebar_partials_bp.get("/_partials/sidebar")
@login_required
def sidebar_partial() -> Any:
    """HTMX-Polling-Endpoint fuer die Sidebar-Server-Liste (ADR-0019).

    Liefert ausschliesslich das `<ul id="server-list">`-Fragment ohne
    `<html>`/`<head>`/`<body>`-Shell. Wird von `base_app.html` per
    `hx-get` alle 10 s (nur bei sichtbarem Tab) nachgezogen und ersetzt
    sich selbst via `outerHTML`.

    Filter-Tags werden — analog zum Dashboard-Polling-Pane — aus dem
    Query-String (`?tag=...`) uebernommen, damit ein aktiver Tag-Filter
    auch in der Sidebar-Server-Liste persistiert.
    """
    filter_tags = request.args.getlist("tag") or None
    ctx = build_sidebar_context(filter_tags=filter_tags)
    active_id = request.args.get("active_server_id", type=int)
    if active_id is not None:
        ctx["active_server_id"] = active_id
    return render_template("sidebar/_server_list.html", **ctx)


__all__ = ["build_sidebar_context", "is_hx_request", "sidebar_partials_bp"]
