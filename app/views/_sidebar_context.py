"""Sidebar-Context-Builder fuer Block-I-View-Routes (Phase C, ADR-0030).

Variablen-Vertrag — initialer Page-Render (Context-Processor-Pfad):
  - sidebar_servers    : list[Server]  (mit eager-loaded tag_links/tag)
  - available_tags     : list[Tag]
  - filter_tags        : list[str]
  - active_server_id   : int | None  (vom View gesetzt)

Teure Aggregate (Heartbeats, Risk-Counts, Header-Counter) werden NICHT
mehr im Context-Processor gebaut. Sie erscheinen ausschliesslich im
Polling-Endpoint `GET /_partials/sidebar` (Phase C, ADR-0030 Befund 8):
  - sidebar_heartbeats   : dict[int, list[DailyStatus]]
  - sidebar_risk_counts  : dict[int, dict[str, int]]
  - hosts_total          : int
  - alarm_count          : int

Das Template `sidebar/_server_list.html` rendert beim initialen Page-Load
ein Skeleton fuer die teuren Felder. Der Polling-Endpoint ersetzt das
Skeleton via HTMX `outerHTML`-Swap mit den echten Werten.

Dieses Modul stellt ausserdem den HTMX-Polling-Endpoint
`GET /_partials/sidebar` bereit (ADR-0019).
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
from app.services.sidebar_risk_counts import escalate_act_counts_by_server


def build_sidebar_context(
    filter_tags: list[str] | None = None,
) -> dict[str, Any]:
    """Sammelt die **billigen** Variablen die `base_app.html` fuer die Sidebar braucht.

    Liefert nur die Server-Liste (Namen, Tags, Lifecycle-Status) und die
    verfuegbaren Filter-Tags — keine Heartbeats, keine Risk-Counts.
    Diese teuren Aggregate kommen ausschliesslich vom Polling-Endpoint
    `/_partials/sidebar` (ADR-0030 Phase C).

    Argumente:
      `filter_tags` — aktive Tag-Filter (OR), optional.

    Rueckgabe: dict mit den oben definierten Keys. `active_server_id`
    wird vom aufrufenden View selbst gesetzt.
    """
    sess = get_session()
    tags = filter_tags or []

    server_stmt = (
        select(Server)
        .options(selectinload(Server.tag_links).selectinload(ServerTag.tag))
        .order_by(Server.retired_at.isnot(None), Server.name.asc())
    )
    servers = list(sess.execute(server_stmt).scalars().unique().all())

    available_tags = list(sess.execute(select(Tag).order_by(Tag.name)).scalars().all())

    return {
        "sidebar_servers": servers,
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
    """HTMX-Polling-Endpoint fuer die Sidebar-Server-Liste (ADR-0019, Phase C).

    Liefert ausschliesslich das `<ul id="server-list">`-Fragment ohne
    `<html>`/`<head>`/`<body>`-Shell. Wird von `base_app.html` per
    `hx-get` alle 60 s (nur bei sichtbarem Tab) nachgezogen und ersetzt
    sich selbst via `outerHTML` (Cadence-Wechsel 10 s -> 60 s, ADR-0030
    §Konsequenzen).

    Dies ist der **einzige** Pfad der die teuren Aggregate baut:
    - `sidebar_heartbeats`  — Findings + Scans, schmale Projektion (Befund 6).
    - `sidebar_risk_counts` — ESCALATE/ACT-Counts pro Server (eine Query).
    - `hosts_total`         — Anzahl Server (aus der ohnehin geladenen Liste).
    - `alarm_count`         — Anzahl Server mit mind. 1 ESCALATE-Finding.

    Filter-Tags werden — analog zum Dashboard-Polling-Pane — aus dem
    Query-String (`?tag=...`) uebernommen, damit ein aktiver Tag-Filter
    auch in der Sidebar-Server-Liste persistiert.
    """
    filter_tags = request.args.getlist("tag") or None
    ctx = build_sidebar_context(filter_tags=filter_tags)

    active_id = request.args.get("active_server_id", type=int)
    if active_id is not None:
        ctx["active_server_id"] = active_id

    sess = get_session()
    server_ids = [srv.id for srv in ctx["sidebar_servers"]]

    now = datetime.now(tz=UTC)
    ctx["sidebar_heartbeats"] = heartbeats_for_servers(sess, server_ids, now=now)

    risk_counts = escalate_act_counts_by_server(sess, server_ids)
    ctx["sidebar_risk_counts"] = risk_counts

    ctx["hosts_total"] = len(server_ids)
    ctx["alarm_count"] = sum(
        1 for sid in server_ids if risk_counts.get(sid, {}).get("escalate", 0) > 0
    )

    return render_template("sidebar/_server_list.html", **ctx)


__all__ = ["build_sidebar_context", "is_hx_request", "sidebar_partials_bp"]
