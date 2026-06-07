# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Sidebar-Context-Builder fuer Block-I-View-Routes (Phase C, ADR-0030).

Variablen-Vertrag — initialer Page-Render (Context-Processor-Pfad):
  - sidebar_servers    : list[Server]  (mit eager-loaded tag_links/tag)
  - filter_tags        : list[str]
  - active_server_id   : int | None  (vom View gesetzt)
  - sidebar_groups     : list[ServerGroup]  (sortiert nach position, name)
  - server_group_aggregates : dict[int | None, GroupCounts]
  - sidebar_open_group_ids  : set[int]  (offene Gruppen aus Cookie, ADR-0046)

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

Dieses Modul stellt ausserdem zwei HTMX-Endpoints bereit:
  - `GET /_partials/sidebar`       — Polling-Endpoint (ADR-0019)
  - `POST /_partials/sidebar/batch` — Viewport-Batch-Endpoint (ADR-0035)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Blueprint, abort, has_request_context, render_template, request
from flask_login import login_required
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db import get_session
from app.models import Server, ServerGroup, ServerTag
from app.services.heartbeat_aggregation import heartbeats_for_servers
from app.services.sidebar_group_aggregates import group_counts
from app.services.sidebar_risk_counts import escalate_act_counts_by_server

# Block AC (ADR-0046): Persistenter Aufklapp-Zustand der Sidebar-Gruppen via
# Cookie. JS schreibt `sidebar_open_groups` aus dem DOM-Ist-Zustand, der Server
# liest es hier und rendert `open` direkt — single-source ueber beide Render-Pfade
# (Context-Processor + Polling-Endpoint), weil beide durch build_sidebar_context()
# laufen.
_SIDEBAR_OPEN_GROUPS_COOKIE = "sidebar_open_groups"
_SIDEBAR_OPEN_GROUPS_MAX_RAW_LEN = 512
_SIDEBAR_OPEN_GROUPS_MAX_IDS = 64


def _parse_open_group_ids(raw: str) -> set[int]:
    """Parst das `sidebar_open_groups`-Cookie defensiv zu einem `set[int]`.

    Vertrag (ADR-0046): kommaseparierte ganzzahlige Group-IDs (z.B. `"1,5,12"`).
    Defense-in-Depth gegen manipulierte/ueberlange Cookies:
      - Roh-String laenger als 512 Zeichen -> leeres Set (kein Parsing von Garbage).
      - Maximal 64 IDs uebernehmen, Rest ignorieren.
      - Nicht-parsebare Tokens still verwerfen — niemals eine Exception/500.

    Negative oder unbekannte IDs sind harmlos: sie matchen schlicht keine echte
    `group.id` und bleiben damit ohne Render-Effekt.
    """
    if not raw or len(raw) > _SIDEBAR_OPEN_GROUPS_MAX_RAW_LEN:
        return set()
    ids: set[int] = set()
    for token in raw.split(","):
        if len(ids) >= _SIDEBAR_OPEN_GROUPS_MAX_IDS:
            break
        token = token.strip()
        if not token:
            continue
        try:
            ids.add(int(token))
        except ValueError:
            continue
    return ids


def _read_open_group_ids() -> set[int]:
    """Liest die offenen Gruppen-IDs aus dem Request-Cookie (beide Render-Pfade).

    Ausserhalb eines aktiven Request-Kontexts (isolierte Pure-Unit-Tests von
    `build_sidebar_context()` ohne Test-Request-Context) liefert die Funktion
    bewusst ein leeres Set, statt zu werfen.
    """
    if not has_request_context():
        return set()
    return _parse_open_group_ids(request.cookies.get(_SIDEBAR_OPEN_GROUPS_COOKIE, ""))


def build_sidebar_context(
    filter_tags: list[str] | None = None,
) -> dict[str, Any]:
    """Sammelt die **billigen** Variablen die `base_app.html` fuer die Sidebar braucht.

    Liefert die Server-Liste (Namen, Tags, Lifecycle-Status) plus die
    Group-Struktur fuer die Section-Header — keine Heartbeats, keine
    Risk-Counts und keine globalen Tag-Select-Daten.
    Diese teuren Aggregate kommen ausschliesslich vom Polling-Endpoint
    `/_partials/sidebar` (ADR-0030 Phase C).

    Block W (ADR-0034) ergaenzt:
      - `sidebar_groups`            : sortierte Group-Liste
      - `server_group_aggregates`   : GroupCounts pro group_id (inkl. None)

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

    # Block W (ADR-0034): sortierte Group-Liste fuer Section-Header.
    groups_stmt = select(ServerGroup).order_by(ServerGroup.position, ServerGroup.name)
    sidebar_groups = list(sess.execute(groups_stmt).scalars().all())

    # Block W (ADR-0034): GROUP-BY-Aggregation fuer Header-Counts.
    aggregates = group_counts(sess)

    return {
        "sidebar_servers": servers,
        "filter_tags": tags,
        "active_server_id": None,
        "sidebar_groups": sidebar_groups,
        "server_group_aggregates": aggregates,
        # Block AC (ADR-0046): persistente Aufklapp-Gruppen aus dem Cookie.
        "sidebar_open_group_ids": _read_open_group_ids(),
    }


def is_hx_request(request: Any) -> bool:
    """Kleiner Helper: True wenn der Request HTMX-getriggert ist.

    `request` ist `flask.request`; wir nehmen `Any` damit der Helper auch
    in Tests mit Mock-Requests genutzt werden kann.
    """
    return bool(request.headers.get("HX-Request") == "true")


def _filter_visible_server_ids(
    sess: Session,
    raw_ids: list[int],
    filter_tags: list[str] | None = None,
) -> list[int]:
    """Filtert rohe Server-IDs gegen die DB — nur tatsaechlich existierende IDs.

    Security: kein User-Input-Wert wird direkt als Template-Variable
    genutzt. Erst DB-Whitelist, dann Response.

    `filter_tags` wird noch nicht implementiert (Block-W-Scope: kein
    Group-Filter via URL). Der Parameter ist fuer spaetere Erweiterung
    vorbereitet (ADR-0034 §"Filter mit Tag").
    """
    if not raw_ids:
        return []
    stmt = select(Server.id).where(Server.id.in_(raw_ids))
    return list(sess.execute(stmt).scalars().all())


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
    ctx["sidebar_heartbeats"] = heartbeats_for_servers(sess, server_ids, now=now, days=30)

    risk_counts = escalate_act_counts_by_server(sess, server_ids)
    ctx["sidebar_risk_counts"] = risk_counts

    ctx["hosts_total"] = len(server_ids)
    ctx["alarm_count"] = sum(
        1 for sid in server_ids if risk_counts.get(sid, {}).get("escalate", 0) > 0
    )
    # Polling-Response: kein Hidden-Lazy-Load-Trigger ins DOM, sonst Re-Trigger-
    # Loop beim outerHTML-Swap (HTMX uebernimmt den gesamten Response-Body in
    # das Swap-Ziel, mehrere Top-Level-Elemente eingeschlossen).
    ctx["lazy_load_trigger"] = False

    return render_template("sidebar/_server_list.html", **ctx)


@sidebar_partials_bp.post("/_partials/sidebar/batch")
@login_required
def sidebar_batch() -> Any:
    """Viewport-Batch-Endpoint fuer Sidebar-Heartbeat-OOB-Swaps (ADR-0035).

    Client schickt JSON `{"server_ids": [1, 2, 3]}` mit den aktuell
    sichtbaren Server-IDs (IntersectionObserver-Viewport-Pattern). Der
    Endpoint antwortet mit einem HTMX-OOB-Fragment-Body pro Server
    (Heartbeat-Bar + escalate/act-Counts).

    Sicherheits-Haertungen (security-auditor-pflichtig):
      - CSRF-Token: Flask-WTF `csrf.protect` ist App-weit aktiv auf allen
        POST-Requests (inkl. diesem Blueprint). HTMX schickt `X-CSRFToken`-
        Header aus dem Meta-Tag.
      - Pydantic `extra="forbid"`: unbekannte Felder -> 400.
      - max_length=200 Cap: mehr als 200 IDs -> 400.
      - @login_required: unauthentifizierte Requests -> Redirect/401.
      - DB-Whitelist: rohe IDs werden gegen `servers.id` gefiltert, bevor
        irgendwas an Templates geht. Kein User-Input direkt im Template-Pfad.

    Response: HTMX-OOB-Fragment-Body (mehrere Top-Level-Elemente) fuer
    den `hx-swap="outerHTML"` Pattern pro Server-Row.
    """
    from app.schemas.sidebar_batch import SidebarBatchRequest

    # Body-Parse + Pydantic-Validation.
    raw_body = request.get_json(silent=True)
    if raw_body is None:
        abort(400)

    try:
        payload = SidebarBatchRequest.model_validate(raw_body)
    except ValidationError:
        abort(400)

    sess = get_session()

    # DB-Whitelist: nur tatsaechlich existierende Server-IDs.
    visible_ids = _filter_visible_server_ids(sess, payload.server_ids)

    if not visible_ids:
        # Kein Server sichtbar oder alle IDs ungueltig -> leere OOB-Response.
        return render_template(
            "_partials/sidebar_batch_oob.html",
            batch_servers=[],
            batch_heartbeats={},
            batch_risk_counts={},
        )

    now = datetime.now(tz=UTC)
    batch_heartbeats = heartbeats_for_servers(sess, visible_ids, days=30, now=now)
    batch_risk_counts = escalate_act_counts_by_server(sess, visible_ids)

    # Server-Objekte fuer das Template (Namen, IDs, OS-Info).
    servers_stmt = select(Server).where(Server.id.in_(visible_ids))
    batch_servers = list(sess.execute(servers_stmt).scalars().all())

    return render_template(
        "_partials/sidebar_batch_oob.html",
        batch_servers=batch_servers,
        batch_heartbeats=batch_heartbeats,
        batch_risk_counts=batch_risk_counts,
    )


__all__ = [
    "build_sidebar_context",
    "is_hx_request",
    "sidebar_partials_bp",
]
