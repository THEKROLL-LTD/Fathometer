"""Audit-View `GET /audit` und CSV-Export `/audit/export.csv`.

ARCHITECTURE.md §13 (Audit-Log) und §7 (UI-View). Filter:

- `date_from`, `date_to` : ISO-Datum (`YYYY-MM-DD`). Inklusiv. Werden auf
                           00:00 UTC bzw. 23:59 UTC erweitert.
- `actor`                : Username- oder Server-Name-Substring (`ILIKE`).
- `action`               : exakter Match auf das Action-Vokabular.
- `server_id` / `server_name` : Filter auf `target_type='server'` mit
                           passender Server-ID oder Namens-Substring.
- `tag`                  : Server-Tag. Filtert auf Events deren
                           Target-Server das Tag traegt (oder deren
                           `metadata`-jsonb einen Server-Ref enthaelt
                           der das Tag traegt — im MVP nur target_type
                           ='server'-Events).

Pagination: 50 pro Seite (Default), Page-Param `page` 1-basiert.

Template-Variablen-Vertrag (`audit/list.html`):

- `events`         : list[AuditEvent]
- `total`          : int
- `page`, `per_page`: int
- `pages`          : int
- `filter`         : dict mit den geparsten Filter-Werten (date_from,
                     date_to, actor, action, server_id, server_name, tag)
- `actions`        : list[str] — bekannte Action-Werte fuer den Dropdown
- `available_tags` : list[Tag]
- `csv_url`        : str — `/audit/export.csv?<same-filter>`
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from urllib.parse import urlencode

import structlog
from flask import Blueprint, Response, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import String, cast, or_, select
from sqlalchemy.orm import Session

from app.db import get_session
from app.forms import TAG_NAME_REGEX
from app.models import AuditEvent, Server, ServerTag, Tag
from app.services.csv_export import stream_audit_csv
from app.views._sidebar_context import is_hx_request

log = structlog.get_logger(__name__)

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")

_PER_PAGE = 50

# Aktivitaets-Strip (Audit-Redesign). Histogramm der Event-Anzahl ueber die
# letzten 24h in `_ACTIVITY_BUCKETS` gleich breiten Zeit-Buckets. Der Peak-
# Bucket traegt das einzige Cyan-Signal (Design: `audit__bar--peak`).
_ACTIVITY_BUCKETS = 48
_ACTIVITY_WINDOW_H = 24
# Minimale Balken-Hoehe in Prozent fuer nicht-leere Buckets (Design-Floor),
# damit kleine Buckets sichtbar bleiben.
_ACTIVITY_MIN_PCT = 6


def _compute_activity(
    timestamps: list[datetime],
    now: datetime,
    *,
    bucket_count: int = _ACTIVITY_BUCKETS,
    window_h: int = _ACTIVITY_WINDOW_H,
) -> dict[str, Any]:
    """Bucketisiert Event-Timestamps in ein 24h-Histogramm (pure, testbar).

    Liefert pro Bucket `count` und `height_pct` (auf den Peak normiert) sowie
    `peak`-Flag (genau ein Bucket: das erste Maximum mit count > 0). `now` und
    alle `timestamps` werden als tz-aware UTC erwartet; naive Werte werden als
    UTC interpretiert.

    Returns dict mit Keys: `bars` (list[dict]), `total` (int), `max` (int).
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    window = timedelta(hours=window_h)
    start = now - window
    span = window / bucket_count
    counts = [0] * bucket_count

    for ts in timestamps:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        if ts < start or ts > now:
            continue
        idx = int((ts - start) / span)
        if idx >= bucket_count:
            idx = bucket_count - 1
        elif idx < 0:
            idx = 0
        counts[idx] += 1

    total = sum(counts)
    peak_val = max(counts) if counts else 0
    peak_idx = counts.index(peak_val) if peak_val > 0 else -1

    bars: list[dict[str, Any]] = []
    for i, c in enumerate(counts):
        if peak_val > 0 and c > 0:
            height_pct = max(_ACTIVITY_MIN_PCT, round(c / peak_val * 100))
        else:
            height_pct = 0
        bars.append({"count": c, "height_pct": height_pct, "peak": i == peak_idx})

    return {"bars": bars, "total": total, "max": peak_val}


# Bekannte Action-Werte aus §13 — fuer den Filter-Dropdown im Template.
# Reihenfolge ist absichtlich gruppiert: Findings, Tags, Server, Auth,
# Sonstiges. Templates iterieren in Reihenfolge.
KNOWN_ACTIONS: list[str] = [
    "finding.acknowledged",
    "finding.reopened",
    "finding.bulk_acknowledged",
    "finding.acknowledged.bulk",  # Block-E group-ack (Legacy-Naming)
    "finding.note.added",
    "finding.note.deleted",
    "finding.resolved",
    "tag.created",
    "tag.deleted",
    "tag.renamed",
    "tag.color_changed",
    "group.created",
    "group.renamed",
    "group.deleted",
    "group.moved",
    "server.registered",
    "server.revoked",
    "server.retired",
    "server.group_changed",
    "server.scan_interval_changed",
    "server.tag.added",
    "server.tag.removed",
    "key.rotated.master",
    "key.rotated.server",
    "master_key.rotated",
    "settings.updated",
    "scan.ingested",
    "auth.login",
    "auth.logout",
    "auth.failed",
    "ratelimit.tripped",
    "setup.completed",
]


# ---------------------------------------------------------------------------
# Filter-Parsing
# ---------------------------------------------------------------------------


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def _normalize_filter_args(args: Any) -> dict[str, Any]:
    """Liest und validiert die Filter-Werte aus dem Query-String."""
    actor = (args.get("actor") or "").strip()[:128] or None
    action = (args.get("action") or "").strip()[:64] or None
    if action is not None and action not in KNOWN_ACTIONS:
        # Unbekannte Action -> Filter verwerfen statt 422; Bookmarks duerfen
        # nicht hart brechen.
        action = None

    server_id_raw = (args.get("server_id") or "").strip()
    server_id: int | None
    try:
        server_id = int(server_id_raw) if server_id_raw else None
    except ValueError:
        server_id = None

    server_name = (args.get("server_name") or "").strip()[:128] or None

    tag_raw = (args.get("tag") or "").strip().lower()
    tag: str | None = None
    if tag_raw and TAG_NAME_REGEX.match(tag_raw):
        tag = tag_raw

    return {
        "date_from": _parse_date(args.get("date_from")),
        "date_to": _parse_date(args.get("date_to")),
        "actor": actor,
        "action": action,
        "server_id": server_id,
        "server_name": server_name,
        "tag": tag,
    }


def _build_audit_query(filt: dict[str, Any]) -> Any:
    """Baut `select(AuditEvent)` mit allen aktiven Filtern."""
    stmt = select(AuditEvent)

    if filt["date_from"] is not None:
        dt_from = datetime.combine(filt["date_from"], time.min, tzinfo=UTC)
        stmt = stmt.where(AuditEvent.ts >= dt_from)
    if filt["date_to"] is not None:
        # Inklusiv: bis Ende des Tages.
        dt_to = datetime.combine(filt["date_to"] + timedelta(days=1), time.min, tzinfo=UTC)
        stmt = stmt.where(AuditEvent.ts < dt_to)
    if filt["actor"]:
        stmt = stmt.where(AuditEvent.actor.ilike(f"%{filt['actor']}%"))
    if filt["action"]:
        stmt = stmt.where(AuditEvent.action == filt["action"])
    if filt["server_id"] is not None:
        stmt = stmt.where(
            AuditEvent.target_type == "server",
            AuditEvent.target_id == str(filt["server_id"]),
        )
    if filt["server_name"]:
        # Subquery: alle Server-IDs (gecastet zu TEXT) deren Name den Substring
        # enthaelt. Spalte `audit_events.target_id` ist VARCHAR(128) — Postgres
        # weigert sich, INTEGER ohne expliziten Cast dagegen zu vergleichen.
        srv_ids_sq = select(cast(Server.id, String)).where(
            Server.name.ilike(f"%{filt['server_name']}%")
        )
        stmt = stmt.where(
            AuditEvent.target_type == "server",
            AuditEvent.target_id.in_(srv_ids_sq),
        )
    if filt["tag"]:
        # Server-IDs (gecastet zu TEXT) die dieses Tag tragen. Gleicher
        # Cast-Grund wie oben.
        tag_srv_sq = (
            select(cast(ServerTag.server_id, String))
            .join(Tag, Tag.id == ServerTag.tag_id)
            .where(Tag.name == filt["tag"])
        )
        stmt = stmt.where(
            AuditEvent.target_type == "server",
            AuditEvent.target_id.in_(tag_srv_sq),
        )

    stmt = stmt.order_by(AuditEvent.ts.desc(), AuditEvent.id.desc())
    return stmt


def _filter_to_query_string(filt: dict[str, Any]) -> str:
    """Serialisiert die Filter in einen Query-String fuer Pagination/CSV-Link."""
    parts: list[tuple[str, str]] = []
    if filt["date_from"] is not None:
        parts.append(("date_from", filt["date_from"].isoformat()))
    if filt["date_to"] is not None:
        parts.append(("date_to", filt["date_to"].isoformat()))
    if filt["actor"]:
        parts.append(("actor", str(filt["actor"])))
    if filt["action"]:
        parts.append(("action", str(filt["action"])))
    if filt["server_id"] is not None:
        parts.append(("server_id", str(filt["server_id"])))
    if filt["server_name"]:
        parts.append(("server_name", str(filt["server_name"])))
    if filt["tag"]:
        parts.append(("tag", str(filt["tag"])))
    return urlencode(parts)


# ---------------------------------------------------------------------------
# Route: List
# ---------------------------------------------------------------------------


@audit_bp.get("/")
@login_required
def list_events() -> Any:
    sess = get_session()
    filt = _normalize_filter_args(request.args)

    try:
        page = max(1, int(request.args.get("page", "1")))
    except (TypeError, ValueError):
        page = 1

    base_stmt = _build_audit_query(filt)

    from sqlalchemy import func

    total = int(sess.execute(select(func.count()).select_from(base_stmt.subquery())).scalar() or 0)
    pages = max(1, (total + _PER_PAGE - 1) // _PER_PAGE)
    page = min(page, pages)

    page_stmt = base_stmt.offset((page - 1) * _PER_PAGE).limit(_PER_PAGE)
    events = list(sess.execute(page_stmt).scalars().all())

    available_tags = list(sess.execute(select(Tag).order_by(Tag.name)).scalars().all())

    # Aktivitaets-Strip: Event-Timestamps der letzten 24h (ungefiltert — der
    # Strip zeigt die Gesamtlast, nicht die aktuelle Filter-Auswahl).
    now = datetime.now(tz=UTC)
    activity_cutoff = now - timedelta(hours=_ACTIVITY_WINDOW_H)
    activity_ts = list(
        sess.execute(select(AuditEvent.ts).where(AuditEvent.ts >= activity_cutoff)).scalars().all()
    )
    activity = _compute_activity(activity_ts, now)

    qs = _filter_to_query_string(filt)
    csv_url = url_for("audit.export_csv")
    if qs:
        csv_url = f"{csv_url}?{qs}"

    return render_template(
        "audit/list.html",
        events=events,
        total=total,
        page=page,
        per_page=_PER_PAGE,
        pages=pages,
        filter=filt,
        actions=KNOWN_ACTIONS,
        available_tags=available_tags,
        activity=activity,
        csv_url=csv_url,
        # Block I: Sidebar-Layout-Flag.
        hx_partial=is_hx_request(request),
    )


# ---------------------------------------------------------------------------
# Route: CSV-Export
# ---------------------------------------------------------------------------


@audit_bp.get("/export.csv")
@login_required
def export_csv() -> Response:
    """Streamt das gefilterte Audit-Log als CSV."""
    sess: Session = get_session()
    filt = _normalize_filter_args(request.args)
    base_stmt = _build_audit_query(filt)

    log.info("audit.csv_export", filter=_loggable_filter(filt))

    # Wichtig: wir geben einen Generator an Flask weiter — Flask streamt das
    # an den Client ohne den vollen Buffer im Speicher zu halten.
    response = Response(
        stream_audit_csv(sess, filter_query=base_stmt),
        mimetype="text/csv; charset=utf-8",
    )
    response.headers["Content-Disposition"] = 'attachment; filename="audit.csv"'
    return response


def _loggable_filter(filt: dict[str, Any]) -> dict[str, Any]:
    """Reduziert den Filter auf Werte die im Log auftauchen duerfen."""
    return {
        "date_from": str(filt["date_from"]) if filt["date_from"] else None,
        "date_to": str(filt["date_to"]) if filt["date_to"] else None,
        "actor_has_value": bool(filt["actor"]),
        "action": filt["action"],
        "server_id": filt["server_id"],
        "server_name_has_value": bool(filt["server_name"]),
        "tag": filt["tag"],
    }


# Unused-but-imported guard (or_ benutzt im Filter, lassen wir).
_ = or_

__all__ = ["audit_bp"]
