"""Globale Suche `GET /findings/search` — CVE-/Paket-/Server-Suche.

ARCHITECTURE.md §7 (Such-Seite mit Aggregations-Header und "Alle abhaken"-
Knopf). Tag-Filter wie auf dem Dashboard.

Query-Params:
- `q`        : Such-Term (Pflicht fuer sinnvolle Treffer; ohne `q` zeigen
               wir eine leere Trefferliste mit Hinweis).
- `kind`     : `cve|package|server|auto` (Default `auto`). `auto` versucht
               eine CVE-ID-Regex; matcht sie, ist es CVE-Suche; sonst
               wird sowohl Paket- als auch Server-Substring gesucht.
- `tag`      : Mehrfach (oder comma-separated). Filtert auf Findings deren
               Server mindestens eines dieser Tags traegt (OR-Semantik).
- `status`   : Whitelist `open|acknowledged|resolved|all` (Default `all`).
- `page`     : 1-basiert, Default 1.
- `per_page` : Default 50, Max 200.

Template-Variablen-Vertrag (`findings/search.html`):

- `q`              : str (Eingabe; bereits beschnitten)
- `kind`           : Literal["cve","package","server","auto"]
- `effective_kind` : Literal["cve","package","server","empty"]
                     — was wir tatsaechlich gesucht haben (fuer UI-Hinweis).
- `results`        : list[SearchHit] (siehe Dataclass)
- `aggregation`    : SearchAggregation | None — befuellt nur bei
                     `effective_kind == 'cve'`.
- `tag`            : list[str] (Filter aktiv)
- `status`         : Literal["open","acknowledged","resolved","all"]
- `page`           : int
- `per_page`       : int
- `total`          : int (alle Treffer ohne Pagination)
- `available_tags` : list[Tag]
- `bulk_form`      : CSRFOnlyForm — Token fuer den Modal-Submit
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

import structlog
from flask import Blueprint, render_template, request
from flask_login import login_required
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.db import get_session
from app.forms import CSRFOnlyForm
from app.models import Finding, FindingStatus, Server, ServerTag, Tag

log = structlog.get_logger(__name__)

search_bp = Blueprint("search", __name__, url_prefix="/findings")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_VALID_KINDS: frozenset[str] = frozenset({"cve", "package", "server", "auto"})
_VALID_STATUS: frozenset[str] = frozenset({"open", "acknowledged", "resolved", "all"})

_PER_PAGE_DEFAULT = 50
_PER_PAGE_MAX = 200

SearchKind = Literal["cve", "package", "server", "auto"]
EffectiveKind = Literal["cve", "package", "server", "empty"]


# ---------------------------------------------------------------------------
# View-Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SearchHit:
    """Eine Such-Trefferzeile.

    Wir liefern das Finding sowie eine Server-Snapshot (Name + Tag-Pills).
    Das Template macht den Rest.
    """

    finding: Finding
    server: Server


@dataclass(frozen=True)
class SearchAggregation:
    """Aggregations-Header bei CVE-Suche."""

    cve_id: str
    server_count: int
    open_count: int
    ack_count: int
    resolved_count: int

    @property
    def total(self) -> int:
        return self.open_count + self.ack_count + self.resolved_count


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _parse_tags(args: Any) -> list[str]:
    """Tag-Liste aus Query parsen — dieselbe Konvention wie auf dem Dashboard."""
    from app.forms import TAG_NAME_REGEX

    raw_list: list[str] = []
    for entry in args.getlist("tag"):
        for part in entry.split(","):
            stripped = part.strip().lower()
            if stripped and TAG_NAME_REGEX.match(stripped) and stripped not in raw_list:
                raw_list.append(stripped)
    return raw_list


def _parse_status(value: str | None) -> Literal["open", "acknowledged", "resolved", "all"]:
    if value is None:
        return "all"
    v = value.strip().lower()
    if v in _VALID_STATUS:
        return v  # type: ignore[return-value]
    return "all"


def _parse_kind(value: str | None) -> SearchKind:
    if value is None:
        return "auto"
    v = value.strip().lower()
    if v in _VALID_KINDS:
        return v  # type: ignore[return-value]
    return "auto"


def _classify(q: str, kind: SearchKind) -> EffectiveKind:
    if not q.strip():
        return "empty"
    if kind == "auto":
        if _CVE_RE.match(q.strip()):
            return "cve"
        # `auto` ohne CVE-Treffer -> Paket-Suche (Default); Server-Suche
        # bekommt der User durch explizites `kind=server`. Das vermeidet
        # die Union-Such-Verwirrung in der UI.
        return "package"
    return kind


def _apply_tag_filter(stmt: Any, tags: list[str]) -> Any:
    """Filtert Findings auf Server, die mindestens eines der Tags tragen (OR)."""
    if not tags:
        return stmt
    server_ids_sq = (
        select(ServerTag.server_id)
        .join(Tag, Tag.id == ServerTag.tag_id)
        .where(Tag.name.in_(tags))
        .scalar_subquery()
    )
    return stmt.where(Finding.server_id.in_(server_ids_sq))


def _apply_status_filter(
    stmt: Any,
    status: Literal["open", "acknowledged", "resolved", "all"],
) -> Any:
    if status == "all":
        return stmt
    enum_value = {
        "open": FindingStatus.OPEN,
        "acknowledged": FindingStatus.ACKNOWLEDGED,
        "resolved": FindingStatus.RESOLVED,
    }[status]
    return stmt.where(Finding.status == enum_value)


def _build_query(
    *,
    effective_kind: EffectiveKind,
    q: str,
    tags: list[str],
    status: Literal["open", "acknowledged", "resolved", "all"],
) -> Any:
    """Liefert die Basis-Query fuer die Suche (ohne Limit/Offset)."""
    stmt = select(Finding).options(selectinload(Finding.server))

    if effective_kind == "cve":
        stmt = stmt.where(Finding.identifier_key == q.strip())
    elif effective_kind == "package":
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(Finding.package_name.ilike(pattern))
    elif effective_kind == "server":
        pattern = f"%{q.strip()}%"
        server_ids_sq = select(Server.id).where(Server.name.ilike(pattern)).scalar_subquery()
        stmt = stmt.where(Finding.server_id.in_(server_ids_sq))
    else:  # empty
        # Bewusst eine Bedingung die immer false ist, damit das Template
        # eine leere Trefferliste sieht und seinen Hinweis zeigt.
        stmt = stmt.where(Finding.id < 0)

    stmt = _apply_tag_filter(stmt, tags)
    stmt = _apply_status_filter(stmt, status)
    return stmt


def _aggregate_cve(
    session: Session,
    *,
    cve_id: str,
    tags: list[str],
) -> SearchAggregation:
    """Aggregations-Counts fuer CVE-Suche."""
    status_stmt = (
        select(Finding.status, func.count(Finding.id))
        .where(Finding.identifier_key == cve_id)
        .group_by(Finding.status)
    )
    status_stmt = _apply_tag_filter(status_stmt, tags)
    rows = session.execute(status_stmt).all()
    counts = {"open": 0, "acknowledged": 0, "resolved": 0}
    for status, n in rows:
        if status == FindingStatus.OPEN:
            counts["open"] = int(n)
        elif status == FindingStatus.ACKNOWLEDGED:
            counts["acknowledged"] = int(n)
        elif status == FindingStatus.RESOLVED:
            counts["resolved"] = int(n)

    server_stmt = select(func.count(func.distinct(Finding.server_id))).where(
        Finding.identifier_key == cve_id
    )
    server_stmt = _apply_tag_filter(server_stmt, tags)
    server_count = int(session.execute(server_stmt).scalar() or 0)

    return SearchAggregation(
        cve_id=cve_id,
        server_count=server_count,
        open_count=counts["open"],
        ack_count=counts["acknowledged"],
        resolved_count=counts["resolved"],
    )


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@search_bp.get("/search")
@login_required
def search() -> Any:
    sess = get_session()

    q_raw = (request.args.get("q") or "").strip()[:128]
    kind = _parse_kind(request.args.get("kind"))
    status = _parse_status(request.args.get("status"))
    tags = _parse_tags(request.args)

    try:
        page = max(1, int(request.args.get("page", "1")))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = int(request.args.get("per_page", str(_PER_PAGE_DEFAULT)))
    except (TypeError, ValueError):
        per_page = _PER_PAGE_DEFAULT
    per_page = max(1, min(per_page, _PER_PAGE_MAX))

    effective_kind = _classify(q_raw, kind)

    aggregation: SearchAggregation | None = None
    if effective_kind == "cve":
        aggregation = _aggregate_cve(sess, cve_id=q_raw, tags=tags)

    base_stmt = _build_query(
        effective_kind=effective_kind,
        q=q_raw,
        tags=tags,
        status=status,
    )

    # Total fuer Pagination — `count(*)` ueber eine wiederverwendete Subquery.
    total_stmt = select(func.count()).select_from(base_stmt.subquery())
    total = int(sess.execute(total_stmt).scalar() or 0)

    # Sortierung: KEV zuerst, dann Severity-Rank (numerisch), dann
    # first_seen_at desc. Sehr aehnlich zum Server-Detail-Default, aber wir
    # tauschen `first_seen_at asc` gegen `desc`, damit die juengsten oben
    # auftauchen — das passt zu globaler Suche besser.
    from sqlalchemy import case

    from app.models import Severity

    sev_rank = case(
        (Finding.severity == Severity.CRITICAL, 4),
        (Finding.severity == Severity.HIGH, 3),
        (Finding.severity == Severity.MEDIUM, 2),
        (Finding.severity == Severity.LOW, 1),
        (Finding.severity == Severity.UNKNOWN, 0),
        else_=0,
    )

    page_stmt = (
        base_stmt.order_by(
            Finding.is_kev.desc(),
            sev_rank.desc(),
            Finding.first_seen_at.desc(),
        )
        .offset((page - 1) * per_page)
        .limit(per_page)
    )

    rows = list(sess.execute(page_stmt).scalars().all())
    results = [SearchHit(finding=f, server=f.server) for f in rows]

    available_tags = list(sess.execute(select(Tag).order_by(Tag.name)).scalars().all())

    log.info(
        "search.executed",
        q=q_raw,
        kind=kind,
        effective_kind=effective_kind,
        total=total,
        page=page,
    )

    # Bei Status-Filter `all` ist `or_` oben ein No-Op — wir lassen Pylance
    # ruhig (Import oben).
    _ = or_

    return render_template(
        "findings/search.html",
        q=q_raw,
        kind=kind,
        effective_kind=effective_kind,
        results=results,
        aggregation=aggregation,
        tag=tags,
        status=status,
        page=page,
        per_page=per_page,
        total=total,
        available_tags=available_tags,
        bulk_form=CSRFOnlyForm(),
    )


__all__ = ["search_bp"]
