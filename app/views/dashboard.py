"""Dashboard-View `/` — Server-Karten mit Tag-Filter und Aufmerksamkeits-Sektion.

ARCHITECTURE.md §7 + §14 + §15.

Datenfluss:
1. Filter aus Query-String parsen (`DashboardFilter.from_request`).
2. Alle Server mit eager-loaded Tag-Links laden (selectinload — vermeidet
   N+1).
3. EINE Aggregations-Query: OPEN-Findings pro `(server_id, severity)` zaehlen,
   inklusive KEV-Counter pro Server (eigene Aggregation).
4. Filter anwenden (Tags via Set-Ops im Python, KEV/Stale post-query).
5. "Aufmerksamkeit noetig" zusammenstellen (stale, KEV, db-stale) und
   deduplizieren.

Der `frontend-implementer` baut auf die unten dokumentierten Dataclasses
auf — die Variablen-Vertraege sind im Block-Plan beschrieben.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from flask import Blueprint, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.db import get_session
from app.models import Finding, FindingStatus, Server, ServerTag, Severity, Tag
from app.schemas.dashboard_filter import DashboardFilter
from app.services.stale_detection import (
    get_db_stale_threshold_h,
    is_db_stale,
    is_stale,
)
from app.settings_service import get_settings_row

log = structlog.get_logger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)


# ---------------------------------------------------------------------------
# View-Models — die Templates konsumieren diese Strukturen.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SeverityCounts:
    """OPEN-Findings nach Severity-Bucket. Default: alles 0."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unknown

    @property
    def above_threshold(self) -> int:
        """Counts kumuliert ab einer Schwelle — Template kann das nutzen."""
        return self.total


@dataclass
class ServerCardData:
    """Render-Daten fuer eine Server-Karte.

    Felder bleiben mutable, damit der Builder sie schrittweise befuellen
    kann. `severity_counts` ist nach Initialisierung effektiv read-only.
    """

    server: Server
    severity_counts: SeverityCounts = field(default_factory=SeverityCounts)
    kev_open_count: int = 0
    is_stale: bool = False
    is_db_stale: bool = False
    is_active: bool = True  # nicht revoked und nicht retired

    @property
    def highest_severity(self) -> Severity | None:
        """Hoechste offene Severity — fuer Karten-Badge-Farbe."""
        if self.severity_counts.critical:
            return Severity.CRITICAL
        if self.severity_counts.high:
            return Severity.HIGH
        if self.severity_counts.medium:
            return Severity.MEDIUM
        if self.severity_counts.low:
            return Severity.LOW
        if self.severity_counts.unknown:
            return Severity.UNKNOWN
        return None

    @property
    def needs_attention(self) -> bool:
        return self.is_stale or self.is_db_stale or self.kev_open_count > 0


@dataclass
class AttentionSection:
    """Drei Buckets fuer die "Aufmerksamkeit noetig"-Sektion.

    Ein Server kann in mehreren Buckets erscheinen — das Template entscheidet
    ueber die Darstellung. `all_cards` ist die deduplizierte Liste aller
    Karten die mindestens einen Marker tragen.
    """

    stale_servers: list[ServerCardData] = field(default_factory=list)
    kev_servers: list[ServerCardData] = field(default_factory=list)
    db_stale_servers: list[ServerCardData] = field(default_factory=list)
    all_cards: list[ServerCardData] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.all_cards


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@dashboard_bp.get("/")
@login_required
def index() -> Any:
    sess = get_session()
    now = datetime.now(tz=UTC)

    filt = DashboardFilter.from_request(request.args)
    settings_row = get_settings_row(sess)
    severity_threshold = filt.severity or settings_row.severity_threshold
    db_stale_h = get_db_stale_threshold_h()

    # Alle Tags fuer den Filter-Chip-Bereich — egal welcher Filter aktiv ist.
    available_tags = sess.execute(select(Tag).order_by(Tag.name)).scalars().all()

    servers = _load_servers(sess)
    counts_by_server, kev_by_server = _load_open_aggregates(sess)

    cards: list[ServerCardData] = []
    for srv in servers:
        is_active = srv.revoked_at is None and srv.retired_at is None
        card = ServerCardData(
            server=srv,
            severity_counts=counts_by_server.get(srv.id, SeverityCounts()),
            kev_open_count=kev_by_server.get(srv.id, 0),
            is_stale=is_stale(srv, now=now) if is_active else False,
            is_db_stale=(is_db_stale(srv, now=now, threshold_h=db_stale_h) if is_active else False),
            is_active=is_active,
        )
        cards.append(card)

    visible = _apply_filters(cards, filt)
    attention = _build_attention(cards)

    # SSE-Endpoint-URL fuer das Frontend. Block H — Live-Updates.
    try:
        events_url = url_for("events.stream_events")
    except Exception:  # pragma: no cover — Endpoint nicht registriert (Tests)
        events_url = "/events"

    return render_template(
        "dashboard/index.html",
        servers=visible,
        attention=attention,
        filter=filt,
        available_tags=available_tags,
        severity_threshold=severity_threshold,
        db_stale_threshold_h=db_stale_h,
        events_url=events_url,
    )


# ---------------------------------------------------------------------------
# Loader-Helper
# ---------------------------------------------------------------------------


def _load_servers(sess: Session) -> list[Server]:
    """Laedt alle Server inklusive Tag-Links (eager).

    Sort: aktive Server zuerst (alphabetisch nach Name), dann retired/revoked
    am Ende. Das macht das Dashboard im Default-Zustand vorhersehbar.
    """
    stmt = (
        select(Server)
        .options(selectinload(Server.tag_links).selectinload(ServerTag.tag))
        .order_by(Server.retired_at.isnot(None), Server.name.asc())
    )
    return list(sess.execute(stmt).scalars().unique().all())


def _load_open_aggregates(
    sess: Session,
) -> tuple[dict[int, SeverityCounts], dict[int, int]]:
    """Eine SQL-Query fuer Severity-Counts, zweite fuer KEV-Counts.

    Wir koennten beides in einer Query mit `FILTER (WHERE ...)` machen, aber
    zwei klare Queries sind lesbarer und vermeiden eine unschoene
    SQL-Struktur. Beide Queries skalieren mit `count(servers)`, nicht mit
    `count(findings)` — daher reicht das.
    """
    counts: dict[int, SeverityCounts] = {}

    sev_stmt = (
        select(
            Finding.server_id,
            Finding.severity,
            func.count(Finding.id).label("n"),
        )
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.server_id, Finding.severity)
    )
    rows = sess.execute(sev_stmt).all()

    # Map: server_id -> dict[severity_value -> count]
    interim: dict[int, dict[str, int]] = {}
    for server_id, severity, n in rows:
        interim.setdefault(server_id, {})[severity.value] = int(n)

    for server_id, by_sev in interim.items():
        counts[server_id] = SeverityCounts(
            critical=by_sev.get(Severity.CRITICAL.value, 0),
            high=by_sev.get(Severity.HIGH.value, 0),
            medium=by_sev.get(Severity.MEDIUM.value, 0),
            low=by_sev.get(Severity.LOW.value, 0),
            unknown=by_sev.get(Severity.UNKNOWN.value, 0),
        )

    kev_stmt = (
        select(Finding.server_id, func.count(Finding.id).label("n"))
        .where(Finding.status == FindingStatus.OPEN)
        .where(Finding.is_kev.is_(True))
        .group_by(Finding.server_id)
    )
    kev_counts: dict[int, int] = {row.server_id: int(row.n) for row in sess.execute(kev_stmt).all()}
    return counts, kev_counts


# ---------------------------------------------------------------------------
# Filter und Aufmerksamkeit
# ---------------------------------------------------------------------------


def _apply_filters(cards: list[ServerCardData], filt: DashboardFilter) -> list[ServerCardData]:
    result: Iterable[ServerCardData] = cards

    if filt.tags:
        wanted = set(filt.tags)
        if filt.tags_mode == "and":
            result = [c for c in result if wanted.issubset(_card_tag_names(c))]
        else:
            result = [c for c in result if wanted.intersection(_card_tag_names(c))]

    if filt.kev_only:
        result = [c for c in result if c.kev_open_count > 0]

    if filt.stale_only:
        result = [c for c in result if c.is_stale]

    return list(result)


def _card_tag_names(card: ServerCardData) -> set[str]:
    return {link.tag.name for link in card.server.tag_links}


def _build_attention(cards: list[ServerCardData]) -> AttentionSection:
    section = AttentionSection()
    seen: set[int] = set()
    for card in cards:
        if not card.is_active:
            continue
        any_marker = False
        if card.is_stale:
            section.stale_servers.append(card)
            any_marker = True
        if card.kev_open_count > 0:
            section.kev_servers.append(card)
            any_marker = True
        if card.is_db_stale:
            section.db_stale_servers.append(card)
            any_marker = True
        if any_marker and card.server.id not in seen:
            section.all_cards.append(card)
            seen.add(card.server.id)
    return section


__all__ = [
    "AttentionSection",
    "ServerCardData",
    "SeverityCounts",
    "dashboard_bp",
]
