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
from flask import Blueprint, render_template, request
from flask_login import login_required
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.db import get_session
from app.forms import BulkActionForm, CSRFOnlyForm
from app.models import (
    ApplicationGroup,
    Finding,
    FindingStatus,
    Server,
    ServerTag,
    Severity,
    Tag,
)
from app.schemas.dashboard_filter import DashboardFilter
from app.services.findings_query import list_findings_cross_server
from app.services.risk_engine import RiskBand, yes_band_values
from app.services.severity_history import daily_severity_counts_fleet
from app.services.stale_detection import (
    get_db_stale_threshold_h,
    is_db_stale,
    is_stale,
)
from app.services.stale_history import daily_stale_server_counts
from app.settings_service import get_settings_row
from app.views._sidebar_context import is_hx_request

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


@dataclass(frozen=True, slots=True)
class RiskKpiCounters:
    """Aggregierte Risk-/Action-Required-Counter fuer den Dashboard-Header.

    Block O (ADR-0022) §UI-Redesign. Werte sind alle OPEN-Findings-basiert
    (status=OPEN), gefiltert auf aktive Server (nicht retired, nicht
    revoked). Filter-unabhaengig, analog zur Sparkline-Semantik aus ADR-0020.
    """

    action_yes_servers: int
    action_no_servers: int
    # Sieben Bands -> Findings-Counts. Fehlende Bands -> 0.
    risk_band_counts: dict[str, int]
    # Yes-Sub-Counters: Findings-Counts pro Yes-Band.
    action_yes_subcounts: dict[str, int]
    # Severity-Strip: CRITICAL/HIGH/MEDIUM/LOW Findings-Counts ohne UNKNOWN.
    severity_strip_counts: dict[str, int]


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


# ---------------------------------------------------------------------------
# Risk-KPI-Loader (Block O, ADR-0022 §UI-Redesign)
# ---------------------------------------------------------------------------


_ALL_BANDS: tuple[str, ...] = tuple(b.value for b in RiskBand)


def _load_risk_kpi_counters(sess: Session) -> RiskKpiCounters:
    """Baut die KPI-Counter fuer Action-Required-Cards, Band-Pills und
    Severity-Strip.

    Vier separate Queries, alle ueber `Finding.status == OPEN`:

    1. Risk-Band-Counts (Findings, GROUP BY `risk_band`).
    2. Distinct-Server-Count fuer `risk_band IN yes_bands`.
    3. Total aktive Server (nicht retired, nicht revoked) -> daraus
       `action_no_servers = total - action_yes_servers`.
    4. Severity-Strip (Findings, GROUP BY `severity`, ohne UNKNOWN).
    """
    yes_bands = yes_band_values()

    # 1. Risk-Band-Counts (Findings).
    band_stmt = (
        select(Finding.risk_band, func.count(Finding.id))
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.risk_band)
    )
    band_counts: dict[str, int] = dict.fromkeys(_ALL_BANDS, 0)
    for band_value, n in sess.execute(band_stmt).all():
        if band_value in band_counts:
            band_counts[band_value] = int(n)

    # 2. Distinct-Server-Count fuer Yes-Bands (aktive Server).
    yes_servers_stmt = (
        select(func.count(func.distinct(Finding.server_id)))
        .join(Server, Server.id == Finding.server_id)
        .where(
            Finding.status == FindingStatus.OPEN,
            Finding.risk_band.in_(yes_bands),
            Server.retired_at.is_(None),
            Server.revoked_at.is_(None),
        )
    )
    action_yes_servers = int(sess.execute(yes_servers_stmt).scalar() or 0)

    # 3. Total aktive Server.
    active_servers_stmt = select(func.count(Server.id)).where(
        Server.retired_at.is_(None),
        Server.revoked_at.is_(None),
    )
    total_active = int(sess.execute(active_servers_stmt).scalar() or 0)
    action_no_servers = max(0, total_active - action_yes_servers)

    # 4. Yes-Sub-Counters: Findings-Counts pro Yes-Band, in der Reihenfolge
    #    von yes_band_values() (escalate -> unknown).
    action_yes_subcounts: dict[str, int] = {band: band_counts.get(band, 0) for band in yes_bands}

    # 5. Severity-Strip — Findings-Counts pro Severity, ohne UNKNOWN.
    sev_stmt = (
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.severity)
    )
    severity_strip: dict[str, int] = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
    }
    for sev_value, n in sess.execute(sev_stmt).all():
        sev_key = sev_value.value if hasattr(sev_value, "value") else str(sev_value)
        if sev_key in severity_strip:
            severity_strip[sev_key] = int(n)

    return RiskKpiCounters(
        action_yes_servers=action_yes_servers,
        action_no_servers=action_no_servers,
        risk_band_counts=band_counts,
        action_yes_subcounts=action_yes_subcounts,
        severity_strip_counts=severity_strip,
    )


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


def _build_pane_context(
    sess: Session,
    filt: DashboardFilter,
    now: datetime,
) -> dict[str, Any]:
    """Sammelt alle Variablen die `dashboard/_detail_pane.html` braucht.

    ADR-0017: HX-Pfad und Full-Page-Pfad konsumieren denselben Context-Dict,
    damit das Pane-Markup identisch ist. Beide Pfade rufen diesen Helper auf
    und rendern dann jeweils ihr Outer-Template (`_detail_pane.html` direkt
    fuer HX, `index.html` mit `{% extends base_app.html %}` fuer Full-Page).
    """
    from app.services.quick_stats import get_quick_stats

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

    # Sidebar-Variablen werden via Context-Processor injiziert
    # (`_inject_sidebar_context` in app/__init__.py). Damit der Tag-Filter
    # `?tag=prod` auch die QuickStats in der Sidebar mitfiltert, ueber-
    # schreiben wir `quick_stats` und `filter_tags` hier explizit.
    quick_stats = get_quick_stats(sess, filter_tags=filt.tags or None, now=now)

    # Block M (ADR-0020): Cross-Server-Findings-Tabelle, KPI-Sparklines,
    # Stale-Sparkline. Findings-Limit hart auf 200 (Truncation-Hinweis im
    # Template). KPI-Counter bleiben filter-unabhaengig OPEN — Sparklines
    # auch flotten-weit (siehe ADR-0020 "Sparkline-Semantik").
    findings_results, findings_total = list_findings_cross_server(
        sess,
        filt,
        limit=200,
        sort=filt.sort,
        dir=filt.dir,
        now=now,
    )
    kpi_sparklines = daily_severity_counts_fleet(sess, days=50, now=now)
    stale_sparkline = daily_stale_server_counts(sess, days=50, now=now)

    # Block O (ADR-0022): Risk-KPI-Counter fuer Action-Required-Cards,
    # Risk-Band-Pills und Severity-Strip.
    risk_kpis = _load_risk_kpi_counters(sess)

    # Block P (ADR-0023): Application-Group-Library fuer den Filter-Bar-
    # Select. Alphabetisch, Cap auf 100 Eintraege — bei groesseren
    # Libraries ist der URL-Filter ohnehin der bessere Pfad.
    available_application_groups = list(
        sess.execute(select(ApplicationGroup).order_by(ApplicationGroup.label.asc()).limit(100))
        .scalars()
        .all()
    )

    return {
        "servers": visible,
        "filter": filt,
        "view_filter": filt,
        "available_tags": available_tags,
        "severity_threshold": severity_threshold,
        "db_stale_threshold_h": db_stale_h,
        "quick_stats": quick_stats,
        "filter_tags": filt.tags,
        # Block M (ADR-0020).
        "findings": findings_results,
        "findings_total": findings_total,
        "kpi_sparklines": kpi_sparklines,
        "stale_sparkline": stale_sparkline,
        "bulk_form": BulkActionForm(),
        "csrf_form": CSRFOnlyForm(),
        # Block O (ADR-0022).
        "risk_kpis": risk_kpis,
        # Block P (ADR-0023).
        "available_application_groups": available_application_groups,
    }


@dashboard_bp.get("/")
@login_required
def index() -> Any:
    sess = get_session()
    now = datetime.now(tz=UTC)

    filt = DashboardFilter.from_request(request.args)
    ctx = _build_pane_context(sess, filt, now)

    # ADR-0017: beide Pfade rendern denselben Pane-Inhalt. Der HX-Pfad
    # liefert nur das Pane-Fragment (fuer `hx-target="#detail-pane"`); der
    # Full-Page-Pfad rendert `dashboard/index.html`, das via
    # `{% extends "base_app.html" %}` Sidebar/Header drumherum legt und im
    # `{% block detail_pane %}` dasselbe Partial inkludiert.
    template = "dashboard/_detail_pane.html" if is_hx_request(request) else "dashboard/index.html"
    return render_template(template, **ctx)


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


__all__ = [
    "RiskKpiCounters",
    "ServerCardData",
    "SeverityCounts",
    "dashboard_bp",
]
