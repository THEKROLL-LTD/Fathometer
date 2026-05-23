"""Dashboard-View `/` — Risk-KPI-Uebersicht mit Server-Filter-Counter.

ARCHITECTURE.md §7 + §14 + §15.

Datenfluss:
1. Filter aus Query-String parsen (`DashboardFilter.from_request`).
2. Alle Server mit eager-loaded Tag-Links laden (selectinload — vermeidet
   N+1).
3. Eine konsolidierte Aggregations-Query: OPEN-Findings pro server_id mit
   FILTER-Aggregaten fuer KEV und alle risk_bands. Liefert `kev_by_server`
   und `risk_bands_by_server`.
4. Filter anwenden (Tags via Set-Ops im Python, KEV/Stale post-query).
5. Risk-KPIs fuer das aktuelle Dashboard-Markup laden.

Der `frontend-implementer` baut auf die unten dokumentierten Dataclasses
auf — die Variablen-Vertraege sind im Block-Plan beschrieben.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from flask import Blueprint, render_template, request
from flask_login import login_required
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.db import get_session
from app.models import (
    Finding,
    FindingStatus,
    Server,
    ServerTag,
    Severity,
)
from app.schemas.dashboard_filter import DashboardFilter
from app.services.risk_engine import yes_band_values
from app.services.stale_detection import (
    is_stale,
)
from app.views._sidebar_context import is_hx_request

log = structlog.get_logger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)


# ---------------------------------------------------------------------------
# View-Models — die Templates konsumieren diese Strukturen.
# ---------------------------------------------------------------------------


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

    Wird aktuell nur noch fuer die sichtbare Server-Anzahl und Filterlogik
    genutzt; die fruehere Karten-UI ist auf die Sidebar gewandert.
    """

    server: Server
    kev_open_count: int = 0
    is_stale: bool = False
    is_active: bool = True  # nicht revoked und nicht retired


# ---------------------------------------------------------------------------
# Risk-KPI-Loader (Block O, ADR-0022 §UI-Redesign)
# ---------------------------------------------------------------------------


def _load_risk_kpi_counters(
    sess: Session,
    risk_bands_by_server: dict[int, dict[str, int]],
    active_server_ids: set[int],
) -> RiskKpiCounters:
    """Baut die KPI-Counter fuer Action-Required-Cards, Band-Pills und
    Severity-Strip.

    Phase D (ADR-0030 Befund 5): vorher 4 Queries, jetzt 2 Queries.

    1. Eine konsolidierte Findings-Query mit COUNT(*) FILTER (...) pro
       risk_band-Bucket UND pro severity-Wert (alle OPEN).
    2. Total aktive Server (nicht retired, nicht revoked) — operiert auf
       `servers`-Tabelle, bleibt eigenstaendig.

    `yes_servers` wird aus dem bereits berechneten `risk_bands_by_server`
    (Ergebnis von `_load_open_aggregates`) abgeleitet — kein separater
    Distinct-Count-JOIN mehr noetig (Variante a gemaess Block-V-Spec §Phase D).

    Phase-D-Fix (ADR-0030 Befund 5 Folge): `active_server_ids` schliesst den
    Revoke-Drift. Nur Server in diesem Set werden bei `action_yes_servers`
    gezaehlt. Ein revoked Server mit historischen OPEN-Findings taucht in
    `risk_bands_by_server` auf, wird aber hier herausgefiltert, sodass
    `action_yes_servers <= total_active` immer gilt.
    """
    yes_bands = set(yes_band_values())

    # 1. Konsolidierte Findings-Query: fleet-weite risk_band- und
    #    severity-Buckets als FILTER-Aggregate in einem einzigen Seq Scan.
    findings_stmt = select(
        func.count().filter(Finding.risk_band == "escalate").label("rb_escalate"),
        func.count().filter(Finding.risk_band == "act").label("rb_act"),
        func.count().filter(Finding.risk_band == "mitigate").label("rb_mitigate"),
        func.count().filter(Finding.risk_band == "pending").label("rb_pending"),
        func.count().filter(Finding.risk_band == "unknown").label("rb_unknown"),
        func.count().filter(Finding.risk_band == "monitor").label("rb_monitor"),
        func.count().filter(Finding.risk_band == "noise").label("rb_noise"),
        func.count().filter(Finding.severity == Severity.CRITICAL).label("sev_critical"),
        func.count().filter(Finding.severity == Severity.HIGH).label("sev_high"),
        func.count().filter(Finding.severity == Severity.MEDIUM).label("sev_medium"),
        func.count().filter(Finding.severity == Severity.LOW).label("sev_low"),
    ).where(Finding.status == FindingStatus.OPEN)
    row = sess.execute(findings_stmt).one()

    band_counts: dict[str, int] = {
        "escalate": int(row.rb_escalate),
        "act": int(row.rb_act),
        "mitigate": int(row.rb_mitigate),
        "pending": int(row.rb_pending),
        "unknown": int(row.rb_unknown),
        "monitor": int(row.rb_monitor),
        "noise": int(row.rb_noise),
    }
    severity_strip: dict[str, int] = {
        Severity.CRITICAL.value: int(row.sev_critical),
        Severity.HIGH.value: int(row.sev_high),
        Severity.MEDIUM.value: int(row.sev_medium),
        Severity.LOW.value: int(row.sev_low),
    }

    # Yes-Sub-Counters aus band_counts ableiten (Reihenfolge: yes_band_values).
    action_yes_subcounts: dict[str, int] = {
        band: band_counts.get(band, 0) for band in yes_band_values()
    }

    # yes_servers aus den Pro-Server-Risk-Band-Daten ableiten — kein
    # separater Distinct-Count-JOIN noetig (Variante a).
    # Nur aktive Server (nicht retired, nicht revoked) werden gezaehlt,
    # damit revoked Server mit historischen OPEN-Findings nicht faelschlich
    # als action_yes_servers auftauchen (Phase-D-Fix, ADR-0030 Befund 5).
    action_yes_servers = sum(
        1
        for sid, server_bands in risk_bands_by_server.items()
        if sid in active_server_ids and any(server_bands.get(b, 0) > 0 for b in yes_bands)
    )

    # 2. Total aktive Server (eigenstaendige Query auf servers-Tabelle).
    active_servers_stmt = select(func.count(Server.id)).where(
        Server.retired_at.is_(None),
        Server.revoked_at.is_(None),
    )
    total_active = int(sess.execute(active_servers_stmt).scalar() or 0)
    action_no_servers = max(0, total_active - action_yes_servers)

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
    servers = _load_servers(sess)
    kev_by_server, risk_bands_by_server = _load_open_aggregates(sess)

    cards: list[ServerCardData] = []
    for srv in servers:
        is_active = srv.revoked_at is None and srv.retired_at is None
        card = ServerCardData(
            server=srv,
            kev_open_count=kev_by_server.get(srv.id, 0),
            is_stale=is_stale(srv, now=now) if is_active else False,
            is_active=is_active,
        )
        cards.append(card)

    visible = _apply_filters(cards, filt)

    # Sidebar-Variablen werden via Context-Processor injiziert
    # (`_inject_sidebar_context` in app/__init__.py).
    #
    # Block O (ADR-0022): Risk-KPI-Counter fuer Action-Required-Cards,
    # Risk-Band-Pills und Severity-Strip. Phase D: risk_bands_by_server aus
    # _load_open_aggregates weitergeben, damit yes_servers ohne separaten
    # Distinct-Count-JOIN ableitbar ist.
    # Phase-D-Fix: active_server_ids aus der bereits geladenen servers-Liste
    # ableiten, damit revoked Server mit OPEN-Findings nicht mitgezaehlt werden.
    active_server_ids = {
        srv.id for srv in servers if srv.retired_at is None and srv.revoked_at is None
    }
    risk_kpis = _load_risk_kpi_counters(sess, risk_bands_by_server, active_server_ids)

    return {
        "servers": visible,
        "filter": filt,
        "filter_tags": filt.tags,
        # Block O (ADR-0022).
        "risk_kpis": risk_kpis,
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
) -> tuple[dict[int, int], dict[int, dict[str, int]]]:
    """EINE konsolidierte SQL-Query fuer KEV- und Risk-Band-Counts.

    Das aktuelle Dashboard-Markup braucht fuer die Server-Filterung nur KEV
    pro Server; die Risk-Band-Buckets werden fuer die Yes-Server-Ableitung in
    `_load_risk_kpi_counters` wiederverwendet.

    Rueckgabe:
      kev_by_server      — dict[server_id, int]  (Anzahl OPEN KEV-Findings)
      risk_bands_by_server — dict[server_id, dict[risk_band_str, int]]

    Das `risk_bands_by_server`-Ergebnis wird an `_load_risk_kpi_counters`
    weitergereicht, damit der yes_servers-Count ohne separaten JOIN ableitbar
    ist (Variante a gemaess Block-V-Spec §Phase D).
    """
    aggregate_stmt = (
        select(
            Finding.server_id,
            func.count().filter(Finding.is_kev.is_(True)).label("kev"),
            func.count().filter(Finding.risk_band == "escalate").label("rb_escalate"),
            func.count().filter(Finding.risk_band == "act").label("rb_act"),
            func.count().filter(Finding.risk_band == "mitigate").label("rb_mitigate"),
            func.count().filter(Finding.risk_band == "pending").label("rb_pending"),
            func.count().filter(Finding.risk_band == "unknown").label("rb_unknown"),
            func.count().filter(Finding.risk_band == "monitor").label("rb_monitor"),
            func.count().filter(Finding.risk_band == "noise").label("rb_noise"),
        )
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.server_id)
    )

    kev_counts: dict[int, int] = {}
    risk_bands_by_server: dict[int, dict[str, int]] = {}

    for row in sess.execute(aggregate_stmt).all():
        sid = int(row.server_id)
        kev_counts[sid] = int(row.kev)
        risk_bands_by_server[sid] = {
            "escalate": int(row.rb_escalate),
            "act": int(row.rb_act),
            "mitigate": int(row.rb_mitigate),
            "pending": int(row.rb_pending),
            "unknown": int(row.rb_unknown),
            "monitor": int(row.rb_monitor),
            "noise": int(row.rb_noise),
        }

    return kev_counts, risk_bands_by_server


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
    "dashboard_bp",
]
