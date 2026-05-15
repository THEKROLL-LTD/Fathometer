"""Quick-Stats-Service fuer die Sidebar (Block I, ARCHITECTURE.md §7a).

Fuenf Counter werden oben in der Sidebar gerendert:

- `total_open`   — Anzahl aller OPEN-Findings (ueber alle sichtbaren Server).
- `kev_open`     — Anzahl OPEN-Findings mit `is_kev=True`.
- `critical_open`— Anzahl OPEN-Findings mit `severity = CRITICAL`.
- `high_open`    — Anzahl OPEN-Findings mit `severity = HIGH`.
- `stale_servers`— Anzahl Server die als stale gelten (Block-D-Logik aus
                   `stale_detection.is_stale`).

Der Tag-Filter wirkt nur auf Findings/Server — wenn `filter_tags` gesetzt,
werden nur Findings auf Servern gezaehlt deren Tag mindestens einen der
Werte traegt (OR-Semantik, identisch zur Such-/Dashboard-Konvention).

ORM-only, eine Aggregations-Query fuer die vier Findings-Counter mit
`COUNT(*) FILTER (WHERE …)`. Der `stale_servers`-Counter laeuft separat,
weil er auf `Server.last_scan_at` operiert und nicht ueber Findings
aggregierbar ist.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models import Finding, FindingStatus, Server, ServerTag, Severity, Tag
from app.services.stale_detection import is_stale


@dataclass(frozen=True, slots=True)
class QuickStats:
    """Fuenf-Counter-Tupel fuer die Sidebar-Quick-Stats."""

    total_open: int
    kev_open: int
    critical_open: int
    high_open: int
    stale_servers: int


def _server_ids_for_tags(session: Session, tags: list[str]) -> list[int]:
    """Liefert IDs aller Server die mindestens eines der Tags tragen (OR)."""
    stmt = (
        select(ServerTag.server_id)
        .join(Tag, Tag.id == ServerTag.tag_id)
        .where(Tag.name.in_(tags))
        .distinct()
    )
    return list(session.execute(stmt).scalars().all())


def get_quick_stats(
    session: Session,
    filter_tags: list[str] | None = None,
    now: datetime | None = None,
) -> QuickStats:
    """Berechnet die fuenf Counter mit optionalem Tag-Filter (OR-Semantik).

    `filter_tags` als `None` oder leere Liste -> kein Tag-Filter
    (gesamte Flotte). `now` wird ausschliesslich fuer den `stale_servers`-
    Counter weitergereicht (Test-Determinismus).
    """
    current = now if now is not None else datetime.now(tz=UTC)
    tags = filter_tags or []

    # Optional: Sub-Set Server-IDs fuer den Tag-Filter.
    restrict_server_ids: list[int] | None = None
    if tags:
        restrict_server_ids = _server_ids_for_tags(session, tags)
        if not restrict_server_ids:
            # Filter aktiv, aber keine matchenden Server -> alles 0.
            return QuickStats(0, 0, 0, 0, 0)

    # Eine Aggregations-Query mit FILTER-Clauses fuer die Findings-Counter.
    is_kev_filter = Finding.is_kev.is_(True)
    sev_crit = Finding.severity == Severity.CRITICAL
    sev_high = Finding.severity == Severity.HIGH

    stmt = select(
        func.count().filter(Finding.status == FindingStatus.OPEN).label("total_open"),
        func.count().filter(Finding.status == FindingStatus.OPEN, is_kev_filter).label("kev_open"),
        func.count().filter(Finding.status == FindingStatus.OPEN, sev_crit).label("critical_open"),
        func.count().filter(Finding.status == FindingStatus.OPEN, sev_high).label("high_open"),
    )
    if restrict_server_ids is not None:
        stmt = stmt.where(Finding.server_id.in_(restrict_server_ids))

    row = session.execute(stmt).one()
    total_open = int(row.total_open or 0)
    kev_open = int(row.kev_open or 0)
    critical_open = int(row.critical_open or 0)
    high_open = int(row.high_open or 0)

    # Stale-Server-Counter — nur ueber Server die aktiv sind (nicht retired,
    # nicht revoked). Tag-Filter, falls aktiv, schraenkt die Menge ein.
    srv_stmt = select(Server).where(
        Server.retired_at.is_(None),
        Server.revoked_at.is_(None),
    )
    if restrict_server_ids is not None:
        srv_stmt = srv_stmt.where(Server.id.in_(restrict_server_ids))

    servers = list(session.execute(srv_stmt).scalars().all())
    stale_count = sum(1 for srv in servers if is_stale(srv, now=current))

    # `case` wird hier nicht gebraucht — Import bleibt fuer kuenftige
    # Erweiterung sichtbar.
    _ = case

    return QuickStats(
        total_open=total_open,
        kev_open=kev_open,
        critical_open=critical_open,
        high_open=high_open,
        stale_servers=stale_count,
    )


__all__ = ["QuickStats", "get_quick_stats"]
