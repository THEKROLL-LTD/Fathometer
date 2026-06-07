# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pro-Server ESCALATE/ACT-Count-Aggregation fuer den Sidebar-Polling-Endpoint.

Liefert fuer jeden Server-ID die Anzahl OPEN-Findings in den Risk-Bands
'escalate' und 'act'. Wird ausschliesslich vom Polling-Endpoint
`/_partials/sidebar` genutzt (Phase C, ADR-0030 Befund 8).

Eine einzige GROUP-BY-Query; leere `server_ids` werden ohne DB-Roundtrip
als leeres Dict zurueckgegeben.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Finding, FindingStatus


def escalate_act_counts_by_server(
    session: Session,
    server_ids: list[int],
) -> dict[int, dict[str, int]]:
    """Pro Server ein Dict mit Keys 'escalate' und 'act' (Counts OPEN-Findings).

    Server ohne entsprechende Findings fehlen im Result-Dict — der Aufrufer
    muss `.get(sid, {})` handhaben.

    Argumente:
      `session`    — aktive SQLAlchemy-Session.
      `server_ids` — Liste der Server-IDs fuer den IN-Filter. Leere Liste
                     gibt sofort ein leeres Dict zurueck, ohne Query.

    Rueckgabe: ``{server_id: {"escalate": n, "act": m}}``. Keys 'escalate'
    und 'act' sind nur gesetzt wenn der jeweilige Count > 0.
    """
    if not server_ids:
        return {}

    stmt = (
        select(
            Finding.server_id,
            Finding.risk_band,
            func.count(Finding.id).label("n"),
        )
        .where(
            Finding.status == FindingStatus.OPEN,
            Finding.risk_band.in_(["escalate", "act"]),
            Finding.server_id.in_(server_ids),
        )
        .group_by(Finding.server_id, Finding.risk_band)
    )

    result: dict[int, dict[str, int]] = {}
    for row in session.execute(stmt).all():
        sid: int = row.server_id
        band: str = row.risk_band
        count: int = row.n
        if sid not in result:
            result[sid] = {}
        result[sid][band] = count

    return result


__all__ = ["escalate_act_counts_by_server"]
