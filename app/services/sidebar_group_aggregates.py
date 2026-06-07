# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Group-Aggregat-Counts fuer Sidebar-Section-Header (Block W, ADR-0034).

Liefert pro `group_id` (inkl. NULL = ungrouped) die Summen:
  - `server_count` (key: 'hosts') — Anzahl Server in der Gruppe
  - `escalate_count` (key: 'escalate') — OPEN-Findings mit risk_band='escalate'
  - `act_count` (key: 'act') — OPEN-Findings mit risk_band='act'

Eine einzige GROUP-BY-Query — kein Per-Server-Loop. Pattern ist analog zu
`escalate_act_counts_by_server` in `sidebar_risk_counts.py`.

Rückgabeformat (ADR-0034 §Aggregat-Counts):
  `{group_id: {"escalate": n, "act": m, "hosts": h}}`

NULL-Group-Bucket: Server ohne Gruppe (`group_id IS NULL`) werden unter dem
Key `None` aggregiert — der Aufrufer kann diesen Wert fuer den globalen
Header-Counter nutzen (ungrouped-Sektion hat keinen eigenen Group-Header).
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Finding, FindingStatus, Server

# Typ-Alias fuer einen einzelnen Group-Aggregate-Eintrag.
# Schluessel: 'escalate', 'act', 'hosts'.
GroupCounts = dict[str, int]


def group_counts(session: Session) -> dict[int | None, GroupCounts]:
    """Liefert aggregierte Counts pro group_id (inkl. NULL = ungrouped).

    Eine einzige JOIN+GROUP-BY-Query — kein Round-Trip pro Server, kein
    Per-Finding-Loop. Gibt immer ein Dict zurueck; falls kein Server
    existiert: leeres Dict.

    Rueckgabe: ``{group_id: {"escalate": n, "act": m, "hosts": h}}``.
      - ``group_id = None`` entspricht ungrouped Servern.
      - ``group_id = N``    entspricht Server-Group mit ``id = N``.

    Server ohne Findings tauchen im Counts-Dict trotzdem auf, weil der
    JOIN von `servers` ausgeht (LEFT JOIN auf findings). Das ermoeglicht
    dem Template korrekte `hosts`-Werte auch fuer leere Gruppen.
    """
    # Aeussere Query: Anzahl Server + ESCALATE/ACT-Counts pro group_id.
    # LEFT JOIN auf findings damit Server ohne Findings trotzdem gezaehlt werden.
    stmt = (
        select(
            Server.group_id,
            func.count(Server.id.distinct()).label("server_count"),
            func.count(Finding.id)
            .filter(
                Finding.status == FindingStatus.OPEN,
                Finding.risk_band == "escalate",
            )
            .label("escalate_count"),
            func.count(Finding.id)
            .filter(
                Finding.status == FindingStatus.OPEN,
                Finding.risk_band == "act",
            )
            .label("act_count"),
        )
        .outerjoin(Finding, Finding.server_id == Server.id)
        .group_by(Server.group_id)
    )

    result: dict[int | None, GroupCounts] = {}
    for row in session.execute(stmt).all():
        gid: int | None = row.group_id
        result[gid] = {
            "escalate": row.escalate_count,
            "act": row.act_count,
            "hosts": row.server_count,
        }
    return result


__all__ = ["GroupCounts", "group_counts"]
