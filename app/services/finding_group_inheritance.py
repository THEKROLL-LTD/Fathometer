# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Vererbung von Per-(group, server)-Eval-Bands auf Findings.

Pass-2 bewertet Risk pro ``(ApplicationGroup, Server)`` — die Junction-Tabelle
``application_group_evaluations`` haelt diese Bewertungen (ADR-0028, Block T).
Dieser Service denormalisiert das Verdict auf ``findings.risk_band``, damit
bestehende Queries/Filter ohne Join korrekte Werte sehen.

**Composite-Match (Block T):** Ein Finding erbt aus der Junction-Row die
seinen ``server_id`` UND seinen ``application_group_id`` matched — kein
Cross-Server-Leak mehr (im Gegensatz zur frueheren Logik, die nur auf
``group_id`` jointe und damit den last-write-wins-Bug vererbte).

Seit TICKET-012 (ADR-0054) wird ``risk_band_reason`` NICHT mehr auf Findings
vererbt — das AI-Assessment ist ausschliesslich Group-Level
(``ApplicationGroupEvaluation.risk_band_reason``).

**Lane-Match (TICKET-013, ADR-0053):** Pass 2 bewertet pro Fix-Lane — die
Junction haelt bis zu zwei Rows pro ``(group, server)`` (``fix_lane`` in
{``patch``, ``mitigate``}). Der Join joint deshalb zusaetzlich auf die Lane:
ein Finding erbt aus der Junction-Row **seiner eigenen** Lane. Die Lane folgt
deterministisch aus ``Finding.has_fix`` (die generierte Spalte
``fixed_version IS NOT NULL AND fixed_version <> ''`` — identische Semantik wie
``bool(fixed_version)`` in der Enqueue-/Worker-Partitionierung; leerer String →
``mitigate``). Kern-Gewinn: ein patchbares und ein nicht-patchbares Finding
**derselben** Group koennen jetzt **unterschiedliche** Bands tragen.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from sqlalchemy import case, func, update

from app.models import ApplicationGroupEvaluation, Finding

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def inherit_group_risk_to_findings(
    session: Session,
    *,
    group_ids: Sequence[int] | None = None,
    server_id: int | None = None,
) -> int:
    """Setzt Finding-Risk-Bands auf das Verdict der zugeordneten Junction-Row.

    Composite-Match ``(Finding.application_group_id == Junction.group_id
    AND Finding.server_id == Junction.server_id)`` — Server-A's Findings
    erben aus ``(group, A)``-Junction, B's Findings aus ``(group, B)``.

    Lane-Match (TICKET-013, ADR-0053): zusaetzlich ``Junction.fix_lane ==
    CASE WHEN Finding.has_fix THEN 'patch' ELSE 'mitigate' END`` — ein
    patchbares Finding erbt aus der ``patch``-Row, ein no-fix Finding aus der
    ``mitigate``-Row **derselben** Group; beide koennen unterschiedliche Bands
    tragen. ``has_fix`` ist die generierte Spalte (``bool(fixed_version)``),
    identisch zur Enqueue-/Worker-Partitionierung — kein Lane-Drift.

    Der Service ist idempotent und transaktionsneutral: er fuehrt keinen
    Commit aus. Caller behalten ihre bestehende Transaktionsgrenze.
    """
    session.flush()
    stmt = (
        update(Finding)
        .where(Finding.application_group_id == ApplicationGroupEvaluation.group_id)
        .where(Finding.server_id == ApplicationGroupEvaluation.server_id)
        .where(
            ApplicationGroupEvaluation.fix_lane
            == case((Finding.has_fix, "patch"), else_="mitigate")
        )
        .where(
            (Finding.risk_band.is_distinct_from(ApplicationGroupEvaluation.risk_band))
            | (Finding.risk_band_source.is_distinct_from("llm"))
        )
        .values(
            risk_band=ApplicationGroupEvaluation.risk_band,
            risk_band_source="llm",
            risk_band_computed_at=func.now(),
        )
        .execution_options(synchronize_session=False)
    )
    if group_ids is not None:
        stmt = stmt.where(ApplicationGroupEvaluation.group_id.in_(list(group_ids)))
    if server_id is not None:
        stmt = stmt.where(Finding.server_id == server_id)

    result = session.execute(stmt)
    rowcount = getattr(result, "rowcount", 0)
    return int(rowcount or 0)


__all__ = ["inherit_group_risk_to_findings"]
