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
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from sqlalchemy import func, update

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

    Der Service ist idempotent und transaktionsneutral: er fuehrt keinen
    Commit aus. Caller behalten ihre bestehende Transaktionsgrenze.
    """
    session.flush()
    stmt = (
        update(Finding)
        .where(Finding.application_group_id == ApplicationGroupEvaluation.group_id)
        .where(Finding.server_id == ApplicationGroupEvaluation.server_id)
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
