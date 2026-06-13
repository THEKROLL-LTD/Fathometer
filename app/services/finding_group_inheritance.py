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

**Lane-Match (ADR-0053, erweitert ADR-0061):** Pass 2 bewertet pro Fix-Lane —
die Junction haelt bis zu drei Rows pro ``(group, server)`` (``fix_lane`` in
{``patch``, ``upstream``, ``mitigate``}). Der Join joint deshalb zusaetzlich
auf die Lane: ein Finding erbt aus der Junction-Row **seiner eigenen** Lane.
Die Lane folgt deterministisch aus ``Finding.finding_class`` UND
``Finding.has_fix`` ueber den Single-Source-SQL-Spiegel
:func:`risk_engine.fix_lane_sql_case`: ``not has_fix`` → ``mitigate``,
``has_fix`` AND ``os-pkgs`` → ``patch``, ``has_fix`` AND ``lang-pkgs``/``other``
→ ``upstream``. Kern-Gewinn: patchbare, upstream-only und nicht-fixbare Findings
**derselben** Group koennen jetzt **unterschiedliche** Bands tragen.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from sqlalchemy import func, update

from app.models import ApplicationGroupEvaluation, Finding
from app.services.risk_engine import fix_lane_sql_case

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

    Lane-Match (ADR-0053, erweitert ADR-0061): zusaetzlich
    ``Junction.fix_lane == fix_lane_sql_case(finding_class, has_fix)`` —
    ein os-pkgs-Fix-Finding erbt aus der ``patch``-Row, ein
    lang-pkgs/other-Fix-Finding aus der ``upstream``-Row, ein no-fix Finding
    aus der ``mitigate``-Row **derselben** Group; alle koennen unterschiedliche
    Bands tragen. Der CASE ist die Single-Source aus :mod:`risk_engine`,
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
            == fix_lane_sql_case(
                Finding.finding_class,
                Finding.has_fix,
                Finding.host_update_available,
            )
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
