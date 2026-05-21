"""Vererbung von ApplicationGroup-Risk-Bands auf Findings.

Block P bewertet Risk final auf Group-Ebene. Dieser Service denormalisiert das
Verdict auf ``findings.risk_band``, damit bestehende Queries/Filter ohne Join
korrekte Werte sehen.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from sqlalchemy import func, update

from app.models import ApplicationGroup, Finding

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def inherit_group_risk_to_findings(
    session: Session,
    *,
    group_ids: Sequence[int] | None = None,
    server_id: int | None = None,
) -> int:
    """Setzt Finding-Risk-Bands auf das Verdict der zugeordneten Group.

    Der Service ist idempotent und transaktionsneutral: er fuehrt keinen
    Commit aus. Caller behalten ihre bestehende Transaktionsgrenze.
    """
    session.flush()
    stmt = (
        update(Finding)
        .where(Finding.application_group_id == ApplicationGroup.id)
        .where(ApplicationGroup.risk_band.is_not(None))
        .where(
            (Finding.risk_band.is_distinct_from(ApplicationGroup.risk_band))
            | (Finding.risk_band_source.is_distinct_from("llm"))
            | (Finding.risk_band_reason.is_distinct_from(ApplicationGroup.risk_band_reason))
        )
        .values(
            risk_band=ApplicationGroup.risk_band,
            risk_band_reason=ApplicationGroup.risk_band_reason,
            risk_band_source="llm",
            risk_band_computed_at=func.now(),
        )
        .execution_options(synchronize_session=False)
    )
    if group_ids is not None:
        stmt = stmt.where(ApplicationGroup.id.in_(list(group_ids)))
    if server_id is not None:
        stmt = stmt.where(Finding.server_id == server_id)

    result = session.execute(stmt)
    rowcount = getattr(result, "rowcount", 0)
    return int(rowcount or 0)


__all__ = ["inherit_group_risk_to_findings"]
