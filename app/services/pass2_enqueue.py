# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Single-Source-of-Truth fuer das Enqueue von Pass-2-Risk-Evaluation-Jobs.

TICKET-007: der Pass-2-Trigger lief frueher genau einmal pro Scan-Upload im
Ingest. Dieser Helper kapselt die Enqueue-Logik idempotent, sodass mehrere
Trigger-Punkte (Scan-Ingest, Pass-1-Completion-Hook, Final-Failed-Hook,
Backstop-Sweep) denselben Code benutzen — ohne Doppel-Jobs zu erzeugen.

Bezug: ARCHITECTURE.md §12 (Risk-Reviewer), ADR-0023 (Two-Pass-Architektur),
ADR-0028 (application_group_evaluations-Junction).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import log_event
from app.models import (
    ApplicationGroup,
    ApplicationGroupEvaluation,
    Finding,
    FindingStatus,
    LLMJob,
)
from app.services.llm_fingerprints import group_findings_fingerprint

log = logging.getLogger("fathometer.pass2_enqueue")

Pass2Trigger = Literal[
    "scan_ingest",
    "pass1_completion",
    "pass1_final_failed",
    "backstop_sweep",
]

# Pass-2-Jobs die noch laufen/warten blockieren ein Re-Enqueue derselben Group.
_ACTIVE_PASS2_STATUSES = ("queued", "in_progress")


def enqueue_pass2_for_server(
    session: Session,
    server_id: int,
    *,
    trigger: Pass2Trigger,
) -> int:
    """Enqueued Pass-2-Jobs fuer alle Groups auf diesem Server die bewertet
    werden muessen. Returns die Anzahl tatsaechlich enqueueter Jobs.

    Idempotent: kann beliebig oft aufgerufen werden ohne Doppel-Jobs zu
    erzeugen. Eine Group wird NUR enqueued wenn:
    - sie mindestens ein OPEN Finding auf diesem Server hat,
    - es noch keinen queued/in_progress Pass-2-Job fuer (group_id, server_id)
      gibt (Guard gegen Doppel-Enqueue durch fast gleichzeitige Trigger), und
    - keine ``application_group_evaluations``-Row mit identischem
      ``group_findings_fingerprint`` existiert (Fingerprint-Skip: schon bewertet).

    Die neu erzeugten ``LLMJob``-Rows tragen **kein** ``depends_on`` — die
    Sibling-Wait-Semantik in der Pickup-SQL (``_pick_next_job_id``) ist die
    alleinige Gate-Bedingung (TICKET-007 Fix 1: ``depends_on`` blockierte bei
    failed Pass-1).

    Der Helper macht ein einziges ``session.flush()`` am Ende; der Caller ist
    fuer ``session.commit()`` zustaendig. Kein impliziter Sibling-„sind alle
    Pass-1 fertig?"-Check — das ist Caller-Verantwortung (isoliert testbar).

    Audit-Event ``llm.pass2_auto_enqueued`` mit ``metadata={server_id,
    pass2_queued_count, trigger}`` — nur wenn ``pass2_queued_count > 0``.
    """
    affected_groups = list(
        session.execute(
            select(ApplicationGroup)
            .join(Finding, Finding.application_group_id == ApplicationGroup.id)
            .where(
                Finding.server_id == server_id,
                Finding.status == FindingStatus.OPEN,
            )
            .distinct()
        )
        .scalars()
        .all()
    )
    if not affected_groups:
        return 0

    affected_ids = [grp.id for grp in affected_groups]

    # Junction-Rows (bereits berechnete Evals) fuer alle affected_groups.
    evaluations_by_group_id: dict[int, ApplicationGroupEvaluation] = {
        ev.group_id: ev
        for ev in session.execute(
            select(ApplicationGroupEvaluation).where(
                ApplicationGroupEvaluation.server_id == server_id,
                ApplicationGroupEvaluation.group_id.in_(affected_ids),
            )
        )
        .scalars()
        .all()
    }

    # Doppel-Enqueue-Guard: Group-IDs mit bereits aktivem Pass-2-Job. Batched
    # statt N+1-``NOT EXISTS`` — semantisch identisch zum Ticket-Guard.
    active_pass2_group_ids: set[int] = set()
    for (payload,) in session.execute(
        select(LLMJob.payload).where(
            LLMJob.job_type == "risk_evaluation",
            LLMJob.server_id == server_id,
            LLMJob.status.in_(_ACTIVE_PASS2_STATUSES),
        )
    ).all():
        if not payload:
            continue
        gid = payload.get("group_id")
        if gid is None:
            continue
        try:
            active_pass2_group_ids.add(int(gid))
        except (TypeError, ValueError):
            continue

    # OPEN-Findings aller affected_groups in einem Query laden, in Python
    # nach group_id buendeln (vermeidet N+1 in der Fingerprint-Schleife).
    findings_by_group_id: dict[int, list[Finding]] = defaultdict(list)
    for finding in (
        session.execute(
            select(Finding).where(
                Finding.server_id == server_id,
                Finding.application_group_id.in_(affected_ids),
                Finding.status == FindingStatus.OPEN,
            )
        )
        .scalars()
        .all()
    ):
        gid = finding.application_group_id
        if gid is not None:
            findings_by_group_id[gid].append(finding)

    queued = 0
    for grp in affected_groups:
        if grp.id in active_pass2_group_ids:
            continue
        findings_in_group = findings_by_group_id.get(grp.id, [])
        if not findings_in_group:
            continue
        new_fp = group_findings_fingerprint(findings_in_group)
        existing_eval = evaluations_by_group_id.get(grp.id)
        if existing_eval is not None and existing_eval.group_findings_fingerprint == new_fp:
            # Junction-Row existiert und Fingerprint stimmt — kein Pass-2 noetig.
            continue
        session.add(
            LLMJob(
                job_type="risk_evaluation",
                server_id=server_id,
                payload={"group_id": grp.id, "server_id": server_id},
            )
        )
        queued += 1

    if queued > 0:
        session.flush()
        log_event(
            "llm.pass2_auto_enqueued",
            target_type="server",
            target_id=server_id,
            metadata={
                "server_id": server_id,
                "pass2_queued_count": queued,
                "trigger": trigger,
            },
            actor="system",
            session=session,
        )

    return queued


__all__ = ["Pass2Trigger", "enqueue_pass2_for_server"]
