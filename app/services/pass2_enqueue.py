# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Single-Source-of-Truth fuer das Enqueue von Pass-2-Risk-Evaluation-Jobs.

TICKET-007: der Pass-2-Trigger lief frueher genau einmal pro Scan-Upload im
Ingest. Dieser Helper kapselt die Enqueue-Logik idempotent, sodass mehrere
Trigger-Punkte (Scan-Ingest, Pass-1-Completion-Hook, Final-Failed-Hook,
Backstop-Sweep, Triage-Aktionen wie Acknowledge/Reopen/Bulk-Ack —
TICKET-010 Etappe 4) denselben Code benutzen — ohne Doppel-Jobs zu erzeugen.

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
from app.services.pass2_input_selection import FIX_LANES, FixLane, partition_by_lane

log = logging.getLogger("fathometer.pass2_enqueue")

Pass2Trigger = Literal[
    "scan_ingest",
    "pass1_completion",
    "pass1_final_failed",
    "backstop_sweep",
    "triage_action",
]

# Pass-2-Jobs die noch laufen/warten blockieren ein Re-Enqueue derselben Lane.
_ACTIVE_PASS2_STATUSES = ("queued", "in_progress")


def _enqueue_lane_job(
    session: Session,
    *,
    server_id: int,
    group_id: int,
    fix_lane: FixLane,
) -> None:
    """Fuegt einen Pass-2-Job fuer genau eine ``(group, lane)`` hinzu."""
    session.add(
        LLMJob(
            job_type="risk_evaluation",
            server_id=server_id,
            payload={"group_id": group_id, "server_id": server_id, "fix_lane": fix_lane},
        )
    )
    log.debug(
        "pass2_lane_enqueued",
        extra={"server_id": server_id, "group_id": group_id, "fix_lane": fix_lane},
    )


def enqueue_pass2_for_server(
    session: Session,
    server_id: int,
    *,
    trigger: Pass2Trigger,
) -> int:
    """Enqueued Pass-2-Jobs pro ``(group, fix_lane)`` auf diesem Server.
    Returns die Anzahl tatsaechlich enqueueter Jobs.

    ADR-0053 / TICKET-013 Etappe 4: Pass 2 bewertet pro Fix-Lane statt pro
    Group. Eine Group mit OPEN-Findings beider Lane-Typen (Findings mit und
    ohne ``fixed_version``) erzeugt bis zu **zwei** Jobs (je einen pro
    nicht-leerer Lane), eine reine Lane genau einen. Payload je Job:
    ``{group_id, server_id, fix_lane}``. Leere Lane → kein Job, keine Row.

    Idempotent: kann beliebig oft aufgerufen werden ohne Doppel-Jobs zu
    erzeugen. Eine ``(group, lane)`` wird NUR enqueued wenn:
    - die Lane mindestens ein OPEN Finding auf diesem Server hat,
    - es noch keinen queued/in_progress Pass-2-Job fuer
      ``(group_id, server_id, fix_lane)`` gibt (Guard gegen Doppel-Enqueue
      durch fast gleichzeitige Trigger), und
    - keine ``application_group_evaluations``-Row dieser Lane mit identischem
      ``group_findings_fingerprint`` (ueber das **Lane**-OPEN-Set) existiert
      (Fingerprint-Skip: schon bewertet).

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

    # Junction-Rows (bereits berechnete Evals) fuer alle affected_groups —
    # jetzt bis zu zwei pro Group (eine pro Lane), Schluessel ``(gid, lane)``.
    evaluations_by_group_lane: dict[tuple[int, str], ApplicationGroupEvaluation] = {
        (ev.group_id, ev.fix_lane): ev
        for ev in session.execute(
            select(ApplicationGroupEvaluation).where(
                ApplicationGroupEvaluation.server_id == server_id,
                ApplicationGroupEvaluation.group_id.in_(affected_ids),
            )
        )
        .scalars()
        .all()
    }

    # Doppel-Enqueue-Guard: ``(group_id, fix_lane)`` mit bereits aktivem
    # Pass-2-Job. Batched statt N+1-``NOT EXISTS``. Jobs ohne ``fix_lane`` im
    # Payload (Alt-Format vor Etappe 4) blockieren konservativ beide Lanes
    # der Group, damit ein laufender Legacy-Job kein Doppel-Enqueue zulaesst.
    active_pass2_group_lanes: set[tuple[int, str | None]] = set()
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
            gid_int = int(gid)
        except (TypeError, ValueError):
            continue
        lane = payload.get("fix_lane")
        active_pass2_group_lanes.add((gid_int, lane if lane in FIX_LANES else None))

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
        findings_in_group = findings_by_group_id.get(grp.id, [])
        if not findings_in_group:
            continue
        lanes = partition_by_lane(findings_in_group)
        for lane in FIX_LANES:
            lane_findings = lanes[lane]
            if not lane_findings:
                # Leere Lane — kein Job, keine Row (ADR-0053).
                continue
            # Guard: exakt diese Lane aktiv ODER ein Legacy-Job (ohne
            # fix_lane) der diese Group blockiert.
            if (grp.id, lane) in active_pass2_group_lanes or (
                grp.id,
                None,
            ) in active_pass2_group_lanes:
                continue
            # Fingerprint ueber das **Lane**-OPEN-Set, verglichen mit der
            # Lane-Eval-Row.
            new_fp = group_findings_fingerprint(lane_findings)
            existing_eval = evaluations_by_group_lane.get((grp.id, lane))
            if existing_eval is not None and existing_eval.group_findings_fingerprint == new_fp:
                # Junction-Row dieser Lane existiert und Fingerprint stimmt
                # — kein Pass-2 fuer diese Lane noetig.
                continue
            _enqueue_lane_job(session, server_id=server_id, group_id=grp.id, fix_lane=lane)
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
