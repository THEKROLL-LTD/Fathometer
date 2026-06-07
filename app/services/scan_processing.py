# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Service-Extraktion fuer Scan-Verarbeitung (ADR-0026, Block R Phase C).

Kapselt die vollstaendige Verarbeitungssequenz die vorher inline in
`app/api/scans.py` lief. Wird sowohl vom Worker-Sub-Tick als auch vom
Sync-Edge-Pfad aufgerufen.

WICHTIG: `process_scan_envelope` ruft `session.commit()` NICHT selber.
Der Caller (Worker oder Edge-Sync-Branch) committet — damit kann der Worker
den `scan_ingest_jobs.status='done'`-UPDATE + `payload_gzip=NULL` +
`scan_id=...` zusammen mit dem Ergebnis in einer einzigen Transaktion
committen (DoD-C Punkt 6, ADR-0026 §Bedrohungsmodell).
"""

from __future__ import annotations

import gzip
import json
import logging
from collections import Counter
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit import log_event
from app.config import Settings, load_settings
from app.models import (
    Finding,
    FindingStatus,
    LLMJob,
    Server,
)
from app.schemas.scan_envelope import Envelope
from app.services.finding_group_inheritance import inherit_group_risk_to_findings
from app.services.findings_ingest import ingest_scan as run_ingest
from app.services.group_matcher import (
    GroupMatcher,
    affinity_sort_for_pass1,
    apply_matches_for_server,
)
from app.services.host_state_ingest import persist_host_state
from app.services.pass2_enqueue import enqueue_pass2_for_server
from app.services.risk_engine import RiskBand, pretriage
from app.settings_service import get_settings_row

log = logging.getLogger("fathometer.scan_processing")

# §10: JSON-Parse-Tiefe maximal 32 Ebenen (identisch zu app/api/scans.py).
_MAX_JSON_DEPTH = 32


# ---------------------------------------------------------------------------
# Ergebnis-Datenstruktur
# ---------------------------------------------------------------------------


class ScanProcessingResult(BaseModel):
    """Ergebnis eines vollstaendigen Scan-Verarbeitungs-Laufs.

    Alle Counts sind nicht-negativ (>= 0). Pydantic-Validation erzwingt das.
    """

    model_config = ConfigDict(extra="ignore")

    scan_id: int
    findings_total: int
    findings_inserted: int
    findings_updated: int
    findings_resolved: int
    class_os_pkgs: int
    class_lang_pkgs: int
    class_other: int

    @field_validator(
        "scan_id",
        "findings_total",
        "findings_inserted",
        "findings_updated",
        "findings_resolved",
        "class_os_pkgs",
        "class_lang_pkgs",
        "class_other",
    )
    @classmethod
    def must_be_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Wert darf nicht negativ sein, bekommen: {v}")
        return v


# ---------------------------------------------------------------------------
# JSON-Parsing mit Tiefenlimit (analog api/scans.py)
# ---------------------------------------------------------------------------


def _check_depth(obj: Any, *, depth: int) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError(f"JSON-Tiefe > {_MAX_JSON_DEPTH}")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(v, depth=depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _check_depth(v, depth=depth + 1)


def _json_loads_bounded(payload: bytes) -> Any:
    """JSON-Decode mit Tiefenbegrenzung."""
    try:
        doc = json.loads(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("UTF-8-Decode fehlgeschlagen") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON-Parse fehlgeschlagen: {exc.msg}") from exc
    _check_depth(doc, depth=0)
    return doc


# ---------------------------------------------------------------------------
# Pre-Triage-Logik (extrahiert aus app/api/scans.py)
# ---------------------------------------------------------------------------


def _run_pretriage(
    session: Session,
    server: Server,
    snapshot_available: bool,
) -> Counter[str]:
    """Fuehrt den Pre-Triage-Loop ueber alle OPEN-Findings des Servers aus.

    LLM-gesetzte Bands (risk_band_source == 'llm') werden nicht ueberschrieben.
    Gibt die Band-Counters zurueck (fuer das Audit-Event im Caller).
    """
    band_counters: Counter[str] = Counter()
    open_findings = (
        session.query(Finding)
        .filter(Finding.server_id == server.id, Finding.status == FindingStatus.OPEN)
        .all()
    )
    for finding in open_findings:
        if finding.risk_band_source == "llm":
            band_counters[finding.risk_band or "unset"] += 1
            continue
        evaluation = pretriage(finding, server, snapshot_available)
        new_band = evaluation.band.value
        finding.risk_band = new_band
        finding.risk_band_reason = evaluation.reason
        finding.risk_band_source = "engine"
        finding.risk_band_computed_at = evaluation.computed_at
        band_counters[new_band] += 1
    return band_counters


# ---------------------------------------------------------------------------
# Haupt-Service-Funktion
# ---------------------------------------------------------------------------


def process_scan_envelope(
    session: Session,
    server: Server,
    payload_gzip: bytes,
) -> ScanProcessingResult:
    """Vollstaendige Scan-Verarbeitungssequenz aus dem heutigen Sync-Pfad.

    Inputs:
        session: Offene SQLAlchemy-Session. Caller committet.
        server: Vollstaendig geladenes Server-ORM-Objekt.
        payload_gzip: Gzip-komprimierter JSON-Body (wird intern dekomprimiert).

    Returns:
        ScanProcessingResult mit allen Counts.

    Raises:
        ValidationError: Bei Pydantic-Vollparse-Fehler (Worker setzt
            status='failed', Payload bleibt fuer Debugging erhalten).
        ValueError: Bei JSON-Parse-Fehlern oder Tiefenlimit-Ueberschreitung.

    KEIN session.commit() hier — Caller-Verantwortung (ADR-0026).
    """
    # ---- 1. gzip-Decompress ---------------------------------------------------
    decompressed = gzip.decompress(payload_gzip)

    # ---- 2. JSON-Parse + Pydantic-Envelope-Vollparse -------------------------
    raw_doc = _json_loads_bounded(decompressed)
    if not isinstance(raw_doc, dict):
        raise ValueError("Top-Level muss ein JSON-Objekt sein")

    # Kann ValidationError werfen — Worker faengt das ab und setzt failed.
    envelope = Envelope.model_validate(raw_doc)

    # ---- 3. Findings-Ingest --------------------------------------------------
    result = run_ingest(server, envelope, session=session)

    # ---- 4. Host-Snapshot persistieren (Best-Effort) -------------------------
    snapshot_available = False
    if envelope.host_state is not None:
        try:
            persist_host_state(session, server, envelope.host_state)
            snapshot_available = True
            log_event(
                "host_state.snapshot_received",
                target_type="server",
                target_id=server.id,
                metadata={
                    "tools_available": list(envelope.host_state.tools_available),
                    "gaps": list(envelope.host_state.gaps),
                    "listener_count": len(envelope.host_state.listeners),
                    "process_count": len(envelope.host_state.processes),
                },
                actor=server.name,
                session=session,
            )
        except (SQLAlchemyError, ValueError) as exc:
            log.warning(
                "scan_processing.host_state_persist_failed server_id=%s error=%s",
                server.id,
                type(exc).__name__,
            )
            log_event(
                "host_state.parse_failed",
                target_type="server",
                target_id=server.id,
                metadata={"error": str(exc)[:256]},
                actor=server.name,
                session=session,
            )
            snapshot_available = False

    # ---- 5. Pre-Triage-Loop --------------------------------------------------
    band_counters = _run_pretriage(session, server, snapshot_available)

    log_event(
        "risk.pretriage_evaluated",
        target_type="server",
        target_id=server.id,
        metadata={"counters": dict(band_counters)},
        actor=server.name,
        session=session,
    )

    # ---- 6. Block-P LLM-Job-Queueing (ADR-0023) ------------------------------
    settings_row = get_settings_row(session)
    if settings_row.block_p_llm_mode != "off":
        GroupMatcher.get().reload(session)
        apply_matches_for_server(session, server.id)
        session.flush()
        inherited = inherit_group_risk_to_findings(session, server_id=server.id)

        # Ungrouped PENDING Findings → Pass-1-Job
        ungrouped = list(
            session.execute(
                select(Finding).where(
                    Finding.server_id == server.id,
                    Finding.application_group_id.is_(None),
                    Finding.status == FindingStatus.OPEN,
                    Finding.risk_band == RiskBand.PENDING.value,
                )
            )
            .scalars()
            .all()
        )

        cfg = _get_settings()
        batch_size = cfg.llm_pass1_findings_per_batch
        pass1_batches_count = 0

        if ungrouped:
            sorted_findings = affinity_sort_for_pass1(ungrouped)
            sorted_ids = [f.id for f in sorted_findings]
            batches = [
                sorted_ids[i : i + batch_size] for i in range(0, len(sorted_ids), batch_size)
            ]
            for batch_ids in batches:
                session.add(
                    LLMJob(
                        job_type="group_detection",
                        server_id=server.id,
                        payload={"finding_ids": batch_ids},
                    )
                )
            session.flush()
            pass1_batches_count = len(batches)

        # Betroffene Groups → Pass-2-Jobs. TICKET-007: zentraler idempotenter
        # Helper (Fingerprint-Skip via application_group_evaluations-Junction +
        # NOT-EXISTS-Guard gegen Doppel-Jobs). Kein ``depends_on`` mehr — die
        # Sibling-Wait-Semantik in der Pickup-SQL ist die alleinige Gate-
        # Bedingung (ein failed Pass-1 darf Pass-2 nicht ewig blockieren).
        pass2_queued = enqueue_pass2_for_server(session, server.id, trigger="scan_ingest")

        log_event(
            "llm.jobs_queued",
            target_type="server",
            target_id=server.id,
            metadata={
                "pass1_queued": pass1_batches_count,
                "pass1_batch_size": batch_size if pass1_batches_count else None,
                "pass2_queued": pass2_queued,
                "findings_inherited": inherited,
                "mode": settings_row.block_p_llm_mode,
            },
            actor=server.name,
            session=session,
        )

    # ---- 7. Audit scan.ingested ----------------------------------------------
    log_event(
        "scan.ingested",
        target_type="server",
        target_id=server.id,
        metadata={
            "scan_id": result.scan_id,
            "findings_total": result.findings_total,
            "findings_inserted": result.findings_inserted,
            "findings_updated": result.findings_updated,
            "findings_resolved": result.findings_resolved,
            "class_os_pkgs": result.findings_class_os_pkgs,
            "class_lang_pkgs": result.findings_class_lang_pkgs,
            "class_other": result.findings_class_other,
        },
        actor=server.name,
        session=session,
    )

    log.info(
        "scan_processing.completed server_id=%s scan_id=%s findings_total=%s",
        server.id,
        result.scan_id,
        result.findings_total,
    )

    # ---- 9. Ergebnis zurückgeben (KEIN commit hier!) -------------------------
    return ScanProcessingResult(
        scan_id=result.scan_id,
        findings_total=result.findings_total,
        findings_inserted=result.findings_inserted,
        findings_updated=result.findings_updated,
        findings_resolved=result.findings_resolved,
        class_os_pkgs=result.findings_class_os_pkgs,
        class_lang_pkgs=result.findings_class_lang_pkgs,
        class_other=result.findings_class_other,
    )


def _get_settings() -> Settings:
    """Laedt Settings lazily — kein Flask-Kontext noetig (Worker-kompatibel)."""
    try:
        from flask import current_app

        if current_app:
            return cast(Settings, current_app.config["FM_SETTINGS"])
    except RuntimeError:
        pass
    return load_settings()


__all__ = ["ScanProcessingResult", "process_scan_envelope"]
