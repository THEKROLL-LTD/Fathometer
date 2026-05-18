"""`POST /api/scans` — Scan-Ingest mit Auth-vor-Body-Parse.

Strikte Reihenfolge — niemals vertauschen (ARCHITECTURE.md §9):

1. Bearer-Token aus `Authorization` lesen. Wenn fehlt/malformed -> 401, KEIN
   Body-Lesen.
2. SHA-256(token) gegen `servers.api_key_hash` mit `hmac.compare_digest`.
3. Server-Status: weder `revoked_at` noch `retired_at` -> 403 sonst.
4. Erst JETZT: gzip-Decompress (mit Bound) und JSON-Parse.
5. Pydantic-Envelope-Validation -> 422 bei Fehlern.
6. Findings-Ingest via `findings_ingest.ingest_scan`.
7. Audit-Event `scan.ingested` mit Counts.
8. 202 Accepted + JSON-Body.

DoS-Schutz:
- 401 erfolgt VOR jedem Body-Read; ein 10-MB-Body mit ungueltigem Bearer
  schluerft keine CPU am Parser.
- gzip-Decompress streamend mit hartem 100-MB-Bound (`SECSCAN_MAX_DECOMPRESSED_MB`).
- JSON-Parse-Tiefe auf 32 begrenzt (§10 "JSON-Parser-Tiefenlimit").
"""

from __future__ import annotations

import hmac
import json
from collections import Counter
from typing import Any, cast

import structlog
from flask import current_app, request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.wrappers import Response

from app import csrf, limiter
from app.api import api_bp
from app.api._common import format_pydantic_errors, json_error
from app.audit import log_event
from app.auth import hash_server_key
from app.config import Settings
from app.db import get_session
from app.middleware.gzip import (
    DecompressError,
    DecompressLimitError,
    read_decompressed_body,
)
from app.models import ApplicationGroup, Finding, FindingStatus, LLMJob, Server
from app.schemas.scan_envelope import Envelope
from app.services.agent_version import version_lt
from app.services.findings_ingest import ingest_scan as run_ingest
from app.services.findings_ingest import server_is_active
from app.services.group_matcher import GroupMatcher, apply_matches_for_server
from app.services.host_state_ingest import persist_host_state
from app.services.llm_fingerprints import group_findings_fingerprint
from app.services.risk_engine import RiskBand, pretriage
from app.settings_service import get_settings_row

log = structlog.get_logger(__name__)

# §10: JSON-Parse-Tiefe maximal 32 Ebenen. stdlib `json` hat keine
# Tiefenbegrenzung — wir bauen einen kleinen Wrapper.
_MAX_JSON_DEPTH = 32


def _scans_unauth_rate_limit() -> str:
    limits: dict[str, str] = current_app.config["SECSCAN_RATELIMITS"]
    return limits["scans_unauth"]


def _scans_auth_rate_limit() -> str:
    limits: dict[str, str] = current_app.config["SECSCAN_RATELIMITS"]
    return limits["scans_auth"]


def _parse_bearer(header: str | None) -> str | None:
    """Extrahiert ein Bearer-Token aus dem `Authorization`-Header.

    Loggt KEIN Bearer-Token — der Redaction-Filter im logging_setup wuerde
    das zwar abfangen, aber sauberer ist gar nicht erst zu loggen.
    """
    if not header:
        return None
    parts = header.strip().split(None, 1)
    if len(parts) != 2:
        return None
    scheme, token = parts
    if scheme.lower() != "bearer":
        return None
    token = token.strip()
    if not token:
        return None
    if len(token) > 512:
        # Schutz gegen absurd lange Tokens — wir hashen sie eh, das waere
        # nur Verschwendung von CPU.
        return None
    return token


def _find_server_by_token(token: str) -> Server | None:
    """Konstantzeit-Vergleich des Bearer-Tokens gegen alle Server-Hashes.

    Wir hashen das Eingabe-Token EINMAL (SHA-256, billig), iterieren dann
    ueber alle aktiven Server und vergleichen den Hash via `compare_digest`.
    Bei einer Flotte unter ~10k Servern ist das fix genug; eine Index-Lookup
    auf einem Hash-Vergleich gibt's nicht ohne DB-Funktion.
    """
    sess = get_session()
    candidate_hash = hash_server_key(token)
    # Wir laden nur `id, api_key_hash, revoked_at, retired_at` der Server,
    # nicht den ganzen Datensatz, um den Hot-Path schlank zu halten.
    rows = sess.execute(
        select(
            Server.id,
            Server.api_key_hash,
            Server.revoked_at,
            Server.retired_at,
        )
    ).all()
    for row in rows:
        if hmac.compare_digest(row.api_key_hash, candidate_hash):
            # Voller Server-Load erst nach Hash-Match.
            return sess.execute(select(Server).where(Server.id == row.id)).scalar_one()
    return None


def _json_loads_bounded(payload: bytes) -> Any:
    """JSON-Decode mit Tiefenbegrenzung (§10).

    `json.JSONDecoder` traegt keine Depth-Bound — wir realisieren sie
    nachtraeglich durch eine rekursive Traversierung. Das ist O(n) auf dem
    geparsten Objekt; fuer 5-MB-Bodies ist das im einstelligen ms-Bereich.
    """
    try:
        doc = json.loads(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("UTF-8-Decode fehlgeschlagen") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON-Parse fehlgeschlagen: {exc.msg}") from exc
    _check_depth(doc, depth=0)
    return doc


def _check_depth(obj: Any, *, depth: int) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError(f"JSON-Tiefe > {_MAX_JSON_DEPTH}")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(v, depth=depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _check_depth(v, depth=depth + 1)


def _decompress_limit_bytes() -> int:
    s = cast(Settings, current_app.config["SECSCAN_SETTINGS"])
    return s.max_decompressed_mb * 1024 * 1024


def _max_body_bytes() -> int:
    s = cast(Settings, current_app.config["SECSCAN_SETTINGS"])
    return s.max_body_bytes


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@api_bp.post("/scans")
@csrf.exempt
@limiter.limit(lambda: _scans_unauth_rate_limit())
def ingest_scan() -> Response | tuple[Response, int]:
    """Kritischer Pfad — Reihenfolge nicht aendern."""

    # ---- 1. Bearer-Header lesen, VOR jedem Body-Read -------------------
    token = _parse_bearer(request.headers.get("Authorization"))
    if token is None:
        # KEIN Audit-Event hier (DoS-Schutz: log-fan-out vermeiden bei
        # Welle von schlechten Tokens; das `ratelimit.tripped`-Event greift
        # wenn das Limit reisst).
        return json_error(401, "unauthorized", "Bearer-Token fehlt oder ist ungueltig")

    server = _find_server_by_token(token)
    if server is None:
        sess = get_session()
        log_event(
            "auth.failed",
            target_type="server",
            target_id=None,
            metadata={"ip": request.remote_addr or "unknown", "endpoint": "/api/scans"},
            actor="unknown",
            session=sess,
        )
        sess.commit()
        return json_error(401, "unauthorized", "Bearer-Token unbekannt")

    if not server_is_active(server):
        return json_error(403, "server_inactive", "Server ist revoked oder retired")

    # Per-Server-Rate-Limit (anwendbar nach Auth).
    # `flask-limiter` hat keinen post-hoc-Decorator; in Block C reicht uns
    # der Default-Per-IP-Limit. Per-Server-Limit ist in §9 erwaehnt, aber
    # nicht fuer Block C als DoD verlangt — wird ggf. in Block H ergaenzt.

    # ---- 2. Body-Stream lesen + ggf. dekomprimieren --------------------
    content_encoding = request.headers.get("Content-Encoding")
    try:
        decompressed = read_decompressed_body(
            request.stream,
            content_encoding=content_encoding,
            max_compressed_bytes=_max_body_bytes() + 1,
            max_decompressed_bytes=_decompress_limit_bytes(),
        )
    except DecompressLimitError as exc:
        log.warning(
            "api.scans.decompress_limit",
            server_id=server.id,
            limit_bytes=exc.limit_bytes,
        )
        return json_error(
            413,
            "decompressed_too_large",
            f"Dekomprimierter Body groesser als {exc.limit_bytes // (1024 * 1024)} MB",
        )
    except DecompressError as exc:
        log.info("api.scans.decompress_failed", server_id=server.id, error=str(exc))
        return json_error(400, "bad_encoding", str(exc))

    # ---- 3. JSON-Parse mit Tiefen-Bound --------------------------------
    try:
        raw_doc = _json_loads_bounded(decompressed)
    except ValueError as exc:
        log.info("api.scans.json_parse_failed", server_id=server.id, error=str(exc))
        return json_error(400, "bad_json", str(exc))

    if not isinstance(raw_doc, dict):
        return json_error(400, "bad_json", "Top-Level muss ein JSON-Objekt sein")

    # ---- 4. Pydantic-Envelope-Parse ------------------------------------
    try:
        envelope = Envelope.model_validate(raw_doc)
    except ValidationError as exc:
        return json_error(
            422,
            "validation_error",
            "Envelope-Validierung fehlgeschlagen",
            details=format_pydantic_errors(exc),
        )

    # ---- 4b. Agent-Version-Gate (ADR-0021) ----------------------------
    # Reihenfolge: Auth (Schritt 1) hat Vorrang vor Body-Parse (Schritt 4);
    # die Version-Pruefung kann erst nach erfolgreichem Parse erfolgen,
    # weil `agent_version` aus dem Envelope kommt. Bei "veraltet" → 400.
    if version_lt(envelope.agent_version, Settings.MIN_AGENT_VERSION):
        sess = get_session()
        log_event(
            "agent.rejected_outdated",
            target_type="server",
            target_id=server.id,
            metadata={
                "agent_version": envelope.agent_version,
                "min_agent_version": Settings.MIN_AGENT_VERSION,
            },
            actor=server.name,
            session=sess,
        )
        sess.commit()
        return json_error(
            400,
            "agent_outdated",
            (
                f"agent version {envelope.agent_version} is below minimum "
                f"{Settings.MIN_AGENT_VERSION}, please update"
            ),
        )

    # ---- 5. Findings-Ingest -------------------------------------------
    sess = get_session()
    result = run_ingest(server, envelope, session=sess)

    # ---- 6. Host-Snapshot persistieren (Block O Phase C Task #7) -------
    # Reihenfolge: erst nach erfolgreichem Findings-UPSERT. Bei Schema-Fehlern
    # oder DB-Constraint-Verletzungen wird der Snapshot verworfen und der
    # Pre-Triage-Lauf faellt auf `snapshot_available=False` zurueck — Findings
    # bleiben aber ingested, der Operator sieht den Versionsstand.
    snapshot_available = False
    if envelope.host_state is not None:
        try:
            persist_host_state(sess, server, envelope.host_state)
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
                session=sess,
            )
        except (SQLAlchemyError, ValueError) as exc:
            log.warning(
                "api.scans.host_state_persist_failed",
                server_id=server.id,
                error=type(exc).__name__,
            )
            log_event(
                "host_state.parse_failed",
                target_type="server",
                target_id=server.id,
                metadata={"error": str(exc)[:256]},
                actor=server.name,
                session=sess,
            )
            snapshot_available = False

    # ---- 7. Pre-Triage-Schleife (Block O Phase C Task #8) --------------
    # Iteriert ueber alle aktuell offenen Findings des Servers. LLM-gesetzte
    # Bands (`risk_band_source == "llm"`) werden nicht ueberschrieben — diese
    # Logik lebt hier im Caller, nicht in `pretriage()` selbst
    # (Single-Responsibility, ADR-0022 §Re-Evaluation).
    band_counters: Counter[str] = Counter()
    open_findings = (
        sess.query(Finding)
        .filter(Finding.server_id == server.id, Finding.status == FindingStatus.OPEN)
        .all()
    )
    for finding in open_findings:
        if finding.risk_band_source == "llm":
            band_counters[finding.risk_band or "unset"] += 1
            continue

        evaluation = pretriage(finding, server, snapshot_available)
        new_band = evaluation.band.value

        if finding.risk_band != new_band:
            log_event(
                "risk.band_changed",
                target_type="finding",
                target_id=str(finding.id),
                metadata={
                    "from": finding.risk_band,
                    "to": new_band,
                    "source": "engine",
                    "reason": evaluation.reason,
                },
                actor=server.name,
                session=sess,
            )

        finding.risk_band = new_band
        finding.risk_band_reason = evaluation.reason
        finding.risk_band_source = "engine"
        finding.risk_band_computed_at = evaluation.computed_at
        band_counters[new_band] += 1

    log_event(
        "risk.pretriage_evaluated",
        target_type="server",
        target_id=server.id,
        metadata={"counters": dict(band_counters)},
        actor=server.name,
        session=sess,
    )

    # ---- 7b. Block-P LLM-Job-Queueing (ADR-0023) ----------------------
    # Mode-Flag steuert das komplette Block-P-System: `off` ueberspringt
    # Pattern-Match UND Job-Queueing. `observation` und `live` queuen Jobs;
    # der Worker entscheidet wie er sie verarbeitet (Stub vs. Live-LLM).
    settings_row = get_settings_row(sess)
    if settings_row.block_p_llm_mode != "off":
        # 1) Library-Reload + Pattern-Match. `reload()` muss bei jedem
        # Scan laufen — der Web-Container weiss nichts von Pass-1-Inserts
        # im Worker-Container ohne expliziten Refresh. `apply_matches_for_server`
        # laeuft erst NACH dem Findings-UPSERT (Block O), sonst sind frisch
        # eingefuegte Findings noch ungrouped.
        GroupMatcher.get().reload(sess)
        apply_matches_for_server(sess, server.id)
        # Flush, damit die nachfolgenden SELECTs die neu gesetzten
        # `application_group_id`-Werte sehen (autoflush koennte sonst
        # ueberlistet werden, wenn die ORM-Identity-Map die Findings noch
        # ohne Group hat).
        sess.flush()

        # 2) Pending Findings ohne Group → Pass-1-Job (Group-Detection).
        ungrouped = list(
            sess.execute(
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
        pass1_job_id: int | None = None
        if ungrouped:
            pass1_job = LLMJob(
                job_type="group_detection",
                server_id=server.id,
                payload={"finding_ids": [f.id for f in ungrouped]},
            )
            sess.add(pass1_job)
            sess.flush()
            pass1_job_id = pass1_job.id

        # 3) Fuer jede betroffene Group ein Pass-2-Job, sofern Fingerprint
        # sich geaendert hat oder noch keine Bewertung existiert.
        # Re-Eval bei `cve_data_fingerprint`-Drift wird hier NICHT
        # zusaetzlich getriggert; der Worker erkennt den Drift via
        # Cache-Miss (cve_data_fingerprint ist Teil des Cache-Keys),
        # solange ein Pass-2-Job gequeued ist. MVP-Kompromiss
        # (siehe ADR-0023 §"Cache-Invalidation"): wir queuen Pass-2
        # genau dann, wenn das Group-Findings-Set sich aendert oder die
        # Group noch unbewertet ist.
        affected_groups = list(
            sess.execute(
                select(ApplicationGroup)
                .join(Finding, Finding.application_group_id == ApplicationGroup.id)
                .where(
                    Finding.server_id == server.id,
                    Finding.status == FindingStatus.OPEN,
                )
                .distinct()
            )
            .scalars()
            .all()
        )

        pass2_queued = 0
        for grp in affected_groups:
            findings_in_group = list(
                sess.execute(
                    select(Finding).where(
                        Finding.server_id == server.id,
                        Finding.application_group_id == grp.id,
                        Finding.status == FindingStatus.OPEN,
                    )
                )
                .scalars()
                .all()
            )
            if not findings_in_group:
                continue

            new_fp = group_findings_fingerprint(findings_in_group)
            # Idempotenz: gleicher Fingerprint + bereits bewertet → skip.
            if grp.group_findings_fingerprint == new_fp and grp.risk_band is not None:
                continue

            pass2_job = LLMJob(
                job_type="risk_evaluation",
                server_id=server.id,
                payload={"group_id": grp.id, "server_id": server.id},
                depends_on=pass1_job_id,  # darf None sein
            )
            sess.add(pass2_job)
            pass2_queued += 1

        log_event(
            "llm.jobs_queued",
            target_type="server",
            target_id=server.id,
            metadata={
                "pass1_queued": 1 if pass1_job_id is not None else 0,
                "pass2_queued": pass2_queued,
                "mode": settings_row.block_p_llm_mode,
            },
            actor=server.name,
            session=sess,
        )

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
        session=sess,
    )

    # LLM-Update-Hook (Block G): aktive Conversations bekommen eine
    # System-Message angehaengt, wenn dieser Scan Delta brachte. Wir
    # nehmen `findings_inserted` als Proxy fuer "neue" und
    # `findings_resolved` direkt. `changed_count` ist im MVP immer 0
    # (Block-E-Limitation).
    from app.services.llm_update_hook import notify_conversations_for_scan

    try:
        notify_conversations_for_scan(
            sess,
            server.id,
            new_count=result.findings_inserted,
            resolved_count=result.findings_resolved,
            changed_count=0,
        )
    except Exception as exc:  # pragma: no cover — Hook darf Ingest nicht killen
        log.warning("api.scans.llm_hook_failed", error=type(exc).__name__)

    sess.commit()

    log.info(
        "api.scans.ingested",
        server_id=server.id,
        scan_id=result.scan_id,
        findings_total=result.findings_total,
    )

    from flask import jsonify

    body: dict[str, Any] = {
        "scan_id": result.scan_id,
        "ingested_at": result.received_at.isoformat(),
        "findings_total": result.findings_total,
        "findings_inserted": result.findings_inserted,
        "findings_updated": result.findings_updated,
        "findings_resolved": result.findings_resolved,
    }
    resp = cast(Response, jsonify(body))
    resp.status_code = 202
    return resp


__all__ = ["ingest_scan"]
