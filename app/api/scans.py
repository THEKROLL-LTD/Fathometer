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
from typing import Any, cast

import structlog
from flask import current_app, request
from pydantic import ValidationError
from sqlalchemy import select
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
from app.models import Server
from app.schemas.scan_envelope import Envelope
from app.services.findings_ingest import ingest_scan as run_ingest
from app.services.findings_ingest import server_is_active

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

    # ---- 5. Findings-Ingest -------------------------------------------
    sess = get_session()
    result = run_ingest(server, envelope, session=sess)

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
