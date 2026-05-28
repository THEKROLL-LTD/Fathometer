"""`POST /api/scans` — Async-Scan-Ingest mit Auth-vor-Body-Parse.

Strikte Reihenfolge — niemals vertauschen (ARCHITECTURE.md §9):

1. Bearer-Token aus `Authorization` lesen. Wenn fehlt/malformed -> 401, KEIN
   Body-Lesen.
2. SHA-256(token) gegen `servers.api_key_hash` mit `hmac.compare_digest`.
3. Server-Status: weder `revoked_at` noch `retired_at` -> 403 sonst.
4. Erst JETZT: gzip-Decompress (mit Bound).
5. Schmal-Validierung (`_pre_validate_envelope`) — nur Top-Level-Felder.
6. Agent-Version-Gate.
7. Soft-Cap + INSERT in `scan_ingest_jobs` (Idempotency via Partial-Unique).
8. Audit `scan.queued`.
9. 202 + `{job_id, status}`.

Die Verarbeitung (Findings-UPSERT, Host-State, Pre-Triage, Group-Matcher,
LLM-Job-Queueing, Audit `scan.ingested`) laeuft asynchron im
`secscan-llm-worker` (`app/workers/scan_ingest_worker.py`). Der Agent beendet
nach der 202-Annahme und wartet nicht auf das Ergebnis.

Historischer Hinweis: das urspruenglich in ADR-0026 / Block R Phase H als
Cutover-Schutz eingefuehrte Feature-Flag `SCAN_INGEST_ASYNC` ist seit
v0.12.0 ersatzlos entfernt — Async ist der einzige Pfad. Die ehemalige
Sync-Logik lebt in `app/services/scan_processing.process_scan_envelope`
unveraendert weiter und wird vom Worker aufgerufen.

DoS-Schutz:
- 401 erfolgt VOR jedem Body-Read; ein 10-MB-Body mit ungueltigem Bearer
  schluerft keine CPU am Parser.
- gzip-Decompress streamend mit hartem 100-MB-Bound (`SECSCAN_MAX_DECOMPRESSED_MB`).
- JSON-Parse-Tiefe auf 32 begrenzt (§10 "JSON-Parser-Tiefenlimit").
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, cast

import structlog
from flask import current_app, jsonify, request
from sqlalchemy import select
from werkzeug.wrappers import Response

from app import csrf, limiter
from app.api import api_bp
from app.api._common import json_error
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
from app.services.agent_version import version_lt
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


def _pre_validate_envelope(body: bytes) -> tuple[str | None, str | None]:
    """Schmale Validierung: Top-Level-Objekt, agent_version, host.hostname, scan.

    Returnt (agent_version, error). Bei Erfolg (agent_version, None).
    Bei Fehler (None, error_string). KEIN Pydantic — manuelles dict-Walking
    fuer <5ms Latenz im Edge.

    Checks in Reihenfolge (bei erstem Failure abbrechen):
    1. json.loads(body) — JSONDecodeError -> ("invalid_json", ...).
    2. Top-Level dict -> sonst "not_an_object".
    3. agent_version Key existiert und ist String von Laenge 1..32.
    4. host Key existiert und ist dict.
    5. scan Key ist dict.

    Hinweis: ``host.hostname`` ist KEIN Pflichtfeld — die Server-Identitaet
    kommt aus dem Bearer-Token, nicht aus dem Body. Der Referenz-Agent
    (``agent/secscan-agent.sh``) sendet das Feld nicht, und es darf nicht
    zur Pre-Validate-Pflicht gemacht werden (war ein Block-R-Fehler, mit
    v0.12.x korrigiert). Detail-Felder im ``host``-Block werden in der
    Pydantic-Vollvalidierung im Worker geprueft.
    """
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "invalid_json"

    if not isinstance(doc, dict):
        return None, "not_an_object"

    agent_version = doc.get("agent_version")
    if not isinstance(agent_version, str) or not (1 <= len(agent_version) <= 32):
        return None, "missing_agent_version"

    host = doc.get("host")
    if not isinstance(host, dict):
        return None, "missing_host"

    scan = doc.get("scan")
    if not isinstance(scan, dict):
        return None, "missing_scan"

    return agent_version, None


def _handle_async_ingest(
    session: Any,
    server: Server,
    decompressed_body: bytes,
    gzipped_body: bytes,
) -> Response | tuple[Response, int]:
    """Asynchroner Fast-Path fuer POST /api/scans (Block R Phase B, ADR-0026).

    Laeuft nur wenn `SECSCAN_SCAN_INGEST_ASYNC=true`. Fuehrt Schmal-Validierung,
    Agent-Version-Gate, Soft-Cap-Check, Job-Insert und Audit-Event durch;
    antwortet mit 202 + job_id binnen <1s.

    Schritte (ADR-0026 §Entscheidung Fast-Path):
    1. Schmal-Validierung.
    2. Agent-Version-Gate.
    3. Soft-Cap + Idempotency-UPSERT.
    4. Audit `scan.queued` (nur bei Neu-Insert).
    5. 202 Response.
    """
    from app.services.scan_ingest_queue import QueueFullError, enqueue_or_resolve

    settings = cast(Settings, current_app.config["SECSCAN_SETTINGS"])

    # --- 1. Schmal-Validierung ---
    agent_version, pre_err = _pre_validate_envelope(decompressed_body)
    if pre_err is not None:
        # Flat error-Format fuer Fast-Path-Responses (ADR-0026 §Entscheidung).
        resp_err = cast(Response, jsonify({"error": pre_err}))
        resp_err.status_code = 400
        return resp_err

    # Mypy-Hint: nach pre_err == None ist agent_version garantiert str.
    assert agent_version is not None

    # --- 2. Agent-Version-Gate ---
    if version_lt(agent_version, Settings.MIN_AGENT_VERSION):
        log_event(
            "agent.rejected_outdated",
            target_type="server",
            target_id=server.id,
            metadata={
                "agent_version": agent_version,
                "min_agent_version": Settings.MIN_AGENT_VERSION,
            },
            actor=server.name,
            session=session,
        )
        session.commit()
        resp_outdated = cast(Response, jsonify({"error": "agent_outdated"}))
        resp_outdated.status_code = 400
        return resp_outdated

    # --- 3. Soft-Cap + Idempotency-UPSERT ---
    # gzipped_body ist der vom Caller re-komprimierte Body (compress_payload
    # wurde bereits im Endpoint aufgerufen).
    try:
        job, was_existing = enqueue_or_resolve(
            session,
            server,
            payload_bytes=decompressed_body,
            payload_gzip=gzipped_body,
            max_queued=settings.max_queued_ingest_jobs,
        )
    except QueueFullError as exc:
        return (
            cast(
                Response,
                jsonify({"error": "queue_full", "queued": exc.current_count}),
            ),
            429,
        )

    # --- 4. Audit `scan.queued` (nur bei echtem Neu-Insert) ---
    if not was_existing:
        payload_sha256 = hashlib.sha256(decompressed_body).hexdigest()
        log_event(
            "scan.queued",
            target_type="server",
            target_id=server.id,
            metadata={
                "job_id": job.id,
                "payload_sha256": payload_sha256,
                "payload_bytes": len(decompressed_body),
            },
            actor=server.name,
            session=session,
        )

    session.commit()

    log.info(
        "api.scans.async_queued",
        server_id=server.id,
        job_id=job.id,
        was_existing=was_existing,
    )

    # --- 5. 202 Response ---
    resp = cast(
        Response,
        jsonify(
            {
                "job_id": job.id,
                "status": "queued",
            }
        ),
    )
    resp.status_code = 202
    return resp


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

    # ---- 3. Async-Fast-Path (ADR-0026, ueberall einziger Pfad seit v0.12.0) -
    # Schmal-Validierung -> Agent-Version-Gate -> Soft-Cap + Idempotency-Insert
    # in scan_ingest_jobs -> 202 + job_id. Worker-Sub-Tick verarbeitet asynchron.
    # Das urspruengliche Feature-Flag `SCAN_INGEST_ASYNC` aus dem Block-R-
    # Cutover ist ersatzlos entfernt (siehe ADR-0026 §Cutover-Abschluss).
    from app.services.scan_ingest_queue import compress_payload as _compress

    _gzipped = _compress(decompressed)
    return _handle_async_ingest(get_session(), server, decompressed, _gzipped)


__all__ = ["ingest_scan"]
