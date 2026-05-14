"""`POST /api/register` — Server-Registrierung per Master-Key.

Strikter Flow:
1. Body als JSON parsen (Flask-Default).
2. Pydantic-Validation auf `RegisterRequest` (§10 — Server-Name-Regex etc.).
3. Master-Key gegen `settings.master_key_hash` mit `verify_master_key`
   (SHA-256 + `hmac.compare_digest`).
4. Bei Fail: 401, Audit-Event `server.register.failed`. Keine Hint, ob
   Master-Key oder Name fehlerhaft war.
5. Bei Erfolg: 256-bit `api_key` generieren, SHA-256-Hash speichern, Klartext
   einmalig in Response zurueck.

Rate-Limit: `flask-limiter`-Default aus Settings (`ratelimit_register`).
"""

from __future__ import annotations

from typing import Any, cast

import structlog
from flask import current_app, request, url_for
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from werkzeug.wrappers import Response

from app import csrf, limiter
from app.api import api_bp
from app.api._common import format_pydantic_errors, json_error
from app.audit import log_event
from app.auth import (
    generate_server_key,
    hash_server_key,
    verify_master_key,
)
from app.db import get_session
from app.models import Server, Setting
from app.schemas.scan_envelope import RegisterRequest

log = structlog.get_logger(__name__)


def _register_rate_limit() -> str:
    limits: dict[str, str] = current_app.config["SECSCAN_RATELIMITS"]
    return limits["register"]


@api_bp.post("/register")
@csrf.exempt
@limiter.limit(lambda: _register_rate_limit())
def register_server() -> Response | tuple[Response, int]:
    # ---- 1. Body parsen ------------------------------------------------
    raw = request.get_json(silent=True)
    if not isinstance(raw, dict):
        return json_error(400, "invalid_body", "JSON-Objekt erwartet")

    try:
        body = RegisterRequest.model_validate(raw)
    except ValidationError as exc:
        return json_error(
            422,
            "validation_error",
            "Ungueltige Felder im Request-Body",
            details=format_pydantic_errors(exc),
        )

    # ---- 2. Master-Key verifizieren ------------------------------------
    sess = get_session()
    settings_row = sess.execute(select(Setting).where(Setting.id == 1)).scalar_one_or_none()
    if (
        settings_row is None
        or settings_row.master_key_hash is None
        or not verify_master_key(settings_row.master_key_hash, body.master_key)
    ):
        log_event(
            "server.register.failed",
            target_type="server",
            target_id=body.name,
            metadata={"ip": request.remote_addr or "unknown"},
            actor=body.name,
            session=sess,
        )
        sess.commit()
        return json_error(401, "unauthorized", "Master-Key falsch oder Setup unvollstaendig")

    # ---- 3. Server anlegen ---------------------------------------------
    api_key_plain = generate_server_key()
    api_key_hash = hash_server_key(api_key_plain)

    server = Server(
        name=body.name,
        api_key_hash=api_key_hash,
        expected_scan_interval_h=body.expected_scan_interval_h,
    )
    sess.add(server)
    try:
        sess.flush()
    except IntegrityError:
        sess.rollback()
        log_event(
            "server.register.failed",
            target_type="server",
            target_id=body.name,
            metadata={"reason": "name_conflict"},
            actor=body.name,
            session=sess,
        )
        sess.commit()
        # Wir geben hier 409 zurueck — der Name ist eindeutig, Operator soll
        # einen anderen waehlen. Kein Auth-Leak.
        return json_error(409, "name_conflict", "Server-Name bereits vergeben")

    log_event(
        "server.registered",
        target_type="server",
        target_id=server.id,
        metadata={"name": body.name, "interval_h": body.expected_scan_interval_h},
        actor=body.name,
        session=sess,
    )
    sess.commit()

    log.info("api.register.success", server_id=server.id, name=body.name)

    # Klartext-Key NUR HIER zurueck. scan_endpoint hilft dem Agent-Skript.
    response_body: dict[str, Any] = {
        "server_id": server.id,
        "api_key": api_key_plain,
        "scan_endpoint": url_for("api.ingest_scan", _external=True),
    }
    from flask import jsonify

    resp = cast(Response, jsonify(response_body))
    resp.status_code = 201
    return resp


__all__ = ["register_server"]
