# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""`POST /api/keys/rotate` — Master- oder Server-Key rotieren.

Body:
```json
{
  "target": "master" | "server",
  "server_id": 42,            # Pflicht wenn target=server
  "current_master_key": "..." # immer Pflicht
}
```

Antwort 200:
```json
{
  "target": "master",
  "new_key": "...",           # Klartext, einmalig
  "server_id": 42             # wenn target=server
}
```

Audit-Events: `key.rotated.master` / `key.rotated.server`.
"""

from __future__ import annotations

from typing import cast

import structlog
from flask import jsonify, request
from pydantic import ValidationError
from sqlalchemy import select
from werkzeug.wrappers import Response

from app import csrf, limiter
from app.api import api_bp
from app.api._common import format_pydantic_errors, json_error
from app.audit import log_event
from app.auth import (
    generate_master_key,
    generate_server_key,
    hash_master_key,
    hash_server_key,
    verify_master_key,
)
from app.db import get_session
from app.models import Server, Setting
from app.schemas.scan_envelope import KeyRotateRequest

log = structlog.get_logger(__name__)


def _rotate_rate_limit() -> str:
    from flask import current_app

    limits: dict[str, str] = current_app.config["FM_RATELIMITS"]
    # Wir nutzen das `register`-Bucket, weil Rotation aehnlich selten ist und
    # genauso schuetzenswert.
    return limits["register"]


@api_bp.post("/keys/rotate")
@csrf.exempt
@limiter.limit(lambda: _rotate_rate_limit())
def rotate_key() -> Response | tuple[Response, int]:
    raw = request.get_json(silent=True)
    if not isinstance(raw, dict):
        return json_error(400, "invalid_body", "JSON-Objekt erwartet")

    try:
        body = KeyRotateRequest.model_validate(raw)
    except ValidationError as exc:
        return json_error(
            422,
            "validation_error",
            "Ungueltige Felder im Request-Body",
            details=format_pydantic_errors(exc),
        )

    sess = get_session()
    settings_row = sess.execute(select(Setting).where(Setting.id == 1)).scalar_one_or_none()
    if (
        settings_row is None
        or settings_row.master_key_hash is None
        or not verify_master_key(settings_row.master_key_hash, body.current_master_key)
    ):
        log_event(
            "auth.failed",
            target_type="settings",
            target_id=1,
            metadata={
                "ip": request.remote_addr or "unknown",
                "endpoint": "/api/keys/rotate",
            },
            actor="unknown",
            session=sess,
        )
        sess.commit()
        return json_error(401, "unauthorized", "Master-Key falsch")

    if body.target == "master":
        new_master = generate_master_key()
        settings_row.master_key_hash = hash_master_key(new_master)
        log_event(
            "key.rotated.master",
            target_type="settings",
            target_id=1,
            metadata={"ip": request.remote_addr or "unknown"},
            session=sess,
        )
        sess.commit()
        log.info("api.keys.rotate.master")
        resp = cast(Response, jsonify({"target": "master", "new_key": new_master}))
        resp.status_code = 200
        return resp

    # target == "server"
    server_id = cast(int, body.server_id)
    server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one_or_none()
    if server is None:
        return json_error(404, "not_found", "Server nicht gefunden")

    new_key = generate_server_key()
    server.api_key_hash = hash_server_key(new_key)
    log_event(
        "key.rotated.server",
        target_type="server",
        target_id=server.id,
        metadata={"name": server.name},
        session=sess,
    )
    sess.commit()
    log.info("api.keys.rotate.server", server_id=server.id)

    resp = cast(
        Response,
        jsonify({"target": "server", "server_id": server.id, "new_key": new_key}),
    )
    resp.status_code = 200
    return resp


__all__ = ["rotate_key"]
