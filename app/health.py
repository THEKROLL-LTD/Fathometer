"""Health- und Readiness-Endpoints.

`/healthz` macht einen DB-Ping (SELECT 1) und antwortet mit 503 falls die DB
nicht erreichbar ist. `/readyz` ist ein leichter Liveness-Check ohne DB.
"""

from __future__ import annotations

from typing import Any

import structlog
from flask import Blueprint, current_app, jsonify
from flask.wrappers import Response
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

bp = Blueprint("health", __name__)
log = structlog.get_logger(__name__)


def _db_ping(database_url: str) -> bool:
    """Fuehrt ein `SELECT 1` gegen die konfigurierte DB aus.

    Bewusst synchron via `create_engine` — wir wollen in `/healthz` keine
    async-Eventloop-Komplexitaet. Postgres-Treiber ist `psycopg` (sync-API
    desselben Pakets, das auch async kann). Engine ist short-lived, damit
    der Healthcheck keine persistente Connection im Worker-Prozess hinterlaesst.
    """
    sync_url = database_url.replace("+psycopg", "")  # psycopg ist auch sync.
    if "+psycopg" in database_url:
        sync_url = database_url  # psycopg dialect erkennt sync vs async automatisch
    engine = create_engine(sync_url, pool_pre_ping=True, future=True)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    finally:
        engine.dispose()


@bp.get("/healthz")
def healthz() -> tuple[Response, int]:
    """Health-Check mit DB-Ping."""
    database_url: str = current_app.config["SECSCAN_DATABASE_URL"]
    try:
        _db_ping(database_url)
    except SQLAlchemyError as exc:
        log.warning("healthz.db_unreachable", error=str(exc))
        payload: dict[str, Any] = {"status": "degraded", "reason": "database unreachable"}
        return jsonify(payload), 503
    return jsonify({"status": "ok"}), 200


@bp.get("/readyz")
def readyz() -> tuple[Response, int]:
    """Readiness-Check ohne externe Abhaengigkeiten."""
    return jsonify({"status": "ready"}), 200
