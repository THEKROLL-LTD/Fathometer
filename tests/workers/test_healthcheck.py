"""Tests fuer ``app.workers.healthcheck`` — Block P (ADR-0023) Phase F.

Das Healthcheck-Skript wird vom docker-compose-Healthcheck-Eintrag des
``secscan-llm-worker``-Containers aufgerufen. Es liest die Singleton-
``settings``-Zeile, prueft das Alter von ``llm_worker_heartbeat_at`` und
exit'et 0 (healthy) oder 1 (unhealthy).

Hier verifizieren wir die vier Pfade:

1. Frischer Heartbeat → exit 0.
2. ``llm_worker_heartbeat_at IS NULL`` → exit 1.
3. Alter Heartbeat (> 30s) → exit 1.
4. DB-Exception → exit 1.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

from flask import Flask

from app.db import get_session_factory
from app.settings_service import ensure_settings_row
from app.workers import healthcheck, llm_worker


def _route_worker_session(db_app: Flask) -> None:
    """Routet die Worker-Session-Factory auf die Test-DB."""
    factory = get_session_factory(db_app)
    llm_worker.set_session_factory_for_tests(factory)


def _open_sess(db_app: Flask) -> Any:
    return get_session_factory(db_app)()


def test_healthcheck_fresh_heartbeat_returns_zero(db_app: Flask) -> None:
    """Heartbeat juenger als 30s → exit 0."""
    _route_worker_session(db_app)
    sess = _open_sess(db_app)
    try:
        row = ensure_settings_row(sess)
        row.llm_worker_heartbeat_at = datetime.now(tz=UTC)
        sess.commit()
    finally:
        sess.close()

    assert healthcheck.main() == 0


def test_healthcheck_no_heartbeat_returns_one(db_app: Flask) -> None:
    """``llm_worker_heartbeat_at IS NULL`` → exit 1."""
    _route_worker_session(db_app)
    sess = _open_sess(db_app)
    try:
        row = ensure_settings_row(sess)
        # Default ist NULL fuer eine frisch angelegte Singleton-Row.
        assert row.llm_worker_heartbeat_at is None
    finally:
        sess.close()

    assert healthcheck.main() == 1


def test_healthcheck_stale_heartbeat_returns_one(db_app: Flask) -> None:
    """Heartbeat aelter als 30s → exit 1."""
    _route_worker_session(db_app)
    sess = _open_sess(db_app)
    try:
        row = ensure_settings_row(sess)
        row.llm_worker_heartbeat_at = datetime.now(tz=UTC) - timedelta(seconds=120)
        sess.commit()
    finally:
        sess.close()

    assert healthcheck.main() == 1


def test_healthcheck_db_exception_returns_one(db_app: Flask) -> None:
    """DB-Exception beim Session-Aufbau → exit 1, kein Traceback nach STDOUT."""
    _route_worker_session(db_app)

    # `get_session` wirft → defensiver Pfad muss greifen.
    def _explode() -> Any:
        raise RuntimeError("simulated db outage")

    with patch.object(healthcheck, "get_session", side_effect=_explode):
        assert healthcheck.main() == 1


def test_healthcheck_naive_timestamp_is_treated_as_utc(db_app: Flask) -> None:
    """Defensive: ein tz-naiver Heartbeat wird als UTC interpretiert.

    Migration und ORM-Spalte sind ``DateTime(timezone=True)``, aber falls
    je ein Backfill oder Test-Setup einen naiven Wert in die Zeile setzt,
    soll der Healthcheck nicht mit ``TypeError`` crashen.
    """
    _route_worker_session(db_app)
    sess = _open_sess(db_app)
    try:
        row = ensure_settings_row(sess)
        # Frischer Heartbeat ohne tzinfo — Healthcheck muss als UTC werten
        # und sollte exit 0 liefern.
        row.llm_worker_heartbeat_at = datetime.now(tz=UTC).replace(tzinfo=None)
        sess.commit()
    finally:
        sess.close()

    assert healthcheck.main() == 0
