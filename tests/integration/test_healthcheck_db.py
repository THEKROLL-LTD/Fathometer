"""Integration-Smokes fuer ``app.workers.healthcheck.main`` gegen echte
Postgres-DB.

Diese Tests wurden aus ``tests/workers/test_healthcheck.py`` ausgelagert
(TICKET-004, Slice 6). Die pure ``_is_alive``-Entscheidung liegt DB-frei
in der Worker-Test-Datei. Hier verbleiben Roundtrips durch das Raw-SQL-
``SELECT llm_worker_heartbeat_at FROM settings``-Statement und die
``main()``-Exit-Codes.

Auto-Markierung als ``db_integration`` (und damit ``acceptance``) erfolgt
ueber ``tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

from flask import Flask
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_engine
from app.settings_service import ensure_settings_row
from app.workers import healthcheck


def _ensure_settings_row(db_app: Flask) -> None:
    """Sorgt fuer eine Singleton-``settings``-Zeile in der Test-DB.

    Der ``db_app``-Fixture truncated vor jedem Test alle Tabellen — also
    auch ``settings``. Wir legen die Zeile per ``ensure_settings_row``
    wieder an, damit die UPDATEs unten Wirkung haben.
    """
    engine = get_engine(db_app)
    with Session(bind=engine) as sess:
        ensure_settings_row(sess)
        sess.commit()


def _route_healthcheck_connection(db_app: Flask) -> Any:
    """Routet ``healthcheck._open_connection`` auf die Test-DB-Engine.

    Die Helper liefert einen ``contextlib.closing``-faehigen Wrapper auf
    die Test-Connection, damit das Skript ``conn.close()`` aufrufen darf,
    ohne die Test-Engine zu zerstoeren.
    """
    engine = get_engine(db_app)
    return patch.object(healthcheck, "_open_connection", side_effect=engine.connect)


def test_healthcheck_fresh_heartbeat_returns_zero(db_app: Flask) -> None:
    """Heartbeat juenger als 30s → exit 0."""
    _ensure_settings_row(db_app)
    engine = get_engine(db_app)
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE settings SET llm_worker_heartbeat_at = :ts WHERE id = 1"),
            {"ts": datetime.now(tz=UTC)},
        )

    with _route_healthcheck_connection(db_app):
        assert healthcheck.main() == 0


def test_healthcheck_no_heartbeat_returns_one(db_app: Flask) -> None:
    """``llm_worker_heartbeat_at IS NULL`` → exit 1."""
    _ensure_settings_row(db_app)
    engine = get_engine(db_app)
    with engine.begin() as conn:
        conn.execute(text("UPDATE settings SET llm_worker_heartbeat_at = NULL WHERE id = 1"))

    with _route_healthcheck_connection(db_app):
        assert healthcheck.main() == 1


def test_healthcheck_stale_heartbeat_returns_one(db_app: Flask) -> None:
    """Heartbeat aelter als 30s → exit 1."""
    _ensure_settings_row(db_app)
    engine = get_engine(db_app)
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE settings SET llm_worker_heartbeat_at = :ts WHERE id = 1"),
            {"ts": datetime.now(tz=UTC) - timedelta(seconds=120)},
        )

    with _route_healthcheck_connection(db_app):
        assert healthcheck.main() == 1


def test_healthcheck_db_exception_returns_one(db_app: Flask) -> None:
    """DB-Exception beim Connection-Aufbau → exit 1, kein Traceback nach STDOUT."""

    def _explode() -> Any:
        raise RuntimeError("simulated db outage")

    with patch.object(healthcheck, "_open_connection", side_effect=_explode):
        assert healthcheck.main() == 1


def test_healthcheck_naive_timestamp_is_treated_as_utc(db_app: Flask) -> None:
    """Defensive: ein tz-naiver Heartbeat wird als UTC interpretiert.

    Migration und ORM-Spalte sind ``DateTime(timezone=True)``, aber falls
    je ein Backfill oder Test-Setup einen naiven Wert in die Zeile setzt,
    soll der Healthcheck nicht mit ``TypeError`` crashen.
    """
    _ensure_settings_row(db_app)
    engine = get_engine(db_app)
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE settings SET llm_worker_heartbeat_at = :ts WHERE id = 1"),
            {"ts": datetime.now(tz=UTC).replace(tzinfo=None)},
        )

    with _route_healthcheck_connection(db_app):
        assert healthcheck.main() == 0
