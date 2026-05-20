"""Tests fuer ``app.workers.healthcheck`` — Block P (ADR-0023) Phase F.

Das Healthcheck-Skript wird vom docker-compose-Healthcheck-Eintrag des
``secscan-llm-worker``-Containers sowie von den k8s-Liveness/Readiness-
Probes aufgerufen. Es liest die Singleton-``settings``-Zeile, prueft das
Alter von ``llm_worker_heartbeat_at`` und exit'et 0 (healthy) oder
1 (unhealthy).

Hier verifizieren wir vier funktionale Pfade plus eine Import-Footprint-
Garantie (v0.9.1):

1. Frischer Heartbeat → exit 0.
2. ``llm_worker_heartbeat_at IS NULL`` → exit 1.
3. Alter Heartbeat (> 30s) → exit 1.
4. DB-Exception → exit 1.
5. **Import-Footprint** — ``app.workers.healthcheck`` darf das fette
   ``app.workers.llm_worker``-Modul nicht laden (sonst zieht der Probe-
   Cold-Start die komplette LLM-Service-Lage mit und ueberschreitet
   ``timeoutSeconds: 5`` auf RKE2-Realbedingungen).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

from flask import Flask
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
        from sqlalchemy import text

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
        from sqlalchemy import text

        conn.execute(text("UPDATE settings SET llm_worker_heartbeat_at = NULL WHERE id = 1"))

    with _route_healthcheck_connection(db_app):
        assert healthcheck.main() == 1


def test_healthcheck_stale_heartbeat_returns_one(db_app: Flask) -> None:
    """Heartbeat aelter als 30s → exit 1."""
    _ensure_settings_row(db_app)
    engine = get_engine(db_app)
    with engine.begin() as conn:
        from sqlalchemy import text

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
        from sqlalchemy import text

        conn.execute(
            text("UPDATE settings SET llm_worker_heartbeat_at = :ts WHERE id = 1"),
            {"ts": datetime.now(tz=UTC).replace(tzinfo=None)},
        )

    with _route_healthcheck_connection(db_app):
        assert healthcheck.main() == 0


def test_healthcheck_does_not_import_llm_worker_module() -> None:
    """v0.9.1: das Healthcheck-Modul darf das fette ``llm_worker``-Modul
    nicht transitiv laden.

    Hintergrund: ``app.workers.llm_worker`` zieht via Service-Layer
    ``openai`` + ``app.services.llm_risk_reviewer`` + ``app.models`` rein.
    Bei jeder k8s-Exec-Probe (alle 30s) wuerde diese Import-Last anfallen
    und das Default-``timeoutSeconds: 5`` reissen.

    Wir verifizieren das in einem **Sub-Process** — andernfalls verfaelscht
    der gemeinsame ``sys.modules``-State der laufenden Test-Session das
    Ergebnis (andere Tests laden ``llm_worker`` regulaer).
    """
    import subprocess
    import sys

    forbidden = [
        "app.workers.llm_worker",
        "app.services.llm_risk_reviewer",
        "app.services.llm_client",
        "app.services.group_matcher",
        "app.services.llm_cache",
        "app.services.llm_fingerprints",
        "app.services.llm_budget",
        "openai",
    ]
    code = (
        "import sys, json; "
        "import app.workers.healthcheck; "
        f"print(json.dumps([m for m in {forbidden!r} if m in sys.modules]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    import json as _json

    loaded = _json.loads(result.stdout.strip())
    assert loaded == [], (
        f"app.workers.healthcheck zieht verbotene Module mit: {loaded}. "
        "Das sprengt das k8s-Probe-Timeout (siehe v0.9.1 CHANGELOG)."
    )
