"""Pure-Unit-Tests fuer ``app.workers.healthcheck``.

Die Heartbeat-Alter-Entscheidung wurde als ``_is_alive(heartbeat_at, now,
max_age_sec)`` aus dem Skript-``main()`` herausgeschnitten (Block-P /
ADR-0023 Phase F; TICKET-004 Slice 6). Diese Datei testet die pure
Entscheidung plus die Import-Footprint-Garantie aus v0.9.1.

DB-backed Smokes (Singleton-``settings``-Roundtrip durch ``main()`` und
das Raw-SQL-SELECT) liegen in
``tests/integration/test_healthcheck_db.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.workers.healthcheck import HEARTBEAT_MAX_AGE_SEC, _is_alive

# ---------------------------------------------------------------------------
# Pure Heartbeat-Alter-Entscheidung
# ---------------------------------------------------------------------------


def test_is_alive_fresh_heartbeat_returns_true() -> None:
    """Heartbeat juenger als ``max_age_sec`` → alive."""
    now = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)
    hb = now - timedelta(seconds=5)
    assert _is_alive(hb, now, HEARTBEAT_MAX_AGE_SEC) is True


def test_is_alive_none_heartbeat_returns_false() -> None:
    """``heartbeat_at IS NULL`` → unhealthy."""
    now = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)
    assert _is_alive(None, now, HEARTBEAT_MAX_AGE_SEC) is False


def test_is_alive_stale_heartbeat_returns_false() -> None:
    """Heartbeat aelter als ``max_age_sec`` → unhealthy."""
    now = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)
    hb = now - timedelta(seconds=HEARTBEAT_MAX_AGE_SEC + 1)
    assert _is_alive(hb, now, HEARTBEAT_MAX_AGE_SEC) is False


def test_is_alive_naive_timestamp_is_treated_as_utc() -> None:
    """Defensive: tz-naive Heartbeat-Werte werden als UTC interpretiert.

    Migration und ORM-Spalte sind ``DateTime(timezone=True)``, aber falls
    je ein Backfill oder Test-Setup einen naiven Wert in die Zeile setzt,
    soll der Healthcheck nicht mit ``TypeError`` crashen.
    """
    now = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)
    hb_naive = (now - timedelta(seconds=5)).replace(tzinfo=None)
    assert _is_alive(hb_naive, now, HEARTBEAT_MAX_AGE_SEC) is True


def test_is_alive_exactly_at_boundary_is_true() -> None:
    """Genau am Grenzwert (== max_age_sec) → noch alive (``<=``)."""
    now = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)
    hb = now - timedelta(seconds=HEARTBEAT_MAX_AGE_SEC)
    assert _is_alive(hb, now, HEARTBEAT_MAX_AGE_SEC) is True


# ---------------------------------------------------------------------------
# Import-Footprint
# ---------------------------------------------------------------------------


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
