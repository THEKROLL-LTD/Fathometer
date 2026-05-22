"""Pure-Unit-Tests fuer ``app.services.llm_budget`` (TICKET-004 Slice 6).

Die ORM-/Singleton-Settings-Operationen (``budget_check``,
``budget_consume``, ``maybe_reset_budget``, ``mark_exhausted_audit_once``)
brauchen echte DB-Persistenz und liegen daher in
``tests/integration/test_token_budget_db.py``.

Hier verbleiben die rein funktionalen Helfer:

* ``_next_utc_midnight`` — Berechnung des naechsten Reset-Zeitpunkts.
* ``estimate_tokens`` — Token-Heuristik pro Job-Typ.
"""

from __future__ import annotations

from datetime import UTC, datetime, time

from app.models import LLMJob
from app.services.llm_budget import _next_utc_midnight, estimate_tokens

# ---------------------------------------------------------------------------
# _next_utc_midnight
# ---------------------------------------------------------------------------


def test_next_utc_midnight_returns_following_day_at_zero() -> None:
    """Mittag UTC → naechster Tag 00:00 UTC."""
    now = datetime(2026, 5, 22, 12, 34, 56, tzinfo=UTC)
    expected = datetime(2026, 5, 23, 0, 0, 0, tzinfo=UTC)
    assert _next_utc_midnight(now) == expected


def test_next_utc_midnight_at_midnight_returns_next_day() -> None:
    """Genau 00:00 UTC → 24 Stunden spaeter (nicht jetzt)."""
    now = datetime(2026, 5, 22, 0, 0, 0, tzinfo=UTC)
    expected = datetime(2026, 5, 23, 0, 0, 0, tzinfo=UTC)
    assert _next_utc_midnight(now) == expected


def test_next_utc_midnight_naive_input_treated_as_utc() -> None:
    """Defensive: tz-naive Eingaben werden als UTC angenommen."""
    now_naive = datetime(2026, 5, 22, 23, 59, 59)
    result = _next_utc_midnight(now_naive)
    assert result.tzinfo is UTC
    assert result.time() == time(0, 0, 0)
    assert result.date().isoformat() == "2026-05-23"


def test_next_utc_midnight_returns_aware_utc() -> None:
    """Ergebnis ist immer tz-aware UTC und liegt um 00:00:00."""
    now = datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)
    result = _next_utc_midnight(now)
    assert result.tzinfo is UTC
    assert result.time() == time(0, 0, 0)
    # Jahreswechsel.
    assert result == datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# estimate_tokens
# ---------------------------------------------------------------------------


def test_estimate_tokens_pass1_scales_with_findings() -> None:
    """``group_detection``: 50 Tokens pro Finding, min 50."""
    job = LLMJob(job_type="group_detection", payload={"finding_ids": [1, 2, 3, 4, 5]})
    assert estimate_tokens(job) == 250


def test_estimate_tokens_pass1_empty_uses_minimum() -> None:
    """``group_detection`` mit leerer Liste → min-Cap 50."""
    job = LLMJob(job_type="group_detection", payload={"finding_ids": []})
    assert estimate_tokens(job) == 50


def test_estimate_tokens_pass2_constant() -> None:
    """``risk_evaluation``: konstant 2000."""
    job = LLMJob(job_type="risk_evaluation", payload={"group_id": 1, "server_id": 1})
    assert estimate_tokens(job) == 2000


def test_estimate_tokens_unknown_job_type_fallback() -> None:
    """Unbekannter ``job_type`` → defensiver Fallback 1000."""
    job = LLMJob(job_type="other", payload={})
    assert estimate_tokens(job) == 1000


def test_estimate_tokens_pass1_with_missing_payload_key() -> None:
    """``group_detection`` ohne ``finding_ids``-Key → min-Cap 50."""
    job = LLMJob(job_type="group_detection", payload={})
    assert estimate_tokens(job) == 50
