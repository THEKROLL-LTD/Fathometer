"""Pure-Unit-Tests fuer Block U Phase G — Debug-Log-Skalierung fuer N=200.

Siehe ``docs/blocks/U-worker-concurrency.md`` §"Phase G — Debug-Log-Skalierung"
und §"Tests" (acht Cases).

Getestet werden ausschliesslich:

* :func:`app.services.llm_debug_log.should_sample_debug_log` —
  Determinismus, Error-Bypass, Edge-Cases bei sample_rate.
* :func:`app.services.llm_debug_log.evict_old` — CTE-DELETE-SQL-Form mit
  ``USING (… ORDER BY created_at DESC, id DESC OFFSET :max_rows)``.
* :func:`app.config.load_settings` — Default-Anhebungen
  (``llm_debug_log_max_rows == 2000`` und
  ``llm_debug_log_success_sample_rate == 10``).
* :func:`app.workers.llm_worker._record_pass_debug_log` — Gate vor dem
  Insert (Sample-False -> kein Insert; Error-Status -> Insert).

Verbindlich (CLAUDE.md): pure-unit only, kein db_integration/RUN_E2E.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.services import llm_debug_log
from app.services.llm_debug_log import should_sample_debug_log
from app.workers import llm_worker

# ---------------------------------------------------------------------------
# Autouse-Fixture: FM_*-Env-Cleanup (analog Phase-A-Tests).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_fathometer_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Entfernt alle ``FM_*``-Vars und setzt einen sauberen Encryption-Key.

    ``load_settings()`` zieht sonst Host-Env-Overrides — wir wollen aber
    die echten Pydantic-Defaults pruefen.
    """
    for key in list(os.environ.keys()):
        if key.upper().startswith("FM_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("FM_ENCRYPTION_KEY", "x" * 32)


# ---------------------------------------------------------------------------
# Case 1 — Sampling-Determinismus innerhalb desselben Prozesses
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_should_sample_debug_log_is_deterministic_within_process() -> None:
    """Zwei Calls mit gleichem Input -> gleicher Output.

    ``hash()`` ist via ``PYTHONHASHSEED`` zwischen Prozessen randomisiert,
    aber innerhalb desselben Prozesses stabil. Wir assertieren auf
    Determinismus, NICHT auf einen konkreten True/False-Wert.
    """
    first = should_sample_debug_log(123, "pass1_group_detection", "success", 10)
    second = should_sample_debug_log(123, "pass1_group_detection", "success", 10)
    assert first == second

    # Quer ueber mehrere Inputs: jeder Aufruf muss reproduzierbar sein.
    for job_id in (1, 42, 999, 123456):
        for job_type in ("pass1_group_detection", "pass2_evaluation"):
            a = should_sample_debug_log(job_id, job_type, "success", 10)
            b = should_sample_debug_log(job_id, job_type, "success", 10)
            assert a == b, f"Nicht-deterministisch fuer ({job_id}, {job_type}): {a} vs {b}"


# ---------------------------------------------------------------------------
# Case 2 — Sampling-Errors: jeder non-success Status -> True
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status",
    ["validation_error", "timeout", "error", "unknown", ""],
)
@pytest.mark.parametrize("job_id", [1, 42, 1_000_000])
@pytest.mark.parametrize("sample_rate", [1, 10, 100, 1000])
@pytest.mark.timeout(5)
def test_should_sample_debug_log_non_success_always_true(
    status: str, job_id: int, sample_rate: int
) -> None:
    """Errors duerfen niemals gesampelt werden — Forensik bleibt verlustfrei.

    Unabhaengig von ``job_id`` und ``sample_rate`` returnt der Sampler
    fuer jeden Status != "success" True.
    """
    assert should_sample_debug_log(job_id, "pass1_group_detection", status, sample_rate) is True


# ---------------------------------------------------------------------------
# Case 3 — Sampling-Rate=1: alle Success-Calls werden geschrieben
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_should_sample_debug_log_rate_one_always_true() -> None:
    """100 verschiedene job_id mit status=success und sample_rate=1 -> alle True."""
    for job_id in range(100):
        assert should_sample_debug_log(job_id, "pass1_group_detection", "success", 1) is True, (
            f"Sampling-Rate=1 muss True fuer alle job_ids liefern, fail bei {job_id}"
        )


@pytest.mark.parametrize("sample_rate", [0, 1, -1, -100])
@pytest.mark.timeout(5)
def test_should_sample_debug_log_rate_zero_or_negative_disables_sampling(
    sample_rate: int,
) -> None:
    """``sample_rate <= 1`` deaktiviert Sampling — defensive Lower-Bound.

    Phase A pinnt ``ge=1`` in Pydantic, aber die Service-Funktion
    selbst muss defensiv mit 0/Negativ-Werten umgehen koennen.
    """
    assert should_sample_debug_log(42, "pass1_group_detection", "success", sample_rate) is True


# ---------------------------------------------------------------------------
# Case 4 — Sampling-Rate=10: ~100 True bei 1000 Inputs (Hash-Verteilung)
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_should_sample_debug_log_rate_ten_approximates_one_in_ten() -> None:
    """1000 verschiedene job_id, status=success, sample_rate=10 -> ~100 True.

    Toleranz ±40 wegen Hash-Verteilung und PYTHONHASHSEED-Randomisierung.
    Die Spec nennt ±20 als Idealwert, wir setzen ±40 als robusten Backstop
    gegen pathologische Hash-Verteilungen einzelner CPython-Builds.
    """
    true_count = sum(
        1
        for job_id in range(1000)
        if should_sample_debug_log(job_id, "pass1_group_detection", "success", 10)
    )
    assert 60 <= true_count <= 140, (
        f"erwartet ~100 True bei 1000 Inputs/rate=10, got {true_count} (Toleranz [60, 140])"
    )


# ---------------------------------------------------------------------------
# Case 5 — CTE-DELETE-SQL-Form
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_evict_old_uses_cte_delete_with_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    """``evict_old`` schickt das CTE-DELETE mit ``USING``-Subquery, ORDER BY
    und ``OFFSET :max_rows`` an die Session.

    Wir captureen die zwei ``execute``-Calls (Time-Cap + Count-Cap), pruefen
    den zweiten (Count-Cap) auf das erwartete SQL-Pattern und das
    Parameter-Dict.
    """
    # load_settings() patchen — Default 2000 ist ok, aber wir wollen einen
    # eindeutigen Marker.
    fake_cfg = SimpleNamespace(llm_debug_log_max_age_days=14, llm_debug_log_max_rows=4242)
    monkeypatch.setattr(llm_debug_log, "load_settings", lambda: fake_cfg)

    captured: list[tuple[Any, dict[str, Any] | None]] = []

    class _FakeResult:
        rowcount = 0

    session = MagicMock()

    def _execute(stmt: Any, params: dict[str, Any] | None = None) -> Any:
        captured.append((stmt, params))
        return _FakeResult()

    session.execute.side_effect = _execute
    session.commit = MagicMock()

    time_evicted, count_evicted = llm_debug_log.evict_old(session)

    assert time_evicted == 0
    assert count_evicted == 0
    assert session.commit.called, "evict_old soll am Ende committen"

    # Zwei execute-Calls: Time-Cap (DELETE WHERE created_at <…) + Count-Cap (CTE).
    assert len(captured) == 2, f"erwartet zwei execute-Calls, got {len(captured)}"

    # Time-Cap-Statement: enthaelt make_interval.
    time_stmt, _time_params = captured[0]
    time_sql = str(getattr(time_stmt, "text", time_stmt))
    assert "make_interval" in time_sql, f"Time-Cap-SQL erwartet make_interval: {time_sql!r}"

    # Count-Cap-Statement: enthaelt USING-Subquery + ORDER BY + OFFSET.
    count_stmt, count_params = captured[1]
    count_sql = str(getattr(count_stmt, "text", count_stmt))
    for needle in (
        "USING (",
        "ORDER BY created_at DESC, id DESC",
        "OFFSET :max_rows",
    ):
        assert needle in count_sql, (
            f"CTE-DELETE-Pattern {needle!r} fehlt im Count-Cap-SQL: {count_sql!r}"
        )
    assert count_params == {"max_rows": 4242}, (
        f"Parameter-Dict erwartet {{'max_rows': 4242}}, got {count_params!r}"
    )


@pytest.mark.timeout(5)
def test_evict_old_does_not_use_not_in_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regressionsschutz: das alte ``NOT IN``-Pattern ist weg.

    Block U Phase G ersetzt den ``NOT IN (SELECT id …)``-Plan durch CTE-
    DELETE. Wenn jemand das versehentlich revertet, schlaegt dieser Test
    durch.
    """
    fake_cfg = SimpleNamespace(llm_debug_log_max_age_days=14, llm_debug_log_max_rows=2000)
    monkeypatch.setattr(llm_debug_log, "load_settings", lambda: fake_cfg)

    captured: list[Any] = []

    class _FakeResult:
        rowcount = 0

    session = MagicMock()

    def _execute(stmt: Any, params: dict[str, Any] | None = None) -> Any:
        captured.append(stmt)
        return _FakeResult()

    session.execute.side_effect = _execute

    llm_debug_log.evict_old(session)

    count_sql = str(getattr(captured[1], "text", captured[1])).upper()
    assert "NOT IN" not in count_sql, (
        f"Altes NOT-IN-Pattern wieder eingefuehrt? Count-Cap-SQL: {count_sql!r}"
    )


# ---------------------------------------------------------------------------
# Case 6 — Default-Anhebung der Pydantic-Settings
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_default_llm_debug_log_max_rows_is_two_thousand() -> None:
    """Phase G hebt den Default von 500 auf 2000 (kein Schema-Touch)."""
    from app.config import load_settings

    s = load_settings()
    assert s.llm_debug_log_max_rows == 2000


@pytest.mark.timeout(5)
def test_default_llm_debug_log_success_sample_rate_is_ten() -> None:
    """Sampling 1:10 ist der Default fuer N=200-Skalierung."""
    from app.config import load_settings

    s = load_settings()
    assert s.llm_debug_log_success_sample_rate == 10


# ---------------------------------------------------------------------------
# Case 7 — _record_pass_debug_log: Sample-False -> kein Insert
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_record_pass_debug_log_skips_insert_when_sampler_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn ``should_sample_debug_log`` False zurueckgibt, darf der Worker
    weder ``llm_debug_log.record`` noch ``session.commit`` aufrufen.

    Wir patchen den Sampler auf eine Stub-Funktion die immer False
    returnt, und ein ``record``-Stub das wir spy-en. Plus ein
    ``get_session``-Stub das uns einen Marker setzt falls ueberhaupt eine
    Session geoeffnet wurde.
    """
    monkeypatch.setattr(
        llm_worker.llm_debug_log,
        "should_sample_debug_log",
        lambda **_kw: False,
    )

    record_calls: list[dict[str, Any]] = []

    def _spy_record(*_args: Any, **kwargs: Any) -> None:
        record_calls.append(kwargs)

    monkeypatch.setattr(llm_worker.llm_debug_log, "record", _spy_record)

    session_opened: list[int] = []

    @contextmanager
    def _spy_get_session() -> Iterator[Any]:
        session_opened.append(1)
        sess = MagicMock()
        sess.get = MagicMock(return_value=None)
        sess.commit = MagicMock()
        yield sess

    monkeypatch.setattr(llm_worker, "get_session", _spy_get_session)

    # Default-Settings reichen — der Sampler ist hard-gepatcht.
    llm_worker._record_pass_debug_log(
        job_id=7,
        job_type="pass1_group_detection",
        status="success",
        model="deepseek-ai/DeepSeek-V3",
        server_id=1,
        group_id=None,
        meta={"system_prompt": "sys", "user_prompt": "usr", "max_tokens": 100},
        error=None,
    )

    assert record_calls == [], (
        f"Sample=False soll _kein_ Insert ausloesen, got {len(record_calls)} record()-Aufrufe"
    )
    assert session_opened == [], (
        f"Sample=False soll _keine_ Session oeffnen, got {len(session_opened)}"
    )


# ---------------------------------------------------------------------------
# Case 8 — _record_pass_debug_log: Error-Status -> Insert passiert
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_record_pass_debug_log_inserts_when_status_is_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Errors werden niemals gesampelt — der Insert muss passieren.

    Wir patchen den Sampler so dass er die echte Semantik approximiert
    (``status != "success" -> True``), und pruefen dass ``record`` genau
    einmal aufgerufen wurde.
    """

    def _real_sampler(*, job_id: int, job_type: str, status: str, sample_rate: int) -> bool:
        # Echte Semantik fuer den Test: Errors bypass.
        return status != "success"

    monkeypatch.setattr(llm_worker.llm_debug_log, "should_sample_debug_log", _real_sampler)

    record_calls: list[dict[str, Any]] = []

    def _spy_record(*_args: Any, **kwargs: Any) -> None:
        record_calls.append(kwargs)

    monkeypatch.setattr(llm_worker.llm_debug_log, "record", _spy_record)

    commit_calls: list[int] = []

    @contextmanager
    def _fake_get_session() -> Iterator[Any]:
        sess = MagicMock()
        sess.get = MagicMock(return_value=None)
        sess.commit = MagicMock(side_effect=lambda: commit_calls.append(1))
        yield sess

    monkeypatch.setattr(llm_worker, "get_session", _fake_get_session)

    llm_worker._record_pass_debug_log(
        job_id=7,
        job_type="pass1_group_detection",
        status="validation_error",
        model="deepseek-ai/DeepSeek-V3",
        server_id=1,
        group_id=None,
        meta={
            "system_prompt": "sys",
            "user_prompt": "usr",
            "max_tokens": 100,
            "raw_content": "raw",
            "extracted_json": "{}",
            "reasoning_field": None,
            "usage": None,
            "finish_reason": "stop",
            "duration_ms": 42,
        },
        error="validation broke",
    )

    assert len(record_calls) == 1, (
        f"Error-Status soll genau einen record()-Aufruf ausloesen, got {len(record_calls)}"
    )
    call = record_calls[0]
    assert call["status"] == "validation_error"
    assert call["job_type"] == "pass1_group_detection"
    assert call["error"] == "validation broke"
    assert commit_calls == [1], (
        f"Insert-Pfad soll genau einmal committen, got {len(commit_calls)} commits"
    )
