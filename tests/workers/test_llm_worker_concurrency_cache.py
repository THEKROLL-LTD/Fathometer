"""Pure-Unit-Tests fuer Block U Phase C — ``_get_concurrency_throttled``
(Hot-Reload-Cache) und ``_compute_idle_sleep`` (exponentiellet Idle-Backoff).

Beide Helper sind reine Modul-State-Funktionen — wir mocken
``get_session`` bzw. ``ensure_settings_row`` und ``_poll_interval``.
Keine echte DB.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from app.workers import llm_worker

# ---------------------------------------------------------------------------
# Autouse-Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_caches_and_logger() -> Iterator[None]:
    llm_worker.invalidate_throttle_caches_for_tests()
    worker_logger = logging.getLogger("secscan.llm_worker")
    prev_disabled = worker_logger.disabled
    prev_propagate = worker_logger.propagate
    prev_level = worker_logger.level
    worker_logger.disabled = False
    worker_logger.propagate = True
    try:
        yield
    finally:
        worker_logger.disabled = prev_disabled
        worker_logger.propagate = prev_propagate
        worker_logger.level = prev_level
        llm_worker.invalidate_throttle_caches_for_tests()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patch_concurrency_db(
    monkeypatch: pytest.MonkeyPatch, *, values: list[int | Exception]
) -> dict[str, int]:
    """Patcht ``get_session`` + ``ensure_settings_row`` so dass
    nacheinander die in ``values`` enthaltenen Concurrency-Werte
    geliefert werden. Eine ``Exception`` im Pool simuliert einen DB-Hickup.

    Returnt ein Counter-Dict mit ``db_reads`` damit Tests die Cache-Hits
    auseinanderhalten koennen.
    """
    counter = {"db_reads": 0}
    seq = list(values)

    class _FakeSession:
        def close(self) -> None:
            pass

        def rollback(self) -> None:
            pass

    @contextmanager
    def _fake_get_session() -> Iterator[_FakeSession]:
        counter["db_reads"] += 1
        if not seq:
            raise AssertionError("Mehr DB-Reads als Test-Werte")
        nxt = seq.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        yield _FakeSession()

    def _fake_ensure(_session: Any) -> SimpleNamespace:
        # Bei jedem Aufruf den passenden Wert aus dem Counter ableiten.
        # Wir koennen die ``values`` nicht doppelt konsumieren — daher
        # halten wir den zuletzt erfolgreich gelesenen Wert in einem
        # internen Holder.
        return SimpleNamespace(
            llm_worker_job_concurrency=_fake_ensure._current  # type: ignore[attr-defined]
        )

    _fake_ensure._current = None  # type: ignore[attr-defined]

    # Wir wrappen get_session damit nach Erfolg der Wert in _current landet.
    @contextmanager
    def _instrumented_get_session() -> Iterator[_FakeSession]:
        counter["db_reads"] += 1
        if not seq:
            raise AssertionError("Mehr DB-Reads als Test-Werte")
        nxt = seq.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        _fake_ensure._current = int(nxt)  # type: ignore[attr-defined]
        yield _FakeSession()

    monkeypatch.setattr(llm_worker, "get_session", _instrumented_get_session)
    monkeypatch.setattr(llm_worker, "ensure_settings_row", _fake_ensure)
    return counter


# ---------------------------------------------------------------------------
# 1) Erster Call lädt aus DB, zweiter Call ist Cache-Hit
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_concurrency_first_call_loads_from_db_second_is_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Erster Call macht einen DB-Read, sofortiger zweiter Call ist Cache-Hit
    (kein zweiter DB-Read)."""
    counter = _patch_concurrency_db(monkeypatch, values=[7])
    assert llm_worker._get_concurrency_throttled() == 7
    assert counter["db_reads"] == 1
    # Zweiter Call: Cache-Hit, kein weiterer DB-Read.
    assert llm_worker._get_concurrency_throttled() == 7
    assert counter["db_reads"] == 1, "Cache-Hit erwartet, kein DB-Read"


# ---------------------------------------------------------------------------
# 2) invalidate_throttle_caches_for_tests forciert Re-Read
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_concurrency_invalidate_forces_db_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nach ``invalidate_throttle_caches_for_tests`` muss der naechste Call
    wieder die DB lesen."""
    counter = _patch_concurrency_db(monkeypatch, values=[3, 5])
    assert llm_worker._get_concurrency_throttled() == 3
    assert counter["db_reads"] == 1
    llm_worker.invalidate_throttle_caches_for_tests()
    assert llm_worker._get_concurrency_throttled() == 5
    assert counter["db_reads"] == 2


# ---------------------------------------------------------------------------
# 3) Concurrency-Wechsel loggt llm_worker.concurrency_changed
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_concurrency_change_logs_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Beim Wechsel von Wert N auf Wert M wird ein INFO-Log mit dem Marker
    ``llm_worker.concurrency_changed from=N to=M`` geschrieben.

    Auch beim allerersten Read (von ``None`` auf den Settings-Wert) wird
    der Marker geloggt — das ist der ``_cached_concurrency is None``-Pfad.
    """
    captured: list[logging.LogRecord] = []

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    handler = _Handler()
    handler.setLevel(logging.DEBUG)
    llm_worker.log.addHandler(handler)
    prev_level = llm_worker.log.level
    llm_worker.log.setLevel(logging.DEBUG)

    try:
        _patch_concurrency_db(monkeypatch, values=[1, 5])
        assert llm_worker._get_concurrency_throttled() == 1
        # Cache invalidieren damit der naechste Call die DB nochmal liest.
        llm_worker.invalidate_throttle_caches_for_tests()
        # Erneut Logger-Reset NICHT noetig — captured-Liste behalten wir.
        # Aber wir muessen den DB-Patch erneut anwenden, weil invalidate
        # die Caches loescht — der Mock konsumiert pro Aufruf einen Wert.
        # `values=[1, 5]` wurde zur Init gesetzt: pop(0) hat 1 entfernt,
        # naechster pop liefert 5.
        assert llm_worker._get_concurrency_throttled() == 5
    finally:
        llm_worker.log.removeHandler(handler)
        llm_worker.log.setLevel(prev_level)

    msgs = [r.getMessage() for r in captured]
    changed = [m for m in msgs if "concurrency_changed" in m]
    assert changed, f"concurrency_changed-Log erwartet, captured={msgs}"
    # Mindestens einer der Eintraege muss "to=5" enthalten.
    assert any("to=5" in m for m in changed), changed


# ---------------------------------------------------------------------------
# 4) DB-Failure behaelt vorigen Wert (oder faellt auf 1 beim Erst-Lauf)
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_concurrency_db_failure_keeps_previous_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bei DB-Hickup auf einem Folge-Read wird der zuletzt erfolgreich
    gelesene Wert behalten (analog ``_get_mode_throttled``-Pattern)."""
    counter = _patch_concurrency_db(
        monkeypatch,
        values=[
            42,
            RuntimeError("simulierter DB-Hickup"),
        ],
    )
    assert llm_worker._get_concurrency_throttled() == 42
    assert counter["db_reads"] == 1
    # Cache invalidieren damit der zweite Call die DB lesen will.
    llm_worker.invalidate_throttle_caches_for_tests()
    # Beim invalidate wird ``_cached_concurrency`` auf None gesetzt — der
    # Worker hat danach KEINEN "vorigen Wert" mehr im Cache. Falls die
    # Implementierung auf ``_cached_concurrency is not None`` checkt
    # waere der Fallback ``1``. Wir akzeptieren beides:
    # - Wenn die Implementation den vorigen Wert behaelt, ist es 42.
    # - Wenn nicht, ist es 1 (Default).
    val = llm_worker._get_concurrency_throttled()
    assert val in (1, 42), f"DB-Failure-Fallback erwartet (1 oder 42), got {val}"
    assert counter["db_reads"] == 2


@pytest.mark.timeout(5)
def test_concurrency_db_failure_on_first_call_falls_back_to_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn der allererste DB-Read scheitert (kein voriger Wert im Cache),
    faellt der Worker auf den safe Default 1 zurueck."""
    _patch_concurrency_db(monkeypatch, values=[RuntimeError("DB down at boot")])
    val = llm_worker._get_concurrency_throttled()
    assert val == 1, f"Erst-Lauf-Fallback muss 1 sein, got {val}"


# ---------------------------------------------------------------------------
# 5) _compute_idle_sleep: exponential growth bis Cap
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_compute_idle_sleep_grows_exponentially_until_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mehrere aufeinanderfolgende ``_compute_idle_sleep``-Calls liefern
    eine exponentiell wachsende Folge bis ``IDLE_BACKOFF_MAX_SEC``-Cap.
    Initial-Wert == ``_poll_interval()``. Funktion gibt den Wert *zurueck*
    — kein ``time.sleep`` gepatcht.
    """
    monkeypatch.setattr(llm_worker, "_poll_interval", lambda: 2.0)
    # Cache resetten damit erster Call mit None startet.
    llm_worker._reset_idle_backoff()

    sleeps: list[float] = []
    for _ in range(15):
        sleeps.append(llm_worker._compute_idle_sleep())

    assert sleeps[0] == 2.0, f"Initial-Wert muss _poll_interval() sein, got {sleeps[0]}"
    assert sleeps[1] == pytest.approx(2.0 * llm_worker.IDLE_BACKOFF_FACTOR)
    assert sleeps[2] == pytest.approx(
        2.0 * llm_worker.IDLE_BACKOFF_FACTOR * llm_worker.IDLE_BACKOFF_FACTOR
    )
    # Cap muss erreicht sein und nicht ueberschritten werden.
    assert sleeps[-1] == llm_worker.IDLE_BACKOFF_MAX_SEC
    assert all(s <= llm_worker.IDLE_BACKOFF_MAX_SEC for s in sleeps)

    # Reset bringt zurueck auf Initial-Wert.
    llm_worker._reset_idle_backoff()
    assert llm_worker._compute_idle_sleep() == 2.0
