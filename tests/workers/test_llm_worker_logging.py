"""Pure-Unit-Tests fuer Block U Phase F — Logging-Refactor (Status-Snapshot
statt Per-Job-Laerm).

Siehe ``docs/blocks/U-worker-concurrency.md`` §"Phase F" und §"Tests".

Getestet werden ausschliesslich:

* Removal-Smoke — der Modul-Source enthaelt keine ``log.info``-Calls mit
  den entfernten Per-Job-Markern mehr. Pure-Static-Check, kein DB-Lauf.
* Error-Log unveraendert — ``llm_call_failed`` bleibt als WARNING-Marker
  im Source.
* :func:`_record_task_completion` — Counter fuer Done/Failed/Cache-Hits/
  Duration-Window.
* :func:`_maybe_emit_status_snapshot` — 30s-Cadence, Reset, Format,
  defensive DB-Read.
* :func:`_push_duration` — Cap auf 100 Eintraege im Rolling-Window.

Pattern fuer Logger-Reset und Modul-State-Reset orientiert sich an
``test_llm_worker_async_client.py`` (Phase B) und ``test_llm_worker_
dispatcher.py`` (Phase C).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.workers import llm_worker

# ---------------------------------------------------------------------------
# Removed log-marker keywords (Phase F). Diese Strings duerfen im Source
# NICHT mehr in einem ``log.info``-Call vorkommen. Lifecycle-Logs (z.B.
# ``dispatcher_started``) und Audit-Events (z.B. ``llm.job_picked`` in
# ``_audit``) sind nicht betroffen — nur der ``log.info``-Pfad.
# ---------------------------------------------------------------------------

# Wir matchen mit Trailing-Boundary-Zeichen (Whitespace, Quote) damit
# ``llm_worker.pass2_started`` NICHT versehentlich
# ``llm_worker.pass2_started_with_failed_pass1`` (bleibt erhalten, WARNING-
# Marker) matcht. Per Marker geben wir die Boundary-Suffixe explizit an —
# in der Praxis sind das das Trennzeichen vor dem ersten ``%s`` plus
# Quote- und Whitespace-Zeichen.
REMOVED_LOG_MARKERS: tuple[str, ...] = (
    "llm_worker.pass1_started ",
    "llm_worker.pass2_started ",
    "llm_worker.job_picked ",
    "llm_worker.job_done ",
    "llm_worker.llm_call_started ",
    "llm_worker.llm_call_completed ",
    "llm_worker.pass1_persist_done ",
    "llm_worker.pass2_persist_done ",
    "llm_worker.pass1_skipped ",
    "llm_worker.pass2_skipped ",
    "llm_worker.pass2_cache_lookup ",
    "llm_worker.pass2_cache_hit_applied ",
)


# ---------------------------------------------------------------------------
# Autouse-Fixtures: Modul-State und Logger-State zwischen Tests sauber
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_status_state() -> Iterator[None]:
    """Setzt Phase-F-Modul-State (Counter + Last-Snapshot-Zeit) zurueck.

    Damit Reihenfolge der Tests irrelevant ist — jeder Test startet mit
    Counter==0 und ``_last_status_at==0.0``.
    """
    llm_worker._status_counters["done"] = 0
    llm_worker._status_counters["failed"] = 0
    llm_worker._status_counters["cache_hits"] = 0
    llm_worker._status_counters["durations_ms"] = []
    llm_worker._last_status_at = 0.0
    yield
    llm_worker._status_counters["done"] = 0
    llm_worker._status_counters["failed"] = 0
    llm_worker._status_counters["cache_hits"] = 0
    llm_worker._status_counters["durations_ms"] = []
    llm_worker._last_status_at = 0.0


@pytest.fixture(autouse=True)
def _reset_worker_logger_state() -> Iterator[None]:
    """Defensive Logger-State-Reset (Pattern aus Phase B/C-Tests).

    ``configure_logging()`` / vorhergehende Tests koennen den
    ``secscan.llm_worker``-Logger ``disabled=True`` oder
    ``propagate=False`` setzen — dann waere ``caplog`` blind. Wir bringen
    den Logger in einen bekannten Zustand und stellen das Original danach
    wieder her.
    """
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


# ---------------------------------------------------------------------------
# Helper — Fake-Task fuer _record_task_completion
# ---------------------------------------------------------------------------


def _make_fake_task(*, exception: BaseException | None = None, result: Any = None) -> MagicMock:
    """Liefert ein ``MagicMock`` das wie ein ``asyncio.Task`` aussieht.

    Wichtig: ``exception()`` muss VOR ``result()`` aufrufbar sein, sonst
    waere der Test-Pfad fuer den Failed-Counter kaputt. Wir bauen das
    Mock so dass ``exception()`` einfach den vorgegebenen Wert zurueckgibt
    und ``result()`` den vorgegebenen Wert; nichts wird re-raisert.
    """
    task = MagicMock(spec=asyncio.Task)
    task.exception.return_value = exception
    task.result.return_value = result
    return task


# ---------------------------------------------------------------------------
# 1) Removal-Smoke — keine entfernten Marker mehr als log.info-Aufruf
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_removed_log_markers_are_absent_from_source() -> None:
    """Pure-Static-Check: keiner der entfernten Marker taucht im
    ``llm_worker.py``-Source als ``log.info``-Argument auf.

    Wir koennten den Mock-Pass-1-Lauf via ``_drive_dispatch_iteration``
    starten und ``caplog`` einsammeln — aber das laeuft gegen die echte
    DB (``db_integration``-Marker). Pure-Unit braucht den Source-Check:
    wenn der Marker als ``log.info``-Pattern im File steht, ist Phase F
    nicht vollstaendig.

    Lifecycle-Logs (``dispatcher_started``, ``client_rebuilt``,
    ``concurrency_changed``, ``shutdown_drain``, ``engine_built``,
    ``status``) duerfen weiterhin als ``log.info`` auftauchen — diese
    sind explizit erlaubt.
    """
    src = inspect.getsource(llm_worker)
    for marker in REMOVED_LOG_MARKERS:
        # Pattern: log.info-Aufruf mit dem Marker-Substring.
        # Wir suchen auf String-Level — ein einzelnes Vorkommen genuegt
        # zum Fehlschlag (das war ja in jedem Removed-Marker-Fall ein
        # log.info-Aufruf, die Audit-Events nutzen ``"llm.…"``-Tags ohne
        # ``llm_worker.``-Praefix).
        # Wir muessen aber den Test-File-Source ausschliessen — falls
        # dieser Code-Block in Coverage-Tools landet etc. Da
        # ``inspect.getsource(llm_worker)`` nur den Modul-Source liefert,
        # ist das automatisch der Fall.
        assert marker not in src, (
            f"Entfernter Log-Marker {marker!r} ist noch im Source — Phase F unvollstaendig."
        )


# ---------------------------------------------------------------------------
# 2) Error-Smoke — llm_call_failed bleibt als WARNING-Marker erhalten
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_error_log_marker_still_present() -> None:
    """``llm_worker.llm_call_failed`` bleibt unveraendert als WARNING.

    Source-Check: der Marker muss im File noch vorhanden sein (sonst
    haette Phase F versehentlich einen Error-Pfad mitgenommen).
    """
    src = inspect.getsource(llm_worker)
    assert "llm_worker.llm_call_failed" in src, (
        "WARNING-Marker llm_call_failed wurde versehentlich entfernt — "
        "Phase F darf Error-Pfade NICHT abklemmen."
    )


# ---------------------------------------------------------------------------
# 3) Snapshot-Counter (Done) — exception()==None, result-Dict
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_record_task_completion_counts_done() -> None:
    """Erfolgreicher Task → ``done`` +1, ``duration_ms`` ans Window."""
    task = _make_fake_task(exception=None, result={"duration_ms": 50, "cache_hit": False})
    llm_worker._record_task_completion(task)
    assert llm_worker._status_counters["done"] == 1
    assert llm_worker._status_counters["failed"] == 0
    assert llm_worker._status_counters["cache_hits"] == 0
    assert llm_worker._status_counters["durations_ms"] == [50]


@pytest.mark.timeout(5)
def test_record_task_completion_counts_cache_hit() -> None:
    """``result={'cache_hit': True}`` → ``cache_hits`` +1 zusaetzlich zu done."""
    task = _make_fake_task(exception=None, result={"duration_ms": 12, "cache_hit": True})
    llm_worker._record_task_completion(task)
    assert llm_worker._status_counters["done"] == 1
    assert llm_worker._status_counters["cache_hits"] == 1
    assert llm_worker._status_counters["durations_ms"] == [12]


# ---------------------------------------------------------------------------
# 4) Snapshot-Counter (Failed) — exception() liefert eine Exception
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_record_task_completion_counts_failed() -> None:
    """Task mit ``exception()`` != None → ``failed`` +1, kein result-Zugriff.

    Wichtig: der Implementer ruft ``task.exception()`` VOR ``task.result()``
    auf, sonst wuerde ``task.result()`` die Exception re-raisen. Wir
    bauen das Mock so dass ``result()`` einen Sentinel zurueckgibt, der
    nie verarbeitet werden darf — wenn das doch passiert, faellt das
    Cache-Hit-Assert durch.
    """
    sentinel_result = {"cache_hit": True, "duration_ms": 999}
    task = _make_fake_task(exception=RuntimeError("boom"), result=sentinel_result)
    llm_worker._record_task_completion(task)
    assert llm_worker._status_counters["failed"] == 1
    assert llm_worker._status_counters["done"] == 0
    # Defensive: weder cache_hits noch durations_ms duerfen aus dem
    # Sentinel-Result gelesen worden sein.
    assert llm_worker._status_counters["cache_hits"] == 0
    assert llm_worker._status_counters["durations_ms"] == []


# ---------------------------------------------------------------------------
# 5) Snapshot-Reset nach Emit
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_status_snapshot_resets_counters(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Nach ``_maybe_emit_status_snapshot`` sind alle Counter zurueckgesetzt."""
    # Counter befuellen.
    llm_worker._status_counters["done"] = 5
    llm_worker._status_counters["failed"] = 2
    llm_worker._status_counters["cache_hits"] = 1
    llm_worker._status_counters["durations_ms"] = [10, 20, 30]
    llm_worker._last_status_at = 0.0  # erzwingt Emit (Cadence-Check faellt durch)

    _patch_snapshot_db_reads(monkeypatch, queued=7, tokens_used=100, budget=1000)
    with caplog.at_level(logging.INFO, logger="secscan.llm_worker"):
        llm_worker._maybe_emit_status_snapshot(in_flight=3, cap=5)

    assert llm_worker._status_counters["done"] == 0
    assert llm_worker._status_counters["failed"] == 0
    assert llm_worker._status_counters["cache_hits"] == 0
    assert llm_worker._status_counters["durations_ms"] == []


# ---------------------------------------------------------------------------
# 6) Snapshot-Cadence — innerhalb 30s kein zweiter Emit
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_status_snapshot_cadence_skips_within_30s(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Zwei direkt aufeinanderfolgende Calls → nur eine Log-Line.

    Wir setzen ``_last_status_at`` auf "gerade eben" (``time.monotonic()``)
    — der Cadence-Check muss greifen und der zweite Call early-returnen.
    """
    import time as _time

    llm_worker._last_status_at = _time.monotonic()

    # DB-Reads patchen falls der Cadence-Check broken waere — die
    # Patches duerfen NICHT aufgerufen werden, sonst ist der Test
    # broken statt der Code.
    db_calls: dict[str, int] = {"get_session": 0, "ensure_settings_row": 0}

    def _spy_get_session() -> Any:
        db_calls["get_session"] += 1
        raise AssertionError("Cadence-Check broken — get_session() wurde aufgerufen")

    monkeypatch.setattr(llm_worker, "get_session", _spy_get_session)

    with caplog.at_level(logging.INFO, logger="secscan.llm_worker"):
        llm_worker._maybe_emit_status_snapshot(in_flight=1, cap=5)

    # Filter caplog auf den Snapshot-Marker (Trailing-Space damit
    # ``status_query_failed`` ausgeschlossen ist).
    status_records = [r for r in caplog.records if "llm_worker.status " in r.getMessage()]
    assert status_records == [], (
        f"Cadence-Check broken — Snapshot wurde innerhalb 30s emitted: "
        f"{[r.getMessage() for r in status_records]!r}"
    )
    assert db_calls["get_session"] == 0


# ---------------------------------------------------------------------------
# 7) Snapshot-Format — alle erwarteten Substrings im Log-Record
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_status_snapshot_format_contains_all_fields(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Der ``llm_worker.status``-Record enthaelt alle erwarteten Substrings."""
    llm_worker._status_counters["done"] = 4
    llm_worker._status_counters["failed"] = 1
    llm_worker._status_counters["cache_hits"] = 2
    llm_worker._status_counters["durations_ms"] = [40, 60]  # avg = 50
    llm_worker._last_status_at = 0.0

    _patch_snapshot_db_reads(monkeypatch, queued=12, tokens_used=250, budget=1000)

    with caplog.at_level(logging.INFO, logger="secscan.llm_worker"):
        llm_worker._maybe_emit_status_snapshot(in_flight=3, cap=5)

    status_records = [r for r in caplog.records if "llm_worker.status " in r.getMessage()]
    assert len(status_records) == 1, (
        f"genau einen status-Record erwartet, got {len(status_records)}: "
        f"{[r.getMessage() for r in status_records]!r}"
    )
    msg = status_records[0].getMessage()
    for needle in (
        "in_flight=3/5",
        "queued=12",
        "done_30s=4",
        "failed_30s=1",
        "cache_hits_30s=2",
        "budget_pct=25",
        "avg_call_ms=50",
    ):
        assert needle in msg, f"Substring {needle!r} fehlt in Snapshot-Message: {msg!r}"


# ---------------------------------------------------------------------------
# 8) Duration-Window-Cap — 105 Pushes → letzte 100 bleiben
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_push_duration_caps_at_one_hundred() -> None:
    """105 ``_push_duration``-Calls → Window-Laenge bleibt 100, aelteste werden gedroppt."""
    for ms in range(1, 106):  # 1..105 inkl.
        llm_worker._push_duration(ms)

    durations: list[int] = llm_worker._status_counters["durations_ms"]
    assert len(durations) == 100, f"Cap nicht eingehalten, len={len(durations)} statt 100"
    # Die aeltesten 5 (1..5) wurden gedroppt — der Window-Inhalt ist
    # 6..105.
    assert durations[0] == 6, (
        f"erstes Element nach Cap == 6 erwartet (1..5 gedroppt), got {durations[0]}"
    )
    assert durations[-1] == 105, f"letztes Element == 105 erwartet, got {durations[-1]}"


# ---------------------------------------------------------------------------
# 9) Snapshot defensiv bei DB-Read-Fehler
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
def test_status_snapshot_defensive_against_db_failure(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """DB-Read wirft → kein Crash, Snapshot loggt mit Fallback ``-1``.

    Der Implementer wrappt den DB-Read in ``try/except`` und loggt
    ``llm_worker.status_query_failed`` als WARNING. Der Snapshot selbst
    wird trotzdem emitted (sonst bliebe der Operator ohne Lebenszeichen),
    mit ``queued=-1`` und ``budget_pct=-1``.
    """
    llm_worker._last_status_at = 0.0

    class _BrokenSession:
        def execute(self, *_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("simulated DB failure")

    from contextlib import contextmanager

    @contextmanager
    def _broken_get_session() -> Iterator[Any]:
        yield _BrokenSession()

    monkeypatch.setattr(llm_worker, "get_session", _broken_get_session)
    # ensure_settings_row darf nicht aufgerufen werden — die Exception
    # in session.execute() schlaegt davor zu.
    monkeypatch.setattr(
        llm_worker,
        "ensure_settings_row",
        lambda _s: pytest.fail("ensure_settings_row sollte nach DB-Fehler nicht aufgerufen werden"),
    )

    # Caplog auf DEBUG damit sowohl INFO-Snapshot als auch WARNING-Marker
    # eingesammelt werden.
    with caplog.at_level(logging.DEBUG, logger="secscan.llm_worker"):
        # Darf NICHT crashen.
        llm_worker._maybe_emit_status_snapshot(in_flight=2, cap=5)

    # Status-Snapshot wird trotzdem emitted, mit Fallback-Werten.
    # Strenge Substring-Suche: ``llm_worker.status `` mit Trailing-Space
    # damit ``llm_worker.status_query_failed`` NICHT als Snapshot zaehlt.
    status_records = [r for r in caplog.records if "llm_worker.status " in r.getMessage()]
    assert len(status_records) == 1, (
        f"Snapshot soll auch bei DB-Fehler emitted werden, got {len(status_records)}: "
        f"{[r.getMessage() for r in status_records]!r}"
    )
    msg = status_records[0].getMessage()
    assert "queued=-1" in msg, f"Fallback queued=-1 fehlt: {msg!r}"
    assert "budget_pct=-1" in msg, f"Fallback budget_pct=-1 fehlt: {msg!r}"

    # WARNING-Marker fuer den DB-Fehler.
    warn_records = [r for r in caplog.records if "llm_worker.status_query_failed" in r.getMessage()]
    assert len(warn_records) == 1, (
        f"genau einen status_query_failed-WARNING erwartet, got {len(warn_records)}"
    )


# ---------------------------------------------------------------------------
# Helper — DB-Read-Patches fuer Snapshot-Tests
# ---------------------------------------------------------------------------


def _patch_snapshot_db_reads(
    monkeypatch: pytest.MonkeyPatch,
    *,
    queued: int,
    tokens_used: int,
    budget: int,
) -> None:
    """Patcht ``get_session``, ``ensure_settings_row`` und ``load_settings``
    fuer den Snapshot-DB-Read.

    ``_maybe_emit_status_snapshot`` liest:

    * ``session.execute(text("SELECT count(*) ... ")).scalar()`` → ``queued``
    * ``ensure_settings_row(session).llm_token_budget_used_today`` → ``tokens_used``
    * ``load_settings().llm_token_budget_daily`` → ``budget``
    """
    from contextlib import contextmanager

    class _FakeScalarResult:
        def __init__(self, value: int) -> None:
            self._value = value

        def scalar(self) -> int:
            return self._value

    class _FakeSession:
        def execute(self, *_args: Any, **_kwargs: Any) -> _FakeScalarResult:
            return _FakeScalarResult(queued)

    @contextmanager
    def _fake_get_session() -> Iterator[_FakeSession]:
        yield _FakeSession()

    fake_row = SimpleNamespace(llm_token_budget_used_today=tokens_used)
    fake_settings = SimpleNamespace(llm_token_budget_daily=budget)

    monkeypatch.setattr(llm_worker, "get_session", _fake_get_session)
    monkeypatch.setattr(llm_worker, "ensure_settings_row", lambda _s: fake_row)
    monkeypatch.setattr(llm_worker, "load_settings", lambda: fake_settings)
