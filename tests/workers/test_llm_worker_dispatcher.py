"""Pure-Unit-Tests fuer Block U Phase C — Async-Dispatcher mit Greedy
Slot-Refill (siehe ``docs/blocks/U-worker-concurrency.md`` §"Phase C").

Getestet wird ausschliesslich :func:`app.workers.llm_worker._run_async_main`
mit gemockten Pickup-/Mode-/Budget-/Concurrency-Helpern und einer
mock-Job-Coroutine. Es laufen weder Postgres-Sessions noch echte LLM-Calls.

Acht Test-Cases entsprechend der Block-Spec:

1. N=1 — Single-Slot, Refill nach Done.
2. N=5 — fuenf parallele Slots bis Queue leer.
3. N=200 — maximales In-Flight, FIFO via Pick-Sequenz.
4. Hot-Reload — Concurrency-Up und -Down mid-run.
5. Shutdown-Drain happy path.
6. Shutdown-Drain Timeout (mit gepatchtem ``SHUTDOWN_DRAIN_TIMEOUT_SEC``).
7. Mode-flip auf "off" mid-flight blockt neuen Pickup.
8. Budget-exhausted mid-flight blockt neuen Pickup.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator
from typing import Any

import pytest

from app.workers import llm_worker

# ---------------------------------------------------------------------------
# Autouse-Fixtures: deterministischer State und Logger-Reset
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_worker_state() -> Iterator[None]:
    """Setzt Modul-State (Shutdown-Flag, Caches) vor und nach jedem Test zurueck."""
    llm_worker.reset_shutdown_for_tests()
    llm_worker.invalidate_throttle_caches_for_tests()
    yield
    llm_worker.reset_shutdown_for_tests()
    llm_worker.invalidate_throttle_caches_for_tests()


@pytest.fixture(autouse=True)
def _reset_worker_logger() -> Iterator[None]:
    """Defensive Logger-State-Reset gegen Test-Pollution (siehe Phase-B-Pattern)."""
    worker_logger = logging.getLogger("fathometer.llm_worker")
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


@pytest.fixture(autouse=True)
def _patch_subticks_and_idle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sub-Ticks (Reaper/Eviction/Feed-Pull/Ingest/Retention) und Idle-Sleep
    auf No-Ops setzen — Dispatcher-Tests duerfen keine DB anfassen und nicht
    real schlafen."""
    monkeypatch.setattr(llm_worker, "_run_subticks", lambda: None)
    # ``_compute_idle_sleep`` darf seinen State updaten, soll aber nicht
    # tatsaechlich blockieren. Wir patchen den Helfer auf einen kurzen
    # Sleep-Wert; der Dispatcher ``await``-t dann auf eine Zero-Sleep-Variante.
    monkeypatch.setattr(llm_worker, "_compute_idle_sleep", lambda: 0.0)
    monkeypatch.setattr(llm_worker, "_reset_idle_backoff", lambda: None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _PickSequence:
    """Mock-``_pick_next_job_id`` der eine vordefinierte Sequenz abarbeitet.

    Nach Erschoepfen der Sequenz liefert er ``None``. Zaehlt zusaetzlich die
    Aufrufe damit Tests die FIFO-/Pickup-Anzahl assertieren koennen.
    """

    def __init__(self, sequence: list[int | None]) -> None:
        self._seq = list(sequence)
        self.calls = 0
        self.picked: list[int] = []

    def __call__(self) -> int | None:
        self.calls += 1
        if not self._seq:
            return None
        val = self._seq.pop(0)
        if val is not None:
            self.picked.append(val)
        return val


class _ConcurrencyValueSequence:
    """Mock-``_get_concurrency_throttled`` der nacheinander vorgegebene Werte
    liefert. Letzter Wert bleibt sticky.

    Anders als bei ``_PickSequence`` wird der zuletzt gelieferte Wert
    behalten — Hot-Reload-Tests wollen typischerweise "erste N Iterationen
    Wert X, dann Wert Y, dann sticky Wert Z" abbilden.
    """

    def __init__(self, sequence: list[int]) -> None:
        assert sequence, "Mindestens ein Wert noetig"
        self._seq = list(sequence)
        self.calls = 0

    def __call__(self) -> int:
        self.calls += 1
        if len(self._seq) > 1:
            return self._seq.pop(0)
        return self._seq[0]


# ---------------------------------------------------------------------------
# 1) N=1 — Single-Slot, Refill nach Done
# ---------------------------------------------------------------------------


@pytest.mark.timeout(10)
async def test_dispatcher_n1_single_slot_serial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bei concurrency=1 laeuft hoechstens 1 Task gleichzeitig.

    Wir geben drei Pickup-Ids vor, danach ``None``. Jeder Task wartet auf
    sein eigenes Event — der Test gibt sie nacheinander frei. Maximum
    gleichzeitiger Tasks wird beobachtet und muss <= 1 sein.
    """
    pick_sequence: list[int | None] = [1, 2, 3, None]
    pick = _PickSequence(pick_sequence)
    monkeypatch.setattr(llm_worker, "_pick_next_job_id", pick)
    monkeypatch.setattr(llm_worker, "_get_concurrency_throttled", lambda: 1)
    monkeypatch.setattr(llm_worker, "_get_mode_throttled", lambda: "live")
    monkeypatch.setattr(llm_worker, "_budget_ok_throttled", lambda: True)

    in_flight_counter: dict[str, int] = {"current": 0, "max": 0}
    started_events: dict[int, asyncio.Event] = {}

    async def _process_one_async(job_id: int, mode: str) -> dict[str, Any] | None:
        in_flight_counter["current"] += 1
        in_flight_counter["max"] = max(in_flight_counter["max"], in_flight_counter["current"])
        ev = started_events.setdefault(job_id, asyncio.Event())
        await ev.wait()
        in_flight_counter["current"] -= 1
        return {"duration_ms": 1, "cache_hit": False}

    monkeypatch.setattr(llm_worker, "_process_one_async", _process_one_async)

    # Driver-Coroutine: gibt Tasks nacheinander frei und triggert Shutdown
    # nachdem alle drei durch sind.
    async def _driver() -> None:
        for jid in (1, 2, 3):
            # Warten bis der Task tatsaechlich gestartet wurde.
            for _ in range(200):
                if jid in started_events:
                    break
                await asyncio.sleep(0.001)
            else:  # pragma: no cover — Defense
                raise AssertionError(f"Task {jid} never started")
            started_events[jid].set()
            # Kurz yielden damit Task aufgeraeumt wird bevor naechster Pick.
            await asyncio.sleep(0.005)
        # Queue ist leer, kein in_flight → Shutdown setzen damit Dispatcher
        # die Schleife verlaesst.
        llm_worker.request_shutdown_for_tests()

    await asyncio.gather(llm_worker._run_async_main(), _driver())

    assert in_flight_counter["max"] == 1, (
        f"N=1 erlaubt nur 1 in-flight Task, gemessen={in_flight_counter['max']}"
    )
    assert pick.picked == [1, 2, 3], f"FIFO-Pickup erwartet, got {pick.picked}"


# ---------------------------------------------------------------------------
# 2) N=5 mit 10 queued Jobs — fuenf Slots gefuellt, FIFO-Refill
# ---------------------------------------------------------------------------


@pytest.mark.timeout(10)
async def test_dispatcher_n5_keeps_five_slots_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mit concurrency=5 und 10 queued Jobs hat der Dispatcher zu jedem
    Zeitpunkt zwischen 1 und 5 in-flight Tasks. Maximum-Beobachtung == 5.
    """
    n_jobs = 10
    pick = _PickSequence([*range(1, n_jobs + 1), None])
    monkeypatch.setattr(llm_worker, "_pick_next_job_id", pick)
    monkeypatch.setattr(llm_worker, "_get_concurrency_throttled", lambda: 5)
    monkeypatch.setattr(llm_worker, "_get_mode_throttled", lambda: "live")
    monkeypatch.setattr(llm_worker, "_budget_ok_throttled", lambda: True)

    in_flight_counter: dict[str, int] = {"current": 0, "max": 0}
    started_events: dict[int, asyncio.Event] = {}
    started_order: list[int] = []

    async def _process_one_async(job_id: int, mode: str) -> dict[str, Any] | None:
        in_flight_counter["current"] += 1
        in_flight_counter["max"] = max(in_flight_counter["max"], in_flight_counter["current"])
        started_order.append(job_id)
        ev = started_events.setdefault(job_id, asyncio.Event())
        await ev.wait()
        in_flight_counter["current"] -= 1
        return {"duration_ms": 1, "cache_hit": False}

    monkeypatch.setattr(llm_worker, "_process_one_async", _process_one_async)

    async def _driver() -> None:
        # Warten bis die ersten 5 Slots gefuellt sind.
        for _ in range(500):
            if len(started_events) >= 5:
                break
            await asyncio.sleep(0.001)
        else:  # pragma: no cover
            raise AssertionError("Dispatcher hat keine 5 Tasks gestartet")
        assert in_flight_counter["current"] == 5, (
            f"5 Slots gefuellt erwartet, got {in_flight_counter['current']}"
        )

        # Jeden Task einzeln freigeben und sicherstellen dass der naechste
        # gestartet wird (Refill greift).
        for jid in range(1, n_jobs + 1):
            for _ in range(500):
                if jid in started_events:
                    break
                await asyncio.sleep(0.001)
            else:  # pragma: no cover
                raise AssertionError(f"Task {jid} nicht gestartet (Refill broken)")
            started_events[jid].set()
            await asyncio.sleep(0.001)

        llm_worker.request_shutdown_for_tests()

    await asyncio.gather(llm_worker._run_async_main(), _driver())

    assert in_flight_counter["max"] == 5, (
        f"Maximum gleichzeitiger Tasks == 5 erwartet, got {in_flight_counter['max']}"
    )
    # FIFO: erste 5 Picks sind 1..5 in dieser Reihenfolge.
    assert started_order[:5] == [1, 2, 3, 4, 5], (
        f"FIFO-Verletzung in den ersten 5 Picks: {started_order[:5]}"
    )
    assert pick.picked == list(range(1, n_jobs + 1))


# ---------------------------------------------------------------------------
# 3) N=200 / 250 queued — maximales In-Flight bei 200
# ---------------------------------------------------------------------------


@pytest.mark.timeout(15)
async def test_dispatcher_n200_caps_at_two_hundred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mit concurrency=200 und 250 queued Jobs uebersteigt das beobachtete
    Maximum in-flight nicht 200.
    """
    n_jobs = 250
    pick = _PickSequence([*range(1, n_jobs + 1), None])
    monkeypatch.setattr(llm_worker, "_pick_next_job_id", pick)
    monkeypatch.setattr(llm_worker, "_get_concurrency_throttled", lambda: 200)
    monkeypatch.setattr(llm_worker, "_get_mode_throttled", lambda: "live")
    monkeypatch.setattr(llm_worker, "_budget_ok_throttled", lambda: True)

    in_flight_counter: dict[str, int] = {"current": 0, "max": 0}
    started_events: dict[int, asyncio.Event] = {}

    async def _process_one_async(job_id: int, mode: str) -> dict[str, Any] | None:
        in_flight_counter["current"] += 1
        in_flight_counter["max"] = max(in_flight_counter["max"], in_flight_counter["current"])
        ev = started_events.setdefault(job_id, asyncio.Event())
        await ev.wait()
        in_flight_counter["current"] -= 1
        return None

    monkeypatch.setattr(llm_worker, "_process_one_async", _process_one_async)

    async def _driver() -> None:
        # Warten bis 200 Slots gefuellt sind.
        for _ in range(2000):
            if in_flight_counter["current"] >= 200:
                break
            await asyncio.sleep(0.001)
        else:  # pragma: no cover
            raise AssertionError(
                f"Dispatcher cap-fill broken, current={in_flight_counter['current']}"
            )
        assert in_flight_counter["max"] == 200, f"Cap-Verletzung: max={in_flight_counter['max']}"

        # Alle freigeben (Refill bringt die letzten 50).
        for jid in range(1, n_jobs + 1):
            for _ in range(2000):
                if jid in started_events:
                    break
                await asyncio.sleep(0.001)
            else:  # pragma: no cover
                raise AssertionError(f"Task {jid} nicht gestartet")
            started_events[jid].set()

        # Yield damit verbleibende Tasks fertig werden.
        await asyncio.sleep(0.01)
        llm_worker.request_shutdown_for_tests()

    await asyncio.gather(llm_worker._run_async_main(), _driver())

    assert in_flight_counter["max"] <= 200, (
        f"Cap N=200 verletzt, beobachtet max={in_flight_counter['max']}"
    )
    assert pick.picked == list(range(1, n_jobs + 1))


# ---------------------------------------------------------------------------
# 4) Hot-Reload — Concurrency-Up und -Down mid-run
# ---------------------------------------------------------------------------


@pytest.mark.timeout(10)
async def test_dispatcher_hot_reload_up_and_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrency-Wechsel mid-run.

    Wir pruefen drei Eigenschaften in einem Lauf:

    * Start mit cap=5 — Dispatcher fuellt genau 5 Slots.
    * cap → 10 mid-run — beim naechsten Refill werden bis zu 10 Slots
      gefuellt.
    * cap → 2 mid-run mit nicht freigegebenen Tasks — solange
      ``len(in_flight) > 2`` bleibt, pickt der Dispatcher KEINE neuen Jobs.
    """
    n_jobs = 30
    pick = _PickSequence([*range(1, n_jobs + 1), None])
    monkeypatch.setattr(llm_worker, "_pick_next_job_id", pick)

    cap_state: dict[str, int] = {"value": 5}
    monkeypatch.setattr(llm_worker, "_get_concurrency_throttled", lambda: cap_state["value"])
    monkeypatch.setattr(llm_worker, "_get_mode_throttled", lambda: "live")
    monkeypatch.setattr(llm_worker, "_budget_ok_throttled", lambda: True)

    started_events: dict[int, asyncio.Event] = {}
    started_ids: list[int] = []

    async def _process_one_async(job_id: int, mode: str) -> dict[str, Any] | None:
        ev = started_events.setdefault(job_id, asyncio.Event())
        started_ids.append(job_id)
        await ev.wait()
        return None

    monkeypatch.setattr(llm_worker, "_process_one_async", _process_one_async)

    async def _driver() -> None:
        # Phase 1: warten bis cap=5 erreicht.
        for _ in range(500):
            if len(started_events) >= 5:
                break
            await asyncio.sleep(0.001)
        assert len(started_events) == 5, (
            f"cap=5 in Phase 1 nicht erreicht, started={len(started_events)}"
        )

        # Phase 2: cap auf 10 hochregeln. Wir muessen mindestens einen Task
        # finish'en lassen damit der Dispatcher den naechsten Refill-Zyklus
        # erreicht (er wartet in ``asyncio.wait(FIRST_COMPLETED)``).
        cap_state["value"] = 10
        started_events[1].set()
        for _ in range(500):
            if len(started_events) >= 10:
                break
            await asyncio.sleep(0.001)
        assert len(started_events) >= 9, (
            f"Hochregeln auf 10 hat nicht gegriffen, started={len(started_events)}"
        )

        # Phase 3: cap auf 2 herunterregeln. KEIN neuer Pickup darf passieren,
        # solange in_flight > 2. Wir messen die Pick-Count vor dem Wechsel und
        # geben EINEN weiteren Task frei (Trigger fuer den naechsten Refill).
        cap_state["value"] = 2
        picks_before = len(pick.picked)
        # Genau einen Task freigeben — Dispatcher kommt aus dem wait(), liest
        # cap=2 und sieht len(in_flight) > 2 → kein Pickup.
        first_unset = next(j for j, e in started_events.items() if not e.is_set())
        started_events[first_unset].set()
        await asyncio.sleep(0.05)
        # In dieser Pause darf der Dispatcher keinen weiteren Job gepickt haben.
        assert len(pick.picked) == picks_before, (
            "cap-Reduction broken: Pickup waehrend in_flight > cap, "
            f"picks_before={picks_before}, picks_after={len(pick.picked)}"
        )

        # Cleanup: zuerst Shutdown setzen damit der Dispatcher NICHT noch
        # weitere Jobs picked. Danach alle bekannten Tasks freigeben.
        llm_worker.request_shutdown_for_tests()
        for ev in started_events.values():
            ev.set()

    await asyncio.gather(llm_worker._run_async_main(), _driver())

    # Falls der Dispatcher unter cap=2 doch noch neue Picks gestartet hat
    # (vor dem Shutdown-Flag), warten wir auf alle Pending-Tasks ab. Ohne
    # diesen Cleanup-Schritt kann pytest-asyncio beim Loop-Close haengen.
    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
    if pending:
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


# ---------------------------------------------------------------------------
# 5) Shutdown-Drain happy path
# ---------------------------------------------------------------------------


@pytest.mark.timeout(10)
async def test_dispatcher_shutdown_drain_happy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn das Shutdown-Flag mit 3 in-flight Tasks faellt und alle Tasks
    binnen Drain-Timeout fertig werden, wartet ``gather`` sauber durch und
    ein finaler ``dispatcher_shutdown``-Log erscheint."""
    pick = _PickSequence([1, 2, 3, None])
    monkeypatch.setattr(llm_worker, "_pick_next_job_id", pick)
    monkeypatch.setattr(llm_worker, "_get_concurrency_throttled", lambda: 3)
    monkeypatch.setattr(llm_worker, "_get_mode_throttled", lambda: "live")
    monkeypatch.setattr(llm_worker, "_budget_ok_throttled", lambda: True)

    started: dict[int, asyncio.Event] = {}
    finished: list[int] = []

    async def _process_one_async(job_id: int, mode: str) -> dict[str, Any] | None:
        ev = started.setdefault(job_id, asyncio.Event())
        await ev.wait()
        finished.append(job_id)
        return None

    monkeypatch.setattr(llm_worker, "_process_one_async", _process_one_async)

    # Log-Capture
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

        async def _driver() -> None:
            for _ in range(500):
                if len(started) >= 3:
                    break
                await asyncio.sleep(0.001)
            llm_worker.request_shutdown_for_tests()
            # Tasks freigeben damit Drain sauber durchkommt.
            await asyncio.sleep(0.005)
            for ev in started.values():
                ev.set()

        await asyncio.gather(llm_worker._run_async_main(), _driver())
    finally:
        llm_worker.log.removeHandler(handler)
        llm_worker.log.setLevel(prev_level)

    assert sorted(finished) == [1, 2, 3], f"Alle 3 Tasks sollten finishen, got {finished}"
    msgs = [r.getMessage() for r in captured]
    assert any("dispatcher_shutdown" in m for m in msgs), (
        f"dispatcher_shutdown-Log erwartet, captured: {msgs}"
    )
    # KEIN Drain-Timeout-Log im Happy Path.
    assert not any("shutdown_drain_timeout" in m for m in msgs), (
        f"Kein Drain-Timeout-Log erwartet, captured: {msgs}"
    )


# ---------------------------------------------------------------------------
# 6) Shutdown-Drain Timeout
# ---------------------------------------------------------------------------


@pytest.mark.timeout(10)
async def test_dispatcher_shutdown_drain_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn in-flight Tasks beim Shutdown nicht binnen Drain-Timeout fertig
    werden, loggt der Dispatcher WARNING ``shutdown_drain_timeout`` und
    kehrt trotzdem (mit ``dispatcher_shutdown``-Log) zurueck.

    Wir testen den Drain-Pfad gezielt: ``_shutdown`` ist *vor* Dispatcher-
    Start gesetzt, so dass der Loop sofort die Drain-Phase erreicht.
    Wir bauen zuvor 2 blockierende Pseudo-Tasks via ``asyncio.create_task``
    und injecten sie in das ``in_flight``-Set — das ginge im Live-Pfad
    nicht, aber fuer den Test-Helper machen wir den Drain-Branch explizit.

    Alternativ rufen wir den Dispatcher mit zwei Pickup-Schritten so auf
    dass er hochfaehrt, einen Task pickt, ihn aber als ``done`` sieht
    bevor der zweite picked wird — dann Shutdown.

    Wir wahlen den Ansatz "Tasks sind alle ``done``-able": jeder Task
    blockiert auf einem Event, das der Driver kurz VOR dem Drain-Timeout
    setzt fuer EINEN Task und VOR dem Drain-Timeout NICHT fuer den
    anderen → Drain endet mit TimeoutError, WARNING wird geloggt.
    """
    pick = _PickSequence([10, 20, None])
    monkeypatch.setattr(llm_worker, "_pick_next_job_id", pick)
    monkeypatch.setattr(llm_worker, "_get_concurrency_throttled", lambda: 2)
    monkeypatch.setattr(llm_worker, "_get_mode_throttled", lambda: "live")
    monkeypatch.setattr(llm_worker, "_budget_ok_throttled", lambda: True)
    monkeypatch.setattr(llm_worker, "SHUTDOWN_DRAIN_TIMEOUT_SEC", 0.05)

    started: dict[int, asyncio.Event] = {}
    finish_signal: dict[int, asyncio.Event] = {}

    async def _process_one_async(job_id: int, mode: str) -> dict[str, Any] | None:
        ev = finish_signal.setdefault(job_id, asyncio.Event())
        started[job_id] = asyncio.Event()
        started[job_id].set()  # Marker: gestartet
        await ev.wait()
        return None

    monkeypatch.setattr(llm_worker, "_process_one_async", _process_one_async)

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

        async def _driver() -> None:
            # Warten bis beide Tasks im _process_one_async angekommen sind.
            for _ in range(500):
                if len(started) >= 2:
                    break
                await asyncio.sleep(0.001)
            # Einen Task freigeben damit asyncio.wait(FIRST_COMPLETED) returnt;
            # nach return setzt der Dispatcher sofort _shutdown wahr (driver),
            # picked nicht weiter (Sequenz None), und faellt in den Drain mit
            # dem zweiten Task → der bleibt blockiert → Drain-TimeoutError.
            llm_worker.request_shutdown_for_tests()
            finish_signal[10].set()
            # Task 20 bleibt absichtlich blockiert.

        await asyncio.gather(llm_worker._run_async_main(), _driver())

        # Cleanup: hängenden Task 20 jetzt freigeben damit pytest-asyncio
        # den Loop sauber schliessen kann.
        finish_signal[20].set()
        pending = [
            t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()
        ]
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    finally:
        llm_worker.log.removeHandler(handler)
        llm_worker.log.setLevel(prev_level)

    msgs = [r.getMessage() for r in captured]
    assert any("shutdown_drain_timeout" in m for m in msgs), (
        f"WARNING-Log shutdown_drain_timeout erwartet, captured: {msgs}"
    )
    assert any("dispatcher_shutdown" in m for m in msgs), (
        f"dispatcher_shutdown-Log erwartet (Drain-Funktion kehrt sauber zurueck), captured: {msgs}"
    )


# ---------------------------------------------------------------------------
# 7) Mode flip auf "off" mid-flight
# ---------------------------------------------------------------------------


@pytest.mark.timeout(10)
async def test_dispatcher_mode_off_blocks_new_pickup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn ``_get_mode_throttled`` mid-run "off" zurueckliefert, pickt der
    Dispatcher keine neuen Jobs mehr. Bereits in-flight Tasks laufen sauber
    aus.
    """
    pick = _PickSequence([1, 2, 3, 4, 5, None])
    monkeypatch.setattr(llm_worker, "_pick_next_job_id", pick)
    monkeypatch.setattr(llm_worker, "_get_concurrency_throttled", lambda: 5)
    monkeypatch.setattr(llm_worker, "_budget_ok_throttled", lambda: True)

    mode_state: dict[str, str] = {"value": "live"}
    monkeypatch.setattr(llm_worker, "_get_mode_throttled", lambda: mode_state["value"])

    started: dict[int, asyncio.Event] = {}
    finished: list[int] = []

    async def _process_one_async(job_id: int, mode: str) -> dict[str, Any] | None:
        ev = started.setdefault(job_id, asyncio.Event())
        await ev.wait()
        finished.append(job_id)
        return None

    monkeypatch.setattr(llm_worker, "_process_one_async", _process_one_async)

    async def _driver() -> None:
        # Warten bis drei Tasks gestartet sind.
        for _ in range(500):
            if len(started) >= 3:
                break
            await asyncio.sleep(0.001)
        picks_before_flip = len(pick.picked)

        # Mode auf off setzen.
        mode_state["value"] = "off"

        # Einen Task freigeben → Dispatcher kommt zum naechsten Refill-Loop;
        # darf aber NICHT picken weil mode=off.
        first_jid = next(iter(started))
        started[first_jid].set()
        await asyncio.sleep(0.02)

        # Keine neuen Picks seit dem flip (3 waren schon gepickt, aber kein
        # Refill).
        assert len(pick.picked) == picks_before_flip, (
            f"Mode=off muss neuen Pickup blocken, picks_before={picks_before_flip}, "
            f"picks_after={len(pick.picked)}"
        )

        # Restliche freigeben → in-flight laeuft aus.
        for _jid, ev in list(started.items()):
            ev.set()
        await asyncio.sleep(0.02)
        llm_worker.request_shutdown_for_tests()

    await asyncio.gather(llm_worker._run_async_main(), _driver())

    # Es darf NICHT mehr als die initial gepickten Tasks finishen.
    assert sorted(finished) == sorted(started.keys()), (
        f"Nur initial gepickte Tasks duerfen finishen, finished={finished}"
    )


# ---------------------------------------------------------------------------
# 8) Budget-exhausted mid-flight
# ---------------------------------------------------------------------------


@pytest.mark.timeout(10)
async def test_dispatcher_budget_exhausted_blocks_new_pickup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Analog Test 7 mit ``_budget_ok_throttled`` statt Mode."""
    pick = _PickSequence([1, 2, 3, 4, 5, None])
    monkeypatch.setattr(llm_worker, "_pick_next_job_id", pick)
    monkeypatch.setattr(llm_worker, "_get_concurrency_throttled", lambda: 5)
    monkeypatch.setattr(llm_worker, "_get_mode_throttled", lambda: "live")

    budget_state: dict[str, bool] = {"ok": True}
    monkeypatch.setattr(llm_worker, "_budget_ok_throttled", lambda: budget_state["ok"])

    started: dict[int, asyncio.Event] = {}
    finished: list[int] = []

    async def _process_one_async(job_id: int, mode: str) -> dict[str, Any] | None:
        ev = started.setdefault(job_id, asyncio.Event())
        await ev.wait()
        finished.append(job_id)
        return None

    monkeypatch.setattr(llm_worker, "_process_one_async", _process_one_async)

    async def _driver() -> None:
        for _ in range(500):
            if len(started) >= 3:
                break
            await asyncio.sleep(0.001)
        picks_before_flip = len(pick.picked)

        # Budget erschoepfen.
        budget_state["ok"] = False

        # Einen Task freigeben → Dispatcher Refill-Loop blockt am Budget-Check.
        first_jid = next(iter(started))
        started[first_jid].set()
        await asyncio.sleep(0.02)

        assert len(pick.picked) == picks_before_flip, (
            f"Budget-exhausted muss neuen Pickup blocken, "
            f"picks_before={picks_before_flip}, picks_after={len(pick.picked)}"
        )

        # Restliche freigeben + Shutdown.
        for ev in list(started.values()):
            ev.set()
        await asyncio.sleep(0.02)
        llm_worker.request_shutdown_for_tests()

    await asyncio.gather(llm_worker._run_async_main(), _driver())

    assert sorted(finished) == sorted(started.keys())
