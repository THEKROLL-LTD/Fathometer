"""Pure-Unit-Tests fuer ``app.workers.llm_worker``.

Behalten sind ausschliesslich DB-freie Tests:

* Idle-Backoff-Verhalten (exponential growth + reset on pickup) — ``_idle_sleep_and_backoff``.
* Shutdown-Verhalten: ``main()`` kehrt sofort zurueck wenn ``_shutdown`` vor dem
  ersten Tick gesetzt ist. Heartbeat-Thread und Mode-Log-Read werden via
  ``monkeypatch`` auf der Modul-Ebene durch No-Ops ersetzt — kein DB-Zugriff.
* ``_aclose_reviewer_client``: Helfer-Funktion fuer httpx-Pool-Cleanup,
  vollstaendig pure (kein DB-/HTTP-Zugriff im Test-Body).

Die DB-/Race-/Heartbeat-Tests (Pickup mit SKIP LOCKED, depends_on,
Stale-Reaper, Mode-/Budget-Throttle, Live-Pass1/Pass2-Pipeline,
Validation-Error-Meta usw.) liegen in
``tests/integration/test_llm_worker_db.py``. Auto-Markierung als
``db_integration``/``acceptance`` erfolgt ueber
``tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from app.workers import llm_worker

# ---------------------------------------------------------------------------
# v0.9.6: Idle-Backoff
# ---------------------------------------------------------------------------


def test_idle_backoff_grows_exponentially_until_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bei aufeinanderfolgenden Leer-Pickups klettert die Sleep-Dauer von
    ``_poll_interval()`` (2s) ueber Faktor 1.5 hoch bis 30s-Cap."""
    sleeps: list[float] = []
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: sleeps.append(s))
    monkeypatch.setattr(llm_worker, "_poll_interval", lambda: 2.0)

    llm_worker.invalidate_throttle_caches_for_tests()
    for _ in range(10):
        llm_worker._idle_sleep_and_backoff()

    assert sleeps[0] == 2.0
    assert sleeps[1] == 3.0
    assert sleeps[2] == 4.5
    # Cap nach einigen Iterationen erreicht.
    assert sleeps[-1] == llm_worker.IDLE_BACKOFF_MAX_SEC
    assert sleeps[-2] == llm_worker.IDLE_BACKOFF_MAX_SEC


def test_idle_backoff_resets_on_pickup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nach erfolgreichem Pickup setzt ``_reset_idle_backoff`` den Zaehler
    zurueck sodass der naechste Idle-Cycle wieder bei 2s startet."""
    sleeps: list[float] = []
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: sleeps.append(s))
    monkeypatch.setattr(llm_worker, "_poll_interval", lambda: 2.0)

    llm_worker.invalidate_throttle_caches_for_tests()
    for _ in range(5):
        llm_worker._idle_sleep_and_backoff()
    assert sleeps[-1] > 2.0

    llm_worker._reset_idle_backoff()
    llm_worker._idle_sleep_and_backoff()
    assert sleeps[-1] == 2.0


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------


def test_main_returns_when_shutdown_flag_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wenn das Shutdown-Flag VOR dem ersten Dispatcher-Loop gesetzt ist,
    kehrt ``main()`` sofort zurueck — ohne Sub-Tick / Pickup auszufuehren.

    Pure-Unit-Variante (Block U Phase C, ADR-0029): das alte ``_tick()`` ist
    durch :func:`_run_async_main` ersetzt. Wir patchen Heartbeat-Thread und
    Mode-Log-Read modulweit auf No-Ops und ersetzen ``_run_subticks``,
    ``_pick_next_job_id`` und ``_get_concurrency_throttled`` durch
    Defensivsicherungen — sobald das Shutdown-Flag *vor* ``main()`` gesetzt
    ist, darf nichts davon aufgerufen werden.
    """
    monkeypatch.setenv("FM_ENCRYPTION_KEY", "x" * 32)
    monkeypatch.setenv("FM_SECRET_KEY", "test-secret-key-not-used-in-prod")
    monkeypatch.setenv(
        "FM_DATABASE_URL",
        "postgresql+psycopg://test:test@127.0.0.1:1/test",
    )
    monkeypatch.setenv("FM_LOG_LEVEL", "WARNING")

    # DB-Helpers raus aus dem main()-Pfad.
    monkeypatch.setattr(llm_worker, "_read_mode_safe", lambda: "off")
    monkeypatch.setattr(llm_worker, "_start_heartbeat_thread", lambda: None)
    monkeypatch.setattr(llm_worker, "_stop_heartbeat_thread", lambda timeout=5.0: None)
    monkeypatch.setattr(llm_worker.time, "sleep", lambda s: None)

    # Block U Phase C: _run_subticks und Pickup duerfen gar nicht erst
    # aufgerufen werden — Defensivsicherung damit ein Bug im Shutdown-Pfad
    # sofort sichtbar wird. Das Dispatcher-Run wird ueber das _shutdown-Flag
    # bereits in der ersten ``while not _shutdown``-Pruefung verlassen.
    def _boom_subticks() -> None:  # pragma: no cover
        raise AssertionError("_run_subticks must not run when _shutdown is set before main()")

    def _boom_pick() -> int | None:  # pragma: no cover
        raise AssertionError("_pick_next_job_id must not run when _shutdown is set before main()")

    monkeypatch.setattr(llm_worker, "_run_subticks", _boom_subticks)
    monkeypatch.setattr(llm_worker, "_pick_next_job_id", _boom_pick)
    # Concurrency-Read ist *vor* der while-Pruefung — wir lassen ihn 1
    # liefern (legal), darf aber keinen DB-Zugriff machen.
    monkeypatch.setattr(llm_worker, "_get_concurrency_throttled", lambda: 1)

    try:
        llm_worker.request_shutdown_for_tests()
        # signal.signal() funktioniert nur im Main-Thread — pytest erfuellt das.
        llm_worker.main()
        # Kein Hang, keine Exception → Test gruen.
    finally:
        llm_worker.reset_shutdown_for_tests()


# ---------------------------------------------------------------------------
# v0.9.x: httpx-Pool sauber schliessen (kein "Event loop is closed"-Trace)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aclose_reviewer_client_calls_client_aclose() -> None:
    """``_aclose_reviewer_client`` MUSS ``client.aclose()`` rufen sobald der
    Reviewer ein ``.client``-Attribut hat — damit der httpx-Pool im noch-
    offenen Event-Loop sauber schliesst und kein GC-Stacktrace entsteht."""
    aclose_calls = {"n": 0}

    class _SpyClient:
        async def aclose(self) -> None:
            aclose_calls["n"] += 1

    class _ReviewerWithSpy:
        def __init__(self) -> None:
            self.client = _SpyClient()

    await llm_worker._aclose_reviewer_client(_ReviewerWithSpy())
    assert aclose_calls["n"] == 1


@pytest.mark.asyncio
async def test_aclose_reviewer_client_tolerates_mock_without_client() -> None:
    """Test-Mocks (``_FakeReviewer``) haben kein ``client``-Attribut —
    ``_aclose_reviewer_client`` MUSS das ohne Exception aushalten."""

    class _ReviewerWithoutClient:
        pass

    # Soll NICHT werfen
    await llm_worker._aclose_reviewer_client(_ReviewerWithoutClient())


@pytest.mark.asyncio
async def test_aclose_reviewer_client_swallows_aclose_error() -> None:
    """Wenn ``client.aclose()`` selbst wirft (z.B. Loop schon zu), MUSS
    ``_aclose_reviewer_client`` defensiv loggen und nicht weiterwerfen —
    sonst wuerde der Finally-Cleanup eine Exception aus dem urspruenglichen
    Pfad ueberschreiben."""

    class _FailingClient:
        async def aclose(self) -> None:
            raise RuntimeError("Event loop is closed")

    class _ReviewerWithFailingClient:
        def __init__(self) -> None:
            self.client: Any = _FailingClient()

    # Soll NICHT werfen
    await llm_worker._aclose_reviewer_client(_ReviewerWithFailingClient())


# ---------------------------------------------------------------------------
# ADR-0035-Addendum (TD-013): daily_risk_state-Finalize-Sub-Tick
# ---------------------------------------------------------------------------


def test_daily_risk_state_finalize_swallows_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_run_daily_risk_state_finalize`` darf bei DB-/Service-Fehler NICHT
    crashen — ein Sub-Tick-Fehler kippt sonst den ganzen Worker-Loop.

    Wir patchen ``finalize_pending_days`` so dass es wirft, und ``get_session``
    auf eine triviale (DB-freie) Session. Der Helper muss ``log.exception``
    rufen und ohne weitergeworfene Exception zurueckkehren.
    """
    from contextlib import contextmanager

    @contextmanager
    def _fake_session() -> Any:
        yield MagicMock()

    monkeypatch.setattr(llm_worker, "get_session", _fake_session)

    def _boom(_session: Any) -> int:
        raise RuntimeError("db hickup during finalize")

    # finalize_pending_days wird via lokalem Import gezogen — wir patchen das
    # Symbol im Quellmodul.
    monkeypatch.setattr(
        "app.services.daily_risk_state.finalize_pending_days",
        _boom,
    )

    logged: dict[str, bool] = {"exception": False}
    monkeypatch.setattr(
        llm_worker.log,
        "exception",
        lambda *a, **k: logged.__setitem__("exception", True),
    )

    # Darf NICHT werfen.
    llm_worker._run_daily_risk_state_finalize()
    assert logged["exception"] is True


def test_daily_risk_state_finalize_commits_and_logs_inserts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bei erfolgreichem Finalize wird committed und (bei >0 Rows) geloggt."""
    from contextlib import contextmanager

    session = MagicMock()

    @contextmanager
    def _fake_session() -> Any:
        yield session

    monkeypatch.setattr(llm_worker, "get_session", _fake_session)
    monkeypatch.setattr(
        "app.services.daily_risk_state.finalize_pending_days",
        lambda _s: 7,
    )
    info_msgs: list[Any] = []
    monkeypatch.setattr(llm_worker.log, "info", lambda *a, **k: info_msgs.append(a))

    llm_worker._run_daily_risk_state_finalize()

    session.commit.assert_called_once()
    # inserted=7 -> genau eine info-Line.
    assert any("daily_risk_state_finalized" in str(a[0]) for a in info_msgs), info_msgs


def test_daily_risk_state_cadence_gating(monkeypatch: pytest.MonkeyPatch) -> None:
    """Modul-Global-Gating: innerhalb des Check-Intervalls wird nicht erneut
    finalisiert.

    Wir treiben ``_run_subticks`` mehrfach mit eingefrorener
    ``time.monotonic`` und gemockten Sub-Tick-Helfern (kein DB-Zugriff). Der
    erste Lauf (``_last_daily_risk_state_at == 0`` nach Reset) MUSS
    finalisieren; der zweite Lauf *kurz danach* (monotonic unveraendert) darf
    NICHT erneut finalisieren.
    """
    from contextlib import contextmanager

    # Alle anderen Sub-Tick-Helfer und Pickup auf No-Op patchen, damit
    # _run_subticks keinen DB-Zugriff macht.
    monkeypatch.setattr(llm_worker, "_run_stale_reaper", lambda: None)
    monkeypatch.setattr(llm_worker, "_run_debug_log_eviction", lambda: None)
    monkeypatch.setattr(llm_worker, "_run_feed_enrichment_check", lambda: None)
    monkeypatch.setattr(llm_worker, "_run_scan_ingest_retention_sweep_safe", lambda: None)
    monkeypatch.setattr(llm_worker, "_run_pass2_backstop_sweep_safe", lambda: None)
    monkeypatch.setattr(llm_worker, "_pick_next_scan_ingest_job_id", lambda _s: None)
    monkeypatch.setattr(llm_worker, "_process_scan_ingest_job_safe", lambda _i: None)

    @contextmanager
    def _fake_session() -> Any:
        yield MagicMock()

    monkeypatch.setattr(llm_worker, "get_session", _fake_session)

    finalize_calls = {"n": 0}
    monkeypatch.setattr(
        llm_worker,
        "_run_daily_risk_state_finalize",
        lambda: finalize_calls.__setitem__("n", finalize_calls["n"] + 1),
    )

    # Zeit einfrieren — ein fixer monotonic-Wert > 0, damit das Reset auf 0.0
    # den ersten Lauf als faellig markiert (now - 0 > Intervall).
    fixed_t = 10_000.0
    monkeypatch.setattr(llm_worker.time, "monotonic", lambda: fixed_t)

    try:
        llm_worker.reset_shutdown_for_tests()  # _last_daily_risk_state_at = 0.0
        llm_worker._run_subticks()
        # Erster Lauf: faellig (fixed_t - 0 > Intervall).
        assert finalize_calls["n"] == 1

        # Zweiter Lauf, monotonic UNVERAENDERT -> innerhalb Intervall -> kein
        # erneuter Finalize.
        llm_worker._run_subticks()
        assert finalize_calls["n"] == 1

        # Dritter Lauf, monotonic weit nach Intervall -> wieder faellig.
        monkeypatch.setattr(
            llm_worker.time,
            "monotonic",
            lambda: fixed_t + llm_worker.DAILY_RISK_STATE_CHECK_INTERVAL_SEC + 1.0,
        )
        llm_worker._run_subticks()
        assert finalize_calls["n"] == 2
    finally:
        llm_worker.reset_shutdown_for_tests()
