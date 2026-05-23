"""Pure-Unit-Tests fuer Block U Phase D — DB-Pool-Sizing
(siehe ``docs/blocks/U-worker-concurrency.md`` §Phase D).

Getestet werden ausschliesslich die Pure-Funktion
:func:`app.workers.llm_worker._compute_pool_sizing` und das Engine-Singleton-
Verhalten in :func:`app.workers.llm_worker._get_session_factory`.

Alle Tests vermeiden echten DB-Zugriff durch Monkeypatch von
``create_engine``, ``sessionmaker`` und ``load_settings``. Niemals echte
Postgres-Engine-Builds in Pure-Unit-Tests.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.workers import llm_worker

# ---------------------------------------------------------------------------
# Setup-Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_session_factory() -> Iterator[None]:
    """Stellt sicher dass jeder Test mit leerem Session-Factory-Cache startet."""
    llm_worker._session_factory = None
    yield
    llm_worker._session_factory = None


# ---------------------------------------------------------------------------
# 1) _compute_pool_sizing — Untergrenze
# ---------------------------------------------------------------------------


def test_pool_sizing_lower_bound_n1() -> None:
    """N=1: pool_size klemmt auf 10, max_overflow=1."""
    assert llm_worker._compute_pool_sizing(1) == (10, 1), (
        "N=1 muss (10, 1) liefern — Untergrenze 10 fuer Sub-Tick-Headroom"
    )


# ---------------------------------------------------------------------------
# 2) _compute_pool_sizing — Mittelfeld
# ---------------------------------------------------------------------------


def test_pool_sizing_mid_n50() -> None:
    """N=50: pool_size=N*2=100, max_overflow=N=50."""
    assert llm_worker._compute_pool_sizing(50) == (100, 50), (
        "N=50 muss (100, 50) liefern — Formel N*2 fuer pool_size"
    )


# ---------------------------------------------------------------------------
# 3) _compute_pool_sizing — Obergrenze
# ---------------------------------------------------------------------------


def test_pool_sizing_upper_bound_n200() -> None:
    """N=200: pool_size=400, max_overflow=200."""
    assert llm_worker._compute_pool_sizing(200) == (400, 200), (
        "N=200 muss (400, 200) liefern — Obergrenze, lineares Scaling"
    )


# ---------------------------------------------------------------------------
# 4) _compute_pool_sizing — Untergrenze-Klemmung im niedrigen N-Bereich
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "concurrency,expected",
    [
        (1, (10, 1)),  # Untergrenze klemmt
        (3, (10, 3)),  # 3*2=6 < 10 → klemmt auf 10
        (5, (10, 5)),  # 5*2=10, max_overflow=5
        (6, (12, 6)),  # 6*2=12, ueber Untergrenze → kein Klemmen
        (10, (20, 10)),
    ],
)
def test_pool_sizing_lower_bound_clamp(concurrency: int, expected: tuple[int, int]) -> None:
    """Untergrenze 10 wird nur fuer N*2 < 10 angewendet (N <= 4 klemmt)."""
    actual = llm_worker._compute_pool_sizing(concurrency)
    assert actual == expected, (
        f"_compute_pool_sizing({concurrency}) → {actual}, erwartet {expected}"
    )


# ---------------------------------------------------------------------------
# 5) Engine-Singleton — zweiter Aufruf gibt selbe Factory zurueck,
#    create_engine wird nur einmal gerufen.
# ---------------------------------------------------------------------------


def test_get_session_factory_is_singleton(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Engine + Factory werden lazy einmal gebaut, Folge-Calls geben Cache.

    Asserted:
    * ``create_engine`` wird genau einmal gerufen (nicht zweimal).
    * Kwargs enthalten ``pool_size=10, max_overflow=1, pool_pre_ping=True``
      fuer ``concurrency=1`` (Default).
    * Zweiter ``_get_session_factory()``-Call gibt dieselbe Factory-Instanz
      (selbe Objekt-ID) zurueck — kein Re-Build.
    """
    # Spy auf create_engine: sammelt Kwargs ein, liefert Dummy-Engine.
    fake_engine = MagicMock(name="fake_engine")
    create_engine_calls: list[dict[str, Any]] = []

    def _spy_create_engine(url: str, **kwargs: Any) -> Any:
        create_engine_calls.append({"url": url, **kwargs})
        return fake_engine

    # sessionmaker patchen damit der Bind nicht echt verdrahtet wird.
    fake_factory = MagicMock(name="fake_session_factory")
    sessionmaker_calls: list[dict[str, Any]] = []

    def _spy_sessionmaker(**kwargs: Any) -> Any:
        sessionmaker_calls.append(kwargs)
        return fake_factory

    # load_settings liefert Concurrency=1 und eine Dummy-URL.
    fake_cfg = SimpleNamespace(
        llm_worker_job_concurrency=1,
        database_url="postgresql+psycopg://test",
    )

    monkeypatch.setattr(llm_worker, "create_engine", _spy_create_engine)
    monkeypatch.setattr(llm_worker, "sessionmaker", _spy_sessionmaker)
    monkeypatch.setattr(llm_worker, "load_settings", lambda: fake_cfg)

    first = llm_worker._get_session_factory()
    second = llm_worker._get_session_factory()

    assert first is fake_factory, "erster Call sollte die patched Factory zurueckgeben"
    assert second is first, "zweiter Call muss dieselbe Factory-Objekt-ID liefern (Singleton-Cache)"

    # create_engine genau einmal — nicht pro Call.
    assert len(create_engine_calls) == 1, (
        f"create_engine sollte 1x gerufen werden, war {len(create_engine_calls)}x"
    )
    kwargs = create_engine_calls[0]
    assert kwargs["url"] == "postgresql+psycopg://test", kwargs
    assert kwargs.get("pool_size") == 10, kwargs
    assert kwargs.get("max_overflow") == 1, kwargs
    assert kwargs.get("pool_pre_ping") is True, kwargs
    assert kwargs.get("future") is True, kwargs

    # sessionmaker auch nur einmal gebaut.
    assert len(sessionmaker_calls) == 1, (
        f"sessionmaker sollte 1x gerufen werden, war {len(sessionmaker_calls)}x"
    )
