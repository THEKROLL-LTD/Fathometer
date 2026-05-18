"""Adversarial: Zwei Worker simulieren simultanen Job-Pickup (ADR-0023).

`SELECT FOR UPDATE SKIP LOCKED` muss garantieren, dass bei N gleichzeitigen
Pickup-Versuchen exakt einer das Lock gewinnt und der/die anderen `None`
erhalten — ohne Hang, ohne Deadlock, ohne Doppel-Lock.

Wir testen mit zwei Threads, die je eine eigene Session-Factory haben.
Die Threads warten an einem `Barrier`-Punkt bis beide ready sind, dann
rufen sie gleichzeitig `_pick_next_job_id()` auf.

Mit zwei Jobs: beide muessen unterschiedliche Jobs picken (kein Re-Pick).
Mit einem Job: genau einer pickt, der andere bekommt `None`.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from flask import Flask

from app.db import get_session_factory
from app.models import LLMJob, Server
from app.workers import llm_worker


@pytest.fixture(autouse=True)
def _route_worker(db_app: Flask) -> Any:
    factory = get_session_factory(db_app)
    llm_worker.set_session_factory_for_tests(factory)
    llm_worker.reset_shutdown_for_tests()
    yield
    llm_worker.reset_shutdown_for_tests()


def _seed_jobs(db_app: Flask, count: int) -> list[int]:
    factory = get_session_factory(db_app)
    ids: list[int] = []
    with db_app.app_context():
        sess = factory()
        try:
            srv = Server(
                name="srv-race",
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
            )
            sess.add(srv)
            sess.flush()
            for _ in range(count):
                job = LLMJob(
                    job_type="group_detection",
                    server_id=srv.id,
                    payload={"finding_ids": []},
                    status="queued",
                )
                sess.add(job)
                sess.flush()
                ids.append(int(job.id))
            sess.commit()
        finally:
            sess.close()
    return ids


def test_two_workers_one_job_exactly_one_wins(db_app: Flask) -> None:
    """Ein Job, zwei Pickup-Threads → genau einer bekommt die ID."""
    _seed_jobs(db_app, count=1)

    results: list[int | None] = []
    barrier = threading.Barrier(2)

    def _worker() -> None:
        barrier.wait()
        with db_app.app_context():
            results.append(llm_worker._pick_next_job_id())

    threads = [threading.Thread(target=_worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive(), "thread hung — possible deadlock"

    non_none = [r for r in results if r is not None]
    assert len(non_none) == 1, f"exactly one worker must pick, got {results!r}"


def test_two_workers_two_jobs_no_double_pickup(db_app: Flask) -> None:
    """Zwei Jobs, zwei Pickup-Threads → beide bekommen einen, keine Dopplung."""
    seeded = sorted(_seed_jobs(db_app, count=2))

    results: list[int | None] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(2)

    def _worker() -> None:
        barrier.wait()
        with db_app.app_context():
            r = llm_worker._pick_next_job_id()
        with results_lock:
            results.append(r)

    threads = [threading.Thread(target=_worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive(), "thread hung — possible deadlock"

    picked = sorted(r for r in results if r is not None)
    assert picked == seeded, (
        f"both jobs must be picked exactly once, got picked={picked} seeded={seeded}"
    )


def test_five_workers_three_jobs_strict_partition(db_app: Flask) -> None:
    """5 Threads, 3 Jobs → genau 3 picken, 2 bekommen `None`."""
    seeded = sorted(_seed_jobs(db_app, count=3))

    results: list[int | None] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(5)

    def _worker() -> None:
        barrier.wait()
        with db_app.app_context():
            r = llm_worker._pick_next_job_id()
        with results_lock:
            results.append(r)

    threads = [threading.Thread(target=_worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive()

    picked = sorted(r for r in results if r is not None)
    nones = [r for r in results if r is None]
    assert picked == seeded, f"all 3 jobs picked exactly once, got {picked} vs {seeded}"
    assert len(nones) == 2, f"two workers must skip, got {len(nones)}"
