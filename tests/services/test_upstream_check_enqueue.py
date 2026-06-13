# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pure-Unit-Tests fuer ``app.services.upstream_check_enqueue`` (Block AI, ADR-0063, P5).

DB-frei: Session als Fake (`.execute`/`.add`), Rows als ``SimpleNamespace``-Stub.
Kein echtes Postgres, kein Live-Netz/LLM.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.services import upstream_check_enqueue as mod
from app.services.upstream_check_enqueue import (
    UPSTREAM_CHECK_TTL_DAYS,
    _default_ttl_days,
    _is_fresh,
    enqueue_upstream_check,
)


def _finding(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "finding_class": "lang-pkgs",
        "fixed_version": "1.26.2",
        "target_path": "usr/sbin/tailscaled",
        "installed_version": "v1.26.1",
        "package_purl": "pkg:golang/stdlib@v1.26.1",
        "package_name": "stdlib@target",
        "identifier_key": "CVE-2026-42504",
        "result_type": "gobinary",
        "title": "stdlib flaw",
        "description": "desc",
        "owning_package": "tailscale",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _row(**overrides: Any) -> SimpleNamespace:
    """SimpleNamespace mit allen Spalten die enqueue setzt/liest."""
    base: dict[str, Any] = {
        "status": "done",
        "attempts": 5,
        "checked_at": datetime.now(UTC),
        "artifact_module": "tailscaled",
        "installed_version": "v1.26.1",
        "picked_up_at": datetime.now(UTC),
        "picked_up_by": "w",
        "next_attempt_at": None,
        "requested_at": None,
        "cve": None,
        "vulnerable_component": None,
        "fixing_component_version": None,
        "ecosystem": None,
        "binary_path": None,
        "search_hint": None,
        "description": None,
        "delivery": "fixed_release_exists",
        "latest_release_component_version": "x",
        "fixed_build_release": "x",
        "fixed_build_release_date": "x",
        "operator_action": "x",
        "confidence": "high",
        "sources_used": ["x"],
        "reasoning": "x",
        "error": None,
        "model": "m",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _FakeResult:
    def __init__(self, row: Any) -> None:
        self._row = row

    def scalar_one_or_none(self) -> Any:
        return self._row


class _FakeNested:
    """Stand-in fuer ``session.begin_nested()`` (Context-Manager, no-op)."""

    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    def __enter__(self) -> _FakeNested:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeSession:
    """Minimaler Session-Fake: `.execute` gibt vorprogrammierte Zeile, `.add` merkt sich.

    ``flush_raises`` simuliert einen Parallel-Enqueue-Race: der erste ``flush``
    wirft ``IntegrityError``; danach liefert ``execute`` die ``race_row`` (die
    von der „anderen" Transaktion angelegte Zeile).
    """

    def __init__(
        self,
        existing_row: Any = None,
        *,
        flush_raises: bool = False,
        race_row: Any = None,
    ) -> None:
        self._existing = existing_row
        self.added: list[Any] = []
        self._flush_raises = flush_raises
        self._race_row = race_row
        self._flushed = False
        self.flush_calls = 0
        self.begin_nested_calls = 0

    def execute(self, *_a: Any, **_k: Any) -> _FakeResult:
        # Nach einem geworfenen Flush (Race) liefert das Re-Select die race_row.
        if self._flushed and self._flush_raises:
            return _FakeResult(self._race_row)
        return _FakeResult(self._existing)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def begin_nested(self) -> _FakeNested:
        self.begin_nested_calls += 1
        return _FakeNested(self)

    def flush(self) -> None:
        self.flush_calls += 1
        if self._flush_raises and not self._flushed:
            self._flushed = True
            from sqlalchemy.exc import IntegrityError

            raise IntegrityError("INSERT", {}, Exception("duplicate key"))
        self._flushed = True


class _StubResult:
    """Leichtgewichtiger Stand-in fuer das ORM-``UpstreamCheckResult``.

    Klassen-Attribute ``artifact_module``/``installed_version`` decken den
    ``select(...).where(UpstreamCheckResult.artifact_module == ...)``-Ausdruck
    ab (kein echter ORM-Mapper noetig — ``_FakeSession.execute`` ignoriert die
    Query ohnehin). Der Konstruktor fuellt alle Felder mit ``None`` vor, die
    enqueue dann setzt.
    """

    artifact_module = None
    installed_version = None

    def __init__(self, **kwargs: Any) -> None:
        for name in _row().__dict__:
            setattr(self, name, None)
        for k, v in kwargs.items():
            setattr(self, k, v)


class _StubSelect:
    """No-op-Select: ``select(X).where(...)`` ohne SQLAlchemy-Compile."""

    def where(self, *_a: Any, **_k: Any) -> _StubSelect:
        return self


@pytest.fixture(autouse=True)
def _stub_upstream_check_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ersetzt das ORM-``UpstreamCheckResult`` + ``select`` durch Stubs.

    ``_FakeSession.execute`` ignoriert die Query ohnehin und liefert die
    vorprogrammierte Zeile — kein echter SQLAlchemy-Compile/-Mapper noetig.
    """
    monkeypatch.setattr(mod, "UpstreamCheckResult", _StubResult)
    monkeypatch.setattr(mod, "select", lambda *_a, **_k: _StubSelect())


# ---------------------------------------------------------------------------
# _default_ttl_days / ENV-Parser
# ---------------------------------------------------------------------------


def test_ttl_default_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FM_UPSTREAM_CHECK_TTL_DAYS", raising=False)
    assert _default_ttl_days() == 14


def test_ttl_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FM_UPSTREAM_CHECK_TTL_DAYS", "30")
    assert _default_ttl_days() == 30


@pytest.mark.parametrize("bad", ["abc", "", "-5", "0"])
def test_ttl_invalid_or_nonpositive_falls_back(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setenv("FM_UPSTREAM_CHECK_TTL_DAYS", bad)
    assert _default_ttl_days() == 14


# ---------------------------------------------------------------------------
# _is_fresh — TTL-Grenze + tz-naive checked_at
# ---------------------------------------------------------------------------


def test_is_fresh_done_within_ttl_true() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    row = _row(status="done", checked_at=now - timedelta(days=1))
    assert _is_fresh(row, ttl_days=14, now=now) is True


def test_is_fresh_done_beyond_ttl_false() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    row = _row(status="done", checked_at=now - timedelta(days=15))
    assert _is_fresh(row, ttl_days=14, now=now) is False


def test_is_fresh_non_done_false() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    row = _row(status="running", checked_at=now)
    assert _is_fresh(row, ttl_days=14, now=now) is False


def test_is_fresh_none_checked_at_false() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    row = _row(status="done", checked_at=None)
    assert _is_fresh(row, ttl_days=14, now=now) is False


def test_is_fresh_tz_naive_checked_at_treated_as_utc() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    naive = (now - timedelta(days=1)).replace(tzinfo=None)
    row = _row(status="done", checked_at=naive)
    assert _is_fresh(row, ttl_days=14, now=now) is True


# ---------------------------------------------------------------------------
# enqueue_upstream_check
# ---------------------------------------------------------------------------


def test_enqueue_returns_none_for_non_researchable() -> None:
    session = _FakeSession()
    assert enqueue_upstream_check(session, _finding(finding_class="os-pkgs")) is None


def test_enqueue_fresh_done_cache_hit_unchanged() -> None:
    row = _row(status="done", checked_at=datetime.now(UTC), attempts=7)
    session = _FakeSession(existing_row=row)
    out = enqueue_upstream_check(session, _finding())
    assert out is row
    # Unveraendert: kein Re-Enqueue.
    assert out.status == "done"
    assert out.attempts == 7
    assert session.added == []


@pytest.mark.parametrize("status", ["queued", "running"])
def test_enqueue_in_flight_unchanged_doubleclick_guard(status: str) -> None:
    # checked_at alt genug damit nicht als "fresh done" durchgeht.
    row = _row(status=status, checked_at=None, attempts=1)
    session = _FakeSession(existing_row=row)
    out = enqueue_upstream_check(session, _finding())
    assert out is row
    assert out.status == status  # nicht zurueckgesetzt
    assert out.attempts == 1


def test_enqueue_miss_creates_queued_row_with_seed_snapshot() -> None:
    session = _FakeSession(existing_row=None)
    out = enqueue_upstream_check(session, _finding())
    assert out is not None
    assert len(session.added) == 1
    assert out.status == "queued"
    assert out.attempts == 0
    assert out.cve == "CVE-2026-42504"
    assert out.vulnerable_component == "stdlib"
    assert out.fixing_component_version == "1.26.2"
    assert out.ecosystem == "gobinary"
    assert out.binary_path == "usr/sbin/tailscaled"
    assert out.search_hint == "tailscale"
    # Verdict-Felder geleert.
    assert out.delivery is None
    assert out.fixed_build_release is None
    assert out.operator_action is None
    assert out.confidence is None
    assert out.sources_used is None
    assert out.reasoning is None
    assert out.error is None
    assert out.model is None


def test_enqueue_stale_done_re_queues() -> None:
    row = _row(
        status="done",
        checked_at=datetime.now(UTC) - timedelta(days=100),
        attempts=3,
        delivery="fixed_release_exists",
    )
    session = _FakeSession(existing_row=row)
    out = enqueue_upstream_check(session, _finding())
    assert out is row
    assert out.status == "queued"
    assert out.attempts == 0
    assert out.delivery is None
    # Bestehende Zeile wird wiederverwendet (kein add).
    assert session.added == []


def test_enqueue_error_status_re_queues() -> None:
    row = _row(status="error", checked_at=None, error="provider_error", attempts=3)
    session = _FakeSession(existing_row=row)
    out = enqueue_upstream_check(session, _finding())
    assert out is row
    assert out.status == "queued"
    assert out.attempts == 0
    assert out.error is None


def test_enqueue_force_overrides_fresh_cache_hit() -> None:
    row = _row(status="done", checked_at=datetime.now(UTC), attempts=2)
    session = _FakeSession(existing_row=row)
    out = enqueue_upstream_check(session, _finding(), force=True)
    assert out is row
    assert out.status == "queued"
    assert out.attempts == 0
    assert out.delivery is None


def test_enqueue_respects_explicit_ttl_days() -> None:
    """``ttl_days``-Override: knapp ausserhalb -> re-queue statt Cache-Hit."""
    row = _row(status="done", checked_at=datetime.now(UTC) - timedelta(days=3), attempts=1)
    session = _FakeSession(existing_row=row)
    out = enqueue_upstream_check(session, _finding(), ttl_days=1)
    assert out is row
    assert out.status == "queued"


def test_module_ttl_constant_is_positive() -> None:
    assert UPSTREAM_CHECK_TTL_DAYS > 0


# ---------------------------------------------------------------------------
# Enqueue-Race (GELB #2, ADR-0063): Parallel-Insert -> IntegrityError -> re-select
# ---------------------------------------------------------------------------


def test_enqueue_insert_uses_savepoint_and_flush() -> None:
    """Der Miss-Insert-Pfad laeuft ueber begin_nested + flush (race-sicher)."""
    session = _FakeSession(existing_row=None)
    out = enqueue_upstream_check(session, _finding())
    assert out is not None
    assert session.begin_nested_calls == 1
    assert session.flush_calls == 1
    assert len(session.added) == 1


def test_enqueue_insert_race_reselects_inflight_row_unchanged() -> None:
    """Race: erster flush wirft IntegrityError; re-selectete in-flight Zeile bleibt unangetastet."""
    race_row = _row(status="running", checked_at=None, attempts=2)
    session = _FakeSession(existing_row=None, flush_raises=True, race_row=race_row)
    out = enqueue_upstream_check(session, _finding())
    # Re-Select liefert die von der anderen TX angelegte in-flight-Zeile.
    assert out is race_row
    # Nicht zurueckgesetzt (Idempotenz): die andere TX hat sie schon enqueued.
    assert out.status == "running"
    assert out.attempts == 2
    assert session.begin_nested_calls == 1


def test_enqueue_insert_race_reselects_fresh_done_unchanged() -> None:
    """Race auf eine bereits frisch-fertige Zeile -> Cache-Hit, kein Re-Queue."""
    race_row = _row(status="done", checked_at=datetime.now(UTC), attempts=4)
    session = _FakeSession(existing_row=None, flush_raises=True, race_row=race_row)
    out = enqueue_upstream_check(session, _finding())
    assert out is race_row
    assert out.status == "done"
    assert out.attempts == 4


def test_enqueue_insert_race_reselects_error_row_requeues() -> None:
    """Race auf eine error-Zeile -> normale Re-Queue-Logik greift."""
    race_row = _row(status="error", checked_at=None, error="provider_error", attempts=3)
    session = _FakeSession(existing_row=None, flush_raises=True, race_row=race_row)
    out = enqueue_upstream_check(session, _finding())
    assert out is race_row
    assert out.status == "queued"
    assert out.attempts == 0
    assert out.error is None
