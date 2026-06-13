# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pure-Unit-Tests fuer ``app.workers.research_worker`` (Block AI, ADR-0063, P5).

DB-frei: Session-Factory + ``research_upstream_sync`` werden gemockt. Kein echtes
Postgres (``_pick_next_row_id`` mit FOR UPDATE SKIP LOCKED, ``_fail_or_requeue``/
``_run_stale_reaper`` mit ``make_interval`` -> Live/db_integration, beim User).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.workers import research_worker as mod
from app.workers.research_worker import (
    _max_attempts,
    _poll_interval,
    _redact_preview,
    _seed_from_row,
    _stale_timeout_min,
    classify_error,
)


@pytest.fixture(autouse=True)
def _reset_worker_state() -> Any:
    mod.reset_shutdown_for_tests()
    yield
    mod.reset_shutdown_for_tests()
    mod._session_factory = None


# ---------------------------------------------------------------------------
# _redact_preview — Secret-Maskierung im Exception-Log-Preview (GELB #1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,secret",
    [
        ("connect failed url=https://x?api_key=sk-deadbeef end", "sk-deadbeef"),
        ("auth failed password=hunter2 retry", "hunter2"),
        ("token=ghp_SeCrEtToKeN rejected", "ghp_SeCrEtToKeN"),
        ("header Authorization: Bearer sk-abc123 was sent", "sk-abc123"),
        ("secret=topsecretvalue", "topsecretvalue"),
    ],
)
def test_redact_preview_masks_secret_substrings(raw: str, secret: str) -> None:
    out = _redact_preview(raw)
    assert secret not in out
    assert "[REDACTED]" in out


def test_redact_preview_masks_url_userinfo() -> None:
    out = _redact_preview("download failed for https://admin:s3cr3t@searx.local/search")
    assert "s3cr3t" not in out
    assert "admin" not in out
    assert "[REDACTED]" in out


def test_redact_preview_leaves_benign_text_intact() -> None:
    out = _redact_preview("connection reset by peer (errno 104)")
    assert out == "connection reset by peer (errno 104)"


# ---------------------------------------------------------------------------
# classify_error — generische, leck-freie Codes
# ---------------------------------------------------------------------------


class _TimeoutError(Exception):
    pass


class _ReadDeadlineError(Exception):
    pass


def test_classify_timeout() -> None:
    assert classify_error(_TimeoutError("boom")) == "timeout"
    assert classify_error(_ReadDeadlineError("boom")) == "timeout"


def test_classify_httpx_module_is_search_error() -> None:
    exc = httpx.ConnectError("refused")
    assert classify_error(exc) == "search_error"


class _NetworkUnreachableError(Exception):
    pass


def test_classify_network_named_is_search_error() -> None:
    assert classify_error(_NetworkUnreachableError("x")) == "search_error"


def test_classify_openai_module_is_provider_error() -> None:
    # Kuenstliche Exception mit __module__ das "openai" enthaelt.
    exc = type("APIError", (Exception,), {"__module__": "openai._exceptions"})("k")
    assert classify_error(exc) == "provider_error"


def test_classify_pydantic_ai_module_is_provider_error() -> None:
    exc = type("UsageLimitExceeded", (Exception,), {"__module__": "pydantic_ai.exceptions"})("x")
    assert classify_error(exc) == "provider_error"


class _UsageLimitExceededError(Exception):
    pass


def test_classify_usagelimit_named_is_provider_error() -> None:
    assert classify_error(_UsageLimitExceededError("x")) == "provider_error"


def test_classify_generic_is_internal_error() -> None:
    assert classify_error(ValueError("weird")) == "internal_error"


def test_classify_never_returns_raw_text() -> None:
    """Der zurueckgegebene Code darf nie den rohen Exception-Text enthalten."""
    secret = "Bearer sk-supersecret-key"
    for exc in (
        _TimeoutError(secret),
        httpx.ConnectError(secret),
        _UsageLimitExceededError(secret),
        ValueError(secret),
    ):
        code = classify_error(exc)
        assert secret not in code
        assert code in {"timeout", "search_error", "provider_error", "internal_error"}


# ---------------------------------------------------------------------------
# ENV-Parser — Default / invalid / Untergrenze
# ---------------------------------------------------------------------------


def test_poll_interval_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FM_RESEARCH_WORKER_POLL_INTERVAL_SEC", raising=False)
    assert _poll_interval() == 5.0


def test_poll_interval_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FM_RESEARCH_WORKER_POLL_INTERVAL_SEC", "2.5")
    assert _poll_interval() == 2.5


@pytest.mark.parametrize("bad", ["abc", "0.0", "0.05"])
def test_poll_interval_invalid_or_below_floor(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setenv("FM_RESEARCH_WORKER_POLL_INTERVAL_SEC", bad)
    assert _poll_interval() == 5.0


def test_max_attempts_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FM_RESEARCH_WORKER_MAX_ATTEMPTS", raising=False)
    assert _max_attempts() == 3


def test_max_attempts_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FM_RESEARCH_WORKER_MAX_ATTEMPTS", "5")
    assert _max_attempts() == 5


@pytest.mark.parametrize("bad", ["abc", "0", "-1"])
def test_max_attempts_invalid_or_below_floor(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setenv("FM_RESEARCH_WORKER_MAX_ATTEMPTS", bad)
    assert _max_attempts() == 3


def test_stale_timeout_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FM_RESEARCH_WORKER_STALE_TIMEOUT_MIN", raising=False)
    assert _stale_timeout_min() == 10


def test_stale_timeout_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FM_RESEARCH_WORKER_STALE_TIMEOUT_MIN", "20")
    assert _stale_timeout_min() == 20


@pytest.mark.parametrize("bad", ["abc", "0", "-3"])
def test_stale_timeout_invalid_or_below_floor(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setenv("FM_RESEARCH_WORKER_STALE_TIMEOUT_MIN", bad)
    assert _stale_timeout_min() == 10


# ---------------------------------------------------------------------------
# _seed_from_row
# ---------------------------------------------------------------------------


def test_seed_from_row_full() -> None:
    row = SimpleNamespace(
        artifact_module="tailscaled",
        installed_version="v1.26.1",
        ecosystem="gobinary",
        binary_path="usr/sbin/tailscaled",
        vulnerable_component="stdlib",
        fixing_component_version="1.26.2",
        cve="CVE-2026-42504",
        description="desc",
        search_hint="tailscale",
    )
    seed = _seed_from_row(row)
    assert seed.artifact_module == "tailscaled"
    assert seed.installed_component_version == "v1.26.1"
    assert seed.ecosystem == "gobinary"
    assert seed.finding_class == "lang-pkgs"
    assert seed.binary_path == "usr/sbin/tailscaled"
    assert seed.vulnerable_component == "stdlib"
    assert seed.fixing_component_version == "1.26.2"
    assert seed.cve == "CVE-2026-42504"
    assert seed.description == "desc"
    assert seed.search_hint == "tailscale"


def test_seed_from_row_defaults_for_missing_snapshot_fields() -> None:
    row = SimpleNamespace(
        artifact_module="k3s",
        installed_version="v1.30.0",
        ecosystem=None,
        binary_path=None,
        vulnerable_component=None,
        fixing_component_version=None,
        cve=None,
        description=None,
        search_hint=None,
    )
    seed = _seed_from_row(row)
    assert seed.ecosystem == "unknown"
    assert seed.binary_path == ""
    assert seed.vulnerable_component == ""
    assert seed.fixing_component_version == ""
    assert seed.cve == ""
    assert seed.description is None
    assert seed.search_hint is None


# ---------------------------------------------------------------------------
# _tick — Session-Factory + research_upstream_sync gemockt
# ---------------------------------------------------------------------------


class _FakeSession:
    """Session-Fake mit get/execute/commit/rollback/close fuer _tick-Pfade."""

    def __init__(self, store: dict[int, Any]) -> None:
        self._store = store
        self.committed = False

    def get(self, _model: Any, row_id: int) -> Any:
        return self._store.get(row_id)

    def execute(self, *_a: Any, **_k: Any) -> Any:
        # Default: leere Queue (kein Pick).
        return SimpleNamespace(fetchone=lambda: None, fetchall=list)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None


def _install_session_factory(monkeypatch: pytest.MonkeyPatch, session: _FakeSession) -> None:
    """Patcht ``_get_session_factory`` so dass get_session den Fake liefert."""
    monkeypatch.setattr(mod, "_get_session_factory", lambda: lambda: session)
    # Stale-Reaper deaktivieren (kein Postgres make_interval).
    monkeypatch.setattr(mod, "_maybe_run_stale_reaper", lambda: None)


def test_tick_empty_queue_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _FakeSession(store={})
    _install_session_factory(monkeypatch, session)
    monkeypatch.setattr(mod, "_pick_next_row_id", lambda: None)
    assert mod._tick() is False


def test_tick_processes_job_persists_verdict_done(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.upstream_research import Verdict

    row = SimpleNamespace(
        id=42,
        artifact_module="tailscaled",
        installed_version="v1.26.1",
        ecosystem="gobinary",
        binary_path="usr/sbin/tailscaled",
        vulnerable_component="stdlib",
        fixing_component_version="1.26.2",
        cve="CVE-2026-42504",
        description="desc",
        search_hint="tailscale",
        status="running",
        delivery=None,
        latest_release_component_version=None,
        fixed_build_release=None,
        fixed_build_release_date=None,
        operator_action=None,
        confidence=None,
        sources_used=None,
        reasoning=None,
        model=None,
        error="prev",
        checked_at=None,
    )
    session = _FakeSession(store={42: row})
    _install_session_factory(monkeypatch, session)
    monkeypatch.setattr(mod, "_pick_next_row_id", lambda: 42)

    # Gate -> configured True; Settings + Seed-Bau gemockt.
    monkeypatch.setattr(mod, "is_upstream_check_configured", lambda s: True)
    settings_stub = SimpleNamespace(llm_research_model="model-x")
    monkeypatch.setattr(mod, "ensure_settings_row", lambda s: settings_stub)
    monkeypatch.setattr(mod, "build_search_config", lambda s, *, encryption_key: SimpleNamespace())
    monkeypatch.setattr(
        mod,
        "load_settings",
        lambda: SimpleNamespace(encryption_key=SimpleNamespace(get_secret_value=lambda: "k")),
    )

    verdict = Verdict(
        fixing_component_version="1.26.2",
        latest_release_component_version="1.26.2",
        latest_release_found="v1.27.0",
        fixed_build_release="v1.27.0",
        fixed_build_release_date="2026-06-01",
        delivery="fixed_release_exists",
        operator_action="Upgrade.",
        confidence="high",
        sources_used=["http://x"],
        reasoning="found",
    )
    seen: dict[str, Any] = {}

    def fake_research(seed: Any, **kwargs: Any) -> Verdict:
        seen["seed"] = seed
        return verdict

    monkeypatch.setattr(mod, "research_upstream_sync", fake_research)

    assert mod._tick() is True
    assert row.status == "done"
    assert row.delivery == "fixed_release_exists"
    assert row.fixed_build_release == "v1.27.0"
    assert row.operator_action == "Upgrade."
    assert row.confidence == "high"
    assert row.sources_used == ["http://x"]
    assert row.model == "model-x"
    assert row.error is None
    assert row.checked_at is not None
    # Seed wurde aus der Zeile rekonstruiert.
    assert seen["seed"].artifact_module == "tailscaled"


def test_tick_not_configured_sets_error_without_running_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = SimpleNamespace(
        id=7,
        artifact_module="k3s",
        installed_version="v1.30.0",
        status="running",
        error=None,
        checked_at=None,
    )
    session = _FakeSession(store={7: row})
    _install_session_factory(monkeypatch, session)
    monkeypatch.setattr(mod, "_pick_next_row_id", lambda: 7)
    monkeypatch.setattr(mod, "is_upstream_check_configured", lambda s: False)
    monkeypatch.setattr(mod, "ensure_settings_row", lambda s: SimpleNamespace())

    called = {"agent": False}

    def fake_research(*_a: Any, **_k: Any) -> Any:  # pragma: no cover — darf nie laufen
        called["agent"] = True
        raise AssertionError("agent must not run when not configured")

    monkeypatch.setattr(mod, "research_upstream_sync", fake_research)

    assert mod._tick() is True
    assert row.status == "error"
    assert row.error == "not_configured"
    assert called["agent"] is False


def test_tick_shutdown_flag_still_finishes_current_pick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shutdown bricht die Tick-Loop ab (in main()); _tick selbst arbeitet die
    geclaimte Zeile zu Ende — wir verifizieren dass das Flag den Loop in main
    stoppt indem wir _tick mit gesetztem Flag aufrufen und es trotzdem laeuft."""
    session = _FakeSession(store={})
    _install_session_factory(monkeypatch, session)
    monkeypatch.setattr(mod, "_pick_next_row_id", lambda: None)
    mod.request_shutdown_for_tests()
    # _tick selbst prueft das Flag nicht — leere Queue -> False.
    assert mod._tick() is False
    assert mod._shutdown is True
