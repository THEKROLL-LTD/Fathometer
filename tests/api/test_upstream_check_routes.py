"""Pure-Unit-/Mock-Tests fuer das Upstream-Check-Blueprint (Block AI-2, ADR-0063, P1).

Bewusst DB-FREI (analog ``tests/api/test_group_chat.py``): die Module-globalen
Symbole im ``app.api.upstream_check``-Namespace werden gepatcht —
``_guard_or_404`` (IDOR-Guard), ``get_session``, ``get_settings_row``,
``is_upstream_check_configured`` (Gating), ``worst_upstream_finding`` (server-
seitige Finding-Wahl) und ``enqueue_upstream_check``. Auth via
``LOGIN_DISABLED=True``, Limiter zurueckgesetzt.

Das echte Panel-Template wird gerendert (P2-Single-Source); wir pruefen
Status-Codes, Gating, force-Parsing, Guard/IDOR und den IntegrityError->409-Pfad.
Live-LLM/Netz und der echte Enqueue-DB-Roundtrip stehen beim User an.
"""

from __future__ import annotations

import contextlib
from types import SimpleNamespace
from typing import Any

import pytest
from flask import Flask
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import NotFound

import app.api.upstream_check as uc


class _Settings:
    pass


class _FakeSession:
    def __init__(self) -> None:
        self.commit_count = 0
        self.rollback_count = 0

    def commit(self) -> None:
        self.commit_count += 1

    def rollback(self) -> None:
        self.rollback_count += 1


def _seed() -> SimpleNamespace:
    return SimpleNamespace(
        artifact_module="tailscaled",
        installed_component_version="v1.26.1",
        vulnerable_component="stdlib",
        fixing_component_version="1.26.2",
        cve="CVE-2026-0001",
    )


def _result_row(status: str = "queued") -> SimpleNamespace:
    return SimpleNamespace(
        status=status,
        checked_at=None,
        error=None,
        delivery=None,
        fixed_build_release=None,
        fixed_build_release_date=None,
        latest_release_component_version=None,
        operator_action=None,
        confidence=None,
        sources_used=None,
        reasoning=None,
    )


@pytest.fixture
def nodb_app(app: Flask) -> Flask:
    from app import limiter

    app.config.update(TESTING=True, LOGIN_DISABLED=True, WTF_CSRF_ENABLED=False)
    with contextlib.suppress(Exception):
        limiter.reset()
    return app


def _patch_common(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sess: _FakeSession,
    guard_ok: bool = True,
    configured: bool = True,
    finding: Any = ...,
) -> None:
    """Patcht Guard + Session + Settings + Gating + Finding-Wahl."""

    def _guard(sid: int, gid: int) -> tuple[Any, list[Any]]:
        if not guard_ok:
            raise NotFound()
        return SimpleNamespace(id=sid), [SimpleNamespace(id=1)]

    monkeypatch.setattr(uc, "_guard_or_404", _guard)
    monkeypatch.setattr(uc, "get_session", lambda: sess)
    monkeypatch.setattr(uc, "get_settings_row", lambda _s=None: _Settings())
    monkeypatch.setattr(uc, "is_upstream_check_configured", lambda _row: configured)
    if finding is not ...:
        monkeypatch.setattr(uc, "worst_upstream_finding", lambda _s, _sid, _gid: finding)


# ===========================================================================
# enqueue (POST)
# ===========================================================================


def test_enqueue_not_configured_returns_409_no_enqueue(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    sess = _FakeSession()
    enqueue_calls: list[Any] = []
    _patch_common(monkeypatch, sess=sess, configured=False)
    monkeypatch.setattr(
        uc, "enqueue_upstream_check", lambda *a, **k: enqueue_calls.append(a) or _result_row()
    )

    resp = nodb_app.test_client().post("/servers/1/groups/1/upstream-check")
    assert resp.status_code == 409, resp.data
    assert b'data-state="disabled"' in resp.data
    assert enqueue_calls == [], "kein Enqueue wenn nicht konfiguriert"
    assert sess.commit_count == 0


def test_enqueue_no_upstream_finding_returns_404(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    sess = _FakeSession()
    _patch_common(monkeypatch, sess=sess, configured=True, finding=None)
    monkeypatch.setattr(uc, "enqueue_upstream_check", lambda *a, **k: _result_row())

    resp = nodb_app.test_client().post("/servers/1/groups/1/upstream-check")
    assert resp.status_code == 404, resp.data
    assert b'data-state="idle"' in resp.data
    assert sess.commit_count == 0


def test_enqueue_success_renders_running_panel(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    sess = _FakeSession()
    finding = SimpleNamespace(id=5)
    _patch_common(monkeypatch, sess=sess, configured=True, finding=finding)
    monkeypatch.setattr(uc, "enqueue_upstream_check", lambda *a, **k: _result_row(status="queued"))
    monkeypatch.setattr(uc, "build_research_seed", lambda _f: _seed())

    resp = nodb_app.test_client().post("/servers/1/groups/2/upstream-check")
    assert resp.status_code == 200, resp.data
    assert b'data-state="running"' in resp.data
    assert b'id="upstream-check-1-2-panel"' in resp.data
    assert sess.commit_count == 1


@pytest.mark.parametrize(
    ("form_value", "expected_force"),
    [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("0", False),
        ("", False),
        (None, False),
    ],
)
def test_enqueue_force_parsing(
    nodb_app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    form_value: str | None,
    expected_force: bool,
) -> None:
    sess = _FakeSession()
    finding = SimpleNamespace(id=5)
    captured: dict[str, Any] = {}
    _patch_common(monkeypatch, sess=sess, configured=True, finding=finding)

    def _enq(_s: Any, _f: Any, *, force: bool = False) -> Any:
        captured["force"] = force
        return _result_row()

    monkeypatch.setattr(uc, "enqueue_upstream_check", _enq)
    monkeypatch.setattr(uc, "build_research_seed", lambda _f: _seed())

    data = {} if form_value is None else {"force": form_value}
    resp = nodb_app.test_client().post("/servers/1/groups/1/upstream-check", data=data)
    assert resp.status_code == 200, resp.data
    assert captured["force"] is expected_force, captured


def test_enqueue_force_via_query_arg(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """``?force=true`` (Re-check-Button) wird ebenfalls geparst."""
    sess = _FakeSession()
    captured: dict[str, Any] = {}
    _patch_common(monkeypatch, sess=sess, configured=True, finding=SimpleNamespace(id=5))

    def _enq(_s: Any, _f: Any, *, force: bool = False) -> Any:
        captured["force"] = force
        return _result_row()

    monkeypatch.setattr(uc, "enqueue_upstream_check", _enq)
    monkeypatch.setattr(uc, "build_research_seed", lambda _f: _seed())

    resp = nodb_app.test_client().post("/servers/1/groups/1/upstream-check?force=true")
    assert resp.status_code == 200, resp.data
    assert captured["force"] is True


def test_enqueue_guard_blocks_cross_group_404(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guard wirft 404 (IDOR/Cross-Group) -> kein Gating-Check, kein Enqueue."""
    sess = _FakeSession()
    enqueue_calls: list[Any] = []
    _patch_common(monkeypatch, sess=sess, guard_ok=False, configured=True)
    monkeypatch.setattr(
        uc, "enqueue_upstream_check", lambda *a, **k: enqueue_calls.append(a) or _result_row()
    )

    resp = nodb_app.test_client().post("/servers/1/groups/9999/upstream-check")
    assert resp.status_code == 404, resp.data
    assert enqueue_calls == []


def test_enqueue_integrity_error_returns_409_not_500(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Parallel-Enqueue-Commit-Konflikt -> 409 (rollback + re-lookup), nie 500."""
    sess = _FakeSession()
    _patch_common(monkeypatch, sess=sess, configured=True, finding=SimpleNamespace(id=5))

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise IntegrityError("stmt", {}, Exception("dup"))

    monkeypatch.setattr(uc, "enqueue_upstream_check", _boom)
    monkeypatch.setattr(
        uc,
        "lookup_state_for_group",
        lambda *_a, **_k: uc.derive_state(_result_row("running"), _seed(), configured=True),
    )

    resp = nodb_app.test_client().post("/servers/1/groups/1/upstream-check")
    assert resp.status_code == 409, resp.data
    assert sess.rollback_count == 1, "IntegrityError muss rollback ausloesen"
    assert sess.commit_count == 0


def test_enqueue_row_none_renders_idle(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """enqueue liefert None (Finding doch nicht researchbar) -> idle, 200."""
    sess = _FakeSession()
    _patch_common(monkeypatch, sess=sess, configured=True, finding=SimpleNamespace(id=5))
    monkeypatch.setattr(uc, "enqueue_upstream_check", lambda *a, **k: None)

    resp = nodb_app.test_client().post("/servers/1/groups/1/upstream-check")
    assert resp.status_code == 200, resp.data
    assert b'data-state="idle"' in resp.data


# ===========================================================================
# poll (GET)
# ===========================================================================


def test_poll_renders_panel_in_lookup_state(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    sess = _FakeSession()
    _patch_common(monkeypatch, sess=sess, configured=True)
    monkeypatch.setattr(
        uc,
        "lookup_state_for_group",
        lambda *_a, **_k: uc.derive_state(_result_row("running"), _seed(), configured=True),
    )

    resp = nodb_app.test_client().get("/servers/3/groups/4/upstream-check")
    assert resp.status_code == 200, resp.data
    assert b'data-state="running"' in resp.data
    assert b'id="upstream-check-3-4-panel"' in resp.data


def test_poll_disabled_when_not_configured(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    sess = _FakeSession()
    _patch_common(monkeypatch, sess=sess, configured=False)
    monkeypatch.setattr(
        uc,
        "lookup_state_for_group",
        lambda *a, **k: uc.derive_state(None, None, configured=False),
    )

    resp = nodb_app.test_client().get("/servers/1/groups/1/upstream-check")
    assert resp.status_code == 200, resp.data
    assert b'data-state="disabled"' in resp.data


def test_poll_guard_blocks_unknown_server_404(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    sess = _FakeSession()
    _patch_common(monkeypatch, sess=sess, guard_ok=False, configured=True)

    resp = nodb_app.test_client().get("/servers/999/groups/1/upstream-check")
    assert resp.status_code == 404, resp.data


def test_poll_get_needs_no_csrf(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """GET-Poll laeuft auch mit aktivem CSRF (kein Token noetig)."""
    from app import limiter

    app.config.update(TESTING=True, LOGIN_DISABLED=True, WTF_CSRF_ENABLED=True)
    with contextlib.suppress(Exception):
        limiter.reset()
    sess = _FakeSession()
    _patch_common(monkeypatch, sess=sess, configured=True)
    monkeypatch.setattr(
        uc,
        "lookup_state_for_group",
        lambda *a, **k: uc.derive_state(None, _seed(), configured=True),
    )

    resp = app.test_client().get("/servers/1/groups/1/upstream-check")
    assert resp.status_code == 200, resp.data


# ===========================================================================
# Rate-Limit-Decorator vorhanden (statische Inspektion)
# ===========================================================================


def test_routes_have_rate_limits_registered(app: Flask) -> None:
    """Beide Routen tragen einen flask-limiter-Decorator (POST 10/min, GET 120/min)."""
    from app import limiter

    decorated = limiter.limit_manager._decorated_limits
    providers = {
        key: [getattr(grp, "limit_provider", None) for grp in grps]
        for key, grps in decorated.items()
        if "upstream_check" in key
    }
    enqueue_key = "app.api.upstream_check.enqueue.enqueue"
    poll_key = "app.api.upstream_check.poll.poll"
    assert enqueue_key in providers, providers
    assert poll_key in providers, providers
    assert "10/minute" in providers[enqueue_key], providers[enqueue_key]
    assert "120/minute" in providers[poll_key], providers[poll_key]
