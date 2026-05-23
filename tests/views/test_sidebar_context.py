"""Pure-Unit-Tests fuer `app.views._sidebar_context` (Phase C, ADR-0030).

Prueft:
  - `build_sidebar_context` ruft KEIN `heartbeats_for_servers` auf.
  - `build_sidebar_context` liefert nur die billigen Keys.
  - Der Polling-Endpoint `sidebar_partial` liefert alle teuren Aggregate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import flask_login
import pytest
from flask import Flask

FIXED_NOW = datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# build_sidebar_context — billig-only, kein Heartbeat-Loader-Aufruf
# ---------------------------------------------------------------------------


def test_build_sidebar_context_does_not_call_heartbeats(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_sidebar_context darf heartbeats_for_servers NICHT aufrufen."""
    mock_sess = MagicMock()
    mock_sess.execute.return_value.scalars.return_value.unique.return_value.all.return_value = []
    mock_sess.execute.return_value.scalars.return_value.all.return_value = []

    heartbeat_spy = MagicMock()

    monkeypatch.setattr(
        "app.views._sidebar_context.get_session",
        lambda: mock_sess,
    )
    monkeypatch.setattr(
        "app.views._sidebar_context.heartbeats_for_servers",
        heartbeat_spy,
    )

    from app.views._sidebar_context import build_sidebar_context

    build_sidebar_context()

    heartbeat_spy.assert_not_called()


def test_build_sidebar_context_returns_cheap_keys_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_sidebar_context liefert nur die billigen Keys, kein sidebar_heartbeats."""
    mock_sess = MagicMock()
    mock_sess.execute.return_value.scalars.return_value.unique.return_value.all.return_value = []
    mock_sess.execute.return_value.scalars.return_value.all.return_value = []

    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views._sidebar_context.heartbeats_for_servers", MagicMock())

    from app.views._sidebar_context import build_sidebar_context

    ctx = build_sidebar_context()

    assert "sidebar_servers" in ctx
    assert "filter_tags" in ctx
    assert "active_server_id" in ctx
    # Teure Keys duerfen NICHT im Context-Processor-Pfad stehen
    assert "available_tags" not in ctx
    assert "sidebar_heartbeats" not in ctx
    assert "sidebar_risk_counts" not in ctx
    assert "hosts_total" not in ctx
    assert "alarm_count" not in ctx


def test_build_sidebar_context_active_server_id_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """active_server_id wird vom View-Code gesetzt, hier immer None."""
    mock_sess = MagicMock()
    mock_sess.execute.return_value.scalars.return_value.unique.return_value.all.return_value = []
    mock_sess.execute.return_value.scalars.return_value.all.return_value = []

    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views._sidebar_context.heartbeats_for_servers", MagicMock())

    from app.views._sidebar_context import build_sidebar_context

    ctx = build_sidebar_context()
    assert ctx["active_server_id"] is None


def test_build_sidebar_context_filter_tags_passed_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """filter_tags werden unveraendert in den Context uebernommen."""
    mock_sess = MagicMock()
    mock_sess.execute.return_value.scalars.return_value.unique.return_value.all.return_value = []
    mock_sess.execute.return_value.scalars.return_value.all.return_value = []

    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views._sidebar_context.heartbeats_for_servers", MagicMock())

    from app.views._sidebar_context import build_sidebar_context

    ctx = build_sidebar_context(filter_tags=["prod", "k8s"])
    assert ctx["filter_tags"] == ["prod", "k8s"]


# ---------------------------------------------------------------------------
# sidebar_partial — liefert alle teuren Aggregate
# ---------------------------------------------------------------------------


def _call_sidebar_partial_inner(
    monkeypatch: pytest.MonkeyPatch, fake_server: MagicMock, fake_risk_counts: dict
) -> dict:
    """Hilfsfunktion: ruft sidebar_partial.__wrapped__ im Test-App-Kontext auf
    und gibt den an render_template uebergebenen Context zurueck.
    """
    fake_heartbeats = {fake_server.id: []}

    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: MagicMock())
    monkeypatch.setattr(
        "app.views._sidebar_context.build_sidebar_context",
        lambda **kwargs: {
            "sidebar_servers": [fake_server],
            "available_tags": [],
            "filter_tags": [],
            "active_server_id": None,
        },
    )
    monkeypatch.setattr(
        "app.views._sidebar_context.heartbeats_for_servers",
        lambda sess, sids, **kw: fake_heartbeats,
    )
    monkeypatch.setattr(
        "app.views._sidebar_context.escalate_act_counts_by_server",
        lambda sess, sids: fake_risk_counts,
    )

    captured_ctx: dict = {}

    def fake_render(template: str, **ctx: object) -> str:
        captured_ctx.update(ctx)
        return "<ul>fake</ul>"

    monkeypatch.setattr("app.views._sidebar_context.render_template", fake_render)

    app = Flask(__name__)
    mock_user = MagicMock()
    mock_user.is_authenticated = True

    with app.test_request_context("/_partials/sidebar"):
        from app.views._sidebar_context import sidebar_partial as _partial_view

        with patch.object(flask_login, "current_user", mock_user, create=True):
            inner = getattr(_partial_view, "__wrapped__", _partial_view)
            inner()

    return captured_ctx


def test_sidebar_partial_provides_heartbeats_and_risk_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sidebar_partial baut Heartbeats + Risk-Counts + Header-Counter."""
    fake_server = MagicMock()
    fake_server.id = 1
    fake_risk_counts: dict[int, dict[str, int]] = {1: {"escalate": 2}}

    ctx = _call_sidebar_partial_inner(monkeypatch, fake_server, fake_risk_counts)

    assert "sidebar_heartbeats" in ctx
    assert "sidebar_risk_counts" in ctx
    assert "hosts_total" in ctx
    assert "alarm_count" in ctx

    assert ctx["hosts_total"] == 1
    # alarm_count: Server 1 hat escalate=2 -> 1 Alarm
    assert ctx["alarm_count"] == 1
    assert ctx["sidebar_risk_counts"] == fake_risk_counts


def test_sidebar_partial_alarm_count_zero_when_no_escalate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """alarm_count ist 0 wenn kein Server escalate-Findings hat."""
    fake_server = MagicMock()
    fake_server.id = 5
    fake_risk_counts: dict[int, dict[str, int]] = {5: {"act": 3}}

    ctx = _call_sidebar_partial_inner(monkeypatch, fake_server, fake_risk_counts)

    assert ctx["alarm_count"] == 0
    assert ctx["hosts_total"] == 1


def test_sidebar_partial_hosts_total_matches_server_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """hosts_total entspricht der Anzahl der Server in sidebar_servers."""
    fake_server = MagicMock()
    fake_server.id = 7
    fake_risk_counts: dict[int, dict[str, int]] = {}

    ctx = _call_sidebar_partial_inner(monkeypatch, fake_server, fake_risk_counts)

    assert ctx["hosts_total"] == 1


def test_sidebar_partial_alarm_count_multiple_servers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """alarm_count zaehlt korrekt bei mehreren Servern."""
    fake_server_a = MagicMock()
    fake_server_a.id = 10
    fake_server_b = MagicMock()
    fake_server_b.id = 11
    fake_server_c = MagicMock()
    fake_server_c.id = 12

    fake_heartbeats: dict = {10: [], 11: [], 12: []}
    # Nur Server 10 und 12 haben escalate-Findings
    fake_risk_counts: dict[int, dict[str, int]] = {
        10: {"escalate": 1},
        11: {"act": 2},
        12: {"escalate": 3, "act": 1},
    }

    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: MagicMock())
    monkeypatch.setattr(
        "app.views._sidebar_context.build_sidebar_context",
        lambda **kwargs: {
            "sidebar_servers": [fake_server_a, fake_server_b, fake_server_c],
            "available_tags": [],
            "filter_tags": [],
            "active_server_id": None,
        },
    )
    monkeypatch.setattr(
        "app.views._sidebar_context.heartbeats_for_servers",
        lambda sess, sids, **kw: fake_heartbeats,
    )
    monkeypatch.setattr(
        "app.views._sidebar_context.escalate_act_counts_by_server",
        lambda sess, sids: fake_risk_counts,
    )

    captured_ctx: dict = {}

    def fake_render(template: str, **ctx: object) -> str:
        captured_ctx.update(ctx)
        return ""

    monkeypatch.setattr("app.views._sidebar_context.render_template", fake_render)

    app = Flask(__name__)
    mock_user = MagicMock()
    mock_user.is_authenticated = True

    with app.test_request_context("/_partials/sidebar"):
        from app.views._sidebar_context import sidebar_partial as _partial_view

        with patch.object(flask_login, "current_user", mock_user, create=True):
            inner = getattr(_partial_view, "__wrapped__", _partial_view)
            inner()

    assert captured_ctx["hosts_total"] == 3
    assert captured_ctx["alarm_count"] == 2  # Server 10 + 12
