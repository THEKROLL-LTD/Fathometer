"""Pure-Unit-Tests fuer `app/views/servers.py::delete_server`.

Deckt die neue 'Delete server'-Action (vollstaendiges Loeschen eines revoked
Servers) ab:
  1. Server nicht gefunden -> Fehler-Flash, kein Delete.
  2. Guard: nicht-revoked Server -> Fehler-Flash, kein Delete.
  3. Happy-Path: revoked Server -> Findings zuerst geloescht, dann Server,
     Audit-Event `server.deleted`, Commit.

Render-/Aufruf-Strategie analog `test_server_settings.py`:
  - Handler via `func.__wrapped__` direkt aufrufen (umgeht `@login_required`).
  - `get_session`, `_delete_all_findings`, `log_event` per `monkeypatch`
    gestubbt — kein echter DB-Zugriff (reiner Pure-Unit-Test).
"""

from __future__ import annotations

import types
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    """App mit deaktiviertem CSRF und TESTING=True."""
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


def _make_server(
    *,
    id: int = 7,
    name: str = "old-host",
    revoked_at: Any = None,
) -> types.SimpleNamespace:
    return types.SimpleNamespace(id=id, name=name, revoked_at=revoked_at)


def _call_delete_server(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    *,
    server: Any,
    server_id: int = 7,
    deleted_findings: int = 0,
) -> tuple[Any, MagicMock, list[tuple[str, dict[str, Any]]]]:
    """Ruft `delete_server.__wrapped__` mit gemockten Dependencies auf.

    Gibt `(response, mock_session, audit_calls)` zurueck.
    """
    from app.views import servers as servers_view

    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = server
    monkeypatch.setattr(servers_view, "get_session", lambda: sess)
    monkeypatch.setattr(servers_view, "_delete_all_findings", lambda s, sid: deleted_findings)

    audit_calls: list[tuple[str, dict[str, Any]]] = []

    def _fake_log_event(action: str, **kwargs: Any) -> None:
        audit_calls.append((action, kwargs))

    monkeypatch.setattr(servers_view, "log_event", _fake_log_event)

    inner = getattr(servers_view.delete_server, "__wrapped__", servers_view.delete_server)
    with app.test_request_context(f"/settings/servers/{server_id}/delete", method="POST"):
        resp = inner(server_id=server_id)
    return resp, sess, audit_calls


def test_delete_server_not_found_flashes_and_skips_delete(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    resp, sess, audit_calls = _call_delete_server(no_csrf_app, monkeypatch, server=None)

    assert resp.status_code == 302
    assert "/settings/servers" in resp.headers["Location"]
    sess.delete.assert_not_called()
    sess.commit.assert_not_called()
    assert audit_calls == []


def test_delete_server_rejected_when_not_revoked(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Aktiver (nicht-revoked) Server darf NICHT geloescht werden."""
    server = _make_server(revoked_at=None)
    resp, sess, audit_calls = _call_delete_server(no_csrf_app, monkeypatch, server=server)

    assert resp.status_code == 302
    sess.delete.assert_not_called()
    sess.commit.assert_not_called()
    assert audit_calls == []


def test_delete_server_revoked_deletes_findings_then_server(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revoked Server: erst Findings, dann Server, mit Audit + Commit."""
    from datetime import UTC, datetime

    server = _make_server(revoked_at=datetime(2026, 6, 1, tzinfo=UTC))
    resp, sess, audit_calls = _call_delete_server(
        no_csrf_app, monkeypatch, server=server, deleted_findings=4
    )

    assert resp.status_code == 302
    assert "/settings/servers" in resp.headers["Location"]

    # Server selbst geloescht + committet.
    sess.delete.assert_called_once_with(server)
    sess.commit.assert_called_once()

    # Audit-Event `server.deleted` mit Findings-Zahl.
    assert len(audit_calls) == 1
    action, kwargs = audit_calls[0]
    assert action == "server.deleted"
    assert kwargs["target_id"] == server.id
    assert kwargs["metadata"]["deleted_findings"] == 4
    assert kwargs["metadata"]["name"] == server.name


def test_delete_server_audit_written_before_row_delete(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Das Audit-Event wird VOR `sess.delete(server)` geschrieben, damit der
    Name noch verfuegbar ist und kein FK-Konflikt entsteht."""
    from datetime import UTC, datetime

    from app.views import servers as servers_view

    server = _make_server(revoked_at=datetime(2026, 6, 1, tzinfo=UTC))

    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = server
    monkeypatch.setattr(servers_view, "get_session", lambda: sess)
    monkeypatch.setattr(servers_view, "_delete_all_findings", lambda s, sid: 0)

    order: list[str] = []
    monkeypatch.setattr(
        servers_view, "log_event", lambda action, **kw: order.append(f"audit:{action}")
    )
    sess.delete.side_effect = lambda obj: order.append("delete")

    inner = getattr(servers_view.delete_server, "__wrapped__", servers_view.delete_server)
    with no_csrf_app.test_request_context("/settings/servers/7/delete", method="POST"):
        inner(server_id=7)

    assert order == ["audit:server.deleted", "delete"]
