"""Pure-Unit-Tests fuer `groups_delete` (Block Z, Phase C).

Deckt:
  1. Happy mit member_count>0: `sess.delete(group)` aufgerufen (nur die Group, kein
     Server), `group.deleted`-Audit mit `member_count_before` == gemocktem Count, commit.
  2. Audit `member_count_before` korrekt (member_count==0-Variante).
  3. CSRF-Fehler: bewusst NICHT getestet im no_csrf_app-Kontext (Begruendung s.u.) —
     dafuer wird der CSRF-aktive Reject-Pfad ueber eine eigene App-Instanz geprueft.
  4. Unknown-ID -> Flash + redirect, kein delete, kein Audit.
  5. Auth + Route.

CSRF-Hinweis (analog Phase A):
  Der View ruft `CSRFOnlyForm().validate_on_submit()`. Mit WTF_CSRF_ENABLED=False ist
  dieser Pfad immer True; den Reject-Pfad pruefen wir mit einer separaten App mit
  WTF_CSRF_ENABLED=True (POST ohne Token -> validate_on_submit False -> Flash + redirect,
  kein delete). Das bleibt ein Pure-Unit-Test (kein DB-Zugriff).
"""

from __future__ import annotations

import types
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_group(*, id: int = 1, name: str = "prod", position: int = 0) -> types.SimpleNamespace:
    return types.SimpleNamespace(id=id, name=name, position=position)


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


@pytest.fixture
def csrf_app(app_env: None) -> Flask:
    """App mit AKTIVEM CSRF — fuer den Reject-Pfad ohne Token."""
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    return flask_app


def _make_sess(*, group: Any, member_count: int) -> MagicMock:
    """Mock-Session: erster execute -> group-Lookup, zweiter -> count(*)."""
    sess = MagicMock()
    group_result = MagicMock()
    group_result.scalar_one_or_none.return_value = group
    count_result = MagicMock()
    count_result.scalar_one.return_value = member_count
    sess.execute.side_effect = [group_result, count_result]
    return sess


def _patch_common(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sess: MagicMock,
    flashes: list[tuple[str, str]],
    audit: list[dict[str, Any]],
) -> None:
    def fake_flash(msg: str, category: str = "message") -> None:
        flashes.append((msg, category))

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        audit.append({"action": action, **kwargs})
        return MagicMock()

    monkeypatch.setattr("app.views.settings.get_session", lambda: sess)
    monkeypatch.setattr("app.views.settings.flash", fake_flash)
    monkeypatch.setattr("app.views.settings.log_event", fake_log_event)


def _call_delete(app: Flask, *, group_id: int = 1) -> Any:
    from app.views.settings import groups_delete

    inner = getattr(groups_delete, "__wrapped__", groups_delete)
    with app.test_request_context(f"/settings/groups/{group_id}/delete", method="POST", data={}):
        return inner(group_id=group_id)


# ===========================================================================
# 1. Happy mit member_count > 0
# ===========================================================================


def test_delete_happy_deletes_group_and_audits(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Group geloescht, Audit member_count_before==3, commit, nur die Group an sess.delete."""
    group = _make_group(id=1, name="prod")
    sess = _make_sess(group=group, member_count=3)
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_delete(no_csrf_app, group_id=1)

    assert resp.status_code == 302, resp
    # Nur die Group selbst wird geloescht — kein Server.
    sess.delete.assert_called_once_with(group)
    call = next((c for c in audit if c["action"] == "group.deleted"), None)
    assert call is not None, f"group.deleted fehlt. Audit: {audit}"
    assert call["metadata"] == {"name": "prod", "member_count_before": 3}, call
    assert call.get("target_type") == "group" and call.get("target_id") == 1, call
    sess.commit.assert_called_once()


# ===========================================================================
# 2. member_count == 0 (Audit-Metadata korrekt)
# ===========================================================================


def test_delete_member_count_zero_in_audit(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leere Gruppe -> member_count_before==0 im Audit."""
    group = _make_group(id=7, name="empty-grp")
    sess = _make_sess(group=group, member_count=0)
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_delete(no_csrf_app, group_id=7)

    assert resp.status_code == 302, resp
    call = next(c for c in audit if c["action"] == "group.deleted")
    assert call["metadata"]["member_count_before"] == 0, call
    assert call["metadata"]["name"] == "empty-grp", call


# ===========================================================================
# 3. CSRF-Reject (CSRF-aktive App, kein Token)
# ===========================================================================


def test_delete_csrf_reject_flashes_no_delete(
    csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST ohne CSRF-Token -> validate_on_submit False -> Flash + redirect, kein delete/Audit.

    Pure-Unit: get_session/log_event/flash gemockt; es passiert kein DB-Zugriff weil
    die Form-Validation vor dem Group-Lookup greift.
    """
    sess = MagicMock()
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_delete(csrf_app, group_id=1)

    assert resp.status_code == 302, resp
    sess.delete.assert_not_called()
    sess.execute.assert_not_called()
    assert not any(c["action"] == "group.deleted" for c in audit), audit
    assert len(flashes) > 0, "CSRF-Reject soll eine Flash-Message setzen"


# ===========================================================================
# 4. Unknown-ID
# ===========================================================================


def test_delete_unknown_id_flashes_redirect(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Group-Lookup -> None -> Flash 'nicht gefunden' + redirect, kein delete/Audit."""
    sess = MagicMock()
    group_result = MagicMock()
    group_result.scalar_one_or_none.return_value = None
    sess.execute.side_effect = [group_result]
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_delete(no_csrf_app, group_id=9999)

    assert resp.status_code == 302, resp
    sess.delete.assert_not_called()
    assert any("nicht gefunden" in msg for msg, _ in flashes), flashes
    assert not any(c["action"] == "group.deleted" for c in audit), audit
    sess.commit.assert_not_called()


# ===========================================================================
# 5. Auth + Route
# ===========================================================================


def test_delete_is_login_protected_and_routed(no_csrf_app: Flask) -> None:
    """groups_delete traegt `__wrapped__` (login_required) und ist als POST-Route registriert."""
    from app.views.settings import groups_delete

    assert hasattr(groups_delete, "__wrapped__"), "groups_delete ist nicht @login_required-wrapped"

    rules = [r for r in no_csrf_app.url_map.iter_rules() if r.endpoint == "settings.groups_delete"]
    assert rules, "Route settings.groups_delete ist nicht registriert"
    assert "POST" in rules[0].methods, f"Route muss POST erlauben: {rules[0].methods}"
    assert rules[0].rule.endswith("/delete"), f"Unerwartete Route-Regel: {rules[0].rule}"
