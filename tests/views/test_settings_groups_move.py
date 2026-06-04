"""Pure-Unit-Tests fuer `groups_move` (Block Z, Phase C).

Deckt:
  1. Swap-up: Positionen getauscht, `group.moved`-Audit mit {from_position,to_position}.
  2. Swap-down: analog.
  3. Top-No-Op: kein Nachbar (up) -> Flash 'info', KEIN log_event, kein commit.
  4. Bottom-No-Op: kein Nachbar (down) -> Flash 'info', KEIN log_event.
  5. Audit-Metadata korrekt (from/to-Positionswerte).
  6. direction-Whitelist: GroupMoveForm lehnt `sideways` ab -> validate False ->
     Flash + redirect, KEIN Swap, KEIN Audit.

Render-Strategie wie `test_server_settings.py` — Handler via `__wrapped__`,
get_session/log_event/flash gemockt.
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


def _make_group(*, id: int, name: str, position: int) -> types.SimpleNamespace:
    return types.SimpleNamespace(id=id, name=name, position=position)


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


def _make_sess(*, group: Any, neighbor: Any) -> MagicMock:
    """Mock-Session: erster execute -> group-Lookup, zweiter -> neighbor-Lookup."""
    sess = MagicMock()
    group_result = MagicMock()
    group_result.scalar_one_or_none.return_value = group
    neighbor_result = MagicMock()
    neighbor_result.scalar_one_or_none.return_value = neighbor
    sess.execute.side_effect = [group_result, neighbor_result]
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


def _call_move(app: Flask, *, group_id: int, direction: str) -> Any:
    from app.views.settings import groups_move

    inner = getattr(groups_move, "__wrapped__", groups_move)
    with app.test_request_context(
        f"/settings/groups/{group_id}/move", method="POST", data={"direction": direction}
    ):
        return inner(group_id=group_id)


# ===========================================================================
# 1. Swap-up
# ===========================================================================


def test_move_up_swaps_positions(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """direction=up -> group<->neighbor Positionen getauscht, Audit {from,to}."""
    group = _make_group(id=2, name="dev", position=2)
    neighbor = _make_group(id=1, name="prod", position=1)
    sess = _make_sess(group=group, neighbor=neighbor)
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_move(no_csrf_app, group_id=2, direction="up")

    assert resp.status_code == 302, resp
    assert group.position == 1, f"group.position soll 1 sein: {group.position}"
    assert neighbor.position == 2, f"neighbor.position soll 2 sein: {neighbor.position}"
    call = next((c for c in audit if c["action"] == "group.moved"), None)
    assert call is not None, f"group.moved fehlt. Audit: {audit}"
    assert call["metadata"] == {"from_position": 2, "to_position": 1}, call
    assert call.get("target_id") == 2, call
    sess.commit.assert_called_once()


# ===========================================================================
# 2. Swap-down
# ===========================================================================


def test_move_down_swaps_positions(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """direction=down -> group<->unterer Nachbar getauscht, Audit {from,to}."""
    group = _make_group(id=1, name="prod", position=1)
    neighbor = _make_group(id=2, name="dev", position=2)
    sess = _make_sess(group=group, neighbor=neighbor)
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_move(no_csrf_app, group_id=1, direction="down")

    assert resp.status_code == 302, resp
    assert group.position == 2, f"group.position soll 2 sein: {group.position}"
    assert neighbor.position == 1, f"neighbor.position soll 1 sein: {neighbor.position}"
    call = next(c for c in audit if c["action"] == "group.moved")
    assert call["metadata"] == {"from_position": 1, "to_position": 2}, call


# ===========================================================================
# 3. Top-No-Op
# ===========================================================================


def test_move_up_at_top_is_noop(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Kein Nachbar bei up -> Flash 'info' (bereits ganz oben), KEIN Audit, kein commit."""
    group = _make_group(id=1, name="prod", position=0)
    sess = _make_sess(group=group, neighbor=None)
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_move(no_csrf_app, group_id=1, direction="up")

    assert resp.status_code == 302, resp
    assert group.position == 0, f"position darf sich nicht aendern: {group.position}"
    assert not any(c["action"] == "group.moved" for c in audit), audit
    sess.commit.assert_not_called()
    assert any(cat == "info" for _, cat in flashes), f"info-Flash erwartet: {flashes}"
    assert any("top" in msg for msg, _ in flashes), flashes


# ===========================================================================
# 4. Bottom-No-Op
# ===========================================================================


def test_move_down_at_bottom_is_noop(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Kein Nachbar bei down -> Flash 'info' (bereits ganz unten), KEIN Audit."""
    group = _make_group(id=9, name="last", position=99)
    sess = _make_sess(group=group, neighbor=None)
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_move(no_csrf_app, group_id=9, direction="down")

    assert resp.status_code == 302, resp
    assert group.position == 99, f"position unveraendert erwartet: {group.position}"
    assert not any(c["action"] == "group.moved" for c in audit), audit
    sess.commit.assert_not_called()
    assert any("bottom" in msg for msg, _ in flashes), flashes


# ===========================================================================
# 5. Audit-Metadata korrekt (nicht-triviale Positionswerte)
# ===========================================================================


def test_move_audit_metadata_reflects_neighbor_position(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """from_position == alte group.position, to_position == uebernommene neighbor.position."""
    group = _make_group(id=5, name="g5", position=10)
    neighbor = _make_group(id=4, name="g4", position=7)
    sess = _make_sess(group=group, neighbor=neighbor)
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_move(no_csrf_app, group_id=5, direction="up")

    assert resp.status_code == 302, resp
    call = next(c for c in audit if c["action"] == "group.moved")
    assert call["metadata"]["from_position"] == 10, call
    assert call["metadata"]["to_position"] == 7, call
    assert group.position == 7 and neighbor.position == 10, (group.position, neighbor.position)


# ===========================================================================
# 6. direction-Whitelist
# ===========================================================================


def test_move_invalid_direction_rejected(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """direction='sideways' nicht in SelectField-Whitelist -> validate False -> Flash, kein Swap.

    Form-Validation greift VOR dem Group-Lookup, daher kein DB-Zugriff/Audit/commit.
    """
    sess = MagicMock()
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_move(no_csrf_app, group_id=1, direction="sideways")

    assert resp.status_code == 302, resp
    sess.execute.assert_not_called()
    assert not any(c["action"] == "group.moved" for c in audit), audit
    sess.commit.assert_not_called()
    assert len(flashes) > 0, "Flash bei ungueltiger Richtung erwartet"


def test_move_form_rejects_invalid_direction_choice(no_csrf_app: Flask) -> None:
    """Unit-Beleg: GroupMoveForm.validate() ist False fuer direction ausserhalb up|down."""
    from werkzeug.datastructures import ImmutableMultiDict

    from app.forms import GroupMoveForm

    with no_csrf_app.test_request_context("/"):
        bad = GroupMoveForm(formdata=ImmutableMultiDict([("direction", "sideways")]))
        assert bad.validate() is False, "GroupMoveForm darf 'sideways' nicht akzeptieren"
        ok = GroupMoveForm(formdata=ImmutableMultiDict([("direction", "up")]))
        assert ok.validate() is True, f"'up' soll valide sein. Errors: {ok.errors}"


# ===========================================================================
# 6b. Unknown-ID
# ===========================================================================


def test_move_unknown_id_flashes_redirect(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gueltige Richtung aber Group-Lookup -> None -> Flash 'nicht gefunden', kein Swap/Audit."""
    sess = MagicMock()
    group_result = MagicMock()
    group_result.scalar_one_or_none.return_value = None
    sess.execute.side_effect = [group_result]
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_move(no_csrf_app, group_id=9999, direction="up")

    assert resp.status_code == 302, resp
    assert any("not found" in msg for msg, _ in flashes), flashes
    assert not any(c["action"] == "group.moved" for c in audit), audit
    sess.commit.assert_not_called()


# ===========================================================================
# 7. Auth + Route
# ===========================================================================


def test_move_is_login_protected_and_routed(no_csrf_app: Flask) -> None:
    """groups_move traegt `__wrapped__` (login_required) und ist als POST-Route registriert."""
    from app.views.settings import groups_move

    assert hasattr(groups_move, "__wrapped__"), "groups_move ist nicht @login_required-wrapped"

    rules = [r for r in no_csrf_app.url_map.iter_rules() if r.endpoint == "settings.groups_move"]
    assert rules, "Route settings.groups_move ist nicht registriert"
    assert "POST" in rules[0].methods, f"Route muss POST erlauben: {rules[0].methods}"
    assert rules[0].rule.endswith("/move"), f"Unerwartete Route-Regel: {rules[0].rule}"
