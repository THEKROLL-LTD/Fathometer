"""Pure-Unit-Tests fuer `tags_color` (Block Z, Phase D).

Deckt:
  1. Happy: Farbe geaendert, `tag.color_changed`-Audit mit {from,to}, commit, Flash success.
  2. Invalid-Hex (`#xyz` / `red` / zu kurz) -> Flash, KEIN log_event, redirect, kein commit.
  3. No-Op (old==new) -> redirect, KEIN log_event, kein commit.
  4. Unknown-ID (scalar_one_or_none -> None) -> Flash + redirect.
  5. Auth: `__wrapped__` vorhanden + Route als POST registriert.

Render-Strategie analog `test_settings_groups_rename.py`:
  - Handler via `func.__wrapped__` (umgeht `@login_required`).
  - `get_session`, `log_event`, `flash` per `monkeypatch.setattr` gestubbt.
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


def _make_tag(*, id: int = 1, name: str = "prod", color: str = "#6b7280") -> types.SimpleNamespace:
    return types.SimpleNamespace(id=id, name=name, color=color)


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


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


def _call_color(app: Flask, *, tag_id: int = 1, color: str) -> Any:
    from app.views.settings import tags_color

    inner = getattr(tags_color, "__wrapped__", tags_color)
    with app.test_request_context(
        f"/settings/tags/{tag_id}/color",
        method="POST",
        data={"color": color},
    ):
        return inner(tag_id=tag_id)


# ===========================================================================
# 1. Happy
# ===========================================================================


def test_color_happy_changes_color_and_audits(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gueltige neue Farbe -> tag.color aktualisiert, Audit {from,to}, commit, success."""
    tag = _make_tag(id=1, name="prod", color="#6b7280")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = tag

    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_color(no_csrf_app, tag_id=1, color="#ff0000")

    assert resp.status_code == 302, resp
    assert tag.color == "#ff0000", f"color nicht aktualisiert: {tag.color}"
    call = next((c for c in audit if c["action"] == "tag.color_changed"), None)
    assert call is not None, f"tag.color_changed fehlt. Audit: {audit}"
    assert call["metadata"] == {"from": "#6b7280", "to": "#ff0000"}, call
    assert call.get("target_type") == "tag" and call.get("target_id") == 1, call
    sess.commit.assert_called_once()
    assert any(cat == "success" for _, cat in flashes), flashes


# ===========================================================================
# 2. Invalid-Hex
# ===========================================================================


@pytest.mark.parametrize("bad_color", ["#xyz", "red", "#123", "#1234567", "123456"])
def test_color_invalid_hex_flashes_no_audit(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch, bad_color: str
) -> None:
    """Ungueltiges Hex -> Flash, KEIN log_event, redirect, kein commit, color unveraendert."""
    tag = _make_tag(id=1, name="prod", color="#6b7280")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = tag
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_color(no_csrf_app, tag_id=1, color=bad_color)

    assert resp.status_code == 302, resp
    assert not any(c["action"] == "tag.color_changed" for c in audit), audit
    assert len(flashes) > 0, f"Flash-Message bei ungueltigem Hex {bad_color!r} erwartet"
    assert tag.color == "#6b7280", f"color darf nicht geaendert sein: {tag.color}"
    sess.commit.assert_not_called()


# ===========================================================================
# 3. No-Op
# ===========================================================================


def test_color_noop_when_unchanged(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """old==new -> redirect, KEIN log_event, kein commit (No-Op, kein Audit)."""
    tag = _make_tag(id=1, name="prod", color="#6b7280")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = tag
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_color(no_csrf_app, tag_id=1, color="#6b7280")

    assert resp.status_code == 302, resp
    assert not any(c["action"] == "tag.color_changed" for c in audit), audit
    sess.commit.assert_not_called()


# ===========================================================================
# 4. Unknown-ID
# ===========================================================================


def test_color_unknown_id_flashes_redirect(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """scalar_one_or_none -> None -> Flash 'nicht gefunden' + redirect, kein Audit."""
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = None
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_color(no_csrf_app, tag_id=9999, color="#ff0000")

    assert resp.status_code == 302, resp
    assert any("nicht gefunden" in msg for msg, _ in flashes), flashes
    assert not any(c["action"] == "tag.color_changed" for c in audit), audit
    sess.commit.assert_not_called()


# ===========================================================================
# 5. Auth + Route
# ===========================================================================


def test_color_is_login_protected_and_routed(no_csrf_app: Flask) -> None:
    """tags_color traegt `__wrapped__` (login_required) und ist als POST-Route registriert."""
    from app.views.settings import tags_color

    assert hasattr(tags_color, "__wrapped__"), "tags_color ist nicht @login_required-wrapped"

    rules = [r for r in no_csrf_app.url_map.iter_rules() if r.endpoint == "settings.tags_color"]
    assert rules, "Route settings.tags_color ist nicht registriert"
    assert rules[0].methods is not None and "POST" in rules[0].methods, (
        f"Route muss POST erlauben: {rules[0].methods}"
    )
    assert "/settings/tags/" in rules[0].rule and rules[0].rule.endswith("/color"), (
        f"Unerwartete Route-Regel: {rules[0].rule}"
    )
