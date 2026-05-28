"""Pure-Unit-Tests fuer `tags_rename` (Block Z, Phase D).

Deckt:
  1. Happy: Name geaendert, `tag.renamed`-Audit mit {from,to}, commit, Flash success.
  2. Invalid-Name (Regex-Verstoss `Foo Bar` / Uppercase) -> Flash, KEIN log_event, redirect.
  3. Duplicate-Name (`sess.flush` -> IntegrityError) -> rollback + Flash "bereits vergeben",
     KEIN tag.renamed, kein 500.
  4. No-Op (old==new) -> redirect, KEIN log_event, kein commit.
  5. Unknown-ID (scalar_one_or_none -> None) -> Flash + redirect.
  6. Auth: `__wrapped__` vorhanden + Route als POST registriert.

Render-Strategie analog `test_settings_groups_rename.py`:
  - Handler via `func.__wrapped__` (umgeht `@login_required`).
  - `get_session`, `log_event`, `flash` per `monkeypatch.setattr` gestubbt.

Kein strip: anders als `groups_rename` strippt `tags_rename` NICHT — die
`TAG_NAME_REGEX` erlaubt ohnehin keine Leerzeichen.
"""

from __future__ import annotations

import types
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask
from sqlalchemy.exc import IntegrityError

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


@pytest.fixture
def csrf_app(app_env: None) -> Flask:
    """App mit AKTIVEM CSRF — fuer den reinen CSRF-Fail-Pfad ohne Field-Errors."""
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
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


def _call_rename(app: Flask, *, tag_id: int = 1, name: str) -> Any:
    from app.views.settings import tags_rename

    inner = getattr(tags_rename, "__wrapped__", tags_rename)
    with app.test_request_context(
        f"/settings/tags/{tag_id}/rename",
        method="POST",
        data={"name": name},
    ):
        return inner(tag_id=tag_id)


# ===========================================================================
# 1. Happy
# ===========================================================================


def test_rename_happy_changes_name_and_audits(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gueltiger neuer Name -> tag.name aktualisiert, Audit {from,to}, commit, success."""
    tag = _make_tag(id=1, name="prod")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = tag

    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, tag_id=1, name="prod-eu")

    assert resp.status_code == 302, resp
    assert tag.name == "prod-eu", f"name nicht aktualisiert: {tag.name}"
    call = next((c for c in audit if c["action"] == "tag.renamed"), None)
    assert call is not None, f"tag.renamed fehlt. Audit: {audit}"
    assert call["metadata"] == {"from": "prod", "to": "prod-eu"}, call
    assert call.get("target_type") == "tag" and call.get("target_id") == 1, call
    sess.commit.assert_called_once()
    assert any(cat == "success" for _, cat in flashes), flashes


# ===========================================================================
# 2. Invalid-Name (Regex-Verstoss, kein strip-Rescue)
# ===========================================================================


@pytest.mark.parametrize("bad_name", ["Foo Bar", "PROD", "tag/foo"])
def test_rename_invalid_name_flashes_no_audit(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch, bad_name: str
) -> None:
    """Regex-Verstoss (Space/Uppercase/Slash) -> Flash, KEIN log_event, redirect, kein commit."""
    tag = _make_tag(id=1, name="prod")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = tag
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, tag_id=1, name=bad_name)

    assert resp.status_code == 302, resp
    assert not any(c["action"] == "tag.renamed" for c in audit), audit
    assert len(flashes) > 0, f"Flash-Message bei Regex-Verstoss {bad_name!r} erwartet"
    assert tag.name == "prod", f"name darf nicht geaendert sein: {tag.name}"
    sess.commit.assert_not_called()


# ===========================================================================
# 3. Duplicate-Name (IntegrityError)
# ===========================================================================


def test_rename_duplicate_name_rolls_back(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """sess.flush -> IntegrityError -> rollback + Flash 'bereits vergeben', kein Audit, kein 500."""
    tag = _make_tag(id=1, name="prod")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = tag
    sess.flush.side_effect = IntegrityError("dup", {}, Exception("unique"))
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, tag_id=1, name="dev")

    assert resp.status_code == 302, resp
    sess.rollback.assert_called_once()
    assert not any(c["action"] == "tag.renamed" for c in audit), audit
    sess.commit.assert_not_called()
    assert any("bereits vergeben" in msg for msg, _ in flashes), (
        f"Flash 'bereits vergeben' erwartet. Flashes: {flashes}"
    )


# ===========================================================================
# 4. No-Op
# ===========================================================================


def test_rename_noop_when_unchanged(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """old==new -> redirect, KEIN log_event, kein commit/flush (No-Op, kein Audit)."""
    tag = _make_tag(id=1, name="prod")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = tag
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, tag_id=1, name="prod")

    assert resp.status_code == 302, resp
    assert not any(c["action"] == "tag.renamed" for c in audit), audit
    sess.commit.assert_not_called()
    sess.flush.assert_not_called()


# ===========================================================================
# 5. Unknown-ID
# ===========================================================================


def test_rename_unknown_id_flashes_redirect(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """scalar_one_or_none -> None -> Flash 'nicht gefunden' + redirect, kein Audit."""
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = None
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, tag_id=9999, name="whatever")

    assert resp.status_code == 302, resp
    assert any("nicht gefunden" in msg for msg, _ in flashes), flashes
    assert not any(c["action"] == "tag.renamed" for c in audit), audit
    sess.commit.assert_not_called()


# ===========================================================================
# 6. Auth + Route
# ===========================================================================


def test_rename_is_login_protected_and_routed(no_csrf_app: Flask) -> None:
    """tags_rename traegt `__wrapped__` (login_required) und ist als POST-Route registriert."""
    from app.views.settings import tags_rename

    assert hasattr(tags_rename, "__wrapped__"), "tags_rename ist nicht @login_required-wrapped"

    rules = [r for r in no_csrf_app.url_map.iter_rules() if r.endpoint == "settings.tags_rename"]
    assert rules, "Route settings.tags_rename ist nicht registriert"
    assert rules[0].methods is not None and "POST" in rules[0].methods, (
        f"Route muss POST erlauben: {rules[0].methods}"
    )
    assert "/settings/tags/" in rules[0].rule and rules[0].rule.endswith("/rename"), (
        f"Unerwartete Route-Regel: {rules[0].rule}"
    )
