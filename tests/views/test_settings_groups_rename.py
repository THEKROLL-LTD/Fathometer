"""Pure-Unit-Tests fuer `groups_rename` (Block Z, Phase C).

Deckt:
  1. Happy: Name geaendert, `group.renamed`-Audit mit {from,to}, commit, Flash success.
  2. Invalid-Name (Regex-Verstoss `prod/eu`) -> Flash, KEIN log_event, redirect.
  3. Duplicate-Name (`sess.flush` -> IntegrityError) -> rollback + Flash "bereits vergeben",
     KEIN group.renamed, kein 500.
  4. No-Op (old==new) -> redirect, KEIN log_event, kein commit.
  5. Unknown-ID (scalar_one_or_none -> None) -> Flash + redirect.
  6. Auth: `__wrapped__` vorhanden + Route registriert.

Render-Strategie wie `test_server_settings.py`:
  - Handler via `func.__wrapped__` (umgeht `@login_required`).
  - `get_session`, `log_event`, `flash` per `monkeypatch.setattr` gestubbt.
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


def _call_rename(
    app: Flask, monkeypatch: pytest.MonkeyPatch, *, group_id: int = 1, name: str
) -> Any:
    from app.views.settings import groups_rename

    inner = getattr(groups_rename, "__wrapped__", groups_rename)
    with app.test_request_context(
        f"/settings/groups/{group_id}/rename",
        method="POST",
        data={"name": name},
    ):
        return inner(group_id=group_id)


# ===========================================================================
# 1. Happy
# ===========================================================================


def test_rename_happy_changes_name_and_audits(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gueltiger neuer Name -> group.name aktualisiert, Audit {from,to}, commit, success."""
    group = _make_group(id=1, name="prod")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = group

    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, monkeypatch, group_id=1, name="prod-eu")

    assert resp.status_code == 302, resp
    assert group.name == "prod-eu", f"name nicht aktualisiert: {group.name}"
    call = next((c for c in audit if c["action"] == "group.renamed"), None)
    assert call is not None, f"group.renamed fehlt. Audit: {audit}"
    assert call["metadata"] == {"from": "prod", "to": "prod-eu"}, call
    assert call.get("target_type") == "group" and call.get("target_id") == 1, call
    sess.commit.assert_called_once()
    assert any(cat == "success" for _, cat in flashes), flashes


def test_rename_strips_whitespace(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fuehrende/abschliessende Spaces werden gestrippt bevor gespeichert wird."""
    group = _make_group(id=1, name="prod")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = group
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, monkeypatch, group_id=1, name="  prod-eu  ")

    assert resp.status_code == 302, resp
    assert group.name == "prod-eu", f"Whitespace nicht gestrippt: {group.name!r}"


# ===========================================================================
# 2. Invalid-Name
# ===========================================================================


def test_rename_invalid_name_flashes_no_audit(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regex-Verstoss `prod/eu` (Slash nicht erlaubt) -> Flash, KEIN log_event, redirect."""
    group = _make_group(id=1, name="prod")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = group
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, monkeypatch, group_id=1, name="prod/eu")

    assert resp.status_code == 302, resp
    assert not any(c["action"] == "group.renamed" for c in audit), audit
    assert len(flashes) > 0, "Flash-Message bei Regex-Verstoss erwartet"
    assert group.name == "prod", f"name darf nicht geaendert sein: {group.name}"
    sess.commit.assert_not_called()


# ===========================================================================
# 3. Duplicate-Name (IntegrityError)
# ===========================================================================


def test_rename_duplicate_name_rolls_back(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """sess.flush -> IntegrityError -> rollback + Flash 'bereits vergeben', kein Audit, kein 500."""
    group = _make_group(id=1, name="prod")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = group
    sess.flush.side_effect = IntegrityError("dup", {}, Exception("unique"))
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, monkeypatch, group_id=1, name="dev")

    assert resp.status_code == 302, resp
    sess.rollback.assert_called_once()
    assert not any(c["action"] == "group.renamed" for c in audit), audit
    sess.commit.assert_not_called()
    assert any("bereits vergeben" in msg for msg, _ in flashes), (
        f"Flash 'bereits vergeben' erwartet. Flashes: {flashes}"
    )


# ===========================================================================
# 4. No-Op
# ===========================================================================


def test_rename_noop_when_unchanged(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """old==new -> redirect, KEIN log_event, kein commit (No-Op, kein Audit)."""
    group = _make_group(id=1, name="prod")
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = group
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(no_csrf_app, monkeypatch, group_id=1, name="prod")

    assert resp.status_code == 302, resp
    assert not any(c["action"] == "group.renamed" for c in audit), audit
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

    resp = _call_rename(no_csrf_app, monkeypatch, group_id=9999, name="whatever")

    assert resp.status_code == 302, resp
    assert any("not found" in msg for msg, _ in flashes), flashes
    assert not any(c["action"] == "group.renamed" for c in audit), audit
    sess.commit.assert_not_called()


# ===========================================================================
# 5b. CSRF-Fail ohne Field-Errors -> generischer Flash
# ===========================================================================


def test_rename_csrf_fail_without_field_errors_flashes(
    csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CSRF aktiv + gueltiger name aber ohne Token -> validate False, KEINE Field-Errors.

    Deckt den `if not form.errors`-Zweig (generischer CSRF-Token-Flash) im View ab:
    `name` ist regex-valide, also produziert WTForms keinen name-Fehler — nur der
    CSRF-Token fehlt. Erwartung: Flash + redirect, kein Lookup/Audit.
    """
    sess = MagicMock()
    flashes: list[tuple[str, str]] = []
    audit: list[dict[str, Any]] = []
    _patch_common(monkeypatch, sess=sess, flashes=flashes, audit=audit)

    resp = _call_rename(csrf_app, monkeypatch, group_id=1, name="valid-name")

    assert resp.status_code == 302, resp
    sess.execute.assert_not_called()
    assert not any(c["action"] == "group.renamed" for c in audit), audit
    assert any("CSRF" in msg for msg, _ in flashes), (
        f"Generischer CSRF-Token-Flash erwartet. Flashes: {flashes}"
    )


# ===========================================================================
# 6. Auth + Route
# ===========================================================================


def test_rename_is_login_protected_and_routed(no_csrf_app: Flask) -> None:
    """groups_rename traegt `__wrapped__` (login_required) und ist als POST-Route registriert."""
    from app.views.settings import groups_rename

    assert hasattr(groups_rename, "__wrapped__"), "groups_rename ist nicht @login_required-wrapped"

    rules = [r for r in no_csrf_app.url_map.iter_rules() if r.endpoint == "settings.groups_rename"]
    assert rules, "Route settings.groups_rename ist nicht registriert"
    assert "POST" in rules[0].methods, f"Route muss POST erlauben: {rules[0].methods}"
    assert "/settings/groups/" in rules[0].rule and rules[0].rule.endswith("/rename"), (
        f"Unerwartete Route-Regel: {rules[0].rule}"
    )
