"""Pure-Unit-Tests fuer `groups_list` + `_groups_with_member_counts` (Block Z, Phase C).

Deckt:
  1. `_groups_with_member_counts` baut korrekte Dict-Struktur aus Mock-Rows.
  2. Sortierung/Member-Count-Mapping korrekt uebernommen aus den Rows.
  3. Empty-Liste -> [].
  4. `groups_list` ruft `render_settings` mit `active="groups"`, content_template
     `settings/groups.html` und den drei Forms (rename/move/delete) auf.
  5. `groups_list` reicht die `_groups_with_member_counts`-Liste durch.

Render-Strategie:
  - View-Handler via `func.__wrapped__` (umgeht `@login_required` ohne Auth-Bypass).
  - `get_session`, `render_settings` und `_groups_with_member_counts` werden per
    `monkeypatch.setattr` gestubbt — kein DB-Zugriff, kein echtes Jinja-Render.
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


def _make_row(*, id: int, name: str, position: int, member_count: int) -> types.SimpleNamespace:
    """Erstellt eine Mock-Row analog `sess.execute(stmt).all()`-Result."""
    return types.SimpleNamespace(id=id, name=name, position=position, member_count=member_count)


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    """App mit deaktiviertem CSRF und TESTING=True."""
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


# ===========================================================================
# 1. test_member_counts_builds_dict_structure
# ===========================================================================


def test_member_counts_builds_dict_structure() -> None:
    """`_groups_with_member_counts` mappt Rows in {id,name,position,member_count}."""
    from app.views.settings import _groups_with_member_counts

    rows = [
        _make_row(id=1, name="prod", position=0, member_count=3),
        _make_row(id=2, name="dev", position=1, member_count=0),
    ]
    sess = MagicMock()
    sess.execute.return_value.all.return_value = rows

    result = _groups_with_member_counts(sess)

    assert result == [
        {"id": 1, "name": "prod", "position": 0, "member_count": 3},
        {"id": 2, "name": "dev", "position": 1, "member_count": 0},
    ], f"Dict-Struktur weicht ab: {result}"


# ===========================================================================
# 2. test_member_counts_coerces_to_int
# ===========================================================================


def test_member_counts_coerces_to_int() -> None:
    """id/position/member_count werden hart auf int gecastet (DB liefert ggf. Decimal)."""
    from app.views.settings import _groups_with_member_counts

    # Strings/Float simulieren — der Helper soll int(...) erzwingen.
    rows = [_make_row(id="5", name="ops", position="2", member_count="7")]
    sess = MagicMock()
    sess.execute.return_value.all.return_value = rows

    result = _groups_with_member_counts(sess)

    assert result[0]["id"] == 5 and isinstance(result[0]["id"], int), result
    assert result[0]["position"] == 2 and isinstance(result[0]["position"], int), result
    assert result[0]["member_count"] == 7 and isinstance(result[0]["member_count"], int), result
    assert result[0]["name"] == "ops", result


# ===========================================================================
# 3. test_member_counts_empty_list
# ===========================================================================


def test_member_counts_empty_list() -> None:
    """Keine Gruppen -> leere Liste, kein Crash."""
    from app.views.settings import _groups_with_member_counts

    sess = MagicMock()
    sess.execute.return_value.all.return_value = []

    assert _groups_with_member_counts(sess) == []


# ===========================================================================
# 4. test_member_counts_preserves_row_order
# ===========================================================================


def test_member_counts_preserves_row_order() -> None:
    """Sortierung kommt aus der Query — der Helper darf die Row-Reihenfolge nicht aendern.

    Wir liefern bewusst eine bereits sortierte Row-Folge (position,name) und pruefen,
    dass der Helper sie 1:1 uebernimmt (kein clientseitiges Re-Sort).
    """
    from app.views.settings import _groups_with_member_counts

    rows = [
        _make_row(id=10, name="alpha", position=0, member_count=1),
        _make_row(id=11, name="zulu", position=0, member_count=2),
        _make_row(id=12, name="beta", position=1, member_count=0),
    ]
    sess = MagicMock()
    sess.execute.return_value.all.return_value = rows

    result = _groups_with_member_counts(sess)
    assert [d["id"] for d in result] == [10, 11, 12], result


# ===========================================================================
# 5. test_groups_list_calls_render_settings_with_forms
# ===========================================================================


def test_groups_list_calls_render_settings_with_forms(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`groups_list` ruft render_settings mit active/template + 3 Forms + groups auf."""
    from app.forms import CSRFOnlyForm, GroupMoveForm, GroupRenameForm
    from app.views.settings import groups_list

    fake_groups = [{"id": 1, "name": "prod", "position": 0, "member_count": 2}]

    captured: dict[str, Any] = {}

    def fake_render_settings(**kwargs: Any) -> str:
        captured.update(kwargs)
        return "RENDERED"

    monkeypatch.setattr("app.views.settings.get_session", lambda: MagicMock())
    monkeypatch.setattr("app.views.settings._groups_with_member_counts", lambda sess: fake_groups)
    monkeypatch.setattr("app.views.settings.render_settings", fake_render_settings)

    inner = getattr(groups_list, "__wrapped__", groups_list)
    with no_csrf_app.test_request_context("/settings/groups"):
        result = inner()

    assert result == "RENDERED", result
    assert captured.get("active") == "groups", captured
    assert captured.get("content_template") == "settings/groups.html", captured
    assert captured.get("groups") is fake_groups, captured
    assert isinstance(captured.get("rename_form"), GroupRenameForm), captured
    assert isinstance(captured.get("move_form"), GroupMoveForm), captured
    assert isinstance(captured.get("delete_form"), CSRFOnlyForm), captured
