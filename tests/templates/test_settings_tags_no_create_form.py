"""Pure-Unit Template-Tests: /settings/tags Manage-Only-Seite (Block Z, Phase D, ADR-0040).

Verifiziert dass `settings/tags.html` auf Manage-Only + `sd-*`-Markup
refactored wurde:
  - KEIN Anlege-Form mehr (kein `tags_create`-Endpoint, kein "Anlegen"-Submit),
    stattdessen Hint-Block der auf den Inline-Create im Server-Detail lenkt,
  - `sd-*`-Klassen statt DaisyUI (kein `card`/`btn`/`badge`/`table`/`input-bordered`),
  - befuellter State (Color-/Rename-/Delete-Hooks pro Row) + Empty-State.

Render-Strategie analog `tests/views/test_settings_groups_template.py` (Phase C):
Content-Only-Template direkt via `flask.render_template` im App-Context, Context =
Liste echter Tag-aehnlicher Objekte (id/name/color) plus echte Form-Instanzen.
CSRF aktiv → `csrf_token` rendert ein echtes Hidden-Input. Kein DB-Zugriff.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from flask import Flask, render_template


@dataclass
class _FakeTag:
    """Minimaler Tag-ORM-Stub: nur die im Template genutzten Attribute."""

    id: int
    name: str
    color: str


@pytest.fixture
def csrf_app(app_env: None) -> Flask:
    """App mit aktiviertem CSRF und TESTING=True."""
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=True, SECRET_KEY="test-secret")
    return flask_app


def _render(app: Flask, tags: list[_FakeTag]) -> str:
    """Rendert settings/tags.html mit gemocktem Backend-Context."""
    from app.forms import CSRFOnlyForm, TagColorForm, TagRenameForm

    with app.test_request_context("/settings/tags"):
        return render_template(
            "settings/tags.html",
            active="tags",
            tags=tags,
            rename_form=TagRenameForm(),
            color_form=TagColorForm(),
            delete_form=CSRFOnlyForm(),
        )


def _two_tags() -> list[_FakeTag]:
    return [
        _FakeTag(id=1, name="prod", color="#ff8800"),
        _FakeTag(id=2, name="staging", color="#0088ff"),
    ]


# ===========================================================================
# 1. KEIN Anlege-Form: Hint-Block vorhanden, kein Create-Submit/DaisyUI
# ===========================================================================


def test_no_create_form_hint_present(csrf_app: Flask) -> None:
    html = _render(csrf_app, _two_tags())
    # Hint lenkt auf den Inline-Create-Pfad im Server-Detail-Settings.
    assert "Tags are created by assigning a new tag in the server detail settings" in html
    # Kein Create-Form: weder "Anlegen"-Text noch eine Create-Section-Ueberschrift.
    assert "Anlegen" not in html
    assert "Neuen Tag anlegen" not in html


# ===========================================================================
# 2. sd-*-Markup statt DaisyUI
# ===========================================================================


def test_sd_markup_not_daisyui(csrf_app: Flask) -> None:
    html = _render(csrf_app, _two_tags())
    assert "sd-manage-table" in html
    assert 'data-test="tags-table"' in html
    # Keine DaisyUI-Komponenten-Klassen mehr.
    assert 'class="card' not in html
    assert 'class="btn' not in html
    assert "badge" not in html
    assert "input-bordered" not in html
    assert "form-control" not in html


# ===========================================================================
# 3. Befuellter State: Color-/Rename-/Delete-Hooks pro Row
# ===========================================================================


def test_filled_state_row_hooks(csrf_app: Flask) -> None:
    html = _render(csrf_app, _two_tags())
    for tid in (1, 2):
        assert f'data-test="tag-row-{tid}"' in html
        assert f'data-test="tag-color-input-{tid}"' in html
        assert f'data-test="tag-color-submit-{tid}"' in html
        assert f'data-test="tag-rename-input-{tid}"' in html
        assert f'data-test="tag-rename-submit-{tid}"' in html
        assert f'data-test="tag-delete-{tid}"' in html
    # Aktueller Name + Farbe + Whitelist-Pattern auf dem Rename-Input.
    assert 'value="prod"' in html
    assert 'value="#ff8800"' in html
    assert 'pattern="^[a-z0-9][a-z0-9._-]{0,31}$"' in html
    # Delete hat einen client-seitigen Confirm-Dialog (kein Pflicht-Feld).
    assert "confirm(" in html


# ===========================================================================
# 4. Empty-State bei leerer Liste, KEINE Tabelle
# ===========================================================================


def test_empty_state_no_table(csrf_app: Flask) -> None:
    html = _render(csrf_app, [])
    assert 'data-test="tags-empty"' in html
    assert 'data-test="tags-table"' not in html
    assert "No tags yet" in html
