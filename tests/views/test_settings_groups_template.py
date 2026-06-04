"""Pure-Unit Template-Tests: /settings/groups Manage-Only-Seite (Block Z, Phase C, ADR-0040).

Verifiziert dass `settings/groups.html` die Manage-Tabelle korrekt rendert:
  - zwei Gruppen → Namen + Member-Counts + data-test-Hooks vorhanden,
  - Up-Button erste Zeile / Down-Button letzte Zeile `disabled`,
  - Rename-Input + Delete-Button mit korrekten data-test-Hooks pro Row,
  - Empty-State (`groups-empty`) bei leerer Liste, KEINE Tabelle,
  - KEIN Create-Form (kein POST auf `groups_list`),
  - CSRF-Token in Rename/Delete/Move-Forms.

Render-Strategie:
  Das Content-Only-Template wird direkt via `flask.render_template` im
  App-Context gerendert. Context = Liste von Dicts (exakt der Backend-Vertrag
  aus `settings.groups_list`) plus echte Form-Instanzen. CSRF ist aktiv,
  damit `csrf_token` ein echtes Hidden-Input rendert. Kein DB-Zugriff,
  kein db_integration-Marker.
"""

from __future__ import annotations

import pytest
from flask import Flask, render_template

# ---------------------------------------------------------------------------
# Fixture: App mit aktivem CSRF (csrf_token-Render-Test braucht echtes Token)
# ---------------------------------------------------------------------------


@pytest.fixture
def csrf_app(app_env: None) -> Flask:
    """App mit aktiviertem CSRF und TESTING=True."""
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=True, SECRET_KEY="test-secret")
    return flask_app


# ---------------------------------------------------------------------------
# Render-Helper
# ---------------------------------------------------------------------------


def _render(app: Flask, groups: list[dict[str, object]]) -> str:
    """Rendert settings/groups.html mit gemocktem Backend-Context."""
    from app.forms import CSRFOnlyForm, GroupMoveForm, GroupRenameForm

    with app.test_request_context("/settings/groups"):
        return render_template(
            "settings/groups.html",
            active="groups",
            groups=groups,
            rename_form=GroupRenameForm(),
            move_form=GroupMoveForm(),
            delete_form=CSRFOnlyForm(),
        )


def _two_groups() -> list[dict[str, object]]:
    return [
        {"id": 1, "name": "prod-eu", "position": 0, "member_count": 3},
        {"id": 2, "name": "staging", "position": 1, "member_count": 0},
    ]


# ===========================================================================
# 1. Render mit 2 Gruppen — Namen, Counts, Tabelle, Row-Hooks
# ===========================================================================


def test_two_groups_rendered(csrf_app: Flask) -> None:
    html = _render(csrf_app, _two_groups())
    assert 'data-test="groups-table"' in html
    assert 'data-test="group-row-1"' in html
    assert 'data-test="group-row-2"' in html
    assert "prod-eu" in html
    assert "staging" in html
    # Member-Counts in den dafuer vorgesehenen Spans.
    assert 'data-test="group-member-count-1"' in html
    assert 'data-test="group-member-count-2"' in html
    assert ">3</span>" in html
    assert ">0</span>" in html


# ===========================================================================
# 2. Up-Button erste Zeile disabled, Down-Button letzte Zeile disabled
# ===========================================================================


def test_move_buttons_boundary_disabled(csrf_app: Flask) -> None:
    html = _render(csrf_app, _two_groups())
    # Up auf erster Row (id=1) disabled, Down auf erster Row NICHT.
    up_first = html.split('data-test="group-move-up-1"')[1].split(">")[0]
    assert "disabled" in up_first
    down_first = html.split('data-test="group-move-down-1"')[1].split(">")[0]
    assert "disabled" not in down_first
    # Down auf letzter Row (id=2) disabled, Up auf letzter Row NICHT.
    down_last = html.split('data-test="group-move-down-2"')[1].split(">")[0]
    assert "disabled" in down_last
    up_last = html.split('data-test="group-move-up-2"')[1].split(">")[0]
    assert "disabled" not in up_last
    # Submit-Buttons populieren das SelectField via name/value.
    assert 'name="direction"' in html
    assert 'value="up"' in html
    assert 'value="down"' in html


# ===========================================================================
# 3. Rename-Input + Delete-Button mit korrekten data-test-Hooks pro Row
# ===========================================================================


def test_rename_and_delete_hooks_per_row(csrf_app: Flask) -> None:
    html = _render(csrf_app, _two_groups())
    for gid in (1, 2):
        assert f'data-test="group-rename-input-{gid}"' in html
        assert f'data-test="group-rename-submit-{gid}"' in html
        assert f'data-test="group-delete-{gid}"' in html
    # Rename-Input traegt den aktuellen Namen als value + Whitelist-Pattern.
    assert 'value="prod-eu"' in html
    assert 'pattern="^[A-Za-z0-9 _.-]+$"' in html
    # Delete hat einen client-seitigen Confirm-Dialog (kein Pflicht-Feld).
    assert "confirm(" in html
    assert "ungrouped" in html


# ===========================================================================
# 4. Empty-State bei leerer Liste, KEINE Tabelle
# ===========================================================================


def test_empty_state_no_table(csrf_app: Flask) -> None:
    html = _render(csrf_app, [])
    assert 'data-test="groups-empty"' in html
    assert 'data-test="groups-table"' not in html
    assert "No groups yet" in html


# ===========================================================================
# 5. KEIN Create-Form — kein POST auf groups_list-Endpoint
# ===========================================================================


def test_no_create_form(csrf_app: Flask) -> None:
    html = _render(csrf_app, _two_groups())
    # Der Listen-Endpoint /settings/groups darf NICHT als Form-Action auftauchen.
    with csrf_app.test_request_context("/settings/groups"):
        from flask import url_for

        list_url = url_for("settings.groups_list")
    assert f'action="{list_url}"' not in html
    # Hint-Block lenkt auf den Inline-Create-Pfad im Server-Detail-Settings.
    assert "in the server detail settings" in html


# ===========================================================================
# 6. CSRF-Token in Rename/Delete/Move-Forms vorhanden
# ===========================================================================


def test_csrf_token_in_state_changing_forms(csrf_app: Flask) -> None:
    html = _render(csrf_app, _two_groups())
    # CSRF aktiv → hidden csrf_token-Inputs gerendert. Pro Row: 2x move + 1x
    # rename + 1x delete = 4 Tokens, bei zwei Rows mindestens 8 Vorkommen.
    assert html.count('name="csrf_token"') >= 8, (
        f"Zu wenige csrf_token-Inputs: {html.count(chr(34) + 'csrf_token' + chr(34))}"
    )
