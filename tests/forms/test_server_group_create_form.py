"""Pure-Unit-Tests fuer `ServerGroupCreateForm` (Block Z, Phase A, ADR-0040).

Single-Field-Form fuer die Inline-Anlage einer ServerGroup. Validierung:
`DataRequired() + Length(1, 64) + Regexp(SERVER_GROUP_NAME_REGEX)`.

Regex (Single Source of Truth): `^[A-Za-z0-9 _.-]+$`.

Form-Instanziierung im App-Context analog `test_server_settings.py` Tests 26/27
(`app.test_request_context()` + `formdata=ImmutableMultiDict([...])`).
"""

from __future__ import annotations

import pytest
from flask import Flask
from werkzeug.datastructures import ImmutableMultiDict


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


@pytest.mark.parametrize(
    "name",
    ["prod-eu", "prod eu", "a" * 64, "Prod_EU.1", "x", "group-01"],
    ids=["hyphen", "space", "max_len_64", "mixed", "single_char", "alnum_hyphen"],
)
def test_server_group_create_form_accepts_valid(no_csrf_app: Flask, name: str) -> None:
    """Gueltige Gruppen-Namen validieren erfolgreich."""
    from app.forms import ServerGroupCreateForm

    with no_csrf_app.test_request_context("/"):
        form = ServerGroupCreateForm(formdata=ImmutableMultiDict([("name", name)]))
        result = form.validate()

    assert result is True, (
        f"ServerGroupCreateForm soll name={name!r} akzeptieren. Fehler: {form.errors}"
    )


@pytest.mark.parametrize(
    "name",
    ["prod/eu", "prod@eu", "x" * 65, "", "prod#eu", "prod\teu"],
    ids=["slash", "at_sign", "too_long_65", "empty", "hash", "tab"],
)
def test_server_group_create_form_rejects_invalid(no_csrf_app: Flask, name: str) -> None:
    """Ungueltige Gruppen-Namen (Regex/Length/Required) werden abgewiesen."""
    from app.forms import ServerGroupCreateForm

    with no_csrf_app.test_request_context("/"):
        form = ServerGroupCreateForm(formdata=ImmutableMultiDict([("name", name)]))
        result = form.validate()

    assert result is False, (
        f"ServerGroupCreateForm soll name={name!r} ablehnen, validiert aber. Fehler: {form.errors}"
    )
    assert "name" in form.errors, f"Fehler-Key 'name' erwartet. Errors: {form.errors}"


@pytest.mark.parametrize(
    "name",
    ["   ", " ", "\t ", "  \t"],
    ids=["three_spaces", "single_space", "tab_space", "spaces_tab"],
)
def test_server_group_create_form_rejects_whitespace_only(no_csrf_app: Flask, name: str) -> None:
    """Whitespace-only-Namen werden abgewiesen (Regression: ROT-1 Security-Audit).

    Das Leerzeichen ist Teil der Charset, daher wuerde `"   "` Regex + Length
    bestehen — der View strippt den Namen aber, das Ergebnis `""` verletzt die
    DB-CHECK-Constraints und der Race-Catch-`scalar_one()` faende keine Row
    (NoResultFound -> 500). `validate_name` faengt das Form-seitig ab.
    """
    from app.forms import ServerGroupCreateForm

    with no_csrf_app.test_request_context("/"):
        form = ServerGroupCreateForm(formdata=ImmutableMultiDict([("name", name)]))
        result = form.validate()

    assert result is False, (
        f"ServerGroupCreateForm soll whitespace-only name={name!r} ablehnen. Fehler: {form.errors}"
    )
    assert "name" in form.errors, f"Fehler-Key 'name' erwartet. Errors: {form.errors}"


def test_server_group_create_form_missing_field_rejected(no_csrf_app: Flask) -> None:
    """Komplett fehlendes name-Feld (DataRequired) -> invalid."""
    from app.forms import ServerGroupCreateForm

    with no_csrf_app.test_request_context("/"):
        form = ServerGroupCreateForm(formdata=ImmutableMultiDict())
        result = form.validate()

    assert result is False, "Fehlendes name-Feld muss als invalid gelten."
    assert "name" in form.errors, f"Fehler-Key 'name' erwartet. Errors: {form.errors}"


def test_server_group_create_form_has_no_color_field(no_csrf_app: Flask) -> None:
    """ServerGroupCreateForm hat nur das name-Feld (kein color/position)."""
    from app.forms import ServerGroupCreateForm

    with no_csrf_app.test_request_context("/"):
        form = ServerGroupCreateForm()

    field_names = {f.name for f in form if f.name != "csrf_token"}
    assert field_names == {"name"}, (
        f"ServerGroupCreateForm soll nur 'name' fuehren (kein color/position). Felder: {field_names}"
    )


def test_server_group_create_form_regex_is_shared_constant(no_csrf_app: Flask) -> None:
    """Die Form nutzt SERVER_GROUP_NAME_REGEX als Single Source of Truth.

    Regression-Guard gegen Drift: das Regex-Pattern muss dem Modul-Konstante-Wert
    entsprechen (gleicher Charset wie DB-CHECK-Constraint).
    """
    from app.forms import SERVER_GROUP_NAME_REGEX

    assert SERVER_GROUP_NAME_REGEX.pattern == r"^[A-Za-z0-9 _.-]+$", (
        f"SERVER_GROUP_NAME_REGEX-Pattern unerwartet: {SERVER_GROUP_NAME_REGEX.pattern!r}"
    )
    assert SERVER_GROUP_NAME_REGEX.match("prod-eu") is not None
    assert SERVER_GROUP_NAME_REGEX.match("prod/eu") is None
