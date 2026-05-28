"""Pure-Unit-Tests fuer `ServerTagCreateForm` (Block Z, Phase A, ADR-0040).

Single-Field-Form fuer die Inline-Anlage eines Tags. Validierung:
`DataRequired() + Length(1, 32) + Regexp(TAG_NAME_REGEX)`. Kein color-Feld —
der View-Handler setzt den Default `#6b7280`.

Regex: `^[a-z0-9][a-z0-9._\\-]{0,31}$` (Start mit Buchstabe/Ziffer).

Form-Instanziierung im App-Context analog `test_server_settings.py` Tests 26/27.
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
    ["prod", "web-01", "a", "0abc", "a" * 32, "db.primary_1"],
    ids=["simple", "hyphen", "single_char", "leading_digit", "max_len_32", "dots_underscore"],
)
def test_server_tag_create_form_accepts_valid(no_csrf_app: Flask, name: str) -> None:
    """Gueltige Tag-Namen validieren erfolgreich."""
    from app.forms import ServerTagCreateForm

    with no_csrf_app.test_request_context("/"):
        form = ServerTagCreateForm(formdata=ImmutableMultiDict([("name", name)]))
        result = form.validate()

    assert result is True, (
        f"ServerTagCreateForm soll name={name!r} akzeptieren. Fehler: {form.errors}"
    )


@pytest.mark.parametrize(
    "name",
    ["Prod", "", "a" * 33, "-prod", ".prod", "_prod", "prod eu", "prod@eu", "prod/eu"],
    ids=[
        "uppercase",
        "empty",
        "too_long_33",
        "leading_dash",
        "leading_dot",
        "leading_underscore",
        "space",
        "at_sign",
        "slash",
    ],
)
def test_server_tag_create_form_rejects_invalid(no_csrf_app: Flask, name: str) -> None:
    """Ungueltige Tag-Namen (Uppercase/leer/zu lang/falscher Start/Sonderzeichen) -> invalid."""
    from app.forms import ServerTagCreateForm

    with no_csrf_app.test_request_context("/"):
        form = ServerTagCreateForm(formdata=ImmutableMultiDict([("name", name)]))
        result = form.validate()

    assert result is False, (
        f"ServerTagCreateForm soll name={name!r} ablehnen, validiert aber. Fehler: {form.errors}"
    )
    assert "name" in form.errors, f"Fehler-Key 'name' erwartet. Errors: {form.errors}"


def test_server_tag_create_form_missing_field_rejected(no_csrf_app: Flask) -> None:
    """Komplett fehlendes name-Feld (DataRequired) -> invalid."""
    from app.forms import ServerTagCreateForm

    with no_csrf_app.test_request_context("/"):
        form = ServerTagCreateForm(formdata=ImmutableMultiDict())
        result = form.validate()

    assert result is False, "Fehlendes name-Feld muss als invalid gelten."
    assert "name" in form.errors, f"Fehler-Key 'name' erwartet. Errors: {form.errors}"


def test_server_tag_create_form_has_no_color_field(no_csrf_app: Flask) -> None:
    """ServerTagCreateForm hat nur das name-Feld (kein color)."""
    from app.forms import ServerTagCreateForm

    with no_csrf_app.test_request_context("/"):
        form = ServerTagCreateForm()

    field_names = {f.name for f in form if f.name != "csrf_token"}
    assert field_names == {"name"}, (
        f"ServerTagCreateForm soll nur 'name' fuehren (kein color). Felder: {field_names}"
    )


def test_server_tag_create_form_shares_tag_name_regex(no_csrf_app: Flask) -> None:
    """Die Form nutzt TAG_NAME_REGEX identisch zu TagForm.name (kein Drift)."""
    from app.forms import TAG_NAME_REGEX

    assert TAG_NAME_REGEX.pattern == r"^[a-z0-9][a-z0-9._\-]{0,31}$", (
        f"TAG_NAME_REGEX-Pattern unerwartet: {TAG_NAME_REGEX.pattern!r}"
    )
    assert TAG_NAME_REGEX.match("prod") is not None
    assert TAG_NAME_REGEX.match("-prod") is None
    assert TAG_NAME_REGEX.match("Prod") is None
