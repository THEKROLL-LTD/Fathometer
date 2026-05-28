"""Adversarial-Tests fuer die Tag-Validierung.

Regex aus ARCHITECTURE.md §10 und `app/forms.py`:
    TAG_NAME_REGEX = re.compile(r"^[a-z0-9][a-z0-9._\\-]{0,31}$")

Heisst:
- Erstes Zeichen MUSS `[a-z0-9]` sein. Bindestrich und Underscore an Position 1
  sind verboten.
- Folgezeichen: `[a-z0-9._-]`.
- Gesamtlaenge 1..32 Zeichen.
- Nur Kleinbuchstaben — Grossbuchstaben werden abgelehnt.
- Whitespace, Sonderzeichen, Unicode -> abgelehnt.

Wir testen sowohl direkt gegen den WTForms-`TagForm`-Validator als auch ueber
die HTTP-Route, damit beide Pfade konsistent verhalten.
"""

from __future__ import annotations

import pytest
from flask import Flask
from werkzeug.datastructures import MultiDict

from app.forms import TAG_NAME_REGEX, TagForm

# ---------------------------------------------------------------------------
# Reines Regex-Pattern (unit-level).
# ---------------------------------------------------------------------------


INVALID_NAMES: list[tuple[str, str]] = [
    ("Foo Bar", "uppercase + space"),
    ("FOO", "all uppercase"),
    ("tag mit space", "internal space"),
    ("-leading-dash", "leading dash"),
    ("_leading-underscore", "leading underscore"),
    (".leading-dot", "leading dot"),
    ("", "empty string"),
    ("a" * 33, "33 chars > max"),
    ("tag!", "exclamation"),
    ("tag?", "question mark"),
    ("tag/foo", "slash"),
    ("tag\\foo", "backslash"),
    ("tag\nfoo", "newline"),
    ("tag\tfoo", "tab"),
    ("tag\x00foo", "NUL byte"),
    ("täg", "umlaut"),
    ("café", "non-ascii"),
    ("中文", "CJK"),
    ("tag$", "dollar"),
    ("tag@home", "at-sign"),
    ("tag:port", "colon"),
    ("tag;sql", "semicolon"),
    ("../etc", "path traversal"),
    ("<script>", "HTML"),
    ("'; DROP TABLE", "sql"),
]

VALID_NAMES: list[tuple[str, str]] = [
    ("prod", "lowercase word"),
    ("web", "short"),
    ("db-fleet", "hyphen middle"),
    ("region-eu", "hyphen middle"),
    ("0prod", "leading digit"),
    ("a", "single char"),
    ("a" * 32, "max length"),
    ("kube.prod.eu", "dots"),
    ("my_tag", "underscore middle"),
    ("v1.2.3", "version-ish"),
    ("123", "digits only"),
]


@pytest.mark.parametrize("name,reason", INVALID_NAMES, ids=[r for _, r in INVALID_NAMES])
def test_regex_rejects_invalid(name: str, reason: str) -> None:
    assert TAG_NAME_REGEX.match(name) is None, f"regex unexpectedly accepted {name!r} ({reason})"


@pytest.mark.parametrize("name,reason", VALID_NAMES, ids=[r for _, r in VALID_NAMES])
def test_regex_accepts_valid(name: str, reason: str) -> None:
    assert TAG_NAME_REGEX.match(name) is not None, (
        f"regex unexpectedly rejected {name!r} ({reason})"
    )


# ---------------------------------------------------------------------------
# Form-Level (mit CSRF deaktiviert, damit wir die Datenklasse direkt testen).
# ---------------------------------------------------------------------------


def _make_form_data(name: str, color: str = "#6b7280") -> MultiDict[str, str]:
    return MultiDict({"name": name, "color": color})


def test_tag_form_validation_uses_regex(app: Flask) -> None:
    """`TagForm` muss exakt die selben Strings ablehnen wie der Regex."""
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_request_context():
        for name, reason in INVALID_NAMES:
            form = TagForm(formdata=_make_form_data(name))
            assert not form.validate(), f"form accepted invalid name {name!r} ({reason})"
            # `name`-Errors enthalten unsere Fehlermeldung — leerer String wird
            # bereits durch `DataRequired` abgefangen.
            assert "name" in form.errors, form.errors

        for name, reason in VALID_NAMES:
            form = TagForm(formdata=_make_form_data(name))
            assert form.validate(), (
                f"form rejected valid name {name!r} ({reason}): errors={form.errors}"
            )


def test_tag_form_validation_rejects_bad_color(app: Flask) -> None:
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_request_context():
        for color in ("red", "#abc", "#12345g", "rgb(0,0,0)", "#1234567"):
            form = TagForm(formdata=_make_form_data("prod", color=color))
            assert not form.validate(), f"form accepted bad color {color!r}"
            assert "color" in form.errors, form.errors
