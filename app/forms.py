"""WTForms-Klassen fuer alle Browser-Endpunkte aus Block B.

Validierung folgt ARCHITECTURE.md §10 (Regex-Whitelists). CSRF-Schutz kommt
ueber `Flask-WTF` (CSRFProtect ist in `create_app()` aktiviert).
"""

from __future__ import annotations

import re

from flask_wtf import FlaskForm
from wtforms import BooleanField, IntegerField, PasswordField, SelectField, StringField
from wtforms.validators import (
    DataRequired,
    EqualTo,
    Length,
    NumberRange,
    Regexp,
    ValidationError,
)

# Aus ARCHITECTURE.md §10:
#   Tag-Namen: `^[a-z0-9][a-z0-9._\-]{0,31}$`
# Wir nutzen das Pattern auch fuer `llm_provider_name`.
TAG_NAME_REGEX = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,31}$")
TAG_COLOR_REGEX = re.compile(r"^#[0-9a-fA-F]{6}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9._\-]{3,64}$")

# Theme-Werte aus §7.
THEME_CHOICES: list[tuple[str, str]] = [
    ("auto", "Auto (System)"),
    ("light", "Hell"),
    ("dark", "Dunkel"),
]
SEVERITY_CHOICES: list[tuple[str, str]] = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
]


class SetupStep1Form(FlaskForm):
    """Admin-Account anlegen."""

    username = StringField(
        "Benutzername",
        validators=[
            DataRequired(),
            Length(min=3, max=64),
            Regexp(
                USERNAME_REGEX, message="Erlaubt: a-z, A-Z, 0-9, Punkt, Unter- und Bindestrich."
            ),
        ],
    )
    password = PasswordField(
        "Passwort",
        validators=[
            DataRequired(),
            Length(min=12, max=256, message="Mindestens 12 Zeichen."),
        ],
    )
    password_confirm = PasswordField(
        "Passwort bestaetigen",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwoerter stimmen nicht ueberein."),
        ],
    )


class SetupStep2Form(FlaskForm):
    """Master-Key-Bestaetigung. Der Key selbst wird vom View generiert."""

    confirmed = BooleanField(
        "Ich habe den Master-Key notiert und sicher abgelegt.",
        validators=[DataRequired(message="Bitte Notiz bestaetigen.")],
    )


class SetupStep3Form(FlaskForm):
    """Defaults setzen (Severity-Schwelle, Stale-Thresholds, Theme)."""

    severity_threshold = SelectField(
        "Severity-Schwelle",
        choices=SEVERITY_CHOICES,
        default="high",
        validators=[DataRequired()],
    )
    stale_threshold_h = IntegerField(
        "Stale-Server nach (Stunden)",
        default=48,
        validators=[DataRequired(), NumberRange(min=1, max=720)],
    )
    stale_trivy_db_threshold_h = IntegerField(
        "Stale Trivy-DB nach (Stunden)",
        default=30,
        validators=[DataRequired(), NumberRange(min=1, max=720)],
    )
    default_theme = SelectField(
        "Default-Theme",
        choices=THEME_CHOICES,
        default="auto",
        validators=[DataRequired()],
    )


class LoginForm(FlaskForm):
    """Login-Form fuer den Admin-Account."""

    username = StringField(
        "Benutzername",
        validators=[DataRequired(), Length(min=3, max=64)],
    )
    password = PasswordField(
        "Passwort",
        validators=[DataRequired(), Length(min=1, max=256)],
    )


class TagForm(FlaskForm):
    """Neues Tag anlegen."""

    name = StringField(
        "Tag-Name",
        validators=[DataRequired(), Length(min=1, max=32)],
    )
    color = StringField(
        "Farbe (Hex, z.B. #6b7280)",
        default="#6b7280",
        validators=[DataRequired(), Length(min=7, max=7)],
    )

    def validate_name(self, field: StringField) -> None:
        """Pattern-Check fuer Tag-Namen — siehe §10."""
        if not field.data or not TAG_NAME_REGEX.match(field.data):
            raise ValidationError(
                "Ungueltiger Tag-Name. Erlaubt: a-z, 0-9, '.', '_', '-' "
                "(Start mit Buchstabe/Ziffer, max 32 Zeichen)."
            )

    def validate_color(self, field: StringField) -> None:
        if not field.data or not TAG_COLOR_REGEX.match(field.data):
            raise ValidationError("Farbe muss im Format #rrggbb sein.")


class CSRFOnlyForm(FlaskForm):
    """Leere Form ausschliesslich fuer den CSRF-Token (z.B. Delete-Buttons)."""


__all__ = [
    "TAG_COLOR_REGEX",
    "TAG_NAME_REGEX",
    "CSRFOnlyForm",
    "LoginForm",
    "SetupStep1Form",
    "SetupStep2Form",
    "SetupStep3Form",
    "TagForm",
]
