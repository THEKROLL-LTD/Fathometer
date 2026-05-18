"""WTForms-Klassen fuer alle Browser-Endpunkte aus Block B.

Validierung folgt ARCHITECTURE.md §10 (Regex-Whitelists). CSRF-Schutz kommt
ueber `Flask-WTF` (CSRFProtect ist in `create_app()` aktiviert).
"""

from __future__ import annotations

import re

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    TextAreaField,
)
from wtforms.validators import (
    DataRequired,
    EqualTo,
    Length,
    NumberRange,
    Regexp,
    ValidationError,
)
from wtforms.validators import Optional as OptionalValidator

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


class MasterKeyRotateForm(FlaskForm):
    """Reines CSRF-Token-Form fuer die Master-Key-Rotation.

    Die Rotation hat keine User-Inputs — Flask-WTF stellt `csrf_token`
    automatisch bereit. Eigene Klasse (statt `CSRFOnlyForm`-Reuse), damit
    Tests und Reviewer den Zweck am Form-Namen erkennen koennen und der
    Audit-Helfer in §13 die richtige Aktion zuordnen kann.
    """


class LlmReviewerModeForm(FlaskForm):
    """Mode-Wechsel-Form fuer den LLM-Risk-Reviewer (Block P, ADR-0023).

    Felder:
      - `new_mode`   : off/observation/live — Whitelist im SelectField.
      - `master_key` : Klartext-Master-Key zur Bestaetigung (analog
                       Master-Key-Pattern aus §8).

    Beide Felder sind required; CSRF kommt automatisch.
    """

    new_mode = SelectField(
        "Neuer Mode",
        choices=[
            ("off", "off"),
            ("observation", "observation"),
            ("live", "live"),
        ],
        validators=[DataRequired()],
    )
    master_key = PasswordField(
        "Master-Key",
        validators=[
            DataRequired(),
            Length(min=10, max=128),
        ],
    )


class LlmReviewerRequeueForm(FlaskForm):
    """Backlog-Re-queue-Form (Block P, ADR-0023).

    Nur `master_key` als Bestaetigung — `new_mode` waere hier sinnlos, weil
    Re-queue nur im `live`-Mode aufgerufen werden soll (View prueft den
    aktuellen Mode-Wert).
    """

    master_key = PasswordField(
        "Master-Key",
        validators=[
            DataRequired(),
            Length(min=10, max=128),
        ],
    )


# Max-Laenge fuer Notiz-/Kommentar-Texte aus ARCHITECTURE.md §10: max 8 KB
# pro Notiz. Wir setzen das als WTForms-Validator und verlassen uns nicht
# auf die DB allein.
NOTE_TEXT_MAX_LEN = 8 * 1024


class AcknowledgeForm(FlaskForm):
    """Acknowledge-Action mit *optionalem* Kommentar.

    ADR-0006: Kommentar ist niemals Pflicht. Wenn vorhanden, wird er als
    Notiz mit `author='system-ack'` an den Thread angehaengt.
    """

    # Bewusst KEIN DataRequired/InputRequired — nur Laengen-Cap.
    comment = TextAreaField(
        "Kommentar (optional)",
        validators=[OptionalValidator(), Length(max=NOTE_TEXT_MAX_LEN)],
    )


class ReopenForm(FlaskForm):
    """Re-Open-Action — analog zu Acknowledge. Comment optional."""

    comment = TextAreaField(
        "Kommentar (optional)",
        validators=[OptionalValidator(), Length(max=NOTE_TEXT_MAX_LEN)],
    )


class NoteForm(FlaskForm):
    """Neue Notiz im Finding-Thread.

    Hier ist `body` Pflicht — eine leere Notiz ist semantisch sinnlos. Aber
    das ist ein Body-Feld, kein Acknowledge-Comment — ADR-0006 bezieht sich
    explizit auf Kommentar-Felder bei state-changing Actions (Ack/Reopen/
    Bulk). Notes selbst duerfen Pflicht-Inhalt verlangen.
    """

    body = TextAreaField(
        "Notiz",
        validators=[
            DataRequired(message="Notiz darf nicht leer sein."),
            Length(min=1, max=NOTE_TEXT_MAX_LEN),
        ],
    )


class LlmSettingsForm(FlaskForm):
    """LLM-Provider-Konfiguration (siehe ARCHITECTURE.md §7 / §10).

    - `provider_name`: freier Anzeigename, max 64 Zeichen, gleiche Regex
      wie Tag-Namen.
    - `base_url`: Whitelist via `app.services.llm_client.validate_base_url`
      (HTTPS oder `http://localhost`/`http://127.0.0.1`).
    - `api_key`: optional; leer = behalte alten Wert.
    - `model`: druckbares ASCII, max 128.
    - `daily_token_cap`: Integer >= 1.
    """

    provider_name = StringField(
        "Anzeigename",
        validators=[OptionalValidator(), Length(max=64)],
    )
    base_url = StringField(
        "Base-URL",
        validators=[DataRequired(), Length(max=256)],
    )
    api_key = PasswordField(
        "API-Key (leer lassen, um den bestehenden zu behalten)",
        validators=[OptionalValidator(), Length(max=512)],
    )
    model = StringField(
        "Modell-Name",
        validators=[DataRequired(), Length(max=128)],
    )
    daily_token_cap = IntegerField(
        "Tages-Token-Cap",
        validators=[DataRequired(), NumberRange(min=1, max=10_000_000_000)],
    )

    def validate_provider_name(self, field: StringField) -> None:
        if field.data is None or not field.data.strip():
            return
        candidate = field.data.strip()
        if not TAG_NAME_REGEX.match(candidate):
            raise ValidationError(
                "Erlaubt: a-z, 0-9, '.', '_', '-' (Start mit Buchstabe/Ziffer, max 32 Zeichen)."
            )

    def validate_base_url(self, field: StringField) -> None:
        from app.services.llm_client import validate_base_url as _vbu

        if not field.data:
            raise ValidationError("Base-URL erforderlich.")
        try:
            _vbu(field.data.strip())
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

    def validate_model(self, field: StringField) -> None:
        value = (field.data or "").strip()
        if not value:
            raise ValidationError("Modell-Name erforderlich.")
        # Druckbares ASCII (0x20-0x7E), kein Whitespace am Anfang/Ende
        # nach strip() bereits eliminiert.
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
            raise ValidationError("Nur druckbares ASCII erlaubt.")


class BulkActionForm(FlaskForm):
    """Container fuer die Checkbox-basierte Bulk-Auswahl im Server-Detail.

    Eigentliche Auswahl-IDs werden per JSON-Body an `/api/findings/bulk-
    acknowledge` geschickt; diese Form dient nur als CSRF-Token-Halter
    fuer den Modal-Submit aus dem Server-Detail-View und der globalen
    Suche.
    """


class GroupAcknowledgeForm(FlaskForm):
    """Bulk-Acknowledge fuer alle OPEN-Findings eines Pakets.

    Wird vom *Gruppiert-nach-Paket*-View aufgerufen. `server_id` und
    `package_name` werden via Hidden-Inputs aus dem Group-Header
    uebernommen. Kommentar bleibt optional (ADR-0006).
    """

    server_id = IntegerField(
        "Server",
        validators=[DataRequired(), NumberRange(min=1)],
    )
    package_name = StringField(
        "Paket",
        validators=[DataRequired(), Length(min=1, max=256)],
    )
    comment = TextAreaField(
        "Kommentar (optional)",
        validators=[OptionalValidator(), Length(max=NOTE_TEXT_MAX_LEN)],
    )


__all__ = [
    "NOTE_TEXT_MAX_LEN",
    "TAG_COLOR_REGEX",
    "TAG_NAME_REGEX",
    "AcknowledgeForm",
    "BulkActionForm",
    "CSRFOnlyForm",
    "GroupAcknowledgeForm",
    "LlmSettingsForm",
    "LoginForm",
    "MasterKeyRotateForm",
    "NoteForm",
    "ReopenForm",
    "SetupStep1Form",
    "SetupStep2Form",
    "SetupStep3Form",
    "TagForm",
]
