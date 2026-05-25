"""WTForms-Klassen fuer alle Browser-Endpunkte aus Block B.

Validierung folgt ARCHITECTURE.md §10 (Regex-Whitelists). CSRF-Schutz kommt
ueber `Flask-WTF` (CSRFProtect ist in `create_app()` aktiviert).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from app.models import ServerGroup

# Aus ARCHITECTURE.md §10:
#   Tag-Namen: `^[a-z0-9][a-z0-9._\-]{0,31}$`
# Wir nutzen das Pattern auch fuer `llm_provider_name`.
TAG_NAME_REGEX = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,31}$")
TAG_COLOR_REGEX = re.compile(r"^#[0-9a-fA-F]{6}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9._\-]{3,64}$")

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
    """Defaults setzen (Severity-Schwelle, Stale-Thresholds)."""

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


class LlmReviewerConcurrencyForm(FlaskForm):
    """Concurrency-Wechsel-Form fuer den LLM-Risk-Reviewer (Block U, ADR-0029).

    Felder:
      - `concurrency` : Integer im Bereich [1, 200] — neuer Wert fuer
                        ``settings.llm_worker_job_concurrency``.
      - `master_key`  : Klartext-Master-Key zur Bestaetigung (analog
                        Mode-Form aus Block P).

    Format-Validierung passiert hier; der Master-Key-Vergleich (Konstant-
    zeit via ``hmac.compare_digest``) findet im View-Handler statt — siehe
    ``LlmReviewerModeForm``-Pattern.
    """

    concurrency = IntegerField(
        "Concurrency",
        validators=[
            DataRequired(),
            NumberRange(min=1, max=200, message="Concurrency muss zwischen 1 und 200 liegen."),
        ],
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


class ServerGroupForm(FlaskForm):
    """Server-Group-Selector — single-select aus existierenden server_groups oder NULL.

    Block X (ADR-0038): setzt `server.group_id` auf eine existierende Group oder NULL
    ("— keine —"). Validation erfolgt zusaetzlich per Whitelist im View-Handler.
    """

    group_id = SelectField(
        "Group",
        coerce=lambda v: int(v) if v not in (None, "", "none") else None,
        validators=[OptionalValidator()],
    )

    def __init__(
        self,
        *args: object,
        available_groups: Sequence[ServerGroup] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)
        choices: list[tuple[str, str]] = [("none", "— keine —")]
        if available_groups:
            choices.extend((str(g.id), g.name) for g in available_groups)
        self.group_id.choices = choices


class ServerScanIntervalForm(FlaskForm):
    """Expected-Scan-Interval-Editor — Stunden 1..168 (1 Woche max).

    Block X (ADR-0038): setzt `server.expected_scan_interval_h`.
    """

    scan_interval_h = IntegerField(
        "Scan-Intervall (h)",
        validators=[DataRequired(), NumberRange(min=1, max=168)],
    )


class ServerSettingsForm(FlaskForm):
    """Kombiniertes Single-Save-Form fuer Server-Settings (Block X, Track F).

    Felder:
      - `group_id`        : SelectField — existierende ServerGroup oder None.
      - `scan_interval_h` : IntegerField — Stunden 1..168.

    Tags werden NICHT in diesem Form verwaltet; Add/Remove laufen weiterhin
    ueber separate Endpoints (`server_settings.add_tag` / `remove_tag`).

    Choices fuer `group_id` werden im Konstruktor gesetzt, damit der View-
    Handler keine extra Lookup-Logik benoetigt.
    """

    group_id = SelectField(
        "Group",
        coerce=lambda v: int(v) if v not in (None, "", "none") else None,
        validators=[OptionalValidator()],
    )
    scan_interval_h = IntegerField(
        "Scan-Intervall (h)",
        validators=[DataRequired(), NumberRange(min=1, max=168)],
    )

    def __init__(
        self,
        *args: object,
        available_groups: Sequence[ServerGroup] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)
        choices: list[tuple[str, str]] = [("none", "— keine —")]
        if available_groups:
            choices.extend((str(g.id), g.name) for g in available_groups)
        self.group_id.choices = choices


__all__ = [
    "NOTE_TEXT_MAX_LEN",
    "TAG_COLOR_REGEX",
    "TAG_NAME_REGEX",
    "AcknowledgeForm",
    "BulkActionForm",
    "CSRFOnlyForm",
    "GroupAcknowledgeForm",
    "LlmReviewerConcurrencyForm",
    "LlmSettingsForm",
    "LoginForm",
    "MasterKeyRotateForm",
    "NoteForm",
    "ReopenForm",
    "ServerGroupForm",
    "ServerScanIntervalForm",
    "ServerSettingsForm",
    "SetupStep1Form",
    "SetupStep2Form",
    "SetupStep3Form",
    "TagForm",
]
