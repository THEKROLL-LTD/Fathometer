# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

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

# ServerGroup-Namen (ADR-0034 §Schema, CHECK-Constraint `ck_server_groups_name_charset`).
# Single Source of Truth fuer ServerGroupCreateForm (Phase A) UND GroupRenameForm
# (Phase C) — Block-Z-Risiken-Tabelle verlangt identische Regex in beiden Pfaden.
SERVER_GROUP_NAME_REGEX = re.compile(r"^[A-Za-z0-9 _.-]+$")

SEVERITY_CHOICES: list[tuple[str, str]] = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
]


class SetupStep1Form(FlaskForm):
    """Admin-Account anlegen."""

    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=64),
            Regexp(USERNAME_REGEX, message="Allowed: a-z, A-Z, 0-9, dot, underscore and hyphen."),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=12, max=256, message="At least 12 characters."),
        ],
    )
    password_confirm = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords do not match."),
        ],
    )


class SetupStep2Form(FlaskForm):
    """Master-Key-Bestaetigung. Der Key selbst wird vom View generiert."""

    confirmed = BooleanField(
        "I have noted and securely stored the master key.",
        validators=[DataRequired(message="Confirmation required.")],
    )


class SetupStep3Form(FlaskForm):
    """Defaults setzen (Severity-Schwelle, Stale-Thresholds)."""

    severity_threshold = SelectField(
        "Severity threshold",
        choices=SEVERITY_CHOICES,
        default="high",
        validators=[DataRequired()],
    )
    stale_threshold_h = IntegerField(
        "Stale server after (hours)",
        default=48,
        validators=[DataRequired(), NumberRange(min=1, max=720)],
    )
    stale_trivy_db_threshold_h = IntegerField(
        "Stale Trivy DB after (hours)",
        default=30,
        validators=[DataRequired(), NumberRange(min=1, max=720)],
    )


class LoginForm(FlaskForm):
    """Login-Form fuer den Admin-Account."""

    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=64)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=1, max=256)],
    )


class TagForm(FlaskForm):
    """Neues Tag anlegen."""

    name = StringField(
        "Tag name",
        validators=[DataRequired(), Length(min=1, max=32)],
    )
    color = StringField(
        "Color (hex, e.g. #6b7280)",
        default="#6b7280",
        validators=[DataRequired(), Length(min=7, max=7)],
    )

    def validate_name(self, field: StringField) -> None:
        """Pattern-Check fuer Tag-Namen — siehe §10."""
        if not field.data or not TAG_NAME_REGEX.match(field.data):
            raise ValidationError(
                "Invalid tag name. Allowed: a-z, 0-9, '.', '_', '-' "
                "(start with letter/digit, max 32 characters)."
            )

    def validate_color(self, field: StringField) -> None:
        if not field.data or not TAG_COLOR_REGEX.match(field.data):
            raise ValidationError("Color must be in #rrggbb format.")


class TagRenameForm(FlaskForm):
    """Rename eines Tags auf der `/settings/tags`-Manage-Seite (Block Z).

    Gleiche Regex/Length-Validation wie `TagForm.name` (Single Source of Truth
    `TAG_NAME_REGEX`).
    """

    name = StringField(
        "New name",
        validators=[DataRequired(), Length(min=1, max=32)],
    )

    def validate_name(self, field: StringField) -> None:
        if not field.data or not TAG_NAME_REGEX.match(field.data):
            raise ValidationError(
                "Invalid tag name. Allowed: a-z, 0-9, '.', '_', '-' "
                "(start with letter/digit, max 32 characters)."
            )


class TagColorForm(FlaskForm):
    """Color-Edit eines Tags auf der `/settings/tags`-Manage-Seite (Block Z).

    Gleiche Regex wie `TagForm.color` (`TAG_COLOR_REGEX`, `^#[0-9a-fA-F]{6}$`).
    """

    color = StringField(
        "Color (hex, e.g. #6b7280)",
        validators=[DataRequired(), Length(min=7, max=7)],
    )

    def validate_color(self, field: StringField) -> None:
        if not field.data or not TAG_COLOR_REGEX.match(field.data):
            raise ValidationError("Color must be in #rrggbb format.")


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
        "New mode",
        choices=[
            ("off", "off"),
            ("observation", "observation"),
            ("live", "live"),
        ],
        validators=[DataRequired()],
    )
    master_key = PasswordField(
        "Master key",
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
            NumberRange(min=1, max=200, message="Concurrency must be between 1 and 200."),
        ],
    )
    master_key = PasswordField(
        "Master key",
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
        "Master key",
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
        "Comment (optional)",
        validators=[OptionalValidator(), Length(max=NOTE_TEXT_MAX_LEN)],
    )


class ReopenForm(FlaskForm):
    """Re-Open-Action — analog zu Acknowledge. Comment optional."""

    comment = TextAreaField(
        "Comment (optional)",
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
        "Note",
        validators=[
            DataRequired(message="Note must not be empty."),
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
    - `reviewer_model`: druckbares ASCII, max 128 (Risk-Reviewer-Modell).
    - `chat_model`: druckbares ASCII, max 128 (Per-Group-Chat-Modell).
    - `daily_token_cap`: Integer >= 1.
    """

    provider_name = StringField(
        "Display name",
        validators=[OptionalValidator(), Length(max=64)],
    )
    base_url = StringField(
        "Base URL",
        validators=[DataRequired(), Length(max=256)],
    )
    api_key = PasswordField(
        "API key (leave empty to keep the existing one)",
        validators=[OptionalValidator(), Length(max=512)],
    )
    reviewer_model = StringField(
        "Reviewer model",
        validators=[DataRequired(), Length(max=128)],
    )
    chat_model = StringField(
        "Chat model",
        validators=[DataRequired(), Length(max=128)],
    )
    daily_token_cap = IntegerField(
        "Daily token cap",
        validators=[DataRequired(), NumberRange(min=1, max=10_000_000_000)],
    )

    def validate_provider_name(self, field: StringField) -> None:
        if field.data is None or not field.data.strip():
            return
        candidate = field.data.strip()
        if not TAG_NAME_REGEX.match(candidate):
            raise ValidationError(
                "Allowed: a-z, 0-9, '.', '_', '-' (start with letter/digit, max 32 characters)."
            )

    def validate_base_url(self, field: StringField) -> None:
        from app.services.llm_client import validate_base_url as _vbu

        if not field.data:
            raise ValidationError("Base URL required.")
        try:
            _vbu(field.data.strip())
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

    @staticmethod
    def _validate_model_value(field: StringField, *, label: str) -> None:
        """Gemeinsame Modell-Feld-Validierung fuer Reviewer- und Chat-Modell."""
        value = (field.data or "").strip()
        if not value:
            raise ValidationError(f"{label} required.")
        # Druckbares ASCII (0x20-0x7E), kein Whitespace am Anfang/Ende
        # nach strip() bereits eliminiert.
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
            raise ValidationError("Only printable ASCII allowed.")

    def validate_reviewer_model(self, field: StringField) -> None:
        self._validate_model_value(field, label="Reviewer model")

    def validate_chat_model(self, field: StringField) -> None:
        self._validate_model_value(field, label="Chat model")


# Such-Backend-Whitelist (ADR-0063 §Such-/Fetch-Backend). Single Source of Truth
# fuer das ``upstream_search_backend``-SelectField — gespiegelt von
# ``app.services.upstream_research.SEARCH_BACKENDS`` (dort als Tuple definiert;
# hier als Form-Choices). Der leere Wert ist erlaubt, solange das Feature
# disabled ist; das View setzt zusaetzlich eine Defense-in-Depth-Whitelist.
UPSTREAM_SEARCH_BACKENDS: tuple[str, ...] = ("searxng", "tavily", "firecrawl", "serper")


class UpstreamCheckSettingsForm(FlaskForm):
    """Config-Form fuer die agentische Upstream-Update-Suche (Block AI-2, ADR-0063).

    Eigenstaendige Form (kein Reuse von :class:`LlmSettingsForm`), weil sie ein
    eigener Settings-Tab ist; das Provider-View-``update()`` instanziiert/
    validiert sie getrennt. Felder spiegeln die ``Setting``-Spalten
    (``upstream_*`` + ``llm_research_model``).

    - ``upstream_check_enabled``: Master-Schalter (opt-in, Air-Gap-Default OFF).
    - ``upstream_search_backend``: Whitelist ``searxng``/``tavily``/``firecrawl``/
      ``serper``; leer erlaubt solange disabled (das View gated den scharfen
      Konfig-Check via :func:`is_upstream_check_configured`).
    - ``upstream_search_base_url``: gleiche Whitelist wie ``llm_base_url``
      (``validate_base_url``); optional (SearXNG braucht sie, paid-APIs haben
      Defaults — aber wir verlangen den expliziten Backend-Pick).
    - ``upstream_search_api_key``: Klartext-Eingabe, wird Fernet-verschluesselt
      persistiert; leer = bestehenden Wert behalten (Muster wie ``llm_api_key``).
    - ``upstream_search_username``: optionale SearXNG-Basic-Auth-User (Klartext).
    - ``upstream_search_password``: optional, Fernet-verschluesselt; leer =
      bestehenden Wert behalten.
    - ``llm_research_model``: optionales Modell (leer -> NULL ->
      ``DEFAULT_RESEARCH_MODEL`` greift im Worker).
    """

    upstream_check_enabled = BooleanField(
        "Enable upstream update search",
        validators=[OptionalValidator()],
    )
    upstream_search_backend = SelectField(
        "Search backend",
        choices=[
            ("", "— none —"),
            ("searxng", "SearXNG (self-hosted)"),
            ("tavily", "Tavily"),
            ("firecrawl", "Firecrawl"),
            ("serper", "Serper"),
        ],
        validators=[OptionalValidator()],
    )
    upstream_search_base_url = StringField(
        "Search base URL",
        validators=[OptionalValidator(), Length(max=512)],
    )
    upstream_search_api_key = PasswordField(
        "Search API key (leave empty to keep the existing one)",
        validators=[OptionalValidator(), Length(max=512)],
    )
    upstream_search_username = StringField(
        "Search username (SearXNG basic-auth, optional)",
        validators=[OptionalValidator(), Length(max=128)],
    )
    upstream_search_password = PasswordField(
        "Search password (leave empty to keep the existing one)",
        validators=[OptionalValidator(), Length(max=512)],
    )
    llm_research_model = StringField(
        "Research model (leave empty for the built-in default)",
        validators=[OptionalValidator(), Length(max=128)],
    )

    def validate_upstream_search_backend(self, field: SelectField) -> None:
        """Whitelist-Check (Defense-in-Depth zusaetzlich zum SelectField).

        Leer ist erlaubt (Feature disabled / unkonfiguriert). Ein nicht-leerer
        Wert muss in der :data:`UPSTREAM_SEARCH_BACKENDS`-Whitelist liegen.
        """
        value = (field.data or "").strip()
        if not value:
            return
        if value not in UPSTREAM_SEARCH_BACKENDS:
            raise ValidationError("Unknown search backend.")

    def validate_upstream_search_base_url(self, field: StringField) -> None:
        """Gleiche Whitelist wie ``llm_base_url`` — aber leer ist erlaubt."""
        from app.services.llm_client import validate_base_url as _vbu

        value = (field.data or "").strip()
        if not value:
            return
        try:
            _vbu(value)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

    def validate_llm_research_model(self, field: StringField) -> None:
        """Druckbares ASCII (analog Reviewer-/Chat-Modell); leer ist erlaubt."""
        value = (field.data or "").strip()
        if not value:
            return
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
            raise ValidationError("Only printable ASCII allowed.")


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
        "Package",
        validators=[DataRequired(), Length(min=1, max=256)],
    )
    comment = TextAreaField(
        "Comment (optional)",
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
        choices: list[tuple[str, str]] = [("none", "— none —")]
        if available_groups:
            choices.extend((str(g.id), g.name) for g in available_groups)
        self.group_id.choices = choices


class ServerScanIntervalForm(FlaskForm):
    """Expected-Scan-Interval-Editor — Stunden 1..168 (1 Woche max).

    Block X (ADR-0038): setzt `server.expected_scan_interval_h`.
    """

    scan_interval_h = IntegerField(
        "Scan interval (h)",
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
        "Scan interval (h)",
        validators=[DataRequired(), NumberRange(min=1, max=168)],
    )

    def __init__(
        self,
        *args: object,
        available_groups: Sequence[ServerGroup] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)
        choices: list[tuple[str, str]] = [("none", "— none —")]
        if available_groups:
            choices.extend((str(g.id), g.name) for g in available_groups)
        self.group_id.choices = choices


class ServerGroupCreateForm(FlaskForm):
    """Inline-Anlage einer neuen ServerGroup im Server-Settings-Sub-View (Block Z).

    Single-Field-Form (ADR-0006 — keine Pflicht-Felder ueber `name` hinaus).
    `position` setzt der View-Handler auf `MAX(position) + 1`, ein Operator
    waehlt sie nicht. Regex teilt sich die Quelle mit `GroupRenameForm`
    (`SERVER_GROUP_NAME_REGEX`).
    """

    name = StringField(
        "Group name",
        validators=[
            DataRequired(),
            Length(min=1, max=64),
            Regexp(
                SERVER_GROUP_NAME_REGEX,
                message="Allowed: A-Z, a-z, 0-9, spaces, '_', '.', '-' (max 64 characters).",
            ),
        ],
    )

    def validate_name(self, field: StringField) -> None:
        """Whitespace-only-Namen ablehnen.

        Das Leerzeichen ist Teil der `SERVER_GROUP_NAME_REGEX`-Charset, also
        wuerde `"   "` Regex + `Length(min=1)` bestehen. Der View strippt den
        Namen aber vor dem Insert — das Ergebnis `""` verletzt dann die DB-
        CHECK-Constraints (`ck_server_groups_name_length`/`_charset`) und der
        Race-Catch-`scalar_one()` faende keine Row (NoResultFound → 500).
        Form-seitig abfangen, damit Form-Akzeptanz die DB-CHECKs deckt.
        """
        if not field.data or not field.data.strip():
            raise ValidationError("Group name must not be only spaces.")


class GroupRenameForm(FlaskForm):
    """Rename einer ServerGroup auf der `/settings/groups`-Manage-Seite (Block Z).

    Gleiche Regex/Length-Validation wie `ServerGroupCreateForm` (geteilte
    `SERVER_GROUP_NAME_REGEX`-Konstante — Block-Z-Risiken-Tabelle verlangt
    Drift-Freiheit). Whitespace-only wird Form-seitig abgelehnt, damit die
    Form-Akzeptanz die DB-CHECK-Constraints deckt.
    """

    name = StringField(
        "New name",
        validators=[
            DataRequired(),
            Length(min=1, max=64),
            Regexp(
                SERVER_GROUP_NAME_REGEX,
                message="Allowed: A-Z, a-z, 0-9, spaces, '_', '.', '-' (max 64 characters).",
            ),
        ],
    )

    def validate_name(self, field: StringField) -> None:
        if not field.data or not field.data.strip():
            raise ValidationError("Group name must not be only spaces.")


class GroupMoveForm(FlaskForm):
    """Position-Reorder einer ServerGroup (Up/Down-Swap) auf `/settings/groups`.

    `direction` ist ein SelectField mit Whitelist `up`/`down` — Drag-Drop ist
    ADR-0040-Re-Open-Trigger, hier genuegen Pfeil-Buttons.
    """

    direction = SelectField(
        "Direction",
        choices=[("up", "up"), ("down", "down")],
        validators=[DataRequired()],
    )


class ServerTagCreateForm(FlaskForm):
    """Inline-Anlage eines neuen Tags im Server-Settings-Sub-View (Block Z).

    Single-Field-Form. Color wird NICHT gefuehrt — der View-Handler setzt den
    Default `#6b7280` (analog `TagForm.color.default`); kein Color-Picker im
    Inline-Flow (ADR-0040 §Verworfen). Regex identisch zu `TagForm.name`.
    """

    name = StringField(
        "Tag name",
        validators=[
            DataRequired(),
            Length(min=1, max=32),
            Regexp(
                TAG_NAME_REGEX,
                message=(
                    "Invalid tag name. Allowed: a-z, 0-9, '.', '_', '-' "
                    "(start with letter/digit, max 32 characters)."
                ),
            ),
        ],
    )


__all__ = [
    "NOTE_TEXT_MAX_LEN",
    "SERVER_GROUP_NAME_REGEX",
    "TAG_COLOR_REGEX",
    "TAG_NAME_REGEX",
    "UPSTREAM_SEARCH_BACKENDS",
    "AcknowledgeForm",
    "BulkActionForm",
    "CSRFOnlyForm",
    "GroupAcknowledgeForm",
    "GroupMoveForm",
    "GroupRenameForm",
    "LlmReviewerConcurrencyForm",
    "LlmSettingsForm",
    "LoginForm",
    "MasterKeyRotateForm",
    "NoteForm",
    "ReopenForm",
    "ServerGroupCreateForm",
    "ServerGroupForm",
    "ServerScanIntervalForm",
    "ServerSettingsForm",
    "ServerTagCreateForm",
    "SetupStep1Form",
    "SetupStep2Form",
    "SetupStep3Form",
    "TagColorForm",
    "TagForm",
    "TagRenameForm",
    "UpstreamCheckSettingsForm",
]
