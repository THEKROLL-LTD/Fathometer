"""Pure-Unit-Tests fuer `LlmSettingsForm` — getrennte Reviewer-/Chat-Modelle.

Block AF / ADR-0057: zwei explizit benannte Modell-Felder auf dem Provider-Form.
Beide sind `DataRequired` + `Length(max=128)` + druckbares-ASCII. Validiert wird
hier ausschliesslich die Form-Schicht (kein DB-Zugriff, kein View).

Form-Instanziierung im App-Request-Context mit deaktiviertem CSRF, analog
`tests/forms/test_server_tag_create_form.py`.
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


def _formdata(**over: str) -> ImmutableMultiDict[str, str]:
    base = {
        "provider_name": "deepinfra",
        "base_url": "https://api.deepinfra.com/v1/openai",
        "api_key": "",
        "reviewer_model": "openai/gpt-oss-120b",
        "chat_model": "deepseek-ai/DeepSeek-V4-Flash",
        "daily_token_cap": "1000000",
    }
    base.update(over)
    return ImmutableMultiDict(list(base.items()))


# ---------------------------------------------------------------------------
# Happy-Path
# ---------------------------------------------------------------------------


def test_valid_with_both_models(no_csrf_app: Flask) -> None:
    """Gueltige Werte fuer beide Modelle -> validate() == True."""
    from app.forms import LlmSettingsForm

    with no_csrf_app.test_request_context("/"):
        form = LlmSettingsForm(formdata=_formdata())
        ok = form.validate()

    assert ok is True, f"Form sollte valide sein. Fehler: {form.errors}"


def test_form_has_both_model_fields(no_csrf_app: Flask) -> None:
    """Die Form fuehrt beide Modell-Felder (reviewer_model + chat_model)."""
    from app.forms import LlmSettingsForm

    with no_csrf_app.test_request_context("/"):
        form = LlmSettingsForm()

    field_names = {f.name for f in form if f.name != "csrf_token"}
    assert "reviewer_model" in field_names, field_names
    assert "chat_model" in field_names, field_names
    # Das alte Einzel-Feld `model` darf nicht mehr existieren.
    assert "model" not in field_names, field_names


# ---------------------------------------------------------------------------
# Required (leere Modelle)
# ---------------------------------------------------------------------------


def test_reviewer_model_required(no_csrf_app: Flask) -> None:
    """Leeres reviewer_model -> invalid mit Fehler am reviewer_model-Key."""
    from app.forms import LlmSettingsForm

    with no_csrf_app.test_request_context("/"):
        form = LlmSettingsForm(formdata=_formdata(reviewer_model=""))
        ok = form.validate()

    assert ok is False, "Leeres reviewer_model muss invalid sein."
    assert "reviewer_model" in form.errors, form.errors


def test_chat_model_required(no_csrf_app: Flask) -> None:
    """Leeres chat_model -> invalid mit Fehler am chat_model-Key."""
    from app.forms import LlmSettingsForm

    with no_csrf_app.test_request_context("/"):
        form = LlmSettingsForm(formdata=_formdata(chat_model=""))
        ok = form.validate()

    assert ok is False, "Leeres chat_model muss invalid sein."
    assert "chat_model" in form.errors, form.errors


def test_both_models_required_independently(no_csrf_app: Flask) -> None:
    """Whitespace-only Modelle -> beide Felder fehlerhaft (DataRequired strippt).

    Belegt, dass Reviewer- UND Chat-Modell unabhaengig voneinander Pflicht sind
    (kein gemeinsamer Validator der einen leeren Wert durchlaesst).
    """
    from app.forms import LlmSettingsForm

    with no_csrf_app.test_request_context("/"):
        form = LlmSettingsForm(formdata=_formdata(reviewer_model="   ", chat_model="   "))
        ok = form.validate()

    assert ok is False, "Whitespace-only Modelle muessen invalid sein."
    assert "reviewer_model" in form.errors, form.errors
    assert "chat_model" in form.errors, form.errors


# ---------------------------------------------------------------------------
# Length-Cap (> 128)
# ---------------------------------------------------------------------------


def test_reviewer_model_length_cap(no_csrf_app: Flask) -> None:
    """reviewer_model > 128 Zeichen -> invalid."""
    from app.forms import LlmSettingsForm

    with no_csrf_app.test_request_context("/"):
        form = LlmSettingsForm(formdata=_formdata(reviewer_model="a" * 129))
        ok = form.validate()

    assert ok is False, "reviewer_model > 128 muss invalid sein."
    assert "reviewer_model" in form.errors, form.errors


def test_chat_model_length_cap(no_csrf_app: Flask) -> None:
    """chat_model > 128 Zeichen -> invalid."""
    from app.forms import LlmSettingsForm

    with no_csrf_app.test_request_context("/"):
        form = LlmSettingsForm(formdata=_formdata(chat_model="b" * 129))
        ok = form.validate()

    assert ok is False, "chat_model > 128 muss invalid sein."
    assert "chat_model" in form.errors, form.errors


def test_model_exactly_128_chars_accepted(no_csrf_app: Flask) -> None:
    """128 Zeichen ist die Grenze und muss akzeptiert werden."""
    from app.forms import LlmSettingsForm

    with no_csrf_app.test_request_context("/"):
        form = LlmSettingsForm(formdata=_formdata(reviewer_model="a" * 128, chat_model="b" * 128))
        ok = form.validate()

    assert ok is True, f"128-Zeichen-Modelle muessen valide sein. Fehler: {form.errors}"


# ---------------------------------------------------------------------------
# Druckbares-ASCII (NUL-/Control-Bytes ablehnen)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["reviewer_model", "chat_model"])
def test_model_rejects_control_bytes(no_csrf_app: Flask, field: str) -> None:
    """Control-/NUL-Bytes im Modell-String -> invalid (nur printable ASCII)."""
    from app.forms import LlmSettingsForm

    with no_csrf_app.test_request_context("/"):
        form = LlmSettingsForm(formdata=_formdata(**{field: "model\x00name"}))
        ok = form.validate()

    assert ok is False, f"{field} mit NUL-Byte muss invalid sein."
    assert field in form.errors, form.errors
