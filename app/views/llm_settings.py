"""LLM-Settings-View `/settings/llm` und `/settings/llm/test-connection`.

ARCHITECTURE.md §7 (Settings-Provider-Block mit Preset-Dropdown) und §12
(Provider-Wechsel-Hook: alle aktiven Conversations archivieren).

Felder:
- `provider_name` — freier Anzeigename, Pattern wie Tag-Namen.
- `base_url` — Whitelist via `llm_client.validate_base_url`.
- `api_key` — optional; leer = behalte alten Wert.
- `model` — druckbares ASCII, max 128 Zeichen.
- `daily_token_cap` — Integer >= 1.

Beim Speichern:
1. Wenn `base_url` ODER `model` sich aendert -> archiviere alle aktiven
   Conversations, Audit `llm.provider_changed`.
2. API-Key Fernet-encrypt mit `SECSCAN_ENCRYPTION_KEY`.
3. Audit `settings.updated` mit den geaenderten Feldnamen
   (Klartext-Werte werden NIE in `metadata` gelegt).

`POST /settings/llm/test-connection` ruft eine 1-Token-Probe-Anfrage
gegen den **aktuellen** Settings-Stand (nicht die Form-Werte, damit
ein Test ohne Speichern den persistierten State testet — fuer das
Form-orientierte Testen schickt der Frontend den Key noch nicht).
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import structlog
from flask import Blueprint, flash, jsonify, redirect, url_for
from flask_login import login_required
from sqlalchemy import select

from app import limiter
from app.audit import log_event
from app.config import Settings
from app.db import get_session
from app.forms import LlmSettingsForm
from app.models import LlmConversation, LlmConversationStatus
from app.services.llm_client import (
    ConnectionTestResult,
    LlmClient,
    encrypt_api_key,
    validate_base_url,
)
from app.settings_service import get_settings_row
from app.views._settings_shell import render_settings

log = structlog.get_logger(__name__)
llm_settings_bp = Blueprint("llm_settings", __name__, url_prefix="/settings/llm")


# Preset-Liste fuer den Dropdown im Template — siehe ARCHITECTURE §12.
LLM_PRESETS: list[dict[str, str]] = [
    {
        # v0.9.3 (ADR-0023 §"Update v0.9.3"): Default-Modell-Wechsel auf
        # ``openai/gpt-oss-120b`` — semantisch staerkstes Modell in der
        # Block-P-Test-Suite, Apache 2.0 self-hostable, Provider-flexibel.
        "name": "DeepInfra",
        "base_url": "https://api.deepinfra.com/v1/openai",
        "model": "openai/gpt-oss-120b",
    },
    {
        "name": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
    },
    {
        "name": "Together AI",
        "base_url": "https://api.together.xyz/v1",
        "model": "deepseek-ai/DeepSeek-V3",
    },
    {
        "name": "Groq",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.1-70b-versatile",
    },
    {
        "name": "Mistral",
        "base_url": "https://api.mistral.ai/v1",
        "model": "mistral-large-latest",
    },
    {
        "name": "Ollama (lokal)",
        "base_url": "http://localhost:11434/v1",
        "model": "llama3.1",
    },
]


def _settings_obj() -> Settings:
    from flask import current_app

    return cast(Settings, current_app.config["SECSCAN_SETTINGS"])


def _has_existing_key(setting_row: Any) -> bool:
    return (
        setting_row.llm_api_key_encrypted is not None and len(setting_row.llm_api_key_encrypted) > 0
    )


def _archive_active_conversations(session: Any) -> list[int]:
    """Archiviere alle aktiven Conversations und liefere ihre IDs zurueck."""
    rows = list(
        session.execute(
            select(LlmConversation).where(LlmConversation.status == LlmConversationStatus.ACTIVE)
        )
        .scalars()
        .all()
    )
    archived_ids: list[int] = []
    for conv in rows:
        conv.status = LlmConversationStatus.ARCHIVED
        archived_ids.append(conv.id)
    return archived_ids


@llm_settings_bp.get("/")
@login_required
def show() -> Any:
    sess = get_session()
    setting_row = get_settings_row(sess)
    form = LlmSettingsForm(
        provider_name=setting_row.llm_provider_name or "",
        base_url=setting_row.llm_base_url or "",
        model=setting_row.llm_model or "",
        daily_token_cap=setting_row.llm_daily_token_cap,
    )
    return render_settings(
        active="llm",
        content_template="settings/llm_provider.html",
        form=form,
        has_existing_key=_has_existing_key(setting_row),
        presets=LLM_PRESETS,
        active_conversation_count=sess.execute(
            select(LlmConversation).where(LlmConversation.status == LlmConversationStatus.ACTIVE)
        )
        .scalars()
        .all()
        .__len__(),
    )


@llm_settings_bp.post("/")
@login_required
def update() -> Any:
    sess = get_session()
    setting_row = get_settings_row(sess)
    form = LlmSettingsForm()

    if not form.validate_on_submit():
        for field_name, errors in form.errors.items():
            for err in errors:
                flash(f"{field_name}: {err}", "error")
        return (
            render_settings(
                active="llm",
                content_template="settings/llm_provider.html",
                form=form,
                has_existing_key=_has_existing_key(setting_row),
                presets=LLM_PRESETS,
                active_conversation_count=0,
            ),
            400,
        )

    new_provider_name = (form.provider_name.data or "").strip() or None
    new_base_url = (form.base_url.data or "").strip() or None
    new_model = (form.model.data or "").strip() or None
    new_cap = int(form.daily_token_cap.data or setting_row.llm_daily_token_cap)
    new_api_key_plain = (form.api_key.data or "").strip()

    # Provider-Wechsel-Detect: base_url ODER model aendert sich.
    provider_changed = (setting_row.llm_base_url or None) != new_base_url or (
        setting_row.llm_model or None
    ) != new_model

    archived_ids: list[int] = []
    if provider_changed:
        archived_ids = _archive_active_conversations(sess)
        log_event(
            "llm.provider_changed",
            target_type="settings",
            target_id=1,
            metadata={
                "old_base_url": setting_row.llm_base_url,
                "new_base_url": new_base_url,
                "old_model": setting_row.llm_model,
                "new_model": new_model,
                "archived_conversations": archived_ids,
            },
            session=sess,
        )

    setting_row.llm_provider_name = new_provider_name
    setting_row.llm_base_url = new_base_url
    setting_row.llm_model = new_model
    setting_row.llm_daily_token_cap = new_cap

    changed_fields = ["provider_name", "base_url", "model", "daily_token_cap"]
    if new_api_key_plain:
        enc = encrypt_api_key(new_api_key_plain, _settings_obj().encryption_key.get_secret_value())
        setting_row.llm_api_key_encrypted = enc
        changed_fields.append("api_key")

    log_event(
        "settings.updated",
        target_type="settings",
        target_id=1,
        metadata={
            "fields": changed_fields,
            "provider_changed": provider_changed,
            "archived_conversations": archived_ids,
        },
        session=sess,
    )
    sess.commit()
    flash("LLM-Einstellungen gespeichert.", "success")
    if provider_changed and archived_ids:
        flash(
            f"{len(archived_ids)} aktive Bewertungen archiviert wegen Provider-/Modell-Wechsel.",
            "info",
        )
    return redirect(url_for("llm_settings.show"))


@llm_settings_bp.post("/test-connection")
@login_required
@limiter.limit("60/hour")
def test_connection() -> Any:
    """Probe-Anfrage gegen die aktuell gespeicherten Settings."""
    sess = get_session()
    setting_row = get_settings_row(sess)
    if not setting_row.llm_base_url or not setting_row.llm_model:
        return jsonify(
            {
                "success": False,
                "error": "llm_not_configured",
                "message": "Bitte erst Provider-Settings speichern.",
            }
        ), 400

    try:
        validate_base_url(setting_row.llm_base_url)
    except ValueError as exc:
        return jsonify({"success": False, "error": "invalid_base_url", "message": str(exc)}), 400

    from app.services.llm_client import build_client_from_settings

    enc_key = _settings_obj().encryption_key.get_secret_value()
    try:
        client = build_client_from_settings(setting_row, encryption_key=enc_key)
    except (ValueError, RuntimeError) as exc:
        return jsonify({"success": False, "error": "client_init_failed", "message": str(exc)}), 400

    result = asyncio.run(_probe(client))
    payload = {
        "success": result.success,
        "latency_ms": result.latency_ms,
        "model": result.model,
        "error": result.error,
    }
    return jsonify(payload)


async def _probe(client: LlmClient) -> ConnectionTestResult:
    try:
        return await client.test_connection()
    finally:
        await client.aclose()


__all__ = ["llm_settings_bp"]
