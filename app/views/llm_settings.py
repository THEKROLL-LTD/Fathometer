# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""LLM-Settings-View `/settings/llm` und `/settings/llm/test-connection`.

ARCHITECTURE.md §7 (Settings-Provider-Block mit Preset-Dropdown) und §12
(Provider-Config — geteilt vom LLM-Risk-Reviewer).

Felder:
- `provider_name` — freier Anzeigename, Pattern wie Tag-Namen.
- `base_url` — Whitelist via `llm_client.validate_base_url`.
- `api_key` — optional; leer = behalte alten Wert.
- `reviewer_model` — druckbares ASCII, max 128 Zeichen (Risk-Reviewer).
- `chat_model` — druckbares ASCII, max 128 Zeichen (Per-Group-Chat).
- `daily_token_cap` — Integer >= 1.

Ein Provider (geteilter `base_url` / `api_key`), zwei Modelle (ADR-0057).

Beim Speichern:
1. Wenn `base_url`, `llm_reviewer_model` ODER `llm_chat_model` sich
   aendert -> Audit `llm.provider_changed`.
2. API-Key Fernet-encrypt mit `FM_ENCRYPTION_KEY`.
3. Audit `settings.updated` mit den geaenderten Feldnamen
   (Klartext-Werte werden NIE in `metadata` gelegt).

`POST /settings/llm/test-connection` ruft **zwei** 1-Token-Probe-Anfragen
(Reviewer-Modell + Chat-Modell, geteilter `base_url`/`api_key`) gegen den
**aktuellen** Settings-Stand (nicht die Form-Werte, damit ein Test ohne
Speichern den persistierten State testet — fuer das Form-orientierte
Testen schickt der Frontend den Key noch nicht). Antwort ist ein
2-Teil-Objekt `{reviewer, chat}` (ADR-0057 §4).
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import structlog
from flask import Blueprint, flash, jsonify, redirect, url_for
from flask_login import login_required

from app import limiter
from app.audit import log_event
from app.config import Settings
from app.db import get_session
from app.forms import (
    UPSTREAM_SEARCH_BACKENDS,
    LlmSettingsForm,
    UpstreamCheckSettingsForm,
)
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


# Default-Modelle (ADR-0057 §Entscheidung 2). Geteilter Provider, zwei Modelle.
DEFAULT_REVIEWER_MODEL = "openai/gpt-oss-120b"
DEFAULT_CHAT_MODEL = "deepseek-ai/DeepSeek-V4-Flash"
# Default-Modell der agentischen Upstream-Suche (Block AI, ADR-0063 §Modell).
# Geteilter Provider, eigenes Modell. Opt-in -> kein DB-``server_default``, der
# Wert wird nur als App-Default fuers AI-2-Form genutzt. Tipp: grosses
# Reasoning-Modell fuer hoehere Treffsicherheit.
DEFAULT_RESEARCH_MODEL = "deepseek-ai/DeepSeek-V4-Flash"


# Preset-Liste fuer den Dropdown im Template — siehe ARCHITECTURE §12.
# Jeder Eintrag traegt beide Modelle (Reviewer + Chat); der Preset-Pick im
# Provider-Tab fuellt base_url + beide Modell-Felder vor (ADR-0057 §4).
LLM_PRESETS: list[dict[str, str]] = [
    {
        # v0.9.3 (ADR-0023 §"Update v0.9.3"): Reviewer-Default
        # ``openai/gpt-oss-120b`` — semantisch staerkstes Modell in der
        # Block-P-Test-Suite, Apache 2.0 self-hostable, Provider-flexibel.
        # Chat-Default ``deepseek-ai/DeepSeek-V4-Flash`` (ADR-0057).
        # Einziges Preset: nur DeepInfra ist verprobt; weitere Provider
        # bleiben per manueller Base-URL/Model-Eingabe moeglich.
        "name": "DeepInfra",
        "base_url": "https://api.deepinfra.com/v1/openai",
        "reviewer_model": DEFAULT_REVIEWER_MODEL,
        "chat_model": DEFAULT_CHAT_MODEL,
    },
]


def _settings_obj() -> Settings:
    from flask import current_app

    return cast(Settings, current_app.config["FM_SETTINGS"])


def _has_existing_key(setting_row: Any) -> bool:
    return (
        setting_row.llm_api_key_encrypted is not None and len(setting_row.llm_api_key_encrypted) > 0
    )


def _has_existing_search_key(setting_row: Any) -> bool:
    enc = getattr(setting_row, "upstream_search_api_key_encrypted", None)
    return enc is not None and len(enc) > 0


def _has_existing_search_password(setting_row: Any) -> bool:
    enc = getattr(setting_row, "upstream_search_password_encrypted", None)
    return enc is not None and len(enc) > 0


def _upstream_form_from_row(setting_row: Any) -> UpstreamCheckSettingsForm:
    """Baut das Upstream-Config-Form aus der ``Setting``-Zeile (GET-Pfad).

    Die verschluesselten Secrets (API-Key, SearXNG-Passwort) werden bewusst
    NICHT vorgefuellt — das Template zeigt nur den „gesetzt/nicht gesetzt"-
    Indikator (analog ``llm_api_key``). Leer-lassen = unveraendert.
    """
    return UpstreamCheckSettingsForm(
        upstream_check_enabled=bool(getattr(setting_row, "upstream_check_enabled", False)),
        upstream_search_backend=getattr(setting_row, "upstream_search_backend", None) or "",
        upstream_search_base_url=getattr(setting_row, "upstream_search_base_url", None) or "",
        upstream_search_username=getattr(setting_row, "upstream_search_username", None) or "",
        llm_research_model=getattr(setting_row, "llm_research_model", None) or "",
    )


@llm_settings_bp.get("/")
@login_required
def show() -> Any:
    sess = get_session()
    setting_row = get_settings_row(sess)
    form = LlmSettingsForm(
        provider_name=setting_row.llm_provider_name or "",
        base_url=setting_row.llm_base_url or "",
        reviewer_model=setting_row.llm_reviewer_model or "",
        chat_model=setting_row.llm_chat_model or DEFAULT_CHAT_MODEL,
        daily_token_cap=setting_row.llm_daily_token_cap,
    )
    return render_settings(
        active="llm",
        content_template="settings/llm_provider.html",
        form=form,
        has_existing_key=_has_existing_key(setting_row),
        presets=LLM_PRESETS,
        upstream_form=_upstream_form_from_row(setting_row),
        upstream_has_search_key=_has_existing_search_key(setting_row),
        upstream_has_search_password=_has_existing_search_password(setting_row),
        upstream_default_research_model=DEFAULT_RESEARCH_MODEL,
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
            ),
            400,
        )

    new_provider_name = (form.provider_name.data or "").strip() or None
    new_base_url = (form.base_url.data or "").strip() or None
    # Reviewer-Modell ist nullable (System ohne Provider hat hier None).
    new_reviewer = (form.reviewer_model.data or "").strip() or None
    # Chat-Modell ist NOT NULL (server_default) — leeren String NICHT zu None
    # machen; DataRequired verhindert leer ohnehin.
    new_chat = (form.chat_model.data or "").strip()
    new_cap = int(form.daily_token_cap.data or setting_row.llm_daily_token_cap)
    new_api_key_plain = (form.api_key.data or "").strip()

    # Provider-Wechsel-Detect: base_url, Reviewer- ODER Chat-Modell aendert sich.
    provider_changed = (
        (setting_row.llm_base_url or None) != new_base_url
        or (setting_row.llm_reviewer_model or None) != new_reviewer
        or (setting_row.llm_chat_model or None) != new_chat
    )

    if provider_changed:
        log_event(
            "llm.provider_changed",
            target_type="settings",
            target_id=1,
            metadata={
                "old_base_url": setting_row.llm_base_url,
                "new_base_url": new_base_url,
                "old_reviewer_model": setting_row.llm_reviewer_model,
                "new_reviewer_model": new_reviewer,
                "old_chat_model": setting_row.llm_chat_model,
                "new_chat_model": new_chat,
            },
            session=sess,
        )

    setting_row.llm_provider_name = new_provider_name
    setting_row.llm_base_url = new_base_url
    setting_row.llm_reviewer_model = new_reviewer
    setting_row.llm_chat_model = new_chat
    setting_row.llm_daily_token_cap = new_cap

    changed_fields = [
        "provider_name",
        "base_url",
        "reviewer_model",
        "chat_model",
        "daily_token_cap",
    ]
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
        },
        session=sess,
    )
    sess.commit()
    flash("LLM settings saved.", "success")
    return redirect(url_for("llm_settings.show"))


@llm_settings_bp.post("/upstream")
@login_required
def update_upstream() -> Any:
    """Persistiert die Upstream-Update-Suche-Config (Block AI-2, ADR-0063).

    Eigener POST-Endpoint im selben LLM-Settings-Tab — die Provider-Config
    (:func:`update`) und die Upstream-Config (hier) sind zwei getrennte Forms,
    jede mit eigenem ``<form action>`` (kein fragiler Submit-Discriminator).
    Die Provider-``update()`` bleibt unangetastet und liest ausschliesslich
    ihre eigenen Felder.

    Secrets (``upstream_search_api_key``/``upstream_search_password``) werden
    via :func:`encrypt_api_key` (gleiche Fernet-Pipeline wie ``llm_api_key``)
    verschluesselt; leere Eingabe behaelt den bestehenden Wert. Der Backend-
    Wert wird zusaetzlich gegen die Whitelist geprueft (Defense-in-Depth zum
    SelectField). Audit-Event ``upstream_check.configured`` mit der Liste der
    geaenderten Felder (NIE Klartext-Secrets in ``metadata``).
    """
    sess = get_session()
    setting_row = get_settings_row(sess)
    form = UpstreamCheckSettingsForm()

    if not form.validate_on_submit():
        for field_name, errors in form.errors.items():
            for err in errors:
                flash(f"{field_name}: {err}", "error")
        provider_form = LlmSettingsForm(
            provider_name=setting_row.llm_provider_name or "",
            base_url=setting_row.llm_base_url or "",
            reviewer_model=setting_row.llm_reviewer_model or "",
            chat_model=setting_row.llm_chat_model or DEFAULT_CHAT_MODEL,
            daily_token_cap=setting_row.llm_daily_token_cap,
        )
        return (
            render_settings(
                active="llm",
                content_template="settings/llm_provider.html",
                form=provider_form,
                has_existing_key=_has_existing_key(setting_row),
                presets=LLM_PRESETS,
                upstream_form=form,
                upstream_has_search_key=_has_existing_search_key(setting_row),
                upstream_has_search_password=_has_existing_search_password(setting_row),
                upstream_default_research_model=DEFAULT_RESEARCH_MODEL,
            ),
            400,
        )

    new_enabled = bool(form.upstream_check_enabled.data)
    new_backend = (form.upstream_search_backend.data or "").strip() or None
    # Defense-in-Depth: Whitelist zusaetzlich zum SelectField/Form-Validator.
    if new_backend is not None and new_backend not in UPSTREAM_SEARCH_BACKENDS:
        flash("upstream_search_backend: Unknown search backend.", "error")
        return redirect(url_for("llm_settings.show"))
    new_base_url = (form.upstream_search_base_url.data or "").strip() or None
    new_username = (form.upstream_search_username.data or "").strip() or None
    new_research_model = (form.llm_research_model.data or "").strip() or None
    new_search_key_plain = (form.upstream_search_api_key.data or "").strip()
    new_search_pw_plain = (form.upstream_search_password.data or "").strip()

    setting_row.upstream_check_enabled = new_enabled
    setting_row.upstream_search_backend = new_backend
    setting_row.upstream_search_base_url = new_base_url
    setting_row.upstream_search_username = new_username
    setting_row.llm_research_model = new_research_model

    changed_fields = [
        "upstream_check_enabled",
        "upstream_search_backend",
        "upstream_search_base_url",
        "upstream_search_username",
        "llm_research_model",
    ]
    enc_key = _settings_obj().encryption_key.get_secret_value()
    if new_search_key_plain:
        setting_row.upstream_search_api_key_encrypted = encrypt_api_key(
            new_search_key_plain, enc_key
        )
        changed_fields.append("upstream_search_api_key")
    if new_search_pw_plain:
        setting_row.upstream_search_password_encrypted = encrypt_api_key(
            new_search_pw_plain, enc_key
        )
        changed_fields.append("upstream_search_password")

    log_event(
        "upstream_check.configured",
        target_type="settings",
        target_id=1,
        metadata={
            "fields": changed_fields,
            "enabled": new_enabled,
            "backend": new_backend,
        },
        session=sess,
    )
    sess.commit()
    flash("Upstream update search settings saved.", "success")
    return redirect(url_for("llm_settings.show"))


@llm_settings_bp.post("/test-connection")
@login_required
@limiter.limit("60/hour")
def test_connection() -> Any:
    """Doppel-Probe gegen die aktuell gespeicherten Settings (ADR-0057 §4).

    Zwei 1-Token-Proben gegen den geteilten `base_url`/`api_key`:
    Reviewer-Modell + Chat-Modell. `400 llm_not_configured` nur wenn
    `base_url` fehlt (gemeinsamer Gate). Ist das Reviewer-Modell `None`,
    wird das Reviewer-Teilergebnis als ``not_configured`` markiert (kein
    Call), statt den ganzen Request abzulehnen.
    """
    sess = get_session()
    setting_row = get_settings_row(sess)
    if not setting_row.llm_base_url:
        return jsonify(
            {
                "success": False,
                "error": "llm_not_configured",
                "message": "Save provider settings first.",
            }
        ), 400

    try:
        validate_base_url(setting_row.llm_base_url)
    except ValueError as exc:
        return jsonify({"success": False, "error": "invalid_base_url", "message": str(exc)}), 400

    enc_key = _settings_obj().encryption_key.get_secret_value()

    reviewer_model = (setting_row.llm_reviewer_model or "").strip() or None
    chat_model = (setting_row.llm_chat_model or "").strip() or None

    if reviewer_model is None:
        # Reviewer-Modell nicht konfiguriert -> kein Call, Teilergebnis.
        reviewer_part = _not_configured_part()
    else:
        reviewer_part = _probe_model(setting_row, encryption_key=enc_key, model_override=None)

    if chat_model is None:
        # Sollte durch server_default nie passieren; defensiv behandelt.
        chat_part = _not_configured_part()
    else:
        chat_part = _probe_model(setting_row, encryption_key=enc_key, model_override=chat_model)

    return jsonify({"reviewer": reviewer_part, "chat": chat_part})


def _not_configured_part() -> dict[str, Any]:
    """Teilergebnis fuer ein nicht konfiguriertes Modell (kein Provider-Call)."""
    return {"success": False, "latency_ms": None, "model": None, "error": "not_configured"}


def _probe_model(
    setting_row: Any,
    *,
    encryption_key: str,
    model_override: str | None,
) -> dict[str, Any]:
    """Fuehrt eine einzelne 1-Token-Probe aus und mappt das Ergebnis auf die
    Teil-Shape `{success, latency_ms, model, error}`.

    Fehler werden auf einen kurzen, maschinen-lesbaren Error-Code reduziert —
    niemals der rohe Provider-Exception-Text oder der API-Key (ADR-0057 §4).
    Bei Fehler ist `model` der **versuchte** Modellname.
    """
    from app.services.llm_client import build_client_from_settings

    # Effektiv genutztes Modell (fuer den Fehler-Fall-`model`-Wert).
    attempted_model = model_override or setting_row.llm_reviewer_model
    try:
        client = build_client_from_settings(
            setting_row,
            encryption_key=encryption_key,
            model_override=model_override,
        )
    except (ValueError, RuntimeError):
        return {
            "success": False,
            "latency_ms": None,
            "model": attempted_model,
            "error": "client_init_failed",
        }

    result = asyncio.run(_probe(client))
    if result.success:
        return {
            "success": True,
            "latency_ms": result.latency_ms,
            "model": result.model or attempted_model,
            "error": None,
        }
    return {
        "success": False,
        "latency_ms": None,
        "model": attempted_model,
        "error": _map_error_code(result.error),
    }


def _map_error_code(raw_error: str | None) -> str:
    """Mappt eine rohe `ConnectionTestResult.error`-Message auf einen kurzen,
    maschinen-lesbaren Code — ohne Provider-Detail/Key zu leaken.

    `ConnectionTestResult.error` hat das Format ``"<ExcClass>: <msg[:200]>"``.
    Wir matchen auf charakteristische Substrings und fallen sonst auf
    ``"provider_error"`` zurueck.
    """
    if not raw_error:
        return "provider_error"
    lowered = raw_error.lower()
    if "not found" in lowered or "404" in lowered or "does not exist" in lowered:
        return "model_not_found"
    if "timeout" in lowered or "timed out" in lowered:
        return "timeout"
    if "authentication" in lowered or "401" in lowered or "api key" in lowered:
        return "auth_error"
    return "provider_error"


async def _probe(client: LlmClient) -> ConnectionTestResult:
    try:
        return await client.test_connection()
    finally:
        await client.aclose()


__all__ = ["llm_settings_bp"]
