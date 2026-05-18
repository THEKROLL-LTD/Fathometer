"""Settings-Browser-Views unter `/settings`.

Enthaelt:

- ``GET /settings`` — Alias-Redirect auf ``/settings/servers/`` (Default-
  Sub-Tab laut ADR-0016 + User-Klaerung).
- ``GET /settings/tags`` / ``POST /settings/tags`` / ``POST /settings/tags/<id>/delete``
  — Tag-Verwaltung (Block B).
- ``GET /settings/master-key`` / ``POST /settings/master-key/rotate``
  — Master-Key-Rotations-UI (ADR-0016, schliesst Spec-Luecke aus
  ``ARCHITECTURE.md §8``).
- ``GET /settings/about`` — Versions-/Build-Info (read-only).

Render-Strategie: alle Sub-Views nutzen `render_settings(...)` aus
`app.views._settings_shell` und werden je nach `HX-Request`/`HX-Target`
in drei Modi ausgespielt — siehe Helper-Docstring fuer Details.
"""

from __future__ import annotations

import importlib.metadata as ilm
import os
import sys
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import structlog
from flask import Blueprint, flash, make_response, redirect, url_for
from flask_login import login_required
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from werkzeug.wrappers import Response as WerkzeugResponse

from app.audit import log_event
from app.auth import generate_master_key, hash_master_key, verify_master_key
from app.config import load_settings
from app.db import get_session
from app.forms import (
    CSRFOnlyForm,
    LlmReviewerModeForm,
    LlmReviewerRequeueForm,
    MasterKeyRotateForm,
    TagForm,
)
from app.models import (
    ApplicationGroup,
    AuditEvent,
    LLMJob,
    LLMRiskCache,
    Server,
    Tag,
)
from app.services.stale_detection import is_db_stale
from app.settings_service import get_settings_row
from app.views._settings_shell import render_settings

log = structlog.get_logger(__name__)
settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


# ---------------------------------------------------------------------------
# Alias-Redirect (ADR-0016)
# ---------------------------------------------------------------------------


@settings_bp.get("/")
@login_required
def settings_index() -> WerkzeugResponse:
    """`/settings` -> `/settings/servers/`.

    Laut User-Klaerung ist Server-Verwaltung der Default-Sub-Tab; das
    Addendum hatte zwar `Tags` vorgesehen, der finale Wunsch ist aber
    Server. Direkt-URLs auf `/settings/tags` etc. bleiben erreichbar.
    """
    return redirect(url_for("servers.list_servers"))


# ---------------------------------------------------------------------------
# Tags — bestehende Routen (unveraendert in Verhalten, Templates kommen
# vom frontend-implementer auf den neuen `_shell.html`-Pfad).
# ---------------------------------------------------------------------------


@settings_bp.get("/tags")
@login_required
def tags_list() -> Any:
    sess = get_session()
    tags = sess.execute(select(Tag).order_by(Tag.name)).scalars().all()
    return render_settings(
        active="tags",
        content_template="settings/tags.html",
        tags=tags,
        form=TagForm(),
        delete_form=CSRFOnlyForm(),
    )


@settings_bp.post("/tags")
@login_required
def tags_create() -> Any:
    sess = get_session()
    form = TagForm()
    if not form.validate_on_submit():
        tags = sess.execute(select(Tag).order_by(Tag.name)).scalars().all()
        for field_name, errors in form.errors.items():
            for err in errors:
                flash(f"{field_name}: {err}", "error")
        return make_response(
            render_settings(
                active="tags",
                content_template="settings/tags.html",
                tags=tags,
                form=form,
                delete_form=CSRFOnlyForm(),
            ),
            400,
        )

    tag = Tag(name=cast(str, form.name.data), color=cast(str, form.color.data))
    sess.add(tag)
    try:
        sess.flush()
    except IntegrityError:
        sess.rollback()
        flash("Tag existiert bereits.", "error")
        return redirect(url_for("settings.tags_list"))

    log_event(
        "tag.created",
        target_type="tag",
        target_id=tag.id,
        metadata={"name": tag.name, "color": tag.color},
        session=sess,
    )
    sess.commit()
    flash(f"Tag '{tag.name}' angelegt.", "success")
    return redirect(url_for("settings.tags_list"))


@settings_bp.post("/tags/<int:tag_id>/delete")
@login_required
def tags_delete(tag_id: int) -> Any:
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        return redirect(url_for("settings.tags_list"))

    sess = get_session()
    tag = sess.execute(select(Tag).where(Tag.id == tag_id)).scalar_one_or_none()
    if tag is None:
        flash("Tag nicht gefunden.", "error")
        return redirect(url_for("settings.tags_list"))

    name = tag.name
    sess.delete(tag)
    log_event(
        "tag.deleted",
        target_type="tag",
        target_id=tag_id,
        metadata={"name": name},
        session=sess,
    )
    sess.commit()
    flash(f"Tag '{name}' geloescht.", "success")
    return redirect(url_for("settings.tags_list"))


# ---------------------------------------------------------------------------
# Master-Key-Rotation (ADR-0016 — schliesst §8-Spec-Luecke).
# ---------------------------------------------------------------------------


def _last_master_key_rotation_at(sess: Any) -> Any:
    """Letztes `master_key.rotated`-Audit-Event oder Setup-Datum.

    Liefert ein `datetime | None`. Wenn weder Rotation noch Setup-Event
    existiert (frische DB, kein Setup), kommt `None` zurueck — der UI-
    Indikator zeigt dann "noch nie" via Jinja-Filter.
    """
    rotated = sess.execute(
        select(AuditEvent.ts)
        .where(AuditEvent.action == "master_key.rotated")
        .order_by(AuditEvent.ts.desc())
        .limit(1)
    ).scalar_one_or_none()
    if rotated is not None:
        return rotated

    # Fallback: Setup-Datum.
    setup = sess.execute(
        select(AuditEvent.ts)
        .where(AuditEvent.action == "setup.master_key_set")
        .order_by(AuditEvent.ts.desc())
        .limit(1)
    ).scalar_one_or_none()
    if setup is not None:
        return setup

    # Letzte Notnagel-Option: Settings.setup_completed_at.
    setting_row = get_settings_row(sess)
    return setting_row.setup_completed_at


@settings_bp.get("/master-key")
@login_required
def master_key_view() -> Any:
    """Rendert die Master-Key-Rotations-View.

    Zeigt:
      - Datum der letzten Rotation (oder Setup-Datum als Fallback).
      - "Neu generieren"-Button mit Confirm-Modal (Frontend baut das Modal).
      - **Niemals** den Klartext-Key, ausser direkt nach einer Rotation
        (`new_master_key`-Kontext aus dem POST-Re-Render).
    """
    sess = get_session()
    last_rotated_at = _last_master_key_rotation_at(sess)
    return render_settings(
        active="master_key",
        content_template="settings/master_key.html",
        rotate_form=MasterKeyRotateForm(),
        last_rotated_at=last_rotated_at,
        new_master_key=None,
    )


@settings_bp.post("/master-key/rotate")
@login_required
def master_key_rotate() -> Any:
    """Rotiert den Master-Key.

    Ablauf:
      1. CSRF-Validierung (Flask-WTF).
      2. Neuen 32-Byte-URL-safe-Key generieren (analog Setup, §8).
      3. SHA-256-Hash speichern in ``settings.master_key_hash``.
      4. Audit-Event ``master_key.rotated`` mit Hash-Prefix-Metadata —
         **niemals** den Klartext in Audit oder Logs.
      5. Re-render der View mit dem Klartext-Key als einmaliger Anzeige.

    Sicherheits-Hinweise:
      - `generate_master_key()` -> `secrets.token_urlsafe(32)`; entropisch
        wie der Setup-Pfad.
      - `hash_master_key()` -> SHA-256-Hex; Verifikation mit
        `hmac.compare_digest` in `app/auth.py::verify_master_key`.
      - Alte Server-Keys bleiben gueltig — die Rotation aendert nur den
        Master-Key, nicht die Server-Hashes (siehe ARCHITECTURE.md §8).
    """
    sess = get_session()
    form = MasterKeyRotateForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        # 400 statt 302, damit der Client den Submit als Fehler erkennt
        # und nicht stillschweigend einen neuen GET ausloest.
        last = _last_master_key_rotation_at(sess)
        return make_response(
            render_settings(
                active="master_key",
                content_template="settings/master_key.html",
                rotate_form=form,
                last_rotated_at=last,
                new_master_key=None,
            ),
            400,
        )

    new_master = generate_master_key()
    new_hash = hash_master_key(new_master)
    setting_row = get_settings_row(sess)
    setting_row.master_key_hash = new_hash

    log_event(
        "master_key.rotated",
        target_type="settings",
        target_id="1",
        comment=None,
        metadata={"hash_prefix": new_hash[:8]},
        session=sess,
    )
    sess.commit()

    # Bewusst KEIN structlog-Log mit dem Klartext — der Audit-Helfer hat
    # bereits `audit.logged` ohne Klartext geloggt, und `structlog` mit
    # Redaction-Filter wuerde den Wert eh maskieren. Doppelte Vorsicht:
    # wir leiten den Klartext direkt in den Template-Kontext und nirgendwo
    # sonst hin.
    last = _last_master_key_rotation_at(sess)
    return render_settings(
        active="master_key",
        content_template="settings/master_key.html",
        rotate_form=MasterKeyRotateForm(),
        last_rotated_at=last,
        new_master_key=new_master,
    )


# ---------------------------------------------------------------------------
# LLM Risk Reviewer (Block P, ADR-0023) — `/settings/llm-reviewer`.
#
# Drei Routen:
#   - GET  /settings/llm-reviewer            — Tab rendern (Stats + Mode).
#   - POST /settings/llm-reviewer/mode       — Mode-Wechsel (Master-Key).
#   - POST /settings/llm-reviewer/requeue-backlog
#     — Observation-Backlog auf `queued` zuruecksetzen (Master-Key).
#
# Mode-Wechsel ist eine sensible Aktion (DSGVO/Cost-Implikation bei `live`),
# darum dieselbe Master-Key-Bestaetigung wie `/settings/master-key` (siehe
# ADR-0023 §"Mode-Wechsel-Workflow").
# ---------------------------------------------------------------------------


_LLM_MODE_VALUES: tuple[str, ...] = ("off", "observation", "live")


def _llm_reviewer_stats(sess: Any) -> dict[str, Any]:
    """Sammelt die Stats fuer das Settings-Tab.

    Eine Mehrzahl-Aggregation-Query, leicht im Lesefluss zerlegt:

      1. ``llm_jobs``-Status-Counts der letzten 24h (queued/in_progress/done/
         failed).
      2. ``llm_jobs`` mit ``result.would_call=true`` Count (Observation-
         Backlog-Indikator) und Token-Schaetzungs-Summe.
      3. ``application_groups`` Library: Total + Top-5 by ``last_used_at``.
      4. ``llm_risk_cache`` Total-Count.
      5. Token-Budget aus der Settings-Singleton-Row + Daily-Cap aus der
         App-Settings.
      6. Worker-Heartbeat-Alter.
    """
    now = datetime.now(tz=UTC)
    since_24h = now - timedelta(hours=24)

    # 1. Queue-Status-Counts (letzte 24h).
    job_counts: dict[str, int] = {
        "queued": 0,
        "in_progress": 0,
        "done": 0,
        "failed": 0,
    }
    status_stmt = (
        select(LLMJob.status, func.count(LLMJob.id))
        .where(LLMJob.created_at >= since_24h)
        .group_by(LLMJob.status)
    )
    for status_value, n in sess.execute(status_stmt).all():
        if status_value in job_counts:
            job_counts[status_value] = int(n)
    # `queued` zaehlen wir komplett (nicht nur letzte 24h), damit der
    # Operator das aktuelle Backlog sieht.
    open_queued_stmt = select(func.count(LLMJob.id)).where(LLMJob.status == "queued")
    job_counts["queued"] = int(sess.execute(open_queued_stmt).scalar() or 0)
    open_inprogress_stmt = select(func.count(LLMJob.id)).where(LLMJob.status == "in_progress")
    job_counts["in_progress"] = int(sess.execute(open_inprogress_stmt).scalar() or 0)

    # 2. Observation-Backlog: done-Jobs mit `result.would_call=true`.
    # JSONB-Pfad-Operator `->>` liefert Text; Vergleich gegen "true".
    would_call_stmt = select(func.count(LLMJob.id)).where(
        LLMJob.status == "done",
        text("(result ->> 'would_call') = 'true'"),
    )
    would_call_count = int(sess.execute(would_call_stmt).scalar() or 0)

    # 3. Library-Stats.
    groups_total_stmt = select(func.count(ApplicationGroup.id))
    groups_total = int(sess.execute(groups_total_stmt).scalar() or 0)
    top_groups_stmt = (
        select(ApplicationGroup).order_by(ApplicationGroup.last_used_at.desc().nullslast()).limit(5)
    )
    top_groups = list(sess.execute(top_groups_stmt).scalars().all())

    # 4. Cache-Stats.
    cache_total_stmt = select(func.count(LLMRiskCache.cache_key))
    cache_total = int(sess.execute(cache_total_stmt).scalar() or 0)

    # 5. Token-Budget.
    setting_row = get_settings_row(sess)
    app_settings = load_settings()
    token_budget = {
        "used_today": int(setting_row.llm_token_budget_used_today or 0),
        "daily_limit": int(app_settings.llm_token_budget_daily),
        "resets_at": setting_row.llm_token_budget_reset_at,
    }

    # 6. Heartbeat.
    heartbeat_at = setting_row.llm_worker_heartbeat_at
    if heartbeat_at is None:
        heartbeat_age_s: float | None = None
        heartbeat_healthy = False
    else:
        if heartbeat_at.tzinfo is None:
            heartbeat_at = heartbeat_at.replace(tzinfo=UTC)
        heartbeat_age_s = (now - heartbeat_at).total_seconds()
        # `30s`-Frische-Schwelle: Worker-Polling-Intervall ist 2s, Heartbeat
        # alle paar Ticks — < 30s ist gemuetlich, daruber als stale anzeigen.
        heartbeat_healthy = heartbeat_age_s < 30.0

    return {
        "current_mode": setting_row.block_p_llm_mode,
        "job_counts": job_counts,
        "would_call_count": would_call_count,
        "groups_total": groups_total,
        "top_groups": top_groups,
        "cache_total": cache_total,
        "token_budget": token_budget,
        "heartbeat_at": setting_row.llm_worker_heartbeat_at,
        "heartbeat_age_s": heartbeat_age_s,
        "heartbeat_healthy": heartbeat_healthy,
    }


@settings_bp.get("/llm-reviewer")
@login_required
def llm_reviewer_view() -> Any:
    """Rendert den LLM-Reviewer-Settings-Tab (Mode + Stats)."""
    sess = get_session()
    stats = _llm_reviewer_stats(sess)
    return render_settings(
        active="llm_reviewer",
        content_template="settings/llm_reviewer.html",
        mode_form=LlmReviewerModeForm(),
        requeue_form=LlmReviewerRequeueForm(),
        **stats,
    )


def _verify_master_key_from_form(sess: Any, plain_master_key: str | None) -> bool:
    """Prueft den im POST mitgegebenen Klartext-Master-Key gegen den Hash.

    Liefert False bei fehlendem Hash, fehlendem Klartext oder Mismatch.
    Vergleich ueber `verify_master_key` (HMAC.compare_digest).
    """
    if not plain_master_key:
        return False
    setting_row = get_settings_row(sess)
    if not setting_row.master_key_hash:
        return False
    return verify_master_key(setting_row.master_key_hash, plain_master_key)


@settings_bp.post("/llm-reviewer/mode")
@login_required
def llm_reviewer_change_mode() -> Any:
    """Setzt `block_p_llm_mode` neu (mit Master-Key-Bestaetigung).

    Erfolg: 302-Redirect auf den Tab; Flash mit Success-Meldung. Audit-
    Event `llm.mode_changed` mit `from`/`to`/Actor-Metadata.

    Fehler:
      - CSRF-Fehler -> 400 + Render mit Form-Errors.
      - Master-Key falsch -> 403 + Render mit Form-Error.
      - Unbekannter Mode -> 400 (durch SelectField-Whitelist eigentlich nicht
        erreichbar; defensiv abgefangen).
    """
    sess = get_session()
    form = LlmReviewerModeForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token oder Pflichtfelder fehlen.", "error")
        stats = _llm_reviewer_stats(sess)
        return make_response(
            render_settings(
                active="llm_reviewer",
                content_template="settings/llm_reviewer.html",
                mode_form=form,
                requeue_form=LlmReviewerRequeueForm(),
                **stats,
            ),
            400,
        )

    new_mode = (form.new_mode.data or "").strip()
    if new_mode not in _LLM_MODE_VALUES:
        flash("Unbekannter Mode.", "error")
        stats = _llm_reviewer_stats(sess)
        return make_response(
            render_settings(
                active="llm_reviewer",
                content_template="settings/llm_reviewer.html",
                mode_form=form,
                requeue_form=LlmReviewerRequeueForm(),
                **stats,
            ),
            400,
        )

    if not _verify_master_key_from_form(sess, form.master_key.data):
        flash("Master-Key falsch.", "error")
        stats = _llm_reviewer_stats(sess)
        return make_response(
            render_settings(
                active="llm_reviewer",
                content_template="settings/llm_reviewer.html",
                mode_form=form,
                requeue_form=LlmReviewerRequeueForm(),
                **stats,
            ),
            403,
        )

    setting_row = get_settings_row(sess)
    old_mode = setting_row.block_p_llm_mode
    if old_mode == new_mode:
        flash(f"Mode ist bereits '{new_mode}'.", "info")
        return redirect(url_for("settings.llm_reviewer_view"))

    setting_row.block_p_llm_mode = new_mode
    log_event(
        "llm.mode_changed",
        target_type="settings",
        target_id="1",
        metadata={"from": old_mode, "to": new_mode},
        session=sess,
    )
    sess.commit()
    flash(f"LLM-Mode auf '{new_mode}' gesetzt.", "success")
    return redirect(url_for("settings.llm_reviewer_view"))


@settings_bp.post("/llm-reviewer/requeue-backlog")
@login_required
def llm_reviewer_requeue_backlog() -> Any:
    """Setzt alle Observation-`would_call`-Jobs zurueck auf `queued`.

    Pre-Conditions:
      - CSRF gueltig.
      - Master-Key korrekt.
      - Aktueller Mode ist `live` (sonst macht das Re-Queue keinen Sinn —
        Observation wuerde dieselben would-call-Jobs erneut erzeugen).

    Effekt:
      - `UPDATE llm_jobs SET status='queued', attempts=0, result=NULL
        WHERE status='done' AND result->>'would_call' = 'true'`.
      - Audit-Event `llm.backlog_requeued` mit `count`-Metadata.
    """
    sess = get_session()
    form = LlmReviewerRequeueForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        return redirect(url_for("settings.llm_reviewer_view"))

    setting_row = get_settings_row(sess)
    if setting_row.block_p_llm_mode != "live":
        flash(
            "Re-queue ist nur im 'live'-Mode erlaubt. Schalte erst auf live.",
            "error",
        )
        return redirect(url_for("settings.llm_reviewer_view"))

    if not _verify_master_key_from_form(sess, form.master_key.data):
        flash("Master-Key falsch.", "error")
        return redirect(url_for("settings.llm_reviewer_view"))

    # Welche Jobs sind "would_call"? — done + result.would_call=true.
    target_ids_stmt = select(LLMJob.id).where(
        LLMJob.status == "done",
        text("(result ->> 'would_call') = 'true'"),
    )
    target_ids = [int(row) for row in sess.execute(target_ids_stmt).scalars().all()]

    if not target_ids:
        flash("Kein Observation-Backlog zum Re-queuen vorhanden.", "info")
        return redirect(url_for("settings.llm_reviewer_view"))

    # Reset: status=queued, attempts=0, result=NULL. `next_attempt_at` setzen
    # wir auf `now()` damit der Worker sofort picken kann.
    for job in sess.execute(select(LLMJob).where(LLMJob.id.in_(target_ids))).scalars():
        job.status = "queued"
        job.attempts = 0
        job.result = None
        job.next_attempt_at = datetime.now(tz=UTC)
        job.picked_up_by = None
        job.picked_up_at = None
        job.completed_at = None

    count = len(target_ids)
    log_event(
        "llm.backlog_requeued",
        target_type="settings",
        target_id="1",
        metadata={"count": count},
        session=sess,
    )
    sess.commit()
    flash(f"{count} Observation-Job(s) wieder eingereiht.", "success")
    return redirect(url_for("settings.llm_reviewer_view"))


# ---------------------------------------------------------------------------
# About (ADR-0016 — read-only Versions-/Build-Info).
# ---------------------------------------------------------------------------


def _safe_version(distribution_name: str) -> str:
    """Liefert die installierte Version eines Packages oder ``"unknown"``.

    Bewusst defensiv — Docker-Slim-Layer koennen einzelne Metadaten-
    Verzeichnisse loeschen. Niemals SystemExit/Crash wegen About-View.
    """
    try:
        return ilm.version(distribution_name)
    except ilm.PackageNotFoundError:
        return "unknown"


@settings_bp.get("/about")
@login_required
def about_view() -> Any:
    """Read-only About-Page (Versions-/Build-Info).

    Kontext-Dict enthaelt **ausschliesslich** unsensible Werte. Niemals
    ``SECSCAN_ENCRYPTION_KEY``, ``SECSCAN_SECRET_KEY``, ``master_key_hash``,
    ``llm_api_key_encrypted`` oder vergleichbare Geheimnisse — siehe
    Security-Auditor-Checkliste.
    """
    sess = get_session()

    alembic_rev = sess.execute(text("SELECT version_num FROM alembic_version")).scalar()

    # Trivy-DB-Stale-Counter: Anzahl Server mit veralteter DB.
    # Nicht-retired Server iterieren — `is_db_stale` respektiert das selbst,
    # aber wir filtern in der Query schon einmal vor.
    servers = sess.execute(select(Server).where(Server.retired_at.is_(None))).scalars().all()
    trivy_db_stale_count = sum(1 for srv in servers if is_db_stale(srv))

    about: dict[str, Any] = {
        "app_version": _safe_version("secscan"),
        "build_revision": os.environ.get("SECSCAN_BUILD_REVISION", "dev"),
        "alembic_revision": alembic_rev or "unknown",
        "python_version": sys.version.split()[0],
        "flask_version": _safe_version("flask"),
        "sqlalchemy_version": _safe_version("sqlalchemy"),
        "trivy_db_stale_count": trivy_db_stale_count,
        "healthz_url": url_for("health.healthz"),
    }

    return render_settings(
        active="about",
        content_template="settings/about.html",
        about=about,
    )


__all__ = ["settings_bp"]
