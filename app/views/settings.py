# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

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
from app.db import get_session
from app.forms import (
    CSRFOnlyForm,
    GroupMoveForm,
    GroupRenameForm,
    LlmReviewerConcurrencyForm,
    LlmReviewerModeForm,
    LlmReviewerRequeueForm,
    MasterKeyRotateForm,
    TagColorForm,
    TagRenameForm,
)
from app.models import (
    ApplicationGroup,
    AuditEvent,
    LLMDebugLog,
    LLMJob,
    LLMRiskCache,
    Server,
    ServerGroup,
    Tag,
)
from app.services.feed_status import get_all_feed_statuses
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
# Tags — Manage-Only-Seite (Block Z, ADR-0040 — Refactor).
#
# KEIN Create-Pfad mehr — Tags entstehen ausschliesslich inline im Server-
# Settings-Sub-View (`server_settings.tag_create`). Diese Seite bietet nur
# Rename, Color-Edit und Delete. Der frühere `POST /settings/tags`-Create-
# Endpoint ist ersatzlos entfernt (POST liefert jetzt 405).
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
        rename_form=TagRenameForm(),
        color_form=TagColorForm(),
        delete_form=CSRFOnlyForm(),
    )


@settings_bp.post("/tags/<int:tag_id>/rename")
@login_required
def tags_rename(tag_id: int) -> Any:
    """`POST /settings/tags/<id>/rename` — Tag umbenennen.

    No-Op bei identischem Namen (kein Audit). `IntegrityError` (Name bereits
    vergeben) → Flash + Redirect ohne 500.
    """
    sess = get_session()
    form = TagRenameForm()
    if not form.validate_on_submit():
        for field_name, errors in form.errors.items():
            for err in errors:
                flash(f"{field_name}: {err}", "error")
        if not form.errors:
            flash("Invalid CSRF token.", "error")
        return redirect(url_for("settings.tags_list"))

    tag = sess.execute(select(Tag).where(Tag.id == tag_id)).scalar_one_or_none()
    if tag is None:
        flash("Tag not found.", "error")
        return redirect(url_for("settings.tags_list"))

    new_name = cast(str, form.name.data)
    old_name = tag.name
    if old_name == new_name:
        return redirect(url_for("settings.tags_list"))  # No-op, kein Audit

    tag.name = new_name
    try:
        sess.flush()
    except IntegrityError:
        sess.rollback()
        flash(f"Name '{new_name}' is already taken.", "error")
        return redirect(url_for("settings.tags_list"))

    log_event(
        "tag.renamed",
        target_type="tag",
        target_id=tag_id,
        metadata={"from": old_name, "to": new_name},
        session=sess,
    )
    sess.commit()
    flash(f"Tag '{old_name}' renamed to '{new_name}'.", "success")
    return redirect(url_for("settings.tags_list"))


@settings_bp.post("/tags/<int:tag_id>/color")
@login_required
def tags_color(tag_id: int) -> Any:
    """`POST /settings/tags/<id>/color` — Tag-Farbe aendern.

    No-Op bei identischer Farbe (kein Audit).
    """
    sess = get_session()
    form = TagColorForm()
    if not form.validate_on_submit():
        for field_name, errors in form.errors.items():
            for err in errors:
                flash(f"{field_name}: {err}", "error")
        if not form.errors:
            flash("Invalid CSRF token.", "error")
        return redirect(url_for("settings.tags_list"))

    tag = sess.execute(select(Tag).where(Tag.id == tag_id)).scalar_one_or_none()
    if tag is None:
        flash("Tag not found.", "error")
        return redirect(url_for("settings.tags_list"))

    new_color = cast(str, form.color.data)
    old_color = tag.color
    if old_color == new_color:
        return redirect(url_for("settings.tags_list"))  # No-op, kein Audit

    tag.color = new_color
    log_event(
        "tag.color_changed",
        target_type="tag",
        target_id=tag_id,
        metadata={"from": old_color, "to": new_color},
        session=sess,
    )
    sess.commit()
    flash(f"Color of tag '{tag.name}' changed.", "success")
    return redirect(url_for("settings.tags_list"))


@settings_bp.post("/tags/<int:tag_id>/delete")
@login_required
def tags_delete(tag_id: int) -> Any:
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Invalid CSRF token.", "error")
        return redirect(url_for("settings.tags_list"))

    sess = get_session()
    tag = sess.execute(select(Tag).where(Tag.id == tag_id)).scalar_one_or_none()
    if tag is None:
        flash("Tag not found.", "error")
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
    flash(f"Tag '{name}' deleted.", "success")
    return redirect(url_for("settings.tags_list"))


# ---------------------------------------------------------------------------
# Gruppen — Manage-Only-Seite (Block Z, ADR-0040).
#
# KEIN Create-Pfad — Gruppen entstehen ausschliesslich inline im Server-
# Settings-Sub-View (`server_settings.group_create`). Diese Seite bietet nur
# Rename, Delete und Position-Reorder (Up/Down-Swap).
# ---------------------------------------------------------------------------


def _groups_with_member_counts(sess: Any) -> list[dict[str, Any]]:
    """Liefert alle Gruppen mit aggregiertem Member-Count, sortiert.

    Ein LEFT JOIN servers GROUP BY group — leere Gruppen tauchen mit
    `member_count = 0` auf (sie werden hier bewusst gezeigt, nur die Sidebar
    blendet sie weg). Sortierung wie die Sidebar: `position, name`.
    """
    stmt = (
        select(
            ServerGroup.id,
            ServerGroup.name,
            ServerGroup.position,
            func.count(Server.id).label("member_count"),
        )
        .outerjoin(Server, Server.group_id == ServerGroup.id)
        .group_by(ServerGroup.id, ServerGroup.name, ServerGroup.position)
        .order_by(ServerGroup.position, ServerGroup.name)
    )
    return [
        {
            "id": int(row.id),
            "name": row.name,
            "position": int(row.position),
            "member_count": int(row.member_count),
        }
        for row in sess.execute(stmt).all()
    ]


@settings_bp.get("/groups")
@login_required
def groups_list() -> Any:
    """`GET /settings/groups` — Manage-Only-Liste aller Gruppen."""
    sess = get_session()
    return render_settings(
        active="groups",
        content_template="settings/groups.html",
        groups=_groups_with_member_counts(sess),
        rename_form=GroupRenameForm(),
        move_form=GroupMoveForm(),
        delete_form=CSRFOnlyForm(),
    )


@settings_bp.post("/groups/<int:group_id>/rename")
@login_required
def groups_rename(group_id: int) -> Any:
    """`POST /settings/groups/<id>/rename` — Gruppe umbenennen.

    No-Op bei identischem Namen (kein Audit). `IntegrityError` (Name bereits
    vergeben) → Flash + Redirect ohne 500.
    """
    sess = get_session()
    form = GroupRenameForm()
    if not form.validate_on_submit():
        for field_name, errors in form.errors.items():
            for err in errors:
                flash(f"{field_name}: {err}", "error")
        if not form.errors:
            flash("Invalid CSRF token.", "error")
        return redirect(url_for("settings.groups_list"))

    group = sess.execute(select(ServerGroup).where(ServerGroup.id == group_id)).scalar_one_or_none()
    if group is None:
        flash("Group not found.", "error")
        return redirect(url_for("settings.groups_list"))

    new_name = cast(str, form.name.data).strip()
    old_name = group.name
    if old_name == new_name:
        return redirect(url_for("settings.groups_list"))  # No-op, kein Audit

    group.name = new_name
    try:
        sess.flush()
    except IntegrityError:
        sess.rollback()
        flash(f"Name '{new_name}' is already taken.", "error")
        return redirect(url_for("settings.groups_list"))

    log_event(
        "group.renamed",
        target_type="group",
        target_id=group_id,
        metadata={"from": old_name, "to": new_name},
        session=sess,
    )
    sess.commit()
    flash(f"Group '{old_name}' renamed to '{new_name}'.", "success")
    return redirect(url_for("settings.groups_list"))


@settings_bp.post("/groups/<int:group_id>/delete")
@login_required
def groups_delete(group_id: int) -> Any:
    """`POST /settings/groups/<id>/delete` — Gruppe loeschen.

    ON-DELETE-SET-NULL (ADR-0034) setzt `server.group_id = NULL` fuer alle
    Member — kein Server wird geloescht. Member-Count wird VOR dem Delete
    gelesen und ins Audit geschrieben (`member_count_before`).
    """
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Invalid CSRF token.", "error")
        return redirect(url_for("settings.groups_list"))

    sess = get_session()
    group = sess.execute(select(ServerGroup).where(ServerGroup.id == group_id)).scalar_one_or_none()
    if group is None:
        flash("Group not found.", "error")
        return redirect(url_for("settings.groups_list"))

    member_count = int(
        sess.execute(select(func.count(Server.id)).where(Server.group_id == group_id)).scalar_one()
    )
    name = group.name
    sess.delete(group)
    log_event(
        "group.deleted",
        target_type="group",
        target_id=group_id,
        metadata={"name": name, "member_count_before": member_count},
        session=sess,
    )
    sess.commit()
    flash(f"Group '{name}' deleted ({member_count} servers now ungrouped).", "success")
    return redirect(url_for("settings.groups_list"))


@settings_bp.post("/groups/<int:group_id>/move")
@login_required
def groups_move(group_id: int) -> Any:
    """`POST /settings/groups/<id>/move` — Position-Reorder per Up/Down-Swap.

    Findet den Nachbarn mit `position < this` (up) bzw. `position > this`
    (down) und tauscht beide `position`-Werte atomar. No-Op + Flash wenn kein
    Nachbar existiert (Gruppe bereits ganz oben/unten).
    """
    sess = get_session()
    form = GroupMoveForm()
    if not form.validate_on_submit():
        flash("Invalid direction.", "error")
        return redirect(url_for("settings.groups_list"))

    group = sess.execute(select(ServerGroup).where(ServerGroup.id == group_id)).scalar_one_or_none()
    if group is None:
        flash("Group not found.", "error")
        return redirect(url_for("settings.groups_list"))

    direction = form.direction.data
    if direction == "up":
        neighbor = sess.execute(
            select(ServerGroup)
            .where(ServerGroup.position < group.position)
            .order_by(ServerGroup.position.desc())
            .limit(1)
        ).scalar_one_or_none()
    else:  # "down" — SelectField-Whitelist garantiert up|down
        neighbor = sess.execute(
            select(ServerGroup)
            .where(ServerGroup.position > group.position)
            .order_by(ServerGroup.position.asc())
            .limit(1)
        ).scalar_one_or_none()

    if neighbor is None:
        edge = "top" if direction == "up" else "bottom"
        flash(f"Group is already at the {edge}.", "info")
        return redirect(url_for("settings.groups_list"))

    old_position = group.position
    group.position = neighbor.position
    neighbor.position = old_position
    log_event(
        "group.moved",
        target_type="group",
        target_id=group_id,
        metadata={"from_position": old_position, "to_position": group.position},
        session=sess,
    )
    sess.commit()
    return redirect(url_for("settings.groups_list"))


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
        flash("Invalid CSRF token.", "error")
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

    # 5. Token-Budget. Das Limit ist der Operator-steuerbare DB-Cap
    # ``llm_daily_token_cap`` (Provider-Tab) — derselbe Wert den der Worker
    # in ``llm_budget.budget_check`` erzwingt (kein Env-Drift).
    setting_row = get_settings_row(sess)
    token_budget = {
        "used_today": int(setting_row.llm_token_budget_used_today or 0),
        "daily_limit": int(setting_row.llm_daily_token_cap or 0),
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
        "current_concurrency": int(setting_row.llm_worker_job_concurrency),
        "active_model": setting_row.llm_model,
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
        concurrency_form=LlmReviewerConcurrencyForm(),
        sub_tab="overview",
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
        flash("Invalid CSRF token or required fields missing.", "error")
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
        flash("Master key incorrect.", "error")
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
        flash(f"Mode is already '{new_mode}'.", "info")
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
    flash(f"LLM mode set to '{new_mode}'.", "success")
    return redirect(url_for("settings.llm_reviewer_view"))


@settings_bp.post("/llm-reviewer/concurrency")
@login_required
def llm_reviewer_change_concurrency() -> Any:
    """Setzt ``settings.llm_worker_job_concurrency`` (mit Master-Key-Bestaetigung).

    Block U / ADR-0029 §Entscheidung Punkt 7. Worker liest den neuen Wert
    binnen <30 s via ``_get_concurrency_throttled`` (Phase C) — kein
    Pod-Restart noetig.

    Erfolg: 302-Redirect auf den Tab; Flash mit Success-Meldung. Audit-
    Event ``llm.concurrency_changed`` mit ``from``/``to``-Metadata.

    Fehler:
      - CSRF-Fehler oder out-of-range (1..200) / non-int -> 400 + Render
        mit Form-Errors.
      - Master-Key falsch -> 403 + Render mit Form-Error.

    No-Op: wenn der neue Wert == alter Wert ist, kein Audit-Event und ein
    302-Redirect mit Info-Flash ``Concurrency ist bereits 'N'.``.
    """
    sess = get_session()
    form = LlmReviewerConcurrencyForm()
    if not form.validate_on_submit():
        # Sowohl CSRF-Fehler als auch Bounds-/Type-Fehler landen hier.
        for field_name, errors in form.errors.items():
            for err in errors:
                flash(f"{field_name}: {err}", "error")
        if not form.errors:
            flash("Invalid CSRF token or required fields missing.", "error")
        stats = _llm_reviewer_stats(sess)
        return make_response(
            render_settings(
                active="llm_reviewer",
                content_template="settings/llm_reviewer.html",
                mode_form=LlmReviewerModeForm(),
                requeue_form=LlmReviewerRequeueForm(),
                concurrency_form=form,
                sub_tab="overview",
                **stats,
            ),
            400,
        )

    if not _verify_master_key_from_form(sess, form.master_key.data):
        flash("Master key incorrect.", "error")
        stats = _llm_reviewer_stats(sess)
        return make_response(
            render_settings(
                active="llm_reviewer",
                content_template="settings/llm_reviewer.html",
                mode_form=LlmReviewerModeForm(),
                requeue_form=LlmReviewerRequeueForm(),
                concurrency_form=form,
                sub_tab="overview",
                **stats,
            ),
            403,
        )

    new_value = int(cast(int, form.concurrency.data))
    setting_row = get_settings_row(sess)
    old_value = int(setting_row.llm_worker_job_concurrency)
    if old_value == new_value:
        flash(f"Concurrency is already '{new_value}'.", "info")
        return redirect(url_for("settings.llm_reviewer_view"))

    setting_row.llm_worker_job_concurrency = new_value
    log_event(
        "llm.concurrency_changed",
        target_type="settings",
        target_id="1",
        metadata={"from": old_value, "to": new_value},
        session=sess,
    )
    sess.commit()
    flash(
        f"Concurrency set to '{new_value}' — worker picks it up within 30 s.",
        "success",
    )
    return redirect(url_for("settings.llm_reviewer_view"))


@settings_bp.get("/llm-reviewer/debug-log")
@login_required
def llm_reviewer_debug_log() -> Any:
    """Read-only Operator-Inspektion fuer die letzten LLM-Debug-Log-Eintraege.

    v0.9.3 (ADR-0023 §e): zeigt die letzten 50 ``llm_debug_log``-Rows mit
    Job-Type, Group, Status, Duration, Timestamp; Klick auf einen Eintrag
    expandiert Request/Response/Reasoning. Master-Key-Gate ist **nicht**
    noetig — read-only, Operator-Visibility ohne State-Change.

    Eviction laeuft im Worker (Count-Cap + Time-Cap), darum keine UI-
    Limit-Pagination — 50 Eintraege decken die nuetzlichste Recent-View ab.
    """
    sess = get_session()
    entries = list(
        sess.execute(select(LLMDebugLog).order_by(LLMDebugLog.created_at.desc()).limit(50))
        .scalars()
        .all()
    )

    # Group-Label-Lookup fuer die Anzeige. Wir ziehen die referenzierten
    # Groups in einer einzigen Query (kein N+1) und fallbacken auf "-" wenn
    # `group_id` NULL oder die Group inzwischen geloescht wurde.
    group_ids = {e.group_id for e in entries if e.group_id is not None}
    group_labels: dict[int, str] = {}
    if group_ids:
        grp_stmt = select(ApplicationGroup.id, ApplicationGroup.label).where(
            ApplicationGroup.id.in_(group_ids)
        )
        for gid, label in sess.execute(grp_stmt).all():
            group_labels[int(gid)] = str(label)

    return render_settings(
        active="llm_reviewer",
        content_template="settings/llm_debug_log.html",
        debug_log_entries=entries,
        group_labels=group_labels,
        sub_tab="debug_log",
    )


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
        flash("Invalid CSRF token.", "error")
        return redirect(url_for("settings.llm_reviewer_view"))

    setting_row = get_settings_row(sess)
    if setting_row.block_p_llm_mode != "live":
        flash(
            "Re-queue is only allowed in 'live' mode. Switch to live first.",
            "error",
        )
        return redirect(url_for("settings.llm_reviewer_view"))

    if not _verify_master_key_from_form(sess, form.master_key.data):
        flash("Master key incorrect.", "error")
        return redirect(url_for("settings.llm_reviewer_view"))

    # Welche Jobs sind "would_call"? — done + result.would_call=true.
    target_ids_stmt = select(LLMJob.id).where(
        LLMJob.status == "done",
        text("(result ->> 'would_call') = 'true'"),
    )
    target_ids = [int(row) for row in sess.execute(target_ids_stmt).scalars().all()]

    if not target_ids:
        flash("No observation backlog to re-queue.", "info")
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
    ``FM_ENCRYPTION_KEY``, ``FM_SECRET_KEY``, ``master_key_hash``,
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
        "app_version": _safe_version("fathometer"),
        "build_revision": os.environ.get("FM_BUILD_REVISION", "dev"),
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
        # External-Feeds-Freshness (EPSS / CISA-KEV) — read-only, von der
        # LLM-Provider-Seite hierher verschoben (Block AD Folge-Fix).
        feed_statuses=get_all_feed_statuses(sess),
    )


__all__ = ["settings_bp"]
