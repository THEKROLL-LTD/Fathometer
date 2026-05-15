"""Tag-Verwaltung unter `/settings/tags`."""

from __future__ import annotations

from typing import Any, cast

import structlog
from flask import Blueprint, flash, make_response, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.audit import log_event
from app.db import get_session
from app.forms import CSRFOnlyForm, TagForm
from app.models import Tag
from app.views._sidebar_context import is_hx_request

log = structlog.get_logger(__name__)
settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.get("/tags")
@login_required
def tags_list() -> Any:
    sess = get_session()
    tags = sess.execute(select(Tag).order_by(Tag.name)).scalars().all()
    return render_template(
        "settings/tags.html",
        tags=tags,
        form=TagForm(),
        delete_form=CSRFOnlyForm(),
        # Block I: Sidebar-Layout-Flag.
        hx_partial=is_hx_request(request),
    )


@settings_bp.post("/tags")
@login_required
def tags_create() -> Any:
    sess = get_session()
    form = TagForm()
    if not form.validate_on_submit():
        # Re-render mit Fehlermeldungen.
        tags = sess.execute(select(Tag).order_by(Tag.name)).scalars().all()
        for field_name, errors in form.errors.items():
            for err in errors:
                flash(f"{field_name}: {err}", "error")
        return make_response(
            render_template(
                "settings/tags.html",
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


__all__ = ["settings_bp"]
