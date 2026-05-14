"""Server-Detail-View `/servers/<id>` — nur Header + Tag-Editor.

Die Findings-Tabelle ist Block-E-Material und folgt spaeter. Hier nur:
- Header mit Name, OS-Subtext, Last-Scan, Status-Badges, Tags.
- Inline-HTMX-Add/Remove auf Tags (CSRF-pflichtig, Audit-Events).

Add/Remove geben jeweils das gleiche Partial `_tag_editor.html` zurueck,
das HTMX mit `hx-swap="outerHTML"` an den `#tag-editor-wrap`-Container
swapt.
"""

from __future__ import annotations

from typing import Any

import structlog
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from werkzeug.wrappers import Response as WerkzeugResponse

from app.audit import log_event
from app.db import get_session
from app.forms import TAG_NAME_REGEX, CSRFOnlyForm
from app.models import Server, ServerTag, Tag

log = structlog.get_logger(__name__)

server_detail_bp = Blueprint("server_detail", __name__, url_prefix="/servers")


def _load_server_with_tags(server_id: int) -> Server | None:
    sess = get_session()
    stmt = (
        select(Server)
        .options(selectinload(Server.tag_links).selectinload(ServerTag.tag))
        .where(Server.id == server_id)
    )
    return sess.execute(stmt).scalar_one_or_none()


def _all_tags() -> list[Tag]:
    sess = get_session()
    return list(sess.execute(select(Tag).order_by(Tag.name)).scalars().all())


def _render_tag_editor(server: Server) -> str:
    """Rendert nur das Tag-Editor-Fragment (fuer HTMX-Swaps)."""
    return render_template(
        "servers/_tag_editor.html",
        server=server,
        available_tags=_all_tags(),
        add_form=CSRFOnlyForm(),
        remove_form=CSRFOnlyForm(),
    )


@server_detail_bp.get("/<int:server_id>")
@login_required
def show(server_id: int) -> Any:
    server = _load_server_with_tags(server_id)
    if server is None:
        abort(404)
    return render_template(
        "servers/detail.html",
        server=server,
        available_tags=_all_tags(),
        add_form=CSRFOnlyForm(),
        remove_form=CSRFOnlyForm(),
    )


@server_detail_bp.post("/<int:server_id>/tags/add")
@login_required
def add_tag(server_id: int) -> WerkzeugResponse | str:
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        return redirect(url_for("server_detail.show", server_id=server_id))

    server = _load_server_with_tags(server_id)
    if server is None:
        abort(404)

    raw_name = (request.form.get("tag_name") or "").strip().lower()
    if not raw_name or not TAG_NAME_REGEX.match(raw_name):
        flash("Ungueltiger Tag-Name.", "error")
        return _redirect_or_partial(server)

    sess = get_session()
    tag = sess.execute(select(Tag).where(Tag.name == raw_name)).scalar_one_or_none()
    if tag is None:
        flash(
            f"Tag '{raw_name}' existiert nicht. Lege ihn zuerst unter Settings an.",
            "error",
        )
        return _redirect_or_partial(server)

    # Schon vorhanden? Idempotent behandeln, kein Fehler — UI-Re-Submit nach
    # Doppelklick darf nicht crashen.
    existing = sess.execute(
        select(ServerTag).where(ServerTag.server_id == server.id, ServerTag.tag_id == tag.id)
    ).scalar_one_or_none()
    if existing is None:
        sess.add(ServerTag(server_id=server.id, tag_id=tag.id))
        try:
            log_event(
                "server.tag.added",
                target_type="server",
                target_id=server.id,
                metadata={"tag_id": tag.id, "tag_name": tag.name},
                session=sess,
            )
            sess.commit()
        except IntegrityError:
            sess.rollback()
            log.warning("server_detail.tag_add_race", server_id=server.id, tag_id=tag.id)

    server = _load_server_with_tags(server_id)
    if server is None:  # pragma: no cover — race with retire/delete
        abort(404)
    return _redirect_or_partial(server)


@server_detail_bp.post("/<int:server_id>/tags/<int:tag_id>/remove")
@login_required
def remove_tag(server_id: int, tag_id: int) -> WerkzeugResponse | str:
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        return redirect(url_for("server_detail.show", server_id=server_id))

    server = _load_server_with_tags(server_id)
    if server is None:
        abort(404)

    sess = get_session()
    link = sess.execute(
        select(ServerTag).where(ServerTag.server_id == server_id, ServerTag.tag_id == tag_id)
    ).scalar_one_or_none()
    if link is not None:
        tag_name = link.tag.name if link.tag is not None else str(tag_id)
        sess.delete(link)
        log_event(
            "server.tag.removed",
            target_type="server",
            target_id=server.id,
            metadata={"tag_id": tag_id, "tag_name": tag_name},
            session=sess,
        )
        sess.commit()

    server = _load_server_with_tags(server_id)
    if server is None:  # pragma: no cover
        abort(404)
    return _redirect_or_partial(server)


def _redirect_or_partial(server: Server) -> WerkzeugResponse | str:
    """HTMX-Requests bekommen das Fragment, normale Browser einen Redirect."""
    if request.headers.get("HX-Request") == "true":
        return _render_tag_editor(server)
    return redirect(url_for("server_detail.show", server_id=server.id))


__all__ = ["server_detail_bp"]
