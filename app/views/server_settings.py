"""Server-Settings-Sub-View `GET /servers/<id>/settings` und zugehoerige POSTs.

Block X (ADR-0038, Phase B): Tag-Editor und neue Group-/Scan-Interval-Editoren
in einer dedizierten Sub-View. Tag-Add/Remove-Handler sind von
`server_detail.py` hierher refactored worden.

URL-Praefix: `/servers/<server_id>/settings`
Blueprint-Name: `server_settings`

Drei Modi analog zum `_settings_shell.py`-Pattern (ADR-0016 / Block-I):
  1. Vollseite (kein HX-Request): `base_app.html` + Settings-Content im
     Detail-Pane.
  2. HX-Fragment (HX-Request): `_partial_shell.html`-Wrapper + Content.
     Setzt `hx_partial=True` im Template-Kontext.

Auth: `@login_required` auf jeder Route. Owner-Check im Single-User-Setup =
Authenticated + revoked/retired-Negativ-Filter. Revoked/Retired-Server liefern
404 (aus Sicht des Operators sind sie "nicht zugehoerig").
"""

from __future__ import annotations

import structlog
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from werkzeug.wrappers import Response as WerkzeugResponse

from app.audit import log_event
from app.db import get_session
from app.forms import (
    TAG_NAME_REGEX,
    CSRFOnlyForm,
    ServerGroupForm,
    ServerScanIntervalForm,
)
from app.models import Server, ServerGroup, ServerTag, Tag

log = structlog.get_logger(__name__)

server_settings_bp = Blueprint(
    "server_settings", __name__, url_prefix="/servers/<int:server_id>/settings"
)


# ---------------------------------------------------------------------------
# Loader-Helper
# ---------------------------------------------------------------------------


def _load_server_with_settings(server_id: int) -> Server | None:
    """Laedt den Server mit Tag-Links und Group fuer das Settings-Template.

    Eager-laedt `tag_links.tag` und `group` per selectinload, damit das
    Settings-Template keine N+1-Queries erzeugt.
    """
    sess = get_session()
    return sess.execute(
        select(Server)
        .where(Server.id == server_id)
        .options(
            selectinload(Server.tag_links).selectinload(ServerTag.tag),
            selectinload(Server.group),
        )
    ).scalar_one_or_none()


def _all_tags() -> list[Tag]:
    sess = get_session()
    return list(sess.execute(select(Tag).order_by(Tag.name)).scalars().all())


def _all_groups() -> list[ServerGroup]:
    sess = get_session()
    return list(sess.execute(select(ServerGroup).order_by(ServerGroup.name)).scalars().all())


# ---------------------------------------------------------------------------
# Render-Helper
# ---------------------------------------------------------------------------


def _render_settings(server: Server) -> str:
    """Rendert die Settings-Sub-View in einem von zwei Modi.

    - Kein HX-Request -> volle Seite (base_app.html + Content im Detail-Pane).
    - HX-Request -> Detail-Pane-Fragment (_partial_shell.html + Content).
      `hx_partial=True` signalisiert dem Template das richtige `extends`.

    Template-Variablen-Vertrag (fuer frontend-implementer):
      - `server`: Server-ORM-Objekt mit eager-geladenen tag_links + group.
      - `available_tags`: alle Tags aus der DB (fuer das Tag-Add-Dropdown).
      - `current_tags`: Tags des Servers (fuer Remove-Buttons).
      - `available_groups`: alle ServerGroups (fuer den Group-Selector).
      - `current_group_id`: server.group_id (int oder None).
      - `scan_interval_h`: server.expected_scan_interval_h.
      - `tag_add_form`: CSRFOnlyForm — CSRF-Token fuer das Tag-Add-Form.
      - `tag_remove_form`: CSRFOnlyForm — CSRF-Token fuer die Remove-Buttons.
      - `group_form`: ServerGroupForm — Group-Selector-Form mit choices.
      - `scan_interval_form`: ServerScanIntervalForm.
      - `hx_partial`: bool.
    """
    available_tags = _all_tags()
    available_groups = _all_groups()

    group_initial = str(server.group_id) if server.group_id is not None else "none"
    ctx = {
        "server": server,
        "available_tags": available_tags,
        "current_tags": [link.tag for link in server.tag_links if link.tag is not None],
        "available_groups": available_groups,
        "current_group_id": server.group_id,
        "scan_interval_h": server.expected_scan_interval_h,
        "tag_add_form": CSRFOnlyForm(),
        "tag_remove_form": CSRFOnlyForm(),
        "group_form": ServerGroupForm(
            available_groups=available_groups,
            data={"group_id": group_initial},
        ),
        "scan_interval_form": ServerScanIntervalForm(
            data={"scan_interval_h": server.expected_scan_interval_h},
        ),
    }

    hx_request = request.headers.get("HX-Request") == "true"

    if hx_request:
        return render_template(
            "servers/settings.html",
            hx_partial=True,
            **ctx,
        )

    return render_template(
        "servers/settings.html",
        hx_partial=False,
        **ctx,
    )


def _redirect_to_settings(server_id: int) -> WerkzeugResponse:
    """Redirect auf die Settings-Sub-View nach einer POST-Aktion."""
    return redirect(url_for("server_settings.show", server_id=server_id))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@server_settings_bp.get("/")
@login_required
def show(server_id: int) -> str | WerkzeugResponse:
    """GET /servers/<id>/settings — rendert die Settings-Sub-View.

    404 wenn der Server nicht existiert, revoked oder retired ist.
    """
    server = _load_server_with_settings(server_id)
    if server is None or server.revoked_at is not None or server.retired_at is not None:
        abort(404)
    return _render_settings(server)


@server_settings_bp.post("/tags/add")
@login_required
def add_tag(server_id: int) -> str | WerkzeugResponse:
    """POST /servers/<id>/settings/tags/add — fuegt einen Tag zum Server hinzu.

    Refactored von `server_detail.add_tag`. Logik bleibt identisch:
    CSRFOnlyForm-Pruefung, TAG_NAME_REGEX-Whitelist, Idempotenz bei
    already-existing-Link. Redirect nach server_settings.show statt
    server_detail.show.
    """
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        return redirect(url_for("server_detail.show", server_id=server_id))

    server = _load_server_with_settings(server_id)
    if server is None or server.revoked_at is not None or server.retired_at is not None:
        abort(404)

    raw_name = (request.form.get("tag_name") or "").strip().lower()
    if not raw_name or not TAG_NAME_REGEX.match(raw_name):
        flash("Ungueltiger Tag-Name.", "error")
        return _redirect_to_settings(server_id)

    sess = get_session()
    tag = sess.execute(select(Tag).where(Tag.name == raw_name)).scalar_one_or_none()
    if tag is None:
        flash(
            f"Tag '{raw_name}' existiert nicht. Lege ihn zuerst unter Settings an.",
            "error",
        )
        return _redirect_to_settings(server_id)

    # Schon vorhanden? Idempotent behandeln, kein Fehler.
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
            log.warning(
                "server_settings.tag_add_race",
                server_id=server.id,
                tag_id=tag.id,
            )

    return _redirect_to_settings(server_id)


@server_settings_bp.post("/tags/<int:tag_id>/remove")
@login_required
def remove_tag(server_id: int, tag_id: int) -> str | WerkzeugResponse:
    """POST /servers/<id>/settings/tags/<tag_id>/remove — entfernt einen Tag.

    Refactored von `server_detail.remove_tag`. Idempotent bei nicht-vorhandenem
    Link (kein Fehler, kein Audit-Event). Redirect nach server_settings.show.
    """
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        return redirect(url_for("server_detail.show", server_id=server_id))

    server = _load_server_with_settings(server_id)
    if server is None or server.revoked_at is not None or server.retired_at is not None:
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

    return _redirect_to_settings(server_id)


@server_settings_bp.post("/group")
@login_required
def update_group(server_id: int) -> str | WerkzeugResponse:
    """POST /servers/<id>/settings/group — setzt server.group_id.

    Validation: `group_id` muss entweder None sein oder eine ID aus den
    existierenden ServerGroups. Eingeschleuste Fake-IDs werden per Whitelist-
    Pruefung abgewiesen (flash + Redirect, kein DB-Touch).
    """
    server = _load_server_with_settings(server_id)
    if server is None or server.revoked_at is not None or server.retired_at is not None:
        abort(404)

    sess = get_session()
    available = list(sess.execute(select(ServerGroup).order_by(ServerGroup.name)).scalars().all())
    form = ServerGroupForm(available_groups=available)
    if not form.validate_on_submit():
        flash("Ungueltige Group-Auswahl.", "error")
        return _redirect_to_settings(server_id)

    new_group_id: int | None = form.group_id.data

    # Whitelist: None ODER ID muss in available existieren.
    if new_group_id is not None and not any(g.id == new_group_id for g in available):
        flash("Gewaehlte Group existiert nicht (mehr).", "error")
        return _redirect_to_settings(server_id)

    old_group_id = server.group_id
    if old_group_id == new_group_id:
        return _redirect_to_settings(server_id)  # No-op, kein Audit

    server.group_id = new_group_id
    log_event(
        "server.group_changed",
        target_type="server",
        target_id=server.id,
        metadata={"from": old_group_id, "to": new_group_id},
        session=sess,
    )
    sess.commit()
    return _redirect_to_settings(server_id)


@server_settings_bp.post("/scan-interval")
@login_required
def update_scan_interval(server_id: int) -> str | WerkzeugResponse:
    """POST /servers/<id>/settings/scan-interval — setzt expected_scan_interval_h.

    Validation: Integer im Bereich [1, 168]. Out-of-Range-Inputs werden mit
    flash + Redirect abgewiesen ohne DB-Touch.
    """
    server = _load_server_with_settings(server_id)
    if server is None or server.revoked_at is not None or server.retired_at is not None:
        abort(404)

    form = ServerScanIntervalForm()
    if not form.validate_on_submit():
        flash("Scan-Intervall muss zwischen 1 und 168 Stunden liegen.", "error")
        return _redirect_to_settings(server_id)

    new_interval: int = form.scan_interval_h.data
    old_interval = server.expected_scan_interval_h
    if old_interval == new_interval:
        return _redirect_to_settings(server_id)  # No-op, kein Audit

    server.expected_scan_interval_h = new_interval
    sess = get_session()
    log_event(
        "server.scan_interval_changed",
        target_type="server",
        target_id=server.id,
        metadata={"from": old_interval, "to": new_interval},
        session=sess,
    )
    sess.commit()
    return _redirect_to_settings(server_id)


__all__ = ["server_settings_bp"]
