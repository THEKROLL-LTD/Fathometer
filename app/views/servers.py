# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Browser-View `/settings/servers` — Server-Liste mit Revoke/Retire.

Funktionen:
- `GET /settings/servers` — Liste aller Server (Name, Status, Tags, Last-Seen).
- `POST /settings/servers/<id>/revoke` — `revoked_at = now`, Key effektiv tot.
- `POST /settings/servers/<id>/retire` — `retired_at = now`, alle OPEN-Findings
  -> RESOLVED mit Grund `server_retired`. Audit-Event mit Liste.

Auth: `login_required`. CSRF ueber Flask-WTF. Templates folgen Block-D-Politur;
hier liefert der `frontend-implementer` das polierte HTML nach.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from flask import Blueprint, flash, redirect, url_for
from flask_login import login_required
from sqlalchemy import select, update
from werkzeug.wrappers import Response as WerkzeugResponse

from app.audit import log_event
from app.db import get_session
from app.forms import CSRFOnlyForm
from app.models import Finding, FindingStatus, Server
from app.views._settings_shell import render_settings

log = structlog.get_logger(__name__)
servers_bp = Blueprint("servers", __name__, url_prefix="/settings/servers")


@servers_bp.get("/")
@login_required
def list_servers() -> Any:
    sess = get_session()
    rows = sess.execute(select(Server).order_by(Server.created_at.desc())).scalars().all()
    return render_settings(
        active="servers",
        content_template="settings/servers.html",
        servers=rows,
        revoke_form=CSRFOnlyForm(),
        retire_form=CSRFOnlyForm(),
    )


@servers_bp.post("/<int:server_id>/revoke")
@login_required
def revoke_server(server_id: int) -> WerkzeugResponse:
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Invalid CSRF token.", "error")
        return redirect(url_for("servers.list_servers"))

    sess = get_session()
    server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one_or_none()
    if server is None:
        flash("Server not found.", "error")
        return redirect(url_for("servers.list_servers"))

    if server.revoked_at is not None:
        flash(f"Server '{server.name}' is already revoked.", "warning")
        return redirect(url_for("servers.list_servers"))

    now = datetime.now(tz=UTC)
    server.revoked_at = now
    # Hash invalidieren — auch wenn `revoked_at`-Check eh greift, ist das
    # Defense-in-Depth: ein bekannter Klartext-Key wuerde nach Hash-Reset
    # gar nicht mehr matchen.
    server.api_key_hash = ""  # leerer Hash matcht keinen SHA-256-Hex.
    log_event(
        "server.revoked",
        target_type="server",
        target_id=server.id,
        metadata={"name": server.name},
        session=sess,
    )
    sess.commit()
    flash(f"Server '{server.name}' revoked.", "success")
    return redirect(url_for("servers.list_servers"))


@servers_bp.post("/<int:server_id>/retire")
@login_required
def retire_server(server_id: int) -> WerkzeugResponse:
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Invalid CSRF token.", "error")
        return redirect(url_for("servers.list_servers"))

    sess = get_session()
    server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one_or_none()
    if server is None:
        flash("Server not found.", "error")
        return redirect(url_for("servers.list_servers"))

    if server.retired_at is not None:
        flash(f"Server '{server.name}' is already decommissioned.", "warning")
        return redirect(url_for("servers.list_servers"))

    now = datetime.now(tz=UTC)
    server.retired_at = now

    # Alle nicht-resolved Findings dieses Servers -> resolved.
    affected_ids = [
        row.id
        for row in sess.execute(
            select(Finding.id).where(
                Finding.server_id == server_id,
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]),
            )
        ).all()
    ]
    if affected_ids:
        sess.execute(
            update(Finding)
            .where(Finding.id.in_(affected_ids))
            .values(status=FindingStatus.RESOLVED, resolved_at=now)
        )

    log_event(
        "server.retired",
        target_type="server",
        target_id=server.id,
        comment="server_retired",
        metadata={
            "name": server.name,
            "resolved_finding_ids": affected_ids,
            "resolved_count": len(affected_ids),
        },
        session=sess,
    )
    sess.commit()
    flash(
        f"Server '{server.name}' decommissioned. {len(affected_ids)} open findings set to 'resolved'.",
        "success",
    )
    return redirect(url_for("servers.list_servers"))


__all__ = ["servers_bp"]
