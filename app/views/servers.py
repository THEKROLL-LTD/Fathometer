# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Browser-View `/settings/servers` — Server-Liste mit Revoke/Retire.

Funktionen:
- `GET /settings/servers` — Liste aller Server (Name, Status, Tags, Last-Seen).
- `POST /settings/servers/<id>/revoke` — `revoked_at = now`, Key effektiv tot.
- `POST /settings/servers/<id>/retire` — `retired_at = now`, alle OPEN-Findings
  -> RESOLVED mit Grund `server_retired`. Audit-Event mit Liste.
- `POST /settings/servers/<id>/delete-findings` — loescht *alle* Findings des
  Servers (jeden Status) unwiderruflich; Server bleibt bestehen. Fuer
  Reparatur eines defekten Scan-Stands durch Neu-Einspielen.

Auth: `login_required`. CSRF ueber Flask-WTF. Templates folgen Block-D-Politur;
hier liefert der `frontend-implementer` das polierte HTML nach.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from flask import Blueprint, flash, redirect, url_for
from flask_login import login_required
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session
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
        delete_findings_form=CSRFOnlyForm(),
        delete_server_form=CSRFOnlyForm(),
    )


def _delete_all_findings(sess: Session, server_id: int) -> int:
    """Loescht alle Findings eines Servers (jeden Status) und gibt die Anzahl zurueck.

    Abhaengige `finding_notes` werden per DB-FK-CASCADE mitgeloescht. Kein
    Commit — der Aufrufer committet im Rahmen seiner Transaktion.
    """
    deleted_count: int = sess.execute(
        select(func.count()).select_from(Finding).where(Finding.server_id == server_id)
    ).scalar_one()
    sess.execute(
        delete(Finding)
        .where(Finding.server_id == server_id)
        .execution_options(synchronize_session=False)
    )
    return deleted_count


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


@servers_bp.post("/<int:server_id>/delete-findings")
@login_required
def delete_findings(server_id: int) -> WerkzeugResponse:
    """Loescht *alle* Findings eines Servers (jeden Status), unwiderruflich.

    Use-Case: defekter Scan-Stand reparieren durch Neu-Einspielen. Der
    Server-Eintrag selbst bleibt unangetastet — der naechste Scan-Ingest
    haengt neue Findings wieder an dieselbe `server_id`. Abhaengige
    `finding_notes` werden per DB-FK-CASCADE mitgeloescht.
    """
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Invalid CSRF token.", "error")
        return redirect(url_for("servers.list_servers"))

    sess = get_session()
    server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one_or_none()
    if server is None:
        flash("Server not found.", "error")
        return redirect(url_for("servers.list_servers"))

    deleted_count = _delete_all_findings(sess, server_id)

    log_event(
        "server.findings_deleted",
        target_type="server",
        target_id=server.id,
        metadata={"name": server.name, "deleted_count": deleted_count},
        session=sess,
    )
    sess.commit()
    flash(
        f"Deleted {deleted_count} findings for '{server.name}'.",
        "success",
    )
    return redirect(url_for("servers.list_servers"))


@servers_bp.post("/<int:server_id>/delete")
@login_required
def delete_server(server_id: int) -> WerkzeugResponse:
    """Loescht einen *revoked* Server vollstaendig aus der Datenbank.

    Use-Case: ein dauerhaft stillgelegter Server soll restlos verschwinden.
    Reihenfolge wie vom Operator erwartet: zuerst alle Findings loeschen
    (`_delete_all_findings`), dann den Server-Eintrag selbst. Alle weiteren
    abhaengigen Zeilen (Tags, Daily-Aggregate, Listeners/Processes, LLM-Jobs,
    Scan-Ingest-Jobs, Group-Evaluations, Group-Chats) haengen per FK
    `ondelete=CASCADE` am Server und werden beim Server-Delete mitgeraeumt;
    `llm_debug_logs.server_id` ist `SET NULL`.

    Guard: nur erlaubt wenn der Server `revoked` ist — ein aktiver Server muss
    erst revoked werden, damit kein Agent waehrenddessen noch Scans nachschiebt.
    """
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Invalid CSRF token.", "error")
        return redirect(url_for("servers.list_servers"))

    sess = get_session()
    server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one_or_none()
    if server is None:
        flash("Server not found.", "error")
        return redirect(url_for("servers.list_servers"))

    if server.revoked_at is None:
        flash(
            f"Server '{server.name}' must be revoked before it can be deleted.",
            "error",
        )
        return redirect(url_for("servers.list_servers"))

    server_name = server.name
    deleted_findings = _delete_all_findings(sess, server_id)

    # Audit-Event VOR dem Server-Delete schreiben — danach existiert die
    # `server_id` nicht mehr; der Event referenziert sie nur als loser
    # `target_id` (kein FK auf servers), bleibt also nach dem Delete erhalten.
    log_event(
        "server.deleted",
        target_type="server",
        target_id=server_id,
        metadata={"name": server_name, "deleted_findings": deleted_findings},
        session=sess,
    )

    sess.delete(server)
    sess.commit()
    flash(
        f"Server '{server_name}' deleted ({deleted_findings} findings removed).",
        "success",
    )
    return redirect(url_for("servers.list_servers"))


__all__ = ["servers_bp"]
