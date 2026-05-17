"""Server-Detail-View `/servers/<id>` — Triage-Hauptansicht (Block E).

Erweitert den Block-D-Header um die Findings-Sektion mit drei View-Modi:
- `mode=list`  (Default) — flache Tabelle, Default-Sort nach §15.
- `mode=group` — gruppiert nach `package_name`.
- `mode=diff`  — Diff der letzten zwei Scans (siehe `diff_view`).

URL-Filter (alle optional, Defaults sicher): `mode`, `status`, `class`,
`severity`, `kev_only`, `q`.

HTMX-Pattern: bei `HX-Request: true` rendert der Endpoint die Detail-
Pane-Fragment-Variante von `servers/detail.html` (Server-Header +
Findings-Sektion) via `_partial_shell.html`, nicht die ganze Seite mit
Sidebar.
"""

from __future__ import annotations

from typing import Any

import structlog
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from werkzeug.wrappers import Response as WerkzeugResponse

from app.audit import log_event
from app.db import get_session
from app.forms import (
    TAG_NAME_REGEX,
    AcknowledgeForm,
    BulkActionForm,
    CSRFOnlyForm,
    GroupAcknowledgeForm,
    NoteForm,
    ReopenForm,
)
from app.models import Finding, FindingStatus, Server, ServerTag, Severity, Tag
from app.schemas.findings_view_filter import FindingsViewFilter
from app.services.diff_view import DiffSection, compute_diff
from app.settings_service import get_settings_row
from app.services.findings_query import (
    PackageGroup,
    count_findings,
    group_findings_by_package,
    list_findings,
)
from app.services.heartbeat_aggregation import DailyStatus, heartbeats_for_servers
from app.services.severity_history import (
    DailySeverityCount,
    count_kev_events_50d,
    daily_severity_counts_for_server,
    severity_snapshots_for_server,
)
from app.services.trend import Tendency, compute_tendency

log = structlog.get_logger(__name__)

server_detail_bp = Blueprint("server_detail", __name__, url_prefix="/servers")


# ---------------------------------------------------------------------------
# Loader-Helper
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Findings-Section-Render
# ---------------------------------------------------------------------------


def _render_findings_section(
    server: Server,
    view_filter: FindingsViewFilter,
) -> dict[str, Any]:
    """Sammelt die Render-Daten fuer die Findings-Sektion.

    Rueckgabe als dict — die Template-Inklusion (`servers/_findings_section
    .html`) konsumiert die Keys direkt. Wird sowohl beim Vollseiten- als
    auch beim HTMX-Partial-Render genutzt.
    """
    sess = get_session()
    findings_filter = view_filter.to_findings_filter()

    counts = count_findings(sess, server.id, findings_filter)

    findings_list: list[Any] = []
    groups: list[PackageGroup] = []
    diff: DiffSection | None = None

    if view_filter.mode == "list":
        findings_list = list_findings(
            sess,
            server.id,
            findings_filter,
            sort=view_filter.sort,
            dir=view_filter.dir,
        )
    elif view_filter.mode == "group":
        groups = group_findings_by_package(sess, server.id, findings_filter)
    else:  # diff
        diff = compute_diff(sess, server.id)

    return {
        "server": server,
        "view_filter": view_filter,
        "counts": counts,
        "findings": findings_list,
        "groups": groups,
        "diff": diff,
        "ack_form": AcknowledgeForm(),
        "reopen_form": ReopenForm(),
        "note_form": NoteForm(),
        "group_ack_form": GroupAcknowledgeForm(),
        "bulk_form": BulkActionForm(),
        "csrf_form": CSRFOnlyForm(),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@server_detail_bp.get("/<int:server_id>")
@login_required
def show(server_id: int) -> Any:
    server = _load_server_with_tags(server_id)
    if server is None:
        abort(404)

    view_filter = FindingsViewFilter.from_request(
        request.args,
        user_default_severity=get_settings_row().severity_threshold,
    )
    section_ctx = _render_findings_section(server, view_filter)

    # Block K (ADR-0018): Header-Stats und Trend-Daten aufsammeln. Alle
    # Aggregations-Calls fuehren je 1 SELECT aus — der Detail-Render bleibt
    # auch bei ~10k Findings unter den ADR-Zielwerten (siehe Performance-
    # Bekannte-Limitation).
    sess = get_session()
    tendency: Tendency = compute_tendency(sess, server.id)
    sparklines: dict[str, list[int]] = severity_snapshots_for_server(sess, server.id, days=50)
    trend_data: list[DailySeverityCount] = daily_severity_counts_for_server(
        sess, server.id, days=50
    )
    kev_events_50d: int = count_kev_events_50d(sess, server.id)
    heartbeat_cells: list[DailyStatus] = heartbeats_for_servers(sess, [server.id], days=50)[
        server.id
    ]
    quick_counts = _quick_counts_for_server(sess, server.id)

    # Block I: `active_server_id` markiert die Sidebar-Zeile, `hx_partial`
    # entscheidet zwischen Vollseite (`base_app.html`) und Fragment-Shell
    # (`_partial_shell.html`).
    is_hx = request.headers.get("HX-Request") == "true"
    return render_template(
        "servers/detail.html",
        available_tags=_all_tags(),
        add_form=CSRFOnlyForm(),
        remove_form=CSRFOnlyForm(),
        active_server_id=server.id,
        hx_partial=is_hx,
        tendency=tendency,
        sparklines=sparklines,
        trend_data=trend_data,
        kev_events_50d=kev_events_50d,
        heartbeat_cells=heartbeat_cells,
        quick_counts=quick_counts,
        **section_ctx,
    )


def _quick_counts_for_server(sess: Any, server_id: int) -> dict[str, int]:
    """Liefert OPEN-Counts pro Severity + KEV + Total fuer die KPI-Kacheln.

    Eine einzige aggregierte Query mit `FILTER (WHERE …)`-Clauses, analog zu
    `quick_stats.get_quick_stats()` — aber Server-scoped statt Tag-gefiltert.
    """
    is_open = Finding.status == FindingStatus.OPEN
    stmt = select(
        func.count().filter(is_open).label("total_open"),
        func.count().filter(is_open, Finding.is_kev.is_(True)).label("kev_open"),
        func.count().filter(is_open, Finding.severity == Severity.CRITICAL).label("critical_open"),
        func.count().filter(is_open, Finding.severity == Severity.HIGH).label("high_open"),
        func.count().filter(is_open, Finding.severity == Severity.MEDIUM).label("medium_open"),
        func.count().filter(is_open, Finding.severity == Severity.LOW).label("low_open"),
    ).where(Finding.server_id == server_id)
    row = sess.execute(stmt).one()
    return {
        "total_open": int(row.total_open or 0),
        "kev_open": int(row.kev_open or 0),
        "critical_open": int(row.critical_open or 0),
        "high_open": int(row.high_open or 0),
        "medium_open": int(row.medium_open or 0),
        "low_open": int(row.low_open or 0),
    }


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
