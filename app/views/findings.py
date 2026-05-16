"""Findings-Action-Routes (Block E).

ARCHITECTURE.md §6 (Endpoints) und §13 (Audit-Actions).

Routen:
- `POST /findings/<id>/acknowledge` — Status auf ACKNOWLEDGED, optionaler
  Comment landet als Note mit `author='system-ack'`.
- `POST /findings/<id>/reopen` — Status zurueck auf OPEN, optionaler
  Comment landet als Note mit `author='system-reopen'`.
- `POST /findings/<id>/notes` — neue Notiz im Thread (`author=<username>`).
- `POST /findings/<id>/notes/<note_id>/delete` — Soft-Delete einer Notiz
  (DELETE-Verb wird via Form-Method-Override emuliert, weil HTML-Forms
  kein DELETE koennen; wir akzeptieren POST).
- `POST /findings/group/acknowledge` — Bulk-Acknowledge aller OPEN-Findings
  eines Pakets pro Server. **Ein** Audit-Event mit Liste der betroffenen
  IDs.

ADR-0006: Kommentare sind in der gesamten UI optional. Wir nutzen
`AcknowledgeForm`/`ReopenForm`/`GroupAcknowledgeForm` ohne
`InputRequired`/`DataRequired` auf den Comment-Feldern.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload
from werkzeug.wrappers import Response as WerkzeugResponse

from app.audit import log_event
from app.db import get_session
from app.forms import AcknowledgeForm, CSRFOnlyForm, GroupAcknowledgeForm, NoteForm, ReopenForm
from app.models import Finding, FindingNote, FindingStatus
from app.schemas.findings_view_filter import FindingsViewFilter
from app.services.csv_export import CsvExportMode, stream_findings_csv

log = structlog.get_logger(__name__)

findings_bp = Blueprint("findings", __name__, url_prefix="/findings")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_finding(finding_id: int) -> Finding | None:
    sess = get_session()
    stmt = select(Finding).options(selectinload(Finding.notes)).where(Finding.id == finding_id)
    return sess.execute(stmt).scalar_one_or_none()


def _current_username() -> str:
    """Liefert den Username des eingeloggten Users (oder 'admin' als Fallback).

    `login_required` stellt sicher, dass `current_user` authenticated ist —
    der Fallback ist nur fuer Type-Safety da.
    """
    return str(getattr(current_user, "username", "admin"))


def _back_url(finding: Finding) -> str:
    """Redirect-Ziel nach einer Action: zurueck zur Server-Detail-Seite."""
    return url_for("server_detail.show", server_id=finding.server_id)


def _is_htmx_request() -> bool:
    return request.headers.get("HX-Request") == "true"


# ---------------------------------------------------------------------------
# Acknowledge
# ---------------------------------------------------------------------------


@findings_bp.post("/<int:finding_id>/acknowledge")
@login_required
def acknowledge(finding_id: int) -> WerkzeugResponse | str:
    form = AcknowledgeForm()
    if not form.validate_on_submit():
        flash("Ungueltige Eingabe.", "error")
        finding = _load_finding(finding_id)
        if finding is None:
            abort(404)
        return redirect(_back_url(finding))

    finding = _load_finding(finding_id)
    if finding is None:
        abort(404)

    sess = get_session()
    now = datetime.now(tz=UTC)

    comment_raw = (form.comment.data or "").strip()
    has_comment = bool(comment_raw)

    user_id_value = getattr(current_user, "id", None)
    user_id_int: int | None = int(user_id_value) if user_id_value is not None else None

    finding.status = FindingStatus.ACKNOWLEDGED
    finding.acknowledged_at = now
    finding.acknowledged_by = user_id_int

    note_id: int | None = None
    if has_comment:
        note = FindingNote(
            finding_id=finding.id,
            author="system-ack",
            author_user_id=user_id_int,
            text=comment_raw,
        )
        sess.add(note)
        sess.flush()
        note_id = note.id

    log_event(
        "finding.acknowledged",
        target_type="finding",
        target_id=finding.id,
        comment=comment_raw if has_comment else None,
        metadata={"has_comment": has_comment, "note_id": note_id},
        session=sess,
    )
    sess.commit()

    return _redirect_or_partial(finding)


# ---------------------------------------------------------------------------
# Reopen
# ---------------------------------------------------------------------------


@findings_bp.post("/<int:finding_id>/reopen")
@login_required
def reopen(finding_id: int) -> WerkzeugResponse | str:
    form = ReopenForm()
    if not form.validate_on_submit():
        flash("Ungueltige Eingabe.", "error")
        finding = _load_finding(finding_id)
        if finding is None:
            abort(404)
        return redirect(_back_url(finding))

    finding = _load_finding(finding_id)
    if finding is None:
        abort(404)

    sess = get_session()
    comment_raw = (form.comment.data or "").strip()
    has_comment = bool(comment_raw)
    user_id_value = getattr(current_user, "id", None)
    user_id_int: int | None = int(user_id_value) if user_id_value is not None else None

    finding.status = FindingStatus.OPEN
    finding.acknowledged_at = None
    finding.acknowledged_by = None

    note_id: int | None = None
    if has_comment:
        note = FindingNote(
            finding_id=finding.id,
            author="system-reopen",
            author_user_id=user_id_int,
            text=comment_raw,
        )
        sess.add(note)
        sess.flush()
        note_id = note.id

    log_event(
        "finding.reopened",
        target_type="finding",
        target_id=finding.id,
        comment=comment_raw if has_comment else None,
        metadata={"has_comment": has_comment, "note_id": note_id},
        session=sess,
    )
    sess.commit()

    return _redirect_or_partial(finding)


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


@findings_bp.post("/<int:finding_id>/notes")
@login_required
def add_note(finding_id: int) -> WerkzeugResponse | str:
    form = NoteForm()
    if not form.validate_on_submit():
        flash("Notiz darf nicht leer sein.", "error")
        finding = _load_finding(finding_id)
        if finding is None:
            abort(404)
        return redirect(_back_url(finding))

    finding = _load_finding(finding_id)
    if finding is None:
        abort(404)

    sess = get_session()
    body = (form.body.data or "").strip()
    if not body:
        flash("Notiz darf nicht leer sein.", "error")
        return redirect(_back_url(finding))

    user_id_value = getattr(current_user, "id", None)
    user_id_int: int | None = int(user_id_value) if user_id_value is not None else None

    note = FindingNote(
        finding_id=finding.id,
        author=_current_username(),
        author_user_id=user_id_int,
        text=body,
    )
    sess.add(note)
    sess.flush()

    log_event(
        "finding.note.added",
        target_type="finding",
        target_id=finding.id,
        metadata={"note_id": note.id},
        session=sess,
    )
    sess.commit()

    return _redirect_or_partial(finding)


@findings_bp.post("/<int:finding_id>/notes/<int:note_id>/delete")
@login_required
def delete_note(finding_id: int, note_id: int) -> WerkzeugResponse | str:
    csrf_form = CSRFOnlyForm()
    if not csrf_form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        return redirect(url_for("server_detail.show", server_id=0))

    finding = _load_finding(finding_id)
    if finding is None:
        abort(404)

    sess = get_session()
    note = sess.execute(
        select(FindingNote).where(FindingNote.id == note_id, FindingNote.finding_id == finding_id)
    ).scalar_one_or_none()
    if note is None:
        abort(404)

    actor = _current_username()

    # Authorization: System-generierte Notes (`system-ack`, `system-reopen`)
    # duerfen NIEMALS geloescht werden — sie sind Teil des Audit-Trails.
    # Hier 403 (mit klarer Meldung) statt 404, weil aus Audit-Sicht die
    # Information "dieser Endpoint hat System-Notes geschuetzt" wichtiger ist
    # als Existenz-Verschleierung.
    if note.author.startswith("system-"):
        log.warning(
            "finding.note.delete.unauthorized",
            actor=actor,
            note_id=note.id,
            note_author=note.author,
            reason="system_note",
        )
        abort(403, description="System-generierte Notes koennen nicht geloescht werden")

    # Fremde Note: 404 (defensiv — Existenz fremder Notes nicht enthuellen).
    if note.author != actor:
        log.warning(
            "finding.note.delete.unauthorized",
            actor=actor,
            note_id=note.id,
            note_author=note.author,
            reason="not_owner",
        )
        abort(404)

    if note.deleted_at is not None:
        # Schon weg — idempotent.
        return _redirect_or_partial(finding)

    note.deleted_at = datetime.now(tz=UTC)

    log_event(
        "finding.note.deleted",
        target_type="finding",
        target_id=finding.id,
        metadata={"note_id": note.id},
        session=sess,
    )
    sess.commit()

    return _redirect_or_partial(finding)


# ---------------------------------------------------------------------------
# Group-Acknowledge (Block-E Mini-Bulk pro Paket)
# ---------------------------------------------------------------------------


@findings_bp.post("/group/acknowledge")
@login_required
def group_acknowledge() -> WerkzeugResponse | str:
    """Markiert alle OPEN-Findings eines Pakets auf einem Server als acknowledged.

    Ein EINZIGER Audit-Event `finding.acknowledged.bulk` haelt die Liste der
    betroffenen Finding-IDs. Comment optional (ADR-0006).
    """
    form = GroupAcknowledgeForm()
    if not form.validate_on_submit():
        flash("Ungueltige Eingabe.", "error")
        return redirect(url_for("dashboard.index"))

    server_id_data = form.server_id.data
    if server_id_data is None:
        abort(400)
    server_id = int(server_id_data)
    package_name = (form.package_name.data or "").strip()
    comment_raw = (form.comment.data or "").strip()
    has_comment = bool(comment_raw)

    sess = get_session()
    user_id_value = getattr(current_user, "id", None)
    user_id_int: int | None = int(user_id_value) if user_id_value is not None else None

    # Betroffene OPEN-Findings sammeln (separate Query, damit wir die IDs in
    # das Audit-Metadata schreiben koennen).
    stmt = select(Finding).where(
        Finding.server_id == server_id,
        Finding.package_name == package_name,
        Finding.status == FindingStatus.OPEN,
    )
    affected = list(sess.execute(stmt).scalars().all())
    affected_ids = [f.id for f in affected]

    if not affected_ids:
        flash("Keine offenen Findings fuer dieses Paket gefunden.", "info")
        return redirect(url_for("server_detail.show", server_id=server_id))

    now = datetime.now(tz=UTC)
    sess.execute(
        update(Finding)
        .where(Finding.id.in_(affected_ids))
        .values(
            status=FindingStatus.ACKNOWLEDGED,
            acknowledged_at=now,
            acknowledged_by=user_id_int,
        )
    )

    note_ids: list[int] = []
    if has_comment:
        # Eine Notiz pro Finding — wenn der Operator einen Kommentar mitgibt,
        # taucht er im Thread jedes betroffenen Findings auf.
        for fid in affected_ids:
            note = FindingNote(
                finding_id=fid,
                author="system-ack",
                author_user_id=user_id_int,
                text=comment_raw,
            )
            sess.add(note)
        sess.flush()
        # IDs nachladen (selectinload-frei, direkt aus dem ID-Stream).
        new_notes = (
            sess.execute(
                select(FindingNote.id).where(
                    FindingNote.finding_id.in_(affected_ids),
                    FindingNote.author == "system-ack",
                    FindingNote.text == comment_raw,
                    FindingNote.created_at >= now,
                )
            )
            .scalars()
            .all()
        )
        note_ids = list(new_notes)

    log_event(
        "finding.acknowledged.bulk",
        target_type="server",
        target_id=server_id,
        comment=comment_raw if has_comment else None,
        metadata={
            "package_name": package_name,
            "count": len(affected_ids),
            "finding_ids": affected_ids,
            "note_ids": note_ids,
        },
        session=sess,
    )
    sess.commit()

    if _is_htmx_request():
        # Nach Bulk-Action neu rendern — wir reichen die Verantwortung an den
        # Server-Detail-Endpoint zurueck, indem wir auf den HX-Redirect-Header
        # setzen. Einfacher: 303-Redirect auf den Server-Detail-View.
        return redirect(url_for("server_detail.show", server_id=server_id), code=303)
    return redirect(url_for("server_detail.show", server_id=server_id))


# ---------------------------------------------------------------------------
# Findings-CSV-Export
# ---------------------------------------------------------------------------


_VALID_CSV_MODES: frozenset[str] = frozenset({"flach", "gruppiert", "diff"})


@findings_bp.get("/export.csv")
@login_required
def export_csv() -> Response:
    """Streamt die gefilterte Findings-Liste als CSV.

    Akzeptiert dieselben Query-Parameter wie `/servers/<id>` (Findings-
    View): `status`, `class`, `severity`, `kev_only`, `q`, `sort`, `dir`.
    Zusaetzlich `server_id` (optional) um den Export auf einen Server
    einzuschraenken — ohne `server_id` exportieren wir ueber die ganze
    Flotte.

    `mode` (Block K, ADR-0018):
      - `flach`     (Default) — flache Liste.
      - `gruppiert` — flache Liste plus Spalte `Group` (Paket-Name),
                      primaer nach Gruppe sortiert.
      - `diff`      — nur Diff-Findings (neu/resolved seit vorletztem
                      Scan) plus Spalte `DiffStatus`. Braucht `server_id`.
    """
    sess = get_session()
    view_filter = FindingsViewFilter.from_request(request.args)
    findings_filter = view_filter.to_findings_filter()

    server_id_raw = (request.args.get("server_id") or "").strip()
    server_id: int | None
    try:
        server_id = int(server_id_raw) if server_id_raw else None
    except ValueError:
        server_id = None

    mode_raw = (request.args.get("mode") or "flach").strip().lower()
    # `mode` aus dem FindingsViewFilter ist "list/group/diff" (Block E) —
    # der CSV-Endpoint nutzt seine eigene Whitelist mit deutschen Werten,
    # damit die URL der UI-Buttons (flach/gruppiert/diff) 1:1 erhalten
    # bleibt. Ungueltige Werte fallen leise auf `flach` zurueck.
    if mode_raw not in _VALID_CSV_MODES:
        mode_raw = "flach"
    mode: CsvExportMode = mode_raw  # type: ignore[assignment]

    log.info(
        "findings.csv_export",
        server_id=server_id,
        status=view_filter.status,
        kev_only=view_filter.kev_only,
        mode=mode,
        sort=view_filter.sort,
        dir=view_filter.dir,
    )

    response = Response(
        stream_findings_csv(
            sess,
            server_id=server_id,
            filter_obj=findings_filter,
            mode=mode,
            sort=view_filter.sort,
            dir=view_filter.dir,
        ),
        mimetype="text/csv; charset=utf-8",
    )
    response.headers["Content-Disposition"] = 'attachment; filename="findings.csv"'
    return response


# ---------------------------------------------------------------------------
# Render-/Redirect-Helper
# ---------------------------------------------------------------------------


def _redirect_or_partial(finding: Finding) -> WerkzeugResponse | str:
    """Nach einer Action: bei HTMX nur das Notes-Fragment, sonst Redirect."""
    if _is_htmx_request():
        # Notes neu laden — die Session hat schon einen aktualisierten Stand.
        sess = get_session()
        refreshed = sess.execute(
            select(Finding).options(selectinload(Finding.notes)).where(Finding.id == finding.id)
        ).scalar_one_or_none()
        if refreshed is None:
            abort(404)
        return _render_notes_thread(refreshed)
    return redirect(_back_url(finding))


def _render_notes_thread(finding: Finding) -> str:
    return render_template(
        "findings/_notes_thread.html",
        finding=finding,
        note_form=NoteForm(),
        csrf_form=CSRFOnlyForm(),
    )


# ---------------------------------------------------------------------------
# Unused-Import-Suppression
# ---------------------------------------------------------------------------


# `Any` wird hier indirekt gehalten — Flask-Decorators erwarten manchmal
# kompatible Rueckgaben. Wir behalten den Import fuer Klarheit.
_ = Any


__all__ = ["findings_bp"]
