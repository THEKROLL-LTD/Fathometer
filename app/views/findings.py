# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Findings-Routen (Block E + ADR-0037 Bucket-View).

ARCHITECTURE.md §6 (Endpoints) und §13 (Audit-Actions).

Routen:

- `GET  /findings`                       — Bucket-View Outer-Page (ADR-0037 §(2)).
- `GET  /findings/bucket`                — Lazy-Fragment fuer einen Bucket-Body.
- `GET  /findings/pending`               — Lazy-Fragment fuer Pending-Sammler.
- `POST /findings/bulk/acknowledge`      — Bulk-Ack mit Bucket+Finding-Mix
                                          (ADR-0037 §(4)).
- `POST /findings/<id>/acknowledge`      — Einzel-Acknowledge (Block E).
- `POST /findings/<id>/reopen`           — Reopen (Block E).
- `POST /findings/<id>/notes`            — Note hinzufuegen (Block E).
- `POST /findings/<id>/notes/<note_id>/delete` — Soft-Delete einer Notiz.
- `POST /findings/group/acknowledge`     — Group-Ack pro Paket (Block E).
- `GET  /findings/export.csv`            — CSV-Export (ADR-0020, unveraendert).

ADR-0006: Kommentare sind in der gesamten UI optional. Wir nutzen
`AcknowledgeForm`/`ReopenForm`/`GroupAcknowledgeForm` ohne
`InputRequired`/`DataRequired` auf den Comment-Feldern. Der Bulk-Endpoint
`POST /findings/bulk/acknowledge` erzwingt ebenfalls keinen Kommentar.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl

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
from flask_wtf.csrf import CSRFError, validate_csrf
from sqlalchemy import func, select, update
from sqlalchemy.orm import selectinload
from werkzeug.datastructures import MultiDict
from werkzeug.wrappers import Response as WerkzeugResponse

from app.audit import log_event
from app.db import get_session
from app.forms import (
    AcknowledgeForm,
    BulkActionForm,
    CSRFOnlyForm,
    GroupAcknowledgeForm,
    NoteForm,
    ReopenForm,
)
from app.models import (
    ApplicationGroup,
    Finding,
    FindingNote,
    FindingStatus,
    Server,
    Tag,
)
from app.schemas.dashboard_filter import DashboardFilter
from app.schemas.findings_view_filter import FindingsViewFilter
from app.services.csv_export import (
    stream_findings_csv,
    stream_findings_csv_cross_server,
)
from app.services.findings_bucket_query import (
    BucketHeader,
    group_bucket_findings_by_lane,
    list_bucket_findings,
    list_buckets,
    pending_bucket_header,
    resolve_bucket_to_finding_ids,
)
from app.services.pass2_enqueue import enqueue_pass2_for_server
from app.settings_service import get_settings_row

log = structlog.get_logger(__name__)

findings_bp = Blueprint("findings", __name__, url_prefix="/findings")


# ---------------------------------------------------------------------------
# Index-Helper (ADR-0037, vormals Block Q / ADR-0025 §(5))
# ---------------------------------------------------------------------------


def _filter_is_active(filt: DashboardFilter) -> bool:
    """ADR-0037 §Entscheidung: Default-State der Bucket-View bleibt leer.

    Im Gegensatz zu `DashboardFilter.is_active` zaehlt hier `status != 'open'`
    ebenfalls als aktiv (User-explizite Status-Wahl). Sort/Dir entfallen
    (ADR-0037 §(5): Sort-Selector wird aus der Bucket-View entfernt).
    """
    return bool(
        filt.q
        or filt.tags
        or filt.severity is not None
        or filt.status != "open"
        or filt.risk_band is not None
        or filt.action_required is not None
        or filt.application_group_id is not None
        or filt.kev_only
        or filt.stale_only
    )


def _count_open_findings(sess: Any) -> int:
    """Billiger Aggregat-Count fuer den Empty-State-Block."""
    return int(
        sess.execute(
            select(func.count(Finding.id)).where(Finding.status == FindingStatus.OPEN)
        ).scalar()
        or 0
    )


def _count_active_servers(sess: Any) -> int:
    """Billiger Aggregat-Count: aktive Server (nicht revoked, nicht retired)."""
    return int(
        sess.execute(
            select(func.count(Server.id)).where(
                Server.revoked_at.is_(None),
                Server.retired_at.is_(None),
            )
        ).scalar()
        or 0
    )


# ---------------------------------------------------------------------------
# Filter-Querystring-Helper (ADR-0037 §(3))
# ---------------------------------------------------------------------------


def _filter_querystring_from_request(args: Any) -> str:
    """Kanonischer Filter-Querystring fuer Lazy-HTMX-URLs.

    Wir rekonstruieren `DashboardFilter` aus den Request-Args und serialisieren
    ihn zurueck via `to_query_string()`. Vorteil: Whitelist-Filterung der
    Felder, deterministische Schluessel-Reihenfolge, `page` taucht nicht auf
    (ist im Schema nicht definiert).
    """
    filt = DashboardFilter.from_request(args)
    return filt.to_query_string()


def _filter_from_querystring(qs: str) -> DashboardFilter:
    """Rekonstruiert einen `DashboardFilter` aus einem rohen Querystring.

    Wird vom Bulk-Acknowledge-Endpoint benoetigt: jede Bucket-Selektion
    fuehrt den eigenen Filter-Querystring mit, der serverseitig dieselbe
    `_apply_bucket_filters`-Klausel ergeben muss wie das Outer-Render der
    Bucket-Header (ADR-0037 §(3) — Filter-Konsistenz).
    """
    pairs = parse_qsl(qs or "", keep_blank_values=False)
    md: MultiDict[str, str] = MultiDict()
    for key, value in pairs:
        md.add(key, value)
    return DashboardFilter.from_request(md)


def _validate_bucket_id(raw: Any, *, allow_zero: bool = False) -> int:
    """Strikte Int-Validierung fuer Bucket-Routing-Parameter.

    `allow_zero=False` (Default): nur `>= 1`. `allow_zero=True`: `>= 0` —
    der Wert `0` ist die Service-Convention fuer "kein Server-/Group-Filter"
    bzw. Pending-Sammler (siehe `findings_bucket_query`).
    """
    if raw is None:
        abort(400, description="Parameter fehlt")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        abort(400, description="Parameter must be an integer")
    minimum = 0 if allow_zero else 1
    if value < minimum:
        abort(400, description="Parameter ausserhalb des erlaubten Bereichs")
    return value


# ---------------------------------------------------------------------------
# Index-Route — Bucket-View Outer-Page (ADR-0037 §(2))
# ---------------------------------------------------------------------------


@findings_bp.get("", strict_slashes=False)
@login_required
def index() -> str:
    """Cross-Server Bucket-View mit collapsed HTMX-Lazy-Cards.

    ADR-0037: Default-State ohne Filter rendert nur den Empty-State (keine
    Buckets). Erst nach Filter-Submit liefert der Service-Layer die Bucket-
    Header. Bucket-Bodies werden lazy via `/findings/bucket` bzw.
    `/findings/pending` nachgeladen — die Outer-Page selbst rendert nie
    Findings-Zeilen.
    """
    sess = get_session()
    filt = DashboardFilter.from_request(request.args)
    is_filtered = _filter_is_active(filt)

    buckets: list[BucketHeader] = []
    pending_bucket: BucketHeader | None = None
    if is_filtered:
        buckets = list_buckets(sess, filt)
        pending_bucket = pending_bucket_header(sess, filt)

    total_buckets = len(buckets) + (1 if pending_bucket is not None else 0)
    total_findings_in_buckets = sum(b.finding_count for b in buckets) + (
        pending_bucket.finding_count if pending_bucket is not None else 0
    )
    filter_qs = _filter_querystring_from_request(request.args)

    available_tags = list(sess.execute(select(Tag).order_by(Tag.name)).scalars().all())
    available_application_groups = list(
        sess.execute(select(ApplicationGroup).order_by(ApplicationGroup.label.asc()).limit(100))
        .scalars()
        .all()
    )

    total_findings = _count_open_findings(sess)
    visible_servers = _count_active_servers(sess)

    return render_template(
        "findings/index.html",
        hx_partial=_is_htmx_request(),
        filt=filt,
        # `view_filter`-Alias wird vom CSV-Export-Link im Index-Template
        # benoetigt (`view_filter.to_query_string()`); ansonsten teilen sich
        # `filt` und `view_filter` denselben `DashboardFilter`-Vertrag.
        view_filter=filt,
        buckets=buckets,
        pending_bucket=pending_bucket,
        total_buckets=total_buckets,
        total_findings_in_buckets=total_findings_in_buckets,
        filter_qs=filter_qs,
        is_filtered=is_filtered,
        total_findings=total_findings,
        visible_servers=visible_servers,
        available_tags=available_tags,
        available_application_groups=available_application_groups,
        bulk_form=BulkActionForm(),
        csrf_form=CSRFOnlyForm(),
    )


# ---------------------------------------------------------------------------
# Bucket-Fragment — Lazy-Body fuer aufgeklappte Bucket-Cards (ADR-0037 §(2))
# ---------------------------------------------------------------------------


@findings_bp.get("/bucket")
@login_required
def bucket_fragment() -> str:
    """Render-Endpoint fuer den Body eines einzelnen `(server_id, group_id)`-Buckets.

    Pflicht-Query-Params:
    - `server_id` (>=1) — der Bucket gehoert zu genau einem Server.
    - `group_id` (>=1) — `group_id=0` markiert Pending und hat einen eigenen
      Endpoint (`/findings/pending`); hier 400.

    Optional: `page` (>=1, Default 1) und der vollstaendige Filter-Querystring
    der Outer-Page (`q`, `tags`, `risk_band`, ...). Der Filter muss
    bit-genau identisch zu dem sein, mit dem `list_buckets()` den Header
    gerendert hat — sonst laufen Count und Inhalt auseinander.

    `total==0` -> 404 (Cross-ID-Probing-Schutz: ungueltige Bucket-Tuples
    duerfen keine 200er-Empty-Render-Antwort liefern).
    """
    sess = get_session()

    server_id = _validate_bucket_id(request.args.get("server_id"), allow_zero=False)
    group_id = _validate_bucket_id(request.args.get("group_id"), allow_zero=False)

    try:
        page_raw = int(request.args.get("page", "1"))
    except (TypeError, ValueError):
        page_raw = 1
    page = max(1, page_raw)
    per_page = 20

    filt = DashboardFilter.from_request(request.args)
    findings, total = list_bucket_findings(
        sess,
        server_id=server_id,
        group_id=group_id,
        filt=filt,
        page=page,
        per_page=per_page,
    )

    if total == 0:
        abort(404)

    # TICKET-016 / ADR-0065: Findings der Seite nach Fix-Lane gruppieren und je
    # Lane das Band + die volle Reason (Junction) voranstellen (Strategie a).
    lane_groups = group_bucket_findings_by_lane(
        sess,
        server_id=server_id,
        group_id=group_id,
        findings=findings,
    )

    filter_qs = _filter_querystring_from_request(request.args)

    return render_template(
        "_partials/bucket_findings_table.html",
        findings=findings,
        lane_groups=lane_groups,
        total=total,
        page=page,
        per_page=per_page,
        server_id=server_id,
        group_id=group_id,
        filt=filt,
        filter_qs=filter_qs,
        note_form=NoteForm(),
        csrf_form=CSRFOnlyForm(),
        ack_form=AcknowledgeForm(),
        reopen_form=ReopenForm(),
    )


# ---------------------------------------------------------------------------
# Pending-Fragment — Cross-Server-Sammler ohne Group (ADR-0037 §(2))
# ---------------------------------------------------------------------------


@findings_bp.get("/pending")
@login_required
def pending_fragment() -> str:
    """Render-Endpoint fuer den Pending-Bucket-Body.

    Cross-Server-Sammler (`application_group_id IS NULL`); die Server-Spalte
    bleibt in der Tabelle erhalten (siehe ADR-0037 §(2) — Operator muss
    erkennen koennen, woher das Finding kommt). `server_id=0` ist die
    Service-Convention "kein Server-Filter".
    """
    sess = get_session()

    try:
        page_raw = int(request.args.get("page", "1"))
    except (TypeError, ValueError):
        page_raw = 1
    page = max(1, page_raw)
    per_page = 20

    filt = DashboardFilter.from_request(request.args)
    findings, total = list_bucket_findings(
        sess,
        server_id=0,
        group_id=0,
        filt=filt,
        page=page,
        per_page=per_page,
    )

    filter_qs = _filter_querystring_from_request(request.args)

    return render_template(
        "_partials/pending_bucket_findings_table.html",
        findings=findings,
        total=total,
        page=page,
        per_page=per_page,
        filt=filt,
        filter_qs=filter_qs,
        note_form=NoteForm(),
        csrf_form=CSRFOnlyForm(),
        ack_form=AcknowledgeForm(),
        reopen_form=ReopenForm(),
    )


# ---------------------------------------------------------------------------
# Bulk-Acknowledge mit Bucket + Finding-Mix (ADR-0037 §(4))
# ---------------------------------------------------------------------------


def _parse_json_list(raw: str | None) -> list[Any]:
    """JSON-Liste defensiv parsen; bei Fehler 400.

    Leerer/fehlender Input -> leere Liste. Sonst muss `json.loads(...)` eine
    Liste liefern. Alles andere ist ein User- oder Frontend-Bug, kein
    Empty-Default — wir lassen 400 fliegen.
    """
    if raw is None or not raw.strip():
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        abort(400, description="JSON payload could not be parsed")
    if not isinstance(value, list):
        abort(400, description="JSON payload must be a list")
    return value


def _normalize_bucket_selections(raw: list[Any]) -> list[tuple[int, int, str]]:
    """Validiert die Bucket-Selektions-Tuples aus dem POST-Body.

    Erwartet `[{"server_id": int, "group_id": int, "filter": str}, ...]`.
    `server_id` und `group_id` muessen Integer >= 0 sein (0 ist erlaubt fuer
    Pending bzw. Cross-Server-Sammler). `filter` ist ein String (auch leer
    erlaubt — "kein Filter").
    """
    result: list[tuple[int, int, str]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            abort(400, description="Bucket-Selektion hat falsches Format")
        try:
            server_id = int(entry.get("server_id"))  # type: ignore[arg-type]
            group_id = int(entry.get("group_id"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            abort(400, description="Bucket-Selektion erfordert int-IDs")
        filter_qs_raw = entry.get("filter") or ""
        if not isinstance(filter_qs_raw, str):
            abort(400, description="Bucket-Selektion erwartet String-Filter")
        if server_id < 0 or group_id < 0:
            abort(400, description="Bucket IDs must be >= 0")
        result.append((server_id, group_id, filter_qs_raw))
    return result


def _normalize_finding_ids(raw: list[Any]) -> list[int]:
    """Validiert die expliziten Finding-IDs aus dem POST-Body."""
    result: list[int] = []
    for entry in raw:
        try:
            fid = int(entry)
        except (TypeError, ValueError):
            abort(400, description="finding_ids must be a list of integers")
        if fid < 1:
            abort(400, description="finding_ids must be >= 1")
        result.append(fid)
    return result


@findings_bp.post("/bulk/acknowledge")
@login_required
def bulk_acknowledge() -> WerkzeugResponse | str:
    """Bulk-Acknowledge mit Bucket-Selektionen + expliziten Finding-IDs.

    ADR-0037 §(4):

    - `bucket_selections` (JSON-String): Liste von `{server_id, group_id,
      filter}`. Server resolved via `resolve_bucket_to_finding_ids(...)` zur
      konkreten ID-Liste. `group_id=0` markiert Pending. Filter wird via
      `_filter_from_querystring` rekonstruiert — die Service-Logik nutzt
      denselben `_apply_bucket_filters`-Helper wie der Outer-Render der
      Bucket-Header, damit Count und Update-Set identisch bleiben.
    - `finding_ids` (JSON-String): explizite Liste.
    - `comment` (optional): wird ans Audit-Event gehaengt und (falls nicht
      leer) pro Finding als `FindingNote` mit `author='system-ack'`
      gespeichert (analog `group_acknowledge`).

    Idempotent: doppelte IDs aus Bucket+Explicit-Mix werden via `set()`
    dedupliziert. UPDATE-WHERE filtert zusaetzlich auf `status='OPEN'`, damit
    bereits acknowledged Findings nicht erneut Audit-getriggert werden.

    Audit: **ein** Event `finding.acknowledged.bulk` mit `metadata={
    finding_ids, bucket_count, explicit_count, comment?}`.
    """
    # CSRF haendisch validieren: der POST-Body ist Form-encoded (HTMX/Form-
    # Submit), wir akzeptieren das Token im `csrf_token`-Form-Field oder im
    # `X-CSRFToken`-Header.
    token = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRFToken")
        or request.headers.get("X-CSRF-Token")
    )
    try:
        validate_csrf(token)
    except CSRFError:
        abort(400, description="CSRF token invalid or missing")

    raw_buckets = _parse_json_list(request.form.get("bucket_selections"))
    raw_finding_ids = _parse_json_list(request.form.get("finding_ids"))
    bucket_selections = _normalize_bucket_selections(raw_buckets)
    explicit_ids = _normalize_finding_ids(raw_finding_ids)

    comment_raw = (request.form.get("comment") or "").strip()
    has_comment = bool(comment_raw)

    sess = get_session()

    # Bucket-Selektionen aufloesen.
    resolved: set[int] = set(explicit_ids)
    for server_id, group_id, qs in bucket_selections:
        sub_filt = _filter_from_querystring(qs)
        bucket_ids = resolve_bucket_to_finding_ids(
            sess,
            server_id=server_id,
            group_id=group_id,
            filt=sub_filt,
        )
        resolved.update(bucket_ids)

    final_ids = sorted(resolved)

    redirect_qs = _filter_querystring_from_request(request.args)
    redirect_target = url_for("findings.index")
    if redirect_qs:
        redirect_target = f"{redirect_target}?{redirect_qs}"

    if not final_ids:
        flash("No open findings selected.", "info")
        if _is_htmx_request():
            response = Response("", status=204)
            response.headers["HX-Redirect"] = redirect_target
            return response
        return redirect(redirect_target)

    now = datetime.now(tz=UTC)
    user_id_value = getattr(current_user, "id", None)
    user_id_int: int | None = int(user_id_value) if user_id_value is not None else None

    # TICKET-010 Etappe 4 (Vorbereitung): distinct server_ids der Findings,
    # die gleich wirklich von OPEN -> ACKNOWLEDGED wechseln. MUSS vor dem
    # UPDATE laufen — danach matcht der OPEN-Filter nicht mehr. Leeres Set
    # (z. B. alle bereits acknowledged) heisst spaeter: kein Enqueue.
    changed_server_ids: list[int] = list(
        sess.execute(
            select(Finding.server_id)
            .where(Finding.id.in_(final_ids), Finding.status == FindingStatus.OPEN)
            .distinct()
        )
        .scalars()
        .all()
    )

    # Idempotenz: nur OPEN-Findings wechseln. So bleibt ein Bucket+Finding-
    # Overlap (Header selektiert, Member nochmal manuell) ohne Doppel-Audit.
    sess.execute(
        update(Finding)
        .where(Finding.id.in_(final_ids), Finding.status == FindingStatus.OPEN)
        .values(
            status=FindingStatus.ACKNOWLEDGED,
            acknowledged_at=now,
            acknowledged_by=user_id_int,
        )
    )

    if has_comment:
        # Pro betroffenem Finding eine Note (analog `group_acknowledge`-
        # Pattern). Author `system-ack` ist Audit-geschuetzt (nicht loeschbar).
        for fid in final_ids:
            note = FindingNote(
                finding_id=fid,
                author="system-ack",
                author_user_id=user_id_int,
                text=comment_raw,
            )
            sess.add(note)
        sess.flush()

    metadata: dict[str, Any] = {
        "finding_ids": final_ids,
        "bucket_count": len(bucket_selections),
        "explicit_count": len(explicit_ids),
    }
    if has_comment:
        metadata["comment"] = comment_raw

    log_event(
        "finding.acknowledged.bulk",
        target_type="finding",
        target_id=None,
        comment=comment_raw if has_comment else None,
        metadata=metadata,
        session=sess,
    )

    # TICKET-010 Etappe 4: Triage-Aktion triggert das Pass-2-Re-Eval sofort —
    # ohne Sofort-Trigger passiert das Re-Eval erst beim naechsten Scan
    # (24-h-Luecke). Ein Aufruf pro betroffenem Server; wenn kein Finding
    # wirklich gewechselt hat, ist `changed_server_ids` leer -> kein Aufruf.
    for changed_server_id in changed_server_ids:
        enqueue_pass2_for_server(sess, changed_server_id, trigger="triage_action")

    sess.commit()

    if _is_htmx_request():
        response = Response("", status=204)
        response.headers["HX-Redirect"] = redirect_target
        return response
    return redirect(redirect_target, code=303)


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
        flash("Invalid input.", "error")
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

    # TICKET-010 Etappe 4: Vorher-Status merken — Ack auf ein bereits
    # acknowledged Finding aendert nichts und darf kein Re-Eval triggern.
    previous_status = finding.status

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

    # TICKET-010 Etappe 4: Triage-Aktion triggert das Pass-2-Re-Eval sofort —
    # ohne Sofort-Trigger passiert das Re-Eval erst beim naechsten Scan
    # (24-h-Luecke). Nur wenn der Status wirklich gewechselt hat (No-Op-Ack
    # darf nicht enqueuen); der Helper ist idempotent + fingerprint-gated.
    if previous_status != FindingStatus.ACKNOWLEDGED:
        enqueue_pass2_for_server(sess, finding.server_id, trigger="triage_action")

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
        flash("Invalid input.", "error")
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

    # TICKET-010 Etappe 4: Vorher-Status merken — Reopen auf ein bereits
    # offenes Finding aendert nichts und darf kein Re-Eval triggern.
    previous_status = finding.status

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

    # TICKET-010 Etappe 4: Triage-Aktion triggert das Pass-2-Re-Eval sofort —
    # ohne Sofort-Trigger passiert das Re-Eval erst beim naechsten Scan
    # (24-h-Luecke). Nur wenn der Status wirklich gewechselt hat (No-Op-
    # Reopen darf nicht enqueuen).
    if previous_status != FindingStatus.OPEN:
        enqueue_pass2_for_server(sess, finding.server_id, trigger="triage_action")

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
        flash("Note must not be empty.", "error")
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
        flash("Note must not be empty.", "error")
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
        flash("Invalid CSRF token.", "error")
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
        abort(403, description="System-generated notes cannot be deleted")

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
        flash("Invalid input.", "error")
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
        flash("No open findings found for this package.", "info")
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

    # TICKET-010 Etappe 4: Triage-Aktion triggert das Pass-2-Re-Eval sofort —
    # ohne Sofort-Trigger passiert das Re-Eval erst beim naechsten Scan
    # (24-h-Luecke). `affected_ids` ist hier garantiert nicht leer (Early-
    # Return oben), d. h. es hat wirklich mindestens ein Finding gewechselt.
    enqueue_pass2_for_server(sess, server_id, trigger="triage_action")

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


@findings_bp.get("/export.csv")
@login_required
def export_csv() -> Response:
    """Streamt die gefilterte Findings-Liste als CSV.

    Akzeptiert dieselben Query-Parameter wie `/servers/<id>` (Findings-
    View): `status`, `class`, `severity`, `kev_only`, `q`, `sort`, `dir`.
    Zusaetzlich `server_id` (optional) um den Export auf einen Server
    einzuschraenken — ohne `server_id` exportieren wir ueber die ganze
    Flotte.

    ADR-0025 / Block Q: die frueheren `?mode=`-Varianten (`flach`/
    `gruppiert`/`diff`) entfallen ersatzlos; der Export liefert immer die
    flache gefilterte Findings-Liste. Ein etwaiger `?mode=`-Param wird
    still ignoriert.

    Block Q (ADR-0025 §(5)) — Pagination/Export-Trennung: der Export
    ignoriert den `?page=N`-Param vollstaendig. Output entspricht immer dem
    aktiven Filter ueber alle Seiten (kein `offset`, kein page-bezogenes
    `limit`). `DashboardFilter.to_query_string()` emittiert `page` nicht,
    Templates referenzieren den CSV-Link daher mit dem reinen Filter-Query-
    String ohne `page`.
    """
    sess = get_session()

    server_id_raw = (request.args.get("server_id") or "").strip()
    server_id: int | None
    try:
        server_id = int(server_id_raw) if server_id_raw else None
    except ValueError:
        server_id = None

    # Block M (ADR-0020): Cross-Server-CSV-Export, wenn kein `server_id`
    # gegeben ist. Filter kommen aus `DashboardFilter`, nicht aus dem
    # Server-Detail-`FindingsViewFilter` (verschiedene Sort-Whitelists, q-
    # Semantik inkl. Server-Name, Status-Default `open` statt `all`).
    if server_id is None:
        dash_filt = DashboardFilter.from_request(request.args)
        log.info(
            "findings.csv_export",
            server_id=None,
            cross_server=True,
            q=dash_filt.q,
            status=dash_filt.status,
            kev_only=dash_filt.kev_only,
            stale_only=dash_filt.stale_only,
            sort=dash_filt.sort,
            dir=dash_filt.dir,
        )
        response = Response(
            stream_findings_csv_cross_server(
                sess,
                dash_filt,
                sort=dash_filt.sort,
                dir=dash_filt.dir,
            ),
            mimetype="text/csv; charset=utf-8",
        )
        response.headers["Content-Disposition"] = 'attachment; filename="findings.csv"'
        return response

    view_filter = FindingsViewFilter.from_request(
        request.args,
        user_default_severity=get_settings_row(sess).severity_threshold,
    )
    findings_filter = view_filter.to_findings_filter()

    log.info(
        "findings.csv_export",
        server_id=server_id,
        status=view_filter.status,
        kev_only=view_filter.kev_only,
        sort=view_filter.sort,
        dir=view_filter.dir,
    )

    response = Response(
        stream_findings_csv(
            sess,
            server_id=server_id,
            filter_obj=findings_filter,
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
