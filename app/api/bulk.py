"""`POST /api/findings/bulk-acknowledge` — zwei-Phasen-Bulk-Acknowledge.

ARCHITECTURE.md §6 (Endpoint), §13 (Audit-Action `finding.bulk_acknowledged`).

Zwei Flavors:

- **Flavor A**: explizite `finding_ids`-Liste. Wirkt auf genau diese IDs
  (typischer Caller: Checkbox-Auswahl im Server-Detail-View).
- **Flavor B**: `match`-Kriterium mit `cve_id`/`package_name`, optionalem
  Tag- und Status-Filter. Wirkt ueber die gesamte Flotte (typischer Caller:
  globale Suche, "Alle Vorkommen abhaken").

Zwei-Phasen:

- `dry_run=true` (Default): nur Vorschau — kein DB-Write. Antwort enthaelt
  `count`, `server_count`, `finding_ids`.
- `dry_run=false`: fuehrt das Acknowledge aus. Schreibt **einen** Audit-
  Event mit allen betroffenen IDs in `metadata`. Wenn `comment` mitgegeben
  wurde, wird er pro betroffenem Finding als `FindingNote` mit
  `author='system-bulk-ack'` angehaengt.

Auth: `login_required`. CSRF: das ist ein **JSON-Endpoint hinter Browser-
Auth**, der CSRF-Schutz darf NICHT ausgeschaltet werden — Flask-WTF
akzeptiert das CSRF-Token im `X-CSRFToken`-Header (HTMX und Alpine senden
das automatisch wenn das `csrf_token()`-Tag im Layout liegt).

Rate-Limit: 30/Minute pro IP — Bulk-Actions sind teurer und wir wollen
nicht dass ein hijackter Tab in Endlos-Iteration die Flotte ack't.

Package-Match-Semantik (ADR-0011): wenn `package_name` keinen `@` enthaelt,
matchen wir `package_name LIKE '<name>@%'` ODER exakter Match — das deckt
sowohl die alten Datensaetze ohne Target-Disambiguation als auch die neuen
mit `pkg@target` ab. Wenn `package_name` einen `@` enthaelt, machen wir
exakten Match.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from flask import jsonify, request
from flask_login import current_user, login_required
from pydantic import ValidationError
from sqlalchemy import func, insert, or_, select, update
from werkzeug.wrappers import Response

from app import limiter
from app.api import api_bp
from app.api._common import format_pydantic_errors, json_error
from app.audit import log_event
from app.db import get_session
from app.models import (
    Finding,
    FindingNote,
    FindingStatus,
    Server,
    ServerTag,
    Tag,
)
from app.schemas.bulk_request import (
    BulkAckMatchCriterion,
    BulkAckRequest,
    BulkAckServerScope,
)

# Maximale Anzahl IDs in `metadata.finding_ids` (ADR-0044 §(4); Praezedenz
# llm_worker.py). `metadata.count` traegt immer die volle Zahl.
_AUDIT_FINDING_IDS_CAP = 50

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Query-Builder
# ---------------------------------------------------------------------------


_STATUS_ENUM_BY_FILTER: dict[str, FindingStatus] = {
    "open": FindingStatus.OPEN,
    "acknowledged": FindingStatus.ACKNOWLEDGED,
    "resolved": FindingStatus.RESOLVED,
}


def _build_match_query(match: BulkAckMatchCriterion) -> Any:
    """Baut die SELECT-Query fuer Flavor B (Match-Kriterium).

    - `cve_id` wird gegen `identifier_key` gematcht (exakter Match).
    - `package_name` ohne `@` -> exakter Match ODER Prefix-LIKE auf
      `<name>@%` (ADR-0011-Disambiguation). Mit `@` -> exakter Match.
    - `tag` -> Subquery: nur Findings auf Servern, die das Tag tragen.
    - `status` -> direkter Filter.
    """
    stmt = select(Finding).where(Finding.status == _STATUS_ENUM_BY_FILTER[match.status])

    if match.cve_id is not None:
        stmt = stmt.where(Finding.identifier_key == match.cve_id)

    if match.package_name is not None:
        pkg = match.package_name.strip()
        if "@" in pkg:
            stmt = stmt.where(Finding.package_name == pkg)
        else:
            # Exakter Match (alte Daten ohne Target) ODER mit Target-Suffix.
            stmt = stmt.where(
                or_(
                    Finding.package_name == pkg,
                    Finding.package_name.like(f"{pkg}@%"),
                )
            )

    if match.tag is not None:
        tag_name = match.tag.strip().lower()
        # Subquery: server_ids mit diesem Tag.
        server_ids_sq = (
            select(ServerTag.server_id)
            .join(Tag, Tag.id == ServerTag.tag_id)
            .where(Tag.name == tag_name)
            .scalar_subquery()
        )
        stmt = stmt.where(Finding.server_id.in_(server_ids_sq))

    return stmt


def _build_ids_query(finding_ids: list[int]) -> Any:
    """Baut die SELECT-Query fuer Flavor A (explizite ID-Liste).

    Beachte: wir filtern nicht auf `status=OPEN`, sondern liefern alle IDs
    zurueck — der Apply-Pfad ignoriert anschliessend Findings die nicht im
    OPEN-Status sind (skipped). So bleibt der dry-run-`count` ehrlich zur
    User-Auswahl, und der Apply-Pfad reportet den `skipped`-Anteil.
    """
    return select(Finding).where(Finding.id.in_(finding_ids))


def _build_server_scope_query(scope: BulkAckServerScope) -> Any:
    """Baut die SELECT-Query fuer Flavor C (server-scoped Per-Band).

    Wirkt ausschliesslich auf offene Findings genau dieses Servers und
    Bands. **Kein** `.limit()` — der Scope ist die Begrenzung (ADR-0044
    §Entscheidung (1)).
    """
    return select(Finding).where(
        Finding.server_id == scope.server_id,
        Finding.status == FindingStatus.OPEN,
        Finding.risk_band == scope.risk_band,
    )


def _active_server_guard(sess: Any, server_id: int) -> Response | None:
    """JSON-404-Guard fuer Flavor C: aktiver Server oder `server_not_found`.

    Nachbau der HTML-Guard-Logik aus `server_detail._load_active_server_or_404`
    (existiert, revoked_at IS NULL, retired_at IS NULL), aber als JSON-Antwort
    statt `abort(404)` — dieser Endpoint ist ein JSON-Endpoint. Gibt `None`
    zurueck wenn der Server aktiv ist, sonst die fertige Fehler-Antwort.
    """
    row = sess.execute(
        select(Server.id).where(
            Server.id == server_id,
            Server.revoked_at.is_(None),
            Server.retired_at.is_(None),
        )
    ).first()
    if row is None:
        return json_error(
            404,
            "server_not_found",
            "Server existiert nicht oder ist revoked/retired",
        )
    return None


def _insert_bulk_notes(
    sess: Any,
    finding_ids: list[int],
    comment_text: str,
    user_id_int: int | None,
    now: datetime,
) -> list[int]:
    """Haengt `comment_text` als EINE Bulk-Insert-Operation an alle Findings.

    Statt N-fach `sess.add` (ADR-0044 §(4)) — bei tausenden Findings sonst
    tausende Einzel-Statements. Gibt die neu erzeugten Note-IDs zurueck.
    """
    if not finding_ids:
        return []
    rows = [
        {
            "finding_id": fid,
            "author": "system-bulk-ack",
            "author_user_id": user_id_int,
            "text": comment_text,
        }
        for fid in finding_ids
    ]
    sess.execute(insert(FindingNote), rows)
    sess.flush()
    new_notes = (
        sess.execute(
            select(FindingNote.id).where(
                FindingNote.finding_id.in_(finding_ids),
                FindingNote.author == "system-bulk-ack",
                FindingNote.text == comment_text,
                FindingNote.created_at >= now,
            )
        )
        .scalars()
        .all()
    )
    return list(new_notes)


def _ack_rate_limit() -> str:
    """30 Bulk-Acks pro Minute und IP — bewusst eng."""
    return "30/minute"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@api_bp.post("/findings/bulk-acknowledge")
@login_required
@limiter.limit(_ack_rate_limit)
def bulk_acknowledge() -> Response | tuple[Response, int]:
    """Zwei-Phasen-Bulk-Acknowledge. JSON in, JSON out."""

    if not request.is_json:
        return json_error(400, "bad_content_type", "Content-Type muss application/json sein")

    raw = request.get_json(silent=True)
    if not isinstance(raw, dict):
        return json_error(400, "bad_json", "JSON-Body muss ein Objekt sein")

    try:
        req = BulkAckRequest.model_validate(raw)
    except ValidationError as exc:
        return json_error(
            422,
            "validation_error",
            "Bulk-Ack-Request konnte nicht validiert werden",
            details=format_pydantic_errors(exc),
        )

    sess = get_session()

    # ---- Flavor C: server-scoped Per-Band (eigener Pfad, ADR-0044) ---------
    if req.server_scope is not None:
        return _handle_server_scope(sess, req, req.server_scope)

    # ---- Phase 1: Findings sammeln (gilt fuer dry_run und apply) -----------
    if req.finding_ids:
        stmt = _build_ids_query(req.finding_ids)
        match_meta: dict[str, Any] = {"finding_ids_input": len(req.finding_ids)}
    else:
        assert req.match is not None  # by validator
        stmt = _build_match_query(req.match)
        match_meta = {
            "cve_id": req.match.cve_id,
            "package_name": req.match.package_name,
            "tag": req.match.tag,
            "status": req.match.status,
        }

    # Subset: Findings (objekte) + IDs + distinct server_ids.
    findings: list[Finding] = list(sess.execute(stmt).scalars().all())

    finding_ids: list[int] = [f.id for f in findings]
    server_count = len({f.server_id for f in findings})

    # ---- Phase 2a: dry_run -> Vorschau zurueck ----------------------------
    if req.dry_run:
        log.info(
            "bulk_ack.dry_run",
            count=len(finding_ids),
            server_count=server_count,
            actor=getattr(current_user, "username", "unknown"),
        )
        return _ok(
            {
                "dry_run": True,
                "count": len(finding_ids),
                "server_count": server_count,
                "finding_ids": finding_ids,
            }
        )

    # ---- Phase 2b: Apply --------------------------------------------------
    if not finding_ids:
        # Nichts zu tun — wir loggen trotzdem einen leeren Audit-Event,
        # damit der Versuch sichtbar bleibt.
        log_event(
            "finding.bulk_acknowledged",
            target_type="finding",
            target_id=None,
            comment=req.clean_comment(),
            metadata={
                "count": 0,
                "server_count": 0,
                "finding_ids": [],
                "skipped": 0,
                "has_comment": req.has_comment,
                "match": match_meta,
            },
            session=sess,
        )
        sess.commit()
        return _ok(
            {
                "dry_run": False,
                "applied": True,
                "count": 0,
                "skipped": 0,
                "server_count": 0,
                "finding_ids": [],
            }
        )

    now = datetime.now(tz=UTC)
    user_id_value = getattr(current_user, "id", None)
    user_id_int: int | None = int(user_id_value) if user_id_value is not None else None

    # Nur OPEN-Findings werden gewechselt; ACK/RESOLVED bleiben unangetastet.
    open_ids = [f.id for f in findings if f.status == FindingStatus.OPEN]
    skipped = len(finding_ids) - len(open_ids)

    if open_ids:
        sess.execute(
            update(Finding)
            .where(Finding.id.in_(open_ids))
            .values(
                status=FindingStatus.ACKNOWLEDGED,
                acknowledged_at=now,
                acknowledged_by=user_id_int,
            )
        )

    comment_text = req.clean_comment()
    note_ids: list[int] = []
    if comment_text is not None and open_ids:
        note_ids = _insert_bulk_notes(sess, open_ids, comment_text, user_id_int, now)

    # EIN gemeinsamer Audit-Event. `finding_ids` ist auf die ersten 50 IDs
    # gecappt (ADR-0044 §(4)); `count` traegt die volle Zahl.
    log_event(
        "finding.bulk_acknowledged",
        target_type="finding",
        target_id=None,
        comment=comment_text,
        metadata={
            "count": len(open_ids),
            "server_count": len({f.server_id for f in findings if f.id in set(open_ids)}),
            "finding_ids": open_ids[:_AUDIT_FINDING_IDS_CAP],
            "skipped": skipped,
            "has_comment": comment_text is not None,
            "match": match_meta,
            "note_ids": note_ids,
        },
        session=sess,
    )
    sess.commit()

    log.info(
        "bulk_ack.applied",
        count=len(open_ids),
        skipped=skipped,
        server_count=len({f.server_id for f in findings if f.id in set(open_ids)}),
        actor=getattr(current_user, "username", "unknown"),
    )

    return _ok(
        {
            "dry_run": False,
            "applied": True,
            "count": len(open_ids),
            "skipped": skipped,
            "server_count": len({f.server_id for f in findings if f.id in set(open_ids)}),
            "finding_ids": open_ids,
        }
    )


def _ok(body: dict[str, Any]) -> Response:
    resp = jsonify(body)
    resp.status_code = 200
    return resp


def _handle_server_scope(sess: Any, req: BulkAckRequest, scope: BulkAckServerScope) -> Response:
    """Flavor-C-Pfad: server-scoped Per-Band-Bulk-Ack (ADR-0044).

    Resolved die Findings server-seitig ueber `(server_id, risk_band,
    status=OPEN)`. dry_run liefert `count` + `server_scope` (KEIN
    `finding_ids`-Array, KEINE `examples` — das Band-UI rendert den Count
    server-seitig, ADR-0044-Amendment). Apply fuehrt ein direktes UPDATE ueber
    den WHERE-Scope aus (keine ORM-Hydration) und liefert die betroffene Anzahl
    aus `result.rowcount`.
    """
    guard = _active_server_guard(sess, scope.server_id)
    if guard is not None:
        return guard

    actor = getattr(current_user, "username", "unknown")
    scope_echo = {"server_id": scope.server_id, "risk_band": scope.risk_band}

    # Single Source des WHERE-Scopes (server_id, status=OPEN, risk_band).
    # Count und der Note-ID-Scope leiten sich davon ab; das Apply-UPDATE traegt
    # denselben WHERE inline (klare SQL-Shape, kein Subquery).
    scope_subq = _build_server_scope_query(scope).with_only_columns(Finding.id).subquery()

    # ---- Phase 2a: dry_run -> echter COUNT --------------------------------
    if req.dry_run:
        count_stmt = select(func.count()).select_from(scope_subq)
        count = int(sess.execute(count_stmt).scalar_one())

        log.info(
            "bulk_ack.dry_run",
            count=count,
            server_count=1 if count else 0,
            scope_server_id=scope.server_id,
            scope_risk_band=scope.risk_band,
            actor=actor,
        )
        return _ok(
            {
                "dry_run": True,
                "count": count,
                "server_scope": scope_echo,
            }
        )

    # ---- Phase 2b: Apply --------------------------------------------------
    now = datetime.now(tz=UTC)
    user_id_value = getattr(current_user, "id", None)
    user_id_int: int | None = int(user_id_value) if user_id_value is not None else None

    comment_text = req.clean_comment()

    # IDs VOR dem UPDATE einsammeln (danach matcht der OPEN-Scope nicht mehr).
    # Schmale Projektion, keine ORM-Hydration. Das Audit-Event traegt IMMER bis
    # zu 50 betroffene `finding_ids` (TICKET-009 §52 / DoD 4/9), unabhaengig
    # vom Kommentar.
    #   - mit Kommentar: ALLE open-IDs (deterministisch sortiert) — wird fuer
    #     den Notes-Bulk-Insert gebraucht; fuers Audit `[:50]`.
    #   - ohne Kommentar: nur bis zu 50 IDs fuers Audit (deterministisch).
    open_ids: list[int] = []
    audit_finding_ids: list[int] = []
    id_scope = _build_server_scope_query(scope).with_only_columns(Finding.id).order_by(Finding.id)
    if comment_text is not None:
        open_ids = list(sess.execute(id_scope).scalars().all())
        audit_finding_ids = open_ids[:_AUDIT_FINDING_IDS_CAP]
    else:
        audit_finding_ids = list(
            sess.execute(id_scope.limit(_AUDIT_FINDING_IDS_CAP)).scalars().all()
        )

    result = sess.execute(
        update(Finding)
        .where(
            Finding.server_id == scope.server_id,
            Finding.status == FindingStatus.OPEN,
            Finding.risk_band == scope.risk_band,
        )
        .values(
            status=FindingStatus.ACKNOWLEDGED,
            acknowledged_at=now,
            acknowledged_by=user_id_int,
        )
    )
    count = int(result.rowcount or 0)

    note_ids: list[int] = []
    if comment_text is not None and open_ids:
        note_ids = _insert_bulk_notes(sess, open_ids, comment_text, user_id_int, now)

    log_event(
        "finding.bulk_acknowledged",
        target_type="finding",
        target_id=None,
        comment=comment_text,
        metadata={
            "count": count,
            "server_count": 1 if count else 0,
            "finding_ids": audit_finding_ids,
            "skipped": 0,
            "has_comment": comment_text is not None,
            "note_ids": note_ids,
            "server_scope": scope_echo,
        },
        session=sess,
    )
    sess.commit()

    log.info(
        "bulk_ack.applied",
        count=count,
        skipped=0,
        server_count=1 if count else 0,
        scope_server_id=scope.server_id,
        scope_risk_band=scope.risk_band,
        actor=actor,
    )

    return _ok(
        {
            "dry_run": False,
            "applied": True,
            "count": count,
            "server_scope": scope_echo,
        }
    )


# Aliases / type hints to keep ruff happy about the unused-ish imports.
_ = Server  # selectinload-Importe sind oben deklarativ; mypy ist zufrieden.

__all__ = ["bulk_acknowledge"]
