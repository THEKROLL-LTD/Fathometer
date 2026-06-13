# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Per-`(server, group)`-Routen fuer die agentische Upstream-Update-Suche.

Block AI-2, ADR-0063 §UI/UX. Zwei Browser-facing Routen (Login-Pflicht,
``flask-limiter``), beide gegen denselben 404-Guard wie der Per-Group-Chat
(:func:`app.api.group_chat._guard_or_404`): aktiver Server UND Group mit
OPEN-Findings auf genau diesem Server — Cross-Server-/Cross-Group-IDOR-Schutz.

- ``POST /servers/<sid>/groups/<gid>/upstream-check`` (CSRF, ``10/minute``):
  stoesst den Check an. Gate: :func:`is_upstream_check_configured` — ist das
  Feature nicht konfiguriert, ``409`` + ``disabled``-Partial (kein Enqueue).
  Das zu pruefende Finding wird **server-seitig** als Worst-Finding der
  ``upstream``-Lane dieser ``(sid, gid)`` ermittelt (NIE per Client-
  ``finding_id`` — IDOR/Tampering). Kein upstream-Finding -> ``idle``-Partial.
  ``enqueue_upstream_check(..., force=<form/query>)``; commit; das Status-
  Partial der Zeile zurueck.

- ``GET /servers/<sid>/groups/<gid>/upstream-check`` (kein CSRF, ``120/minute``):
  Poll-Endpoint. Ermittelt denselben State (Worst-Upstream-Finding -> Seed ->
  Cache-Zeile) und rendert dasselbe Status-Partial.

**Beratend, nie Band-flippend (ADR-0063 §Leitplanken).** Diese Routen schreiben
NIE ``Finding.risk_band``/``fix_lane`` — nur (via Enqueue-Service) die
``upstream_check_results``-Zeile.

**Untrusted Output.** Das Verdikt (LLM/Web) wird im Template (P2) ueber nh3
sanitisiert gerendert — hier nur strukturierte Weitergabe, keine HTML-Erzeugung.
"""

from __future__ import annotations

from typing import Any

import structlog
from flask import Blueprint, render_template, request
from flask_login import login_required
from sqlalchemy.exc import IntegrityError

from app import limiter
from app.api.group_chat import _guard_or_404
from app.db import get_session
from app.forms import CSRFOnlyForm
from app.services.upstream_check_enqueue import enqueue_upstream_check
from app.services.upstream_check_state import (
    UpstreamCheckState,
    derive_state,
    lookup_state_for_group,
    worst_upstream_finding,
)
from app.services.upstream_research import is_upstream_check_configured
from app.services.upstream_seed import build_research_seed
from app.settings_service import get_settings_row

log = structlog.get_logger(__name__)

upstream_check_bp = Blueprint(
    "upstream_check",
    __name__,
    url_prefix="/servers/<int:sid>/groups/<int:gid>/upstream-check",
)

#: Template-Name, den P2 (frontend-implementer) anlegt + fuellt. Single-Source-
#: Partial fuer Initial-Render (escalate-mitigate-Card, ADR-0064) UND Poll-/POST-Response.
UPSTREAM_CHECK_PANEL_TEMPLATE = "servers/_partials/upstream_check_panel.html"


def _truthy(value: str | None) -> bool:
    """Form-/Query-Flag-Parsing (``force``): ``1``/``true``/``yes``/``on``."""
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _render_panel(state: UpstreamCheckState, sid: int, gid: int) -> str:
    """Rendert das Status-Partial fuer eine ``(server, group)`` (P2-Template).

    Template-Variablen-Vertrag fuer :data:`UPSTREAM_CHECK_PANEL_TEMPLATE`
    (frontend-implementer, P2):

      - ``state``: str — einer von ``disabled``/``idle``/``running``/``done``/
        ``cached`` (``app.services.upstream_check_state.STATE_*``). Bestimmt das
        Markup; das HTMX-Poll-Attribut (``hx-get`` auf den GET-Endpoint,
        ``hx-trigger="load delay:...``) wird **nur** im ``running``-State gesetzt.
      - ``row``: ``UpstreamCheckResult | None`` — Verdikt-Felder (``delivery``,
        ``fixed_build_release``, ``fixed_build_release_date``, ``operator_action``,
        ``confidence``, ``sources_used``, ``reasoning``, ``error``,
        ``latest_release_component_version``). **Untrusted** Web-/LLM-Output ->
        ueber nh3 sanitisieren, KEIN ``|safe``.
      - ``seed``: ``ResearchSeed | None`` — Anzeige-Kontext (``artifact_module``,
        ``installed_component_version``, ``vulnerable_component``,
        ``fixing_component_version``, ``cve``).
      - ``checked_age``: ``timedelta | None`` — fuer „checked <relative> ago".
      - ``is_fresh``: bool — frisches Verdikt innerhalb der TTL (``cached``).
      - ``sid`` / ``gid``: ints fuer ``url_for`` der POST-/GET-Endpoints
        (``upstream_check.enqueue`` / ``upstream_check.poll``).
      - ``csrf_form``: CSRFOnlyForm — CSRF-Token fuer den POST-(Re-)Check-Button.
    """
    return render_template(
        UPSTREAM_CHECK_PANEL_TEMPLATE,
        state=state.state,
        row=state.row,
        seed=state.seed,
        checked_age=state.checked_age,
        is_fresh=state.is_fresh,
        sid=sid,
        gid=gid,
        csrf_form=CSRFOnlyForm(),
    )


@upstream_check_bp.post("")
@login_required
@limiter.limit("10/minute")
def enqueue(sid: int, gid: int) -> Any:
    """POST — stoesst den Upstream-Check fuer das researchbare Finding der Group an.

    Gate -> schlimmstes researchbares (has-fix lang-pkgs, mitigate-Lane) Finding
    (server-seitig, ADR-0064) -> Enqueue -> Status-Partial.
    """
    _guard_or_404(sid, gid)
    sess = get_session()
    settings_row = get_settings_row(sess)

    if not is_upstream_check_configured(settings_row):
        # Feature nicht konfiguriert -> kein Enqueue, disabled-Partial mit 409.
        state = derive_state(None, None, configured=False)
        return _render_panel(state, sid, gid), 409

    finding = worst_upstream_finding(sess, sid, gid)
    if finding is None:
        # Kein researchbares (has-fix lang-pkgs) Finding -> leerer State, kein Enqueue.
        state = derive_state(None, None, configured=True)
        return _render_panel(state, sid, gid), 404

    force = _truthy(request.form.get("force") or request.args.get("force"))
    try:
        row = enqueue_upstream_check(sess, finding, force=force)
        sess.commit()
    except IntegrityError:
        # Der Enqueue-Service ist race-sicher (Savepoint-Reselect); faellt der
        # aeussere Commit dennoch wegen eines Parallel-Enqueues -> 409 statt 500.
        sess.rollback()
        log.info("upstream_check.enqueue_commit_conflict", sid=sid, gid=gid)
        state = lookup_state_for_group(sess, sid, gid, configured=True)
        return _render_panel(state, sid, gid), 409

    if row is None:
        # build_research_seed lieferte None (Finding doch nicht researchbar) ->
        # idle. Sollte nach dem researchbar-Filter praktisch nicht passieren.
        state = derive_state(None, None, configured=True)
        return _render_panel(state, sid, gid)

    seed = build_research_seed(finding)
    state = derive_state(row, seed, configured=True)
    return _render_panel(state, sid, gid)


@upstream_check_bp.get("")
@login_required
@limiter.limit("120/minute")
def poll(sid: int, gid: int) -> str:
    """GET — Poll-Endpoint: aktueller State der ``(server, group)`` als Partial.

    Ermittelt dieselbe ``(artifact_module, installed_version)`` (Worst-Upstream-
    Finding -> Seed), laedt die Cache-Zeile und rendert das Status-Partial. Das
    HTMX-Poll-Attribut wird vom Template nur im ``running``-State gesetzt — der
    Poll stoppt von selbst sobald ``done``/``cached`` erreicht ist.
    """
    _guard_or_404(sid, gid)
    sess = get_session()
    settings_row = get_settings_row(sess)
    configured = is_upstream_check_configured(settings_row)
    state = lookup_state_for_group(sess, sid, gid, configured=configured)
    return _render_panel(state, sid, gid)


__all__ = ["UPSTREAM_CHECK_PANEL_TEMPLATE", "upstream_check_bp"]
