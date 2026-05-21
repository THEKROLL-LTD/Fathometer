"""Server-Detail-View `/servers/<id>` — Triage-Hauptansicht (Block E).

Erweitert den Block-D-Header um die Findings-Sektion im einzigen
verbleibenden View-Modus: Application-Group-Cards plus Pending-Grouping-
Sektion bzw. flache Tabelle bei aktivem Finding-Filter oder `?flat=1`.

ADR-0025 / Block Q: die frueheren View-Modi `gruppiert` und `diff` sind
ersatzlos entfallen; veraltete Bookmarks mit altem `mode`-Query-Param
werden still ignoriert.

URL-Filter (alle optional, Defaults sicher): `status`, `class`,
`severity`, `kev_only`, `q`, `risk_band`, `action_required`,
`application_group`, `sort`, `dir`, `flat`.

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
from app.models import (
    ApplicationGroup,
    Finding,
    FindingStatus,
    Server,
    ServerKernelModule,
    ServerListener,
    ServerProcess,
    ServerService,
    ServerTag,
    Severity,
    Tag,
)
from app.schemas.findings_view_filter import FindingsViewFilter
from app.services.findings_query import (
    count_findings,
    list_findings,
)
from app.services.heartbeat_aggregation import DailyStatus, heartbeats_for_servers
from app.services.risk_engine import RISK_BAND_SORT_RANK, RiskBand, no_band_values, yes_band_values
from app.services.severity_history import (
    DailySeverityCount,
    count_kev_events_50d,
    daily_severity_counts_for_server,
    severity_snapshots_for_server,
)
from app.services.trend import Tendency, compute_tendency
from app.settings_service import get_settings_row

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


def _load_application_groups_for_server(sess: Any, server_id: int) -> list[dict[str, Any]]:
    """Liefert die Application-Groups fuer den Server, sortiert nach Risk-Band.

    Block P (ADR-0023): Findings werden in der Server-Detail-Findings-Section
    nach `application_group_id` gruppiert. Wir laden:

      1. Alle Groups die mindestens ein OPEN-Finding auf dem Server haben.
      2. Pro Group: die OPEN-Findings, sortiert nach §15
         (KEV/EPSS/CVSS/Severity-Tiebreak).
      3. Falls `group.worst_finding_id` gesetzt: das Worst-Finding-Objekt.

    Sortierung der Groups: DESC nach `RISK_BAND_SORT_RANK` — escalate first,
    NULL-Band-Groups (Worker arbeitet noch) als `pending`-Rank-40 einsortiert.

    Rueckgabe-Format: list[dict] mit Keys `group`, `findings`, `worst_finding`.
    Das ist absichtlich keine Dataclass, weil Templates direkt dict-Access
    nutzen und keine Typ-Stabilitaet brauchen.
    """
    # Alle Groups die mindestens ein OPEN-Finding auf diesem Server haben.
    # `distinct()` damit pro Group ein Eintrag rauskommt; `selectinload` waere
    # ueberkopf weil Findings ohnehin in einer Folge-Query gezielt geladen
    # werden (Sortierung nach §15).
    groups_stmt = (
        select(ApplicationGroup)
        .join(Finding, Finding.application_group_id == ApplicationGroup.id)
        .where(
            Finding.server_id == server_id,
            Finding.status == FindingStatus.OPEN,
        )
        .distinct()
    )
    groups = list(sess.execute(groups_stmt).scalars().all())

    if not groups:
        return []

    # Worst-Finding-Lookup vorbereiten — `worst_finding_id` ist kein FK,
    # darum manuell auflueoesen. Filter auf Server, damit ein veralteter
    # Cross-Server-Verweis nicht stiltlich angezeigt wird.
    wf_ids = [g.worst_finding_id for g in groups if g.worst_finding_id is not None]
    worst_by_id: dict[int, Finding] = {}
    if wf_ids:
        worst_stmt = select(Finding).where(Finding.id.in_(wf_ids), Finding.server_id == server_id)
        for f in sess.execute(worst_stmt).scalars().all():
            worst_by_id[f.id] = f

    # Findings pro Group laden — eine Query pro Group ist akzeptabel: die
    # Anzahl Groups pro Server liegt bei 5-15 (Operator-Realitaet), und die
    # Block-K-Sort-Order braucht dieselben Tiebreaker wie der Server-weite
    # Listen-Modus. Wir reuse `list_findings()` mit einem Group-Filter via
    # Direct-Query (FindingsFilter hat keinen `application_group_id`-Slot,
    # weil das eine Server-Detail-spezifische Achse ist).
    result: list[dict[str, Any]] = []
    for grp in groups:
        findings_stmt = (
            select(Finding)
            .where(
                Finding.server_id == server_id,
                Finding.application_group_id == grp.id,
                Finding.status == FindingStatus.OPEN,
            )
            .order_by(
                Finding.is_kev.desc(),
                Finding.cvss_v3_score.desc().nullslast(),
                Finding.first_seen_at.asc(),
            )
        )
        grp_findings = list(sess.execute(findings_stmt).scalars().all())
        result.append(
            {
                "group": grp,
                "findings": grp_findings,
                "worst_finding": (
                    worst_by_id.get(grp.worst_finding_id)
                    if grp.worst_finding_id is not None
                    else None
                ),
            }
        )

    # Sortierung: DESC nach RISK_BAND_SORT_RANK. NULL-Band ranked als
    # PENDING (40) ein — Operator soll evaluating-Groups oben sehen, nicht
    # versteckt am Ende.
    def _rank(entry: dict[str, Any]) -> int:
        band = entry["group"].risk_band
        if band is None:
            return RISK_BAND_SORT_RANK[RiskBand.PENDING]
        # Map String -> Enum -> Rank. Fallback 0 bei unbekanntem Wert.
        try:
            return RISK_BAND_SORT_RANK[RiskBand(band)]
        except (KeyError, ValueError):
            return 0

    result.sort(key=_rank, reverse=True)
    return result


def _build_action_sections(
    application_groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Baut die "Was zu tun ist"-Card-Sektionen fuer den Server-Detail-Header.

    Block P / v0.9.3 (ADR-0023 §"Update v0.9.3 (c)"): die 4-Band-Reduktion
    deckt die operative Frage "patchen vs. mitigieren vs. App-Vendor-Update"
    nicht ab. Diese strukturierte Aktions-Sektion teilt die
    Operator-Workflows visuell in bis zu fuenf Cards auf — in der Reihenfolge
    operativer Dringlichkeit. Leere Cards werden geskippt; die ganze Sektion
    blendet sich im Template aus wenn das Ergebnis leer ist.

    Die Card-Filter spiegeln das ``(risk_band, action_type, group_kind)``-
    Tripel aus der ADR-Tabelle. NULL-``action_type``-Groups (vor dem ersten
    Pass-2-Re-Eval) matchen **keine** Card und sind absichtlich unsichtbar;
    sie tauchen wieder auf sobald der Worker das Feld setzt.
    """
    card_specs: list[dict[str, Any]] = [
        {
            "id": "escalate-distro-patch",
            "label": "ESCALATE · Distro patchen",
            "variant": "escalate-distro",
            "risk_band": "escalate",
            "action_type": "patch",
            "group_kind": "os_package",
            "show_labels": True,
        },
        {
            "id": "escalate-app-update",
            "label": "ESCALATE · App-Update einspielen",
            "variant": "escalate-app",
            "risk_band": "escalate",
            "action_type": "patch",
            "group_kind": "application_bundle",
            "show_labels": True,
        },
        {
            "id": "escalate-mitigate",
            "label": "ESCALATE · Kein Patch — mitigieren",
            "variant": "escalate-mitigate",
            "risk_band": "escalate",
            "action_type": "mitigate",
            "group_kind": None,
            "show_labels": True,
        },
        {
            "id": "act-distro-patch",
            "label": "ACT · Distro patchen (normal cycle)",
            "variant": "act-distro",
            "risk_band": "act",
            "action_type": "patch",
            "group_kind": "os_package",
            "show_labels": False,
        },
        {
            "id": "act-app-update",
            "label": "ACT · App-Update einspielen (normal cycle)",
            "variant": "act-app",
            "risk_band": "act",
            "action_type": "patch",
            "group_kind": "application_bundle",
            "show_labels": False,
        },
    ]

    result: list[dict[str, Any]] = []
    for spec in card_specs:
        matches: list[dict[str, Any]] = []
        for entry in application_groups:
            grp = entry["group"]
            if grp.risk_band != spec["risk_band"]:
                continue
            if grp.action_type != spec["action_type"]:
                continue
            if spec["group_kind"] is not None and grp.group_kind != spec["group_kind"]:
                continue
            matches.append(entry)

        if not matches:
            continue

        result.append(
            {
                "id": spec["id"],
                "label": spec["label"],
                "variant": spec["variant"],
                "filter": (spec["risk_band"], spec["action_type"], spec["group_kind"]),
                "count": len(matches),
                "show_labels": spec["show_labels"],
                "groups": matches,
            }
        )

    return result


def _load_ungrouped_findings_for_server(sess: Any, server_id: int) -> list[Finding]:
    """OPEN-Findings ohne `application_group_id` ("Pending grouping"-Bucket)."""
    stmt = (
        select(Finding)
        .where(
            Finding.server_id == server_id,
            Finding.application_group_id.is_(None),
            Finding.status == FindingStatus.OPEN,
        )
        .order_by(
            Finding.is_kev.desc(),
            Finding.cvss_v3_score.desc().nullslast(),
            Finding.first_seen_at.asc(),
        )
        .limit(500)
    )
    return list(sess.execute(stmt).scalars().all())


def _render_findings_section(
    server: Server,
    view_filter: FindingsViewFilter,
) -> dict[str, Any]:
    """Sammelt die Render-Daten fuer die Findings-Sektion.

    Rueckgabe als dict — die Template-Inklusion (`servers/_findings_section
    .html`) konsumiert die Keys direkt. Wird sowohl beim Vollseiten- als
    auch beim HTMX-Partial-Render genutzt.

    Block P (ADR-0023): zusaetzlich werden die Application-Groups und ihre
    Findings geladen — die Section-Hauptansicht gruppiert nach Application-
    Group statt nach Risk-Band auf Finding-Ebene.

    Block Q (ADR-0025): es gibt nur noch einen Modus (die frueheren
    `mode=group` und `mode=diff` sind ersatzlos entfallen). Der Helper
    laedt unkonditional die flache Liste + Application-Groups +
    Pending-Grouping-Sektion-Daten; das Template entscheidet via
    `_filters_active`/`_force_flat`/`_sort_default` ob Group-Cards oder
    flache Tabelle gerendert werden.
    """
    sess = get_session()
    findings_filter = view_filter.to_findings_filter()

    counts = count_findings(sess, server.id, findings_filter)

    findings_list = list_findings(
        sess,
        server.id,
        findings_filter,
        sort=view_filter.sort,
        dir=view_filter.dir,
    )
    # Block P: Group-Aufschluesselung — laeuft ergaenzend zur Listen-Query,
    # weil das Template (siehe `_findings_section.html`) die Groups als
    # primaere Render-Quelle nutzt und die flache Liste nur als
    # Fallback/Sort-Ueberschreibung haelt.
    application_groups = _load_application_groups_for_server(sess, server.id)
    ungrouped_findings = _load_ungrouped_findings_for_server(sess, server.id)

    return {
        "server": server,
        "view_filter": view_filter,
        "counts": counts,
        "findings": findings_list,
        "application_groups": application_groups,
        "ungrouped_findings": ungrouped_findings,
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
    # v0.9.3 (ADR-0023 §c): "Was zu tun ist"-Sektion zwischen Header und
    # Host-Snapshot. Wenn die View nicht im `list`-Mode laeuft, sind die
    # `application_groups` leer und die Sektion bleibt unsichtbar.
    action_sections = _build_action_sections(section_ctx.get("application_groups", []))

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
    # Block O (ADR-0022): Action-Required-Counts + Host-Snapshot fuer Header.
    action_required = _load_action_required_counts(sess, server.id)
    snapshot_ctx = _load_host_snapshot(sess, server.id)
    # Noise-Findings fuer den Bulk-Ack-Noise-Modal-Inhalt (max 50 inline +
    # Truncation-Hinweis im Template). Wir laden gezielt nur OPEN-noise-IDs
    # + identifier_key + package_name (selectinload nicht noetig).
    noise_findings = list(
        sess.execute(
            select(Finding)
            .where(
                Finding.server_id == server.id,
                Finding.status == FindingStatus.OPEN,
                Finding.risk_band == "noise",
            )
            .order_by(Finding.identifier_key.asc())
            .limit(50)
        )
        .scalars()
        .all()
    )
    noise_total = int(
        sess.execute(
            select(func.count(Finding.id)).where(
                Finding.server_id == server.id,
                Finding.status == FindingStatus.OPEN,
                Finding.risk_band == "noise",
            )
        ).scalar()
        or 0
    )

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
        action_required=action_required,
        listeners=snapshot_ctx["listeners"],
        services=snapshot_ctx["services"],
        processes=snapshot_ctx["processes"],
        noise_findings=noise_findings,
        noise_total=noise_total,
        action_sections=action_sections,
        **section_ctx,
    )


def _load_action_required_counts(sess: Any, server_id: int) -> dict[str, Any]:
    """Liefert Action-Required-Counter fuer den Server-Detail-Header (Block O).

    Rueckgabe:
      - `yes_count`        : Anzahl OPEN-Findings im Yes-Bucket.
      - `no_count`         : Anzahl OPEN-Findings im No-Bucket.
      - `yes_subcounts`    : dict[str,int] pro Yes-Band (escalate..unknown).
      - `no_subcounts`     : dict[str,int] pro No-Band (monitor/noise).
    """
    band_stmt = (
        select(Finding.risk_band, func.count(Finding.id))
        .where(Finding.server_id == server_id, Finding.status == FindingStatus.OPEN)
        .group_by(Finding.risk_band)
    )
    band_counts: dict[str, int] = {}
    for band_value, n in sess.execute(band_stmt).all():
        if band_value is not None:
            band_counts[band_value] = int(n)

    yes_bands = yes_band_values()
    no_bands = no_band_values()
    yes_subcounts = {band: band_counts.get(band, 0) for band in yes_bands}
    no_subcounts = {band: band_counts.get(band, 0) for band in no_bands}

    return {
        "yes_count": sum(yes_subcounts.values()),
        "no_count": sum(no_subcounts.values()),
        "yes_subcounts": yes_subcounts,
        "no_subcounts": no_subcounts,
        "noise_count": band_counts.get("noise", 0),
    }


def _load_host_snapshot(sess: Any, server_id: int) -> dict[str, Any]:
    """Liefert die Snapshot-Daten fuer die `host_snapshot`-Sektion (Block O).

    Rueckgabe-Keys:
      - `listeners` : list[ServerListener], sortiert nach (port, proto, addr).
      - `services`  : list[str], alphabetisch.
      - `processes` : list[ServerProcess], fuer Args-Tooltip.
    """
    listeners = list(
        sess.execute(
            select(ServerListener)
            .where(ServerListener.server_id == server_id)
            .order_by(
                ServerListener.port.asc(), ServerListener.proto.asc(), ServerListener.addr.asc()
            )
        )
        .scalars()
        .all()
    )
    services = list(
        sess.execute(
            select(ServerService.name)
            .where(ServerService.server_id == server_id)
            .order_by(ServerService.name.asc())
        )
        .scalars()
        .all()
    )
    processes = list(
        sess.execute(select(ServerProcess).where(ServerProcess.server_id == server_id))
        .scalars()
        .all()
    )
    # ServerKernelModule wird im MVP nicht inline gerendert; in Loader
    # vorbereiten waere ueberflussig.
    _ = ServerKernelModule
    return {
        "listeners": listeners,
        "services": services,
        "processes": processes,
    }


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
