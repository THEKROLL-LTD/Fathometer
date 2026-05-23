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
from sqlalchemy import func, nulls_last, select
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
    NoteForm,
    ReopenForm,
)
from app.models import (
    ApplicationGroup,
    ApplicationGroupEvaluation,
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
from app.services.trend import Tendency, tendency_from_counts
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
    nach `application_group_id` gruppiert.

    Block Q (ADR-0025 §2): der Loader rendert nur noch das Card-Inventar.
    Die Findings-Tabellen pro Group werden vom Browser via HTMX-Lazy-Load
    nachgefordert (`group_findings_fragment`-Endpoint). Block T (ADR-0028)
    ergaenzt einen vierten Batch-SELECT fuer die Junction-Bewertungen — statt
    N+1 fuehren wir exakt vier aggregierte Queries aus:

      1. Count-Aggregat: pro Group die Anzahl OPEN-Findings auf diesem
         Server. Liefert gleichzeitig die Liste relevanter Group-IDs.
      2. Group-Metadaten: ein `IN (...)`-Batch der `ApplicationGroup`-Zeilen
         fuer die im Count-Aggregat ermittelten IDs.
      3. Junction-Batch (Block T): ein `WHERE server_id=? AND group_id IN
         (...)`-Lookup der per-(group, server)-Eval-Rows. Fehlende Rows
         bedeuten "Nicht bewertet" — Group-Card rendert in dem Fall die
         entsprechende Pille (siehe ADR-0028 §UI-bei-Eval-Lücke).
      4. Worst-Finding-Batch: ein `IN (...)`-Batch der Worst-Finding-
         Objekte (server-gefiltert, damit Cross-Server-Drift unsichtbar
         bleibt). `worst_finding_id` kommt jetzt aus der Junction-Row.

    Sortierung der Groups: DESC nach `RISK_BAND_SORT_RANK` — escalate first,
    Groups ohne Junction-Row als `pending`-Rank-40 einsortiert (UI-Pille
    "Nicht bewertet").

    Rueckgabe-Format: list[dict] mit Keys `group`, `count`, `evaluation`,
    `worst_finding`. `evaluation` ist die Junction-Row oder `None`.
    """
    # (1) Count-Aggregat: liefert sowohl die Group-IDs (mindestens 1 OPEN-
    # Finding auf diesem Server) als auch den Counter-Wert pro Group fuer
    # den Card-Header. Damit entfaellt die alte DISTINCT-JOIN-Query.
    count_stmt = (
        select(Finding.application_group_id, func.count(Finding.id))
        .where(
            Finding.server_id == server_id,
            Finding.status == FindingStatus.OPEN,
            Finding.application_group_id.is_not(None),
        )
        .group_by(Finding.application_group_id)
    )
    counts_by_id: dict[int, int] = {
        int(group_id): int(n)
        for group_id, n in sess.execute(count_stmt).all()
        if group_id is not None
    }

    if not counts_by_id:
        return []

    # (2) Group-Metadaten-Batch: nur fuer die Groups die im Count-Aggregat
    # auftauchen. Reihenfolge ist hier egal; wir sortieren unten manuell
    # nach Risk-Band-Rank.
    group_ids = list(counts_by_id.keys())
    groups_stmt = select(ApplicationGroup).where(ApplicationGroup.id.in_(group_ids))
    groups = list(sess.execute(groups_stmt).scalars().all())

    # (3) Junction-Batch (Block T, ADR-0028): per-(group, server)-Eval-Rows
    # in einem Sprung laden. Fehlende Rows -> "Nicht bewertet".
    evaluations_by_id: dict[int, ApplicationGroupEvaluation] = {
        ev.group_id: ev
        for ev in sess.execute(
            select(ApplicationGroupEvaluation).where(
                ApplicationGroupEvaluation.server_id == server_id,
                ApplicationGroupEvaluation.group_id.in_(group_ids),
            )
        )
        .scalars()
        .all()
    }

    # (4) Worst-Finding-Batch: `worst_finding_id` ist kein FK, darum manuell
    # aufloesen. Filter auf Server, damit ein veralteter Cross-Server-Verweis
    # nicht stillschweigend angezeigt wird. Quelle ist jetzt die Junction.
    wf_ids = [
        ev.worst_finding_id for ev in evaluations_by_id.values() if ev.worst_finding_id is not None
    ]
    worst_by_id: dict[int, Finding] = {}
    if wf_ids:
        worst_stmt = select(Finding).where(Finding.id.in_(wf_ids), Finding.server_id == server_id)
        for f in sess.execute(worst_stmt).scalars().all():
            worst_by_id[f.id] = f

    result: list[dict[str, Any]] = []
    for grp in groups:
        ev = evaluations_by_id.get(grp.id)
        result.append(
            {
                "group": grp,
                "evaluation": ev,
                "count": counts_by_id.get(grp.id, 0),
                "worst_finding": (
                    worst_by_id.get(ev.worst_finding_id)
                    if ev is not None and ev.worst_finding_id is not None
                    else None
                ),
            }
        )

    # Sortierung: DESC nach RISK_BAND_SORT_RANK. Groups ohne Junction-Row
    # ranked als PENDING (40) ein — Operator soll "Nicht bewertet"-Cards oben
    # sehen, nicht versteckt am Ende.
    def _rank(entry: dict[str, Any]) -> int:
        ev = entry["evaluation"]
        if ev is None:
            return RISK_BAND_SORT_RANK[RiskBand.PENDING]
        try:
            return RISK_BAND_SORT_RANK[RiskBand(ev.risk_band)]
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
            ev = entry.get("evaluation")
            if ev is None:
                # Block T: ohne Junction-Row gibt es weder Band noch
                # Action-Type — Group wird in keiner Card aufgefuehrt.
                continue
            if ev.risk_band != spec["risk_band"]:
                continue
            if ev.action_type != spec["action_type"]:
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


def _load_pending_grouping_counts(sess: Any, server_id: int) -> dict[str, int]:
    """Liefert pro Risk-Band die Anzahl OPEN-Findings ohne Application-Group.

    Block Q (ADR-0025 §3): Pending-Grouping-Sektion rendert nur die
    Counts; Findings werden via HTMX vom `pending_findings_fragment`-
    Endpoint lazy nachgeladen.

    Rueckgabe-Format: dict[risk_band -> count]. Alle bekannten Bands
    sind als Keys vorhanden, defaulten auf 0; Insertion-Order entspricht
    der operativen Dringlichkeit (escalate zuerst, noise zuletzt), damit
    Templates die Buckets ohne eigene Sortier-Logik in der erwarteten
    Reihenfolge ueber `.items()` iterieren koennen.
    """
    stmt = (
        select(Finding.risk_band, func.count(Finding.id))
        .where(
            Finding.server_id == server_id,
            Finding.application_group_id.is_(None),
            Finding.status == FindingStatus.OPEN,
        )
        .group_by(Finding.risk_band)
    )
    raw: dict[str, int] = {}
    for band, n in sess.execute(stmt).all():
        if band is not None:
            raw[band] = int(n)
    # Dict in fester Risk-Band-Sort-Order aufbauen — Python 3.7+ haelt
    # Insertion-Order, das bestimmt die Rendering-Reihenfolge im Template.
    return {band: raw.get(band, 0) for band in _PENDING_BANDS}


def _is_flat_mode(view_filter: FindingsViewFilter) -> bool:
    """Spiegelt die Template-Conditional aus `_findings_section.html:122-133`.

    Liefert True wenn die flache Tabelle (`_view_list.html`) gerendert wird,
    False wenn die Group-Card-Ansicht (`_view_groups.html`) gerendert wird.

    Phase B (ADR-0030 Befund 2): `list_findings` wird nur aufgerufen wenn
    der Rueckgabewert True ist — im Group-Default-Pfad ist die flache Liste
    nicht sichtbar und jeder `list_findings`-Call waere verworfen.

    Exakte Kopie der Template-Logik:
        _filters_active = (status != open OR class != both OR kev_only OR
                           search OR risk_band OR action_required OR ag_id)
        _sort_default = (sort == 'risk' AND dir == 'desc')
        _force_flat   = request.args.get('flat') == '1'
        flat_mode     = _force_flat OR _filters_active OR NOT _sort_default
    """
    _filters_active = (
        view_filter.status != "open"
        or view_filter.finding_class != "both"
        or view_filter.kev_only
        or bool(view_filter.search)
        or view_filter.risk_band is not None
        or view_filter.action_required is not None
        or view_filter.application_group_id is not None
    )
    _sort_default = view_filter.sort == "risk" and view_filter.dir == "desc"
    _force_flat = request.args.get("flat") == "1"
    return _force_flat or _filters_active or not _sort_default


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
    `mode=group` und `mode=diff` sind ersatzlos entfallen).

    Phase B (ADR-0030 Befund 2): `list_findings` wird nur aufgerufen wenn
    der Group-Default-Pfad NICHT aktiv ist (d.h. wenn der Flat-Pfad gerendert
    wird). Im Group-Default-Pfad ist die flache Liste nicht sichtbar; der
    `list_findings`-Call wuerde ~50 ms DB-Zeit plus N-Row-Hydration kosten
    fuer Daten die vollstaendig verworfen werden. `total_findings` wird aus
    `counts` abgeleitet (counts["open"]) statt aus `findings | length`.
    """
    sess = get_session()
    findings_filter = view_filter.to_findings_filter()

    counts = count_findings(sess, server.id, findings_filter)

    flat_mode = _is_flat_mode(view_filter)
    if flat_mode:
        findings_list = list_findings(
            sess,
            server.id,
            findings_filter,
            sort=view_filter.sort,
            dir=view_filter.dir,
        )
    else:
        # Group-Default-Pfad: flache Liste wird im Template nicht gerendert.
        # Leere Liste in den Context — kein DB-Call.
        findings_list = []

    # Block P: Group-Aufschluesselung — laeuft ergaenzend zur Listen-Query,
    # weil das Template (siehe `_findings_section.html`) die Groups als
    # primaere Render-Quelle nutzt und die flache Liste nur als
    # Fallback/Sort-Ueberschreibung haelt.
    application_groups = _load_application_groups_for_server(sess, server.id)
    pending_grouping_counts: dict[str, int] = _load_pending_grouping_counts(sess, server.id)

    ctx = {
        "server": server,
        "view_filter": view_filter,
        "counts": counts,
        "findings": findings_list,
        "application_groups": application_groups,
        "pending_grouping_counts": pending_grouping_counts,
    }
    if flat_mode:
        ctx.update(
            {
                "ack_form": AcknowledgeForm(),
                "reopen_form": ReopenForm(),
                "note_form": NoteForm(),
                "bulk_form": BulkActionForm(),
                "csrf_form": CSRFOnlyForm(),
            }
        )
    return ctx


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


# Whitelist der Risk-Bands fuer die Pending-Grouping-Sektion (ADR-0025 §3).
# Wird sowohl vom Default-Loader (`_load_pending_grouping_counts`) als auch
# vom Lazy-Endpoint (`pending_findings_fragment`) konsumiert.
_PENDING_BANDS: tuple[str, ...] = (
    "escalate",
    "act",
    "mitigate",
    "pending",
    "unknown",
    "monitor",
    "noise",
)


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

    # Block K (ADR-0018): Header-Stats und Trend-Daten aufsammeln.
    # Phase E (ADR-0030 Befund 3): SQL-Aggregation aktiviert — beide
    # Aggregatoren laufen ohne vorgeladene `rows=`-Liste direkt gegen die DB.
    # `_load_findings`-Python-Loop entfaellt; Postgres erledigt die
    # Aggregation per `generate_series` + FILTER-Aggregate. Query-Count steigt
    # um 2, CPU-Last sinkt drastisch (keine 1.4M-Python-Iterationen mehr).
    sess = get_session()
    sparklines: dict[str, list[int]] = severity_snapshots_for_server(sess, server.id, days=50)
    trend_data: list[DailySeverityCount] = daily_severity_counts_for_server(
        sess, server.id, days=50
    )
    tendency: Tendency = tendency_from_counts(trend_data)
    kev_events_50d: int = count_kev_events_50d(sess, server.id)
    heartbeat_cells: list[DailyStatus] = heartbeats_for_servers(sess, [server.id], days=50)[
        server.id
    ]
    quick_counts = _quick_counts_for_server(sess, server.id)
    # Block O (ADR-0022): Action-Required-Counts + Host-Snapshot fuer Header.
    action_required = _load_action_required_counts(sess, server.id)
    snapshot_ctx = _load_host_snapshot(sess, server.id)
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
    # Noise-Findings fuer den Bulk-Ack-Noise-Modal-Inhalt (max 50 inline +
    # Truncation-Hinweis im Template). Ohne Noise-Button braucht das Template
    # keine Vorschau-Liste.
    noise_findings = []
    if noise_total > 0:
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


@server_detail_bp.get("/<int:server_id>/groups/<int:group_id>/findings")
@login_required
def group_findings_fragment(server_id: int, group_id: int) -> str:
    """HTMX-Lazy-Load-Endpoint fuer die Findings-Tabelle einer Application-Group.

    Block Q (ADR-0025 §2): Application-Group-Cards rendern initial nur
    Count + Worst-Finding-Metadaten. Sobald der Operator das Card-`<details>`
    aufklappt, holt das HTMX-Pattern dieses Fragment nach.

    Rueckgabe ist ein HTML-Partial (`_partials/group_findings_table.html`)
    ohne `<html>`/`<body>`-Huelle. 404, wenn der Server nicht existiert oder
    die angefragte Group auf diesem Server keine OPEN-Findings hat —
    letzteres deckt sowohl Cross-Server- als auch Cross-Group-ID-Probing ab.

    Sortierung ist Spec-fix (siehe ADR-0025 §2): KEV desc, EPSS desc nulls
    last, CVSS desc nulls last, `first_seen_at` asc. Der Endpoint kennt
    keine URL-Parameter.
    """
    server = _load_server_with_tags(server_id)
    if server is None:
        abort(404)
    sess = get_session()
    findings = list(
        sess.execute(
            select(Finding)
            .where(
                Finding.server_id == server_id,
                Finding.application_group_id == group_id,
                Finding.status == FindingStatus.OPEN,
            )
            .order_by(
                Finding.is_kev.desc(),
                nulls_last(Finding.epss_score.desc()),
                nulls_last(Finding.cvss_v3_score.desc()),
                Finding.first_seen_at.asc(),
            )
        )
        .scalars()
        .all()
    )
    if not findings:
        abort(404)
    return render_template(
        "_partials/group_findings_table.html",
        findings=findings,
    )


@server_detail_bp.get("/<int:server_id>/findings/pending")
@login_required
def pending_findings_fragment(server_id: int) -> str:
    """HTMX-Lazy-Load-Endpoint fuer die Pending-Grouping-Findings pro Risk-Band.

    Block Q (ADR-0025 §3): die Pending-Grouping-Sektion rendert initial nur
    pro Risk-Band einen collapsed `<details>`-Rollup mit Count. Sobald der
    Operator das Bucket-`<details>` aufklappt, holt das HTMX-Pattern das
    `<tbody>`-Fragment hier nach.

    Rueckgabe ist ein HTML-Partial (`_partials/pending_findings_table.html`).
    400, wenn `risk_band` fehlt oder nicht in der Whitelist
    (`_PENDING_BANDS`) liegt. 404, wenn der Server nicht existiert oder der
    Bucket auf diesem Server keine OPEN-Findings hat.

    Sortierung ist Spec-fix (siehe ADR-0025 §15-Default): KEV desc, EPSS desc
    nulls last, CVSS desc nulls last, `first_seen_at` asc.
    """
    band = request.args.get("risk_band")
    if band not in _PENDING_BANDS:
        abort(400)
    server = _load_server_with_tags(server_id)
    if server is None:
        abort(404)
    sess = get_session()
    findings = list(
        sess.execute(
            select(Finding)
            .where(
                Finding.server_id == server_id,
                Finding.application_group_id.is_(None),
                Finding.status == FindingStatus.OPEN,
                Finding.risk_band == band,
            )
            .order_by(
                Finding.is_kev.desc(),
                nulls_last(Finding.epss_score.desc()),
                nulls_last(Finding.cvss_v3_score.desc()),
                Finding.first_seen_at.asc(),
            )
        )
        .scalars()
        .all()
    )
    if not findings:
        abort(404)
    return render_template(
        "_partials/pending_findings_table.html",
        findings=findings,
        risk_band=band,
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

    Eine einzige aggregierte Query mit `FILTER (WHERE …)`-Clauses,
    Server-scoped (keine Tag-Filterung).
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
