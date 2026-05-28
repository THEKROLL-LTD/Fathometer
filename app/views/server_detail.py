"""Server-Detail-View `/servers/<id>` — Triage-Hauptansicht (Block E).

ADR-0025 / Block Q: die frueheren View-Modi `gruppiert` und `diff` sind
ersatzlos entfallen; veraltete Bookmarks mit altem `mode`-Query-Param
werden still ignoriert.

ADR-0039 / Block Y Phase A: der Initial-Render liefert nur noch das was
der Operator sofort sieht — Header, Action-Workflows, KPI-Tiles
(Skeleton-Sparklines), Triage-Queue-Akkordeon-Header (Counts). Alle uebrigen
Sektionen (Sparklines, Heartbeat, Trend, Host-Snapshot, Noise, Triage-
Findings) werden via HTMX-Fragments nachgeladen — Phase B/C wired die
URLs. Tendency wird ueber eine leichtgewichtige 7-vs-7-Tage-Query
berechnet (siehe `_tendency_quick`); die volle 30-Tage-Aggregation kommt
spaeter aus dem Trend-Fragment.

URL-Filter (alle optional, Defaults sicher): `status`, `class`,
`severity`, `kev_only`, `q`, `risk_band`, `action_required`,
`application_group`, `sort`, `dir`, `flat`.

HTMX-Pattern: bei `HX-Request: true` rendert der Endpoint die Detail-
Pane-Fragment-Variante von `servers/detail.html` (Server-Header +
Findings-Sektion) via `_partial_shell.html`, nicht die ganze Seite mit
Sidebar.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from flask import Blueprint, abort, render_template, request
from flask_login import login_required
from sqlalchemy import case, func, nulls_last, select
from sqlalchemy.orm import selectinload

from app.db import get_session
from app.forms import (
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
from app.services.heartbeat_aggregation import heartbeats_for_servers
from app.services.listener_exposure import classify_exposure
from app.services.risk_engine import RISK_BAND_SORT_RANK, RiskBand, no_band_values, yes_band_values
from app.services.severity_history import (
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


def _load_active_server_or_404(server_id: int) -> Server:
    """Lade Server fuer einen Fragment-Endpoint oder 404.

    Block Y / ADR-0039 Phase B: alle Fragment-Endpoints liefern 404 wenn
    der Server nicht existiert oder bereits revoked/retired ist. `show()`
    rendert revoked/retired Server bewusst weiter und nutzt diesen Helper
    daher NICHT.
    """
    server = _load_server_with_tags(server_id)
    if server is None:
        abort(404)
    if server.revoked_at is not None or server.retired_at is not None:
        abort(404)
    return server


def _load_host_snapshot(sess: Any, server_id: int) -> dict[str, Any]:
    """Liefert die Snapshot-Daten fuer die Header-Pills (Block X, ADR-0038 §(3)).

    Block Y / ADR-0039 Phase B: aus `show()` entfernt und ausschliesslich
    vom `host_snapshot_fragment`-Endpoint genutzt.

    Rueckgabe-Keys:
      - ``listeners`` : ``list[dict[str, Any]]``, sortiert nach (port, proto,
        addr). Jeder Eintrag enthaelt die Schluessel ``process``, ``addr``,
        ``port``, ``proto``, ``pid`` sowie ``exposure`` —
        ``"LOOPBACK"`` oder ``"PUBLIC EXPOSED"`` gemaess
        :func:`app.services.listener_exposure.classify_exposure`.
      - ``services``  : ``list[str]``, alphabetisch.
      - ``processes`` : ``list[ServerProcess]``, fuer den Pid-zu-Args-Lookup
        in den Panel-Partials.
    """
    listeners_orm = list(
        sess.execute(
            select(ServerListener)
            .where(ServerListener.server_id == server_id)
            .order_by(
                ServerListener.port.asc(),
                ServerListener.proto.asc(),
                ServerListener.addr.asc(),
            )
        )
        .scalars()
        .all()
    )
    listeners: list[dict[str, Any]] = [
        {
            "process": li.process,
            "addr": li.addr,
            "port": li.port,
            "proto": li.proto,
            "pid": li.pid,
            "exposure": classify_exposure(li.addr or ""),
        }
        for li in listeners_orm
    ]
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
    # ServerKernelModule wird im MVP nicht inline gerendert; die Symbol-
    # Referenz haelt den Import in mypy-strict-Lints sichtbar.
    _ = ServerKernelModule
    return {
        "listeners": listeners,
        "services": services,
        "processes": processes,
    }


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
    nachgefordert (`group_findings_fragment`-Endpoint).

    Block Y / ADR-0039 §4: die Queries (2), (3), (4) holen jetzt Projektionen
    (SQLAlchemy `Row`-Objekte) statt voller ORM-Objekte — die Templates und
    `_build_action_sections` greifen nur auf eine Handvoll Spalten zu.
    Row-Objekte unterstuetzen Attribut-Zugriff via `row.label`, kompatibel
    zur bisherigen Schnittstelle.

    Vier aggregierte Queries:

      1. Count-Aggregat: pro Group die Anzahl OPEN-Findings auf diesem
         Server. Liefert gleichzeitig die Liste relevanter Group-IDs.
      2. Group-Metadaten-Batch (Projektion): id, label, group_kind,
         explanation.
      3. Junction-Batch (Projektion): group_id, risk_band, risk_band_reason,
         worst_finding_id, action_type, risk_band_computed_at. Fehlende
         Rows bedeuten "Nicht bewertet" — Group-Card rendert die
         entsprechende Pille (siehe ADR-0028 §UI-bei-Eval-Lücke).
      4. Worst-Finding-Batch (Projektion): id, identifier_key, package_name,
         title.

    Sortierung der Groups: DESC nach `RISK_BAND_SORT_RANK` — escalate first,
    Groups ohne Junction-Row als `pending`-Rank-40 einsortiert (UI-Pille
    "Nicht bewertet").

    Rueckgabe-Format: list[dict] mit Keys `group`, `count`, `evaluation`,
    `worst_finding`. Die Werte sind Row-Objekte oder `None`.
    """
    # (1) Count-Aggregat: liefert sowohl die Group-IDs (mindestens 1 OPEN-
    # Finding auf diesem Server) als auch den Counter-Wert pro Group fuer
    # den Card-Header.
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

    # (2) Group-Metadaten-Batch (Projektion): nur die Spalten die Templates
    # und `_build_action_sections` brauchen.
    group_ids = list(counts_by_id.keys())
    groups_stmt = select(
        ApplicationGroup.id,
        ApplicationGroup.label,
        ApplicationGroup.group_kind,
        ApplicationGroup.explanation,
    ).where(ApplicationGroup.id.in_(group_ids))
    groups: list[Any] = list(sess.execute(groups_stmt).all())

    # (3) Junction-Batch (Projektion): nur die Spalten die `_build_action_
    # sections` und Templates lesen.
    evaluations_by_id: dict[int, Any] = {}
    eval_stmt = select(
        ApplicationGroupEvaluation.group_id,
        ApplicationGroupEvaluation.risk_band,
        ApplicationGroupEvaluation.risk_band_reason,
        ApplicationGroupEvaluation.worst_finding_id,
        ApplicationGroupEvaluation.action_type,
        ApplicationGroupEvaluation.risk_band_computed_at,
    ).where(
        ApplicationGroupEvaluation.server_id == server_id,
        ApplicationGroupEvaluation.group_id.in_(group_ids),
    )
    for row in sess.execute(eval_stmt).all():
        evaluations_by_id[int(row.group_id)] = row

    # (4) Worst-Finding-Batch (Projektion): id, identifier_key, package_name,
    # title. Filter auf Server, damit ein veralteter Cross-Server-Verweis
    # nicht stillschweigend angezeigt wird.
    wf_ids = [
        ev.worst_finding_id for ev in evaluations_by_id.values() if ev.worst_finding_id is not None
    ]
    worst_by_id: dict[int, Any] = {}
    if wf_ids:
        worst_stmt = select(
            Finding.id,
            Finding.identifier_key,
            Finding.package_name,
            Finding.title,
        ).where(Finding.id.in_(wf_ids), Finding.server_id == server_id)
        for row in sess.execute(worst_stmt).all():
            worst_by_id[int(row.id)] = row

    result: list[dict[str, Any]] = []
    for grp in groups:
        ev = evaluations_by_id.get(int(grp.id))
        result.append(
            {
                "group": grp,
                "evaluation": ev,
                "count": counts_by_id.get(int(grp.id), 0),
                "worst_finding": (
                    worst_by_id.get(int(ev.worst_finding_id))
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


# Sechs Top-Level-Slots fuer den Risk-Band-Accordion in der Triage-Queue
# (ADR-0038 §6). Reihenfolge per Operator-Dringlichkeit; Pending-Grouping-
# Block haengt unter PENDING. Spec verlangt sechs Slots ohne "unknown" —
# unknown-Risk-Findings sind sehr selten und werden im Pending-Block
# subsumiert (wenn application_group_id IS NULL) oder rendern in der
# nominalen Group-Card mit risk_band='unknown'.
_RISK_BAND_SECTION_ORDER: tuple[str, ...] = (
    "escalate",
    "act",
    "mitigate",
    "pending",
    "monitor",
    "noise",
)


def _risk_band_header_counts(sess: Any, server_id: int) -> dict[str, int]:
    """Liefert pro Risk-Band die Anzahl OPEN-Findings auf diesem Server.

    Block Y / ADR-0039 §1: ersetzt den frueheren Risk-Band-Section-Builder
    (Block X Phase F) durch einen leichtgewichtigen Count-Aggregat-Query.
    Die Akkordeon-Header zeigen nur den Count pro Band, die Findings selbst
    kommen aus dem Phase-C-Triage-Endpoint (Lazy-Load bei Expand).

    Rueckgabe in `_RISK_BAND_SECTION_ORDER`-Reihenfolge (Insertion-Order
    erhalten), fehlende Bands defaulten auf 0. Findings mit unbekanntem
    oder NULL-`risk_band` werden in `pending` aggregiert.
    """
    stmt = (
        select(Finding.risk_band, func.count(Finding.id))
        .where(
            Finding.server_id == server_id,
            Finding.status == FindingStatus.OPEN,
        )
        .group_by(Finding.risk_band)
    )
    raw: dict[str, int] = dict.fromkeys(_RISK_BAND_SECTION_ORDER, 0)
    for band, n in sess.execute(stmt).all():
        if band in raw:
            raw[band] += int(n)
        else:
            # NULL- oder unbekannter Band-Wert -> in pending subsumieren.
            raw["pending"] += int(n)
    return raw


def _tendency_quick(sess: Any, server_id: int) -> Tendency:
    """Leichtgewichtige 7-vs-7-Tage-Tendency-Berechnung fuer den Header.

    Block Y / ADR-0039 §1: ersetzt den teuren `severity_snapshots_for_server`
    + `daily_severity_counts_for_server` Doppelaufruf im Critical Path.
    Vergleicht die Anzahl OPEN-Findings die in den letzten 7 Tagen erstmals
    gesehen wurden vs. die der vorherigen 7 Tage. Liefert ein `Tendency`-
    Enum (STABLE/RISING/FALLING).

    Die volle 30-Tage-Aggregation mit Sparkline kommt spaeter aus dem
    Trend-Fragment-Endpoint (Phase B/D).

    Heuristik: gleicher 5%-Threshold wie `tendency_from_counts`, normalisiert
    auf max(prev, 1) — so dominiert ein einzelnes neues Finding bei prev=0
    nicht direkt das Ergebnis (kein "Division durch 0").
    """
    now = datetime.now(UTC)
    cutoff_7 = now - timedelta(days=7)
    cutoff_14 = now - timedelta(days=14)

    stmt = select(
        func.count()
        .filter(
            Finding.first_seen_at >= cutoff_7,
        )
        .label("current"),
        func.count()
        .filter(
            Finding.first_seen_at >= cutoff_14,
            Finding.first_seen_at < cutoff_7,
        )
        .label("prev"),
    ).where(
        Finding.server_id == server_id,
        Finding.status == FindingStatus.OPEN,
    )
    row = sess.execute(stmt).one()
    current = int(row.current or 0)
    prev = int(row.prev or 0)

    threshold = 0.05
    denom = max(prev, 1)
    diff = (current - prev) / denom

    if diff >= threshold:
        return Tendency.RISING
    if diff <= -threshold:
        return Tendency.FALLING
    return Tendency.STABLE


def _load_server_band_aggregates(sess: Any, server_id: int) -> dict[str, Any]:
    """Unified Band-Aggregat: ersetzt Pending-Counts + Action-Required-Counts.

    Block Y / ADR-0039 §5: ein einziger `GROUP BY risk_band`-Query mit zwei
    FILTER-Aggregaten statt zwei separater Queries. Liefert die Informationen
    fuer die Action-Required-Pille (yes_count/no_count + Sub-Counts) UND die
    Pending-Grouping-Whitelist (Findings ohne `application_group_id` pro Band).

    Rueckgabe-Keys:
      - `pending_by_band` : dict[str, int] — Findings ohne Group pro Band,
        Insertion-Order ueber `_PENDING_BANDS`.
      - `yes_subcounts`   : dict[str, int] pro Yes-Band (escalate..unknown).
      - `no_subcounts`    : dict[str, int] pro No-Band (monitor/noise).
      - `yes_count`       : int — Summe Yes-Bucket.
      - `no_count`        : int — Summe No-Bucket.
      - `noise_count`     : int — Noise-Bucket fuer Bulk-Ack-Noise-Button.
    """
    stmt = (
        select(
            Finding.risk_band,
            func.count(Finding.id).label("total"),
            func.count().filter(Finding.application_group_id.is_(None)).label("pending"),
        )
        .where(
            Finding.server_id == server_id,
            Finding.status == FindingStatus.OPEN,
        )
        .group_by(Finding.risk_band)
    )

    total_by_band: dict[str, int] = {}
    pending_by_band_raw: dict[str, int] = {}
    for row in sess.execute(stmt).all():
        band = row.risk_band
        if band is None:
            continue
        total_by_band[band] = int(row.total or 0)
        pending_by_band_raw[band] = int(row.pending or 0)

    yes_bands = yes_band_values()
    no_bands = no_band_values()
    yes_subcounts = {band: total_by_band.get(band, 0) for band in yes_bands}
    no_subcounts = {band: total_by_band.get(band, 0) for band in no_bands}

    pending_by_band = {band: pending_by_band_raw.get(band, 0) for band in _PENDING_BANDS}

    return {
        "pending_by_band": pending_by_band,
        "yes_subcounts": yes_subcounts,
        "no_subcounts": no_subcounts,
        "yes_count": sum(yes_subcounts.values()),
        "no_count": sum(no_subcounts.values()),
        "noise_count": total_by_band.get("noise", 0),
    }


def _load_pending_grouping_counts(sess: Any, server_id: int) -> dict[str, int]:
    """Backward-Compat-Wrapper um `_load_server_band_aggregates`.

    Block Y / ADR-0039 §5 hat den dedizierten Pending-Counts-Helper durch
    das unified `_load_server_band_aggregates` ersetzt. Der vorherige
    Helper-Name wird weiterhin gebraucht:

      - `tests/views/test_server_detail.py` patcht `_load_pending_grouping_
        counts` als Mock-Target (Pure-Unit-Test, kein DB-Zugriff). Solange
        der Test-Patch existiert MUSS dieser Wrapper als attached Symbol
        am Modul erhalten bleiben — sonst schlaegt `mock.patch` mit
        AttributeError fehl.
      - `tests/integration/test_server_detail_pending_lazy_db.py` ruft den
        Wrapper direkt auf (db_integration-Suite).

    Block Y Phase D: bewusst NICHT geloescht — Reviewer-Notiz bei Refactor:
    Wrapper darf erst entfernt werden wenn ALLE Konsumenten (Pure-Unit-
    Mock UND Integration-Test) auf `_load_server_band_aggregates` migriert
    sind.
    """
    result: dict[str, int] = _load_server_band_aggregates(sess, server_id)["pending_by_band"]
    return result


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
    *,
    application_groups: list[dict[str, Any]] | None = None,
    pending_grouping_counts: dict[str, int] | None = None,
    risk_band_header_counts: dict[str, int] | None = None,
    default_open_band: str | None = None,
) -> dict[str, Any]:
    """Sammelt die Render-Daten fuer die Findings-Sektion.

    Block Y / ADR-0039 §1: die teuren Loader (`_load_application_groups_for_
    server`, `_load_server_band_aggregates`, `_risk_band_header_counts`)
    werden in `show()` einmal aufgerufen und in diese Funktion durchgereicht
    — so verteilt `show()` die Queries selbst und der Test kann sie isoliert
    patchen.

    Phase B (ADR-0030 Befund 2): `list_findings` wird nur aufgerufen wenn
    der Group-Default-Pfad NICHT aktiv ist.
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
        findings_list = []

    # Defensive Defaults — wenn der Caller nichts mitgibt, holen wir die
    # Daten hier nach (z.B. fuer Tests die nur die Findings-Section testen).
    if application_groups is None:
        application_groups = _load_application_groups_for_server(sess, server.id)
    if pending_grouping_counts is None or risk_band_header_counts is None:
        if pending_grouping_counts is None:
            band_aggs = _load_server_band_aggregates(sess, server.id)
            pending_grouping_counts = band_aggs["pending_by_band"]
        if risk_band_header_counts is None:
            risk_band_header_counts = _risk_band_header_counts(sess, server.id)

    if default_open_band is None:
        default_open_band = _pick_default_open_band(risk_band_header_counts)

    ctx = {
        "server": server,
        "view_filter": view_filter,
        "counts": counts,
        "findings": findings_list,
        "application_groups": application_groups,
        "pending_grouping_counts": pending_grouping_counts,
        "risk_band_header_counts": risk_band_header_counts,
        "default_open_band": default_open_band,
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


def _pick_default_open_band(header_counts: dict[str, int]) -> str | None:
    """Bestimmt das erste Band das im Initial-Render aufgeklappt sein soll.

    Priorisiert ESCALATE, faellt sonst auf das erste nicht-leere Band in
    `_RISK_BAND_SECTION_ORDER` zurueck.
    """
    if header_counts.get("escalate", 0) > 0:
        return "escalate"
    for band in _RISK_BAND_SECTION_ORDER:
        if header_counts.get(band, 0) > 0:
            return band
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


# Whitelist der Risk-Bands fuer die Pending-Grouping-Sektion (ADR-0025 §3).
# Wird sowohl vom Default-Loader (`_load_server_band_aggregates`) als auch
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

    sess = get_session()

    # Block Y / ADR-0039: Initial-Render-Reduktion. Wir laden hier alles
    # was der First-Paint braucht — nichts mehr. Sparklines, Heartbeat,
    # Trend, Host-Snapshot, Noise und Triage-Findings kommen ueber HTMX-
    # Fragment-Endpoints (Phase B/C).
    application_groups = _load_application_groups_for_server(sess, server.id)
    band_aggs = _load_server_band_aggregates(sess, server.id)
    risk_band_header_counts = _risk_band_header_counts(sess, server.id)
    default_open_band = _pick_default_open_band(risk_band_header_counts)

    section_ctx = _render_findings_section(
        server,
        view_filter,
        application_groups=application_groups,
        pending_grouping_counts=band_aggs["pending_by_band"],
        risk_band_header_counts=risk_band_header_counts,
        default_open_band=default_open_band,
    )
    # v0.9.3 (ADR-0023 §c): "Was zu tun ist"-Sektion zwischen Header und
    # Host-Snapshot. Wenn die View nicht im `list`-Mode laeuft, sind die
    # `application_groups` leer und die Sektion bleibt unsichtbar.
    action_sections = _build_action_sections(application_groups)

    quick_counts = _quick_counts_for_server(sess, server.id)
    action_required = {
        "yes_count": band_aggs["yes_count"],
        "no_count": band_aggs["no_count"],
        "yes_subcounts": band_aggs["yes_subcounts"],
        "no_subcounts": band_aggs["no_subcounts"],
        "noise_count": band_aggs["noise_count"],
    }
    tendency: Tendency = _tendency_quick(sess, server.id)

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
        quick_counts=quick_counts,
        total_findings_count=quick_counts["total_all"],
        action_required=action_required,
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

    Block Y Phase D Hinweis: ``select(Finding)`` ist hier bewusst beibehalten
    — das Template ``_partials/group_findings_table.html`` greift auf eine
    breite Palette von ORM-Feldern und Beziehungs-Properties zu (Note-Counts,
    Severity-Display-Helpers etc.), eine Projektions-Migration wuerde die
    Template-Schnittstelle brechen. Die Projektions-Umstellung dieses
    Endpoints ist als Folge-Refactor ausserhalb von Block Y geplant
    (Triage-Page-Endpoint ist bereits projektiert, dieser Lazy-Endpoint
    folgt).
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

    Block Y Phase D Hinweis: ``select(Finding)`` ist hier bewusst beibehalten
    — das Template ``_partials/pending_findings_table.html`` greift auf
    dieselbe breite Palette von ORM-Feldern wie der Group-Lazy-Endpoint zu.
    Die Projektions-Migration ist als Folge-Refactor ausserhalb Block Y
    geplant.
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


def _quick_counts_for_server(sess: Any, server_id: int) -> dict[str, int]:
    """Liefert OPEN-Counts pro Severity + KEV + Total fuer die KPI-Kacheln.

    Eine einzige aggregierte Query mit `FILTER (WHERE …)`-Clauses,
    Server-scoped (keine Tag-Filterung).

    `total_all` enthaelt alle Findings unabhaengig vom Status (fuer den
    HeaderStats-Eyebrow "von N Findings gesamt").
    """
    from app.models import Severity

    is_open = Finding.status == FindingStatus.OPEN
    stmt = select(
        func.count().label("total_all"),
        func.count().filter(is_open).label("total_open"),
        func.count().filter(is_open, Finding.is_kev.is_(True)).label("kev_open"),
        func.count().filter(is_open, Finding.severity == Severity.CRITICAL).label("critical_open"),
        func.count().filter(is_open, Finding.severity == Severity.HIGH).label("high_open"),
        func.count().filter(is_open, Finding.severity == Severity.MEDIUM).label("medium_open"),
        func.count().filter(is_open, Finding.severity == Severity.LOW).label("low_open"),
    ).where(Finding.server_id == server_id)
    row = sess.execute(stmt).one()
    return {
        "total_all": int(row.total_all or 0),
        "total_open": int(row.total_open or 0),
        "kev_open": int(row.kev_open or 0),
        "critical_open": int(row.critical_open or 0),
        "high_open": int(row.high_open or 0),
        "medium_open": int(row.medium_open or 0),
        "low_open": int(row.low_open or 0),
    }


# ---------------------------------------------------------------------------
# Block Y / ADR-0039 Phase B: HTMX-Fragment-Endpoints
# ---------------------------------------------------------------------------


@server_detail_bp.get("/<int:server_id>/fragments/sparklines")
@login_required
def sparklines_fragment(server_id: int) -> str:
    """HTMX-Fragment: KPI-Tiles inklusive 30-Tage-Sparklines.

    Liefert den Wrapper-DIV `#sd-tiles` mit den vier KPI-Cards (KEV,
    Critical, High, Medium). Wird beim Initial-Render via
    `hx-trigger="load"` automatisch geholt und ersetzt den Skeleton.
    """
    server = _load_active_server_or_404(server_id)
    sess = get_session()
    quick_counts = _quick_counts_for_server(sess, server.id)
    sparklines = severity_snapshots_for_server(sess, server.id, days=30)
    return render_template(
        "servers/_partials/sparklines_fragment.html",
        server=server,
        quick_counts=quick_counts,
        sparklines=sparklines,
    )


@server_detail_bp.get("/<int:server_id>/fragments/heartbeat")
@login_required
def heartbeat_fragment(server_id: int) -> str:
    """HTMX-Fragment: 30-Tage-Heartbeat-Bar.

    Bei never-scanned-Servern (host_state_snapshot_at IS NULL) liefert der
    Endpoint den `--empty`-State statt einer leeren Bar.
    """
    server = _load_active_server_or_404(server_id)
    sess = get_session()
    cells: list[Any] = []
    if server.host_state_snapshot_at is not None:
        per_server = heartbeats_for_servers(sess, [server.id], days=30)
        cells = per_server.get(server.id, [])
    return render_template(
        "servers/_partials/heartbeat_fragment.html",
        server=server,
        cells=cells,
    )


@server_detail_bp.get("/<int:server_id>/fragments/host-snapshot")
@login_required
def host_snapshot_fragment(server_id: int) -> str:
    """HTMX-Fragment: Listeners- und Services-Slide-Down-Panels."""
    server = _load_active_server_or_404(server_id)
    sess = get_session()
    snapshot = _load_host_snapshot(sess, server.id)
    return render_template(
        "servers/_partials/host_snapshot_fragment.html",
        server=server,
        listeners=snapshot["listeners"],
        services=snapshot["services"],
        processes=snapshot["processes"],
    )


@server_detail_bp.get("/<int:server_id>/fragments/trend")
@login_required
def trend_fragment(server_id: int) -> str:
    """HTMX-Fragment: Severity-Trend-Chart + Tendency-OOB-Swap.

    Liefert das volle 30-Tage-Aggregations-Chart und ueberschreibt die im
    Header gerenderte Quick-Schaetzung des Tendency-Spans per OOB-Swap.
    """
    server = _load_active_server_or_404(server_id)
    sess = get_session()
    trend_data = daily_severity_counts_for_server(sess, server.id, days=30)
    tendency = tendency_from_counts(trend_data)
    return render_template(
        "servers/_partials/trend_fragment.html",
        server=server,
        trend_data=trend_data,
        tendency=tendency,
    )


@server_detail_bp.get("/<int:server_id>/fragments/noise")
@login_required
def noise_fragment(server_id: int) -> str:
    """HTMX-Fragment: Bulk-Ack-Noise-Toolbar + Modal.

    Liefert den Toolbar-Slot in `_findings_section.html`. Wenn kein Noise
    existiert, ist das Fragment leer (Slot bleibt im DOM, aber unsichtbar).
    Pragmatischer Phase-B-Pfad: die Bulk-Ack-Noise-Alpine-Komponente lebt
    erst nach dem Swap im DOM — Re-Init via `htmx:afterSwap` ist
    Folge-Schritt.

    Block Y Phase D Hinweis: ``select(Finding)`` ist hier bewusst beibehalten
    — das Bulk-Ack-Noise-Modal rendert volle Finding-Karten mit Severity-
    Display, Package-Links und Note-Status; eine Projektion wuerde die
    Modal-Schnittstelle brechen. Limit 50 deckelt die Hydrations-Kosten.
    """
    server = _load_active_server_or_404(server_id)
    sess = get_session()
    noise_total = (
        sess.execute(
            select(func.count(Finding.id)).where(
                Finding.server_id == server.id,
                Finding.status == FindingStatus.OPEN,
                Finding.risk_band == "noise",
            )
        ).scalar()
        or 0
    )
    noise_findings: list[Finding] = []
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
    return render_template(
        "servers/_partials/noise_fragment.html",
        server=server,
        noise_total=int(noise_total),
        noise_findings=noise_findings,
    )


# ---------------------------------------------------------------------------
# Block Y / ADR-0039 Phase C: Triage-Queue Lazy + Paginated
# ---------------------------------------------------------------------------


# Page-Size fuer die Triage-Queue-Pagination (ADR-0039 §3).
_TRIAGE_PAGE_SIZE = 10


def _triage_severity_sort_expr() -> Any:
    """CASE-Expression: Severity -> numerischer Rank fuer ASC-Sortierung.

    ADR-0039 §3 verlangt `severity ASC` mit `CRITICAL=0`. Da `Finding.severity`
    eine Postgres-ENUM-Spalte mit Werten `critical`/`high`/`medium`/`low`/
    `unknown` ist, wuerde `Finding.severity.asc()` alphabetisch sortieren
    (`critical < high < low < medium < unknown`) — Reihenfolge waere falsch.
    Daher explizites CASE-Mapping.
    """
    return case(
        (Finding.severity == Severity.CRITICAL, 0),
        (Finding.severity == Severity.HIGH, 1),
        (Finding.severity == Severity.MEDIUM, 2),
        (Finding.severity == Severity.LOW, 3),
        (Finding.severity == Severity.UNKNOWN, 4),
        else_=5,
    )


@server_detail_bp.get("/<int:server_id>/triage/<string:band>")
@login_required
def triage_band_fragment(server_id: int, band: str) -> str:
    """HTMX-Fragment: paginierte Findings fuer ein Risk-Band (Block Y Phase C).

    ADR-0039 §3:
      - Whitelist-Validierung des Band-Parameters gegen
        `_RISK_BAND_SECTION_ORDER` (400 bei ungueltigem Wert).
      - 404 bei unbekanntem oder revoked/retired Server.
      - Page-Size 25, seitenbasierte Vor/Zurueck-Navigation (Footer mit
        `Seite N von M · X Findings`). Ein COUNT-Query liefert den Total
        fuer `total_pages` und den Footer-Zaehler.
      - Sort: `is_kev DESC, severity ASC (CRITICAL=0), epss_score DESC NULLS LAST`.
      - Projektion auf 13 Spalten — keine ORM-Hydration.
    """
    if band not in _RISK_BAND_SECTION_ORDER:
        abort(400)
    server = _load_active_server_or_404(server_id)
    raw_page = request.args.get("page", "1")
    try:
        page = int(raw_page)
    except (TypeError, ValueError):
        abort(400)
    if page < 1:
        page = 1

    sess = get_session()
    base_where = (
        Finding.server_id == server_id,
        Finding.status == FindingStatus.OPEN,
        Finding.risk_band == band,
    )
    # Gesamt-Count fuer die seitenbasierte Pagination (ADR-0039 §3, Design
    # `docs/design/ServerDetail.jsx` WorkflowCard-Footer): der Operator
    # navigiert per Vor/Zurueck zwischen Seiten — dafuer braucht das Footer
    # `Seite N von M` plus den Gesamt-Findings-Zaehler. Ein zweiter schlanker
    # COUNT-Roundtrip; die Findings-Query bleibt projiziert.
    total = int(sess.execute(select(func.count(Finding.id)).where(*base_where)).scalar() or 0)
    total_pages = max(1, (total + _TRIAGE_PAGE_SIZE - 1) // _TRIAGE_PAGE_SIZE)
    if page > total_pages:
        page = total_pages

    stmt = (
        select(
            Finding.id,
            Finding.identifier_key,
            Finding.title,
            Finding.package_name,
            Finding.installed_version,
            Finding.fixed_version,
            Finding.epss_score,
            Finding.cvss_v3_score,
            Finding.severity,
            Finding.is_kev,
            Finding.risk_band_reason,
            Finding.status,
            Finding.finding_class,
        )
        .where(*base_where)
        .order_by(
            Finding.is_kev.desc(),
            _triage_severity_sort_expr().asc(),
            nulls_last(Finding.epss_score.desc()),
        )
        .limit(_TRIAGE_PAGE_SIZE)
        .offset((page - 1) * _TRIAGE_PAGE_SIZE)
    )
    findings = list(sess.execute(stmt).all())
    return render_template(
        "servers/_partials/triage_findings_page.html",
        findings=findings,
        server=server,
        band=band,
        page=page,
        total=total,
        total_pages=total_pages,
        has_prev=page > 1,
        has_next=page < total_pages,
    )


__all__ = ["server_detail_bp"]
