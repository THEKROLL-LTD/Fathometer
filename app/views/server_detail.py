# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

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
`application_group`, `sort`, `dir`.

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
    _severity_rank_expr,
    count_findings,
)
from app.services.heartbeat_aggregation import heartbeats_for_servers
from app.services.listener_exposure import classify_exposure
from app.services.llm_fingerprints import group_findings_fingerprint
from app.services.pass2_input_selection import FIX_LANES
from app.services.risk_engine import (
    RISK_BAND_SORT_RANK,
    RiskBand,
    fix_lane_sql_case,
    no_band_values,
    yes_band_values,
)
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
    """Liefert die Application-Groups fuer den Server, gruppiert nach Fix-Lane.

    Block P (ADR-0023): Findings werden in der Server-Detail-Findings-Section
    nach `application_group_id` gruppiert.

    Block Q (ADR-0025 §2): der Loader rendert nur noch das Card-Inventar.
    Die Findings-Tabellen pro Group werden vom Browser via HTMX-Lazy-Load
    nachgefordert (`group_findings_fragment`-Endpoint).

    Block Y / ADR-0039 §4: die Queries holen Projektionen (SQLAlchemy
    `Row`-Objekte) statt voller ORM-Objekte — die Templates und
    `_build_action_sections` greifen nur auf eine Handvoll Spalten zu.

    ADR-0053 (Fix-Lane-Evaluation), erweitert ADR-0061: Pass 2 bewertet pro
    Fix-Lane statt pro Gruppe. Die Junction-Tabelle traegt jetzt bis zu
    drei Rows pro `(group, server)` — `patch`-, `upstream`- und
    `mitigate`-Lane. Die Lane-Zugehoerigkeit eines Findings folgt
    deterministisch aus `Finding.finding_class` UND `Finding.has_fix` ueber
    den Single-Source-SQL-Spiegel `risk_engine.fix_lane_sql_case`
    (`not has_fix` -> mitigate, `has_fix & os-pkgs` -> patch, `has_fix &
    lang-pkgs/other` -> upstream) — kein LLM-Output, kein eigener Query.
    Da `has_fix` allein die Lane NICHT mehr bestimmt (eine Group kann
    os-pkgs+fix -> patch UND lang-pkgs+fix -> upstream haben, beide
    `has_fix=True`), gruppieren/distinct'en die Queries auf den
    Lane-CASE-Ausdruck statt auf `has_fix`.

    Vier aggregierte Queries:

      1. Count-Aggregat: `GROUP BY application_group_id, <lane_case>` — pro
         `(group, lane)` die Anzahl OPEN-Findings. Liefert gleichzeitig die
         Liste relevanter Group-IDs (mindestens 1 OPEN-Finding) und das
         Lane-Inventar pro Group. Nur Lanes mit count > 0 erscheinen.
      2. Group-Metadaten-Batch (Projektion): id, label, group_kind,
         explanation.
      3. Junction-Batch (Projektion): group_id, **fix_lane**, risk_band,
         risk_band_reason, worst_finding_id, action_type,
         risk_band_computed_at. Indiziert nach `(group_id, fix_lane)`.
         Fehlende Rows bedeuten "Lane nicht bewertet".
      4. Live-Worst-Finding-Batch (TICKET-010 / ADR-0052, Bug C):
         `DISTINCT ON (application_group_id, <lane_case>)` ueber die
         OPEN-Findings aller `group_ids`, Order beginnt mit
         `(application_group_id, <lane_case>)` und folgt dann der
         §15-Triage-Order — so bekommt jede Lane ihren EIGENEN Live-Worst.
         Projektion: application_group_id, fix_lane, id, identifier_key,
         package_name, title.

    Rueckgabe-Format: list[dict], EINE dict pro Group, mit Keys:

      - `group`: Row (id, label, group_kind, explanation).
      - `count`: int — Summe der OPEN-Findings ueber alle Lanes der Group.
      - `lanes`: list[dict] — nur Lanes mit >= 1 OPEN-Finding, Reihenfolge
        `patch`, `upstream`, `mitigate` (FIX_LANES-Order). Pro Lane-Eintrag:
          - `fix_lane`: "patch" | "upstream" | "mitigate".
          - `evaluation`: Row | None — die `(group, server, lane)`-Eval.
          - `count`: int — OPEN-Findings dieser Lane.
          - `worst_finding`: Row | None — Live-Worst INNERHALB der Lane.
          - `worst_finding_drift`: bool — die Lane-Eval ist veraltet ggue.
            dem aktuellen Lane-OPEN-Set: Lane-Fingerprint != Eval-
            `group_findings_fingerprint` ODER `worst_finding_id` nicht mehr
            offen (ADR-0052 Entscheidung 2 i.d.F. TICKET-014, Hint
            "re-evaluation pending"). Selbes Kriterium wie das Enqueue-Gate,
            NICHT "LLM-Worst != Triage-Live-Worst".

    Sortierung der Groups: DESC nach der **Max-Urgency ueber ihre Lanes** —
    der hoechste `RISK_BAND_SORT_RANK` unter den Lane-Evals der Group; eine
    Lane ohne Eval-Row zaehlt als `pending`-Rank. So stehen Groups mit einer
    escalate-Lane oben, egal in welcher Lane.
    """
    # (1) Count-Aggregat pro (group, lane): `GROUP BY application_group_id,
    # <lane_case>`. Liefert die Group-IDs (>= 1 OPEN-Finding) und das Lane-
    # Inventar. Lane folgt aus dem Single-Source-SQL-Spiegel
    # `fix_lane_sql_case` (finding_class + has_fix), NICHT mehr aus has_fix
    # allein — sonst kollabierten os-pkgs+fix (patch) und lang-pkgs+fix
    # (upstream) faelschlich in einen Bucket.
    count_lane_case = fix_lane_sql_case(Finding.finding_class, Finding.has_fix)
    count_stmt = (
        select(
            Finding.application_group_id,
            count_lane_case.label("fix_lane"),
            func.count(Finding.id),
        )
        .where(
            Finding.server_id == server_id,
            Finding.status == FindingStatus.OPEN,
            Finding.application_group_id.is_not(None),
        )
        .group_by(Finding.application_group_id, count_lane_case)
    )
    # lane_counts_by_group[group_id][lane] = count (nur Lanes mit count > 0).
    lane_counts_by_group: dict[int, dict[str, int]] = {}
    total_count_by_group: dict[int, int] = {}
    for group_id, lane, n in sess.execute(count_stmt).all():
        if group_id is None:
            continue
        gid = int(group_id)
        lane = str(lane)
        count = int(n)
        if count <= 0:
            continue
        lane_counts_by_group.setdefault(gid, {})[lane] = count
        total_count_by_group[gid] = total_count_by_group.get(gid, 0) + count

    if not lane_counts_by_group:
        return []

    # (2) Group-Metadaten-Batch (Projektion): nur die Spalten die Templates
    # und `_build_action_sections` brauchen.
    group_ids = list(lane_counts_by_group.keys())
    groups_stmt = select(
        ApplicationGroup.id,
        ApplicationGroup.label,
        ApplicationGroup.group_kind,
        ApplicationGroup.explanation,
    ).where(ApplicationGroup.id.in_(group_ids))
    groups: list[Any] = list(sess.execute(groups_stmt).all())

    # (3) Junction-Batch (Projektion): bis zu zwei Rows pro Group (eine je
    # Lane). Indiziert nach `(group_id, fix_lane)`.
    evaluations_by_lane: dict[tuple[int, str], Any] = {}
    eval_stmt = select(
        ApplicationGroupEvaluation.group_id,
        ApplicationGroupEvaluation.fix_lane,
        ApplicationGroupEvaluation.risk_band,
        ApplicationGroupEvaluation.risk_band_reason,
        ApplicationGroupEvaluation.worst_finding_id,
        ApplicationGroupEvaluation.action_type,
        ApplicationGroupEvaluation.risk_band_computed_at,
        ApplicationGroupEvaluation.group_findings_fingerprint,
    ).where(
        ApplicationGroupEvaluation.server_id == server_id,
        ApplicationGroupEvaluation.group_id.in_(group_ids),
    )
    for row in sess.execute(eval_stmt).all():
        evaluations_by_lane[(int(row.group_id), str(row.fix_lane))] = row

    # (4) Live-Worst-Finding-Batch pro Lane (TICKET-010 / ADR-0052, Bug C):
    # `DISTINCT ON (application_group_id, <lane_case>)` — pro `(group, lane)`
    # das Top-Finding nach §15-Triage-Order, ausschliesslich OPEN-Findings.
    # `DISTINCT ON` verlangt dass die ORDER BY mit denselben Ausdruecken
    # beginnt; danach folgt die Triage-Order (Single-Source fuer den
    # Severity-Rank: `findings_query._severity_rank_expr`). Postgres verlangt
    # dass die DISTINCT-ON-Ausdruecke die fuehrenden ORDER-BY-Ausdruecke sind
    # — derselbe `case`-Objekt-Identitaet (`worst_lane_case`) wird in
    # distinct() UND order_by() verwendet.
    worst_lane_case = fix_lane_sql_case(Finding.finding_class, Finding.has_fix)
    worst_stmt = (
        select(
            Finding.application_group_id,
            worst_lane_case.label("fix_lane"),
            Finding.id,
            Finding.identifier_key,
            Finding.package_name,
            Finding.title,
        )
        .where(
            Finding.server_id == server_id,
            Finding.status == FindingStatus.OPEN,
            Finding.application_group_id.in_(group_ids),
        )
        .distinct(Finding.application_group_id, worst_lane_case)
        .order_by(
            Finding.application_group_id,
            worst_lane_case,
            Finding.is_kev.desc(),
            nulls_last(Finding.epss_score.desc()),
            nulls_last(Finding.cvss_v3_score.desc()),
            _severity_rank_expr().desc(),
            Finding.first_seen_at.asc(),
        )
    )
    worst_by_lane: dict[tuple[int, str], Any] = {}
    for row in sess.execute(worst_stmt).all():
        worst_by_lane[(int(row.application_group_id), str(row.fix_lane))] = row

    # (5) Lane-OPEN-Set-Projektion (TICKET-014): die `(identifier_key,
    # package_purl, id)` ALLER OPEN-Findings pro `(group, lane)` — Basis fuer
    # den Drift-Hint. Aus diesen Rows wird pro Lane sowohl der
    # `group_findings_fingerprint` (Read-Reuse von `llm_fingerprints`, liest
    # nur `.identifier_key`/`.package_purl`) als auch das `id`-Set gebildet.
    # Bewusst getrennt von Query (4): Query (4) liefert per `DISTINCT ON` nur
    # das Top-Finding pro Lane, hier brauchen wir das gesamte Lane-OPEN-Set.
    open_lane_case = fix_lane_sql_case(Finding.finding_class, Finding.has_fix)
    lane_open_stmt = select(
        Finding.application_group_id,
        open_lane_case.label("fix_lane"),
        Finding.id,
        Finding.identifier_key,
        Finding.package_purl,
    ).where(
        Finding.server_id == server_id,
        Finding.status == FindingStatus.OPEN,
        Finding.application_group_id.in_(group_ids),
    )
    lane_rows_by_lane: dict[tuple[int, str], list[Any]] = {}
    for row in sess.execute(lane_open_stmt).all():
        key = (int(row.application_group_id), str(row.fix_lane))
        lane_rows_by_lane.setdefault(key, []).append(row)

    result: list[dict[str, Any]] = []
    for grp in groups:
        gid = int(grp.id)
        lane_counts = lane_counts_by_group.get(gid, {})
        lanes: list[dict[str, Any]] = []
        # Reihenfolge: patch, upstream, mitigate (FIX_LANES-Order). Nur
        # Lanes mit >= 1 OPEN-Finding erscheinen.
        for lane in FIX_LANES:
            count = lane_counts.get(lane, 0)
            if count <= 0:
                continue
            ev = evaluations_by_lane.get((gid, lane))
            worst = worst_by_lane.get((gid, lane))
            # Drift-Kennzeichnung (ADR-0052 Entscheidung 2, korrigiert durch
            # TICKET-014): der Hint "re-evaluation pending" haengt am SELBEN
            # Kriterium wie das Enqueue-Gate (`pass2_enqueue`) — die
            # gespeicherte Eval ist veraltet ggue. dem aktuellen Lane-OPEN-Set.
            # Das ist NICHT "LLM-Worst != Triage-Live-Worst" (das ist der
            # erwartete Normalfall und wuerde dauerhaft falsch-positiv
            # feuern). Drift gilt genau dann, wenn:
            #   (a) der Lane-Fingerprint vom Eval-Fingerprint abweicht — das
            #       OPEN-Set hat sich seit der Eval geaendert (neu/resolved/
            #       acked/reopened); beim naechsten Scan-/Triage-Trigger wird
            #       tatsaechlich enqueued und der Hint verschwindet (kein Loop)
            #   ODER
            #   (b) das Snapshot-Worst-Finding nicht mehr im Lane-OPEN-Set
            #       ist (inzwischen geschlossen) — deckt den TICKET-010-Fall.
            # `worst_finding_id is None` ist kein Drift (Snapshot hat nie auf
            # ein Finding gezeigt).
            lane_rows = lane_rows_by_lane.get((gid, lane), [])
            lane_fp = group_findings_fingerprint(lane_rows)
            lane_open_ids = {int(r.id) for r in lane_rows}
            drift = bool(
                ev is not None
                and (
                    ev.group_findings_fingerprint != lane_fp
                    or (
                        ev.worst_finding_id is not None
                        and int(ev.worst_finding_id) not in lane_open_ids
                    )
                )
            )
            lanes.append(
                {
                    "fix_lane": lane,
                    "evaluation": ev,
                    "count": count,
                    "worst_finding": worst,
                    "worst_finding_drift": drift,
                }
            )
        result.append(
            {
                "group": grp,
                "count": total_count_by_group.get(gid, 0),
                "lanes": lanes,
            }
        )

    # Sortierung: DESC nach Max-Urgency ueber die Lanes der Group. Eine Lane
    # ohne Junction-Row zaehlt als PENDING-Rank — Operator soll Groups mit
    # einer escalate-Lane oben sehen, egal in welcher Lane.
    def _lane_rank(lane_entry: dict[str, Any]) -> int:
        ev = lane_entry["evaluation"]
        if ev is None:
            return RISK_BAND_SORT_RANK[RiskBand.PENDING]
        try:
            return RISK_BAND_SORT_RANK[RiskBand(ev.risk_band)]
        except (KeyError, ValueError):
            return 0

    def _group_rank(entry: dict[str, Any]) -> int:
        lanes = entry["lanes"]
        if not lanes:
            return RISK_BAND_SORT_RANK[RiskBand.PENDING]
        return max(_lane_rank(lane) for lane in lanes)

    result.sort(key=_group_rank, reverse=True)
    return result


def _build_action_sections(
    application_groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Baut die "Was zu tun ist"-Card-Sektionen fuer den Server-Detail-Header.

    Block P / v0.9.3 (ADR-0023 §"Update v0.9.3 (c)"): die 4-Band-Reduktion
    deckt die operative Frage "patchen vs. mitigieren vs. App-Vendor-Update"
    nicht ab. Diese strukturierte Aktions-Sektion teilt die
    Operator-Workflows visuell in bis zu sechs Cards auf — in der Reihenfolge
    operativer Dringlichkeit. Leere Cards werden geskippt; die ganze Sektion
    blendet sich im Template aus wenn das Ergebnis leer ist.

    Die Card-Filter spiegeln das ``(risk_band, action_type, group_kind)``-
    Tripel aus der ADR-Tabelle. NULL-``action_type``-Groups (vor dem ersten
    Pass-2-Re-Eval) matchen **keine** Card und sind absichtlich unsichtbar;
    sie tauchen wieder auf sobald der Worker das Feld setzt.

    TICKET-013 / ADR-0053 (Fix-Lane-Evaluation): die Eingabe ist jetzt der
    Lane-Kontrakt von :func:`_load_application_groups_for_server` — eine
    dict pro Group mit ``lanes: list[...]``. Das Matching iteriert ueber
    ``(group, lane)``: jede Lane mit ``evaluation is not None`` ist ein
    flacher Eintrag, der wie bisher auf ``risk_band``, ``action_type`` und
    ``group_kind`` gematcht wird. Eine Group kann so in **zwei** Cards
    erscheinen (patch-Lane -> Patch-Card, mitigate-Lane -> mitigate-Card) —
    je mit ihrem Lane-Worst (live, ADR-0052). Es gibt **kein** ``act +
    mitigate``/``act + upstream`` (``act`` ist per Band-Whitelist patch-only).
    ADR-0061: die ``upstream``-Lane (lang-pkgs-Fix, nicht host-applizierbar)
    teilt sich den abgeleiteten ``action_type == "mitigate"`` mit der echten
    no-patch-Lane; die zwei escalate-Cards werden daher zusaetzlich ueber
    ``fix_lane`` diskriminiert (``escalate-mitigate`` vs. ``escalate-upstream``).

    Eintrags-Format (flach, pro `(group, lane)`):
    ``{"group", "fix_lane", "evaluation", "count", "worst_finding",
    "worst_finding_drift"}`` — das Template liest ``entry.group``,
    ``entry.evaluation.risk_band_reason``, ``entry.worst_finding`` und
    ``entry.worst_finding_drift``.
    """
    card_specs: list[dict[str, Any]] = [
        {
            "id": "escalate-distro-patch",
            "label": "ESCALATE · Patch distro",
            "variant": "escalate-distro",
            "risk_band": "escalate",
            "action_type": "patch",
            "group_kind": "os_package",
            "show_labels": True,
        },
        {
            "id": "escalate-app-update",
            "label": "ESCALATE · Apply app update",
            "variant": "escalate-app",
            "risk_band": "escalate",
            "action_type": "patch",
            "group_kind": "application_bundle",
            "show_labels": True,
        },
        {
            "id": "escalate-mitigate",
            "label": "ESCALATE · No patch — mitigate",
            "variant": "escalate-mitigate",
            "risk_band": "escalate",
            "action_type": "mitigate",
            "fix_lane": "mitigate",
            "group_kind": None,
            "show_labels": True,
        },
        {
            # ADR-0061: lang-pkgs-Fixes sind nicht host-applizierbar. Die
            # upstream-Lane teilt sich den abgeleiteten action_type "mitigate"
            # mit der echten no-patch-mitigate-Lane (escalate->mitigate), daher
            # diskriminiert hier zusaetzlich ``fix_lane``. Card-Copy macht
            # klar: ein Fix existiert upstream, ist aber nur per Rebuild des
            # besitzenden Pakets applizierbar (kein dnf/apt-Patch).
            "id": "escalate-upstream",
            "label": "ESCALATE · Upstream fix — mitigate until rebuild",
            "variant": "escalate-upstream",
            "risk_band": "escalate",
            "action_type": "mitigate",
            "fix_lane": "upstream",
            "group_kind": None,
            "show_labels": True,
        },
        {
            "id": "act-distro-patch",
            "label": "ACT · Patch distro (normal cycle)",
            "variant": "act-distro",
            "risk_band": "act",
            "action_type": "patch",
            "group_kind": "os_package",
            "show_labels": False,
        },
        {
            "id": "act-app-update",
            "label": "ACT · Apply app update (normal cycle)",
            "variant": "act-app",
            "risk_band": "act",
            "action_type": "patch",
            "group_kind": "application_bundle",
            "show_labels": False,
        },
    ]

    # Flache `(group, lane)`-Eintraege aus dem Lane-Kontrakt aufbauen — nur
    # Lanes mit Eval-Row (ohne Junction-Row gibt es weder Band noch
    # Action-Type; die Lane matcht keine Card).
    lane_entries: list[dict[str, Any]] = []
    for group_entry in application_groups:
        grp = group_entry["group"]
        for lane in group_entry["lanes"]:
            ev = lane.get("evaluation")
            if ev is None:
                continue
            lane_entries.append(
                {
                    "group": grp,
                    "fix_lane": lane["fix_lane"],
                    "evaluation": ev,
                    "count": lane["count"],
                    "worst_finding": lane["worst_finding"],
                    "worst_finding_drift": lane["worst_finding_drift"],
                }
            )

    result: list[dict[str, Any]] = []
    for spec in card_specs:
        matches: list[dict[str, Any]] = []
        for entry in lane_entries:
            grp = entry["group"]
            ev = entry["evaluation"]
            if ev.risk_band != spec["risk_band"]:
                continue
            if ev.action_type != spec["action_type"]:
                continue
            # ADR-0061: ``fix_lane``-Diskriminator nur wo gesetzt (escalate-
            # mitigate vs. escalate-upstream teilen action_type "mitigate").
            if spec.get("fix_lane") is not None and entry["fix_lane"] != spec["fix_lane"]:
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

    Block AA (ADR-0041): der Flat-Switch und die flache Tabelle sind entfernt.
    `_findings_section.html` rendert unkonditional die Group-Card-Ansicht; die
    Form-Objekte werden immer in den Context gehaengt (Bulk-Toolbar +
    Lazy-Fragment-Bodies).
    """
    sess = get_session()
    findings_filter = view_filter.to_findings_filter()

    counts = count_findings(sess, server.id, findings_filter)

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
        # Block AA (ADR-0041): kein Flat-Pfad mehr — `findings` bleibt leer
        # (Backward-Compat falls ein Template den Key referenziert).
        "findings": [],
        "application_groups": application_groups,
        "pending_grouping_counts": pending_grouping_counts,
        "risk_band_header_counts": risk_band_header_counts,
        "default_open_band": default_open_band,
        # Form-Objekte unkonditional — Bulk-Toolbar + Lazy-Fragment-Bodies.
        "ack_form": AcknowledgeForm(),
        "reopen_form": ReopenForm(),
        "note_form": NoteForm(),
        "bulk_form": BulkActionForm(),
        "csrf_form": CSRFOnlyForm(),
    }
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
            .options(selectinload(Finding.notes))
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
        note_form=NoteForm(),
        csrf_form=CSRFOnlyForm(),
        ack_form=AcknowledgeForm(),
        reopen_form=ReopenForm(),
    )


@server_detail_bp.get("/<int:server_id>/findings/pending")
@login_required
def pending_findings_fragment(server_id: int) -> str:
    """HTMX-Lazy-Load-Endpoint fuer die Pending-Grouping-Findings pro Risk-Band.

    Block Q (ADR-0025 §3): die Pending-Grouping-Sektion rendert initial nur
    pro Risk-Band einen collapsed `<details>`-Rollup mit Count. Sobald der
    Operator das Bucket-`<details>` aufklappt, holt das HTMX-Pattern das
    `<tbody>`-Fragment hier nach.

    Rueckgabe ist ein HTML-Partial (`_partials/group_findings_table.html` —
    die `<details>`-Variante). 400, wenn `risk_band` fehlt oder nicht in der
    Whitelist (`_PENDING_BANDS`) liegt. 404, wenn der Server nicht existiert
    oder der Bucket auf diesem Server keine OPEN-Findings hat.

    Sortierung ist Spec-fix (siehe ADR-0025 §15-Default): KEV desc, EPSS desc
    nulls last, CVSS desc nulls last, `first_seen_at` asc.

    Block AA (ADR-0041): die Pending-Grouping-Sektion nutzt fortan dieselbe
    `<details class="sd-finding">`-Variante wie der Group-Drilldown
    (`group_findings_table.html`) inkl. `finding_inline_body.html`. Volle
    ORM-Hydration mit `selectinload(Finding.notes)`.
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
            .options(selectinload(Finding.notes))
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
        "_partials/group_findings_table.html",
        findings=findings,
        note_form=NoteForm(),
        csrf_form=CSRFOnlyForm(),
        ack_form=AcknowledgeForm(),
        reopen_form=ReopenForm(),
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
      - Block AA (ADR-0041): die <=10 sichtbaren Rows werden voll als ORM-
        `Finding` hydratisiert (`selectinload(Finding.notes)`) — der Inline-
        Body greift auf `description`/`references`/`primary_url`/`notes` zu.
      - Perf-Refactor 2026-06-07 (Two-Step): die ADR-0041-Annahme
        „Paginations-Groesse 10 macht den Performance-Vorteil
        vernachlaessigbar" hat sich per EXPLAIN (Server mit 14k offenen
        Findings im Band) als falsch erwiesen — `select(Finding) … LIMIT 10`
        materialisierte fuer den Sort *alle* Kandidaten-Rows fett aus dem
        Heap. Daher zweistufig: schlanke `select(Finding.id)`-Query
        (Index-Only ueber `ix_findings_server_open_triage`) fuer Sort+LIMIT,
        dann volle Hydration nur der Seiten-IDs. Output ist identisch.
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

    # Two-Step-Hydration (Perf, EXPLAIN 2026-06-07): die fruehere
    # `select(Finding) … LIMIT 10`-Variante materialisierte fuer den Sort
    # *alle* Kandidaten-Rows des Bands fett aus dem Heap (Q2: 14.027 Rows
    # à ~1.6 KB / ~70 MB Buffer), nur um 10 zu rendern — die LIMIT greift
    # erst nach dem Sort. Stattdessen:
    #   Step 1: schlanke ID-Query nur ueber die Sort-Keys. Laeuft als
    #           Index-Only-Scan ueber `ix_findings_server_open_triage`
    #           (INCLUDE is_kev/severity/epss_score) -> top-N-Sort auf
    #           schmalen Index-Tupeln, kein Heap-Fetch der Nicht-Sichtbaren.
    #   Step 2: volle ORM-Hydration (+ selectinload notes) nur fuer die <=10
    #           sichtbaren IDs. Die `IN`-Query liefert keine Ordnung, daher
    #           re-sortieren wir in Python nach der Step-1-Reihenfolge.
    id_stmt = (
        select(Finding.id)
        .where(*base_where)
        .order_by(
            Finding.is_kev.desc(),
            _triage_severity_sort_expr().asc(),
            nulls_last(Finding.epss_score.desc()),
        )
        .limit(_TRIAGE_PAGE_SIZE)
        .offset((page - 1) * _TRIAGE_PAGE_SIZE)
    )
    page_ids = list(sess.execute(id_stmt).scalars().all())
    if page_ids:
        by_id = {
            f.id: f
            for f in sess.execute(
                select(Finding).options(selectinload(Finding.notes)).where(Finding.id.in_(page_ids))
            )
            .scalars()
            .all()
        }
        findings = [by_id[i] for i in page_ids if i in by_id]
    else:
        findings = []
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
        note_form=NoteForm(),
        csrf_form=CSRFOnlyForm(),
        ack_form=AcknowledgeForm(),
        reopen_form=ReopenForm(),
    )


__all__ = ["server_detail_bp"]
