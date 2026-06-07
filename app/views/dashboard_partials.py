# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Dashboard-Partials-Blueprint (Block W Phase F, ADR-0036).

Stellt den OOB-Polling-Endpoint ``GET /_partials/dashboard/kpis`` bereit.
Der Endpoint antwortet mit einem konsolidierten HTML-Fragment das mehrere
disjunkte OOB-Targets aktualisiert — ohne den Action-Card-Wrapper (der hat
``hx-preserve="true"`` und wird nie ersetzt).

Polling-Cadence: 60 s nur bei sichtbarem Tab (``hx-trigger`` im Pane-Template).
``hx-swap="none"`` am Trigger-Element: der Pane selbst wird nicht ersetzt,
nur die OOB-Fragmente werden angewendet.

Verweise:
  - ADR-0036 §"Endpoint-Response-Skizze"
  - Block W Phase F §"DoD-F Items 1-6"
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Blueprint, render_template
from flask_login import login_required

from app.db import get_session
from app.services.dashboard_kpis import (
    _load_action_needed_card_data,
    _load_nominal_card_data,
    _load_severity_counts,
    _load_triage_counts,
)
from app.services.sysline_context import build_sysline_context

dashboard_partials_bp = Blueprint("dashboard_partials", __name__)


def _load_open_aggregates_for_kpis(
    sess: Any,
) -> tuple[dict[int, int], dict[int, dict[str, int]]]:
    """Konsolidierte Aggregations-Query fuer KEV + Risk-Band-Counts.

    Lokale Kopie der gleichnamigen Funktion aus ``app/views/dashboard.py``
    — wird hier benoetigt damit der Partials-Endpoint ohne Import-Zyklus
    auskommt. Beide Implementierungen muessen synchron gehalten werden.

    Rueckgabe:
      kev_by_server        -- dict[server_id, int]
      risk_bands_by_server -- dict[server_id, dict[risk_band, int]]
    """
    from sqlalchemy import func, select

    from app.models import Finding, FindingStatus

    aggregate_stmt = (
        select(
            Finding.server_id,
            func.count().filter(Finding.is_kev.is_(True)).label("kev"),
            func.count().filter(Finding.risk_band == "escalate").label("rb_escalate"),
            func.count().filter(Finding.risk_band == "act").label("rb_act"),
            func.count().filter(Finding.risk_band == "mitigate").label("rb_mitigate"),
            func.count().filter(Finding.risk_band == "pending").label("rb_pending"),
            func.count().filter(Finding.risk_band == "unknown").label("rb_unknown"),
            func.count().filter(Finding.risk_band == "monitor").label("rb_monitor"),
            func.count().filter(Finding.risk_band == "noise").label("rb_noise"),
        )
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.server_id)
    )

    kev_counts: dict[int, int] = {}
    risk_bands: dict[int, dict[str, int]] = {}

    for row in sess.execute(aggregate_stmt).all():
        sid = int(row.server_id)
        kev_counts[sid] = int(row.kev)
        risk_bands[sid] = {
            "escalate": int(row.rb_escalate),
            "act": int(row.rb_act),
            "mitigate": int(row.rb_mitigate),
            "pending": int(row.rb_pending),
            "unknown": int(row.rb_unknown),
            "monitor": int(row.rb_monitor),
            "noise": int(row.rb_noise),
        }

    return kev_counts, risk_bands


def _active_server_ids_for_kpis(sess: Any) -> set[int]:
    """Gibt die IDs aller aktiven (nicht retired, nicht revoked) Server zurueck."""
    from sqlalchemy import select

    from app.models import Server

    stmt = select(Server.id).where(
        Server.retired_at.is_(None),
        Server.revoked_at.is_(None),
    )
    return set(sess.execute(stmt).scalars().all())


@dashboard_partials_bp.get("/_partials/dashboard/kpis")
@login_required
def dashboard_kpis_oob() -> Any:
    """OOB-Polling-Endpoint fuer alle Dashboard-KPI-Targets (ADR-0036).

    Antwortet mit konsolidierten OOB-Fragmenten fuer:
      - ``#action-needed-num``        (Span: grosse Zahl)
      - ``#action-needed-hosts-total`` (Span: Gesamt-Hosts)
      - ``#action-needed-sub``        (P: escalate/act/pending Counts)
      - ``#nominal-card``             (Div: gesamte Nominal-Card)
      - ``#triage-row``               (Section: Triage-Grid)
      - ``#severity-strip``           (Section: Severity-Bars)
      - ``#sysline``                  (Div: System-Status-Zeile)
      - ``#dashboard-last-refresh``   (Span: Uhrzeit)

    Der ``#action-needed-card``-Wrapper ist NICHT in der Response — er hat
    ``hx-preserve="true"`` und darf nicht ersetzt werden (Scan-Beam-Animation
    laeuft kontinuierlich).

    Polling-Trigger sitzt auf ``#dashboard-pane`` mit ``hx-swap="none"``
    (Pane wird nicht ersetzt, nur OOB-Fragmente werden applied).
    """
    sess = get_session()
    now = datetime.now(tz=UTC)

    # Konsolidierte Aggregations-Query.
    _kev_by_server, risk_bands_by_server = _load_open_aggregates_for_kpis(sess)
    active_server_ids = _active_server_ids_for_kpis(sess)

    # KPI-Card-Daten.
    action_needed_card_data = _load_action_needed_card_data(
        sess, risk_bands_by_server, active_server_ids
    )
    nominal_card_data = _load_nominal_card_data(
        sess,
        risk_bands_by_server,
        active_server_ids,
        hosts_total=action_needed_card_data["hosts_total"],
        action_server_count=action_needed_card_data["server_count"],
    )

    # Triage-Counts (aus vorhandenen Aggregaten, kein extra DB-Roundtrip).
    triage_counts = _load_triage_counts(
        sess,
        risk_bands_by_server=risk_bands_by_server,
        active_server_ids=active_server_ids,
    )

    # Severity-Counts (standalone SELECT).
    severity_counts = _load_severity_counts(sess)

    # Sysline-Context.
    sysline = build_sysline_context(sess, _now=now)

    # Letzte Refresh-Zeit fuer den Eyebrow-Span (HH:MM UTC).
    last_refresh = f"{now.hour:02d}:{now.minute:02d} UTC"

    return render_template(
        "dashboard/_kpis_oob_response.html",
        action_needed_card_data=action_needed_card_data,
        nominal_card_data=nominal_card_data,
        triage_counts=triage_counts,
        severity_counts=severity_counts,
        sysline=sysline,
        last_refresh=last_refresh,
    )


__all__ = ["dashboard_partials_bp"]
