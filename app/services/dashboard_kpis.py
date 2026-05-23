"""Dashboard-KPI-Service — Phase D Grundstein.

Kapselt die Aggregations-Queries fuer die neuen Context-Keys
`action_needed_card_data` und `nominal_card_data` in
`app/views/dashboard.py::_build_pane_context`.

Phase E baut darauf auf mit `_load_triage_counts` und
`_load_severity_counts` (7-Bucket-Triage-Row + Severity-Strip).

Beides sind reine Pure-Function-Wrapper ohne Side-Effects — leicht
Unit-testbar mit Mock-Sessions.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Server


def _load_action_needed_card_data(
    session: Session,
    risk_bands_by_server: dict[int, dict[str, int]],
    active_server_ids: set[int],
) -> dict[str, int]:
    """Aggregat-Daten fuer die Action-Needed-Card (stat--alarm).

    Liefert:
      server_count  — Anzahl aktiver Server mit >=1 OPEN-Finding in
                      risk_band IN ('escalate', 'act', 'pending').
      hosts_total   — Gesamtzahl aktiver Server (nicht retired, nicht revoked).
      escalate      — Fleet-weiter OPEN-Finding-Count fuer risk_band='escalate'.
      act           — Fleet-weiter OPEN-Finding-Count fuer risk_band='act'.
      pending       — Fleet-weiter OPEN-Finding-Count fuer risk_band='pending'.

    Nutzt die bereits berechneten `risk_bands_by_server`- und
    `active_server_ids`-Daten aus `_load_open_aggregates` weiter —
    kein separater Distinct-Server-JOIN noetig.

    Argumente:
      session             — aktive SQLAlchemy-Session.
      risk_bands_by_server — dict[server_id, dict[risk_band, count]].
                             Ergebnis von `_load_open_aggregates`.
      active_server_ids   — set[int] aktiver Server (retired=None, revoked=None).
    """
    # Server-Count: aktive Server mit mind. einem Finding in
    # escalate, act oder pending.
    action_bands = {"escalate", "act", "pending"}
    server_count = sum(
        1
        for sid, bands in risk_bands_by_server.items()
        if sid in active_server_ids and any(bands.get(b, 0) > 0 for b in action_bands)
    )

    # Fleet-weite Band-Counts (aus risk_bands_by_server ableiten —
    # identisch mit dem Ergebnis der konsolidierten Findings-Query).
    escalate = sum(
        bands.get("escalate", 0)
        for sid, bands in risk_bands_by_server.items()
        if sid in active_server_ids
    )
    act = sum(
        bands.get("act", 0)
        for sid, bands in risk_bands_by_server.items()
        if sid in active_server_ids
    )
    pending = sum(
        bands.get("pending", 0)
        for sid, bands in risk_bands_by_server.items()
        if sid in active_server_ids
    )

    # Gesamtzahl aktiver Server.
    hosts_total_stmt = select(func.count(Server.id)).where(
        Server.retired_at.is_(None),
        Server.revoked_at.is_(None),
    )
    hosts_total = int(session.execute(hosts_total_stmt).scalar() or 0)

    return {
        "server_count": server_count,
        "hosts_total": hosts_total,
        "escalate": escalate,
        "act": act,
        "pending": pending,
    }


def _load_nominal_card_data(
    session: Session,
    risk_bands_by_server: dict[int, dict[str, int]],
    active_server_ids: set[int],
    hosts_total: int,
    action_server_count: int,
) -> dict[str, int]:
    """Aggregat-Daten fuer die Nominal-Card (stat--safe).

    Liefert:
      monitor_count — Anzahl aktiver Server OHNE Findings in escalate/act/pending
                      (= 'nominal', gruener Bereich).
      hosts_total   — Gesamtzahl aktiver Server (wird durchgereicht).
      monitor       — Fleet-weiter OPEN-Finding-Count fuer risk_band='monitor'.
      noise         — Fleet-weiter OPEN-Finding-Count fuer risk_band='noise'.
      unknown       — Fleet-weiter OPEN-Finding-Count fuer risk_band='unknown'.

    `monitor_count` = hosts_total - action_server_count (Server die NICHT in
    der Action-Needed-Gruppe sind). Nutzt die uebergebenen Vorberechnungen um
    einen separaten DB-Roundtrip zu sparen.

    Argumente:
      session             — aktive SQLAlchemy-Session (fuer kuenftige Erweiterungen).
      risk_bands_by_server — dict[server_id, dict[risk_band, count]].
      active_server_ids   — set[int] aktiver Server.
      hosts_total         — bereits berechneter Gesamt-Active-Server-Count.
      action_server_count — bereits berechneter Action-Needed-Server-Count.
    """
    # monitor_count = aktive Server ohne action-Bands.
    monitor_count = max(0, hosts_total - action_server_count)

    # Fleet-weite Band-Counts aus risk_bands_by_server ableiten.
    monitor = sum(
        bands.get("monitor", 0)
        for sid, bands in risk_bands_by_server.items()
        if sid in active_server_ids
    )
    noise = sum(
        bands.get("noise", 0)
        for sid, bands in risk_bands_by_server.items()
        if sid in active_server_ids
    )
    unknown = sum(
        bands.get("unknown", 0)
        for sid, bands in risk_bands_by_server.items()
        if sid in active_server_ids
    )

    return {
        "monitor_count": monitor_count,
        "hosts_total": hosts_total,
        "monitor": monitor,
        "noise": noise,
        "unknown": unknown,
    }


__all__ = [
    "_load_action_needed_card_data",
    "_load_nominal_card_data",
]
