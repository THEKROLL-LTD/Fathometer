"""Dashboard-KPI-Service — Phase D Grundstein + Phase E Erweiterung.

Kapselt die Aggregations-Queries fuer die Context-Keys:
- `action_needed_card_data` und `nominal_card_data` (Phase D)
- `triage_counts` und `severity_counts` (Phase E)

in `app/views/dashboard.py::_build_pane_context`.

Alle Funktionen sind Pure-Function-Wrapper ohne Side-Effects — leicht
Unit-testbar mit Mock-Sessions.

Phase-E-Design-Entscheidung:
  `_load_triage_counts` und `_load_severity_counts` koennen wahlweise
  aus bereits berechneten `risk_bands_by_server`-Daten abgeleitet werden
  (kein DB-Roundtrip) oder direkt ueber einen einzigen SELECT auf der DB.
  `_build_pane_context` nutzt die Ableitung aus vorhandenen Daten;
  die Standalone-Varianten mit Session sind fuer Pure-Unit-Tests exponiert.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Finding, FindingStatus, Server, Severity

# Deterministische Reihenfolge der 7 Triage-Buckets (Design-Spec Phase E).
_TRIAGE_BUCKET_ORDER: tuple[str, ...] = (
    "escalate",
    "act",
    "mitigate",
    "pending",
    "monitor",
    "noise",
    "unknown",
)


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


def _load_triage_counts(
    session: Session,
    *,
    risk_bands_by_server: dict[int, dict[str, int]] | None = None,
    active_server_ids: set[int] | None = None,
) -> dict[str, int]:
    """Aggregierte OPEN-Finding-Counts pro Triage-Bucket (7 Buckets garantiert).

    Liefert immer alle 7 deterministischen Buckets in der Design-Reihenfolge:
      escalate · act · mitigate · pending · monitor · noise · unknown

    Fehlende Bands werden mit 0 aufgefuellt.

    Zwei Betriebsmodi:
    1. **Ableitung** (schnell, kein DB-Roundtrip): wenn `risk_bands_by_server`
       und `active_server_ids` uebergeben werden, werden die Counts aus den
       bereits vorliegenden Pro-Server-Aggregaten summiert. Nutzt
       `_build_pane_context` intern nach `_load_open_aggregates`.

    2. **Standalone** (Pure-Unit-testbar via Mock-Session): wenn keine
       Vorberechnungen vorliegen, fuehrt die Funktion einen einzigen
       GROUP-BY-SELECT auf `findings` durch (OPEN-Findings, GROUP BY risk_band).
       Nutzbar als isolierte Funktion mit einer Fake-Session.

    Argumente:
      session              — aktive SQLAlchemy-Session (wird in Modus 2 genutzt).
      risk_bands_by_server — dict[server_id, dict[risk_band_str, count]].
                             Ergebnis von `_load_open_aggregates`. Optional.
      active_server_ids    — set[int] aktiver Server. Optional.
    """
    base: dict[str, int] = dict.fromkeys(_TRIAGE_BUCKET_ORDER, 0)

    if risk_bands_by_server is not None:
        # Modus 1: Ableitung aus vorhandenen Pro-Server-Aggregaten.
        # active_server_ids einschraenken wenn uebergeben (defensive Defaults).
        filter_ids = active_server_ids  # None == alle
        for sid, bands in risk_bands_by_server.items():
            if filter_ids is not None and sid not in filter_ids:
                continue
            for bucket in _TRIAGE_BUCKET_ORDER:
                base[bucket] += bands.get(bucket, 0)
        return base

    # Modus 2: Standalone-SELECT (ein einziger DB-Roundtrip).
    stmt = (
        select(Finding.risk_band, func.count().label("cnt"))
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.risk_band)
    )
    for row in session.execute(stmt).all():
        band = str(row.risk_band) if row.risk_band is not None else "unknown"
        if band in base:
            base[band] += int(row.cnt)
        else:
            # Unbekannte Bands (z.B. zukuenftige Erweiterungen) landen in
            # "unknown" damit die 7-Bucket-Garantie nicht bricht.
            base["unknown"] += int(row.cnt)

    return base


def _load_severity_counts(
    session: Session,
) -> dict[str, int]:
    """Aggregierte OPEN-Finding-Counts pro Severity (4 Buckets + max_count).

    Liefert immer alle 5 Keys:
      critical · high · medium · low · max_count

    `max_count` = max(critical, high, medium, low).
    Wenn alle Counts 0 sind, wird `max_count=1` gesetzt (Schutz gegen
    Division-by-Zero im Template bei der Bar-Width-Berechnung).

    Ein einziger GROUP-BY-SELECT (OPEN-Findings, GROUP BY severity).
    Pure-Unit-testbar mit Fake-Session die `.execute().all()` mockt.

    Argumente:
      session — aktive SQLAlchemy-Session.
    """
    counts: dict[str, int] = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
    }

    stmt = (
        select(Finding.severity, func.count().label("cnt"))
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.severity)
    )
    for row in session.execute(stmt).all():
        sev = str(row.severity) if row.severity is not None else ""
        if sev in counts:
            counts[sev] += int(row.cnt)
        # UNKNOWN-Severity und andere unerwartete Werte werden ignoriert
        # (sie erscheinen nicht im Severity-Strip).

    raw_max = max(counts.values())
    counts["max_count"] = raw_max if raw_max > 0 else 1

    return counts


__all__ = [
    "_load_action_needed_card_data",
    "_load_nominal_card_data",
    "_load_severity_counts",
    "_load_triage_counts",
]
