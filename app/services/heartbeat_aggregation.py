# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Heartbeat-Aggregation fuer die Sidebar-Server-Liste (Block I).

ARCHITECTURE.md §7a (UI v2 Sidebar) und Block-I-Aufgabe 3.

Pro `(server_id, day)` aggregieren wir:

- `max_severity`: hoechste Severity ueber alle Findings die an diesem Tag
  als OPEN gelten (Tagesende-Schnappschuss). `None` wenn an diesem Tag kein
  OPEN-Finding existiert hat.
- `kev_count`: Anzahl OPEN-Findings mit `is_kev=True`.
- `had_scan`: `True` wenn an diesem Tag mindestens ein Scan empfangen wurde.

Implementierungs-Entscheidung (siehe Block-I-Plan): **Variante B —
Python-Service mit Datenbank-Aggregation pro Render**. Es gibt **keine**
materialisierte View und **keine** Alembic-Migration fuer diesen Block, da
die Aggregation fuer den MVP-Zielwert (50 Server x 50 Tage = 2500 Cells)
in einer einzigen Batch-Query unter 200ms bleibt.

Tagesende-Approximation: ein Finding gilt an Tag `D` als "OPEN", wenn
gilt:

    first_seen_at <= end_of_day(D)
    AND (
        status = 'open'
        OR (status IN ('acknowledged', 'resolved')
            AND acknowledged_at/resolved_at > end_of_day(D))
    )

Im MVP vereinfachen wir: wir betrachten `first_seen_at <= end_of_day(D)`
und `(resolved_at IS NULL OR resolved_at > end_of_day(D))`. Acknowledged
zaehlt weiter als "vorhanden" — die Sidebar-Heartbeat zeigt ja "schlimmster
Zustand am Tagesende", und ein acked Finding ist nach §7a noch nicht weg.
Die Farb-Logik (gelb vs. orange/rot) liegt im Frontend (§7a Heartbeat-Mapping):
hier liefern wir nur die Roh-Daten.

`had_scan` wird aus `scans.received_at::date` abgeleitet.

Performance: eine Query laeuft ueber `findings` mit `generate_series`-
artiger Join-Logik. Wir vermeiden das via Python-Aggregation: alle Findings
des Servers werden mit `first_seen_at`, `resolved_at`, `severity`, `is_kev`
geladen und Tag-fuer-Tag im Python ueber den 50-Tages-Bereich gerollt. Bei
50 Servern * ~500 Findings = ~25k Rows, das ist akzeptabel.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import NamedTuple, Protocol, runtime_checkable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, FindingStatus, Scan, Severity

# RiskBand ist in der DB als String(16) gespeichert (kein nativer PG-Enum).
# Wir definieren hier einen lokalen Typ-Alias fuer die statische Analyse.
RiskBand = str


@runtime_checkable
class _FindingLike(Protocol):
    """Strukturelles Protokoll fuer die Heartbeat-Aggregations-Schleife.

    Beides wird unterstuetzt: vollstaendige ORM-`Finding`-Instanzen (Einzel-
    Server-Pfad in `heartbeat_for_server`) und `_FindingRow`-NamedTuples
    (Batch-Pfad mit schmaler Projektion in `heartbeats_for_servers`).
    """

    first_seen_at: datetime
    resolved_at: datetime | None
    severity: Severity
    is_kev: bool
    risk_band: RiskBand | None


class _FindingRow(NamedTuple):
    """Schmale Projektion aus der Findings-Tabelle fuer die Heartbeat-Aggregation.

    Enthaelt 8 Spalten (die 7 bisherigen plus `risk_band` aus Block W ADR-0035).
    Kein vollstaendiges ORM-Objekt, kein JSONB-`data`-Hydrate.

    `risk_band` hat Default `None` fuer Backwards-Compat mit bestehenden Tests
    die `_FindingRow` ohne dieses Feld konstruieren.
    """

    server_id: int
    severity: Severity
    first_seen_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    is_kev: bool
    kev_added_at: datetime | None
    risk_band: RiskBand | None = None


# ---------------------------------------------------------------------------
# Severity-Rank — gleiche Ordnung wie in findings_query.py
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}

# ---------------------------------------------------------------------------
# Risk-Band-Rank — Severity-Ordnung fuer `dominant_risk_band` (ADR-0035).
# escalate > act > mitigate > pending > monitor > noise > unknown
# ---------------------------------------------------------------------------

_RISK_BAND_RANK: dict[str, int] = {
    "escalate": 7,
    "act": 6,
    "mitigate": 5,
    "pending": 4,
    "monitor": 3,
    "noise": 2,
    "unknown": 1,
}


@dataclass(frozen=True, slots=True)
class DailyStatus:
    """Ein Heartbeat-Cell-Datensatz fuer einen Server an einem Tag.

    Felder:
      - `day`                — Datum (UTC).
      - `max_severity`       — hoechste Severity offener Findings am Tagesende,
                               `None` wenn keine offenen Findings existierten.
                               Bleibt fuer Backwards-Compat (Server-Detail-
                               Heatmap konsumiert dieses Feld, Phase 2).
      - `kev_count`          — Anzahl OPEN+KEV Findings am Tagesende.
                               Bleibt fuer Backwards-Compat.
      - `had_scan`           — `True` wenn an diesem Tag mindestens ein Scan
                               eingegangen ist.
      - `dominant_risk_band` — hoechster Risk-Band offener Findings am
                               Tagesende gemaess ADR-0035-Severity-Ordnung
                               (escalate > act > mitigate > pending > monitor >
                               noise > unknown). `None` wenn keine Findings.
                               Wird fuer den neuen Sidebar-Heartbeat-Bar genutzt.
    """

    day: date
    max_severity: Severity | None
    kev_count: int
    had_scan: bool
    dominant_risk_band: RiskBand | None = None


def _resolve_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(tz=UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now


def _end_of_day(d: date) -> datetime:
    """Inklusives Tagesende — 23:59:59.999999 UTC.

    Wir vergleichen Datums-Schwellen `<= end_of_day(d)` und
    `> end_of_day(d)`. Ein Finding das genau in der Sekunde
    `00:00:00.000001` des Folgetags entsteht, wird Tag `d+1` zugeordnet.
    """
    return datetime.combine(d, time.max, tzinfo=UTC)


def _day_range(end_day: date, days: int) -> list[date]:
    """Aelteste-zuerst-Liste der letzten `days` Tage inkl. `end_day`."""
    return [end_day - timedelta(days=days - 1 - i) for i in range(days)]


def _aggregate_one_server(
    findings: Sequence[_FindingLike] | list[_FindingRow],
    scan_days: set[date],
    day_list: list[date],
) -> list[DailyStatus]:
    """Reduziert die geladenen Findings/Scans auf eine Tages-Liste.

    `findings` sind alle Findings des Servers, unabhaengig vom Status —
    wir entscheiden pro Tag selbst, ob ein Finding an diesem Tag noch
    "vorhanden" war.

    Akzeptiert vollstaendige ORM-`Finding`-Instanzen (Einzel-Server-Pfad)
    oder `_FindingRow`-NamedTuples (Batch-Pfad mit schmaler Projektion).
    Beide haben dieselben Attribute: `first_seen_at`, `resolved_at`,
    `severity`, `is_kev`.

    Annahme: `first_seen_at` und `resolved_at` sind tz-aware UTC. Falls
    naiv, behandeln wir defensiv als UTC.
    """
    result: list[DailyStatus] = []
    for d in day_list:
        end = _end_of_day(d)
        max_rank: int = -1
        max_sev: Severity | None = None
        kev_count = 0
        dom_risk_rank: int = -1
        dom_risk_band: RiskBand | None = None
        for f in findings:
            first_seen = f.first_seen_at
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=UTC)
            if first_seen > end:
                # Finding existierte an diesem Tag noch nicht.
                continue
            resolved = f.resolved_at
            if resolved is not None:
                if resolved.tzinfo is None:
                    resolved = resolved.replace(tzinfo=UTC)
                if resolved <= end:
                    # War zum Tagesende bereits resolved.
                    continue
            # Acknowledged-Findings zaehlen weiter als "vorhanden" — die
            # Differenzierung macht das Frontend (Heartbeat-Farb-Mapping
            # gemaess §7a). Wir liefern nur die hoechste Severity.
            rank = _SEVERITY_RANK.get(f.severity, 0)
            if rank > max_rank:
                max_rank = rank
                max_sev = f.severity
            if f.is_kev:
                kev_count += 1
            # Block W (ADR-0035): dominant_risk_band — hoechster Risk-Band
            # gemaess _RISK_BAND_RANK-Ordnung. None-risk_band wird uebersprungen.
            rb = f.risk_band
            if rb is not None:
                rb_rank = _RISK_BAND_RANK.get(rb, 0)
                if rb_rank > dom_risk_rank:
                    dom_risk_rank = rb_rank
                    dom_risk_band = rb
        result.append(
            DailyStatus(
                day=d,
                max_severity=max_sev,
                kev_count=kev_count,
                had_scan=d in scan_days,
                dominant_risk_band=dom_risk_band,
            )
        )
    return result


def heartbeat_for_server(
    session: Session,
    server_id: int,
    days: int = 50,
    now: datetime | None = None,
) -> list[DailyStatus]:
    """Liefert die letzten `days` Tage Heartbeat-Daten fuer einen Server.

    Aelteste zuerst (Index 0 = heute - (days-1) Tage), heute = letzter
    Eintrag. Damit kann das Frontend die Liste 1:1 als Pillen rendern.
    """
    current = _resolve_now(now)
    end_day = current.date()
    start_day = end_day - timedelta(days=days - 1)
    start_dt = datetime.combine(start_day, time.min, tzinfo=UTC)

    # Findings: alle die am Start-Datum noch nicht resolved waren ODER danach
    # entstanden sind. Wir filtern grosszuegig — die Python-Schleife wirft
    # spaeter Tag-fuer-Tag raus was nicht ins Fenster passt.
    f_stmt = select(Finding).where(
        Finding.server_id == server_id,
        # Entweder noch nicht resolved oder erst nach Fenster-Start resolved.
        (Finding.resolved_at.is_(None)) | (Finding.resolved_at >= start_dt),
    )
    findings_list = list(session.execute(f_stmt).scalars().all())

    # Scans im Fenster — wir wollen nur das Datum.
    s_stmt = select(Scan.received_at).where(
        Scan.server_id == server_id,
        Scan.received_at >= start_dt,
    )
    scan_days: set[date] = set()
    for (ts,) in session.execute(s_stmt).all():
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        scan_days.add(ts.date())

    return _aggregate_one_server(findings_list, scan_days, _day_range(end_day, days))


def heartbeats_for_servers(
    session: Session,
    server_ids: list[int],
    days: int = 30,
    now: datetime | None = None,
) -> dict[int, list[DailyStatus]]:
    """Batch-Variante fuer die Sidebar — eine Query je fuer Findings/Scans.

    Garantiert: jeder uebergebene `server_id` taucht im Result-Dict auf,
    auch wenn der Server keine Findings/Scans hat (Liste enthaelt dann
    `days` Cells mit `max_severity=None`, `kev_count=0`, `had_scan=False`).
    """
    if not server_ids:
        return {}

    current = _resolve_now(now)
    end_day = current.date()
    start_day = end_day - timedelta(days=days - 1)
    start_dt = datetime.combine(start_day, time.min, tzinfo=UTC)
    day_list = _day_range(end_day, days)

    # Findings: schmale Projektion — 8 Spalten (die 7 bisherigen plus
    # `risk_band` fuer dominant_risk_band-Reduce, ADR-0035).
    # Kein select(Finding) mehr, kein JSONB-data-Hydrate.
    f_stmt = select(
        Finding.server_id,
        Finding.severity,
        Finding.first_seen_at,
        Finding.acknowledged_at,
        Finding.resolved_at,
        Finding.is_kev,
        Finding.kev_added_at,
        Finding.risk_band,
    ).where(
        Finding.server_id.in_(server_ids),
        (Finding.resolved_at.is_(None)) | (Finding.resolved_at >= start_dt),
    )
    findings_by_server: dict[int, list[_FindingRow]] = defaultdict(list)
    for row in session.execute(f_stmt).all():
        findings_by_server[row.server_id].append(
            _FindingRow(
                server_id=row.server_id,
                severity=row.severity,
                first_seen_at=row.first_seen_at,
                acknowledged_at=row.acknowledged_at,
                resolved_at=row.resolved_at,
                is_kev=row.is_kev,
                kev_added_at=row.kev_added_at,
                risk_band=row.risk_band,
            )
        )

    # Scans pro Server im Fenster.
    s_stmt = select(Scan.server_id, Scan.received_at).where(
        Scan.server_id.in_(server_ids),
        Scan.received_at >= start_dt,
    )
    scan_days_by_server: dict[int, set[date]] = defaultdict(set)
    for sid, ts in session.execute(s_stmt).all():
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        scan_days_by_server[sid].add(ts.date())

    out: dict[int, list[DailyStatus]] = {}
    for sid in server_ids:
        out[sid] = _aggregate_one_server(
            findings_by_server.get(sid, []),
            scan_days_by_server.get(sid, set()),
            day_list,
        )
    return out


# Status-Filter wird im Service explizit nicht angewendet — die Vorhanden-
# Logik basiert auf `resolved_at`. Damit `FindingStatus` als Import
# weiterhin sauber verfuegbar ist (z.B. fuer Tests), exportieren wir es.
_ = FindingStatus

__all__ = [
    "DailyStatus",
    "heartbeat_for_server",
    "heartbeats_for_servers",
]

# TICKET-004 Slice 3: pure Aggregations-Funktion `_aggregate_one_server` und
# `_day_range` werden in `tests/services/test_heartbeat_aggregation.py` direkt
# importiert. Sie bleiben bewusst module-private, gelten aber als stabile
# interne Schnittstelle. Die Eingabe akzeptiert duck-typed Objekte mit den
# Feldern `first_seen_at`, `resolved_at`, `severity`, `is_kev` — Tests koennen
# unpersistierte ORM-Instanzen nutzen.
