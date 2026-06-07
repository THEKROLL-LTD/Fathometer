# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Materialisierter Tages-Heartbeat-Snapshot (`daily_risk_state`).

ADR-0035-Addendum (2026-06-07) "Vergangenheit einfrieren, heute live" +
TD-013. Zwei oeffentliche Funktionen:

- :func:`finalize_pending_days` — friert per Anti-Join-`INSERT … ON CONFLICT
  DO NOTHING` alle noch fehlenden `(server, day)`-Paare im Fenster
  `[today-30, gestern]` ein. Idempotent, catch-up-sicher bei Worker-Downtime,
  deckt neue Server ab und ist zugleich der Deploy-Backfill. Wird vom
  Worker-Sub-Tick `_run_daily_risk_state_finalize` getrieben.
- :func:`today_live_aggregate` — billiges Bestands-Aggregat ueber die aktuell
  praesenten Findings pro Server fuer die heutige (nicht-eingefrorene) Cell.

**Konsistenz-Pflicht (ADR-0035-Addendum):** Die SQL-Tagesende-Range

    first_seen_at <= eod(D) AND (resolved_at IS NULL OR resolved_at > eod(D))

muss exakt der Python-Logik in
`heartbeat_aggregation.py::_aggregate_one_server` entsprechen (abgesichert
durch den Paritaets-Test mit der Live-Aggregation als Oracle).

SQL-Form fuer "hoechster Rang -> Wert": wir berechnen `MAX(rank)` ueber eine
CASE-Rang-Spalte und mappen das Rang-Integer per Reverse-CASE zurueck auf den
kanonischen String. Die Rang->Wert-Abbildung ist bijektiv, deshalb ist das
korrekt und parity-stabil zur Python-Reduce-Logik (`_RISK_BAND_RANK` /
`_SEVERITY_RANK`, hoechster Rang gewinnt). NULL-`risk_band` wird (wie in
Python via `if rb is not None`) uebersprungen.

`generate_series`-Intervalle werden als sichere Literale uebergeben (kein
`text()` mit User-Input — die einzigen variablen Werte sind Datums-Grenzen
und Server-IDs, die als gebundene Parameter laufen).
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    String,
    and_,
    bindparam,
    case,
    cast,
    exists,
    func,
    literal,
    or_,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from sqlalchemy.sql import ColumnElement

from app.models import DailyRiskState, Finding, Scan, Server, Severity
from app.services.heartbeat_aggregation import (
    _RISK_BAND_RANK,
    _SEVERITY_RANK,
    DailyStatus,
    _resolve_now,
)

# Anzahl Tage rueckwaerts die wir einfrieren (heute exklusiv): [today-30, gestern].
_FINALIZE_WINDOW_DAYS = 30

# Interval-Literale fuer generate_series / eod — sichere Postgres-Literale,
# kein User-Input (analog severity_history._INTERVAL_*).
_INTERVAL_1_DAY = text("interval '1 day'")
_INTERVAL_1_MICROSECOND = text("interval '1 microsecond'")


def _eod_expr(d_col: ColumnElement[date]) -> ColumnElement[datetime]:
    """SQL-Tagesende (23:59:59.999999 UTC) eines Date-Ausdrucks.

    Semantisch identisch zu `heartbeat_aggregation._end_of_day(d)` in Python:
        d + interval '1 day' - interval '1 microsecond'

    Cast nach TIMESTAMPTZ damit Postgres keine impliziten Konversionen beim
    Vergleich mit den TIMESTAMPTZ-Finding-Spalten macht (UTC-Only-Ansatz).
    """
    casted: ColumnElement[datetime] = cast(d_col, DateTime(timezone=True))
    return casted + _INTERVAL_1_DAY - _INTERVAL_1_MICROSECOND


# ---------------------------------------------------------------------------
# Rank<->Value-Mappings als SQL-CASE-Ausdruecke (Parity zu Python-Reduce).
# ---------------------------------------------------------------------------


def _risk_band_rank_expr(col: Any) -> ColumnElement[int]:
    """Maps `findings.risk_band` (String) auf seinen `_RISK_BAND_RANK`-Wert.

    NULL und unbekannte Werte -> 0 (Python: `_RISK_BAND_RANK.get(rb, 0)`;
    NULL-Bands werden in Python uebersprungen, fuer den MAX-Rang ist 0 aber
    irrelevant solange wir nur Bands >= 1 zurueckmappen — siehe `_rank_to_band`).
    """
    whens = [(col == band, literal(rank)) for band, rank in _RISK_BAND_RANK.items()]
    return case(*whens, else_=literal(0))


def _rank_to_band_expr(rank_col: ColumnElement[int]) -> ColumnElement[str | None]:
    """Reverse-Map: Rang-Integer -> kanonischer Risk-Band-String.

    Rang 0 (keine/None/unbekannte Bands) -> NULL (Python: `dominant_risk_band
    = None` wenn kein Band mit Rang > -1 gefunden wurde).
    """
    whens = [(rank_col == rank, literal(band)) for band, rank in _RISK_BAND_RANK.items()]
    return case(*whens, else_=literal(None, type_=String(16)))


def _severity_rank_expr(col: Any) -> ColumnElement[int]:
    """Maps `findings.severity` (Enum) auf seinen `_SEVERITY_RANK`-Wert.

    Der niedrigste Rang ist 0 (UNKNOWN). Damit "keine Findings" von
    "nur unknown-Findings" unterscheidbar bleibt, verschieben wir hier um +1
    (rank+1), sodass praesente Findings stets Rang >= 1 liefern und das
    `MAX(... ) FILTER`-Resultat NULL ist wenn gar kein Finding praesent war.
    Der Reverse-Map zieht das +1 wieder ab.
    """
    whens = [
        (cast(col, String) == sev.value, literal(rank + 1)) for sev, rank in _SEVERITY_RANK.items()
    ]
    return case(*whens, else_=literal(0))


def _rank_to_severity_expr(rank_col: ColumnElement[int]) -> ColumnElement[str | None]:
    """Reverse-Map: (rank+1)-Integer -> Severity-String-Wert.

    NULL (kein Finding praesent) bleibt NULL. Der Offset +1 aus
    `_severity_rank_expr` wird hier implizit beruecksichtigt (wir matchen
    gegen `rank + 1`).
    """
    whens = [(rank_col == rank + 1, literal(sev.value)) for sev, rank in _SEVERITY_RANK.items()]
    return case(*whens, else_=literal(None, type_=String(16)))


# ---------------------------------------------------------------------------
# Praesenz-Praedikat (Tagesende-Range) — identisch zu Python.
# ---------------------------------------------------------------------------


def _present_at(eod: ColumnElement[datetime]) -> ColumnElement[bool]:
    """`first_seen_at <= eod AND (resolved_at IS NULL OR resolved_at > eod)`.

    Exakt die Tagesende-Range aus `_aggregate_one_server`. Acknowledged
    zaehlt weiter als praesent (kein acknowledged_at-Filter — bewusst, der
    Heartbeat zeigt "schlimmster Zustand am Tagesende").
    """
    return and_(
        Finding.first_seen_at <= eod,
        or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
    )


# ---------------------------------------------------------------------------
# (1) finalize_pending_days — Anti-Join-UPSERT der vergangenen Tage.
# ---------------------------------------------------------------------------


def finalize_pending_days(session: Session, *, now: datetime | None = None) -> int:
    """Friert alle fehlenden `(server, day)`-Paare im Fenster `[today-30, gestern]` ein.

    Anti-Join: nur Paare fuer die noch KEINE frozen-Row existiert werden
    eingefuegt (`NOT EXISTS` + `ON CONFLICT DO NOTHING` als Race-Backstop).
    Nur vollstaendig abgelaufene Tage (<= gestern) — NIE heute. Idempotent.

    Pro `(server, day)` wird exakt die `_aggregate_one_server`-Semantik in
    SQL nachgebildet:
      - Praesenz: `first_seen_at <= eod(day) AND (resolved_at IS NULL OR
        resolved_at > eod(day))`.
      - `dominant_risk_band` = Band mit hoechstem `_RISK_BAND_RANK`
        (NULL-Bands uebersprungen; NULL wenn keine).
      - `max_severity` = Severity mit hoechstem `_SEVERITY_RANK` (als String).
      - `kev_count` = Anzahl praesenter Findings mit `is_kev = true`.
      - `had_scan` = es existiert ein Scan mit `received_at::date = day`.

    Returns:
        Anzahl tatsaechlich eingefuegter Rows (fuer Logging).
    """
    current = _resolve_now(now)
    today = current.date()
    # Fenster: [today-30, gestern]. generate_series ist inklusiv beidseitig.
    start_day = today - timedelta(days=_FINALIZE_WINDOW_DAYS)
    yesterday = today - timedelta(days=1)
    if yesterday < start_day:
        # Degenerierter Fall (window<=0) — nichts einzufrieren.
        return 0

    # generate_series(start_day, yesterday, interval '1 day') -> ein Date pro Tag.
    days_subq = select(
        cast(
            func.generate_series(
                bindparam("drs_start_day", value=start_day, type_=Date),
                bindparam("drs_end_day", value=yesterday, type_=Date),
                _INTERVAL_1_DAY,
            ),
            Date,
        ).label("d")
    ).subquery()
    day_col = days_subq.c.d
    eod = _eod_expr(day_col)

    band_rank = _risk_band_rank_expr(Finding.risk_band)
    sev_rank = _severity_rank_expr(Finding.severity)

    # MAX-Rang nur ueber praesente Findings; NULL-Band -> Rang 0 -> wird vom
    # Reverse-Map zu NULL (entspricht Python: None-Band ueberspringen).
    present = _present_at(eod)
    max_band_rank = func.max(case((present, band_rank), else_=literal(0)))
    max_sev_rank = func.max(case((present, sev_rank), else_=literal(0)))
    kev_count = func.count().filter(and_(present, Finding.is_kev.is_(True)))

    # had_scan: korreliert auf scans, received_at::date == day.
    had_scan_expr = exists(
        select(literal(1)).where(
            Scan.server_id == Server.id,
            cast(Scan.received_at, Date) == day_col,
        )
    )

    # Anti-Join: nur Paare ohne bereits eingefrorene Row.
    not_frozen = ~exists(
        select(literal(1)).where(
            DailyRiskState.server_id == Server.id,
            DailyRiskState.day == day_col,
        )
    )

    select_stmt = (
        select(
            Server.id.label("server_id"),
            day_col.label("day"),
            _rank_to_band_expr(max_band_rank).label("dominant_risk_band"),
            _rank_to_severity_expr(max_sev_rank).label("max_severity"),
            kev_count.label("kev_count"),
            cast(had_scan_expr, Boolean).label("had_scan"),
        )
        .select_from(Server)
        .join(days_subq, literal(True))
        .outerjoin(
            Finding,
            and_(Finding.server_id == Server.id, present),
        )
        .where(not_frozen)
        .group_by(Server.id, day_col)
    )

    insert_stmt = (
        pg_insert(DailyRiskState)
        .from_select(
            [
                "server_id",
                "day",
                "dominant_risk_band",
                "max_severity",
                "kev_count",
                "had_scan",
            ],
            select_stmt,
        )
        .on_conflict_do_nothing(index_elements=["server_id", "day"])
        .returning(DailyRiskState.day)
    )

    # `rowcount` ist bei `INSERT … FROM SELECT … ON CONFLICT DO NOTHING`
    # unzuverlässig (liefert 0 statt der eingefügten Zeilenzahl). RETURNING
    # liefert bei ON CONFLICT DO NOTHING dagegen exakt die wirklich
    # eingefügten Rows — beim Re-Lauf also korrekt 0 (idempotent).
    result = session.execute(insert_stmt)
    return len(result.all())


# ---------------------------------------------------------------------------
# (2) today_live_aggregate — billiges Bestands-Aggregat fuer heute.
# ---------------------------------------------------------------------------


def today_live_aggregate(
    session: Session,
    server_ids: list[int],
    *,
    now: datetime | None = None,
) -> dict[int, DailyStatus]:
    """Live-Aggregat der aktuell praesenten Findings je Server (heutige Cell).

    Praesenz "jetzt": `first_seen_at <= now AND (resolved_at IS NULL OR
    resolved_at > now)`. Eine billige GROUP-BY-Query (nutzt
    `ix_findings_server_open_triage`), kein 30-Tage-Loop.

    Garantie: jeder uebergebene `server_id` taucht im Result-Dict auf — auch
    ohne Findings (`DailyStatus(day=today, max_severity=None, kev_count=0,
    had_scan=<scan-heute?>, dominant_risk_band=None)`).
    """
    current = _resolve_now(now)
    today = current.date()
    if not server_ids:
        return {}

    now_param = bindparam("drs_now", value=current, type_=DateTime(timezone=True))
    present = and_(
        Finding.first_seen_at <= now_param,
        or_(Finding.resolved_at.is_(None), Finding.resolved_at > now_param),
    )

    band_rank = case((present, _risk_band_rank_expr(Finding.risk_band)), else_=literal(0))
    sev_rank = case((present, _severity_rank_expr(Finding.severity)), else_=literal(0))

    f_stmt = (
        select(
            Finding.server_id.label("server_id"),
            _rank_to_band_expr(func.max(band_rank)).label("dominant_risk_band"),
            _rank_to_severity_expr(func.max(sev_rank)).label("max_severity"),
            func.count().filter(and_(present, Finding.is_kev.is_(True))).label("kev_count"),
        )
        .where(Finding.server_id.in_(server_ids))
        .group_by(Finding.server_id)
    )

    agg_by_server: dict[int, tuple[str | None, str | None, int]] = {}
    for row in session.execute(f_stmt).all():
        agg_by_server[row.server_id] = (
            row.dominant_risk_band,
            row.max_severity,
            int(row.kev_count or 0),
        )

    # had_scan heute: ein Scan mit received_at::date == today.
    s_stmt = (
        select(Scan.server_id)
        .where(
            Scan.server_id.in_(server_ids),
            cast(Scan.received_at, Date) == today,
        )
        .group_by(Scan.server_id)
    )
    scanned_today: set[int] = {sid for (sid,) in session.execute(s_stmt).all()}

    out: dict[int, DailyStatus] = {}
    for sid in server_ids:
        band, sev, kev = agg_by_server.get(sid, (None, None, 0))
        out[sid] = DailyStatus(
            day=today,
            max_severity=Severity(sev) if sev is not None else None,
            kev_count=kev,
            had_scan=sid in scanned_today,
            dominant_risk_band=band,
        )
    return out


__all__ = [
    "finalize_pending_days",
    "today_live_aggregate",
]
