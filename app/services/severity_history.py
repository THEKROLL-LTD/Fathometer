# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Daily-Severity-Snapshots fuer den Server-Detail-Trend (Block K, ADR-0018).

ARCHITECTURE.md §7a (Detail-Pane) und §15 (Triage-Sortierung). ADR-0018
spezifiziert die OPEN-am-Tag-T-Heuristik:

    first_seen_at <= end_of_day(T)
    AND (acknowledged_at IS NULL OR acknowledged_at > end_of_day(T))
    AND (resolved_at IS NULL OR resolved_at > end_of_day(T))

Im Gegensatz zur Heartbeat-Aggregation (siehe `heartbeat_aggregation.py`)
zaehlt hier `acknowledged` **nicht** als "noch offen" — der Trend-Chart
soll den Triage-Fortschritt zeigen. Acknowledged-Findings sind aus
Operator-Sicht erledigt; nur OPEN ist offen.

Vier Public Entry-Points:

- `severity_snapshots_for_server()` — pro Severity (plus Pseudo-Key `"kev"`)
  eine Liste von Tag-Ende-OPEN-Counts. Speist die KPI-Sparklines.
- `daily_severity_counts_for_server()` — pro Tag ein `DailySeverityCount`,
  `kev`-Feld ist ein Tages-Event-Counter (neu als KEV markiert an dem
  Tag), nicht der OPEN-KEV-Stand. Speist den Stacked-Bar-Chart inkl.
  KEV-Dot-Overlay.
- `count_kev_events_50d()` — Anzahl distincter Findings, die in den letzten
  50 Tagen entweder neu als KEV markiert oder neu mit `is_kev=True`
  ingestet wurden. Speist die Meta-Zeile in der Lebenszeichen-Sektion.
  (deprecated, Block X / ADR-0038)
- `daily_severity_counts_fleet()` — Flotten-weite Daily-OPEN-Counts fuer
  die Dashboard-KPI-Sparklines.

Performance-Profil (Phase E, ADR-0030 Befund 3):
- Default-Pfad: eine SQL-Query mit `generate_series` + `COUNT(*) FILTER
  (WHERE ...)` pro Tag-Bucket liefert die Aggregation direkt aus Postgres.
  Erwartet < 50 ms fuer 10k Findings * 50 Tage vs. ~500k Python-Iterationen
  im alten O(F * D)-Python-Loop.
- Backward-Compat: `rows=`-Parameter (Phase B, ADR-0030 Befund 1) kanalisi-
  ert vorgeladene Rows an den Python-Loop — bleibt erhalten fuer Tests und
  fuer Aufrufer, die den Loader-Call bereits selbst gemacht haben.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Literal

from sqlalchemy import Date, DateTime, bindparam, cast, func, or_, select, text
from sqlalchemy.orm import Session

from app.models import Finding, Severity

# ---------------------------------------------------------------------------
# Datentyp fuer den Stacked-Bar-Chart
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DailySeverityCount:
    """Tages-Snapshot der OPEN-Counts pro Severity plus KEV-Events.

    Felder:
      - `day`       — Datum (UTC).
      - `critical`/`high`/`medium`/`low` — OPEN-Count am Tagesende fuer die
        jeweilige Severity (gemaess ADR-0018-OPEN-Heuristik).
      - `kev`       — Anzahl NEUER KEV-Ereignisse an genau diesem Tag
        (Finding mit `kev_added_at::date == day`). Tages-Event-Counter,
        NICHT OPEN-Stand.
    """

    day: date
    critical: int
    high: int
    medium: int
    low: int
    kev: int


# ---------------------------------------------------------------------------
# Helpers — Zeit/Datums-Mathe
# ---------------------------------------------------------------------------


def _resolve_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(tz=UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now


def _end_of_day(d: date) -> datetime:
    """Inklusives Tagesende — 23:59:59.999999 UTC."""
    return datetime.combine(d, time.max, tzinfo=UTC)


def _start_of_day(d: date) -> datetime:
    return datetime.combine(d, time.min, tzinfo=UTC)


def _day_range(end_day: date, days: int) -> list[date]:
    """Aelteste-zuerst-Liste der letzten `days` Tage inkl. `end_day`."""
    return [end_day - timedelta(days=days - 1 - i) for i in range(days)]


def _as_utc(value: datetime) -> datetime:
    """Naive Werte als UTC interpretieren (DB liefert tz-aware, defensiv)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


# ---------------------------------------------------------------------------
# Interne Aggregation
# ---------------------------------------------------------------------------


# Severities, die wir in den Trend einbeziehen — UNKNOWN bleibt aussen vor,
# weil es im Stacked-Chart keinen sinnvollen visuellen Stack-Layer hat.
_TRACKED_SEVERITIES: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)


def _is_open_at(
    first_seen: datetime,
    acknowledged: datetime | None,
    resolved: datetime | None,
    end_of_day: datetime,
) -> bool:
    """OPEN-am-Tag-T-Test gemaess ADR-0018."""
    if first_seen > end_of_day:
        return False
    if acknowledged is not None and acknowledged <= end_of_day:
        return False
    if resolved is not None and resolved <= end_of_day:  # noqa: SIM103 — Klarheit
        return False
    return True


@dataclass(frozen=True, slots=True)
class _FindingRow:
    """Schmales Tuple statt voller ORM-Instanz fuer die Aggregation."""

    severity: Severity
    first_seen_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    kev_added_at: datetime | None
    is_kev: bool


def _load_findings(
    session: Session,
    server_id: int,
    *,
    window_start: datetime,
) -> list[_FindingRow]:
    """Laedt die fuer das Fenster relevanten Findings als schmale Rows.

    Eingrenzung: Findings, die am Fenster-Start oder spaeter noch "lebten"
    (also nicht vor Fenster-Start endgueltig erledigt waren). Die Python-
    Schleife filtert pro Tag exakt nach OPEN-Definition.

    Eingegrenzt wird grosszuegig: ein Finding kommt rein, wenn weder
    `acknowledged_at < window_start` UND `resolved_at < window_start` noch
    `first_seen_at > window_end_in_future` gilt. Vereinfacht: wir holen
    alle Findings des Servers ausser die offensichtlich vor dem Fenster
    schon erledigten — die DB-Filter sind hier billig.
    """
    # Wir wollen Findings, die am Tagesende irgendeines Tages im Fenster
    # OPEN gewesen sein KOENNTEN. Strikte DB-seitige Eingrenzung ist
    # komplizierter als der Nutzen rechtfertigt — wir holen alle Findings
    # des Servers, deren `acknowledged_at` (falls gesetzt) ODER `resolved_at`
    # (falls gesetzt) >= window_start ist, plus alle bei denen beide NULL
    # sind.
    stmt = (
        select(
            Finding.severity,
            Finding.first_seen_at,
            Finding.acknowledged_at,
            Finding.resolved_at,
            Finding.kev_added_at,
            Finding.is_kev,
        )
        .where(Finding.server_id == server_id)
        .where(
            or_(
                # noch nicht erledigt
                Finding.acknowledged_at.is_(None),
                Finding.acknowledged_at >= window_start,
            )
        )
        .where(
            or_(
                Finding.resolved_at.is_(None),
                Finding.resolved_at >= window_start,
            )
        )
    )
    rows: list[_FindingRow] = []
    for sev, first_seen, ack, res, kev_at, is_kev in session.execute(stmt).all():
        rows.append(
            _FindingRow(
                severity=sev,
                first_seen_at=_as_utc(first_seen),
                acknowledged_at=_as_utc(ack) if ack is not None else None,
                resolved_at=_as_utc(res) if res is not None else None,
                kev_added_at=_as_utc(kev_at) if kev_at is not None else None,
                is_kev=bool(is_kev),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# SQL-Aggregations-Helper (Phase E, ADR-0030 Befund 3)
# ---------------------------------------------------------------------------

# Interval-Literal fuer generate_series — sicheres Postgres-Literal, kein
# User-Input. `text()` ist hier erlaubt weil kein externer Wert injiziert
# wird (nur Konstanten).
_INTERVAL_1_DAY = text("interval '1 day'")
_INTERVAL_1_MICROSECOND = text("interval '1 microsecond'")


def _eod_expr(d_col: object) -> object:
    """SQL-Ausdruck fuer Tagesende (23:59:59.999999 UTC) eines Date-Ausdrucks.

    Semantisch identisch zu `_end_of_day(d)` in Python:
        d + interval '1 day' - interval '1 microsecond'

    Postgres liefert TIMESTAMP; die Finding-Timestamp-Spalten sind
    TIMESTAMP WITH TIME ZONE — der Vergleich ist korrekt solange die
    DB-Timezone-Konfiguration stimmt (UTC-Only-Behoerden-Ansatz). Die
    generate_series-Column ist naiv (kein TZ), daher casten wir explizit
    nach TIMESTAMPTZ bevor wir mit TIMESTAMPTZ-Feldern vergleichen.
    """
    # cast to TIMESTAMPTZ (timezone=True) damit Postgres keine impliziten
    # Konversionen macht.
    return cast(d_col, DateTime(timezone=True)) + _INTERVAL_1_DAY - _INTERVAL_1_MICROSECOND


def _build_server_daily_sql(
    session: Session,
    server_id: int,
    *,
    days: int,
    now: datetime,
) -> list[tuple[date, int, int, int, int, int]]:
    """Eine SQL-Query liefert die Daily-Aggregation fuer einen Server.

    Verwendet `generate_series` + `COUNT(*) FILTER (...)` pro Tag-Bucket.
    Semantik der OPEN-Bedingung ist identisch zu `_is_open_at`:

        first_seen_at <= end_of_day(T)
        AND (acknowledged_at IS NULL OR acknowledged_at > end_of_day(T))
        AND (resolved_at IS NULL OR resolved_at > end_of_day(T))

    KEV-Events-Bucket: `kev_added_at::date == d` — identisch zur Python-
    Implementierung in `_compute_daily_counts` (kev_events_per_day-Lookup).

    Sicherheits-Constraint: `server_id` und `days` werden als gebundene
    Parameter uebergeben (`:server_id`, `:days` via SQLAlchemy-Core-Bind).
    Das `text()`-Literal fuer `interval '1 day'` enthaelt keinerlei User-Input.

    Returns:
        Liste von (day, critical, high, medium, low, kev_events) — aelteste
        zuerst. `days` Zeilen (eine pro Tag) — Tage ohne Findings enthalten
        0-Werte (LEFT JOIN + COALESCE im SELECT).
    """
    end_day = now.date()
    start_day = end_day - timedelta(days=days - 1)

    # generate_series liefert einen Date-Row pro Tag von start_day bis end_day.
    # Wir joinen LEFT OUTER alle Findings des Servers die im Fenster noch
    # offen gewesen sein koennen (grosszuegiger Vorfilter analog _load_findings).
    # Dann COUNT(*) FILTER (...) pro Severity — Postgres rechnet das in einem
    # einzigen Sequential Scan ab, ohne Python-Loop.
    #
    # `bindparam` ist der korrekte SQLAlchemy-2.x-Weg um Werte an eine
    # generate_series-Inline-Funktion zu binden. Kein `text()` mit User-Input.
    days_subq = select(
        func.cast(
            func.generate_series(
                bindparam("srv_start_day", value=start_day, type_=Date),
                bindparam("srv_end_day", value=end_day, type_=Date),
                _INTERVAL_1_DAY,
            ),
            Date,
        ).label("d")
    ).subquery()

    # Tagesende-Ausdruck fuer das Join-On und die FILTER-Klauseln.
    eod = _eod_expr(days_subq.c.d)

    # Vorfilter-Bedingungen auf Finding-Ebene (LEFT-JOIN-ON-Erweiterung
    # im WHERE ist nicht moeglich; stattdessen: nur nicht-offensichtlich-
    # erledigte Findings joinen via join condition).
    window_start = _start_of_day(start_day)

    stmt = (
        select(
            days_subq.c.d,
            func.count()
            .filter(
                Finding.severity == Severity.CRITICAL,
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("crit"),
            func.count()
            .filter(
                Finding.severity == Severity.HIGH,
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("high"),
            func.count()
            .filter(
                Finding.severity == Severity.MEDIUM,
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("medium"),
            func.count()
            .filter(
                Finding.severity == Severity.LOW,
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("low"),
            # KEV-Event-Counter: Anzahl Findings deren kev_added_at::date == d.
            # Semantisch identisch zu kev_events_per_day[d] in _compute_daily_counts.
            func.count()
            .filter(
                Finding.kev_added_at.is_not(None),
                func.cast(Finding.kev_added_at, Date) == days_subq.c.d,
            )
            .label("kev_events"),
        )
        .select_from(days_subq)
        .outerjoin(
            Finding,
            (Finding.server_id == server_id)
            & or_(
                Finding.acknowledged_at.is_(None),
                Finding.acknowledged_at >= window_start,
            )
            & or_(
                Finding.resolved_at.is_(None),
                Finding.resolved_at >= window_start,
            ),
        )
        .group_by(days_subq.c.d)
        .order_by(days_subq.c.d)
    )

    rows = session.execute(stmt).all()
    return [
        (
            r.d if isinstance(r.d, date) else r.d.date(),
            r.crit,
            r.high,
            r.medium,
            r.low,
            r.kev_events,
        )
        for r in rows
    ]


def _sql_rows_to_snapshots(
    sql_rows: list[tuple[date, int, int, int, int, int]],
    day_list: list[date],
    session: Session,
    server_id: int,
) -> dict[str, list[int]]:
    """Baut den Snapshots-Dict aus SQL-Aggregat-Rows.

    Wir benoetigen fuer den `"kev"`-Bucket im Snapshot den OPEN-KEV-STAND
    (nicht den KEV-Event-Counter). Die SQL-Query liefert keinen kumulativen
    KEV-OPEN-Stand — wir holen den gezielt via separater Query oder rechnen
    ihn aus den OPEN-Counts wenn wir `is_kev` in der SQL haben.

    Loesung: wir ersetzen den kev-OPEN-Snapshot-Bucket durch eine separate
    leichtgewichtige Query die nur den is_kev-Filter neben der normalen
    OPEN-Bedingung hinzufuegt. Diese Query hat dieselbe Tagesraster-Logik
    wie `_build_server_daily_sql`, ist aber auf den KEV-OPEN-Stand ausgelegt.

    Diese Funktion wird nur durch `severity_snapshots_for_server` benutzt.
    """
    # Normale Severity-Buckets aus den Aggregat-Rows bauen.
    by_day: dict[date, tuple[int, int, int, int, int]] = {}
    for d, crit, high, medium, low, kev_events in sql_rows:
        by_day[d] = (crit, high, medium, low, kev_events)

    crit_list = [by_day.get(d, (0, 0, 0, 0, 0))[0] for d in day_list]
    high_list = [by_day.get(d, (0, 0, 0, 0, 0))[1] for d in day_list]
    medium_list = [by_day.get(d, (0, 0, 0, 0, 0))[2] for d in day_list]
    low_list = [by_day.get(d, (0, 0, 0, 0, 0))[3] for d in day_list]

    # KEV-OPEN-Bucket: separate SQL-Query mit is_kev-Filter.
    kev_list = _build_kev_open_sql(session, server_id, day_list=day_list)

    return {
        "critical": crit_list,
        "high": high_list,
        "medium": medium_list,
        "low": low_list,
        "kev": kev_list,
    }


def _build_kev_open_sql(
    session: Session,
    server_id: int,
    *,
    day_list: list[date],
) -> list[int]:
    """OPEN-KEV-Stand pro Tag fuer den Sparkline-kev-Bucket.

    Identisch zu `_build_server_daily_sql` aber mit `is_kev = True`-Filter
    zusaetzlich zur OPEN-Bedingung. Ergebnis: pro Tag die Anzahl Findings
    die an diesem Tag OPEN + is_kev waren.
    """
    if not day_list:
        return []

    start_day = day_list[0]
    end_day = day_list[-1]
    window_start = _start_of_day(start_day)

    days_subq = select(
        func.cast(
            func.generate_series(
                bindparam("kev_start_day", value=start_day, type_=Date),
                bindparam("kev_end_day", value=end_day, type_=Date),
                _INTERVAL_1_DAY,
            ),
            Date,
        ).label("d")
    ).subquery()

    eod = _eod_expr(days_subq.c.d)

    stmt = (
        select(
            days_subq.c.d,
            func.count()
            .filter(
                Finding.is_kev.is_(True),
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("kev_open"),
        )
        .select_from(days_subq)
        .outerjoin(
            Finding,
            (Finding.server_id == server_id)
            & or_(
                Finding.acknowledged_at.is_(None),
                Finding.acknowledged_at >= window_start,
            )
            & or_(
                Finding.resolved_at.is_(None),
                Finding.resolved_at >= window_start,
            ),
        )
        .group_by(days_subq.c.d)
        .order_by(days_subq.c.d)
    )

    rows = session.execute(stmt).all()
    by_day: dict[date, int] = {}
    for r in rows:
        d = r.d if isinstance(r.d, date) else r.d.date()
        by_day[d] = r.kev_open

    return [by_day.get(d, 0) for d in day_list]


def _build_fleet_daily_sql(
    session: Session,
    *,
    days: int,
    now: datetime,
) -> dict[FleetSparklineKey, list[int]]:
    """Fleet-weite Daily-OPEN-Counts via SQL-Aggregation (Phase E, ADR-0030).

    Identisch zu `_build_server_daily_sql` aber ohne server_id-Filter —
    zaehlt alle Findings flotten-weit. Buckets: total, kev, critical, high.

    Returns:
        Dict mit Keys `"total"`, `"kev"`, `"critical"`, `"high"`.
        Jeder Wert ist eine Liste von `days` ints — aelteste zuerst.
    """
    end_day = now.date()
    start_day = end_day - timedelta(days=days - 1)
    day_list = _day_range(end_day, days)
    window_start = _start_of_day(start_day)

    days_subq = select(
        func.cast(
            func.generate_series(
                bindparam("fleet_start_day", value=start_day, type_=Date),
                bindparam("fleet_end_day", value=end_day, type_=Date),
                _INTERVAL_1_DAY,
            ),
            Date,
        ).label("d")
    ).subquery()

    eod = _eod_expr(days_subq.c.d)

    stmt = (
        select(
            days_subq.c.d,
            func.count()
            .filter(
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("total"),
            func.count()
            .filter(
                Finding.is_kev.is_(True),
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("kev"),
            func.count()
            .filter(
                Finding.severity == Severity.CRITICAL,
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("crit"),
            func.count()
            .filter(
                Finding.severity == Severity.HIGH,
                Finding.first_seen_at <= eod,
                or_(Finding.acknowledged_at.is_(None), Finding.acknowledged_at > eod),
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > eod),
            )
            .label("high"),
        )
        .select_from(days_subq)
        .outerjoin(
            Finding,
            or_(
                Finding.acknowledged_at.is_(None),
                Finding.acknowledged_at >= window_start,
            )
            & or_(
                Finding.resolved_at.is_(None),
                Finding.resolved_at >= window_start,
            ),
        )
        .group_by(days_subq.c.d)
        .order_by(days_subq.c.d)
    )

    sql_rows = session.execute(stmt).all()

    by_day: dict[date, tuple[int, int, int, int]] = {}
    for r in sql_rows:
        d = r.d if isinstance(r.d, date) else r.d.date()
        by_day[d] = (r.total, r.kev, r.crit, r.high)

    return {
        "total": [by_day.get(d, (0, 0, 0, 0))[0] for d in day_list],
        "kev": [by_day.get(d, (0, 0, 0, 0))[1] for d in day_list],
        "critical": [by_day.get(d, (0, 0, 0, 0))[2] for d in day_list],
        "high": [by_day.get(d, (0, 0, 0, 0))[3] for d in day_list],
    }


# ---------------------------------------------------------------------------
# Public API #0: Shared Row-Loader fuer Aufrufer mit mehreren Aggregatoren
# ---------------------------------------------------------------------------


def load_findings_for_server(
    session: Session,
    server_id: int,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> list[_FindingRow]:
    """Laedt die Findings-Rows fuer das angegebene Fenster.

    Thin Public-Wrapper um `_load_findings`, damit Aufrufer die die Rows
    an mehrere Aggregatoren weiterreichen wollen (Phase B, ADR-0030) keinen
    Underscore-Import benoetigen. Der Rueckgabetyp ist bewusst `list[_FindingRow]`
    — ein Modul-privater Typ, der stabil als interne Schnittstelle gilt
    (TICKET-004 Slice 3).
    """
    current = _resolve_now(now)
    end_day = current.date()
    start_day = end_day - timedelta(days=days - 1)
    window_start = _start_of_day(start_day)
    return _load_findings(session, server_id, window_start=window_start)


# ---------------------------------------------------------------------------
# Public API #1: Per-Severity-Sparkline-Daten
# ---------------------------------------------------------------------------


def _compute_snapshots(rows: list[_FindingRow], day_list: list[date]) -> dict[str, list[int]]:
    """Pure-Aggregation fuer `severity_snapshots_for_server`.

    Erwartet eine bereits aus der DB geladene Row-Liste plus die fertige
    Tages-Liste (aelteste zuerst). Direkt aus Unit-Tests ohne Session
    aufrufbar; siehe TICKET-004, Slice 3 (Pure-Unit-Split der Aggregations-
    Service-Files).
    """
    days = len(day_list)
    out: dict[str, list[int]] = {
        "critical": [0] * days,
        "high": [0] * days,
        "medium": [0] * days,
        "low": [0] * days,
        "kev": [0] * days,
    }

    for idx, d in enumerate(day_list):
        end = _end_of_day(d)
        for row in rows:
            if not _is_open_at(row.first_seen_at, row.acknowledged_at, row.resolved_at, end):
                continue
            if row.severity in _TRACKED_SEVERITIES:
                out[row.severity.value][idx] += 1
            if row.is_kev:
                out["kev"][idx] += 1
    return out


def severity_snapshots_for_server(
    session: Session,
    server_id: int,
    *,
    days: int = 50,
    now: datetime | None = None,
    rows: list[_FindingRow] | None = None,
) -> dict[str, list[int]]:
    """Pro Severity (plus `"kev"`) eine Liste von `days` ints.

    Args:
        session: aktive SQLAlchemy-Session.
        server_id: Ziel-Server.
        days: Anzahl der Tage (Default 50).
        now: optionaler "Jetzt"-Zeitstempel (fuer Tests).
        rows: optionale vorgeladene Row-Liste (Phase B, ADR-0030). Wenn
            gesetzt, wird der DB-Aufruf uebersprungen. Nützlich wenn der
            Aufrufer bereits `_load_findings` aufgerufen hat, um den
            redundanten Seq-Scan zu vermeiden. Rueckwaerts-kompatibel:
            Bestands-Aufrufer ohne `rows=` verwenden den normalen Pfad.

    Returns:
        Ein Dict mit den Keys `"critical"`, `"high"`, `"medium"`, `"low"`
        und `"kev"`. Jeder Wert ist eine Liste von `days` ints — aelteste-
        zuerst — mit dem OPEN-Count am Tagesende. `"kev"` ist der OPEN-
        KEV-Count am Tagesende (nicht der Event-Counter — dafuer
        `daily_severity_counts_for_server().kev`).

    Leere History: alle Listen enthalten `days` Nullen.
    """
    current = _resolve_now(now)
    end_day = current.date()
    day_list = _day_range(end_day, days)

    if rows is not None:
        # Phase-B-Backward-Compat: vorgeladene Rows -> Python-Aggregator.
        return _compute_snapshots(rows, day_list)

    # Phase E (ADR-0030 Befund 3): Default-Pfad ist SQL-Aggregation.
    sql_rows = _build_server_daily_sql(session, server_id, days=days, now=current)
    return _sql_rows_to_snapshots(sql_rows, day_list, session, server_id)


# ---------------------------------------------------------------------------
# Public API #2: Stacked-Bar-Chart-Daten
# ---------------------------------------------------------------------------


def _compute_daily_counts(
    rows: list[_FindingRow], day_list: list[date]
) -> list[DailySeverityCount]:
    """Pure-Aggregation fuer `daily_severity_counts_for_server`.

    Identische Semantik wie der Public-Wrapper — operiert nur auf bereits
    geladenen Rows plus Tages-Liste. Direkt aus Unit-Tests ohne Session
    aufrufbar; siehe TICKET-004, Slice 3.
    """
    if not day_list:
        return []
    start_day = day_list[0]
    end_day = day_list[-1]

    # KEV-Events pro Tag vorrechnen — einfacher Dict-Lookup spart innere
    # O(F)-Schleife pro Tag.
    kev_events_per_day: dict[date, int] = {}
    for row in rows:
        if row.kev_added_at is None:
            continue
        kev_day = row.kev_added_at.date()
        if start_day <= kev_day <= end_day:
            kev_events_per_day[kev_day] = kev_events_per_day.get(kev_day, 0) + 1

    out: list[DailySeverityCount] = []
    for d in day_list:
        end = _end_of_day(d)
        c = h = m = lo = 0
        for row in rows:
            if not _is_open_at(row.first_seen_at, row.acknowledged_at, row.resolved_at, end):
                continue
            if row.severity is Severity.CRITICAL:
                c += 1
            elif row.severity is Severity.HIGH:
                h += 1
            elif row.severity is Severity.MEDIUM:
                m += 1
            elif row.severity is Severity.LOW:
                lo += 1
            # UNKNOWN faellt durch — Stacked-Chart fuehrt keinen
            # UNKNOWN-Layer.
        out.append(
            DailySeverityCount(
                day=d,
                critical=c,
                high=h,
                medium=m,
                low=lo,
                kev=kev_events_per_day.get(d, 0),
            )
        )
    return out


def daily_severity_counts_for_server(
    session: Session,
    server_id: int,
    *,
    days: int = 50,
    now: datetime | None = None,
    rows: list[_FindingRow] | None = None,
) -> list[DailySeverityCount]:
    """Pro Tag ein `DailySeverityCount`-Record (aelteste-zuerst).

    Args:
        session: aktive SQLAlchemy-Session.
        server_id: Ziel-Server.
        days: Anzahl der Tage (Default 50).
        now: optionaler "Jetzt"-Zeitstempel (fuer Tests).
        rows: optionale vorgeladene Row-Liste (Phase B, ADR-0030). Wenn
            gesetzt, wird der DB-Aufruf uebersprungen. Rueckwaerts-kompatibel:
            Bestands-Aufrufer ohne `rows=` verwenden den normalen Pfad.

    `kev` ist die Anzahl NEUER KEV-Ereignisse an dem Tag
    (`kev_added_at::date == day`) — Event-Counter fuer das KEV-Dot-Overlay
    im Stacked-Chart, NICHT der OPEN-KEV-Stand.
    """
    current = _resolve_now(now)
    end_day = current.date()
    day_list = _day_range(end_day, days)

    if rows is not None:
        # Phase-B-Backward-Compat: vorgeladene Rows -> Python-Aggregator.
        return _compute_daily_counts(rows, day_list)

    # Phase E (ADR-0030 Befund 3): Default-Pfad ist SQL-Aggregation.
    sql_rows = _build_server_daily_sql(session, server_id, days=days, now=current)
    return [
        DailySeverityCount(day=d, critical=crit, high=high, medium=med, low=low, kev=kev)
        for d, crit, high, med, low, kev in sql_rows
    ]


# ---------------------------------------------------------------------------
# Public API #3: KEV-Event-50T-Counter
# ---------------------------------------------------------------------------


def count_kev_events_50d(
    session: Session,
    server_id: int,
    *,
    now: datetime | None = None,
) -> int:
    """Anzahl distincter Findings mit KEV-Ereignis in den letzten 50 Tagen.

    Definition (ADR-0018):
        kev_added_at >= now - 50d
        OR (first_seen_at >= now - 50d AND is_kev = TRUE)

    Eine einzige SELECT-Query, ORM-basiert (kein `text()`).

    .. deprecated:: Block X (2026-05-24)
       Der KEV-Ereignisse-50T-Tile auf der Server-Detail-View entfaellt
       mit ADR-0038. Finaler Removal in einem Cleanup-PR sobald keine
       Konsumenten mehr existieren.
    """
    warnings.warn(
        "count_kev_events_50d ist ab Block X deprecated (ADR-0038). "
        "Finaler Removal folgt in einem Cleanup-PR.",
        DeprecationWarning,
        stacklevel=2,
    )
    current = _resolve_now(now)
    window_start = current - timedelta(days=50)

    stmt = (
        select(func.count(func.distinct(Finding.id)))
        .where(Finding.server_id == server_id)
        .where(
            or_(
                Finding.kev_added_at >= window_start,
                (Finding.first_seen_at >= window_start) & Finding.is_kev.is_(True),
            )
        )
    )
    return int(session.execute(stmt).scalar() or 0)


# ---------------------------------------------------------------------------
# Public API #4 — Block M (ADR-0020): Flotten-Daily-Severity-Snapshots
# ---------------------------------------------------------------------------


FleetSparklineKey = Literal["total", "kev", "critical", "high"]


def daily_severity_counts_fleet(
    session: Session,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> dict[FleetSparklineKey, list[int]]:
    """Flotten-weite Daily-OPEN-Counts fuer die Dashboard-KPI-Sparklines.

    Returns:
        Ein Dict mit den Keys `"total"`, `"kev"`, `"critical"`, `"high"`.
        Jeder Wert ist eine Liste von `days` ints — aelteste-zuerst — mit
        dem OPEN-Count am Tagesende (Definition wie
        `severity_snapshots_for_server`):

            first_seen_at <= end_of_day(T)
            AND (acknowledged_at IS NULL OR acknowledged_at > end_of_day(T))
            AND (resolved_at IS NULL OR resolved_at > end_of_day(T))

        Buckets:
        - `"total"`    : alle OPEN-Findings (severity-agnostisch).
        - `"kev"`      : OPEN + `is_kev = True`.
        - `"critical"` : OPEN + `severity = CRITICAL`.
        - `"high"`     : OPEN + `severity = HIGH`.

        Bei leerer Flotte liefert jede Liste `days` Nullen — kein Crash,
        kein NaN. ADR-0020 spezifiziert filter-unabhaengige Sparklines, daher
        kein Tag-/Severity-Filter-Parameter.

    Performance (Phase E, ADR-0030 Befund 3): SQL-Aggregation mit
    `generate_series` + `COUNT(*) FILTER (WHERE ...)` pro Tag-Bucket.
    Erwartet < 100 ms fuer 50k Findings * 50 Tage vs. 2.5M Python-Iterationen
    im alten Differenz-Array-Walk.
    """
    current = _resolve_now(now)
    return _build_fleet_daily_sql(session, days=days, now=current)


__all__ = [
    "DailySeverityCount",
    "FleetSparklineKey",
    "_FindingRow",
    "count_kev_events_50d",
    "daily_severity_counts_fleet",
    "daily_severity_counts_for_server",
    "load_findings_for_server",
    "severity_snapshots_for_server",
]

# TICKET-004 Slice 3: pure Aggregations-Funktionen `_compute_snapshots` und
# `_compute_daily_counts` werden in `tests/services/test_severity_history.py`
# direkt importiert. Sie bleiben bewusst module-private (Underscore-Prefix),
# aber gelten als stabile interne Schnittstelle.
