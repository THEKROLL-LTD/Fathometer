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

Drei Public Entry-Points:

- `severity_snapshots_for_server()` — pro Severity (plus Pseudo-Key `"kev"`)
  eine Liste von Tag-Ende-OPEN-Counts. Speist die KPI-Sparklines.
- `daily_severity_counts_for_server()` — pro Tag ein `DailySeverityCount`,
  `kev`-Feld ist ein Tages-Event-Counter (neu als KEV markiert an dem
  Tag), nicht der OPEN-KEV-Stand. Speist den Stacked-Bar-Chart inkl.
  KEV-Dot-Overlay.
- `count_kev_events_50d()` — Anzahl distincter Findings, die in den letzten
  50 Tagen entweder neu als KEV markiert oder neu mit `is_kev=True`
  ingestet wurden. Speist die Meta-Zeile in der Lebenszeichen-Sektion.

Performance-Profil: ein einziges SELECT laedt alle relevanten Findings,
die Python-Aggregation rollt die 50 Tages-Buckets in O(F * D). Bei 10k
Findings * 50 Tage = 500k Iterationen — unter 100 ms auf moderner Hardware,
ohne Index-Spielereien.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import func, or_, select
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
# Public API #1: Per-Severity-Sparkline-Daten
# ---------------------------------------------------------------------------


def severity_snapshots_for_server(
    session: Session,
    server_id: int,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> dict[str, list[int]]:
    """Pro Severity (plus `"kev"`) eine Liste von `days` ints.

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
    start_day = end_day - timedelta(days=days - 1)
    window_start = _start_of_day(start_day)
    day_list = _day_range(end_day, days)

    rows = _load_findings(session, server_id, window_start=window_start)

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


# ---------------------------------------------------------------------------
# Public API #2: Stacked-Bar-Chart-Daten
# ---------------------------------------------------------------------------


def daily_severity_counts_for_server(
    session: Session,
    server_id: int,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> list[DailySeverityCount]:
    """Pro Tag ein `DailySeverityCount`-Record (aelteste-zuerst).

    `kev` ist die Anzahl NEUER KEV-Ereignisse an dem Tag
    (`kev_added_at::date == day`) — Event-Counter fuer das KEV-Dot-Overlay
    im Stacked-Chart, NICHT der OPEN-KEV-Stand.
    """
    current = _resolve_now(now)
    end_day = current.date()
    start_day = end_day - timedelta(days=days - 1)
    window_start = _start_of_day(start_day)
    day_list = _day_range(end_day, days)

    rows = _load_findings(session, server_id, window_start=window_start)

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
    """
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


__all__ = [
    "DailySeverityCount",
    "count_kev_events_50d",
    "daily_severity_counts_for_server",
    "severity_snapshots_for_server",
]
