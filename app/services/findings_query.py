"""Findings-Query-Service fuer die Triage-Hauptansicht (Block E).

ARCHITECTURE.md §5 (Findings-Schema), §7 (View-Modi auf `/servers/<id>`),
§15 (Triage-Sortierung: KEV desc, EPSS desc nulls last, CVSS desc nulls
last, Severity desc, first_seen_at asc).

Drei oeffentliche Entry-Points:

- `list_findings(...)` fuer den *Liste*-View.
- `group_findings_by_package(...)` fuer den *Gruppiert-nach-Paket*-View.
- `count_findings(...)` fuer die Header-Badges (open/ack/resolved-Zaehler).

Alle Queries sind ORM-basiert (kein `text()` ohne Bind) und nutzen ein
gemeinsames Filter-Dataclass `FindingsFilter`.

Sortierung-Detail (siehe §15):
- KEV-Findings *immer* zuoberst (`is_kev DESC`).
- EPSS desc mit NULLS LAST.
- CVSS-v3-Score desc mit NULLS LAST.
- Severity desc — Postgres-Enum sortiert lexikografisch, das ist nicht das,
  was wir wollen. Wir sortieren deshalb ueber eine `CASE`-Expression, die
  CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, UNKNOWN=0 zuordnet.
- `first_seen_at ASC` als Tiebreaker.

Bei `finding_class="both"` wird zusaetzlich `os-pkgs DESC` als erster Sort-
Key vor KEV gesetzt — `os-pkgs` (CASE=1) oben, `lang-pkgs`/`other` (CASE=0)
darunter. So sieht der Operator zuerst die System-Paket-Findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import case, func, nulls_last, or_, select
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql import ColumnElement

from app.models import Finding, FindingClass, FindingStatus, Severity

# ---------------------------------------------------------------------------
# Filter-Dataclass
# ---------------------------------------------------------------------------


FindingsStatusFilter = Literal["open", "acknowledged", "resolved", "all"]
FindingsClassFilter = Literal["os-pkgs", "lang-pkgs", "both"]

# Block-K (ADR-0018): sortierbare Spalten-Header.
# Whitelist-Literal — `_SORT_COLUMNS` mappt jeden Key auf eine fest
# referenzierte Column. Damit ist `ORDER BY` immer ein Column-Objekt aus
# dem Mapping, NIE eine User-Eingabe — kein SQL-Injection-Surface.
FindingsSortKey = Literal["cve", "pkg", "epss", "cvss", "sev", "status", "first_seen"]
FindingsSortDir = Literal["asc", "desc"]


@dataclass(frozen=True, slots=True)
class FindingsFilter:
    """Filter-Werte fuer die drei Views auf `/servers/<id>`.

    Defaults entsprechen dem Block-Plan: `status="open"`,
    `finding_class="both"`, keine weiteren Einschraenkungen. Severity-Minimum,
    KEV-Only und Such-Term sind optional.
    """

    status: FindingsStatusFilter = "open"
    severity_min: Severity | None = None
    finding_class: FindingsClassFilter = "both"
    kev_only: bool = False
    search: str | None = None  # case-insensitive substring


# ---------------------------------------------------------------------------
# Sortier-Helper
# ---------------------------------------------------------------------------


def _severity_rank_expr() -> Any:
    """CASE-Expression: Severity -> numerischer Rank fuer Sortierung.

    Wir vergleichen direkt `Finding.severity == <Enum>`, statt das Enum mit
    einem String-Key zu matchen. Postgres-ENUM-Spalten haben keinen impliziten
    Cast zu `varchar` — der `case({str: ...}, value=col)`-Pattern erzeugt
    sonst `severity = varchar`-Vergleiche, die fehlschlagen.
    """
    return case(
        (Finding.severity == Severity.CRITICAL, 4),
        (Finding.severity == Severity.HIGH, 3),
        (Finding.severity == Severity.MEDIUM, 2),
        (Finding.severity == Severity.LOW, 1),
        (Finding.severity == Severity.UNKNOWN, 0),
        else_=0,
    )


_SEVERITY_THRESHOLD_VALUES: dict[Severity, list[str]] = {
    Severity.CRITICAL: [Severity.CRITICAL.value],
    Severity.HIGH: [Severity.CRITICAL.value, Severity.HIGH.value],
    Severity.MEDIUM: [
        Severity.CRITICAL.value,
        Severity.HIGH.value,
        Severity.MEDIUM.value,
    ],
    Severity.LOW: [
        Severity.CRITICAL.value,
        Severity.HIGH.value,
        Severity.MEDIUM.value,
        Severity.LOW.value,
    ],
    # UNKNOWN als untere Schwelle bedeutet: keine Einschraenkung.
    Severity.UNKNOWN: [
        Severity.CRITICAL.value,
        Severity.HIGH.value,
        Severity.MEDIUM.value,
        Severity.LOW.value,
        Severity.UNKNOWN.value,
    ],
}


_STATUS_VALUES_BY_FILTER: dict[FindingsStatusFilter, list[str] | None] = {
    "open": [FindingStatus.OPEN.value],
    "acknowledged": [FindingStatus.ACKNOWLEDGED.value],
    "resolved": [FindingStatus.RESOLVED.value],
    "all": None,
}


_CLASS_VALUES_BY_FILTER: dict[FindingsClassFilter, list[str] | None] = {
    "os-pkgs": [FindingClass.OS_PKGS.value],
    "lang-pkgs": [FindingClass.LANG_PKGS.value],
    "both": None,
}


_SEVERITY_RANK_TABLE: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}


def _status_rank_expr() -> ColumnElement[int]:
    """CASE-Expression: Status -> Rank fuer Sortierung.

    Operationssemantik: OPEN zuerst (3), ACK in der Mitte (2), RESOLVED
    unten (1). Bei `dir=asc` kehrt sich das natuerlich um.
    """
    return case(
        (Finding.status == FindingStatus.OPEN, 3),
        (Finding.status == FindingStatus.ACKNOWLEDGED, 2),
        (Finding.status == FindingStatus.RESOLVED, 1),
        else_=0,
    )


# Whitelist-Mapping: Sort-Key -> Column/Expression. Jeder Eintrag wird in
# `list_findings()` direkt via `.asc()`/`.desc()` benutzt — ORM-only, kein
# `text()`, kein User-String fliesst in das ORDER BY.
#
# Mypy-Hinweis: `InstrumentedAttribute[...]` und `case(...)` haben einen
# gemeinsamen Bound bei `ColumnElement`, mypy laesst die Co-Variance hier
# aber nicht inferieren — wir typisieren bewusst auf `Any` damit die
# heterogene Sammlung valide bleibt. Die Sicherheit kommt aus der
# Literal-Whitelist auf `sort` (siehe `FindingsSortKey`).
_SORT_COLUMNS: dict[str, Any] = {
    "cve": Finding.identifier_key,
    "pkg": Finding.package_name,
    "epss": Finding.epss_score,
    "cvss": Finding.cvss_v3_score,
    "sev": _severity_rank_expr(),
    "status": _status_rank_expr(),
    "first_seen": Finding.first_seen_at,
}


# ---------------------------------------------------------------------------
# Filter-Application
# ---------------------------------------------------------------------------


def _apply_filters(stmt: Any, server_id: int, filt: FindingsFilter) -> Any:
    """Wendet alle Filter aus `FindingsFilter` auf eine SELECT-Statement an.

    Generisch ueber den Statement-Typ getypt, damit die gleiche Helper-
    Funktion sowohl `select(Finding)` als auch `select(Finding.status,
    func.count(...))` bedienen kann.
    """
    stmt = stmt.where(Finding.server_id == server_id)

    status_values = _STATUS_VALUES_BY_FILTER[filt.status]
    if status_values is not None:
        stmt = stmt.where(Finding.status.in_(status_values))

    class_values = _CLASS_VALUES_BY_FILTER[filt.finding_class]
    if class_values is not None:
        stmt = stmt.where(Finding.finding_class.in_(class_values))

    if filt.severity_min is not None:
        sev_values = _SEVERITY_THRESHOLD_VALUES[filt.severity_min]
        stmt = stmt.where(Finding.severity.in_(sev_values))

    if filt.kev_only:
        stmt = stmt.where(Finding.is_kev.is_(True))

    if filt.search:
        # Case-insensitive substring auf identifier_key, package_name, title.
        # `ilike` bindet den Wert -> kein SQL-Injection-Risiko.
        pattern = f"%{filt.search.strip()}%"
        if pattern != "%%":
            stmt = stmt.where(
                or_(
                    Finding.identifier_key.ilike(pattern),
                    Finding.package_name.ilike(pattern),
                    Finding.title.ilike(pattern),
                )
            )

    return stmt


# ---------------------------------------------------------------------------
# Sortier-Klauseln aufbauen
# ---------------------------------------------------------------------------


def _order_clauses(filt: FindingsFilter) -> list[Any]:
    """Default-Sortierung gemaess §15 plus optionaler OS-Pakete-zuerst-Logik.

    Reihenfolge bei `finding_class="both"`:
      1. `finding_class = 'os-pkgs'` zuerst.
      2. KEV desc.
      3. EPSS desc nulls last.
      4. CVSS-v3-Score desc nulls last.
      5. Severity-Rank desc.
      6. first_seen_at asc.

    Bei expliziter Klassen-Wahl (`os-pkgs`/`lang-pkgs`) entfaellt Schritt 1.
    """
    clauses: list[Any] = []
    if filt.finding_class == "both":
        # Vergleich gegen das Enum-Member (nicht gegen `.value`), damit der
        # Postgres-Enum-Typ konsistent gematcht wird — ein String-Vergleich
        # liefert "operator does not exist: finding_class = varchar".
        os_pkgs_priority = case(
            (Finding.finding_class == FindingClass.OS_PKGS, 1),
            else_=0,
        )
        clauses.append(os_pkgs_priority.desc())

    clauses.append(Finding.is_kev.desc())
    clauses.append(nulls_last(Finding.epss_score.desc()))
    clauses.append(nulls_last(Finding.cvss_v3_score.desc()))
    clauses.append(_severity_rank_expr().desc())
    clauses.append(Finding.first_seen_at.asc())
    return clauses


# ---------------------------------------------------------------------------
# Public API: Liste
# ---------------------------------------------------------------------------


def list_findings(
    session: Session,
    server_id: int,
    filt: FindingsFilter,
    *,
    limit: int = 500,
    sort: FindingsSortKey | None = None,
    dir: FindingsSortDir = "desc",
) -> list[Finding]:
    """Liefert eine flache Liste von Findings fuer den *Liste*-View.

    Sortierung:
    - Wenn `sort` `None` ist: Default-Reihenfolge aus §15 (KEV/EPSS/CVSS/
      Severity/first_seen) ueber `_order_clauses()`.
    - Wenn `sort` gesetzt ist (ADR-0018 spaltensortierbare Tabelle): das
      `_SORT_COLUMNS`-Mapping liefert die Primary-Column; `Finding.cve_id`
      (= `identifier_key`) als deterministischer Tiebreaker.

    `sort` ist `Literal`-typed — kein User-String fliesst direkt in das
    ORDER BY. Falls trotzdem ein nicht-gemappter Key durchkommt, faellt
    die Funktion auf die §15-Default-Order zurueck statt zu crashen.

    Eager-Load der Notes vermeidet N+1, wenn die Liste in einer Schleife
    geoeffnet wird.
    """
    stmt = select(Finding).options(selectinload(Finding.notes))
    stmt = _apply_filters(stmt, server_id, filt)
    if sort is None or sort not in _SORT_COLUMNS:
        stmt = stmt.order_by(*_order_clauses(filt))
    else:
        primary = _SORT_COLUMNS[sort]
        primary_clause = nulls_last(primary.asc()) if dir == "asc" else nulls_last(primary.desc())
        # Sekundaerer Sort fuer deterministische Reihenfolge bei Ties.
        stmt = stmt.order_by(primary_clause, Finding.identifier_key.asc())
    stmt = stmt.limit(limit)
    return list(session.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Public API: Group-by-Package
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PackageGroup:
    """Aggregations-Ergebnis fuer eine Paket-Zeile im *Gruppiert*-View."""

    package_name: str
    findings: list[Finding] = field(default_factory=list)
    count_open: int = 0
    count_total: int = 0
    has_kev: bool = False
    max_epss: float | None = None
    max_cvss: float | None = None
    highest_severity: Severity | None = None

    @property
    def severity_rank(self) -> int:
        """Numerischer Rank der hoechsten Severity (CRITICAL=4 .. UNKNOWN=0)."""
        if self.highest_severity is None:
            return -1
        return _SEVERITY_RANK_TABLE[self.highest_severity]


def group_findings_by_package(
    session: Session,
    server_id: int,
    filt: FindingsFilter,
) -> list[PackageGroup]:
    """Gruppiert Findings nach `package_name`.

    Sortierung der Gruppen (analog §15 fuer Aggregate):
      1. `has_kev` desc.
      2. `max_epss` desc nulls last.
      3. `max_cvss` desc nulls last.
      4. `severity_rank` desc.
      5. `package_name` asc.

    Innerhalb einer Gruppe sind die `findings` wieder per Standard-Order
    sortiert (KEV/EPSS/CVSS/Severity/first_seen_at) — `list_findings`
    bringt sie schon in dieser Reihenfolge.
    """
    findings = list_findings(session, server_id, filt, limit=5000)

    groups: dict[str, PackageGroup] = {}
    for f in findings:
        bucket = groups.setdefault(f.package_name, PackageGroup(package_name=f.package_name))
        bucket.findings.append(f)
        bucket.count_total += 1
        if f.status == FindingStatus.OPEN:
            bucket.count_open += 1
        if f.is_kev:
            bucket.has_kev = True
        if f.epss_score is not None and (bucket.max_epss is None or f.epss_score > bucket.max_epss):
            bucket.max_epss = f.epss_score
        if f.cvss_v3_score is not None and (
            bucket.max_cvss is None or f.cvss_v3_score > bucket.max_cvss
        ):
            bucket.max_cvss = f.cvss_v3_score
        if (
            bucket.highest_severity is None
            or _SEVERITY_RANK_TABLE[f.severity] > _SEVERITY_RANK_TABLE[bucket.highest_severity]
        ):
            bucket.highest_severity = f.severity

    def _sort_key(g: PackageGroup) -> tuple[int, float, float, int, str]:
        return (
            -1 if g.has_kev else 0,
            -(g.max_epss or 0.0),
            -(g.max_cvss or 0.0),
            -g.severity_rank,
            g.package_name.lower(),
        )

    return sorted(groups.values(), key=_sort_key)


# ---------------------------------------------------------------------------
# Public API: Counts fuer Header-Badges
# ---------------------------------------------------------------------------


def count_findings(
    session: Session,
    server_id: int,
    filt: FindingsFilter,
) -> dict[str, int]:
    """Liefert Status-Zaehler fuer die Header-Badges.

    Der `filt`-Parameter wirkt auf Severity/Class/KEV/Search — der Status-
    Filter selbst wird **ignoriert**, damit die Badges immer alle drei
    Status konsistent anzeigen (auch wenn der User gerade
    `status=acknowledged` eingestellt hat).

    Rueckgabe-Keys: `open`, `acknowledged`, `resolved`, `total`, `kev_open`.
    """
    bypass = FindingsFilter(
        status="all",
        severity_min=filt.severity_min,
        finding_class=filt.finding_class,
        kev_only=filt.kev_only,
        search=filt.search,
    )
    stmt = select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
    stmt = _apply_filters(stmt, server_id, bypass)
    rows = session.execute(stmt).all()

    counts: dict[str, int] = {
        "open": 0,
        "acknowledged": 0,
        "resolved": 0,
        "total": 0,
        "kev_open": 0,
    }
    for status_value, n in rows:
        n_int = int(n)
        counts["total"] += n_int
        if status_value == FindingStatus.OPEN:
            counts["open"] = n_int
        elif status_value == FindingStatus.ACKNOWLEDGED:
            counts["acknowledged"] = n_int
        elif status_value == FindingStatus.RESOLVED:
            counts["resolved"] = n_int

    kev_stmt = select(func.count(Finding.id)).where(
        Finding.server_id == server_id,
        Finding.status == FindingStatus.OPEN,
        Finding.is_kev.is_(True),
    )
    counts["kev_open"] = int(session.execute(kev_stmt).scalar() or 0)
    return counts


__all__ = [
    "FindingsClassFilter",
    "FindingsFilter",
    "FindingsSortDir",
    "FindingsSortKey",
    "FindingsStatusFilter",
    "PackageGroup",
    "count_findings",
    "group_findings_by_package",
    "list_findings",
]
