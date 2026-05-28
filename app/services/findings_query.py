"""Findings-Query-Service fuer die Triage-Hauptansicht (Block E).

ARCHITECTURE.md §5 (Findings-Schema), §7 (List-View auf `/servers/<id>`),
§15 (Triage-Sortierung: KEV desc, EPSS desc nulls last, CVSS desc nulls
last, Severity desc, first_seen_at asc).

Oeffentliche Entry-Points:

- `list_findings(...)` fuer den *Liste*-View.
- `count_findings(...)` fuer die Header-Badges (open/ack/resolved-Zaehler).
- `list_findings_cross_server(...)` fuer die Cross-Server-Findings-Tabelle.

Alle Queries sind ORM-basiert (kein `text()` ohne Bind) und nutzen ein
gemeinsames Filter-Dataclass `FindingsFilter`.

ADR-0025 / Block Q: die frueher hier lebenden Aggregations-Helper fuer
den Paket-Gruppen-View wurden ersatzlos entfernt — der Modus ist seit
ADR-0025 §(1) durch die Application-Group-Cards abgeloest.

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

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from sqlalchemy import case, func, nulls_last, or_, select
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql import ColumnElement

from app.models import (
    ApplicationGroup,
    Finding,
    FindingClass,
    FindingStatus,
    Server,
    ServerTag,
    Severity,
    Tag,
)
from app.services.risk_engine import RISK_BAND_SORT_RANK, RiskBand, no_band_values, yes_band_values

if TYPE_CHECKING:
    from app.schemas.dashboard_filter import DashboardFilter

# ---------------------------------------------------------------------------
# Filter-Dataclass
# ---------------------------------------------------------------------------


FindingsStatusFilter = Literal["open", "acknowledged", "resolved", "all"]
FindingsClassFilter = Literal["os-pkgs", "lang-pkgs", "both"]
FindingsRiskBandFilter = Literal[
    "escalate", "act", "mitigate", "pending", "unknown", "monitor", "noise"
]
FindingsActionRequiredFilter = Literal["yes", "no"]

# Block-K (ADR-0018): sortierbare Spalten-Header.
# Whitelist-Literal — `_SORT_COLUMNS` mappt jeden Key auf eine fest
# referenzierte Column. Damit ist `ORDER BY` immer ein Column-Objekt aus
# dem Mapping, NIE eine User-Eingabe — kein SQL-Injection-Surface.
# Block O (ADR-0022): `"risk"` als neuer Default-Primary-Sort.
FindingsSortKey = Literal[
    "risk",
    "cve",
    "pkg",
    "epss",
    "cvss",
    "sev",
    "status",
    "first_seen",
    # Block P (ADR-0023): Sort nach ApplicationGroup.label.
    "group",
]
FindingsSortDir = Literal["asc", "desc"]

# Block M (ADR-0020): Cross-Server-Sort enthaelt zusaetzlich `"server"`
# (Sortierung nach `Server.name`).
FindingsCrossSortKey = Literal[
    "risk",
    "server",
    "cve",
    "pkg",
    "epss",
    "cvss",
    "sev",
    "status",
    "first_seen",
    # Block P (ADR-0023).
    "group",
]


@dataclass(frozen=True, slots=True)
class FindingsFilter:
    """Filter-Werte fuer die drei Views auf `/servers/<id>`.

    Defaults entsprechen dem Block-Plan: `status="open"`,
    `finding_class="both"`, keine weiteren Einschraenkungen. Severity-Minimum,
    KEV-Only und Such-Term sind optional.

    Block O (ADR-0022): `risk_band` und `action_required` filtern auf den
    neuen `Finding.risk_band`-Spaltenwert; `action_required="yes"` wird
    aus `ACTION_REQUIRED_MAP` abgeleitet (kein Hardcode).
    """

    status: FindingsStatusFilter = "open"
    severity_min: Severity | None = None
    finding_class: FindingsClassFilter = "both"
    kev_only: bool = False
    search: str | None = None  # case-insensitive substring
    risk_band: FindingsRiskBandFilter | None = None
    action_required: FindingsActionRequiredFilter | None = None
    # Block P (ADR-0023): Filter auf `Finding.application_group_id`. `None`
    # bedeutet "kein Filter" — wir filtern KEIN ungrouped (das macht eine
    # separate "Pending grouping"-Sektion). Wert `0` ist semantisch nicht
    # erlaubt (Schema haelt `ge=1`).
    application_group_id: int | None = None


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


def _risk_band_rank_expr() -> ColumnElement[int]:
    """CASE-Expression: `Finding.risk_band` -> numerischer Rank (Block O).

    Mapping aus `RISK_BAND_SORT_RANK` (ADR-0022). NULL-Band laeuft via
    `else_=0` ans Ende — frische, noch nicht klassifizierte Findings
    landen unter `noise` (Rank 10). Konsistent mit ADR-0022 §Sort-Order.
    """
    whens = [
        (Finding.risk_band == band.value, RISK_BAND_SORT_RANK[band])
        for band in (
            RiskBand.ESCALATE,
            RiskBand.ACT,
            RiskBand.MITIGATE,
            RiskBand.PENDING,
            RiskBand.UNKNOWN,
            RiskBand.MONITOR,
            RiskBand.NOISE,
        )
    ]
    return case(*whens, else_=0)


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
    "risk": _risk_band_rank_expr(),
    "cve": Finding.identifier_key,
    "pkg": Finding.package_name,
    "epss": Finding.epss_score,
    "cvss": Finding.cvss_v3_score,
    "sev": _severity_rank_expr(),
    "status": _status_rank_expr(),
    "first_seen": Finding.first_seen_at,
    # Block P (ADR-0023): Sort nach ApplicationGroup.label. Findings ohne
    # zugewiesene Group haben `application_group_id IS NULL` und landen
    # via `nullslast()` (siehe `list_findings()`) im asc/desc-Tail. Der
    # Outer-Join auf `ApplicationGroup` muss in der jeweiligen Query
    # explizit angefuegt werden — siehe `list_findings()` /
    # `list_findings_cross_server()`.
    "group": ApplicationGroup.label,
}


# Block M (ADR-0020): Cross-Server-Mapping erbt alle Eintraege aus dem
# Block-K-Mapping und ergaenzt `"server" -> Server.name`. Selbe Whitelist-
# Disziplin: nur Werte aus diesem Dict landen je im ORDER BY, der User-
# Eingabe-String ist immer ein Literal-Lookup.
_SORT_COLUMNS_CROSS: dict[str, Any] = {
    "server": Server.name,
    **_SORT_COLUMNS,
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

    # Block O (ADR-0022): risk_band / action_required.
    if filt.risk_band is not None:
        stmt = stmt.where(Finding.risk_band == filt.risk_band)
    if filt.action_required == "yes":
        stmt = stmt.where(Finding.risk_band.in_(yes_band_values()))
    elif filt.action_required == "no":
        stmt = stmt.where(Finding.risk_band.in_(no_band_values()))

    # Block P (ADR-0023): application_group_id-Filter.
    if filt.application_group_id is not None:
        stmt = stmt.where(Finding.application_group_id == filt.application_group_id)

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
    """Default-Sortierung gemaess §15 (post-Block-O) plus OS-Pakete-zuerst.

    Block O (ADR-0022): `risk_band`-Rank rutscht als neuer Primary-Sort vor
    KEV; CVSS-Severity bleibt im Tiebreak. Konkrete Reihenfolge bei
    `finding_class="both"`:
      1. `finding_class = 'os-pkgs'` zuerst.
      2. Risk-Band-Rank desc (escalate -> noise).
      3. KEV desc.
      4. EPSS desc nulls last.
      5. CVSS-v3-Score desc nulls last.
      6. Severity-Rank desc.
      7. first_seen_at asc.

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

    clauses.append(_risk_band_rank_expr().desc())
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
    # Block P (ADR-0023): Outer-Join auf ApplicationGroup nur wenn nach
    # `group` sortiert wird — sonst spart der Plan einen Join.
    if sort == "group":
        stmt = stmt.outerjoin(
            ApplicationGroup,
            ApplicationGroup.id == Finding.application_group_id,
        )
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
    # Block Y / ADR-0039 §5: KEV-Count via FILTER-Aggregat in derselben
    # GROUP-BY-Status-Query — kein zweiter SELECT mehr (ein DB-Roundtrip
    # statt zwei). Wir tragen das KEV-FILTER-Aggregat als nicht-gruppierte
    # Spalte ueber einen Subquery-OR-Trick — einfacher: separates Aggregat
    # ueber das gleiche Where mit `subquery()`. Praktisch portieren wir das
    # `Finding.is_kev`-FILTER direkt in jede Status-Group-Row und summieren
    # dann das OPEN-Bucket heraus.
    stmt = select(
        Finding.status,
        func.count(Finding.id).label("total"),
        func.count()
        .filter(Finding.is_kev.is_(True), Finding.status == FindingStatus.OPEN)
        .label("kev_open"),
    ).group_by(Finding.status)
    stmt = _apply_filters(stmt, server_id, bypass)
    rows = session.execute(stmt).all()

    counts: dict[str, int] = {
        "open": 0,
        "acknowledged": 0,
        "resolved": 0,
        "total": 0,
        "kev_open": 0,
    }
    for row in rows:
        n_int = int(row.total)
        counts["total"] += n_int
        if row.status == FindingStatus.OPEN:
            counts["open"] = n_int
            counts["kev_open"] = int(row.kev_open or 0)
        elif row.status == FindingStatus.ACKNOWLEDGED:
            counts["acknowledged"] = n_int
        elif row.status == FindingStatus.RESOLVED:
            counts["resolved"] = n_int

    return counts


# ---------------------------------------------------------------------------
# Block M (ADR-0020) — Cross-Server-Findings-Query fuer die Dashboard-Tabelle
# ---------------------------------------------------------------------------


def _apply_tag_filter_cross(stmt: Any, tags: list[str]) -> Any:
    """Filtert Findings auf Server, die mindestens eines der Tags tragen (OR).

    1:1 portiert aus dem geloeschten `app/views/search.py:_apply_tag_filter`.
    Der Tag-Mode ist hier hartkodiert OR — die Dashboard-Filter-Bar nutzt
    Single-Select, Multi-Tag-Power-User-Modus kommt ueber wiederholte
    `?tag=`-Params; AND-Semantik ist bewusst nicht implementiert.
    """
    if not tags:
        return stmt
    server_ids_sq = (
        select(ServerTag.server_id)
        .join(Tag, Tag.id == ServerTag.tag_id)
        .where(Tag.name.in_(tags))
        .scalar_subquery()
    )
    return stmt.where(Finding.server_id.in_(server_ids_sq))


def list_findings_cross_server(
    session: Session,
    filt: DashboardFilter,
    *,
    limit: int = 200,
    offset: int = 0,
    sort: FindingsCrossSortKey = "risk",
    dir: FindingsSortDir = "desc",
    now: datetime | None = None,
) -> tuple[list[Finding], int]:
    """Liefert (results, total_count) der Cross-Server-Findings-Tabelle.

    ADR-0020: Eager-Load der Server-Relation (inkl. Tag-Pills) per
    `selectinload(Finding.server).selectinload(Server.tag_links).selectinload(
    ServerTag.tag)`. `total_count` ist ein separater `COUNT(*)` ueber das
    *gefilterte* Subselect — exakt, vor dem Limit, damit der Truncation-
    Hinweis stimmt.

    Filter-Anwendung (jeweils gebindet, kein f-String-SQL):
    - `q`: case-insensitive OR-Substring auf `Finding.identifier_key`,
      `Finding.package_name`, `Finding.title` und `Server.name`. Letzteres
      via JOIN.
    - `tags`: OR-Subset via `_apply_tag_filter_cross`.
    - `severity`: Threshold via `_SEVERITY_THRESHOLD_VALUES`.
    - `status`: via `_STATUS_VALUES_BY_FILTER` (Default `open`).
    - `kev_only`: `Finding.is_kev.is_(True)`.
    - `stale_only`: Python-side via `is_stale(srv, now)`-Iteration ueber
      eine Server-Subset-Query — `is_stale` referenziert
      `Server.expected_scan_interval_h` und `Server.last_scan_at`, was sich
      nicht als einzelne ORM-WHERE-Klausel ausdruecken laesst (Schwelle
      ist server-spezifisch). Wenn `stale_ids` leer ist, geben wir direkt
      `([], 0)` zurueck — kein wasted COUNT-Query.

    Sortierung: `_SORT_COLUMNS_CROSS[sort]` mit `.asc()`/`.desc()` +
    `nulls_last`; sekundaerer Tiebreak `Finding.identifier_key.asc()` fuer
    deterministische Reihenfolge bei Ties. Wenn `sort` nicht in der
    Whitelist ist, faellt die Funktion auf `sev/desc` zurueck.

    `limit` und `offset` greifen nur auf das Listen-Ergebnis, nicht auf
    `total_count` (Block-Q, ADR-0025 §(5): klassische Pagination mit fester
    Seitengroesse, `total_count` weiterhin exakt aus dem gefilterten
    Subselect).
    """
    from app.services.stale_detection import is_stale

    # Tag-Filter braucht JOIN nur wenn `q` Server.name matchen soll oder
    # `sort == "server"` gewaehlt ist. Wir JOINen defensiv immer (selectinload
    # waere keine Alternative — die WHERE-/ORDER-BY-Klausel braucht den JOIN
    # in derselben Statement-Scope).
    base_stmt = select(Finding).join(Server, Server.id == Finding.server_id)
    # Block P (ADR-0023): Outer-Join auf ApplicationGroup defensiv anlegen,
    # weil entweder der Sort `"group"` oder die Group-Spalten-Anzeige
    # (eager_load via selectinload) die Tabelle braucht. Outer, weil
    # Findings ohne Zuordnung in der Liste auftauchen muessen.
    base_stmt = base_stmt.outerjoin(
        ApplicationGroup, ApplicationGroup.id == Finding.application_group_id
    )
    base_stmt = base_stmt.options(
        selectinload(Finding.server).selectinload(Server.tag_links).selectinload(ServerTag.tag),
        # Eager-Load der Group fuer die Dashboard-Spalte. Block-P-Render
        # zeigt `f.application_group.label` direkt — kein N+1.
        selectinload(Finding.application_group),
    )

    # Tag-Filter (OR).
    base_stmt = _apply_tag_filter_cross(base_stmt, filt.tags)

    # Severity-Threshold.
    if filt.severity is not None:
        sev_values = _SEVERITY_THRESHOLD_VALUES[filt.severity]
        base_stmt = base_stmt.where(Finding.severity.in_(sev_values))

    # Status (Default open).
    status_values = _STATUS_VALUES_BY_FILTER[filt.status]
    if status_values is not None:
        base_stmt = base_stmt.where(Finding.status.in_(status_values))

    # KEV-Only.
    if filt.kev_only:
        base_stmt = base_stmt.where(Finding.is_kev.is_(True))

    # Such-String — `ilike` bindet die Werte, kein SQL-Injection-Risiko.
    if filt.q:
        pattern = f"%{filt.q}%"
        base_stmt = base_stmt.where(
            or_(
                Finding.identifier_key.ilike(pattern),
                Finding.package_name.ilike(pattern),
                Finding.title.ilike(pattern),
                Server.name.ilike(pattern),
            )
        )

    # Stale-Only — Python-side, weil `is_stale` server-spezifische Schwelle
    # liest. Server-Subset-Query ueber die *Roh-Server-Tabelle* (nicht ueber
    # die Findings-Query), damit der Stale-Status nicht von den anderen
    # Filtern abhaengt.
    if filt.stale_only:
        srv_stmt = select(Server).where(
            Server.retired_at.is_(None),
        )
        all_servers = list(session.execute(srv_stmt).scalars().all())
        stale_ids = [srv.id for srv in all_servers if is_stale(srv, now=now)]
        if not stale_ids:
            return [], 0
        base_stmt = base_stmt.where(Finding.server_id.in_(stale_ids))

    # Block O (ADR-0022): Filter risk_band / action_required.
    if filt.risk_band is not None:
        base_stmt = base_stmt.where(Finding.risk_band == filt.risk_band)
    if filt.action_required == "yes":
        base_stmt = base_stmt.where(Finding.risk_band.in_(yes_band_values()))
    elif filt.action_required == "no":
        base_stmt = base_stmt.where(Finding.risk_band.in_(no_band_values()))

    # Block P (ADR-0023): Application-Group-ID-Filter.
    if filt.application_group_id is not None:
        base_stmt = base_stmt.where(Finding.application_group_id == filt.application_group_id)

    # `total_count` — exakter COUNT(*) ueber das gefilterte Subselect. Wir
    # bauen das Subselect aus dem aktuellen Statement ohne ORDER BY/LIMIT
    # (SQL-Standard akzeptiert beides in Subqueries, aber unnoetig).
    count_subq = base_stmt.with_only_columns(Finding.id).order_by(None).subquery()
    total_count = int(session.execute(select(func.count()).select_from(count_subq)).scalar() or 0)

    # Sortier-Klauseln aufbauen — Whitelist-Lookup, sonst Default risk/desc.
    sort_col = _SORT_COLUMNS_CROSS.get(sort)
    if sort_col is None:
        sort_col = _SORT_COLUMNS_CROSS["risk"]
        dir = "desc"
    primary_clause = sort_col.asc() if dir == "asc" else sort_col.desc()
    primary_clause = nulls_last(primary_clause)
    # Block O: Tiebreak-Kette nach §15 (post-Block-O):
    # 1. KEV desc
    # 2. EPSS desc nulls last
    # 3. CVSS desc nulls last
    # 4. Severity-Rank desc
    # 5. identifier_key asc (deterministisch).
    tiebreaks: list[Any] = [
        Finding.is_kev.desc(),
        nulls_last(Finding.epss_score.desc()),
        nulls_last(Finding.cvss_v3_score.desc()),
        _severity_rank_expr().desc(),
        Finding.identifier_key.asc(),
    ]
    list_stmt = base_stmt.order_by(primary_clause, *tiebreaks).offset(offset).limit(limit)
    results = list(session.execute(list_stmt).scalars().unique().all())
    return results, total_count


__all__ = [
    "FindingsClassFilter",
    "FindingsCrossSortKey",
    "FindingsFilter",
    "FindingsSortDir",
    "FindingsSortKey",
    "FindingsStatusFilter",
    "count_findings",
    "list_findings",
    "list_findings_cross_server",
]
