"""Bucket-Query-Service fuer die Cross-Server Bucket-View auf `/findings`.

ADR-0037: `/findings` rendert eine Cross-Server Bucket-View nach
`(server_id, application_group_id)` mit collapsed HTMX-Lazy-Cards.
TICKET-006 Etappe 1: dieser Service kapselt alle DB-Zugriffe.

Oeffentliche Entry-Points:

- `list_buckets(...)` — Aggregat aller gefuellten Buckets (Findings MIT
  Application-Group). Liefert sortierte `BucketHeader`-Liste.
- `pending_bucket_header(...)` — Cross-Server-Sammler fuer Findings ohne
  Group (`application_group_id IS NULL`). Liefert genau einen Header oder
  `None` (leerer Pending-Bucket).
- `list_bucket_findings(...)` — Sub-Pagination fuer den lazy gerenderten
  Bucket-Body (20 Findings + COUNT).
- `resolve_bucket_to_finding_ids(...)` — fuer den Bulk-Acknowledge-Endpoint
  (`POST /findings/bulk/acknowledge`); Convention: `group_id == 0` markiert
  den Pending-Sammler.

Disziplin (Spec §(3)): EIN privater Helper `_apply_bucket_filters()` wird
von ALLEN vier Public-Funktionen gemeinsam genutzt. Sonst laufen
Bucket-Header-Count und Bucket-Body-Inhalt auseinander. Die Severity-/
Status-/Risk-Whitelists werden aus `findings_query` re-importiert, damit
die Single-Source-Of-Truth (siehe ADR-0020/0022) erhalten bleibt.

Sortierung:
- Bucket-Liste: Risk-Band-Rank DESC (escalate -> noise, fehlende Eval
  als `pending` Rank 40 einsortiert), dann `Server.name ASC`, dann
  `ApplicationGroup.label ASC`. Der Pending-Bucket gehoert NICHT in
  diese Liste — er wird vom View ueber `pending_bucket_header()` an die
  Liste angehaengt (ADR-0037 §(1)).
- Findings innerhalb eines Buckets: Spec-fix `is_kev DESC`,
  `epss_score DESC NULLS LAST`, `cvss_v3_score DESC NULLS LAST`,
  `first_seen_at ASC`, plus `identifier_key ASC` als deterministischer
  Tiebreak.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import case, func, nulls_last, or_, select
from sqlalchemy.orm import selectinload
from sqlalchemy.sql import ColumnElement

from app.models import (
    ApplicationGroup,
    ApplicationGroupEvaluation,
    Finding,
    Server,
    ServerTag,
)
from app.services.findings_query import (
    _SEVERITY_THRESHOLD_VALUES,
    _STATUS_VALUES_BY_FILTER,
    _apply_tag_filter_cross,
)
from app.services.risk_engine import RISK_BAND_SORT_RANK, RiskBand, no_band_values, yes_band_values

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.schemas.dashboard_filter import DashboardFilter


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BucketHeader:
    """Header-Record eines Bucket-Eintrags fuer die `/findings`-Liste.

    `group_id == 0` markiert den Pending-Sammler (Findings ohne Group,
    cross-server). Der Pending-Header hat `server_id == 0`, leeren
    `server_name` und `group_label == "(ohne Group)"` (siehe
    `pending_bucket_header()`).
    """

    server_id: int
    group_id: int
    server_name: str
    group_label: str
    risk_band: str
    finding_count: int


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------


_PENDING_BUCKET_LABEL: str = "(ohne Group)"
_PENDING_RISK_BAND: str = "pending"


# ---------------------------------------------------------------------------
# Filter-Helper — EINE Quelle fuer ALLE vier Public-Funktionen
# ---------------------------------------------------------------------------


def _apply_bucket_filters(stmt: Any, filt: DashboardFilter) -> Any:
    """Wendet die `DashboardFilter`-Felder auf ein `select(...)`-Statement an.

    Pflicht-Helper: wird von `list_buckets`, `pending_bucket_header`,
    `list_bucket_findings` und `resolve_bucket_to_finding_ids` gemeinsam
    benutzt. Verhindert dass Bucket-Header-Count und Bucket-Body-Inhalt
    durch divergierende Filter auseinanderlaufen (ADR-0037 §(3)).

    Behandelte Felder (analog `list_findings_cross_server`):
    - `q`: 4-Spalten-ILIKE auf `Finding.identifier_key`,
      `Finding.package_name`, `Finding.title` + Server-Name. Server-Name-
      Match laeuft als Subquery `Finding.server_id IN (SELECT id FROM
      servers WHERE name ILIKE :p)` statt JOIN-Filter (ADR-0037 §(6)
      Performance-Mitigation — der haeufige Fall "Suchbegriff matcht
      keine Server-Zeile" laesst den Planner das Server-IN sofort
      verwerfen).
    - `tags`: OR-Subset via `_apply_tag_filter_cross` (Single-Source aus
      `findings_query`).
    - `severity`: Threshold via `_SEVERITY_THRESHOLD_VALUES`.
    - `status`: via `_STATUS_VALUES_BY_FILTER` (DashboardFilter-Default
      ist `"open"`, also bleibt der OPEN-Filter aktiv falls nichts
      uebergeben wird).
    - `kev_only`: `Finding.is_kev IS TRUE`.
    - `stale_only`: Python-side via `is_stale(...)`-Iteration; kompatibel
      mit `list_findings_cross_server`. Wenn keine Stale-Server existieren,
      wird `Finding.server_id IN ()` zum effektiven "alles raus" — wir
      bilden das ueber ein `False`-WHERE ab, damit das Statement-Shape
      einheitlich bleibt und die Aufrufer keine Sonderbehandlung brauchen.
    - `risk_band`: WHERE `Finding.risk_band = :v`.
    - `action_required`: `yes`/`no` via `yes_band_values()`/`no_band_values()`.
    - `application_group_id`: WHERE `Finding.application_group_id = :v`.
    """
    from app.services.stale_detection import is_stale

    # Tags (OR-Subset).
    stmt = _apply_tag_filter_cross(stmt, filt.tags)

    # Severity-Threshold.
    if filt.severity is not None:
        sev_values = _SEVERITY_THRESHOLD_VALUES[filt.severity]
        stmt = stmt.where(Finding.severity.in_(sev_values))

    # Status (Default `"open"`).
    status_values = _STATUS_VALUES_BY_FILTER[filt.status]
    if status_values is not None:
        stmt = stmt.where(Finding.status.in_(status_values))

    # KEV-Only.
    if filt.kev_only:
        stmt = stmt.where(Finding.is_kev.is_(True))

    # Such-String — Performance-Mitigation: Server-Name-Match als
    # Subquery statt Join-Filter. Verhindert Cross-Join-Explosion bei
    # haeufigen Substrings (siehe ADR-0037 §(6) Worst-Case-Suche).
    if filt.q:
        pattern = f"%{filt.q}%"
        server_match_sq = select(Server.id).where(Server.name.ilike(pattern)).scalar_subquery()
        stmt = stmt.where(
            or_(
                Finding.identifier_key.ilike(pattern),
                Finding.package_name.ilike(pattern),
                Finding.title.ilike(pattern),
                Finding.server_id.in_(server_match_sq),
            )
        )

    # Stale-Only — server-spezifische Schwelle, deshalb Python-side.
    # Konsistent mit `list_findings_cross_server`; wir benutzen hier aber
    # keine `(`Filter,`session`)`-Signatur, weil der Filter-Helper sonst
    # Session-coupled wuerde. Loesung: `stale_only` wird in den jeweiligen
    # Public-Funktionen *vor* dem Aufruf von `_apply_bucket_filters` aufgeloest
    # und der Filter ist hier ein No-Op — siehe `_stale_server_ids()`.
    # Begruendung des Schnitts: damit `_apply_bucket_filters` reine
    # Statement-Transformation bleibt (testbar als pure-unit, kein
    # Session-Mock noetig fuer den Helper-Test).
    # Die Public-Funktionen reichen Stale-IDs ueber `_apply_stale_filter`
    # vor dem Helper an. Hier nichts zu tun.
    _ = is_stale  # nur Import nutzen, kein Aufruf hier

    # Risk-Band Direct-Filter.
    if filt.risk_band is not None:
        stmt = stmt.where(Finding.risk_band == filt.risk_band)
    if filt.action_required == "yes":
        stmt = stmt.where(Finding.risk_band.in_(yes_band_values()))
    elif filt.action_required == "no":
        stmt = stmt.where(Finding.risk_band.in_(no_band_values()))

    # Application-Group-ID Direct-Filter (Block P Carry-over).
    if filt.application_group_id is not None:
        stmt = stmt.where(Finding.application_group_id == filt.application_group_id)

    return stmt


def _apply_stale_filter(session: Session, stmt: Any, filt: DashboardFilter) -> Any:
    """Optionaler Stale-Server-Subset-Filter, der eine Session braucht.

    Trennt das `stale_only`-Side-Effect (Server-Subset-Lookup) aus dem
    reinen `_apply_bucket_filters`-Helper heraus. Wenn `stale_only` False
    ist: No-Op. Wenn True und kein Server stale: WHERE `1=0` damit das
    Statement leer wird ohne Sonderbehandlung im Caller.
    """
    if not filt.stale_only:
        return stmt
    from app.services.stale_detection import is_stale

    srv_stmt = select(Server).where(Server.retired_at.is_(None))
    all_servers = list(session.execute(srv_stmt).scalars().all())
    stale_ids = [srv.id for srv in all_servers if is_stale(srv)]
    if not stale_ids:
        # Statement-Shape erhalten: `IN ()` ist in SQLAlchemy ein in-place
        # False-Predicate; wir wollen aber eine portable, ORM-konforme
        # "match nichts"-WHERE-Klausel.
        return stmt.where(Finding.id.is_(None))
    return stmt.where(Finding.server_id.in_(stale_ids))


# ---------------------------------------------------------------------------
# Sortier-Helper fuer die Bucket-Liste
# ---------------------------------------------------------------------------


def _bucket_risk_band_rank_expr() -> ColumnElement[int]:
    """`COALESCE(eval.risk_band, 'pending')` -> numerischer Rank.

    Buckets ohne Junction-Eval-Row gelten als `pending` (Rank 40), nicht
    als `noise`. Operator-Soll: "Nicht bewertet"-Buckets sollen NICHT
    versteckt am Ende landen (siehe `_load_application_groups_for_server`).
    """
    band_col = func.coalesce(ApplicationGroupEvaluation.risk_band, _PENDING_RISK_BAND)
    whens = [
        (band_col == band.value, RISK_BAND_SORT_RANK[band])
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


def _bucket_finding_order_clauses() -> list[Any]:
    """Spec-fixe Sortierung INNERHALB eines Buckets (ADR-0037 §(1) Tail).

    KEV desc, EPSS desc nulls last, CVSS desc nulls last, first_seen asc,
    identifier_key asc (deterministischer Tiebreak).
    """
    return [
        Finding.is_kev.desc(),
        nulls_last(Finding.epss_score.desc()),
        nulls_last(Finding.cvss_v3_score.desc()),
        Finding.first_seen_at.asc(),
        Finding.identifier_key.asc(),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def list_buckets(session: Session, filt: DashboardFilter) -> list[BucketHeader]:
    """Liefert alle gefuellten Buckets (server_id, application_group_id).

    Aggregat-SELECT mit GROUP BY `(Finding.server_id,
    Finding.application_group_id, Server.name, ApplicationGroup.label,
    ApplicationGroupEvaluation.risk_band)`. INNER JOIN auf `Server` und
    `ApplicationGroup` (nur Buckets mit Group — der Pending-Sammler kommt
    aus `pending_bucket_header()`). LEFT OUTER JOIN auf
    `ApplicationGroupEvaluation` mit Composite-Match auf `(group_id,
    server_id)` — fehlende Eval-Row -> `risk_band = NULL`, im Header via
    `COALESCE(..., 'pending')` als `"pending"` ausgewiesen (analog
    `_load_application_groups_for_server`).

    Sortierung der Liste: Risk-Band-Rank DESC (escalate -> noise/pending),
    Tiebreak `Server.name ASC`, dann `ApplicationGroup.label ASC`. Der
    Pending-Bucket gehoert NICHT in diese Liste; ADR-0037 §(1): "Pending
    erscheint als letzter Eintrag in der Liste, unabhaengig vom Rang" —
    der View haengt den Pending-Header ans Ende.
    """
    band_label = func.coalesce(ApplicationGroupEvaluation.risk_band, _PENDING_RISK_BAND).label(
        "risk_band"
    )
    count_label = func.count(Finding.id).label("finding_count")
    rank_expr = _bucket_risk_band_rank_expr()

    stmt = (
        select(
            Finding.server_id,
            Finding.application_group_id,
            Server.name,
            ApplicationGroup.label,
            band_label,
            count_label,
        )
        .join(Server, Server.id == Finding.server_id)
        .join(ApplicationGroup, ApplicationGroup.id == Finding.application_group_id)
        .outerjoin(
            ApplicationGroupEvaluation,
            (ApplicationGroupEvaluation.group_id == Finding.application_group_id)
            & (ApplicationGroupEvaluation.server_id == Finding.server_id),
        )
        .where(Finding.application_group_id.is_not(None))
    )
    stmt = _apply_stale_filter(session, stmt, filt)
    stmt = _apply_bucket_filters(stmt, filt)
    stmt = stmt.group_by(
        Finding.server_id,
        Finding.application_group_id,
        Server.name,
        ApplicationGroup.label,
        ApplicationGroupEvaluation.risk_band,
    ).order_by(
        rank_expr.desc(),
        Server.name.asc(),
        ApplicationGroup.label.asc(),
    )

    rows = session.execute(stmt).all()
    result: list[BucketHeader] = []
    for server_id, group_id, server_name, group_label, risk_band, finding_count in rows:
        result.append(
            BucketHeader(
                server_id=int(server_id),
                group_id=int(group_id),
                server_name=str(server_name),
                group_label=str(group_label),
                risk_band=str(risk_band) if risk_band is not None else _PENDING_RISK_BAND,
                finding_count=int(finding_count),
            )
        )
    return result


def pending_bucket_header(session: Session, filt: DashboardFilter) -> BucketHeader | None:
    """Cross-Server-Sammler-Header fuer Findings ohne Group.

    `WHERE Finding.application_group_id IS NULL` + die `DashboardFilter`-
    Filter. Liefert `None` wenn der Bucket leer ist (kein Eintrag in der
    Liste, kein Card-Render im View). Sonst ein einzelner `BucketHeader`
    mit Marker `server_id=0`, `group_id=0`, leerem `server_name` und
    `group_label = "(ohne Group)"`.
    """
    stmt = select(func.count(Finding.id)).where(Finding.application_group_id.is_(None))
    stmt = _apply_stale_filter(session, stmt, filt)
    stmt = _apply_bucket_filters(stmt, filt)
    total = int(session.execute(stmt).scalar() or 0)
    if total == 0:
        return None
    return BucketHeader(
        server_id=0,
        group_id=0,
        server_name="",
        group_label=_PENDING_BUCKET_LABEL,
        risk_band=_PENDING_RISK_BAND,
        finding_count=total,
    )


def list_bucket_findings(
    session: Session,
    *,
    server_id: int,
    group_id: int,
    filt: DashboardFilter,
    page: int,
    per_page: int = 20,
) -> tuple[list[Finding], int]:
    """Sub-Pagination eines Buckets (20 Findings + COUNT).

    `group_id == 0` markiert den Pending-Sammler — WHERE wird dann
    `application_group_id IS NULL`. Sonst exakt `application_group_id =
    :group_id`. `server_id` bleibt immer ein Strict-Equal-Filter (auch im
    Pending-Pfad — Pending-Bucket-Body wird auf der View-Seite ueber den
    `/findings/pending`-Endpoint angefragt, der `server_id` setzt; bei
    `server_id == 0` (Pending-Cross-Server) liefert die WHERE-Klausel
    nichts — der Caller muss in dem Fall den `/pending`-Pfad mit Server-
    Spalte verwenden, der `server_id`-Filter weglaesst. Service-Convention:
    `server_id == 0` heisst "kein Server-Filter").

    Sortierung Spec-fix (ADR-0037 §(1) Tail): KEV desc, EPSS desc nulls
    last, CVSS desc nulls last, first_seen asc, identifier_key asc.
    `total` ist ein COUNT-Subselect ueber das gefilterte Statement OHNE
    ORDER BY / LIMIT.
    """
    base_stmt = select(Finding).options(
        selectinload(Finding.server).selectinload(Server.tag_links).selectinload(ServerTag.tag),
        selectinload(Finding.application_group),
        # Block AA (ADR-0041): Notes fuer den Inline-Body eager-loaden.
        selectinload(Finding.notes),
    )

    if server_id != 0:
        base_stmt = base_stmt.where(Finding.server_id == server_id)
    if group_id == 0:
        base_stmt = base_stmt.where(Finding.application_group_id.is_(None))
    else:
        base_stmt = base_stmt.where(Finding.application_group_id == group_id)

    base_stmt = _apply_stale_filter(session, base_stmt, filt)
    base_stmt = _apply_bucket_filters(base_stmt, filt)

    # COUNT-Subselect: nur `Finding.id`, kein ORDER BY, kein LIMIT.
    count_subq = base_stmt.with_only_columns(Finding.id).order_by(None).subquery()
    total = int(session.execute(select(func.count()).select_from(count_subq)).scalar() or 0)

    list_stmt = (
        base_stmt.order_by(*_bucket_finding_order_clauses())
        .offset(max(page - 1, 0) * per_page)
        .limit(per_page)
    )
    findings = list(session.execute(list_stmt).scalars().unique().all())
    return findings, total


def resolve_bucket_to_finding_ids(
    session: Session,
    *,
    server_id: int,
    group_id: int,
    filt: DashboardFilter,
) -> list[int]:
    """Liefert die deterministisch sortierte Finding-ID-Liste eines Buckets.

    Wird vom Bulk-Acknowledge-Endpoint (`POST /findings/bulk/acknowledge`,
    siehe TICKET-006 Etappe 2) aufgerufen — der Server bekommt Bucket-
    Selektionen `{server_id, group_id, filter}` und muss die konkreten
    Finding-IDs zur Bucket-Bedingung aufloesen.

    Selbe WHERE-Klausel wie `list_bucket_findings`, aber ohne LIMIT/OFFSET
    und nur die ID-Spalte (Performance). Sortierung ist hier rein
    deterministisch (`identifier_key ASC, id ASC`) — die fachliche Reihen-
    folge spielt fuer den Bulk-UPDATE keine Rolle, aber wir wollen
    reproduzierbare Audit-Event-Listen.

    Leerer Bucket -> leere Liste.
    """
    stmt = select(Finding.id)
    if server_id != 0:
        stmt = stmt.where(Finding.server_id == server_id)
    if group_id == 0:
        stmt = stmt.where(Finding.application_group_id.is_(None))
    else:
        stmt = stmt.where(Finding.application_group_id == group_id)

    stmt = _apply_stale_filter(session, stmt, filt)
    stmt = _apply_bucket_filters(stmt, filt)
    stmt = stmt.order_by(Finding.identifier_key.asc(), Finding.id.asc())
    return [int(row) for row in session.execute(stmt).scalars().all()]


__all__ = [
    "BucketHeader",
    "list_bucket_findings",
    "list_buckets",
    "pending_bucket_header",
    "resolve_bucket_to_finding_ids",
]
