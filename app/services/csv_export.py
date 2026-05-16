"""CSV-Export-Service mit Streaming und Formula-Injection-Mitigation.

ARCHITECTURE.md §7 (CSV-Export aus Audit- und Findings-Listen). Streaming
verhindert dass der Server den kompletten Export im RAM aufbaut — selbst
50.000 Findings sollen den Worker nicht sprengen.

**CSV-Injection-Haertung (DoD-grep):** Excel und LibreOffice interpretieren
Zell-Werte, die mit `=`, `+`, `-`, `@`, Tab oder CR beginnen, als Formel.
Ein boeswillig gewaehltes Note-Text-Feld koennte damit beim Oeffnen der
CSV in Excel Schadcode ausfuehren (klassische OWASP-Formula-Injection).
Mitigation: jedes solche Feld bekommt ein fuehrendes `'` (Apostroph). Das
ist die kanonische Mitigation — Excel zeigt den Apostroph nicht im UI an,
verhindert aber die Formel-Interpretation.

API:

- `stream_csv(rows, columns)` -> Generator[bytes] — generische Streaming-
  CSV-Erzeugung. Yieldet zuerst eine Header-Zeile, dann eine Zeile pro
  Eintrag aus `rows`. Spalten-Reihenfolge ist stabil (kommt aus `columns`).
- `stream_audit_csv(session, filter)` -> Generator[bytes] — Audit-Events
  als CSV (Filter siehe `AuditFilter`).
- `stream_findings_csv(session, filter, server_id?)` -> Generator[bytes] —
  Findings als CSV (nutzt `FindingsFilter`).
"""

from __future__ import annotations

import csv
import io
from collections.abc import Generator, Iterable, Iterator
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import nulls_last, select
from sqlalchemy.orm import Session, selectinload

from app.models import AuditEvent, Finding, Server
from app.schemas.dashboard_filter import DashboardFilter
from app.services.diff_view import compute_diff
from app.services.findings_query import (
    _SEVERITY_THRESHOLD_VALUES,
    _SORT_COLUMNS,
    _SORT_COLUMNS_CROSS,
    _STATUS_VALUES_BY_FILTER,
    FindingsCrossSortKey,
    FindingsFilter,
    FindingsSortDir,
    FindingsSortKey,
    _apply_filters,
    _apply_tag_filter_cross,
    _order_clauses,
)

# Zeichen, die am Anfang eines Felds eine Formel triggern (OWASP-Liste).
_FORMULA_TRIGGERS: frozenset[str] = frozenset({"=", "+", "-", "@", "\t", "\r"})


def _harden_against_formula(value: Any) -> str:
    """Stringifiziert `value` und entscherft Formula-Injection.

    Konvertiert `None` zu `""`, alle anderen Werte zu `str(value)`. Wenn das
    Ergebnis mit einem Trigger-Zeichen beginnt, wird ein `'` vorangestellt.
    Das ist die kanonische OWASP-Mitigation gegen CSV-/Formula-Injection.
    """
    if value is None:
        return ""
    # ISO-8601 mit TZ vermeidet locale-spezifische Excel-Konvertierung.
    text = value.isoformat() if isinstance(value, datetime) else str(value)
    if text and text[0] in _FORMULA_TRIGGERS:
        return "'" + text
    return text


def stream_csv(
    rows: Iterable[dict[str, Any]],
    columns: list[str],
) -> Generator[bytes]:
    """Yieldet CSV-Bytes inkl. Header, eine Zeile pro Eintrag aus `rows`.

    - Header wird aus `columns` gebildet (stabile Reihenfolge).
    - Jeder Zellen-Wert laeuft durch `_harden_against_formula`.
    - Wir nutzen `csv.writer` auf einem In-Memory `StringIO`, das nach jeder
      Zeile geleert wird — Memory bleibt konstant unabhaengig von der
      Zeilenzahl.
    - Quoting: `QUOTE_MINIMAL` — Felder mit Komma/Newline/Anfuehrungszeichen
      werden korrekt gequotet. Das aendert nichts am Formula-Apostroph,
      Excel sieht das Apostroph als Formel-Escape unabhaengig von Quoting.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")

    # Header (Spaltennamen selbst koennten auch mit '=' beginnen, was zwar
    # unwahrscheinlich ist, aber kostet uns nichts).
    writer.writerow([_harden_against_formula(c) for c in columns])
    yield buffer.getvalue().encode("utf-8")
    buffer.seek(0)
    buffer.truncate(0)

    for row in rows:
        writer.writerow([_harden_against_formula(row.get(col)) for col in columns])
        yield buffer.getvalue().encode("utf-8")
        buffer.seek(0)
        buffer.truncate(0)


# ---------------------------------------------------------------------------
# Audit-CSV
# ---------------------------------------------------------------------------


AUDIT_CSV_COLUMNS: list[str] = [
    "ts",
    "actor",
    "action",
    "target_type",
    "target_id",
    "comment",
    "metadata",
]


def stream_audit_csv(
    session: Session,
    *,
    filter_query: Any,
) -> Generator[bytes]:
    """Streamt Audit-Events als CSV.

    `filter_query` ist eine bereits gefilterte `select(AuditEvent)`-Query —
    der Caller (`audit_view.export_csv`) baut die WHERE-Klauseln auf und
    reicht sie hier durch. So bleibt die Filter-Logik an genau einer Stelle.
    """

    def _row_iter() -> Iterator[dict[str, Any]]:
        # Wir holen in kleinen Batches und yielden zeilenweise.
        result = session.execute(filter_query.execution_options(yield_per=200))
        for event in result.scalars():
            yield _audit_row(event)

    return stream_csv(_row_iter(), AUDIT_CSV_COLUMNS)


def _audit_row(event: AuditEvent) -> dict[str, Any]:
    """Wandelt einen AuditEvent in ein flaches CSV-Dict um.

    Wichtig: `metadata` und `comment` sind user-controlled — die
    Formula-Mitigation in `stream_csv` greift hier.
    """
    md = event.event_metadata
    # Metadata sehr kompakt: key=value;key=value — gut grepbar in Excel,
    # ohne JSON-Anfuehrungszeichen, die Excel-Felder zerschneiden.
    if md is None:
        meta_str = ""
    elif isinstance(md, dict):
        parts = []
        for k, v in md.items():
            v_str = ",".join(str(x) for x in v) if isinstance(v, list) else str(v)
            parts.append(f"{k}={v_str}")
        meta_str = ";".join(parts)
    else:
        meta_str = str(md)
    return {
        "ts": event.ts,
        "actor": event.actor,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id or "",
        "comment": event.comment or "",
        "metadata": meta_str,
    }


# ---------------------------------------------------------------------------
# Findings-CSV
# ---------------------------------------------------------------------------


FINDINGS_CSV_COLUMNS: list[str] = [
    "server_name",
    "cve_id",
    "package_name",
    "installed_version",
    "fixed_version",
    "severity",
    "cvss_v3_score",
    "epss_score",
    "is_kev",
    "status",
    "first_seen_at",
    "title",
]

# Block-K (ADR-0018): Mode-abhaengige CSV-Erweiterungen.
FINDINGS_CSV_COLUMNS_GROUPED: list[str] = ["Group", *FINDINGS_CSV_COLUMNS]
FINDINGS_CSV_COLUMNS_DIFF: list[str] = ["DiffStatus", *FINDINGS_CSV_COLUMNS]

# Whitelist-Modi — der View prueft selbst und gibt nur valide Werte weiter.
CsvExportMode = Literal["flach", "gruppiert", "diff"]


def stream_findings_csv(
    session: Session,
    *,
    server_id: int | None,
    filter_obj: FindingsFilter,
    mode: CsvExportMode = "flach",
    sort: FindingsSortKey | None = None,
    dir: FindingsSortDir = "desc",
) -> Generator[bytes]:
    """Streamt Findings als CSV — Mode-abhaengig (Block K, ADR-0018).

    Modi:
        "flach"      — flache Liste aller gefilterten/sortierten Findings.
        "gruppiert"  — wie "flach", plus Spalte `Group` (package_name);
                       Sortierung: primaer nach Gruppe (asc), dann nach
                       `sort` (gemaess `dir`).
        "diff"       — nur Diff-Findings (neu+resolved seit vorletztem Scan)
                       mit Spalte `DiffStatus`. `server_id` ist Pflicht;
                       wenn kein Vorgaenger-Scan existiert, gibt es eine
                       Hinweis-Zeile statt einer leeren CSV.

    Sortierung im flachen/gruppierten Modus:
    - Wenn `sort` None ist: §15-Default.
    - Sonst: `_SORT_COLUMNS`-Whitelist (ORM-only, kein User-String im SQL).

    Globaler Export (`server_id=None`) ist nur fuer `mode="flach"` und
    `mode="gruppiert"` zulaessig — `mode="diff"` braucht zwingend einen
    Server (sonst keine sinnvolle Diff-Semantik); der View kappt das ab.
    """
    if mode == "diff":
        return _stream_findings_csv_diff(session, server_id=server_id)
    columns = FINDINGS_CSV_COLUMNS_GROUPED if mode == "gruppiert" else FINDINGS_CSV_COLUMNS

    stmt = select(Finding).options(selectinload(Finding.server))
    if server_id is not None:
        stmt = _apply_filters(stmt, server_id, filter_obj)
    else:
        # Globaler Export ueber alle Server — `_apply_filters` setzt aktuell
        # `Finding.server_id == server_id`. Wir wollen hier flott eine
        # Variante ohne diesen Constraint. Loesung: server_id=-1 wuerde 0
        # Treffer ergeben; stattdessen bauen wir die Filter inline OHNE die
        # Server-Bedingung.
        stmt = _apply_filters_no_server(stmt, filter_obj)

    order_clauses = _csv_order_clauses(filter_obj, mode=mode, sort=sort, dir=dir)
    stmt = stmt.order_by(*order_clauses)

    def _row_iter() -> Iterator[dict[str, Any]]:
        result = session.execute(stmt.execution_options(yield_per=200))
        for finding in result.scalars():
            row = _finding_row(finding)
            if mode == "gruppiert":
                row = {"Group": finding.package_name, **row}
            yield row

    return stream_csv(_row_iter(), columns)


def _csv_order_clauses(
    filt: FindingsFilter,
    *,
    mode: CsvExportMode,
    sort: FindingsSortKey | None,
    dir: FindingsSortDir,
) -> list[Any]:
    """Baut die ORDER-BY-Klauseln fuer den CSV-Export.

    - "gruppiert": primaer `package_name` ASC (= Gruppen-Buckets), dann
      `sort`/`dir` (oder §15-Default), dann `identifier_key` ASC fuer
      Determinismus.
    - "flach": `sort`/`dir` falls gesetzt, sonst §15-Default.
    """
    clauses: list[Any] = []
    if mode == "gruppiert":
        clauses.append(Finding.package_name.asc())

    if sort is not None and sort in _SORT_COLUMNS:
        primary = _SORT_COLUMNS[sort]
        clauses.append(nulls_last(primary.asc() if dir == "asc" else primary.desc()))
        clauses.append(Finding.identifier_key.asc())
    else:
        clauses.extend(_order_clauses(filt))
    return clauses


def _stream_findings_csv_diff(
    session: Session,
    *,
    server_id: int | None,
) -> Generator[bytes]:
    """Diff-Mode-CSV: nur neue/resolved Findings seit vorletztem Scan.

    Wenn kein Vorgaenger-Scan existiert (oder `server_id=None`), liefert
    der Stream die Header-Zeile plus eine einzelne Hinweis-Zeile:
    "Kein vorheriger Scan zum Vergleich" — siehe ADR-0018 Mitigation
    fuer leeren Diff.
    """
    columns = FINDINGS_CSV_COLUMNS_DIFF

    if server_id is None:
        # Globaler Diff-Export ist nicht definiert.
        return stream_csv(iter([_diff_notice_row("Kein Server angegeben")]), columns)

    diff = compute_diff(session, server_id)
    if diff.previous_scan_at is None:
        # Erst-Scan oder kein Scan — Hinweis-Zeile mit "neu".
        return stream_csv(
            iter([_diff_notice_row("Kein vorheriger Scan zum Vergleich")]),
            columns,
        )

    def _row_iter() -> Iterator[dict[str, Any]]:
        # Server-Name nachladen — `compute_diff` selectiert kein
        # `selectinload(Finding.server)`, also greifen wir ueber das
        # Finding-Objekt zu. Fuer den Diff-Output ist die Latenz egal
        # (max. 2 Datenbank-Hops pro Server, da alle Findings desselben
        # Servers sind und ihn ueber relationship() teilen).
        for f in diff.new:
            row = {"DiffStatus": "neu", **_finding_row(f)}
            yield row
        for f in diff.resolved:
            row = {"DiffStatus": "resolved", **_finding_row(f)}
            yield row

    return stream_csv(_row_iter(), columns)


def _diff_notice_row(notice: str) -> dict[str, Any]:
    """Erzeugt eine Hinweis-Zeile fuer den Diff-Modus (siehe ADR-0018)."""
    row: dict[str, Any] = dict.fromkeys(FINDINGS_CSV_COLUMNS_DIFF, "")
    row["DiffStatus"] = notice
    return row


def _apply_filters_no_server(stmt: Any, filt: FindingsFilter) -> Any:
    """Wie `_apply_filters` aber ohne den Server-Constraint.

    Spiegelt absichtlich die Logik aus `findings_query._apply_filters`
    — Aenderungen dort muessen hier nachgezogen werden. Eine bessere
    Faktorisierung waere, einen `server_id: int | None`-Parameter in
    `_apply_filters` zu erlauben; das kann der naechste Refactor machen,
    fuer Block F genuegt diese Kopie.
    """
    from sqlalchemy import or_

    from app.services.findings_query import (
        _CLASS_VALUES_BY_FILTER,
        _SEVERITY_THRESHOLD_VALUES,
        _STATUS_VALUES_BY_FILTER,
    )

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


def _finding_row(f: Finding) -> dict[str, Any]:
    server_name = ""
    server_attr: Server | None = getattr(f, "server", None)
    if server_attr is not None:
        server_name = server_attr.name
    return {
        "server_name": server_name,
        "cve_id": f.identifier_key,
        "package_name": f.package_name,
        "installed_version": f.installed_version or "",
        "fixed_version": f.fixed_version or "",
        "severity": f.severity.value,
        "cvss_v3_score": f.cvss_v3_score if f.cvss_v3_score is not None else "",
        "epss_score": f.epss_score if f.epss_score is not None else "",
        "is_kev": "true" if f.is_kev else "false",
        "status": f.status.value,
        "first_seen_at": f.first_seen_at,
        "title": f.title or "",
    }


# ---------------------------------------------------------------------------
# Block M (ADR-0020) — Cross-Server-CSV-Export aus dem Dashboard
# ---------------------------------------------------------------------------


# Erste Spalte explizit `Server` (Title-Case, vom Block-Plan vorgegeben), dann
# der bisherige Spalten-Satz **ohne** `server_name` — das alte Feld waere
# redundant zu `Server`. Format-Stabilitaet ist hier kein Argument, der
# Cross-Server-Endpoint ist mit Block M neu.
FINDINGS_CSV_COLUMNS_CROSS: list[str] = [
    "Server",
    "cve_id",
    "package_name",
    "installed_version",
    "fixed_version",
    "severity",
    "cvss_v3_score",
    "epss_score",
    "is_kev",
    "status",
    "first_seen_at",
    "title",
]


def stream_findings_csv_cross_server(
    session: Session,
    filt: DashboardFilter,
    *,
    sort: FindingsCrossSortKey = "sev",
    dir: FindingsSortDir = "desc",
    now: datetime | None = None,
) -> Generator[bytes]:
    """Streamt Cross-Server-Findings als CSV (Dashboard-Export, ADR-0020).

    Filter-Felder kommen aus `DashboardFilter` (`q`, `tags`, `severity`,
    `status`, `kev_only`, `stale_only`, `sort`, `dir`). KEIN Limit — alle
    Treffer landen im Export (CSV ist die Eskalations-Ebene wenn die 200-
    Truncation zu eng wird).

    Spalten: `Server` zuerst (= `finding.server.name`), gefolgt von der
    Block-K-Findings-Spalten-Palette. Die `Server`-Spalte unterliegt
    derselben OWASP-Formula-Injection-Mitigation aus `_harden_against_formula`.
    """
    from app.services.stale_detection import is_stale

    stmt = select(Finding).options(selectinload(Finding.server))
    stmt = stmt.join(Server, Server.id == Finding.server_id)

    # Tags (OR-Set).
    stmt = _apply_tag_filter_cross(stmt, filt.tags)

    # Severity-Threshold.
    if filt.severity is not None:
        sev_values = _SEVERITY_THRESHOLD_VALUES[filt.severity]
        stmt = stmt.where(Finding.severity.in_(sev_values))

    # Status (Default open).
    status_values = _STATUS_VALUES_BY_FILTER[filt.status]
    if status_values is not None:
        stmt = stmt.where(Finding.status.in_(status_values))

    # KEV-Only.
    if filt.kev_only:
        stmt = stmt.where(Finding.is_kev.is_(True))

    # Such-String (gebindet via `ilike`).
    if filt.q:
        from sqlalchemy import or_

        pattern = f"%{filt.q}%"
        stmt = stmt.where(
            or_(
                Finding.identifier_key.ilike(pattern),
                Finding.package_name.ilike(pattern),
                Finding.title.ilike(pattern),
                Server.name.ilike(pattern),
            )
        )

    # Stale-Only — Python-side wie in `list_findings_cross_server`.
    if filt.stale_only:
        srv_stmt = select(Server).where(Server.retired_at.is_(None))
        all_servers = list(session.execute(srv_stmt).scalars().all())
        stale_ids = [srv.id for srv in all_servers if is_stale(srv, now=now)]
        if not stale_ids:
            return stream_csv(iter([]), FINDINGS_CSV_COLUMNS_CROSS)
        stmt = stmt.where(Finding.server_id.in_(stale_ids))

    # Sortierung — Whitelist + sekundaerer Tiebreak.
    sort_col = _SORT_COLUMNS_CROSS.get(sort)
    if sort_col is None:
        sort_col = _SORT_COLUMNS_CROSS["sev"]
        dir = "desc"
    primary_clause = sort_col.asc() if dir == "asc" else sort_col.desc()
    primary_clause = nulls_last(primary_clause)
    stmt = stmt.order_by(primary_clause, Finding.identifier_key.asc())

    def _row_iter() -> Iterator[dict[str, Any]]:
        # ORM-`yield_per` ist mit `unique()` inkompatibel — wir brauchen
        # `unique()`, weil das JOIN auf Server fuer den `q`-Filter mehrere
        # Finding-Rows produzieren koennte (selectinload-Eager-Load + JOIN).
        # Loesung: explizite `.unique().all()`-Materialisierung. CSV bleibt
        # streamend per Zeile dank `stream_csv`-Generator unten; ein einmaliger
        # All-Buffer in Python ist akzeptabel — die 200-Truncation gilt fuer
        # CSV bewusst nicht (ADR-0020), aber realistische Fleet-Volumes sind
        # < 50k Rows.
        result = session.execute(stmt)
        for f in result.scalars().unique().all():
            server_name = ""
            server_attr: Server | None = getattr(f, "server", None)
            if server_attr is not None:
                server_name = server_attr.name
            yield {
                "Server": server_name,
                "cve_id": f.identifier_key,
                "package_name": f.package_name,
                "installed_version": f.installed_version or "",
                "fixed_version": f.fixed_version or "",
                "severity": f.severity.value,
                "cvss_v3_score": f.cvss_v3_score if f.cvss_v3_score is not None else "",
                "epss_score": f.epss_score if f.epss_score is not None else "",
                "is_kev": "true" if f.is_kev else "false",
                "status": f.status.value,
                "first_seen_at": f.first_seen_at,
                "title": f.title or "",
            }

    return stream_csv(_row_iter(), FINDINGS_CSV_COLUMNS_CROSS)


__all__ = [
    "AUDIT_CSV_COLUMNS",
    "FINDINGS_CSV_COLUMNS",
    "FINDINGS_CSV_COLUMNS_CROSS",
    "FINDINGS_CSV_COLUMNS_DIFF",
    "FINDINGS_CSV_COLUMNS_GROUPED",
    "CsvExportMode",
    "stream_audit_csv",
    "stream_csv",
    "stream_findings_csv",
    "stream_findings_csv_cross_server",
]
