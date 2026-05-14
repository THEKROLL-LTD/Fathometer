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
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import AuditEvent, Finding, Server
from app.services.findings_query import FindingsFilter, _apply_filters, _order_clauses

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


def stream_findings_csv(
    session: Session,
    *,
    server_id: int | None,
    filter_obj: FindingsFilter,
) -> Generator[bytes]:
    """Streamt Findings als CSV. Wenn `server_id` None ist, ueber die Flotte.

    Nutzt die in `findings_query.py` definierten Filter-Helpers. Reihenfolge:
    §15-Default (KEV/EPSS/CVSS/Severity/first_seen_at).
    """
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

    stmt = stmt.order_by(*_order_clauses(filter_obj))

    def _row_iter() -> Iterator[dict[str, Any]]:
        result = session.execute(stmt.execution_options(yield_per=200))
        for finding in result.scalars():
            yield _finding_row(finding)

    return stream_csv(_row_iter(), FINDINGS_CSV_COLUMNS)


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


__all__ = [
    "AUDIT_CSV_COLUMNS",
    "FINDINGS_CSV_COLUMNS",
    "stream_audit_csv",
    "stream_csv",
    "stream_findings_csv",
]
