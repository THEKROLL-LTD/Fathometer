"""Diff-View-Service: was hat sich seit dem letzten Scan geaendert?

ARCHITECTURE.md §5 (Diff-Berechnung), §7 (Diff-Sektionen Neu/Resolved/
Veraendert).

**Bekannte Limitation (Block-E-Scope):** Block C persistiert kein Field-
Level-History pro Finding — die Findings-Tabelle haelt nur den jeweils
aktuellen Zustand. Ein echter "Verändert"-Vergleich (CVSS-/EPSS-/Severity-
Sprung zwischen zwei Scans) ist deshalb ohne Schema-Erweiterung nicht
moeglich. Wir liefern die `changed`-Liste als **leere Liste** und
dokumentieren das hier. Wenn der User eine `findings_history`-Tabelle
moechte, ist das eine eigene ADR.

Pragmatische Heuristik fuer Neu/Resolved:

- `new`: Findings mit `first_seen_at >= previous_scan_at` (also seit dem
  vorletzten Scan zum ersten Mal aufgetaucht).
- `resolved`: Findings mit Status `RESOLVED` und `resolved_at >=
  previous_scan_at`.

Wenn nur **ein** Scan existiert (Erst-Scan):
- `new` = alle aktuellen Findings.
- `resolved` = leer.
- `previous_scan_at = None`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models import Finding, FindingStatus, Scan


@dataclass(frozen=True, slots=True)
class FindingChange:
    """Platzhalter fuer ein "verändertes" Finding.

    Wird in der aktuellen Implementierung nicht befuellt — siehe Modul-
    Docstring zur Limitation. Felder sind schon definiert, damit zukuenftige
    Schema-Erweiterungen (mit History-Tabelle) die Datenstruktur direkt
    befuellen koennen.
    """

    finding: Finding
    old_severity: str | None = None
    new_severity: str | None = None
    old_cvss: float | None = None
    new_cvss: float | None = None
    old_epss: float | None = None
    new_epss: float | None = None
    old_is_kev: bool | None = None
    new_is_kev: bool | None = None


@dataclass(slots=True)
class DiffSection:
    """Ergebnis der Diff-Berechnung fuer den `mode=diff`-View.

    Felder:
    - `new`: Findings, die seit dem vorletzten Scan zum ersten Mal auftauchen.
    - `resolved`: Findings, die zwischen vorletztem und letztem Scan auf
      `RESOLVED` gesetzt wurden.
    - `changed`: derzeit immer leer — siehe Limitation im Modul-Docstring.
    - `previous_scan_at`: `received_at` des vorletzten Scans, oder `None`
      wenn der Server bisher nur einen Scan hatte.
    - `current_scan_at`: `received_at` des letzten Scans, oder `None` wenn
      noch kein Scan existiert.
    """

    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    changed: list[FindingChange] = field(default_factory=list)
    previous_scan_at: datetime | None = None
    current_scan_at: datetime | None = None


def _two_latest_scan_times(
    session: Session, server_id: int
) -> tuple[datetime | None, datetime | None]:
    """Liefert (current_scan_at, previous_scan_at) als `received_at`-Stempel."""
    stmt = (
        select(Scan.received_at)
        .where(Scan.server_id == server_id)
        .order_by(desc(Scan.received_at))
        .limit(2)
    )
    rows = list(session.execute(stmt).scalars().all())
    if not rows:
        return None, None
    if len(rows) == 1:
        return rows[0], None
    return rows[0], rows[1]


def compute_diff(session: Session, server_id: int) -> DiffSection:
    """Berechnet die Diff-Sektionen Neu/Resolved fuer den `mode=diff`-View.

    Siehe Modul-Docstring zur Heuristik und zur `changed=[]`-Limitation.
    """
    current_at, previous_at = _two_latest_scan_times(session, server_id)
    section = DiffSection(
        current_scan_at=current_at,
        previous_scan_at=previous_at,
    )

    # Kein Scan -> alles leer.
    if current_at is None:
        return section

    # Genau ein Scan -> alle aktuellen Findings sind "neu" (Erst-Bestand).
    if previous_at is None:
        stmt = (
            select(Finding)
            .where(Finding.server_id == server_id)
            .where(Finding.status != FindingStatus.RESOLVED)
            .order_by(Finding.is_kev.desc(), Finding.first_seen_at.desc())
        )
        section.new = list(session.execute(stmt).scalars().all())
        return section

    # Zwei oder mehr Scans: Diff-Fenster zwischen `previous_at` und `current_at`.
    new_stmt = (
        select(Finding)
        .where(Finding.server_id == server_id)
        .where(Finding.first_seen_at >= previous_at)
        .order_by(Finding.is_kev.desc(), Finding.first_seen_at.desc())
    )
    section.new = list(session.execute(new_stmt).scalars().all())

    resolved_stmt = (
        select(Finding)
        .where(Finding.server_id == server_id)
        .where(Finding.status == FindingStatus.RESOLVED)
        .where(Finding.resolved_at.is_not(None))
        .where(Finding.resolved_at >= previous_at)
        .order_by(Finding.resolved_at.desc())
    )
    section.resolved = list(session.execute(resolved_stmt).scalars().all())

    # `changed` bleibt leer — siehe Modul-Docstring.
    section.changed = []

    return section


__all__ = ["DiffSection", "FindingChange", "compute_diff"]
