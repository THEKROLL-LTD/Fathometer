"""Unit-Tests fuer `app.services.diff_view.compute_diff` (Block E) ohne DB.

`compute_diff` macht 1-3 `session.execute(...)`-Calls:

1. Scan-Times (`select(Scan.received_at).order_by(...).limit(2)`) →
   `.scalars().all()` liefert [current_at, previous_at] oder kuerzer.
2. Wenn ein Scan: `select(Finding)` fuer New-Bucket → `.scalars().all()`.
3. Wenn zwei Scans: zwei separate `select(Finding)` (New + Resolved) →
   `.scalars().all()`.

Wir mocken `session.execute(...).scalars().all()` mit einer side_effect-
Sequenz und verifizieren die Call-Reihenfolge und das DiffSection-Ergebnis.

`changed=[]` ist **by design** leer (siehe `diff_view`-Modul-Docstring: keine
Field-Level-History im Schema). Wir testen das explizit.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Severity,
)
from app.services.diff_view import compute_diff

_T0 = datetime(2026, 4, 1, 9, 0, tzinfo=UTC)


def _new_finding(
    *,
    server_id: int,
    key: str,
    first_seen_at: datetime,
    status: FindingStatus = FindingStatus.OPEN,
    resolved_at: datetime | None = None,
) -> Finding:
    return Finding(
        server_id=server_id,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key=key,
        package_name="openssl",
        installed_version="1.0",
        severity=Severity.HIGH,
        attack_vector=AttackVector.UNKNOWN,
        status=status,
        first_seen_at=first_seen_at,
        last_seen_at=first_seen_at,
        resolved_at=resolved_at,
        is_kev=False,
    )


def _mock_session_with_executes(execute_results: list[Any]) -> MagicMock:
    """Erzeugt eine MagicMock-Session, deren `.execute()` der Reihe nach durchgeht.

    Jedes Element in `execute_results` ist die `scalars().all()`-Liste die
    der jeweilige Call liefern soll. So koennen wir die drei moeglichen
    `compute_diff`-Pfade (0/1/2 Scans) modellieren.
    """
    session = MagicMock()
    execute_returns = []
    for payload in execute_results:
        result_obj = MagicMock()
        result_obj.scalars.return_value.all.return_value = payload
        execute_returns.append(result_obj)
    session.execute.side_effect = execute_returns
    return session


# ---------------------------------------------------------------------------
# Szenarien
# ---------------------------------------------------------------------------


def test_zero_scans_returns_empty_diff() -> None:
    """Keine Scan-Zeiten -> leere DiffSection, beide Timestamps None."""
    session = _mock_session_with_executes([[]])  # scan-times = []

    diff = compute_diff(session, server_id=1)

    assert diff.new == []
    assert diff.resolved == []
    assert diff.changed == []
    assert diff.previous_scan_at is None
    assert diff.current_scan_at is None
    # Nur EIN execute-Call (Scan-Times).
    assert session.execute.call_count == 1


def test_one_scan_marks_all_findings_as_new() -> None:
    """Genau ein Scan -> alle non-resolved Findings landen in `new`."""
    scan_at = _T0
    open_finding = _new_finding(server_id=1, key="CVE-2026-A001", first_seen_at=scan_at)
    # RESOLVED-Findings tauchen im "new"-Bucket des Erst-Scans nicht auf —
    # die Query filtert via `status != RESOLVED`, wir liefern also nur den
    # Open-Finding.

    session = _mock_session_with_executes(
        [
            [scan_at],  # scan-times = [current]
            [open_finding],  # findings für New-Bucket
        ]
    )

    diff = compute_diff(session, server_id=1)

    assert [f.identifier_key for f in diff.new] == ["CVE-2026-A001"]
    assert diff.resolved == []
    assert diff.changed == []
    assert diff.previous_scan_at is None
    assert diff.current_scan_at == scan_at
    # Zwei execute-Calls: Scan-Times + New-Bucket.
    assert session.execute.call_count == 2


def test_two_scans_classify_new_and_resolved() -> None:
    """Zwei Scans -> Findings nach `first_seen_at`/`resolved_at` klassifiziert.

    Die SQL-Filter (first_seen_at >= prev_at; resolved_at >= prev_at) werden
    DB-seitig ausgewertet — wir mocken die schon gefilterten Returns. Test
    verifiziert dass die zwei Buckets korrekt an `DiffSection` durchgereicht
    werden.
    """
    prev_at = _T0
    curr_at = _T0 + timedelta(hours=24)
    # New-Bucket (first_seen_at >= prev_at)
    new_b002 = _new_finding(server_id=1, key="CVE-2026-B002", first_seen_at=prev_at)
    new_b003 = _new_finding(
        server_id=1,
        key="CVE-2026-B003",
        first_seen_at=prev_at + timedelta(hours=2),
    )
    # Resolved-Bucket (resolved_at >= prev_at)
    resolved_b004 = _new_finding(
        server_id=1,
        key="CVE-2026-B004",
        first_seen_at=prev_at - timedelta(hours=10),
        status=FindingStatus.RESOLVED,
        resolved_at=prev_at + timedelta(hours=3),
    )

    session = _mock_session_with_executes(
        [
            [curr_at, prev_at],  # scan-times (DESC-sortiert)
            [new_b002, new_b003],  # New-Bucket
            [resolved_b004],  # Resolved-Bucket
        ]
    )

    diff = compute_diff(session, server_id=1)

    assert {f.identifier_key for f in diff.new} == {"CVE-2026-B002", "CVE-2026-B003"}
    assert {f.identifier_key for f in diff.resolved} == {"CVE-2026-B004"}
    assert diff.previous_scan_at == prev_at
    assert diff.current_scan_at == curr_at
    # Drei execute-Calls: Scan-Times + New + Resolved.
    assert session.execute.call_count == 3


def test_diff_changed_is_empty_documented_limitation() -> None:
    """`changed` ist im MVP **immer** leer.

    Das Schema persistiert keine Field-Level-History — ein echter Vergleich
    (CVSS-/EPSS-/Severity-Sprung zwischen zwei Scans) ist ohne
    `findings_history`-Tabelle nicht moeglich. `compute_diff` liefert
    deshalb bewusst `changed=[]`. Wenn das je geaendert wird, muss eine
    ADR diesen Test brechen.
    """
    prev_at = _T0
    curr_at = _T0 + timedelta(hours=24)
    finding = _new_finding(server_id=1, key="CVE-2026-C001", first_seen_at=prev_at)

    session = _mock_session_with_executes(
        [
            [curr_at, prev_at],  # scan-times
            [finding],  # new-bucket
            [],  # resolved-bucket leer
        ]
    )

    diff = compute_diff(session, server_id=1)
    assert diff.changed == []
