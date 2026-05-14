"""Unit-Tests fuer `app.services.diff_view.compute_diff` (Block E).

Drei Hauptszenarien:
- Kein Scan -> alles leer, beide Timestamps `None`.
- Genau ein Scan -> alle non-resolved Findings landen in `new`,
  `previous_scan_at=None`.
- Zwei Scans -> Findings mit `first_seen_at >= previous_scan_at` -> `new`,
  Findings mit `status=RESOLVED` und `resolved_at >= previous_scan_at` -> `resolved`.

`changed=[]` ist **by design** leer (siehe `diff_view`-Modul-Docstring: keine
Field-Level-History im Schema). Der Test dokumentiert das explizit.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Flask

from app.db import get_session_factory
from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Scan,
    Severity,
)
from app.services.diff_view import compute_diff
from tests._helpers import register_test_server

_T0 = datetime(2026, 4, 1, 9, 0, tzinfo=UTC)


def _add(app: Flask, items: list[object]) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            for obj in items:
                sess.add(obj)
            sess.commit()
        finally:
            sess.close()


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


# ---------------------------------------------------------------------------
# Szenarien
# ---------------------------------------------------------------------------


def test_zero_scans_returns_empty_diff(db_app: Flask) -> None:
    sid, _ = register_test_server(db_app, name="srv-diff-zero")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            diff = compute_diff(sess, sid)
        finally:
            sess.close()

    assert diff.new == []
    assert diff.resolved == []
    assert diff.changed == []
    assert diff.previous_scan_at is None
    assert diff.current_scan_at is None


def test_one_scan_marks_all_findings_as_new(db_app: Flask) -> None:
    sid, _ = register_test_server(db_app, name="srv-diff-one")
    scan_at = _T0
    _add(
        db_app,
        [
            Scan(server_id=sid, received_at=scan_at),
            _new_finding(server_id=sid, key="CVE-2026-A001", first_seen_at=scan_at),
            _new_finding(
                server_id=sid,
                key="CVE-2026-A002",
                first_seen_at=scan_at,
                status=FindingStatus.RESOLVED,
                resolved_at=scan_at,
            ),
        ],
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            diff = compute_diff(sess, sid)
        finally:
            sess.close()

    keys = [f.identifier_key for f in diff.new]
    # RESOLVED-Findings tauchen im "new"-Bucket des Erst-Scans nicht auf.
    assert keys == ["CVE-2026-A001"]
    assert diff.resolved == []
    assert diff.previous_scan_at is None
    assert diff.current_scan_at == scan_at


def test_two_scans_classify_new_and_resolved(db_app: Flask) -> None:
    """Zwei Scans -> Findings nach `first_seen_at`/`resolved_at` klassifiziert."""
    sid, _ = register_test_server(db_app, name="srv-diff-two")
    prev_at = _T0
    curr_at = _T0 + timedelta(hours=24)
    older_at = _T0 - timedelta(hours=1)

    _add(
        db_app,
        [
            Scan(server_id=sid, received_at=prev_at),
            Scan(server_id=sid, received_at=curr_at),
            # Bereits vorher gesehen (vor previous_at) -> NICHT in new.
            _new_finding(server_id=sid, key="CVE-2026-B001", first_seen_at=older_at),
            # Genau zum previous_at zuerst gesehen -> in new (>= previous_at).
            _new_finding(server_id=sid, key="CVE-2026-B002", first_seen_at=prev_at),
            # Nach previous_at zuerst gesehen -> in new.
            _new_finding(
                server_id=sid,
                key="CVE-2026-B003",
                first_seen_at=prev_at + timedelta(hours=2),
            ),
            # Resolved zwischen previous und current -> in resolved.
            _new_finding(
                server_id=sid,
                key="CVE-2026-B004",
                first_seen_at=older_at,
                status=FindingStatus.RESOLVED,
                resolved_at=prev_at + timedelta(hours=3),
            ),
            # Resolved VOR previous_at -> nicht in resolved.
            _new_finding(
                server_id=sid,
                key="CVE-2026-B005",
                first_seen_at=older_at - timedelta(hours=10),
                status=FindingStatus.RESOLVED,
                resolved_at=older_at - timedelta(hours=5),
            ),
        ],
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            diff = compute_diff(sess, sid)
        finally:
            sess.close()

    new_keys = {f.identifier_key for f in diff.new}
    resolved_keys = {f.identifier_key for f in diff.resolved}

    # `new`: first_seen_at >= previous_at.
    #   B001 first_seen = older_at < prev_at -> NICHT in new.
    #   B002 first_seen = prev_at            -> in new.
    #   B003 first_seen = prev_at + 2h       -> in new.
    #   B004 first_seen = older_at < prev_at -> NICHT in new (aber resolved).
    #   B005 first_seen sehr alt             -> NICHT in new.
    assert new_keys == {"CVE-2026-B002", "CVE-2026-B003"}, new_keys

    # `resolved`: status=RESOLVED + resolved_at >= previous_at.
    #   B004 resolved_at = prev_at + 3h -> in resolved.
    #   B005 resolved_at sehr alt        -> NICHT.
    assert resolved_keys == {"CVE-2026-B004"}, resolved_keys

    assert diff.previous_scan_at == prev_at
    assert diff.current_scan_at == curr_at


def test_diff_changed_is_empty_documented_limitation(db_app: Flask) -> None:
    """`changed` ist im MVP **immer** leer.

    Das Schema persistiert keine Field-Level-History — ein echter Vergleich
    (CVSS-/EPSS-/Severity-Sprung zwischen zwei Scans) ist ohne
    `findings_history`-Tabelle nicht moeglich. `compute_diff` liefert
    deshalb bewusst `changed=[]`. Wenn das je geaendert wird, muss eine
    ADR diesen Test brechen.
    """
    sid, _ = register_test_server(db_app, name="srv-diff-changed")
    _add(
        db_app,
        [
            Scan(server_id=sid, received_at=_T0),
            Scan(server_id=sid, received_at=_T0 + timedelta(hours=24)),
            _new_finding(server_id=sid, key="CVE-2026-C001", first_seen_at=_T0),
        ],
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            diff = compute_diff(sess, sid)
        finally:
            sess.close()

    assert diff.changed == []
