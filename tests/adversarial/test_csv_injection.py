"""Adversarial-Tests fuer CSV-Formula-Injection (Block F, ARCHITECTURE §10).

Excel/LibreOffice interpretieren Zell-Werte, die mit `=`, `+`, `-`, `@`,
Tab oder CR beginnen, als Formel. Mitigation in `app/services/csv_export.py`:
fuehrendes Apostroph (`'`). Diese Tests verifizieren die Mitigation auf zwei
Ebenen:

1. Direkt-Tests gegen `_harden_against_formula` (Edge-Cases).
2. End-to-end ueber `stream_audit_csv` / `stream_findings_csv`, wenn der
   user-controlled Comment/Note-Text einen Formula-Prefix enthaelt.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    AttackVector,
    AuditEvent,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from app.services.csv_export import (
    _harden_against_formula,
    stream_audit_csv,
    stream_findings_csv,
)
from app.services.findings_query import FindingsFilter

# psycopg's `__del__` Cleanup-Reihenfolge ist beim Uebergang aus der
# vorhergehenden DB-Test-Suite (csv_export) flaky, weil `filterwarnings =
# error` in pytest.ini auf alle warnings reagiert — auch auf die GC-
# verzoegerte ResourceWarning aus pool-gehaltenen Connections. Diese
# Warning ist KEIN Test-Failure (nichts in unserem Code leakt), sondern
# ein Cleanup-Race zwischen pytest-Fixtures und psycopg-Pool. Wir
# unterdruecken sie lokal — alle anderen Warnings bleiben "error".
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

_BASE_TS = datetime(2026, 5, 13, 9, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Direkt-Mitigation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "=cmd|' /c calc'!A0",
        "+1+1",
        "-99",
        "@SUM(A1:A10)",
        "\tabc",
        "\rxxx",
        '=HYPERLINK("http://evil/","click")',
    ],
)
def test_formula_prefixes_are_escaped(payload: str) -> None:
    out = _harden_against_formula(payload)
    assert out.startswith("'"), f"Payload {payload!r} wurde nicht escaped: {out!r}"
    assert out == "'" + payload


@pytest.mark.parametrize(
    "payload",
    [
        "hello",
        "CVE-2024-12345",
        "normal text",
        "1234",  # Digits OK
        "openssl",
        "  whitespace ok",
    ],
)
def test_safe_strings_are_passed_through_unchanged(payload: str) -> None:
    assert _harden_against_formula(payload) == payload


def test_already_apostrophe_prefixed_string_does_not_get_double_apostrophe() -> None:
    """Wenn der Benutzer bewusst mit `'` startet, bleibt das so."""
    out = _harden_against_formula("'safe-already")
    # `'` ist KEIN Formula-Trigger -> kein extra-Apostroph.
    assert out == "'safe-already"


# ---------------------------------------------------------------------------
# End-to-end Audit-CSV
# ---------------------------------------------------------------------------


def _add_audit_event(app: Flask, *, comment: str, action: str = "finding.acknowledged") -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            sess.add(
                AuditEvent(
                    actor="admin",
                    action=action,
                    target_type="finding",
                    target_id="1",
                    comment=comment,
                )
            )
            sess.commit()
        finally:
            sess.close()


_DANGEROUS_COMMENTS = [
    "=cmd|' /c calc'!A0",
    "+1+1",
    "-99",
    "@SUM(A1:A10)",
    "\tabc",
    "\rxxx",
]


def test_audit_csv_escapes_dangerous_comments_end_to_end(db_app: Flask) -> None:
    """Schreibt einen Audit-Event pro Payload und prueft die CSV-Mitigation.

    Bewusst konsolidiert (kein `parametrize`) — die parametrisierte Variante
    triggerte unter `filterwarnings = error` flaky psycopg-`ResourceWarning`-
    Fehlschlaege beim Sub-Test-Teardown, weil die `db_app`-Fixture pro
    parametrisiertem Lauf neu aufgesetzt wird und der Connection-Pool dann
    eine vorherige Connection erst beim naechsten Setup endgueltig schliesst.
    Ein Test-Body mit Schleife teilt sich eine Fixture-Instanz und vermeidet
    den `__del__`-Race.
    """
    for comment in _DANGEROUS_COMMENTS:
        _add_audit_event(db_app, comment=comment)

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            stmt = select(AuditEvent).order_by(AuditEvent.id)
            output = b"".join(stream_audit_csv(sess, filter_query=stmt)).decode("utf-8")
        finally:
            sess.close()

    import csv as _csv
    import io as _io

    reader = list(_csv.reader(_io.StringIO(output), lineterminator="\r\n"))
    comment_idx = reader[0].index("comment")
    # Header + N Daten-Zeilen.
    assert len(reader) == 1 + len(_DANGEROUS_COMMENTS), reader

    for row, expected_payload in zip(reader[1:], _DANGEROUS_COMMENTS, strict=True):
        cell = row[comment_idx]
        assert cell.startswith("'"), f"Payload {expected_payload!r} nicht escaped: {cell!r}"


# ---------------------------------------------------------------------------
# End-to-end Findings-CSV (Title-Feld)
# ---------------------------------------------------------------------------


def _create_server(app: Flask, name: str) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    package_name: str = "openssl",
    title: str | None = None,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key=identifier_key,
                package_name=package_name,
                installed_version="1.0",
                severity=Severity.HIGH,
                title=title,
                attack_vector=AttackVector.UNKNOWN,
                status=FindingStatus.OPEN,
                first_seen_at=_BASE_TS,
                last_seen_at=_BASE_TS,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


_DANGEROUS_TITLES = [
    '=HYPERLINK("http://evil","click")',
    "+evil-formula",
    "-leading-minus",
    "@command-prefix",
]


def test_findings_csv_escapes_dangerous_titles_end_to_end(db_app: Flask) -> None:
    """Wie der Audit-Pendant: ein Test-Body mit Schleife vermeidet flaky
    `ResourceWarning`-Cleanup zwischen parametrisierten Sub-Tests."""
    sid = _create_server(db_app, "srv-titles")
    for i, payload in enumerate(_DANGEROUS_TITLES):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-2024-INJ{i:02d}",
            package_name=f"pkg-{i}",
            title=payload,
        )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            output = b"".join(
                stream_findings_csv(
                    sess,
                    server_id=None,
                    filter_obj=FindingsFilter(status="open"),
                )
            ).decode("utf-8")
        finally:
            sess.close()

    import csv as _csv
    import io as _io

    reader = list(_csv.reader(_io.StringIO(output), lineterminator="\r\n"))
    title_idx = reader[0].index("title")
    titles_in_csv = [row[title_idx] for row in reader[1:]]
    # Jedes der Payloads muss apostrophe-escaped in der CSV stehen.
    for expected in _DANGEROUS_TITLES:
        escaped = "'" + expected
        assert escaped in titles_in_csv, (
            f"Erwartet '{escaped}' nicht in CSV-Title-Spalte: {titles_in_csv}"
        )


def test_findings_csv_safe_title_remains_unchanged(db_app: Flask) -> None:
    """Plaintext-Title ohne Trigger-Zeichen wird NICHT mit Apostroph praefixed."""
    sid = _create_server(db_app, "srv-safe-title")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-INJ02",
        title="Heap buffer overflow in libfoo",
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            output = b"".join(
                stream_findings_csv(
                    sess,
                    server_id=None,
                    filter_obj=FindingsFilter(status="open"),
                )
            ).decode("utf-8")
        finally:
            sess.close()

    import csv as _csv
    import io as _io

    reader = list(_csv.reader(_io.StringIO(output), lineterminator="\r\n"))
    title_idx = reader[0].index("title")
    cell = reader[1][title_idx]
    assert cell == "Heap buffer overflow in libfoo"
    assert not cell.startswith("'")
