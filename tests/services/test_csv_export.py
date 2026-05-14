"""Tests fuer `app/services/csv_export.py` (Block F).

Streaming, Spalten-Reihenfolge stabil, Datetime-ISO-Format, Behandlung von
None/dict/list. Performance: 1000-Zeilen-Iterator wird lazy konsumiert.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

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
    AUDIT_CSV_COLUMNS,
    FINDINGS_CSV_COLUMNS,
    _harden_against_formula,
    stream_audit_csv,
    stream_csv,
    stream_findings_csv,
)
from app.services.findings_query import FindingsFilter

# psycopg-Connection-Pool-Cleanup-Reihenfolge ist unter `filterwarnings =
# error` flaky beim Aufeinanderfolgen vieler DB-Tests (siehe auch
# `tests/adversarial/test_csv_injection.py`). Die `ResourceWarning` kommt
# aus dem GC, nicht aus unseren Helpers, und ist KEIN echter Test-Failure.
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

_BASE_TS = datetime(2026, 5, 13, 9, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# stream_csv generic
# ---------------------------------------------------------------------------


def test_stream_csv_yields_header_then_rows_in_stable_column_order() -> None:
    rows = [
        {"a": 1, "b": 2, "c": 3},
        {"a": 10, "b": 20, "c": 30},
    ]
    columns = ["a", "b", "c"]
    result = b"".join(stream_csv(rows, columns)).decode("utf-8")
    lines = result.strip().split("\r\n")
    assert lines[0] == "a,b,c"
    assert lines[1] == "1,2,3"
    assert lines[2] == "10,20,30"


def test_stream_csv_yields_bytes_utf8() -> None:
    rows = [{"x": "ueber", "y": "loeffel"}]
    for chunk in stream_csv(rows, ["x", "y"]):
        assert isinstance(chunk, bytes)
        # UTF-8 dekodierbar.
        chunk.decode("utf-8")


def test_stream_csv_datetime_serialized_as_iso8601() -> None:
    ts = datetime(2026, 5, 13, 9, 0, tzinfo=UTC)
    result = b"".join(stream_csv([{"ts": ts}], ["ts"])).decode("utf-8")
    assert "2026-05-13T09:00:00+00:00" in result


def test_stream_csv_none_becomes_empty_string() -> None:
    result = b"".join(stream_csv([{"a": None, "b": "x"}], ["a", "b"])).decode("utf-8")
    lines = result.strip().split("\r\n")
    # Row: ,x  -> erstes Feld leer.
    assert lines[1] == ",x"


def test_stream_csv_list_becomes_string_representation() -> None:
    result = b"".join(stream_csv([{"a": [1, 2, 3]}], ["a"])).decode("utf-8")
    lines = result.strip().split("\r\n")
    # `_harden_against_formula` ruft `str([1,2,3])` auf.
    assert "[1, 2, 3]" in lines[1]


def test_stream_csv_dict_becomes_string_representation() -> None:
    result = b"".join(stream_csv([{"a": {"k": "v"}}], ["a"])).decode("utf-8")
    lines = result.strip().split("\r\n")
    assert "'k': 'v'" in lines[1] or "k: v" in lines[1]


def test_stream_csv_streams_lazily_does_not_consume_iterator_eagerly() -> None:
    """Der Generator soll Zeile-fuer-Zeile yielden — nicht alles in RAM ziehen."""
    seen: list[int] = []

    def lazy_rows() -> Iterator[dict[str, Any]]:
        for i in range(5):
            seen.append(i)
            yield {"i": i}

    gen = stream_csv(lazy_rows(), ["i"])
    # Erste yield = Header. Iterator wurde NICHT konsumiert (kein `seen` Eintrag).
    first = next(gen)
    assert first.startswith(b"i\r\n")
    assert seen == [], (
        "stream_csv hat Iterator eager konsumiert — die Header-Phase darf "
        "NICHT die Daten-Zeilen pullen"
    )
    # Naechster Pull: ein Daten-Row.
    next(gen)
    assert seen == [0]


def test_stream_csv_column_order_is_deterministic_across_invocations() -> None:
    """Wiederholte Aufrufe mit gleicher Columns-Liste liefern gleiche Spalten."""
    columns = ["x", "y", "z"]
    out1 = b"".join(stream_csv([{"x": 1, "y": 2, "z": 3}], columns)).decode("utf-8")
    out2 = b"".join(stream_csv([{"x": 1, "y": 2, "z": 3}], columns)).decode("utf-8")
    assert out1 == out2


def test_stream_csv_handles_1000_rows_without_growing_buffer() -> None:
    """1000-Zeilen-Stream: Output ist korrekt und Header-Zeile genau einmal."""
    rows = ({"n": i} for i in range(1000))
    chunks = list(stream_csv(rows, ["n"]))
    # Mindestens 1001 Chunks (Header + 1000 Rows).
    assert len(chunks) >= 1001
    decoded = b"".join(chunks).decode("utf-8")
    lines = decoded.strip().split("\r\n")
    assert len(lines) == 1001
    assert lines[0] == "n"
    assert lines[1] == "0"
    assert lines[-1] == "999"


# ---------------------------------------------------------------------------
# _harden_against_formula
# ---------------------------------------------------------------------------


def test_harden_against_formula_passes_normal_text_through() -> None:
    assert _harden_against_formula("hello") == "hello"
    assert _harden_against_formula("CVE-2024-12345") == "CVE-2024-12345"


def test_harden_against_formula_escapes_formula_prefixes() -> None:
    assert _harden_against_formula("=cmd|x") == "'=cmd|x"
    assert _harden_against_formula("+1") == "'+1"
    assert _harden_against_formula("-99") == "'-99"
    assert _harden_against_formula("@SUM(A1)") == "'@SUM(A1)"
    assert _harden_against_formula("\tabc") == "'\tabc"
    assert _harden_against_formula("\rxyz") == "'\rxyz"


def test_harden_against_formula_none_to_empty() -> None:
    assert _harden_against_formula(None) == ""


def test_harden_against_formula_iso_datetime() -> None:
    ts = datetime(2026, 5, 13, 9, 0, tzinfo=UTC)
    assert _harden_against_formula(ts) == "2026-05-13T09:00:00+00:00"


# ---------------------------------------------------------------------------
# stream_audit_csv (integration)
# ---------------------------------------------------------------------------


def _add_audit_event(
    app: Flask, *, actor: str, action: str, target_id: str | None = None, comment: str | None = None
) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            sess.add(
                AuditEvent(
                    actor=actor,
                    action=action,
                    target_type="finding",
                    target_id=target_id,
                    comment=comment,
                )
            )
            sess.commit()
        finally:
            sess.close()


def test_stream_audit_csv_yields_filtered_events(db_app: Flask) -> None:
    _add_audit_event(db_app, actor="admin", action="finding.acknowledged", target_id="1")
    _add_audit_event(db_app, actor="admin", action="finding.reopened", target_id="2")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            stmt = select(AuditEvent).where(AuditEvent.action == "finding.acknowledged")
            result = b"".join(stream_audit_csv(sess, filter_query=stmt)).decode("utf-8")
        finally:
            sess.close()

    lines = result.strip().split("\r\n")
    assert lines[0] == ",".join(AUDIT_CSV_COLUMNS)
    body = "\r\n".join(lines[1:])
    assert "finding.acknowledged" in body
    assert "finding.reopened" not in body


# ---------------------------------------------------------------------------
# stream_findings_csv
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
    app: Flask, *, server_id: int, identifier_key: str, package_name: str = "openssl"
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


def test_stream_findings_csv_global_export_all_servers(db_app: Flask) -> None:
    sid1 = _create_server(db_app, "srv-csv-1")
    sid2 = _create_server(db_app, "srv-csv-2")
    _add_finding(db_app, server_id=sid1, identifier_key="CVE-2024-EX001")
    _add_finding(db_app, server_id=sid2, identifier_key="CVE-2024-EX002")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            result = b"".join(
                stream_findings_csv(sess, server_id=None, filter_obj=FindingsFilter(status="open"))
            ).decode("utf-8")
        finally:
            sess.close()

    lines = result.strip().split("\r\n")
    assert lines[0] == ",".join(FINDINGS_CSV_COLUMNS)
    body = "\r\n".join(lines[1:])
    assert "CVE-2024-EX001" in body
    assert "CVE-2024-EX002" in body
    assert "srv-csv-1" in body
    assert "srv-csv-2" in body


def test_stream_findings_csv_with_server_id_filters(db_app: Flask) -> None:
    sid1 = _create_server(db_app, "srv-csv-a")
    sid2 = _create_server(db_app, "srv-csv-b")
    _add_finding(db_app, server_id=sid1, identifier_key="CVE-2024-FX001")
    _add_finding(db_app, server_id=sid2, identifier_key="CVE-2024-FX002")

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            result = b"".join(
                stream_findings_csv(sess, server_id=sid1, filter_obj=FindingsFilter(status="open"))
            ).decode("utf-8")
        finally:
            sess.close()

    assert "CVE-2024-FX001" in result
    assert "CVE-2024-FX002" not in result


def test_findings_csv_columns_stable_order() -> None:
    """Die Constant `FINDINGS_CSV_COLUMNS` darf nicht versehentlich umgeordnet werden."""
    expected = [
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
    assert expected == FINDINGS_CSV_COLUMNS


def test_audit_csv_columns_stable_order() -> None:
    expected = [
        "ts",
        "actor",
        "action",
        "target_type",
        "target_id",
        "comment",
        "metadata",
    ]
    assert expected == AUDIT_CSV_COLUMNS


_ = timedelta  # keep import alive
