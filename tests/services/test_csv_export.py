"""Unit-Tests fuer `app/services/csv_export.py` (Block F).

Streaming, Spalten-Reihenfolge stabil, Datetime-ISO-Format, Behandlung von
None/dict/list. Performance: 1000-Zeilen-Iterator wird lazy konsumiert.

DB-abhaengige Smokes (echte `stream_audit_csv` / `stream_findings_csv` gegen
SQLAlchemy-Session) liegen in `tests/integration/test_csv_export_db.py`
(TICKET-004 Slice 1).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from app.services.csv_export import (
    AUDIT_CSV_COLUMNS,
    FINDINGS_CSV_COLUMNS,
    _harden_against_formula,
    stream_csv,
)

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
# Spalten-Reihenfolge stabil
# ---------------------------------------------------------------------------


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
