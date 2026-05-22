"""Pure-Unit-Tests fuer `_serialize_job_status` (Block R Phase D).

Testet ausschliesslich die Serialisierungs-Helper-Funktion — kein Flask-Context,
kein DB-Fixture. Die Funktion ist von der Route losgeloest und gibt ein
reines dict zurueck.

On-Demand-Verifikation (erfordert db_integration, NICHT hier):
- Cross-Server-404-Verhalten via echten DB-Rows.
- Auth-Fail-401 / Server-Inactive-403 gegen echten HTTP-Stack.
- Polling-Burst-Test (50 Calls, Rate-Limit-Bucket).
- Alle vier Status-Werte per echten DB-Round-Trip.
Siehe Kommentar-Block am Kopf von `app/api/scans.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

from app.api.scans import _MAX_ERROR_LEN, _serialize_job_status

# ---------------------------------------------------------------------------
# Fixtures — minimale ScanIngestJob-Mocks (kein ORM-Session benoetigt)
# ---------------------------------------------------------------------------


def _make_job(**kwargs: Any) -> MagicMock:
    """Erstellt einen MagicMock der ScanIngestJob-Interface-Konventionen erfuellt.

    Defaults entsprechen einem frischen 'queued'-Job.
    """
    now = datetime(2026, 5, 22, 10, 0, 0, tzinfo=UTC)
    job = MagicMock()
    job.id = kwargs.get("id", 42)
    job.status = kwargs.get("status", "queued")
    job.created_at = kwargs.get("created_at", now)
    job.picked_up_at = kwargs.get("picked_up_at")
    job.finished_at = kwargs.get("finished_at")
    job.attempts = kwargs.get("attempts", 0)
    job.scan_id = kwargs.get("scan_id")
    job.result = kwargs.get("result")
    job.error = kwargs.get("error")
    return job


# ---------------------------------------------------------------------------
# Test 1: queued — keine Counts, kein error, kein scan_id
# ---------------------------------------------------------------------------


def test_serialize_queued_no_extras() -> None:
    """status='queued': Basis-Felder vorhanden, kein counts/error/scan_id."""
    job = _make_job(status="queued", attempts=0)
    body = _serialize_job_status(job)

    assert body["job_id"] == 42
    assert body["status"] == "queued"
    assert body["attempts"] == 0
    assert body["picked_up_at"] is None
    assert body["finished_at"] is None
    assert "counts" not in body
    assert "error" not in body
    assert "scan_id" not in body


# ---------------------------------------------------------------------------
# Test 2: in_progress — picked_up_at gesetzt
# ---------------------------------------------------------------------------


def test_serialize_in_progress_has_picked_up_at() -> None:
    """status='in_progress': picked_up_at ist gesetzt, kein counts/error."""
    pickup = datetime(2026, 5, 22, 10, 5, 0, tzinfo=UTC)
    job = _make_job(status="in_progress", picked_up_at=pickup, attempts=1)
    body = _serialize_job_status(job)

    assert body["status"] == "in_progress"
    assert body["picked_up_at"] == pickup.isoformat()
    assert body["attempts"] == 1
    assert "counts" not in body
    assert "error" not in body
    assert "scan_id" not in body


# ---------------------------------------------------------------------------
# Test 3: done — counts + scan_id vorhanden
# ---------------------------------------------------------------------------


def test_serialize_done_includes_counts_and_scan_id() -> None:
    """status='done': scan_id und counts-Dict aus result-JSONB."""
    finished = datetime(2026, 5, 22, 10, 6, 30, tzinfo=UTC)
    result_jsonb = {
        "scan_id": 99,
        "findings_total": 500,
        "findings_inserted": 480,
        "findings_updated": 15,
        "findings_resolved": 5,
        "class_os_pkgs": 400,
        "class_lang_pkgs": 90,
        "class_other": 10,
    }
    job = _make_job(status="done", scan_id=99, result=result_jsonb, finished_at=finished)
    body = _serialize_job_status(job)

    assert body["status"] == "done"
    assert body["scan_id"] == 99
    assert body["finished_at"] == finished.isoformat()
    counts = body["counts"]
    assert counts["findings_total"] == 500
    assert counts["findings_inserted"] == 480
    assert counts["findings_updated"] == 15
    assert counts["findings_resolved"] == 5
    assert counts["class_os_pkgs"] == 400
    assert counts["class_lang_pkgs"] == 90
    assert counts["class_other"] == 10
    assert "error" not in body


# ---------------------------------------------------------------------------
# Test 4: failed — error-Feld vorhanden
# ---------------------------------------------------------------------------


def test_serialize_failed_includes_error() -> None:
    """status='failed': error-Feld gesetzt, kein counts/scan_id."""
    job = _make_job(status="failed", error="Pydantic ValidationError: field 'x' missing")
    body = _serialize_job_status(job)

    assert body["status"] == "failed"
    assert body["error"] == "Pydantic ValidationError: field 'x' missing"
    assert "counts" not in body
    assert "scan_id" not in body


# ---------------------------------------------------------------------------
# Test 5: Counts-Pass-Through aus JSONB (alle Schluessel vorhanden)
# ---------------------------------------------------------------------------


def test_serialize_done_counts_passthrough_all_keys() -> None:
    """done-Job: alle sieben Counts-Schluessel werden 1:1 durchgereicht."""
    result = {
        "findings_total": 1,
        "findings_inserted": 2,
        "findings_updated": 3,
        "findings_resolved": 4,
        "class_os_pkgs": 5,
        "class_lang_pkgs": 6,
        "class_other": 7,
    }
    job = _make_job(status="done", scan_id=1, result=result)
    counts = _serialize_job_status(job)["counts"]

    assert counts == {
        "findings_total": 1,
        "findings_inserted": 2,
        "findings_updated": 3,
        "findings_resolved": 4,
        "class_os_pkgs": 5,
        "class_lang_pkgs": 6,
        "class_other": 7,
    }


# ---------------------------------------------------------------------------
# Test 6: error-Truncation bei > 4096 Chars
# ---------------------------------------------------------------------------


def test_serialize_failed_error_truncated_at_max_len() -> None:
    """Langer error-String wird auf _MAX_ERROR_LEN Zeichen abgeschnitten."""
    long_error = "X" * (_MAX_ERROR_LEN + 100)
    job = _make_job(status="failed", error=long_error)
    body = _serialize_job_status(job)

    assert len(body["error"]) == _MAX_ERROR_LEN
    assert body["error"] == "X" * _MAX_ERROR_LEN


# ---------------------------------------------------------------------------
# Test 7: Timestamps sind ISO-formatiert
# ---------------------------------------------------------------------------


def test_serialize_timestamps_are_iso_format() -> None:
    """created_at, picked_up_at und finished_at werden als ISO-Strings serialisiert."""
    created = datetime(2026, 1, 15, 8, 30, 0, tzinfo=UTC)
    picked = datetime(2026, 1, 15, 8, 30, 5, tzinfo=UTC)
    finished = datetime(2026, 1, 15, 8, 31, 0, tzinfo=UTC)

    job = _make_job(
        status="done",
        created_at=created,
        picked_up_at=picked,
        finished_at=finished,
        scan_id=7,
        result={},
    )
    body = _serialize_job_status(job)

    assert body["created_at"] == created.isoformat()
    assert body["picked_up_at"] == picked.isoformat()
    assert body["finished_at"] == finished.isoformat()


# ---------------------------------------------------------------------------
# Test 8: done mit leerem result-JSONB (None/fehlende Felder -> 0-Fallback)
# ---------------------------------------------------------------------------


def test_serialize_done_empty_result_defaults_to_zero() -> None:
    """done-Job mit result=None: Counts-Felder fallen auf 0 zurueck."""
    job = _make_job(status="done", scan_id=5, result=None)
    counts = _serialize_job_status(job)["counts"]

    assert counts["findings_total"] == 0
    assert counts["findings_inserted"] == 0
    assert counts["findings_updated"] == 0
    assert counts["findings_resolved"] == 0
    assert counts["class_os_pkgs"] == 0
    assert counts["class_lang_pkgs"] == 0
    assert counts["class_other"] == 0


# ---------------------------------------------------------------------------
# Test 9: failed mit error=None -> leerer String (kein crash)
# ---------------------------------------------------------------------------


def test_serialize_failed_error_none_produces_empty_string() -> None:
    """failed-Job mit error=None: error-Feld ist leerer String, kein Crash."""
    job = _make_job(status="failed", error=None)
    body = _serialize_job_status(job)

    assert body["error"] == ""
