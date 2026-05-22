"""Integration-Smokes fuer `app/services/llm_debug_log.py` gegen echte
Postgres-DB.

Diese Tests wurden aus `tests/services/test_llm_debug_log.py` ausgelagert
(TICKET-004, Slice 4). Pure-Unit-Tests fuer ``_apply_body_cap`` verbleiben
in der Service-Test-Datei. Hier liegen die Tests fuer:

  * ``record()`` — schreibt eine Row, applied Body-Cap, normalisiert Felder.
  * ``evict_old()`` — Time-Cap (DELETE bei ``created_at`` < cap) und
    Count-Cap (DELETE alle ausser den ``max_rows`` neuesten).
  * ORM-Round-Trip ueber das ``LLMDebugLog``-Modell.

Auto-Markierung als ``db_integration`` (und damit ``acceptance``) erfolgt
ueber `tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES`.
"""

from __future__ import annotations

from typing import Any

import pytest
from flask import Flask
from sqlalchemy import text

from app.db import get_engine
from app.models import LLMDebugLog
from app.services.llm_debug_log import evict_old, record


def _sync_engine(db_app: Flask) -> Any:
    engine = get_engine(db_app)
    return engine.sync_engine if hasattr(engine, "sync_engine") else engine


# ---------------------------------------------------------------------------
# record()-Tests (DB)
# ---------------------------------------------------------------------------


class TestLLMDebugLogRecord:
    def test_record_writes_row(self, db_app: Flask, db_session: Any) -> None:
        entry = record(
            db_session,
            job=None,
            job_type="group_detection",
            status="success",
            model="mock-model",
            request_body={"k": "v"},
            response_body={"ok": True},
            duration_ms=42,
            server_id=None,
            group_id=None,
            error=None,
        )
        db_session.commit()
        assert entry.id is not None
        # Read-back via raw SQL — Bypass session-cache.
        with _sync_engine(db_app).begin() as conn:
            row = conn.execute(
                text(
                    "SELECT job_type, status, model, duration_ms, request_body, "
                    "response_body FROM llm_debug_log WHERE id = :i"
                ),
                {"i": entry.id},
            ).one()
        assert row.job_type == "group_detection"
        assert row.status == "success"
        assert row.model == "mock-model"
        assert row.duration_ms == 42
        assert row.request_body == {"k": "v"}
        assert row.response_body == {"ok": True}

    def test_record_negative_duration_clamped_to_zero(self, db_app: Flask, db_session: Any) -> None:
        entry = record(
            db_session,
            job=None,
            job_type="risk_evaluation",
            status="failed",
            model="m",
            request_body={"x": 1},
            response_body=None,
            duration_ms=-100,
            error="boom",
        )
        db_session.commit()
        assert entry.duration_ms == 0

    def test_record_caps_request_body_above_size_limit(
        self,
        db_app: Flask,
        db_session: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Request-Body > Cap (gesetzt via Env auf 1024) wird zu Stub-Dict."""
        monkeypatch.setenv("SECSCAN_LLM_DEBUG_LOG_BODY_SIZE_CAP", "1024")
        try:
            big = {"data": "x" * 10_000}
            entry = record(
                db_session,
                job=None,
                job_type="group_detection",
                status="success",
                model="m",
                request_body=big,
                response_body=None,
                duration_ms=10,
            )
            db_session.commit()
        finally:
            pass

        with _sync_engine(db_app).begin() as conn:
            row = conn.execute(
                text("SELECT request_body FROM llm_debug_log WHERE id = :i"),
                {"i": entry.id},
            ).one()
        assert row.request_body.get("__truncated") is True
        assert "preview" in row.request_body

    def test_record_caps_response_body_above_size_limit(
        self,
        db_app: Flask,
        db_session: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("SECSCAN_LLM_DEBUG_LOG_BODY_SIZE_CAP", "1024")
        try:
            big = {"data": "y" * 5_000}
            entry = record(
                db_session,
                job=None,
                job_type="risk_evaluation",
                status="success",
                model="m",
                request_body={"small": 1},
                response_body=big,
                duration_ms=10,
            )
            db_session.commit()
        finally:
            pass

        with _sync_engine(db_app).begin() as conn:
            row = conn.execute(
                text("SELECT response_body FROM llm_debug_log WHERE id = :i"),
                {"i": entry.id},
            ).one()
        assert row.response_body.get("__truncated") is True


# ---------------------------------------------------------------------------
# evict_old()-Tests
# ---------------------------------------------------------------------------


def _insert_log(
    db_app: Flask,
    *,
    age_days: int = 0,
    status: str = "success",
) -> int:
    sync_engine = _sync_engine(db_app)
    with sync_engine.begin() as conn:
        row_id = conn.execute(
            text(
                "INSERT INTO llm_debug_log (job_type, model, request_body, "
                "response_body, duration_ms, status, created_at) VALUES "
                "('group_detection', 'm', '{}'::jsonb, '{}'::jsonb, 0, :st, "
                "now() - make_interval(days => :age)) RETURNING id"
            ),
            {"st": status, "age": age_days},
        ).scalar_one()
    return int(row_id)


def _count_logs(db_app: Flask) -> int:
    sync_engine = _sync_engine(db_app)
    with sync_engine.begin() as conn:
        return int(conn.execute(text("SELECT count(*) FROM llm_debug_log")).scalar_one())


class TestLLMDebugLogEviction:
    def test_evict_old_removes_rows_older_than_age_cap(
        self,
        db_app: Flask,
        db_session: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Age-Cap auf 14 Tage (Default) — Rows aelter als 14 Tage fliegen raus."""
        monkeypatch.setenv("SECSCAN_LLM_DEBUG_LOG_MAX_AGE_DAYS", "14")
        try:
            # 5 alte (30 Tage) + 5 frische (1 Tag) — Cap 14 Tage.
            old_ids = [_insert_log(db_app, age_days=30) for _ in range(5)]
            fresh_ids = [_insert_log(db_app, age_days=1) for _ in range(5)]
            assert _count_logs(db_app) == 10

            time_evicted, count_evicted = evict_old(db_session)
        finally:
            pass

        assert time_evicted == 5
        # Frische sind erhalten.
        sync_engine = _sync_engine(db_app)
        with sync_engine.begin() as conn:
            remaining_ids = {r[0] for r in conn.execute(text("SELECT id FROM llm_debug_log")).all()}
        assert remaining_ids == set(fresh_ids)
        # Alte IDs sind weg.
        assert not (set(old_ids) & remaining_ids)
        # count_evicted ist 0 weil < max_rows.
        assert count_evicted == 0

    def test_evict_old_enforces_count_cap(
        self,
        db_app: Flask,
        db_session: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Count-Cap auf 10 — wenn 25 Rows da sind, bleiben nur 10 uebrig."""
        monkeypatch.setenv("SECSCAN_LLM_DEBUG_LOG_MAX_ROWS", "10")
        monkeypatch.setenv("SECSCAN_LLM_DEBUG_LOG_MAX_AGE_DAYS", "365")
        try:
            for _ in range(25):
                _insert_log(db_app, age_days=0)
            assert _count_logs(db_app) == 25

            time_evicted, count_evicted = evict_old(db_session)
        finally:
            pass

        assert time_evicted == 0
        assert count_evicted == 15
        assert _count_logs(db_app) == 10

    def test_evict_old_idempotent_when_within_caps(
        self,
        db_app: Flask,
        db_session: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Wenn alles innerhalb der Caps liegt, loescht evict_old() nichts."""
        monkeypatch.setenv("SECSCAN_LLM_DEBUG_LOG_MAX_ROWS", "100")
        monkeypatch.setenv("SECSCAN_LLM_DEBUG_LOG_MAX_AGE_DAYS", "30")
        try:
            for _ in range(3):
                _insert_log(db_app, age_days=1)
            time_ev, count_ev = evict_old(db_session)
        finally:
            pass

        assert (time_ev, count_ev) == (0, 0)
        assert _count_logs(db_app) == 3


# ---------------------------------------------------------------------------
# ORM-Integration: Mapped-Model muss Row korrekt round-trippen.
# ---------------------------------------------------------------------------


class TestLLMDebugLogORMRoundtrip:
    def test_load_via_orm(self, db_app: Flask, db_session: Any) -> None:
        entry = record(
            db_session,
            job=None,
            job_type="group_detection",
            status="validation_error",
            model="m",
            request_body={"x": "y"},
            response_body=None,
            duration_ms=99,
            error="bad json",
        )
        db_session.commit()
        loaded = db_session.get(LLMDebugLog, entry.id)
        assert loaded is not None
        assert loaded.job_type == "group_detection"
        assert loaded.status == "validation_error"
        assert loaded.error == "bad json"
        assert loaded.duration_ms == 99
