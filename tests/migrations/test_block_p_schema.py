"""Block P Phase A (ADR-0023) — Migration-Smoke fuer Schema-Erweiterung.

Reflektiert nach `alembic upgrade head` die neuen Tabellen, Spalten,
Indizes, FKs und Settings-Defaults via SQLAlchemy-Inspector. Voller
Roundtrip ist ueber `alembic upgrade head && alembic downgrade -1 &&
alembic upgrade head` in der CI abgedeckt; hier nur Schema-Smoke.
"""

from __future__ import annotations

from flask import Flask
from sqlalchemy import inspect, select

from app.db import get_engine, get_session_factory
from app.models import Setting
from app.settings_service import ensure_settings_row


def _inspector(db_app: Flask):  # type: ignore[no-untyped-def]
    engine = get_engine(db_app)
    return inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)


# ---------------------------------------------------------------------------
# Tabellen-Existenz
# ---------------------------------------------------------------------------


def test_block_p_tables_exist(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    table_names = set(inspector.get_table_names())
    for name in ("application_groups", "llm_jobs", "llm_risk_cache"):
        assert name in table_names, f"missing table {name}"


# ---------------------------------------------------------------------------
# application_groups Spalten + CheckConstraints
# ---------------------------------------------------------------------------


def test_application_groups_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("application_groups")}
    for name in (
        "id",
        "label",
        "explanation",
        "path_prefixes",
        "pkg_name_exact",
        "pkg_name_glob",
        "pkg_purl_pattern",
        "risk_band",
        "risk_band_reason",
        "risk_band_source",
        "risk_band_computed_at",
        "worst_finding_id",
        "group_findings_fingerprint",
        "source",
        "detected_at",
        "last_used_at",
    ):
        assert name in cols, f"missing column application_groups.{name}"


def test_application_groups_check_constraints(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    checks = inspector.get_check_constraints("application_groups")
    names = {c["name"] for c in checks}
    assert "ck_application_groups_band" in names
    assert "ck_application_groups_source" in names


# ---------------------------------------------------------------------------
# llm_jobs Spalten + Indizes + Check
# ---------------------------------------------------------------------------


def test_llm_jobs_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("llm_jobs")}
    for name in (
        "id",
        "job_type",
        "server_id",
        "payload",
        "depends_on",
        "status",
        "attempts",
        "next_attempt_at",
        "picked_up_by",
        "picked_up_at",
        "result",
        "error",
        "created_at",
        "completed_at",
    ):
        assert name in cols, f"missing column llm_jobs.{name}"


def test_llm_jobs_indexes(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {ix["name"] for ix in inspector.get_indexes("llm_jobs")}
    for name in ("ix_llm_jobs_pickup", "ix_llm_jobs_stale", "ix_llm_jobs_server"):
        assert name in names, f"missing index {name}"


def test_llm_jobs_check_constraints(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {c["name"] for c in inspector.get_check_constraints("llm_jobs")}
    assert "ck_llm_jobs_type" in names
    assert "ck_llm_jobs_status" in names
    assert "ck_llm_jobs_attempts" in names


# ---------------------------------------------------------------------------
# llm_risk_cache Spalten + Indizes
# ---------------------------------------------------------------------------


def test_llm_risk_cache_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("llm_risk_cache")}
    for name in (
        "cache_key",
        "group_id",
        "group_findings_fp",
        "cve_data_fp",
        "server_context_fp",
        "risk_band",
        "worst_finding_id",
        "reason",
        "llm_model",
        "computed_at",
        "used_count",
        "last_used_at",
    ):
        assert name in cols, f"missing column llm_risk_cache.{name}"


def test_llm_risk_cache_indexes(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {ix["name"] for ix in inspector.get_indexes("llm_risk_cache")}
    assert "ix_llm_risk_cache_lru" in names
    assert "ix_llm_risk_cache_group" in names


# ---------------------------------------------------------------------------
# findings.application_group_id FK + Index
# ---------------------------------------------------------------------------


def test_findings_application_group_column(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("findings")}
    assert "application_group_id" in cols
    assert cols["application_group_id"]["nullable"] is True


def test_findings_application_group_index(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {ix["name"] for ix in inspector.get_indexes("findings")}
    assert "ix_findings_application_group" in names


def test_findings_application_group_fk_set_null(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    fks = inspector.get_foreign_keys("findings")
    matches = [
        fk
        for fk in fks
        if fk.get("constrained_columns") == ["application_group_id"]
        and fk.get("referred_table") == "application_groups"
    ]
    assert matches, "FK findings.application_group_id -> application_groups.id fehlt"
    options = matches[0].get("options") or {}
    assert options.get("ondelete", "").upper() == "SET NULL"


# ---------------------------------------------------------------------------
# Settings-Defaults (Block P)
# ---------------------------------------------------------------------------


def test_settings_block_p_columns_exist(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("settings")}
    assert "block_p_llm_mode" in cols
    assert "llm_worker_heartbeat_at" in cols
    assert "llm_token_budget_used_today" in cols
    assert cols["block_p_llm_mode"]["nullable"] is False
    assert cols["llm_worker_heartbeat_at"]["nullable"] is True
    assert cols["llm_token_budget_used_today"]["nullable"] is False


def test_settings_block_p_defaults_after_ensure_row(db_app: Flask) -> None:
    """Nach `ensure_settings_row` haben die drei Felder ihre Defaults."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            ensure_settings_row(sess)
            row = sess.execute(select(Setting).where(Setting.id == 1)).scalar_one()
            assert row.block_p_llm_mode == "off"
            assert row.llm_worker_heartbeat_at is None
            assert row.llm_token_budget_used_today == 0
        finally:
            sess.close()


def test_settings_block_p_check_constraints(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {c["name"] for c in inspector.get_check_constraints("settings")}
    assert "ck_settings_block_p_llm_mode" in names
    assert "ck_settings_llm_token_budget_used_today_nonneg" in names
