"""Block O Phase A (ADR-0022) — Migration-Smoke fuer Schema-Erweiterung.

Reflektiert nach `alembic upgrade head` die neuen Spalten + Tabellen + Indizes
via SQLAlchemy-Inspector. Voller Roundtrip (upgrade/downgrade/upgrade) ist
ueber `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`
in der CI abgedeckt; hier nur Schema-Smoke gegen die migrierte DB.
"""

from __future__ import annotations

from flask import Flask
from sqlalchemy import inspect

from app.db import get_engine

# ---------------------------------------------------------------------------
# Server-Spalte
# ---------------------------------------------------------------------------


def test_server_host_state_snapshot_at_exists(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    cols = {col["name"]: col for col in inspector.get_columns("servers")}
    assert "host_state_snapshot_at" in cols
    assert cols["host_state_snapshot_at"]["nullable"] is True


# ---------------------------------------------------------------------------
# Findings-Spalten (sechs neue)
# ---------------------------------------------------------------------------


def test_finding_block_o_columns_exist(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    cols = {col["name"]: col for col in inspector.get_columns("findings")}
    for name in (
        "risk_band",
        "risk_band_reason",
        "risk_band_source",
        "risk_band_computed_at",
        "severity_by_provider",
        "vendor_status",
    ):
        assert name in cols, f"missing column {name}"
        assert cols[name]["nullable"] is True, f"{name} must be nullable"


# ---------------------------------------------------------------------------
# Findings-Indizes
# ---------------------------------------------------------------------------


def test_finding_block_o_indexes_exist(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    index_names = {ix["name"] for ix in inspector.get_indexes("findings")}
    assert "ix_findings_risk_band_open" in index_names
    assert "ix_findings_server_risk_band" in index_names


# ---------------------------------------------------------------------------
# Vier neue Snapshot-Tabellen
# ---------------------------------------------------------------------------


def test_snapshot_tables_exist(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    table_names = set(inspector.get_table_names())
    for name in (
        "server_listeners",
        "server_processes",
        "server_kernel_modules",
        "server_services",
    ):
        assert name in table_names, f"missing snapshot table {name}"


def test_server_listeners_has_port_check_constraint(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    checks = inspector.get_check_constraints("server_listeners")
    names = {c["name"] for c in checks}
    assert "ck_server_listeners_port_range" in names


def test_server_listeners_columns(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    cols = {col["name"]: col for col in inspector.get_columns("server_listeners")}
    for name in ("server_id", "proto", "port", "addr", "process", "pid"):
        assert name in cols, f"missing column {name}"


def test_server_processes_columns(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    cols = {col["name"]: col for col in inspector.get_columns("server_processes")}
    for name in ("server_id", "pid", "user", "comm", "args"):
        assert name in cols, f"missing column {name}"


def test_snapshot_listener_port_index_exists(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    index_names = {ix["name"] for ix in inspector.get_indexes("server_listeners")}
    assert "ix_server_listeners_port" in index_names


def test_snapshot_process_comm_index_exists(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    index_names = {ix["name"] for ix in inspector.get_indexes("server_processes")}
    assert "ix_server_processes_comm" in index_names
