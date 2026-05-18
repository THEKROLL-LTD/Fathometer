"""Block N (ADR-0021) — Migration-Smoke: alle sieben neuen Spalten existieren.

Volle Migration-Roundtrip-Tests (upgrade/downgrade/upgrade) sind in der
CI-Pipeline ueber `alembic upgrade head && alembic downgrade -1 &&
alembic upgrade head` abgedeckt; hier nur ein Schema-Smoke gegen die
fertig migrierte DB.

Achtung: `servers.agent_version` existiert schon aus Migration 0002 —
Block N fuegt nur `trivy_version` und `agent_version_seen_at` neu hinzu.
"""

from __future__ import annotations

from flask import Flask
from sqlalchemy import inspect

from app.db import get_engine


def test_server_block_n_columns_exist(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    cols = {col["name"]: col for col in inspector.get_columns("servers")}
    assert "trivy_version" in cols
    assert "agent_version_seen_at" in cols
    # Beide nullable (kein Backfill).
    assert cols["trivy_version"]["nullable"] is True
    assert cols["agent_version_seen_at"]["nullable"] is True


def test_finding_block_n_columns_exist(db_app: Flask) -> None:
    engine = get_engine(db_app)
    inspector = inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)
    cols = {col["name"]: col for col in inspector.get_columns("findings")}
    for name in (
        "package_purl",
        "target_path",
        "result_type",
        "severity_source",
        "vendor_ids",
    ):
        assert name in cols, f"missing column {name}"
        assert cols[name]["nullable"] is True, f"{name} must be nullable"
