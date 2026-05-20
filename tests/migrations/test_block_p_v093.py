"""Block P v0.9.3 (ADR-0023 §"Update v0.9.3") — Migration-Roundtrip + Backfill.

Drei Testklassen:

* :class:`TestSchemaAfterMigration` — Inspektion gegen die bereits migrierte
  `db_app`-DB (head). Schnell, kein Roundtrip.
* :class:`TestRoundtrip0006To0007` — direkter Roundtrip via `alembic command`
  gegen die Test-DB (`postgres_url`). Verifiziert dass downgrade alles
  wieder entfernt und re-upgrade idempotent ist.
* :class:`TestGroupKindBackfill` — schreibt zwei Rows in 0006 und prueft
  dass 0007 sie deterministisch backfillet.
* :class:`TestDebugLogFkSetNull` — FK-ON-DELETE-SET-NULL fuer alle drei FKs
  von `llm_debug_log`.
"""

from __future__ import annotations

import contextlib
import warnings
from collections.abc import Iterator
from typing import Any

import pytest
from alembic.config import Config
from flask import Flask
from sqlalchemy import create_engine, inspect, text

from alembic import command
from app.db import get_engine


def _inspector_for(db_app: Flask) -> Any:
    engine = get_engine(db_app)
    return inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)


# ---------------------------------------------------------------------------
# Schema-Smoke gegen head
# ---------------------------------------------------------------------------


class TestSchemaAfterMigration:
    def test_application_groups_action_type_column(self, db_app: Flask) -> None:
        cols = {c["name"]: c for c in _inspector_for(db_app).get_columns("application_groups")}
        assert "action_type" in cols
        assert cols["action_type"]["nullable"] is True

    def test_application_groups_group_kind_column(self, db_app: Flask) -> None:
        cols = {c["name"]: c for c in _inspector_for(db_app).get_columns("application_groups")}
        assert "group_kind" in cols
        assert cols["group_kind"]["nullable"] is True

    def test_application_groups_v093_check_constraints(self, db_app: Flask) -> None:
        checks = _inspector_for(db_app).get_check_constraints("application_groups")
        names = {c["name"] for c in checks}
        assert "ck_application_groups_action_type" in names
        assert "ck_application_groups_group_kind" in names

    def test_llm_risk_cache_action_type_column(self, db_app: Flask) -> None:
        cols = {c["name"]: c for c in _inspector_for(db_app).get_columns("llm_risk_cache")}
        assert "action_type" in cols
        assert cols["action_type"]["nullable"] is True

    def test_llm_risk_cache_v093_check_constraint(self, db_app: Flask) -> None:
        checks = _inspector_for(db_app).get_check_constraints("llm_risk_cache")
        names = {c["name"] for c in checks}
        assert "ck_llm_risk_cache_action_type" in names

    def test_llm_debug_log_table_exists(self, db_app: Flask) -> None:
        assert "llm_debug_log" in _inspector_for(db_app).get_table_names()

    def test_llm_debug_log_columns(self, db_app: Flask) -> None:
        cols = {c["name"] for c in _inspector_for(db_app).get_columns("llm_debug_log")}
        expected = {
            "id",
            "job_type",
            "job_id",
            "server_id",
            "group_id",
            "model",
            "request_body",
            "response_body",
            "duration_ms",
            "status",
            "error",
            "created_at",
        }
        assert expected <= cols

    def test_llm_debug_log_indexes(self, db_app: Flask) -> None:
        names = {ix["name"] for ix in _inspector_for(db_app).get_indexes("llm_debug_log")}
        assert "ix_llm_debug_log_created" in names
        assert "ix_llm_debug_log_job_type" in names
        assert "ix_llm_debug_log_group" in names

    def test_llm_debug_log_status_constraint(self, db_app: Flask) -> None:
        checks = _inspector_for(db_app).get_check_constraints("llm_debug_log")
        names = {c["name"] for c in checks}
        assert "ck_llm_debug_log_status" in names

    def test_llm_debug_log_fks_all_set_null(self, db_app: Flask) -> None:
        fks = _inspector_for(db_app).get_foreign_keys("llm_debug_log")
        cols_to_check = {"job_id", "server_id", "group_id"}
        seen = set()
        for fk in fks:
            cc = fk.get("constrained_columns") or []
            if not cc:
                continue
            col = cc[0]
            if col in cols_to_check:
                opts = fk.get("options") or {}
                assert opts.get("ondelete", "").upper() == "SET NULL", (
                    f"FK on llm_debug_log.{col} ist nicht ON DELETE SET NULL"
                )
                seen.add(col)
        assert seen == cols_to_check, f"FK fehlt fuer Spalten: {cols_to_check - seen}"


# ---------------------------------------------------------------------------
# Roundtrip 0006 → 0007 → 0006 → 0007
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_db_at_0006(postgres_url: str) -> Iterator[str]:
    """Setzt die Test-DB hart auf base und upgradet exakt bis 0006.

    Cleanup: nach dem Test wieder auf head — damit die Suite weiterlaufen
    kann und nachfolgende ``db_app``-Tests konsistent sind.
    """
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with contextlib.suppress(Exception):
            command.downgrade(cfg, "base")
        command.upgrade(cfg, "0006")
    try:
        yield postgres_url
    finally:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with contextlib.suppress(Exception):
                command.downgrade(cfg, "base")
            command.upgrade(cfg, "head")


class TestRoundtrip0006To0007:
    def test_upgrade_creates_new_artifacts(self, fresh_db_at_0006: str) -> None:
        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", fresh_db_at_0006)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            command.upgrade(cfg, "0007")
        eng = create_engine(fresh_db_at_0006, future=True)
        try:
            insp = inspect(eng)
            assert "llm_debug_log" in insp.get_table_names()
            app_grp_cols = {c["name"] for c in insp.get_columns("application_groups")}
            assert "action_type" in app_grp_cols
            assert "group_kind" in app_grp_cols
            cache_cols = {c["name"] for c in insp.get_columns("llm_risk_cache")}
            assert "action_type" in cache_cols
        finally:
            eng.dispose()

    def test_downgrade_removes_artifacts(self, fresh_db_at_0006: str) -> None:
        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", fresh_db_at_0006)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            command.upgrade(cfg, "0007")
            command.downgrade(cfg, "0006")
        eng = create_engine(fresh_db_at_0006, future=True)
        try:
            insp = inspect(eng)
            assert "llm_debug_log" not in insp.get_table_names()
            app_grp_cols = {c["name"] for c in insp.get_columns("application_groups")}
            assert "action_type" not in app_grp_cols
            assert "group_kind" not in app_grp_cols
            cache_cols = {c["name"] for c in insp.get_columns("llm_risk_cache")}
            assert "action_type" not in cache_cols
        finally:
            eng.dispose()

    def test_upgrade_downgrade_upgrade_idempotent(self, fresh_db_at_0006: str) -> None:
        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", fresh_db_at_0006)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            command.upgrade(cfg, "0007")
            command.downgrade(cfg, "0006")
            command.upgrade(cfg, "0007")
        eng = create_engine(fresh_db_at_0006, future=True)
        try:
            insp = inspect(eng)
            assert "llm_debug_log" in insp.get_table_names()
        finally:
            eng.dispose()


# ---------------------------------------------------------------------------
# Backfill von group_kind
# ---------------------------------------------------------------------------


class TestGroupKindBackfill:
    def test_application_bundle_when_path_prefixes_nonempty(self, fresh_db_at_0006: str) -> None:
        """Group mit path_prefixes → group_kind='application_bundle'."""
        eng = create_engine(fresh_db_at_0006, future=True)
        try:
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO application_groups (label, path_prefixes, pkg_name_exact, "
                        "pkg_name_glob, pkg_purl_pattern, source) VALUES "
                        "('k3s-test', ARRAY[:p]::text[], ARRAY[]::varchar[], "
                        "ARRAY[]::varchar[], ARRAY[]::varchar[], 'llm')"
                    ),
                    {"p": "/var/lib/rancher/k3s/"},
                )
            cfg = Config("alembic.ini")
            cfg.set_main_option("sqlalchemy.url", fresh_db_at_0006)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                command.upgrade(cfg, "0007")
            with eng.begin() as conn:
                kind = conn.execute(
                    text("SELECT group_kind FROM application_groups WHERE label = 'k3s-test'")
                ).scalar_one()
            assert kind == "application_bundle"
        finally:
            eng.dispose()

    def test_os_package_when_no_path_prefixes(self, fresh_db_at_0006: str) -> None:
        """Group ohne path_prefixes → group_kind='os_package'."""
        eng = create_engine(fresh_db_at_0006, future=True)
        try:
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO application_groups (label, path_prefixes, pkg_name_exact, "
                        "pkg_name_glob, pkg_purl_pattern, source) VALUES "
                        "('openssl-test', ARRAY[]::text[], ARRAY[:p]::varchar[], "
                        "ARRAY[]::varchar[], ARRAY[]::varchar[], 'llm')"
                    ),
                    {"p": "openssl"},
                )
            cfg = Config("alembic.ini")
            cfg.set_main_option("sqlalchemy.url", fresh_db_at_0006)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                command.upgrade(cfg, "0007")
            with eng.begin() as conn:
                kind = conn.execute(
                    text("SELECT group_kind FROM application_groups WHERE label = 'openssl-test'")
                ).scalar_one()
            assert kind == "os_package"
        finally:
            eng.dispose()

    def test_backfill_both_kinds_in_one_batch(self, fresh_db_at_0006: str) -> None:
        """Sanity: zwei Rows in einer Migration, jeder bekommt seinen Wert."""
        eng = create_engine(fresh_db_at_0006, future=True)
        try:
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO application_groups (label, path_prefixes, pkg_name_exact, "
                        "pkg_name_glob, pkg_purl_pattern, source) VALUES "
                        "('bundle-x', ARRAY[:p1]::text[], ARRAY[]::varchar[], "
                        "ARRAY[]::varchar[], ARRAY[]::varchar[], 'llm'), "
                        "('pkg-y', ARRAY[]::text[], ARRAY[:p2]::varchar[], "
                        "ARRAY[]::varchar[], ARRAY[]::varchar[], 'llm')"
                    ),
                    {"p1": "/opt/bundle-x/", "p2": "pkg-y"},
                )
            cfg = Config("alembic.ini")
            cfg.set_main_option("sqlalchemy.url", fresh_db_at_0006)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                command.upgrade(cfg, "0007")
            with eng.begin() as conn:
                rows = dict(
                    conn.execute(
                        text(
                            "SELECT label, group_kind FROM application_groups "
                            "WHERE label IN ('bundle-x', 'pkg-y')"
                        )
                    ).all()
                )
            assert rows == {"bundle-x": "application_bundle", "pkg-y": "os_package"}
        finally:
            eng.dispose()


# ---------------------------------------------------------------------------
# FK-ON-DELETE-SET-NULL fuer llm_debug_log
# ---------------------------------------------------------------------------


class TestDebugLogFkSetNull:
    """Loescht referenzierte Entitaeten und prueft dass der Log-Eintrag mit
    NULL-FKs ueberlebt."""

    def _setup_row(self, db_app: Flask) -> tuple[int, int, int, int]:
        """Erstellt einen Job, einen Server, eine Group und einen Debug-Log-
        Eintrag, der alle drei referenziert. Liefert die IDs zurueck."""
        engine = get_engine(db_app)
        sync_engine = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        with sync_engine.begin() as conn:
            server_id = conn.execute(
                text(
                    "INSERT INTO servers (name, api_key_hash, expected_scan_interval_h) "
                    "VALUES ('srv-fk-test', :h, 24) RETURNING id"
                ),
                {"h": "x" * 64},
            ).scalar_one()
            group_id = conn.execute(
                text(
                    "INSERT INTO application_groups (label, path_prefixes, pkg_name_exact, "
                    "pkg_name_glob, pkg_purl_pattern, source) VALUES "
                    "('fk-test-grp', ARRAY[]::text[], ARRAY[]::varchar[], "
                    "ARRAY[]::varchar[], ARRAY[]::varchar[], 'llm') RETURNING id"
                )
            ).scalar_one()
            job_id = conn.execute(
                text(
                    "INSERT INTO llm_jobs (job_type, server_id, payload, status, attempts) "
                    "VALUES ('group_detection', :sid, '{}'::jsonb, 'queued', 0) RETURNING id"
                ),
                {"sid": server_id},
            ).scalar_one()
            log_id = conn.execute(
                text(
                    "INSERT INTO llm_debug_log (job_type, job_id, server_id, group_id, "
                    "model, request_body, response_body, duration_ms, status) VALUES "
                    "('group_detection', :jid, :sid, :gid, 'mock', '{}'::jsonb, "
                    "'{}'::jsonb, 0, 'success') RETURNING id"
                ),
                {"jid": job_id, "sid": server_id, "gid": group_id},
            ).scalar_one()
        return int(log_id), int(job_id), int(server_id), int(group_id)

    def test_delete_job_sets_job_id_null(self, db_app: Flask) -> None:
        log_id, job_id, _sid, _gid = self._setup_row(db_app)
        engine = get_engine(db_app)
        sync_engine = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        with sync_engine.begin() as conn:
            conn.execute(text("DELETE FROM llm_jobs WHERE id = :jid"), {"jid": job_id})
        with sync_engine.begin() as conn:
            row = conn.execute(
                text("SELECT job_id, server_id, group_id FROM llm_debug_log WHERE id = :lid"),
                {"lid": log_id},
            ).one()
        assert row.job_id is None
        # Andere FKs bleiben unangetastet.
        assert row.server_id is not None
        assert row.group_id is not None

    def test_delete_group_sets_group_id_null(self, db_app: Flask) -> None:
        log_id, _jid, _sid, gid = self._setup_row(db_app)
        engine = get_engine(db_app)
        sync_engine = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        with sync_engine.begin() as conn:
            conn.execute(text("DELETE FROM application_groups WHERE id = :gid"), {"gid": gid})
        with sync_engine.begin() as conn:
            row = conn.execute(
                text("SELECT job_id, server_id, group_id FROM llm_debug_log WHERE id = :lid"),
                {"lid": log_id},
            ).one()
        assert row.group_id is None

    def test_delete_server_sets_server_id_null(self, db_app: Flask) -> None:
        log_id, _jid, sid, _gid = self._setup_row(db_app)
        engine = get_engine(db_app)
        sync_engine = engine.sync_engine if hasattr(engine, "sync_engine") else engine
        # Server-Loeschung kaskadiert via FKs auf llm_jobs → ebenfalls
        # `ON DELETE SET NULL` (Block-P-Migration). Pruefen.
        with sync_engine.begin() as conn:
            conn.execute(text("DELETE FROM servers WHERE id = :sid"), {"sid": sid})
        with sync_engine.begin() as conn:
            row = conn.execute(
                text("SELECT server_id FROM llm_debug_log WHERE id = :lid"),
                {"lid": log_id},
            ).one()
        assert row.server_id is None
