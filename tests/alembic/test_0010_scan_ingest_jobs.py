"""Schema-Reflection-Test fuer Migration 0010_scan_ingest_jobs (ADR-0026).

Verifiziert nach ``alembic upgrade head`` via SQLAlchemy-Inspector:
- Alle 15 Spalten vorhanden mit korrekten Typen und Nullability.
- CheckConstraints: status IN (...), attempts >= 0.
- 4 Indizes: Namen, Spalten, Partial-Praedikate.
- ForeignKeys: servers.id ON DELETE CASCADE, scans.id ON DELETE SET NULL.
- Storage-Mode EXTERNAL fuer payload_gzip via pg_attribute.

Marker: db_integration (Postgres-Reflection braucht echte DB).
"""

from __future__ import annotations

import pytest
from flask import Flask
from sqlalchemy import inspect, text


def _inspector(db_app: Flask):  # type: ignore[no-untyped-def]
    from app.db import get_engine

    engine = get_engine(db_app)
    return inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)


def _get_engine(db_app: Flask):  # type: ignore[no-untyped-def]
    from app.db import get_engine

    engine = get_engine(db_app)
    return engine.sync_engine if hasattr(engine, "sync_engine") else engine


# ---------------------------------------------------------------------------
# Tabellen-Existenz
# ---------------------------------------------------------------------------


@pytest.mark.db_integration
def test_scan_ingest_jobs_table_exists(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    assert "scan_ingest_jobs" in inspector.get_table_names()


# ---------------------------------------------------------------------------
# Spalten — Typen und Nullability
# ---------------------------------------------------------------------------


@pytest.mark.db_integration
def test_scan_ingest_jobs_all_columns_present(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"] for col in inspector.get_columns("scan_ingest_jobs")}
    expected = {
        "id",
        "server_id",
        "payload_gzip",
        "payload_sha256",
        "payload_bytes",
        "status",
        "attempts",
        "next_attempt_at",
        "picked_up_by",
        "picked_up_at",
        "result",
        "error",
        "created_at",
        "finished_at",
        "scan_id",
    }
    missing = expected - cols
    assert not missing, f"Fehlende Spalten: {missing}"


@pytest.mark.db_integration
def test_scan_ingest_jobs_not_null_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("scan_ingest_jobs")}
    # NOT NULL-Pflicht-Spalten
    for name in (
        "id",
        "server_id",
        "payload_sha256",
        "payload_bytes",
        "status",
        "attempts",
        "next_attempt_at",
        "created_at",
    ):
        assert cols[name]["nullable"] is False, f"{name} sollte NOT NULL sein"


@pytest.mark.db_integration
def test_scan_ingest_jobs_nullable_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("scan_ingest_jobs")}
    # NULL-erlaubte Spalten
    for name in (
        "payload_gzip",
        "picked_up_by",
        "picked_up_at",
        "result",
        "error",
        "finished_at",
        "scan_id",
    ):
        assert cols[name]["nullable"] is True, f"{name} sollte nullable sein"


@pytest.mark.db_integration
def test_scan_ingest_jobs_primary_key(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    pk = inspector.get_pk_constraint("scan_ingest_jobs")
    assert pk["constrained_columns"] == ["id"], pk


@pytest.mark.db_integration
def test_scan_ingest_jobs_status_column_type(db_app: Flask) -> None:
    """status-Spalte ist VARCHAR(16)."""
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("scan_ingest_jobs")}
    status_col = cols["status"]
    type_str = str(status_col["type"]).upper()
    assert "VARCHAR" in type_str or "CHARACTER VARYING" in type_str, type_str
    assert status_col["nullable"] is False


# ---------------------------------------------------------------------------
# Check-Constraints
# ---------------------------------------------------------------------------


@pytest.mark.db_integration
def test_scan_ingest_jobs_check_constraints_listed(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {c["name"] for c in inspector.get_check_constraints("scan_ingest_jobs")}
    assert "ck_scan_ingest_jobs_status" in names, f"Constraints: {names}"
    assert "ck_scan_ingest_jobs_attempts" in names, f"Constraints: {names}"


@pytest.mark.db_integration
def test_scan_ingest_jobs_status_constraint_rejects_invalid(db_app: Flask) -> None:
    """status='invalid' muss vom Check-Constraint geblockt werden."""
    from sqlalchemy.exc import IntegrityError

    engine = _get_engine(db_app)
    with engine.begin() as conn:
        # Erst einen Server einfuegen (FK-Pflicht)
        conn.execute(
            text(
                "INSERT INTO servers (name, api_key_hash, expected_scan_interval_h) "
                "VALUES ('test-srv-ck-status', 'hash', 24)"
            )
        )
        srv_id = conn.execute(
            text("SELECT id FROM servers WHERE name='test-srv-ck-status'")
        ).scalar_one()
        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    "INSERT INTO scan_ingest_jobs "
                    "(server_id, payload_sha256, payload_bytes, status) "
                    "VALUES (:sid, 'abc123', 100, 'invalid')"
                ),
                {"sid": srv_id},
            )


@pytest.mark.db_integration
def test_scan_ingest_jobs_attempts_constraint_rejects_negative(db_app: Flask) -> None:
    """attempts=-1 muss vom Check-Constraint geblockt werden."""
    from sqlalchemy.exc import IntegrityError

    engine = _get_engine(db_app)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO servers (name, api_key_hash, expected_scan_interval_h) "
                "VALUES ('test-srv-ck-attempts', 'hash', 24)"
            )
        )
        srv_id = conn.execute(
            text("SELECT id FROM servers WHERE name='test-srv-ck-attempts'")
        ).scalar_one()
        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    "INSERT INTO scan_ingest_jobs "
                    "(server_id, payload_sha256, payload_bytes, status, attempts) "
                    "VALUES (:sid, 'abc456', 100, 'queued', -1)"
                ),
                {"sid": srv_id},
            )


# ---------------------------------------------------------------------------
# Indizes
# ---------------------------------------------------------------------------


@pytest.mark.db_integration
def test_scan_ingest_jobs_index_names(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {ix["name"] for ix in inspector.get_indexes("scan_ingest_jobs")}
    for expected in (
        "ix_scan_ingest_jobs_pickup",
        "ix_scan_ingest_jobs_stale",
        "ix_scan_ingest_jobs_server",
        "ux_scan_ingest_jobs_payload_sha256",
    ):
        assert expected in names, f"Index '{expected}' fehlt. Vorhandene: {names}"


@pytest.mark.db_integration
def test_scan_ingest_jobs_pickup_index_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    indexes = {ix["name"]: ix for ix in inspector.get_indexes("scan_ingest_jobs")}
    ix = indexes["ix_scan_ingest_jobs_pickup"]
    cols = [c for c in (ix.get("column_names") or []) if c]
    assert "next_attempt_at" in cols, f"Pickup-Index-Spalten: {cols}"
    assert "created_at" in cols, f"Pickup-Index-Spalten: {cols}"


@pytest.mark.db_integration
def test_scan_ingest_jobs_stale_index_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    indexes = {ix["name"]: ix for ix in inspector.get_indexes("scan_ingest_jobs")}
    ix = indexes["ix_scan_ingest_jobs_stale"]
    cols = [c for c in (ix.get("column_names") or []) if c]
    assert "picked_up_at" in cols, f"Stale-Index-Spalten: {cols}"


@pytest.mark.db_integration
def test_scan_ingest_jobs_server_index_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    indexes = {ix["name"]: ix for ix in inspector.get_indexes("scan_ingest_jobs")}
    ix = indexes["ix_scan_ingest_jobs_server"]
    cols = ix.get("column_names") or []
    assert "server_id" in cols, f"Server-Index-Spalten: {cols}"
    assert "status" in cols, f"Server-Index-Spalten: {cols}"


@pytest.mark.db_integration
def test_scan_ingest_jobs_payload_sha256_unique_index(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    indexes = {ix["name"]: ix for ix in inspector.get_indexes("scan_ingest_jobs")}
    ix = indexes["ux_scan_ingest_jobs_payload_sha256"]
    assert ix.get("unique") is True, "ux_scan_ingest_jobs_payload_sha256 muss UNIQUE sein"
    cols = ix.get("column_names") or []
    assert "payload_sha256" in cols, f"Unique-Index-Spalten: {cols}"


@pytest.mark.db_integration
def test_scan_ingest_jobs_partial_indexes_have_where(db_app: Flask) -> None:
    """Partial-Indizes muessen ein postgresql_where-Praedikat haben."""
    inspector = _inspector(db_app)
    indexes = {ix["name"]: ix for ix in inspector.get_indexes("scan_ingest_jobs")}

    for ix_name in (
        "ix_scan_ingest_jobs_pickup",
        "ix_scan_ingest_jobs_stale",
        "ux_scan_ingest_jobs_payload_sha256",
    ):
        ix = indexes[ix_name]
        # Postgres-Dialekt liefert das Praedikat in dialect_options oder
        # direkt als 'postgresql_where'. Wir akzeptieren beide Positionen.
        dialect_opts = ix.get("dialect_options", {})
        where = dialect_opts.get("postgresql_where") or ix.get("postgresql_where")
        assert where is not None, (
            f"Index '{ix_name}' hat kein postgresql_where-Praedikat. ix-Dict: {ix}"
        )


# ---------------------------------------------------------------------------
# Foreign Keys
# ---------------------------------------------------------------------------


@pytest.mark.db_integration
def test_scan_ingest_jobs_fk_servers(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    fks = inspector.get_foreign_keys("scan_ingest_jobs")
    server_fks = [fk for fk in fks if fk.get("referred_table") == "servers"]
    assert server_fks, "FK auf servers fehlt"
    fk = server_fks[0]
    assert fk.get("options", {}).get("ondelete", "").upper() == "CASCADE", (
        f"FK auf servers sollte ON DELETE CASCADE sein. Options: {fk.get('options')}"
    )
    assert "server_id" in fk.get("constrained_columns", [])


@pytest.mark.db_integration
def test_scan_ingest_jobs_fk_scans(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    fks = inspector.get_foreign_keys("scan_ingest_jobs")
    scan_fks = [fk for fk in fks if fk.get("referred_table") == "scans"]
    assert scan_fks, "FK auf scans fehlt"
    fk = scan_fks[0]
    assert fk.get("options", {}).get("ondelete", "").upper() == "SET NULL", (
        f"FK auf scans sollte ON DELETE SET NULL sein. Options: {fk.get('options')}"
    )
    assert "scan_id" in fk.get("constrained_columns", [])


# ---------------------------------------------------------------------------
# Storage-Mode EXTERNAL fuer payload_gzip (pg_attribute)
# ---------------------------------------------------------------------------


@pytest.mark.db_integration
def test_scan_ingest_jobs_payload_gzip_storage_external(db_app: Flask) -> None:
    """payload_gzip muss STORAGE EXTERNAL haben (attstorage = 'e').

    'e' = EXTERNAL (out-of-line, keine Toast-Kompression).
    Relevant weil der Body bereits gzip-komprimiert ist — erneute Kompression
    waere CPU-Verschwendung (ADR-0026 §Begruendung, §Bedrohungsmodell).
    """
    engine = _get_engine(db_app)
    with engine.connect() as conn:
        result = conn.execute(
            text(
                "SELECT attstorage FROM pg_attribute "
                "WHERE attrelid = 'scan_ingest_jobs'::regclass "
                "AND attname = 'payload_gzip'"
            )
        ).scalar_one_or_none()

    assert result is not None, "pg_attribute-Eintrag fuer payload_gzip nicht gefunden"
    assert result == "e", (
        f"payload_gzip sollte STORAGE EXTERNAL (attstorage='e') haben, "
        f"ist aber '{result}'. "
        "'p'=plain, 'm'=main, 'x'=extended (default BYTEA), 'e'=external."
    )


# ---------------------------------------------------------------------------
# Defaults und Roundtrip-Smoke
# ---------------------------------------------------------------------------


@pytest.mark.db_integration
def test_scan_ingest_jobs_insert_defaults(db_app: Flask) -> None:
    """Insert ohne status/attempts/next_attempt_at → Server-Defaults greifen."""
    engine = _get_engine(db_app)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO servers (name, api_key_hash, expected_scan_interval_h) "
                "VALUES ('test-srv-defaults', 'hash', 24)"
            )
        )
        srv_id = conn.execute(
            text("SELECT id FROM servers WHERE name='test-srv-defaults'")
        ).scalar_one()
        job_id = conn.execute(
            text(
                "INSERT INTO scan_ingest_jobs (server_id, payload_sha256, payload_bytes) "
                "VALUES (:sid, :sha, :pb) RETURNING id"
            ),
            {"sid": srv_id, "sha": "a" * 64, "pb": 1024},
        ).scalar_one()
        row = (
            conn.execute(
                text(
                    "SELECT status, attempts, next_attempt_at, created_at "
                    "FROM scan_ingest_jobs WHERE id = :jid"
                ),
                {"jid": job_id},
            )
            .mappings()
            .one()
        )

    assert row["status"] == "queued", f"Default-Status: {row['status']}"
    assert row["attempts"] == 0, f"Default-attempts: {row['attempts']}"
    assert row["next_attempt_at"] is not None
    assert row["created_at"] is not None


@pytest.mark.db_integration
def test_scan_ingest_jobs_partial_unique_allows_same_hash_after_done(db_app: Flask) -> None:
    """Derselbe payload_sha256 darf zweimal inseriert werden wenn der erste 'done' ist."""
    sha = "b" * 64
    engine = _get_engine(db_app)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO servers (name, api_key_hash, expected_scan_interval_h) "
                "VALUES ('test-srv-reupload', 'hash', 24)"
            )
        )
        srv_id = conn.execute(
            text("SELECT id FROM servers WHERE name='test-srv-reupload'")
        ).scalar_one()
        # Ersten Job einfuegen und auf 'done' setzen
        job1_id = conn.execute(
            text(
                "INSERT INTO scan_ingest_jobs (server_id, payload_sha256, payload_bytes) "
                "VALUES (:sid, :sha, 512) RETURNING id"
            ),
            {"sid": srv_id, "sha": sha},
        ).scalar_one()
        conn.execute(
            text("UPDATE scan_ingest_jobs SET status='done' WHERE id = :jid"),
            {"jid": job1_id},
        )
        # Zweiten Job mit gleichem Hash einfuegen — Partial-Unique greift nicht
        # (done-Status liegt ausserhalb des Index-Praedikats).
        job2_id = conn.execute(
            text(
                "INSERT INTO scan_ingest_jobs (server_id, payload_sha256, payload_bytes) "
                "VALUES (:sid, :sha, 512) RETURNING id"
            ),
            {"sid": srv_id, "sha": sha},
        ).scalar_one()

    assert job2_id != job1_id, "Zweiter Insert sollte eine neue ID vergeben"


@pytest.mark.db_integration
def test_scan_ingest_jobs_partial_unique_blocks_duplicate_queued(db_app: Flask) -> None:
    """Derselbe payload_sha256 darf NICHT zweimal im Status 'queued' existieren."""
    from sqlalchemy.exc import IntegrityError

    sha = "c" * 64
    engine = _get_engine(db_app)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO servers (name, api_key_hash, expected_scan_interval_h) "
                "VALUES ('test-srv-idem', 'hash', 24)"
            )
        )
        srv_id = conn.execute(
            text("SELECT id FROM servers WHERE name='test-srv-idem'")
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO scan_ingest_jobs (server_id, payload_sha256, payload_bytes) "
                "VALUES (:sid, :sha, 256)"
            ),
            {"sid": srv_id, "sha": sha},
        )
        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    "INSERT INTO scan_ingest_jobs (server_id, payload_sha256, payload_bytes) "
                    "VALUES (:sid, :sha, 256)"
                ),
                {"sid": srv_id, "sha": sha},
            )
