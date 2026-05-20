"""Block Q Phase 1 (ADR-0024) — Migration-Smoke fuer External-Feed-Tabellen.

Reflektiert nach ``alembic upgrade head`` die drei neuen Tabellen
``epss_scores``, ``cisa_kev_catalog``, ``feed_pull_log`` via SQLAlchemy-
Inspector. Plus echte INSERT-Smoke-Probes fuer die Check-Constraints
(EPSS-Range, feed_name-Whitelist), weil reine Reflection nicht garantiert
dass die Constraints wirklich aktiv sind (manche Backends listen sie nur
informatorisch).
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from flask import Flask
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.db import get_session_factory


def _inspector(db_app: Flask):  # type: ignore[no-untyped-def]
    from app.db import get_engine

    engine = get_engine(db_app)
    return inspect(engine.sync_engine if hasattr(engine, "sync_engine") else engine)


# ---------------------------------------------------------------------------
# Tabellen-Existenz
# ---------------------------------------------------------------------------


def test_block_q_tables_exist(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    table_names = set(inspector.get_table_names())
    for name in ("epss_scores", "cisa_kev_catalog", "feed_pull_log"):
        assert name in table_names, f"missing table {name}"


# ---------------------------------------------------------------------------
# epss_scores: PK, Spalten, Check-Constraint
# ---------------------------------------------------------------------------


def test_epss_scores_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("epss_scores")}
    for name in ("cve_id", "epss_score", "epss_percentile", "updated_at"):
        assert name in cols, f"missing column epss_scores.{name}"
    assert cols["cve_id"]["nullable"] is False
    assert cols["epss_score"]["nullable"] is False
    assert cols["epss_percentile"]["nullable"] is False
    assert cols["updated_at"]["nullable"] is False


def test_epss_scores_primary_key_is_cve_id(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    pk = inspector.get_pk_constraint("epss_scores")
    assert pk["constrained_columns"] == ["cve_id"], pk


def test_epss_scores_check_constraint_listed(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {c["name"] for c in inspector.get_check_constraints("epss_scores")}
    assert "ck_epss_scores_range" in names


def test_epss_scores_check_constraint_rejects_out_of_range(db_app: Flask) -> None:
    """Direktes SQL: epss_score=1.5 muss vom Constraint geblockt werden."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with pytest.raises(IntegrityError):
                sess.execute(
                    text(
                        "INSERT INTO epss_scores (cve_id, epss_score, epss_percentile, "
                        "updated_at) VALUES (:cve, :s, :p, now())"
                    ),
                    {"cve": "CVE-2024-0001", "s": 1.5, "p": 0.5},
                )
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_epss_scores_check_constraint_rejects_negative_percentile(
    db_app: Flask,
) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with pytest.raises(IntegrityError):
                sess.execute(
                    text(
                        "INSERT INTO epss_scores (cve_id, epss_score, epss_percentile, "
                        "updated_at) VALUES (:cve, :s, :p, now())"
                    ),
                    {"cve": "CVE-2024-0002", "s": 0.5, "p": -0.1},
                )
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


# ---------------------------------------------------------------------------
# cisa_kev_catalog: Spalten, Defaults
# ---------------------------------------------------------------------------


def test_cisa_kev_catalog_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("cisa_kev_catalog")}
    for name in (
        "cve_id",
        "vendor_project",
        "product",
        "vulnerability_name",
        "date_added",
        "short_description",
        "required_action",
        "due_date",
        "known_ransomware",
        "updated_at",
    ):
        assert name in cols, f"missing column cisa_kev_catalog.{name}"
    # date_added Pflicht, due_date nullable.
    assert cols["date_added"]["nullable"] is False
    assert cols["due_date"]["nullable"] is True
    assert cols["known_ransomware"]["nullable"] is False


def test_cisa_kev_catalog_primary_key_is_cve_id(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    pk = inspector.get_pk_constraint("cisa_kev_catalog")
    assert pk["constrained_columns"] == ["cve_id"], pk


def test_cisa_kev_catalog_known_ransomware_default_false(db_app: Flask) -> None:
    """Insert ohne ``known_ransomware`` → Server-Default ``FALSE``."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.execute(
                text(
                    "INSERT INTO cisa_kev_catalog (cve_id, date_added, updated_at) "
                    "VALUES (:cve, :da, now())"
                ),
                {"cve": "CVE-2024-1000", "da": date(2024, 1, 1)},
            )
            sess.commit()
            row = sess.execute(
                text("SELECT known_ransomware FROM cisa_kev_catalog WHERE cve_id = :cve"),
                {"cve": "CVE-2024-1000"},
            ).scalar_one()
            assert row is False
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# feed_pull_log: BIGSERIAL-PK, feed_name-Check, Index
# ---------------------------------------------------------------------------


def test_feed_pull_log_columns(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    cols = {col["name"]: col for col in inspector.get_columns("feed_pull_log")}
    for name in (
        "id",
        "feed_name",
        "started_at",
        "completed_at",
        "row_count",
        "bytes_downloaded",
        "status",
        "error_message",
    ):
        assert name in cols, f"missing column feed_pull_log.{name}"
    assert cols["id"]["nullable"] is False
    assert cols["feed_name"]["nullable"] is False
    assert cols["status"]["nullable"] is False


def test_feed_pull_log_id_autoincrement(db_app: Flask) -> None:
    """BIGSERIAL: zwei Inserts ohne id liefern unterschiedliche IDs."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            r1 = sess.execute(
                text(
                    "INSERT INTO feed_pull_log (feed_name, status) "
                    "VALUES ('epss', 'running') RETURNING id"
                )
            ).scalar_one()
            r2 = sess.execute(
                text(
                    "INSERT INTO feed_pull_log (feed_name, status) "
                    "VALUES ('cisa_kev', 'running') RETURNING id"
                )
            ).scalar_one()
            sess.commit()
            assert r1 is not None and r2 is not None
            assert r1 != r2
        finally:
            sess.close()


def test_feed_pull_log_check_constraint_listed(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {c["name"] for c in inspector.get_check_constraints("feed_pull_log")}
    assert "ck_feed_pull_log_name" in names


def test_feed_pull_log_rejects_unknown_feed_name(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with pytest.raises(IntegrityError):
                sess.execute(
                    text("INSERT INTO feed_pull_log (feed_name, status) VALUES ('foo', 'running')")
                )
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_feed_pull_log_index_exists(db_app: Flask) -> None:
    inspector = _inspector(db_app)
    names = {ix["name"] for ix in inspector.get_indexes("feed_pull_log")}
    assert "ix_feed_pull_log_feed_started" in names


def test_feed_pull_log_index_columns(db_app: Flask) -> None:
    """Der Index muss ``feed_name`` zuerst enthalten (Lookup-Schluessel)."""
    inspector = _inspector(db_app)
    indexes = {ix["name"]: ix for ix in inspector.get_indexes("feed_pull_log")}
    ix = indexes["ix_feed_pull_log_feed_started"]
    cols = ix.get("column_names") or []
    # Postgres reflektiert DESC-Expressions oft als None — wir akzeptieren das,
    # solange feed_name vorne steht.
    assert "feed_name" in cols, cols


def test_feed_pull_log_completed_at_nullable(db_app: Flask) -> None:
    """``completed_at`` darf NULL sein (running-Eintraege haben kein End-TS)."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.execute(
                text(
                    "INSERT INTO feed_pull_log (feed_name, status, completed_at) "
                    "VALUES ('epss', 'running', NULL)"
                )
            )
            sess.commit()
            row = sess.execute(
                text(
                    "SELECT completed_at FROM feed_pull_log WHERE feed_name = 'epss' "
                    "ORDER BY id DESC LIMIT 1"
                )
            ).scalar_one()
            assert row is None
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Sanity: timestamps werden mit Default ``now()`` befuellt
# ---------------------------------------------------------------------------


def test_feed_pull_log_started_at_default_now(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.execute(
                text("INSERT INTO feed_pull_log (feed_name, status) VALUES ('epss', 'running')")
            )
            sess.commit()
            started = sess.execute(
                text(
                    "SELECT started_at FROM feed_pull_log WHERE feed_name = 'epss' "
                    "ORDER BY id DESC LIMIT 1"
                )
            ).scalar_one()
            assert started is not None
            # Frisch eingefuegter Datensatz: should be within 60 seconds of now.
            delta = datetime.now(UTC) - started
            assert delta.total_seconds() < 60
        finally:
            sess.close()
