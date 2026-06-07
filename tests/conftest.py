"""Globale pytest-Fixtures.

Block A: minimale App-Fixtures ohne DB.
Block B: zusaetzliche DB-Fixtures, die einen echten Postgres erwarten.

DB-Strategie:
- Tests, die nur App-Wiring testen (Block A), bleiben DB-frei (`app_env`,
  `app`, `client`-Fixtures).
- Tests, die echte ORM-Operationen brauchen, nutzen die `db_*`-Fixtures:
  - `postgres_url` (session-scope): URL aus `TEST_DATABASE_URL` oder
    Default `postgresql+psycopg://fathometer:fathometer@localhost:55432/fathometer_test`.
    Wenn nicht erreichbar -> `pytest.skip(...)`.
  - `migrated_db` (session-scope): laesst `alembic upgrade head` einmal pro
    Suite laufen und droppt am Ende.
  - `db_app` (function-scope): `create_app()` gegen die migrierte DB.
  - `db_client`: Flask-Testclient gegen `db_app`.
  - `db_session`: SAVEPOINT-basierte ORM-Session, die nach jedem Test komplett
    zurueckgerollt wird, damit Tests sich nicht gegenseitig sehen.

Argon2-Cost-Werte werden in DB-Fixtures bewusst auf das Minimum reduziert
(time=1, memory=8 KiB, parallelism=1) — Tests laufen sonst pro Login viele
Sekunden.
"""

from __future__ import annotations

import contextlib
import os
import socket
from collections.abc import Generator, Iterator
from typing import Any
from urllib.parse import urlparse

import pytest
from flask import Flask
from flask.testing import FlaskClient

# ---------------------------------------------------------------------------
# Auto-Marker (feedback_tests_unit_only)
# ---------------------------------------------------------------------------
#
# Default pytest invocation (`pytest`) laeuft nur Unit-Tests, alles mit
# echter DB / Live-Service bleibt aussen vor (Acceptance-Suite). Marker
# werden pfadbasiert vergeben in ``pytest_collection_modifyitems``:
#
# - ``acceptance``: Tests die echte Postgres-Migration, ORM-Round-Trips,
#   Postgres-spezifische Constraints, oder Live-LLM-Integration brauchen.
#   Standard-Pytest schliesst sie aus (siehe ``pytest.ini`` ``addopts``).
#   Run via ``pytest -m acceptance`` bei RC-Vorbereitung.
#
# - ``db_integration``: Acceptance-Tests, die als echte DB-/Integrationssuite
#   erhalten bleiben sollen statt in Mock-Unit-Tests migriert zu werden.
#   Run-Liste sehen via ``pytest -m db_integration --collect-only -q``.
#
# - ``todo_mock``: Tests die heute noch echte DB benutzen, aber langfristig
#   zu Mocks refactored werden sollen (LOW/MED/HIGH-Kategorisierung in
#   ADR-Anhang). Bleiben aktiv, sind nur zum Wiederfinden markiert.
#   Run-Liste sehen via ``pytest -m todo_mock --collect-only -q``.
#
# Files die in keine der zwei Kategorien fallen sind reine Unit-Tests
# (kein DB-Fixture noetig) und laufen ohne Marker.

# Files die als Acceptance gelten — hauptsaechlich Migration-Schema-Tests,
# ORM-Round-Trip-Tests mit Postgres-spezifischen Constraints und Live-E2E.
_ACCEPTANCE_PATH_PREFIXES: tuple[str, ...] = (
    "tests/alembic/",
    "tests/migrations/",
    "tests/models/",
    "tests/integration/test_about_view_db",
    "tests/integration/test_agent_install_db",
    "tests/integration/test_agent_install_render_db",
    "tests/integration/test_agent_install_smoke_db",
    "tests/integration/test_application_group_cards_db",
    "tests/integration/test_audit_db",
    "tests/integration/test_block_p_e2e_live",
    "tests/integration/test_block_p_e2e_observation",
    "tests/integration/test_block_p_mode_switch",
    "tests/integration/test_bulk_acknowledge_db",
    "tests/integration/test_csv_export_cross_db",
    "tests/integration/test_csv_export_db",
    "tests/integration/test_dashboard_db",
    "tests/integration/test_dashboard_group_filter_db",
    "tests/integration/test_dashboard_pane_consistency_db",
    "tests/integration/test_dashboard_polling_db",
    "tests/integration/test_dashboard_risk_kpis_db",
    "tests/integration/test_error_classification_db",
    "tests/integration/test_feed_enrichment_db",
    "tests/integration/test_findings_actions_db",
    "tests/integration/test_findings_filter_risk_band_db",
    "tests/integration/test_findings_index_db",
    "tests/integration/test_findings_query_cross_db",
    "tests/integration/test_findings_query_db",
    "tests/integration/test_findings_section_cause_row_db",
    "tests/integration/test_header_navigation_db",
    "tests/integration/test_healthcheck_db",
    "tests/integration/test_heartbeat_aggregation_db",
    "tests/integration/test_keys_rotate_db",
    "tests/integration/test_llm_cache_db",
    "tests/integration/test_llm_debug_log_db",
    "tests/integration/test_llm_settings_view_db",
    "tests/integration/test_llm_worker_db",
    "tests/integration/test_master_key_rotation_db",
    "tests/integration/test_register_db",
    "tests/integration/test_scans_envelope_trivy_version_db",
    "tests/integration/test_scans_host_state_db",
    "tests/integration/test_search_keyboard_shortcut_db",
    "tests/integration/test_server_detail_action_required_db",
    "tests/integration/test_server_detail_action_section_db",
    "tests/integration/test_server_detail_db",
    "tests/integration/test_server_detail_groups_db",
    "tests/integration/test_server_detail_lazy_groups_db",
    "tests/integration/test_server_detail_outdated_pills_db",
    "tests/integration/test_server_detail_pending_lazy_db",
    "tests/integration/test_server_detail_redesign_db",
    "tests/integration/test_server_detail_status_pills_db",
    "tests/integration/test_servers_db",
    "tests/integration/test_settings_alias_redirect_db",
    "tests/integration/test_settings_dropdown_swap_db",
    "tests/integration/test_settings_llm_reviewer_db",
    "tests/integration/test_settings_servers_active_pill_db",
    "tests/integration/test_severity_history_db",
    "tests/integration/test_sidebar_layout_db",
    "tests/integration/test_sidebar_outdated_marker_db",
    "tests/integration/test_sidebar_partial_db",
    "tests/integration/test_stale_history_db",
    "tests/integration/test_token_budget_db",
    # Block R — Async-Ingest Edge-Handler-Tests (echte Postgres-Semantik
    # fuer on_conflict_do_nothing Partial-Index-Match).
    "tests/api/test_scans_async_edge.py",
    # Block R — Payload-Lifecycle (atomares Clear, Stale-Reaper, Retention).
    "tests/workers/test_scan_ingest_payload_lifecycle.py",
    # Block R — End-to-End-Smoke (Edge-POST + Worker + Status-Endpoint).
    "tests/workers/test_scan_ingest_e2e_flow.py",
)

# Files die in der LOW-Kategorie sind und schon zu Mocks refactored wurden.
# Diese werden NICHT mit todo_mock markiert. Wird erweitert wenn weitere
# LOW-Files migriert sind.
_MOCKED_UNIT_FILES: frozenset[str] = frozenset(
    {
        # Liste wird im Zuge der LOW-Migration erweitert.
        "tests/audit/test_log_event.py",
        "tests/services/test_diff_view.py",
        "tests/services/test_feed_backfill.py",
        "tests/services/test_feed_status.py",
        "tests/services/test_findings_ingest.py",
        "tests/services/test_findings_ingest_cause_mapping.py",
        "tests/services/test_findings_ingest_feed_enrichment.py",
        "tests/services/test_findings_ingest_vendor_status.py",
        "tests/services/test_kev_events.py",
        "tests/services/test_stale_detection.py",
        "tests/services/test_csv_export.py",
        "tests/services/test_feed_enrichment.py",
        "tests/services/test_llm_debug_log.py",
        "tests/services/test_heartbeat_aggregation.py",
        "tests/services/test_severity_history.py",
        "tests/services/test_tendency_from_counts.py",
        "tests/views/test_server_detail.py",
        "tests/views/test_dashboard_phase_d.py",
        "tests/services/test_stale_history.py",
        "tests/workers/test_error_classification.py",
        "tests/workers/test_healthcheck.py",
        "tests/workers/test_llm_worker.py",
        "tests/workers/test_token_budget.py",
    }
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-Marker pro Test-Pfad."""
    for item in items:
        rel_path = str(item.fspath).rsplit("fathometer/", 1)[-1]

        if any(rel_path.startswith(p) for p in _ACCEPTANCE_PATH_PREFIXES):
            item.add_marker(pytest.mark.acceptance)
            item.add_marker(pytest.mark.db_integration)
            continue

        if rel_path in _MOCKED_UNIT_FILES:
            continue

        # Verbleibende Tests die DB-Fixtures nutzen: todo_mock-Marker.
        # Heuristik: wenn das Test-File irgendwo "db_app" oder "migrated_db"
        # importiert/nutzt, ist es ein DB-abhaengiger Test der refactored
        # werden muss.
        try:
            src = item.fspath.read_text(encoding="utf-8")
        except OSError:
            continue
        if "db_app" in src or "migrated_db" in src or "postgres_url" in src:
            item.add_marker(pytest.mark.todo_mock)


# ---------------------------------------------------------------------------
# Block-A-Fixtures (DB-frei).
# ---------------------------------------------------------------------------


@pytest.fixture
def app_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Setzt die minimal noetigen Env-Vars fuer `create_app()`."""
    monkeypatch.setenv("FM_ENCRYPTION_KEY", "x" * 32)
    monkeypatch.setenv("FM_SECRET_KEY", "test-secret-key-not-used-in-prod")
    monkeypatch.setenv(
        "FM_DATABASE_URL",
        # Bewusst nicht erreichbar — Healthz darf scheitern, andere Tests
        # rufen die DB nicht direkt auf.
        "postgresql+psycopg://test:test@127.0.0.1:1/test",
    )
    monkeypatch.setenv("FM_LOG_LEVEL", "WARNING")
    yield


@pytest.fixture
def app(app_env: None) -> Flask:
    """Erzeugt eine Test-App-Instanz pro Test."""
    # Lazy-Import damit Env-Setup vor `load_settings()` laeuft.
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Flask-Testclient fuer HTTP-Smoke-Tests."""
    return app.test_client()


@pytest.fixture(autouse=True)
def _clean_environment() -> Iterator[None]:
    """Stellt sicher, dass keine Test-Vars in nachfolgende Tests bluten."""
    snapshot = dict(os.environ)
    yield
    for key in list(os.environ.keys()):
        if key not in snapshot:
            del os.environ[key]
    for key, value in snapshot.items():
        os.environ[key] = value


# ---------------------------------------------------------------------------
# Block-B-Fixtures (echte Postgres-DB).
# ---------------------------------------------------------------------------

DEFAULT_TEST_DB_URL = "postgresql+psycopg://fathometer:fathometer@localhost:55432/fathometer_test"


def _is_postgres_reachable(url: str) -> bool:
    """Prueft Port-Erreichbarkeit (ohne sich um Auth zu kuemmern)."""
    parsed = urlparse(url.replace("postgresql+psycopg://", "postgresql://"))
    host = parsed.hostname or "localhost"
    port = parsed.port or 5432
    try:
        with socket.create_connection((host, port), timeout=2.0):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def postgres_url() -> str:
    """Liefert die Test-DB-URL oder skipt die gesamte DB-Suite.

    Reihenfolge:
    1. `TEST_DATABASE_URL` aus dem Environment.
    2. Default `postgresql+psycopg://fathometer:fathometer@localhost:55432/fathometer_test`.
    """
    url = os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_DB_URL)
    if not _is_postgres_reachable(url):
        pytest.skip(
            f"Postgres unter {url} nicht erreichbar — DB-Tests werden uebersprungen. "
            "Starte `docker run -d --name fathometer-test-db -e POSTGRES_USER=fathometer "
            "-e POSTGRES_PASSWORD=fathometer -e POSTGRES_DB=fathometer_test -p 55432:5432 "
            "postgres:17-alpine` oder setze TEST_DATABASE_URL.",
            allow_module_level=False,
        )
    return url


@pytest.fixture(scope="session")
def migrated_db(postgres_url: str) -> Iterator[str]:
    """Fuehrt `alembic upgrade head` einmal pro Suite aus und droppt am Ende.

    Wir setzen `FM_DATABASE_URL` waehrend der Migration auf die Test-DB,
    damit `alembic/env.py` die URL korrekt findet.
    """
    import warnings

    from alembic.config import Config

    from alembic import command

    prev_url = os.environ.get("FM_DATABASE_URL")
    os.environ["FM_DATABASE_URL"] = postgres_url

    cfg = Config("alembic.ini")
    # Sicherheitsnetz: auch via cfg-Attribute setzen.
    cfg.set_main_option("sqlalchemy.url", postgres_url)

    # Alembic 1.13+ wirft DeprecationWarnings fuer fehlendes path_separator.
    # pytest.ini macht `filterwarnings = error` — wir muessen das lokal mute'n.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)

        # Vor dem Hochfahren auf base — falls vorheriger Lauf abgestuerzt ist.
        with contextlib.suppress(Exception):
            command.downgrade(cfg, "base")

        command.upgrade(cfg, "head")
    try:
        yield postgres_url
    finally:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with contextlib.suppress(Exception):
                command.downgrade(cfg, "base")
        if prev_url is None:
            os.environ.pop("FM_DATABASE_URL", None)
        else:
            os.environ["FM_DATABASE_URL"] = prev_url


@pytest.fixture
def db_app_env(
    migrated_db: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Env-Vars fuer Tests gegen die echte DB.

    - DB-URL auf die migrierte Test-DB.
    - Argon2-Cost drastisch reduziert (time=1, memory=8 KiB, parallelism=1).
    - Login-Rate-Limit so eng, dass wir den 429-Pfad in ueberschaubaren
      Schritten testen koennen. Standard bleibt `5/minute`.
    """
    monkeypatch.setenv("FM_ENCRYPTION_KEY", "x" * 32)
    monkeypatch.setenv("FM_SECRET_KEY", "test-secret-key-not-used-in-prod")
    monkeypatch.setenv("FM_DATABASE_URL", migrated_db)
    monkeypatch.setenv("FM_LOG_LEVEL", "WARNING")
    # Argon2-Minimum: time_cost>=1, memory_cost>=8 KiB, parallelism>=1.
    monkeypatch.setenv("FM_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("FM_ARGON2_MEMORY_COST", "8192")
    monkeypatch.setenv("FM_ARGON2_PARALLELISM", "1")
    monkeypatch.setenv("FM_RATELIMIT_LOGIN", "5/minute")
    yield


def _truncate_all(engine: Any) -> None:
    """Leert alle in Block-B-Tests beschreibbaren Tabellen und reset't Sequences.

    Robustheit: vorherige Tests koennen Connections mit offener Transaction
    hinterlassen (Connection-Leak im View-Pfad o.ae.). Diese blocken den
    ACCESS-EXCLUSIVE-Lock den TRUNCATE braucht. Ohne Schutz haengt der
    ganze Test-Lauf still. Drei Defensiv-Massnahmen:

    1. `lock_timeout` cap't den Wait — nach 5s Fehler statt Endlos-Hang.
    2. `statement_timeout` Fail-Safe auf der TRUNCATE-Statement-Ebene.
    3. `pg_terminate_backend` killt verbliebene Connections auf derselben
       DB (ausser uns selbst), damit der TRUNCATE freie Bahn hat.

    Nicht-paralleltauglich (xdist), aber die Suite laeuft seriell.
    """
    from sqlalchemy import text

    with engine.begin() as conn:
        conn.execute(text("SET lock_timeout = '5s'"))
        conn.execute(text("SET statement_timeout = '10s'"))
        conn.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = current_database() AND pid <> pg_backend_pid()"
            )
        )
        conn.execute(
            text(
                "TRUNCATE TABLE "
                "scan_ingest_jobs, "
                "feed_pull_log, epss_scores, cisa_kev_catalog, "
                "llm_risk_cache, llm_jobs, application_groups, "
                "finding_notes, findings, server_tags, tags, scans, servers, "
                "audit_events, settings, users "
                "RESTART IDENTITY CASCADE"
            )
        )


@pytest.fixture
def db_app(db_app_env: None) -> Generator[Flask]:
    """Echte App gegen die migrierte Test-DB.

    Vor jedem Test: TRUNCATE auf alle relevanten Tabellen, damit Tests
    unabhaengig voneinander sind.
    Nach jedem Test: `engine.dispose()` und Limiter-Reset, damit psycopg keine
    offenen Connections leaked (`filterwarnings = error` in pytest.ini wuerde
    sonst ResourceWarnings zu Fehlern eskalieren).
    """
    from app import create_app, limiter
    from app.db import get_engine

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

    # Limiter-Storage zwischen Tests platt machen.
    with contextlib.suppress(Exception):
        limiter.reset()

    # DB-State vor jedem Test komplett leeren.
    engine = get_engine(flask_app)
    _truncate_all(engine)

    try:
        yield flask_app
    finally:
        with contextlib.suppress(Exception):
            limiter.reset()
        engine.dispose()


@pytest.fixture
def db_client(db_app: Flask) -> FlaskClient:
    """Flask-Testclient mit deaktiviertem CSRF (siehe `db_app`)."""
    return db_app.test_client()


@pytest.fixture
def db_session(db_app: Flask) -> Generator[Any]:
    """Eine ORM-Session gegen die App-Engine.

    `db_app` hat die DB bereits geleert; wir liefern hier einfach eine
    sauber wieder schliessbare Session fuer Tests, die direkt ORM-Calls
    machen wollen.
    """
    from sqlalchemy.orm import Session

    from app.db import get_engine

    engine = get_engine(db_app)
    session = Session(bind=engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def csrf_enabled_db_app(db_app_env: None) -> Generator[Flask]:
    """Variante mit aktivem CSRF-Schutz fuer Tests, die das brauchen."""
    from app import create_app, limiter
    from app.db import get_engine

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    with contextlib.suppress(Exception):
        limiter.reset()
    engine = get_engine(flask_app)
    _truncate_all(engine)
    try:
        yield flask_app
    finally:
        with contextlib.suppress(Exception):
            limiter.reset()
        engine.dispose()
