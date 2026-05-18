"""Block N (ADR-0021) — Sidebar-Marker fuer veraltete Server (Task #12)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Flask

from app.config import Settings
from app.db import get_session_factory
from app.models import Server
from tests._helpers import create_admin_user, login


def _create_server(
    app: Flask,
    *,
    name: str,
    agent_version: str | None,
    trivy_version: str | None,
    trivy_db_updated_at: datetime | None,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                agent_version=agent_version,
                trivy_version=trivy_version,
                trivy_db_updated_at=trivy_db_updated_at,
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def test_sidebar_marker_visible_for_outdated_agent(db_app: Flask) -> None:
    """Server mit unbekanntem Agent -> Sidebar-Marker mit data-test-Id."""
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="sidebar-outdated",
        agent_version=None,
        trivy_version=Settings.MIN_TRIVY_VERSION,
        trivy_db_updated_at=now - timedelta(hours=2),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    assert f'data-test="sidebar-marker-outdated-{sid}"' in body


def test_sidebar_marker_hidden_for_current_server(db_app: Flask) -> None:
    """Aktueller Server -> kein Sidebar-Marker."""
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="sidebar-current",
        agent_version=Settings.CURRENT_AGENT_VERSION,
        trivy_version=Settings.RECOMMENDED_TRIVY_VERSION,
        trivy_db_updated_at=now - timedelta(hours=2),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    assert f'data-test="sidebar-marker-outdated-{sid}"' not in body


def test_sidebar_marker_visible_for_stale_trivy_db(db_app: Flask) -> None:
    """DB > 7 Tage -> Sidebar-Marker erscheint (drei OR-Bedingungen)."""
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="sidebar-staledb",
        agent_version=Settings.CURRENT_AGENT_VERSION,
        trivy_version=Settings.RECOMMENDED_TRIVY_VERSION,
        trivy_db_updated_at=now - timedelta(days=30),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    assert f'data-test="sidebar-marker-outdated-{sid}"' in body


def test_polling_sidebar_partial_also_renders_marker(db_app: Flask) -> None:
    """Block L Polling-Pfad `/_partials/sidebar` rendert denselben Marker."""
    create_admin_user(db_app)
    sid = _create_server(
        db_app,
        name="sidebar-poll",
        agent_version=None,
        trivy_version=None,
        trivy_db_updated_at=None,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/_partials/sidebar", headers={"HX-Request": "true"})
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    assert f'data-test="sidebar-marker-outdated-{sid}"' in body
