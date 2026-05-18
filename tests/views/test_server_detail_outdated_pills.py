"""Block N (ADR-0021) — View-Test fuer die Outdated-Pills im Server-Detail.

Drei DoD-Cases (Task #11):
* agent-outdated -> `data-test="pill-agent-outdated"` sichtbar.
* normal-server (alle Versionen aktuell, DB frisch) -> keine Pill.
* trivy-db stale -> `data-test="pill-trivy-db-stale"` sichtbar.
"""

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
    agent_version: str | None = None,
    trivy_version: str | None = None,
    trivy_db_updated_at: datetime | None = None,
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


def test_agent_outdated_pill_visible(db_app: Flask) -> None:
    """Agent-Version `None` -> agent-outdated pill ist im HTML."""
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="srv-no-agent",
        agent_version=None,
        trivy_version=Settings.MIN_TRIVY_VERSION,
        trivy_db_updated_at=now - timedelta(hours=2),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    assert 'data-test="pill-agent-outdated"' in body


def test_normal_server_has_no_outdated_pills(db_app: Flask) -> None:
    """Aktuelle Versionen + frische DB -> keine der drei Pills."""
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="srv-current",
        agent_version=Settings.CURRENT_AGENT_VERSION,
        trivy_version=Settings.RECOMMENDED_TRIVY_VERSION,
        trivy_db_updated_at=now - timedelta(hours=2),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    assert 'data-test="pill-agent-outdated"' not in body
    assert 'data-test="pill-trivy-outdated"' not in body
    assert 'data-test="pill-trivy-db-stale"' not in body


def test_trivy_db_stale_pill_visible(db_app: Flask) -> None:
    """DB-Update >7 Tage her -> trivy-db-stale pill ist im HTML."""
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="srv-stale-db",
        agent_version=Settings.CURRENT_AGENT_VERSION,
        trivy_version=Settings.RECOMMENDED_TRIVY_VERSION,
        trivy_db_updated_at=now - timedelta(days=10),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    assert 'data-test="pill-trivy-db-stale"' in body
    # humanize_delta liefert eine englischsprachige Relativangabe im Tooltip.
    assert "10 days ago" in body
    # Threshold-Hinweis wird aus den Settings ins Tooltip eingebaut.
    assert "Threshold: 7 days" in body


# Zusatz-Cases aus Block-Brief Task #11 — vollstaendige Pill-Matrix.


def test_agent_below_minimum_shows_agent_pill(db_app: Flask) -> None:
    """agent_version='0.0.5', MIN='0.1.0' -> agent-outdated pill."""
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="srv-old-agent",
        agent_version="0.0.5",
        trivy_version=Settings.RECOMMENDED_TRIVY_VERSION,
        trivy_db_updated_at=now - timedelta(hours=2),
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="pill-agent-outdated"' in body


def test_trivy_version_none_shows_trivy_pill(db_app: Flask) -> None:
    """trivy_version=None -> trivy-outdated pill."""
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="srv-no-trivy",
        agent_version=Settings.CURRENT_AGENT_VERSION,
        trivy_version=None,
        trivy_db_updated_at=now - timedelta(hours=2),
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="pill-trivy-outdated"' in body


def test_trivy_db_3d_old_no_pill(db_app: Flask) -> None:
    """trivy_db_updated_at = now - 3d -> KEINE DB-Pill (< Threshold 7d)."""
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="srv-fresh-db",
        agent_version=Settings.CURRENT_AGENT_VERSION,
        trivy_version=Settings.RECOMMENDED_TRIVY_VERSION,
        trivy_db_updated_at=now - timedelta(days=3),
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="pill-trivy-db-stale"' not in body


def test_trivy_db_updated_at_none_shows_db_pill(db_app: Flask) -> None:
    """trivy_db_updated_at=None -> DB-Pill (kein Beleg fuer Frische)."""
    create_admin_user(db_app)
    sid = _create_server(
        db_app,
        name="srv-no-db-ts",
        agent_version=Settings.CURRENT_AGENT_VERSION,
        trivy_version=Settings.RECOMMENDED_TRIVY_VERSION,
        trivy_db_updated_at=None,
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="pill-trivy-db-stale"' in body
