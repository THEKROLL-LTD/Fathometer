"""Tests fuer das Sidebar+Detail-Pane-Layout (Block I, §7a).

Deckt:
  * `GET /` ohne HX-Request: volle Seite mit `<aside>` Sidebar.
  * `GET /` mit `HX-Request: true`: nur Welcome-Pane-Fragment, kein
    `<html>`/`<aside>`.
  * `GET /` ohne Login: 302 auf `/login`.
  * `GET /servers/<id>` markiert die Sidebar-Zeile als aktiv
    (`active_server_id` -> `bg-primary/10` an der Row).
  * `GET /servers/<id>` mit HX-Request: nur Detail-Fragment.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from flask import Flask

from app.db import get_session_factory
from app.models import Server
from tests._helpers import create_admin_user, login


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _create_server(app: Flask, name: str = "srv-1") -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=_now() - timedelta(hours=2),
                trivy_db_updated_at=_now() - timedelta(hours=2),
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_dashboard_redirects_when_not_logged_in(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302), resp.status_code
    assert "/login" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# Vollseite vs. HX-Fragment auf /
# ---------------------------------------------------------------------------


def test_dashboard_full_page_renders_sidebar(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="vis-srv-1")
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    # Sidebar-<aside> + IDs aus base_app.html.
    assert "<aside" in body, body[:600]
    assert 'id="sidebar-root"' in body
    assert 'id="quick-stats"' in body
    assert 'id="server-list"' in body
    assert 'id="detail-pane"' in body
    # Server-Name in Sidebar.
    assert "vis-srv-1" in body


def test_dashboard_full_page_renders_quick_stats_counters(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="qs-srv-1")
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    # 5 Quick-Stats-Marker (data-stat-Attribute) aus _quick_stats.html.
    for stat in ("total_open", "kev_open", "critical_open", "high_open", "stale_servers"):
        assert f'data-stat="{stat}"' in body, stat


def test_dashboard_full_page_dashboard_template_renders(db_app: Flask) -> None:
    """Vollseiten-Request auf `/` rendert die Block-D-Dashboard-Vorlage —
    Welcome-Pane ist nur beim HX-Fragment-Pfad sichtbar (siehe Dashboard-
    View). Wir verifizieren hier nur, dass der Dashboard-Titel im Detail-
    Pane erscheint."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    assert "Dashboard" in body
    # Detail-Pane-Container ist vorhanden.
    assert 'id="detail-pane"' in body


def test_dashboard_hx_request_renders_welcome_pane(db_app: Flask) -> None:
    """Beim HX-Pfad liefert die Dashboard-Route die Welcome-Card (Fragment)."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Willkommen bei secscan" in body


def test_dashboard_hx_request_returns_fragment_only(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="hx-srv-1")
    client = db_app.test_client()
    login(client)
    resp = client.get("/", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Fragment hat kein <html> und kein <aside>.
    assert "<html" not in body.lower(), body[:300]
    assert "<aside" not in body.lower(), body[:300]
    # Welcome-Content vorhanden.
    assert "Willkommen bei secscan" in body


# ---------------------------------------------------------------------------
# Server-Detail-Route — active-Marker + HX-Variante
# ---------------------------------------------------------------------------


def test_server_detail_marks_active_server_in_sidebar(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, name="active-srv")
    _create_server(db_app, name="other-srv")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Beide Servers sind in der Sidebar.
    assert "active-srv" in body
    assert "other-srv" in body

    # Die aktive Zeile (active-srv) hat `bg-primary/10` UND `data-server-id="<sid>"`.
    # Wir suchen einen `<li>`-Tag mit diesem `data-server-id` und pruefen dass
    # `bg-primary/10` im selben Tag steht.
    row_pat = re.compile(
        r'<li[^>]*data-server-id="' + str(sid) + r'"[^>]*>',
        re.MULTILINE | re.DOTALL,
    )
    m = row_pat.search(body)
    assert m is not None, "Aktive Sidebar-Zeile nicht gefunden"
    li_open = m.group(0)
    assert "bg-primary/10" in li_open, li_open

    # Der andere Server-Eintrag soll NICHT die active-Klasse haben.
    # Wir suchen seine Zeile.
    other_row_pat = re.compile(
        r'<li[^>]*data-server-name="other-srv"[^>]*>', re.MULTILINE | re.DOTALL
    )
    m2 = other_row_pat.search(body)
    assert m2 is not None
    assert "bg-primary/10" not in m2.group(0)


def test_server_detail_hx_request_returns_fragment_only(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, name="hx-active-srv")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # HX-Variante liefert nur die Findings-Sektion (kein Sidebar/HTML-Wrapper).
    assert "<html" not in body.lower()
    assert "<aside" not in body.lower()
    assert 'id="sidebar-root"' not in body
