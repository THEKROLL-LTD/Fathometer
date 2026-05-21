"""Status-Pill-Reihe im Server-Detail-Header (Block Q Phase D / ADR-0025).

ADR-0025 §Entscheidung (4) entfernt die gruene `active`-Default-Pille aus dem
Header von `app/templates/servers/detail.html`. Die `revoked`/`retired`-Pillen
bleiben erhalten, ebenso alle Aufmerksamkeits-Marker (`scale`, `db veraltet`,
`agent`/`trivy`/`trivy-db`-Outdated, `action_required`).

Diese Datei testet das beobachtbare Render-Ergebnis fuer drei Pfade:

1. Aktiver Server ohne Auffaelligkeit -> keine Status-Pille im Header.
2. Revoked Server -> `revoked`-Pille bleibt sichtbar.
3. Retired Server -> `retired`-Pille bleibt sichtbar.

Geltungsbereich: ausschliesslich Server-Detail-Header. Die `active`-Pille in
`app/templates/settings/servers.html` ist anderer Kontext und wird in
`tests/views/test_settings_servers_active_pill.py` separat abgesichert.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import Server
from tests._helpers import create_admin_user, login
from tests.views.test_server_detail_redesign import _create_server


def _mark_revoked(app: Flask, server_id: int) -> None:
    """Setzt `revoked_at = now()` direkt via ORM (kein HTTP, kein CSRF)."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            srv.revoked_at = datetime.now(tz=UTC)
            sess.commit()
        finally:
            sess.close()


def _mark_retired(app: Flask, server_id: int) -> None:
    """Setzt `retired_at = now()` direkt via ORM."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            srv.retired_at = datetime.now(tz=UTC)
            sess.commit()
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Phase Q.D Kern-Test: aktive Server ohne Auffaelligkeit -> keine Status-Pille.
# ---------------------------------------------------------------------------


def test_active_pill_removed_for_active_server_in_detail_header(db_app: Flask) -> None:
    """Aktiver Server ohne Stale-/Outdated-Marker rendert KEINE Status-Pille.

    Setup:
      - Server ohne `revoked_at` / `retired_at`.
      - Frisches `last_scan_at` (< expected_scan_interval_h -> nicht stale).
      - Frisches `trivy_db_updated_at` (< 168h -> nicht db-veraltet).
      - Agent-/Trivy-Version-Felder leer (kommen aus Heartbeat — fuer den
        Default-Server irrelevant; die `is_*_outdated`-Helper koennen je nach
        Konfiguration triggern. Wir pruefen daher pro Pill explizit ihre
        Abwesenheit.).

    Erwartung:
      - HTTP 200.
      - HTML enthaelt keinen `>active<`-Marker.
      - HTML enthaelt keinen `>revoked<`-Marker.
      - HTML enthaelt keinen `>retired<`-Marker.
    """
    create_admin_user(db_app)
    now = datetime.now(tz=UTC)
    sid = _create_server(
        db_app,
        name="srv-pill-active",
        last_scan_at=now - timedelta(hours=1),
        trivy_db_updated_at=now - timedelta(hours=2),
        expected_scan_interval_h=24,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert ">active<" not in body, (
        "active-Pille darf nach Phase Q.D nicht mehr im Server-Detail-Header rendern"
    )
    assert ">revoked<" not in body, "revoked-Pille faelschlich gerendert"
    assert ">retired<" not in body, "retired-Pille faelschlich gerendert"


# ---------------------------------------------------------------------------
# Regression: revoked/retired-Pillen bleiben sichtbar.
# ---------------------------------------------------------------------------


def test_revoked_pill_still_renders_for_revoked_server(db_app: Flask) -> None:
    """Server mit gesetztem `revoked_at` rendert weiterhin die `revoked`-Pille."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-pill-revoked")
    _mark_revoked(db_app, sid)

    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert ">\n            revoked\n          <" in body or "revoked\n          </span>" in body, (
        "revoked-Pille fehlt im Header"
    )
    assert ">active<" not in body


def test_retired_pill_still_renders_for_retired_server(db_app: Flask) -> None:
    """Server mit gesetztem `retired_at` (ohne `revoked_at`) rendert die `retired`-Pille."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-pill-retired")
    _mark_retired(db_app, sid)

    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert ">\n            retired\n          <" in body or "retired\n          </span>" in body, (
        "retired-Pille fehlt im Header"
    )
    assert ">active<" not in body
    # Kein doppelter revoked-Marker — retired-Zweig ist ein `{% elif %}`.
    assert ">\n            revoked\n          <" not in body
