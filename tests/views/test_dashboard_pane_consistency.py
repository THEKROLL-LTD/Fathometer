"""Regression-Test: Full-Page und HX-Response auf `/` liefern identisches Pane.

ADR-0017 verlangt, dass der Dashboard-Detail-Pane aus EINEM Jinja-Partial
gerendert wird, das beide Render-Pfade konsumieren. Dieser Test ist der
strukturelle Schutz gegen Re-Drift: er prueft, dass beide Responses
dieselben Pane-Marker enthalten (Headline, Server-Count, Quick-Stats,
Platzhalter).

Wenn jemand erneut zwei Templates anlegt oder das HX-Partial vom Full-Page-
Pfad divergieren laesst, schlaegt dieser Test sofort an.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Flask

from app.db import get_session_factory
from app.models import Server
from tests._helpers import create_admin_user, login


def _create_server(app: Flask, name: str = "pane-srv-1") -> int:
    factory = get_session_factory(app)
    now = datetime.now(tz=UTC)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=now - timedelta(hours=2),
                trivy_db_updated_at=now - timedelta(hours=2),
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Pane-Marker — beide Responses muessen sie enthalten.
# ---------------------------------------------------------------------------

# Marker, die nach ADR-0020 (Block M) zum Dashboard-Pane gehoeren. Bewusst
# keine tiefen CSS-Klassen-Strings — die Marker sollen Layout-Refactors
# ueberleben, aber Template-Austausch sofort erkennen. Block M hat die
# alte `Dashboard</h1>`-Headline auf `Alle Findings</h1>` umgestellt,
# Quick-Stats-Container durch KPI-Cards (`data-test="kpi-card-…"`) ersetzt
# und den Platzhalter ersatzlos entfernt.
PANE_MARKERS = (
    # Headline aus _detail_pane.html (Block M).
    "Alle Findings</h1>",
    # Server-Count-Indikator.
    "Server sichtbar",
    # KPI-Card-Marker (Block M, ADR-0020) — mindestens die TOTAL-OPEN-Card.
    'data-test="kpi-card-total_open"',
    # Findings-Section-Container (Triage-Queue).
    'data-test="dashboard-findings-section"',
)


def test_dashboard_pane_is_identical_between_hx_and_full(db_app: Flask) -> None:
    """Pane-Marker muessen in beiden Render-Pfaden auftauchen."""
    create_admin_user(db_app)
    _create_server(db_app, name="consistency-srv")
    client = db_app.test_client()
    login(client)

    full = client.get("/")
    hx = client.get("/", headers={"HX-Request": "true"})

    assert full.status_code == 200, full.get_data(as_text=True)[:400]
    assert hx.status_code == 200, hx.get_data(as_text=True)[:400]

    full_body = full.get_data(as_text=True)
    hx_body = hx.get_data(as_text=True)

    for marker in PANE_MARKERS:
        assert marker in full_body, (
            f"Pane-Marker {marker!r} fehlt im Full-Page-Render von `/`. "
            f"Erste 400 Bytes: {full_body[:400]!r}"
        )
        assert marker in hx_body, (
            f"Pane-Marker {marker!r} fehlt im HX-Response von `/`. "
            f"Beide Render-Pfade muessen denselben Pane-Inhalt liefern "
            f"(ADR-0017). Erste 400 Bytes: {hx_body[:400]!r}"
        )


def test_dashboard_hx_response_is_fragment_only(db_app: Flask) -> None:
    """HX-Response liefert nur das Pane-Fragment, kein `<html>` oder `<aside>`.

    Der Full-Page-Pfad legt Sidebar+Header drumherum; der HX-Pfad nicht.
    Wenn der HX-Branch versehentlich das volle `dashboard/index.html`
    rendert (statt `_detail_pane.html`), schlaegt dieser Test an.
    """
    create_admin_user(db_app)
    _create_server(db_app, name="fragment-srv")
    client = db_app.test_client()
    login(client)

    resp = client.get("/", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    body_lower = resp.get_data(as_text=True).lower()

    assert "<html" not in body_lower, body_lower[:300]
    assert "<aside" not in body_lower, body_lower[:300]


def test_dashboard_old_welcome_partial_not_used(db_app: Flask) -> None:
    """Der HX-Response darf nicht mehr die alte Welcome-Card rendern.

    `_pane/welcome.html` ist nach ADR-0017 entfernt. Wenn jemand das alte
    Partial wieder einfuehrt oder die View zurueckdreht, war der Hauptpunkt
    der Konsolidierung der Welcome-Card-Header `card-title text-base` — der
    sollte im Pane nicht mehr auftauchen, weil der Pane jetzt `<h1>Dashboard
    </h1>` als Headline benutzt.
    """
    create_admin_user(db_app)
    _create_server(db_app, name="no-welcome-srv")
    client = db_app.test_client()
    login(client)

    resp = client.get("/", headers={"HX-Request": "true"})
    body = resp.get_data(as_text=True)

    # Der spezifische Welcome-Card-Header darf nicht mehr auftauchen.
    assert "Willkommen bei secscan" not in body, (
        "Altes `_pane/welcome.html`-Partial wieder im Pane gelandet — "
        "ADR-0017 verlangt ein einziges Pane-Partial."
    )
