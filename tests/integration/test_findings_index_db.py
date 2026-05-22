"""Block Q (ADR-0025 §(5)) / DoD E.2: Smoketests fuer `/findings`-View.

Geprueft werden:

  - Default ohne Filter rendert den Empty-State (keine Tabelle, kein Pager).
  - Mit Filter `?q=...` rendert die Tabelle inkl. Pager.
  - `?page=2` allein (ohne weiteren Filter) triggert KEINEN Render
    (Empty-State bleibt sichtbar).
  - `?sort=epss&dir=desc` allein triggert den Render (expliziter Sort ist
    User-Intent — `_explicit_sort()` returnt True).
  - Ohne Login -> 302 auf den Login.
  - Bonus: CSV-Export-Link in der Filter-Bar verlinkt `findings.export_csv`.

Setup-Pattern aus `tests/views/test_dashboard.py` (`_create_server`,
`_add_finding`) — Server/Finding via direktem ORM, kein Ingest-Pfad noetig.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Flask

from app.db import get_session_factory
from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from tests._helpers import create_admin_user, login

# ---------------------------------------------------------------------------
# Fixture-Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _create_server(app: Flask, *, name: str) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=_now(),
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _bulk_findings(app: Flask, server_id: int, count: int) -> None:
    """Bulk-Insert `count` OPEN-Findings via einer Session — schneller als
    `count` Einzel-Commits."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            for i in range(count):
                f = Finding(
                    server_id=server_id,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key=f"CVE-2024-{i + 1:05d}",
                    package_name="openssl",
                    installed_version="1.0",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.OPEN,
                    is_kev=False,
                    attack_vector=AttackVector.UNKNOWN,
                    first_seen_at=_now(),
                    last_seen_at=_now(),
                )
                sess.add(f)
            sess.commit()
        finally:
            sess.close()


def _login(client: Any) -> None:
    """Login-Wrapper — hebt den 302-Assert aus `tests._helpers.login` und
    nutzt nur die HTTP-Routen."""
    login(client)


# ---------------------------------------------------------------------------
# Tests (DoD E.2)
# ---------------------------------------------------------------------------


def test_findings_index_unfiltered_renders_empty_state(db_app: Flask) -> None:
    """ADR-0025 §(5): GET `/findings` ohne Filter -> 200, Empty-State,
    kein Pager.

    Der Empty-State-Block (`data-test="findings-empty-state"`) ist immer
    sichtbar wenn `is_filtered=False`. Der Pager (`data-test="findings-pager"`)
    fehlt — wir rendern die Tabelle gar nicht erst.
    """
    create_admin_user(db_app)
    # Wir legen einen Server + 3 Findings an, damit `total_findings` > 0 im
    # Empty-State-Hinweis renderbar ist; das aendert nichts am Default-State.
    sid = _create_server(db_app, name="empty-state-srv")
    _bulk_findings(db_app, sid, 3)

    client = db_app.test_client()
    _login(client)
    resp = client.get("/findings")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert 'data-test="findings-empty-state"' in body, (
        "Empty-State-Block muss bei ungefiltertem Default sichtbar sein"
    )
    assert 'data-test="findings-pager"' not in body, (
        "Pager darf bei Empty-State NICHT gerendert sein"
    )
    # Counter im Empty-State zeigt `total_findings` (= 3 OPEN Findings).
    # Wir pruefen den Hinweis-Text und die Zahl als font-mono Span.
    assert "Findings ueber" in body, "Empty-State-Hinweis muss den Counter erklaeren"
    assert ">3<" in body or ">3 <" in body, "total_findings=3 muss im Empty-State stehen"


def test_findings_index_with_filter_renders_table_and_pager(db_app: Flask) -> None:
    """ADR-0025 §(5): `?q=CVE` mit 75 Treffern rendert Tabelle + Pager
    (Seite 1 von 2).
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="filter-srv")
    _bulk_findings(db_app, sid, 75)

    client = db_app.test_client()
    _login(client)
    resp = client.get("/findings?q=CVE")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert 'data-test="findings-pager"' in body, "Pager muss bei aktiv. Filter sichtbar sein"
    # Mindestens eine Findings-Row.
    assert "data-finding-id=" in body, "Findings-Row(s) muessen gerendert werden"
    # Pager-Text: 75 / 50 per page -> 2 Seiten.
    assert "Seite 1 von 2" in body, body[body.find("findings-pager") :][:400]


def test_findings_index_page_alone_does_not_trigger_render(db_app: Flask) -> None:
    """ADR-0025 §(5): `?page=2` allein ohne weiteren Filter ist KEIN Trigger.

    `_filter_is_active()` schliesst `page` explizit aus, `_explicit_sort()`
    prueft nur `sort`/`dir`. Folge: Empty-State bleibt.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="page-only-srv")
    _bulk_findings(db_app, sid, 10)

    client = db_app.test_client()
    _login(client)
    resp = client.get("/findings?page=2")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert 'data-test="findings-empty-state"' in body, (
        "?page=2 allein darf den Empty-State nicht ueberschreiben"
    )
    assert 'data-test="findings-pager"' not in body


def test_findings_index_explicit_sort_triggers_render(db_app: Flask) -> None:
    """ADR-0025 §(5): expliziter Sort ist User-Intent — `_explicit_sort()`
    returnt True bei `?sort=`/`?dir=`. Der Empty-State darf bei Sort-only-
    Bookmark NICHT mehr sichtbar sein; die Tabelle wird gerendert.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="sort-only-srv")
    _bulk_findings(db_app, sid, 5)

    client = db_app.test_client()
    _login(client)
    resp = client.get("/findings?sort=epss&dir=desc")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert 'data-test="findings-empty-state"' not in body, (
        "expliziter Sort triggert Render — Empty-State darf NICHT erscheinen"
    )
    # Tabellen-Section vorhanden.
    assert 'data-test="findings-table-section"' in body, (
        "Tabellen-Section muss bei explizitem Sort gerendert werden"
    )


def test_findings_index_login_required(db_app: Flask) -> None:
    """GET /findings ohne Login -> 302 auf den Login."""
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/findings", follow_redirects=False)
    assert resp.status_code in (301, 302), resp.status_code
    assert "/login" in resp.headers.get("Location", ""), resp.headers.get("Location")


def test_findings_index_csv_link_visible_in_filter_form(db_app: Flask) -> None:
    """Bonus: CSV-Export-Link in der Filter-Bar verweist auf
    `findings.export_csv`. Bei `?q=foo` traegt der Link den Query-String."""
    create_admin_user(db_app)
    _create_server(db_app, name="csv-link-srv")
    client = db_app.test_client()
    _login(client)
    resp = client.get("/findings?q=foo")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    assert 'data-test="findings-csv-export"' in body, "CSV-Export-Link fehlt im Markup"
    # Link zeigt auf den export_csv-Endpoint.
    assert "/findings/export.csv" in body, "Export-CSV-URL fehlt"
    # Query-String enthaelt das aktuell aktive `q=foo`.
    csv_pos = body.find('data-test="findings-csv-export"')
    # Wir suchen in einem Fenster rund um das Marker-Attribut nach `q=foo`.
    window = body[max(0, csv_pos - 400) : csv_pos + 200]
    assert "q=foo" in window, f"Query-String `q=foo` nicht im CSV-Link-Window: {window[:300]}"
