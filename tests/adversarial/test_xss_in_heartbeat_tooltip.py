"""Adversarial: XSS-Payloads in Sidebar-Server-Names und Heartbeat-Daten.

ARCHITECTURE.md §10: Skript-Tags in user-provided Strings (Server-Name,
Tag-Namen, CVE-Title) muessen beim Jinja-Render escaped werden — der
Sidebar-Render-Pfad ist neu (Block I) und wird hier explizit gegen
Script-Injection abgesichert.

Wir umgehen den Register-Endpoint (der validiert Hostnames serverseitig)
und legen die XSS-Server direkt via ORM an — der Render-Pfad sieht
identische Daten unabhaengig davon, woher sie kamen, und ein
DB-Corruption-Szenario (z.B. via manuelles SQL) wuerde die Sidebar
ebenfalls als XSS-Vektor missbrauchbar machen.

Abdeckung:
  * `<script>`-Payload in `Server.name` -> escaped in Sidebar-Zeile.
  * `<img onerror=...>` in `Finding.title` -> taucht entweder gar nicht
    in der Sidebar auf, oder ist escaped (kein lauffaehiges `<img>`).
  * `data-*`-Attribute der Heartbeat-Pillen enthalten keine
    unescaped Anfuehrungszeichen (Attribute-Injection-Schutz).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

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

SCRIPT_PAYLOAD = "<script>alert('xss')</script>"
IMG_PAYLOAD = "<img src=x onerror=alert(1)>"
ATTR_PAYLOAD = 'a" onmouseover="alert(1)'


def _create_xss_server(app: Flask, name: str) -> int:
    """Legt einen Server direkt via ORM an, ohne Register-Endpoint-Validierung."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=datetime.now(tz=UTC) - timedelta(hours=2),
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _add_finding_with_title(
    app: Flask, *, server_id: int, title: str, identifier_key: str = "CVE-XSS-1"
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key=identifier_key,
                package_name="pkg-xss",
                installed_version="1.0",
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                attack_vector=AttackVector.UNKNOWN,
                title=title,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# <script> im Server-Name
# ---------------------------------------------------------------------------


def test_script_payload_in_server_name_is_escaped_in_sidebar(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_xss_server(db_app, name=SCRIPT_PAYLOAD)
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Escaped Variante taucht auf.
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in body, body[:600]
    # Roher Payload als lauffaehiges <script>-Element NICHT.
    assert SCRIPT_PAYLOAD not in body, body[:600]


def test_script_payload_in_server_name_no_executable_script_tag(db_app: Flask) -> None:
    """Detail-Pruefung: in der Sidebar gibt es kein `<script>alert`-Pattern
    das tatsaechlich vom Browser ausgefuehrt wuerde."""
    create_admin_user(db_app)
    _create_xss_server(db_app, name=SCRIPT_PAYLOAD)
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)
    # Wir akzeptieren `<script>`-Tags fuer Tailwind/Alpine, aber keinen
    # `<script>alert(`-String.
    assert re.search(r"<script[^>]*>\s*alert\(", body) is None, body[:600]


# ---------------------------------------------------------------------------
# Attribute-Injection via Name (Anfuehrungszeichen)
# ---------------------------------------------------------------------------


def test_quote_payload_in_server_name_does_not_break_attribute(db_app: Flask) -> None:
    """`data-server-name="..."` darf durch einen Anfuehrungs-Payload nicht
    aufgebrochen werden — Jinja-Autoescape rendert `"` als `&#34;`."""
    create_admin_user(db_app)
    _create_xss_server(db_app, name=ATTR_PAYLOAD)
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    # Roher Payload mit unescaped `"` darf NICHT als Attribute-Wert auftreten.
    assert 'data-server-name="a" onmouseover="alert(1)' not in body
    # Stattdessen erwarten wir die escaped Form (Jinja escaped `"` -> `&#34;`
    # innerhalb von Attribut-Strings).
    assert "&#34;" in body or "&quot;" in body, body[:600]


# ---------------------------------------------------------------------------
# <img onerror=...> in CVE-Title
# ---------------------------------------------------------------------------


def test_img_onerror_in_cve_title_does_not_reach_dom_unescaped(db_app: Flask) -> None:
    """CVE-Titles tauchen nicht in der Sidebar auf — falls sie es doch tun
    sollten (zukuenftiges Sidebar-Detail), muss der Payload escaped sein."""
    create_admin_user(db_app)
    sid = _create_xss_server(db_app, name="img-srv")
    _add_finding_with_title(db_app, server_id=sid, title=IMG_PAYLOAD, identifier_key="CVE-XSS-IMG")
    client = db_app.test_client()
    login(client)
    body = client.get("/").get_data(as_text=True)

    # Roher Payload darf nicht im HTML stehen.
    assert IMG_PAYLOAD not in body
    # Server selbst ist sichtbar.
    assert "img-srv" in body


# ---------------------------------------------------------------------------
# Heartbeat-Cells: data-*-Attribute auf der Sidebar-Seite
# ---------------------------------------------------------------------------


def test_heartbeat_cells_data_attributes_are_safe(db_app: Flask) -> None:
    """Heartbeat-Pillen tragen `data-day`, `data-severity`, `data-kev`,
    `data-had-scan` — alle Werte stammen aus ISO-Dates, Enum-Werten und
    ganzzahligen Counts. Wir verifizieren, dass kein Attribut einen
    unescaped Quote enthaelt (Token-Sanity).

    Phase C (ADR-0030): Heartbeat-Cells werden nicht mehr im initialen
    Page-Render geliefert, sondern ausschliesslich vom Polling-Endpoint
    `/_partials/sidebar`. Der Test prueft daher diesen Endpoint.
    """
    create_admin_user(db_app)
    _create_xss_server(db_app, name="hb-data-srv")
    client = db_app.test_client()
    login(client)
    # Polling-Endpoint liefert die Heartbeat-Cells (Phase C, ADR-0030).
    body = client.get("/_partials/sidebar").get_data(as_text=True)

    # Alle data-day-Werte folgen `YYYY-MM-DD`-Form.
    days = re.findall(r'data-day="([^"]*)"', body)
    assert days, "Keine Heartbeat-Cells gerendert"
    for d in days:
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", d), d
        # Keine Quote-Smuggling-Versuche.
        assert '"' not in d and "'" not in d and "<" not in d

    # data-severity ist '' oder einer der bekannten Enum-Strings.
    sevs = re.findall(r'data-severity="([^"]*)"', body)
    allowed = {"", "critical", "high", "medium", "low", "unknown"}
    for s in sevs:
        assert s in allowed, s

    # data-kev ist eine Ganzzahl.
    kevs = re.findall(r'data-kev="([^"]*)"', body)
    for k in kevs:
        assert k.isdigit(), k

    # data-had-scan ist `0` oder `1`.
    scans = re.findall(r'data-had-scan="([^"]*)"', body)
    for s in scans:
        assert s in ("0", "1"), s
