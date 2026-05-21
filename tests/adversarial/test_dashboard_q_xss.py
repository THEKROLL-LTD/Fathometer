"""Adversarial: `/findings?q=<script>…</script>` rendert escaped (Block Q, ADR-0025).

ARCHITECTURE.md §10 (Input-Validierung) + ADR-0020/0025 (q-Field als XSS-
Surface). Das `view_filter.q`-Echo im Filter-Bar-`value`-Attribut darf
NIEMALS `|safe` verwenden — Jinja-Autoescape ist die einzige Verteidigung.
Tabellen-Render des Findings-Treffers escapet ebenfalls jegliche User-Werte.

Block Q (ADR-0025) hat die Filter-Bar vom Dashboard `/` auf die dedizierte
`/findings`-Seite verlagert — diese Suite verifiziert die XSS-Sicherheit
weiterhin, gegen den neuen Endpoint.

Diese Suite verifiziert: bei einem `<script>`-Payload im `q`-Query-Param
- Status 200,
- Roher Payload erscheint NICHT als lauffaehiges `<script>`-Tag im HTML,
- Die escaped Form (`&lt;script&gt;`) erscheint im Filter-Echo.
"""

from __future__ import annotations

import re

from flask import Flask

from app.db import get_session_factory
from app.models import Server
from tests._helpers import create_admin_user, login


def _create_server(app: Flask, name: str) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


SCRIPT_PAYLOAD = "<script>alert(1)</script>"
IMG_PAYLOAD = "<img src=x onerror=alert(1)>"
ATTR_PAYLOAD = 'foo" onmouseover="alert(1)'


def test_q_script_payload_rendered_escaped_in_filter_input(db_app: Flask) -> None:
    """`q=<script>…</script>` erscheint im `value="…"`-Attribut der Filter-
    Bar als escaped HTML — kein `|safe`-Leak."""
    create_admin_user(db_app)
    _create_server(db_app, name="q-xss-srv")
    client = db_app.test_client()
    login(client)
    resp = client.get("/findings", query_string={"q": SCRIPT_PAYLOAD})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Roher Payload als lauffaehiges <script>alert( ... darf NICHT im Body sein.
    assert re.search(r"<script[^>]*>\s*alert\(", body) is None, (
        "Raw script-Tag im Body — `q` muss escaped gerendert werden, "
        "siehe ADR-0020 + ARCHITECTURE.md §10"
    )
    # Escaped Form muss in dem `value`-Attribut der Filter-Bar erscheinen.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body, body[:600]


def test_q_attribute_breakout_payload_escaped(db_app: Flask) -> None:
    """`q=foo" onmouseover="alert(1)` darf das `value="…"`-Attribut NICHT
    aufbrechen."""
    create_admin_user(db_app)
    _create_server(db_app, name="q-attr-xss")
    client = db_app.test_client()
    login(client)
    body = client.get("/findings", query_string={"q": ATTR_PAYLOAD}).get_data(as_text=True)

    # Roher unescaped Payload mit ungescaptem `"` darf NICHT als Attribut
    # auftauchen.
    assert 'value="foo" onmouseover="alert(1)' not in body, (
        'ATTR-Payload mit unescaped `"` brach das Attribut auf — Autoescape kaputt'
    )
    # Escaped Form: `"` -> `&#34;` (Jinja).
    assert "&#34;" in body or "&quot;" in body


def test_q_img_onerror_payload_escaped(db_app: Flask) -> None:
    """`<img src=x onerror=alert(1)>` rendert escaped, kein lauffaehiges Img."""
    create_admin_user(db_app)
    _create_server(db_app, name="q-img-xss")
    client = db_app.test_client()
    login(client)
    body = client.get("/findings", query_string={"q": IMG_PAYLOAD}).get_data(as_text=True)

    assert IMG_PAYLOAD not in body, "Raw <img onerror>-Payload im Body"
    # Escaped Form auf irgendeiner Form (`&lt;img` ist generisch genug).
    assert "&lt;img" in body, body[:400]


def test_q_payload_appears_only_in_filter_input(db_app: Flask) -> None:
    """Das escaped Payload taucht im Filter-Bar-Input auf — der Tabellen-
    Bereich rendert keinen Suchterm-Highlight (ADR-0020: kein |safe auf
    User-Input im Findings-Render)."""
    create_admin_user(db_app)
    _create_server(db_app, name="q-isolation")
    client = db_app.test_client()
    login(client)
    body = client.get("/findings", query_string={"q": SCRIPT_PAYLOAD}).get_data(as_text=True)

    # Pruefe konkret das `value="…"`-Attribut der `filter-q`-Input.
    filter_q_match = re.search(
        r'data-test="filter-q"[^>]*?value="([^"]*)"',
        body,
        re.DOTALL,
    )
    # `value="…"` kommt vor `data-test="filter-q"` im Template-Output.
    # Suchen wir generisch im `<input … name="q" … value="…">`-Block.
    input_match = re.search(
        r'<input[^>]*name="q"[^>]*value="([^"]*)"',
        body,
        re.DOTALL,
    )
    assert input_match is not None or filter_q_match is not None
    raw_value = (input_match or filter_q_match).group(1)
    # Der Attribut-Inhalt enthaelt KEIN echtes `<` — der Browser sieht den
    # Wert als gestrippten Text. Jinja schreibt `&lt;` ins HTML.
    assert "<script>" not in raw_value, (
        f"raw `<script>` im value-Attribut — Autoescape kaputt: {raw_value!r}"
    )
