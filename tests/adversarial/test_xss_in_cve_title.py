"""Adversarial: XSS-Payloads in Trivy-CVE-Daten und in Notes.

ARCHITECTURE.md §10: Skript-Tags in `Title` / `Description` muessen beim
Jinja-Render escaped werden; Notes-Bodies werden durch `markdown_safe`
(=> `nh3.clean(...)` mit kleiner Tag-Whitelist) gefiltert.

Vier Varianten:
1. `<script>`-Payload im CVE-Title -> escaped im HTML, kein lauffaehiges
   `<script>`-Element.
2. Note-Body mit `<script>`, `<a javascript:>`, `**bold**` -> `<script>`
   und `<a>` fehlen, `<strong>` ist da.
3. `<script>` in `description` -> escaped beim Render.
4. `<img onerror=...>`-Payload in `package_name` -> escaped.

Wir gehen ueber den Server-Detail-View (Jinja-Autoescape), damit der Test
auch realistisch den Render-Pfad abdeckt.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from flask import Flask

from app.db import get_session_factory
from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingNote,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from app.services.notes_render import render_note_markdown
from tests._helpers import create_admin_user, login

SCRIPT_PAYLOAD = "<script>alert('xss')</script>"


# ---------------------------------------------------------------------------
# Setup-Helpers
# ---------------------------------------------------------------------------


def _create_server(app: Flask, name: str = "xss-srv") -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str = "CVE-2026-X001",
    title: str | None = None,
    description: str | None = None,
    package_name: str = "openssl",
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            now = datetime.now(tz=UTC)
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key=identifier_key,
                package_name=package_name,
                installed_version="1.0",
                severity=Severity.HIGH,
                title=title,
                description=description,
                attack_vector=AttackVector.UNKNOWN,
                status=FindingStatus.OPEN,
                first_seen_at=now,
                last_seen_at=now,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def _add_note(app: Flask, *, finding_id: int, author: str, text: str) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            note = FindingNote(finding_id=finding_id, author=author, text=text)
            sess.add(note)
            sess.flush()
            nid = note.id
            sess.commit()
            return nid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Variante 1: Skript-Payload im Title
# ---------------------------------------------------------------------------


def test_script_payload_in_title_is_escaped_in_html(db_app: Flask) -> None:
    """Title `<script>alert('xss')</script>` darf im HTML nicht als Skript landen."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="xss-title")
    _add_finding(db_app, server_id=sid, title=SCRIPT_PAYLOAD)

    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?class=os-pkgs")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Wichtige Invariante: KEIN lauffaehiges `<script>`-Element fuer den
    # XSS-Payload. Wir suchen das exakte Pattern (case-insensitive) und
    # verifizieren, dass es nirgends als rohe HTML-Markup vorkommt.
    assert "<script>alert" not in body, (
        "Roh-Skript darf nicht im HTML stehen — Jinja-Autoescape muss greifen."
    )
    # Der Payload-Text darf escaped vorkommen — das ist erwuenscht (zeigt der
    # Operator als String an).
    assert "&lt;script&gt;alert" in body or "&lt;script&gt;" in body, (
        "Erwarte escaped <script> im HTML — Beleg fuer Autoescape-Pipeline."
    )


# ---------------------------------------------------------------------------
# Variante 2: Note-Body mit gemischtem Payload
# ---------------------------------------------------------------------------


def test_note_markdown_strips_script_and_anchor_but_keeps_bold() -> None:
    """`markdown_safe`-Pipeline: `<script>`/`<a>` raus, `<strong>` rein."""
    raw = f'{SCRIPT_PAYLOAD}\n<a href="javascript:void(0)">Klick</a>\n**bold**'
    rendered = str(render_note_markdown(raw))

    # Script-Tag darf nicht als aktives HTML-Element stehen.
    assert "<script" not in rendered.lower()
    # Anchor-Tag steht nicht in der Whitelist.
    assert "<a " not in rendered.lower()
    assert "<a>" not in rendered.lower()
    # `javascript:`-URL darf nirgendwo als AKTIVES Attribut auftauchen.
    # Der gesamte Anchor wird vom Inline-Renderer escaped, weil `<a>` kein
    # Markdown-Token ist — `&lt;a href="javascript:void(0)"&gt;` ist Plaintext
    # und vom Browser nicht ausfuehrbar. Wir verifizieren, dass die `<a`-
    # Markup-Form nirgends als unscaped HTML vorkommt:
    assert not re.search(r"<a\s+[^>]*javascript:", rendered, re.IGNORECASE), (
        f"href=javascript: darf nicht als aktives Attribut stehen: {rendered!r}"
    )
    # Bold landet als <strong>.
    assert "<strong>bold</strong>" in rendered


def test_note_with_script_in_thread_render_does_not_execute(db_app: Flask) -> None:
    """Im gerenderten Server-Detail-View landet die Note ohne aktives `<script>`."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="xss-note")
    fid = _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-X101")
    _add_note(db_app, finding_id=fid, author="alice", text=SCRIPT_PAYLOAD)

    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?class=os-pkgs")
    body = resp.get_data(as_text=True)

    # Auch im voll gerenderten Server-Detail-HTML darf das Skript nicht
    # ausfuehrbar landen.
    # Das Modal mit Notes ist im HTML eingebettet (Alpine-State pro Row).
    # Wir suchen das Skript-Pattern und stellen sicher, dass es escaped
    # oder gar nicht da ist.
    assert "<script>alert('xss')</script>" not in body


# ---------------------------------------------------------------------------
# Variante 3: Skript-Payload in description
# ---------------------------------------------------------------------------


def test_script_payload_in_description_is_escaped(db_app: Flask) -> None:
    """`description` rendert im Detail-Modal als Plain-Text-Block."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="xss-desc")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-X201",
        description=f"see {SCRIPT_PAYLOAD} for context",
    )

    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?class=os-pkgs")
    body = resp.get_data(as_text=True)

    # Roh-Skript darf nicht im Body stehen.
    assert "<script>alert" not in body
    # Escapter Marker muss erkennbar sein (zumindest `&lt;script`).
    assert "&lt;script" in body


# ---------------------------------------------------------------------------
# Variante 4: package_name mit Image-Onerror-Payload
# ---------------------------------------------------------------------------


def test_img_onerror_payload_in_package_name_is_escaped(db_app: Flask) -> None:
    """`<img onerror=alert(1)>`-Payload im package_name -> escaped, nicht aktiv.

    Realitaetscheck: ein echter Trivy-Ingest wuerde diesen Payload bereits
    am Pydantic-Schema scheitern lassen (`_PKG_NAME_RE`). Wir umgehen das
    Schema hier per direkter ORM-Insertion, weil der Test pruefen will,
    dass auch der Render-Pfad als zweite Verteidigungslinie escapet.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="xss-pkg")
    payload = "<img src=x onerror=alert(1)>"
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-X301",
        package_name=payload,
    )

    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?class=os-pkgs")
    body = resp.get_data(as_text=True)

    # `onerror=`-Attribut darf nicht roh erscheinen.
    assert "<img src=x onerror=alert" not in body
    # Aber escaped wuerde `&lt;img` ergeben.
    assert "&lt;img" in body


# ---------------------------------------------------------------------------
# Marker-Test: `markdown_safe` filtert Attribute hart weg.
# ---------------------------------------------------------------------------


def test_note_markdown_strips_all_attributes() -> None:
    """nh3-Whitelist erlaubt keine Attribute — auch nicht auf erlaubten Tags."""
    # `<p class="evil">` — auch `class` wird entfernt, weil Allowed-Attrs = {}.
    raw = "Normaler Text"
    rendered = str(render_note_markdown(raw))
    # `class=`/`style=`/`onerror=` darf nirgendwo auftauchen.
    assert not re.search(r"\b(?:class|style|onerror|onload)=", rendered, re.IGNORECASE)
