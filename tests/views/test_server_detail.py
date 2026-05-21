"""Tests fuer `/servers/<id>` und Tag-Add/Remove (Block D + Block E).

Deckt Detail-View, 404-Pfad, HTMX-Tag-Editor (Add/Remove inkl. Audit-
Events und CSRF-Schutz) und die Findings-Sektion (List-Modus, einziger
verbleibender Modus nach Block Q) inklusive Filter und Sortierung ab.
Legacy-URLs `?mode=group` und `?mode=diff` werden ohne Redirect/Fehler
auf den List-Pfad gerendert (siehe ADR-0025).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    AttackVector,
    AuditEvent,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    ServerTag,
    Severity,
    Tag,
)
from tests._helpers import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin_user, login

# ---------------------------------------------------------------------------
# Setup-Helper
# ---------------------------------------------------------------------------


def _create_server(app: Flask, name: str = "srv-detail") -> int:
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


def _create_tag(app: Flask, name: str = "prod", color: str = "#6b7280") -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            tag = sess.execute(select(Tag).where(Tag.name == name)).scalar_one_or_none()
            if tag is None:
                tag = Tag(name=name, color=color)
                sess.add(tag)
                sess.flush()
            tid = tag.id
            sess.commit()
            return tid
        finally:
            sess.close()


def _audit_actions(app: Flask) -> list[str]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return [e.action for e in sess.execute(select(AuditEvent)).scalars().all()]
        finally:
            sess.close()


def _server_tags(app: Flask, server_id: int) -> list[str]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            links = (
                sess.execute(select(ServerTag).where(ServerTag.server_id == server_id))
                .scalars()
                .all()
            )
            tags: list[str] = []
            for link in links:
                tag = sess.execute(select(Tag).where(Tag.id == link.tag_id)).scalar_one()
                tags.append(tag.name)
            return tags
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Auth/Show
# ---------------------------------------------------------------------------


def test_detail_redirects_when_not_logged_in(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    client = db_app.test_client()
    resp = client.get(f"/servers/{sid}", follow_redirects=False)
    assert resp.status_code in (301, 302), resp.status_code
    assert "/login" in resp.headers.get("Location", "")


def test_detail_shows_server_for_admin(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-visible")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    assert "srv-visible" in body


def test_detail_returns_404_for_unknown_server(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/servers/999999")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tag-Add
# ---------------------------------------------------------------------------


def test_add_existing_tag_succeeds_and_audits(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    _create_tag(db_app, name="prod")

    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), resp.status_code
    assert "prod" in _server_tags(db_app, sid)
    assert "server.tag.added" in _audit_actions(db_app)


def test_add_nonexistent_tag_does_nothing(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "ghost"},
        follow_redirects=False,
    )
    # Redirect oder 200 (HTMX), aber kein DB-Insert und kein Audit.
    assert resp.status_code in (200, 302, 303)
    assert _server_tags(db_app, sid) == []
    assert "server.tag.added" not in _audit_actions(db_app)


def test_add_tag_with_invalid_regex_rejected(db_app: Flask) -> None:
    """Eingabe `Foo Bar` matched TAG_NAME_REGEX nicht — nichts wird geschrieben."""
    create_admin_user(db_app)
    sid = _create_server(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "Foo Bar"},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 302, 303)
    assert _server_tags(db_app, sid) == []
    assert "server.tag.added" not in _audit_actions(db_app)


def test_add_existing_tag_twice_is_idempotent(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)

    r1 = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        follow_redirects=False,
    )
    r2 = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        follow_redirects=False,
    )
    assert r1.status_code in (200, 302, 303)
    assert r2.status_code in (200, 302, 303)
    # Tag-Mapping bleibt 1x.
    assert _server_tags(db_app, sid) == ["prod"]
    # Audit-Event nur einmal.
    actions = _audit_actions(db_app)
    assert actions.count("server.tag.added") == 1


def test_add_tag_lowercases_input(db_app: Flask) -> None:
    """Input `PROD` wird auf `prod` normalisiert."""
    create_admin_user(db_app)
    sid = _create_server(db_app)
    _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "PROD"},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 302, 303)
    assert "prod" in _server_tags(db_app, sid)


# ---------------------------------------------------------------------------
# Tag-Remove
# ---------------------------------------------------------------------------


def test_remove_tag_succeeds_and_audits(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    tid = _create_tag(db_app, name="prod")

    # Erst Tag setzen.
    client = db_app.test_client()
    login(client)
    client.post(f"/servers/{sid}/tags/add", data={"tag_name": "prod"})
    assert "prod" in _server_tags(db_app, sid)

    resp = client.post(f"/servers/{sid}/tags/{tid}/remove", follow_redirects=False)
    assert resp.status_code in (200, 302, 303)
    assert _server_tags(db_app, sid) == []
    assert "server.tag.removed" in _audit_actions(db_app)


def test_remove_nonexistent_link_is_safe(db_app: Flask) -> None:
    """Tag existiert, ist aber dem Server nicht zugewiesen → no-op."""
    create_admin_user(db_app)
    sid = _create_server(db_app)
    tid = _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)
    resp = client.post(f"/servers/{sid}/tags/{tid}/remove", follow_redirects=False)
    assert resp.status_code in (200, 302, 303)
    assert "server.tag.removed" not in _audit_actions(db_app)


# ---------------------------------------------------------------------------
# HTMX-Pfad
# ---------------------------------------------------------------------------


def test_add_tag_with_htmx_header_returns_fragment(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        headers={"HX-Request": "true"},
    )
    # HTMX-Response: 200 + HTML-Fragment (kein Redirect).
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    # Fragment beginnt mit `tag-editor-wrap`-Container.
    assert "tag-editor-wrap" in body
    # Kein vollstaendiges `<html`-Dokument.
    assert "<html" not in body.lower()


def test_remove_tag_with_htmx_header_returns_fragment(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app)
    tid = _create_tag(db_app, name="prod")
    client = db_app.test_client()
    login(client)
    # Erst zuweisen.
    client.post(f"/servers/{sid}/tags/add", data={"tag_name": "prod"})

    resp = client.post(
        f"/servers/{sid}/tags/{tid}/remove",
        headers={"HX-Request": "true"},
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "tag-editor-wrap" in body
    assert "<html" not in body.lower()


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


def test_add_tag_without_csrf_token_is_rejected(csrf_enabled_db_app: Flask) -> None:
    """Bei aktivem CSRF-Schutz muss der POST ohne Token abgewiesen werden."""
    create_admin_user(csrf_enabled_db_app)
    sid = _create_server(csrf_enabled_db_app)
    _create_tag(csrf_enabled_db_app, name="prod")

    client = csrf_enabled_db_app.test_client()
    # Login via Form — der Form-Endpoint zieht den Token aus der GET-Seite,
    # was wir manuell tun muessen.
    login_get = client.get("/login")
    assert login_get.status_code == 200
    # Token extrahieren.
    import re

    match = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', login_get.data)
    assert match is not None, "csrf_token nicht im /login-Form gefunden"
    token = match.group(1).decode()

    resp_login = client.post(
        "/login",
        data={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD,
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert resp_login.status_code == 302, resp_login.get_data(as_text=True)[:400]

    # Add-Request OHNE Token — sollte abgewiesen werden (Redirect mit Flash
    # oder 400). Implementer-Code: bei ungueltigem CSRF gibt es einen
    # Redirect mit Flash-Message. Wir akzeptieren beide vernuenftigen
    # Verhaltensweisen, schliessen aber definitiv den Success-Pfad aus.
    resp = client.post(
        f"/servers/{sid}/tags/add",
        data={"tag_name": "prod"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303, 400), resp.get_data(as_text=True)[:400]
    # DB ist NICHT veraendert worden.
    assert _server_tags(csrf_enabled_db_app, sid) == []
    assert "server.tag.added" not in _audit_actions(csrf_enabled_db_app)


# ---------------------------------------------------------------------------
# Block E: Findings-Section (drei View-Modi, Filter, Sortierung, HTMX-Partial)
# ---------------------------------------------------------------------------


_BLOCK_E_TS = datetime(2026, 5, 1, 10, 0, tzinfo=UTC)


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    package_name: str = "openssl",
    severity: Severity = Severity.HIGH,
    finding_class: FindingClass = FindingClass.OS_PKGS,
    status: FindingStatus = FindingStatus.OPEN,
    is_kev: bool = False,
    epss_score: float | None = None,
    cvss_v3_score: float | None = None,
    title: str | None = None,
    first_seen_offset_h: int = 0,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            ts = _BLOCK_E_TS + timedelta(hours=first_seen_offset_h)
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=finding_class,
                identifier_key=identifier_key,
                package_name=package_name,
                installed_version="1.0",
                severity=severity,
                title=title,
                cvss_v3_score=cvss_v3_score,
                epss_score=epss_score,
                is_kev=is_kev,
                attack_vector=AttackVector.UNKNOWN,
                status=status,
                first_seen_at=ts,
                last_seen_at=ts,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def _setup_findings_server(app: Flask, name: str = "srv-findings") -> int:
    sid = _create_server(app, name=name)
    return sid


def test_show_default_renders_list_mode(db_app: Flask) -> None:
    """Default-`mode=list` rendert eine Tabelle.

    ADR-0025 §2/§3 (Block Q Phase B/C): Server-Detail rendert Findings
    default lazy (Application-Group-Cards collapsed). `?flat=1` erzwingt
    den flachen Tabellen-Pfad fuer Markup-Tests, die direkt die Tabelle
    und CVE-Row-Markup pruefen.
    """
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-mode-list")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D001")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?flat=1")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "<table" in body
    assert "CVE-2026-D001" in body


def test_legacy_group_mode_url_renders_list(db_app: Flask) -> None:
    """ADR-0025 (1): `?mode=group` wird still ignoriert; List-Body rendert.

    Kein Redirect (kein 302), kein 4xx/5xx, kein Marker des entfernten
    Group-Templates. Der Standard-List-Body muss sichtbar sein
    (`id="findings-section"`).
    """
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-legacy-mode-group")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D101", package_name="openssl")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?mode=group")
    assert resp.status_code == 200, resp.status_code
    body = resp.get_data(as_text=True)
    # Legacy-Template-Marker dürfen nicht mehr im Output sein.
    assert 'data-test="mode-group"' not in body
    assert 'data-test="mode-diff"' not in body
    # Standard-List-Body rendert.
    assert 'id="findings-section"' in body


def test_legacy_diff_mode_url_renders_list(db_app: Flask) -> None:
    """ADR-0025 (1): `?mode=diff` wird still ignoriert; List-Body rendert."""
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-legacy-mode-diff")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D102", package_name="openssl")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?mode=diff")
    assert resp.status_code == 200, resp.status_code
    body = resp.get_data(as_text=True)
    assert 'data-test="mode-group"' not in body
    assert 'data-test="mode-diff"' not in body
    assert 'id="findings-section"' in body


def test_show_filter_status_acknowledged_filters(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-filter-status")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D201", status=FindingStatus.OPEN)
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-D202",
        status=FindingStatus.ACKNOWLEDGED,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?status=acknowledged")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "CVE-2026-D202" in body
    assert "CVE-2026-D201" not in body


def test_show_filter_class_os_pkgs_only_shows_os(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-filter-class")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-D301",
        package_name="openssl",
        finding_class=FindingClass.OS_PKGS,
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-D302",
        package_name="libfoo",
        finding_class=FindingClass.LANG_PKGS,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?class=os-pkgs")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "CVE-2026-D301" in body
    assert "CVE-2026-D302" not in body


def test_show_filter_kev_only(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-filter-kev")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D401", is_kev=False)
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D402", is_kev=True)
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?kev_only=1")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "CVE-2026-D402" in body
    assert "CVE-2026-D401" not in body


def test_show_search_q_filters(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-filter-q")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D501", package_name="stdlib-foo")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D502", package_name="nginx")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?q=stdlib")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "CVE-2026-D501" in body
    assert "CVE-2026-D502" not in body


def test_show_default_sort_renders_both_findings(db_app: Flask) -> None:
    """ADR-0018: Default-Sort der Detail-Tabelle ist `sev desc` (Spalten-Sort).

    Block K hat das §15-Default-Order (KEV->EPSS->CVSS->Severity->first_seen) durch
    den Server-Side-Spalten-Sort ersetzt — der View-Code reicht jetzt immer
    `view_filter.sort` (Default `sev`) an `list_findings` weiter. Tiebreak
    bei gleicher Severity ist `identifier_key asc`, NICHT mehr `is_kev desc`.

    Wir testen entsprechend nur dass beide Findings im Output stehen — die
    KEV-zuerst-Logik gehoert jetzt zum CVSS-/EPSS-Sort, nicht zum Default.
    """
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-sort")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-D601",
        is_kev=False,
        epss_score=0.9,
        cvss_v3_score=9.0,
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-D602",
        is_kev=True,
        epss_score=0.1,
        cvss_v3_score=4.0,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?class=os-pkgs")
    body = resp.get_data(as_text=True)
    assert "CVE-2026-D601" in body
    assert "CVE-2026-D602" in body


def test_show_with_htmx_header_returns_partial_only(db_app: Flask) -> None:
    """Bei `HX-Request: true` rendert der Endpoint nur das Findings-Fragment.

    ADR-0025 §2/§3: ohne `?flat=1` waere das Initial-HTML die Group-Card-
    Ansicht ohne Finding-Rows — `CVE-2026-D701` wuerde lazy ueber HTMX
    nachgeladen. Hier prueftn wir, dass der Fragment-Pfad funktioniert UND
    Markup mit Row-Inhalt liefert, also `?flat=1`.
    """
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-htmx")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D701")
    client = db_app.test_client()
    login(client)
    resp = client.get(
        f"/servers/{sid}?flat=1",
        headers={"HX-Request": "true"},
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Fragment: kein vollstaendiges `<html>`.
    assert "<html" not in body.lower()
    # Aber der Findings-Section-Container muss da sein.
    assert "findings-section" in body
    assert "CVE-2026-D701" in body


def test_show_counts_header_sums_match_total(db_app: Flask) -> None:
    """Open + Acknowledged + Resolved == Total."""
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-counts")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D801", status=FindingStatus.OPEN)
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-D802",
        status=FindingStatus.ACKNOWLEDGED,
    )
    _add_finding(
        db_app, server_id=sid, identifier_key="CVE-2026-D803", status=FindingStatus.RESOLVED
    )
    client = db_app.test_client()
    login(client)
    # Mode=list, status=all -> Counts spiegelt alle Status.
    resp = client.get(f"/servers/{sid}?status=all")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Die Counts-Badges enthalten die Zahlen — wir verifizieren ueber die DB.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            from app.services.findings_query import FindingsFilter, count_findings

            counts = count_findings(sess, sid, FindingsFilter(status="all"))
        finally:
            sess.close()
    assert counts["open"] + counts["acknowledged"] + counts["resolved"] == counts["total"]
    # Sanity: die Zahlen sind auch im HTML.
    assert str(counts["open"]) in body
    assert str(counts["acknowledged"]) in body
    assert str(counts["resolved"]) in body


def test_show_invalid_mode_falls_back_to_list(db_app: Flask) -> None:
    """Ein bogus `mode=xy` darf nicht 422 ergeben — wir fallen auf list zurueck.

    ADR-0025 §2/§3: List-Modus default lazy in Group-Cards; `?flat=1`
    erzwingt die flache Tabelle, deren `<table>`-Tag wir hier explizit
    pruefen wollen.
    """
    create_admin_user(db_app)
    sid = _setup_findings_server(db_app, "srv-mode-bad")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2026-D901")
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}?mode=xy&flat=1")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # list-Layout: Tabelle.
    assert "<table" in body
