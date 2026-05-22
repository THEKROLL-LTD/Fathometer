"""Tests fuer `POST /api/findings/bulk-acknowledge` (Block F).

Deckt beide Flavors (`finding_ids` und `match`), dry-run vs. apply, die
Audit-Event-Properties, sowie XOR-Validierung, Auth und CSRF.

ARCHITECTURE.md §6 (Endpoint), §13 (Action `finding.bulk_acknowledged`).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    AttackVector,
    AuditEvent,
    Finding,
    FindingClass,
    FindingNote,
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


_BASE_TS = datetime(2026, 5, 10, 8, 0, tzinfo=UTC)


def _create_server(app: Flask, name: str, tags: list[str] | None = None) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            for tag_name in tags or []:
                tag = sess.execute(select(Tag).where(Tag.name == tag_name)).scalar_one_or_none()
                if tag is None:
                    tag = Tag(name=tag_name)
                    sess.add(tag)
                    sess.flush()
                sess.add(ServerTag(server_id=sid, tag_id=tag.id))
            sess.commit()
            return sid
        finally:
            sess.close()


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    package_name: str = "openssl",
    severity: Severity = Severity.HIGH,
    finding_class: FindingClass = FindingClass.OS_PKGS,
    status: FindingStatus = FindingStatus.OPEN,
    offset_h: int = 0,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            ts = _BASE_TS + timedelta(hours=offset_h)
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=finding_class,
                identifier_key=identifier_key,
                package_name=package_name,
                installed_version="1.0",
                severity=severity,
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


def _get_finding(app: Flask, fid: int) -> Finding:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return sess.execute(select(Finding).where(Finding.id == fid)).scalar_one()
        finally:
            sess.close()


def _get_notes(app: Flask, finding_id: int) -> list[FindingNote]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(select(FindingNote).where(FindingNote.finding_id == finding_id))
                .scalars()
                .all()
            )
        finally:
            sess.close()


def _bulk_events(app: Flask) -> list[AuditEvent]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(
                    select(AuditEvent).where(AuditEvent.action == "finding.bulk_acknowledged")
                )
                .scalars()
                .all()
            )
        finally:
            sess.close()


# ===========================================================================
# Flavor A — finding_ids
# ===========================================================================


def test_dry_run_with_finding_ids_returns_counts_and_does_not_write(
    db_app: Flask,
) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-a")
    ids = [
        _add_finding(db_app, server_id=sid, identifier_key=f"CVE-2026-FA{i:03d}") for i in range(3)
    ]
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": ids, "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["dry_run"] is True
    assert body["count"] == 3
    assert body["server_count"] == 1
    assert sorted(body["finding_ids"]) == sorted(ids)
    # DB unveraendert.
    for fid in ids:
        f = _get_finding(db_app, fid)
        assert f.status == FindingStatus.OPEN
        assert f.acknowledged_at is None
    assert _bulk_events(db_app) == []


def test_apply_with_finding_ids_acknowledges_all(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-a-apply")
    ids = [
        _add_finding(db_app, server_id=sid, identifier_key=f"CVE-2026-FB{i:03d}") for i in range(3)
    ]
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": ids, "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["dry_run"] is False
    assert body["applied"] is True
    assert body["count"] == 3
    assert body["skipped"] == 0

    for fid in ids:
        f = _get_finding(db_app, fid)
        assert f.status == FindingStatus.ACKNOWLEDGED, fid
        assert f.acknowledged_at is not None
        assert f.acknowledged_by is not None

    events = _bulk_events(db_app)
    assert len(events) == 1, [e.action for e in events]
    ev = events[0]
    assert ev.event_metadata is not None
    assert ev.event_metadata["count"] == 3
    assert sorted(ev.event_metadata["finding_ids"]) == sorted(ids)


def test_apply_with_comment_creates_notes(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-a-comment")
    ids = [
        _add_finding(db_app, server_id=sid, identifier_key=f"CVE-2026-FC{i:03d}") for i in range(3)
    ]
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": ids, "dry_run": False, "comment": "Patch-Window"},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)

    for fid in ids:
        notes = _get_notes(db_app, fid)
        assert len(notes) == 1, fid
        assert notes[0].author == "system-bulk-ack", notes[0].author
        assert notes[0].text == "Patch-Window"


def test_apply_without_comment_does_not_create_notes(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-a-nocomment")
    ids = [
        _add_finding(db_app, server_id=sid, identifier_key=f"CVE-2026-FD{i:03d}") for i in range(2)
    ]
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": ids, "dry_run": False},
    )
    assert resp.status_code == 200
    for fid in ids:
        assert _get_notes(db_app, fid) == []


def test_apply_mix_of_open_and_acknowledged_skips_already_acked(
    db_app: Flask,
) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-a-mix")
    open_ids = [
        _add_finding(db_app, server_id=sid, identifier_key=f"CVE-2026-FE{i:03d}") for i in range(2)
    ]
    ack_id = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-FE-ACK",
        status=FindingStatus.ACKNOWLEDGED,
    )
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": [*open_ids, ack_id], "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 2
    assert body["skipped"] == 1
    assert sorted(body["finding_ids"]) == sorted(open_ids)

    events = _bulk_events(db_app)
    assert len(events) == 1
    md = events[0].event_metadata
    assert md is not None
    assert sorted(md["finding_ids"]) == sorted(open_ids)
    assert md["skipped"] == 1


# ===========================================================================
# Flavor B — match-Kriterium
# ===========================================================================


def test_match_by_cve_dry_run_aggregates_across_servers(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid1 = _create_server(db_app, "srv-b1")
    sid2 = _create_server(db_app, "srv-b2")
    id1 = _add_finding(db_app, server_id=sid1, identifier_key="CVE-2024-12345")
    id2 = _add_finding(db_app, server_id=sid2, identifier_key="CVE-2024-12345")
    # Andere CVE darf nicht gematched werden.
    _add_finding(db_app, server_id=sid1, identifier_key="CVE-2024-99999")
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"match": {"cve_id": "CVE-2024-12345"}, "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["dry_run"] is True
    assert body["count"] == 2
    assert body["server_count"] == 2
    assert sorted(body["finding_ids"]) == sorted([id1, id2])


def test_match_by_cve_apply_acknowledges_both(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid1 = _create_server(db_app, "srv-b1-apply")
    sid2 = _create_server(db_app, "srv-b2-apply")
    id1 = _add_finding(db_app, server_id=sid1, identifier_key="CVE-2024-22222")
    id2 = _add_finding(db_app, server_id=sid2, identifier_key="CVE-2024-22222")
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"match": {"cve_id": "CVE-2024-22222"}, "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 2

    for fid in (id1, id2):
        assert _get_finding(db_app, fid).status == FindingStatus.ACKNOWLEDGED, fid

    events = _bulk_events(db_app)
    assert len(events) == 1
    assert sorted(events[0].event_metadata["finding_ids"]) == sorted([id1, id2])  # type: ignore[index]


def test_match_with_tag_filter_restricts_to_tagged_servers(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid_prod = _create_server(db_app, "srv-prod", tags=["prod"])
    sid_dev = _create_server(db_app, "srv-dev", tags=["dev"])
    prod_id = _add_finding(db_app, server_id=sid_prod, identifier_key="CVE-2024-33333")
    _add_finding(db_app, server_id=sid_dev, identifier_key="CVE-2024-33333")
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"match": {"cve_id": "CVE-2024-33333", "tag": "prod"}, "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 1
    assert body["finding_ids"] == [prod_id]


def test_match_package_without_at_matches_disambiguated_variants(
    db_app: Flask,
) -> None:
    """ADR-0011: `package_name='openssl'` matched `openssl` und `openssl@/x`."""
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-pkg-disambig")
    id_plain = _add_finding(
        db_app, server_id=sid, identifier_key="CVE-2024-44441", package_name="openssl"
    )
    id_target = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-44442",
        package_name="openssl@/usr/local/bin/k3s",
    )
    # Anderes Paket darf nicht gematched werden.
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-44443", package_name="libxslt")
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"match": {"package_name": "openssl"}, "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert sorted(body["finding_ids"]) == sorted([id_plain, id_target])


def test_match_package_with_at_uses_exact_match(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-pkg-exact")
    id_target = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-55551",
        package_name="openssl@/usr/local/bin/k3s",
    )
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-55552", package_name="openssl")
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={
            "match": {"package_name": "openssl@/usr/local/bin/k3s"},
            "dry_run": True,
        },
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["finding_ids"] == [id_target]


def test_match_status_default_is_open(db_app: Flask) -> None:
    """Ohne explizites `status` matched die Bulk-Match-Query nur OPEN-Findings."""
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-status-default")
    open_id = _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-66661")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-66661",
        package_name="other",
        status=FindingStatus.ACKNOWLEDGED,
    )
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"match": {"cve_id": "CVE-2024-66661"}, "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["finding_ids"] == [open_id]


# ===========================================================================
# Validation / Auth / CSRF
# ===========================================================================


def test_both_finding_ids_and_match_returns_422(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={
            "finding_ids": [1, 2],
            "match": {"cve_id": "CVE-2024-77777"},
            "dry_run": True,
        },
    )
    assert resp.status_code == 422, resp.get_data(as_text=True)


def test_neither_finding_ids_nor_match_returns_422(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.post("/api/findings/bulk-acknowledge", json={"dry_run": True})
    assert resp.status_code == 422, resp.get_data(as_text=True)


def test_invalid_cve_id_regex_returns_422(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"match": {"cve_id": "CVE-foo"}, "dry_run": True},
    )
    assert resp.status_code == 422, resp.get_data(as_text=True)


def test_unauthenticated_request_is_rejected(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": [1], "dry_run": True},
    )
    # Login-Required liefert 401 oder Redirect zum Login, abhaengig von
    # flask_login-Konfiguration. JSON-Endpoints sollten 401 sein, aber
    # historisch redirected flask_login auch JSON-Calls.
    assert resp.status_code in (401, 302), resp.status_code
    if resp.status_code == 302:
        assert "/login" in resp.headers.get("Location", "")


def test_csrf_required_with_csrf_enabled_app(
    csrf_enabled_db_app: Flask,
) -> None:
    """Bei aktivem CSRF-Schutz wird ein POST ohne Token abgewiesen.

    Flask-WTF akzeptiert das CSRF-Token im `X-CSRFToken`-Header. Ohne den
    Header darf der Bulk-Endpoint nicht writen.
    """
    create_admin_user(csrf_enabled_db_app)
    sid = _create_server(csrf_enabled_db_app, "srv-csrf")
    fid = _add_finding(csrf_enabled_db_app, server_id=sid, identifier_key="CVE-2024-88888")
    client = csrf_enabled_db_app.test_client()

    # Login via Form mit CSRF-Token.
    login_get = client.get("/login")
    assert login_get.status_code == 200
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

    # Bulk-Apply OHNE X-CSRFToken-Header.
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": [fid], "dry_run": False},
    )
    assert resp.status_code in (400, 403), resp.get_data(as_text=True)[:400]
    # Finding ist nicht acked.
    assert _get_finding(csrf_enabled_db_app, fid).status == FindingStatus.OPEN, (
        "Finding wurde trotz CSRF-Fehler veraendert"
    )


_ = Any
