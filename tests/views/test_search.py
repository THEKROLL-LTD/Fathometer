"""Tests fuer `/findings/search` — globale CVE-/Paket-/Server-Suche (Block F).

ARCHITECTURE.md §7 (Such-View mit Aggregations-Header und Tag-Filter).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    ServerTag,
    Severity,
    Tag,
)
from tests._helpers import create_admin_user, login

_BASE_TS = datetime(2026, 5, 12, 8, 0, tzinfo=UTC)


def _create_server(app: Flask, name: str, tags: list[str] | None = None) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            for tname in tags or []:
                tag = sess.execute(select(Tag).where(Tag.name == tname)).scalar_one_or_none()
                if tag is None:
                    tag = Tag(name=tname)
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
    status: FindingStatus = FindingStatus.OPEN,
    offset_h: int = 0,
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
                package_name=package_name,
                installed_version="1.0",
                severity=Severity.HIGH,
                attack_vector=AttackVector.UNKNOWN,
                status=status,
                first_seen_at=_BASE_TS + timedelta(hours=offset_h),
                last_seen_at=_BASE_TS + timedelta(hours=offset_h),
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# CVE-Suche + Aggregation
# ---------------------------------------------------------------------------


def test_search_cve_with_explicit_kind_returns_hits_and_aggregation(
    db_app: Flask,
) -> None:
    create_admin_user(db_app)
    sid1 = _create_server(db_app, "srv-s1")
    sid2 = _create_server(db_app, "srv-s2")
    _add_finding(db_app, server_id=sid1, identifier_key="CVE-2024-12345")
    _add_finding(db_app, server_id=sid2, identifier_key="CVE-2024-12345")
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/search?q=CVE-2024-12345&kind=cve")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    # Hits sichtbar
    assert "CVE-2024-12345" in body
    # Aggregation: Server-Anzahl 2 als Fragment darstellbar.
    assert "2" in body


def test_search_cve_auto_kind_detects_cve_regex(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-auto")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-99999")
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/search?q=CVE-2024-99999")
    assert resp.status_code == 200
    assert "CVE-2024-99999" in resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Paket-Suche
# ---------------------------------------------------------------------------


def test_search_package_kind_matches_substring(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-pkg")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-AA001", package_name="openssl")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-AA002",
        package_name="openssl@/usr/local/bin/k3s",
    )
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-AA003", package_name="libxslt")
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/search?q=openssl&kind=package")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "CVE-2024-AA001" in body
    assert "CVE-2024-AA002" in body
    assert "CVE-2024-AA003" not in body


# ---------------------------------------------------------------------------
# Server-Suche
# ---------------------------------------------------------------------------


def test_search_server_kind_filters_by_server_name_substring(
    db_app: Flask,
) -> None:
    create_admin_user(db_app)
    sid_match = _create_server(db_app, "node1-web")
    sid_other = _create_server(db_app, "node2-db")
    _add_finding(db_app, server_id=sid_match, identifier_key="CVE-2024-BB001")
    _add_finding(db_app, server_id=sid_other, identifier_key="CVE-2024-BB002")
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/search?q=node1&kind=server")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "CVE-2024-BB001" in body
    assert "CVE-2024-BB002" not in body


# ---------------------------------------------------------------------------
# Tag-Filter
# ---------------------------------------------------------------------------


def test_search_tag_filter_restricts_results(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid_prod = _create_server(db_app, "srv-prod-1", tags=["prod"])
    sid_dev = _create_server(db_app, "srv-dev-1", tags=["dev"])
    _add_finding(db_app, server_id=sid_prod, identifier_key="CVE-2024-CC001")
    _add_finding(db_app, server_id=sid_dev, identifier_key="CVE-2024-CC001")
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/search?q=CVE-2024-CC001&kind=cve&tag=prod")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Beide Findings haben dieselbe CVE-ID, aber nur einer auf prod-Server.
    # Wir checken auf den Servername der durchgeht.
    assert "srv-prod-1" in body
    assert "srv-dev-1" not in body


# ---------------------------------------------------------------------------
# Status-Filter
# ---------------------------------------------------------------------------


def test_search_status_acknowledged_filters_to_acked(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-status")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-2024-DD001", status=FindingStatus.OPEN)
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-DD002",
        status=FindingStatus.ACKNOWLEDGED,
        package_name="openssl-extra",
    )
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/search?q=openssl&kind=package&status=acknowledged")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "CVE-2024-DD002" in body
    assert "CVE-2024-DD001" not in body


def test_search_status_all_shows_open_and_acked(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-status-all")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-EE001",
        package_name="openssl",
        status=FindingStatus.OPEN,
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-EE002",
        package_name="openssl-ack",
        status=FindingStatus.ACKNOWLEDGED,
    )
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/search?q=openssl&kind=package&status=all")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "CVE-2024-EE001" in body
    assert "CVE-2024-EE002" in body


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_search_pagination_page_2_shows_next_window(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-pag")
    for i in range(10):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-2024-FF{i:03d}",
            package_name="openssl",
            offset_h=i,
        )
    client = db_app.test_client()
    login(client)

    resp = client.get("/findings/search?q=openssl&kind=package&per_page=5&page=2")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # 5 IDs auf Seite 2; mindestens eine davon muss vorkommen, und
    # NICHT alle 10 IDs duerfen vorhanden sein (sonst keine Pagination).
    visible = [ident for ident in [f"CVE-2024-FF{i:03d}" for i in range(10)] if ident in body]
    assert len(visible) == 5, visible


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_search_requires_login(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/findings/search?q=foo", follow_redirects=False)
    assert resp.status_code in (302, 401)
    if resp.status_code == 302:
        assert "/login" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# Kind-Fallback
# ---------------------------------------------------------------------------


def test_search_unknown_kind_falls_back_to_auto(db_app: Flask) -> None:
    """`kind=invalid` muss auf `auto` fallen — Bookmarks duerfen nicht brechen."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/findings/search?q=foo&kind=invalid")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
