"""Tests fuer das Dashboard `/` (Block D).

Deckt Card-Rendering, "Aufmerksamkeit noetig"-Sektion, Tag-/KEV-/Stale-
Filter und die Severity-Aggregation ab. Findings werden direkt via ORM
angelegt, um den Ingest-Service nicht im Spiel zu haben.
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

# ---------------------------------------------------------------------------
# Setup-Helper
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _create_server(
    app: Flask,
    *,
    name: str,
    last_scan_at: datetime | None = None,
    expected_scan_interval_h: int = 24,
    retired_at: datetime | None = None,
    revoked_at: datetime | None = None,
    trivy_db_updated_at: datetime | None = None,
    tags: list[str] | None = None,
) -> int:
    """Legt einen Server inkl. Tags direkt via ORM an, liefert die ID."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=expected_scan_interval_h,
                last_scan_at=last_scan_at,
                retired_at=retired_at,
                revoked_at=revoked_at,
                trivy_db_updated_at=trivy_db_updated_at,
            )
            sess.add(srv)
            sess.flush()
            srv_id = srv.id

            if tags:
                for tag_name in tags:
                    tag = sess.execute(select(Tag).where(Tag.name == tag_name)).scalar_one_or_none()
                    if tag is None:
                        tag = Tag(name=tag_name, color="#6b7280")
                        sess.add(tag)
                        sess.flush()
                    sess.add(ServerTag(server_id=srv_id, tag_id=tag.id))

            sess.commit()
            return srv_id
        finally:
            sess.close()


def _card_grid_section(body: str) -> str:
    """Extrahiert nur den Karten-Grid-Block aus dem Dashboard.

    Die "Aufmerksamkeit noetig"-Sektion und der Filter listen Server-Namen
    auch ausserhalb der gefilterten Card-Liste — wir wollen nur die Cards
    pruefen, wenn wir Filter-Tests machen."""
    marker = '<div class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">'
    idx = body.find(marker)
    if idx == -1:
        return ""
    return body[idx:]


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    severity: Severity,
    status: FindingStatus = FindingStatus.OPEN,
    is_kev: bool = False,
    package_name: str = "pkg",
) -> int:
    """Legt ein Finding direkt via ORM an."""
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
                severity=severity,
                status=status,
                is_kev=is_kev,
                attack_vector=AttackVector.UNKNOWN,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Auth-Pfad
# ---------------------------------------------------------------------------


def test_dashboard_redirects_when_not_logged_in(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302), resp.status_code
    assert "/login" in resp.headers.get("Location", "")


def test_dashboard_renders_empty_state_when_no_servers(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    assert "Noch keine Server" in body, body[:600]


# ---------------------------------------------------------------------------
# Card-Rendering + Aufmerksamkeit
# ---------------------------------------------------------------------------


def test_dashboard_renders_three_cards_with_kev_and_stale(db_app: Flask) -> None:
    create_admin_user(db_app)
    now = _now()

    # 1) Normaler Server, frischer Scan.
    _create_server(
        db_app,
        name="srv-normal",
        last_scan_at=now - timedelta(hours=2),
        trivy_db_updated_at=now - timedelta(hours=2),
    )
    # 2) KEV-Server, ebenfalls frisch.
    sid_kev = _create_server(
        db_app,
        name="srv-kev",
        last_scan_at=now - timedelta(hours=2),
        trivy_db_updated_at=now - timedelta(hours=2),
    )
    _add_finding(
        db_app,
        server_id=sid_kev,
        identifier_key="CVE-2024-0001",
        severity=Severity.CRITICAL,
        is_kev=True,
    )
    # 3) Stale-Server (last_scan_at = -50h, interval 24h).
    _create_server(
        db_app,
        name="srv-stale",
        last_scan_at=now - timedelta(hours=50),
        expected_scan_interval_h=24,
        trivy_db_updated_at=now - timedelta(hours=2),
    )

    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Drei Karten — Namen tauchen alle auf.
    assert "srv-normal" in body
    assert "srv-kev" in body
    assert "srv-stale" in body

    # "Aufmerksamkeit noetig"-Sektion sichtbar.
    assert "Aufmerksamkeit noetig" in body

    # KEV-Badge mit Counter (KEV 1) sichtbar.
    assert "KEV 1" in body

    # Stale-Badge sichtbar.
    assert "stale" in body

    # Die Werte 1 — assert kev_open_count, severity. Indirektes Pruefen
    # via Server-Status: keine FAIL-Strings.
    assert resp.status_code == 200, body[:600]
    # Filter-Header sollte "3 Server sichtbar" anzeigen.
    assert "3 Server sichtbar" in body


def test_dashboard_kev_server_appears_in_attention_section(db_app: Flask) -> None:
    create_admin_user(db_app)
    now = _now()
    sid = _create_server(
        db_app,
        name="srv-kev-only",
        last_scan_at=now - timedelta(hours=2),
        trivy_db_updated_at=now - timedelta(hours=2),
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-9999",
        severity=Severity.HIGH,
        is_kev=True,
    )

    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    assert "Aufmerksamkeit noetig" in body
    assert "KEV-betroffen" in body


# ---------------------------------------------------------------------------
# Tag-Filter
# ---------------------------------------------------------------------------


def test_dashboard_tags_or_filter_shows_matching_servers(db_app: Flask) -> None:
    """Filter wirkt auf das Card-Grid — die Aufmerksamkeits-Sektion (oben)
    zeigt unabhaengig vom Filter alle "wichtigen" Server. Wir pruefen
    daher nur den Card-Grid-Bereich."""
    now = _now()
    create_admin_user(db_app)
    _create_server(
        db_app, name="srv-prod", tags=["prod"], last_scan_at=now, trivy_db_updated_at=now
    )
    _create_server(db_app, name="srv-web", tags=["web"], last_scan_at=now, trivy_db_updated_at=now)
    _create_server(
        db_app,
        name="srv-other",
        tags=["staging"],
        last_scan_at=now,
        trivy_db_updated_at=now,
    )

    client = db_app.test_client()
    login(client)
    resp = client.get("/?tags=prod")
    body = resp.get_data(as_text=True)
    grid = _card_grid_section(body)
    assert "srv-prod" in grid
    assert "srv-web" not in grid
    assert "srv-other" not in grid


def test_dashboard_tags_or_mode_matches_any(db_app: Flask) -> None:
    now = _now()
    create_admin_user(db_app)
    _create_server(
        db_app,
        name="srv-only-prod",
        tags=["prod"],
        last_scan_at=now,
        trivy_db_updated_at=now,
    )
    _create_server(
        db_app,
        name="srv-only-web",
        tags=["web"],
        last_scan_at=now,
        trivy_db_updated_at=now,
    )
    _create_server(
        db_app,
        name="srv-staging",
        tags=["staging"],
        last_scan_at=now,
        trivy_db_updated_at=now,
    )

    client = db_app.test_client()
    login(client)
    resp = client.get("/?tags=prod,web&tags_mode=or")
    body = resp.get_data(as_text=True)
    grid = _card_grid_section(body)
    assert "srv-only-prod" in grid
    assert "srv-only-web" in grid
    assert "srv-staging" not in grid


def test_dashboard_tags_and_mode_requires_all(db_app: Flask) -> None:
    now = _now()
    create_admin_user(db_app)
    _create_server(
        db_app,
        name="srv-both",
        tags=["prod", "web"],
        last_scan_at=now,
        trivy_db_updated_at=now,
    )
    _create_server(
        db_app,
        name="srv-only-prod",
        tags=["prod"],
        last_scan_at=now,
        trivy_db_updated_at=now,
    )
    _create_server(
        db_app,
        name="srv-only-web",
        tags=["web"],
        last_scan_at=now,
        trivy_db_updated_at=now,
    )

    client = db_app.test_client()
    login(client)
    resp = client.get("/?tags=prod,web&tags_mode=and")
    body = resp.get_data(as_text=True)
    grid = _card_grid_section(body)
    assert "srv-both" in grid
    assert "srv-only-prod" not in grid
    assert "srv-only-web" not in grid


def test_dashboard_invalid_tag_silently_ignored(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="srv-prod", tags=["prod"])
    client = db_app.test_client()
    login(client)
    # `invalid!tag` matched die Regex nicht → leere Tag-Liste → kein Filter.
    resp = client.get("/?tags=invalid!tag")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "srv-prod" in body


# ---------------------------------------------------------------------------
# KEV-/Stale-Filter
# ---------------------------------------------------------------------------


def test_dashboard_kev_only_shows_only_servers_with_open_kev(db_app: Flask) -> None:
    create_admin_user(db_app)
    now = _now()
    sid_kev = _create_server(db_app, name="srv-kev", last_scan_at=now, trivy_db_updated_at=now)
    _add_finding(
        db_app,
        server_id=sid_kev,
        identifier_key="CVE-2024-1111",
        severity=Severity.HIGH,
        is_kev=True,
    )
    _create_server(db_app, name="srv-clean", last_scan_at=now, trivy_db_updated_at=now)

    client = db_app.test_client()
    login(client)
    resp = client.get("/?kev_only=1")
    body = resp.get_data(as_text=True)
    grid = _card_grid_section(body)
    assert "srv-kev" in grid
    assert "srv-clean" not in grid


def test_dashboard_kev_only_hides_acknowledged_kev_findings(db_app: Flask) -> None:
    create_admin_user(db_app)
    now = _now()
    sid = _create_server(db_app, name="srv-ack-kev", last_scan_at=now, trivy_db_updated_at=now)
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2024-2222",
        severity=Severity.HIGH,
        is_kev=True,
        status=FindingStatus.ACKNOWLEDGED,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/?kev_only=1")
    body = resp.get_data(as_text=True)
    grid = _card_grid_section(body)
    # KEV-Counter zaehlt nur OPEN → der Server taucht im kev_only-Filter NICHT auf.
    assert "srv-ack-kev" not in grid


def test_dashboard_stale_only_shows_only_stale_servers(db_app: Flask) -> None:
    create_admin_user(db_app)
    now = _now()
    _create_server(
        db_app,
        name="srv-fresh",
        last_scan_at=now - timedelta(hours=2),
        expected_scan_interval_h=24,
        trivy_db_updated_at=now,
    )
    _create_server(
        db_app,
        name="srv-stale",
        last_scan_at=now - timedelta(hours=50),
        expected_scan_interval_h=24,
        trivy_db_updated_at=now,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/?stale_only=1")
    body = resp.get_data(as_text=True)
    grid = _card_grid_section(body)
    assert "srv-stale" in grid
    assert "srv-fresh" not in grid


# ---------------------------------------------------------------------------
# Severity-Aggregation
# ---------------------------------------------------------------------------


def test_dashboard_severity_counts_aggregate_correctly(db_app: Flask) -> None:
    create_admin_user(db_app)
    now = _now()
    sid = _create_server(db_app, name="srv-counts", last_scan_at=now, trivy_db_updated_at=now)
    # 2 CRITICAL OPEN, 3 HIGH OPEN, 1 HIGH ACKNOWLEDGED (zaehlt nicht).
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-A",
        severity=Severity.CRITICAL,
        package_name="pkg-a",
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-B",
        severity=Severity.CRITICAL,
        package_name="pkg-b",
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-C",
        severity=Severity.HIGH,
        package_name="pkg-c",
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-D",
        severity=Severity.HIGH,
        package_name="pkg-d",
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-E",
        severity=Severity.HIGH,
        package_name="pkg-e",
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-F",
        severity=Severity.HIGH,
        package_name="pkg-f",
        status=FindingStatus.ACKNOWLEDGED,
    )

    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    # Severity-Badges im Card-Partial: "crit 2" und "high 3".
    assert "crit 2" in body
    assert "high 3" in body
    # 5 offen.
    assert "5 offen" in body


# ---------------------------------------------------------------------------
# Retired/Revoked-Verhalten
# ---------------------------------------------------------------------------


def test_dashboard_retired_server_appears_but_not_in_attention(db_app: Flask) -> None:
    create_admin_user(db_app)
    now = _now()
    # Retired Server, last_scan_at=None — wuerde sonst als stale gelten.
    _create_server(
        db_app,
        name="srv-retired",
        last_scan_at=None,
        retired_at=now - timedelta(days=10),
    )
    # Plus ein normaler Server, damit die Attention-Sektion nicht eh leer ist.
    sid_kev = _create_server(
        db_app, name="srv-active-kev", last_scan_at=now, trivy_db_updated_at=now
    )
    _add_finding(
        db_app,
        server_id=sid_kev,
        identifier_key="CVE-X",
        severity=Severity.HIGH,
        is_kev=True,
    )

    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)

    # Retired Server taucht in der normalen Liste auf (Card).
    assert "srv-retired" in body
    # Aktiver KEV-Server in der Attention-Sektion.
    assert "Aufmerksamkeit noetig" in body
    assert "srv-active-kev" in body

    # Retired-Badge sichtbar.
    assert "retired" in body


def test_dashboard_revoked_server_marked_as_revoked(db_app: Flask) -> None:
    create_admin_user(db_app)
    now = _now()
    _create_server(
        db_app,
        name="srv-revoked",
        last_scan_at=now,
        revoked_at=now - timedelta(hours=1),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    assert "srv-revoked" in body
    assert "revoked" in body


# ---------------------------------------------------------------------------
# Filter-Persistenz im URL-Query-String (Bookmark-Test)
# ---------------------------------------------------------------------------


def test_dashboard_filter_is_active_marker_shown(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="srv-prod", tags=["prod"])
    client = db_app.test_client()
    login(client)
    resp = client.get("/?tags=prod")
    body = resp.get_data(as_text=True)
    # "gefiltert"-Badge erscheint nur wenn ein Filter aktiv ist.
    assert "gefiltert" in body


def test_dashboard_empty_filter_no_filtered_badge(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="srv-1")
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    assert "gefiltert" not in body


def test_dashboard_filter_no_match_shows_empty_filter_state(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="srv-prod", tags=["prod"])
    client = db_app.test_client()
    login(client)
    # Tag existiert in der DB ("staging") nicht — alle Server haben "prod".
    # Wir erzwingen Filter mit AND-Mode auf zwei Tags von denen einer fehlt.
    _create_server(db_app, name="srv-x", tags=["staging"])
    resp = client.get("/?tags=prod,nonsense&tags_mode=and")
    body = resp.get_data(as_text=True)
    # "Keine Server passen zu deinem Filter" Empty-Filter-Zustand.
    assert "Filter zuruecksetzen" in body or "passen zu deinem Filter" in body


# ---------------------------------------------------------------------------
# DB-Stale Anzeige
# ---------------------------------------------------------------------------


def test_dashboard_db_stale_badge_when_trivy_db_outdated(db_app: Flask) -> None:
    create_admin_user(db_app)
    now = _now()
    # Default Threshold = 30h, wir machen die DB 48h alt.
    _create_server(
        db_app,
        name="srv-db-stale",
        last_scan_at=now - timedelta(hours=2),
        trivy_db_updated_at=now - timedelta(hours=48),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    assert "srv-db-stale" in body
    assert "db veraltet" in body
    # Attention-Sektion zeigt "Trivy-DB veraltet"-Bucket.
    assert "Trivy-DB veraltet" in body
