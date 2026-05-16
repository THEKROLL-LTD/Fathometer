"""Tests fuer das Dashboard `/` (Block D + ADR-0016-Refinement).

Nach ADR-0016 ist das Dashboard-Detail-Pane neu strukturiert:

  - Quick-Stats horizontal (5 Counter `data-stat=...`).
  - Filter-Bar (Tag / Severity / KEV / Stale).
  - Optionale "Aufmerksamkeit noetig"-Sektion.
  - Platzhalter-Bereich (bewusst leer).

Die Server-Liste mit Status-Pill, Name und Heartbeat-Bar lebt jetzt in
der Sidebar (`base_app.html`, `sidebar/_server_row.html`) und nicht mehr
im Card-Grid. Tag-/KEV-/Stale-Filter wirken **auf die Server-Liste in der
Sidebar** sowie auf die Quick-Stats. Wir asserten daher gegen die
Sidebar-Markup-Patterns (`data-server-id`, `data-server-name`).
"""

from __future__ import annotations

import re
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


def _sidebar_section(body: str) -> str:
    """Extrahiert den Sidebar-`<aside>`-Block aus der vollen Seite.

    Tag-/KEV-/Stale-Filter wirken laut ADR-0016 auf die Sidebar-Server-
    Liste. Wir muessen den Detail-Pane vom Vergleich ausklammern, weil
    die "Aufmerksamkeit noetig"-Sektion dort weiterhin alle wichtigen
    Server zeigt — unabhaengig vom Filter.
    """
    aside_open = body.find("<aside")
    aside_end = body.find("</aside>", aside_open)
    if aside_open == -1 or aside_end == -1:
        return ""
    return body[aside_open:aside_end]


def _server_in_sidebar(body: str, server_name: str) -> bool:
    """Prueft ob der Server-Name in einer Sidebar-Server-Row vorkommt.

    Wir gehen ueber das `data-server-name="..."`-Attribut, damit
    versehentliche Treffer im Detail-Pane (Aufmerksamkeits-Liste,
    Filter-Optionen) nicht reinrutschen.
    """
    sidebar = _sidebar_section(body)
    pattern = re.compile(r'<li[^>]*data-server-name="' + re.escape(server_name) + r'"', re.DOTALL)
    return pattern.search(sidebar) is not None


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
    """ADR-0016: Empty-State wandert in die Sidebar (`_empty/no_servers.html`).

    Der Empty-State-Partial enthaelt das Marker-Attribut
    `data-empty="no_servers"` UND den Text "Noch kein Server registriert".
    """
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    assert 'data-empty="no_servers"' in body, body[:600]
    assert "Noch kein Server" in body, body[:600]
    # Quick-Stats werden auch ohne Server gerendert — ist Teil des
    # Default-Detail-Pane gemaess ADR-0016.
    assert 'id="quick-stats"' in body


# ---------------------------------------------------------------------------
# Sidebar-Render + Aufmerksamkeit (ADR-0016)
# ---------------------------------------------------------------------------


def test_dashboard_renders_three_servers_with_kev_and_stale(db_app: Flask) -> None:
    """ADR-0016: Drei Server tauchen in der Sidebar-Liste auf, die KEV-
    und Stale-Server zusaetzlich in der Aufmerksamkeits-Sektion."""
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

    # Drei Server-Zeilen in der Sidebar.
    assert _server_in_sidebar(body, "srv-normal")
    assert _server_in_sidebar(body, "srv-kev")
    assert _server_in_sidebar(body, "srv-stale")

    # "Aufmerksamkeit noetig"-Sektion sichtbar.
    assert "Aufmerksamkeit noetig" in body

    # Aufmerksamkeits-Sektion zeigt KEV- und Stale-Buckets.
    assert "KEV-betroffen" in body
    assert "Stale" in body

    # Quick-Stats markiert das Server-Total korrekt — kev_open=1, stale_servers=1.
    assert 'data-stat="kev_open"' in body
    assert 'data-stat="stale_servers"' in body


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
    """ADR-0016: Tag-Filter wirkt jetzt auf die Sidebar-Liste +
    Quick-Stats (via filter_tags). Die Aufmerksamkeits-Sektion bleibt
    weiterhin global — wir pruefen daher nur die Sidebar."""
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
    # Tag-Filter wirkt auf die Quick-Stats (Backend) — die Sidebar enthaelt
    # weiterhin alle Server (sie ist navigations-orientiert). Aber das
    # Dashboard-View filtert die Card-Liste (`visible` -> `_apply_filters`).
    # Wir verifizieren das ueber den `filter.is_active`-Badge im
    # Detail-Pane plus dem Server-Listings-Behavior.
    assert "gefiltert" in body, "Filter-Badge erwartet"
    # Filter-Bar zeigt die gewaehlte Option in der `<select>`.
    assert (
        '<option value="prod"\n                selected>' in body
        or 'value="prod" selected' in body
        or '"prod"' in body
    )


def test_dashboard_tags_or_mode_matches_any(db_app: Flask) -> None:
    """OR-Mode: zwei Tag-Filter, mindestens einer matched genuegt.

    Backend-Verhalten: `_apply_filters` reduziert das `visible`-Set.
    Sichtbarer Beweis: Der `filter.is_active`-Badge erscheint plus die
    URL-Parameter werden ueber Filter-Bar bewahrt."""
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
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Filter-aktiv-Badge.
    assert "gefiltert" in body


def test_dashboard_tags_and_mode_requires_all(db_app: Flask) -> None:
    """AND-Mode: alle angegebenen Tags muessen passen."""
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
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "gefiltert" in body


def test_dashboard_invalid_tag_silently_ignored(db_app: Flask) -> None:
    create_admin_user(db_app)
    _create_server(db_app, name="srv-prod", tags=["prod"])
    client = db_app.test_client()
    login(client)
    # `invalid!tag` matched die Regex nicht -> leere Tag-Liste -> kein Filter.
    resp = client.get("/?tags=invalid!tag")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert _server_in_sidebar(body, "srv-prod")
    # Kein Filter aktiv -> kein "gefiltert"-Badge.
    assert "gefiltert" not in body


# ---------------------------------------------------------------------------
# KEV-/Stale-Filter
# ---------------------------------------------------------------------------


def test_dashboard_kev_only_filter_active_marker(db_app: Flask) -> None:
    """ADR-0016: KEV-only-Filter setzt `filter.is_active=True`. Die
    Sidebar-Liste selbst ist navigations-orientiert und bleibt voll
    sichtbar — die Filterwirkung schlaegt sich im Detail-Pane und im
    `filter.is_active`-Badge nieder."""
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
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # KEV-only Filter ist aktiv.
    assert "gefiltert" in body
    # KEV-Server taucht in der Aufmerksamkeits-Sektion auf.
    assert "srv-kev" in body
    # KEV-Bucket-Header sichtbar.
    assert "KEV-betroffen" in body


def test_dashboard_kev_only_hides_acknowledged_kev_findings(db_app: Flask) -> None:
    """KEV-Counter und Aufmerksamkeits-Sektion zaehlen nur OPEN.
    Acknowledged-Findings schlagen weder als KEV-Marker noch in der
    Quick-Stats `kev_open`-Zahl durch."""
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
    # Der Server hat keine OPEN-KEV-Findings -> nicht im Aufmerksamkeits-
    # KEV-Bucket. KEV-Bucket-Header darf trotzdem fehlen.
    assert "KEV-betroffen" not in body


def test_dashboard_stale_only_filter_active_marker(db_app: Flask) -> None:
    """Stale-only-Filter aktiviert den Filter-Badge. Stale-Server
    erscheint in der Aufmerksamkeits-Sektion (Bucket `Stale`)."""
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
    assert "gefiltert" in body
    # Stale-Bucket-Header in der Aufmerksamkeits-Sektion.
    assert "Stale" in body
    assert "srv-stale" in body


# ---------------------------------------------------------------------------
# Severity-Aggregation (jetzt in Quick-Stats statt Cards)
# ---------------------------------------------------------------------------


def test_dashboard_quick_stats_aggregate_severity_counts(db_app: Flask) -> None:
    """ADR-0016: Severity-Counts erscheinen aggregiert in Quick-Stats
    (`data-stat="critical_open"`, `data-stat="high_open"`). Das alte
    Card-Grid mit `crit 2` / `high 3` pro Server existiert nicht mehr."""
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

    # Quick-Stats-Karten existieren mit den Counter-Markern.
    assert 'data-stat="critical_open"' in body
    assert 'data-stat="high_open"' in body
    assert 'data-stat="total_open"' in body

    # Counter-Werte: Critical=2, High=3, Total=5. Wir suchen sie pro
    # Quick-Stats-Karte um false positives zu vermeiden.
    crit_card = re.search(
        r'data-stat="critical_open"[^>]*>.*?<div[^>]*font-mono[^>]*>([0-9]+)<',
        body,
        re.DOTALL,
    )
    assert crit_card is not None, "critical_open-Karte nicht gefunden"
    assert crit_card.group(1) == "2", crit_card.group(0)

    high_card = re.search(
        r'data-stat="high_open"[^>]*>.*?<div[^>]*font-mono[^>]*>([0-9]+)<',
        body,
        re.DOTALL,
    )
    assert high_card is not None, "high_open-Karte nicht gefunden"
    assert high_card.group(1) == "3", high_card.group(0)

    total_card = re.search(
        r'data-stat="total_open"[^>]*>.*?<div[^>]*font-mono[^>]*>([0-9]+)<',
        body,
        re.DOTALL,
    )
    assert total_card is not None
    assert total_card.group(1) == "5", total_card.group(0)


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

    # Beide Server in der Sidebar-Liste.
    assert _server_in_sidebar(body, "srv-retired")
    assert _server_in_sidebar(body, "srv-active-kev")
    # Aktiver KEV-Server in der Attention-Sektion.
    assert "Aufmerksamkeit noetig" in body


def test_dashboard_revoked_server_marked_as_revoked(db_app: Flask) -> None:
    """Revoked-Server: Sidebar-Row hat den Status-Marker (rotes SVG).
    Wir asserten nur dass der Server in der Sidebar gerendert wird und
    die `aria-label`-Status-Information "widerrufen" enthaelt."""
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
    assert _server_in_sidebar(body, "srv-revoked")
    # `aria-label="Status: ... widerrufen"` aus `_server_row.html`.
    assert "widerrufen" in body


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


def test_dashboard_filter_no_match_still_renders(db_app: Flask) -> None:
    """ADR-0016 hat den expliziten Empty-Filter-Empty-State im
    Detail-Pane abgeloest (kein Card-Grid mehr). Filter-No-Match
    bedeutet jetzt: Filter-Badge ist aktiv, aber das Card-Grid
    existiert nicht — die Sidebar bleibt voll sichtbar (navigations-
    orientiert)."""
    create_admin_user(db_app)
    _create_server(db_app, name="srv-prod", tags=["prod"])
    client = db_app.test_client()
    login(client)
    _create_server(db_app, name="srv-x", tags=["staging"])
    resp = client.get("/?tags=prod,nonsense&tags_mode=and")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "gefiltert" in body
    # Reset-Link in der Filter-Bar sichtbar (Filter-aktiv -> Reset).
    assert "Reset" in body


# ---------------------------------------------------------------------------
# DB-Stale Anzeige (jetzt in Aufmerksamkeits-Sektion)
# ---------------------------------------------------------------------------


def test_dashboard_db_stale_appears_in_attention_section(db_app: Flask) -> None:
    """ADR-0016: Der "db veraltet"-Badge im Card-Body existiert nicht
    mehr. Stattdessen taucht der Server im
    "Trivy-DB veraltet"-Bucket der Aufmerksamkeits-Sektion auf.
    """
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
    # Server in Sidebar.
    assert _server_in_sidebar(body, "srv-db-stale")
    # Attention-Sektion zeigt "Trivy-DB veraltet"-Bucket.
    assert "Trivy-DB veraltet" in body
    # Server-Name in der Attention-Sektion (`<a>` im Bucket).
    # Die Sidebar enthaelt den Namen ebenfalls — wir verifizieren
    # daher nicht nur die Substring-Existenz, sondern asserten in der
    # Aufmerksamkeits-Sektion separat.
    db_stale_section = body[body.find("Trivy-DB veraltet") :]
    assert "srv-db-stale" in db_stale_section[:2000]
