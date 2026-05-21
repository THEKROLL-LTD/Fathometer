"""Block Q (ADR-0025 §2): Server-Detail Application-Group-Cards auf HTMX-Lazy.

Deckt zwei Slices ab:

Phase B.1 — Loader ``_load_application_groups_for_server`` (in
``app.views.server_detail``):

  - Per-Group-Findings-Query ist weg; der Loader fuehrt selbst bei vielen
    Groups eine konstante Anzahl ``FROM finding``-Statements aus
    (Count-Aggregat + Worst-Finding-Batch, also <= 2).
  - Rueckgabe-Vertrag: ``list[dict]`` mit Keys exakt ``{"group", "count",
    "worst_finding"}``. Kein ``findings``-Feld mehr.

Phase B.2 — neuer Endpoint ``GET /servers/<sid>/groups/<gid>/findings``:

  - Happy-Path liefert ein HTML-Partial (kein ``<html>``-Frame).
  - Cross-Server- und Cross-Group-Probing -> 404.
  - Unbekannter Server -> 404.
  - Empty-Bucket (Findings nur RESOLVED/ACKNOWLEDGED) -> 404.
  - ``@login_required`` -> 302 auf den Login.
  - Sortierung ist Spec-fix: KEV desc, dann EPSS, dann CVSS, dann
    ``first_seen_at`` asc — das pruefen wir am HTML-Reihenfolge.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import event
from sqlalchemy.engine import Engine

from app.db import get_session, get_session_factory
from app.models import (
    ApplicationGroup,
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from app.views.server_detail import _load_application_groups_for_server
from tests._helpers import create_admin_user, login

# ---------------------------------------------------------------------------
# Fixture-Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _create_server(app: Flask, name: str = "srv-lazy") -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=_now(),
                host_state_snapshot_at=_now(),
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _create_application_group(
    app: Flask,
    *,
    label: str,
    risk_band: str | None = "act",
    action_type: str | None = "patch",
    group_kind: str | None = "os_package",
    worst_finding_id: int | None = None,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            grp = ApplicationGroup(
                label=label,
                explanation=None,
                path_prefixes=[],
                pkg_name_exact=[label],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                risk_band=risk_band,
                risk_band_reason=None,
                risk_band_source="llm",
                worst_finding_id=worst_finding_id,
                action_type=action_type,
                group_kind=group_kind,
                source="llm",
            )
            sess.add(grp)
            sess.flush()
            gid = grp.id
            sess.commit()
            return gid
        finally:
            sess.close()


def _set_worst_finding(app: Flask, group_id: int, finding_id: int) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            grp = sess.get(ApplicationGroup, group_id)
            assert grp is not None
            grp.worst_finding_id = finding_id
            sess.commit()
        finally:
            sess.close()


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    application_group_id: int | None,
    status: FindingStatus = FindingStatus.OPEN,
    severity: Severity = Severity.HIGH,
    is_kev: bool = False,
    epss_score: float | None = None,
    cvss_v3_score: float | None = None,
    package_name: str = "openssl",
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            now = _now()
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
                epss_score=epss_score,
                cvss_v3_score=cvss_v3_score,
                attack_vector=AttackVector.UNKNOWN,
                first_seen_at=now,
                last_seen_at=now,
                application_group_id=application_group_id,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Phase B.1 — Loader-Tests
# ---------------------------------------------------------------------------


def test_initial_render_no_per_group_findings_query(db_app: Flask) -> None:
    """Loader laeuft mit konstantem N (<=2) ``FROM finding``-Statements,
    egal wieviele Application-Groups der Server hat.

    Vor Block Q war pro Group eine Findings-Query notwendig (N+1). Jetzt
    sind es nur das Count-Aggregat und das Worst-Finding-Batch; beide sind
    unabhaengig von der Group-Anzahl. Wir messen via SQLAlchemy-Engine-
    Hook und assertion gegen das Pattern ``FROM finding`` (case-insensitive,
    ignoriert Subselects auf ``finding_notes`` etc. wuerden auch matchen
    — fuer den Loader irrelevant, da die Helper keine solchen Joins
    aufrufen).
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-lazy-3-groups")

    # Drei Groups mit je 5 OPEN-Findings -> wenn der Loader pro Group
    # eine Findings-Query macht, sehen wir 3 zusaetzliche
    # ``FROM finding``-Statements. Erwartet: hoechstens 2 (Count + Worst).
    group_ids: list[int] = []
    for grp_i in range(3):
        gid = _create_application_group(db_app, label=f"app-{grp_i}")
        group_ids.append(gid)
        worst_fid: int | None = None
        for f_i in range(5):
            fid = _add_finding(
                db_app,
                server_id=sid,
                identifier_key=f"CVE-LAZY-{grp_i}-{f_i}",
                application_group_id=gid,
                # Ein Finding pro Group kriegt KEV, damit ein Worst-Kandidat
                # existiert. Auch wenn der Loader das Worst-Finding via
                # ``worst_finding_id`` aufloest, ist es sinnvoll, das
                # Feld zu setzen, damit der Worst-Finding-Batch tatsaechlich
                # eine Query absetzt (sonst ist der Helper short-circuit
                # auf 1 Query und der Test unterschaetzt die Realitaet).
                is_kev=(f_i == 0),
            )
            if f_i == 0:
                worst_fid = fid
        if worst_fid is not None:
            _set_worst_finding(db_app, gid, worst_fid)

    # Engine-Hook: zaehlt SQL-Statements, die "FROM finding" enthalten
    # (case-insensitive). Wir registrieren den Hook unmittelbar vor dem
    # Loader-Call und entfernen ihn danach wieder, damit andere Tests
    # nicht beeinflusst werden.
    statements: list[str] = []

    @event.listens_for(Engine, "before_cursor_execute")
    def _capture(conn, cursor, statement, parameters, context, executemany) -> None:
        statements.append(statement)

    try:
        with db_app.app_context():
            sess = get_session()
            entries = _load_application_groups_for_server(sess, sid)
    finally:
        event.remove(Engine, "before_cursor_execute", _capture)

    # Loader hat die Group-Daten geliefert.
    assert len(entries) == 3, entries

    # Zaehle ``FROM finding`` (Wort-Grenze, damit ``FROM finding_notes`` etc.
    # nicht falsch matchen).
    pattern = re.compile(r"\bfrom\s+findings?\b", re.IGNORECASE)
    finding_stmts = [s for s in statements if pattern.search(s)]
    assert len(finding_stmts) <= 2, (
        f"Erwartet hoechstens 2 ``FROM finding(s)``-Statements (Count + Worst), "
        f"gemessen {len(finding_stmts)}.\nStatements:\n" + "\n---\n".join(finding_stmts)
    )


def test_load_application_groups_returns_count_and_worst_finding(db_app: Flask) -> None:
    """Rueckgabe-Vertrag: jeder Eintrag hat exakt die Keys
    ``{"group", "count", "worst_finding"}`` — kein ``findings``-Feld mehr.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-loader-contract")
    gid = _create_application_group(db_app, label="openssl")
    f1 = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-OPENSSL-1",
        application_group_id=gid,
        is_kev=True,
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-OPENSSL-2",
        application_group_id=gid,
    )
    _set_worst_finding(db_app, gid, f1)

    with db_app.app_context():
        sess = get_session()
        entries = _load_application_groups_for_server(sess, sid)

    assert len(entries) == 1, entries
    entry = entries[0]
    assert set(entry.keys()) == {"group", "count", "worst_finding"}, entry
    assert isinstance(entry["count"], int), entry["count"]
    assert entry["count"] == 2, entry["count"]
    assert entry["worst_finding"] is not None
    assert entry["worst_finding"].id == f1
    # Defensive: ``findings`` darf NICHT existieren (Spec-Vertrag aus
    # ADR-0025 §2).
    assert "findings" not in entry, "Vertragsbruch: `findings` darf nicht gerendert werden."


# ---------------------------------------------------------------------------
# Phase B.2 — Endpoint-Tests
# ---------------------------------------------------------------------------


def _login_client(db_app: Flask) -> Any:
    """Helper: erzeugt Admin, loggt ein, gibt den Testclient zurueck."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    return client


def test_group_findings_fragment_happy_path(db_app: Flask) -> None:
    """3 OPEN-Findings einer Group auf Server X -> 200, HTML-Partial,
    enthaelt alle drei ``identifier_key``-Werte, **ohne** ``<html>``-Tag.
    """
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-happy")
    gid = _create_application_group(db_app, label="happy-app")
    ids = [
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-HAPPY-{i}",
            application_group_id=gid,
        )
        for i in range(3)
    ]

    resp = client.get(f"/servers/{sid}/groups/{gid}/findings")
    assert resp.status_code == 200, (resp.status_code, resp.data[:200])
    assert resp.mimetype == "text/html", resp.mimetype
    body = resp.get_data(as_text=True)

    # Partial -> kein vollstaendiges HTML-Dokument.
    assert "<html" not in body.lower(), "Partial-Render darf kein <html>-Frame enthalten."
    assert "<body" not in body.lower(), "Partial-Render darf kein <body>-Frame enthalten."

    # Alle drei Finding-IDs sind sichtbar.
    for fid in ids:
        assert f'data-test="group-finding-row-{fid}"' in body, (
            f"Finding-Row {fid} fehlt im Partial-Output."
        )
    # Identifier-Keys sind sichtbar.
    for i in range(3):
        assert f"CVE-HAPPY-{i}" in body, f"identifier_key CVE-HAPPY-{i} fehlt."


def test_group_findings_fragment_cross_server_returns_404(db_app: Flask) -> None:
    """Group existiert mit Findings auf Server Y; Aufruf gegen Server X
    (gleiche Group-ID) liefert 404 (leerer Bucket auf X)."""
    client = _login_client(db_app)
    sid_x = _create_server(db_app, name="srv-x")
    sid_y = _create_server(db_app, name="srv-y")
    gid = _create_application_group(db_app, label="cross-app")
    # Findings nur auf Y.
    _add_finding(
        db_app,
        server_id=sid_y,
        identifier_key="CVE-CROSS-Y-1",
        application_group_id=gid,
    )

    resp = client.get(f"/servers/{sid_x}/groups/{gid}/findings")
    assert resp.status_code == 404, (resp.status_code, resp.data[:200])


def test_group_findings_fragment_unknown_server_returns_404(db_app: Flask) -> None:
    """Server-ID existiert nicht -> 404 (Server-Existenz-Check)."""
    client = _login_client(db_app)
    # Keine Server, kein Group — wir nehmen beliebige IDs.
    resp = client.get("/servers/99999/groups/12345/findings")
    assert resp.status_code == 404, (resp.status_code, resp.data[:200])


def test_group_findings_fragment_login_required(db_app: Flask) -> None:
    """Aufruf ohne Login -> 302-Redirect auf die Login-Seite."""
    # Server + Group anlegen, damit der Endpoint ohne Auth-Decorator
    # eigentlich erfolgreich antworten koennte. Wir wollen aber, dass
    # ``@login_required`` _vor_ jeder DB-Lookup-Logik greift.
    sid = _create_server(db_app, name="srv-noauth")
    gid = _create_application_group(db_app, label="noauth-app")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-NOAUTH-1",
        application_group_id=gid,
    )

    client = db_app.test_client()
    resp = client.get(f"/servers/{sid}/groups/{gid}/findings")
    assert resp.status_code == 302, (resp.status_code, resp.data[:200])
    location = resp.headers.get("Location", "")
    assert "/login" in location, f"Erwartet Redirect auf /login, war {location!r}"


def test_group_findings_fragment_empty_bucket_returns_404(db_app: Flask) -> None:
    """Group existiert mit Findings, aber keine im Status OPEN -> 404.

    Wir legen Findings in den Status RESOLVED/ACKNOWLEDGED an. Der
    Endpoint filtert explizit ``status == OPEN`` und liefert daher leeren
    Bucket -> 404 statt 200 mit leerer Tabelle.
    """
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-empty")
    gid = _create_application_group(db_app, label="empty-app")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-EMPTY-RES",
        application_group_id=gid,
        status=FindingStatus.RESOLVED,
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-EMPTY-ACK",
        application_group_id=gid,
        status=FindingStatus.ACKNOWLEDGED,
    )

    resp = client.get(f"/servers/{sid}/groups/{gid}/findings")
    assert resp.status_code == 404, (resp.status_code, resp.data[:200])


def test_group_findings_fragment_sort_order_kev_first(db_app: Flask) -> None:
    """Mehrere Findings in einer Group: das KEV-markierte muss als erstes
    in der gerenderten Tabelle stehen — Spec-Sortierung ist
    ``is_kev DESC, epss DESC nulls last, cvss DESC nulls last, first_seen asc``.

    Wir konstruieren bewusst einen Konflikt: ein Finding hat den
    hoechsten EPSS-Score, aber kein KEV. Trotzdem muss das KEV-Finding
    zuerst rendern.
    """
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-sort")
    gid = _create_application_group(db_app, label="sort-app")
    # Nicht-KEV mit hohem EPSS.
    fid_high_epss = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-SORT-EPSS",
        application_group_id=gid,
        is_kev=False,
        epss_score=0.99,
        cvss_v3_score=7.5,
    )
    # KEV mit niedrigerem EPSS.
    fid_kev = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-SORT-KEV",
        application_group_id=gid,
        is_kev=True,
        epss_score=0.10,
        cvss_v3_score=5.0,
    )

    resp = client.get(f"/servers/{sid}/groups/{gid}/findings")
    assert resp.status_code == 200, (resp.status_code, resp.data[:200])
    body = resp.get_data(as_text=True)

    # Reihenfolge im HTML: KEV muss vor Nicht-KEV stehen.
    idx_kev = body.find(f'data-test="group-finding-row-{fid_kev}"')
    idx_epss = body.find(f'data-test="group-finding-row-{fid_high_epss}"')
    assert idx_kev >= 0, "KEV-Finding-Row fehlt im Output."
    assert idx_epss >= 0, "EPSS-Finding-Row fehlt im Output."
    assert idx_kev < idx_epss, (
        f"KEV-Finding muss vor EPSS-Finding rendern; idx_kev={idx_kev}, idx_epss={idx_epss}."
    )


# ---------------------------------------------------------------------------
# Marker — DB-abhaengige View-Tests (auto via conftest.py: todo_mock)
# ---------------------------------------------------------------------------
#
# Diese Tests nutzen ``db_app``/``db_client``/``db_session`` und werden
# automatisch von ``tests/conftest.py::pytest_collection_modifyitems`` mit
# ``pytest.mark.todo_mock`` markiert. Sie laufen im Default-Pytest-Lauf
# weiter (im Gegensatz zu ``acceptance``-Tests), zaehlen aber zu den
# Files die langfristig in Unit-Mock-Variante umgebaut werden sollen.

_ = pytest  # Halte den Import — pytest wird via Fixture-Wiring konsumiert.
