"""Block Q (ADR-0025 §3): Pending-Grouping-Sektion auf HTMX-Lazy.

Deckt drei Slices ab:

Phase C.1 — Loader ``_load_pending_grouping_counts`` (in
``app.views.server_detail``):

  - Pro Aufruf genau 1 SELECT (das GROUP-BY-Aggregat). Keine N+1.
  - Rueckgabe enthaelt alle 7 bekannten Risk-Bands in fester
    Insertion-Order (escalate, act, mitigate, pending, unknown,
    monitor, noise), defaultet auf 0.
  - Server-Isolation: Findings anderer Server werden nicht mitgezaehlt.
  - Filter: ``application_group_id IS NULL`` und ``status == OPEN``.

Phase C.2 — Endpoint ``GET /servers/<sid>/findings/pending``:

  - Happy-Path liefert ein HTML-Partial (kein ``<html>``-Frame).
  - ``risk_band``-Param fehlt oder nicht in Whitelist -> 400.
  - 400-Check laeuft vor dem Server-Existenz-Check.
  - Unbekannter Server -> 404.
  - Empty-Bucket (nur grouped oder nur CLOSED Findings) -> 404.
  - ``@login_required`` -> 302 auf den Login.
  - Sortierung: KEV desc, dann EPSS, dann CVSS, dann ``first_seen_at``
    asc — pruefen wir an der HTML-Reihenfolge.

Phase C.3 — Initial-Render der Server-Detail-Seite:

  - Bei 50 Pending-Findings rendert ``GET /servers/<id>`` keine
    einzige Finding-Row im Initial-HTML (kein ``pending-findings-
    table``, keine ``finding-<id>``-Anker).
  - Die Pending-Grouping-Sektion selbst ist sichtbar
    (``data-test="pending-grouping-section"``).
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
from app.views.server_detail import _PENDING_BANDS, _load_pending_grouping_counts
from tests._helpers import create_admin_user, login

# ---------------------------------------------------------------------------
# Fixture-Helpers (analog zu test_server_detail_lazy_groups.py)
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _create_server(app: Flask, name: str = "srv-pending") -> int:
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
                worst_finding_id=None,
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


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    risk_band: str | None,
    application_group_id: int | None = None,
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
                risk_band=risk_band,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def _login_client(db_app: Flask) -> Any:
    """Helper: erzeugt Admin, loggt ein, gibt den Testclient zurueck."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    return client


# ---------------------------------------------------------------------------
# Phase C.1 — Loader-Tests
# ---------------------------------------------------------------------------


def test_initial_render_no_findings_query_for_pending(db_app: Flask) -> None:
    """Der Helper ``_load_pending_grouping_counts`` macht genau 1 SQL-Statement
    gegen ``findings``: das GROUP-BY-Aggregat. Insbesondere keine pro-Band-
    oder pro-Finding-Queries.

    Wir messen via SQLAlchemy-``before_cursor_execute``-Hook gegen das
    Pattern ``FROM findings`` (case-insensitive, Wort-Grenze).
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-pending-aggregate")

    # 30 ungroupierte OPEN-Findings, verteilt auf mehrere Bands. Falls
    # der Helper N Queries pro Band machen wuerde, sehen wir >>1
    # ``FROM findings``-Statement.
    bands = ["escalate", "act", "monitor", "noise", "monitor", "escalate"]
    for i in range(30):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-PENDING-{i:03d}",
            risk_band=bands[i % len(bands)],
            application_group_id=None,
        )

    statements: list[str] = []

    @event.listens_for(Engine, "before_cursor_execute")
    def _capture(conn, cursor, statement, parameters, context, executemany) -> None:
        statements.append(statement)

    try:
        with db_app.app_context():
            sess = get_session()
            result = _load_pending_grouping_counts(sess, sid)
    finally:
        event.remove(Engine, "before_cursor_execute", _capture)

    # Der Helper hat sinnvolle Counts geliefert (escalate: 10, act: 5,
    # monitor: 10, noise: 5).
    assert sum(result.values()) == 30, result

    pattern = re.compile(r"\bfrom\s+findings?\b", re.IGNORECASE)
    finding_stmts = [s for s in statements if pattern.search(s)]
    assert len(finding_stmts) == 1, (
        f"Erwartet genau 1 ``FROM findings``-Statement (GROUP-BY-Aggregat), "
        f"gemessen {len(finding_stmts)}.\nStatements:\n" + "\n---\n".join(finding_stmts)
    )


def test_load_pending_grouping_counts_returns_all_seven_bands_with_defaults(
    db_app: Flask,
) -> None:
    """Auf einem leeren Server liefert der Helper alle 7 bekannten Bands
    in fester Insertion-Order, jeweils mit Count 0.

    Insertion-Order ist Spec-fix (siehe Helper-Comprehension):
    escalate, act, mitigate, pending, unknown, monitor, noise.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-pending-empty")

    with db_app.app_context():
        sess = get_session()
        result = _load_pending_grouping_counts(sess, sid)

    assert list(result.keys()) == [
        "escalate",
        "act",
        "mitigate",
        "pending",
        "unknown",
        "monitor",
        "noise",
    ], list(result.keys())
    for band, count in result.items():
        assert count == 0, f"Erwartet 0 fuer Band {band!r}, war {count}"


def test_load_pending_grouping_counts_counts_correctly(db_app: Flask) -> None:
    """Server mit 3 escalate + 5 monitor + 2 noise ungroupierten OPEN-Findings.
    Findings auf einem anderen Server werden nicht mitgezaehlt.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-pending-main")
    sid_other = _create_server(db_app, name="srv-pending-other")

    for i in range(3):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-ESC-{i}",
            risk_band="escalate",
        )
    for i in range(5):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-MON-{i}",
            risk_band="monitor",
        )
    for i in range(2):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-NOI-{i}",
            risk_band="noise",
        )

    # Cross-Server-Noise — duerfen NICHT mitgezaehlt werden.
    for i in range(99):
        _add_finding(
            db_app,
            server_id=sid_other,
            identifier_key=f"CVE-OTH-{i}",
            risk_band="escalate",
        )

    with db_app.app_context():
        sess = get_session()
        result = _load_pending_grouping_counts(sess, sid)

    assert result == {
        "escalate": 3,
        "act": 0,
        "mitigate": 0,
        "pending": 0,
        "unknown": 0,
        "monitor": 5,
        "noise": 2,
    }, result


def test_load_pending_grouping_counts_excludes_grouped(db_app: Flask) -> None:
    """Ein Finding mit gesetzter ``application_group_id`` wird NICHT
    mitgezaehlt — egal welches Risk-Band es hat."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-pending-grouped")
    gid = _create_application_group(db_app, label="some-app")

    # Ein grouped Finding im Band "monitor" — darf nicht im Counter
    # auftauchen.
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-GROUPED-1",
        risk_band="monitor",
        application_group_id=gid,
    )
    # Ein ungroupiertes Finding im Band "monitor" — wird gezaehlt.
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-UNGROUPED-1",
        risk_band="monitor",
        application_group_id=None,
    )

    with db_app.app_context():
        sess = get_session()
        result = _load_pending_grouping_counts(sess, sid)

    assert result["monitor"] == 1, result


def test_load_pending_grouping_counts_excludes_closed(db_app: Flask) -> None:
    """Findings im Status ACKNOWLEDGED oder RESOLVED werden nicht gezaehlt."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-pending-closed")

    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-CLOSED-ACK",
        risk_band="escalate",
        status=FindingStatus.ACKNOWLEDGED,
    )
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-CLOSED-RES",
        risk_band="escalate",
        status=FindingStatus.RESOLVED,
    )
    # Ein OPEN-Finding, damit der Test wirklich nur die CLOSED-Wirkung misst.
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-OPEN-ESC",
        risk_band="escalate",
        status=FindingStatus.OPEN,
    )

    with db_app.app_context():
        sess = get_session()
        result = _load_pending_grouping_counts(sess, sid)

    assert result["escalate"] == 1, result


# ---------------------------------------------------------------------------
# Phase C.2 — Endpoint-Tests
# ---------------------------------------------------------------------------


def test_pending_findings_fragment_happy_path(db_app: Flask) -> None:
    """3 ungroupierte OPEN-Findings im Band ``monitor`` -> 200, Partial-HTML,
    alle drei ``identifier_key``-Werte sichtbar, kein ``<html>``-Frame.
    """
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-pending-happy")

    ids = [
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-MONITOR-{i}",
            risk_band="monitor",
            application_group_id=None,
        )
        for i in range(3)
    ]

    resp = client.get(f"/servers/{sid}/findings/pending?risk_band=monitor")
    assert resp.status_code == 200, (resp.status_code, resp.data[:200])
    assert resp.mimetype == "text/html", resp.mimetype
    body = resp.get_data(as_text=True)

    # Partial -> kein vollstaendiges HTML-Dokument.
    assert "<html" not in body.lower(), "Partial-Render darf kein <html>-Frame enthalten."
    assert "<body" not in body.lower(), "Partial-Render darf kein <body>-Frame enthalten."

    # Identifier-Keys sichtbar.
    for i in range(3):
        assert f"CVE-MONITOR-{i}" in body, f"identifier_key CVE-MONITOR-{i} fehlt."
    # Finding-Row-Markierungen vorhanden.
    for fid in ids:
        assert f'data-test="pending-finding-row-{fid}"' in body, (
            f"Finding-Row {fid} fehlt im Partial-Output."
        )


def test_pending_findings_fragment_400_for_invalid_band(db_app: Flask) -> None:
    """``?risk_band=invalid`` -> 400 (Whitelist-Check)."""
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-pending-invalid-band")

    resp = client.get(f"/servers/{sid}/findings/pending?risk_band=invalid")
    assert resp.status_code == 400, (resp.status_code, resp.data[:200])


def test_pending_findings_fragment_400_for_missing_band(db_app: Flask) -> None:
    """Ohne ``risk_band``-Param -> 400. ``request.args.get("risk_band")``
    ist ``None`` und ``None not in _PENDING_BANDS``.
    """
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-pending-missing-band")

    resp = client.get(f"/servers/{sid}/findings/pending")
    assert resp.status_code == 400, (resp.status_code, resp.data[:200])


def test_pending_findings_fragment_400_takes_precedence_over_unknown_server(
    db_app: Flask,
) -> None:
    """Whitelist-Check laeuft vor dem Server-Existenz-Check: unbekannter
    Server + invalides Band -> 400, NICHT 404.
    """
    client = _login_client(db_app)

    resp = client.get("/servers/9999/findings/pending?risk_band=invalid")
    assert resp.status_code == 400, (resp.status_code, resp.data[:200])


def test_pending_findings_fragment_404_unknown_server(db_app: Flask) -> None:
    """Gueltiges Band, unbekannter Server -> 404."""
    client = _login_client(db_app)

    resp = client.get("/servers/9999/findings/pending?risk_band=monitor")
    assert resp.status_code == 404, (resp.status_code, resp.data[:200])


def test_pending_findings_fragment_404_empty_bucket(db_app: Flask) -> None:
    """Gueltiges Band, aber Server hat keine ungroupierten OPEN-Findings
    in dem Band -> 404.
    """
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-pending-empty-bucket")
    # Ein Finding in einem anderen Band — damit der Server "existiert"
    # aber das angefragte Band leer ist.
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-OTHER-BAND",
        risk_band="escalate",
        application_group_id=None,
    )

    resp = client.get(f"/servers/{sid}/findings/pending?risk_band=monitor")
    assert resp.status_code == 404, (resp.status_code, resp.data[:200])


def test_pending_findings_fragment_404_excludes_grouped_in_same_band(
    db_app: Flask,
) -> None:
    """Finding mit ``risk_band=monitor`` aber gesetzter
    ``application_group_id`` -> 404 (Endpoint filtert nur ungroupierte).
    """
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-pending-grouped-same-band")
    gid = _create_application_group(db_app, label="some-app")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-GROUPED-MONITOR",
        risk_band="monitor",
        application_group_id=gid,
    )

    resp = client.get(f"/servers/{sid}/findings/pending?risk_band=monitor")
    assert resp.status_code == 404, (resp.status_code, resp.data[:200])


def test_pending_findings_fragment_login_required(db_app: Flask) -> None:
    """Aufruf ohne Login -> 302-Redirect auf die Login-Seite.

    ``create_admin_user`` schliesst gleichzeitig den Setup-Wizard ab
    (setzt ``setup_completed_at``), damit der Setup-Guard nicht
    fruehzeitig auf ``/setup/`` redirected und der ``@login_required``-
    Pfad tatsaechlich getestet wird.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-pending-noauth")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-NOAUTH-MON",
        risk_band="monitor",
        application_group_id=None,
    )

    client = db_app.test_client()
    resp = client.get(f"/servers/{sid}/findings/pending?risk_band=monitor")
    assert resp.status_code == 302, (resp.status_code, resp.data[:200])
    location = resp.headers.get("Location", "")
    assert "/login" in location, f"Erwartet Redirect auf /login, war {location!r}"


def test_pending_findings_fragment_sort_order(db_app: Flask) -> None:
    """Mehrere Findings im selben Band: KEV-Finding muss vor dem
    Nicht-KEV-Finding mit hoechstem EPSS rendern (KEV-DESC dominiert).
    """
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-pending-sort")
    # Nicht-KEV mit hohem EPSS.
    fid_high_epss = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-PEND-EPSS",
        risk_band="monitor",
        is_kev=False,
        epss_score=0.99,
        cvss_v3_score=7.5,
    )
    # KEV mit niedrigerem EPSS.
    fid_kev = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-PEND-KEV",
        risk_band="monitor",
        is_kev=True,
        epss_score=0.10,
        cvss_v3_score=5.0,
    )

    resp = client.get(f"/servers/{sid}/findings/pending?risk_band=monitor")
    assert resp.status_code == 200, (resp.status_code, resp.data[:200])
    body = resp.get_data(as_text=True)

    idx_kev = body.find(f'data-test="pending-finding-row-{fid_kev}"')
    idx_epss = body.find(f'data-test="pending-finding-row-{fid_high_epss}"')
    assert idx_kev >= 0, "KEV-Finding-Row fehlt im Output."
    assert idx_epss >= 0, "EPSS-Finding-Row fehlt im Output."
    assert idx_kev < idx_epss, (
        f"KEV-Finding muss vor EPSS-Finding rendern; idx_kev={idx_kev}, idx_epss={idx_epss}."
    )


# ---------------------------------------------------------------------------
# Phase C.3 — Initial-Render-Snapshot
# ---------------------------------------------------------------------------


def test_initial_render_has_no_finding_row_in_pending_section(db_app: Flask) -> None:
    """Server mit 50 ungroupierten OPEN-Findings: das Initial-HTML der
    Server-Detail-Seite enthaelt die Pending-Grouping-Sektion (visuell
    sichtbar), aber **keine** Finding-Rows.

    Verifikation:
      - ``data-test="pending-grouping-section"`` ist vorhanden.
      - ``data-test="pending-findings-table"`` ist NICHT vorhanden.
      - Kein ``<tr id="finding-`` (Anker-IDs der Lazy-Partials) im Initial-HTML.
    """
    client = _login_client(db_app)
    sid = _create_server(db_app, name="srv-pending-initial")

    # 50 ungroupierte OPEN-Findings, verteilt auf mehrere Bands.
    bands = ("escalate", "act", "monitor", "noise", "unknown")
    for i in range(50):
        _add_finding(
            db_app,
            server_id=sid,
            identifier_key=f"CVE-INITIAL-{i:03d}",
            risk_band=bands[i % len(bands)],
            application_group_id=None,
        )

    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, (resp.status_code, resp.data[:200])
    body = resp.get_data(as_text=True)

    # Die Pending-Grouping-Sektion ist im Initial-HTML sichtbar.
    assert 'data-test="pending-grouping-section"' in body, (
        "Pending-Grouping-Sektion fehlt im Initial-HTML — "
        "der Block-Q Phase-C.3-Umbau soll sie weiterhin rendern."
    )

    # Aber: KEINE Tabelle und KEINE einzelnen Finding-Rows.
    assert 'data-test="pending-findings-table"' not in body, (
        "Initial-HTML enthaelt bereits die Pending-Findings-Tabelle — "
        "ADR-0025 §3 erfordert HTMX-Lazy-Load."
    )
    # Anker-Format aus pending_findings_table.html: ``<tr id="finding-{id}"``.
    finding_anchor_pattern = re.compile(r'<tr\s+id="finding-\d+"')
    assert not finding_anchor_pattern.search(body), (
        "Initial-HTML enthaelt einzelne Finding-Rows — "
        "die sollen erst nach HTMX-Aufklappen im Browser laden."
    )


# ---------------------------------------------------------------------------
# Marker — DB-abhaengige View-Tests (auto via conftest.py: todo_mock)
# ---------------------------------------------------------------------------
#
# Diese Tests nutzen ``db_app``/``db_client``/``db_session`` und werden
# automatisch von ``tests/conftest.py::pytest_collection_modifyitems`` mit
# ``pytest.mark.todo_mock`` markiert.

_ = pytest  # Import wird via Fixture-Wiring konsumiert.
_ = _PENDING_BANDS  # re-export zur Sanity, damit Refactors das Tuple nicht stumm entfernen.
