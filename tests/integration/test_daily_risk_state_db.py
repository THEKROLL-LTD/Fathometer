"""DB-Integration-Tests fuer `app.services.daily_risk_state` (ADR-0035-Addendum).

LAUF NUR AUF EXPLIZITE USER-GENEHMIGUNG (Heavy-Suite, echte Postgres).

Diese Tests brauchen echte Postgres-Semantik:

* **Paritaets-Test (ADR-Pflicht / Konsistenz-Pflicht):** Die SQL-Tagesende-
  Range in `finalize_pending_days` MUSS exakt der Python-Logik in
  `_aggregate_one_server` entsprechen. Beweis: seede eine echte DB ueber
  mehrere Tage/Server (inkl. der scharfen Kanten — nur-unknown-Tag,
  NULL-risk_band, resolved-vor-Tagesende, acked, KEV), friere mit
  `finalize_pending_days` ein, lese ueber `heartbeats_for_servers`
  (frozen-Pfad) und vergleiche Cell-fuer-Cell gegen `live_heartbeats_for_servers`
  (Python-Oracle) fuer die vergangenen Tage.
* **Idempotenz:** `finalize_pending_days` zweimal -> Tabellen-Inhalt
  identisch, frozen-Cells unveraendert (ON CONFLICT DO NOTHING).
* **Catch-up:** simulierte Luecke -> ein Lauf fuellt alle fehlenden Tage bis
  gestern; today wird NIE finalisiert.

Auto-Markierung als `db_integration` (und `acceptance`) erfolgt ueber
`tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES` (Pfad-Praefix
`tests/integration/test_daily_risk_state_db`).
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from flask import Flask
from sqlalchemy import func, select

from app.db import get_session_factory
from app.models import (
    AttackVector,
    DailyRiskState,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Scan,
    Server,
    Severity,
)
from app.services.daily_risk_state import finalize_pending_days
from app.services.heartbeat_aggregation import (
    heartbeats_for_servers,
    live_heartbeats_for_servers,
)

# Mittags fixiert, damit "today" eindeutig und resolved/first_seen-Vergleiche
# gegen Tagesende stabil sind.
FIXED_NOW = datetime(2026, 6, 7, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Seed-Helper
# ---------------------------------------------------------------------------


def _create_server(app: Flask, name: str) -> int:
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


def _create_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    severity: Severity,
    first_seen_at: datetime,
    resolved_at: datetime | None = None,
    is_kev: bool = False,
    risk_band: str | None = None,
    status: FindingStatus = FindingStatus.OPEN,
    acknowledged_at: datetime | None = None,
    package_name: str = "pkg",
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
                severity=severity,
                status=status,
                is_kev=is_kev,
                first_seen_at=first_seen_at,
                last_seen_at=first_seen_at,
                resolved_at=resolved_at,
                acknowledged_at=acknowledged_at,
                risk_band=risk_band,
                attack_vector=AttackVector.UNKNOWN,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def _create_scan(app: Flask, *, server_id: int, received_at: datetime) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            sess.add(Scan(server_id=server_id, received_at=received_at))
            sess.commit()
        finally:
            sess.close()


def _seed_edge_case_fleet(app: Flask) -> list[int]:
    """Seedet eine Flotte mit allen scharfen Kanten ueber mehrere Tage.

    Tagebasis relativ zu FIXED_NOW (2026-06-07):
      - d-10 .. d-1 sind vergangene (einfrierbare) Tage; d-0 = today.

    Server A: KEV + resolved-vor-Tagesende + acked + verschiedene Bands.
    Server B: nur-unknown-Severity-Finding (Kante #1).
    Server C: Findings mit risk_band=NULL (Kante #2).
    Server D: gar keine Findings (leerer Server -> alle Cells None).
    """
    base = FIXED_NOW

    sid_a = _create_server(app, "drs-A")
    sid_b = _create_server(app, "drs-B")
    sid_c = _create_server(app, "drs-C")
    sid_d = _create_server(app, "drs-D")

    # --- Server A: gemischte Bands/Severities, KEV, resolved, acked. ---
    # Langlebiges escalate-CRITICAL-KEV-Finding (seit d-9 offen, nie resolved).
    _create_finding(
        app,
        server_id=sid_a,
        identifier_key="CVE-A-ESC",
        severity=Severity.CRITICAL,
        first_seen_at=base - timedelta(days=9),
        is_kev=True,
        risk_band="escalate",
    )
    # acked HIGH/act-Finding (acked zaehlt weiter als praesent).
    _create_finding(
        app,
        server_id=sid_a,
        identifier_key="CVE-A-ACK",
        severity=Severity.HIGH,
        first_seen_at=base - timedelta(days=8),
        status=FindingStatus.ACKNOWLEDGED,
        acknowledged_at=base - timedelta(days=7),
        risk_band="act",
    )
    # resolved-vor-Tagesende: an d-5 12:00 resolved -> ab d-5 weg.
    _create_finding(
        app,
        server_id=sid_a,
        identifier_key="CVE-A-RES",
        severity=Severity.MEDIUM,
        first_seen_at=base - timedelta(days=9),
        resolved_at=base - timedelta(days=5),
        status=FindingStatus.RESOLVED,
        risk_band="mitigate",
    )

    # --- Server B: nur-unknown-Severity-Finding (Kante #1). ---
    _create_finding(
        app,
        server_id=sid_b,
        identifier_key="CVE-B-UNK",
        severity=Severity.UNKNOWN,
        first_seen_at=base - timedelta(days=6),
        risk_band="noise",
    )

    # --- Server C: risk_band=NULL aber Severity gesetzt (Kante #2). ---
    _create_finding(
        app,
        server_id=sid_c,
        identifier_key="CVE-C-NULLBAND",
        severity=Severity.HIGH,
        first_seen_at=base - timedelta(days=4),
        is_kev=True,
        risk_band=None,
    )

    # Scans verteilt — had_scan-Parity testen.
    for off in (9, 8, 6, 4, 2):
        _create_scan(app, server_id=sid_a, received_at=base - timedelta(days=off))
    _create_scan(app, server_id=sid_b, received_at=base - timedelta(days=6))
    _create_scan(app, server_id=sid_c, received_at=base - timedelta(days=4))

    return [sid_a, sid_b, sid_c, sid_d]


# ---------------------------------------------------------------------------
# Paritaets-Test (ADR-Konsistenz-Pflicht): SQL == Python-Oracle
# ---------------------------------------------------------------------------


def test_frozen_matches_live_oracle_cell_for_cell(db_app: Flask) -> None:
    """Frozen-Pfad (`daily_risk_state`) == Live-Python-Oracle fuer Past-Cells.

    Zentraler Korrektheits-Beweis der ADR-0035-Addendum-Konsistenz-Pflicht.
    Vergleicht `dominant_risk_band`, `max_severity`, `kev_count`, `had_scan`
    fuer ALLE vergangenen Tage (today ausgenommen — today ist live in beiden
    Pfaden, aber wir vergleichen hier explizit die eingefrorenen Cells).
    """
    server_ids = _seed_edge_case_fleet(db_app)
    days = 30
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            inserted = finalize_pending_days(sess, now=FIXED_NOW)
            sess.commit()
            assert inserted > 0, "Finalize haette Past-Cells einfrieren muessen"

            frozen = heartbeats_for_servers(sess, server_ids, days=days, now=FIXED_NOW)
            oracle = live_heartbeats_for_servers(sess, server_ids, days=days, now=FIXED_NOW)
        finally:
            sess.close()

    today = FIXED_NOW.date()
    assert set(frozen.keys()) == set(server_ids)
    for sid in server_ids:
        fcells = {c.day: c for c in frozen[sid]}
        ocells = {c.day: c for c in oracle[sid]}
        assert set(fcells.keys()) == set(ocells.keys()), sid
        for day, ocell in ocells.items():
            if day == today:
                # today ist in beiden Pfaden live — kein frozen-Vergleich.
                continue
            fcell = fcells[day]
            assert fcell.dominant_risk_band == ocell.dominant_risk_band, (
                sid,
                day,
                fcell,
                ocell,
            )
            assert fcell.max_severity == ocell.max_severity, (sid, day, fcell, ocell)
            assert fcell.kev_count == ocell.kev_count, (sid, day, fcell, ocell)
            assert fcell.had_scan == ocell.had_scan, (sid, day, fcell, ocell)


def test_unknown_only_day_not_confused_with_no_finding(db_app: Flask) -> None:
    """Kante #1: ein Tag mit ausschliesslich unknown-Severity-Findings hat
    `max_severity == "unknown"`, NICHT None.

    Server B hat ab d-6 ein einziges unknown-Severity-Finding. Vor d-6 (kein
    Finding) muss max_severity None sein; ab d-6 muss es Severity.UNKNOWN sein.
    Der +1-Offset in der SQL-Rank-Expression ist genau dafuer da.
    """
    server_ids = _seed_edge_case_fleet(db_app)
    sid_b = server_ids[1]
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            finalize_pending_days(sess, now=FIXED_NOW)
            sess.commit()
            frozen = heartbeats_for_servers(sess, [sid_b], days=30, now=FIXED_NOW)
        finally:
            sess.close()

    by_day = {c.day: c for c in frozen[sid_b]}
    d6 = FIXED_NOW.date() - timedelta(days=6)
    d7 = FIXED_NOW.date() - timedelta(days=7)
    # Vor first_seen -> kein Finding -> None.
    assert by_day[d7].max_severity is None, by_day[d7]
    # Ab first_seen -> nur-unknown -> Severity.UNKNOWN (NICHT None).
    assert by_day[d6].max_severity == Severity.UNKNOWN, by_day[d6]
    # dominant_risk_band an d6 ist "noise" (das Band des unknown-Findings).
    assert by_day[d6].dominant_risk_band == "noise"


def test_null_risk_band_dominant_none_but_severity_set(db_app: Flask) -> None:
    """Kante #2: Finding mit risk_band=NULL -> dominant_risk_band None, aber
    max_severity / kev_count trotzdem gesetzt.

    Server C hat ab d-4 ein HIGH+KEV-Finding ohne risk_band.
    """
    server_ids = _seed_edge_case_fleet(db_app)
    sid_c = server_ids[2]
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            finalize_pending_days(sess, now=FIXED_NOW)
            sess.commit()
            frozen = heartbeats_for_servers(sess, [sid_c], days=30, now=FIXED_NOW)
        finally:
            sess.close()

    by_day = {c.day: c for c in frozen[sid_c]}
    d4 = FIXED_NOW.date() - timedelta(days=4)
    cell = by_day[d4]
    assert cell.dominant_risk_band is None, cell
    assert cell.max_severity == Severity.HIGH, cell
    assert cell.kev_count == 1, cell


# ---------------------------------------------------------------------------
# Idempotenz: ON CONFLICT DO NOTHING — frozen wird NIE ueberschrieben.
# ---------------------------------------------------------------------------


def test_finalize_is_idempotent(db_app: Flask) -> None:
    """Zwei Laeufe -> identischer Tabellen-Inhalt; frozen-Cells unveraendert.

    Zweiter Lauf darf 0 Rows einfuegen (alles bereits frozen) und KEINE
    bestehende Cell ueberschreiben (ON CONFLICT DO NOTHING).
    """
    server_ids = _seed_edge_case_fleet(db_app)
    factory = get_session_factory(db_app)

    def _snapshot() -> list[tuple]:
        with db_app.app_context():
            sess = factory()
            try:
                rows = sess.execute(
                    select(
                        DailyRiskState.server_id,
                        DailyRiskState.day,
                        DailyRiskState.dominant_risk_band,
                        DailyRiskState.max_severity,
                        DailyRiskState.kev_count,
                        DailyRiskState.had_scan,
                    ).order_by(DailyRiskState.server_id, DailyRiskState.day)
                ).all()
                return [tuple(r) for r in rows]
            finally:
                sess.close()

    with db_app.app_context():
        sess = factory()
        try:
            first = finalize_pending_days(sess, now=FIXED_NOW)
            sess.commit()
        finally:
            sess.close()
    assert first > 0
    snap1 = _snapshot()

    with db_app.app_context():
        sess = factory()
        try:
            second = finalize_pending_days(sess, now=FIXED_NOW)
            sess.commit()
        finally:
            sess.close()
    snap2 = _snapshot()

    # Zweiter Lauf fuegt nichts Neues ein (alles bereits frozen).
    assert second == 0, f"Zweiter Lauf haette 0 Rows einfuegen muessen, war {second}"
    # Tabellen-Inhalt Cell-fuer-Cell identisch.
    assert snap1 == snap2
    _ = server_ids  # nur fuer Klarheit referenziert


def test_finalize_never_touches_today(db_app: Flask) -> None:
    """today wird NIE eingefroren — nur Tage <= gestern landen in der Tabelle."""
    _seed_edge_case_fleet(db_app)
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            finalize_pending_days(sess, now=FIXED_NOW)
            sess.commit()
            max_day = sess.execute(select(func.max(DailyRiskState.day))).scalar_one_or_none()
        finally:
            sess.close()
    yesterday = FIXED_NOW.date() - timedelta(days=1)
    assert max_day is not None
    assert max_day <= yesterday, f"frozen max_day={max_day} darf today nicht enthalten"


# ---------------------------------------------------------------------------
# Catch-up: nach Luecke fuellt ein Lauf alle fehlenden Tage bis gestern.
# ---------------------------------------------------------------------------


def test_catch_up_fills_all_missing_days_after_gap(db_app: Flask) -> None:
    """Simulierte Worker-Downtime: ein spaeter Lauf finalisiert ALLE fehlenden
    `(server, day)`-Paare bis gestern (catch-up via Anti-Join).

    Setup: einfacher Server mit einem langlebigen Finding. Wir laufen
    finalize NICHT bei FIXED_NOW-5d (Downtime simuliert), sondern erst bei
    FIXED_NOW. Der eine Lauf muss alle 30 Past-Cells abdecken.
    """
    sid = _create_server(db_app, "drs-catchup")
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-CATCHUP",
        severity=Severity.HIGH,
        first_seen_at=FIXED_NOW - timedelta(days=40),  # lange vor dem Fenster
        risk_band="act",
    )
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            inserted = finalize_pending_days(sess, now=FIXED_NOW)
            sess.commit()
            # Welche Tage sind nun frozen?
            frozen_days = {
                d
                for (d,) in sess.execute(
                    select(DailyRiskState.day).where(DailyRiskState.server_id == sid)
                ).all()
            }
        finally:
            sess.close()

    today = FIXED_NOW.date()
    expected = {today - timedelta(days=off) for off in range(1, 31)}  # gestern .. today-30
    assert frozen_days == expected, frozen_days ^ expected
    # 30 Past-Tage -> 30 Inserts fuer diesen einen Server.
    assert inserted == 30, inserted
    assert today not in frozen_days


def test_catch_up_partial_gap_fills_only_missing(db_app: Flask) -> None:
    """Wenn ein Teil der Past-Tage bereits frozen ist, fuellt der Lauf nur die
    Luecken — bereits eingefrorene Tage bleiben unangetastet (Anti-Join).

    Wir frieren zunaechst mit einem frueheren `now` (FIXED_NOW - 5d) ein,
    dann mit FIXED_NOW. Der zweite Lauf darf nur die seither neu faelligen
    Tage einfuegen.
    """
    sid = _create_server(db_app, "drs-partial")
    _create_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-PARTIAL",
        severity=Severity.MEDIUM,
        first_seen_at=FIXED_NOW - timedelta(days=40),
        risk_band="mitigate",
    )
    factory = get_session_factory(db_app)
    earlier = FIXED_NOW - timedelta(days=5)
    with db_app.app_context():
        sess = factory()
        try:
            first = finalize_pending_days(sess, now=earlier)
            sess.commit()
            second = finalize_pending_days(sess, now=FIXED_NOW)
            sess.commit()
            frozen_days = {
                d
                for (d,) in sess.execute(
                    select(DailyRiskState.day).where(DailyRiskState.server_id == sid)
                ).all()
            }
        finally:
            sess.close()

    # Erster Lauf: 30 Tage bis (earlier - 1d).
    assert first == 30
    # Zweiter Lauf: nur die 5 neuen Tage [earlier .. FIXED_NOW-1d] die im
    # ersten Fenster noch today/Zukunft waren.
    assert second == 5, second
    # Gesamt: heute (FIXED_NOW) nicht enthalten.
    assert FIXED_NOW.date() not in frozen_days
    # Der frueheste frozen-Tag ist (earlier - 30d).
    assert min(frozen_days) == earlier.date() - timedelta(days=30)
    # Der spaeteste ist gestern (FIXED_NOW - 1d).
    assert max(frozen_days) == FIXED_NOW.date() - timedelta(days=1)


# Silence linter falls date-Import nur indirekt genutzt wird.
_ = date
