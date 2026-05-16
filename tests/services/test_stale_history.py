"""Unit-Tests fuer `daily_stale_server_counts` (Block M, ADR-0020).

Geprueft werden:
- Alle Server frisch -> alle 50 Werte = 0.
- Server retired mid-window -> ab Retire-Tag nicht mehr gezaehlt.
- Wochenintervall (168h) + letzter Scan vor 16 Tagen -> ab Tag 14 stale.
- Server vor 30 Tagen erstellt, kein Scan -> Tag 0..29 nicht aktiv,
  ab Tag 30 stale-zaehler erhoeht.
- Mini-Bench: 200 Server * 50 Tage < 100 ms.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from sqlalchemy import insert

from app.db import get_session_factory
from app.models import Scan, Server
from app.services.stale_history import daily_stale_server_counts

FIXED_NOW = datetime(2026, 5, 15, 12, 0, tzinfo=UTC)


def _add_server(
    app: Flask,
    *,
    name: str,
    interval_h: int = 24,
    created_at: datetime | None = None,
    retired_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=interval_h,
                retired_at=retired_at,
                revoked_at=revoked_at,
            )
            if created_at is not None:
                srv.created_at = created_at
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _add_scan(app: Flask, *, server_id: int, received_at: datetime) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            scan = Scan(server_id=server_id, received_at=received_at)
            sess.add(scan)
            sess.commit()
        finally:
            sess.close()


def test_all_servers_fresh_returns_all_zero(db_app: Flask) -> None:
    """Drei Server, taeglich frisch gescannt: alle 50 Werte = 0."""
    sid = _add_server(
        db_app,
        name="fresh-a",
        interval_h=24,
        created_at=FIXED_NOW - timedelta(days=100),
    )
    # Scan jeden Tag im 50-Tage-Fenster.
    for d in range(60):
        _add_scan(
            db_app,
            server_id=sid,
            received_at=FIXED_NOW - timedelta(days=d, hours=1),
        )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_stale_server_counts(sess, days=50, now=FIXED_NOW)
        finally:
            sess.close()

    assert len(out) == 50
    assert all(v == 0 for v in out), f"erwartet alle 0, got {out}"


def test_retire_mid_window_drops_from_count_after_retire(db_app: Flask) -> None:
    """Server retired ab Tag -20: zaehlt an Tag -19 .. heute nicht mehr.

    Setup-Detail: interval 24h x Faktor 2 = 48h Schwelle.
    Letzter Scan vor 30 Tagen, dh. an jedem Tag ab Tag -27 ist der Server
    stale (Differenz > 48h). Nach dem Retire-Tag (-20) entfaellt er aus
    der Zaehlung — *davor* (Tag -49..-21) konnten wir ihn entsprechend
    seines Stale-Status zaehlen.
    """
    retire_at = FIXED_NOW - timedelta(days=20)
    sid = _add_server(
        db_app,
        name="retired-mid",
        interval_h=24,
        created_at=FIXED_NOW - timedelta(days=100),
        retired_at=retire_at,
    )
    _add_scan(db_app, server_id=sid, received_at=FIXED_NOW - timedelta(days=30))

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_stale_server_counts(sess, days=50, now=FIXED_NOW)
        finally:
            sess.close()

    # Heute (Index 49): retired (out=0).
    assert out[-1] == 0, f"heute: erwartet 0 (retired), got {out[-1]}"
    # Tag -25 (Index 24): vor Retire-Tag, kein Scan seit Tag-30 -> stale.
    assert out[49 - 25] == 1, f"Tag-25: erwartet 1 (stale, noch nicht retired), got {out[49 - 25]}"
    # Tag -19 (nach Retire): out=0.
    assert out[49 - 19] == 0, "Tag-19: erwartet 0 (retired)"
    # Tag -45 (vor Scan-Tag-30): Scan war noch nicht da -> kein Scan im Fenster
    # an dem Zeitpunkt -> stale (pos == 0 im bisect).
    assert out[49 - 45] == 1, "Tag-45: erwartet 1 (kein Scan im Fenster)"


def test_weekly_interval_stale_after_14_days_with_factor_2(db_app: Flask) -> None:
    """Interval 168h (1 Woche): letzter Scan vor 16 Tagen.

    Stale-Schwelle = 2 x 168h = 336h = 14 Tage. Heute (Tag-0) Differenz
    zum Scan ist ~16.5d (end_of_day(heute) minus scan-Zeit) -> stale.
    An Tag-15 ist die Differenz < 1d -> nicht stale.
    """
    sid = _add_server(
        db_app,
        name="weekly-srv",
        interval_h=168,
        created_at=FIXED_NOW - timedelta(days=100),
    )
    _add_scan(db_app, server_id=sid, received_at=FIXED_NOW - timedelta(days=16))

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_stale_server_counts(sess, days=50, now=FIXED_NOW)
        finally:
            sess.close()

    # An heute (Index 49) muss er stale sein.
    assert out[-1] == 1, f"erwartet 1 stale heute, got {out[-1]}"
    # An Tag-15 ist der Scan vor ~0.5d -> nicht stale.
    assert out[49 - 15] == 0, f"Tag-15: erwartet 0 (nicht stale), got {out[49 - 15]}"
    # An Tag-1 (Index 48): Differenz ~15.5d > 14d -> stale.
    assert out[49 - 1] == 1, f"Tag-1: erwartet 1 (stale), got {out[49 - 1]}"
    # An Tag-16 (Index 33): genau am Scan-Tag, Scan war 11h59min vor end_of_day
    # -> nicht stale.
    assert out[49 - 16] == 0, "Tag-16: erwartet 0 (Scan am selben Tag)"
    # Vor dem Scan-Tag (Tag-17, Index 32): kein Scan im Fenster -> stale.
    assert out[49 - 17] == 1, "Tag-17: erwartet 1 (kein Scan im Fenster)"


def test_server_created_30d_ago_no_scan_counts_from_day_30(db_app: Flask) -> None:
    """Server vor 30 Tagen erstellt, kein Scan: ab Tag-30 aktiv und stale."""
    sid = _add_server(
        db_app,
        name="no-scan-srv",
        interval_h=24,
        created_at=FIXED_NOW - timedelta(days=30),
    )
    # Kein Scan.
    _ = sid

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            out = daily_stale_server_counts(sess, days=50, now=FIXED_NOW)
        finally:
            sess.close()

    for i in range(50):
        days_ago = 49 - i
        if days_ago > 30:
            # Vor Tag-30 nicht aktiv.
            assert out[i] == 0, f"Tag-{days_ago}: erwartet 0 (noch nicht aktiv)"
        elif days_ago <= 30:
            # Ab Tag-30 (inkl.) aktiv und sofort stale (kein Scan).
            assert out[i] == 1, f"Tag-{days_ago}: erwartet 1 (aktiv + stale)"


@pytest.mark.bench
def test_bench_200_servers_50_days_under_100ms(db_app: Flask) -> None:
    """200 Server * 50 Tage < 100 ms (Block M, ADR-0020)."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.execute(
                insert(Server),
                [
                    {
                        "name": f"bench-srv-{i:03d}",
                        "api_key_hash": "x" * 64,
                        "expected_scan_interval_h": 24,
                    }
                    for i in range(200)
                ],
            )
            sess.commit()

            # Pro Server 5 Scans im Fenster — realistisches Volumen.
            server_ids = list(
                sess.execute(__import__("sqlalchemy").select(Server.id)).scalars().all()
            )
            scan_rows = []
            for sid in server_ids:
                for d in range(5):
                    scan_rows.append(
                        {
                            "server_id": sid,
                            "received_at": FIXED_NOW - timedelta(days=d * 7),
                        }
                    )
            sess.execute(insert(Scan), scan_rows)
            sess.commit()

            t0 = time.perf_counter()
            out = daily_stale_server_counts(sess, days=50, now=FIXED_NOW)
            elapsed = time.perf_counter() - t0
        finally:
            sess.close()

    assert len(out) == 50
    assert elapsed < 0.1, f"daily_stale_server_counts zu langsam: {elapsed:.3f}s (> 100 ms)"
