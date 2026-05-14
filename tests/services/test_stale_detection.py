"""Tests fuer `app.services.stale_detection` (Block D).

Reine Logik-Tests — beruehrt die DB nur fuer den Settings-Default-Pfad.
`now` wird konsequent injiziert, damit die Tests deterministisch sind.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from flask import Flask

from app.models import Server, Setting
from app.services.stale_detection import (
    get_db_stale_threshold_h,
    get_server_stale_default_h,
    is_db_stale,
    is_stale,
)

# ---------------------------------------------------------------------------
# Fixed reference time fuer alle Tests dieser Suite.
# ---------------------------------------------------------------------------

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _make_server(
    *,
    last_scan_at: datetime | None = None,
    expected_scan_interval_h: int = 24,
    revoked_at: datetime | None = None,
    retired_at: datetime | None = None,
    trivy_db_updated_at: datetime | None = None,
) -> Server:
    """Server-Instanz ohne DB-Persistenz — reine in-memory Werte fuer die Helper."""
    return Server(
        name="dummy",
        api_key_hash="x" * 64,
        expected_scan_interval_h=expected_scan_interval_h,
        last_scan_at=last_scan_at,
        revoked_at=revoked_at,
        retired_at=retired_at,
        trivy_db_updated_at=trivy_db_updated_at,
    )


# ---------------------------------------------------------------------------
# is_stale — Server-Scan-Stale
# ---------------------------------------------------------------------------


def test_is_stale_returns_true_when_never_scanned_and_active() -> None:
    srv = _make_server(last_scan_at=None)
    assert is_stale(srv, now=NOW) is True


def test_is_stale_returns_true_when_last_scan_older_than_interval() -> None:
    srv = _make_server(
        last_scan_at=NOW - timedelta(hours=25),
        expected_scan_interval_h=24,
    )
    assert is_stale(srv, now=NOW) is True


def test_is_stale_returns_false_when_last_scan_inside_interval() -> None:
    srv = _make_server(
        last_scan_at=NOW - timedelta(hours=12),
        expected_scan_interval_h=24,
    )
    assert is_stale(srv, now=NOW) is False


def test_is_stale_returns_false_for_retired_server_even_without_scan() -> None:
    """Retired Server sollen nicht permanent in 'Aufmerksamkeit noetig'
    landen — auch wenn last_scan_at NULL ist."""
    srv = _make_server(
        last_scan_at=None,
        retired_at=NOW - timedelta(hours=1),
    )
    assert is_stale(srv, now=NOW) is False


def test_is_stale_returns_false_for_retired_server_with_old_scan() -> None:
    srv = _make_server(
        last_scan_at=NOW - timedelta(days=30),
        retired_at=NOW - timedelta(hours=1),
        expected_scan_interval_h=24,
    )
    assert is_stale(srv, now=NOW) is False


def test_is_stale_returns_true_for_revoked_server_when_scan_overdue() -> None:
    """Revoked Server bleiben stale — Hinweis darauf, dass ein kaputter Key
    nicht stillschweigend ignoriert wird (siehe Docstring im Helper)."""
    srv = _make_server(
        last_scan_at=NOW - timedelta(hours=72),
        revoked_at=NOW - timedelta(hours=1),
        expected_scan_interval_h=24,
    )
    assert is_stale(srv, now=NOW) is True


def test_is_stale_returns_true_for_revoked_server_without_scan() -> None:
    srv = _make_server(
        last_scan_at=None,
        revoked_at=NOW - timedelta(hours=1),
    )
    assert is_stale(srv, now=NOW) is True


def test_is_stale_accepts_naive_datetime_as_utc() -> None:
    """Naive datetimes duerfen den Helper nicht crashen — `replace(tzinfo=UTC)`
    interpretiert sie als UTC. Wir verifizieren das Verhalten exakt."""
    naive_last_scan = (NOW - timedelta(hours=10)).replace(tzinfo=None)
    srv = _make_server(last_scan_at=naive_last_scan, expected_scan_interval_h=24)
    assert is_stale(srv, now=NOW) is False

    naive_last_scan_old = (NOW - timedelta(hours=50)).replace(tzinfo=None)
    srv_old = _make_server(last_scan_at=naive_last_scan_old, expected_scan_interval_h=24)
    assert is_stale(srv_old, now=NOW) is True


def test_is_stale_now_injection_uses_passed_value() -> None:
    """Wenn `now=datetime(...)` uebergeben wird, darf der Helper kein
    `datetime.now()` aufrufen — Aufruf bleibt deterministisch."""
    srv = _make_server(
        last_scan_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        expected_scan_interval_h=24,
    )
    # 6h spaeter — innerhalb Interval.
    near = datetime(2026, 1, 1, 6, 0, 0, tzinfo=UTC)
    assert is_stale(srv, now=near) is False
    # 25h spaeter — ausserhalb.
    far = datetime(2026, 1, 2, 1, 0, 0, tzinfo=UTC)
    assert is_stale(srv, now=far) is True


def test_is_stale_naive_now_is_interpreted_as_utc() -> None:
    srv = _make_server(
        last_scan_at=NOW - timedelta(hours=10),
        expected_scan_interval_h=24,
    )
    naive_now = NOW.replace(tzinfo=None)
    assert is_stale(srv, now=naive_now) is False


# ---------------------------------------------------------------------------
# is_db_stale — Trivy-DB-Stale
# ---------------------------------------------------------------------------


def test_is_db_stale_returns_true_when_db_never_seen_and_active() -> None:
    srv = _make_server(trivy_db_updated_at=None)
    assert is_db_stale(srv, now=NOW, threshold_h=30) is True


def test_is_db_stale_returns_false_for_retired_server() -> None:
    srv = _make_server(
        trivy_db_updated_at=None,
        retired_at=NOW - timedelta(hours=1),
    )
    assert is_db_stale(srv, now=NOW, threshold_h=30) is False


def test_is_db_stale_with_override_threshold_marks_old_db() -> None:
    srv = _make_server(trivy_db_updated_at=NOW - timedelta(hours=2))
    assert is_db_stale(srv, now=NOW, threshold_h=1) is True


def test_is_db_stale_with_override_threshold_below_age_is_false() -> None:
    srv = _make_server(trivy_db_updated_at=NOW - timedelta(hours=2))
    assert is_db_stale(srv, now=NOW, threshold_h=48) is False


def test_is_db_stale_accepts_naive_datetime_as_utc() -> None:
    naive_db = (NOW - timedelta(hours=10)).replace(tzinfo=None)
    srv = _make_server(trivy_db_updated_at=naive_db)
    assert is_db_stale(srv, now=NOW, threshold_h=30) is False
    assert is_db_stale(srv, now=NOW, threshold_h=5) is True


def test_is_db_stale_returns_true_for_revoked_server_with_old_db() -> None:
    """Revoked = nicht retired → stale-Logik greift weiter."""
    srv = _make_server(
        trivy_db_updated_at=NOW - timedelta(hours=48),
        revoked_at=NOW - timedelta(hours=1),
    )
    assert is_db_stale(srv, now=NOW, threshold_h=30) is True


# ---------------------------------------------------------------------------
# Settings-Default-Pfad (geht ueber die DB).
# ---------------------------------------------------------------------------


def test_is_db_stale_uses_settings_default_when_no_override(
    db_app: Flask,
    db_session: Any,
) -> None:
    """Ohne Override muss der Wert aus `Setting.stale_trivy_db_threshold_h`
    kommen. Wir setzen ihn explizit und pruefen den Helper unter einem
    Test-Request-Context, damit `get_session()` sauber abgeraeumt wird."""
    from app.db import close_session
    from app.settings_service import ensure_settings_row

    # Erst die Settings-Row anlegen/aendern (separate Session).
    row = ensure_settings_row(db_session)
    row.stale_trivy_db_threshold_h = 5
    db_session.commit()

    # `is_db_stale` ohne Override muss einen App-Context haben fuer
    # `get_session()` — Request-Context sorgt fuer sauberen `g.db_session`
    # Teardown.
    with db_app.test_request_context("/"):
        try:
            # DB 4h alt → noch frisch (Schwelle 5h).
            srv_fresh = _make_server(trivy_db_updated_at=NOW - timedelta(hours=4))
            assert is_db_stale(srv_fresh, now=NOW) is False

            # DB 10h alt → stale.
            srv_stale = _make_server(trivy_db_updated_at=NOW - timedelta(hours=10))
            assert is_db_stale(srv_stale, now=NOW) is True
        finally:
            close_session(None)


def test_get_db_stale_threshold_h_reads_settings(
    db_app: Flask,
    db_session: Any,
) -> None:
    from app.db import close_session
    from app.settings_service import ensure_settings_row

    row = ensure_settings_row(db_session)
    row.stale_trivy_db_threshold_h = 42
    db_session.commit()

    with db_app.test_request_context("/"):
        try:
            assert get_db_stale_threshold_h() == 42
        finally:
            close_session(None)


def test_get_server_stale_default_h_reads_settings(
    db_app: Flask,
    db_session: Any,
) -> None:
    from app.db import close_session
    from app.settings_service import ensure_settings_row

    row = ensure_settings_row(db_session)
    row.stale_threshold_h = 17
    db_session.commit()

    with db_app.test_request_context("/"):
        try:
            assert get_server_stale_default_h() == 17
        finally:
            close_session(None)


def test_settings_defaults_match_architecture(
    db_app: Flask,
    db_session: Any,
) -> None:
    """Frische DB → Settings-Row hat die §14-Defaults (48h/30h)."""
    from app.settings_service import ensure_settings_row

    row: Setting = ensure_settings_row(db_session)
    # Defaults aus Migration / ARCHITECTURE §14.
    assert row.stale_threshold_h == 48
    assert row.stale_trivy_db_threshold_h == 30


# ---------------------------------------------------------------------------
# Parametrisierte Boundary-Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hours_since_scan,interval_h,expected",
    [
        (0, 24, False),
        (23, 24, False),
        (24, 24, False),  # genau am Limit → noch nicht stale (strikt >)
        (24, 24, False),
        (25, 24, True),
        (1, 1, False),
        (2, 1, True),
    ],
)
def test_is_stale_boundary(hours_since_scan: int, interval_h: int, expected: bool) -> None:
    srv = _make_server(
        last_scan_at=NOW - timedelta(hours=hours_since_scan),
        expected_scan_interval_h=interval_h,
    )
    assert is_stale(srv, now=NOW) is expected, (
        f"hours={hours_since_scan} interval={interval_h} expected={expected}"
    )


@pytest.mark.parametrize(
    "hours_since_db,threshold_h,expected",
    [
        (0, 30, False),
        (29, 30, False),
        (30, 30, False),  # strikt > Threshold
        (31, 30, True),
        (200, 30, True),
    ],
)
def test_is_db_stale_boundary(hours_since_db: int, threshold_h: int, expected: bool) -> None:
    srv = _make_server(trivy_db_updated_at=NOW - timedelta(hours=hours_since_db))
    assert is_db_stale(srv, now=NOW, threshold_h=threshold_h) is expected, (
        f"hours={hours_since_db} threshold={threshold_h} expected={expected}"
    )
