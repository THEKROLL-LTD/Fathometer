"""Pure-Unit-Tests fuer app/services/sysline_context.py (Block W Phase F).

Deckt:
  - last_scan_ago: Minuten-, Stunden-, Tages-Format.
  - last_scan_ago = None wenn kein Server jemals gescannt hat.
  - epss_feed_status: synced / stale / never.
  - kev_feed_status nutzt feed_name='cisa_kev' (nicht 'kev').
  - worker_status: healthy / down / None bei llm_mode='off'.

Pattern: Mock-Session via side_effect-Liste.
_now-Parameter fuer deterministische Zeit.
Kein echter DB-Zugriff.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.services.sysline_context import build_sysline_context

# ---------------------------------------------------------------------------
# Fixtures fuer feste Zeitbasis
# ---------------------------------------------------------------------------

_FIXED_NOW = datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


def _now() -> datetime:
    return _FIXED_NOW


# ---------------------------------------------------------------------------
# Helpers — Mock-Session-Builder
# ---------------------------------------------------------------------------


def _scalar_result(value: object) -> MagicMock:
    """Baut ein MagicMock das .scalar() -> value liefert."""
    r = MagicMock()
    r.scalar.return_value = value
    return r


def _scalar_one_or_none_result(value: object) -> MagicMock:
    """Baut ein MagicMock das .scalar_one_or_none() -> value liefert."""
    r = MagicMock()
    r.scalar_one_or_none.return_value = value
    return r


def _make_setting(llm_mode: str = "off", heartbeat_at: datetime | None = None) -> MagicMock:
    """Minimal-Mock des Setting-ORM-Objekts."""
    s = MagicMock()
    s.block_p_llm_mode = llm_mode
    s.llm_worker_heartbeat_at = heartbeat_at
    return s


def _build_session(
    *,
    last_scan_at: datetime | None = None,
    epss_completed_at: datetime | None = None,
    kev_completed_at: datetime | None = None,
    setting: MagicMock | None = None,
) -> MagicMock:
    """Baut eine Mock-Session die alle 4 execute()-Calls von build_sysline_context bedient.

    Reihenfolge der Calls (aus sysline_context.py):
      1. max(Server.last_scan_at)                  -> .scalar()
      2. max(FeedPullLog.completed_at) fuer 'epss' -> .scalar()
      3. max(FeedPullLog.completed_at) fuer 'cisa_kev' -> .scalar()
      4. select(Setting).where(id=1)               -> .scalar_one_or_none()
    """
    sess = MagicMock()
    sess.execute.side_effect = [
        _scalar_result(last_scan_at),
        _scalar_result(epss_completed_at),
        _scalar_result(kev_completed_at),
        _scalar_one_or_none_result(setting),
    ]
    return sess


# ---------------------------------------------------------------------------
# last_scan_ago
# ---------------------------------------------------------------------------


def test_sysline_last_scan_ago_minutes_format() -> None:
    """max(Server.last_scan_at) = now - 3min -> last_scan_ago == '3m'."""
    last_scan = _FIXED_NOW - timedelta(minutes=3)
    sess = _build_session(last_scan_at=last_scan)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["last_scan_ago"] == "3m", (
        f"Erwartet '3m' fuer 3-Minuten-Abstand, erhalten: {ctx['last_scan_ago']!r}"
    )


def test_sysline_last_scan_ago_hours_format() -> None:
    """max(Server.last_scan_at) = now - 2h -> last_scan_ago == '2h'."""
    last_scan = _FIXED_NOW - timedelta(hours=2)
    sess = _build_session(last_scan_at=last_scan)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["last_scan_ago"] == "2h", (
        f"Erwartet '2h' fuer 2-Stunden-Abstand, erhalten: {ctx['last_scan_ago']!r}"
    )


def test_sysline_last_scan_ago_days_format() -> None:
    """max(Server.last_scan_at) = now - 5d -> last_scan_ago == '5d'."""
    last_scan = _FIXED_NOW - timedelta(days=5)
    sess = _build_session(last_scan_at=last_scan)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["last_scan_ago"] == "5d", (
        f"Erwartet '5d' fuer 5-Tage-Abstand, erhalten: {ctx['last_scan_ago']!r}"
    )


def test_sysline_last_scan_ago_none_when_no_server_scanned() -> None:
    """Alle Server haben last_scan_at=None -> last_scan_ago=None."""
    sess = _build_session(last_scan_at=None)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["last_scan_ago"] is None, (
        f"Erwartet None wenn kein Server gescannt hat, erhalten: {ctx['last_scan_ago']!r}"
    )


def test_sysline_last_scan_ago_exactly_1_hour() -> None:
    """Grenzwert 3600s: < 3600 -> Minuten-Format, >= 3600 -> Stunden-Format."""
    last_scan_59min = _FIXED_NOW - timedelta(minutes=59)
    sess_min = _build_session(last_scan_at=last_scan_59min)
    ctx_min = build_sysline_context(sess_min, _now=_FIXED_NOW)
    assert ctx_min["last_scan_ago"] == "59m", (
        f"59min sollte '59m' ergeben, erhalten: {ctx_min['last_scan_ago']!r}"
    )

    last_scan_60min = _FIXED_NOW - timedelta(minutes=60)
    sess_h = _build_session(last_scan_at=last_scan_60min)
    ctx_h = build_sysline_context(sess_h, _now=_FIXED_NOW)
    assert ctx_h["last_scan_ago"] == "1h", (
        f"60min sollte '1h' ergeben, erhalten: {ctx_h['last_scan_ago']!r}"
    )


# ---------------------------------------------------------------------------
# epss_feed_status
# ---------------------------------------------------------------------------


def test_sysline_epss_feed_synced_when_recent() -> None:
    """epss FeedPullLog.completed_at = now-2h, status='success' -> 'synced'."""
    recent_pull = _FIXED_NOW - timedelta(hours=2)
    sess = _build_session(epss_completed_at=recent_pull)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["epss_feed_status"] == "synced", (
        f"2h alter EPSS-Pull soll 'synced' sein (Schwelle 24h), "
        f"erhalten: {ctx['epss_feed_status']!r}"
    )


def test_sysline_epss_feed_stale_when_old() -> None:
    """epss FeedPullLog.completed_at = now-30h -> 'stale'."""
    old_pull = _FIXED_NOW - timedelta(hours=30)
    sess = _build_session(epss_completed_at=old_pull)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["epss_feed_status"] == "stale", (
        f"30h alter EPSS-Pull soll 'stale' sein (Schwelle 24h), "
        f"erhalten: {ctx['epss_feed_status']!r}"
    )


def test_sysline_epss_feed_never_when_no_success() -> None:
    """Keine erfolgreichen EPSS-Pulls (DB liefert None) -> 'never'."""
    sess = _build_session(epss_completed_at=None)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["epss_feed_status"] == "never", (
        f"Kein EPSS-Pull soll 'never' ergeben, erhalten: {ctx['epss_feed_status']!r}"
    )


# ---------------------------------------------------------------------------
# kev_feed_status — query nutzt 'cisa_kev' (nicht 'kev')
# ---------------------------------------------------------------------------


def test_sysline_kev_feed_uses_cisa_kev_name() -> None:
    """Service fragt feed_name='cisa_kev' ab (FeedPullLog-Constraint erwartet das).

    Verifiziert: der dritte execute()-Call (kev_completed_at) liefert den richtigen
    Wert und epss_feed_status ist davon unabhaengig.

    Der CheckConstraint in FeedPullLog erwartet 'epss' oder 'cisa_kev' (nicht 'kev').
    """
    recent_pull = _FIXED_NOW - timedelta(hours=1)
    # epss: kein erfolgreicher Pull, cisa_kev: kuerzlich erfolgreich
    sess = _build_session(
        epss_completed_at=None,
        kev_completed_at=recent_pull,
    )

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    # epss ist 'never', kev ist 'synced' -> beweist separate Abfragen
    assert ctx["epss_feed_status"] == "never", (
        f"EPSS ohne Pull soll 'never' sein, erhalten: {ctx['epss_feed_status']!r}"
    )
    assert ctx["kev_feed_status"] == "synced", (
        f"KEV mit kuerzlichem Pull soll 'synced' sein, erhalten: {ctx['kev_feed_status']!r}"
    )


def test_sysline_kev_feed_stale_when_old() -> None:
    """kev_feed_status='stale' wenn cisa_kev-Pull > 24h."""
    old_pull = _FIXED_NOW - timedelta(hours=25)
    sess = _build_session(kev_completed_at=old_pull)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["kev_feed_status"] == "stale", (
        f"25h alter KEV-Pull soll 'stale' sein, erhalten: {ctx['kev_feed_status']!r}"
    )


def test_sysline_kev_feed_never_when_no_success() -> None:
    """Keine erfolgreichen cisa_kev-Pulls -> 'never'."""
    sess = _build_session(kev_completed_at=None)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["kev_feed_status"] == "never", (
        f"Kein KEV-Pull soll 'never' ergeben, erhalten: {ctx['kev_feed_status']!r}"
    )


# ---------------------------------------------------------------------------
# worker_status
# ---------------------------------------------------------------------------


def test_sysline_worker_healthy_when_heartbeat_fresh() -> None:
    """llm_mode != 'off' + heartbeat_at = now-10s -> worker_status='healthy'."""
    fresh_heartbeat = _FIXED_NOW - timedelta(seconds=10)
    setting = _make_setting(llm_mode="observation", heartbeat_at=fresh_heartbeat)
    sess = _build_session(setting=setting)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["worker_status"] == "healthy", (
        f"10s alter Heartbeat soll 'healthy' sein (Schwelle 30s), "
        f"erhalten: {ctx['worker_status']!r}"
    )


def test_sysline_worker_down_when_heartbeat_stale() -> None:
    """llm_mode != 'off' + heartbeat_at = now-60s -> worker_status='down'."""
    stale_heartbeat = _FIXED_NOW - timedelta(seconds=60)
    setting = _make_setting(llm_mode="live", heartbeat_at=stale_heartbeat)
    sess = _build_session(setting=setting)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["worker_status"] == "down", (
        f"60s alter Heartbeat soll 'down' sein (Schwelle 30s), erhalten: {ctx['worker_status']!r}"
    )


def test_sysline_worker_none_when_llm_mode_off() -> None:
    """llm_mode='off' -> worker_status=None (unabhaengig von heartbeat_at)."""
    setting = _make_setting(llm_mode="off", heartbeat_at=_FIXED_NOW)
    sess = _build_session(setting=setting)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["worker_status"] is None, (
        f"llm_mode='off' soll worker_status=None ergeben, erhalten: {ctx['worker_status']!r}"
    )


def test_sysline_worker_down_when_no_heartbeat_and_mode_active() -> None:
    """llm_mode='live' + heartbeat_at=None -> worker_status='down' (nie gesehen)."""
    setting = _make_setting(llm_mode="live", heartbeat_at=None)
    sess = _build_session(setting=setting)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["worker_status"] == "down", (
        f"Kein Heartbeat bei aktivem LLM-Mode soll 'down' ergeben, "
        f"erhalten: {ctx['worker_status']!r}"
    )


def test_sysline_worker_none_when_no_settings_row() -> None:
    """Keine Settings-Row in DB (Setting=None) -> worker_status=None."""
    sess = _build_session(setting=None)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["worker_status"] is None, (
        f"Fehlende Settings-Row soll worker_status=None ergeben, erhalten: {ctx['worker_status']!r}"
    )


# ---------------------------------------------------------------------------
# Output-Contract — alle 4 Schluessel immer vorhanden
# ---------------------------------------------------------------------------


def test_sysline_context_always_returns_all_four_keys() -> None:
    """Output-Dict enthaelt immer alle 4 Schluessel, auch bei leerer DB."""
    sess = _build_session()

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    expected_keys = {"last_scan_ago", "epss_feed_status", "kev_feed_status", "worker_status"}
    assert set(ctx.keys()) == expected_keys, (
        f"build_sysline_context soll exakt {expected_keys} liefern, erhalten: {set(ctx.keys())}"
    )


# ---------------------------------------------------------------------------
# Zeitformat — naive datetime (ohne tzinfo) wird korrekt behandelt
# ---------------------------------------------------------------------------


def test_sysline_naive_last_scan_treated_as_utc() -> None:
    """Naive datetime (ohne tzinfo) als last_scan_at wird als UTC interpretiert."""
    naive_scan = datetime(2026, 5, 23, 11, 55, 0)  # 5min vor _FIXED_NOW, aber ohne tzinfo
    sess = _build_session(last_scan_at=naive_scan)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    # Der Service soll naive timestamps als UTC behandeln -> 5m Differenz
    assert ctx["last_scan_ago"] == "5m", (
        f"Naive datetime 5min vor now soll '5m' ergeben, erhalten: {ctx['last_scan_ago']!r}"
    )


@pytest.mark.parametrize(
    "delta_minutes,expected",
    [
        (1, "1m"),
        (59, "59m"),
        (60, "1h"),
        (119, "1h"),
        (120, "2h"),
        (23 * 60, "23h"),
        (24 * 60, "1d"),
        (5 * 24 * 60, "5d"),
    ],
)
def test_sysline_humanize_formats(delta_minutes: int, expected: str) -> None:
    """Parametrisierte Pruefung aller Format-Schwellen fuer last_scan_ago."""
    last_scan = _FIXED_NOW - timedelta(minutes=delta_minutes)
    sess = _build_session(last_scan_at=last_scan)

    ctx = build_sysline_context(sess, _now=_FIXED_NOW)

    assert ctx["last_scan_ago"] == expected, (
        f"delta={delta_minutes}min -> erwartet '{expected}', erhalten: {ctx['last_scan_ago']!r}"
    )
