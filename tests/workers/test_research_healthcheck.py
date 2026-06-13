# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pure-Unit-Tests fuer ``app.workers.research_healthcheck`` (Block AI, ADR-0063, P5).

Die ``_is_alive``-Entscheidung wird aus ``app.workers.healthcheck`` geteilt; der
Research-Healthcheck setzt nur einen anderen Heartbeat-Spaltennamen + denselben
30s-Schwellwert. DB-backed ``main()``-Roundtrip ist db_integration (beim User).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.workers.healthcheck import _is_alive
from app.workers.research_healthcheck import HEARTBEAT_MAX_AGE_SEC


def test_no_heartbeat_is_unhealthy() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    assert _is_alive(None, now, HEARTBEAT_MAX_AGE_SEC) is False


def test_fresh_heartbeat_is_healthy() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    hb = now - timedelta(seconds=5)
    assert _is_alive(hb, now, HEARTBEAT_MAX_AGE_SEC) is True


def test_stale_heartbeat_is_unhealthy() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    hb = now - timedelta(seconds=HEARTBEAT_MAX_AGE_SEC + 1)
    assert _is_alive(hb, now, HEARTBEAT_MAX_AGE_SEC) is False


def test_boundary_heartbeat_is_healthy() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    hb = now - timedelta(seconds=HEARTBEAT_MAX_AGE_SEC)
    assert _is_alive(hb, now, HEARTBEAT_MAX_AGE_SEC) is True


def test_naive_heartbeat_treated_as_utc() -> None:
    now = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
    hb_naive = (now - timedelta(seconds=5)).replace(tzinfo=None)
    assert _is_alive(hb_naive, now, HEARTBEAT_MAX_AGE_SEC) is True


def test_research_healthcheck_threshold_is_30s() -> None:
    assert HEARTBEAT_MAX_AGE_SEC == 30
