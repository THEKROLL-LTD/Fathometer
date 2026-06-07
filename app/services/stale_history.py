# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Daily-Stale-Server-Counts fuer die Dashboard-Sparkline (ADR-0020).

ARCHITECTURE.md §14 definiert Server-Stale als
`now - last_scan_at > expected_scan_interval_h` (siehe
`stale_detection.is_stale`). Diese Logik wird hier in eine Mehrtagigkeits-
Reihe gewickelt — pro Tag T der letzten `days` Tage zaehlen wir Server,
die am Ende von T stale waren.

ADR-0020 spezifiziert den Stale-Faktor explizit mit `2 *
expected_scan_interval_h`. Hintergrund: ein einzelner verpasster
Scan-Slot ist Rauschen, zwei verpasste Slots sind ein echtes Signal. Die
History-Funktion bleibt damit konservativ und hat denselben Drift-Filter
wie `is_stale`.

Datenquellen: einmalig alle aktiven Server (`id, expected_scan_interval_h,
created_at, retired_at, revoked_at`) und einmalig alle Scans im Fenster
`[now - (days + max_interval_d), now]`. Server-wise sortieren, pro Tag T
binsearch den letzten Scan <= end_of_day(T). Re-Open-Trigger bei
Performance-Drift siehe ADR-0020.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Scan, Server

# ADR-0020 / §14: Stale-Schwelle ist 2 * expected_scan_interval_h.
_STALE_FACTOR: int = 2


def _resolve_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(tz=UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _end_of_day(d: date) -> datetime:
    return datetime.combine(d, time.max, tzinfo=UTC)


def _day_range(end_day: date, days: int) -> list[date]:
    """Aelteste-zuerst-Liste der letzten `days` Tage inkl. `end_day`."""
    return [end_day - timedelta(days=days - 1 - i) for i in range(days)]


@dataclass(slots=True)
class _ServerRow:
    """Schmale Server-Repraesentation fuer die Walk-Schleife."""

    id: int
    interval_h: int
    created_at: datetime
    retired_at: datetime | None
    revoked_at: datetime | None
    scans: list[datetime]  # sortiert ASC


def _compute_stale_counts(server_rows: list[_ServerRow], day_list: list[date]) -> list[int]:
    """Pure Walk ueber bereits geladene Server-Rows.

    Eingabe: jede `_ServerRow` traegt ihre Scans (sortiert ASC). Die
    Funktion entscheidet pro Tag im `day_list` (aelteste zuerst), wieviele
    Server an dem Tag aktiv UND stale waren. Direkt aus Unit-Tests ohne
    Session aufrufbar; siehe TICKET-004, Slice 3.
    """
    days = len(day_list)
    out: list[int] = [0] * days
    for idx, d in enumerate(day_list):
        end = _end_of_day(d)
        count = 0
        for row in server_rows:
            # Aktiv-am-Tag-T?
            if row.created_at > end:
                continue
            if row.retired_at is not None and row.retired_at <= end:
                continue
            if row.revoked_at is not None and row.revoked_at <= end:
                continue
            # Stale-am-Tag-T?
            pos = bisect.bisect_right(row.scans, end)
            if pos == 0:
                count += 1
                continue
            latest = row.scans[pos - 1]
            threshold = timedelta(hours=row.interval_h * _STALE_FACTOR)
            if (end - latest) > threshold:
                count += 1
        out[idx] = count
    return out


def daily_stale_server_counts(
    session: Session,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> list[int]:
    """Pro Tag T (aeltester zuerst): Anzahl aktiver Server, die am Ende von T
    stale waren.

    Aktiv-am-Tag-T:
        retired_at IS NULL OR retired_at > end_of_day(T)
        AND revoked_at IS NULL OR revoked_at > end_of_day(T)
        AND created_at <= end_of_day(T)

    Stale-am-Tag-T: kein Scan mit `received_at <= end_of_day(T)`, ODER
    `end_of_day(T) - latest_scan.received_at > 2 * expected_scan_interval_h`.
    Faktor 2 ist die Definition aus `stale_detection.is_stale()` (siehe
    ADR-0020).

    Args:
        session: Aktive DB-Session.
        days: Anzahl Tages-Buckets (Default 50). Index 0 = `now - days + 1`,
            Index `days - 1` = `now` (jeweils end-of-day).
        now: Optional fuer Test-Determinismus. Defaults zu `datetime.now(UTC)`.

    Returns:
        Liste mit `days` ints (aelteste-zuerst). Leere Flotte oder kein
        Stale-Server: alle Werte 0.

    Performance: zwei Queries (Server + Scans), Python-side Bisect-Walk.
    Bei 200 Servern * 50 Tage unter 100 ms (Mini-Bench in
    `tests/services/test_stale_history.py`). Re-Open-Trigger siehe ADR-0020.
    """
    current = _resolve_now(now)
    end_day = current.date()
    day_list = _day_range(end_day, days)

    # 1. Alle Server-Rows holen — auch retired/revoked, weil die History pro
    # Tag entscheidet, ob ein Server an dem Tag noch aktiv war.
    server_rows: list[_ServerRow] = []
    max_interval_h = 0
    server_stmt = select(
        Server.id,
        Server.expected_scan_interval_h,
        Server.created_at,
        Server.retired_at,
        Server.revoked_at,
    )
    for sid, interval_h, created_at, retired_at, revoked_at in session.execute(server_stmt).all():
        interval_int = int(interval_h)
        if interval_int > max_interval_h:
            max_interval_h = interval_int
        server_rows.append(
            _ServerRow(
                id=int(sid),
                interval_h=interval_int,
                created_at=_as_utc(created_at),
                retired_at=_as_utc(retired_at) if retired_at is not None else None,
                revoked_at=_as_utc(revoked_at) if revoked_at is not None else None,
                scans=[],
            )
        )

    if not server_rows:
        return [0] * days

    # 2. Scans der letzten `days + max_interval_d`-Tage laden — Scans aelter
    # als der aelteste Tag im Fenster minus zweimal das groesste Intervall
    # sind fuer die Stale-Berechnung an Tag 0 nicht mehr relevant (sie
    # wuerden die Schwelle ohnehin reissen). Wir holen grosszuegig damit
    # auch lange `expected_scan_interval_h`-Werte (Wochen-Scans) erfasst
    # werden.
    max_interval_d = max(1, (max_interval_h * _STALE_FACTOR + 23) // 24)
    fenster_start = current - timedelta(days=days + max_interval_d)

    scan_stmt = (
        select(Scan.server_id, Scan.received_at)
        .where(Scan.received_at >= fenster_start)
        .order_by(Scan.server_id, Scan.received_at)
    )
    scans_by_id: dict[int, list[datetime]] = {}
    for sid, received_at in session.execute(scan_stmt).all():
        scans_by_id.setdefault(int(sid), []).append(_as_utc(received_at))

    for row in server_rows:
        row.scans = scans_by_id.get(row.id, [])

    # 3. Walk pro Tag — siehe `_compute_stale_counts`.
    return _compute_stale_counts(server_rows, day_list)


__all__ = ["daily_stale_server_counts"]

# TICKET-004 Slice 3: pure Aggregations-Funktion `_compute_stale_counts` und
# `_ServerRow` werden in `tests/services/test_stale_history.py` direkt
# importiert. Sie bleiben bewusst module-private, gelten aber als stabile
# interne Schnittstelle.
