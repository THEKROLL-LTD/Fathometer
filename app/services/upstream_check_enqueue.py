# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Enqueue-Service fuer die agentische Upstream-Update-Suche (Block AI, ADR-0063, P5).

Eine Tabelle = Queue + Request + Cache: ``upstream_check_results`` (Cache-Key
``UNIQUE(artifact_module, installed_version)``) ist zugleich Job-Queue,
Research-Request und Ergebnis-Cache. Eine Zeile pro Artefakt@Version = ein
In-Flight-Job = ein Cache-Eintrag. Das mappt direkt auf die ADR-UI-States
idle/running/done/cached.

:func:`enqueue_upstream_check` ist der einzige Schreib-Pfad fuer das Anstossen
eines Checks. Idempotent gegen Doppelklick (laufende/wartende Zeile bleibt
unangetastet) und gegen Cache-Hit (frisches Verdikt wird nicht neu gesucht).

**Transaktionsneutral:** der Service committet NICHT — der Caller (HTTP-Route
in AI-2 bzw. ein Test) committet. Das spiegelt das bestehende Service-Muster.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import UpstreamCheckResult
from app.services.upstream_seed import build_research_seed

log = structlog.get_logger(__name__)


def _default_ttl_days() -> int:
    """TTL fuer gecachte Verdikte in Tagen.

    Operator-uebersteuerbar via ``FM_UPSTREAM_CHECK_TTL_DAYS`` — KEINE neue
    Pflicht-Env (Default 14). Defensiv: ungueltige Werte fallen auf den Default
    zurueck, damit der Enqueue-Pfad nie an einer Fehlkonfiguration crasht.
    """
    raw = os.environ.get("FM_UPSTREAM_CHECK_TTL_DAYS")
    if raw is None:
        return 14
    try:
        value = int(raw)
    except ValueError:
        return 14
    return value if value > 0 else 14


#: Default-TTL (Tage) fuer gecachte Verdikte. Modul-Konstante fuer Tests/Caller.
UPSTREAM_CHECK_TTL_DAYS: int = _default_ttl_days()

#: Queue-Status-Werte, die einen laufenden/wartenden Job markieren — fuer die
#: Doppel-Enqueue-Sperre (Button-Doppelklick-Schutz).
_IN_FLIGHT_STATES: frozenset[str] = frozenset({"queued", "running"})


def _is_fresh(row: UpstreamCheckResult, *, ttl_days: int, now: datetime) -> bool:
    """``True`` wenn ``row`` ein frisches ``done``-Verdikt traegt (Cache-Hit).

    Frisch = ``status == 'done'`` UND ``checked_at`` juenger als ``ttl_days``.
    Defensiv gegen tz-naive ``checked_at`` (Backfill-Edge-Case) — als UTC lesen.
    """
    if row.status != "done":
        return False
    checked_at = row.checked_at
    if checked_at is None:
        return False
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=UTC)
    return (now - checked_at) < timedelta(days=ttl_days)


def enqueue_upstream_check(
    session: Session,
    finding: Any,
    *,
    ttl_days: int | None = None,
    force: bool = False,
) -> UpstreamCheckResult | None:
    """Enqueued (oder findet) einen Upstream-Check fuer ein ``Finding``.

    Ablauf:

    1. ``build_research_seed(finding)`` — bei ``None`` ist das Finding nicht
       researchbar (kein lang-pkgs-Fix etc.) -> ``return None``.
    2. Bestehende Zeile per ``(artifact_module, installed_component_version)``
       laden.
    3. **Cache-Hit (idempotent):** existiert eine frische ``done``-Zeile (juenger
       als ``ttl_days``) und nicht ``force`` -> unveraendert zurueckgeben (kein
       Re-Run).
    4. **In-Flight (idempotent):** existiert eine ``queued``/``running``-Zeile
       -> unveraendert zurueckgeben (Doppelklick-Schutz, kein Doppel-Enqueue).
    5. **Sonst (Miss / stale / force / error-retry):** Zeile auf ``queued``
       zuruecksetzen bzw. neu anlegen, Seed-Snapshot fuellen, Verdikt-Felder
       leeren, ``attempts=0``.

    Transaktionsneutral — kein ``commit``. Der Caller committet.
    """
    seed = build_research_seed(finding)
    if seed is None:
        return None

    effective_ttl = ttl_days if ttl_days is not None else UPSTREAM_CHECK_TTL_DAYS
    now = datetime.now(UTC)

    row = _select_existing(session, seed)

    if row is not None and not force:
        # Cache-Hit: frisches Verdikt -> unveraendert zurueck (kein Re-Run).
        if _is_fresh(row, ttl_days=effective_ttl, now=now):
            log.info(
                "upstream_check.enqueue_cache_hit",
                artifact_module=seed.artifact_module,
                installed_version=seed.installed_component_version,
            )
            return row
        # In-Flight: laufender/wartender Job -> unveraendert zurueck
        # (Doppelklick-Schutz).
        if row.status in _IN_FLIGHT_STATES:
            log.info(
                "upstream_check.enqueue_already_in_flight",
                artifact_module=seed.artifact_module,
                installed_version=seed.installed_component_version,
                status=row.status,
            )
            return row

    if row is None:
        # Insert-Pfad — race-sicher gegen Parallel-Enqueue desselben
        # (artifact_module, installed_version): der UNIQUE-Constraint wuerde
        # beim Commit eines zweiten Enqueues knallen (-> 500 im Caller). Wir
        # umschliessen add+flush mit einem Savepoint; faengt der Flush einen
        # IntegrityError (die andere Transaktion war schneller), re-selecten wir
        # die nun existierende Zeile und wenden die gewohnte Idempotenz-Logik
        # darauf an.
        row = _insert_or_select_existing(session, seed, force=force, ttl=effective_ttl, now=now)
        if row is None:  # pragma: no cover — Re-Select schlaegt praktisch nie fehl
            return None
        if not force and _is_idempotent_hit(row, ttl_days=effective_ttl, now=now):
            return row

    _apply_queued_snapshot(row, seed, now=now)

    log.info(
        "upstream_check.enqueued",
        artifact_module=seed.artifact_module,
        installed_version=seed.installed_component_version,
        force=force,
    )
    return row


def _select_existing(session: Session, seed: Any) -> UpstreamCheckResult | None:
    """Laedt die Zeile per ``(artifact_module, installed_version)`` oder ``None``."""
    return session.execute(
        select(UpstreamCheckResult).where(
            UpstreamCheckResult.artifact_module == seed.artifact_module,
            UpstreamCheckResult.installed_version == seed.installed_component_version,
        )
    ).scalar_one_or_none()


def _insert_or_select_existing(
    session: Session, seed: Any, *, force: bool, ttl: int, now: datetime
) -> UpstreamCheckResult | None:
    """Fuegt eine neue ``queued``-Zeile ein; bei Parallel-Race re-selectet sie.

    Savepoint-geschuetztes ``add``+``flush``: faengt der Flush einen
    ``IntegrityError`` (eine andere Transaktion hat die ``UNIQUE``-Zeile gerade
    angelegt), rollt der Savepoint zurueck und wir re-selecten die nun
    vorhandene Zeile. Transaktionsneutral — kein ``commit`` (der Savepoint via
    ``begin_nested`` ist erlaubt; der Caller committet die aeussere TX).
    """
    new_row = UpstreamCheckResult(
        artifact_module=seed.artifact_module,
        installed_version=seed.installed_component_version,
    )
    try:
        with session.begin_nested():
            session.add(new_row)
            session.flush()
        return new_row
    except IntegrityError:
        log.info(
            "upstream_check.enqueue_insert_race_reselect",
            artifact_module=seed.artifact_module,
            installed_version=seed.installed_component_version,
        )
        existing = _select_existing(session, seed)
        if existing is None:  # pragma: no cover — die Zeile MUSS jetzt existieren
            return None
        return existing


def _is_idempotent_hit(row: UpstreamCheckResult, *, ttl_days: int, now: datetime) -> bool:
    """``True`` wenn die (re-selectete) Zeile als Cache-Hit/In-Flight stehen bleibt."""
    if _is_fresh(row, ttl_days=ttl_days, now=now):
        return True
    return row.status in _IN_FLIGHT_STATES


def _apply_queued_snapshot(row: UpstreamCheckResult, seed: Any, *, now: datetime) -> None:
    """Setzt ``row`` auf ``queued`` + fuellt Seed-Snapshot + leert Verdikt-Felder."""
    row.status = "queued"
    row.attempts = 0
    row.picked_up_at = None
    row.picked_up_by = None
    row.next_attempt_at = None
    row.requested_at = now

    # Seed-Snapshot (damit der Worker ohne das Finding auskommt).
    row.cve = seed.cve
    row.vulnerable_component = seed.vulnerable_component
    row.fixing_component_version = seed.fixing_component_version
    row.ecosystem = seed.ecosystem
    row.binary_path = seed.binary_path
    row.search_hint = seed.search_hint
    row.description = seed.description

    # Verdikt-Felder leeren (alter Cache-Eintrag wird ungueltig).
    row.delivery = None
    row.latest_release_component_version = None
    row.fixed_build_release = None
    row.fixed_build_release_date = None
    row.operator_action = None
    row.confidence = None
    row.sources_used = None
    row.reasoning = None
    row.error = None
    row.model = None


__all__ = ["UPSTREAM_CHECK_TTL_DAYS", "enqueue_upstream_check"]
