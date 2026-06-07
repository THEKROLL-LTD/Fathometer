# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Backfill bestehender Findings mit EPSS/KEV-Daten (Block Q Phase 3, ADR-0024).

Bei jedem erfolgreichen Feed-Pull werden ALLE bestehenden Findings in
einem einzigen ``UPDATE ... FROM``-Statement angereichert. Idempotent —
Findings die schon den aktuellen Wert haben werden uebersprungen via
``IS DISTINCT FROM``-Filter (kein WAL-Write, kein Tabellen-Bloat).

Zwei Use-Cases:

1. **Initial-Bootstrap**: erster Pull nach Deploy von Block Q. Saemtliche
   in der DB befindlichen Findings haben noch ``epss_score=NULL``/
   ``is_kev=FALSE`` und werden auf einen Schlag angereichert.

2. **Laufende KEV-Nachpflege**: CISA traegt CVEs auch im Nachhinein nach.
   Wenn heute ein CVE in den KEV-Katalog wandert, sind ALLE bestehenden
   Findings mit dieser CVE-ID beim naechsten Pull-Tick auf ``is_kev=TRUE``
   gesetzt — ohne dass ein Re-Scan noetig ist.

Beide Statements committen ihre Aenderungen selbst. Aufrufer (Worker)
muessen NICHT zusaetzlich committen.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import DateTime, cast, update

from app.models import CisaKevCatalog, EpssScore, Finding

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

log = structlog.get_logger(__name__)


def backfill_epss(session: Session) -> int:
    """Reichert alle Findings mit EPSS-Scores aus ``epss_scores`` an.

    Returns:
        Anzahl der tatsaechlich aktualisierten Findings-Rows.
    """
    started_at = datetime.now(UTC)

    stmt = (
        update(Finding)
        .where(Finding.identifier_key == EpssScore.cve_id)
        .where(
            # Nur Rows aktualisieren wo sich der Wert tatsaechlich aendert
            # — spart WAL und vermeidet Auto-Vacuum-Druck.
            (Finding.epss_score.is_distinct_from(EpssScore.epss_score))
            | (Finding.epss_percentile.is_distinct_from(EpssScore.epss_percentile))
        )
        .values(
            epss_score=EpssScore.epss_score,
            epss_percentile=EpssScore.epss_percentile,
        )
        .execution_options(synchronize_session=False)
    )
    result = session.execute(stmt)
    session.commit()
    rowcount = getattr(result, "rowcount", 0)
    updated = int(rowcount or 0)

    duration_ms = int((datetime.now(UTC) - started_at).total_seconds() * 1000)
    log.info(
        "feed.epss_backfilled",
        updated_rows=updated,
        duration_ms=duration_ms,
    )
    return updated


def backfill_kev(session: Session) -> int:
    """Reichert alle Findings mit KEV-Status aus ``cisa_kev_catalog`` an.

    Setzt ``is_kev=TRUE`` und ``kev_added_at`` auf 00:00 UTC am
    ``date_added``-Tag. KEV-Listings werden nie zurueckgenommen — wir
    machen daher KEIN reverse-Backfill (Findings die nicht mehr im
    Katalog sind bleiben mit ``is_kev=TRUE``). CISA-Konvention.

    Returns:
        Anzahl der tatsaechlich aktualisierten Findings-Rows.
    """
    started_at = datetime.now(UTC)

    # ``date_added`` ist DATE; ``Finding.kev_added_at`` ist TIMESTAMPTZ.
    # SQLAlchemy ``cast(date, DateTime(timezone=True))`` rendert in
    # Postgres als ``date_added::timestamptz`` — bei einer DATE-Quelle
    # ergibt das 00:00:00 im Server-Timezone, was bei UTC-Container-
    # Setup gleich 00:00 UTC ist. Konsistent mit dem Ingest-Pfad
    # (siehe ``findings_ingest._enrich_with_feeds``).
    target_ts = cast(CisaKevCatalog.date_added, DateTime(timezone=True))

    stmt = (
        update(Finding)
        .where(Finding.identifier_key == CisaKevCatalog.cve_id)
        .where((Finding.is_kev.is_(False)) | (Finding.kev_added_at.is_distinct_from(target_ts)))
        .values(
            is_kev=True,
            kev_added_at=target_ts,
        )
        .execution_options(synchronize_session=False)
    )
    result = session.execute(stmt)
    session.commit()
    rowcount = getattr(result, "rowcount", 0)
    updated = int(rowcount or 0)

    duration_ms = int((datetime.now(UTC) - started_at).total_seconds() * 1000)
    log.info(
        "feed.kev_backfilled",
        updated_rows=updated,
        duration_ms=duration_ms,
    )
    return updated


__all__ = ["backfill_epss", "backfill_kev"]
