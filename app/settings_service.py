# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Service rund um die Singleton-`settings`-Zeile.

Die Tabelle haelt genau eine Zeile (Check-Constraint `id = 1`). Beim ersten
Zugriff wird sie idempotent mit Defaults aus ARCHITECTURE.md §5 angelegt:

- `severity_threshold = 'high'`
- `stale_threshold_h = 48`
- `stale_trivy_db_threshold_h = 30`
- `setup_completed_at IS NULL`

`INSERT ... ON CONFLICT (id) DO NOTHING` erzeugt die Zeile race-condition-frei
beim Start des ersten Workers.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config import load_settings
from app.db import get_session
from app.models import Setting, Severity


def ensure_settings_row(session: Session | None = None) -> Setting:
    """Stellt sicher dass die Singleton-Row existiert und gibt sie zurueck.

    Idempotent: parallele Calls aus mehreren Workern produzieren keine
    Duplikate (Check-Constraint `id = 1` plus `ON CONFLICT DO NOTHING`).
    """
    sess = session if session is not None else get_session()

    # Schneller Pfad: Zeile existiert bereits.
    existing = sess.execute(select(Setting).where(Setting.id == 1)).scalar_one_or_none()
    if existing is not None:
        return existing

    # Insert mit ON CONFLICT — die Werte muessen mit den Defaults aus der
    # Migration kompatibel sein, damit ein parallel laufender Worker hier
    # nicht in Race kommt.
    stmt = (
        pg_insert(Setting)
        .values(
            id=1,
            severity_threshold=Severity.HIGH,
            stale_threshold_h=48,
            stale_trivy_db_threshold_h=30,
            # Env ``FM_LLM_TOKEN_BUDGET_DAILY`` seedet nur den Initial-Cap
            # frischer Installs; danach ist ``llm_daily_token_cap`` (DB,
            # Operator-steuerbar via Provider-Tab) die alleinige Autorität.
            llm_daily_token_cap=int(load_settings().llm_token_budget_daily),
        )
        .on_conflict_do_nothing(index_elements=["id"])
    )
    sess.execute(stmt)
    sess.commit()

    row = sess.execute(select(Setting).where(Setting.id == 1)).scalar_one()
    return row


def get_settings_row(session: Session | None = None) -> Setting:
    """Alias auf `ensure_settings_row` — semantischer Lesezugriff."""
    return ensure_settings_row(session)


def is_setup_completed(session: Session | None = None) -> bool:
    """`True` wenn das First-Boot-Setup abgeschlossen ist."""
    sess = session if session is not None else get_session()
    completed = sess.execute(select(Setting.setup_completed_at).where(Setting.id == 1)).scalar()
    return completed is not None


def mark_setup_completed(session: Session | None = None) -> None:
    """Setzt `setup_completed_at` auf jetzt — irreversibel im UI."""
    sess = session if session is not None else get_session()
    row = ensure_settings_row(sess)
    row.setup_completed_at = datetime.now(tz=UTC)
    sess.commit()


__all__ = [
    "ensure_settings_row",
    "get_settings_row",
    "is_setup_completed",
    "mark_setup_completed",
]
