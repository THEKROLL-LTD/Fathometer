# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Token-Budget-Service fuer Block P (ADR-0023) — Tages-Cap mit 00:00-UTC-Reset.

Vier Operationen plus Helfer:

* :func:`maybe_reset_budget` — wenn ``now() >= reset_at``: ``used_today =
  0``, ``reset_at = naechster 00:00 UTC``. Worker ruft das pro Tick als
  Erstes auf. Returns ``True`` wenn ein Reset stattfand.
* :func:`budget_check` — ``True`` wenn ``used_today < llm_daily_token_cap``.
* :func:`budget_consume` — increment + commit. Returns neuer Wert.
* :func:`mark_exhausted_audit_once` — schreibt einmaligen
  ``llm.budget_exhausted``-Audit pro Tag (Audit-Lookup gegen den aktuellen
  Reset-Zyklus, damit kein Spam entsteht).
* :func:`estimate_tokens` — grobe Schaetzung pro Job (Pass1: 50 * #findings,
  Pass2: 2000).

Die Singleton-Row der ``settings``-Tabelle haelt
``llm_token_budget_used_today``, ``llm_token_budget_reset_at`` und den
Operator-steuerbaren Tages-Cap ``llm_daily_token_cap`` (UI: Provider-Tab
„Daily token cap"). Das frühere Env-Cap ``FM_LLM_TOKEN_BUDGET_DAILY`` /
``load_settings().llm_token_budget_daily`` wird NICHT mehr erzwungen —
es seedet nur noch den Initialwert frischer Rows (siehe
``app.settings_service.ensure_settings_row``).
"""

from __future__ import annotations

from datetime import UTC, datetime, time, timedelta

from sqlalchemy.orm import Session

from app.models import LLMJob, Setting
from app.settings_service import ensure_settings_row

# ---------------------------------------------------------------------------
# Reset-Zeitpunkt-Berechnung
# ---------------------------------------------------------------------------


def _next_utc_midnight(now: datetime) -> datetime:
    """Naechste 00:00 UTC nach ``now``.

    ``now`` muss timezone-aware (UTC) sein. Bei naive datetimes wird UTC
    angenommen (defensive).
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    tomorrow = (now + timedelta(days=1)).date()
    return datetime.combine(tomorrow, time(0, 0, 0), tzinfo=UTC)


def maybe_reset_budget(session: Session) -> bool:
    """Setzt den Tageszaehler zurueck wenn der Reset-Zeitpunkt erreicht ist.

    Liest die Singleton-Row, vergleicht ``llm_token_budget_reset_at`` mit
    ``now()`` und setzt bei Faelligkeit ``used_today = 0`` und ``reset_at``
    auf die naechste 00:00 UTC. Caller muss NICHT commit — wir committen
    selbst, damit der Reset auch dann persistiert wird wenn der Caller
    spaeter in derselben Session aborted.

    Returns ``True`` wenn ein Reset stattfand.
    """
    row = ensure_settings_row(session)
    now = datetime.now(UTC)
    reset_at = row.llm_token_budget_reset_at
    if reset_at.tzinfo is None:
        reset_at = reset_at.replace(tzinfo=UTC)
    if now < reset_at:
        return False
    row.llm_token_budget_used_today = 0
    row.llm_token_budget_reset_at = _next_utc_midnight(now)
    session.commit()
    return True


def budget_check(session: Session) -> bool:
    """``True`` wenn das Tages-Cap noch nicht erreicht ist.

    Der Cap ist Operator-steuerbar via ``settings.llm_daily_token_cap``
    (UI: Provider-Tab „Daily token cap"). Worker und Web-Container lesen
    denselben DB-Wert — kein Env-/Pod-Drift mehr (vormals
    ``load_settings().llm_token_budget_daily``).
    """
    row = ensure_settings_row(session)
    daily = int(row.llm_daily_token_cap or 0)
    return int(row.llm_token_budget_used_today or 0) < daily


def budget_consume(session: Session, tokens: int) -> int:
    """Increment ``used_today`` um ``tokens``, committet, returns neuen Wert.

    Negative ``tokens`` werden defensiv auf 0 gekappt — der Aufrufer soll
    nicht versehentlich ein Refund modellieren.
    """
    if tokens < 0:
        tokens = 0
    row = ensure_settings_row(session)
    row.llm_token_budget_used_today = int(row.llm_token_budget_used_today or 0) + int(tokens)
    session.commit()
    return int(row.llm_token_budget_used_today)


def mark_exhausted_audit_once(session: Session) -> bool:
    """Schreibt ``llm.budget_exhausted`` nur dann wenn heute noch nicht passiert.

    Idempotenz-Strategie: Audit-Lookup auf den aktuellen Reset-Zyklus.
    Wir holen ``reset_at`` und schauen ob seit dem letzten Reset (``reset_at
    - 1 day`` als untere Schranke) bereits ein ``llm.budget_exhausted``
    geschrieben wurde. Wenn ja: kein neuer Audit. Returns ``True`` wenn ein
    Audit geschrieben wurde.

    Importiert :func:`app.audit.log_event` lazy weil ``app.audit`` einen
    Flask-Import einbringt; Worker und Pytest brauchen den Lazy-Pfad
    nicht andersweitig.
    """
    from app.audit import log_event
    from app.models import AuditEvent

    row = ensure_settings_row(session)
    reset_at = row.llm_token_budget_reset_at
    if reset_at.tzinfo is None:
        reset_at = reset_at.replace(tzinfo=UTC)
    # Untere Schranke fuer den aktuellen Reset-Zyklus.
    cycle_start = reset_at - timedelta(days=1)
    from sqlalchemy import select

    existing = (
        session.execute(
            select(AuditEvent.id)
            .where(AuditEvent.action == "llm.budget_exhausted")
            .where(AuditEvent.ts >= cycle_start)
        )
        .scalars()
        .first()
    )
    if existing is not None:
        return False
    log_event(
        "llm.budget_exhausted",
        target_type="settings",
        target_id="1",
        actor="worker",
        session=session,
        metadata={
            "used_today": int(row.llm_token_budget_used_today or 0),
            "daily_cap": int(row.llm_daily_token_cap or 0),
            "reset_at": reset_at.isoformat(),
        },
    )
    session.commit()
    return True


# ---------------------------------------------------------------------------
# Token-Schaetzung pro Job
# ---------------------------------------------------------------------------


def estimate_tokens(job: LLMJob) -> int:
    """Grobe Token-Schaetzung fuer den Observation-Mode.

    * ``group_detection`` (Pass 1): 50 Tokens pro Finding (kompakte
      Tabellenzeile mit Pfad + Paketname).
    * ``risk_evaluation`` (Pass 2): konstant 2000 Tokens (Server-Kontext
      dominiert).

    Defensiv: unbekannte ``job_type`` faellt auf 1000 zurueck.
    """
    if job.job_type == "group_detection":
        finding_ids = (job.payload or {}).get("finding_ids") or []
        return max(50, 50 * len(finding_ids))
    if job.job_type == "risk_evaluation":
        return 2000
    return 1000


__all__ = [
    "budget_check",
    "budget_consume",
    "estimate_tokens",
    "mark_exhausted_audit_once",
    "maybe_reset_budget",
]


# Pflicht-Import damit der Type-Checker `Setting` nicht als unused warnt.
_ = Setting
