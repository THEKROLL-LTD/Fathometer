"""Tages-Token-Cap fuer LLM-Anfragen.

ARCHITECTURE.md §9 ("LLM-Endpoint-Schutz"):

- Cap kommt aus `Setting.llm_daily_token_cap` (Default 1.000.000).
- 80% Verbrauch -> Warn-Banner im UI.
- 100% Verbrauch -> hartes 429 mit Reset-Hinweis auf 00:00 UTC.
- Reset taeglich um 00:00 UTC (kein Cron, sondern Zeitfenster-Query).
- Cap gilt fuer **alle** Provider, auch lokal — schuetzt gegen runaway
  Loops.

Implementierung als reine Funktionen mit `session`-Parameter; kein
globaler State, damit Tests vorhersagbar funktionieren.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import LlmMessage, Setting


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Schnappschuss des Tages-Tokens-Verbrauchs.

    `used` = `prompt_tokens + completion_tokens` aller Messages mit
    `created_at >= today_start_utc`. `cap` aus den Settings.
    """

    used: int
    cap: int
    reset_at: datetime

    @property
    def remaining(self) -> int:
        return max(0, self.cap - self.used)

    @property
    def percent(self) -> float:
        if self.cap <= 0:
            return 0.0
        return min(100.0, (self.used / self.cap) * 100.0)

    @property
    def warning_threshold(self) -> bool:
        """`True` ab 80% Verbrauch."""
        if self.cap <= 0:
            return False
        return self.used >= int(self.cap * 0.8)

    @property
    def blocked(self) -> bool:
        """`True` wenn neue Anfragen verweigert werden muessen (>= 100%)."""
        if self.cap <= 0:
            return False
        return self.used >= self.cap


def _today_start_utc(now: datetime | None = None) -> datetime:
    """00:00 UTC des aktuellen Tages."""
    n = now or datetime.now(tz=UTC)
    return datetime.combine(n.date(), time(0, 0), tzinfo=UTC)


def _next_reset_utc(now: datetime | None = None) -> datetime:
    """00:00 UTC des Folgetages — fuer `reset_at`-Anzeige."""
    return _today_start_utc(now) + timedelta(days=1)


def get_today_usage(session: Session, *, now: datetime | None = None) -> TokenUsage:
    """Liest Setting-Cap und summiert die heutigen Token-Counts."""
    setting = session.execute(select(Setting).where(Setting.id == 1)).scalar_one_or_none()
    cap = setting.llm_daily_token_cap if setting is not None else 1_000_000
    start = _today_start_utc(now)

    prompt_sum = session.execute(
        select(func.coalesce(func.sum(LlmMessage.prompt_tokens), 0)).where(
            LlmMessage.created_at >= start
        )
    ).scalar_one()
    completion_sum = session.execute(
        select(func.coalesce(func.sum(LlmMessage.completion_tokens), 0)).where(
            LlmMessage.created_at >= start
        )
    ).scalar_one()
    used = int(prompt_sum or 0) + int(completion_sum or 0)
    return TokenUsage(used=used, cap=int(cap), reset_at=_next_reset_utc(now))


def is_blocked(session: Session, *, now: datetime | None = None) -> bool:
    """Convenience: nur das `blocked`-Flag."""
    return get_today_usage(session, now=now).blocked


def is_warning_threshold(session: Session, *, now: datetime | None = None) -> bool:
    """Convenience: nur das `warning_threshold`-Flag."""
    return get_today_usage(session, now=now).warning_threshold


__all__ = [
    "TokenUsage",
    "get_today_usage",
    "is_blocked",
    "is_warning_threshold",
]
