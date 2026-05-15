"""DB-Tests fuer `app.services.llm_token_tracker`.

Verifiziert:
- `percent`/`warning_threshold`/`blocked` an den 0/50/80/100%-Grenzen.
- Cap=0 (unlimited) blockiert nie.
- `reset_at` ist 00:00 UTC des Folgetages.
- `get_today_usage` summiert nur Messages mit `created_at >= today_start_utc`.
- `record_usage`-Aequivalent: wir schreiben echte `LlmMessage`-Rows mit
  `prompt_tokens`/`completion_tokens` direkt in die DB und verifizieren
  den summierten Verbrauch.

Schreibt direkt ueber `db_session` — keine HTTP-Calls noetig.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.models import (
    LlmConversation,
    LlmConversationStatus,
    LlmMessage,
    LlmMessageRole,
    Server,
    Setting,
)
from app.services.llm_token_tracker import (
    TokenUsage,
    get_today_usage,
    is_blocked,
    is_warning_threshold,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_setting(session: Any, cap: int) -> Setting:
    """Stellt eine Setting-Row mit angegebenem Cap her."""
    row = session.get(Setting, 1)
    if row is None:
        row = Setting(id=1, llm_daily_token_cap=cap)
        session.add(row)
    else:
        row.llm_daily_token_cap = cap
    session.flush()
    return row


def _make_conversation(session: Any) -> LlmConversation:
    srv = Server(name="usage-srv", api_key_hash="x" * 64, expected_scan_interval_h=24)
    session.add(srv)
    session.flush()
    ts = datetime.now(tz=UTC)
    conv = LlmConversation(
        server_id=srv.id,
        started_at=ts,
        last_message_at=ts,
        model="test-model",
        status=LlmConversationStatus.ACTIVE,
        findings_snapshot_at=ts,
    )
    session.add(conv)
    session.flush()
    return conv


def _add_message(
    session: Any,
    conv: LlmConversation,
    *,
    prompt_tokens: int,
    completion_tokens: int,
    when: datetime,
    role: LlmMessageRole = LlmMessageRole.ASSISTANT,
) -> None:
    session.add(
        LlmMessage(
            conversation_id=conv.id,
            role=role,
            content="dummy",
            created_at=when,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
    )
    session.flush()


# ---------------------------------------------------------------------------
# Property-Tests fuer die TokenUsage-Dataclass (pure)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "used,cap,expected_percent,expected_warning,expected_blocked",
    [
        (0, 100, 0.0, False, False),
        (50, 100, 50.0, False, False),
        (79, 100, 79.0, False, False),
        (80, 100, 80.0, True, False),
        (99, 100, 99.0, True, False),
        (100, 100, 100.0, True, True),
        (150, 100, 100.0, True, True),  # capped bei 100% percent
    ],
)
def test_token_usage_thresholds(
    used: int,
    cap: int,
    expected_percent: float,
    expected_warning: bool,
    expected_blocked: bool,
) -> None:
    usage = TokenUsage(used=used, cap=cap, reset_at=datetime.now(tz=UTC))
    assert usage.percent == pytest.approx(expected_percent)
    assert usage.warning_threshold is expected_warning
    assert usage.blocked is expected_blocked


def test_token_usage_remaining_capped_at_zero() -> None:
    usage = TokenUsage(used=150, cap=100, reset_at=datetime.now(tz=UTC))
    assert usage.remaining == 0


def test_token_usage_cap_zero_is_unlimited() -> None:
    """cap=0 (unlimited) => `is_blocked=False`, `percent=0` und `warning_threshold=False`."""
    usage = TokenUsage(used=1_000_000, cap=0, reset_at=datetime.now(tz=UTC))
    assert usage.blocked is False
    assert usage.warning_threshold is False
    assert usage.percent == 0.0
    # Remaining ist max(0, 0-1_000_000) = 0.
    assert usage.remaining == 0


# ---------------------------------------------------------------------------
# DB-Tests
# ---------------------------------------------------------------------------


def test_get_today_usage_empty_db_returns_zero(db_session: Any) -> None:
    _make_setting(db_session, cap=1000)
    usage = get_today_usage(db_session)
    assert usage.used == 0
    assert usage.cap == 1000
    assert usage.blocked is False
    assert usage.warning_threshold is False


def test_get_today_usage_sums_only_todays_messages(db_session: Any) -> None:
    _make_setting(db_session, cap=1000)
    conv = _make_conversation(db_session)

    now = datetime(2026, 5, 14, 12, 0, tzinfo=UTC)
    today_start = datetime(2026, 5, 14, 0, 0, tzinfo=UTC)
    yesterday = today_start - timedelta(hours=2)

    # Gestern: 500 Tokens — duerfen NICHT mitzaehlen.
    _add_message(db_session, conv, prompt_tokens=200, completion_tokens=300, when=yesterday)
    # Heute: 60 + 40 = 100 Tokens.
    _add_message(db_session, conv, prompt_tokens=60, completion_tokens=40, when=now)
    # Heute: 5 + 5 = 10 Tokens.
    _add_message(db_session, conv, prompt_tokens=5, completion_tokens=5, when=now)
    db_session.commit()

    usage = get_today_usage(db_session, now=now)
    assert usage.used == 110  # 60+40+5+5, ohne gestern.
    assert usage.cap == 1000


def test_get_today_usage_treats_null_tokens_as_zero(db_session: Any) -> None:
    """`prompt_tokens=None` darf nicht crashen."""
    _make_setting(db_session, cap=1000)
    conv = _make_conversation(db_session)
    now = datetime.now(tz=UTC)
    db_session.add(
        LlmMessage(
            conversation_id=conv.id,
            role=LlmMessageRole.ASSISTANT,
            content="dummy",
            created_at=now,
            prompt_tokens=None,
            completion_tokens=None,
        )
    )
    db_session.commit()

    usage = get_today_usage(db_session)
    assert usage.used == 0


def test_get_today_usage_blocks_at_or_above_cap(db_session: Any) -> None:
    _make_setting(db_session, cap=100)
    conv = _make_conversation(db_session)
    now = datetime.now(tz=UTC)
    _add_message(db_session, conv, prompt_tokens=60, completion_tokens=60, when=now)
    db_session.commit()

    usage = get_today_usage(db_session, now=now)
    assert usage.used == 120
    assert usage.blocked is True
    assert usage.warning_threshold is True
    assert is_blocked(db_session, now=now) is True
    assert is_warning_threshold(db_session, now=now) is True


def test_get_today_usage_warning_threshold_at_80_percent(db_session: Any) -> None:
    _make_setting(db_session, cap=100)
    conv = _make_conversation(db_session)
    now = datetime.now(tz=UTC)
    _add_message(db_session, conv, prompt_tokens=80, completion_tokens=0, when=now)
    db_session.commit()

    usage = get_today_usage(db_session, now=now)
    assert usage.used == 80
    assert usage.warning_threshold is True
    assert usage.blocked is False


def test_reset_at_is_next_day_midnight_utc(db_session: Any) -> None:
    _make_setting(db_session, cap=100)
    now = datetime(2026, 5, 14, 14, 27, 33, tzinfo=UTC)
    usage = get_today_usage(db_session, now=now)
    expected = datetime(2026, 5, 15, 0, 0, tzinfo=UTC)
    assert usage.reset_at == expected


def test_unlimited_cap_never_blocks_even_with_huge_usage(db_session: Any) -> None:
    _make_setting(db_session, cap=0)
    conv = _make_conversation(db_session)
    now = datetime.now(tz=UTC)
    _add_message(db_session, conv, prompt_tokens=10_000_000, completion_tokens=0, when=now)
    db_session.commit()

    usage = get_today_usage(db_session, now=now)
    assert usage.cap == 0
    assert usage.blocked is False
    assert usage.warning_threshold is False
