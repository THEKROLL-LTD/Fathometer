"""Block N (ADR-0021) — Semver-/Outdated-Helper Tests.

Sammelt die im Block-Brief Task #2 + #11 geforderten Cases plus zusaetzliche
Edge-Cases fuer naive Timestamps und die `is_*_outdated`-Wrapper.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from app.config import Settings
from app.services.agent_version import (
    is_agent_outdated,
    is_trivy_db_outdated,
    is_trivy_outdated,
    version_lt,
)

# ---------------------------------------------------------------------------
# version_lt
# ---------------------------------------------------------------------------


def test_version_lt_semver_edges() -> None:
    assert version_lt("0.1.0", "0.2.0") is True
    assert version_lt("0.2.0", "0.1.0") is False
    # 10 > 9 numerisch (kein lexikalischer Vergleich!).
    assert version_lt("0.10.0", "0.9.0") is False
    assert version_lt("0.9.0", "0.10.0") is True


def test_version_lt_patch_levels() -> None:
    assert version_lt("0.2.0", "0.2.1") is True
    assert version_lt("0.2.1", "0.2.0") is False
    assert version_lt("0.2.1", "0.2.1") is False


def test_version_lt_prerelease_is_lt_release() -> None:
    """`0.2.0-rc1 < 0.2.0` laut PEP-440 / SemVer."""
    assert version_lt("0.2.0-rc1", "0.2.0") is True
    assert version_lt("0.2.0", "0.2.0-rc1") is False


def test_version_lt_none_and_invalid() -> None:
    # Unbekannte Versionen sind konservativ veraltet.
    assert version_lt(None, "0.1.0") is True
    assert version_lt("nonsense", "0.1.0") is True
    assert version_lt("", "0.1.0") is True
    # Keine Referenz, kein Vergleich.
    assert version_lt("0.1.0", None) is False
    assert version_lt(None, None) is False


# ---------------------------------------------------------------------------
# is_agent_outdated / is_trivy_outdated
# ---------------------------------------------------------------------------


def _server(**kwargs: Any) -> Any:
    """Light-weight Server-Stub mit den Feldern, die die Helper lesen."""
    defaults: dict[str, Any] = {
        "agent_version": None,
        "trivy_version": None,
        "trivy_db_updated_at": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_is_agent_outdated_below_min() -> None:
    srv = _server(agent_version="0.0.5")
    assert is_agent_outdated(srv) is True


def test_is_agent_outdated_at_min_is_not_outdated() -> None:
    srv = _server(agent_version=Settings.MIN_AGENT_VERSION)
    # `version_lt(MIN, MIN)` ist False → NICHT outdated.
    assert is_agent_outdated(srv) is False


def test_is_agent_outdated_current_is_not_outdated() -> None:
    srv = _server(agent_version=Settings.CURRENT_AGENT_VERSION)
    assert is_agent_outdated(srv) is False


def test_is_agent_outdated_none_is_outdated() -> None:
    srv = _server(agent_version=None)
    assert is_agent_outdated(srv) is True


def test_is_trivy_outdated_below_min() -> None:
    srv = _server(trivy_version="0.50.0")
    assert is_trivy_outdated(srv) is True


def test_is_trivy_outdated_recommended_is_not_outdated() -> None:
    srv = _server(trivy_version=Settings.RECOMMENDED_TRIVY_VERSION)
    assert is_trivy_outdated(srv) is False


def test_is_trivy_outdated_none_is_outdated() -> None:
    srv = _server(trivy_version=None)
    assert is_trivy_outdated(srv) is True


# ---------------------------------------------------------------------------
# is_trivy_db_outdated
# ---------------------------------------------------------------------------


def test_is_trivy_db_outdated_none_is_outdated() -> None:
    assert is_trivy_db_outdated(_server(trivy_db_updated_at=None)) is True


def test_is_trivy_db_outdated_recent_is_fresh() -> None:
    now = datetime.now(tz=UTC)
    assert (
        is_trivy_db_outdated(_server(trivy_db_updated_at=now - timedelta(days=3)), now=now) is False
    )


def test_is_trivy_db_outdated_old_is_outdated() -> None:
    now = datetime.now(tz=UTC)
    assert (
        is_trivy_db_outdated(_server(trivy_db_updated_at=now - timedelta(days=10)), now=now) is True
    )


def test_is_trivy_db_outdated_exactly_at_threshold_is_fresh() -> None:
    """Threshold `> 7d` (strikt) → genau 7 Tage zaehlt noch als frisch."""
    now = datetime.now(tz=UTC)
    seven_days = now - timedelta(days=Settings.TRIVY_DB_STALE_THRESHOLD_DAYS)
    assert is_trivy_db_outdated(_server(trivy_db_updated_at=seven_days), now=now) is False


def test_is_trivy_db_outdated_naive_datetime_treated_as_utc() -> None:
    """DB liefert manchmal naive Timestamps — Helper darf nicht crashen."""
    now = datetime.now(tz=UTC)
    naive = (now - timedelta(days=10)).replace(tzinfo=None)
    assert is_trivy_db_outdated(_server(trivy_db_updated_at=naive), now=now) is True
