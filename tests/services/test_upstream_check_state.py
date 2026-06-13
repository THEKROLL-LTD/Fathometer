"""Pure-Unit-Tests fuer ``app.services.upstream_check_state`` (Block AI-2, ADR-0063, P1).

Zwei Surfaces:

* :func:`derive_state` — reine State-Maschine (alle Uebergaenge, injiziertes
  ``now``, TTL-Grenze, tz-naive ``checked_at``). Keine DB.
* :func:`worst_upstream_finding` — Query-Shape/Lane-Filter ueber eine Spy-Session
  (kein echtes Postgres): das Statement wird abgefangen und sein ``str()``
  inspiziert (``status = OPEN``, Lane-CASE ``= 'upstream'``, ``(server, group)``-
  Filter, Triage-Order, ``LIMIT 1``).

Voller DB-Roundtrip (echte Lane-Diskriminierung gegen Postgres) ist
db_integration und steht beim User an — hier NICHT dupliziert.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from app.services.upstream_check_state import (
    STATE_CACHED,
    STATE_DISABLED,
    STATE_DONE,
    STATE_IDLE,
    STATE_RUNNING,
    derive_state,
    worst_upstream_finding,
)

_NOW = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)
_TTL = 30


def _seed() -> SimpleNamespace:
    """Minimaler ResearchSeed-Surrogat (derive_state liest nur Identitaet)."""
    return SimpleNamespace(
        artifact_module="tailscaled",
        installed_component_version="v1.26.1",
    )


def _row(
    *,
    status: str = "done",
    checked_at: datetime | None = _NOW,
    error: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(status=status, checked_at=checked_at, error=error)


# ---------------------------------------------------------------------------
# derive_state — disabled dominiert
# ---------------------------------------------------------------------------


def test_disabled_dominates_even_with_row() -> None:
    """configured=False -> disabled, auch wenn eine done-Row + Seed existieren."""
    state = derive_state(_row(), _seed(), configured=False, ttl_days=_TTL, now=_NOW)
    assert state.state == STATE_DISABLED, state
    assert state.row is None, "disabled exposes no row"
    assert state.is_fresh is False
    assert state.checked_age is None


def test_disabled_keeps_seed_for_display() -> None:
    state = derive_state(None, _seed(), configured=False, now=_NOW)
    assert state.state == STATE_DISABLED
    assert state.seed is not None, "seed wird fuer Anzeige-Kontext durchgereicht"


# ---------------------------------------------------------------------------
# derive_state — idle
# ---------------------------------------------------------------------------


def test_idle_when_seed_none() -> None:
    """Kein researchbares Finding -> idle, auch wenn (inkonsistent) eine Row da ist."""
    state = derive_state(_row(), None, configured=True, now=_NOW)
    assert state.state == STATE_IDLE, state
    assert state.row is None


def test_idle_when_row_none() -> None:
    state = derive_state(None, _seed(), configured=True, now=_NOW)
    assert state.state == STATE_IDLE, state
    assert state.row is None
    assert state.seed is not None


# ---------------------------------------------------------------------------
# derive_state — running
# ---------------------------------------------------------------------------


def test_running_when_queued() -> None:
    state = derive_state(_row(status="queued"), _seed(), configured=True, now=_NOW)
    assert state.state == STATE_RUNNING, state
    assert state.row is not None
    assert state.is_fresh is False
    assert state.checked_age is None


def test_running_when_running() -> None:
    state = derive_state(_row(status="running"), _seed(), configured=True, now=_NOW)
    assert state.state == STATE_RUNNING, state


# ---------------------------------------------------------------------------
# derive_state — done / cached (TTL)
# ---------------------------------------------------------------------------


def test_cached_when_fresh_within_ttl() -> None:
    """done + checked_at innerhalb TTL -> cached, is_fresh=True."""
    checked = _NOW - timedelta(days=_TTL - 1)
    state = derive_state(
        _row(status="done", checked_at=checked), _seed(), configured=True, ttl_days=_TTL, now=_NOW
    )
    assert state.state == STATE_CACHED, state
    assert state.is_fresh is True
    assert state.checked_age == timedelta(days=_TTL - 1)


def test_done_when_stale_beyond_ttl() -> None:
    """done + checked_at aelter als TTL -> done (Re-Check empfohlen)."""
    checked = _NOW - timedelta(days=_TTL + 1)
    state = derive_state(
        _row(status="done", checked_at=checked), _seed(), configured=True, ttl_days=_TTL, now=_NOW
    )
    assert state.state == STATE_DONE, state
    assert state.is_fresh is False


def test_ttl_boundary_exact_is_stale() -> None:
    """Grenze exakt: age == TTL ist NICHT fresh (strikt ``<``)."""
    checked = _NOW - timedelta(days=_TTL)
    state = derive_state(
        _row(status="done", checked_at=checked), _seed(), configured=True, ttl_days=_TTL, now=_NOW
    )
    assert state.state == STATE_DONE, "age == TTL ist die Grenze: stale, nicht cached"
    assert state.is_fresh is False


def test_ttl_boundary_just_inside_is_fresh() -> None:
    """Eine Sekunde unter der TTL-Grenze -> cached."""
    checked = _NOW - timedelta(days=_TTL) + timedelta(seconds=1)
    state = derive_state(
        _row(status="done", checked_at=checked), _seed(), configured=True, ttl_days=_TTL, now=_NOW
    )
    assert state.state == STATE_CACHED, state
    assert state.is_fresh is True


def test_tz_naive_checked_at_treated_as_utc() -> None:
    """Naives ``checked_at`` wird defensiv als UTC interpretiert (kein Crash)."""
    naive = (_NOW - timedelta(days=1)).replace(tzinfo=None)
    state = derive_state(
        _row(status="done", checked_at=naive), _seed(), configured=True, ttl_days=_TTL, now=_NOW
    )
    assert state.state == STATE_CACHED, state
    assert state.checked_age == timedelta(days=1)


def test_done_with_null_checked_at_is_not_fresh() -> None:
    """done aber checked_at=None -> kein gueltiges Alter -> done (nicht cached)."""
    state = derive_state(
        _row(status="done", checked_at=None), _seed(), configured=True, ttl_days=_TTL, now=_NOW
    )
    assert state.state == STATE_DONE, state
    assert state.is_fresh is False
    assert state.checked_age is None


# ---------------------------------------------------------------------------
# derive_state — error / unbekannter Status
# ---------------------------------------------------------------------------


def test_error_status_maps_to_done_not_fresh() -> None:
    """status='error' -> done-Markup (Verdikt/Fehler-Anzeige), is_fresh=False."""
    state = derive_state(
        _row(status="error", error="couldn't determine"),
        _seed(),
        configured=True,
        now=_NOW,
    )
    assert state.state == STATE_DONE, state
    assert state.is_fresh is False
    assert state.row is not None


def test_unknown_status_maps_to_done() -> None:
    state = derive_state(_row(status="weird"), _seed(), configured=True, now=_NOW)
    assert state.state == STATE_DONE, state
    assert state.is_fresh is False


def test_default_now_branch_does_not_crash() -> None:
    """Ohne injiziertes ``now`` faellt die Funktion auf datetime.now(UTC) zurueck."""
    state = derive_state(
        _row(status="done", checked_at=datetime.now(UTC)), _seed(), configured=True, ttl_days=_TTL
    )
    assert state.state == STATE_CACHED, state


# ===========================================================================
# worst_upstream_finding — Query-Shape / Lane-Filter (Spy-Session)
# ===========================================================================


class _Result:
    def __init__(self, row: Any) -> None:
        self._row = row

    def scalars(self) -> _Result:
        return self

    def first(self) -> Any:
        return self._row


class _SpySession:
    """Faengt das an ``execute`` uebergebene Statement ab (kein echtes Postgres)."""

    def __init__(self, row: Any = None) -> None:
        self.row = row
        self.last_stmt: Any = None

    def execute(self, stmt: Any) -> _Result:
        self.last_stmt = stmt
        return _Result(self.row)


def _compiled_sql(sess: _SpySession) -> str:
    return str(sess.last_stmt).lower()


def _literal_sql(sess: _SpySession) -> str:
    """SQL mit inline-gebundenen Literalen (zeigt 'upstream' / 'OPEN' im Klartext)."""
    compiled = sess.last_stmt.compile(compile_kwargs={"literal_binds": True})
    return str(compiled).lower()


def test_worst_upstream_finding_filters_status_open_and_research_class() -> None:
    sentinel = SimpleNamespace(id=42)
    sess = _SpySession(row=sentinel)
    out = worst_upstream_finding(sess, server_id=7, group_id=3)  # type: ignore[arg-type]

    assert out is sentinel, "Top-Row wird unveraendert durchgereicht"
    sql = _compiled_sql(sess)
    assert "from findings" in sql, sql
    # (server, group)-Skopierung.
    assert "server_id" in sql and "application_group_id" in sql, sql
    # Status-OPEN-Filter ist Teil der WHERE-Klausel.
    assert "status" in sql, f"Status-Filter fehlt:\n{sql}"

    # ADR-0064: kein 'upstream'-Lane-Filter mehr; gefiltert auf das
    # researchbare Finding (has-fix lang-pkgs in der mitigate-Lane).
    literal = _literal_sql(sess)
    assert "'upstream'" not in literal, f"Upstream-Lane-Filter darf weg sein:\n{literal}"
    assert "'open'" in literal, f"Status-OPEN-Literal fehlt:\n{literal}"
    assert "'lang-pkgs'" in literal, f"lang-pkgs-Filter fehlt:\n{literal}"
    # Has-fix-Filter ueber die generierte Spalte.
    assert "has_fix" in literal and "finding_class" in literal, literal
    # ADR-0064 + Security-Re-Audit: host-updatebare lang-pkgs (ADR-0062, patch-
    # Lane) sind KEIN Anker -> WHERE schliesst host_update_available IS TRUE aus,
    # damit die Anker-Auswahl deckungsgleich mit der mitigate-Lane bleibt.
    assert "host_update_available" in literal, f"host_update-Filter fehlt:\n{literal}"
    assert "is not true" in literal, f"host_update_available IS NOT TRUE fehlt:\n{literal}"


def test_worst_upstream_finding_has_triage_order_and_limit() -> None:
    sess = _SpySession(row=None)
    worst_upstream_finding(sess, server_id=1, group_id=1)  # type: ignore[arg-type]
    sql = _compiled_sql(sess)
    # Triage-Order-Spalten (§15): KEV, EPSS, CVSS, Severity-Rank, first_seen.
    assert "is_kev" in sql, sql
    assert "epss_score" in sql, sql
    assert "cvss_v3_score" in sql, sql
    assert "first_seen_at" in sql, sql
    assert "limit" in sql, f"LIMIT 1 fehlt:\n{sql}"


def test_worst_upstream_finding_returns_none_when_empty() -> None:
    sess = _SpySession(row=None)
    assert worst_upstream_finding(sess, server_id=1, group_id=1) is None  # type: ignore[arg-type]
