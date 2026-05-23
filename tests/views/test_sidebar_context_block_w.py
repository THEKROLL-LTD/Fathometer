"""Pure-Unit-Tests fuer Block-W-Erweiterungen in `app.views._sidebar_context` (ADR-0034).

Prueft:
  - `build_sidebar_context` liefert `sidebar_groups`-Key.
  - `build_sidebar_context` liefert `server_group_aggregates`-Key.
  - Groups sind nach position ASC, name ASC sortiert.
  - Leere Groups-Liste -> `sidebar_groups` ist eine leere Liste (kein KeyError).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def _make_mock_session(groups: list[MagicMock]) -> MagicMock:
    """Stub-Session die fuer Server-Query und Group-Query unterschiedliche Results liefert."""
    session = MagicMock()

    # Wir brauchen zwei unterschiedliche .execute()-Calls:
    # 1. Server-Query: scalars().unique().all() -> []
    # 2. Group-Query:  scalars().all()          -> groups

    server_result = MagicMock()
    server_result.scalars.return_value.unique.return_value.all.return_value = []

    group_result = MagicMock()
    group_result.scalars.return_value.all.return_value = groups

    # execute wird mehrfach aufgerufen; wir nutzen side_effect-Liste.
    # Reihenfolge: Server zuerst, dann Groups, dann group_counts (execute direkt).
    group_counts_result = MagicMock()
    group_counts_result.all.return_value = []

    session.execute.side_effect = [
        server_result,
        group_result,
        group_counts_result,  # fuer group_counts()
    ]
    return session


def _call_build_sidebar_context(monkeypatch: pytest.MonkeyPatch, groups: list[MagicMock]) -> dict:
    mock_sess = _make_mock_session(groups)
    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views._sidebar_context.heartbeats_for_servers", MagicMock())

    from app.views._sidebar_context import build_sidebar_context

    return build_sidebar_context()


# ---------------------------------------------------------------------------
# sidebar_groups-Key
# ---------------------------------------------------------------------------


def test_build_sidebar_context_includes_sidebar_groups_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Context-Dict enthaelt 'sidebar_groups'-Key (kann leere Liste sein)."""
    ctx = _call_build_sidebar_context(monkeypatch, [])
    assert "sidebar_groups" in ctx, f"sidebar_groups fehlt: {list(ctx.keys())}"


def test_build_sidebar_context_sidebar_groups_is_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sidebar_groups ist eine Liste."""
    ctx = _call_build_sidebar_context(monkeypatch, [])
    assert isinstance(ctx["sidebar_groups"], list), (
        f"sidebar_groups muss list sein, got {type(ctx['sidebar_groups'])}"
    )


def test_build_sidebar_context_sidebar_groups_empty_when_no_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wenn keine Groups in DB, ist sidebar_groups eine leere Liste."""
    ctx = _call_build_sidebar_context(monkeypatch, [])
    assert ctx["sidebar_groups"] == [], ctx["sidebar_groups"]


# ---------------------------------------------------------------------------
# server_group_aggregates-Key
# ---------------------------------------------------------------------------


def test_build_sidebar_context_includes_server_group_aggregates_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Context-Dict enthaelt 'server_group_aggregates'-Key."""
    ctx = _call_build_sidebar_context(monkeypatch, [])
    assert "server_group_aggregates" in ctx, f"server_group_aggregates fehlt: {list(ctx.keys())}"


def test_build_sidebar_context_server_group_aggregates_is_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """server_group_aggregates ist ein Dict."""
    ctx = _call_build_sidebar_context(monkeypatch, [])
    assert isinstance(ctx["server_group_aggregates"], dict), (
        f"server_group_aggregates muss dict sein, got {type(ctx['server_group_aggregates'])}"
    )


# ---------------------------------------------------------------------------
# Groups sortiert nach position ASC, name ASC
# ---------------------------------------------------------------------------


def _make_group(gid: int, name: str, position: int) -> MagicMock:
    g = MagicMock()
    g.id = gid
    g.name = name
    g.position = position
    return g


def test_sidebar_groups_sorted_by_position_then_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Groups kommen in DB-Sortierungs-Reihenfolge zurueck (Query macht ORDER BY).

    Da wir die Session mocken, testen wir, dass das Resultat der Session-Query
    unveraendert in sidebar_groups landet (der Service baut die Sortierung nicht
    selbst, er delegiert das an die DB-Query).
    """
    # Die DB liefert die Groups in der sortierten Reihenfolge (position ASC, name ASC).
    group_a = _make_group(10, "Alpha", 0)
    group_b = _make_group(20, "Beta", 1)
    group_c = _make_group(30, "Gamma", 1)  # gleicher position, aber name>Beta

    # DB gibt sie in der richtigen Reihenfolge (Mock-Ausgabe == DB-Ausgabe).
    mock_sess = _make_mock_session([group_a, group_b, group_c])
    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views._sidebar_context.heartbeats_for_servers", MagicMock())

    from app.views._sidebar_context import build_sidebar_context

    ctx = build_sidebar_context()

    groups = ctx["sidebar_groups"]
    assert len(groups) == 3, f"Erwartet 3 Groups, got {len(groups)}"
    # Reihenfolge entspricht dem, was die DB (via Mock) geliefert hat.
    assert groups[0].name == "Alpha"
    assert groups[1].name == "Beta"
    assert groups[2].name == "Gamma"


# ---------------------------------------------------------------------------
# Vollstaendiger Key-Satz
# ---------------------------------------------------------------------------


def test_build_sidebar_context_has_all_required_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """build_sidebar_context liefert alle definierten Keys."""
    ctx = _call_build_sidebar_context(monkeypatch, [])
    required = {
        "sidebar_servers",
        "filter_tags",
        "active_server_id",
        "sidebar_groups",
        "server_group_aggregates",
    }
    missing = required - set(ctx.keys())
    assert not missing, f"Fehlende Keys: {missing}"
