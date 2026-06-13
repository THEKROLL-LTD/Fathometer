"""Pure-Unit-Tests fuer ``_upstream_verdict_for_snapshot`` (Block AJ, ADR-0063
§Integration).

Verifiziert die Auswahl-Logik, welches (gecachte) Upstream-Check-Verdikt in den
eingefrorenen Group-Chat-Snapshot einfliesst — ohne DB/Netz: der State-Lookup
(``lookup_state_for_group``) und das Config-Gate (``is_upstream_check_configured``)
werden in ihren Quell-Modulen gepatcht (die Helper-Funktion importiert sie
lokal). Nur **abgeschlossene** Verdikte (``status == 'done'``) gehen in den
Snapshot; queued/running/error/idle -> ``None`` (kein Block).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import app.services.upstream_check_state as ucs
import app.services.upstream_research as ur
from app.api.group_chat import _upstream_verdict_for_snapshot


def _state(row: Any) -> SimpleNamespace:
    """Minimaler ``UpstreamCheckState``-Stub (nur ``.row`` wird gelesen)."""
    return SimpleNamespace(row=row)


def _patch(monkeypatch: Any, *, configured: bool, row: Any) -> None:
    monkeypatch.setattr(ur, "is_upstream_check_configured", lambda _s: configured)
    monkeypatch.setattr(
        ucs, "lookup_state_for_group", lambda _sess, _sid, _gid, *, configured: _state(row)
    )


def test_returns_none_when_feature_disabled(monkeypatch: Any) -> None:
    # configured=False -> kein Lookup, None (auch wenn eine done-Row existierte).
    _patch(monkeypatch, configured=False, row=SimpleNamespace(status="done"))
    assert _upstream_verdict_for_snapshot(object(), 1, 2, object()) is None


def test_returns_row_for_done_verdict(monkeypatch: Any) -> None:
    row = SimpleNamespace(status="done", delivery="fixed_release_exists")
    _patch(monkeypatch, configured=True, row=row)
    assert _upstream_verdict_for_snapshot(object(), 1, 2, object()) is row


def test_returns_none_for_queued(monkeypatch: Any) -> None:
    _patch(monkeypatch, configured=True, row=SimpleNamespace(status="queued"))
    assert _upstream_verdict_for_snapshot(object(), 1, 2, object()) is None


def test_returns_none_for_running(monkeypatch: Any) -> None:
    _patch(monkeypatch, configured=True, row=SimpleNamespace(status="running"))
    assert _upstream_verdict_for_snapshot(object(), 1, 2, object()) is None


def test_returns_none_for_error(monkeypatch: Any) -> None:
    # Fehler-Verdikt ist kein abgeschlossenes Verdikt -> kein Snapshot-Block.
    _patch(monkeypatch, configured=True, row=SimpleNamespace(status="error"))
    assert _upstream_verdict_for_snapshot(object(), 1, 2, object()) is None


def test_returns_none_when_no_row(monkeypatch: Any) -> None:
    # Kein upstream-Finding / kein Cache-Eintrag -> state.row is None -> None.
    _patch(monkeypatch, configured=True, row=None)
    assert _upstream_verdict_for_snapshot(object(), 1, 2, object()) is None
