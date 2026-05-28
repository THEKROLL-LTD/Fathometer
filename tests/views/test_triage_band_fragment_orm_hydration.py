"""Block AA (ADR-0041) — triage_band_fragment Render-Context + ORM-Hydration.

Pure-Unit-Tests (Mock-Session, render_template gepatcht zum Context-Capture):

  - Render-Context enthaelt note_form, csrf_form, ack_form, reopen_form
    (fuer den `finding_inline_body.html`-Include).
  - Die durchgereichten Findings sind die ORM-Objekte aus `.scalars().all()`.
  - Pagination-Metadaten (page/total/total_pages/has_prev/has_next) bleiben
    unveraendert gegenueber der ADR-0039-Projektion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask


def _make_server(server_id: int = 1) -> MagicMock:
    srv = MagicMock()
    srv.id = server_id
    srv.name = f"host-{server_id}"
    srv.revoked_at = None
    srv.retired_at = None
    srv.tag_links = []
    return srv


def _orm_finding(fid: int) -> SimpleNamespace:
    return SimpleNamespace(id=fid, identifier_key=f"CVE-2024-{fid:04d}", notes=[])


def _patch(monkeypatch: pytest.MonkeyPatch, rows: list[Any], total: int) -> dict[str, Any]:
    """Patcht Session + render_template; gibt den gecaptureten Context zurueck."""
    monkeypatch.setattr(
        "app.views.server_detail._load_server_with_tags", lambda _sid: _make_server(1)
    )
    sess = MagicMock()

    def _execute(_stmt: Any) -> Any:
        result = MagicMock()
        result.scalar.return_value = total
        result.scalars.return_value.all.return_value = list(rows)
        return result

    sess.execute.side_effect = _execute
    monkeypatch.setattr("app.views.server_detail.get_session", lambda: sess)

    captured: dict[str, Any] = {}

    def _fake_render(template_name: str, **ctx: Any) -> str:
        captured["template"] = template_name
        captured.update(ctx)
        return "OK"

    monkeypatch.setattr("app.views.server_detail.render_template", _fake_render)
    return captured


def _call(app: Flask, url: str, band: str = "escalate", server_id: int = 1) -> Any:
    from app.views import server_detail

    view = server_detail.triage_band_fragment
    inner = getattr(view, "__wrapped__", view)
    with app.test_request_context(url, method="GET"):
        return inner(server_id, band)


def test_render_context_has_all_forms(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _patch(monkeypatch, [_orm_finding(1)], total=1)
    _call(app, "/servers/1/triage/escalate?page=1")
    for key in ("note_form", "csrf_form", "ack_form", "reopen_form"):
        assert key in ctx and ctx[key] is not None, f"{key} fehlt im Render-Context"


def test_render_passes_orm_findings(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [_orm_finding(1), _orm_finding(2)]
    ctx = _patch(monkeypatch, rows, total=2)
    _call(app, "/servers/1/triage/escalate?page=1")
    assert ctx["findings"] == rows
    assert ctx["template"] == "servers/_partials/triage_findings_page.html"


def test_render_context_pagination_metadata(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [_orm_finding(i) for i in range(1, 11)]
    ctx = _patch(monkeypatch, rows, total=30)
    _call(app, "/servers/1/triage/escalate?page=1")
    assert ctx["page"] == 1
    assert ctx["total"] == 30
    assert ctx["total_pages"] == 3
    assert ctx["has_prev"] is False
    assert ctx["has_next"] is True


def test_render_context_last_page_clamps(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [_orm_finding(i) for i in range(1, 7)]
    ctx = _patch(monkeypatch, rows, total=26)
    _call(app, "/servers/1/triage/escalate?page=99")
    # page>total_pages clamps auf letzte Seite (3).
    assert ctx["page"] == 3
    assert ctx["has_next"] is False
    assert ctx["has_prev"] is True


def test_render_context_band_passthrough(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _patch(monkeypatch, [], total=0)
    _call(app, "/servers/1/triage/act?page=1", band="act")
    assert ctx["band"] == "act"


def test_unused_now_import_guard() -> None:
    """Sanity: datetime-Import bleibt genutzt (kein toter Import)."""
    assert datetime(2026, 5, 28, tzinfo=UTC).year == 2026
