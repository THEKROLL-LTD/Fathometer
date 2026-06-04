"""Pure-Unit-Tests fuer den persistenten Sidebar-Group-Aufklapp-Zustand (Block AC, ADR-0046).

Prueft:
  - `_parse_open_group_ids`: Garbage/Overlong/Cap-Verhalten (defensiv, niemals 500).
  - `build_sidebar_context()` liefert `sidebar_open_group_ids` aus dem Cookie.
  - Template `_group_section.html` rendert `open` + `aria-expanded` aus dem Set.
  - Beide Render-Pfade (Group-Section direkt + Server-List-Container) rendern bei
    identischem `sidebar_open_group_ids` identische `open`-Zustaende (Single-Source).

Test-Konvention: Pure-Unit, Test-Request-Context bzw. Cookie via `request.cookies`.
Keine DB, kein Endpoint-Roundtrip mit echter Session.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from flask import Flask, render_template

from app.views._sidebar_context import (
    _parse_open_group_ids,
    _read_open_group_ids,
    build_sidebar_context,
)

# ---------------------------------------------------------------------------
# _parse_open_group_ids — defensiver Cookie-Parser
# ---------------------------------------------------------------------------


def test_parse_simple_ids() -> None:
    assert _parse_open_group_ids("1,5") == {1, 5}


def test_parse_empty_string() -> None:
    assert _parse_open_group_ids("") == set()


def test_parse_garbage_keeps_only_valid_ints() -> None:
    """Garbage-Tokens werden still verworfen, nur valide Ints wirken."""
    assert _parse_open_group_ids("abc,,-1,1e9,<script>,7") == {-1, 7}


def test_parse_floats_and_whitespace() -> None:
    """`1.5` ist kein Int-Literal -> verworfen; Whitespace wird getrimmt."""
    assert _parse_open_group_ids(" 3 , 1.5 , 4 ") == {3, 4}


def test_parse_overlong_raw_string_returns_empty() -> None:
    """Roh-String > 512 Zeichen -> leeres Set (Defense-in-Depth)."""
    overlong = ",".join(str(i) for i in range(200))  # weit ueber 512 Zeichen
    assert len(overlong) > 512
    assert _parse_open_group_ids(overlong) == set()


def test_parse_caps_at_64_ids() -> None:
    """Maximal 64 IDs werden uebernommen (Roh-String <= 512 Zeichen halten)."""
    # 70 einstellige+zweistellige IDs als Komma-Liste, knapp unter 512 Zeichen.
    raw = ",".join(str(i) for i in range(70))
    assert len(raw) <= 512
    parsed = _parse_open_group_ids(raw)
    assert len(parsed) == 64


# ---------------------------------------------------------------------------
# _read_open_group_ids — Request-Kontext-Guard
# ---------------------------------------------------------------------------


def test_read_outside_request_context_returns_empty() -> None:
    """Ohne aktiven Request-Kontext -> leeres Set (statt RuntimeError)."""
    assert _read_open_group_ids() == set()


def test_read_from_cookie(app: Flask) -> None:
    with app.test_request_context("/", headers={"Cookie": "sidebar_open_groups=2,9"}):
        assert _read_open_group_ids() == {2, 9}


# ---------------------------------------------------------------------------
# build_sidebar_context — liefert sidebar_open_group_ids aus dem Cookie
# ---------------------------------------------------------------------------


def _patch_empty_session(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_sess = MagicMock()
    mock_sess.execute.return_value.scalars.return_value.unique.return_value.all.return_value = []
    mock_sess.execute.return_value.scalars.return_value.all.return_value = []
    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views._sidebar_context.group_counts", lambda sess: {})


def test_build_context_reads_open_groups_from_cookie(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_empty_session(monkeypatch)
    with app.test_request_context("/", headers={"Cookie": "sidebar_open_groups=1,5"}):
        ctx = build_sidebar_context()
    assert ctx["sidebar_open_group_ids"] == {1, 5}


def test_build_context_no_cookie_is_empty_set(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_empty_session(monkeypatch)
    with app.test_request_context("/"):
        ctx = build_sidebar_context()
    assert ctx["sidebar_open_group_ids"] == set()


# ---------------------------------------------------------------------------
# Template-Render: open + aria-expanded aus sidebar_open_group_ids
# ---------------------------------------------------------------------------


def _make_server(server_id: int, name: str, group_id: int | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=server_id,
        name=name,
        group_id=group_id,
        tag_links=[],
        revoked_at=None,
        retired_at=None,
        os=None,
        kernel=None,
        arch=None,
    )


def _make_group(gid: int, name: str, position: int = 0) -> SimpleNamespace:
    return SimpleNamespace(id=gid, name=name, position=position)


def _details_tag(html: str) -> str:
    start = html.find("<details")
    end = html.find(">", start)
    return html[start : end + 1]


def _render_group_section(app: Flask, gid: int, *, open_ids: set[int] | None) -> str:
    grp = _make_group(gid, f"grp-{gid}")
    srv = _make_server(gid * 10, f"srv-{gid}", group_id=gid)
    ctx: dict = {
        "group": grp,
        "group_servers": [srv],
        "server_group_aggregates": {gid: {"escalate": 0, "act": 0, "hosts": 1}},
        "sidebar_heartbeats": {},
        "sidebar_risk_counts": {},
        "active_server_id": None,
    }
    if open_ids is not None:
        ctx["sidebar_open_group_ids"] = open_ids
    with app.test_request_context("/"):
        return render_template("sidebar/_group_section.html", **ctx)


def test_group_section_open_when_id_in_set(app: Flask) -> None:
    html = _render_group_section(app, 5, open_ids={1, 5})
    tag = _details_tag(html)
    assert " open" in tag, f"erwartet open-Attribut: {tag!r}"
    assert 'aria-expanded="true"' in html


def test_group_section_collapsed_when_id_not_in_set(app: Flask) -> None:
    html = _render_group_section(app, 3, open_ids={1, 5})
    tag = _details_tag(html)
    assert "open" not in tag, f"darf kein open-Attribut haben: {tag!r}"
    assert 'aria-expanded="false"' in html


def test_group_section_collapsed_when_set_undefined(app: Flask) -> None:
    """Undefined-Fallback (`sidebar_open_group_ids` nicht im Context) -> collapsed.

    Deckt den Regressions-Anker ab: bestehende Renders ohne den Key bleiben
    collapsed (ADR-0034-Default).
    """
    html = _render_group_section(app, 7, open_ids=None)
    tag = _details_tag(html)
    assert "open" not in tag, f"Undefined-Fallback muss collapsed rendern: {tag!r}"
    assert 'aria-expanded="false"' in html


# ---------------------------------------------------------------------------
# Beide Render-Pfade identisch (Single-Source-Nachweis)
# ---------------------------------------------------------------------------


def _open_group_ids_from_markup(html: str) -> set[int]:
    """Extrahiert alle `hostgroup-<id>`-Details die ein `open`-Attribut tragen."""
    open_ids: set[int] = set()
    for m in re.finditer(r"<details[^>]*\bid=\"hostgroup-(\d+)\"[^>]*>", html):
        if " open" in m.group(0):
            open_ids.add(int(m.group(1)))
    return open_ids


def test_both_render_paths_identical_open_state(app: Flask) -> None:
    """Group-Section-Pfad und Server-List-Container-Pfad rendern bei identischem
    `sidebar_open_group_ids` identische open-Zustaende."""
    open_ids = {1}
    groups = [_make_group(1, "g1"), _make_group(2, "g2")]
    servers = [
        _make_server(11, "srv-11", group_id=1),
        _make_server(22, "srv-22", group_id=2),
    ]
    aggregates = {
        1: {"escalate": 0, "act": 0, "hosts": 1},
        2: {"escalate": 0, "act": 0, "hosts": 1},
    }

    with app.test_request_context("/"):
        # Pfad 1: Server-List-Container (rendert _group_section.html via include).
        list_html = render_template(
            "sidebar/_server_list.html",
            sidebar_servers=servers,
            sidebar_groups=groups,
            server_group_aggregates=aggregates,
            filter_tags=[],
            active_server_id=None,
            lazy_load_trigger=False,
            sidebar_open_group_ids=open_ids,
        )
        # Pfad 2: Group-Sections einzeln gerendert (wie der include-Body).
        section_html = ""
        for grp in groups:
            section_html += render_template(
                "sidebar/_group_section.html",
                group=grp,
                group_servers=[s for s in servers if s.group_id == grp.id],
                server_group_aggregates=aggregates,
                sidebar_heartbeats={},
                sidebar_risk_counts={},
                active_server_id=None,
                sidebar_open_group_ids=open_ids,
            )

    assert _open_group_ids_from_markup(list_html) == {1}
    assert _open_group_ids_from_markup(section_html) == {1}
    assert _open_group_ids_from_markup(list_html) == _open_group_ids_from_markup(section_html)
