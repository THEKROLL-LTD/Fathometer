"""Template-Smoke-Tests fuer Sidebar-Group-Section-Rendering (Block W, ADR-0034).

Prueft:
  - Group-Sektion erscheint VOR ungrouped-Hosts im Markup.
  - `<details>` ohne `open`-Attribut (default collapsed).
  - Keine Gruppen -> flache Liste, kein `<details>`.
  - Group-Header zeigt server_count + escalate/act-Counts.

Wichtig: Template-Jinja2 `selectattr('group_id', 'equalto', N)` funktioniert
NICHT korrekt mit `unittest.mock.MagicMock`-Objekten (Jinja2 nutzt einen
eigenen Attribut-Getter der MagicMock's __getattr__ nicht konsistent triggert).
Wir verwenden daher `types.SimpleNamespace` fuer Server-Objekte die durch
`selectattr` gefiltert werden muessen.
"""

from __future__ import annotations

from types import SimpleNamespace

from flask import Flask

# ---------------------------------------------------------------------------
# Mock-Helper
# ---------------------------------------------------------------------------


def _make_server(
    server_id: int,
    name: str,
    group_id: int | None = None,
) -> SimpleNamespace:
    """Server-Objekt als SimpleNamespace — Jinja2-selectattr-kompatibel.

    MagicMock-Objekte werden von Jinja2's selectattr-Filter nicht korrekt
    verarbeitet. SimpleNamespace hat echte Slots fuer Attribut-Zugriff.
    """
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


def _render_server_list(
    app: Flask,
    *,
    sidebar_servers: list,
    sidebar_groups: list,
    server_group_aggregates: dict,
    sidebar_heartbeats: dict | None = None,
    sidebar_risk_counts: dict | None = None,
    hosts_total: int | None = None,
    alarm_count: int | None = None,
) -> str:
    from flask import render_template

    ctx: dict = {
        "sidebar_servers": sidebar_servers,
        "sidebar_groups": sidebar_groups,
        "server_group_aggregates": server_group_aggregates,
        "filter_tags": [],
        "active_server_id": None,
        "lazy_load_trigger": False,
    }
    if sidebar_heartbeats is not None:
        ctx["sidebar_heartbeats"] = sidebar_heartbeats
    if sidebar_risk_counts is not None:
        ctx["sidebar_risk_counts"] = sidebar_risk_counts
    if hosts_total is not None:
        ctx["hosts_total"] = hosts_total
    if alarm_count is not None:
        ctx["alarm_count"] = alarm_count

    with app.test_request_context("/"):
        return render_template("sidebar/_server_list.html", **ctx)


def _render_group_section(
    app: Flask,
    *,
    group: SimpleNamespace,
    group_servers: list,
    server_group_aggregates: dict,
    sidebar_heartbeats: dict | None = None,
    sidebar_risk_counts: dict | None = None,
    active_server_id: int | None = None,
) -> str:
    from flask import render_template

    ctx = {
        "group": group,
        "group_servers": group_servers,
        "server_group_aggregates": server_group_aggregates,
        "sidebar_heartbeats": sidebar_heartbeats or {},
        "sidebar_risk_counts": sidebar_risk_counts or {},
        "active_server_id": active_server_id,
    }
    with app.test_request_context("/"):
        return render_template("sidebar/_group_section.html", **ctx)


# ---------------------------------------------------------------------------
# Reihenfolge: Groups oben, Ungrouped unten
# ---------------------------------------------------------------------------


def test_sidebar_renders_groups_above_ungrouped(app: Flask) -> None:
    """Group-Sektion erscheint VOR ungroupten Hosts im Markup."""
    grp = _make_group(1, "ProdGroup")
    grouped_srv = _make_server(10, "srv-grouped", group_id=1)
    ungrouped_srv = _make_server(20, "srv-ungrouped", group_id=None)

    html = _render_server_list(
        app,
        sidebar_servers=[grouped_srv, ungrouped_srv],
        sidebar_groups=[grp],
        server_group_aggregates={},
    )

    # Group-Section-Marker (hostgroup-1) muss VOR dem ungrouped-Server stehen.
    pos_group = html.find("hostgroup-1")
    pos_ungrouped = html.find("srv-ungrouped")
    assert pos_group != -1, f"Group-Section-Marker 'hostgroup-1' nicht gefunden: {html[:500]}"
    assert pos_ungrouped != -1, f"Ungrouped-Server 'srv-ungrouped' nicht gefunden: {html[:500]}"
    assert pos_group < pos_ungrouped, (
        f"Group-Sektion (pos {pos_group}) soll vor ungrouped-Server (pos {pos_ungrouped}) stehen"
    )


def test_sidebar_renders_groups_even_with_no_ungrouped(app: Flask) -> None:
    """Wenn alle Server einer Group gehoeren, gibt es keinen ungrouped-Bereich."""
    grp = _make_group(1, "AllGrouped")
    srv1 = _make_server(1, "srv-a", group_id=1)
    srv2 = _make_server(2, "srv-b", group_id=1)

    html = _render_server_list(
        app,
        sidebar_servers=[srv1, srv2],
        sidebar_groups=[grp],
        server_group_aggregates={},
    )

    assert "hostgroup-1" in html, "Group-Section-Marker erwartet"
    # Kein ungrouped-Bereich (kein second group without header)
    assert html.count("<details") == 1, (
        f"Genau eine details-Section erwartet, got {html.count('<details')}"
    )


# ---------------------------------------------------------------------------
# Default collapsed
# ---------------------------------------------------------------------------


def test_sidebar_group_section_default_collapsed(app: Flask) -> None:
    """<details> ohne `open`-Attribut = eingeklappt (Default, ADR-0034)."""
    grp = _make_group(5, "TestGroup")
    srv = _make_server(1, "srv-01", group_id=5)
    agg = {5: {"escalate": 0, "act": 0, "hosts": 1}}

    html = _render_group_section(
        app,
        group=grp,
        group_servers=[srv],
        server_group_aggregates=agg,
    )

    assert "<details" in html, "<details>-Element erwartet"
    # Kein `open`-Attribut -> eingeklappt
    details_start = html.find("<details")
    details_end = html.find(">", details_start)
    details_tag = html[details_start : details_end + 1]
    assert "open" not in details_tag, (
        f"<details> darf kein 'open'-Attribut haben (default collapsed): {details_tag!r}"
    )


# ---------------------------------------------------------------------------
# Keine Groups -> flache Liste
# ---------------------------------------------------------------------------


def test_sidebar_empty_groups_flat_list(app: Flask) -> None:
    """Wenn sidebar_groups=[], wird eine flache Host-Liste gerendert (kein <details>)."""
    srv1 = _make_server(1, "flat-srv-1")
    srv2 = _make_server(2, "flat-srv-2")

    html = _render_server_list(
        app,
        sidebar_servers=[srv1, srv2],
        sidebar_groups=[],
        server_group_aggregates={},
    )

    assert "<details" not in html, (
        f"Keine <details>-Elemente bei leerer sidebar_groups erwartet: {html[:500]}"
    )
    assert "flat-srv-1" in html, "flat-srv-1 muss in der flachen Liste stehen"
    assert "flat-srv-2" in html, "flat-srv-2 muss in der flachen Liste stehen"


# ---------------------------------------------------------------------------
# Group-Header zeigt host_count + escalate/act-Counts
# ---------------------------------------------------------------------------


def test_sidebar_group_header_shows_host_count_and_escalate_act(app: Flask) -> None:
    """Group-Header zeigt server_count + escalate/act-Counts aus server_group_aggregates."""
    grp = _make_group(7, "MonitoredGroup")
    srv1 = _make_server(11, "srv-11", group_id=7)
    srv2 = _make_server(12, "srv-12", group_id=7)

    agg = {7: {"escalate": 3, "act": 1, "hosts": 2}}

    html = _render_group_section(
        app,
        group=grp,
        group_servers=[srv1, srv2],
        server_group_aggregates=agg,
    )

    # Host-Count aus len(group_servers) = 2
    assert ">2<" in html or ">2 " in html or "2</span>" in html or ">2\n" in html, (
        f"host_count=2 nicht im Markup: {html}"
    )
    # escalate-Count = 3
    assert "3" in html, f"escalate_count=3 nicht im Markup: {html}"
    # act-Count = 1
    assert "1" in html, f"act_count=1 nicht im Markup: {html}"


def test_sidebar_group_header_shows_dash_when_escalate_zero(app: Flask) -> None:
    """Wenn escalate=0, zeigt der Header '—' statt '0'."""
    grp = _make_group(8, "QuietGroup")
    srv = _make_server(50, "srv-50", group_id=8)
    agg = {8: {"escalate": 0, "act": 0, "hosts": 1}}

    html = _render_group_section(
        app,
        group=grp,
        group_servers=[srv],
        server_group_aggregates=agg,
    )

    # Template zeigt '—' wenn escalate=0 und act=0
    assert "—" in html, f"Dash-Marker fuer 0-Counts erwartet: {html}"


def test_sidebar_group_header_name_is_present(app: Flask) -> None:
    """Group-Name erscheint im Header."""
    grp = _make_group(9, "DatabaseServers")
    srv = _make_server(60, "db-01", group_id=9)
    agg = {9: {"escalate": 0, "act": 0, "hosts": 1}}

    html = _render_group_section(
        app,
        group=grp,
        group_servers=[srv],
        server_group_aggregates=agg,
    )

    assert "DatabaseServers" in html, f"Group-Name nicht gefunden: {html}"


def test_sidebar_group_hostgroup_id_in_markup(app: Flask) -> None:
    """<details id='hostgroup-N'> ist im Markup vorhanden."""
    grp = _make_group(42, "Production")
    srv = _make_server(100, "prod-01", group_id=42)
    agg = {42: {"escalate": 0, "act": 0, "hosts": 1}}

    html = _render_group_section(
        app,
        group=grp,
        group_servers=[srv],
        server_group_aggregates=agg,
    )

    assert 'id="hostgroup-42"' in html, f"id='hostgroup-42' erwartet: {html}"
