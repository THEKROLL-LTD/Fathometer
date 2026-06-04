"""Pure-Unit-Tests fuer die HTMX-Fragment-Endpoints (Block Y Phase B, ADR-0039).

Prueft die Fragment-Endpoints in `app/views/server_detail.py`:

  - GET /servers/<id>/fragments/sparklines
  - GET /servers/<id>/fragments/heartbeat
  - GET /servers/<id>/fragments/host-snapshot
  - GET /servers/<id>/fragments/trend

Pro Endpoint: Happy-Path, 404 bei unbekanntem Server, 404 bei revoked,
404 bei retired. Auth-Guard wird zentral pro Endpoint geprueft (302).

Pattern: Flask-Testclient + Mock-Services via monkeypatch + direkter
`__wrapped__`-Aufruf, um `@login_required` fuer Content-Tests zu
umgehen. Keine DB-Round-Trips, keine echten ORM-Objekte — `_load_server_
with_tags` und alle Service-Funktionen werden gepatcht.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.exceptions import HTTPException

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(
    server_id: int = 1,
    *,
    revoked_at: datetime | None = None,
    retired_at: datetime | None = None,
    host_state_snapshot_at: datetime | None = None,
) -> MagicMock:
    """Baut ein MagicMock-Server-Objekt mit den von den Templates und der View
    gelesenen Feldern. Keine echte SQLAlchemy-Instanz noetig."""
    srv = MagicMock()
    srv.id = server_id
    srv.name = f"host-{server_id}"
    srv.revoked_at = revoked_at
    srv.retired_at = retired_at
    srv.host_state_snapshot_at = host_state_snapshot_at
    srv.tag_links = []
    return srv


def _patch_session(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patcht `get_session` in `app.views.server_detail` auf einen Mock."""
    sess = MagicMock()
    monkeypatch.setattr("app.views.server_detail.get_session", lambda: sess)
    return sess


def _call_inner(
    app: Flask,
    view_func_name: str,
    url: str,
    server_id: int,
) -> Any:
    """Ruft `<view>.__wrapped__(server_id)` im Request-Context auf.

    Bypassed `@login_required` damit wir den Response-Body inhaltlich
    testen koennen ohne komplettes Auth-Setup. Gibt das Render-Resultat
    (HTML-String) oder das HTTPException-Status zurueck.
    """
    from app.views import server_detail

    view = getattr(server_detail, view_func_name)
    inner = getattr(view, "__wrapped__", view)
    with app.test_request_context(url, method="GET"):
        try:
            return inner(server_id)
        except HTTPException as exc:
            return exc


def _stub_load_server(
    monkeypatch: pytest.MonkeyPatch,
    server: MagicMock | None,
) -> None:
    """Patcht `_load_server_with_tags` so dass der Endpoint-Helper
    `_load_active_server_or_404` deterministisch reagiert."""
    monkeypatch.setattr(
        "app.views.server_detail._load_server_with_tags",
        lambda _sid: server,
    )


# ---------------------------------------------------------------------------
# Route-Registrierung
# ---------------------------------------------------------------------------


_FRAGMENT_ROUTES = (
    "/servers/<int:server_id>/fragments/sparklines",
    "/servers/<int:server_id>/fragments/heartbeat",
    "/servers/<int:server_id>/fragments/host-snapshot",
    "/servers/<int:server_id>/fragments/trend",
)


@pytest.mark.parametrize("rule", _FRAGMENT_ROUTES)
def test_fragment_route_registered(app: Flask, rule: str) -> None:
    """Jede Fragment-Route muss in der URL-Map mit GET stehen."""
    rules = {r.rule: list(r.methods or []) for r in app.url_map.iter_rules()}
    assert rule in rules, f"Route {rule!r} fehlt. Vorhandene: {sorted(rules)}"
    assert "GET" in rules[rule], f"GET fehlt fuer {rule!r}: {rules[rule]}"


# ---------------------------------------------------------------------------
# Auth-Guard — pro Endpoint ein 302-Test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "/servers/1/fragments/sparklines",
        "/servers/1/fragments/heartbeat",
        "/servers/1/fragments/host-snapshot",
        "/servers/1/fragments/trend",
    ],
)
def test_fragment_endpoint_requires_auth(client: FlaskClient, url: str) -> None:
    """Alle Fragment-Endpoints sind @login_required: ohne Auth -> 302."""
    response = client.get(url)
    assert response.status_code == 302, (
        f"Erwartet 302 (Redirect zu Login) ohne Auth fuer {url}, erhalten: {response.status_code}"
    )
    location = response.headers.get("Location", "")
    assert "login" in location.lower(), f"Redirect-Ziel ohne /login: {location!r}"


# ---------------------------------------------------------------------------
# Sparklines-Fragment
# ---------------------------------------------------------------------------


def test_sparklines_fragment_happy_path(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1))
    _patch_session(monkeypatch)
    monkeypatch.setattr(
        "app.views.server_detail._quick_counts_for_server",
        lambda _s, _sid: {
            "total_all": 10,
            "total_open": 5,
            "kev_open": 1,
            "critical_open": 2,
            "high_open": 1,
            "medium_open": 1,
            "low_open": 0,
        },
    )
    monkeypatch.setattr(
        "app.views.server_detail.severity_snapshots_for_server",
        lambda _s, _sid, days=30: {
            "critical": [1] * 30,
            "high": [0] * 30,
            "medium": [0] * 30,
            "low": [0] * 30,
            "kev": [0] * 30,
        },
    )
    html = _call_inner(app, "sparklines_fragment", "/servers/1/fragments/sparklines", 1)
    assert isinstance(html, str), f"Erwartet HTML-String, erhalten: {type(html)!r}"
    assert 'id="sd-tiles"' in html, "Wrapper-DIV mit id=sd-tiles fehlt"
    assert "kpi-card-kev" in html, "KEV-Tile fehlt im Output"
    assert "kpi-card-critical" in html, "Critical-Tile fehlt im Output"
    assert "kpi-card-high" in html, "High-Tile fehlt im Output"
    assert "kpi-card-medium" in html, "Medium-Tile fehlt im Output"


def test_sparklines_fragment_unknown_server_404(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_load_server(monkeypatch, None)
    result = _call_inner(app, "sparklines_fragment", "/servers/999/fragments/sparklines", 999)
    assert isinstance(result, HTTPException), f"Erwartet HTTPException, erhalten: {result!r}"
    assert result.code == 404


def test_sparklines_fragment_revoked_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1, revoked_at=datetime.now(UTC)))
    result = _call_inner(app, "sparklines_fragment", "/servers/1/fragments/sparklines", 1)
    assert isinstance(result, HTTPException) and result.code == 404


def test_sparklines_fragment_retired_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1, retired_at=datetime.now(UTC)))
    result = _call_inner(app, "sparklines_fragment", "/servers/1/fragments/sparklines", 1)
    assert isinstance(result, HTTPException) and result.code == 404


# ---------------------------------------------------------------------------
# Heartbeat-Fragment
# ---------------------------------------------------------------------------


def test_heartbeat_fragment_happy_path_with_snapshot(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Server mit snapshot_at -> heartbeats_for_servers wird aufgerufen, Live-Bar."""
    srv = _make_server(1, host_state_snapshot_at=datetime.now(UTC))
    _stub_load_server(monkeypatch, srv)
    _patch_session(monkeypatch)
    monkeypatch.setattr(
        "app.views.server_detail.heartbeats_for_servers",
        lambda _s, sids, days=30: {sids[0]: []},
    )
    html = _call_inner(app, "heartbeat_fragment", "/servers/1/fragments/heartbeat", 1)
    assert isinstance(html, str)
    assert 'id="sd-heartbeat"' in html
    assert "heartbeat-fragment" in html


def test_heartbeat_fragment_never_scanned_empty_state(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Server ohne snapshot_at -> --empty-State, kein heartbeats_for_servers-Call."""
    srv = _make_server(1, host_state_snapshot_at=None)
    _stub_load_server(monkeypatch, srv)
    _patch_session(monkeypatch)

    def _explode(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("heartbeats_for_servers darf bei never-scanned NICHT laufen")

    monkeypatch.setattr("app.views.server_detail.heartbeats_for_servers", _explode)

    html = _call_inner(app, "heartbeat_fragment", "/servers/1/fragments/heartbeat", 1)
    assert isinstance(html, str)
    assert 'id="sd-heartbeat"' in html
    assert "heartbeat-empty" in html
    assert "never scanned" in html


def test_heartbeat_fragment_unknown_server_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, None)
    result = _call_inner(app, "heartbeat_fragment", "/servers/999/fragments/heartbeat", 999)
    assert isinstance(result, HTTPException) and result.code == 404


def test_heartbeat_fragment_revoked_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1, revoked_at=datetime.now(UTC)))
    result = _call_inner(app, "heartbeat_fragment", "/servers/1/fragments/heartbeat", 1)
    assert isinstance(result, HTTPException) and result.code == 404


def test_heartbeat_fragment_retired_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1, retired_at=datetime.now(UTC)))
    result = _call_inner(app, "heartbeat_fragment", "/servers/1/fragments/heartbeat", 1)
    assert isinstance(result, HTTPException) and result.code == 404


# ---------------------------------------------------------------------------
# Host-Snapshot-Fragment
# ---------------------------------------------------------------------------


def test_host_snapshot_fragment_happy_path(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1))
    _patch_session(monkeypatch)
    monkeypatch.setattr(
        "app.views.server_detail._load_host_snapshot",
        lambda _s, _sid: {"listeners": [], "services": [], "processes": []},
    )
    html = _call_inner(app, "host_snapshot_fragment", "/servers/1/fragments/host-snapshot", 1)
    assert isinstance(html, str), f"Erwartet HTML-String, erhalten: {type(html)!r}"
    assert 'id="sd-host-snapshot"' in html
    assert "host-snapshot-fragment" in html
    # Beide Slide-Down-Panels muessen enthalten sein (Alpine-Flyouts).
    assert 'id="sd-flyout-listeners"' in html
    assert 'id="sd-flyout-services"' in html


def test_host_snapshot_fragment_unknown_server_404(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_load_server(monkeypatch, None)
    result = _call_inner(app, "host_snapshot_fragment", "/servers/999/fragments/host-snapshot", 999)
    assert isinstance(result, HTTPException) and result.code == 404


def test_host_snapshot_fragment_revoked_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1, revoked_at=datetime.now(UTC)))
    result = _call_inner(app, "host_snapshot_fragment", "/servers/1/fragments/host-snapshot", 1)
    assert isinstance(result, HTTPException) and result.code == 404


def test_host_snapshot_fragment_retired_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1, retired_at=datetime.now(UTC)))
    result = _call_inner(app, "host_snapshot_fragment", "/servers/1/fragments/host-snapshot", 1)
    assert isinstance(result, HTTPException) and result.code == 404


# ---------------------------------------------------------------------------
# Trend-Fragment
# ---------------------------------------------------------------------------


def test_trend_fragment_happy_path(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1))
    _patch_session(monkeypatch)
    monkeypatch.setattr(
        "app.views.server_detail.daily_severity_counts_for_server",
        lambda _s, _sid, days=30: [],
    )
    from app.services.trend import Tendency

    monkeypatch.setattr(
        "app.views.server_detail.tendency_from_counts",
        lambda _counts: Tendency.STABLE,
    )
    html = _call_inner(app, "trend_fragment", "/servers/1/fragments/trend", 1)
    assert isinstance(html, str), f"Erwartet HTML-String, erhalten: {type(html)!r}"
    assert 'id="sd-trend"' in html
    assert "trend-fragment" in html
    # OOB-Swap fuer den Tendency-Span im Header.
    assert 'id="sd-stats-delta"' in html
    assert 'hx-swap-oob="outerHTML"' in html
    # Label-Text aus dem Tendency-Enum (STABLE).
    assert "stabil" in html


def test_trend_fragment_unknown_server_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, None)
    result = _call_inner(app, "trend_fragment", "/servers/999/fragments/trend", 999)
    assert isinstance(result, HTTPException) and result.code == 404


def test_trend_fragment_revoked_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1, revoked_at=datetime.now(UTC)))
    result = _call_inner(app, "trend_fragment", "/servers/1/fragments/trend", 1)
    assert isinstance(result, HTTPException) and result.code == 404


def test_trend_fragment_retired_404(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_load_server(monkeypatch, _make_server(1, retired_at=datetime.now(UTC)))
    result = _call_inner(app, "trend_fragment", "/servers/1/fragments/trend", 1)
    assert isinstance(result, HTTPException) and result.code == 404


# ---------------------------------------------------------------------------
# Template-Smoke: Initial-Render wired die Fragment-URLs
# ---------------------------------------------------------------------------


def test_detail_initial_render_wires_fragment_urls(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`GET /servers/<id>` enthaelt hx-get fuer alle Fragment-URLs.

    Pruef-Strategie: das Detail-Template wird mit minimalen, geseedeten
    Werten direkt via Flask `render_template` gerendert. Wir bauen einen
    Mock-Server und stoppen alle Detail-Services nicht — stattdessen
    nutzen wir `app.test_request_context` + `render_template` mit dem
    Subset an Context den die Template-Section-Header brauchen.
    """
    from flask import render_template

    srv = _make_server(1, host_state_snapshot_at=datetime.now(UTC))
    srv.os_pretty_name = "Ubuntu 24.04"
    srv.kernel_version = "6.8.0"
    srv.architecture = "x86_64"
    srv.last_scan_at = datetime.now(UTC)
    srv.trivy_db_updated_at = datetime.now(UTC)
    srv.expected_scan_interval_h = 24
    srv.agent_version = "0.3.0"
    srv.trivy_version = "0.55.0"

    # Minimaler Context — Template muss durchlaufen, der Output ist
    # vollstaendig, wir grep'en gezielt nach den fuenf URLs.
    ctx = {
        "server": srv,
        "available_tags": [],
        "add_form": MagicMock(),
        "remove_form": MagicMock(),
        "active_server_id": 1,
        "hx_partial": False,
        "tendency": None,
        "quick_counts": {
            "total_all": 0,
            "total_open": 0,
            "kev_open": 0,
            "critical_open": 0,
            "high_open": 0,
            "medium_open": 0,
            "low_open": 0,
        },
        "total_findings_count": 0,
        "action_required": {
            "yes_count": 0,
            "no_count": 0,
            "yes_subcounts": {},
            "no_subcounts": {},
            "noise_count": 0,
        },
        "action_sections": [],
        "view_filter": MagicMock(
            sort="risk",
            dir="desc",
            status="open",
            finding_class="both",
            kev_only=False,
            search="",
            risk_band=None,
            action_required=None,
            application_group_id=None,
        ),
        "counts": {"total": 0, "open": 0, "ack": 0, "resolved": 0},
        "findings": [],
        "application_groups": [],
        "pending_grouping_counts": {},
        "risk_band_header_counts": dict.fromkeys(
            ("escalate", "act", "mitigate", "pending", "monitor", "noise"), 0
        ),
        "default_open_band": None,
        "llm_configured": False,
    }
    with app.test_request_context("/servers/1"):
        html = render_template("servers/detail.html", **ctx)

    # Sparklines
    assert "/servers/1/fragments/sparklines" in html, (
        "Sparklines-Fragment-URL fehlt im Initial-Render"
    )
    # Heartbeat
    assert "/servers/1/fragments/heartbeat" in html, (
        "Heartbeat-Fragment-URL fehlt im Initial-Render"
    )
    # Host-Snapshot
    assert "/servers/1/fragments/host-snapshot" in html, (
        "Host-Snapshot-Fragment-URL fehlt im Initial-Render"
    )
    # Trend
    assert "/servers/1/fragments/trend" in html, "Trend-Fragment-URL fehlt im Initial-Render"

    # Anker-IDs muessen vorhanden sein damit der outerHTML-Swap greift.
    for anchor in ("sd-tiles", "sd-heartbeat", "sd-host-snapshot", "sd-trend"):
        assert f'id="{anchor}"' in html, f"Anker-ID id={anchor!r} fehlt im Initial-Render"
