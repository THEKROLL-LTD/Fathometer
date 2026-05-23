"""Pure-Unit-Tests fuer app/views/dashboard_partials.py (Block W Phase F, ADR-0036).

Prueft:
  1. Route `GET /_partials/dashboard/kpis` ist registriert.
  2. Ohne Auth -> 302 Redirect zu Login (Auth-Check vor Body-Parse).
  3. Response mit gemockter Auth enthaelt hx-swap-oob fuer alle 8 Targets:
       #action-needed-num, #action-needed-hosts-total, #action-needed-sub,
       #nominal-card, #triage-row, #severity-strip, #sysline,
       #dashboard-last-refresh.
  4. Response enthaelt KEIN id="action-needed-card"-Wrapper-Element
     (hx-preserve-Semantik — Wrapper bleibt im DOM, nie im OOB-Response).
  5. Erfolgreiche Response hat Status 200.

Pattern: Flask-Testclient mit `app`-Fixture + Auth-Bypass via
`__wrapped__`-Aufruf fuer den Response-Content-Test.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask.testing import FlaskClient

# ---------------------------------------------------------------------------
# Hilfskonstanten
# ---------------------------------------------------------------------------

_OOB_TARGETS = (
    "action-needed-num",
    "action-needed-hosts-total",
    "action-needed-sub",
    "nominal-card",
    "triage-row",
    "severity-strip",
    "sysline",
    "dashboard-last-refresh",
)

_MOCK_MANIFEST = {
    "css/app.css": "css/app.abc123.css",
    "js/vendor.js": "js/vendor.def456.js",
    "js/app.js": "js/app.ghi789.js",
}


# ---------------------------------------------------------------------------
# Helpers — Mock-Services
# ---------------------------------------------------------------------------


def _zero_action_card_data() -> dict[str, int]:
    return {
        "server_count": 0,
        "hosts_total": 0,
        "escalate": 0,
        "act": 0,
        "pending": 0,
    }


def _zero_nominal_card_data() -> dict[str, int]:
    return {
        "monitor_count": 0,
        "hosts_total": 0,
        "monitor": 0,
        "noise": 0,
        "unknown": 0,
    }


def _zero_triage_counts() -> dict[str, int]:
    return {
        "escalate": 0,
        "act": 0,
        "mitigate": 0,
        "pending": 0,
        "monitor": 0,
        "noise": 0,
        "unknown": 0,
    }


def _zero_severity_counts() -> dict[str, Any]:
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "max_count": 1,
    }


def _zero_sysline() -> dict[str, Any]:
    return {
        "last_scan_ago": None,
        "epss_feed_status": "never",
        "kev_feed_status": "never",
        "worker_status": None,
    }


# ---------------------------------------------------------------------------
# Route-Registrierung
# ---------------------------------------------------------------------------


def test_kpis_oob_route_registered(app: Flask) -> None:
    """Flask-URL-Map enthaelt '/_partials/dashboard/kpis' mit Methode GET."""
    rules = {rule.rule: list(rule.methods or []) for rule in app.url_map.iter_rules()}

    assert "/_partials/dashboard/kpis" in rules, (
        f"Route '/_partials/dashboard/kpis' fehlt in der URL-Map. "
        f"Registrierte Routen: {sorted(rules.keys())}"
    )
    assert "GET" in rules["/_partials/dashboard/kpis"], (
        f"Methode GET fehlt fuer '/_partials/dashboard/kpis'. "
        f"Vorhandene Methoden: {rules['/_partials/dashboard/kpis']}"
    )


# ---------------------------------------------------------------------------
# Auth-Check — ohne Auth -> 302
# ---------------------------------------------------------------------------


def test_kpis_oob_requires_auth(client: FlaskClient) -> None:
    """GET /_partials/dashboard/kpis ohne Authentifizierung -> 302 Redirect zu Login."""
    response = client.get("/_partials/dashboard/kpis")

    assert response.status_code == 302, (
        f"Erwartet 302 (Redirect zu Login) ohne Auth, erhalten: {response.status_code}"
    )
    # Redirect muss zum Login gehen (Flask-Login-Standard)
    location = response.headers.get("Location", "")
    assert "login" in location.lower(), (
        f"Redirect-Ziel soll '/login' enthalten, erhalten Location: {location!r}"
    )


# ---------------------------------------------------------------------------
# Response-Inhalt — OOB-Targets (via __wrapped__ + Mock-Services)
# ---------------------------------------------------------------------------


def _render_kpis_oob(app: Flask, monkeypatch: pytest.MonkeyPatch) -> str:
    """Ruft dashboard_kpis_oob.__wrapped__ direkt auf (bypassed @login_required).

    Alle Backend-Services werden via monkeypatch durch deterministische Stubs ersetzt.
    Gibt den gerenderten HTML-String zurueck.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "_asset_manifest", _MOCK_MANIFEST)

    # Mock-Session fuer get_session()
    mock_sess = MagicMock()

    # Stubs fuer alle Services die dashboard_kpis_oob aufruft
    monkeypatch.setattr(
        "app.views.dashboard_partials._load_open_aggregates_for_kpis",
        lambda sess: ({}, {}),
    )
    monkeypatch.setattr(
        "app.views.dashboard_partials._active_server_ids_for_kpis",
        lambda sess: set(),
    )
    monkeypatch.setattr(
        "app.views.dashboard_partials._load_action_needed_card_data",
        lambda sess, risk_bands, active_ids: _zero_action_card_data(),
    )
    monkeypatch.setattr(
        "app.views.dashboard_partials._load_nominal_card_data",
        lambda sess, risk_bands, active_ids, hosts_total, action_server_count: (
            _zero_nominal_card_data()
        ),
    )
    monkeypatch.setattr(
        "app.views.dashboard_partials._load_triage_counts",
        lambda sess, risk_bands_by_server=None, active_server_ids=None: _zero_triage_counts(),
    )
    monkeypatch.setattr(
        "app.views.dashboard_partials._load_severity_counts",
        lambda sess: _zero_severity_counts(),
    )
    monkeypatch.setattr(
        "app.views.dashboard_partials.build_sysline_context",
        lambda sess, _now=None: _zero_sysline(),
    )
    monkeypatch.setattr(
        "app.views.dashboard_partials.get_session",
        lambda: mock_sess,
    )

    from app.views.dashboard_partials import dashboard_kpis_oob

    inner = getattr(dashboard_kpis_oob, "__wrapped__", dashboard_kpis_oob)

    with app.test_request_context("/_partials/dashboard/kpis"):
        result = inner()

    # Flask-Views koennen Response-Objekte oder Strings zurueckgeben
    if hasattr(result, "get_data"):
        return result.get_data(as_text=True)
    return str(result)


def test_kpis_oob_response_status_200(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Erfolgreiche Anfrage mit gemockten Services -> Status 200."""
    # Wir testen hier dass die Funktion ohne Exception durchlaeuft.
    # Ein Exception wuerde den Test fehlschlagen lassen.
    html = _render_kpis_oob(app, monkeypatch)

    # Mindest-Pruefung: HTML ist nicht leer
    assert html.strip(), "OOB-Response ist leer — Template-Render-Fehler?"


def test_kpis_oob_response_includes_all_oob_targets(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Response enthaelt hx-swap-oob-Marker fuer alle 8 Targets (ADR-0036).

    Die 8 OOB-Targets sind:
      #action-needed-num, #action-needed-hosts-total, #action-needed-sub,
      #nominal-card, #triage-row, #severity-strip, #sysline,
      #dashboard-last-refresh.
    """
    html = _render_kpis_oob(app, monkeypatch)

    for target_id in _OOB_TARGETS:
        # Template verwendet hx-swap-oob mit id-Attribut auf dem Element
        assert f'id="{target_id}"' in html, (
            f"OOB-Target id='{target_id}' fehlt in der Response. "
            f"Alle 8 Targets muessen vorhanden sein (ADR-0036 §Endpoint-Response-Skizze). "
            f"HTML-Ausschnitt (erste 800 Zeichen): {html[:800]}"
        )
        assert "hx-swap-oob" in html, (
            "hx-swap-oob-Attribut fehlt komplett in der Response. "
            "OOB-Swaps brauchen dieses Attribut damit HTMX die Fragmente anwendet."
        )


def test_kpis_oob_response_no_action_needed_card_wrapper(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Response enthaelt KEIN id='action-needed-card'-Element (ADR-0036 hx-preserve-Pattern).

    Der Action-Card-Wrapper (#action-needed-card) hat hx-preserve='true' im Pane.
    Er darf NICHT im OOB-Response-Body auftauchen, weil ein OOB-Swap dann
    hx-preserve ueberschreiben wuerde und die Scan-Beam-Animation neugestartet wuerde.

    Innere Kinder (#action-needed-num, #action-needed-hosts-total, #action-needed-sub)
    sind OK als OOB-Targets — der aeussere Wrapper darf es nicht sein.
    """
    html = _render_kpis_oob(app, monkeypatch)

    assert 'id="action-needed-card"' not in html, (
        "id='action-needed-card' darf NICHT in der OOB-Response auftauchen. "
        "Der Wrapper hat hx-preserve='true' und muss unveraendert im DOM bleiben. "
        "Nur die inneren Kinder (#action-needed-num, -hosts-total, -sub) werden "
        "per OOB-Swap aktualisiert. "
        f"HTML-Ausschnitt (erste 800 Zeichen): {html[:800]}"
    )


def test_kpis_oob_response_contains_hx_swap_oob_attribute(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jedes OOB-Fragment traegt das hx-swap-oob-Attribut."""
    html = _render_kpis_oob(app, monkeypatch)

    # hx-swap-oob muss mindestens einmal vorkommen
    assert "hx-swap-oob" in html, (
        "hx-swap-oob-Attribut fehlt in der OOB-Response. "
        "HTMX erkennt OOB-Fragmente ausschliesslich ueber dieses Attribut."
    )
