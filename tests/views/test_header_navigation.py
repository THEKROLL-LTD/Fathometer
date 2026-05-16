"""Tests fuer den Header (ADR-0016, `app/templates/layout/_header.html`).

DoD aus dem Block-I-Addendum §164:
  - Dashboard-Button auf `/` aktiv.
  - Suche-Button auf `/findings/search` aktiv.
  - Logo-Link fuehrt auf `/` (gleicher Pfad wie Dashboard-Button).
  - Profile-Dropdown enthaelt "Settings", "Audit", "Logout"
    sowie den Avatar mit Initial.
  - Theme-Toggle-Button vorhanden mit Sun-/Moon-SVG.
"""

from __future__ import annotations

import re

import pytest
from flask import Flask
from flask.testing import FlaskClient

from tests._helpers import ADMIN_USERNAME, create_admin_user, login


@pytest.fixture
def logged_in_client(db_app: Flask) -> FlaskClient:
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    return client


def _header_section(body: str) -> str:
    """Extrahiert nur den `<header role="banner">`-Block."""
    header_open = body.find("<header")
    header_end = body.find("</header>", header_open)
    if header_open == -1 or header_end == -1:
        return ""
    return body[header_open:header_end]


# ---------------------------------------------------------------------------
# Dashboard-Button-Aktivierung
# ---------------------------------------------------------------------------


def test_header_dashboard_button_active_on_root(
    logged_in_client: FlaskClient,
) -> None:
    resp = logged_in_client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    header = _header_section(body)
    assert header, "Header-Block nicht gefunden"

    # Das Dashboard-`<a>` enthaelt sowohl den Text "Dashboard" als auch
    # die `btn-active`-Klasse.
    dashboard_match = re.search(
        r'<a[^>]*class="[^"]*btn-active[^"]*"[^>]*>\s*Dashboard\s*</a>',
        header,
        re.DOTALL,
    )
    assert dashboard_match is not None, f"Dashboard-Button nicht aktiv: {header[:600]}"


def test_header_search_button_active_on_search(
    logged_in_client: FlaskClient,
) -> None:
    resp = logged_in_client.get("/findings/search")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    header = _header_section(body)
    assert header

    suche_match = re.search(
        r'<a[^>]*class="[^"]*btn-active[^"]*"[^>]*>\s*Suche\s*</a>',
        header,
        re.DOTALL,
    )
    assert suche_match is not None, f"Suche-Button nicht aktiv: {header[:600]}"


def test_header_dashboard_button_not_active_on_search(
    logged_in_client: FlaskClient,
) -> None:
    """Auf `/findings/search` ist NUR der Suche-Button aktiv."""
    resp = logged_in_client.get("/findings/search")
    body = resp.get_data(as_text=True)
    header = _header_section(body)

    # Suche-Button: `btn-active` direkt vor `Suche`-Text vorhanden.
    # Dashboard-Button: `btn-active` darf NICHT direkt vor `Dashboard`-
    # Text stehen.
    dashboard_match = re.search(
        r'<a[^>]*class="[^"]*btn-active[^"]*"[^>]*>\s*Dashboard\s*</a>',
        header,
        re.DOTALL,
    )
    assert dashboard_match is None, "Dashboard-Button ist auf /findings/search aktiv"


# ---------------------------------------------------------------------------
# Logo-Link
# ---------------------------------------------------------------------------


def test_header_logo_links_to_dashboard(logged_in_client: FlaskClient) -> None:
    """Das Logo (Brand "secscan") linkt auf `/` — gleicher Pfad wie der
    Dashboard-Button."""
    resp = logged_in_client.get("/")
    body = resp.get_data(as_text=True)
    header = _header_section(body)

    # Wir suchen einen `<a href="...">` der "secscan"-Brand enthaelt und
    # extrahieren das href.
    logo_match = re.search(
        r'<a\s+href="([^"]+)"[^>]*>\s*(?:<span[^>]*>[^<]*</span>\s*)*<span>secscan</span>',
        header,
        re.DOTALL,
    )
    assert logo_match is not None, f"Logo-Link nicht gefunden: {header[:600]}"
    href = logo_match.group(1)
    # `url_for('dashboard.index')` -> `/`.
    assert href == "/", f"Logo zeigt auf {href!r} statt auf '/'"


# ---------------------------------------------------------------------------
# Profile-Dropdown
# ---------------------------------------------------------------------------


def test_header_profile_dropdown_has_settings_audit_logout(
    logged_in_client: FlaskClient,
) -> None:
    resp = logged_in_client.get("/")
    body = resp.get_data(as_text=True)

    # Wir muessen das Dropdown-Markup nicht filtern: drei Eintraege +
    # Avatar in `_profile_dropdown.html`.
    assert 'id="profile-dropdown"' in body, "Profile-Dropdown-Container fehlt"

    # Direkte Substring-Pruefung der drei Menu-Items in der richtigen Reihenfolge.
    pos_settings = body.find("Settings")
    pos_audit = body.find("Audit")
    pos_logout = body.find("Logout")
    assert pos_settings >= 0, "Settings-Eintrag fehlt"
    assert pos_audit >= 0, "Audit-Eintrag fehlt"
    assert pos_logout >= 0, "Logout-Eintrag fehlt"
    # Reihenfolge: Settings -> Audit -> Logout (aus dem Template).
    assert pos_settings < pos_audit < pos_logout, (
        f"Reihenfolge falsch: settings={pos_settings} audit={pos_audit} logout={pos_logout}"
    )


def test_header_profile_avatar_shows_admin_initial(
    logged_in_client: FlaskClient,
) -> None:
    """Der Avatar-Kreis zeigt das Initial des Benutzernamens (Admin -> "A")."""
    resp = logged_in_client.get("/")
    body = resp.get_data(as_text=True)

    expected_initial = ADMIN_USERNAME[0].upper()  # "A"
    # Avatar-Span aus `_profile_dropdown.html`.
    avatar_match = re.search(
        r"<span[^>]*rounded-full[^>]*>\s*([A-Z?])\s*</span>",
        body,
    )
    assert avatar_match is not None, "Avatar-Span nicht gefunden"
    assert avatar_match.group(1) == expected_initial, (
        f"Avatar-Initial {avatar_match.group(1)!r} != erwartet {expected_initial!r}"
    )


def test_header_logout_form_uses_post_with_csrf(
    logged_in_client: FlaskClient,
) -> None:
    """Der Logout-Eintrag ist ein POST-Form mit CSRF-Token-Hidden-Input
    (Sicherheits-DoD aus ADR-0016)."""
    resp = logged_in_client.get("/")
    body = resp.get_data(as_text=True)

    # Form mit `action=/logout` + Logout-Button.
    logout_match = re.search(
        r'<form[^>]*method="post"[^>]*action="([^"]*logout[^"]*)"[^>]*>\s*'
        r'<input[^>]*name="csrf_token"',
        body,
        re.DOTALL,
    )
    assert logout_match is not None, "Logout-Form ohne CSRF-Token oder nicht POST"


# ---------------------------------------------------------------------------
# Theme-Toggle
# ---------------------------------------------------------------------------


def test_header_theme_toggle_present_with_sun_and_moon(
    logged_in_client: FlaskClient,
) -> None:
    """Der Theme-Toggle ist ein `<button>` mit Alpine-`x-data="themeToggle(...)"`
    und enthaelt ein Sun- und ein Moon-SVG (Heroicons)."""
    resp = logged_in_client.get("/")
    body = resp.get_data(as_text=True)
    header = _header_section(body)

    # `themeToggle`-Alpine-Component.
    assert "themeToggle" in header, "Theme-Toggle-Alpine-Component fehlt"
    # Sun-Icon (Path-Daten aus dem Template — Kreis + Strahlen).
    assert 'cx="12" cy="12" r="4"' in header, "Sun-SVG (Kreis r=4) fehlt"
    # Moon-Icon (`M21 12.79A9 9 0 ...`).
    assert "M21 12.79" in header, "Moon-SVG-Path fehlt"
    # Button mit aria-label.
    assert "aria-label" in header
    # `tojson | forceescape`: `"` muss als `&#34;` escaped sein, sonst
    # bricht der Attribut-Wert vorzeitig auf und Alpine wirft
    # `resolvedDark is not defined` (siehe Regression in v0.3.0).
    assert 'x-data="themeToggle(&#34;' in header, (
        "themeToggle-Argument muss HTML-escaped sein (`| forceescape`), "
        "sonst schliesst das eingebettete `\"` das x-data-Attribut."
    )
    assert 'x-data="themeToggle("' not in header, (
        "Ungescaptes `\"` im x-data-Attribut bricht das Parsing — "
        "`| forceescape` fehlt im Template."
    )
