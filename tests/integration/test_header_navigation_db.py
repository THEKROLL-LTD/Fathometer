"""Tests fuer den Header (ADR-0016 / ADR-0020 / ADR-0031, `app/templates/layout/_header.html`).

DoD aus dem Block-I-Addendum §164, aktualisiert fuer Block M (ADR-0020)
und ADR-0031 (Theme-Switcher entfernt):
  - Dashboard-Button auf `/` aktiv.
  - Kein dedizierter Suche-Nav-Anker mehr — Suche ist Teil der Dashboard-
    Filter-Bar (Block M, ADR-0020). `/findings/search` ist 404.
  - Logo-Link fuehrt auf `/` (gleicher Pfad wie Dashboard-Button).
  - Profile-Dropdown enthaelt "Settings", "Audit", "Logout"
    sowie den Avatar mit Initial.
  - Kein Theme-Toggle-Button mehr (ADR-0031).
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


def test_header_no_search_nav_anchor(
    logged_in_client: FlaskClient,
) -> None:
    """ADR-0020: dedizierter Suche-Anker im Header wurde entfernt — die
    Suche wandert in die Dashboard-Filter-Bar (`q`-Feld). Das alte
    `<a>Suche</a>` darf nicht mehr auftauchen."""
    resp = logged_in_client.get("/")
    body = resp.get_data(as_text=True)
    header = _header_section(body)
    assert header

    suche_match = re.search(
        r"<a[^>]*>\s*Suche\s*</a>",
        header,
        re.DOTALL,
    )
    assert suche_match is None, f"Suche-Anker existiert noch im Header: {header[:600]}"


def test_findings_search_route_returns_404(
    logged_in_client: FlaskClient,
) -> None:
    """`/findings/search` ist mit Block M (ADR-0020) ersatzlos entfernt."""
    resp = logged_in_client.get("/findings/search")
    assert resp.status_code == 404, resp.status_code


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
# Theme-Toggle entfernt (ADR-0031)
# ---------------------------------------------------------------------------


def test_header_has_no_theme_toggle(
    logged_in_client: FlaskClient,
) -> None:
    """Nach ADR-0031 darf kein themeToggle-Alpine-Component im Header sein."""
    resp = logged_in_client.get("/")
    body = resp.get_data(as_text=True)
    header = _header_section(body)

    assert "themeToggle" not in header, "themeToggle-Alpine-Component ist noch vorhanden (ADR-0031)"
    assert "theme.js" not in header, "theme.js wird noch geladen (ADR-0031)"
