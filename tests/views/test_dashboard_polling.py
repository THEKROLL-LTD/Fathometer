"""Tests fuer das HTMX-Polling auf dem Dashboard-Pane (ADR-0019, Block L).

Block H hat das Dashboard noch ueber SSE (`GET /events` + `dashboardSse`-
Alpine-Komponente) live aktualisiert. Mit Block L ist SSE fuers Dashboard
weg, der Pane pollt sich alle 10 Sekunden via HTMX selbst neu (nur bei
sichtbarem Tab). Diese Tests verifizieren:

  * `id="dashboard-pane"` ist nach jedem Render gesetzt — sonst frisst
    HTMX nach dem ersten Swap den Polling-Trigger.
  * `hx-trigger="every 10s [document.visibilityState === 'visible']"`
    ist im Pane-Wrapper verlinkt.
  * Aktive Filter (`?severity=high`, `?tag=...`) werden im `hx-get` der
    Pane-URL persistiert, damit der Re-Fetch nicht den Filter verliert.
  * Die `hx-get`-URL haengt KEIN leeres `?` an, wenn keine Query da ist
    — `request.full_path` waere der naive Weg und produziert genau das.
"""

from __future__ import annotations

import re

from flask import Flask

from tests._helpers import create_admin_user, login

# ---------------------------------------------------------------------------
# Marker-Helpers
# ---------------------------------------------------------------------------


_PANE_OPEN_RE = re.compile(r'<div id="dashboard-pane"[^>]*>', re.DOTALL)


def _extract_pane_open_tag(body: str) -> str:
    """Liefert den `<div id="dashboard-pane" ...>`-Opener als String.

    AssertionError mit den ersten 400 Bytes des Bodys, wenn nicht gefunden.
    """
    match = _PANE_OPEN_RE.search(body)
    assert match is not None, (
        f'Pane-Container `<div id="dashboard-pane" ...>` nicht im Body gefunden. '
        f"Erste 400 Bytes: {body[:400]!r}"
    )
    return match.group(0)


# ---------------------------------------------------------------------------
# Pane-Marker auf HX-Pfad
# ---------------------------------------------------------------------------


def test_hx_pane_contains_polling_id_marker(db_app: Flask) -> None:
    """`id="dashboard-pane"` muss im HX-Response gesetzt sein — Pflicht
    laut ADR-0019, damit der Polling-Trigger nach einem `outerHTML`-Swap
    weiterlaeuft."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get("/", headers={"HX-Request": "true"})
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert 'id="dashboard-pane"' in body, body[:400]


def test_hx_pane_contains_polling_trigger(db_app: Flask) -> None:
    """`hx-trigger="every 10s [document.visibilityState === 'visible']"`
    ist Bestandteil des Pane-Wrapper-Tags. Polling stoppt bei verdecktem
    Tab — die Visibility-Bedingung ist Teil des UX-Vertrags (Akku-/CPU-
    Schonung in Hintergrund-Tabs)."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get("/", headers={"HX-Request": "true"})
    pane_tag = _extract_pane_open_tag(resp.get_data(as_text=True))

    assert "hx-trigger=\"every 10s [document.visibilityState === 'visible']\"" in pane_tag, pane_tag


def test_hx_pane_has_no_html_or_body_wrapper(db_app: Flask) -> None:
    """Der HX-Response liefert nur das Pane-Fragment ohne Page-Shell —
    sonst dupliziert HTMX bei jedem Polling-Swap den `<html>`-Wrapper
    in den DOM."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get("/", headers={"HX-Request": "true"})
    body_lower = resp.get_data(as_text=True).lower()

    assert "<html" not in body_lower, body_lower[:400]
    # `<head ` (mit Space) und `<head>` getrennt pruefen, damit `<header>`
    # nicht versehentlich matched.
    assert "<head>" not in body_lower, body_lower[:400]
    assert "<head " not in body_lower, body_lower[:400]
    assert "<body" not in body_lower, body_lower[:400]


def test_hx_pane_self_targets_outer_html_swap(db_app: Flask) -> None:
    """`hx-target="this"` + `hx-swap="outerHTML"` — der Pane ersetzt sich
    bei jedem Poll komplett. Nur so bleibt das `id`-Attribut nach dem
    Swap erhalten (sonst Trigger weg).
    """
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get("/", headers={"HX-Request": "true"})
    pane_tag = _extract_pane_open_tag(resp.get_data(as_text=True))
    assert 'hx-target="this"' in pane_tag, pane_tag
    assert 'hx-swap="outerHTML"' in pane_tag, pane_tag


# ---------------------------------------------------------------------------
# Filter-Persistenz im hx-get
# ---------------------------------------------------------------------------


def test_hx_pane_preserves_severity_filter_in_hx_get(db_app: Flask) -> None:
    """`?severity=high` muss im `hx-get`-Attribut des Pane-Containers
    auftauchen — sonst verliert der Polling-Refetch den aktiven
    Severity-Filter."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get("/?severity=high", headers={"HX-Request": "true"})
    pane_tag = _extract_pane_open_tag(resp.get_data(as_text=True))

    assert "severity=high" in pane_tag, pane_tag
    # hx-get muss auf `/` plus Query zeigen — nicht `/?severity=...`-Doppel-Slash.
    assert 'hx-get="/?severity=high"' in pane_tag, pane_tag


def test_hx_pane_preserves_tag_filter_in_hx_get(db_app: Flask) -> None:
    """Tag-Filter muessen im `hx-get` der Pane-URL erhalten bleiben."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get("/?tags=prod", headers={"HX-Request": "true"})
    pane_tag = _extract_pane_open_tag(resp.get_data(as_text=True))
    assert "tags=prod" in pane_tag, pane_tag


def test_hx_pane_no_trailing_question_mark_when_no_query(db_app: Flask) -> None:
    """Wenn KEIN Query-Param da ist, muss `hx-get` auf `/` ohne `?` zeigen.

    Anti-Regression gegen `request.full_path`: Flask haengt dort auch bei
    leerem Query-String ein `?` an, was kosmetisch das `hx-get`-Attribut
    verschmutzt und potenziell Reverse-Proxies (Caching-Keys) durcheinander
    bringt."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get("/", headers={"HX-Request": "true"})
    pane_tag = _extract_pane_open_tag(resp.get_data(as_text=True))

    assert 'hx-get="/"' in pane_tag, pane_tag
    # Defensive: explizit das `/?`-Muster muss fehlen.
    assert 'hx-get="/?"' not in pane_tag, pane_tag


# ---------------------------------------------------------------------------
# Anti-SSE-Regression — der Pane darf keinen `dashboardSse`-Bootstrap mehr enthalten
# ---------------------------------------------------------------------------


def test_hx_pane_does_not_bootstrap_legacy_sse_component(db_app: Flask) -> None:
    """`dashboardSse` ist mit Block L geloescht. Wenn jemand das Alpine-
    `x-data="dashboardSse(...)"`-Attribut versehentlich wieder ein-
    setzt, schlaegt dieser Test sofort an."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get("/", headers={"HX-Request": "true"})
    body = resp.get_data(as_text=True)
    assert "dashboardSse" not in body, body[:400]
