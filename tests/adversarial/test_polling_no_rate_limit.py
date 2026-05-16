"""Adversarial-Test: HTMX-Polling-Endpoints duerfen den Rate-Limiter nicht triggern.

ADR-0019 sagt explizit: Der Dashboard-Pane (`GET /`) und der Sidebar-
Partial (`GET /_partials/sidebar`) werden alle 10 Sekunden gepollt
(6 Polls pro Minute, Tab sichtbar). Ein versehentlich gesetztes
`60/minute`-Default-Limit auf der App wuerde das Polling bereits ab
dem 11. Tick durchschnittlich abwuergen, bei stossweisen Bursts noch
frueher.

Wir feuern 12 schnelle Requests hintereinander (oberhalb der normalen
6/min-Rate) und erwarten, dass alle mit `200 OK` antworten — keiner
mit `429 Too Many Requests`.

Wenn dieser Test 429 sieht, ist ein Limiter falsch konfiguriert
(globales Default oder ein Endpoint-Limit das die Polling-Pfade
mitfaengt). In dem Fall muss der Implementer entweder das Default-Limit
auf den Polling-Pfaden via `@limiter.exempt` oder eine eigene
Whitelist herausnehmen.
"""

from __future__ import annotations

import pytest
from flask import Flask

from tests._helpers import create_admin_user, login


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("/", id="dashboard-pane"),
        pytest.param("/_partials/sidebar", id="sidebar-partial"),
    ],
)
def test_polling_endpoint_does_not_rate_limit(db_app: Flask, path: str) -> None:
    """12 schnelle Polls in Folge — alle muessen 200 zurueckliefern."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)

    for i in range(12):
        resp = client.get(path, headers={"HX-Request": "true"})
        assert resp.status_code == 200, (
            f"Poll #{i + 1} auf {path} lieferte {resp.status_code} — "
            "Rate-Limiter triggert auf einem Polling-Endpoint (ADR-0019 "
            f"verbietet das). Body-Start: {resp.get_data(as_text=True)[:200]!r}"
        )
        assert resp.status_code != 429, "Rate-Limit darf Polling nicht stoeren."
