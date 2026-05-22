"""Regression: `active`-Pille bleibt in `/settings/servers/` sichtbar.

ADR-0025 §Entscheidung (4) entfernt die `active`-Pille NUR aus dem
Server-Detail-Header (`app/templates/servers/detail.html`). Die gruene
`active`-Badge in der Settings-Server-Liste (`app/templates/settings/servers.html`,
Zeile ~122) ist anderer Kontext: dort hilft sie dem Operator zur Abgrenzung
gegen `revoked`/`retired`-Eintraege und MUSS erhalten bleiben.
"""

from __future__ import annotations

from flask import Flask

from tests._helpers import create_admin_user, login, register_test_server


def test_active_pill_kept_in_settings_servers_list(db_app: Flask) -> None:
    """Regression: `/settings/servers/` zeigt fuer aktive Server `>active<`-Badge.

    Setup: ein aktiver Server (kein `revoked_at`, kein `retired_at`).
    Erwartung:
      - HTTP 200.
      - HTML enthaelt mindestens einen `>active<`-Marker
        (badge-success aus dem Status-`<td>` in settings/servers.html).
    """
    create_admin_user(db_app)
    register_test_server(db_app, name="srv-settings-active")

    client = db_app.test_client()
    login(client)
    resp = client.get("/settings/servers/")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert "srv-settings-active" in body, "Server fehlt in der Liste"
    assert ">active<" in body, (
        "active-Pille in der Settings-Server-Liste fehlt — "
        "ADR-0025 betrifft NUR den Server-Detail-Header, nicht diese Liste"
    )
