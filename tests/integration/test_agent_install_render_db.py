"""Block N (ADR-0021) — Render-Test fuer das Bootstrap-Installer-Template.

Prueft, dass das volle Wizard-Template (Task #8) gerendert wird mit allen
sechs Phasen, TTY-Input-Redirects und eingebackenen Konstanten. Der
zugehoerige Smoke-Test in `test_agent_install_smoke.py` deckt die Route
selbst ab; dieser Test fokussiert auf die Template-Inhalte.
"""

from __future__ import annotations

from flask import Flask


def test_install_sh_full_wizard_template(db_app: Flask) -> None:
    """Das gerenderte Skript enthaelt alle Wizard-Phasen und TTY-Inputs."""
    client = db_app.test_client()
    resp = client.get("/install.sh")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    assert resp.mimetype == "text/x-shellscript"
    body = resp.get_data(as_text=True)

    # Header und set-Optionen.
    assert body.startswith("#!/usr/bin/env bash"), body[:80]
    assert "set -euo pipefail" in body

    # Keine ungerenderten Jinja-Marker.
    assert "{{" not in body
    assert "}}" not in body  # auch keine Bash `${X:-${Y}}`-Doppel-Schliesser

    # Alle sechs Phasen sind als 'phase X 6' im Output verankert (passt zur
    # phase()-Helper-Signatur im Template).
    for n in range(1, 7):
        marker = f"phase {n} 6"
        assert marker in body, f"missing phase marker: {marker}"

    # Jeder Prompt-Aufruf liest aus $TTY_INPUT via die ask()-Helper-Funktion;
    # die Helper enthalten `read -r ... < "$TTY_INPUT"` (sichtbarer Prompt)
    # und `read -rsp ... < "$TTY_INPUT"` (silent fuer Master-Key). Beide
    # Redirects muessen exakt vorhanden sein, sonst leitet ein Prompt
    # versehentlich von stdin (= curl-Pipe) statt vom TTY.
    assert 'read -r answer < "$TTY_INPUT"' in body
    assert "read -rsp" in body and '< "$TTY_INPUT"' in body
    # Die drei Prompts (server name, interval, master key) gehen ueber die
    # ask()-Helper.
    assert "Server name" in body
    assert "scan interval" in body or "Expected scan interval" in body
    assert "Master-Key" in body

    # Eingebackene Konstanten.
    assert 'RECOMMENDED_TRIVY_VERSION="0.71.0"' in body
    assert 'MIN_TRIVY_VERSION="0.70.0"' in body
    assert 'CURRENT_AGENT_VERSION="0.7.0"' in body

    # FM_URL ist gesetzt (Fallback auf request.host_url in Tests).
    assert 'FM_URL="http' in body

    # Unattended-Modus ist behandelt.
    assert "FM_UNATTENDED" in body
    assert "FM_MASTER_KEY" in body

    # systemd- UND cron-Fallback sind im Template.
    assert "fathometer-agent.service" in body
    assert "fathometer-agent.timer" in body
    assert "/etc/cron.d/fathometer-agent" in body

    # Trivy-Setup laedt vom Aqua-Release.
    assert "TRIVY_RELEASE_URL_TEMPLATE=" in body
    assert "sha256" in body
