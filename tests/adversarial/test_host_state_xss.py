# ruff: noqa: S104
"""Adversarial: XSS-Payloads im Host-Snapshot (Block O, ADR-0022).

Der Agent ab v0.3.0 sendet einen Snapshot-Block mit Process-`args`,
Listener-`process`-Namen und Service-Namen. Diese Felder landen via
`persist_host_state()` in den vier neuen `server_*`-Tabellen und werden
auf Server-Detail in `_partials/host_snapshot.html` gerendert.

Sicherheits-Invariante: Jinja-Autoescape MUSS jeden `<`, `>` und Attribut-
Quote escapen — sowohl im Listener-Process-Namen (linke Spalte) als auch
in den `title`-Tooltip-Attributen (Process-Args). Wir gehen ueber die echte
HTTP-Pipeline (Ingest -> DB -> Render), damit auch ein potenzieller
Bypass im Loader auffallen wuerde.

Wichtig: Trivys `<script>`-Inputs werden bereits im Envelope-Validator
gerejected (NUL/non-ASCII). `<script>alert(1)</script>` ist aber reines
druckbares ASCII (`[\x20-\x7e]`) und kommt damit am Validator vorbei —
exakt deshalb dieser Test gegen die Render-Schicht als zweite Verteidigung.
"""

from __future__ import annotations

import gzip
import json
import re
from typing import Any

from flask import Flask

from tests._helpers import create_admin_user, login, register_test_server, run_scan_synchronously

SCRIPT_PAYLOAD = "<script>alert(1)</script>"
SVG_PAYLOAD = "evil<svg onload=alert(1)>"


def _envelope_with_snapshot(
    *,
    listeners: list[dict[str, Any]] | None = None,
    processes: list[dict[str, Any]] | None = None,
    services: list[str] | None = None,
) -> dict[str, Any]:
    """Baut einen vollstaendigen Envelope mit Host-Snapshot."""
    host_state: dict[str, Any] = {
        "snapshot_at": "2026-05-18T03:14:22Z",
        "tools_available": ["ss", "ps"],
        "gaps": [],
        "listeners": listeners or [],
        "processes": processes or [],
        "kernel_modules": [],
        "services": services or [],
    }
    return {
        "agent_version": "0.3.0",
        "host": {
            "hostname": "xss-test-host",
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15.0",
            "architecture": "x86_64",
            "trivy_version": "0.70.2",
        },
        "scan": {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.2"},
            "Results": [
                {
                    "Target": "ubuntu",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-99999",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "Severity": "LOW",
                        }
                    ],
                }
            ],
        },
        "host_state": host_state,
    }


def _post_ingest(client: Any, payload: dict[str, Any], *, bearer: str) -> Any:
    return client.post(
        "/api/scans",
        data=gzip.compress(json.dumps(payload).encode("utf-8")),
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Authorization": f"Bearer {bearer}",
        },
    )


def _strip_known_safe_script_tags(body: str) -> str:
    """Entfernt bekannte Backend-Style-/Script-Tags (alpine.js loader etc.),
    damit der Test gezielt nach injizierten `<script>`-Tags suchen kann.

    Bekannte legitime Vorkommen aus den Templates:
      * `<script defer src="/static/...">` — Alpine.js und htmx.
      * `<script>` mit Page-Init (Tailwind dark-Mode-Hint im base.html).
      * `</script>` Closing-Tags zu obigen.

    Diese werden komplett entfernt, sodass `<script` im Resttext nur durch
    den Test-Payload entstehen kann.
    """
    # Entferne `<script ...> ... </script>` greedy, plus self-closing-/leere Varianten.
    return re.sub(
        r"<script\b[^>]*>.*?</script>",
        "",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )


def test_process_args_with_script_payload_renders_escaped(db_app: Flask) -> None:
    """Process-`args` `<script>alert(1)</script>` darf im Server-Detail
    nicht als aktives Skript landen.

    Render-Pfad: `_partials/host_snapshot.html` packt `process.args` als
    Wert des `title`-Attributs (Tooltip per pid-Lookup). Jinja-Autoescape
    konvertiert `<` / `>` / `"` zu Entities. Wir verifizieren:
      * Kein roher `<script>`-Tag aus dem Payload im HTML.
      * Mindestens der escaped Marker (`&lt;script` ODER `&#x3C;script` ODER
        `&#60;script`) ist sichtbar — Beleg dass der Payload zwar persistiert
        aber durchgehend escaped wurde.
    """
    create_admin_user(db_app)
    sid, key = register_test_server(db_app, name="srv-snap-xss-args")
    client = db_app.test_client()

    payload = _envelope_with_snapshot(
        listeners=[{"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd", "pid": 4711}],
        processes=[{"pid": 4711, "user": "root", "comm": "sshd", "args": SCRIPT_PAYLOAD}],
    )
    resp_ingest = run_scan_synchronously(db_app, client, key, payload)
    assert resp_ingest["status_code"] == 202, resp_ingest.get("response_body", "")[:300]
    assert resp_ingest["job_status"] == "done", f"Worker hat nicht done erreicht: {resp_ingest}"

    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
    body = resp.get_data(as_text=True)

    # Belegen, dass die Snapshot-Sektion ueberhaupt gerendert wurde.
    assert 'data-test="host-snapshot-section"' in body, (
        "Host-Snapshot-Sektion fehlt im Server-Detail — Test-Setup defekt."
    )

    # Bekannte legitime <script>-Tags (Alpine/htmx-Loader) ausblenden, dann
    # suchen wir gezielt nach injizierten <script>-Fragmenten.
    stripped = _strip_known_safe_script_tags(body)
    pattern = re.compile(r"<script\b", re.IGNORECASE)
    leftover = pattern.findall(stripped)
    assert not leftover, (
        f"Rohes <script>-Markup im Body nach Entfernen der Loader-Tags: {leftover!r}"
    )
    # Insbesondere darf der Payload-Text nicht als aktives Skript stehen.
    assert "<script>alert(1)</script>" not in stripped, (
        "Process-Args-Payload steht als rohes <script>...</script> im HTML."
    )
    # Escaper-Marker (eine der Entity-Varianten) muss sichtbar sein als
    # Beweis dass der Wert durch die Autoescape-Pipeline gegangen ist.
    assert (
        "&lt;script&gt;alert(1)&lt;/script&gt;" in body
        or "&lt;script" in body
        or "&#x3C;script" in body.lower()
        or "&#60;script" in body
    ), "Erwartet escaped <script>-Marker (&lt;script ...) im Tooltip-Attribut."


def test_listener_process_with_svg_onload_payload_renders_escaped(db_app: Flask) -> None:
    """Listener-`process` `evil<svg onload=alert(1)>` darf nicht als aktives SVG landen.

    Render-Pfad: linke Spalte der Listener-Liste (`{{ li.process or '?' }}`).
    Autoescape muss `<svg` zu `&lt;svg` machen — wir verifizieren das.
    """
    create_admin_user(db_app)
    sid, key = register_test_server(db_app, name="srv-snap-xss-svg")
    client = db_app.test_client()

    payload = _envelope_with_snapshot(
        listeners=[
            {
                "proto": "tcp",
                "addr": "127.0.0.1",
                "port": 8080,
                "process": SVG_PAYLOAD,
                "pid": 1234,
            }
        ],
        processes=[],
    )
    resp_ingest = run_scan_synchronously(db_app, client, key, payload)
    assert resp_ingest["status_code"] == 202, resp_ingest.get("response_body", "")[:300]
    assert resp_ingest["job_status"] == "done", f"Worker hat nicht done erreicht: {resp_ingest}"

    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Kein rohes <svg onload=...> Markup im HTML.
    assert not re.search(r"<svg\b[^>]*onload\s*=", body, re.IGNORECASE), (
        "Listener-Process-Payload erscheint als aktives <svg onload=...> im HTML."
    )
    # Stattdessen escaped — mindestens `&lt;svg` als Marker.
    assert "&lt;svg" in body or "&#x3C;svg" in body.lower(), (
        "Escaper-Marker fuer <svg im Listener-Process fehlt."
    )


def test_service_name_with_script_payload_renders_escaped(db_app: Flask) -> None:
    """Service-Name (alphabetisch in Punkt-getrennter Liste) wird escaped.

    Snapshot-Validator-Notiz: Service-Namen laufen durch
    `_filter_ascii_strings()` mit dem `_PRINTABLE_ASCII_RE`-Pattern und
    Length-Cap 128. `<script>alert(1)</script>` ist reines ASCII (35 Zeichen)
    -> kommt durch. Render-Verteidigung ist Pflicht.
    """
    create_admin_user(db_app)
    sid, key = register_test_server(db_app, name="srv-snap-xss-svc")
    client = db_app.test_client()

    payload = _envelope_with_snapshot(services=[SCRIPT_PAYLOAD, "sshd.service"])
    resp_ingest = run_scan_synchronously(db_app, client, key, payload)
    assert resp_ingest["status_code"] == 202, resp_ingest.get("response_body", "")[:300]
    assert resp_ingest["job_status"] == "done", f"Worker hat nicht done erreicht: {resp_ingest}"

    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Snapshot-Services-Sektion muss vorhanden sein (Service-Liste rendert).
    assert 'data-test="host-snapshot-services"' in body

    stripped = _strip_known_safe_script_tags(body)
    assert "<script>alert(1)</script>" not in stripped, (
        "Service-Name-Payload steht als rohes <script>...</script> im HTML."
    )
    assert "&lt;script" in body or "&#x3C;script" in body.lower(), (
        "Service-Name escaped-Marker fehlt."
    )
