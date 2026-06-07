"""ADR-0049 — Uninstaller-Auslieferung über `/uninstall.sh` + Whitelist.

Pure-Unit (Flask-Testclient, keine DB): der Uninstaller ist ein statisches
File, das über zwei Routes byte-identisch ausgeliefert wird. Plus ein
Content-Guard, der verhindert, dass ein künftiger Pfad-Rename den Uninstaller
still entwertet (analog zum Single-Source-Gedanken in CLAUDE.md).
"""

from __future__ import annotations

from pathlib import Path

from flask.testing import FlaskClient

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_UNINSTALL_SH = _REPO_ROOT / "agent" / "fathometer-uninstall.sh"


def test_uninstall_sh_served_as_shellscript(client: FlaskClient) -> None:
    """`GET /uninstall.sh` → 200 mit Shellscript-Content-Type."""
    resp = client.get("/uninstall.sh")
    assert resp.status_code == 200
    assert resp.mimetype == "text/x-shellscript"
    assert resp.get_data(as_text=True).startswith("#!/usr/bin/env bash")


def test_uninstall_available_via_agent_files_whitelist(client: FlaskClient) -> None:
    """Derselbe Inhalt ist auch über die Agent-Files-Whitelist erreichbar."""
    resp = client.get("/agent/files/fathometer-uninstall.sh")
    assert resp.status_code == 200
    assert resp.mimetype == "text/x-shellscript"


def test_uninstall_sh_alias_byte_identical_to_whitelist(client: FlaskClient) -> None:
    """`/uninstall.sh` und `/agent/files/fathometer-uninstall.sh` liefern
    byte-identisch dasselbe File — keine zweite Quelle, keine Drift."""
    via_alias = client.get("/uninstall.sh").get_data()
    via_whitelist = client.get("/agent/files/fathometer-uninstall.sh").get_data()
    assert via_alias == via_whitelist
    assert via_alias == _UNINSTALL_SH.read_bytes()


def test_unknown_agent_file_still_404(client: FlaskClient) -> None:
    """Die Whitelist bleibt geschlossen — Nicht-Whitelist → 404."""
    assert client.get("/agent/files/not-a-real-file.sh").status_code == 404


def test_uninstaller_removes_every_installer_artifact() -> None:
    """Content-Guard: das Skript adressiert alle Pfade, die der Installer
    anlegt. Bricht ein künftiger Pfad-Rename den Uninstaller, schlägt dieser
    Test sofort an statt dass die Deinstallation still unvollständig wird."""
    body = _UNINSTALL_SH.read_text(encoding="utf-8")
    for target in (
        "/opt/fathometer",
        "/etc/fathometer",
        "fathometer-agent.timer",
        "fathometer-agent.service",
        "/etc/cron.d/fathometer-agent",
        "trivy",
    ):
        assert target in body, f"uninstaller does not reference {target!r}"


def test_uninstaller_requires_root_and_confirms() -> None:
    """Sicherheits-Basics: läuft nur als root und fragt vor dem Löschen nach
    (überspringbar via --yes / FM_UNATTENDED)."""
    body = _UNINSTALL_SH.read_text(encoding="utf-8")
    assert "EUID:-$(id -u)" in body
    assert "Continue?" in body
    assert "--yes" in body
    assert "FM_UNATTENDED" in body
