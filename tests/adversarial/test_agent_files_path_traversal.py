"""Block N (ADR-0021) — Adversarial: Path-Traversal gegen `/agent/files/<name>`.

Whitelist + `send_from_directory` muessen alle Traversal-Patterns mit 404
beantworten. Niemals 200 (Datei ausserhalb von `AGENT_FILES_DIR`) und
niemals 5xx (Crash). Source-Patterns aus ARCHITECTURE.md §10 plus den
ueblichen Verdaechtigen.
"""

from __future__ import annotations

import pytest
from flask import Flask


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("/agent/files/../../etc/passwd", id="dotdot-segment"),
        pytest.param("/agent/files/..%2f..%2fetc%2fpasswd", id="urlencoded-traversal"),
        pytest.param("/agent/files/%2e%2e/secscan-agent.sh", id="encoded-dotdot"),
        pytest.param("/agent/files//etc/passwd", id="absolute-suffix"),
        pytest.param("/agent/files/secscan-agent.sh%00.malicious", id="nul-byte-suffix"),
        pytest.param("/agent/files/..\\..\\etc\\passwd", id="backslash-windows"),
        pytest.param("/agent/files/secscan-agent.sh/../secscan-register.sh", id="chained-dotdot"),
    ],
)
def test_agent_files_traversal_returns_404(db_app: Flask, path: str) -> None:
    """Alle Traversal-Patterns landen auf 404, niemals 200 oder 5xx."""
    client = db_app.test_client()
    resp = client.get(path)
    assert resp.status_code == 404, (path, resp.status_code, resp.data[:200])


def test_agent_files_known_file_outside_whitelist_404(db_app: Flask) -> None:
    """`README.md` liegt im selben `agent/`-Dir, ist aber nicht in der Whitelist."""
    client = db_app.test_client()
    resp = client.get("/agent/files/README.md")
    assert resp.status_code == 404


def test_agent_files_nullbyte_in_name_404(db_app: Flask) -> None:
    """NUL-Byte direkt im Pfad (nicht URL-encoded) wird vom Router gefangen."""
    client = db_app.test_client()
    resp = client.get("/agent/files/secscan-agent.sh\x00.evil")
    # Werkzeug typischerweise 404 oder 400. Niemals 200.
    assert resp.status_code in (400, 404), resp.status_code
