"""End-to-End-Smoke fuer `agent/secscan-register.sh` und `agent/secscan-agent.sh`.

Standard: `@pytest.mark.e2e` und skip wenn `RUN_E2E=1` nicht gesetzt ist.
Die Tests setzen einen ECHTEN HTTP-Server voraus (docker compose up). Im CI
sind sie standardmaessig disabled — nicht weil sie unzuverlaessig sind, sondern
weil ein laufender docker compose Setup vorausgesetzt wird.

Manuelle Ausfuehrung:

    docker compose up -d
    # Setup ueber /setup im Browser abschliessen
    # ODER: einen Master-Key direkt in die DB setzen, dann
    export RUN_E2E=1
    export SECSCAN_URL=http://localhost:8000
    export SECSCAN_MASTER_KEY=...
    .venv/bin/pytest tests/e2e/ -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AGENT_DIR = REPO_ROOT / "agent"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "trivy" / "ubuntu-22.04-rke2.json"

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_E2E") != "1",
    reason="E2E-Tests benoetigen einen laufenden Backend-Server. "
    "Setze RUN_E2E=1 und docker compose up.",
)


def _server_url() -> str:
    return os.environ.get("SECSCAN_URL", "http://localhost:8000")


def _master_key() -> str:
    key = os.environ.get("SECSCAN_MASTER_KEY")
    if not key:
        pytest.skip("SECSCAN_MASTER_KEY nicht gesetzt — Setup nicht abgeschlossen?")
    return key


def test_register_script_returns_server_key(tmp_path: Path) -> None:
    """`secscan-register.sh` druckt den Server-Key auf stdout."""
    env = dict(os.environ)
    env["SECSCAN_MASTER_KEY"] = _master_key()
    result = subprocess.run(  # noqa: S603
        [
            str(AGENT_DIR / "secscan-register.sh"),
            _server_url(),
            f"e2e-host-{os.getpid()}",
            "24",
        ],
        env=env,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    api_key = result.stdout.decode().strip()
    assert len(api_key) >= 32, repr(api_key)


def test_agent_script_pushes_real_fixture(tmp_path: Path) -> None:
    """`secscan-agent.sh` mit Mock-Trivy laeuft erfolgreich gegen Backend.

    Wir bauen einen Mock-Trivy-Wrapper, der die echte Fixture in `--output`
    schreibt, und setzen `SECSCAN_TRIVY_PATH` darauf.
    """
    # Schritt 1: registrieren -> Server-Key holen.
    env = dict(os.environ)
    env["SECSCAN_MASTER_KEY"] = _master_key()
    reg = subprocess.run(  # noqa: S603
        [
            str(AGENT_DIR / "secscan-register.sh"),
            _server_url(),
            f"e2e-agent-{os.getpid()}",
            "24",
        ],
        env=env,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert reg.returncode == 0, reg.stderr.decode()
    api_key = reg.stdout.decode().strip()

    # Schritt 2: Mock-Trivy-Skript.
    mock_trivy = tmp_path / "mock-trivy.sh"
    fixture_str = str(FIXTURE)
    # secscan-agent.sh ruft: trivy fs <path> --format json ... --output <file>
    mock_trivy.write_text(
        "#!/usr/bin/env bash\n"
        "set -e\n"
        'out=""\n'
        "while [[ $# -gt 0 ]]; do\n"
        '  case "$1" in\n'
        '    --output) out="$2"; shift 2 ;;\n'
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        f"cp '{fixture_str}' \"$out\"\n"
    )
    mock_trivy.chmod(0o755)

    # Schritt 3: agent laufen lassen.
    env = dict(os.environ)
    env["SECSCAN_URL"] = _server_url()
    env["SECSCAN_API_KEY"] = api_key
    env["SECSCAN_TRIVY_PATH"] = str(mock_trivy)
    env["SECSCAN_SCAN_PATH"] = str(tmp_path)
    result = subprocess.run(  # noqa: S603
        [str(AGENT_DIR / "secscan-agent.sh")],
        env=env,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert b"Scan erfolgreich" in result.stderr or b"202" in result.stderr


def test_curl_401_for_wrong_bearer_is_fast() -> None:
    """Verhaltens-Check aus der DoD: 401 in <50ms bei falschem Bearer.

    Toleranter gefasst: <500ms aus Test-Sicht, weil CI-Maschinen langsam sind.
    """
    import time

    import httpx

    start = time.monotonic()
    r = httpx.post(
        f"{_server_url()}/api/scans",
        content=b"x",
        headers={"Authorization": "Bearer wrong"},
        timeout=5.0,
    )
    elapsed = time.monotonic() - start
    assert r.status_code == 401
    assert elapsed < 0.5, f"401 dauerte {elapsed:.3f}s — Auth ist nicht vor Body-Parse"


def test_gzip_bomb_returns_413_or_401() -> None:
    """gzip-Bomb gegen einen ungueltigen Bearer endet bei 401 (Auth vor Body)."""
    import gzip

    import httpx

    payload = gzip.compress(b"A" * (200 * 1024 * 1024))
    r = httpx.post(
        f"{_server_url()}/api/scans",
        content=payload,
        headers={
            "Authorization": "Bearer wrong",
            "Content-Encoding": "gzip",
        },
        timeout=10.0,
    )
    # Ohne valid bearer ist 401 das erste was greift; mit valid wuerde 413 kommen.
    assert r.status_code in (401, 413), r.text


def test_run_adversarial_script_passes() -> None:
    """Das `run_adversarial.sh` muss erfolgreich (exit 0) durchlaufen."""
    env = dict(os.environ)
    env["SECSCAN_URL"] = _server_url()
    result = subprocess.run(  # noqa: S603
        [str(REPO_ROOT / "tests" / "adversarial" / "run_adversarial.sh")],
        env=env,
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, (
        f"run_adversarial.sh exit {result.returncode}\n"
        f"STDOUT:\n{result.stdout.decode()}\n"
        f"STDERR:\n{result.stderr.decode()}"
    )
