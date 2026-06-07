"""Block N (ADR-0021, Task #18) — Installer-E2E in Docker.

Diese Tests stehen unter `@pytest.mark.integration` und sind aus der
Default-Suite ausgeschlossen (siehe `pytest.ini`).

Laufen lokal via `pytest -m integration` *oder* `bash tests/integration/
installer/run.sh`. CI-Stage: separater Job (Block-N-DoD-Lokal-Trigger).

Wenn Docker auf dem Test-Host nicht verfuegbar ist, wird der Test
geskipt. Damit bleibt die Reviewer-Pipeline gruen, auch wenn die Lokal-
Docker-Voraussetzung fehlt.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


INSTALLER_DIR = Path(__file__).parent / "installer"


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=False)
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
@pytest.mark.parametrize(
    "distro,dockerfile",
    [
        pytest.param("ubuntu-24.04", "Dockerfile.ubuntu-24.04"),
        pytest.param("almalinux-9", "Dockerfile.almalinux-9"),
    ],
)
def test_installer_runs_in_container(distro: str, dockerfile: str) -> None:
    """Baut das Container-Image und schaut, dass `docker build` selbst grun ist.

    Der vollstaendige `docker run`-Pfad gegen ein Live-Backend faehrt das
    `run.sh`-Helper-Skript (manueller Trigger via `make test-installer`),
    nicht dieser pytest-Lauf — pytest hat keine Backend-Instanz im Setup.
    """
    df = INSTALLER_DIR / dockerfile
    assert df.exists(), f"missing dockerfile: {df}"

    proc = subprocess.run(
        [
            "docker",
            "build",
            "-t",
            f"fathometer-installer-test:{distro}",
            "-f",
            str(df),
            str(df.parent.parent.parent.parent),  # repo root
        ],
        capture_output=True,
        check=False,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", errors="replace")[-500:]
