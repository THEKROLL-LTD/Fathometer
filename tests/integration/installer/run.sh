#!/usr/bin/env bash
#
# Block N (ADR-0021, Task #18) — Helper-Skript fuer `make test-installer`.
#
# Voraussetzung: Docker-Daemon laeuft, ein Mock-Backend hoert auf
# `http://localhost:8000` (z.B. `docker compose up -d secscan`).
#
# Baut die zwei Test-Images und schiesst sie nacheinander gegen das
# Backend. Exit 0 wenn beide grun, sonst 1 mit Output beider Container.
#
# Nicht in der Default-Suite — wird via `pytest -m integration` oder
# `make test-installer` getriggert.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
BACKEND_URL="${SECSCAN_URL:-http://host.docker.internal:8000}"

build_and_run() {
  local distro="$1" dockerfile="$2"
  local image="secscan-installer-test:${distro}"
  echo "==> building ${image}"
  docker build -t "${image}" -f "${REPO_ROOT}/tests/integration/installer/${dockerfile}" "${REPO_ROOT}"
  echo "==> running ${image} against ${BACKEND_URL}"
  docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -e "SECSCAN_URL=${BACKEND_URL}" \
    -e "SECSCAN_UNATTENDED=1" \
    -e "SECSCAN_MASTER_KEY=${SECSCAN_MASTER_KEY:-test-master-key-32-bytes-minimum-entropy-aaa}" \
    -e "SECSCAN_SERVER_NAME=${distro}-installer-test" \
    -e "SECSCAN_INSTALL_TRIVY=yes" \
    "${image}"
}

build_and_run ubuntu-24.04 Dockerfile.ubuntu-24.04
build_and_run almalinux-9 Dockerfile.almalinux-9

echo "All installer-E2E containers passed."
