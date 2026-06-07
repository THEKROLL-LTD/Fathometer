.PHONY: help test test-installer

help:
	@echo "Targets:"
	@echo "  test            Run default pytest suite (excludes bench + integration)"
	@echo "  test-installer  Run Block N installer E2E in Docker (requires docker + running backend)"

test:
	pytest -v --cov=app --cov-fail-under=85

# Block N (ADR-0021, Task #18) — Installer-E2E in Docker.
# Voraussetzung: Docker-Daemon laeuft, ein Backend ist erreichbar unter
# `FM_URL` (Default `http://host.docker.internal:8000`).
test-installer:
	bash tests/integration/installer/run.sh
