PYTHON_VERSION := 3.14
UV := uv
# --locked: never rewrite uv.lock implicitly; --extra dev: the dev tooling lives
# in [project.optional-dependencies] dev.
RUN := $(UV) run --locked --extra dev

.DEFAULT_GOAL := check

.PHONY: help install format lint typecheck test test-fast check test-installer

help:
	@echo "Targets:"
	@echo "  install         Install Python $(PYTHON_VERSION) and the locked dependencies (uv.lock)"
	@echo "  format          Format and auto-fix with ruff (modifies files)"
	@echo "  lint            ruff check, ruff format --check, shellcheck agent/*.sh"
	@echo "  typecheck       mypy (strict) on app/"
	@echo "  test            Default pytest selection with the coverage gate"
	@echo "  test-fast       Default pytest selection without coverage"
	@echo "  check           lint + typecheck + test"
	@echo "  test-installer  Block N installer E2E in Docker (operator only, needs docker + a running backend)"

install:
	$(UV) python install $(PYTHON_VERSION)
	$(UV) sync --locked --extra dev

format:
	$(RUN) ruff format .
	$(RUN) ruff check --fix .

lint:
	$(RUN) ruff check .
	$(RUN) ruff format --check .
	$(RUN) shellcheck agent/*.sh

typecheck:
	$(RUN) mypy app/

test:
	$(RUN) pytest --cov=app --cov-fail-under=73

# Default selection without coverage, for quick iteration.
test-fast:
	$(RUN) pytest --no-cov

check: lint typecheck test

# Block N (ADR-0021) installer E2E in Docker. Operator only: needs a running
# Docker daemon and a backend reachable at FM_URL
# (default http://host.docker.internal:8000).
test-installer:
	bash tests/integration/installer/run.sh
