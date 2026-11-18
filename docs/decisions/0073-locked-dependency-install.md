# ADR-0073 — CI and the image install exactly what `uv.lock` pins

**Status:** Accepted · **Date:** 2026-11-18

Refs: [ADR-0069](0069-runtime-base-image-almalinux-10-minimal.md) (builder and runtime share `/usr/bin/python3.14`).

## Context

`uv.lock` exists and Renovate maintains it, but nothing that ships used it. CI ran `pip install -e ".[dev]"` and the builder stage `pip install .`, both resolving fresh from the `>=` floors in `pyproject.toml`. A lockfile update could therefore pass review while CI tested, and the image shipped, a different set of versions. The floors for transitive packages in `pyproject.toml` existed only to compensate for that.

The agent workflow for Renovate pull requests (AGENTS.md, "Dependency update pull requests") merges on the strength of tests against `uv.lock`. That evidence is only worth something if `uv.lock` is what runs.

## Decision

**1 — One install path.** Local development, CI and the builder stage install with `uv sync --locked`. `--locked` fails when `uv.lock` does not match `pyproject.toml`, so a stale lock is a red build, not a silent re-resolve.

- Local and CI: `make install` (`uv sync --locked --extra dev`). CI runs the same `make` targets as the project contract.
- Image: `uv sync --locked --no-install-project` for the dependency layer, then `uv sync --locked --no-editable` for the app. The venv is created on the AppStream interpreter (`UV_PYTHON=/usr/bin/python3.14`, `UV_PYTHON_DOWNLOADS=never`), which keeps the ADR-0069 property that the runtime stage needs no venv relocation.

**2 — One uv version.** The `Dockerfile` stage `FROM ghcr.io/astral-sh/uv:<version> AS uv` is the only place the uv version is written. The builder copies the binary from it; CI reads the version from that line. Renovate updates it.

**3 — Floors stay.** The `>=` floors in `pyproject.toml` remain as the lower bound for a re-lock; they no longer decide what ships.

## Alternatives rejected

- **`uv export` to a requirements file plus `pip install --no-deps`.** Keeps pip in the image build but adds a generated file and a second tool to keep in step with the lock.
- **Keep pip, pin everything exactly in `pyproject.toml`.** Duplicates the lock by hand and loses the transitive graph.

## Consequences

- A dependency change reaches CI and the image only through `uv.lock`. Renovate lock-file maintenance becomes effective for the shipped image.
- Air-gap builds must mirror `ghcr.io/astral-sh/uv` in addition to the AlmaLinux and Node base images (`docs/operations.md`).
- The CI runner needs `make`; uv installs Python 3.14 itself.
- Changing dependencies by hand means `uv lock` and committing `uv.lock`; `pip install` against the repository is no longer a supported path.
