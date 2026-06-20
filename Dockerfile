# syntax=docker/dockerfile:1.7
# Multi-stage build for fathometer.
# The builder installs dependencies into a venv; the runtime copies the venv
# and runs as a non-root user. Runtime base OS is AlmaLinux 10-minimal
# (builder on almalinux:10) — see ADR-0069.

# Build revision (git SHA or similar) — set by CI via `--build-arg` and
# exported as an ENV in the runtime stage. The About view reads it via
# `os.environ.get("FM_BUILD_REVISION", "dev")`.
ARG FM_BUILD_REVISION=dev

# ---------------------------------------------------------------------------
# Stage 1 — Builder
# ---------------------------------------------------------------------------
FROM almalinux:10 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build tools for native wheels (argon2-cffi, cryptography, psycopg). The
# toolchain is a safety net for any sdist-only dependency; in practice our
# native deps ship manylinux_2_28/abi3 wheels and psycopg[binary] bundles
# libpq, so no compilation is expected. The dnf cache mount survives layer
# invalidations — avoids re-downloading the metadata on every build.
RUN --mount=type=cache,target=/var/cache/dnf,sharing=locked \
    dnf install -y \
        python3.14 \
        python3.14-devel \
        python3.14-pip \
        gcc \
        libffi-devel \
        openssl-devel \
    && dnf clean all

WORKDIR /build

# Create the venv — gets copied into the runtime stage. EL10 ships no
# python3.13; the AppStream interpreter is `python3.14` (not `python`).
# `python3.14-pip` is installed so `python3.14 -m venv` has ensurepip/pip.
RUN python3.14 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# ---- Dependency layer (changes only on pyproject.toml updates) ------------
# Trick: copy only pyproject.toml + README.md + a stub app first and run
# `pip install .`. This installs exclusively the dependencies (including the
# wheel builds for cryptography/argon2-cffi/psycopg). The stub package itself
# is uninstalled right away — the real app code is reinstalled `--no-deps` in
# the next layer.
#
# Cache mount on /root/.cache/pip: pip's HTTP wheel cache survives layer
# invalidations, so even on pyproject changes not all wheels have to be
# re-downloaded.
COPY pyproject.toml README.md ./
RUN --mount=type=cache,target=/root/.cache/pip \
    mkdir -p app && touch app/__init__.py && \
    pip install --upgrade pip && \
    pip install --no-compile . && \
    pip uninstall -y fathometer

# ---- App layer (changes on every code change) -----------------------------
# Copy the real app code and install the package without re-resolving the
# dependencies. This is cheap (no wheel build), so the majority of code-change
# builds finish in single-digit seconds.
COPY app ./app
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-compile --no-deps . && \
    pip uninstall -y pip setuptools wheel 2>/dev/null || true && \
    find /opt/venv -name '*.pyc' -delete && \
    find /opt/venv -depth -name '__pycache__' -type d -exec rm -rf {} + && \
    find /opt/venv -depth -name 'tests' -type d -exec rm -rf {} + && \
    find /opt/venv -depth -name 'test' -type d -exec rm -rf {} + && \
    find /opt/venv -depth -name 'pip' -type d -exec rm -rf {} + && \
    find /opt/venv -depth -name 'pip-*' -type d -exec rm -rf {} + && \
    find /opt/venv -depth -name 'setuptools*' -type d -exec rm -rf {} + && \
    find /opt/venv -depth -name 'wheel*' -type d -exec rm -rf {} + && \
    find /opt/venv -name '*.so' -exec strip --strip-unneeded {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# Stage 2 — Frontend build (esbuild + lightningcss, Block W / ADR-0032)
#
# Produces app/static/dist/{css,js,fonts}/* and manifest.json.
# No Node in the production image — only the finished static files are taken
# over via COPY --from=frontend-build in stage 3.
# ---------------------------------------------------------------------------
FROM node:20-alpine AS frontend-build

WORKDIR /repo/frontend

# Dependency layer first — invalidated only on package-lock.json changes.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Copy the frontend source and build it.
# esbuild writes __dirname-relative to /repo/app/static/dist/ (see
# esbuild.config.mjs: `resolve(__dirname, "../app/static/dist")`), i.e.
# independent of the WORKDIR. `WORKDIR` instead of `cd frontend` avoids DS-0013.
COPY frontend ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 3 — Runtime builder (copied flat into the next stage)
#
# We make all modifications in this stage and then copy the result as *one*
# layer into the final stage. That halves the layer overhead of multi-stage
# builds and brings the final image under the 200 MB DoD cap (otherwise the
# deleted files from the base layer still count toward the image total).
# ---------------------------------------------------------------------------
FROM almalinux:10-minimal AS runtime-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    HOME=/app

# Runtime essentials: python3.14 (the runtime interpreter — EL10 ships no
# python3.13; same /usr/bin path as the builder, so the venv needs no
# relocation), glibc-langpack-en (the only locale we ship — locale is
# controlled by what we install, not pruned after the fact), and shadow-utils
# (provides groupadd/useradd for the non-root user). No libpq (psycopg[binary]
# bundles it) and no curl (the healthcheck is a Python urllib probe — see
# HEALTHCHECK below).
#
# This install is a SEPARATE `RUN` from the strip below: it must NOT carry a
# trailing `; true`, otherwise a failed `microdnf install` (e.g. a missing
# package) is masked and the build silently continues with a broken base layer
# (regression: a masked `python3.13` resolution failure let the build run on to
# `groupadd: command not found`).
RUN --mount=type=cache,target=/var/cache/dnf,sharing=locked \
    microdnf install -y \
        python3.14 \
        glibc-langpack-en \
        shadow-utils \
    && microdnf clean all

# Strip docs/man/info, the gconv converters and most timezone regions, plus the
# Python stdlib modules we never use, so the image volume stays under the 200 MB
# DoD cap. Paths follow the RHEL layout (/usr/lib64). Every removal is guarded
# with `2>/dev/null ; true` so a missing path never fails the build — that guard
# is intentional HERE (idempotent rm of maybe-absent paths) and only here.
RUN rm -rf /usr/share/doc /usr/share/man /usr/share/info 2>/dev/null \
    && find /usr/lib64 -depth -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null \
    && find /usr/lib64 -name '*.pyc' -delete 2>/dev/null \
    # NOTE: do NOT strip `unittest`. Block AI (ADR-0063) pulls in
    # `pydantic-ai` -> `logfire-api`, whose `__init__.py` does
    # `from unittest.mock import MagicMock` at runtime (a no-op shim). The
    # research-worker would otherwise crash with `No module named 'unittest'`
    # as soon as it starts a real agent run (prod finding 2026-06-13).
    # `unittest` is therefore a runtime dep, not a pure test module.
    && rm -rf \
        /usr/lib64/python3.14/idlelib \
        /usr/lib64/python3.14/tkinter \
        /usr/lib64/python3.14/turtledemo \
        /usr/lib64/python3.14/ensurepip \
        /usr/lib64/python3.14/pydoc_data \
        /usr/lib64/python3.14/test \
        /usr/lib64/python3.14/lib2to3 \
        /usr/lib64/python3.14/config-3.14-* 2>/dev/null \
    && find /usr/bin -name 'idle*' -delete 2>/dev/null \
    && find /usr/bin -name 'pydoc*' -delete 2>/dev/null \
    && find /usr/bin -name '2to3*' -delete 2>/dev/null \
    && rm -rf /usr/lib64/gconv 2>/dev/null \
    && rm -rf /usr/share/zoneinfo/Africa /usr/share/zoneinfo/America \
        /usr/share/zoneinfo/Antarctica /usr/share/zoneinfo/Arctic \
        /usr/share/zoneinfo/Atlantic /usr/share/zoneinfo/Australia \
        /usr/share/zoneinfo/Pacific /usr/share/zoneinfo/Indian 2>/dev/null \
    ; true

# Non-root user (backed by shadow-utils).
RUN groupadd --system --gid 1001 fathometer && \
    useradd --system --uid 1001 --gid fathometer --shell /usr/sbin/nologin fathometer

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY app ./app
# Block W / ADR-0032: take over the frontend build artifacts from the
# frontend-build stage. Contains manifest.json + css/app.<hash>.css + js/*.js
# + fonts/*.
COPY --from=frontend-build /repo/app/static/dist ./app/static/dist
COPY alembic ./alembic
COPY alembic.ini ./
# Block N (ADR-0021): `/agent/*.sh` are served by the backend via
# `/agent/files/<name>` (`AGENT_FILES_DIR` points at `/app/agent`).
COPY agent ./agent
COPY scripts/entrypoint.sh /usr/local/bin/fathometer-entrypoint

RUN chmod +x /usr/local/bin/fathometer-entrypoint && \
    chown -R fathometer:fathometer /app

# ---------------------------------------------------------------------------
# Stage 4 — Flat runtime
#
# Copies the entire FS from the runtime-builder as *one* layer into a minimal
# scratch image. This drops the whiteouts of the deleted base-layer files so
# the final image matches the actual container footprint (~190-200 MB instead
# of 225+). This stage is OS-agnostic and must remain the LAST stage —
# release.yml builds the last Dockerfile stage with no explicit `target`.
# ---------------------------------------------------------------------------
FROM scratch AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME=/app

COPY --from=runtime-builder / /

WORKDIR /app
USER fathometer

EXPOSE 8000

# Healthcheck — docker-compose may override it, but the default should also be
# usable for `docker run`. Uses a Python urllib probe (curl is not installed in
# the image — dropping it also removes the libcurl->krb5/ldap/libssh2/gnutls
# transitive group).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/opt/venv/bin/python","-c","import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz').status==200 else 1)"]

# The entrypoint script runs `alembic upgrade head` (with DB-wait retry) and
# then replaces itself with Gunicorn. Worker, thread and timeout values are
# controllable via env.
#
# `--worker-class gthread` is mandatory (not `sync`): the app has a long-lived
# SSE endpoint (`GET /chat/.../stream` for LLM chat token streaming). An open
# SSE connection ties up a sync worker slot permanently — a single running chat
# stream plus a second request would hang the server at 2 sync workers.
# With `gthread`, threads hold the streams open while other threads serve
# normal requests (including dashboard polling fetches) in parallel.
#
# Default 2 workers x 8 threads = 16 concurrent connections. Plenty for
# single-user self-hosting with a few open tabs; barely any memory overhead
# because threads share the process.
# Thread safety: SQLAlchemy uses scoped sessions, structlog is thread-safe —
# everything is thread-safe.
# See ADR-0015 (gthread) and ADR-0019 (dashboard polling instead of SSE).
# Pass the build revision through to the runtime stage so the About view can
# read it. The ARG from stage 1 must be re-declared in the final stage
# (Docker multi-stage behavior).
ARG FM_BUILD_REVISION=dev
ENV FM_BUILD_REVISION=${FM_BUILD_REVISION} \
    FM_GUNICORN_WORKERS=2 \
    FM_GUNICORN_THREADS=8 \
    FM_GUNICORN_TIMEOUT=120

CMD ["fathometer-entrypoint"]
