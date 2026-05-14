# syntax=docker/dockerfile:1.7
# Multi-Stage-Build fuer secscan.
# Builder installiert Dependencies in ein venv, runtime kopiert das venv und
# laeuft als non-root user.

ARG PYTHON_VERSION=3.13

# ---------------------------------------------------------------------------
# Stage 1 — Builder
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build-Tools fuer native Wheels (argon2-cffi, cryptography, psycopg).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# venv anlegen — wird nach runtime kopiert.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY pyproject.toml ./
COPY app ./app

RUN pip install --upgrade pip && \
    pip install .

# ---------------------------------------------------------------------------
# Stage 2 — Runtime
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    HOME=/app

# Runtime-Libraries (libpq fuer psycopg).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user.
RUN groupadd --system --gid 1001 secscan && \
    useradd --system --uid 1001 --gid secscan --shell /usr/sbin/nologin secscan

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

RUN chown -R secscan:secscan /app
USER secscan

EXPOSE 8000

# Healthcheck — docker-compose ueberschreibt das ggf., aber der Default
# soll auch fuer `docker run` brauchbar sein.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/readyz || exit 1

# Gunicorn als Entrypoint. Worker- und Timeout-Werte ueber Env steuerbar.
ENV SECSCAN_GUNICORN_WORKERS=2 \
    SECSCAN_GUNICORN_TIMEOUT=120

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:8000 --workers ${SECSCAN_GUNICORN_WORKERS} --timeout ${SECSCAN_GUNICORN_TIMEOUT} --worker-tmp-dir /dev/shm --access-logfile - --error-logfile - 'app:create_app()'"]
