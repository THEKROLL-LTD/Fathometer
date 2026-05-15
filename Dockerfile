# syntax=docker/dockerfile:1.7
# Multi-Stage-Build fuer secscan.
# Builder installiert Dependencies in ein venv, runtime kopiert das venv und
# laeuft als non-root user.

ARG PYTHON_VERSION=3.13

# ---------------------------------------------------------------------------
# Stage 1 — Builder
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

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

# --no-compile spart Platz; __pycache__ wird im Runtime-Stage ohnehin entfernt.
# Anschliessend pip/setuptools (Build-Tools) aus dem Runtime-venv loeschen, weil
# zur Laufzeit nichts mehr installiert wird.
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --no-compile . && \
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
# Stage 2 — Runtime-Builder (wird im naechsten Stage flach kopiert)
#
# Wir machen alle Modifikationen in diesem Stage, und kopieren das Resultat
# anschliessend als *eine* Schicht in den final-Stage. Das halbiert den
# Layer-Overhead von Multi-Stage-Builds und bringt das End-Image unter den
# 200 MB DoD-Cap (sonst landen die geloeschten Dateien aus dem base-Layer
# noch im Image-Total).
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    HOME=/app

# Runtime-Libraries (libpq fuer psycopg, curl fuer healthcheck).
# Anschliessend doc/man/locale-Dateien entfernen (nur en/de behalten) und
# Python-Bytecode-Caches loeschen, damit das Image-Volumen unter dem
# DoD-Cap von 200 MB bleibt.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* \
    && rm -rf /usr/share/doc /usr/share/man /usr/share/info \
    && find /usr/share/locale -mindepth 1 -maxdepth 1 -type d \
         ! -name 'en' ! -name 'en_US' ! -name 'de' ! -name 'de_DE' \
         -exec rm -rf {} + \
    && find /usr/local/lib -depth -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null \
    && find /usr/local/lib -name '*.pyc' -delete 2>/dev/null \
    && rm -rf \
        /usr/local/lib/python3.13/idlelib \
        /usr/local/lib/python3.13/tkinter \
        /usr/local/lib/python3.13/turtledemo \
        /usr/local/lib/python3.13/ensurepip \
        /usr/local/lib/python3.13/pydoc_data \
        /usr/local/lib/python3.13/unittest \
        /usr/local/lib/python3.13/test \
        /usr/local/lib/python3.13/lib2to3 \
        /usr/local/lib/python3.13/distutils \
        /usr/local/lib/python3.13/config-3.13-* \
    && find /usr/local/bin -name 'pip*' -delete 2>/dev/null \
    && find /usr/local/bin -name 'idle*' -delete 2>/dev/null \
    && find /usr/local/bin -name 'pydoc*' -delete 2>/dev/null \
    && find /usr/local/bin -name '2to3*' -delete 2>/dev/null \
    && rm -rf /usr/lib/aarch64-linux-gnu/perl-base 2>/dev/null \
    && rm -rf /usr/lib/x86_64-linux-gnu/perl-base 2>/dev/null \
    && rm -rf /usr/lib/aarch64-linux-gnu/gconv 2>/dev/null \
    && rm -rf /usr/lib/x86_64-linux-gnu/gconv 2>/dev/null \
    && rm -rf /usr/share/zoneinfo/Africa /usr/share/zoneinfo/America \
        /usr/share/zoneinfo/Antarctica /usr/share/zoneinfo/Arctic \
        /usr/share/zoneinfo/Atlantic /usr/share/zoneinfo/Australia \
        /usr/share/zoneinfo/Pacific /usr/share/zoneinfo/Indian 2>/dev/null \
    ; true

# Non-root user.
RUN groupadd --system --gid 1001 secscan && \
    useradd --system --uid 1001 --gid secscan --shell /usr/sbin/nologin secscan

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts/entrypoint.sh /usr/local/bin/secscan-entrypoint

RUN chmod +x /usr/local/bin/secscan-entrypoint && \
    chown -R secscan:secscan /app

# ---------------------------------------------------------------------------
# Stage 3 — Flat Runtime
#
# Kopiert das gesamte FS aus dem runtime-builder als *eine* Schicht in ein
# minimales scratch-Image. Damit fallen die Whiteouts der geloeschten base-
# Layer-Dateien weg und das End-Image entspricht dem tatsaechlichen
# Container-Footprint (~190-200 MB statt 225+).
# ---------------------------------------------------------------------------
FROM scratch AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME=/app

COPY --from=runtime-builder / /

WORKDIR /app
USER secscan

EXPOSE 8000

# Healthcheck — docker-compose ueberschreibt das ggf., aber der Default
# soll auch fuer `docker run` brauchbar sein.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/readyz || exit 1

# Entrypoint-Skript fuehrt `alembic upgrade head` aus (mit DB-Wait-Retry)
# und ersetzt sich dann mit Gunicorn. Worker-, Thread- und Timeout-Werte
# ueber Env steuerbar.
#
# `--worker-class gthread` ist Pflicht (nicht `sync`): die App hat zwei
# Long-lived-SSE-Endpoints (`GET /events` fuers Dashboard, `GET /chat/.../
# stream` fuer LLM-Chat). Eine offene SSE-Connection bindet einen
# Sync-Worker-Slot dauerhaft — schon ein einziger Browser-Tab plus ein
# zweiter Request laesst den Server bei 2 Sync-Workern komplett haengen.
# Mit `gthread` halten Threads die Streams offen, andere Threads
# bedienen normale Requests parallel.
#
# Default 2 Workers x 8 Threads = 16 gleichzeitige Connections. Reicht
# fuer Single-User-Self-Hosting mit ein paar offenen Tabs locker; gibt
# kaum Memory-Overhead, weil Threads sich den Prozess teilen.
# Thread-Safety: SQLAlchemy nutzt scoped sessions, structlog ist
# thread-safe, der EventBus baut auf `queue.Queue` — alles thread-safe.
# Siehe ADR-0015.
ENV SECSCAN_GUNICORN_WORKERS=2 \
    SECSCAN_GUNICORN_THREADS=8 \
    SECSCAN_GUNICORN_TIMEOUT=120

CMD ["secscan-entrypoint"]
