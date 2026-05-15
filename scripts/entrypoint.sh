#!/bin/sh
# secscan Container-Entrypoint
# ----------------------------
# 1. Wartet auf DB-Erreichbarkeit (max 60 s, exponentielles Backoff).
# 2. Fuehrt `alembic upgrade head` aus.
# 3. Ersetzt sich mit Gunicorn.
#
# Idempotent: `alembic upgrade head` ist no-op wenn die DB schon auf
# dem aktuellsten Stand ist. Race-Condition bei mehreren parallelen
# Container-Starts (z.B. Compose-Scaling) ist akzeptabel, weil alembic
# eine eigene Tabelle `alembic_version` mit Row-Level-Lock fuer den
# Upgrade-Schritt nutzt.

set -eu

# DB-Erreichbarkeit pruefen — wenn Compose mit `depends_on: condition:
# service_healthy` arbeitet, sollte die DB schon ready sein. Bei
# `docker run`-Direkt-Use oder nach Container-Restart kann die DB aber
# noch booten.
wait_for_db() {
  attempt=1
  max_attempts=10
  while [ $attempt -le $max_attempts ]; do
    if python -c "
import os, sys
from sqlalchemy import create_engine, text
url = os.environ.get('SECSCAN_DATABASE_URL', '')
if not url:
    sys.exit('SECSCAN_DATABASE_URL nicht gesetzt')
try:
    engine = create_engine(url, connect_args={'connect_timeout': 3})
    with engine.connect() as conn:
        conn.execute(text('SELECT 1'))
except Exception as exc:
    print(f'db nicht erreichbar: {exc}', file=sys.stderr)
    sys.exit(1)
" >/dev/null 2>&1; then
      echo "[entrypoint] db erreichbar nach $attempt Versuch(en)"
      return 0
    fi
    sleep_s=$((attempt * 2))
    echo "[entrypoint] warte auf db (Versuch $attempt/$max_attempts, ${sleep_s}s) …" >&2
    sleep "$sleep_s"
    attempt=$((attempt + 1))
  done
  echo "[entrypoint] db nicht erreichbar nach $max_attempts Versuchen — Abbruch" >&2
  return 1
}

run_migrations() {
  echo "[entrypoint] alembic upgrade head …"
  cd /app
  alembic upgrade head
  echo "[entrypoint] migrations applied"
}

wait_for_db
run_migrations

echo "[entrypoint] starte gunicorn"
exec gunicorn \
  --bind 0.0.0.0:8000 \
  --worker-class gthread \
  --workers "${SECSCAN_GUNICORN_WORKERS:-2}" \
  --threads "${SECSCAN_GUNICORN_THREADS:-8}" \
  --timeout "${SECSCAN_GUNICORN_TIMEOUT:-120}" \
  --worker-tmp-dir /dev/shm \
  --access-logfile - \
  --error-logfile - \
  'app:create_app()'
