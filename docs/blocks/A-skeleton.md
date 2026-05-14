# Block A — Skelett und Basis

## Ziel

Lauffähiges Repo mit Flask-App-Skelett und Postgres im docker-compose, App-Factory mit allen Cross-Cutting-Defaults (Body-Limits, Rate-Limiter, Logging, Autoescape) und einem `/healthz`-Endpoint. Keine Geschäftslogik. Nach Block A muss `docker compose up -d --build` plus `curl http://localhost:8000/healthz` einen 200er liefern.

## Vorbereitung — zu lesende Sektionen

- `ARCHITECTURE.md` §3 (Tech-Stack)
- `ARCHITECTURE.md` §4 (Architektur-Überblick)
- `ARCHITECTURE.md` §9 (DoS-Schutz — Body-Limits, Rate-Limiter)
- `ARCHITECTURE.md` §10 (Input-Validierung — Jinja-Autoescape, structlog)
- `CLAUDE.md` (Tech-Stack-Konstanten und Coding-Conventions)
- `docs/decisions/0001-no-node-build.md`

## Aufgaben

1. Repo-Layout anlegen (`app/`, `alembic/`, `tests/`, etc.).
2. `pyproject.toml` mit Dependencies: flask, sqlalchemy[asyncio], psycopg[binary], alembic, pydantic, pydantic-settings, flask-login, flask-limiter, flask-wtf, structlog, argon2-cffi, cryptography, openai, nh3, httpx, gunicorn. Dev-Deps: ruff, mypy, pytest, pytest-asyncio, pytest-cov.
3. `Dockerfile` (multi-stage: builder mit pip-install, runtime mit non-root user, gunicorn als entrypoint).
4. `docker-compose.yml` mit zwei Services (`app`, `db`), Healthchecks, `SECSCAN_ENCRYPTION_KEY` aus `.env`.
5. `.env.example` mit allen erwarteten Environment-Variablen plus Kommentaren.
6. `app/__init__.py` als Flask-App-Factory: konfiguriert `MAX_CONTENT_LENGTH=10MB`, registriert `flask-limiter` mit Default-Limits aus §9, initialisiert `structlog` mit JSON-Output und Redaction-Filter für `password|key|token|hash`-Felder, verifiziert `app.jinja_env.autoescape == True`, bindet Theme-Cookie-Handling für Light/Dark/Auto.
7. `app/config.py`: pydantic-settings-Klasse, liest aus Environment, validiert `SECSCAN_ENCRYPTION_KEY` Pflicht (Start-Refusal wenn fehlt), `SECSCAN_DATABASE_URL`, optionale Rate-Limit-Overrides.
8. `app/health.py` mit `/healthz` (DB-Ping + 200) und `/readyz` (nur 200).
9. Alembic-Init in `alembic/` mit erstem leeren Migration-Skript.
10. `pytest.ini` und `tests/conftest.py` mit Flask-Testclient-Fixture.
11. `ruff.toml` (line-length 100, strict-Profile passend), `mypy.ini` (strict für `app/`).
12. `README.md` im Repo (existiert schon — nur Erweiterung um Quick-Start: `docker compose up`, `cp .env.example .env`, Reverse-Proxy-Hinweis, Postgres-Backup-Hinweis als kurzer Absatz ohne Snippet — siehe ADR-005).

## Was NICHT in diesem Block

- Keine SQLAlchemy-Models (Block B).
- Keine Auth-Logik (Block B).
- Kein Setup-Wizard (Block B).
- Keine API-Endpunkte außer `/healthz` und `/readyz`.
- Keine Templates außer einem leeren `base.html` als Skelett.

## Definition of Done

Diese Liste wird vom `reviewer`-Agent ausgeführt. Jeder Eintrag muss grün sein bevor der Block als completed gilt.

### Datei-Existenz

- [ ] file: `pyproject.toml`
- [ ] file: `Dockerfile`
- [ ] file: `docker-compose.yml`
- [ ] file: `.env.example`
- [ ] file: `app/__init__.py`
- [ ] file: `app/config.py`
- [ ] file: `app/health.py`
- [ ] file: `alembic.ini`
- [ ] file: `alembic/env.py`
- [ ] dir: `alembic/versions/`
- [ ] file: `pytest.ini`
- [ ] file: `tests/conftest.py`
- [ ] file: `ruff.toml`
- [ ] file: `mypy.ini`

### Build und Start

- [ ] cmd: `docker compose build` → exit 0
- [ ] cmd: `docker compose up -d` → exit 0
- [ ] cmd: `sleep 5 && curl -fsS http://localhost:8000/healthz` → JSON mit `{"status":"ok"}`
- [ ] cmd: `curl -fsS http://localhost:8000/readyz` → 200
- [ ] cmd: `docker compose logs app | grep -v ERROR` → keine Errors

### Statische Checks

- [ ] cmd: `ruff check . && ruff format --check .` → exit 0
- [ ] cmd: `mypy app/` → exit 0
- [ ] cmd: `pytest -v` → all green (Smoke-Tests für `/healthz`, App-Factory-Defaults)

### Verhaltens-Checks

- [ ] cmd: `curl -fsS -X POST http://localhost:8000/healthz -H 'Content-Length: 99999999' -d 'x'` → 413 oder 405 (nicht 200)
- [ ] cmd: `for i in $(seq 1 30); do curl -fsS -X POST http://localhost:8000/api/register; done` → mindestens einer 429 (Rate-Limit greift)
- [ ] grep: `autoescape=True` ODER kein expliziter `autoescape=False` in `app/__init__.py`
- [ ] grep: `MAX_CONTENT_LENGTH` in `app/__init__.py` oder `app/config.py`
- [ ] grep: `structlog` und `compare_digest` Imports vorhanden in `app/`
- [ ] cmd: `unset SECSCAN_ENCRYPTION_KEY && python -c "from app import create_app; create_app()"` → SystemExit oder ConfigError (App refused start)

### Migration-Smoke

- [ ] cmd: `docker compose exec app alembic upgrade head` → exit 0
- [ ] cmd: `docker compose exec app alembic downgrade base && docker compose exec app alembic upgrade head` → exit 0

### Dokumentation

- [ ] `README.md` enthält "Quick-Start"-Sektion mit `docker compose up`, `cp .env.example .env`, Reverse-Proxy-Hinweis, Postgres-Backup-Hinweis als Prosa-Absatz (kein fertiges pg_dump-Snippet, siehe ADR-005).
- [ ] `STATE.md` ist nach Abschluss aktualisiert: Block A in "Completed", Block B als "Aktueller Block".

## Übergabe an reviewer

Wenn alle Checkboxen oben grün sind, der `reviewer`-Agent wird invoked mit:

> Lies `docs/blocks/A-skeleton.md` und prüfe jede DoD-Checkbox. Du hast nur Read- und Bash-Zugriff. Bei Fehlschlag konkrete Begründung pro Item. Bei Erfolg formelle Freigabe als Markdown-Block, der in den PR übernommen wird.
