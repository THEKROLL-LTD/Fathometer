# AGENTS.md

## Sources Of Truth
- Vor Code-Aenderungen zuerst `ARCHITECTURE.md`, `docs/blocks/STATE.md`, relevante ADRs in `docs/decisions/` und bei Refactors `docs/techdebt.md` lesen; `README.md` enthaelt noch veraltete Status-Passagen, `STATE.md` ist aktueller.
- Aktueller Stand laut `STATE.md`: kein aktiver Block, v0.9.6 ist abgeschlossen; neue Features brauchen User-Entscheidung bzw. ADR/Spec-Update vor Code.
- Doc-Sprache und Code-Kommentare Deutsch; Code-Bezeichner und technische Strings Englisch.

## Architecture Constraints
- Stack ist fix: Python 3.13, Flask, SQLAlchemy 2.x, Alembic, Pydantic v2, Postgres 17, Jinja2/HTMX/Alpine/Tailwind/DaisyUI ohne Node-Build.
- fathometer ist Push-only: ueberwachte Server senden Trivy-Rootfs-Scans an `/api/scans`; keine SSH-/Server-Credentials oder Pull-Scanner einbauen.
- Trivy-JSON-Felder nicht erfinden: Pydantic-Schemas an echten Fixtures unter `tests/fixtures/trivy/` orientieren und `extra="ignore"` fuer Forward-Compat beibehalten.
- Keine `|safe`-Ausgabe fuer Client-/LLM-Daten; Markdown/HTML ueber `nh3`, nicht `bleach` oder direktes `markdown`.
- SQLAlchemy-`text()` nur mit gebundenen Parametern; bevorzugt ORM/SQLAlchemy-Ausdruecke.
- Out of scope bleibt hart: Notifications, Multi-User/RBAC/OIDC, Mobile-Optimierung, Container-Image-Scans, Repo-Scans, Misconfig/Secret-UI, PDF, Redis/verteiltes Rate-Limit, SBOM/License-Findings.

## Entrypoints And Services
- App-Factory ist `app:create_app()`; Container-Entrypoint `scripts/entrypoint.sh` wartet auf DB, fuehrt `alembic upgrade head` aus und startet Gunicorn mit `gthread`.
- Compose startet drei Services: `db`, `app`, `fathometer-llm-worker`; der Worker hat keine Ports und laeuft via `python -m app.workers.llm_worker`.
- `FM_ENCRYPTION_KEY` ist Pflicht; `.env.example` zeigt die Generatoren. `FM_PUBLIC_URL` in Production setzen, sonst rendert `/install.sh` hinter TLS-Proxies falsche interne HTTP-URLs.
- Dashboard-Live-Updates laufen ueber HTMX-Polling, nicht `/events`; nur LLM-Chat streamt per SSE (`/chat/<id>/stream`).
- Externe Feed-Pulls fuer EPSS/KEV laufen im Worker; Air-Gap-Deploys setzen `FM_FEED_PULL_DISABLED=true`.

## Verification Commands
- Standard-Reihenfolge: `ruff check . && ruff format --check .`, dann `mypy app/`, dann fokussierte Tests, dann bei Bedarf Full-Suite.
- Full default suite: `pytest -v` oder mit Coverage-Gate `pytest -v --cov=app --cov-fail-under=85`.
- Adversarial suite separat laufen lassen: `pytest tests/adversarial/ -v`.
- Shell-Agenten pruefen: `shellcheck agent/*.sh`.
- Migration roundtrip: `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`.
- Compose smoke: `docker compose up -d --build && curl -fsSL http://localhost:8000/healthz`; erwartet drei healthy Container inkl. `fathometer-llm-worker`.
- Release-CI baut nur `linux/amd64`; arm64 ist in `.github/workflows/release.yml` bewusst deaktiviert.

## Test Quirks
- `pytest.ini` schliesst `bench`, `integration` und `acceptance` per Default aus; gezielt laufen lassen mit `pytest -m bench`, `pytest -m integration` oder `pytest -m acceptance`.
- Viele DB-Tests nutzen echten Postgres unter `TEST_DATABASE_URL` oder Default `postgresql+psycopg://fathometer:fathometer@localhost:55432/fathometer_test`; ohne erreichbare DB werden sie geskippt.
- Lokale Test-DB: `docker run -d --name fathometer-test-db -e POSTGRES_USER=fathometer -e POSTGRES_PASSWORD=fathometer -e POSTGRES_DB=fathometer_test -p 55432:5432 postgres:17-alpine`.
- Acceptance/Migration-Tests koennen wegen bekannter `tests/conftest.py::_truncate_all`-Race empfindlich sein; siehe `docs/techdebt.md` TD-004 vor RC-Verifikation.
- Worker-Tests, die Mode/Budget mid-test aendern, brauchen den Test-Helper `invalidate_throttle_caches_for_tests()` wegen v0.9.6 Mode-/Budget-Caches.

## Frontend And Templates
- Kein Node-Build einfuehren; vorhandenes Tailwind/DaisyUI-CDN-Pattern respektieren.
- HTMX-Polling-Container brauchen `hx-disinherit="*"`, damit innere `hx-get`-Links keine Polling-Attribute erben.
- Pflicht-Kommentare in der UI vermeiden; Acknowledge/Reopen-Kommentare sind absichtlich optional.

## Agent And Installer
- `agent/` ist deploy-relevant und wird ins Docker-Image kopiert; nicht in `.dockerignore` aufnehmen.
- Referenz-Agent ist Bash, Push-only, gzippt `/api/scans`; er ist kein Daemon und schreibt ausser temporären Dateien nichts ausser seiner Konfiguration.
- Mindestversionen leben als ClassVars in `app/config.py` (`MIN_AGENT_VERSION`, `CURRENT_AGENT_VERSION`, Trivy-Versionen) und sollen nicht per Env konfigurierbar gemacht werden.

## Operational Gotchas
- Reverse-Proxy muss `/api/scans` grosse gzip-Bodies erlauben und idealerweise per IP allowlisten; `/chat/<id>/stream` braucht deaktiviertes Buffering und lange Read-Timeouts.
- LLM-Risk-Reviewer hat Modi `off`/`observation`/`live`; `observation` schreibt `would_call` und bucht Token-Schaetzung, ruft aber kein LLM.
- `llm_debug_log` speichert Request/Response-Bodies begrenzt fuer Operator-Debugging; keine sensiblen Daten ungeprueft in Logs/Templates ausgeben.
- Bekannte Tech-Debt vor Worker-/Feed-Refactors lesen: TD-001 EPSS-Pydantic-Hotspot, TD-002 Worker-Framework, TD-003 DB-gekoppelter Worker-Healthcheck, TD-006 k8s-Probes.

## Imported Claude Cowork project instructions
