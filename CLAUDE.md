# CLAUDE.md — Orchestrator-Kontext

Diese Datei wird bei jedem Claude-Code-Start gelesen. Verbindlich für die Hauptsession und alle Subagenten.

## Pflicht-Lektüre vor jedem Schritt

1. **`ARCHITECTURE.md`** — die Spec. Alle Implementierungs-Entscheidungen leiten sich daraus ab.
2. **`docs/blocks/STATE.md`** — aktueller Block, completed Blöcke, offene Tasks, Blocker.
3. **`docs/blocks/<aktueller-block>.md`** — Aufgaben und maschinell prüfbare Definition of Done.
4. **`docs/decisions/`** — ADRs. Nicht ohne Grund von dort abweichen; neue Entscheidungen als neue ADR ablegen.
5. **`docs/techdebt.md`** — bekannte technische Schulden (lebende Liste mit TD-IDs). Vor einem Refactor reinschauen ob bereits ein TD-Eintrag dazu existiert. Neue Tech-Schulden als neuen `TD-NNN`-Eintrag mit Was/Warum/Lösung/Aufwand/Wann eintragen statt im Code zu kommentieren.
6. **`docs/operations.md`** — Operator-Notizen (Outbound-URLs, Air-Gap-Setup, Feed-Pull-Health-Checks).

Subagent-Aufrufe nennen die zu lesenden Sektions-Nummern explizit (nicht "lies das Repo").

## Tech-Stack-Konstanten — NICHT abweichen

- **Python 3.13**, **Flask**, **SQLAlchemy 2.x**, **Alembic**, **Pydantic v2**.
- **PostgreSQL 17** in eigenem Container (nicht all-in-one).
- **Jinja2** + **HTMX** + **Alpine.js** + **Tailwind CSS** mit **DaisyUI**. **Kein Node-Build im MVP** (siehe ADR-001).
- **`openai`-Python-SDK** für LLM (OpenAI-kompatibles Protokoll, Default-Provider DeepInfra mit `deepseek-ai/DeepSeek-V3`).
- **`structlog`** für Logging mit Redaction-Filter.
- **`flask-limiter`** für Rate-Limits.
- **`nh3`** für Markdown/HTML-Sanitization (nicht `bleach`, nicht `markdown` direkt).
- **`argon2-cffi`** für Password- und Master-Key-Hashing; **SHA-256 + `hmac.compare_digest`** für hochentropische Server-Keys.
- **`cryptography`** Fernet für LLM-API-Key-Verschlüsselung.

## Coding-Conventions

- **Ruff** für Lint und Format (`ruff check . && ruff format --check .` muss grün sein).
- **mypy --strict** auf `app/` (PRs mit Type-Errors werden abgelehnt).
- **pytest** mit `pytest-asyncio` für async Tests.
- Pydantic-Modelle mit `model_config = ConfigDict(extra="ignore")` für Forward-Compat mit Trivy-JSON.
- Niemals `text()` ohne `:param`-Bind in SQLAlchemy. Niemals `|safe` in Jinja auf Client- oder LLM-Daten.
- Niemals Pflicht-Kommentare in der UI (siehe ADR-006).

## Test-, Lint- und Build-Commands

```
ruff check . && ruff format --check .
mypy app/
pytest -v
pytest tests/adversarial/ -v
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
docker compose up -d --build && curl -fsSL http://localhost:8000/healthz
```

## Out of Scope — wörtlich aus ARCHITECTURE §17

- Notifications jeglicher Art (Email, Discord, Webhooks)
- Multi-User mit RBAC oder OIDC-SSO
- Mobile-responsive Layout
- Container-Image-Scans (`trivy image …`)
- Code-Repository-Scans
- Misconfig- und Secret-Findings im UI (Schema vorbereitet, aber nicht aktiv)
- Trend-Graphen über lange Zeiträume
- PDF-Export
- Verteiltes Rate-Limit-Backend (Redis), Multi-Instance-Deploy
- SBOM-Erfassung, License-Findings

Wenn ein Agent Scope erweitern will: ablehnen und neue ADR erfordern.

## Workflow für die Hauptsession (Orchestrator)

1. Lies `docs/blocks/STATE.md`. Identifiziere aktuellen Block.
2. Wenn Block nicht gestartet: erstelle Branch `feat/block-<X>`, lies `docs/blocks/<X>-*.md`, plane Tasks.
3. Delegiere Tasks an Implementer-Agenten (`backend-implementer`, `frontend-implementer`) mit scoped Prompts: nenne explizit zu lesende ARCHITECTURE-Sektionen und Block-Datei.
4. Nach Implementierung: delegiere `test-writer` für die Komponente, dann `reviewer` mit der DoD-Checkliste.
5. Bei Sicherheits-relevanten Blöcken (G, H): zusätzlich `security-auditor`.
6. Wenn `reviewer` ablehnt: feedback an Implementer zurück, loop.
7. Wenn `reviewer` und ggf. `security-auditor` ok: update `STATE.md`, commit, PR-Beschreibung schreiben.
8. **STOP an jedem Block-Übergang** und frage User explizit ob nächster Block startet.

## Was schiefgehen kann (und Mitigation)

- **Halluzinierte Trivy-Felder** → Pydantic-Schema basiert ausschließlich auf den echten Fixtures unter `tests/fixtures/trivy/`. Niemals Felder erfinden.
- **Scope-Drift** → Out-of-Scope-Liste oben strikt einhalten.
- **"Fertig" mit roten Tests** → der `reviewer` führt Tests selbst aus und hat kein Schreibrecht.
- **Migration-Konflikte** → in jeder Block-DoD muss `alembic downgrade -1 && upgrade head` grün sein.
- **Drift zwischen ARCHITECTURE.md und Implementierung** → bei jeder Spec-Abweichung neue ADR oder Spec-Update bevor Code geschrieben wird.

## Kommunikations-Sprache

Doc-Sprache und Code-Kommentare auf Deutsch (User-Präferenz). Code selbst (Bezeichner, Strings) auf Englisch wegen Library-/Framework-Konventionen.
