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

## Test-Konvention — Default vs. On-Demand

**Verbindlich für Hauptsession UND alle Subagenten — keine Ausnahmen.**

**Erlaubt** sind ausschließlich drei Quality-Gates:

1. **Linter** — `ruff check`, `ruff format --check`, `shellcheck` (bash-Linting ist statische Analyse, kein Test).
2. **Static Analyzer** — `mypy app/`.
3. **Pure-Unit-Tests** — `pytest` Default-Selektion ohne `-m db_integration|acceptance|integration|bench`-Marker. Mocks/Stubs/Fakes wo nötig.

**Verboten** sind alle anderen Test-Formen, auch wenn die Block-Spec sie historisch verlangt hat:

- `pytest -m db_integration|acceptance|integration|bench` — alles was echte Postgres/Docker/HTTP-Server braucht.
- `bats` / Bash-Test-Frameworks (`tests/agent/*.bats`, `tests/integration/installer/*.sh`).
- `RUN_E2E=1 pytest …` Live-Compose-Stack.
- Docker-Build-/Compose-Up-Smoke (`docker compose up`, `docker build`, `curl /healthz`).
- Alembic-Roundtrip-Läufe gegen echte DB.
- Browser-/Playwright-/Selenium-Tests.
- Performance-Bench-Läufe.

**Neu schreiben** ist nur für die drei erlaubten Gates zulässig. Wer einen Test mit einem verbotenen Marker oder eine `.bats`-/`.sh`-Test-Datei anlegen will, fragt den User explizit um Genehmigung **bevor** die Datei entsteht. Begründung in einem Satz mitliefern (warum die Logik nicht pure-unit-testbar ist).

**Ausführen** ist ausschließlich für die Default-Selektion erlaubt:
```
pytest                          # Default-Selektor exkludiert acceptance/integration/bench/db_integration
pytest <ziel-pfade>             # fokussiert, nur die geänderten Tests (ohne -m db_integration/etc.)
pytest -m "not todo_mock"       # echte Pure-Unit-Submenge (TICKET-004-Ziel)
```

**NIEMALS proaktiv aufrufen** (egal ob direkt oder via Subagent):
- `pytest -m db_integration` — Tests mit echter Postgres-DB-Semantik.
- `pytest -m acceptance` — Acceptance-/RC-Suite.
- `pytest -m integration` — Docker-/E2E-Integration.
- `RUN_E2E=1 pytest …` — Live-E2E gegen laufendes Compose-Stack.
- `pytest -m bench` — Performance-Mini-Benches.

Diese Suiten laufen ausschließlich auf **ausdrückliche User-Anweisung pro Lauf** (z. B. „RC-Smoke", „Integration prüfen", „Bench gegenmessen", „lass die db_integration für X laufen"). Auch nach einem fertigen Block, vor einem Commit oder „nur zur Sicherheit" verboten. Wenn ein Implementer-Agent für die DoD eines Blocks zwingend Postgres-Reflection-Tests etc. braucht: explizite User-Genehmigung einholen, sonst Block-DoD-Item als „beim User anstehen lassen" markieren statt selbst durchlaufen.

**Begründung:** Default-`pytest` (Pure-Unit) läuft in ~30 s. db_integration/acceptance ziehen die Iteration auf >5 min — die Entwicklungsgeschwindigkeit kippt. Massen-DB-/Integration-Tests verschleiern außerdem oft Logik-Bugs hinter Postgres-Semantik.

**Subagent-Pflicht:** Jeder Implementer-/Test-Writer-/Reviewer-Prompt enthält diese Regel wörtlich („Erlaubte Quality-Gates: ruff, mypy, shellcheck (Linter), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien."). Verstöße werden vom Orchestrator zurückgewiesen.

## pytest-Aufruf — Pflicht-Timeout

Jeder `pytest`-Aufruf (Hauptsession **und** Subagenten) läuft mit **explizitem Timeout** der das Bash-Default-Limit (2 Minuten = 120000 ms) nicht überschreitet. Begründung: ein hängender Test (Postgres-Lock-Wait, Async-Deadlock, requests-mock-Race) muss zeitnah als Hänger erkannt werden, nicht erst nach 10 Minuten Bash-Hard-Cap.

Konvention:
- **Default-Lauf** (`pytest`, `pytest <pfad>`): Bash `timeout: 120000` (2 min). Wenn der Pure-Unit-Default länger braucht, ist etwas falsch — abbrechen und Root-Cause analysieren.
- **Fokussierter Sub-Lauf** (`pytest tests/services/foo.py -v`): Bash `timeout: 60000` (1 min). Pure-Unit-Tests einer einzelnen Datei sind in Sekunden durch.
- **Pytest-internes Hänger-Backstop:** zusätzlich `--timeout=30 --timeout-method=thread` als Flag wo das Plugin `pytest-timeout` installiert ist. Auf Modul-/Test-Ebene per `@pytest.mark.timeout(N)` wenn ein bestimmter Test länger braucht.
- **Heavy-Suiten** (db_integration etc.): laufen nur nach User-Genehmigung — Timeout dann pro Lauf abgestimmt (typisch 300000 ms / 5 min).

Verbotene Aufruf-Form:
```
pytest ...                          # ohne Bash-timeout → 2-min-Default ist OK, aber 0-Indikation des Erwartungswerts
pytest --timeout=300 ...             # ohne Heavy-Suite-Begründung
.venv/bin/pytest 2>&1 | tail -15    # ohne timeout im Bash-Wrapper
```

Erlaubte Form:
```
.venv/bin/pytest tests/services/test_foo.py -v 2>&1 | tail -50   # Bash timeout: 60000
.venv/bin/pytest 2>&1 | tail -30                                   # Bash timeout: 120000, Default-Suite
```

**Subagent-Pflicht:** Implementer-/Test-Writer-Prompts enthalten den Satz: „Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf). Keine pytest-Aufrufe ohne Timeout."

## HTMX-OOB-Single-Source-Pattern

**Pflicht für jeden HTMX-OOB-Endpoint** (Polling-Partials, Batch-Updates, Out-of-Band-Swap-Responses):

1. **Ein Partial, beide Pfade.** Initial-Render und OOB-Response includieren dasselbe Jinja-Partial. OOB-spezifische Attribute (`hx-swap-oob="outerHTML:#…"`, `id="…"`-Anker) werden via Conditional-Flag (`{% if oob_swap %}…{% endif %}`) am Outer-Element gesetzt, der Rest des Markups ist identisch. **Niemals** zwei separate Templates mit „kopiertem" Markup — das ist garantierter Drift.
2. **ID-Konvention.** OOB-Targets bekommen IDs vom Schema `<feature>-<entity>-<id>-<slot>` (z. B. `sidebar-host-42-heartbeat`, `sidebar-host-42-counts`). Initial-Render setzt diese IDs immer, OOB-Response targetet via `outerHTML:#<id>`.
3. **Drift-Regression-Test ist Pflicht.** Pro OOB-Endpoint ein Pure-Unit-Test der Initial-Render und OOB-Render mit identischen Test-Fixtures rendert und strukturell vergleicht (gleiche IDs, gleiches Klassen-Set pro Cell, gleiche `data-*`-Keys). Verhindert dass zukünftige Implementer einen Pfad anfassen ohne den anderen.

**Begründung:** Block-W-Heartbeat-Bug (2026-05-24) — `sidebar/_heartbeat_bar.html` und `_partials/sidebar_batch_oob.html` hatten zwei verschiedene CSS-Klassen-Schemata (`host__beat-tick beat--alarm` vs. `host__beat__cell host__beat__cell--alarm`) und der OOB-Pfad targetete IDs die im Initial-Render gar nicht existierten. Der Per-Row-Viewport-Update-Pfad war damit ~2 Wochen tot ohne dass es jemand gemerkt hat. Single-Source-Partial hätte das von vornherein verhindert.

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
