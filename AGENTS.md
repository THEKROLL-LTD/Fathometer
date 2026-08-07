# AGENTS.md — fathometer

The single source of truth for every coding agent in this repo. `CLAUDE.md` only imports this file; do not maintain rules in two places.

## Read before acting

| File | What it holds |
| --- | --- |
| `ARCHITECTURE.md` | The spec. Implementation decisions derive from it. |
| `docs/blocks/STATE.md` | Current block, completed blocks, open tasks, blockers. Start here — `README.md` still has stale status passages. |
| `docs/blocks/<current-block>.md` | Tasks and the machine-checkable Definition of Done. |
| `docs/tickets/TICKET-NNN-*.md` | A scoped change outside the block flow. `TICKET-TEMPLATE.md` is the format. |
| `docs/decisions/` | ADRs. Do not deviate without reason; record new decisions as a new ADR. |
| `docs/techdebt.md` | Known debt as `TD-NNN`. Check before refactoring; record new debt as a new entry (What/Why/Fix/Effort/When) instead of a code comment. |
| `docs/operations.md` | Operator notes: outbound URLs, air-gap setup, feed-pull health checks. |

Subagent prompts name the exact sections to read — never "read the repo".

## Tech stack — do not deviate

Versions and pinned dependencies live in `pyproject.toml`, the `Dockerfile` and `docker-compose.yml`. What follows is the set of decisions those files do not explain:

- **Python 3.14**, not 3.13 — EL10 AppStream ships no 3.13, and there is no source build. `pyproject.toml` pins `requires-python = ">=3.14"`.
- **Runtime base image AlmaLinux 10-minimal** (builder on `almalinux:10`), replacing Debian `python:3.13-slim` (ADR-0069).
- **Postgres 17 in its own container**, not all-in-one (`docker-compose.yml`).
- **Flask + SQLAlchemy 2.x + Alembic + Pydantic v2.** Gunicorn with `gthread` workers (needed for SSE, ADR-0015).
- **Jinja2 + HTMX + Alpine.js + plain CSS** with our own design tokens. No Tailwind, no DaisyUI (removed in ADR-0032). Frontend build runs via esbuild + lightningcss in a build-only Docker stage — the production image has no Node runtime.
- **`openai` SDK** for all LLM calls (OpenAI-compatible protocol, default provider DeepInfra). Reviewer and chat models are configured separately (ADR-0057) — do not hardcode a model name.
- **`pydantic-ai-slim[openai]` + `trafilatura`** only inside the `research-worker` path (ADR-0063). Never a replacement for the `openai` SDK in reviewer or chat.
- **`nh3`** for Markdown/HTML sanitization — not `bleach`, not `markdown` directly.
- **`argon2-cffi`** for password and master-key hashing; **SHA-256 + `hmac.compare_digest`** for high-entropy server keys.
- **`cryptography`** Fernet for LLM API-key encryption (ADR-0013).
- **`structlog`** for logging, with the redaction filter. **`flask-limiter`** for rate limits.

fathometer is **push-only**: monitored servers send Trivy rootfs scans to `/api/scans`. Never introduce SSH credentials or a pull scanner (ADR-0003).

## Coding conventions

- Pydantic models use `model_config = ConfigDict(extra="ignore")` for forward-compat with Trivy JSON.
- Trivy field names come only from the real fixtures in `tests/fixtures/trivy/`. Never invent a field.
- Never `text()` without a `:param` bind in SQLAlchemy; prefer ORM expressions. Never `|safe` in Jinja on client or LLM data.
- Constant-time comparison for every key or token: `hmac.compare_digest`, never `==` on a hash.
- Auth before body parse on `/api/scans`: verify the bearer, then decompress, then parse.
- Secrets never reach logs. Error paths map to error codes, not raw exception text.
- Never a mandatory comment field in the UI (ADR-0006).
- Never persist raw Trivy JSON in the DB (ADR-0005).
- Any deviation from `ARCHITECTURE.md` needs a new ADR or a spec update **before** the code is written.

## Quality gates

Four gates, and only these, may be run unattended:

```
ruff check . && ruff format --check .    # lint + format
shellcheck agent/*.sh                     # static analysis, not a test
mypy app/                                 # strict, on app/
pytest                                    # default selection
```

`pytest.ini` excludes `bench`, `integration`, `acceptance` and `db_integration`, and sets `--timeout=30 --timeout-method=thread`. A test needing longer carries `@pytest.mark.timeout(N)`.

**The default selection is not fully pure-unit.** `tests/conftest.py` auto-marks DB-touching files as `todo_mock`, which stays in the default selection by design — those tests hit a real Postgres on `localhost:55432` when one is up, and self-skip when it is not. For the genuine pure-unit subset:

```
pytest -m "not todo_mock"                 # TICKET-004 target state
```

Every `pytest` bash call carries an explicit `timeout` argument: ≤ 120000 ms for a default run, ≤ 60000 ms for a focused single-file run. The per-test `--timeout` does not catch a hang during collection or a suite that is slow in aggregate, so the bash-level bound stays required.

**Operator-only — never run proactively, not after a block, not before a commit, not "just to be safe":**

```
pytest -m db_integration                  # real Postgres semantics
pytest -m acceptance                      # acceptance / RC suite
pytest -m integration                     # Docker / E2E
pytest -m bench                           # performance benches
RUN_E2E=1 pytest …                        # live compose stack
bats tests/agent/*.bats                   # and tests/integration/installer/run.sh
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
docker compose up -d --build && curl -fsSL http://localhost:8000/healthz
```

Browser automation — Playwright, Selenium or equivalent — is forbidden outright, both running and writing. Live security probes (rate-limit flooding, gzip-bomb POSTs) are equally forbidden: assert the configuration and the code path statically instead.

These run only on an explicit per-run instruction ("RC smoke", "check integration", "run db_integration for X"). Every block DoD still requires a green `alembic downgrade -1 && upgrade head` roundtrip — mark it as pending on the user rather than running it yourself.

**Writing tests** is allowed only for the gates above. Creating a test with an excluded marker, or any `.bats`/`.sh` test file, requires asking the user first — with a one-sentence reason why the logic is not pure-unit testable.

Coverage target is 85% by the end of the roadmap: `pytest --cov=app --cov-report=term-missing`.

Rationale: the default suite runs in ~30 s. The heavy suites push iteration past 5 minutes and tend to hide logic bugs behind Postgres semantics.

## Changelog — required for every notable change

`CHANGELOG.md` follows Keep a Changelog + SemVer and is updated **in the same PR**. A missing entry is a review reject.

- One `###` block under `## [Unreleased]`, titled `<TICKET/ADR/Block>: <short>`, with `#### Added` / `#### Changed` / `#### Fixed` subsections.
- Covers anything operator-, behaviour-, schema- or build-relevant. Pure internal refactors may be skipped, with a reason in the PR.
- **Version source is the git tag `v*`**, not `pyproject.toml` (which stays static). Runtime shows `FM_VERSION` / `FM_BUILD_REVISION` from the build arg.
- Promotion `[Unreleased]` → `## [vX.Y.Z] — <YYYY-MM-DD>` happens **at release only**, together with the tag. Tags go on `main` after the merge — never on a feature or fix branch. Operator-visible feature → MINOR; pure bugfix → PATCH.

## HTMX OOB single-source pattern

Required for every OOB endpoint (polling partials, batch updates, out-of-band swap responses):

1. **One partial, both paths.** Initial render and OOB response include the same Jinja partial. OOB-specific attributes (`hx-swap-oob="outerHTML:#…"`, id anchors) are set on the outer element behind a conditional flag (`{% if oob_swap %}…{% endif %}`); the rest of the markup is identical. Never two templates with copied markup.
2. **ID scheme** `<feature>-<entity>-<id>-<slot>`, e.g. `sidebar-host-42-heartbeat`. The initial render always sets these IDs; the OOB response targets `outerHTML:#<id>`.
3. **A drift regression test is mandatory** per OOB endpoint: one pure-unit test that renders both paths from the same fixtures and compares structure (same IDs, same class set per cell, same `data-*` keys).

Failure-backed: the Block-W heartbeat bug (2026-05-24) left the per-row viewport update path dead for ~2 weeks because the two templates had diverged.

HTMX polling containers need `hx-disinherit="*"` so inner `hx-get` links do not inherit the polling attributes.

## Out of scope — from ARCHITECTURE §2

<!-- Older docs cite "§17" for this list and "§15" for triage. ARCHITECTURE.md was
renumbered and now ends at §14: scope is §2, triage is §12, input validation is §9. -->


Notifications of any kind · multi-user with RBAC or OIDC-SSO · mobile-responsive layout (ADR-0009) · container image scans · code repository scans · misconfig and secret findings in the UI (schema prepared, not active) · long-range trend graphs · PDF export · distributed rate-limit backend (Redis), multi-instance deploy · SBOM capture, license findings.

Two decisions with narrow exceptions — read the ADR before touching either:

- **Server-wide LLM chat** stays rejected (ADR-0050). Only the focused per-group chat per `(server, application group)` is in scope (ADR-0055).
- **Outbound web research** is out of scope by default (air-gap first). Only the optional, operator-gated, advisory upstream-update search in the `research-worker` path is in scope (ADR-0063). It never flips `risk_band` or `fix_lane` automatically.

If an agent wants to widen scope: refuse, and require a new ADR.

## Orchestrator workflow

1. Read `docs/blocks/STATE.md` and identify the current block.
2. If the block has not started: create branch `feat/block-<X>`, read `docs/blocks/<X>-*.md`, plan the tasks.
3. Delegate to `backend-implementer` / `frontend-implementer` with scoped prompts naming the exact ARCHITECTURE sections and the block file.
4. Then `test-writer` for the component, then `reviewer` against the DoD checklist. Security-relevant blocks (G, H) also get `security-auditor`.
5. If the reviewer rejects: send feedback back to the implementer and loop.
6. On pass: update `STATE.md`, commit, write the PR description.
7. **Stop at every block transition** and ask the user before starting the next one.

Every implementer, test-writer and reviewer prompt restates the quality-gate rule and the changelog requirement as part of its DoD. The reviewer runs the gates itself and has no write access.

A ticket is delegated the same way, minus the block steps: branch, implement against the ticket's Solution and DoD, gates, reviewer, commit.

**Branches:** `feat/block-<x>` · `feat/ticket-<nnn>-<slug>` for a ticket adding behaviour · `fix/<slug>` for a bug fix · `ci/<slug>`, `docs/<slug>` for those alone. Off `main`.

**Commits:** Conventional Commits with a scope, and the ticket or ADR in parentheses at the end — `fix(ingest): host_state best-effort — a bad listener no longer discards the scan (TICKET-018)`. Subject in English, imperative, no trailing period. One commit per ticket unless the work genuinely splits.

## Language policy

**English everywhere**, effective 2026-06-14 — docs, ADRs, block files, code comments, commit messages, identifiers and strings. No new German content anywhere. Existing German is legacy and gets translated on touch: when you edit a German section, convert that section rather than extending it.

**UI strings are English only** (ADR-0045): templates, flash messages, form-validator messages, JS strings, Jinja filter output, the chat system prompt. `tests/test_ui_language.py` fails otherwise. No i18n infrastructure.

## Runtime and services

- App factory is `app:create_app()`. The container entrypoint `scripts/entrypoint.sh` waits for the DB, runs `alembic upgrade head`, then starts Gunicorn.
- Compose runs four services: `db`, `app`, `fathometer-llm-worker`, `fathometer-research-worker`. The research worker is optional, operator-gated and default-off — air-gap deployments simply omit it.
- `FM_ENCRYPTION_KEY` is mandatory; `.env.example` shows the generators. Set `FM_PUBLIC_URL` in production, otherwise `/install.sh` renders internal HTTP URLs behind a TLS proxy.
- Dashboard live updates use HTMX polling, not SSE. The only SSE endpoint is the per-group chat stream (`GET /servers/<id>/groups/<gid>/chat/stream`).
- EPSS/KEV feed pulls run in the worker; air-gap deployments set `FM_FEED_PULL_DISABLED=true`.
- App healthcheck is `/readyz`. The worker healthcheck is an internal Python call (`python -m app.workers.healthcheck`), not HTTP, with a 10 s timeout — cold start under ARM64 measures ~6 s.
- Release CI builds `linux/amd64` only; arm64 is deliberately disabled in `.github/workflows/release.yml`.

## Test quirks

- Local test DB: `docker run -d --name fathometer-test-db -e POSTGRES_USER=fathometer -e POSTGRES_PASSWORD=fathometer -e POSTGRES_DB=fathometer_test -p 55432:5432 postgres:17-alpine`. Override with `TEST_DATABASE_URL`.
- Auto-marking in `tests/conftest.py`: paths in `_ACCEPTANCE_PATH_PREFIXES` (`tests/alembic/`, `tests/migrations/`, `tests/models/`, many `tests/integration/` files) get `acceptance` + `db_integration`. `_PURE_UNIT_OVERRIDES` exempts individual files; `_MOCKED_UNIT_FILES` are already mocked and stay unmarked. Everything else using a DB fixture gets `todo_mock`.
- Acceptance/migration tests can be flaky through the known `tests/conftest.py::_truncate_all` race — read `docs/techdebt.md` TD-004 before RC verification.
- Worker tests that change mode or budget mid-test need the helper `invalidate_throttle_caches_for_tests()` because of the v0.9.6 mode/budget caches.
- `tests/adversarial/` is unmarked and therefore part of the default selection; several block DoDs name it explicitly.

## Operational gotchas

- The reverse proxy must allow large gzip bodies on `/api/scans` and should IP-allowlist it. `/chat/<id>/stream` needs buffering disabled and long read timeouts.
- The LLM risk reviewer has modes `off` / `observation` / `live`. `observation` writes `would_call` and books a token estimate without calling an LLM.
- `llm_debug_log` stores request and response bodies in bounded form for operator debugging — never emit unreviewed sensitive data into logs or templates.
- Known tech debt to read before worker or feed refactors: TD-001 (EPSS Pydantic hotspot), TD-002 (worker framework), TD-003 (DB-coupled worker healthcheck), TD-006 (k8s probes), TD-019 (DNS rebinding / TOCTOU in the research worker).

## Agent and installer

- `agent/` is deploy-relevant and is copied into the Docker image. Never add it to `.dockerignore`.
- The reference agent is Bash, push-only, and gzips to `/api/scans`. It is not a daemon and writes nothing beyond temporary files and its own config.
- Minimum versions live as ClassVars in `app/config.py` (`MIN_AGENT_VERSION`, `CURRENT_AGENT_VERSION`, Trivy versions). Do not make them env-configurable.
