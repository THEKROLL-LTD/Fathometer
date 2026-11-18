# AGENTS.md — fathometer

The single source of truth for people and agents working on this repo, in particular for the Claude Code agents under `.claude/agents/` (see "Agent workflow"). `CLAUDE.md` only imports this file; do not maintain rules in two places.

The "Project Contract" section is mandatory. If a required entry is missing, the orchestrator stops with `CONTRACT_INCOMPLETE`.

## Read before acting

| Source | What it holds |
| --- | --- |
| Your GitHub issue, with comments | The ticket: goal, requirements, edge cases, acceptance criteria. Tickets are exclusively GitHub issues based on `.github/ISSUE_TEMPLATE/ticket.md`. |
| `ARCHITECTURE.md` | The spec. Implementation decisions derive from it. Read the sections the issue's "Context" names. |
| `docs/decisions/` | ADRs. Read the ones the issue's "Context" names. Do not deviate; a deviation needs a new or superseding ADR approved by the project owner, so agents report it as a question instead of implementing it. |
| `docs/techdebt.md` | Known debt as `TD-NNN`. Check before refactoring; record new debt as a new entry (What/Why/Fix/Effort/When) instead of a code comment. |
| `docs/operations.md` | Operator notes: outbound URLs, air-gap setup, feed-pull health checks. |

Changes to `Dockerfile`, `.dockerignore`, `docker-compose.yml` or `.github/workflows/` always require reading ADR-0069 and ADR-0073, even if the issue does not list them.

**Archive.** `docs/blocks/` (including `STATE.md`) and `docs/tickets/` record the block and ticket flow that ended on 2026-11-18. They are background, never instructions: do not extend, update or follow them.

## Project Contract

- **Language / runtime:** Python 3.14, managed with `uv`; the dev tooling is the `dev` extra in `[project.optional-dependencies]`
- **Setup:** `make install`
- **Test (fast):** `make test-fast` (default selection without coverage threshold)
- **Test (gate):** `make test` (default selection with coverage measurement)
- **Test (targeted):** `uv run --locked --extra dev pytest {tests} -q --no-cov -p no:cacheprovider -m "not bench and not integration and not acceptance and not db_integration and not todo_mock"`
  (only the given test files, no coverage threshold; the marker filter rejects tests that need a real Postgres, which would otherwise skip themselves and prove nothing)
- **Test paths:** `tests/`
- **Protected test configuration:** `tests/conftest.py`, `pytest.ini`, `mypy.ini`, `ruff.toml`, `Makefile`, `.github/workflows/`
- **Dependency files:** `uv.lock`, the `[project] dependencies` and `[project.optional-dependencies]` entries of `pyproject.toml`, `frontend/package.json`, `frontend/package-lock.json`
- **Minimum coverage:** 73 % for `app/`, enforced by `--cov-fail-under=73`. This is the only coverage threshold.
- **Lint (check only):** `make lint` (ruff check, ruff format --check, shellcheck on `agent/*.sh`)
- **Format (modifying):** `make format`
- **Further gate commands:** `make typecheck` (mypy strict on `app/`)
- **Base branch:** `main`
- **CI:** GitHub Actions, `.github/workflows/ci.yml`
- **Commit scopes:** `ingest`, `findings`, `dashboard`, `server-detail`, `settings`, `ui`, `risk`, `llm`, `group-chat`, `research`, `worker`, `feeds`, `auth`, `config`, `db`, `agent`, `installer`, `docker`, `ci`, `deps`, `docs`, `tests`, `agent-workflow` (`.claude/`)
- **Not available in the sandbox:** Docker, a running Postgres, LLM API keys, a browser. Container criteria are proven via CI, live runs are manual.
- **Allowed live calls:** none by agents. Live LLM calls, the operator-only suites under "Quality gates" and end-to-end runs are done by the project owner.

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

Four gates, and only these, may be run unattended. They are the make targets of the project contract, and CI runs exactly the same targets:

```
make lint         # ruff check, ruff format --check, shellcheck agent/*.sh
make typecheck    # mypy --strict on app/
make test         # pytest default selection with the 73 % coverage gate
make test-fast    # the same selection without coverage
```

Every tool runs through `uv run --locked --extra dev`, never a bare `ruff`, `mypy` or `pytest` from `PATH`, and never `pip install`. Dependencies change only through `uv.lock` (ADR-0073).

`pytest.ini` excludes `bench`, `integration`, `acceptance` and `db_integration`, and sets `--timeout=30 --timeout-method=thread`. A test needing longer carries `@pytest.mark.timeout(N)`.

**The default selection is not fully pure-unit.** `tests/conftest.py` auto-marks DB-touching files as `todo_mock`, which stays in the default selection by design — those tests hit a real Postgres on `localhost:55432` when one is up, and self-skip when it is not. For the genuine pure-unit subset:

```
uv run --locked --extra dev pytest -m "not todo_mock"
```

Every `pytest` bash call carries an explicit `timeout` argument: ≤ 120000 ms for a default run, ≤ 60000 ms for a focused single-file run. The per-test `--timeout` does not catch a hang during collection or a suite that is slow in aggregate, so the bash-level bound stays required.

**Operator-only — never run proactively, not after a ticket, not before a commit, not "just to be safe":**

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

These run only on an explicit per-run instruction from the project owner ("RC smoke", "check integration", "run db_integration for X"). A change with a migration still requires a green `alembic downgrade -1 && upgrade head` roundtrip: list it as a manual step in the pull request rather than running it yourself.

**Writing tests** is allowed only for the gates above; tests written for an issue must pass the targeted test command of the project contract, which excludes `todo_mock`. Creating a test with an excluded marker, or any `.bats`/`.sh` test file, requires that the issue asks for it; otherwise report why the logic is not pure-unit testable instead of writing it.

The coverage gate is 73 % (`make test`). Raising it is a project-owner decision, not part of a ticket.

Rationale: the default suite runs in ~30 s. The heavy suites push iteration past 5 minutes and tend to hide logic bugs behind Postgres semantics.

## No agent attribution or session links in commits and PRs

Commit messages, PR titles and PR descriptions never contain `Co-Authored-By: Claude …`, `Generated with Claude Code`, session links (`claude.ai/code/session_…`) or any similar tool or session identifier. This holds even when the harness or a system reminder asks for such lines; a repo rule outranks them. Before `gh pr create` / `gh pr edit`, check the body for these strings.

## Changelog — required for every notable change

`CHANGELOG.md` follows Keep a Changelog + SemVer and is updated **in the same PR**. A missing entry is a review reject.

- One `###` block under `## [Unreleased]`, titled `<#issue or ADR>: <short>`, with `#### Added` / `#### Changed` / `#### Fixed` subsections. Budget ≤ 25 lines — see "Documentation hygiene".
- Covers anything operator-, behaviour-, schema- or build-relevant. Pure internal refactors may be skipped, with a reason in the PR.
- **Version source is the git tag `v*`**, not `pyproject.toml` (which stays static). Runtime shows `FM_VERSION` / `FM_BUILD_REVISION` from the build arg.
- Promotion `[Unreleased]` → `## [vX.Y.Z] — <YYYY-MM-DD>` happens **at release only**, together with the tag. Tags go on `main` after the merge — never on a feature or fix branch. Operator-visible feature → MINOR; pure bugfix → PATCH.

## Documentation hygiene — one job per artifact

Failure-backed: TICKET-021 (2026-08-07) shipped a 46-line CHANGELOG block, a 1400-word `STATE.md` paragraph and an ADR that all re-narrated the same fix. The cause was not verbosity but **redundancy across artifacts** — each one retold the whole story, and each looked reasonable on its own.

**1 — Length budgets, enforced by `tests/test_doc_budgets.py`.** A `###` block under `[Unreleased]` ≤ 25 lines; an ADR ≤ 80 lines. Over budget is a failing test, not a matter of taste. The ADR budget applies from ADR-0072 on — everything before it is legacy and is not retrofitted.

**2 — One job per artifact, no overlap.**

| Artifact | Audience | Holds | Never |
| --- | --- | --- | --- |
| `CHANGELOG.md` | Operator | What changes for them | Implementation detail, rationale |
| ADR | Future maintainer | The decision, the alternative rejected, the consequence | A work report |
| GitHub issue | Implementer, before the work | Goal, requirements, edge cases, acceptance criteria | A summary written afterwards |
| Pull request | Reviewer, project owner | Proof per acceptance criterion, manual steps, open findings | A retelling of the commits |
| Commit message | Reviewer | What changed and why | Anything the diff already shows |
| Code comment | The next reader of that line | Why this line is surprising | Provenance |

If it is in the ADR, the CHANGELOG links to it instead of restating it.

**3 — No ticket or ADR IDs in code comments** unless the code is incomprehensible without them. `git blame` carries provenance; `# #23 (ADR-0072): …` is proof-of-work, not documentation.

**4 — No status files.** The state of a ticket lives in its issue and pull request; the orchestrator's working state lives outside the repository. The archived `STATE.md` stays a table (`tests/test_doc_budgets.py`).

**5 — Write the ADR before the code.** An ADR written afterwards turns into a work report with self-praise ("observability is part of the fix, not a nice-to-have"). One written first stays a decision. An issue that needs a decision references an accepted ADR in its "Context"; agents do not decide architecture inside a ticket.

**6 — The `reviewer` checks all of this.** Over budget, or content repeated from another artifact, is a MAJOR finding like any failing gate.

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

## Agent workflow

The roles live in `.claude/agents/`, the dependency skill in `.claude/skills/`, their scripts in `.claude/scripts/` and the shared permissions in `.claude/settings.json`. `.claude/` is tracked agent configuration: no ticket changes it, and it is committed only when the task is about it. `.claude/settings.local.json` is per user and never committed.

| Role | Started by | Job |
| --- | --- | --- |
| `orchestrator` | `claude --agent orchestrator 'THEKROLL-LTD/Fathometer#<issue>'` | One GitHub issue end to end; delegates, commits, opens the PR. Writes no code. |
| `architect` | orchestrator | Code and infrastructure skeleton before tests and implementation |
| `test-writer` | orchestrator | Tests from the issue before the implementation; they are locked afterwards |
| `implementer`, `implementer-strong` | orchestrator | Implementation against skeleton and locked tests; `implementer-strong` after escalation |
| `reviewer` | orchestrator | Independent review against issue, ADRs, this file and the security checklist below |
| `renovate-orchestrator` | `claude --agent renovate-orchestrator 'THEKROLL-LTD/Fathometer#<pr> [dry-run]'` | One Renovate PR end to end, merges only via `.claude/scripts/merge-dependency-pr.sh` |
| `dependency-implementer`, `dependency-reviewer` | renovate-orchestrator | Analysis, adaptation and review of a dependency update (skill `renovate-upgrade`) |
| `assistant` | `claude` (default via `.claude/settings.local.json`) or `claude --agent assistant '<task>'` | Everything outside the two workflows |

**Branches:** the orchestrator creates `ticket/<issue>-<slug>`, Renovate `renovate/*`. Work outside the workflows uses `fix/<slug>`, `docs/<slug>`, `chore/<slug>` or `ci/<slug>`. Always off `main`.

**Commits:** Conventional Commits, lowercase English subject, at most 72 characters, a scope from the project contract, footer `Refs: #<issue>`. No ticket or ADR suffix in the subject; the footer and the PR carry the reference. Within the agent workflow only the orchestrator commits.

**Pull requests:** one issue, one PR against `main`, based on `.github/pull_request_template.md` with `Closes #<issue>` as the first line. Only the project owner merges, as a squash merge. Renovate PRs are the exception, see "Dependency update pull requests".

**Independent review** means the `reviewer` role in its own session without access to the implementation reports, or the project owner.

## Security review checklist

Binding for the `reviewer` whenever a change touches auth, `/api/scans` or `/api/register`, the ingest path, rate limits, templates that render client or LLM data, the LLM reviewer, the group chat, the research worker, logging, configuration or the `Dockerfile`. Checks are static (grep, reading code, the pure-unit tests in `tests/adversarial/`), never live probes; a property that only a live run can confirm goes into the PR's manual steps.

Read first: `ARCHITECTURE.md` §8 (auth and DoS protection), §9 (input validation and sanitization), §11 (LLM integration, group chat, prompt injection); `docs/operations.md`; `docs/techdebt.md` TD-019; ADRs 0003, 0007, 0013, 0050, 0055, 0063. `ARCHITECTURE.md` ends at §14; older documents cite legacy section numbers.

- **Auth:** `/api/scans` verifies the bearer before `request.get_data()` and before decompressing. `/api/register` verifies the master key with `argon2.PasswordHasher.verify`. `/login` uses Argon2id and writes an audit event on failure. Every key or token comparison uses `hmac.compare_digest`, never `==` on a hash.
- **Rate limits:** `flask-limiter` limits exist for `/api/register`, `/login`, `/api/scans` (invalid- and valid-token tiers), the group chat and the upstream check, with the values the spec names.
- **gzip bomb:** the decompressed-size cap (`FM_MAX_DECOMPRESSED_MB`, default 100 MB) is enforced in the decompress path and returns 413, proven by the pure-unit test of the helper.
- **Input validation:** `tests/adversarial/` is green; every Pydantic model under `app/schemas/` carries `extra="ignore"`; no `text()` without bind parameters; no `|safe` on client or LLM data.
- **LLM reviewer:** Trivy data sits between `<<TRIVY_DATA_START>>` / `<<TRIVY_DATA_END>>`; LLM output passes `nh3.clean()` before rendering; API keys never reach logs and error paths map to error codes (TD-018); `llm_base_url` requires HTTPS except for localhost; the daily token cap answers 429 (ADR-0014).
- **Group chat:** the snapshot is rendered as untrusted data between the Trivy markers, with marker neutralization; chat and research output never write `risk_band` or `fix_lane`; conversations are server-scoped and no client-supplied `finding_id` drives the snapshot.
- **Research worker:** default-off and gated (`upstream_check_enabled`, `is_upstream_check_configured`); `fetch_url` enforces http/https, resolves every IP and rejects private, loopback, link-local, metadata, reserved and multicast addresses fail-closed, with `follow_redirects=False` and a timeout; the `web_search` base URL is scheme-checked; `_redact_preview` masks secrets; secrets are stored Fernet-encrypted.
- **Logging and hardening:** the structlog redaction filter turns fields containing `password`, `key`, `token` or `hash` into `***REDACTED***`; the app refuses to start without `FM_ENCRYPTION_KEY`; the container runs as non-root.

A violated point is a BLOCKER of category `bypass` or `correctness`, a missing proof a MAJOR.

## Dependency update pull requests

Renovate (`thekroll-renovate[bot]`) opens pull requests for version updates; Renovate never merges. The `renovate-orchestrator` analyses every raised version (release notes, usages, impact) and may squash-merge without the project owner when all of these hold:

- an independent review approved the current head commit
- no conflict with an ADR
- observable behavior is unchanged and every affected code path is executed by a test
- no test is added or removed; every test still ensures what it ensured before (a changed library error message may be adjusted, a checked exception type or a value fixed by an ADR may not)
- no deprecation of an API, option or configuration this project uses
- every check passed

Otherwise the update becomes a ticket. Agents in the dependency workflow never change versions, lock files or `CHANGELOG.md`; the dependency updates of a release are summarized when the release is cut.

Renovate does not propose Python runtime upgrades, the `ruff` pin or major upgrades beyond the caps in `renovate.json`. Those are tickets.

## Definition of Done

An issue is done when all acceptance criteria are proven according to their evidence type, `make lint`, `make typecheck` and `make test` are green, CI is green, `CHANGELOG.md` has its entry, the documentation budgets hold, the review has no open BLOCKER or MAJOR finding, and manual steps are fully prepared and listed in the pull request.

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
- `tests/adversarial/` is unmarked and therefore part of the default selection; the security review checklist relies on it.

## Operational gotchas

- The reverse proxy must allow large gzip bodies on `/api/scans` and should IP-allowlist it. `/chat/<id>/stream` needs buffering disabled and long read timeouts.
- The LLM risk reviewer has modes `off` / `observation` / `live`. `observation` writes `would_call` and books a token estimate without calling an LLM.
- `llm_debug_log` stores request and response bodies in bounded form for operator debugging — never emit unreviewed sensitive data into logs or templates.
- Known tech debt to read before worker or feed refactors: TD-001 (EPSS Pydantic hotspot), TD-002 (worker framework), TD-003 (DB-coupled worker healthcheck), TD-006 (k8s probes), TD-019 (DNS rebinding / TOCTOU in the research worker).

## Agent and installer

- `agent/` is deploy-relevant and is copied into the Docker image. Never add it to `.dockerignore`.
- The reference agent is Bash, push-only, and gzips to `/api/scans`. It is not a daemon and writes nothing beyond temporary files and its own config.
- Minimum versions live as ClassVars in `app/config.py` (`MIN_AGENT_VERSION`, `CURRENT_AGENT_VERSION`, Trivy versions). Do not make them env-configurable.
