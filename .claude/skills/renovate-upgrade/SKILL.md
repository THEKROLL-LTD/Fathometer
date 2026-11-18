---
name: renovate-upgrade
description: Project rules for analysing, fixing and reviewing Renovate dependency update pull requests in fathometer. Preloaded into dependency-implementer and dependency-reviewer; not for ticket work.
---

# Renovate upgrade contract

SKILL: renovate-upgrade/1

Every report under this skill contains the line `SKILL: renovate-upgrade/1` and all
fields of its format. A report without them is rejected.

## 1. Shared facts

### Where versions live
- Python: `pyproject.toml` (`[project] dependencies`, `[project.optional-dependencies] dev`,
  `[build-system] requires`), full graph in `uv.lock`
- Images: `Dockerfile` (every `FROM`, including the `uv` stage), `docker-compose.yml` (postgres)
- Frontend: `frontend/package.json`, full graph in `frontend/package-lock.json`
- Actions: `.github/workflows/*.yml`, tag pin (`@vX` or `@vX.Y.Z`)
- Trivy scanner: the `version:` input of `aquasecurity/trivy-action` in
  `.github/workflows/trivy.yml` (custom regex manager in `renovate.json`)
- Coupled: the uv version CI installs is read from the `uv` stage of the `Dockerfile`
These files belong to Renovate. You never change them.

Never part of a Renovate update: `requires-python`, the Python version in `Makefile`
and `Dockerfile`, the exact `ruff==` pin, the agent and Trivy version constants in
`app/config.py`. A Renovate PR that touches one of them is `NEEDS_TICKET`.

### Determine changes from the diff
- `git diff <base>...<renovate-head> --stat`
- `git diff <base>...<renovate-head> -- pyproject.toml Dockerfile docker-compose.yml .github/workflows frontend/package.json`
- `git diff <base>...<renovate-head> -- uv.lock | grep -E '^[-+](name|version) = '`
- `git diff <base>...<renovate-head> -- frontend/package-lock.json | grep -E '^[-+]\s+"(version|resolved)"'`

### Classes
- A: Python runtime, direct or transitive
- B: Python dev tool (`[project.optional-dependencies] dev`)
- C: container image
- D: GitHub Action or the Trivy scanner version used in CI
- E: frontend package (`alpinejs` and `htmx.org` ship to the browser; `esbuild` and
  `lightningcss` are build tools)
- F: lock file maintenance; treat every changed `uv.lock` entry as A and every changed
  `frontend/package-lock.json` entry as E

### Analysis duty per class
- A, B, E: release notes of every version between old and new.
- C with tag change: release notes of the new tag. C with digest change only:
  confirm the tag is unchanged, report `digest-only`; evidence is the image build and
  scan in CI (`trivy.yml`, job `image`).
- D: release notes of every version; inputs and outputs our workflows use still
  exist and behave the same.

### Sources
1. PR body: `gh pr view <nr> --json body -q .body`
2. `gh release view <tag> --repo <owner/repo>`
3. Repository URL from `.venv/lib/python3.14/site-packages/<dist>-<version>.dist-info/METADATA`
   (`Project-URL`, `Home-page`) or from `frontend/node_modules/<name>/package.json`
   (`repository`), then 2.
4. Installed source of the new version: final authority for signatures, defaults,
   removed symbols. Frontend packages are installed with
   `npm --prefix frontend ci --ignore-scripts`.
No other network access. No `pip`, `uv add`, `uv lock`, `npm install`.

Transitive package without any source: allowed only if the direct dependency that
pulls it in (`uv tree --invert --package <name>`, `npm --prefix frontend ls <name>`)
states no functional change for this update. Report
`no source, parent <direct> states no functional change`. If the parent states
functional changes, analyse the transitive package like A or E.

### ADRs by area (`docs/decisions/`, plus `ARCHITECTURE.md`)
- web stack, server, SSE (flask, werkzeug, jinja2, gunicorn): 0015, 0019
- auth, CSRF, hashing (flask-login, flask-wtf, wtforms, argon2-cffi): 0004
- scan ingest, wire format, Trivy schema (pydantic, flask): 0003, 0005, 0007, 0021, 0026, 0072
- database, migrations (sqlalchemy, psycopg, alembic): 0026, 0028
- encryption (cryptography): 0013
- LLM reviewer and chat (openai, genai-prices): 0002, 0014, 0023, 0029, 0056, 0057
- upstream research worker (pydantic-ai-slim, trafilatura, httpx): 0063
- EPSS/KEV feed pull (httpx): 0024
- sanitization (nh3): `ARCHITECTURE.md` §9
- frontend (alpinejs, htmx.org, esbuild, lightningcss): 0019, 0032, 0036
- container, base images, CI (classes C, D): 0069, 0048

### App functions for IMPACT
scan ingest, agent installer, auth, dashboard ui, findings ui, server detail ui,
settings, risk engine, llm risk reviewer, group chat, upstream research, feed pull,
encryption, database and migrations, logging, rate limiting, frontend build,
dev tooling, container, ci

### Impact and coverage
For every changed package of class A and B:
1. List every usage in `app`, `alembic` and `scripts` (`git grep -n -E '<names>'`).
2. Map each usage affected by a relevant change to the app functions above.
3. Prove that a test executes each affected line:
   `COVERAGE_FILE=/tmp/claude-tickets/.coverage uv run pytest -q --cov=app --cov-context=test --cov-report=`
   `COVERAGE_FILE=/tmp/claude-tickets/.coverage uv run coverage json --show-contexts -o /tmp/claude-tickets/cov.json`
   Name the test per line.
An affected line no test executes: `NEW TESTS REQUIRED: yes`.

For every changed package of class E:
1. List every usage in `app/templates`, `app/static` (sources, not `app/static/dist`)
   and `frontend/src` (`git grep -n -E '<attributes or APIs>'`).
2. `npm --prefix frontend ci --ignore-scripts` and `npm --prefix frontend run build`
   exit 0.
3. A relevant behavior change of `htmx.org` or `alpinejs` in an attribute, event or
   default we use: `NEW TESTS REQUIRED: yes` (no browser tests exist, see `AGENTS.md`).

### Breakage
- removed or renamed symbol, changed signature or default we rely on
- documented behavior change in an area we use, also with green tests
- class B: new lint or type findings in unchanged code
- class E: changed attribute, event, swap or default semantics in HTMX or Alpine

Security boundaries:
- `/api/scans`: bearer verification before body parse, decompressed-size cap (flask, werkzeug)
- constant-time compares and password hashing (argon2-cffi)
- Fernet encryption of stored API keys (cryptography)
- sanitization of client and LLM data, Jinja autoescape (nh3, jinja2)
- rate limits and CSRF (flask-limiter, flask-wtf)
- outgoing requests: research-worker SSRF allowlist, redirects, timeouts, LLM base URL
  (httpx, pydantic-ai-slim, trafilatura, openai)
- log redaction (structlog)
- configuration loading (pydantic-settings)

### Deprecations
A deprecation of an API, option or configuration this project uses (in `app`,
`alembic`, `scripts`, `tests`, `frontend/src`, templates or configuration) rules out an
automatic update. Warnings from library internals without relation to our code:
report only. `pytest.ini` already turns warnings into errors, with a few ignores.
Check: release notes, and once
`uv run pytest --no-cov -q -W error::DeprecationWarning -W error::PendingDeprecationWarning`
(this also surfaces the warnings `pytest.ini` ignores).

### Conditions for an automatic update
1. No ADR conflict.
2. Observable behavior unchanged.
3. No test needs to be added or becomes obsolete.
4. Every affected line is executed by a test.
5. No deprecation of something we use.
Violated: the update needs a ticket. Do not work around it.

### Test invariant rule
What a test ensures stays the same.
- `mechanics`: imports, library calls in test code, fakes, mocks, fixtures
- `library-detail`: expected value that only the library defines and no ADR fixes
  (error message, `match=` pattern, `repr`); same exception type, same field, same
  outcome
- `behavior`: anything else: changed or broader exception type, ADR-fixed value,
  fewer or weaker checks, removed test or parametrization case
Only `mechanics` and `library-detail` are allowed.

## 2. Fix procedure (dependency-implementer)

1. `make install`; failure: `BLOCKED`.
2. Analyse every changed package per "Analysis duty".
3. Impact and coverage per section 1.
4. ADRs for the touched areas; deprecations.
5. Any condition for an automatic update violated: `BLOCKED`, fill `ADR CHECK`,
   `NEW TESTS NEEDED`, `DEPRECATIONS`.
6. `make lint`, `make typecheck`, `make test-fast`.
7. Adapt code so observable behavior stays the same; impossible: `BLOCKED`.
8. Adapt tests only per test invariant rule.
9. `make lint`, `make typecheck`, `make test`.

Forbidden: version and lock files, files under "Where versions live", `Makefile`,
`renovate.json`, `pyproject.toml` tool sections, `pytest.ini`, `mypy.ini`, `ruff.toml`,
`tests/conftest.py`, `CHANGELOG.md`, adding, deleting or renaming tests or test files,
`skip`, `xfail`, `no cover`, suppressions, unrelated changes. Needed anyway: `BLOCKED`
with the exact change.

### Report
    SKILL: renovate-upgrade/1
    STATUS: NO_CHANGE | DONE | BLOCKED
    SUMMARY: <2 to 4 sentences>
    COMMIT SUGGESTION: fix(deps): <lowercase english subject>
    PACKAGES:
    - <name> <old> -> <new> [A-F] [direct|transitive|digest-only]: <relevant changes or "none relevant">
    CHANGELOG SOURCES:
    - <name>: <source> | no source, parent <direct> states no functional change
    USAGE SEARCH:
    - <git grep command> -> <hits>, <files>
    IMPACT:
    - <name>: <app functions> | <what changes> | covered by <test per affected line> | not covered: <lines>
    ADR CHECK:
    - ADR <nr>: ok | conflict, <what>
    DEPRECATIONS:
    - <api or option we use>: <announced change> (or "none")
    NEW TESTS NEEDED: no | yes, <function or line>
    CHANGED FILES:
    - <path>: <what and why> (or "none")
    TEST CHANGES:
    - <file:function>: mechanics | library-detail, <change>, invariant: <what it still ensures> (or "none")
    COMMANDS AND OUTPUT:
    - <command> -> <exit code>, <relevant lines>
    BLOCKED BECAUSE (only BLOCKED):
    - <reason, exact change or ticket needed>

## 3. Review procedure (dependency-reviewer)

Judge from diff, release notes, installed source, ADRs and command output only.

1. Changed packages from the diff.
2. Release notes yourself, per "Analysis duty".
3. Own `git grep`; old-form usages left?
4. Impact and coverage yourself.
5. Agent changes `git diff <renovate-head>..HEAD`: each one required by a package
   change, else finding `scope`.
6. Classify every test change; `library-detail`: name ADRs checked and the unchanged
   invariant; `behavior`: BLOCKER `tests`.
7. `make lint`, `make typecheck`, `make test`.
8. Pins: the `ruff==` pin is unchanged; class D:
   `git ls-remote --tags https://github.com/<owner>/<repo> '<tag>*'`.
9. Class C: ADR 0069 and the container rules in `AGENTS.md`. Class E:
   `npm --prefix frontend ci --ignore-scripts` and `npm --prefix frontend run build`.
10. Security boundaries for classes A and E.
11. ADRs, deprecations, conditions for an automatic update. Violated: BLOCKER `spec`.

APPROVE only without BLOCKER and MAJOR, all ADR checks ok, `NEW TESTS REQUIRED: no`,
`DEPRECATIONS: none`, all steps done. Otherwise `CHANGES_REQUESTED`; unfinished:
`INCOMPLETE`.

### Report
    SKILL: renovate-upgrade/1
    VERDICT: APPROVE | CHANGES_REQUESTED | INCOMPLETE
    SUMMARY: <2 to 4 sentences>
    PACKAGES:
    - <name> <old> -> <new> [A-F] [direct|transitive|digest-only]: <relevant changes or "none relevant">
    CHANGELOG SOURCES:
    - <name>: <source> | no source, parent <direct> states no functional change
    USAGE SEARCH:
    - <git grep command> -> <hits>, old-form usages left: none | <list>
    IMPACT:
    - <name>: <app functions> | <what changes> | covered by <test per affected line> | not covered: <lines>
    TEST CHANGES:
    - <file:function>: mechanics | library-detail | behavior, <why>, invariant: unchanged | changed, ADRs checked: <nrs> (or "none")
    ADR CHECK:
    - ADR <nr>: ok | conflict, <what>
    DEPRECATIONS:
    - <api or option we use>: <announced change> (or "none")
    NEW TESTS REQUIRED: no | yes, <function or line>
    SECURITY BOUNDARIES:
    - <boundary>: not affected | checked, <how> | finding <ID>
    PIN CHECKS:
    - ruff pin: ok | finding <ID>
    - action tags: ok | n/a | finding <ID>
    TEST RUN: make lint / make typecheck / make test -> <exit codes>, coverage <value>
    FINDINGS:
    - F1 [BLOCKER|MAJOR|MINOR] [correctness|bypass|spec|tests|rules|scope] <file:line> | <problem> | <change>
      or "none"
    PREVIOUS FINDINGS:
    - <ID>: fixed | not fixed (<reason>) or "none"
    OPEN CHECKS (only INCOMPLETE):
    - <step>
