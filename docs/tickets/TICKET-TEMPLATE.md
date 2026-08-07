# TICKET-NNN — <symptom or outcome, one line, no solution in the title>

<!--
HOW TO USE THIS FILE

Copy to docs/tickets/TICKET-NNN-<kebab-slug>.md. Delete this comment, every
OPTIONAL section you do not need, and the inline hints as you fill them in.

Two rules:

  1. Every Definition-of-Done line must be checkable by running something.
     Concrete values, not adjectives: not "handles large reports" but "a report
     with 12000 vulnerabilities is capped, not rejected".

  2. Do not restate AGENTS.md. It is already in the agent's context; this file
     carries only what is specific to this change. The one exception is the
     verbatim test-convention block at the bottom, which subagents receive
     without AGENTS.md.
-->

**Status:** Open · **Date:** YYYY-MM-DD · **Target release:** vX.Y.Z
**Refs:** <ADRs, prior tickets that set precedent, ARCHITECTURE sections, GitHub issue, upstream docs>

## Components (REQUIRED)

<!--
Concrete paths with symbol anchors: app/services/foo.py (`_bar`, `Baz.qux`).
Only the files you already know are involved — the agent finds the rest.
Include the ADR and the ARCHITECTURE section if either has to change.
-->

## Scope (REQUIRED)

**In scope:**

**Out of scope:**

<!--
What this change explicitly does not touch: no DB migration, no agent change,
no UI work, no LLM contract change.
-->

**Protected — stop and ask before touching:**

<!--
Delete what does not apply. A wrong change here is expensive or silent:
  - auth / session handling, master key, server keys (app/auth/, app/security/)
  - Fernet encryption of LLM API keys
  - alembic/versions/ — any schema migration
  - rate limits (flask-limiter config)
  - the risk-band / fix-lane decision logic
  - the scan envelope schema's DoS caps
If the ticket requires one of these, say so here so the reviewer knows it was
intended rather than incidental.
-->

## Problem (REQUIRED)

<!--
Observed behaviour with evidence: log lines, error text, a reproduction, the
issue report. Not a solution. For a feature, give current and desired behaviour
as two paragraphs.
-->

## Root cause (OPTIONAL — required for bugs)

<!--
Which code produces the behaviour, with file:line. Number the defects if
several compound. If ARCHITECTURE already prescribes the correct behaviour this
is a bug fix and needs no spec change; if it does not, an ADR comes first.
-->

## Decisions taken (OPTIONAL)

<!--
Choices already made by the operator that the agent must not re-litigate, as
D1/D2/D3 with a one-line reason each. Anything not listed is the implementer's
call.
-->

## Solution (REQUIRED)

<!--
The intended shape of the change, numbered. Behaviour and constraints, not
line-by-line code.

Name the unhappy paths: empty input, duplicates, over-long input, concurrent
access, missing permission, upstream unavailable.

If the change lets data be silently dropped or skipped, its observability
belongs in this section, not in a follow-up ticket.
-->

## Definition of Done (REQUIRED — machine-checkable)

<!--
One line per verifiable claim, naming what is asserted and where. The last four
lines are the standing gates and stay on every ticket.
-->

- [ ] <behaviour assertion with concrete input and expected result> (`path/to/file.py` + pure-unit test)
- [ ] <edge case assertion>
- [ ] <regression assertion: the thing that must NOT have changed>
- [ ] ADR-NNNN added / ARCHITECTURE §N updated / TD-NNN recorded — *delete what does not apply*
- [ ] `CHANGELOG.md` entry under `[Unreleased]`, ≤ 25 lines
- [ ] `ruff check . && ruff format --check .` green
- [ ] `mypy app/` green
- [ ] `pytest` (default selection) green

## Tests (REQUIRED)

<!--
Name the file and model it on an existing sibling if one fits
(tests/schemas/test_host_state_leniency.py for leniency). List the cases, not
the code: happy path, empty state, error state, and the regression case.

Name any existing test whose expectations this change may legitimately flip, so
nobody edits a green assertion to make a red one pass.
-->

New `tests/<area>/test_<thing>.py`:

- <case>
- <case>
- Re-check `tests/<area>/test_<existing>.py` — no existing expectation may silently flip.

## Rollout (OPTIONAL)

<!--
Server-side only, or does the agent change too? Does a broken state recover on
its own, or is a backfill needed? SemVer: operator-visible feature → MINOR,
pure bugfix → PATCH.
-->

## Risk / Non-goals (OPTIONAL)

<!--
What this fix could make worse, and what a reader might expect it to cover but
which is deliberately left out. Silent data loss, performance regressions and
follow-on tickets belong here.
-->

## Test convention (subagent obligation, verbatim)

Allowed quality gates: ruff, mypy, shellcheck (linters), pytest default selection. Forbidden: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/browser tests — no proactive runs, no new `.bats`/`.sh` test files. Every `pytest` bash call carries an explicit `timeout` ≤ 120000 ms (default suite) / ≤ 60000 ms (focused sub-run). Note the default selection is not strictly pure-unit: `todo_mock` tests stay in and touch a real Postgres when one is up; `pytest -m "not todo_mock"` is the pure subset.
