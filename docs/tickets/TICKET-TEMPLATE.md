# TICKET-NNN — <symptom or outcome, one line, no solution in the title>

<!--
HOW TO USE THIS FILE

Copy to docs/tickets/TICKET-NNN-<kebab-slug>.md and fill in. Delete this comment
and every section marked OPTIONAL that you do not need. Delete the inline hints
too — a ticket that still contains hint text has not been written yet.

The five sections below marked REQUIRED are the ones an implementer agent reads
to decide what to do. Everything else exists to stop a reviewer from having to
reconstruct your reasoning.

Two rules that decide whether this ticket works:

  1. Every Definition-of-Done line must be checkable by running something.
     If you cannot name the command or the assertion, it is not done criteria,
     it is a wish. Replace adjectives with numbers: not "handles large reports"
     but "a report with 12000 vulnerabilities is capped, not rejected".

  2. Do not restate CLAUDE.md. Conventions that always apply live there and are
     already in the agent's context. This file carries only what is specific to
     this change. The one deliberate exception is the verbatim test-convention
     block at the bottom, which subagents receive without CLAUDE.md.
-->

**Status:** Open · **Date:** YYYY-MM-DD · **Target release:** vX.Y.Z
**Refs:** <ADRs, prior tickets that set precedent, ARCHITECTURE sections, GitHub issue, upstream docs>

## Components (REQUIRED)

<!--
Concrete paths, ideally with symbol or line anchors: app/services/foo.py
(`_bar`, `Baz.qux`). Name the files you already know are involved — the agent
can find the rest by itself, so an exhaustive list is wasted context. Include
the ADR and the ARCHITECTURE section if either has to change.
-->

## Scope (REQUIRED)

**In scope:**

**Out of scope:**

<!--
Say what this change explicitly does NOT touch: no DB migration, no agent
change, no UI work, no LLM contract change. This is the single highest-value
line in the ticket — it is what keeps the diff reviewable.
-->

**Protected — stop and ask before touching:**

<!--
Delete the lines that do not apply. These are the paths where a wrong change is
expensive or silent:
  - auth / session handling, master key, server keys (app/auth/, app/security/)
  - Fernet encryption of LLM API keys
  - alembic/versions/ — any schema migration
  - rate limits (flask-limiter config)
  - the risk-band / fix-lane decision logic
  - the scan envelope schema's DoS caps
If the ticket genuinely requires one of these, say so here explicitly so the
reviewer knows it was intended rather than incidental.
-->

## Problem (REQUIRED)

<!--
Observed behaviour, with evidence: log lines, error text, a reproduction, the
issue report. Not a solution. If this is a feature rather than a bug, describe
the current behaviour and the desired behaviour as two separate paragraphs.
-->

## Root cause (OPTIONAL — required for bugs)

<!--
Which code produces the observed behaviour, with file:line. If several defects
compound, number them; the DoD usually needs one line per defect. Note whether
ARCHITECTURE already prescribes the correct behaviour — if it does, this is a
bug fix and needs no spec change. If it does not, an ADR is required before
code is written.
-->

## Decisions taken (OPTIONAL)

<!--
Choices already made by the operator that the agent must not re-litigate,
as D1/D2/D3 with a one-line reason each. Anything not listed here is the
implementer's call.
-->

## Solution (REQUIRED)

<!--
The intended shape of the change, numbered. Describe behaviour and constraints,
not line-by-line code — over-specifying the implementation produces worse
results than naming the outcome and the boundary conditions.

Include the unhappy paths explicitly: empty input, duplicates, over-long input,
concurrent access, missing permission, upstream unavailable. What is not
written here gets invented.

If the change adds a way for data to be silently dropped or skipped, the
observability for it belongs in this section, not in a follow-up ticket.
-->

## Definition of Done (REQUIRED — machine-checkable)

<!--
One line per verifiable claim. Each must name what is asserted, and where.
Concrete values, not adjectives. The last three lines are the standing gates
and stay on every ticket.
-->

- [ ] <behaviour assertion with concrete input and expected result> (`path/to/file.py` + pure-unit test)
- [ ] <edge case assertion>
- [ ] <regression assertion: the thing that must NOT have changed>
- [ ] ADR-NNNN added / ARCHITECTURE §N updated / TD-NNN recorded — *delete what does not apply*
- [ ] `CHANGELOG.md` entry under `[Unreleased]`
- [ ] `ruff check . && ruff format --check .` green
- [ ] `mypy app/` green
- [ ] `pytest` (default selection) green

## Tests (REQUIRED)

<!--
Name the file, and model it on an existing sibling if one fits
(tests/schemas/test_host_state_leniency.py is a good leniency example).
List the cases, not the code. Cover at minimum: happy path, empty state,
error state, and the regression case that would catch a future implementer
breaking this again.

Also name any existing test whose expectations this change might legitimately
flip — so nobody silently edits a green assertion to make a red one pass.
-->

New `tests/<area>/test_<thing>.py`:

- <case>
- <case>
- Re-check `tests/<area>/test_<existing>.py` — no existing expectation may silently flip.

## Rollout (OPTIONAL)

<!--
Server-side only, or does the agent change too? Does an existing broken state
recover on its own, or is a backfill needed? SemVer: operator-visible feature
→ MINOR, pure bugfix → PATCH.
-->

## Risk / Non-goals (OPTIONAL)

<!--
What this fix could make worse, and what a reader might reasonably expect it to
cover but which is deliberately left out. Silent data loss, performance
regressions and follow-on tickets belong here.
-->

## Test convention (subagent obligation, verbatim)

Allowed quality gates: ruff, mypy, shellcheck (linters), pytest default selection. Forbidden: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/browser tests — no proactive runs, no new `.bats`/`.sh` test files. Every `pytest` bash call carries an explicit `timeout` ≤ 120000 ms (default suite) / ≤ 60000 ms (focused sub-run). Note the default selection is not strictly pure-unit: `todo_mock` tests stay in and touch a real Postgres when one is up; `pytest -m "not todo_mock"` is the pure subset.

<!--
NOT A TICKET FOR AN AGENT — hand these to a human instead:

  - broad cross-cutting refactors that need repo-wide judgement
  - anything where the correct behaviour is still undecided
  - auth, key handling or crypto changes beyond a mechanical edit
  - work where you want to understand the code yourself afterwards

An ambiguous ticket does not produce a clarifying question. It produces a
confident wrong answer, reviewed by nobody.
-->
