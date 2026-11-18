---
name: Ticket
about: Implementable ticket for a person or the agent orchestrator
title: "<type>(<scope>): <short title>"
labels: []
---

<!--
A ticket is a unit that can be implemented in one pass: one pull request.
If it does not fit into one pull request, split it.
-->

## Goal

<What exists or works after this ticket, in 1 to 3 sentences.>

## Context

<Binding documents with path and section, e.g. ARCHITECTURE.md §9, docs/decisions/0072-per-vuln-ingest-leniency.md, and prerequisite issues, e.g. #3.>

## Requirements

- <concrete, verifiable requirements: names, values, interfaces, file paths>
- <describe behavior, data and limits. No signatures or internal structures; the architect designs them. Exception: external contracts others already use, e.g. an existing API format.>

## Reproduction

<Only for type fix: steps to reproduce, expected behavior, actual behavior (error message, wrong value). Otherwise "none".>

## Known Edge Cases

<Optional. Boundary cases the solution must handle explicitly, as far as they are known: empty or absent values, values as they appear in example files, unusual but valid inputs, structure announced for later in the ADRs. One bullet per case with the expected behavior. Write "none" if none are known.>

- <case>: <expected behavior>

## Out of Scope

- <what is explicitly not built>

## Acceptance Criteria

<!--
Every criterion has exactly one evidence type:
[test]    behavior, proven by an automated test
[command] locally executable command with an expected result
[ci]      only verifiable in CI, e.g. container build or scan
[review]  confirmed by the reviewer, e.g. documentation, structure
[manual]  needs a person; the agent only delivers the preparation
Lint, typecheck, tests, coverage and the CHANGELOG entry from AGENTS.md always apply and are not listed here.
-->

- [ ] [test] <criterion>
- [ ] [review] <criterion>

## Manual Steps

<Only if there are [manual] criteria: what the person does after the merge and what the agent must prepare for it. Otherwise "none".>
