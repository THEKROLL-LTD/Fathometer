# Orchestrator state

What has landed, what is open, what is waiting on the operator. One row per item. The detail lives in the ADR, the block file and `CHANGELOG.md` — see AGENTS.md, "Documentation hygiene".

## Open

| Item | State | Where |
| --- | --- | --- |
| Agent-tooling consolidation + documentation-hygiene rules | implemented 2026-08-07 | PR #25 |

## Waiting on the operator

- Tag `v0.28.1` on `main` and promote the `[Unreleased]` CHANGELOG block.
- Alembic roundtrip (`upgrade head && downgrade -1 && upgrade head`) before every release tag — agents never run it.

## Completed

| Date | Item | Decision | Release |
| --- | --- | --- | --- |
| 2026-08-10 | TICKET-022 — recommended Trivy bumped to 0.73.0 (revised from 0.72.0 draft) | — | v0.29.0 (tag pending) |
| 2026-08-06 | TICKET-021 — per-vulnerability ingest leniency (issues #22, #23) | ADR-0072 | v0.28.1 (tag pending) |
| 2026-06-15 | Exclude container-runtime data-roots from the agent host scan | ADR-0067 | v0.28.0 |
| 2026-06-14 | AL — Pass-2 filters Trivy stale-artifact false positives | ADR-0066 | v0.27.0 |
| 2026-06-14 | TICKET-016 — risk-band reason in the findings lists | ADR-0065, TD-020/021 | |
| 2026-06-13 | TICKET-017 — Pass-2 drift reconciliation sweep | ADR-0068 | |
| 2026-06-13 | AK — upstream fix as finding-level enrichment | ADR-0064 (amends 0061) | |
| 2026-06-13 | AJ — upstream verdict in the group-chat snapshot | ADR-0063 | |
| 2026-06-13 | AI-2 — agentic upstream-update search, operator UI | ADR-0063 | |
| 2026-06-13 | AI-1 — agentic upstream-update search, backend | ADR-0063 | |
| 2026-06-13 | AH — host-update flag: `upstream` → `patch` promotion | ADR-0062 | |
| 2026-06-13 | AG — fix ownership: `upstream` lane for lang-pkgs | ADR-0061 | |
| 2026-06-12 | AF — separate models for risk reviewer and per-group chat | ADR-0057 | |
| 2026-06-11 | AE — per-group AI chat | ADR-0055 | |
| 2026-06-10 | TICKET-010 — "live now" consistency | ADR-0052 | |
| 2026-06-07 | "Request AI Assessment" chat feature removed | ADR-0050 | |
| 2026-06-04 | AC — sidebar group state | ADR-0046 | |
| 2026-06-04 | AB — English UI migration | ADR-0045 | |
| 2026-06-04 | TICKET-009 — server-scoped bulk acknowledge per risk band | ADR-0044 | |
| 2026-05-29 | TICKET-008 — Pass-2 risk-band exploitability model | ADR-0043 | |
| 2026-05-28 | AA — finding detail inline | ADR-0041 | v0.16.0 |
| 2026-05-28 | Z — group + tag hybrid lifecycle | ADR-0040 | v0.15.0 |
| 2026-05-27 | Y — server-detail lazy render + triage-queue pagination | ADR-0039 | |
| 2026-05-24 | TICKET-006 — findings cross-server bucket view | ADR-0037 | |
| 2026-05-24 | TICKET-005 — heartbeat-bar template bug, OOB drift, hover overlay | — | |
| 2026-05-24 | X — server-detail content refactor + style adoption | ADR-0038 | v0.13.0 |
| 2026-05-24 | W — frontend redesign phase 1, Tailwind/DaisyUI out | ADR-0032…0036 | v0.12.0 |
| 2026-05-23 | V — performance tuning of the UI views | ADR-0030 | v0.12.0 |
| 2026-05-23 | U — parallel LLM job processing in one worker process | ADR-0029 | v0.11.0 |
| 2026-05-22 | TICKET-004 — test suite decoupled from DB/HTTP, 10 slices | — | |
| 2026-05-22 | T — application-group evaluations as a junction | ADR-0028 | v0.11.x |
| 2026-05-22 | R — asynchronous scan ingest | ADR-0026, ADR-0042 | v0.11.0 |
| 2026-05-21 | Q — server-detail and dashboard slim-down, `/findings` page | ADR-0025 | v0.10.0 |
| 2026-05-20 | Patch — worker idle-CPU optimization + CI build speedup | — | v0.9.6 |
| 2026-05-20 | Patch — worker stability after the k8s pod restart loop | — | v0.9.5 |
| 2026-05-20 | Patch — hotfix for the 400 BadRequestError from the worker | — | v0.9.4 |
| 2026-05-20 | Patch — seven Block-P adjustments (prompt, bands, debug log) | ADR-0023 | v0.9.3 |
| 2026-05-19 | P — LLM risk reviewer + application grouping + async worker | ADR-0023 | v0.9.0 |
| 2026-05-18 | O — pre-triage risk engine + host snapshot + vendor severity | ADR-0022 | v0.8.0 |
| 2026-05-18 | N — bootstrap installer + cause fields per finding | ADR-0021 | v0.7.0 |
| 2026-05-16 | M — cross-server findings + KPI sparklines | ADR-0020 | v0.6.0 |
| 2026-05-16 | L — dashboard SSE → HTMX polling (chat SSE stays) | ADR-0019 | v0.5.0 |
| 2026-05-16 | K — server-detail redesign | ADR-0018 | v0.4.0 |
| 2026-05-16 | J — dashboard pane consolidation | ADR-0017 | |
| 2026-05-15 | I-Refinement — header layout | ADR-0016 | v0.3.0 |
| 2026-05-15 | I — UI modernization | — | v0.2.0 |
| 2026-05-15 | H — polish | — | v0.1.0 (MVP) |
| 2026-05-15 | G — LLM | — | |
| 2026-05-14 | A…F — skeleton, models, ingest, dashboard, triage, bulk | — | |

## Blockers

(none)

## Update convention

- At block start: add a row under "Open" with the branch or PR.
- At block completion (after the `reviewer` approves): move the row to "Completed" with its date and release.
- A blocker goes under "Blockers" with a date and is resolved before the block counts as completed.
- Rows stay rows. Rationale and implementation detail belong in the ADR, the block file and `CHANGELOG.md` — never restated here.
