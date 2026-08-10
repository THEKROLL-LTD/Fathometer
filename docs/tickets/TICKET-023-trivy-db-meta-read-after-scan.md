# TICKET-023 — The reported Trivy DB metadata is always one scan behind the DB the scan actually used

**Status:** Open · **Date:** 2026-08-07 · **Target release:** v0.28.1
**Refs:** ADR-0021 (agent bootstrap + version model), TICKET-001 (`trivy_db` block introduced), `app/config.py` (`TRIVY_DB_STALE_THRESHOLD_DAYS`), ARCHITECTURE §10 (agent) and §5 (server denormalization).

## Components (REQUIRED)

- `agent/fathometer-agent.sh` — the `trivy version --format json` block (`:501-521`), the `rootfs` scan (`:581`), the envelope build (`:664`), `AGENT_VERSION` (`:104`)
- `app/config.py` (`CURRENT_AGENT_VERSION`)
- `tests/services/test_agent_host_state.py` (asserts `AGENT_VERSION` and the script's structure)

## Scope (REQUIRED)

**In scope:** read the Trivy DB metadata after the scan instead of before it, and bump the agent version so the change reaches the hosts.

**Out of scope:** no backend change — the envelope field, the schema, the `servers` denormalization and the stale-DB pill all stay as they are and simply receive the correct value. No DB migration, no UI work, no `MIN_AGENT_VERSION` change, no change to the scan invocation itself.

**Protected — stop and ask before touching:**

- The `rootfs` invocation (`--skip-dirs`, `--timeout`, `--scanners vuln`) — ADR-0067 / TICKET-019 territory, unrelated to this fix.
- `auto_update_trivy` — root-running binary replace, security-audited under TICKET-015.

## Problem (REQUIRED)

The agent reports a Trivy DB state that the scan did not use.

Current order in `fathometer-agent.sh`:

1. `:506` — `trivy version --format json` → `trivy_db_block` (`version`, `updated_at`, `next_update_at`, `downloaded_at`)
2. `:581` — `trivy rootfs …`, which downloads or refreshes the vulnerability DB when it is due
3. `:664` — the envelope is built with the `trivy_db_block` from step 1

So step 3 ships the DB state from *before* step 2 updated it. The backend denormalizes it into `servers.trivy_db_version` / `trivy_db_updated_at`, and `servers/detail.html:43` derives the `trivy-db stale` pill from it against `TRIVY_DB_STALE_THRESHOLD_DAYS` (7).

Observable consequence: a host whose DB was older than the threshold refreshes it during the scan, submits findings produced by the *fresh* DB, and is then displayed as `trivy-db stale`. The value is never right in the same run — it is corrected only by the next run, which reads the DB the previous run left behind. A host scanning on a daily timer therefore shows DB metadata one day old at all times; a host that scans after a long gap shows the pre-gap state on its first report back.

## Root cause (OPTIONAL — required for bugs)

Ordering only. `trivy_db_block` is computed at `:506-521` because that is where the other host facts (`trivy_version`, `os_pretty`, `kernel_version`, `arch`) are gathered for the startup log line. Nothing between `:521` and the envelope build consumes it, and the scan at `:581` is the step that mutates what it describes.

## Decisions taken (OPTIONAL)

- **D1 — read after the scan, do not add a second read.** Reading before *and* after would need a tie-break rule and doubles a call that already carries a `timeout 10` guard.
- **D2 — the CLI version read (`trivy --version`, `:499`) stays where it is.** It cannot change during the run and the startup log line uses it.
- **D3 — `trivy_db=null` stays a valid envelope value.** The existing fail-soft path (no `VulnerabilityDB` in the output → warn, send null) is unchanged; a scan must never fail over metadata.

## Solution (REQUIRED)

1. Move the `trivy version --format json` block (`:501-521`) to after the scan's empty-output check and before the envelope build. The `timeout 10` guard, the `jq` extraction, the `trivy_db_block="null"` default and the warning path move with it unchanged.
2. Keep the `Host: …` startup log line at its current position; it uses `trivy_version`, not `trivy_db_block`. Move the `Trivy-DB meta:` log line along with the block, so the log reads in execution order.
3. Bump `AGENT_VERSION` `0.10.0` → `0.11.0` in `agent/fathometer-agent.sh` and `CURRENT_AGENT_VERSION` to the same value in `app/config.py`, in one commit. `auto_update_self` gates on an exact `grep AGENT_VERSION="<server_version>"` match, so without both the fix never rolls out. `MIN_AGENT_VERSION` stays `0.1.0` — an un-updated agent reports stale metadata, which is the status quo, not a breakage.
4. Unhappy paths, all pre-existing and unchanged: scan fails → `exit 2` before the read, nothing is sent; `trivy version` fails or has no `VulnerabilityDB` → `trivy_db=null`; `timeout` binary absent → uncapped call, same as today.

## Definition of Done (REQUIRED — machine-checkable)

- [ ] In `agent/fathometer-agent.sh`, the `trivy version --format json` call appears **after** the `trivy rootfs` call. (Pure-unit: assert on `body.index(...)` of both markers in the script text.)
- [ ] The `timeout 10` guard, the `trivy_db_block="null"` default and the "no VulnerabilityDB data" warning are still present after the move.
- [ ] `agent/fathometer-agent.sh` carries `AGENT_VERSION="0.11.0"` and `app/config.py` `CURRENT_AGENT_VERSION == "0.11.0"`; `MIN_AGENT_VERSION` unchanged at `0.1.0`.
- [ ] `shellcheck agent/*.sh` green.
- [ ] `tests/services/test_agent_host_state.py::test_agent_script_has_host_state_integration` updated to `0.11.0` and green.
- [ ] `CHANGELOG.md` entry under `[Unreleased]`, ≤ 25 lines.
- [ ] `ruff check . && ruff format --check .` green
- [ ] `mypy app/` green
- [ ] `pytest` (default selection) green

## Tests (REQUIRED)

Extend `tests/services/test_agent_host_state.py` — no new file. It already asserts on the agent script's text (`test_agent_script_has_host_state_integration`, `test_agent_script_skips_container_runtime_data_roots`), which is the right sibling:

- New: the index of `version --format json` in the script body is greater than the index of `rootfs "$SCAN_PATH"` — the ordering regression guard.
- New: the moved block still contains `timeout 10`, `trivy_db_block="null"` and the warning string.
- Updated: the `AGENT_VERSION="0.10.0"` assertion flips to `0.11.0`. This is the only existing expectation this ticket may change.

Not run, operator-only: `tests/agent/test_trivy_db_meta_extraction.sh` covers the extraction itself. The extraction is unchanged by this ticket, so it needs no edit — flag it in the PR as worth one manual run.

## Rollout (OPTIONAL)

Agent-side only. Hosts pick the new script up through `auto_update_self` on their next run and report correct DB metadata from that run on. Existing `servers.trivy_db_*` rows are overwritten by the next scan — no backfill. Air-gapped hosts that pin the agent keep the old behaviour, which is the current behaviour. SemVer PATCH.

## Risk / Non-goals (OPTIONAL)

- **A stale-DB pill may disappear on hosts that were only ever "stale" because of this bug.** That is the point of the fix, but it changes what operators see without anything on the host changing. Name it in the CHANGELOG.
- **Not in scope:** verifying that the DB Trivy used for *this* report is the one it reports. Trivy offers no per-report DB stamp; reading right after the scan is the closest available approximation and is what this ticket buys.
- **Not in scope:** the reverse case of a scan run with `--skip-db-update` or an offline DB. The agent does not pass that flag today.

## Test convention (subagent obligation, verbatim)

Allowed quality gates: ruff, mypy, shellcheck (linters), pytest default selection. Forbidden: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/browser tests — no proactive runs, no new `.bats`/`.sh` test files. Every `pytest` bash call carries an explicit `timeout` ≤ 120000 ms (default suite) / ≤ 60000 ms (focused sub-run). Note the default selection is not strictly pure-unit: `todo_mock` tests stay in and touch a real Postgres when one is up; `pytest -m "not todo_mock"` is the pure subset.
