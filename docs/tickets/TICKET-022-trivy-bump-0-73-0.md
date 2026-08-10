# TICKET-022 — Monitored hosts run Trivy 0.71.0 while 0.73.0 carries new detections

**Status:** Open · **Date:** 2026-08-07 (revised 2026-08-10) · **Target release:** v0.29.0
**Refs:** TICKET-015 (introduced `auto_update_trivy`, the mechanism this ticket only re-points), ADR-0021 (agent bootstrap + version model), [Trivy v0.72.0 highlights](https://github.com/aquasecurity/trivy/discussions/10907), [Trivy v0.73.0 highlights](https://github.com/aquasecurity/trivy/discussions/11033), `docs/operations.md` (air-gap / outbound URLs).

## Components (REQUIRED)

- `app/config.py` (`Settings.RECOMMENDED_TRIVY_VERSION`, `MIN_TRIVY_VERSION`, `TRIVY_RELEASE_URL_TEMPLATE`)
- `docs/blocks/N-agent-installer.md` (quotes the constant value verbatim)
- `tests/config/test_agent_constants.py` (`test_ticket015_version_bump_values`)
- `tests/integration/test_agent_install_smoke_db.py` (asserts the value in the `/agent/version` payload)
- `tests/integration/test_agent_install_db.py`, `tests/integration/test_agent_install_render_db.py` (both assert `RECOMMENDED_TRIVY_VERSION="…"` in the rendered `/install.sh` body — found via the DoD grep, not in the original ticket draft)
- `CHANGELOG.md`

## Scope (REQUIRED)

**In scope:** raise `RECOMMENDED_TRIVY_VERSION` from `0.71.0` to `0.73.0` and pull the value through the places that assert or quote it.

**Out of scope:** no change to `agent/fathometer-agent.sh` or `agent/lib_host_state.sh`, no `AGENT_VERSION` / `CURRENT_AGENT_VERSION` bump, no `MIN_TRIVY_VERSION` bump, no installer-template change, no DB migration, no schema change, no UI work.

The agent reads `recommended_trivy_version` from `GET /agent/version` at runtime (`fathometer-agent.sh:303`), so the bump reaches every host on its next run without shipping a new agent script. This is what keeps the ticket to a constant plus its assertions.

**Protected — stop and ask before touching:**

- `auto_update_trivy` in `agent/fathometer-agent.sh` — root-running binary replace, security-audited under TICKET-015. This ticket re-points it at a new version; it must not change its logic, its checksum enforcement or its managed-path guard.

## Problem (REQUIRED)

`RECOMMENDED_TRIVY_VERSION` has stood at `0.71.0` since 2026-06-11. Upstream has since published v0.71.1, v0.71.2, v0.72.0 (2026-06-30) and v0.73.0 (2026-08-03). Every monitored host with a fathometer-managed Trivy therefore scans with a binary four upstream releases behind, missing the detection and data-source work in those releases (among them Bottlerocket OS detection, .NET self-contained runtime detection, JAR license detection, and — new in 0.73.0 — Java Maven-mirror config support and VEX documents discovered as OCI artifacts).

Because `auto_update_trivy` targets *recommended*, not *latest*, the fleet does not drift forward on its own — it sits exactly where this constant puts it.

**Revised target: 0.73.0, not 0.72.0.** The original draft (2026-08-07) deliberately excluded 0.73.0 — it had shipped 2026-08-03, four days earlier, and was judged to have too little field exposure for an automatic fleet-wide binary replace. As of 2026-08-10, 0.73.0 has seven days of exposure and its upstream changelog carries no `⚠ BREAKING CHANGES` section (unlike 0.72.0's `dockers_v2` config migration, which never affected us — see Risk below). Operator decision: skip 0.72.0 as an intermediate step and take 0.73.0 directly; a separate 0.72.0 ticket would add nothing since 0.73.0 is a superset.

## Root cause (OPTIONAL — required for bugs)

Not a defect. The constant is the intended control point and is bumped by hand (`docs/blocks/N-agent-installer.md:53`: "Wird beim Bump im selben Commit aktualisiert").

## Decisions taken (OPTIONAL)

- **D1 — target 0.73.0.** Revised 2026-08-10 from the original 0.72.0 draft once 0.73.0 crossed the same field-exposure threshold (freshness, not content, was always the gate — see Problem).
- **D2 — `MIN_TRIVY_VERSION` stays `0.70.0`.** Same reasoning as TICKET-015: neither v0.72.0 nor v0.73.0 changes any part of the JSON report we consume, so raising MIN would mark 0.70.0/0.71.0 hosts hard-outdated for no compatibility reason. The auto-update lifts them anyway.
- **D3 — no agent version bump.** The agent script is unchanged, and `CURRENT_AGENT_VERSION` gates the self-update by exact string match; bumping it without a script change would push a pointless re-download to every host.

## Solution (REQUIRED)

1. **`app/config.py`:** `RECOMMENDED_TRIVY_VERSION = "0.73.0"`. `MIN_TRIVY_VERSION` and `TRIVY_RELEASE_URL_TEMPLATE` unchanged — verified against the real release (`gh api repos/aquasecurity/trivy/releases/tags/v0.73.0`), the assets are still named `trivy_0.73.0_Linux-64bit.tar.gz`, `trivy_0.73.0_Linux-ARM64.tar.gz` and `trivy_0.73.0_checksums.txt`, so the template resolves and the SHA256 step keeps working.
2. **Pull the value through** `docs/blocks/N-agent-installer.md` and the tests that assert it, including the two `/install.sh`-render tests found via the DoD grep (`test_agent_install_db.py`, `test_agent_install_render_db.py`). Historical documents (TICKET-015, ADR-0072, older CHANGELOG entries) keep their values — they are records.
3. **Unhappy paths, all pre-existing and unchanged by this ticket** — name them in the PR so the reviewer does not have to re-derive them:
   - Host on a system-package Trivy (`/usr/bin/trivy` from apt/rpm): `auto_update_trivy` refuses to touch it and logs; the host keeps showing the `trivy outdated` pill. Expected.
   - Air-gapped host (`FM_TRIVY_AUTO_UPDATE=0` or no outbound): update skipped, scan proceeds on the installed version.
   - Download, checksum or replace failure: fail-soft, rollback from `.bak`, scan proceeds on the old binary.
   - Host already on 0.73.0 or newer: `version_lt` is false, no download.

## Definition of Done (REQUIRED — machine-checkable)

- [ ] `app/config.py`: `RECOMMENDED_TRIVY_VERSION == "0.73.0"`; `MIN_TRIVY_VERSION == "0.70.0"` unchanged; `TRIVY_RELEASE_URL_TEMPLATE` unchanged.
- [ ] `agent/` is byte-identical to `main` — `git diff --stat main -- agent/` is empty, and `AGENT_VERSION` / `CURRENT_AGENT_VERSION` stay `0.10.0`.
- [ ] `TRIVY_RELEASE_URL_TEMPLATE.format(version="0.73.0", arch="64bit")` yields `https://github.com/aquasecurity/trivy/releases/download/v0.73.0/trivy_0.73.0_Linux-64bit.tar.gz` (pure-unit assertion on the string; no network call).
- [ ] `tests/config/test_agent_constants.py` asserts `0.73.0` and still asserts `MIN <= RECOMMENDED`.
- [ ] `tests/integration/test_agent_install_smoke_db.py:31`, `test_agent_install_db.py:149`, `test_agent_install_render_db.py:50` updated to `0.73.0` — edited, **not** run (all three carry the `acceptance` + `db_integration` markers, operator-only).
- [ ] `docs/blocks/N-agent-installer.md` quotes `0.73.0`.
- [ ] `grep -rn "0\.71\.0" app/ tests/ docs/blocks/` returns no hit that claims to be the current recommended version.
- [ ] `CHANGELOG.md` entry under `[Unreleased]`, ≤ 25 lines, naming the version and that no agent update is needed.
- [ ] `ruff check . && ruff format --check .` green
- [ ] `mypy app/` green
- [ ] `pytest` (default selection) green

## Tests (REQUIRED)

Extend `tests/config/test_agent_constants.py` — no new file:

- `RECOMMENDED_TRIVY_VERSION == "0.73.0"`, `MIN_TRIVY_VERSION == "0.70.0"`, `CURRENT_AGENT_VERSION == "0.10.0"`.
- The existing `MIN <= RECOMMENDED` invariant still holds.
- The URL template renders both arch values (`64bit`, `ARM64`) to the upstream asset names, as a string assertion.
- Re-check the three `/install.sh`-render / `/agent/version` integration tests named above — their `0.71.0` expectation legitimately flips to `0.73.0`. They are the only tests whose assertions this ticket may change.

## Rollout (OPTIONAL)

Server-side only. Every host picks the new value up on its next scheduled run: `auto_update_self` first (no-op, the script is unchanged), then `auto_update_trivy` downloads 0.73.0, verifies its SHA256 and replaces `/opt/fathometer/bin/trivy`. No backfill, no operator action on the hosts. SemVer MINOR — the fleet installs a different binary, which is operator-visible.

## Risk / Non-goals (OPTIONAL)

- **Fleet-wide binary replace on the next run.** The mechanism is TICKET-015's and unchanged, but this ticket is what triggers it. A bad upstream release would reach every host; that is why field-exposure age (D1) is the gate at all.
- **v0.72.0's upstream breaking change does not affect us** (it is inherited by 0.73.0, which is cumulative): the APT repository now publishes only to the `generic` distribution, and architecture-suffixed container image tags are gone. We download the GitHub tarball directly and use no Trivy container image. Operators who installed Trivy from the APT repo under a codename are affected in their own tooling and may stay frozen at 0.71.2 — those hosts keep the `trivy outdated` pill, which is correct. **v0.73.0 itself ships no breaking changes** — its upstream changelog carries no `⚠ BREAKING CHANGES` section.
- **Not in scope:** signature verification of the tarball (cosign/sigstore assets exist upstream, `trivy_0.73.0_*.sigstore.json`). SHA256 covers transport integrity, not origin compromise. This remains TICKET-015's documented residual risk and its own re-open trigger.

## Test convention (subagent obligation, verbatim)

Allowed quality gates: ruff, mypy, shellcheck (linters), pytest default selection. Forbidden: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/browser tests — no proactive runs, no new `.bats`/`.sh` test files. Every `pytest` bash call carries an explicit `timeout` ≤ 120000 ms (default suite) / ≤ 60000 ms (focused sub-run). Note the default selection is not strictly pure-unit: `todo_mock` tests stay in and touch a real Postgres when one is up; `pytest -m "not todo_mock"` is the pure subset.
