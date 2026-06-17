# ADR-0067 — Exclude container-runtime data-roots from the agent host scan

**Status:** Accepted · **Date:** 2026-06-15

References: [ADR-0021](0021-agent-bootstrap-installer.md) (agent bootstrap + Trivy `rootfs` invocation), [ADR-0003](0003-push-not-pull.md) (push, not pull — the agent reports, never changes host state), [ADR-0042](0042-agent-fire-and-forget-ingest.md) (fire-and-forget ingest), [ADR-0052](0052-operator-sichten-jetzt-zustand.md) (absent-from-scan → resolved; reopen-on-redetect). Scope anchors: ARCHITECTURE.md §17 (out of scope: container-image scans, `trivy image …`) and ARCHITECTURE.md:11 ("container-image scans … are explicitly not this app's job").

> Numbering note: 0067 is highest-existing + 1. The 0059/0060 slots are an existing gap from the Block-AG renumbering (untracked 0058/0059/0060 → 0061/0062/0063); we do **not** backfill them — numbering stays monotonic.

## Context

The reference agent calls `trivy rootfs / --format json --scanners vuln` (`agent/fathometer-agent.sh:515`) with **no `--skip-dirs` and no `--timeout`**. `rootfs /` is deliberate (ADR-0021): it walks the live root filesystem so statically built host binaries (k3s, tailscale, in-house Go/Java tools under `/usr/local/bin`) are captured via Trivy's gobinary analyzer — `fs` would miss them.

On a host running a container runtime, `rootfs /` also descends into the runtime's data-root and scans the **unpacked container-image layers** stored there. Observed case: a GitLab Omnibus container on a Docker host — Trivy walks `/var/lib/docker/overlay2/*/diff/…`, the file tree explodes, and the scan exceeds Trivy's **silent 5-minute default timeout**:

```
FATAL  run error: rootfs scan error: … walk dir error: … semaphore acquire: context deadline exceeded
```

This is not a single corrupt file — it is the default timeout tripping because the tree blew up through the container layers. The agent exits 2 (scan failed) **before** building or sending any envelope, so the systemd-timer retry hits the identical cause: a recurring failure with no self-heal, and **no scan data ingested for that host at all**.

Two facts make this a scope bug, not a tuning problem:

1. **Scanning unpacked image layers is container-image scanning** — explicitly out of scope (§17, ARCHITECTURE.md:11). `rootfs /` does it by accident.
2. **Excluding those layers loses nothing intended.** Host OS package databases (`/var/lib/dpkg`, `/var/lib/rpm`, `/lib/apk/db`) and statically installed host binaries (k3s, tailscale) live **outside** any container data-root and remain covered. k3s/etcd visibility is preserved specifically: k3s does not use `/var/lib/docker` (its embedded containerd image store is under `/var/lib/rancher/k3s/agent/containerd`), and the etcd version is compiled into the host binary `/usr/local/bin/k3s`, detected by the gobinary analyzer — that binary is never inside a data-root and is untouched by the skip.

Skipping only `/var/lib/docker` would be runtime-specific and incomplete: the same failure mode exists on containerd, k3s-embedded containerd, and podman/CRI-O hosts, plus Docker installations with a custom `data-root` set in `daemon.json`.

## Decision

**Exclude container-runtime data-roots from the agent's `rootfs` scan**, because their contents are unpacked container-image layers and container-image scanning is out of scope (§17). Host OS packages and host binaries are explicitly **not** lost by this exclusion.

The three sub-decisions below were ratified by the operator on 2026-06-15.

### Decision 1 — which paths: the full known-runtime-data-root list (not only Docker)

Pass `--skip-dirs` for the complete set of well-known runtime data-roots:

| Path | Runtime | What is skipped |
|---|---|---|
| `**/io.containerd.runtime.*.task` | all containerd distros (k3s/RKE2/k0s/MicroK8s/standalone/CRI) | live running-container rootfs under the `/run` task tree |
| `**/io.containerd.snapshotter.*` | all containerd distros | unpacked image layers / snapshots |
| `/var/lib/docker` | Docker | overlay2 image/container layers |
| `/var/lib/containerd` | containerd (standalone, k3d, CRI-O via containerd) | image snapshot stores |
| `/var/lib/rancher/k3s/agent/containerd` | k3s embedded containerd | pod-image layers |
| `/var/lib/containers` | podman / CRI-O (`containers/storage`) | image/overlay layers |
| `/run/containers` | podman / CRI-O | runtime state |

The two `io.containerd.*` glob rows and `/run/containers` were added by TICKET-019 to also cover the **live** running-container rootfs under the `/run` task roots (which the per-path list missed) and the RKE2/k0s/MicroK8s data-roots, by skipping on containerd's invariant internal directory markers instead of enumerating per-distro paths. The four original per-path roots (`/var/lib/docker`, `/var/lib/containerd`, `/var/lib/rancher/k3s/agent/containerd`, `/var/lib/containers`) are now **redundant-but-retained** explicit fallbacks (kept for the non-containerd ones and as belt-and-suspenders should a Trivy build's glob behavior differ).

Rationale: skipping only `/var/lib/docker` leaves the identical timeout/scope gap on containerd-, k3s-, and podman-based hosts — the most likely deployments for this operator audience. Every path above holds only unpacked image content (out of scope); none holds host OS package state. The k3s entry is the **containerd sub-path only** (`…/agent/containerd`), not all of `/var/lib/rancher/k3s`, keeping the exclusion surgical and leaving the k3s host binary in `/usr/local/bin` fully scanned.

### Decision 2 — custom data-roots: operator escape hatch `FM_SCAN_SKIP_DIRS`

A Docker `data-root` (or podman `graphroot`) relocated via `daemon.json`/`storage.conf` is **not statically discoverable** by the agent without parsing those files. Add an env override `FM_SCAN_SKIP_DIRS` (comma-separated absolute paths) that is **appended** to the built-in list above. The built-in list covers the common default-path case; the env covers the long tail, stays runtime-agnostic, and is air-gap-friendly (no outbound, no extra dependency). Auto-detecting the Docker data-root from `docker info`/`daemon.json` is deliberately **not** done here (adds Docker-specific logic and a daemon call) — see Re-open triggers.

### Decision 3 — explicit `--timeout`, default 5m, via `FM_SCAN_TIMEOUT`, documented

Add an explicit `--timeout` sourced from a new env `FM_SCAN_TIMEOUT`, **default `5m`** — i.e. make Trivy's existing 5-minute default explicit, logged, and operator-tunable rather than raising it. The explicit timeout addresses only the **symptom**; the real fix is exclusion. Keeping the default at 5m preserves install-probe responsiveness and keeps a failing scan visible quickly instead of letting it hang the systemd unit for a long time.

The operator guidance (README) is the load-bearing part of this decision: **a scan that still exceeds 5 minutes after the built-in skips is a signal to exclude more** (add the offending tree to `FM_SCAN_SKIP_DIRS`), not to blindly raise the timeout. Raising `FM_SCAN_TIMEOUT` is an explicit, deliberate operator choice for a host that genuinely has a large in-scope tree — not the default escape from a scope leak.

### Out of scope (unchanged)

- **No container-image scanning is added** — the skip removes accidental image scanning; it does not introduce a `trivy image …` path. Adding deliberate container-image scanning remains out of scope and would need its own ADR.
- **No host state change** (ADR-0003): read-only scan configuration only.

## Schema / envelope impact: none

No schema change and no migration.

- The affected host **never ingested anything** — `trivy … || exit 2` fires before the envelope is built/sent, so there are no container-layer findings in the DB from it.
- For any *other* host that previously completed a Docker scan with a small enough image tree and did ingest layer findings (`target_path` under a data-root): after this change those findings simply stop appearing in the scan set, and the ingest's resolve phase marks findings absent from the current scan as `RESOLVED` (`findings_ingest.py`, ADR-0052). They age out on the next successful scan with no data loss and no manual cleanup.
- Operator verification (optional, advisory — not a migration): a one-off `SELECT count(*) FROM findings WHERE target_path LIKE '/var/lib/docker/%' OR target_path LIKE '/var/lib/containerd/%' OR target_path LIKE '/var/lib/containers/%' OR target_path LIKE '/var/lib/rancher/k3s/agent/containerd/%';` confirms whether any such rows exist; if so, they resolve on the next scan cycle.

## Rationale

- **Fixes the actual class of bug** (scope leak → timeout → no self-heal), not just the one observed path.
- **Authoritative, local, deterministic, air-gap-safe:** a static path list plus an env escape hatch — no outbound, no LLM, no per-host probing.
- **Loses nothing in scope:** host OS packages and host binaries (k3s/tailscale/etcd-in-k3s) are all outside the excluded roots and remain fully covered.
- **Timeout makes intent explicit:** an explicit, logged 5m budget plus the "exclude, don't raise" rule turns a silent default failure into a deliberate operator decision.

## Consequences

- Agent script (`agent/fathometer-agent.sh`): the `trivy rootfs` invocation gains `--skip-dirs <built-in list + FM_SCAN_SKIP_DIRS>` and `--timeout "$FM_SCAN_TIMEOUT"` (default `5m`); the two new env vars (`FM_SCAN_SKIP_DIRS`, `FM_SCAN_TIMEOUT`) are documented in the header block; agent version bump + `CURRENT_AGENT_VERSION` (gate semantics per ADR-0022; `MIN_AGENT_VERSION` unchanged — old agents that omit the skip are not broken, only less precise). shellcheck-clean.
- No backend, schema, migration, or envelope change.
- Tests (allowed gates only — ruff/mypy/shellcheck + pure-unit pytest): a pure-unit/string-level assertion that the assembled `--skip-dirs` argument contains the four built-in roots and appends `FM_SCAN_SKIP_DIRS`, and that `--timeout` is honored from `FM_SCAN_TIMEOUT` (default `5m`). **No** new `.bats`/live-runtime tests without explicit user approval (CLAUDE.md test convention).
- Documentation follow-ups (named here, not coded in this ADR): ARCHITECTURE.md:206 / :223 (the invocation line + field-reference row), the agent-script header comment block (rationale for `--skip-dirs`/`--timeout`), `docs/operations.md` (operator note: "why container vulnerabilities do not appear — runtime data-roots are excluded by design"), and **`README.md`** (the new env vars plus the "scan > 5 min → exclude more, don't just raise the timeout" guidance).

## Re-open triggers

- **Custom data-root auto-detection.** If `FM_SCAN_SKIP_DIRS` proves too manual in the field, add opt-in detection of the Docker `data-root` from `docker info`/`/etc/docker/daemon.json` (and podman `graphroot` from `storage.conf`) — separate, runtime-specific logic; its own follow-up.
- **New/relocated runtimes.** Additional or relocated data-roots (LXD `/var/lib/lxd`, nerdctl namespaces, rootless container stores under `$HOME/.local/share/containers`) extend the built-in list. TICKET-019 generalized this for containerd by skipping on the containerd-internal-marker globs (`**/io.containerd.runtime.*.task`, `**/io.containerd.snapshotter.*`) — covering the live `/run` task roots plus RKE2/k0s/MicroK8s — instead of per-distro path enumeration.
- **Deliberate container-image scanning.** Still out of scope (§17); if ever wanted, a dedicated ADR for a `trivy image …` path, not a relaxation of this skip.
