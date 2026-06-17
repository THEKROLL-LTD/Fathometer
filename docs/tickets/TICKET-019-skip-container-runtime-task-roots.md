# TICKET-019 — Complete the ADR-0067 skip list: exclude all container-runtime content distro-agnostically (live `/run` task roots + RKE2/k0s/MicroK8s) via containerd globs

**Status:** Open · **Date:** 2026-06-17
**Refs:** ADR-0067 (exclude container-runtime data-roots — this ticket extends it under its own "New/relocated runtimes" re-open trigger; **no new ADR**, amend ADR-0067 + its skip-dir table), ARCHITECTURE.md §17 (out of scope: container-image scans), ADR-0052/TICKET-010 (absent-from-scan → RESOLVED), ADR-0023 (Pass-1 grouping / `GroupMatcher`).
**Components:** `agent/fathometer-agent.sh` (skip-dir list + version bump), `agent/README.md`, `docs/operations.md`, `ARCHITECTURE.md`, ADR-0067 doc, optional data cleanup of polluted `application_groups` rows. Tests: pure-unit/string assertion on the assembled `--skip-dirs`.
**Migration:** none (findings resolve via ADR-0052; group cleanup is optional data hygiene, §4).

---

## 0. Onboarding (base not assumed)

Self-hosted Trivy scan aggregator (Flask + Jinja2 + HTMX + Alpine.js, PostgreSQL 17, single-user). The reference **agent** is a bash script that runs `trivy rootfs /` on each host and pushes the JSON. Read `CLAUDE.md` — especially the **test convention** (only `ruff` / `mypy` / `shellcheck` + pure-unit `pytest` with Bash `timeout ≤ 120000`; **no** db_integration / acceptance / integration / bench / bats / Docker / live-runtime tests run proactively; **no new `.bats`/`.sh` test files without explicit operator approval**) and the **language policy** (new docs/comments English). Read ADR-0067 first — this ticket is its completion.

---

## 1. Problem

ADR-0067 excludes container-runtime data-roots from `trivy rootfs /` because their contents are unpacked container-image layers (out of scope, §17). The built-in skip list (`agent/fathometer-agent.sh:538–543`, agent 0.9.0) is:

```
/var/lib/docker
/var/lib/containerd
/var/lib/rancher/k3s/agent/containerd
/var/lib/containers
```

These cover the **persistent image/snapshot stores**. They do **not** cover the **live running-container root filesystem**, which containerd mounts under `/run`:

```
/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/<container-hash>/rootfs/<binary>
```

`/run/...` is not on the list, so `trivy rootfs /` still descends into every running pod's rootfs and scans coredns, metrics-server, local-path-provisioner, longhorn, etc. as container-image content — exactly the scope ADR-0067 set out to close, leaking through a path family it did not enumerate. A fully ADR-0067-updated agent still leaks.

### 1.1 Downstream damage (why this surfaced)

These container-image findings should not exist per §17/ADR-0067, but because they do, they corrupt grouping and verdicts:

- The Pass-1 LLM (no host context, batched) emits inconsistent path-prefix rules for `/run/.../k8s.io/<hash>/rootfs/...` — sometimes container-specific, sometimes the over-broad root `run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/`. UNION-merged into the global group library, the broad prefix turned the `metrics-server` group (id 26) into a catch-all: via longest-prefix match it swallows **any** running-container finding (coredns, local-path-provisioner, …).
- Because the same logical container is scanned under different path families on different nodes (the now-skipped snapshotter store on one, the un-skipped `/run` task root on another), the same component lands in **different groups on different nodes**. Pass-2 evaluates per `(server, group, fix_lane)` and the band is inherited by all members, so the **same CVE (e.g. CVE-2025-68121) got `monitor` on k3s-sv-0 and `escalate` on k3s-sv-1** — same k3s version, different scan-path family → different group membership → different inherited band. (Confirmed deterministic at `temperature=0`; not sampling variance.)

Operator decision (2026-06-17): container-image content stays **out of scope** (option A). The fix is to complete the skip list, not to build container-aware grouping.

---

## 2. Goal

`trivy rootfs /` scans only host OS packages and host binaries; no running-container rootfs is walked on Docker / containerd / k3s-embedded-containerd / podman / CRI-O hosts. Existing leaked container-image findings resolve automatically; the catch-all group empties; remaining groups are real, stable host components that group and name consistently across nodes — restoring trustworthy, consistent verdicts.

---

## 3. Fix — agent skip list: glob on containerd-internal markers, not per-distro paths

A static per-data-root list is whack-a-mole: every distro adds a persistent store **and** a `/run` task root, and ADR-0067's list misses RKE2 (`/var/lib/rancher/rke2/agent/containerd`), k0s (`/var/lib/k0s/containerd` + `/run/k0s/containerd`), MicroK8s (`/var/snap/microk8s/common/var/lib/containerd`), and every distro's `/run/.../io.containerd.runtime.v2.task/` live rootfs. Enumerating them per distro is fragile (ADR-0067's own "New/relocated runtimes" re-open trigger).

**Instead, skip by the containerd-internal directory markers, which are invariant across distros and data-roots.** Trivy `--skip-dirs` supports doublestar globs, so two patterns replace the whole containerd enumeration:

```
**/io.containerd.runtime.*.task     # live running-container rootfs (the /run task tree) — ALL containerd distros
**/io.containerd.snapshotter.*      # unpacked image layers / snapshots — ALL containerd distros
```

This covers k3s, **RKE2**, k0s, MicroK8s, standalone containerd, and CRI-on-containerd in one rule, regardless of where the data-root lives, and is future-proof against relocated roots.

Keep the explicit roots for the **non-containerd** runtimes (no `io.containerd.*` markers) and as belt-and-suspenders:

```
/var/lib/docker        # Docker overlay2 image/container layers (+ live merged mounts)
/var/lib/containers    # podman / CRI-O containers/storage
/run/containers        # podman / CRI-O runtime state
```

Notes:
- The four ADR-0067 built-ins (`/var/lib/docker`, `/var/lib/containerd`, `/var/lib/rancher/k3s/agent/containerd`, `/var/lib/containers`) become **redundant for the containerd ones** under the glob but can stay (harmless, explicit, and a fallback if a Trivy build's glob behavior differs). Net built-in set: the two globs + `/var/lib/docker` + `/var/lib/containers` + `/run/containers` (the `/var/lib/containerd` and `…/k3s/agent/containerd` entries are now subsumed by the snapshotter glob — keep or drop, document the choice).
- **Docker** live containers mount under `/var/lib/docker/overlay2/*/merged` (already covered); Docker has no `io.containerd.*` marker, hence the explicit root + the `FM_SCAN_SKIP_DIRS` escape hatch for a relocated `data-root`.
- Nothing **in scope** matches these patterns: `io.containerd.runtime.*.task` / `io.containerd.snapshotter.*` are containerd-internal dir names; host OS package DBs (`/var/lib/dpkg`, `/var/lib/rpm`) and host binaries (`/usr/local/bin/k3s`, tailscale, etcd-in-k3s) live elsewhere and remain fully scanned.
- `FM_SCAN_SKIP_DIRS` (operator escape hatch) unchanged, still appended.
- **Version bump:** `AGENT_VERSION` `0.9.0 → 0.10.0` and server-side `CURRENT_AGENT_VERSION` (gate semantics per ADR-0022; `MIN_AGENT_VERSION` unchanged). shellcheck-clean.
- Update the header comment block + the `log` line already prints `skip-dirs=...`.

> **Verify glob support (load-bearing):** confirm the pinned Trivy version honors `--skip-dirs` doublestar globs against `rootfs` walks. This is best confirmed on a real containerd host (live check, operator-run — not a CI gate). If a given Trivy build does **not** glob in skip-dirs, fall back to the explicit per-distro list (add `/var/lib/rancher/rke2/agent/containerd`, `/var/lib/k0s/containerd`, `/run/containerd`, `/run/k3s/containerd`, `/run/k0s/containerd`, `/var/snap/microk8s/common/var/lib/containerd`, … — and accept the whack-a-mole).

---

## 4. Data hygiene (no migration)

- **Leaked findings self-resolve:** after an updated agent runs once, all findings with `target_path` under the new skip roots are absent from the scan set → ingest marks them `RESOLVED` (ADR-0052). No migration, no manual delete. Operator check:
  `SELECT count(*) FROM findings WHERE target_path LIKE '/run/%/containerd/%' OR target_path LIKE '/run/containers/%';` before vs after a scan cycle.
- **Polluted group rules (optional, cosmetic):** the over-broad prefix on group 26 (`run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/`) and the snapshotter/runtime path_prefixes on container-only groups (coredns 38, csi-*, longhorn-* image entries, local-path-provisioner, livenessprobe, grpc(_/-)health-probe, "manager" 74) will simply stop matching anything. They can be left as dead rules or cleaned up. If cleaning: strip path_prefixes that point into any container-runtime root, and let now-empty `source='llm'` groups age out. This is data hygiene, **not** required for correctness — do it as a separate optional step, operator-run.
- **No need to reset `application_group_id`:** the leaked findings resolve rather than re-group, so the never-rematch rule is moot for them.

---

## 5. Definition of Done (machine-checkable where possible)

- [ ] `agent/fathometer-agent.sh` built-in `skip_dirs` contains the two containerd globs (`**/io.containerd.runtime.*.task`, `**/io.containerd.snapshotter.*`) plus the non-containerd roots (`/var/lib/docker`, `/var/lib/containers`, `/run/containers`); header comment updated; `AGENT_VERSION == "0.10.0"`; server `CURRENT_AGENT_VERSION` bumped.
- [ ] `shellcheck agent/fathometer-agent.sh` clean.
- [ ] Pure-unit/string test (extends the existing ADR-0067 skip-dir test): the assembled `--skip-dirs` argument list includes both globs + the explicit roots and still appends `FM_SCAN_SKIP_DIRS`. **No** live-runtime/`.bats` test (operator approval required otherwise).
- [ ] **Trivy glob support confirmed** (live, operator-run — not a CI gate): on a containerd/k3s host the assembled globs actually exclude `**/io.containerd.runtime.*.task/**` and `**/io.containerd.snapshotter.*/**`. If not honored, fall back to the explicit per-distro list (§3 note) — including the RKE2/k0s/MicroK8s roots.
- [ ] Docs updated: ADR-0067 skip-dir table + "New/relocated runtimes" re-open note (mark the `/run` task roots added by TICKET-019), `agent/README.md`, `agent/fathometer-agent.sh` header, `docs/operations.md` ("why container vulnerabilities do not appear — live container rootfs under /run is excluded too"), `ARCHITECTURE.md` scan-invocation reference.
- [ ] Operator-verified (advisory, not a gate): after one scan cycle on a k3s node, findings under `/run/.../containerd/...` are gone and the `metrics-server` group no longer contains coredns/other-container findings; CVE-2025-68121 divergence between k3s-sv-0 and k3s-sv-1 no longer occurs.
- [ ] `ruff check . && ruff format --check .` and `mypy app/` green (no app code changed, but keep gates green).

---

## 6. Test & process guardrails (verbatim, from CLAUDE.md)

Allowed quality gates: `ruff`, `ruff format --check`, `shellcheck` (linter), `mypy app/`, `pytest` default selection (pure-unit). Forbidden (no proactive runs, no new `.bats`/`.sh` test files without explicit operator approval): db_integration / acceptance / integration / bench / `RUN_E2E` / Docker-Compose / live-runtime / browser tests. Every `pytest` Bash call carries a `timeout` ≤ 120000 ms. New docs/comments English.

---

## 7. Notes / relation to other work

- **Supersedes the "container binary-leaf grouping" idea.** With container-image content out of scope, there is no need for a path-family-stable container identity / binary-leaf match dimension (the larger grouping subsystem we considered). Host components live at stable paths without per-container hashes and group consistently on their own.
- **Residual, separate:** even for genuine host-level findings, Pass-2 still evaluates per `(server, group, lane)` with no cross-node consistency anchor. After this fix the dominant cause of divergence is gone; a cross-host band-consistency **detective check** (flag: same CVE+component, different band across hosts) remains a worthwhile low-priority safety net — track separately, not in this ticket.
- TICKET-017 (kernel stale-artifact prompt + cache) is independent and unaffected.
