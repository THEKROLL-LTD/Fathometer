# ADR-0068 — Kernel stale-artifact: prompt clarity + cache re-evaluation on host/CVE state

**Status:** Accepted · **Date:** 2026-06-17

Refs: [ADR-0066](0066-pass2-stale-fix-false-positive.md) (stale-artifact correction — **re-opened**: this ADR sharpens the prompt; the verdict stays an LLM judgment, no deterministic EVR compare), [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md) (Two-Pass reviewer, two-level cache/fingerprints — **amended**: cache_key persisted on the eval row as the enqueue gate, plus added fingerprint inputs), [ADR-0062](0062-agent-host-update-availability.md) (host-update flag), [ADR-0043](0043-llm-risk-band-exploitability-model.md) (band = exploitability judgment), [ADR-0053](0053-fix-lane-evaluation.md) / TICKET-013 (fix-lane eval + fingerprints), [ADR-0052](0052-open-only-eval-input.md) / TICKET-010 (OPEN-only eval input). Ref ticket: TICKET-017.

## Context

ADR-0066 gave the Pass-2 reviewer the data to self-correct Trivy stale-artifact false positives, but a live incident (`hz-tk-k8s-node-001` / server 15, 2026-06-17) showed 256 kernel findings still stuck at `act` after the host had booted the fixed `el9_8` kernel. Three independent defects combined:

1. **Prompt role-confusion.** The per-finding label `installed=<old el9_7 artifact>` reads as "active/in use", but for an `installonly` kernel package it is merely an old artifact on disk. The only field exposing the false positive — the running kernel — sat in a separate `host_context` block, and the correction path framed `host_update=none` only as "corroborates". The model anchored on `installed=` and escalated.
2. **Gate 1 (enqueue) is blind to host/CVE state.** `enqueue_pass2_for_server` compares only `group_findings_fingerprint` (identifier_key + purl over the lane OPEN-set). A re-scan with an unchanged OPEN-set (old artifact still on disk) skips enqueue → no re-evaluation, regardless of a kernel upgrade.
3. **Gate 2 (cache key) is blind to the running kernel.** `server_context_fingerprint` omits `kernel_version`; `cve_data_fingerprint` omits `host_update_available` / `installed_version` / `fixed_version`. Even if a job ran, a stale cached verdict would be reused after a kernel upgrade. The eval row persists only `group_findings_fingerprint`, so Gate 1 could not compare anything broader.

## Decision

### 1 — Prompt clarity (re-opens ADR-0066, Part A)

- Per-finding field rename: `installed=` → **`vulnerable=`** ("the version Trivy flagged as vulnerable, the artifact on disk; NOT necessarily the version in use"), `fix=` → **`fixed=`**. `host_update=` unchanged as a field, re-described.
- The running kernel stays **single-source in `host_context`** (`kernel (running):`). It is **not** duplicated onto finding/group lines (single-source rule, drift risk). The correction wording tells the model that for kernel findings the comparator is the `host_context` running kernel, not the per-finding `vulnerable=`.
- System-prompt rewrite: the field doc describes the four version roles explicitly; the STALE-ARTIFACT path is rewritten so kernel findings compare `fixed` against the running kernel with **"at or above"** semantics (the live case is `running == fixed` exactly), and the reason must **name the two versions compared and which is active**.
- `PASS2_PROMPT_VERSION` **6 → 7** (material prompt-semantics change; also salts the cache key).

### 2 — Gate 1: enqueue reacts to host/CVE state (amends ADR-0023, Part B)

- New nullable column `application_group_evaluations.cache_key String(64)`.
- `_upsert_evaluation` persists the `cache_key` already computed in `_do_pass2` (insert + `on_conflict` set).
- `enqueue_pass2_for_server` computes the **full** `make_cache_key` per `(group, lane)` — using the same helpers and the same lane OPEN-set domain as the worker — and skips enqueue only when `existing_eval.cache_key == computed`. This subsumes the old `group_findings_fingerprint` check (gf_fp is an input to the key). `group_findings_fingerprint` stays on the row for diagnostics/tests.

### 3 — Gate 2: fingerprint composition (amends ADR-0023, Part C)

- `server_context_fingerprint`: add `kernel_version` to the hashed payload.
- `cve_data_fingerprint`: extend the per-finding tuple with `host_update_available`, `installed_version`, `fixed_version`.
- These flow automatically into `make_cache_key`, so both gates react to a kernel upgrade / `host_update` flip.

### Self-heal of the live incident

Existing rows have `cache_key = NULL ≠ computed` → the first enqueue trigger (scan ingest, backstop sweep) re-enqueues every group once; combined with the prompt-version bump and the new fingerprint inputs → cache miss → fresh verdict under the clearer prompt. **No manual purge required.**

### Deliberately NOT in scope

- **No deterministic EVR/`vercmp` comparison in code** — the verdict stays a Pass-2 LLM judgment (ADR-0066 / ADR-0043 spirit).
- No raw NEVRA / epoch internals, no `rpm -qa` inventory, no kernel value duplicated onto finding lines.
- No automatic band flip in code; the reviewer alone decides.
- No new outbound surface, no new LLM call.

## Consequences

- `llm_prompts.py`: field doc + STALE-ARTIFACT path rewrite; `PASS2_PROMPT_VERSION` 6 → 7.
- `llm_risk_reviewer.py`: per-finding `vulnerable=` / `fixed=` rename; running kernel stays single-source in `host_context`.
- `llm_fingerprints.py`: `kernel_version` into the server fingerprint; `host_update_available` / `installed_version` / `fixed_version` into the cve fingerprint; module docstring updated.
- `models.py` + migration `0030` (single-head on `0029`): nullable `cache_key`; `downgrade` drops it.
- `llm_worker.py` `_upsert_evaluation`: writes `cache_key`. `pass2_enqueue.py`: the gate switches to the full `cache_key`; it loads the server snapshot + all three fingerprints per lane (acceptable, single-user / low volume).
- `ARCHITECTURE.md` §12: cache invalidation now reacts to running kernel / host_update.
- Tests (allowed gates only): fingerprint determinism + new-input sensitivity; enqueue re-enqueues on kernel/host_update change and does not churn on unchanged state; enqueue==worker key parity; prompt render asserts the new field names + correction wording + `PASS2_PROMPT_VERSION == 7`; optional stubbed-LLM verdict eval. Alembic roundtrip operator-run only.

## Re-Open triggers

- If the model still anchors on the wrong field despite the wording: consider group-level co-location of the running kernel (rejected here for drift) — **measure before hardening** (ADR-0066 spirit).
- If enqueue cost from per-lane snapshot loading becomes material at higher volume: cache the server snapshot / fingerprints per enqueue call.
