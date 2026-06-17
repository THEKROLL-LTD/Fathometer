# TICKET-017 — Kernel stale-artifact false positive: prompt clarity + cache re-evaluation

**Status:** Open · **Date:** 2026-06-17
**Refs:** ADR-0066 (stale-artifact correction — **re-opened** by this ticket: §3 sharpens the prompt; the verdict stays an LLM judgment, no deterministic EVR comparison in code), ADR-0023 (Two-Pass reviewer, two-level cache / fingerprints — **amended** by §4/§5), ADR-0062 (host-update flag), ADR-0043 (band = exploitability judgment), ADR-0053/TICKET-013 (fix-lane evaluation + fingerprints), ADR-0052/TICKET-010 (OPEN-only eval input).
**Components:** `app/services/llm_prompts.py`, `app/services/llm_risk_reviewer.py`, `app/services/llm_fingerprints.py`, `app/services/pass2_enqueue.py`, `app/workers/llm_worker.py` (`_do_pass2`, `_upsert_evaluation`), `app/models.py` (`ApplicationGroupEvaluation`), new Alembic migration, tests, `ARCHITECTURE.md` §12.
**Migration:** **yes** — one new column on `application_group_evaluations` (§4). DB-near → roundtrip runs only on explicit operator approval (CLAUDE.md).
**New ADR:** `0068-*` (§6). (`0067` was already taken by the container-runtime data-roots ADR; this ticket's ADR is **0068**.)

---

## 0. Onboarding (base not assumed)

Self-hosted Trivy scan aggregator (Flask + Jinja2 + HTMX + Alpine.js, PostgreSQL 17, single-user). Mandatory before the first commit: read `CLAUDE.md` — especially the **test convention** (only `ruff` / `mypy` / `shellcheck` + pure-unit `pytest` with Bash `timeout ≤ 120000`; **no** db_integration / acceptance / integration / bench / bats / Docker / browser tests run proactively; the **Alembic roundtrip runs only on explicit operator approval**), the **HTMX-OOB single-source rule**, and the **language policy** (new docs/comments/UI strings are English).

Read `app/services/llm_fingerprints.py` and `app/services/pass2_enqueue.py` end to end first. The fingerprint module docstring enumerates which fields each fingerprint covers; this ticket *adds* inputs — do not silently drop an existing one.

---

## 1. Problem

Live incident (`hz-tk-k8s-node-001` / server 15, 2026-06-17): 256 kernel findings sit at `act`, although the host already runs the fixed `el9_8` kernel and the flagged `el9_7` packages are only old, non-booted artifacts on disk. The DB and the rendered prompt were correct (`servers.kernel_version = …el9_8`, `host_update=none` for all 256), yet the reviewer escalated. Three independent defects combine:

### 1.1 Prompt role-confusion (the verdict itself)

For an `installonly` kernel finding the per-finding line shows `installed=<old el9_7 artifact> fix=<el9_8>` — on one line that reads as "behind, patch available". The only field that exposes the false positive — the **running** kernel — sits in a separate `host_context` block (`llm_risk_reviewer.py:912`). The model must (a) recognize the finding is a kernel package, (b) ignore the misleading per-finding `installed=`, (c) reach up to `host_context`'s `kernel (running):`, (d) compare EVRs across dist-tags (`el9_7` vs `el9_8`). The label `installed=` actively implies "active", which it is not for `installonly` packages. The stored reason confirms the trap: the model read `installed=` as "running" and the running kernel as the unapplied fix. `host_update=none` was present but framed only as "corroborates" and was ignored. → **A labeling/wording problem amplified by a missing co-located comparator.**

### 1.2 Gate 1 — enqueue is blind to host/CVE state

`enqueue_pass2_for_server` decides *whether a job is created at all* and compares **only** `group_findings_fingerprint` (= `identifier_key + package_purl` over the lane OPEN-set) against the stored eval row (`pass2_enqueue.py:203–208`; it imports only `group_findings_fingerprint`, line 33). `kernel_version`, `host_update_available`, `installed_version`, `fixed_version` never enter the enqueue decision. So a re-scan with an unchanged OPEN-set (same 256 findings, old artifact still on disk) **skips enqueue → no re-evaluation**, regardless of any kernel upgrade. Today the verdict only refreshes when the OPEN-set changes (i.e. when Trivy stops reporting the old artifact after an `installonly` prune — which can be far in the future).

### 1.3 Gate 2 — cache key is blind to the running kernel

The worker-side cache key (`make_cache_key`, used in `_do_pass2` at `llm_worker.py:1576–1579`) is built from the three fingerprints + `PASS2_PROMPT_VERSION`. `server_context_fingerprint` omits `kernel_version` (`llm_fingerprints.py:196–211`); `cve_data_fingerprint` omits `host_update_available` / `installed_version` / `fixed_version` (`llm_fingerprints.py:105–119`). Even if a job *did* run, a stale cached verdict would be reused after a kernel upgrade.

The eval row (`ApplicationGroupEvaluation`, `models.py:971`) persists **only** `group_findings_fingerprint` (line 1022) — not the other two fingerprints and not the `cache_key`. That is why Gate 1 cannot compare anything broader today.

---

## 2. Goal

1. The reviewer reliably distinguishes **active** vs **only-installed** vs **vulnerable** vs **fix** versions, and treats a flagged-but-non-active artifact as `noise` (§3).
2. A change to any reviewer-load-bearing host/CVE input (running kernel, `host_update_available`, installed/fixed version) **re-enqueues** evaluation (Gate 1, §4) **and** misses the cache so the LLM is re-asked (Gate 2, §5).
3. The current 256 stale findings on server 15 close without a manual purge after deploy (§6) — a re-scan or the backstop sweep self-heals.

The verdict stays an LLM judgment (ADR-0066 spirit). No deterministic EVR comparison is added to code.

---

## 3. Part A — Prompt clarity + data (`llm_prompts.py`, `llm_risk_reviewer.py`)

### 3.1 Per-finding field rename (role-encoding labels)

In `_render_pass2_prompt` (`llm_risk_reviewer.py:1009/1014–1016`):

- `installed=` → **`vulnerable=`** — "the exact version Trivy flagged as vulnerable (the artifact found on disk); NOT necessarily the version in use". This kills the "installed ⇒ active" misread.
- `fix=` → **`fixed=`** (parity/clarity).
- `host_update=` unchanged as a field, but re-described (§3.3).

### 3.2 The active kernel — single source, wording bridges the block

Keep the running kernel **single-source in `host_context`** (`kernel (running):`, line 912). Do **NOT** duplicate the value onto finding/group lines — that would violate the single-source rule (CLAUDE.md) and risk drift. Instead, the correction-path wording (§3.3) explicitly tells the model that for kernel findings the comparator is the `host_context` `kernel (running):` value, **not** the per-finding `vulnerable=`. (Group-level co-location was considered and rejected for drift; revisit only if §8 eval shows the model still anchors on the wrong field — measure before hardening, per ADR-0066.)

### 3.3 System-prompt rewrite (`llm_prompts.py`)

- **Field doc (≈ lines 206–217):** describe the four version roles explicitly — `vulnerable=` (flagged artifact, possibly not active), `fixed=` (resolves the CVE), the `host_context` running kernel (the version actually booted/executing — for kernel findings, the only attack-relevant version), `host_update=available|none` (the host package manager's own verdict: `available` = an upgrade for the owning package is offered, `none` = nothing to install).
- **STALE-ARTIFACT correction path (replace lines 275–286):**
  > Trivy reports every vulnerable package file on disk, including ones installed but **not active**. A finding is real only if the version actually in use is the vulnerable one.
  > **Kernel findings:** compare `fixed` against the `host_context` running kernel — **NOT** against `vulnerable`. If the running kernel is **at or above** `fixed` (same version or newer), the booted kernel already contains the fix and `vulnerable=` is an older, non-booted kernel left on disk → stale-artifact false positive → **noise**; `host_update=none` confirms it. Only if the running kernel is **below** `fixed` is it real (fix not yet booted, or not installed) → keep actionable.
  > **Other packages:** `vulnerable=` is the effective version. Below `fixed` with `host_update=available` → genuinely behind → actionable. At or above `fixed` with `host_update=none` → stale-artifact → noise.
  > **In your reason, always name the two versions you compared and which is active**, e.g. `running 687.15.1.el9_8 ≥ fixed 687.15.1.el9_8 → already patched → noise`.
  - Note the **"at or above"** (the live case is `running == fixed` exactly) and the forced version-naming (improves accuracy and makes `llm_debug_log` self-explanatory).
- **`PASS2_PROMPT_VERSION` 6 → 7** (`llm_prompts.py:50`) — the field renames + wording are a material prompt-semantics change; this also salts the cache key (Gate 2).

### 3.4 Data we deliberately do NOT add

No raw NEVRA / epoch internals, no full `rpm -qa` inventory, no duplicated kernel value on finding lines. The four role-labeled fields are sufficient; more is token noise or drift surface.

---

## 4. Part B — Gate 1: enqueue reacts to host/CVE state

Make the enqueue gate compare the **full cache key**, not just the OPEN-set fingerprint.

- **Schema (`models.py`, new migration):** add `cache_key: Mapped[str | None] = mapped_column(String(64), nullable=True)` to `ApplicationGroupEvaluation`. New Alembic migration on the current head, Single-Head; `downgrade` drops the column. Existing rows get `cache_key = NULL`.
- **Worker write (`_upsert_evaluation`, `llm_worker.py:1943/1982/1993`):** persist the `cache_key` already computed in `_do_pass2` (line 1579) into the eval row (both the insert column list and the `on_conflict` update set).
- **Enqueue compare (`pass2_enqueue.py:184–209`):** load the `Server` once; for each `(group, lane)` compute `cache_key = make_cache_key(group.id, group_findings_fingerprint(lane_findings), cve_data_fingerprint(lane_findings), server_context_fingerprint(server, session=session), fix_lane=lane)` and skip enqueue only if `existing_eval is not None and existing_eval.cache_key == cache_key`. This subsumes the current `group_findings_fingerprint` check (gf_fp is an input to the key). Enqueue and worker MUST compute the key identically (same domain = lane OPEN-set) — reuse the same helpers; a mismatch would re-enqueue forever (the failure mode the `group_findings_fingerprint` docstring warns about).
- **Self-heal on deploy:** existing rows have `cache_key = NULL ≠ computed` → the first enqueue trigger (scan ingest, **backstop sweep**, etc.) re-enqueues every group once. Combined with the §3.3 version bump (different key) and §5 (kernel/host_update now in the key), this closes the live incident without a purge.
- **Cost:** enqueue now loads the server snapshot and computes all three fingerprints per lane. Acceptable (single-user, low volume). Keep the existing double-enqueue guard and empty-lane skip unchanged.

> Keep `group_findings_fingerprint` on the eval row (diagnostics / existing tests); the *gate* switches to `cache_key`.

---

## 5. Part C — Gate 2: fingerprint composition

Add the load-bearing inputs to the fingerprints (`llm_fingerprints.py`), same hashing scheme:

- **`server_context_fingerprint` (line 196):** add `kernel_version` to the hashed payload (host property; keep `sort_keys=True`).
- **`cve_data_fingerprint` (lines 105–117):** extend the per-finding tuple with `host_update_available`, `installed_version`, `fixed_version`. (`fixed_version` partially overlaps the lane partition in `group_findings_fingerprint`, but the *value* change is otherwise uncaptured — include it for directness. Keep `default=str` so `None` serializes stably.)
- Update the module docstring's field enumeration to stay truthful.
- These flow automatically into `make_cache_key`, so both gates now react to a kernel upgrade / `host_update` flip.

---

## 6. Part D — One-time correction of the current incident

With §3–§5 deployed, the live 256 self-heal: the `cache_key` column is NULL on existing rows **and** the key composition + prompt version changed → next scan/backstop re-enqueues → cache miss → fresh LLM verdict under the clearer prompt. **A purge should not be necessary.**

If immediate correction is wanted without waiting for a trigger, the operator may purge — but note: deleting findings alone does **not** force re-eval, because `group_findings_fingerprint` is content-based (`identifier_key + purl`) and survives a findings re-scan. A manual purge must include `application_group_evaluations` (the verdict/junction rows) **and** `llm_risk_cache` (and pending `LLMJob` rows), otherwise Gate 1 still skips. **Any purge or re-scan must come after the §3 prompt rewrite is deployed**, else the same false positive is re-derived under the old prompt.

---

## 7. Definition of Done (machine-checkable where possible)

- [ ] **Prompt:** per-finding `vulnerable=`/`fixed=`/`host_update=` rendered; STALE-ARTIFACT path rewritten (kernel compares against running kernel, "at or above", forced version-naming); field doc updated; `PASS2_PROMPT_VERSION == 7`. Pure-unit render tests assert the new field names and that the running-kernel comparator + correction wording are present.
- [ ] **Gate 1:** `ApplicationGroupEvaluation.cache_key` column added; `_upsert_evaluation` writes it; `enqueue_pass2_for_server` skips only on `cache_key` match. Pure-unit tests: kernel-version change re-enqueues; `host_update` flip re-enqueues; unchanged state does **not** re-enqueue (no churn); enqueue and worker compute the identical key for identical state.
- [ ] **Gate 2:** `server_context_fingerprint` includes `kernel_version`; `cve_data_fingerprint` includes `host_update_available`/`installed_version`/`fixed_version`; identical inputs → identical fingerprint (determinism). Module docstring matches.
- [ ] **Migration:** Single-Head; `alembic upgrade head && downgrade -1 && upgrade head` green — **operator-run only** (DB-near; otherwise mark this DoD item "pending operator").
- [ ] **No deterministic EVR comparison introduced** (grep: no version-compare/`vercmp` helper added).
- [ ] `ruff check . && ruff format --check .` green.
- [ ] `mypy app/` green.
- [ ] `pytest` (default / pure-unit selection, Bash `timeout ≤ 120000`) green; `tests/services/test_llm_fingerprints.py`, pass2-enqueue and pass2-prompt render tests extended.
- [ ] **ADR-0068** created (re-opens ADR-0066 for the prompt; amends ADR-0023 caching with the cache_key-on-eval gate + added fingerprint inputs); cross-linked.
- [ ] `ARCHITECTURE.md` §12 updated (cache invalidation now reacts to running kernel / host_update).

---

## 8. Test & process guardrails (verbatim, from CLAUDE.md)

Allowed quality gates: `ruff`, `ruff format --check`, `shellcheck` (linter), `mypy app/`, `pytest` default selection (pure-unit). Forbidden (no proactive runs, no new `.bats`/`.sh` test files): db_integration / acceptance / integration / bench / `RUN_E2E` / Docker-Compose / browser tests. The **Alembic roundtrip and any Postgres-reflection tests run only on explicit operator approval per run**; otherwise mark the DoD item "pending operator". Every `pytest` Bash call carries a `timeout` ≤ 120000 ms (default) / ≤ 60000 ms (focused sub-run). New docs/comments/UI strings: English. No `|safe` on LLM/client data; SQLAlchemy with bound parameters only.

If a behavioral eval of the new prompt against the server-15 fixtures is wanted (running ≥ fixed → noise; running < fixed → actionable), it is a pure-unit reviewer-verdict test with a stubbed LLM, allowed under the default selection.

---

## 9. Suggested implementation order

1. ADR-0068 draft (records the prompt re-open + the two-gate invalidation decision).
2. Part C (fingerprints) — smallest, pure-unit; foundation for the cache key.
3. Part A (prompt + version bump) — pure-unit render + reviewer-verdict tests.
4. Part B (schema + migration + worker write + enqueue compare) — migration roundtrip handed to operator.
5. Tests green (`ruff`/`mypy`/`pytest`), `ARCHITECTURE.md`, ADR finalized.
6. Deploy; confirm server 15 re-evaluates via re-scan/backstop (purge only as fallback, §6).
