# TICKET-021 — A single non-conforming Trivy vulnerability discards the whole scan (vuln ingest must be per-item best-effort)

**Status:** Implemented 2026-08-06 on branch `fix/ticket-021-per-vuln-ingest-leniency` (uncommitted) · **Date:** 2026-08-05 · **Target release:** v0.28.1 · **Refs:** [GitHub issue #23](https://github.com/THEKROLL-LTD/Fathometer/issues/23) (reporter `HeartBtz`, Trivy 0.71.0 on Debian 13 Trixie), TICKET-018 (same bug class, solved for `host_state` — the direct precedent), ARCHITECTURE §9, scan-envelope schema docstring (`app/schemas/scan_envelope.py:333–335`, which already *claims* per-vuln leniency but does not deliver it).
**Components:** `app/schemas/scan_envelope.py` (`TrivyResult.vulnerabilities`, `TrivyVulnerability._validate_vuln_id`, `title`/`description` fields), `app/services/findings_ingest.py` (`_safe_vuln`, `ScanIngestResult`), `app/services/scan_processing.py` (`ScanProcessingResult`, `Envelope.model_validate` wiring), `app/workers/scan_ingest_worker.py` (job-result JSONB), ARCHITECTURE §9, new ADR-0072, tests.
**Scope:** Schema per-item leniency + identifier whitelist widening + two display-field trims + drop counters through the ingest result. No DB migration, no column change, no LLM contract change, no agent change, no UI work.
**Protected — deliberately in scope here, flag in the PR:** the `MAX_VULNS_PER_SCAN` DoS bound. Solution §1 moves the cap to *before* per-item validation; getting that order wrong turns an attacker-supplied array into unbounded work. Everything else under `app/schemas/scan_envelope.py` is ordinary. No auth, key-handling, migration or rate-limit surface is touched.

## Problem (reported 2026-08-05, issue #23)

An agent on Debian 13 (Trixie) with Trivy 0.71.0 uploads a scan. The API accepts it — the agent prints `[fathometer-agent] Scan accepted (job_id=4)`. The asynchronous ingest worker then rejects the **entire report** over a single vulnerability entry, and the UI shows only:

> The most recent scan upload was rejected (validation error).

Two independent failures were observed on otherwise valid reports.

**Case 1 — identifier format:**

```text
scan_ingest_worker.validation_error
scan.Results.0.Vulnerabilities.36.VulnerabilityID
Value error, VulnerabilityID muss CVE-YYYY-NNNN oder GHSA-xxxx-xxxx-xxxx sein
input_value='TEMP-...'
```

**Case 2 — title length** (after the reporter locally patched case 1):

```text
scan_ingest_worker.validation_error
scan.Results.0.Vulnerabilities.472.Title
String should have at most 512 characters
```

Neither entry is malformed scanner output. Both are legitimate Trivy 0.71.0 values that our schema is narrower than. The result is total data loss: hundreds of valid findings for that host are discarded, repeatedly, on every timer cycle.

## Root cause

Three defects compound — one structural, two field-level.

### (a) The vulnerability list is validated monolithically — the real defect

`app/services/scan_processing.py:196` validates the full nested tree in one shot:

```python
envelope = Envelope.model_validate(raw_doc)   # may raise ValidationError; worker marks job failed
```

`TrivyResult.vulnerabilities` is typed `list[TrivyVulnerability]` (`scan_envelope.py:673–675`), so Pydantic validates **every** vulnerability as part of this single call. One failing item aggregates into a `ValidationError` over the whole envelope, which propagates before `run_ingest` and is caught by the worker's validation-error path (`scan_ingest_worker.py:318–326`), marking the job `failed`.

The intended safety net exists but can never fire. `_safe_vuln` (`findings_ingest.py:115`, called at `:443`) is written to swallow a per-vuln validation error and skip that item — and `TrivyVulnerability`'s docstring (`scan_envelope.py:333–335`) advertises that the ingest service *can* discard a single vulnerability. But `_safe_vuln` only ever receives objects that Pydantic has *already* validated; its own call site says so (`"raw_vuln ist bereits durch Pydantic gelaufen"`). For this failure mode it is dead code.

This is the identical structural bug TICKET-018 fixed for `host_state.listeners`/`processes`. That ticket's solution section even cites "the per-vuln leniency that `findings_ingest` already has" as the pattern to mirror — a guarantee that, as this ticket shows, was never actually wired up on the vulnerability path either. Note that `docs/tickets/TICKET-018-host-state-best-effort-ingest.md` still carries `Status: Open` although the fix has landed (`_filter_entries`, `scan_envelope.py:909`, wired to `listeners` at `:971` and `processes` at `:976`). Read it for the pattern, not for the status.

Note that ARCHITECTURE §9 already prescribes the correct behaviour: *"Whatever does not match is **dropped** — no best-effort sanitization."* The spec says drop the item; the implementation rejects the scan. **Fixing (a) requires no spec change — it is a pure bug fix.**

### (b) The identifier whitelist is narrower than the real Trivy output

`scan_envelope.py:95–97` and the validator at `:415–420`:

```python
_CVE_ID_RE  = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_GHSA_ID_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
```

`TEMP-*` identifiers are **Debian Security Tracker** temporary names, assigned when an issue is tracked but has no CVE yet. Trivy's Debian data source passes them through verbatim as `VulnerabilityID`. Verified against the tracker's own documentation ([`/tracker/data/fake-names`](https://security-tracker.debian.org/tracker/data/fake-names)):

> "the first kind starts with the string `TEMP-000000-`. This means that no Debian bug has been assigned to this issue (or a bug has been created and is not recorded in this database). In the second kind of names, there is a Debian bug for the issue, and the `000000` part of the name is replaced with the Debian bug number."

Real, currently-published examples (fetched 2026-08-05):

| Identifier | Source package | Description |
| --- | --- | --- |
| `TEMP-0000000-E57E4E` | `opensmtpd` | Remotely triggerable buffer overflow in OpenSMTPD |
| `TEMP-0290435-0B57B5` | `tar` | `rmt` command issue |
| `TEMP-0517018-A83CE6` | `sysvinit` | security flaw |
| `TEMP-1142894-39EC25` | — | Stack buffer overflow |

Observed shape: `TEMP-` + a 7-digit Debian bug number (all-zero when unassigned) + `-` + 6 uppercase hex characters. On a Debian host this is not an edge case — it occurs on every scan, not sporadically.

`TEMP-*` is also not the only non-CVE/non-GHSA identifier Trivy emits; for lang-pkgs it passes through OSV identifiers (`RUSTSEC-*`, `GO-*`, `PYSEC-*`) and distro advisories (`DSA-*`, `DLA-*`). Only `TEMP-*` is confirmed from the field report; the rest are covered defensively.

### (c) `title`/`description` reject instead of trimming

`MAX_TITLE_LENGTH = 512` (`scan_envelope.py:139`) is a chosen cap, not a format limit. Trivy's `Title` is the advisory `summary` for OSV/GHSA sources and effectively the first line of the description for many os-pkgs entries — neither is length-bounded. In a report with 472+ vulnerabilities in the first result, exceeding 512 characters is close to certain.

The project already learned this lesson and did not apply it to these two fields. `scan_envelope.py:386–389` states it explicitly for `cwe_ids` (`:390`) and `references` (`:391`); `vendor_ids` (`:404`) carries its own comment at `:402–403` referring back to it:

> `max_length` bewusst NICHT am Field — der `field_validator` darunter cleant Junk und trimmt auf das Maximum. Field-Constraints feuern als Built-in-Validation VOR `@field_validator(mode="after")` und wuerden einen Reject ausloesen statt das beabsichtigte Trim (siehe v0.6.1).

`title` and `description` (`:371–372`) still carry `max_length` on the field, so they reject where they should trim.

## Decisions taken (operator sign-off 2026-08-05)

- **D1 — identifier whitelist: curated list**, not a generic pattern. Keeps the §9 whitelist doctrine intact. Acceptable precisely *because* fix (a) lands first: after it, an unknown identifier format costs one vulnerability instead of the whole scan.
- **D2 — over-long `title`/`description`: trim, do not drop.** They are display-only fields with no security semantics, and the trim pattern is already established for `cwe_ids`/`references`/`vendor_ids`.
- **D3 — fixture uses a real Debian identifier** (`TEMP-0000000-E57E4E`, opensmtpd), not an invented one.

## Solution

Vulnerability ingest becomes **per-item best-effort**: a non-conforming entry drops only itself, counted and logged, and never blocks the remaining findings.

### 1 — Per-vuln leniency (the durable fix)

- Give `TrivyResult.vulnerabilities` a `mode="before"` validator following `_filter_entries` (`scan_envelope.py:909`), which TICKET-018 introduced for the same purpose.
- **Carry over the security-auditor requirement verbatim:** because `mode="before"` runs *before* the field's `max_length`, the raw list must be truncated to `MAX_VULNS_PER_SCAN` **before** any per-item `model_validate`, restoring the O(cap) bound against an attacker-supplied array. Truncation is silent; the field `max_length` stays as defense-in-depth.
- Verify the cross-result cap in `TrivyReport` (`scan_envelope.py:712`, total across all results vs. `MAX_VULNS_PER_SCAN`) still holds once it counts filtered rather than raw lists.
- Correct the `TrivyVulnerability` docstring (`:333–335`) and the `_safe_vuln` call-site comment (`findings_ingest.py:441–442`): both currently assert a guarantee the code does not provide.

### 2 — Observability (not optional)

Without this we trade "scan lost, loudly" for "findings vanish, silently" — the worse failure for a security tool.

- Count dropped entries per result; aggregate through `ScanIngestResult` (`findings_ingest.py:72`) and `ScanProcessingResult` (`scan_processing.py:62`) into the job's `result` JSONB — `result_to_jsonb` is defined at `scan_ingest_worker.py:138` and called at `:289`; the new field has to be added at the definition.
- Log one `log.info` per scan with the drop count and the first error sample (truncated), not one line per dropped item.

### 3 — Field rules matched to reality

- **Identifiers (D1).** Extend the whitelist beyond CVE/GHSA with, each anchored and length-bounded: `TEMP-\d{6,10}-[0-9A-F]{6}` (bug-number width deliberately tolerant — Debian bug numbers grow), `DSA-\d{3,5}-\d{1,2}`, `DLA-\d{3,5}-\d{1,2}`, `RUSTSEC-\d{4}-\d{4}`, `GO-\d{4}-\d{4,}`, `PYSEC-\d{4}-\d{1,5}`. `VulnerabilityID` keeps `max_length=64`; `identifier_key` is `String(128)` (`app/models.py:405`), so there is headroom.
- **Error message → English.** `scan_envelope.py:419` is still German; translate-on-touch per the language policy.
- **Fix two stale comments in the same block** — it is being rewritten anyway. `:94` documents the CVE regex as `^CVE-\d{4}-\d{4,}$` while `:95` implements `\d{4,7}` (ARCHITECTURE §9 has it right). `:91` points at "ARCHITECTURE §10" for the whitelist doctrine; it is §9 — §10 is the client agent.
- **`title`/`description` (D2).** Move `max_length` off the field into the `field_validator`, trimming to `MAX_TITLE_LENGTH` / `MAX_STRING_LENGTH` — the `cwe_ids` pattern.

### 4 — Documentation

- **ADR-0072** — per-item leniency doctrine for the vulnerability list plus the widened identifier scope, citing TICKET-018 as precedent.
- **ARCHITECTURE §9** — the section quotes the identifier regex verbatim; update it or spec and code drift.
- **CHANGELOG** — entry under `[Unreleased]`, promoted on the v0.28.1 tag.
- **TD-022** — `bulk_request.cve_id` (`_CVE_ID_RE` defined at `app/schemas/bulk_request.py:42`, applied at `:87`) still accepts CVE only, so bulk-acknowledge *by identifier* does not work for `TEMP-*` findings. Not a breakage (single-finding ack and ack-by-package work), but a deliberately recorded gap.

## Definition of Done (machine-checkable)

- [ ] An envelope whose `Results[].Vulnerabilities[]` contains at least one non-conforming entry still ingests: scan row created, all valid findings present, invalid entries dropped and counted. (`app/schemas/scan_envelope.py` + pure-unit test)
- [ ] The raw vulnerability list is truncated to `MAX_VULNS_PER_SCAN` **before** per-item validation (DoS bound), and an over-long list is capped, not rejected.
- [ ] The cross-result total cap (`TrivyReport`, `scan_envelope.py:712`) still rejects a report exceeding `MAX_VULNS_PER_SCAN` across all results.
- [ ] `TEMP-0000000-E57E4E` and `TEMP-1142894-39EC25` validate as `VulnerabilityID`; `CVE-foo-bar` and other garbage still do not.
- [ ] `DSA-*`, `DLA-*`, `RUSTSEC-*`, `GO-*`, `PYSEC-*` validate per the patterns above.
- [ ] A `Title` of 600 characters is trimmed to `MAX_TITLE_LENGTH` and the vulnerability survives (same for an over-long `Description` against `MAX_STRING_LENGTH`).
- [ ] The drop count reaches the job's `result` JSONB and is visible in the worker log with a truncated first-error sample.
- [ ] The German validator message at `scan_envelope.py:419` is English; `tests/test_ui_language.py` green.
- [ ] `TrivyVulnerability` docstring and the `_safe_vuln` call-site comment no longer claim an unimplemented guarantee.
- [ ] ADR-0072 added; ARCHITECTURE §9 identifier regex updated to match the code; `CHANGELOG.md` entry under `[Unreleased]`; TD-022 recorded in `docs/techdebt.md`.
- [ ] `ruff check . && ruff format --check .` green.
- [ ] `mypy app/` green.
- [ ] `pytest` (default selection) green.
- [ ] `pytest -m "not todo_mock"` green — this ticket's new tests are genuinely pure-unit and must pass without a Postgres on `localhost:55432`.

## Tests (pure-unit)

New `tests/schemas/test_vuln_leniency.py`, structured after `tests/schemas/test_host_state_leniency.py`:

- Envelope with one `TEMP-*` vulnerability **and** several valid ones → envelope parses, valid findings survive, nothing is lost.
- Envelope with one genuinely invalid entry (bad `Severity`, garbage `PkgName`) → that entry is dropped, the rest ingest, the counter reports 1.
- Over-long `Title`/`Description` → trimmed, vulnerability retained.
- Vulnerability list longer than `MAX_VULNS_PER_SCAN` → sliced before per-item validation; holds even when every entry is garbage.
- Cross-result total cap still enforced.
- Drop count propagates into `ScanIngestResult` / `ScanProcessingResult`.
- Identifier table test: accepted formats (CVE, GHSA, TEMP, DSA, DLA, RUSTSEC, GO, PYSEC) vs. rejected garbage.
- Re-check `tests/schemas/test_envelope_cause_fields.py` — no existing reject expectation may silently flip.

## Test convention (subagent obligation, verbatim)

Allowed quality gates: ruff, mypy, shellcheck (linters), pytest default selection. Forbidden: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/browser tests — no proactive runs, no new `.bats`/`.sh` test files. Every `pytest` bash call carries an explicit `timeout` ≤ 120000 ms (default suite) / ≤ 60000 ms (focused sub-run). Note the default selection is not strictly pure-unit: `todo_mock` tests stay in and touch a real Postgres when one is up; `pytest -m "not todo_mock"` is the pure subset.

## Rollout

Server-side only — no agent change, so every field agent is covered the moment v0.28.1 is deployed. The reporter's host recovers on its next timer cycle; no backfill of already-failed jobs is in scope (their `payload_gzip` is dropped on failure, and a fresh agent run is the simpler path). SemVer PATCH: this restores intended, spec-documented behaviour and adds no operator-facing feature.

## Risk / Non-goals

- **Silent data loss is the risk this fix introduces.** Section 2 (counters + log + job result) is therefore part of the fix, not a nice-to-have.
- **`TEMP-*` identifiers are not stable.** Debian states they "can change when the database is updated, so they should not be used in external references." A `TEMP-*` finding can therefore later be renamed or replaced by a CVE, and since findings are keyed on `(identifier_key, package)`, that surfaces as one finding resolving and a new one appearing. Accepted for this ticket; revisit only if it proves noisy in practice.
- **Non-CVE identifiers get no feed enrichment.** EPSS/KEV join on `Finding.identifier_key == cve_id` (`app/services/feed_backfill.py:52`/`:102`), so a `TEMP-*` finding simply carries no EPSS/KEV — correct, since no CVE exists yet. Risk-band logic must not assume enrichment is present.
- Widening the identifier whitelist does **not** change what counts as a valid finding elsewhere, and does not touch the risk engine, the LLM contract, or the agent.
- No UI work: dropped-entry counts live in the job result and the log. Surfacing them on the server-detail page is out of scope here.
