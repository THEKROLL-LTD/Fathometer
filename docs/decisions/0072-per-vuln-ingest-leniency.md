# ADR-0072 — Per-item leniency for the vulnerability list + widened identifier scope

**Status:** Accepted · **Date:** 2026-08-06

Refs: TICKET-021, TICKET-018 (same structural bug in `host_state`, same fix), ARCHITECTURE.md §9 ("whatever does not match is **dropped**"), [ADR-0026](0026-async-scan-ingest.md) (the worker marks a job `failed` on `ValidationError`). Issue #23.

## Context

A Debian 13 host running Trivy 0.71.0 uploaded a scan the API accepted but the ingest worker rejected in full, over two single entries: a `VulnerabilityID` of `TEMP-…` (a Debian Security Tracker temporary name, which our whitelist did not know) and a `Title` longer than 512 chars.

`TrivyResult.vulnerabilities` was typed `list[TrivyVulnerability]`, so one bad entry aggregated into a `ValidationError` over the whole envelope and discarded hundreds of valid findings on every timer cycle. The `_safe_vuln` net in `findings_ingest` could never fire — it only ever saw already-validated objects.

## Decision

**1 — Filter `vulnerabilities` per entry.** A `mode="before"` validator runs each raw entry through `TrivyVulnerability.model_validate` via `_filter_entries` (the TICKET-018 helper); non-conforming entries drop themselves. Top-level and structural errors still fail the envelope.

Because `mode="before"` runs ahead of the field's `max_length`, the raw list is truncated to `MAX_VULNS_PER_SCAN` before any item is validated — without that, an attacker-supplied array would cost one `model_validate` per element. The field constraint stays as defense-in-depth; the cross-result cap is untouched.

**2 — Count what is dropped.** "Scan lost, loudly" must not become "findings vanish, silently". The caller passes a dict through the Pydantic validation context; the filter records the drop count and one sanitized error sample per scan. It surfaces as `vulns_dropped` in the `scan.ingested` audit metadata, the job `result` JSONB, and one log line.

**3 — Widen the identifier whitelist, curated.** §9's whitelist doctrine stays; the list grows to what real Trivy output carries, each pattern anchored:

| Pattern | Source |
| --- | --- |
| `^TEMP-\d{6,10}-[0-9A-F]{6}$` | Debian Security Tracker temporary names (the reported case) |
| `^DSA-\d{3,5}-\d{1,2}$`, `^DLA-\d{3,5}-\d{1,2}$` | Debian advisories |
| `^RUSTSEC-\d{4}-\d{4}$`, `^GO-\d{4}-\d{4,}$`, `^PYSEC-\d{4}-\d{1,5}$` | OSV ecosystem identifiers |

The patterns live in `app/schemas/vuln_identifiers.py` and are shared with bulk-acknowledge, which validated `cve_id` against its own CVE-only copy — a whitelist maintained in two places is how this class of bug starts.

**4 — Trim `title`/`description` instead of rejecting.** Both are display-only. The caps move off the field into the validator, matching `cwe_ids`/`references` (v0.6.1): a field constraint fires first and would reject where a trim is intended.

## Consequences

- A scan with isolated bad entries now ingests; the drops are counted and logged.
- Silent data loss is the risk this introduces by design, which is what decision 2 exists for. Surfacing the count in the UI is out of scope.
- **`TEMP-*` identifiers are not stable** — Debian states they can change when the database updates. Findings are keyed on `(identifier_key, package_name)`, so a later rename shows up as one finding resolving and another appearing. Accepted.
- Non-CVE identifiers get no EPSS/KEV enrichment (both join on `cve_id`), which is correct — no CVE exists yet. Risk-band logic must not assume enrichment is present.
- No migration, no agent, UI or LLM change. Server-side only; already-failed jobs are not backfilled (their payload is dropped on failure — a fresh agent run is simpler).

## Re-open triggers

- `TEMP-*` renames prove noisy → reconsider the dedup key.
- A Trivy data source emits a new identifier family → extend the list (cheap now).
- Operators want drop counts in the UI → surface `vulns_dropped` on the server-detail page.
