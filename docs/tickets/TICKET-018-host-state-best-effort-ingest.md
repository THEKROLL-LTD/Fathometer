# TICKET-018 — A single malformed listener address discards the whole scan (host_state must be best-effort)

**Status:** Open · **Date:** 2026-06-17 · **Refs:** scan-envelope schema docstring (`app/schemas/scan_envelope.py:786–789`, which already *claims* per-item listener leniency but does not deliver it), TICKET-005 (host-state/OOB drift), agent host-state collection (`agent/lib_host_state.sh`).
**Components:** `app/schemas/scan_envelope.py` (`ListenerEntry._validate_addr`), `app/services/scan_processing.py` (`Envelope.model_validate` wiring), `agent/lib_host_state.sh` (`_parse_addr_port`), `app/views/audit_view.py` (`KNOWN_ACTIONS`), `app/views/server_detail.py` + server-detail template (failure indicator), `app/workers/scan_ingest_worker.py` (validation-error path, read-only context), tests.
**Scope:** Schema validator + ingest leniency wiring + agent bash parsing + audit vocabulary + one UI indicator + tests. No DB migration, no LLM contract, no schema-column change.

## Problem (observed 2026-06-17)

An agent on `gitlab02` (Ubuntu 22.04, behind a VPN) uploads a scan. The API accepts it: `POST /api/scans` → `202`, `job_id=27`, audit events `scan.queued` and `api.scans.async_queued` are emitted. Then the scan **disappears with no trace in the frontend** — no host snapshot update, no error banner, nothing.

The LLM worker (which owns the scan-ingest sub-tick — there is no separate ingest container) does pick the job up and logs:

```
WARNING fathometer.scan_ingest_worker scan_ingest_worker.validation_error job_id=27
  error=8 validation errors for Envelope
  host_state.listeners.9.addr
    Value error, addr ist kein gueltiges IP-Literal: [fe80::53a0:796a:5d2:96c1]
    input_value='[fe80::53a0:796a:5d2:96c1]'
audit.logged action=scan.ingest_failed target_id=27 target_type=scan_ingest_job
```

`[fe80::53a0:796a:5d2:96c1]` is the link-local IPv6 address of the host's `tun0` VPN interface (`ip addr`: `inet6 fe80::53a0:796a:5d2:96c1/64 scope link stable-privacy`). One cosmetic listener entry kills the entire scan, **including all vulnerability findings**, and the operator never sees it.

## Root-Cause

Three independent defects compound:

### (a) Agent does not strip brackets when a zone id is present

`agent/lib_host_state.sh` `_parse_addr_port` (~lines 89–112):

```bash
# IPv6 with brackets: [::]:22  -> addr=::  port=22
if [[ "$token" =~ ^\[(.*)\]:([0-9]+)$ ]]; then     # bracket branch
  addr="${BASH_REMATCH[1]}"
  port="${BASH_REMATCH[2]}"
else
  port="${token##*:}"
  addr="${token%:*}"
  [[ "$addr" == "*" || -z "$addr" ]] && addr="0.0.0.0"
  addr="${addr%%%*}"                                # zone strip — ONLY in else branch
fi
```

For an `ss` token like `[fe80::53a0:796a:5d2:96c1]%tun0:22` the bracket regex `^\[(.*)\]:([0-9]+)$` does **not** match (after `]` comes `%tun0:`, not `:`), so it falls into the `else` branch. There the zone is stripped (`addr%%%*`) but the **brackets are not** — bracket stripping lives only in the other branch. Result: `addr = [fe80::53a0:796a:5d2:96c1]` (literal brackets, zone gone). A bare `[::]:22` matches the bracket branch and strips correctly — the break case is specifically *brackets plus `%zone`*.

### (b) Server validator rejects bracketed / zoned literals

`app/schemas/scan_envelope.py` `ListenerEntry._validate_addr` (~lines 804–815) runs `ipaddress.ip_address(v)` on the raw string. `ipaddress.ip_address("[fe80::1]")` raises `ValueError` (brackets unsupported) → exactly the logged message. (A bare `fe80::1%eth0` zone *is* accepted by the Python 3.13 stdlib; the bracket form is the hard failure.)

### (c) One bad listener fails the whole envelope — the real defect

`app/services/scan_processing.py:196` validates the full nested tree in one shot:

```python
envelope = Envelope.model_validate(raw_doc)   # may raise ValidationError; worker marks job failed
```

`Envelope.host_state.listeners: list[ListenerEntry]` is validated as part of this monolithic call, so a single invalid `ListenerEntry.addr` aggregates into one `ValidationError` over the **entire envelope** (the "8 validation errors" = 8 such listeners) and propagates before `run_ingest`. The **vulnerability findings — the product's whole purpose — are discarded over a cosmetic host-state detail.** The schema docstring at lines 786–789 *claims* a rejected `ListenerEntry` "only kills that entry"; nothing wires that up.

### (d) The failure is invisible in the UI

`scan_ingest_worker` marks the job `failed` and emits audit `scan.ingest_failed` with `error_class="validation_error"`, but:
- No view/template surfaces failed ingests — the server-detail page shows only the last *successful* snapshot, leaving stale data with no indicator.
- `scan.ingest_failed` / `host_state.parse_failed` are **not** in `KNOWN_ACTIONS` (`app/views/audit_view.py:122–156`), so an operator cannot even filter the audit log for them.

## Solution

host_state ingest becomes **best-effort and must never block the vulnerability ingest.** Four layers:

### 1 — Server resilience (the durable fix; covers all agents already in the field)

- **Normalize in `_validate_addr`:** before `ipaddress.ip_address()`, strip a single surrounding `[…]` pair and a trailing `%zone` suffix, then validate, and return the normalized form (store normalized). `String(64)` / `MAX_LISTENER_ADDR_LENGTH=64` has headroom.
- **Per-listener leniency:** a malformed `ListenerEntry` (or any best-effort host_state sub-entry) drops only that entry — logged and counted — while the rest of host_state and **all** vulnerability findings ingest normally. Wire this around `Envelope.model_validate` in `scan_processing.py` (e.g. validate listeners item-by-item / coerce the bad ones out before the monolithic validate, mirroring the per-vuln leniency that `findings_ingest` already has). The vulnerability path is untouched.

Server-side is primary because old agents in the field keep sending bracketed addresses until re-rolled, and leniency guards the **entire class** of malformed-host_state bugs, not just this address shape.

### 2 — Agent hygiene

`agent/lib_host_state.sh` `_parse_addr_port`: strip brackets **and** `%zone` uniformly, including the `]%zone:port` token shape. New agents then emit clean literals. `shellcheck` must stay green.

### 3 — Visibility

- Add `scan.ingest_failed` and `host_state.parse_failed` to `KNOWN_ACTIONS` (`audit_view.py`) so failures are filterable.
- Server-detail page: a small indicator when the last ingest failed and/or N host_state entries were dropped, so a silently-lost scan (or partial host_state) is visible to the operator.

### 4 — Tests (pure-unit)

- `_validate_addr`: accept `[fe80::53a0:796a:5d2:96c1]%tun0`, `[fe80::1]`, `[::1]`, `fe80::1%eth0` (all normalize to a bare literal); reject genuinely garbage input.
- **Behaviour flip:** the existing reject case `("[::1]", "addr")` in `tests/adversarial/test_listener_addr_validation.py:44` becomes an accept-after-normalization case — intentional change, call it out.
- Leniency: an envelope with one malformed listener + several valid listeners + vulnerability findings → scan ingests, vulns present, the bad listener is dropped (and counted), the valid listeners remain.
- Agent parsing: cover `_parse_addr_port` for `[fe80::…]%tun0:22`, `[::]:22`, `*:22`, `0.0.0.0:22` (via the existing Python compat mirror; no new `.bats`/`.sh` files).

## Definition of Done (machine-checkable)

- [ ] `ListenerEntry._validate_addr` strips a surrounding `[…]` pair and a trailing `%zone` before `ipaddress.ip_address()` and returns the normalized literal. (`app/schemas/scan_envelope.py`)
- [ ] An envelope whose `host_state.listeners` contains at least one invalid `addr` still ingests: scan row created, all vulnerability findings present, invalid listener(s) dropped and counted, valid listeners retained. (`app/services/scan_processing.py` + pure-unit test)
- [ ] `agent/lib_host_state.sh` `_parse_addr_port` strips brackets **and** `%zone` for the `[fe80::…]%tun0:22` token shape; `shellcheck` green.
- [ ] `scan.ingest_failed` and `host_state.parse_failed` present in `KNOWN_ACTIONS` (`app/views/audit_view.py`).
- [ ] Server-detail surfaces a last-ingest-failed / dropped-host_state-entries indicator (template + view).
- [ ] Pure-unit test: `_validate_addr` accepts `[fe80::53a0:796a:5d2:96c1]%tun0`, `[::1]`, `fe80::1%eth0`; the prior reject case at `test_listener_addr_validation.py:44` is flipped to accept-after-normalization.
- [ ] Pure-unit test: leniency case (one bad + many good listeners → scan + vulns survive, bad listener dropped).
- [ ] `ruff check . && ruff format --check .` green.
- [ ] `mypy app/` green.
- [ ] `pytest` (default / pure-unit selection) green.

## Test convention (subagent obligation, verbatim)

Allowed quality gates: ruff, mypy, shellcheck (linters), pytest default selection (pure-unit). Forbidden: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/browser tests — no proactive runs, no new `.bats`/`.sh` test files. Every `pytest` bash call carries an explicit `timeout` ≤ 120000 ms (default suite) / ≤ 60000 ms (focused sub-run).

## Rollout

Deploy the server fix first (covers `gitlab02` and every field agent immediately), then re-run the agent on `gitlab02` — job 27's payload is retained ~24 h, but a fresh agent run is the simpler path and will now ingest. The agent-script fix (layer 2) ships on the normal agent-update channel.

## Risk / Non-Goal

- host_state is explicitly **advisory/best-effort**; it must never gate vulnerability ingest. This ticket does not change what counts as a valid finding.
- Normalization stores the bare literal (brackets/zone removed). Zone information is not retained — link-local addresses are never publicly exposed, so the exposure classifier is unaffected.
- No new audit semantics beyond making the existing `scan.ingest_failed` / `host_state.parse_failed` actions filterable and visible.
