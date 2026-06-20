# TICKET-020 — Migrate the runtime base image to AlmaLinux 10-minimal (Debian `python:3.13-slim-trixie` → EL10), incl. docs sweep

**Status:** Open · **Date:** 2026-06-20
**Refs:** [ADR-0069](../decisions/0069-runtime-base-image-almalinux-10-minimal.md) (the decision — read first), [ADR-0032](../decisions/0032-frontend-build-plain-css.md) (multi-stage build / no Node runtime in prod — builder & frontend stages unchanged), `ARCHITECTURE.md` §3 (tech stack) / §4 (deployment topology), `.trivyignore` (Debian-tracker suppression list — replaced). **No new block document** (small, self-contained infra change). **No new ADR** (ADR-0069 covers it).
**Components:** `Dockerfile` (builder + runtime-builder stages, healthcheck), `docker-compose.yml` (app + worker healthcheck), `.trivyignore` (re-curate vs. Alma errata), `ARCHITECTURE.md`, `README.md` (audit only — see §4 guard), `docs/operations.md` (air-gap base-image mirror), `CLAUDE.md` (tech-stack constant), `.github/workflows/{trivy,release}.yml` (comments + air-gap mirror note). Tests: pure-unit only (no app code changes); build/boot/scan validation is operator-gated.
**Migration:** none (no schema, no Alembic).

---

## 0. Onboarding (base not assumed)

Self-hosted Trivy filesystem-scan triage aggregator (Flask + Jinja2 + HTMX + Alpine.js, PostgreSQL 17, single-user, air-gap-first). The runtime image is a multi-stage Docker build (`Dockerfile`): a `python:3.13-slim-trixie` **builder** produces `/opt/venv`; a `node:20-alpine` **frontend-build** produces static assets; a `runtime-builder` (also `slim-trixie`) installs runtime libs, strips the image, creates a non-root user; a final `FROM scratch` flattens it. Read `CLAUDE.md` — especially the **test convention** (only `ruff` / `ruff format --check` / `shellcheck` (linter) + `mypy app/` + pure-unit `pytest` default selection; **no** db_integration / acceptance / integration / bench / bats / `RUN_E2E` / Docker-build / Docker-compose / browser runs proactively; **no new `.bats`/`.sh` test files without explicit operator approval**; every `pytest` Bash call carries `timeout ≤ 120000 ms`) and the **language policy** (all new docs/comments English; translate-on-touch for legacy German). Read ADR-0069 first — this ticket implements it.

A throwaway spike (`spike/distroless-runtime`, 2026-06-20, since deleted) established the load-bearing facts: native wheels are `manylinux_2_28`/abi3 + `psycopg[binary]` bundles libpq → glibc satisfies them with **no compilation**; and a builder/runtime **interpreter-path mismatch** breaks the venv at boot (the distroless `ELF / source code cannot contain null bytes` crash). Both inform the fix below.

---

## 1. Problem

The Trivy code-scanning surface is dominated by **Debian OS-package noise**, not app risk. Of 44 open alerts (2026-06), only 3 are Python deps with a fix; 41 are Debian OS packages, almost all `note`/`UNKNOWN` **with no upstream fix**. The repo neutralises these with a hand-curated `.trivyignore` (~90 Debian-tracker IDs) that is pure maintenance burden and re-grows on every base bump.

Root cause is a reporting-model mismatch: **Debian/Ubuntu report unfixed CVEs.** The Debian Security Tracker marks large numbers of entries "affects package, no fix planned / minor"; Trivy shows them by default even when no fixed version exists. **AlmaLinux ships authoritative OVAL/errata (ALSA):** Trivy maps EL findings onto real errata with "not affected / out of support scope" statements and **backport-aware fixed versions**, eliminating both the no-fix-but-listed entries and the classic "package looks old but is actually backport-patched" false signal. See ADR-0069 §Context for the full rationale and for why **AlmaLinux 9.8 was rejected** (no `python3.13` in EL9 AppStream → source build) and **distroless was rejected** (boot crash + no size win + still Debian-tracker data).

---

## 2. Goal

The runtime image is built on **AlmaLinux 10-minimal**; the first Alma Trivy scan produces a dramatically shorter, errata-mapped finding set, and the `.trivyignore` is re-curated from near-zero. Python runs on EL10's AppStream **`python3.14`** (EL10 has no 3.13) **without a source build**; `requires-python >= 3.13` in pyproject is satisfied by 3.14 and stays as-is. The app boots and serves exactly as today (`entrypoint.sh` → DB wait → `alembic upgrade head` → gunicorn `/healthz`), the non-root user is preserved, and all docs naming the base OS are corrected.

---

## 3. Fix — Dockerfile

Builder/frontend **shape** unchanged (ADR-0032); only base FROMs and the package manager change.

- **Builder stage** → `FROM almalinux:10`. Replace the `apt-get install build-essential libpq-dev libffi-dev` with `dnf install -y python3.14 python3.14-devel python3.14-pip gcc libffi-devel openssl-devel` (toolchain is a safety net for any sdist-only dep; binary wheels are expected to cover everything; `python3.14-pip` gives the venv ensurepip/pip). `python3.14 -m venv /opt/venv`; the two-layer pip install (deps, then `--no-deps` app) is unchanged. EL10 ships **no python3.13** — the AppStream stream is `python3.14` (see ADR-0069 amendment).
- **Frontend-build stage** → **unchanged** (`node:20-alpine`).
- **Runtime-builder stage** → `FROM almalinux:10-minimal`. Replace `apt-get install libpq5 curl` with `microdnf install -y python3.14 glibc-langpack-en shadow-utils && microdnf clean all`. **No libpq** (`psycopg[binary]` bundles it). **No curl** — see healthcheck below. Create the `fathometer` user (uid/gid 1001) with `useradd` (needs `shadow-utils`). Copy `/opt/venv` + app/alembic/agent/frontend-dist as today. **The install `RUN` must NOT be guarded by a trailing `; true`** — that would mask a failed `microdnf install` and let the build continue with a broken base layer (the actual bug: a masked `python3.13`-not-found ran on to `groupadd: command not found`). Keep the install in its **own** `RUN`, separate from the strip `RUN` (whose `2>/dev/null ; true` guards on `rm`s of maybe-absent paths are fine).
- **Interpreter-path consistency (load-bearing, the distroless lesson):** builder and runtime both expose `/usr/bin/python3.14` (Alma's AppStream path). The venv therefore needs **no relocation** — `pyvenv.cfg`/`bin/python` already point at a path that exists at runtime. Do **not** introduce a venv `sed`/relink step.
- **Entrypoint stays `scripts/entrypoint.sh`** — Alma has `/bin/sh`; **no `entrypoint.py` rewrite** (that was a distroless-only need).
- **Stripping block rewritten for the RHEL layout, as its own `RUN`:** `/usr/lib64` instead of `/usr/lib/<triplet>`; locale via installing only `glibc-langpack-en` (not post-hoc `find /usr/share/locale … -delete`); `/usr/lib64/python3.14` stdlib pruning; perl-base is typically absent on minimal (drop that removal). The `FROM scratch` flatten stage stays (OS-agnostic).
- **Healthcheck** (`Dockerfile` `HEALTHCHECK`): `curl -fsS http://127.0.0.1:8000/readyz` → a Python `urllib` probe, e.g. `CMD ["/opt/venv/bin/python","-c","import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz').status==200 else 1)"]`. Dropping curl also removes the libcurl→krb5/ldap/libssh2/gnutls transitive group that today needs suppression.

### `.trivyignore`

The current ~90 entries are **all Debian-tracker IDs** and become moot. Replace the file (or empty it down to a short, header-documented EL-errata-keyed set) after the first Alma scan. Keep the file's "scope is intentionally narrow / one ID per evaluated finding" philosophy.

---

## 4. Docs to update (explicit — do not skip)

| File | Change |
|------|--------|
| `ARCHITECTURE.md` **§3 / line ~41** | "The production image (`python:3.13-slim`)…" → `AlmaLinux 10-minimal`. Add one sentence on *why* (EL10 AppStream python3.14 — EL10 has no 3.13; OVAL/ALSA errata signal) — keep it short, link ADR-0069. |
| `ARCHITECTURE.md` §4 (deployment) | If any "Debian"/apt phrasing exists in the image/deploy prose, correct it. |
| `docs/operations.md` | Air-gap section: add "mirror the AlmaLinux 10-minimal base image into the internal registry" (symmetric to the existing `python:slim` mirror expectation). Translate the section header/intro to English if touched (legacy German lines 3–4). |
| `CLAUDE.md` | Tech-stack constants: add/adjust a **Runtime base: AlmaLinux 10-minimal** line next to "PostgreSQL 17 in eigenem Container" so the base OS is a recorded constant (it currently is not). |
| `.github/workflows/trivy.yml`, `release.yml` | Update comments referencing "trixie userland" / the `python:3.13-slim-trixie` digest auto-invalidation; ensure the air-gap base-image mirror is noted. `release.yml` builds the **last** Dockerfile stage with no explicit `target` → the scratch `runtime` stage must remain last (or add `target: runtime`). |
| `README.md` | **Audit only.** The only base-OS-ish hit is **line ~296 "Supported: Debian/Ubuntu, RHEL family (AlmaLinux, …)"** — this is the **scan-target host support matrix** (which OSes the *agent* can scan), **NOT** our container base image. **Do NOT change it.** Only edit README if a *new* base-OS claim is found elsewhere (e.g. a tech-stack/badge line). |

---

## 5. Definition of Done (machine-checkable where possible)

- [ ] `Dockerfile`: builder `FROM almalinux:10` (dnf toolchain); runtime-builder `FROM almalinux:10-minimal` (microdnf, `python3.14 glibc-langpack-en shadow-utils`, `clean all` — own `RUN`, no `; true`); no libpq/curl; `useradd` user 1001; stripping block rewritten for `/usr/lib64`; scratch-flatten kept; Python `urllib` HEALTHCHECK. No venv relocation step.
- [ ] `docker-compose.yml`: `app` (and `fathometer-llm-worker` if it inherits the curl healthcheck) healthcheck switched off curl to the Python probe.
- [ ] `.trivyignore` replaced/trimmed to EL-errata-keyed entries (or emptied with an updated header) — no stale Debian IDs.
- [ ] Docs updated per §4; **README line ~296 untouched**; any touched German prose translated to English.
- [ ] `ruff check . && ruff format --check .` and `mypy app/` green (no app code changed, keep gates green). `shellcheck scripts/entrypoint.sh` clean (unchanged, re-confirm).
- [ ] Pure-unit only. No new `.bats`/`.sh` test files. (Nothing here is pure-unit-testable beyond the lints; the real validation is the operator-gated build below.)

### Operator-gated validation (heavy gates — run only on explicit operator instruction, per CLAUDE.md)

- [ ] `microdnf install python3.14` resolves cleanly on `almalinux:10-minimal` and lands `/usr/bin/python3.14`; `useradd` available via `shadow-utils`.
- [ ] Builder venv import-smoke: `cryptography`, `psycopg`, `argon2`, `nh3`, `trafilatura`, `sqlalchemy`, `gunicorn`, `alembic` import (no missing `.so`).
- [ ] Full boot: `docker compose up --build` → 3 containers healthy → `/healthz` 200; `entrypoint.sh` runs `alembic upgrade head` and execs gunicorn.
- [x] Image size measured: **~249 MB** (arm64, 2026-06-20). The **200 MB cap was raised to 256 MB** (operator decision; AlmaLinux userland > Debian-slim, sub-200 needs fragile system-lib removal). O-risk-engine.md DoD + ADR-0069 updated. **Open:** confirm the amd64 release build also fits 256 MB in CI.
- [ ] First Alma Trivy image scan captured; the new `.trivyignore` seeded from it; confirm the finding count/noise dropped vs. the Debian baseline.

---

## 6. Test & process guardrails (verbatim, from CLAUDE.md)

Allowed quality gates: `ruff`, `ruff format --check`, `shellcheck` (linter), `mypy app/`, `pytest` default selection (pure-unit). Forbidden (no proactive runs, no new `.bats`/`.sh` test files without explicit operator approval): db_integration / acceptance / integration / bench / `RUN_E2E` / Docker-build / Docker-compose / live-runtime / browser tests. Every `pytest` Bash call carries a `timeout` ≤ 120000 ms (≤ 60000 ms for a single focused file). New docs/comments English; translate-on-touch for legacy German.

---

## 7. Notes / relation to other work

- **Orthogonal, not blocked on this ticket:** the two Python-dep fixes surfaced in the same scan — `cryptography` 48.0.0 → 48.0.1 (HIGH) and `pydantic-settings` 2.14.1 → 2.14.2 (MEDIUM). Bump independently in `uv.lock`/`pyproject.toml`; they are real app-dep risk, this ticket is base-OS only.
- **Rejected alternatives** (full rationale in ADR-0069): AlmaLinux 9.8 (no python3.13 in EL9 AppStream → CPython source build, self-owned patching); distroless `python3-debian13` (unresolved boot crash from venv relocation, 226 MB vs. 192 MB so no size win, and still rides the Debian-tracker feed we are leaving).
- **Size is expected to be roughly a wash** — the venv is the bulk on either OS. The win is **CVE-signal quality (OVAL/ALSA), not image size**; do not sell this as a size optimisation.
- **`shellcheck` of the agent** and the agent's own host-OS support (it scans Debian/Ubuntu/RHEL/Alpine hosts) are entirely independent of our container base — no agent change here.
