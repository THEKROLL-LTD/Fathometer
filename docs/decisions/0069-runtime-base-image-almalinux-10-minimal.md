# ADR-0069 — Runtime base image: AlmaLinux 10-minimal (replaces Debian `python:3.13-slim-trixie`)

**Status:** Accepted · **Date:** 2026-06-20

> **Amended 2026-06-20:** target **python3.14**, not python3.13 — verified via `dnf` on `almalinux:10`: EL10 ships **no** python3.13 (it has the default `python3` = 3.12 and AppStream `python3.14`; RHEL/EL10 skipped 3.13). All package names / interpreter paths below read 3.14.

Refs: [ADR-0032](0032-frontend-build-plain-css.md) (multi-stage build / production image has no Node runtime — **amended**: this ADR changes the runtime base OS, not the frontend-build or builder structure), `.trivyignore` (the curated Debian no-fix suppression list — **superseded**: the Debian-tracker IDs become moot, see Consequences), `ARCHITECTURE.md` §1/§17 (tech stack, out-of-scope), CLAUDE.md tech-stack constants (Python 3.13 pin). Supersedes the previously-implicit base-image choice (`python:3.13-slim-trixie`, never formally ADR'd). Implemented by TICKET-020.

## Context

The runtime image is built on `python:3.13-slim-trixie` (Debian 13). The Trivy code-scanning surface (2026-06, 44 open alerts) is dominated by **OS-package noise**, not application risk: only 3 of 44 alerts are Python deps with an available fix (`cryptography` HIGH, `pydantic-settings` MEDIUM); the other 41 are Debian OS packages, almost all `note`/`UNKNOWN` severity **with no upstream fix**. The repo already neutralises these via a hand-curated `.trivyignore` (~90 Debian-tracker IDs), but that list is pure maintenance burden and re-grows on every base-image bump.

The root cause is a reporting-model mismatch between Debian and Trivy:

- **Debian/Ubuntu report unfixed CVEs.** The Debian Security Tracker is extremely granular and marks large numbers of entries as "affects package, no fix planned / minor". Trivy ingests that feed and shows those entries by default even when **no fixed version exists** — there is nothing to upgrade to. This is the bulk of our noise.
- **AlmaLinux ships authoritative OVAL/errata (ALSA).** Trivy maps EL findings onto real Alma errata, including "not affected / out of support scope" statements and **backport-aware fixed versions**. This eliminates the classic "package looks old but is actually patched (Debian backport)" false signal, and removes the no-fix-but-still-listed entries that drive our `.trivyignore`.

**EL10 Python availability (verified via `dnf` on `almalinux:10`, 2026-06-20):** EL10 ships **no `python3.13`**. The default `python3` is 3.12, and AppStream offers **`python3.14`** (3.14.x — packages `python3.14`, `python3.14-devel`, `python3.14-pip`, `python3.14-libs`, …). RHEL/EL10 skipped 3.13 (3.12 → 3.14). The repos appstream/baseos/crb/extras are enabled by default. The OVAL/ALSA CVE-noise benefit is independent of the Python minor version, so we target **python3.14**; `requires-python >= 3.13` in pyproject is satisfied by 3.14 and stays as-is.

Two prior options were evaluated and rejected:

1. **AlmaLinux 9.8** — RHEL 9 AppStream tops out at Python 3.11/3.12; no AppStream stream newer than 3.12. Reaching a 3.13+/3.14 interpreter there would require building CPython from source in the image (≈+1.5 d work, plus we'd own Python's security patching ourselves — the opposite of the goal). Rejected. (EL10's `python3.14` is a packaged AppStream stream, not a source build — that is the point.)
2. **Distroless (`gcr.io/distroless/python3-debian13`)** — spike on branch `spike/distroless-runtime` (2026-06-20). Confirmed: Python 3.13.5 ✅, all native wheels import (no missing `.so`) ✅, `create_app()` boots ✅. But: (a) **no size win** — 226 MB vs. today's 192 MB, because the bulk is the Python venv, not the OS layer; (b) the shell-free boot path required a venv **relocation** from the builder interpreter path (`/usr/local/bin`) onto the distroless path (`/usr/bin`), which produced an **unresolved `ELF / source code cannot contain null bytes` startup crash** at container boot; (c) the image still rides the **Debian trixie** package DB, so it inherits the same reporting-model noise we are trying to escape; (d) `gcr.io` requires an air-gap mirror. The boot failure plus the unchanged CVE-reporting story made it the wrong tool for *this* problem. Spike fully torn down.

## Decision

**Move the runtime base image to `almalinux:10-minimal`; build the venv on `almalinux:10`.** Target **`python3.14`** (the EL10 AppStream Python stream — EL10 has no 3.13). This is a packaged stream, **not a source build** (the source build was the 9.8 rejection); `requires-python >= 3.13` in pyproject is satisfied by 3.14.

### Why `10-minimal` (not full `almalinux:10`) for runtime

- Built for exactly our shape: "applications that bundle their own dependencies" — our venv is the bundle.
- Package manager is **`microdnf`** (libdnf), which itself needs no Python; ~37 MB download / ~102 MB expanded vs. the full image's ~190 MB. Fewer packages → smaller attack/CVE surface by construction.
- We `microdnf install` only what is genuinely needed at runtime (see below).

### Interpreter-path consistency (the explicit fix for the distroless failure)

Builder and runtime **both** use the AlmaLinux `python3.14` at `/usr/bin/python3.14`. The venv created in the builder therefore needs **no relocation** at runtime — `pyvenv.cfg` `home` and the `bin/python` symlinks already point at the path that exists in the runtime image. This is the direct lesson from the distroless spike (the ELF crash came from a builder/runtime interpreter-path mismatch) and is the reason we keep a normal distro-Python runtime rather than going shell-free.

### Image composition

- **Builder stage** → `FROM almalinux:10`. `dnf install python3.14 python3.14-devel python3.14-pip` + a minimal build toolchain (`gcc`, `libffi-devel`, `openssl-devel`) as a safety net for any sdist-only dependency; in practice our native deps ship `manylinux_2_28` / abi3 wheels (`cryptography`, `argon2-cffi`, `nh3`) and `psycopg[binary]` bundles libpq, so glibc-2.39 on Alma 10 satisfies them and no compilation is expected. The abi3 wheels run on 3.14; pip resolves deps from pyproject (not uv.lock) at build time, pulling cp314 wheels from PyPI. venv via `python3.14 -m venv /opt/venv`; the existing two-layer pip install (deps layer, then `--no-deps` app layer) is unchanged.
- **Frontend-build stage** → **unchanged** (`node:20-alpine`, build-only; ADR-0032).
- **Runtime stage** → `FROM almalinux:10-minimal`. `microdnf install python3.14 glibc-langpack-en shadow-utils` then `microdnf clean all` — as its **own** `RUN` (no trailing `; true`, so an install failure aborts the build); the stdlib strip is a second, separately-guarded `RUN`. No `libpq` (psycopg binary bundles it). **No `curl`** — the healthcheck moves to a Python `urllib` probe (also drops the entire libcurl→krb5/ldap/libssh2/gnutls transitive group that today needs suppression).
- **Entrypoint stays `scripts/entrypoint.sh`** (`/bin/sh` present on Alma) — **no `entrypoint.py` rewrite** (unlike the distroless path). The non-root `fathometer` user (uid/gid 1001) is created with `useradd` (`shadow-utils`).
- **scratch-flatten final stage** (`FROM scratch` + `COPY --from=runtime-builder / /`) is **kept** — it is OS-agnostic and still removes the deleted-file whiteouts to keep the image honest.

### Healthcheck

`HEALTHCHECK` switches from `curl -fsS http://127.0.0.1:8000/readyz` to a Python `urllib` one-liner against the same URL. Compose's healthcheck override follows.

### Deliberately NOT in scope

- **No change to the builder/frontend pipeline shape** beyond the base FROM and the package manager (apt → dnf/microdnf).
- **No Python source build** — that was the 9.8 rejection; EL10 ships a packaged 3.14 AppStream stream.
- **No move off a real distro Python** to distroless/scratch-with-bundled-python — rejected above.
- **No scope/feature change**, no new services, no new outbound surface.
- The two Python-dep fixes (`cryptography` → 48.0.1, `pydantic-settings` → 2.14.2) are orthogonal and tracked separately; they are not blocked on this ADR.

## Consequences

- **`Dockerfile`**: builder `FROM` → `almalinux:10` with dnf-based toolchain; runtime-builder `FROM` → `almalinux:10-minimal` with `microdnf`. The Debian-specific stripping block (locale prune, `/usr/lib/<triplet>/perl-base`, `gconv`, apt artifacts) is **rewritten for the RHEL layout**: `/usr/lib64`, locale via `glibc-langpack-en` (install-time, not post-prune), `/usr/lib64/python3.14` stdlib pruning; perl-base is typically absent on minimal (one suppression group naturally disappears).
- **`scripts/entrypoint.sh`**: unchanged (validated: Alma has `/bin/sh`).
- **Healthcheck**: `Dockerfile` `HEALTHCHECK` and `docker-compose.yml` healthcheck switch to the Python `urllib` probe (curl removed from the image).
- **`.trivyignore`**: the current ~90 entries are **all Debian-tracker IDs** and become moot. The file is re-curated from scratch against the first Alma scan — expected to be **dramatically shorter** because (a) curl/krb5/ldap/libssh2/perl/util-linux-login/apt/bash packages are physically gone or not installed, and (b) remaining EL packages map to authoritative ALSA errata with real fix-state, so far fewer "no-fix-but-listed" entries survive.
- **CI** (`.github/workflows/trivy.yml`, `release.yml`): comments referencing "trixie userland" / the `python:3.13-slim-trixie` digest update to the Alma base; the base image must be **mirrored into the air-gap registry** (`operations.md`) — neutral vs. today, where `python:slim` is already mirrored. `release.yml` builds the last Dockerfile stage with no explicit `target`, so the **stage order must keep the scratch `runtime` stage last** (or add an explicit `target: runtime`).
- **`CLAUDE.md`** tech-stack constants + **`ARCHITECTURE.md`** §1: base-OS line updated (Debian slim → AlmaLinux 10-minimal); Python constant moves 3.13 → **3.14** (EL10 AppStream); `requires-python >= 3.13` in pyproject unchanged.
- **Image size**: measured **~249 MB** (arm64, local build 2026-06-20) vs. the 192 MB Debian baseline. The venv (~147 MB, `.so` already stripped) is OS-independent; the delta is the AlmaLinux userland (~100 MB vs. Debian-slim ~45 MB), almost all genuinely-linked libs (glibc, libpython3.14, openssl for Python's `ssl`, libstdc++). Safe stripping (drop the build-only dnf/microdnf stack, `glibc-langpack-en`→C.UTF-8, zoneinfo, ensurepip wheels) reaches only ~232 MB; sub-200 MB would require removing genuinely-linked system libs (fragile). **Decision (operator, 2026-06-20): raise the DoD cap 200 → 256 MB and skip the marginal trims** (the win is CVE-signal quality, not size; +56 MB for a single-container appliance is acceptable). O-risk-engine.md DoD updated. amd64 (the release target) must be re-checked against 256 MB in CI — this was measured on arm64.
- **Native wheels**: glibc 2.39 (Alma 10) ≥ `manylinux_2_28` → all current wheels satisfied (confirmed analogous in the trixie/distroless spike; re-verify with an import smoke in the new builder).

## Validation (operator-run, heavy gates — local arm64, 2026-06-20)

1. ✅ `microdnf install python3.14` resolves on `almalinux:10-minimal` → `/usr/bin/python3.14` (3.14.4). `useradd` via `shadow-utils` works.
2. ✅ Import smoke of all native deps in the Alma-built venv (`cryptography`, `psycopg`, `argon2`, `nh3`, `trafilatura`, `sqlalchemy`, `gunicorn`, `alembic`, `pydantic_core`, `jiter`) — all cp314 wheels resolved from PyPI, no missing `.so`.
3. ✅ Full boot: `entrypoint.sh` → DB reachable → `alembic upgrade head` → gunicorn (gthread) → `/readyz` 200 (new Python `urllib` healthcheck) → `/healthz` 200, container healthy ~12 s.
4. ⚠️ Image size **~249 MB > old 200 MB cap** → cap raised to 256 MB (see Consequences). amd64 release build still to be confirmed in CI against 256 MB.
5. ⏳ First Alma Trivy scan to seed the new `.trivyignore` — pending (CI on push).

## Re-Open triggers

- If `python3.14` is later promoted to the default `python3` on Alma 10 (or a newer `python3.NN` AppStream stream lands), revisit the explicit-version package name.
- If the Alma errata feed proves to surface comparable no-fix noise in practice (i.e. the OVAL/ALSA advantage does not materialise in our scan), re-evaluate whether the migration cost was justified vs. simply keeping the Debian `.trivyignore`.
- The 200 MB cap was raised to **256 MB** (operator decision 2026-06-20; AlmaLinux userland is larger than Debian-slim and sub-200 MB needs fragile system-lib removal). If the venv grows and 256 MB is breached, re-evaluate stripping vs. a further cap bump rather than silently raising it again.
