# ADR-0070 — Omnibus all-in-one release image (single-container easy-install, additional to the modular deployment)

**Status:** Draft (Proposed) — **PAUSED / on hold, not accepted** · **Date:** 2026-06-20

> **PAUSED (2026-06-20).** This ADR is intentionally **not accepted** and **not** being cut into a block yet. The open questions are resolved (see §Resolved / §Open questions), but the work is deferred. **The full-stack `docker-compose` deliverable has been extracted out of this ADR into [ADR-0071](0071-fullstack-compose-caddy-tls.md), which is implemented *first*.** ADR-0071 establishes the Caddy + automatic-TLS + `FM_TLS_*` contract; this omnibus ADR will later **reuse** that contract. Resume this ADR after ADR-0071 ships.
>
> Remaining working-draft caveat: package lists and lifecycle mechanics here are proposals, not commitments, until this ADR is un-paused and reviewed.

Refs: [ADR-0069](0069-runtime-base-image-almalinux-10-minimal.md) (runtime base = `almalinux:10-minimal`; the omnibus **builds on** this, reusing the builder/venv shape — read first), [ADR-0071](0071-fullstack-compose-caddy-tls.md) (**full-stack compose + Caddy + TLS — implemented first; defines the `FM_TLS_*`/Caddy contract this ADR reuses**), [ADR-0032](0032-frontend-build-plain-css.md) (multi-stage build, no Node runtime in prod — the omnibus reuses the same builder + frontend-build stages), [ADR-0003](0003-push-not-pull.md) (push-not-pull / no server credentials — unchanged by the omnibus), [ADR-0063](0063-*.md) (optional operator-gated upstream-update search, default-off — relevant to the "which services are bundled" decision), `ARCHITECTURE.md` §4 (deployment topology) / §17 (out-of-scope), `docs/operations.md` (air-gap, base-image mirror), `CLAUDE.md` tech-stack constants (PostgreSQL 17 in its own container — **this ADR introduces a deliberate exception for the easy-install artifact only**). Implemented by: **TBD block + ticket** (not yet cut; deferred behind ADR-0071).

## Context

The roadmap wants an **easy-install path for non-expert operators**. The supported (and ADR-blessed) deployment is the **modular Compose stack**: app container (ADR-0069) + dedicated PostgreSQL 17 container + LLM worker (+ optional `research-worker`, ADR-0063, default-off). For an experienced operator that is the right shape. For the target "I just want to start one thing" user, standing up a dedicated Postgres, a worker, volumes and a Compose file is too much.

GitLab Omnibus is the explicit model: **one image that bundles every service** (here: PostgreSQL, the Flask/gunicorn app, the LLM worker) under a single process supervisor, so the operator runs one container with one data volume.

Two hard constraints shape this:

1. **The omnibus is an *additional* release artifact, not a replacement.** The modular images (ADR-0069) stay primary and ADR-blessed. The omnibus is built **additionally at release time** from the same codebase and the same builder/venv stage. We do not fork the application.
2. **`almalinux:10-minimal` base (ADR-0069) is reused.** Same CVE-signal rationale (OVAL/ALSA errata, low Trivy noise) — doubly important here because a security product's *bundled* image is exactly what a security-conscious operator will scan first.

Distroless was considered and is a non-starter for this artifact specifically: no shell, no package manager, **no process supervisor**, single-PID-1 design. An all-in-one multi-service image needs a supervisor; that rules out distroless by construction (independent of the ADR-0069 distroless rejection, which was about CVE data + a venv-relocation boot crash).

## Decision (proposed)

> **Env-var scope (authoritative).** The `FM_*` vars in this ADR are **deployment-packaging constructs, not `app/config.py` settings**; they have **no effect** on the modular app image (ADR-0069), which ignores them entirely. Two groups:
> - **Shared TLS/Caddy contract — *defined by [ADR-0071]*, reused here:** `FM_TLS_MODE`, `FM_ACME_EMAIL`, `FM_ACME_CA`, `FM_TLS_CERT_FILE`, `FM_TLS_KEY_FILE` (+ `FM_PUBLIC_URL`, pre-existing). ADR-0071 (full-stack compose) is the source of truth for their semantics; the omnibus consumes the same contract via its bundled Caddy. Keep them identical across both — do not redefine here.
> - **Omnibus-only:** `FM_BACKUP_*`, `FM_LLM_WORKER_ENABLED`, `FM_RESEARCH_WORKER_ENABLED`, and the first-boot key auto-generation — consumed by the omnibus entrypoint / runit run-scripts only; meaningless in compose (which uses its own native service/volume mechanisms).
>
> Pre-existing app vars referenced here (`FM_ENCRYPTION_KEY`, `FM_SECRET_KEY`, `FM_DATABASE_URL`, `FM_GUNICORN_*`) keep their existing meaning across all deployments.

### 1. Topology — one image, supervised, additional artifact

A new build target produces an **omnibus image** that runs, under one supervisor:

- **PostgreSQL 17** (bundled, data on the `/data` volume — see §3),
- the **gunicorn app** (same `create_app()` / entrypoint logic as the modular image),
- the **Caddy reverse proxy** (TLS termination — see §9),
- the **core LLM worker** (`fathometer-llm-worker`) — always on,
- the **research worker** (`fathometer-research-worker`, ADR-0063) — also started by default; disable via `FM_RESEARCH_WORKER_ENABLED=false`; outbound stays gated by the existing `FM_UPSTREAM_CHECK_ENABLED` (see §5).

It is built in the **same release pipeline** as the modular images (`release.yml`), reusing the ADR-0069 `almalinux:10` builder/venv stage. The application code, migrations and assets are identical; only the final assembly differs.

### 2. Supervisor — runit (vendored)

**runit**, per the GitLab Omnibus model. runit is **not packaged** for AlmaLinux 10 (absent from base/AppStream; not reliably in EPEL 10) — and the full `almalinux:10` would not have it either, so this is not a `-minimal` regression. We **vendor runit**: build it in the `almalinux:10` builder stage (which already has `gcc`) and copy the binaries into the minimal runtime, then define one `runit` service directory per bundled service (`/etc/service/{postgres,app,caddy,llm-worker,research-worker}`), each with a `run` script (and `finish`/logging as needed). Both workers start by default; each has an env kill-switch (`FM_{LLM,RESEARCH}_WORKER_ENABLED`, default `true`) — no feature-flag gating in the run scripts (§5). runit is PID 1, handles supervision, restart, and signal/zombie reaping.

(`s6-overlay` and `supervisord` were the alternatives; runit chosen for direct GitLab-Omnibus lineage and battle-tested multi-service-container behaviour.)

### 3. PostgreSQL lifecycle — decided

This, not the Dockerfile, is the real cost of an omnibus, and the operator-experience requirements below are **firm** (not open):

- **One volume, KISS (decided).** The omnibus mounts a **single external volume at `/data`** holding everything stateful, in subdirectories: `/data/postgres` (PGDATA), `/data/backups`, `/data/caddy` (ACME certs/account), `/data/secrets` (auto-generated keys, see below). One `-v <volume>:/data` is all the operator provides — nothing else to remember. The entrypoint **hard-fails** (exits, does not just warn) if `/data` is not a mount point, so a non-expert cannot accidentally run with ephemeral state and lose all scans/certs on the next `docker run`. Trade-off accepted for KISS: PGDATA and its backups share one volume, so the bundled backup protects against logical loss (bad migration, fat-finger) but not against losing the volume itself — an operator wanting off-box safety points `FM_BACKUP_DIR` at a second mount.
- **Keys are self-generated on first boot (decided) — the user is never nagged.** If `FM_ENCRYPTION_KEY` / `FM_SECRET_KEY` (and the master/server-key) are not supplied via env, the entrypoint generates them on first boot and persists them under `/data/secrets`, reusing them on every subsequent boot. The operator can run the container with zero secret configuration. Env-supplied values still win (an operator who wants to manage keys externally, or keep them off the data volume, just sets them). Documented trade-off: auto-generated keys live on the same volume as the data they protect (standard appliance posture); security-conscious operators externalise via env.
- **First-boot bootstrap:** empty PGDATA → `initdb` (locale via `glibc-langpack-en`, or forced `C.UTF-8`) → create role + database → `alembic upgrade head` → start app. Subsequent boots skip initdb and just run `alembic upgrade head` (same migration-on-boot behaviour as today's modular image).
- **Seamless major-version upgrades (required).** The operator upgrade flow is: pull the new image, restart the container — nothing else. To deliver that, the entrypoint detects the on-disk `PG_VERSION` in PGDATA, compares it to the image's bundled Postgres major, and if older runs `pg_upgrade` **automatically before the app starts**. The image therefore **bundles exactly the current + N-1 Postgres server major binaries** (decided — N-1 only, not N-2) so `pg_upgrade` can migrate from the immediately-previous major (GitLab Omnibus does the same). Consequence the docs must state: an operator who skips a major release (N-2 → N) cannot auto-upgrade in one hop — they upgrade through the intermediate image first, or restore from a dump. A **pre-upgrade `pg_dump` safety snapshot** is taken into the backup dir before `pg_upgrade` runs, so a failed upgrade is always recoverable. App-version upgrades (no PG-major change) just run `alembic upgrade head` as today.
- **Standard backup, on by default, env-reconfigurable (in scope for ADR-0070).** The omnibus ships a working `pg_dump`-based backup out of the box — the operator gets backups without configuring anything. It writes to a backup volume and is fully reconfigurable via `FM_BACKUP_*` env vars (the `FM_` prefix matches `app/config.py`'s `env_prefix`; `POSTGRES_*` stays the Postgres-image convention):

  | Env var | Default (proposed) | Meaning |
  |---------|--------------------|---------|
  | `FM_BACKUP_ENABLED` | `true` | Master switch; set `false` to disable the bundled backup entirely. |
  | `FM_BACKUP_CRON` | `0 3 * * *` | Schedule (runit-supervised cron / tiny scheduler). |
  | `FM_BACKUP_DIR` | `/data/backups` | Default is a subdir of the single `/data` volume; point at a second mount for off-box safety. |
  | `FM_BACKUP_RETENTION_DAYS` | `14` | Prune dumps older than N days. |
  | `FM_BACKUP_FORMAT` | `custom` | `pg_dump -Fc` (restorable via `pg_restore`); `plain` for SQL text. |

  Restore is a documented one-liner against the same image (`pg_restore`/`psql` from `FM_BACKUP_DIR`). `tar` + `gzip` are added to the image for this (minimal lacks them).

### 4. Base image — `almalinux:10-minimal` + the omnibus-specific package delta

Reuse ADR-0069's base and builder. Beyond the modular image's runtime set (`python3.13`, `glibc-langpack-en`, `shadow-utils`), the omnibus additionally needs, **installed explicitly in the minimal runtime**:

- `postgresql17-server` (+ client) **from PGDG** — with `shadow-utils` already present so the package's `useradd` scriptlet creates the `postgres` user (ordering is load-bearing on minimal);
- `tar`, `gzip` (backup/restore), `procps-ng`, `findutils` (supervisor/ops scripts);
- the **vendored runit** binaries copied from the builder.

`microdnf` cannot do `dnf module` operations; PGDG's "`module disable postgresql`" step (needed on EL8/9) is expected to be moot on EL10 (modularity effectively removed) but must be verified — if any AppStream `postgresql` module conflicts with PGDG, do that step in the full `almalinux:10` builder stage, not in minimal.

### 5. Services NOT bundled (proposed)

- **Both workers are bundled and start by default (decided — KISS).** The core `fathometer-llm-worker` (`app.workers.llm_worker`, processes the LLM risk-reviewer / chat jobs) and the `fathometer-research-worker` (`app.workers.research_worker`, ADR-0063 upstream-update search) both run as ordinary always-up runit services. We deliberately do **not** gate the worker `run` scripts on the upstream-check feature flag — that would force the run script to read DB/setting state and is exactly the complexity we are avoiding. Instead each worker has a plain **env kill-switch**, `FM_LLM_WORKER_ENABLED` / `FM_RESEARCH_WORKER_ENABLED` (default `true`); set one to `false` and runit keeps that service down (trivial env check / `down` file). Disabling the core worker is rarely sensible; the meaningful switch is `FM_RESEARCH_WORKER_ENABLED=false` for an operator who does not want the research process running at all.
  - **Air-gap stays safe.** The research-worker process running does **not** by itself produce outbound traffic — outbound is still gated by the existing `FM_UPSTREAM_CHECK_ENABLED` (default **off**, ADR-0063): with the feature off, no upstream-check jobs are enqueued, so the worker idles and makes zero outbound calls. Air-gap operators just leave the feature off (the default); the optional `FM_RESEARCH_WORKER_ENABLED=false` additionally removes the idle process.
- **Reverse proxy + TLS: bundled Caddy (decided) — see §9.** Caddy terminates TLS and proxies to gunicorn; gunicorn is not published directly.
- **No scope/feature change.** ARCHITECTURE §17 out-of-scope is unchanged (no notifications, no multi-user/RBAC, no mobile, etc.). The omnibus is a packaging artifact only.

### 6. Resource footprint — accepted, not surfaced as a caveat

The omnibus runs a real Postgres + gunicorn + worker in one box; its memory/CPU footprint is **GitLab-Omnibus-class, by design**. This is an accepted trade for "one container, real database performance" — there is **no fallback to an embedded lightweight engine** (see §8). The footprint is **not** surfaced to the target user as a scary "minimum RAM" caveat; sensible defaults (e.g. `FM_GUNICORN_WORKERS`, Postgres `shared_buffers`) are tuned for a single-box small deployment and documented only where an operator goes looking, not front-and-centre.

### 7. Build, scan, release

This ADR ships **one** artifact: the **omnibus single image** (one container, one `/data` volume; the absolute-simplest path for the non-expert). The previously-paired **full-stack `docker-compose` (with Caddy) has been extracted to [ADR-0071](0071-fullstack-compose-caddy-tls.md)** and is implemented *first* — it is the separate-container path for non-k8s users and the source of the Caddy/TLS contract this omnibus later reuses.

Pipeline:

- New Dockerfile (or a new `omnibus` target stage alongside the existing stages); `release.yml` builds it **in addition to** the modular image. Note ADR-0069's caveat: `release.yml` builds the last stage when no `target` is set — the omnibus must use an **explicit `target`** so it does not disturb the modular default.
- **Its own Trivy scan + its own curated suppression.** The omnibus has a *larger* surface than the modular image (Postgres, runit, extra tools), so it gets its **own `.trivyignore`/VEX**, separate from the modular image's (which ADR-0069 re-curates). Ship an **OpenVEX** document with the omnibus so operators scanning it see real residual risk, not raw OS noise — good dogfooding for a Trivy aggregator.
- **Air-gap:** the omnibus is itself the air-gap-friendly artifact (one image to mirror). Document the single-image mirror in `operations.md`.
- **No image-size cap (decided).** The modular 200 MB cap (O-risk-engine.md DoD) **explicitly does not apply** — the omnibus bundles Postgres + Caddy + runit and **will be large by design**; we do not set or chase a separate cap. The cap remains a modular-image concern only.

### 8. Considered and rejected: embedded/lightweight-DB model (uptime-kuma)

uptime-kuma was reviewed as a counter-model: it defaults to **embedded SQLite** (in-process, file-based, no separate server) and lets an operator attach an external MariaDB/MySQL/Postgres, or opt into a bundled `embedded-mariadb` (a real `mariadbd` launched as a child process in the container). A variant of this — **one image with `BUNDLED_DB=on|off` + a `FM_DATABASE_URL` override** instead of a separate omnibus artifact — was on the table.

**Rejected.** secscan is Postgres-bound (SQLAlchemy 2.x + Alembic + Postgres-specific semantics; "PostgreSQL 17" is a hard tech-stack constant), so an embedded SQLite default would require a full second backend with materially worse performance — explicitly not wanted. We accept the heavier GitLab-Omnibus shape because it gives the non-expert user a real, performant database with zero DB operations. uptime-kuma's `embedded-mariadb` mode does, however, **validate the core pattern** of this ADR: a real DB server supervised as an in-container process is a proven approach, not an exotic one.

### 9. Reverse proxy + TLS — Caddy (decided)

> The Caddy + automatic-TLS design and the `FM_TLS_*` / `FM_ACME_*` env contract are **defined by [ADR-0071](0071-fullstack-compose-caddy-tls.md)** (implemented first). This section records only how the omnibus **packages** that same contract inside the single container; the *semantics* of the modes/vars live in ADR-0071 and must not diverge.

A bundled **Caddy** terminates TLS and reverse-proxies to gunicorn on `127.0.0.1:8000`, running as its own runit service (`/etc/service/caddy`). The container publishes **80 + 443 only**; gunicorn is **not** published. Caddy fits the easy-install goal because automatic HTTPS — ACME cert acquisition, renewal, and HTTP→HTTPS redirect — is built in (no certbot, no renewal cron, no manual steps).

**No app change required.** The app is already reverse-proxy-ready: `werkzeug.middleware.proxy_fix.ProxyFix` trusts exactly one hop of `X-Forwarded-Proto`/`-Host` (CHANGELOG), and `FM_PUBLIC_URL` already drives absolute-URL / `install.sh` rendering behind TLS. Caddy is exactly one hop and sets `X-Forwarded-*` automatically — so the only requirement is to set `FM_PUBLIC_URL`.

**Certificate storage is the critical gotcha.** Caddy stores ACME account keys + issued certs in its data dir; in the omnibus this is pinned to **`/data/caddy`** (via `XDG_DATA_HOME`), a subdir of the single `/data` volume (§3). It **must** persist — otherwise every container restart re-requests certs and hits Let's Encrypt's rate limit (5 duplicate certs / registered domain / week), locking the operator out. Covered by the one-volume mount.

**TLS modes are env-driven, default `internal` (decided).** A non-expert may run this on a public host *or* an internal/air-gapped LAN; public Let's Encrypt needs a real domain + inbound 80/443 + outbound to the ACME server, impossible air-gapped. The **default is `internal`** — consistent with the air-gap-first ethos (like ADR-0063, public/outbound is opt-in, never assumed). Public certs are a deliberate one-variable opt-in. `FM_TLS_MODE`:

| `FM_TLS_MODE` | Behaviour | Use case |
|---|---|---|
| `internal` (**default**) | Caddy's built-in local CA issues a self-signed cert; zero external dependency | LAN / air-gap; works everywhere, browser trust warning |
| `letsencrypt` | Caddy auto-ACME against Let's Encrypt (ZeroSSL fallback) for the `FM_PUBLIC_URL` host, **HTTP-01 challenge only** | Public deployment, real domain, reachable inbound :80 |
| `custom` | Operator supplies `FM_TLS_CERT_FILE` + `FM_TLS_KEY_FILE` | Internal/corporate PKI, own cert |
| `off` | Plain HTTP on 80 | Behind an existing external TLS proxy / trusted LAN |

The operator opts into public certs with `FM_TLS_MODE=letsencrypt` + `FM_PUBLIC_URL=https://host.example.com` + `FM_ACME_EMAIL=…`. **Challenge type is HTTP-01, not DNS-01** (decided): it needs only inbound port 80 + the existing 443 — no DNS-provider API credentials, no custom Caddy build. This means the **stock static Caddy binary is sufficient** and we never bundle DNS-provider plugins.

Supporting env vars: `FM_ACME_EMAIL` (LE registration / expiry notices); `FM_ACME_CA` (override the ACME directory — point at **LE staging** during first setup to avoid burning the prod rate limit, or at an **internal ACME** such as step-ca for air-gap PKI); `FM_TLS_CERT_FILE` / `FM_TLS_KEY_FILE` (custom mode). The entrypoint **generates the Caddyfile from these env vars** so the non-expert never edits Caddy config.

**Build & ops notes:**

- Caddy is a single static Go binary — **vendored like runit** (the **stock** binary, since HTTP-01-only needs no plugins: fetched in the `almalinux:10` builder, copied into the minimal runtime; no `microdnf` dependency; mirrored for air-gap).
- **Privileged ports:** Caddy binds 80/443 as the non-root `fathometer` user → `setcap cap_net_bind_service=+ep` on the binary at build time (or run only the caddy service as root). Decide at build.
- **No DNS-01 / wildcard** support (decided, see table). If a future operator genuinely needs wildcard or has no inbound :80, that is a separate ADR (it would require an `xcaddy` custom build with a `caddy-dns` plugin) — not in this design.

## Consequences

- New Dockerfile/target, new entrypoint + runit service dirs (`postgres`, `app`, `caddy`, `llm-worker`, `research-worker` — both workers up by default, env kill-switchable), vendored runit **and** vendored Caddy build steps (`setcap` on the Caddy binary for 80/443). Application code, migrations, assets: **unchanged/shared** with the modular image (the app is already `ProxyFix`-ready, so no code change for the bundled proxy).
- **Ports/volume:** the omnibus publishes 80 + 443 only; a **single `/data` volume** (subdirs `postgres`/`backups`/`caddy`/`secrets`) under the hard-fail-if-not-mounted discipline.
- **Container-level healthcheck (decided):** **one** Docker `HEALTHCHECK` at the container level reports the whole box healthy — **not** per-service probes inside the container (runit owns intra-container service liveness/restart). The single probe is the ADR-0069 `urllib` check against the app's `/readyz`, which already fails if the app cannot reach Postgres — so app-readiness transitively covers DB-readiness without a separate DB probe.
- The full-stack `docker-compose` is **out of this ADR** — see ADR-0071 (implemented first).
- Release pipeline builds, scans, VEXes and mirrors **one extra image**.
- New docs: `operations.md` omnibus section (single-image mirror, `/data` volume, backup, PG-upgrade runbook incl. the N-1-only skip-release caveat, TLS modes), `README` easy-install section. New docs in English (language policy).
- A **PG-major-upgrade runbook/automation** becomes a maintained artifact — recurring cost on every Postgres major bump.
- `CLAUDE.md` tech-stack: record the **deliberate exception** that the omnibus bundles Postgres in-image (the "PostgreSQL 17 in its own container" constant remains the rule for the modular/blessed deployment).
- **Env-var scoping in docs + config:** the omnibus-only vars (see the scope note under §Decision) are documented **only** in the omnibus/`operations.md` section and the full-stack-compose section, never in the general app config docs / `.env.example` core block. Note: `app/config.py`'s `Settings` already sets `extra="ignore"` (verified), so an operator reusing one `.env` across deployments will not crash the modular app on an omnibus-only `FM_*` var — the modular app silently ignores them, which is exactly the desired isolation. A small pure-unit guard test asserting this stays true is worth adding.
- The modular Compose deployment remains primary and unchanged; the omnibus never becomes the only path.

## Decided (this round)

- **Approach:** stay with the GitLab-Omnibus shape (bundled Postgres, heavy but operationally trivial for the user) — the uptime-kuma embedded/env-flag model is rejected (§8).
- **PGDATA:** mandatory external volume, entrypoint hard-fails if not mounted (§3).
- **Upgrades:** seamless — pull + restart; entrypoint auto-runs `pg_upgrade` with a pre-upgrade safety dump; image bundles **current + N-1 only** (decided) — skip-a-release upgrades go through the intermediate image or a dump restore (§3).
- **Backup:** bundled and on by default, reconfigurable via `FM_BACKUP_*` (§3).
- **Resource footprint:** GitLab-class, accepted, not surfaced as a user caveat (§6).
- **No image-size cap (decided):** the omnibus is large by design; the modular 200 MB cap does not apply and no omnibus cap is set (§7).
- **Container-level healthcheck (decided):** one Docker `HEALTHCHECK` for the whole container (app `/readyz`, which transitively covers Postgres), **not** per-service probes — runit owns intra-container liveness (Consequences).
- **Reverse proxy + TLS:** bundled **Caddy** (runit service), automatic HTTPS; contract (`FM_TLS_*`, modes, HTTP-01-only, `internal` default) **defined by ADR-0071**, reused here; Caddy data at `/data/caddy`; container publishes 80 + 443 only (§9).
- **Volume:** **one** `/data` volume, KISS — PGDATA, backups, Caddy, secrets as subdirs; hard-fail if unmounted (§3).
- **Keys:** `FM_ENCRYPTION_KEY` / `FM_SECRET_KEY` / master+server-key **self-generated on first boot** into `/data/secrets` if not env-supplied; user is never nagged; env override wins (§3).
- **Key rotation:** **deferred — out of scope for now (decided).** Auto-gen on first boot is in; *rotating* a key later is **not** designed in this ADR. When this ADR is un-paused and cut into a block, file a **`docs/techdebt.md` `TD-NNN` entry** for "omnibus key rotation UX (CLI subcommand vs. documented re-encrypt procedure)" — do **not** build it now.
- **Deliverable:** this ADR ships **only** the omnibus image; the full-stack compose moved to **ADR-0071** (implemented first) (§7).
- **Workers:** both bundled and **started by default** (KISS, no feature-flag gating); env kill-switches `FM_LLM_WORKER_ENABLED` / `FM_RESEARCH_WORKER_ENABLED` (default `true`). Air-gap stays safe because outbound is gated by the existing `FM_UPSTREAM_CHECK_ENABLED` (default off) — the research-worker idles with zero outbound until the feature is enabled (§5).

## Open questions

**None blocking** — the substantive design questions are resolved above. This ADR is **paused** (not accepted); it is resumed and cut into a block only **after ADR-0071 ships**. The one explicitly-deferred item is **key rotation UX**, to be filed as a `TD-NNN` tech-debt entry at block-cutting time, not designed now.

## Re-Open / promotion path

- **Currently paused.** Resume **after [ADR-0071](0071-fullstack-compose-caddy-tls.md) ships** (it delivers the Caddy/TLS contract this ADR depends on). On resume: Status → Accepted, a new **block document** (`docs/blocks/<X>-omnibus.md`) + ticket are cut, the deferred key-rotation item is filed as `TD-NNN`, and an index row is added to `docs/decisions/README.md`.
- Re-open trigger after acceptance: if maintaining the bundled-Postgres `pg_upgrade` path proves heavier than the easy-install value it delivers, **promote ADR-0071's full-stack `docker-compose` to the primary easy-install path** and retire the single-image omnibus — that compose uses the official Debian-based `postgres:17`, which owns its own upgrade story, removing the bundled-`pg_upgrade` maintenance burden.
