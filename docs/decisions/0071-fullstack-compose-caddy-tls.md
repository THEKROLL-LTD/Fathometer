# ADR-0071 — Full-stack `docker-compose` with bundled Caddy + automatic TLS (batteries-included, non-k8s)

**Status:** Draft (Proposed) · **Date:** 2026-06-20

> **Implemented *before* [ADR-0070](0070-omnibus-all-in-one-release-image.md) (omnibus, paused).** This ADR is the **source of truth for the Caddy reverse-proxy + automatic-TLS design and the `FM_TLS_*` / `FM_ACME_*` env contract**; the single-image omnibus will later reuse exactly this contract. It is a working draft for review before a block is cut.

Refs: [ADR-0069](0069-runtime-base-image-almalinux-10-minimal.md) (the app runtime image used as a service here), [ADR-0070](0070-omnibus-all-in-one-release-image.md) (single-image omnibus — paused; **reuses this ADR's Caddy/TLS contract**), [ADR-0003](0003-push-not-pull.md) (push-not-pull / no server credentials), [ADR-0063](0063-*.md) (optional operator-gated upstream-update search, default-off — research worker), existing `docker-compose.yml` (the **modular, bring-your-own-proxy** stack — stays as-is), `README` reverse-proxy snippets (nginx/Caddy/Traefik in front — this ADR makes that batteries-included instead), `ARCHITECTURE.md` §4 (deployment) / §17 (out-of-scope), `docs/operations.md` (air-gap mirror list), `app/config.py` (`env_prefix="FM_"`), `CHANGELOG` (`ProxyFix`, `FM_PUBLIC_URL`). Implemented by: **new block + ticket (the first to cut — precedes the omnibus)**.

## Context

There are two deployment audiences. Advanced/k8s operators run the **modular images** (ADR-0069) and bring their own ingress/TLS. The other audience — *"I can run `docker compose up`, but I don't run k8s and I don't want to stand up my own reverse proxy for certificates"* — is currently under-served: today's `docker-compose.yml` is modular and **assumes an external TLS proxy** in front (the README ships nginx/Caddy snippets to copy). For a non-expert that external-proxy step is the wall they hit.

We want a **shipped, ready-to-run full-stack compose** that bundles everything — including **Caddy with automatic HTTPS** — so the operator gets a working TLS deployment from one file with sensible defaults, no proxy assembly.

This is built **first**, ahead of the single-image omnibus (ADR-0070, paused). Beyond being a deliverable in its own right, it **establishes the Caddy + `FM_TLS_*` contract** that the omnibus will later package inside one container. Defining it here, in the simpler separate-container shape, de-risks the omnibus.

## Decision (proposed)

> **Env-var scope.** This ADR **defines** `FM_TLS_MODE`, `FM_ACME_EMAIL`, `FM_ACME_CA`, `FM_TLS_CERT_FILE`, `FM_TLS_KEY_FILE` — consumed by the **Caddy service entrypoint / Caddyfile rendering**, plus the pre-existing `FM_PUBLIC_URL`. They are **not** `app/config.py` settings (the app image ignores them; `Settings` has `extra="ignore"`). The omnibus (ADR-0070) reuses this exact contract — keep them single-sourced, do not diverge. Backup (`FM_BACKUP_*`) and the runit worker kill-switches are **omnibus-only** and do **not** apply to this compose.

### 1. A new shipped, versioned full-stack compose

A `docker-compose.fullstack.yml` (final name TBD), pinned to the released image tags, with services:

- **`caddy`** — official `caddy:2` image; the only service publishing ports (**80 + 443**); reverse-proxies to `app:8000`; automatic HTTPS.
- **`app`** — the ADR-0069 application image; **internal only** (not published).
- **`db`** — official **`postgres:17`** image; named volume for PGDATA.
- **`llm-worker`** — `app.workers.llm_worker` (same image as `app`).
- **`research-worker`** — `app.workers.research_worker` (ADR-0063); present but outbound-gated (see §5).

The existing modular `docker-compose.yml` is **kept unchanged** as the bring-your-own-proxy / advanced option. The new file is **additive**: modular = expert; full-stack = batteries-included. The README must clearly distinguish the two.

### 2. Caddy + automatic TLS

- Caddy terminates TLS and reverse-proxies to the app. **Persistent named volumes `caddy_data`** (ACME account keys + issued certs) **and `caddy_config`** — `caddy_data` is **load-bearing**: without it every `compose down/up` re-requests certs and hits Let's Encrypt's rate limit (5 duplicate certs / registered domain / week), locking the operator out.
- The app is already reverse-proxy-ready (`ProxyFix`, one hop, trusts `X-Forwarded-Proto`/`-Host`; CHANGELOG) and `FM_PUBLIC_URL` already drives absolute-URL / `install.sh` rendering. So the only app-side requirement is to set `FM_PUBLIC_URL`; Caddy sets `X-Forwarded-*` automatically. **No app code change.**

### 3. TLS modes — env-driven, this ADR is the contract (default `internal`)

A non-expert may run on a public host *or* an internal/air-gapped LAN; public Let's Encrypt needs a real domain + inbound 80/443 + outbound to the ACME server, impossible air-gapped. Hence `FM_TLS_MODE`:

| `FM_TLS_MODE` | Behaviour | Use case |
|---|---|---|
| `internal` (**default**) | Caddy's built-in local CA issues a self-signed cert; zero external dependency | LAN / air-gap; works everywhere, browser trust warning |
| `letsencrypt` | Caddy auto-ACME against Let's Encrypt (ZeroSSL fallback) for the `FM_PUBLIC_URL` host, **HTTP-01 challenge only** | Public deployment, real domain, reachable inbound :80 |
| `custom` | Operator supplies `FM_TLS_CERT_FILE` + `FM_TLS_KEY_FILE` (mounted into the caddy service) | Internal/corporate PKI, own cert |
| `off` | Plain HTTP on 80 | Behind an existing external TLS proxy / trusted LAN |

`internal` is the **default**, consistent with the air-gap-first ethos (like ADR-0063, public/outbound is opt-in). Public certs are a one-variable opt-in: `FM_TLS_MODE=letsencrypt` + `FM_PUBLIC_URL=https://host.example.com` + `FM_ACME_EMAIL=…`. **HTTP-01 only, no DNS-01 / wildcard** (keeps the stock `caddy:2` image — no custom `xcaddy` build). `FM_ACME_CA` overrides the ACME directory — point at **LE staging** during first setup to avoid burning the prod rate limit, or at an **internal ACME** (step-ca) for air-gap PKI.

**Caddyfile rendering (mechanism — to finalise at block):** the Caddyfile is rendered from `FM_TLS_MODE` by a tiny entrypoint/template (mode-switching is not expressible in a single static Caddyfile). This render logic is the piece the omnibus reuses (there driven by its own entrypoint). Decide: small shell/template entrypoint wrapping `caddy run` vs. a set of mode-specific Caddyfile snippets selected by env.

### 4. PostgreSQL — official image, owns its own upgrade story

`db` uses the official **`postgres:17`**. Unlike the omnibus (which bundles Postgres and therefore owns `pg_upgrade`), here Postgres is a normal service — **major-version upgrades are the official image's documented procedure**, not our burden. PGDATA on a named volume; `POSTGRES_*` + `FM_DATABASE_URL` wired between `db` and the app/workers as today.

### 5. Workers

- `llm-worker` always runs (core).
- `research-worker` is present but its **outbound is gated by the existing `FM_UPSTREAM_CHECK_ENABLED`** (default **off**, ADR-0063): with the feature off it idles, zero outbound — air-gap-safe by default. An operator who wants the process gone entirely uses a **Compose `profiles:` gate** (e.g. `profiles: ["research"]`) or `--scale research-worker=0` — **not** the omnibus-only `FM_RESEARCH_WORKER_ENABLED` (that switch is runit-specific). Decide profile-vs-always-idle at block.

### 6. Backup

Postgres is a separate service here, so the omnibus's bundled `FM_BACKUP_*` cron does **not** apply. For v1: **documented** `docker compose exec db pg_dump …` (and restore) in `operations.md`; an optional backup sidecar can come later. Bundled backup automation is naturally the omnibus's job, not this compose's.

### 7. Out of scope

- **DNS-01 / wildcard** certificates (would need a custom `xcaddy` build — separate ADR if ever needed).
- **Bundled backup automation** (omnibus territory; here it's a documented command).
- **The single-image omnibus** (ADR-0070).
- **No application scope/feature change** (ARCHITECTURE §17 unchanged).

## Consequences

- New files: `docker-compose.fullstack.yml`, a Caddyfile (+ render entrypoint/template), `.env.fullstack.example`. No application code change (`ProxyFix` already present).
- `README`: a batteries-included "full-stack compose" easy-install section, clearly distinguished from the existing modular bring-your-own-proxy compose.
- `docs/operations.md`: air-gap mirror list gains the **`caddy:2`** image (plus `postgres:17`, the app image); document the TLS modes and the `caddy_data` persistence requirement.
- **The `FM_TLS_*` / `FM_ACME_*` contract is documented here and referenced by ADR-0070.** Single-sourced; must not drift.
- **Trivy posture:** `caddy:2` and `postgres:17` are **official upstream images** (Debian-based) — their CVE signal is upstream's, noisier than our Alma app image, but they are operator-scannable and not ours to re-base. This is acceptable for the compose path; the quiet-Alma argument (ADR-0069) applies to *our* image, not to pinned official dependencies.
- New docs in English (language policy).

## Open items (resolve before / during the block)

1. **Caddyfile rendering mechanism:** entrypoint template vs. mode-selected snippets (the reuse seam with the omnibus).
2. **`research-worker`:** Compose `profiles:` gate vs. always-present-idle.
3. **Compose file name** and its relationship to the existing `docker-compose.yml` (additive sibling — confirm naming).
4. **Backup:** documented `pg_dump` only for v1 vs. an optional sidecar.
5. Operator-gated validation (heavy gates, per `CLAUDE.md` — run only on explicit instruction): `docker compose -f docker-compose.fullstack.yml up` brings the stack healthy; `internal` TLS serves HTTPS; `letsencrypt` against **LE staging** issues a cert; app reachable over HTTPS with correct `FM_PUBLIC_URL` rendering.

## Promotion path

- Refined in-place, then Status → Accepted, a **block document** (`docs/blocks/<X>-fullstack-compose.md`) + ticket are cut (**this is the first block of this initiative, ahead of the omnibus**), and an index row is added to `docs/decisions/README.md`.
- On completion, **un-pause ADR-0070** — its Caddy/TLS dependency is now satisfied.
