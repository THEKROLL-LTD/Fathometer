# ADR-0032 — Frontend-Build-Toolchain: Plain CSS + esbuild, kein Tailwind/DaisyUI im neuen Design

**Status:** Akzeptiert · **Datum:** 2026-05-23 · **Block:** W — Redesign Phase 1

Bezug: [ADR-0001](0001-no-node-build.md) (kein Node-Build im MVP — wird durch diese ADR **teilweise abgelöst**, Migrationspfad in zwei Phasen unten), [ADR-0031](0031-theme-switcher-removed.md) §"Geplante Folge-Arbeit Option D" (npm-Build als Folge-ADR vorgesehen), [TD-010](../techdebt.md#td-010--tailwind-via-cdn-jit-nicht-via-vite-build) (Tailwind-CDN-JIT Mitigation, wird durch diese ADR adressiert).

## Kontext

Heutiger Frontend-Stack (post-Block-V, v0.11.0):

- Tailwind CSS v3.4.16 via Browser-JIT-CDN (`<script src="https://cdn.tailwindcss.com/3.4.16?plugins=forms,typography">`)
- DaisyUI v4.12.14 via CDN (`full.min.css`, lädt alle ~30 Themes obwohl nur `data-theme="dark"` greift, siehe ADR-0031)
- Alpine.js v3.14.7 + HTMX v2.0.4 jeweils via CDN
- TD-010 Mitigation: Inline-Safelist (`base_app.html` Z. 52–73) für high-risk-Klassen die nur in HTMX-Sub-Trees auftauchen, plus Lint-Test `tests/templates/test_tailwind_safelist.py` gegen Drift

Block W (Redesign Phase 1) bringt einen neuen Design-Stand aus `docs/design/` ein:

- 100 % Plain CSS mit Design-Tokens (`design-tokens.css` mit ~100 CSS-Variablen für Surface-Layering, Text-Stufen, Accent, Easing-Doctrine, Spacing-Skala, Radii, Borders, Layout-Maße)
- Eigene Border-Radius-Verbotsliste (max 8 px — DaisyUI-Default `rounded-box`=16 px verletzt das überall)
- Eigene Easing-Doctrine (drei Eases: `--ease-materialize` Enter, `--ease-dismiss` Exit, `--ease-drift` Continuous)
- Box-Shadow-Verbotsliste (Elevation kommt aus Surface-Step gegen Page-Background, nicht aus Schatten)
- Komplexe Animationen (Scan-Beam-Sweep mit `mix-blend-mode: screen`, vertikale Scanlines-Pattern, per-Char `scan-flash` mit JS-synced animation-delay, `fathom-sweep` Logo-Rotate, `op-pulse` Echo-Dot, `skel-scan` Heartbeat-Probe, `skel-materialize` staggered Reveal)
- JetBrains Mono in 3 Weights (Light 300, Regular 400, Bold 700) als selbst-gehostete woff2-Dateien (`font-display: swap`)
- Komponenten-Klassen die deutlich vom DaisyUI-Defaults abweichen (`auth__panel`, `stat--alarm`, `host`, `hostgroup__header`, `topbar__user`, …)

Drei Optionen wurden geprüft:

1. **Tailwind+DaisyUI translatieren**: Design-Tokens als Tailwind-Theme-Extend, alle Komponenten als `@layer components`, eigenes DaisyUI-Theme `fathometer`. **Verworfen** weil:
   - Die Komponenten sind keine Utility-Strings mehr (Pseudo-Elemente, `mix-blend-mode`, gradient-Backgrounds, gestaffelte `@keyframes`). Als Utility-Strings unleserlich (`class="border-l-[3px] border-[var(--accent)] pl-7 isolate overflow-hidden [&::before]:absolute [&::before]:inset-0 [&::before]:w-[42%] [&::before]:bg-gradient-to-r ..."`)
   - DaisyUI-Defaults kollidieren systematisch (Border-Radius 16 px vs. max 8 px, eigene `btn`-/`card`-/`input`-Styles, eigene Hover-/Focus-States)
   - DaisyUI-Theme-Override gegen Design-Tokens fragil (CSS-Specificity-Wars, jedes DaisyUI-Update kann Override brechen)
   - Custom-Utilities für `mix-blend-mode`, `scan-flash`-Keyframes, JS-Layout-Sync (`useScanFlashSync`) sind nicht idiomatisches Tailwind

2. **Hybrid (Tailwind-Utilities + plain CSS Komponenten)**: Tailwind v3 bleibt als Utility-Layer für nicht-redesignte Surfaces, Design-Komponenten als plain CSS. DaisyUI raus. **Verworfen** weil:
   - Design-Tokens duplizieren sich (einmal in `design-tokens.css`, einmal in `tailwind.config.js` als Theme-Extend)
   - Verlockung zur „Tailwind-Vermischung" in den Design-Komponenten (Templates sehen `class="auth__panel mt-8 mx-auto"` und sind inkonsistent)
   - Phase 2 (vollständige Migration) müsste den Hybrid-Zustand erst wieder auflösen — unnötige Zwischen-Architektur

3. **Plain CSS + esbuild + lightningcss**: gewählt. Siehe Entscheidung.

## Entscheidung

**Frontend-Build-Toolchain ab Block W:**

- **Bundler:** `esbuild` für JS-Bundles (Alpine.js + HTMX vendored, App-eigene JS-Module). `lightningcss` für CSS-Minify + Autoprefixer + Hash-Asset-Naming.
- **Kein Tailwind, kein DaisyUI, kein PostCSS-Plugin-Chain, kein Vite, kein React.**
- **Self-hosted Assets:** JetBrains-Mono woff2 in `app/static/dist/fonts/`. Alpine.js + HTMX als `vendor.{hash}.js`-Bundle. Design-Tokens + App-CSS als `app.{hash}.css`-Bundle.
- **Asset-Manifest:** Build erzeugt `app/static/dist/manifest.json` mit Mapping `"app.css" → "app.abc123.css"`. Jinja-Context-Processor liest das einmalig beim App-Start und stellt `{{ asset_url('app.css') }}`-Helper bereit.
- **Multi-Stage-Dockerfile:**
  - **Stage 1** (`node:20-alpine`): Repo kopieren, `npm ci && npm run build`. Produziert `app/static/dist/{css,js,fonts}/*` plus `manifest.json`. Build-Time-Env-Var `SECSCAN_VERSION` aus `git describe --tags` wird als CSS-Custom-Property in das Bundle gebrannt (oder als `<meta>`-Tag im Template — Implementer-Wahl).
  - **Stage 2** (`python:3.13-slim` wie heute): Kopiert nur `app/static/dist/` aus Stage 1, keine Node-Runtime im Production-Image, keine `node_modules/`. Image-Größe steigt um die selbst-gehosteten Assets (~80 KB CSS + ~120 KB JS + ~150 KB Fonts ≈ +350 KB), reduziert sich gleichzeitig um den DaisyUI-CDN-Roundtrip beim ersten Page-Load.
- **Frontend-Source-Layout:**
  ```
  frontend/
    package.json           # esbuild, lightningcss, npm-scripts: "build", "watch"
    package-lock.json      # checked in
    src/
      css/
        tokens.css         # 1:1 aus docs/design/design-tokens.css
        app.css            # Design-Komponenten aus docs/design/styles.css + neue Templates
      js/
        vendor.js          # imports alpinejs + htmx, exportiert global
        dashboard_scan_sync.js   # useScanFlashSync-Hook (vanilla JS, keine React-Abhängigkeit)
        sidebar_viewport.js      # IntersectionObserver für Lazy-Batches (ADR-0035)
        sidebar_loading_wave.js  # staggered Skeleton-Reveal-Logik
        ... (existierende sidebar.js, bulk_ack.js etc. migrieren)
      fonts/
        JetBrainsMono-Light.woff2
        JetBrainsMono-Regular.woff2
        JetBrainsMono-Bold.woff2
    esbuild.config.mjs     # ein Skript, baut CSS + JS + Manifest
  ```
- **CI:** `npm ci && npm run build` läuft im Docker-Build (kein separater CI-Step nötig). `ruff/mypy/pytest` bleiben unverändert.

**Phase-1-Übergangs-Stack (Dual-Stack):**

Block W redesigned **nur Login + Dashboard-Pane + Layout-Shell (Topbar/Sidebar/Footer)**. Settings, Server-Detail, Findings, Audit, Setup-Wizard bleiben in Phase 1 unangetastet und brauchen weiter Tailwind+DaisyUI. Praktisch:

- `base.html` (Pre-Login-Routen + Setup) lädt **weiter** Tailwind-CDN + DaisyUI-CDN für die Legacy-Sub-Templates (Setup-Wizard) plus zusätzlich die neuen Design-Tokens + JetBrains-Mono über das esbuild-Bundle. Login extends `base.html` mit eigenen plain-CSS-Klassen — die Tailwind-Klassen werden ignoriert wenn das HTML sie nicht nutzt.
- `base_app.html` (eingeloggte Routen) lädt **beides parallel**: das neue `app.{hash}.css`-Bundle (Design-Tokens + Komponenten für Topbar/Sidebar/Footer/Dashboard) **und** den Tailwind-CDN-Tag + Daisy-CDN (für Server-Detail/Findings/Settings/Audit-Templates die noch nicht redesigned sind).
- Die TD-010-Inline-Safelist (`base_app.html` Z. 52–73) + Lint-Test bleiben unangetastet bis Phase 2 (Settings/Server-Detail-Redesign) die Legacy-Templates eliminiert. Danach: Safelist raus, Lint-Test löschen, Tailwind-/DaisyUI-CDN-Tags entfernen.

**Phase-2-Endzustand (separater Block, vermutlich nach Server-Detail-Redesign):**

- Sämtliche Templates auf Plain-CSS-Design-System umgestellt
- Tailwind-CDN-`<script>`-Tag entfernt aus `base.html` und `base_app.html`
- DaisyUI-CDN-`<link>`-Tag entfernt
- Inline-Safelist (`base_app.html` Z. 52–73) entfernt
- Lint-Test `tests/templates/test_tailwind_safelist.py` gelöscht
- TD-010 in `docs/techdebt.md` als „Erledigt durch Block W Phase 2" markiert und entfernt
- ADR-0001 final auf "Superseded by ADR-0032" gesetzt (heute nur "Teilweise abgelöst", weil Phase 1 die CDN-Stage noch braucht)

## Konsequenzen

**Build & Deploy:**

- Docker-Image enthält jetzt eine Node-Build-Stage. Build-Time pro Image steigt um ~30–60 s (npm ci cached, esbuild + lightningcss sind schnell). CI-Cache-Strategie aus `release.yml` (v0.9.6 `scope=release`) bleibt anwendbar — neuer Cache-Key für `frontend/package-lock.json`.
- Production-Image hat keinen Node-Runtime — nur die fertigen Static-Files. Keine npm-Audit-Surface im Production-Container.
- `frontend/node_modules/` wird **nicht** committed, kommt nur in der Build-Stage. `package-lock.json` ist committet für reproduzierbare Builds.

**Netzwerk & Air-Gap:**

- Production-Browser zieht keine externen Assets mehr (kein cdn.tailwindcss.com, kein cdn.jsdelivr.net) — passt zu `docs/operations.md` „keine externen asset calls"-Vorgabe. Im Air-Gap-Deployment ist der App-Container ab Phase 2 vollständig selbst-tragend.
- Phase-1-Dual-Stack lädt weiter Tailwind/DaisyUI von CDN solange Legacy-Templates sie brauchen. Air-Gap-Operatoren müssen für Phase 1 weiter die CDN-Domains whitelisten (siehe `docs/operations.md`). Ab Phase 2 fällt diese Anforderung weg.

**CSP-Headers:**

- Phase 1 bleibt CSP wie heute (Tailwind/Daisy-Domains in `script-src` / `style-src` whitelisted).
- Phase 2 kann CSP enger ziehen: `script-src 'self'`, `style-src 'self'`, kein `unsafe-inline` mehr (TD-010-Lint-Test hat heute eine Inline-Safelist im `<script>`-Tag — die Inline-CSP-Lücke wird mit Phase 2 geschlossen).

**Templates:**

- Neue Templates für Topbar/Sidebar/Footer/Dashboard/Login verwenden BEM-artige Plain-CSS-Klassen (`auth__panel`, `host__beat-tick`, `stat--alarm` etc.).
- Legacy-Templates (Settings, Server-Detail, Findings, Audit, Setup) bleiben Phase 1 unverändert mit Tailwind+DaisyUI-Klassen.
- **Konkretes Mischverbot:** Eine Template-Datei nutzt **entweder** Plain-CSS-BEM-Klassen **oder** Tailwind+DaisyUI-Klassen, nicht beides gemischt. Das vermeidet Cascade-Wars und macht die Phase-2-Migration pro Datei einfach scope-bar.

**Performance:**

- App-CSS-Bundle (`app.{hash}.css`): geschätzt ~35–45 KB un-gzipped, ~10 KB gzipped (Design-CSS heute 1286 Zeilen). DaisyUI-Full-CDN heute ~200+ KB un-gzipped — Phase-2-Gewinn ist real.
- JS-Vendor-Bundle: Alpine.js (~15 KB gzipped) + HTMX (~15 KB gzipped) = ~30 KB statt CDN-Roundtrips.
- Asset-Hashing erlaubt aggressives Browser-Caching (`Cache-Control: public, max-age=31536000, immutable`). Bei jedem Deploy ändert sich der Hash → Cache-Bust automatisch.

**Test-Konvention bleibt strikt eingehalten:**

- Build-Toolchain-Tests sind nicht Pflicht (die Toolchain produziert deterministische Output-Dateien; eine kaputte Pipeline bricht den Docker-Build → CI-Fail).
- Manifest-Context-Processor wird Pure-Unit-getestet (Mock-Manifest-Dict, prüft `asset_url("app.css")`-Lookup, prüft Error-Pfad bei fehlendem Manifest).
- Keine neuen `db_integration`/`acceptance`/`integration`-Tests in dieser ADR.

**Migrations-Risiko:**

- Wenn der esbuild-Build im Production-Pipeline-Build fehlschlägt (z.B. npm-Registry-Outage), kann kein neues Image gebaut werden. Mitigation: `npm ci` mit gepinntem `package-lock.json` + npm-Cache in der CI-Cache-Strategie.
- Wenn ein Operator in Phase 1 den Tailwind-CDN-Tag aus `base_app.html` entfernt **bevor** Phase 2 alle Legacy-Templates migriert hat, bricht das Layout von Settings/Server-Detail. Mitigation: Phase-2-Block hat als erste DoD-Aktion „alle Tailwind-Klassen aus Templates eliminiert" **vor** dem CDN-Tag-Removal.

## Verworfen

- **Variante "Tailwind+DaisyUI translatieren"**: Zu viel Custom-Code in `@layer components`, Design-Tokens duplizieren, DaisyUI-Override-Wars. Siehe Kontext §3.
- **Variante "Hybrid Tailwind-Utilities + plain CSS"**: Verlockung zur Vermischung in Templates, doppelte Token-Pflege, Phase-2-Migration müsste den Hybrid-Zustand erst wieder auflösen.
- **Variante "Vite statt esbuild"**: Vite ist HMR + Plugin-Ökosystem-orientiert. Wir brauchen nur CSS-Bundling + JS-Bundling + Asset-Hashing — esbuild reicht und ist eine 8-MB-Binary statt 200-MB-`node_modules`.
- **Variante "Tailwind-Standalone-Binary (kein Node)"**: Schließt DaisyUI aus (DaisyUI ist npm-Plugin), aber wir nehmen DaisyUI ohnehin raus. Bleibt: Tailwind-Standalone als reines Utility-Layer ohne Komponenten. Hat aber das gleiche „Tokens duplizieren"-Problem wie die Hybrid-Variante. Esbuild + plain CSS ist die einfachere Lösung.

## Re-Open-Trigger

- Wenn ein zukünftiger Block in `app/static/`-Assets dynamische Imports / Tree-Shaking / TypeScript braucht (heute alle JS-Module sind plain JS, kein TS), Vite oder ein vollwertiger Bundler kann sinnvoll werden.
- Wenn die Phase-2-Migration der Legacy-Templates **nicht** stattfindet (Block W bleibt einzige Design-Iteration, Settings/Server-Detail bleiben Tailwind+DaisyUI), die Dual-Stack-Lösung wird permanent. Dann separate ADR zum Akzeptieren des Dauer-Hybrid-Stacks oder zum Eliminieren des Plain-CSS-Pfads.
- Wenn `lightningcss` oder `esbuild` ihre Konventionen brechen (Manifest-Format ändert sich, CLI-Flags ändern sich), evaluieren ob ein anderer Bundler stabiler ist.
