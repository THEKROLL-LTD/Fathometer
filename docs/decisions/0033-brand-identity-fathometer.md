# ADR-0033 — Brand-Identity Fathometer + Design-Doctrine + Sprach-Policy

**Status:** Akzeptiert · **Datum:** 2026-05-23 · **Block:** W — Redesign Phase 1

Bezug: [ADR-0031](0031-theme-switcher-removed.md) (Dark-Only), [ADR-0032](0032-frontend-build-plain-css.md) (Build-Toolchain für die hier festgelegten Tokens), [ADR-0009](0009-no-mobile.md) (kein Mobile-Layout — die Display-Type-Stufen sind Desktop-First).

## Kontext

Bis Block W trägt die App den Arbeitstitel `secscan`. Header zeigt ein `s`-Square-Placeholder-Logo + Wort `secscan`. Es gibt kein konsolidiertes Design-System — Tailwind-Defaults + DaisyUI-Defaults sind die Quasi-Tokens.

`docs/design/` (vom Operator als Mockup-Stack geliefert, React + plain CSS + Design-Tokens) führt eine vollständige Brand-Identity und ein Design-System ein. Die Tokens (`docs/design/design-tokens.css`) sind explizit als „source of truth for color, type, motion, spacing" markiert und „mirrors the production stack at thekroll.ltd". Die Komponenten (`docs/design/styles.css`) sind plain CSS und benennen einzelne Doctrine-Punkte als „DS §1 Materialization", „DS §4 Verbotsliste", „DS §1 exits are fast/decisive" etc.

Diese ADR friert die Brand- und Design-Doctrine-Entscheidungen ein, damit sie nicht ohne Begründung wieder driften, und legt die Sprach-Policy fest (heute Mix aus Deutsch in UI + Deutsch in Doc).

## Entscheidung

### 1. Brand

**Produktname:** `Fathometer` (Mixed Case, **nicht** ALLCAPS — Wordmark in der Topbar wird CSS-`text-transform: uppercase` mit `letter-spacing: 0.18em` gerendert, im Markup steht der Mixed-Case-String).

**Subline:** `CVE Intelligence` (kleine UPPERCASE-Mono, accent-cyan).

**Footer-Tagline:** `thekroll ltd · human intent. machine precision.` (rechtsbündig, mono-Caption-Stufe, text-tertiary).

**Org-Slug:** `THEKROLL-LTD` (in GitHub-URLs: `https://github.com/THEKROLL-LTD/fathometer`).

**Logo:** Inline-SVG, 1930er-Echolot-Visual-Language. Komponenten:
- Außen-Halbkreis-Dial (24-Radius über `path A`)
- Drei Cardinal-Tick-Marks (links, oben, rechts)
- Horizontale Wasser-Linie über den Äquator (0.85-Stroke, 0.55-Opacity)
- Seabed-Wave (quadratische `Q`-Bezier, 1-Stroke, 0.45-Opacity)
- Sweep-Needle (cyan, 1.5-Stroke, square linecap) mit Echo-Dot (cyan-Circle r=2.6) am Tip
- Pivot-Circle in der Mitte

**Logo-Animationen:**
- `.topbar__logo-sweep` rotiert -72° ↔ +72° in 4.4 s mit `--ease-drift`, `alternate`, infinite
- `.topbar__logo-echo` pulsiert (opacity 1 ↔ 0.45) in 2.4 s ease-in-out, infinite (Keyframe-Name `op-pulse` — wiederverwendet als „Operational-Pulse" für Status-Dots im Rest des Designs)

Die `FathometerLogo`-React-Komponente aus `docs/design/app.jsx` wird in Block W zu einem Jinja-Macro `{% macro fathometer_logo(class="topbar__logo") %}` in `app/templates/_macros.html` portiert. SVG-Markup identisch, Klassen-Hook für Größe/Farb-Inheritance über `class`-Parameter.

**Renaming-Scope:**
- UI-Strings (`<title>`, Topbar-Wordmark, Footer-Tagline) **ja**
- Repo-Name (`secscan/` Verzeichnis im Filesystem, GitHub-Repo, Docker-Image-Tag, Container-Namen, Audit-String-IDs, CLAUDE.md, ARCHITECTURE.md, ADR-Filenames, Test-Module-Pfade) **nein** — Block W ist Frontend-Rename ohne Backend-/Repo-Churn. Domain-Modell + Code-Identifier behalten `secscan`-Slug. Re-Open-Trigger: wenn ein dedizierter Repo-Rename-Block kommt, separate ADR.

### 2. Typography

**Font-Stack:**
- **Display-Serif:** `Georgia, 'Times New Roman', serif` (Token `--font-display`). Brief erwähnt Editorial New / Romie als Wunsch-Substitution wenn lizenziert verfügbar — Block W liefert das nicht (kein Asset im Repo, keine Lizenz beschafft). Display-Serif wird verwendet für KPI-Zahlen (`.stat__num` 144 px), Auth-Title („Operator credentials." 36 px), Fleet-Section-Header. **Block W lädt keine Web-Font für Display** — Georgia ist System-Font, kein Asset-Roundtrip.
- **Mono (Body + System + Caption):** `'JetBrains Mono', 'Fira Code', ui-monospace, monospace` (Tokens `--font-body`, `--font-mono`). Self-hosted woff2-Assets in `app/static/dist/fonts/`:
  - `JetBrainsMono-Light.woff2` (weight 300)
  - `JetBrainsMono-Regular.woff2` (weight 400)
  - `JetBrainsMono-Bold.woff2` (weight 700)
- `font-display: swap` für alle drei (keine FOIT, akzeptable kurze FOUT). Total Asset-Größe ~150 KB.
- Body ist mono — bewusste Brand-Entscheidung („THEKROLL ships mono everywhere — body IS mono"). Keine Sans-Serif-Body-Font.

**Type-Scale-Tokens (Desktop):**
```
--type-display-xl: clamp(64px,  8vw, 160px);   line-height 0.9,  -0.03em
--type-display-l:  clamp(40px,  5vw,  96px);   line-height 0.95, -0.02em
--type-display-m:  clamp(28px,  3vw,  56px);   line-height 1.0,  -0.01em
--type-heading:    20px;                        line-height 1.3,  -0.01em
--type-body:       16px;                        line-height 1.6
--type-body-sm:    14px;                        line-height 1.5,  +0.01em
--type-caption:    12px;                        line-height 1.4,  +0.03em
```

### 3. Color-Doctrine

**Surface-Layering (geschichtetes Schwarz):**
```
--surface-base:      #0A0A0A   page background
--surface-raised:    #111111   panels, cards
--surface-elevated:  #1A1A1A   modals, active areas
--surface-hover:     #222222   hover states
--border-subtle:     #2A2A2A   hairlines
--border-visible:    #333333   active frames
```

**Text-Stufen:**
```
--text-primary:    #EDEDED
--text-secondary:  #999999
--text-tertiary:   #666666
--text-ghost:      #444444
```

**Accent (single signal):**
```
--accent:        #00E5FF   operational status, focus, cursor proximity
--accent-glow:   rgba(0, 229, 255, 0.15)
```

**Reserved Status Accents (sparingly):**
```
--status-operational: #39FF14   live-indicator pulse (selten genutzt)
--status-degraded:    #FF9500
--status-down:        #FF3B30
--status-restricted:  #FF4444   profile-menu Logout-Item, auth__error
```

**Color-Reduction-Rule (verbindlich):**

> **Nur „escalate" trägt cyan.** Alle anderen Risk-Bands (act / mitigate / pending / monitor / noise / unknown) und alle anderen Server-States (warn / ok / unknown) fallen auf grau-Stufen (`--text-secondary`, `--text-tertiary`, `--border-visible`, `--text-ghost`). Cyan ist das Eye-Catcher-Signal, nicht Wallpaper.

Konsequenz für die Sidebar-Heartbeat-Bar (ADR-0035): pro Daily-Cell nur **escalate-State** → cyan; warn → text-secondary-grau; ok → border-visible-grau; unknown → text-ghost mit 0.35-Opacity. Heute mappen wir 5 CVSS-Severities auf 5 Farben — das wird in ADR-0035 auf 4 Server-Risk-States reduziert, **aber nur escalate ist cyan**. Die alte Severity-Heatmap-Logik fliegt im Heartbeat raus.

Konsequenz für die Dashboard-KPI-Cards: `--accent` nur auf der `stat--alarm`-Card (Action-Needed). Die `stat--safe`/`stat--nominal`-Card bleibt grau-text-secondary. Sub-Counter-Zahlen sind text-primary, Labels text-tertiary. Keine grünen/orangen Severity-Highlights wie heute (Tier-3-Strip).

### 4. Easing-Doctrine

**Drei Eases — und nur diese drei:**
```
--ease-materialize: cubic-bezier(0.16, 1, 0.3, 1)    enter — slow, choreographed
--ease-dismiss:     cubic-bezier(0.4, 0, 1, 1)       exit — fast, decisive
--ease-drift:       cubic-bezier(0.25, 0.1, 0.25, 1) continuous — cursor, parallax, sweep
```

**Dauern:**
```
--dur-enter:    600ms   neue Elemente materialisieren langsam
--dur-exit:     300ms   Exit ist halbsoschnell wie Enter, decisive
--dur-hover:    200ms   alle Hover-Transitions
--dur-cursor:   80ms    Cursor-following
--dur-stagger:  60ms    Per-Item-Stagger-Delays
```

**Doctrine §1 „Materialization, not animation":** Neue Elemente entstehen langsam mit `ease-materialize`. Exits sind kurz und entschieden mit `ease-dismiss`. Kontinuierliche Bewegung (Sweep, Drift) nutzt `ease-drift`. Andere Eases (`ease-in`, `ease-out`, `linear`, Custom-Cubic-Beziers außerhalb der drei oben) sind **nicht erlaubt**, außer für rein dekorative Sub-Anims (z.B. `stat-scan` linear infinite — das ist ein technischer Sweep-Beam, nicht Material-Bewegung).

### 5. Verbotsliste (verbindlich)

- **Border-Radius max 8 px** (Token `--radius-max: 8px`). Keine `rounded-box`/`rounded-2xl`/`rounded-full` außer für Status-Dots (kreis-rund, `border-radius: 50%`) und das Profile-Avatar-Square (kein Radius). Daisy-/Tailwind-Defaults werden in Block W konsequent ersetzt.
- **Box-Shadow:** Verboten als Elevation-Mittel. Elevation kommt aus dem Surface-Step gegen den Page-Background (`--surface-base` → `--surface-raised` → `--surface-elevated`). Ausnahme: `box-shadow` als Glow-Effekt für `--accent`-Status-Dots (`box-shadow: 0 0 8px var(--accent-glow)`) — das ist ein Lichteffekt, keine Elevation.
- **Animationen mit anderen Eases** als den drei oben (siehe §4).
- **Pflicht-Kommentare in der UI** — bleibt aus [ADR-0006](0006-no-forced-comments.md) bestehen, hier nur referenziert.

### 6. Background-Grid

Globales `.bg-grid`-Element auf jeder App-Route + Login: fixed 80×80 px Lattice via `linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px)` horizontal + vertikal, `pointer-events: none`, `z-index: 0`. Content liegt mit `z-index: 1` darüber. Ambient-Detail, dezent — nicht mit dem ähnlichen DaisyUI-Grid verwechseln.

### 7. Footer

Auf **allen** Routen (Login + App-Shell) sichtbar. 28 px hoch (Grid-Row `auto` mit fixed-Höhe), `border-top: var(--hairline)`, mono 11 px text-tertiary, accent on hover. Layout:

```
v{VERSION} · docs · [github-icon] github                       thekroll ltd · human intent. machine precision.
```

- `v{VERSION}` → `https://github.com/THEKROLL-LTD/fathometer/releases/tag/v{VERSION}` (dynamisch aus Build-Time-`SECSCAN_VERSION` via Jinja-Context-Processor)
- `docs` → `https://github.com/THEKROLL-LTD/fathometer#readme` (Default — falls eine dedizierte Docs-URL etabliert wird, wird der Link dort hin gerichtet)
- `github` → `https://github.com/THEKROLL-LTD/fathometer`
- Rechts: `thekroll ltd · human intent. machine precision.`

### 8. Sprach-Policy

**Ziel-Sprache UI:** Englisch. Auf lange Sicht ist die gesamte UI englisch (Login, Topbar, Sidebar, Dashboard, Server-Detail, Findings, Settings, Audit, Setup-Wizard, Flash-Messages, Error-Messages).

**Phase-1-Migration:** Block W übersetzt **nur die Surfaces die in Block W angefasst werden**:
- Login (`Operator credentials.`, `No signup. No reset. No SSO. Internal operators only.`, `username`, `password`, `authenticate`, `verifying`, `[access denied]`)
- Topbar (`Dashboard`, `Findings`)
- Profile-Dropdown (`Angemeldet als` → `Logged in as`, `Settings`, `Audit`, `Logout`)
- Sidebar (`filter hosts ( / )`, `N hosts · N alarm` / `all quiet`, `host · escalate · act`, OS-Subline bleibt unverändert technisch)
- Dashboard-Pane (`Dashboard · Fleet overview · last refresh · {now}`, `[action needed]`, `/ N hosts`, `N escalate · N act · N pending`, `open triage queue →`, `[nominal]`, `N monitor · N noise · N unknown`, `Triage queue`, `CVSS Severity distribution · all hosts`, `> last scan Nm ago · epss-feed synced · kev-feed synced · worker healthy`)
- Footer (`v{VERSION}`, `docs`, `github`, `thekroll ltd · human intent. machine precision.`)

**Phase-1-belasse-auf-Deutsch:**
- Settings (`app/templates/settings/*.html`) — alle Strings bleiben deutsch
- Server-Detail (`app/templates/servers/detail.html` + Partials) — bleibt deutsch
- Findings (`app/templates/findings/*.html` + Modals) — bleibt deutsch
- Audit (`app/templates/audit/list.html`) — bleibt deutsch
- Setup-Wizard (`app/templates/setup/*.html`) — bleibt deutsch
- Flash-Messages aus Views die diese Surfaces betreiben — bleiben deutsch

**Phase-2-Übersetzung** läuft pro Surface-Redesign: wenn z.B. Server-Detail in einem zukünftigen Block redesigned wird, werden die Strings dort gleichzeitig auf Englisch übersetzt. Ein eigener „nur Übersetzung"-Block ist explizit **nicht** geplant — Sprach-Migration ist Sub-Aufgabe pro Re-Design-Block.

**Doc-Sprache + Code-Kommentare** bleiben unverändert auf **Deutsch** (CLAUDE.md-Konvention: „Doc-Sprache und Code-Kommentare auf Deutsch (User-Präferenz). Code selbst (Bezeichner, Strings) auf Englisch."). ADRs, Block-Specs, ARCHITECTURE.md, README, techdebt.md bleiben deutsch. Code-Identifier bleiben englisch wie heute.

**Risk-Band-Labels und Server-State-Labels** (`escalate`, `act`, `mitigate`, `pending`, `monitor`, `noise`, `unknown`, `alarm`, `warn`, `ok`) sind seit ADR-0022 englisch im Code und werden 1:1 ohne Übersetzung in der UI angezeigt. Das war auch im heutigen Deutsch-UI schon so — kein Bruch.

## Konsequenzen

- **Asset-Größe:** +150 KB für JetBrains-Mono-woff2 (3 Weights). Akzeptabel weil self-hosted, cache-fähig, kein externer Roundtrip. Display-Font (Georgia) ist System — kein Asset.
- **Logo-Macro** (`{% macro fathometer_logo() %}` in `_macros.html`) wird von Topbar + Login + Setup-Wizard (wenn der mal redesigned wird) konsumiert. Single-Source-of-Truth.
- **Color-Reduction-Rule** muss bei jedem neuen Element im Code-Review gegen die Doctrine geprüft werden. Implementer-Prompts erinnern explizit daran.
- **Easing-Doctrine** ist im Token-File hart codiert — Custom-Cubic-Beziers in Templates/CSS-Files lösen Reviewer-Reject aus.
- **Verbotsliste Border-Radius/Box-Shadow** ist Pflicht-Lint-Check im Phase-1-Review. Implementer-Agent bekommt die Liste explizit in den Prompt.
- **Sprach-Policy ist Soft-Policy** (keine maschinelle Prüfung) — Reviewer prüft pro PR ob die Surface-Sprache konsistent ist mit dem Redesign-Status. Bei Drift (z.B. deutsche Flash-Message taucht in der neuen englischen Dashboard-Sektion auf): TD-Eintrag oder direkter Fix.

## Verworfen

- **`FATHOMETER` (ALLCAPS) als Produktname** im Markup: User-Korrektur am 2026-05-23 — Markup ist Mixed Case `Fathometer`, CSS macht das uppercase-Rendering. Vorteil: SEO-Tags, `<title>`, ARIA-Labels, Browser-Tabs zeigen lesbares Mixed Case.
- **Repo-Rename auf `fathometer/`** in Phase 1: würde Container-Image-Namen, Audit-IDs, Test-Modul-Pfade, alle ADRs und CLAUDE.md anfassen — out of scope. Re-Open-Trigger separat.
- **Editorial New / Romie als Display-Font**: lizenz-pflichtig, nicht im Repo verfügbar. Georgia-System-Font ist die Substitution. Re-Open wenn Lizenz beschafft.
- **Vollständige UI-Übersetzung in Phase 1** (alle Templates auf Englisch): zu viel Surface-Touch ohne Re-Design — Translation-Drift-Risiko (Strings drücken Bedeutung anders aus als heute, ohne dass das Layout/UX-Pattern auch übersetzt wird).

## Re-Open-Trigger

- Wenn Editorial New / Romie (oder eine andere Custom-Display-Font) lizenziert werden: ADR ergänzen, woff2 in `dist/fonts/`, Token-Update.
- Wenn Tailwind/DaisyUI doch in Phase 1 zurückgeholt werden (siehe ADR-0032 Re-Open-Trigger), Border-Radius-Verbotsliste und Color-Reduction-Rule müssen in deren Theme-Config überführt werden.
- Wenn ein zweites Theme (z.B. ein hochkontrast-Accessibility-Mode) gewünscht wird, ADR-0031 + ADR-0033 müssen die Token-Variation gemeinsam definieren.
- Wenn der Repo-Rename auf `fathometer` beschlossen wird, separater ADR.
