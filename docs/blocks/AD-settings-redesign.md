# Block AD — Settings-Redesign (horizontale Tab-Nav + `s-*`-Komponentenschicht)

**Spec-Quelle:** Mockup `docs/design/Settings.html` (+ `settings.css`, `settings-app.jsx`, `settings-panels-1.jsx`, `settings-panels-2.jsx`) · ADR-0047 (in Phase 0 zu erstellen, löst den Sekundär-Nav-Teil von ADR-0016 ab)
**Branch:** `feat/block-ad-settings-redesign`
**Zielversion:** v0.19.0 (nach Block AC; bei früherem Merge Versionierung mit User klären)
**Vorgänger:** Block AC (Sidebar Group State)
**Status:** Geplant (2026-06-04)

## Ziel

Die Settings-Seite (`/settings`) bekommt das Claude-Design-Mockup: die vertikale
224px-Sekundär-Nav links wird durch eine horizontale Sticky-Tab-Nav
(`.settings-tabs`) oben in `.main` ersetzt; alle sieben Subseiten werden auf die
neue `s-*`-Komponentenschicht aus `docs/design/settings.css` umgestellt und
verlieren ihre DaisyUI-/Tailwind-Legacy-Klassen. **Reines Restyling — keine neue
Funktionalität, keine Routen-/Schema-Änderungen, Render-Helper-Logik
(`render_settings()`, 3 Modi) bleibt unangetastet.**

## User-Entscheidungen (2026-06-04)

- **Eyebrow-Nummerierung weglassen.** Mockup zeigt „Settings · 01 / 07" — übernommen
  wird nur der Header-Pattern `settings__eyebrow` (Text „Settings") +
  `settings__title` + `settings__lede`, ohne Zählung.
- **Reviewer-KPI-Block übernehmen wie im Mockup.** Die Job-Queue-Kacheln
  (`s-kpis`: Queued / In progress / Done · 24h / Failed · 24h) existieren
  funktional bereits (`_llm_reviewer_stats()`) und werden nur schöner. Die
  „less is more"-Präferenz gilt für Server-Detail, nicht für Settings.

## Abgrenzung / Konflikt-Hinweis

- Die `docs/design/*`-Dateien liegen uncommitted im Working-Tree und gehören
  laut STATE.md **nicht** zu Block AC — beim Branch-Start sauber zuordnen
  (Design-Dateien gehören zu Block AD oder einem eigenen Design-Commit, mit
  User klären).
- `servers/settings.html` (Server-Detail-Settings) ist eine **andere** Seite
  und bleibt unberührt.

## Betroffene Dateien (vollständig)

| Datei | Änderung |
|---|---|
| `frontend/src/css/components/settings.css` | **neu** — Port von `docs/design/settings.css` |
| `frontend/src/css/app.css` | `@import` für `settings.css` (vor legacy-shim) |
| `frontend/src/css/components/profile-menu.css` | `.profile-menu__item--active` aus Mockup-CSS hierher |
| `frontend/src/css/components/settings-manage.css` | **löschen** nach Tags/Groups-Migration |
| `app/templates/layout/_header.html` | aktiven Eintrag (Settings) im Profile-Dropdown markieren |
| `app/templates/settings/_nav.html` | vertikale Menu-Liste → horizontale `.settings-tabs` |
| `app/templates/settings/_shell.html` | Flex-Row (Nav \| Content) → Spalte (Tabs oben, Content darunter) |
| `app/templates/settings/_page.html` | dito |
| `app/templates/settings/servers.html` | Restyling auf `s-table`/`s-servers__*`/`s-pill`/`s-overflow` |
| `app/templates/settings/tags.html` | `sd-manage-*` → `s-table`/`s-tags__*`/`s-empty` |
| `app/templates/settings/groups.html` | `sd-manage-*` → `s-table`/`s-groups__*`/`s-empty` |
| `app/templates/settings/llm_provider.html` | Restyling auf `s-card`/`s-fields-grid`/`s-actions`/`s-feeds` |
| `app/templates/settings/llm_reviewer.html` | Restyling auf `s-statusbar`/`s-slider-row`/`s-kpis`/`s-twoup`/`s-kv`/`s-subtabs` |
| `app/templates/settings/llm_debug_log.html` | Restyling auf `s-subtabs`/`s-log`/`s-log-filters` |
| `app/templates/settings/master_key.html` | Restyling auf `s-key-status`/`s-warning`/`s-key-reveal` |
| `app/templates/settings/about.html` | Restyling auf `s-about-grid` |
| `tests/…` | siehe Phase D |

`app/views/_settings_shell.py`, `app/views/settings.py`, `app/views/llm_settings.py`:
**keine Änderung** (Routen, Modi, Kontext-Verträge bleiben).

## Phasen

### Phase 0 — ADR + Branch

- ADR-0047 „Settings: horizontale Tab-Nav + `s-*`-Komponentenschicht" schreiben
  (Ablöse-Verweis auf ADR-0016-Sekundär-Nav, Verweis auf dieses Block-File).
- Branch `feat/block-ad-settings-redesign` von aktuellem `main`.

### Phase A — CSS-Port

- `docs/design/settings.css` → `frontend/src/css/components/settings.css`.
  Beim Port:
  - Kaputten Kommentar Zeile 865 fixen (`*/──…*/`-Garbage nach dem
    Comment-Close — invalides CSS, nicht blind kopieren).
  - `.profile-menu__item--active`-Block nach `profile-menu.css` verschieben
    (Topbar-Scope, nicht Settings-Scope).
  - Token-Abgleich: alle benutzten Custom-Properties existieren bereits in
    `tokens.css` (geprüft 2026-06-04 — keine fehlt). Keine neuen Hex-Farben.
- `@import "./components/settings.css";` in `app.css` vor dem legacy-shim.
- Frontend-Build grün.

### Phase B — Shell-Umbau (vertikal → horizontal)

- `_nav.html`: `<nav class="settings-tabs" role="tablist">` mit 7 Tabs in
  Mockup-Reihenfolge: **Servers, Tags, Groups, LLM Provider, LLM Reviewer,
  Master-Key (Badge „new" als `settings-tabs__badge`), About.**
  - Label „Servers" statt „Server management" (passt zum bestehenden
    `settings_index`-Redirect auf `servers.list_servers`).
  - **HTMX-Attribute 1:1 erhalten:** `hx-get`, `hx-target="#settings-content"`,
    `hx-swap="innerHTML"`, `hx-push-url="true"`,
    `hx-headers='{"HX-Target": "settings-content"}'`, `href`-Fallback.
  - Aktiver Tab: `settings-tabs__item--active` + `aria-selected`.
- `_shell.html` + `_page.html`: Tabs oben, darunter `#settings-content` mit
  `.settings`-Frame. **IDs `settings-content` und `detail-pane-content`
  unverändert** — Test- und HTMX-Verträge.
- `_header.html`: Profile-Dropdown markiert „Settings" via
  `profile-menu__item--active`, wenn eine Settings-Route aktiv ist.

### Phase C — Subseiten-Restyling (pro Template ein Implementer-Task)

Jede Seite: Header-Pattern `settings__eyebrow` („Settings", ohne Nummer) +
`settings__title` + `settings__lede`.

1. **servers.html** — `s-table`/`s-servers__*`; Status als `s-pill`
   (active/retired/revoked); Aktionen (Rotate key / Retire / Revoke) als
   `s-overflow`-Menü (Alpine für open/close, bestehende Form-/Confirm-Flows
   beibehalten); „Add a server"-Hinweis-Sektion (Registrierung via
   `secscan-register.sh`, kein UI-Onboarding).
2. **tags.html** — `s-table`/`s-tags__*`; Color-Picker als Alpine-Popover
   (Palette-Grid über `s-overflow__menu`-Pattern); Rename/Color/Delete-Forms
   + CSRF unverändert; Empty-State `s-empty`; kein Anlege-Form (ADR-0040).
3. **groups.html** — `s-table`/`s-groups__*` inkl. `s-groups__reorder`-Pfeile
   (bestehende Move-Endpoints); sonst wie Tags.
4. **llm_provider.html** — `s-card` + `s-fields-grid` + `s-actions`
   (Preset/Name/Base-URL/Model/API-Key); Token-Cap mit Progress-Hairline;
   External Feeds (EPSS/KEV) als `s-feeds` read-only; Test-Connection- und
   Save-Flow unverändert (`llm_settings.js` ggf. an neue Klassen anpassen).
5. **llm_reviewer.html** — `s-statusbar` (Mode/Model/Worker-Heartbeat),
   `s-slider-row` (Concurrency, Apply), `s-kpis` (Job-Queue, wie Mockup),
   `s-twoup` + `s-kv` (Budget & Cache), Group-Library als `s-table`;
   Sub-Tabs Overview/Debug als `s-subtabs` (bestehende `sub_tab`-Logik).
6. **llm_debug_log.html** — `s-log` + `s-log-filters`; Filter-/Level-Controls
   nur soweit sie heute existieren — Mockup-Buttons ohne Backend (Pause/Copy)
   nur wenn trivial client-seitig, sonst weglassen + TD-Eintrag.
7. **master_key.html** — `s-key-status` (Status/Last rotation/Audit event),
   `s-warning`, Reveal-Box `s-key-reveal`; Rotate-Flow unverändert.
8. **about.html** — `s-about-grid` (Build + Runtime, read-only).

**Querschnitts-Regeln (in jeden Implementer-Prompt wörtlich):**

- UI-Strings **ausschließlich englisch** (ADR-0045) — Mockup-Texte sind teils
  deutsch und werden übersetzt; `tests/test_ui_language.py` muss grün bleiben.
- Kein `|safe` auf User-/LLM-Daten; `tag.color` weiterhin nur in serverseitig
  regex-validierten `style`-Werten.
- Keine Pflicht-Kommentarfelder (ADR-0006).
- Nur Tokens, keine neuen Hex-Farben; ausschließlich `s-*`-/`settings-*`-Klassen,
  kein DaisyUI/Tailwind (kein `card`/`btn`/`badge`/`alert`/`menu`/`tab-active`).
- Erlaubte Quality-Gates: ruff, mypy, shellcheck (Linter), pytest
  Default-Selektion (Pure-Unit). Verboten:
  db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/
  Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien.
- Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms
  (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

### Phase D — Tests

- **Anpassen:**
  - `tests/templates/test_settings_legacy_still_renders.py` — prüft
    DaisyUI-Indikatoren; umschreiben auf `s-*`-Smoke (Render ohne Crash +
    neue Klassen-Indikatoren vorhanden, Legacy-Indikatoren **abwesend**).
  - `tests/templates/test_settings_tags_no_create_form.py` — Selektoren auf
    neue Klassen.
  - `tests/views/test_settings_groups_template.py` / `_move` / `_list` —
    Selektoren auf neue Klassen.
- **Neu (Pure-Unit):**
  - Nav-Render-Test: 7 Tabs in Reihenfolge, Active-Klasse pro `active`-Wert,
    HTMX-Attribute vollständig, Master-Key-Badge.
  - Smoke-Render pro Subseite mit Mock-Kontext (Pattern aus
    `test_settings_legacy_still_renders.py` wiederverwenden).
- **Nicht anfassen / nicht laufen lassen:**
  `tests/integration/test_settings_dropdown_swap_db.py`,
  `tests/integration/test_settings_alias_redirect_db.py` (db_integration —
  nur auf ausdrückliche User-Anweisung).

### Phase E — Cleanup + Doku

- `settings-manage.css` löschen + `@import` entfernen; verbleibende
  `sd-manage-*`-Referenzen grep-verifizieren (0 Treffer). Reste → `TD-NNN`.
- ARCHITECTURE.md: Settings-UI-Abschnitt (horizontale Tabs, `s-*`-Schicht,
  ADR-0047-Verweis).
- CHANGELOG v0.19.0, ADR-Index (`docs/decisions/README.md`), STATE.md.

## Definition of Done (maschinell prüfbar)

1. `ruff check . && ruff format --check .` grün.
2. `mypy app/` grün.
3. Default-`pytest` grün (Timeout-Konvention CLAUDE.md), inkl. neuer
   Template-Tests; `tests/test_ui_language.py` grün.
4. `grep -rn "settings-tabs" app/templates/settings/_nav.html` trifft;
   `grep -rn "w-56\|menu-active" app/templates/settings/` → 0 Treffer.
5. `grep -rn "card\b\|btn\b\|badge\b\|alert\b\|tab-active" app/templates/settings/`
   → 0 Treffer (DaisyUI raus aus Settings-Surfaces).
6. `grep -rn "sd-manage" app/ frontend/` → 0 Treffer;
   `settings-manage.css` existiert nicht mehr.
7. `#settings-content`-ID existiert in `_shell.html` und `_page.html`
   (HTMX-/Test-Vertrag).
8. Keine Änderung an `app/views/_settings_shell.py` (`git diff --stat`).
9. Frontend-Build grün.

**Vom User abzuhaken (Operator-Browser-Smoke, kein automatisierter Test):**
Tab-Wechsel per Klick (HTMX-Content-Swap, Nav bleibt stehen, URL pusht);
Direkt-URL `/settings/tags` etc. (Vollseite); Browser-Refresh auf Sub-Tab;
Profile-Dropdown → Settings (Detail-Pane-Fragment); Master-Key-Rotate-Reveal;
Tag-Farbwechsel; Gruppen-Reorder; schmales Fenster (Container-Query-Fallbacks).

## Out of Scope

- `servers/settings.html` (Server-Detail-Settings — andere Seite).
- Topbar/Sidebar/Footer (Mockup nutzt sie nur als Rahmen; einzige Ausnahme:
  `profile-menu__item--active`-Marker).
- Neue Funktionalität ohne Backend (z. B. Log-Pause/-Copy, Live-Streaming des
  Debug-Logs, „Change mode…"-Modal-Redesign über das Bestehende hinaus).
- Eyebrow-Nummerierung „01 / 07" (User-Entscheidung 2026-06-04).
- Mobile-responsive Layout (ARCHITECTURE §17) — Container-Query-Fallbacks aus
  dem Mockup-CSS werden übernommen, mehr nicht.
