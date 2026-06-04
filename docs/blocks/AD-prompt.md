# Block AD — Orchestrator-Prompt

Implementiere **Block AD** (Settings-Redesign: vertikale 224px-Sekundär-Nav → horizontale Sticky-Tab-Nav `.settings-tabs`, alle sieben Subseiten auf die `s-*`-Komponentenschicht aus dem Claude-Design-Mockup, DaisyUI raus aus den Settings-Surfaces. Reines Restyling — keine Routen-/Schema-/Helper-Änderungen).

## Pflicht-Lektüre vor dem ersten Codestrich

1. `CLAUDE.md` — komplett (Test-Konvention, Timeout-Regeln, UI-Sprache englisch ADR-0045, Out-of-Scope-Liste).
2. `docs/blocks/AD-settings-redesign.md` — Block-Spec: Datei-Tabelle, Phasen 0→E, User-Entscheidungen (Eyebrow ohne Nummerierung, Reviewer-KPI-Block wie Mockup), Querschnitts-Regeln, maschinell prüfbare DoD, Out of Scope.
3. Mockup als Design-Quelle: `docs/design/settings.css` (Komponentenschicht, 1:1-Port-Vorlage), `docs/design/settings-app.jsx` (Tab-Nav: Reihenfolge, Labels, Badge, ARIA), `docs/design/settings-panels-1.jsx` + `settings-panels-2.jsx` (Markup-Struktur jedes Panels). Die JSX-Dateien sind **Markup-Referenz, kein Funktions-Auftrag** — React-State/Mock-Daten nicht nachbauen.
4. `app/views/_settings_shell.py` — der 3-Modi-Render-Helper. **Lesen um ihn NICHT zu ändern:** Modi, Header-Logik und Template-Verträge bleiben exakt so.
5. `app/templates/settings/_nav.html`, `_shell.html`, `_page.html` — Ist-Zustand inkl. HTMX-Attribut-Satz, der 1:1 in die neue Tab-Nav übernommen wird.
6. `app/templates/settings/*.html` (alle 7 Content-Templates) — bestehende Form-/CSRF-/HTMX-Flows; die bleiben funktional identisch, nur Klassen/Struktur ändern sich.
7. `frontend/src/css/app.css` + `tokens.css` + `components/settings-manage.css` — Import-Reihenfolge (neuer Import vor legacy-shim), Token-Bestand (alle Mockup-Vars existieren, geprüft 2026-06-04), was am Ende gelöscht wird.
8. `tests/templates/test_settings_legacy_still_renders.py` — Render-Pattern für Content-Templates ohne `extends` (Mock-Manifest); Vorlage für die neuen Smoke-Tests.
9. `tests/test_ui_language.py` — der Sprach-Sweep, der bei deutschen Mockup-Strings rot wird.

## Arbeitsweise

- **Branch:** `feat/block-ad-settings-redesign` von aktuellem `main`. Vorher klären (User fragen, einmalig): die uncommitted `docs/design/*`-Dateien im Working-Tree gehören laut STATE.md nicht zu Block AC — ob sie mit in den AD-Branch committet werden oder einen eigenen Design-Commit bekommen.
- **Phase 0 zuerst:** ADR-0047 schreiben (löst den Sekundär-Nav-Teil von ADR-0016 ab, verweist auf Block-Spec), in `docs/decisions/README.md` eintragen.
- **Reihenfolge 0 → A → B → C → D → E, ein Commit pro Phase.** Phase C darf in zwei Commits geteilt werden (C1: servers/tags/groups, C2: llm_provider/llm_reviewer/llm_debug_log/master_key/about) — die Subseiten sind disjunkte Dateien und parallelisierbar an zwei Implementer-Agenten.
- Pro Phase: implementieren → Tests → `ruff check . && ruff format --check .` → `mypy app/` → `pytest` (Default-Selektion, Bash-Timeout ≤ 120000 ms; fokussiert ≤ 60000 ms) → Phasen-Punkte der Spec abhaken.
- **Subagent-Prompts** (Implementer/Test-Writer/Reviewer) enthalten wörtlich: die Querschnitts-Regeln aus Spec §Phase C (englische UI-Strings, kein `|safe`, keine Pflicht-Kommentare, nur Tokens, kein DaisyUI) **und** „Erlaubte Quality-Gates: ruff, mypy, shellcheck (Linter), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien." **und** „Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf)." Subagenten nennen die zu lesenden Spec-Sektionen und Mockup-Dateien explizit — nicht „lies das Repo".
- **HTMX-Vertrag exakt einhalten:** IDs `settings-content` + `detail-pane-content` unverändert; Tab-Links behalten `hx-get`/`hx-target="#settings-content"`/`hx-swap="innerHTML"`/`hx-push-url="true"`/`hx-headers='{"HX-Target": "settings-content"}'` + `href`-Fallback.
- **CSS-Port ist ein Port, kein Redesign:** `docs/design/settings.css` inhaltlich 1:1 übernehmen; einzige Eingriffe laut Spec §Phase A (Garbage-Kommentar Zeile 865 fixen, `.profile-menu__item--active` nach `profile-menu.css`). Keine eigenen Verschönerungen.
- **Funktions-Parität:** jede bestehende Form, jeder Endpoint-Aufruf, jeder CSRF-Token, jede Confirm-Logik der 7 Subseiten existiert nachher noch. Mockup-Elemente ohne Backend (Log-Pause/-Copy etc.): weglassen + `TD-NNN`-Eintrag in `docs/techdebt.md`, nicht halb bauen.
- **Kein** Eingriff in `app/views/_settings_shell.py`, `settings.py`, `llm_settings.py` (Views), **keine** Migration, **keine** neuen Endpoints, **keine** neuen deutschen UI-Strings, **kein** Node-Build (ADR-001).
- **Keine** db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-/Browser-Tests — auch nicht „zur Sicherheit" nach Phase E. Die beiden bestehenden db_integration-Settings-Tests werden weder angefasst noch ausgeführt.
- Wenn ein Quality-Gate rot ist: selbst fixen, nicht den User fragen.
- **STOP und User fragen** wenn: (a) ein Render-Modus von `render_settings()` mit der neuen Shell-Struktur nicht mehr funktionieren kann ohne Helper-Änderung, (b) ein bestehender Settings-Flow ohne DaisyUI-JS-Verhalten (z. B. DaisyUI-Modal/Dropdown-Mechanik) nicht rein mit Alpine + neuem CSS abbildbar scheint, (c) ein Test nur mit verbotenem Marker schreibbar wäre.
- Nach Phase E: Block-Gesamt-DoD aus der Spec prüfen (9 Punkte, grep-Kommandos stehen drin), Zusammenfassung mit Test-Zahlen melden, STATE.md aktualisieren. Operator-Browser-Smoke (Liste in der Spec) bleibt beim User. **Nicht committen ohne explizite User-Anweisung gilt NICHT für diesen Block** — ein Commit pro Phase ist hier ausdrücklich Teil des Auftrags; **kein Merge, kein Tag** (v0.19.0 erst nach Merge auf main, durch den User).
- **STOP am Block-Ende** — nicht eigenmächtig den nächsten Block beginnen.

## Was NICHT im Prompt steht (weil in Block-Spec + Mockup)

Tab-Reihenfolge/Labels, Klassen-Mapping pro Subseite (welches `s-*`-Pattern wohin), Header-Pattern ohne Nummerierung, Empty-States, Container-Query-Fallbacks, Test-Matrix (Nav-Render, Smoke pro Subseite, anzupassende Bestandstests), DoD-grep-Kommandos, Out-of-Scope-Liste (`servers/settings.html`, Topbar/Sidebar/Footer, Mockup-Features ohne Backend) — alles in `AD-settings-redesign.md` + den vier Mockup-Dateien. Dort nachschlagen, nicht raten.
