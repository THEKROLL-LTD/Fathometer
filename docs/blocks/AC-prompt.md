# Block AC — Orchestrator-Prompt

Implementiere **Block AC** (Sidebar-Group-Aufklapp-Zustand persistent via Cookie + Server-Render: Operator klappt Gruppe auf → bleibt offen über Polling-Swap, Reload und Browser-Sessions).

## Pflicht-Lektüre vor dem ersten Codestrich

1. `CLAUDE.md` — komplett (Test-Konvention, Timeout-Regeln, OOB-Single-Source-Pattern, UI-Sprache englisch ADR-0045).
2. `docs/blocks/AC-sidebar-group-state.md` — Block-Spec: Datei-Tabelle, drei Phasen, Test-Matrix, maschinell prüfbare DoD, Konflikt-Hinweis zu Block AB.
3. `docs/decisions/0046-sidebar-group-state-cookie.md` — ADR: Cookie-Format, Schreib-/Lese-Semantik (DOM ist Quelle beim Schreiben, Cookie ist Quelle beim Rendern), Verworfenes (kein localStorage, kein hx-preserve, keine DB).
4. `docs/decisions/0034-host-group-data-model.md` §Sidebar-Verhalten — Default collapsed bleibt der Fallback ohne Cookie.
5. `app/views/_sidebar_context.py` — `build_sidebar_context()` ist der gemeinsame Context-Builder beider Render-Pfade (Context-Processor + `GET /_partials/sidebar`). Cookie-Read gehört genau dorthin, nirgendwo doppelt.
6. `app/templates/sidebar/_group_section.html` — das eine Group-Partial (Single-Source, beide Pfade includieren es). `open` + `aria-expanded` conditional hier.
7. `app/static/js/sidebar.js` — bestehender IIFE-Stil, delegierte Handler auf `#server-list` als Vorbild (Heartbeat-Tooltip). Neuer `toggle`-Listener in der Capture-Phase.
8. `app/templates/sidebar/_server_list.html` — Swap-Mechanik (`hx-trigger="load"` + `every 60s`, `outerHTML`), damit klar ist warum Server-Render die einzige drift-freie Lösung ist.

## Arbeitsweise

- **Branch:** Spec §Konflikt-Hinweis zuerst — wenn Block AB (`feat/block-ab-english-ui`) gemerged ist, von aktualisiertem `main` abzweigen; sonst Merge-Konflikt in `sidebar.js` einplanen (AB ändert dort nur Strings). Branch `feat/block-ac-sidebar-group-state`.
- **Reihenfolge A → B → C, ein Commit pro Phase.** A (Server-Read + Render + Tests) ist unabhängig von B (Client-Write) testbar.
- Pro Phase: implementieren → Tests → `ruff check . && ruff format --check .` → `mypy app/` → `pytest` (Default-Selektion, Bash-Timeout ≤ 120000 ms; fokussiert ≤ 60000 ms) → Phasen-DoD prüfen.
- **Cookie-Vertrag exakt einhalten:** Name `sidebar_open_groups`, Wert kommaseparierte Int-IDs, `Max-Age=31536000; Path=/; SameSite=Lax`. Server-Parse defensiv (nur Ints, 512-Zeichen-/64-ID-Cap, Garbage still verwerfen, niemals 500). JS schreibt das Cookie immer **komplett neu aus dem DOM-Ist-Zustand** — kein inkrementelles Add/Remove.
- **Kein** neuer Endpoint, **keine** Migration, **kein** localStorage, **kein** `hx-preserve`, **keine** JS-Test-Infrastruktur, **keine** neuen UI-Strings (falls unvermeidbar: englisch, ADR-0045).
- Default-Verhalten ohne Cookie = alles collapsed — bestehende Sidebar-Tests sind der Regressions-Anker und dürfen nicht angepasst werden um grün zu werden.
- **Keine** db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-/Browser-Tests. Erlaubte Gates: ruff, mypy, shellcheck, pytest Default-Selektion (Pure-Unit, Mocks/Test-Client).
- Wenn ein Quality-Gate rot ist: selbst fixen, nicht den User fragen.
- Wenn sich herausstellt, dass ein Render-Pfad **nicht** durch `build_sidebar_context()` läuft (Spec-Annahme verletzt): **STOP**, User fragen — nicht einen zweiten Cookie-Read-Pfad bauen.
- Nach Phase C: Block-Gesamt-DoD aus der Spec prüfen (6 Punkte), Zusammenfassung mit Test-Zahlen melden. Operator-Browser-Smoke (5 Punkte in der Spec) bleibt beim User. Erst dann stoppt der Agent.

## Was NICHT im Prompt steht (weil in Block-Spec + ADR)

Cookie-Parse-Details, Template-Conditional-Form inkl. Undefined-Fallback, Capture-Phase-Begründung (`toggle` bubbelt nicht), `aria-expanded`-Nachzug, Test-Matrix (Garbage/Overlong/Beide-Pfade-Identität), Out-of-Scope-Liste (kein Auto-Expand bei Suche, keine anderen `<details>`-Flächen) — alles in `AC-sidebar-group-state.md` + ADR-0046. Dort nachschlagen, nicht raten.
