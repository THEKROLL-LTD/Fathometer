# Block AC — Sidebar Group State (Cookie + Server-Render)

**Spec-Quelle:** [ADR-0046](../decisions/0046-sidebar-group-state-cookie.md)
**Branch:** `feat/block-ac-sidebar-group-state`
**Zielversion:** v0.18.0 (nach Block AB; bei früherem Merge Versionierung mit User klären)
**Vorgänger:** Block AB (English UI Migration)
**Status:** Geplant (2026-06-04)

## Ziel

Aufgeklappte Sidebar-Gruppen bleiben aufgeklappt — über Initial-Load, 60s-Polling-Swap, Reload und Browser-Sessions hinweg. Mechanik gemäß ADR-0046: JS schreibt Cookie `sidebar_open_groups`, Server liest es in `build_sidebar_context()` und rendert `open` direkt. **Kein Schema, kein neuer Endpoint, kein neues Markup-Pattern.**

## Konflikt-Hinweis

Block AB (läuft parallel) fasst `sidebar.js` (String-Übersetzung) und Sidebar-Templates an. Vor Branch-Start `git log`/STATE.md prüfen: wenn AB gemerged ist, auf aktualisiertem `main` aufsetzen; sonst Konflikt in `sidebar.js` beim Merge einplanen (nur Strings vs. neue Funktion — trivial auflösbar).

## Betroffene Dateien (vollständig)

| Datei | Änderung |
|---|---|
| `app/views/_sidebar_context.py` | Cookie-Parse-Helper + `sidebar_open_group_ids` in `build_sidebar_context()` |
| `app/templates/sidebar/_group_section.html` | `open`-Attribut + `aria-expanded` conditional |
| `app/static/js/sidebar.js` | `toggle`-Listener (Capture), Cookie-Write aus DOM-Zustand, `aria-expanded`-Nachzug |
| `tests/…` | Pure-Unit-Tests (siehe Phasen) |

## Phasen

### Phase A — Server-Read + Render

- **Cookie-Parser** in `_sidebar_context.py` (modulprivater Helper):
  - Input `request.cookies.get("sidebar_open_groups", "")`.
  - Split auf `,`, pro Token `int()`-Parse, Nicht-Parsebares still verwerfen.
  - Defense-in-Depth: Roh-String > 512 Zeichen → leeres Set; max. 64 IDs übernehmen.
  - Rückgabe `set[int]`, Key `sidebar_open_group_ids` im Context beider Pfade (Context-Processor **und** Polling-Endpoint laufen durch `build_sidebar_context()` — nichts doppelt bauen).
- **Template** `_group_section.html`:
  - `<details … {% if group.id in sidebar_open_group_ids %}open{% endif %}>`
  - `aria-expanded="{{ 'true' if group.id in sidebar_open_group_ids else 'false' }}"`
  - Fallback ohne Variable (`sidebar_open_group_ids` undefined) muss collapsed rendern — `{% if group.id in (sidebar_open_group_ids or ()) %}`-Form oder Context-Garantie; Test deckt beide Pfade.
- **Tests** (Pure-Unit, Test-Client mit `client.set_cookie(…)`):
  - Cookie `"1,5"` → Partial enthält `open` + `aria-expanded="true"` exakt für Gruppen 1 und 5, andere collapsed.
  - Kein Cookie → alles collapsed (ADR-0034-Default bleibt).
  - Garbage-Cookie (`"abc,,-1,1e9,<script>"`) → kein 500, nur valide Ints wirken.
  - Overlong-Cookie (600 Zeichen) → alles collapsed.
  - **Beide Render-Pfade:** Initial-Render (View-Route mit Sidebar) und `GET /_partials/sidebar` rendern bei identischem Cookie identische `open`-Zustände (Single-Source-Nachweis, struktureller Vergleich analog OOB-Drift-Tests).

### Phase B — Client-Write

- In `sidebar.js` (IIFE-Stil des Files beibehalten, kein Alpine nötig):
  - `document.addEventListener("toggle", handler, true)` — Capture, da `toggle` nicht bubbelt. Handler reagiert nur auf `details.hostgroup`-Targets innerhalb `#server-list` (Filter via `closest`/`matches`).
  - Handler sammelt **alle** offenen Gruppen frisch aus dem DOM (`querySelectorAll('#server-list details.hostgroup[open]')`), extrahiert die numerische ID aus `id="hostgroup-<n>"`, schreibt das Cookie komplett neu: `sidebar_open_groups=<ids>; Max-Age=31536000; Path=/; SameSite=Lax`.
  - `aria-expanded` auf dem zugehörigen `<summary>` nachziehen (`true`/`false`).
  - Keine Reaktion auf programmatische Swaps nötig: nach einem HTMX-Swap kommt der Zustand korrekt vom Server, der `toggle`-Listener feuert nur bei echten User-Toggles (Browser feuert `toggle` auch beim Parsen von `open`-Attributen nicht erneut nach Attribut-Set im HTML — verifizieren; falls doch: Handler ist idempotent, weil er den DOM-Ist-Zustand schreibt → kein Schaden).
  - Keine neuen UI-Strings (ADR-0045 beachten — falls doch ein String nötig wird: englisch).
- **Tests:** JS hat keine Test-Infrastruktur im Repo — Verhalten wird über die Server-Tests (Phase A) + Operator-Smoke abgedeckt. Keine neue JS-Test-Infra einführen (wäre Scope-Erweiterung).

### Phase C — Doku + Abschluss

- ARCHITECTURE.md: kurzer Absatz in der Sidebar-Sektion (Cookie-Name, Semantik, ADR-Verweis) — nur wenn die Sidebar dort beschrieben ist, sonst entfällt der Punkt.
- CHANGELOG-Eintrag.
- `docs/decisions/README.md`: Zeile für ADR-0046 (falls noch nicht vorhanden).
- STATE.md-Update (Block AC abgeschlossen, Test-Zahlen).

## Definition of Done (maschinell prüfbar)

1. `ruff check . && ruff format --check .` grün.
2. `mypy app/` grün.
3. Default-`pytest` grün (Timeout-Konvention CLAUDE.md), inkl. der neuen Phase-A-Tests.
4. `grep -n 'sidebar_open_groups' app/views/_sidebar_context.py app/static/js/sidebar.js app/templates/sidebar/_group_section.html` — alle drei Dateien treffen (Name konsistent).
5. Kein neuer Endpoint, keine Migration, kein neues Python-Package: `git diff --stat` zeigt nur die vier Dateibereiche aus der Tabelle + Doku.
6. Bestehende Sidebar-Tests unverändert grün (Default collapsed ohne Cookie ist der Regressions-Anker).

**Vom User abzuhaken (Operator-Browser-Smoke, kein automatisierter Test):** Gruppe aufklappen → 60s-Poll abwarten → bleibt offen; Reload → bleibt offen; zweite Gruppe zu/auf → Zustand beider korrekt; Browser-Neustart → bleibt offen; Suche benutzen → kein Cookie-Schreiben durch Filterei.

## Out of Scope

- Auto-Expand bei aktiver Sidebar-Suche (Re-Open-Trigger in ADR-0046).
- Geräteübergreifende Persistenz / DB-Prefs.
- Aufklapp-Zustand anderer `<details>`-Flächen (Risk-Band-Sections im Server-Detail etc.) — eigener Beschluss falls gewünscht.
- Jegliche Optik-/Markup-Änderungen an der Sidebar über `open`/`aria-expanded` hinaus.
