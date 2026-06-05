# ADR-0047 — Settings: horizontale Tab-Nav + `s-*`-Komponentenschicht

**Status:** Akzeptiert · **Datum:** 2026-06-04 · **Block:** AD — Settings-Redesign

Bezug: [ADR-0016](0016-header-and-profile-dropdown.md) §Settings-View / §Settings-Sekundär-Navigation (der vertikale-Sekundär-Nav-Teil wird hiermit abgelöst — Profile-Dropdown-Eintrag „Settings" und die Drei-Modi-Render-Strategie bleiben gültig), [ADR-0032](0032-frontend-build-plain-css.md) (Plain-CSS + Legacy-Shim, kein DaisyUI/Tailwind), [ADR-0033](0033-brand-identity-fathometer.md) (Design-Doctrine, Token-Schicht), [ADR-0045](0045-english-only-ui.md) (UI englisch), [ADR-0040](0040-group-and-tag-hybrid-lifecycle.md) (Tags/Groups Manage-Only, kein Anlege-Form). Block-Spec: `docs/blocks/AD-settings-redesign.md`.

## Kontext

Die Settings-View (`/settings/*`) lief seit ADR-0016/Block-I auf einer vertikalen 224px-Sekundär-Nav (`_nav.html`, `w-56`-DaisyUI-`menu`) links neben dem Content. Die sieben Subseiten (Servers, Tags, Groups, LLM Provider, LLM Reviewer, Master-Key, About) waren als einzige App-Fläche nach der Block-W-Redesign-Welle noch durchgängig auf DaisyUI/Tailwind (`card`/`btn`/`badge`/`alert`/`menu`/`table`) und damit auf den `legacy-shim.css`-Notbehelf angewiesen. ADR-0040 hatte Tags/Groups bereits auf eine eigene `sd-manage-*`-Schicht gehoben, aber inkonsistent zum übrigen Settings-Bereich.

Das Claude-Design-Mockup (`docs/design/Settings.html` + `settings.css` + `settings-app.jsx` + `settings-panels-{1,2}.jsx`) liefert ein vollständiges Settings-Redesign: horizontale Sticky-Tab-Nav oben in `.main` statt vertikaler Sidebar, plus eine durchgängige `s-*`-Komponentenschicht (Tabellen, Pills, Overflow-Menüs, Form-Primitives, KPI-Kacheln, Log-Terminal) auf der bestehenden Token-Schicht.

## Entscheidung

**Reines Restyling auf die `s-*`-Schicht + horizontale Tab-Nav. Keine Routen-, Schema- oder Render-Helper-Änderung.**

1. **Horizontale Tab-Nav.** Die vertikale `_nav.html` (`w-56` `menu`) wird durch `<nav class="settings-tabs" role="tablist">` ersetzt — sieben Tabs in Mockup-Reihenfolge (**Servers, Tags, Groups, LLM Provider, LLM Reviewer, Master-Key, About**), sticky oben über dem Content. Der **HTMX-Vertrag bleibt byte-für-byte erhalten**: `hx-get` / `hx-target="#settings-content"` / `hx-swap="innerHTML"` / `hx-push-url="true"` / `hx-headers='{"HX-Target": "settings-content"}'` + `href`-Fallback. Aktiver Tab: `settings-tabs__item--active` + `aria-selected`; da die Tab-Leiste außerhalb des Swap-Targets liegt, synchronisiert `settings_tabs.js` den Marker client-seitig.

2. **`s-*`-Komponentenschicht.** `docs/design/settings.css` wird 1:1 nach `frontend/src/css/components/settings.css` portiert (nur Token-Vars, keine neuen Hex-Farben; zwei Port-Eingriffe: kaputter Kommentar Z865 gefixt, `.profile-menu__item--active` nach `profile-menu.css` weil Topbar-Scope). Jede Subseite bekommt den Header-Pattern `settings__eyebrow` (Text „Settings", **ohne** Nummerierung — User-Entscheidung) + `settings__title` + `settings__lede` und die passenden `s-*`-Patterns (`s-table`, `s-pill`, `s-overflow`, `s-card`, `s-fields-grid`, `s-statusbar`, `s-kpis`, `s-twoup`, `s-kv`, `s-slider-row`, `s-subtabs`, `s-log`, `s-key-status`, `s-warning`, `s-key-reveal`, `s-about-grid`, `s-empty`).

3. **Render-Helper unangetastet.** Die Drei-Modi-Render-Strategie aus ADR-0016 (`render_settings()`: Vollseite / Detail-Pane-Fragment / Content-Fragment) und ihr Template-Vertrag (IDs `settings-content`, `detail-pane-content`, `active`-Wert, `content_template`) bleiben exakt. Nur das Markup innerhalb der Shell und der Content-Templates ändert sich.

4. **`settings-manage.css` entfällt.** Die ADR-0040-`sd-manage-*`-Schicht (nur von Tags/Groups genutzt) wird durch `s-table`/`s-tags__*`/`s-groups__*` ersetzt; das Stylesheet wird gelöscht und der `@import` entfernt.

5. **Funktions-Parität.** Jede bestehende Form, jeder Endpoint-Aufruf, jeder CSRF-Token, jede Confirm-Logik bleibt. Mockup-Elemente ohne Backend (Log-Pause/-Copy, Live-Streaming) werden weggelassen + als Tech-Debt vermerkt, nicht halb gebaut.

## Begründung

- **Konsistenz mit der Redesign-Welle:** Settings war die letzte durchgängig DaisyUI-abhängige Fläche. Mit der `s-*`-Schicht trägt sie dieselbe Token-/Mono-/Hairline-Sprache wie Dashboard, Server-Detail, Findings, Login.
- **Horizontal statt vertikal:** Die Fleet-Sidebar links bleibt sichtbar (gleiche Shell wie der Rest der App); die Settings-Sub-Navigation horizontal oben gibt dem Content die volle Spaltenbreite und folgt dem Mockup.
- **Restyling, kein Re-Engineering:** Routen/Schema/Helper sind erprobt (Block I → AC). Ein reiner Markup-/CSS-Touch hält das Risiko klein und den HTMX-/Test-Vertrag stabil.
- **`s-*`-Präfix statt `sd-*`:** eigener Namespace für die Settings-Fläche, sauber abgegrenzt von der Server-Detail-Schicht (`sd-*`) — kein versehentliches Cross-Styling.

## Konsequenzen

- `legacy-shim.css` verliert die Settings-Fläche als Konsumenten; das Ausdünnen des Shims bleibt einem Folge-PR vorbehalten (Findings/Audit/Setup/Chat nutzen ihn noch).
- Die Reviewer-KPI-Kacheln (`s-kpis`: Queued / In progress / Done · 24h / Failed · 24h) werden wie im Mockup übernommen — die „less is more"-Reduktion aus dem Server-Detail-Redesign gilt hier bewusst nicht (User-Entscheidung 2026-06-04).
- Container-Query-Fallbacks aus dem Mockup-CSS werden übernommen; ein echtes Mobile-responsive-Layout bleibt Out of Scope (ARCHITECTURE §17).

## Verworfen

- **Vertikale Nav beibehalten, nur restylen:** widerspricht dem Mockup und verschenkt Content-Breite; die horizontale Tab-Nav ist die Design-Vorgabe.
- **Render-Helper auf zwei Modi reduzieren:** außerhalb des Block-Scopes; die drei Modi (Direkt-URL, Profile-Dropdown-Fragment, Tab-Klick) sind alle in Benutzung.
- **Mockup-Features ohne Backend mitbauen (Log-Pause/-Copy, Live-Stream, Slider-Inline-Apply):** Scope-Drift; als Tech-Debt vermerkt statt halb implementiert.

## Nachtrag (2026-06-04, Folge-Fixes nach erstem Review)

Vier kleine Anpassungen nach dem ersten Operator-Sichttest, kein Scope-Bruch:

1. **Tab-Active-Sync.** Da `.settings-tabs` außerhalb des HTMX-Swap-Targets liegt, zog der Active-Marker erst beim Full-Reload nach. `app/static/js/settings_tabs.js` synchronisiert ihn jetzt pfad-basiert (`htmx:pushedIntoHistory` + `popstate`).
2. **Modal-Zentrierung via `x-teleport`.** Das `container-type:inline-size` auf `.settings` macht es zum Containing-Block für `position:fixed` — die Modals öffneten oben-links. Sie werden jetzt per `x-teleport="body"` an `<body>` gehängt und sind dadurch viewport-zentriert; die Alpine-Scope (inkl. `confirmSubmit()`'s `this.$el = Form`) bleibt erhalten.
3. **External Feeds → About.** Die read-only EPSS/CISA-KEV-Freshness wandert vom LLM-Provider- auf den About-Tab (passt thematisch zu „Runtime"). `about_view` reicht dafür `feed_statuses` durch.
4. **Master-Key-Badge entfernt.** Der „new"-Badge in der Tab-Nav entfällt (Operator-Wunsch).

## Re-Open-Trigger

- Wenn `legacy-shim.css` ausgedünnt werden soll: eigener Cleanup-PR nach Redesign der restlichen Flächen.
- Wenn Live-Werte im Reviewer (in_flight, Durchsatz) oder ein streamendes Debug-Log gewünscht werden: eigener Block mit Backend-Endpoint (heute Out of Scope, siehe Tech-Debt).
