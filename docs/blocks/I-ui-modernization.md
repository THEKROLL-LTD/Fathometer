# Block I — UI-Modernisierung (Single-Page-Layout, Heartbeat-Bars, Density-Polish)

## Ziel

Die existierende MVP-UI aus Block D, E, F (Multi-Page mit Card-Grid, getrennten Routen für Dashboard/Suche/Audit/Settings) wird abgelöst durch ein **Single-Page-Layout mit Sidebar + Detail-Pane** im uptime-kuma-Spirit. Heartbeat-Bars pro Server zeigen den Severity-Verlauf der letzten ~50 Tage. Die Information-Density steigt deutlich (von ~3 auf ~12 Server pro Viewport). Funktional ändert sich nichts — alle Routen, Endpoints, Daten-Verträge aus §6 und §7 bleiben gültig. Nach Block I fühlt sich die App wie ein modernes Ops-Tool an, ohne Funktionalität zu verlieren oder neue zu addieren.

## Vorbereitung — zu lesende Sektionen

- `ARCHITECTURE.md` §7 (UI MVP — bleibt als Referenz für funktionale Endpoints)
- `ARCHITECTURE.md` §7a (UI v2 Spec — Sidebar-Layout, Heartbeat-Bars, Density-Regeln)
- `ARCHITECTURE.md` §15 (Triage-Signale — Severity-Default-Sortierung, KEV-Priorität)
- `docs/decisions/0012-block-i-ui-v2.md` (warum separater Block, was bewusst draußen bleibt)
- `docs/decisions/0001-no-node-build.md` (CDN-Tailwind und CDN-Heroicons, kein Build-Step)
- `docs/decisions/0006-no-forced-comments.md` (Inline-Action-Modals haben weiterhin keine Pflicht-Kommentare)
- `docs/decisions/0009-no-mobile.md` (Mobile-Layout bleibt out of scope, kein Responsive-Aufwand)

## Aufgaben

### Must (1–6) — definieren den Block-Kern

1. **Single-Page-Layout** in einem neuen `base_app.html` (oder `base.html` umbau). Sidebar links 320–360px sticky, Detail-Pane rechts scrollt eigenständig. Topbar wird kleiner (nur App-Name + Theme-Toggle + User + Logout). Bestehende Nav-Links (Dashboard/Suche/Audit/Settings) entfallen aus der Topbar — sie werden über die Sidebar erreicht.
2. **HTMX-Routing-Refactor**: alle bestehenden View-Routes (`dashboard.index`, `server_detail.show`, `search.search`, `audit.list_events`, alle `settings.*`-Views) werden so erweitert dass sie bei `HX-Request: true` nur das Detail-Pane-Fragment liefern, sonst die volle Seite (Sidebar + Detail-Pane mit Initial-Inhalt). Browser-History via HTMX `hx-push-url`. Direkt-URL-Aufrufe und Bookmarks funktionieren weiter.
3. **Heartbeat-Bars** pro Server-Listeneintrag. DB-Aggregation als View `server_daily_status` mit `(server_id, day, max_severity, kev_count, scan_count)`. Frontend: 50 vertikale Pillen, Farbe nach Severity-Mapping aus §7a. Tooltip via Alpine-Komponente mit 300ms Delay, zeigt Datum, Counts, Last-Scan. Materialisierte View täglich refreshed (Cron-Hook in App, nicht Postgres-MV im MVP).
4. **Density-Refactor der Server-Liste**: aus Card-Grid (`dashboard/_card.html`) wird eine Listen-Komponente mit Border-Bottom (`sidebar/_server_row.html`). Pro Zeile: Status-Pill links, Server-Name (mono-Font), Tag-Pills (kompakt), Heartbeat-Bar rechts. Hover- und Active-State per Tailwind-Utilities. Karten-Templates aus Block D bleiben für die Detail-Pane-Variante "Server-Übersicht ohne Auswahl" oder werden gelöscht falls nicht mehr referenziert.
5. **Quick-Stats** als Mini-Block oben in der Sidebar: 5 Counter (Total open / KEV / Critical / High / Stale-Server). SQL-Aggregation pro Render. Klick auf einen Counter setzt den entsprechenden Filter (URL-Query erweitern, Sidebar refresht).
6. **Sticky-Search-Header** mit `/`-Shortcut. Search-Input oben in der Sidebar bleibt beim Scrollen sichtbar. Alpine-Listener auf `keydown` mit `key === '/'` und `not(activeElement is INPUT|TEXTAREA)`. Live-Filter der Server-Liste clientseitig (Fuzzy-Match via einfacher Substring-Suche auf Server-Namen + Tag-Namen). `Enter` öffnet die globale Suche (`search.search`) im Detail-Pane mit dem Suchbegriff.
7. **Settings als Sidebar-Tab**: am unteren Rand der Sidebar eine kompakte Liste "Server" / "Tags" / "LLM-Provider" / "API-Keys & Master-Key" / "About". Klick öffnet die jeweilige Settings-View im Detail-Pane via HTMX. Bestehende `/settings/...`-Routen liefern die Fragmente.

### Should (8–11) — runden den modernen Eindruck ab

8. **Inline-Actions auf Hover** für Findings-Zeilen, Audit-Zeilen, Server-Zeilen. CSS-only via `group` und `group-hover:opacity-100`. Touch-Devices: `@media (hover: none)` lässt sie immer sichtbar.
9. **Status-Pills mit Icons**: Heroicons via CDN (`https://unpkg.com/@heroicons/[email protected]/...` oder als inline SVG-Sprite im base.html). Mapping wie in §7a. Alle Pills bekommen `aria-label` für Screenreader.
10. **Subtle Fade-In bei SSE-Updates**: HTMX-SSE-Swap-Target bekommt nach Swap kurz `bg-info/20` mit `transition-colors duration-1000`. Implementiert über `htmx:afterSettle`-Listener in einem kleinen JS-Snippet (`static/js/sse_highlight.js`).
11. **Konsistente Empty-States** mit klaren CTAs für: leere Server-Liste, leere Findings auf einem Server, leeres Audit, leere Suche. Templates `_empty/<context>.html` als Partial. Pro Empty-State exakt ein primärer Aktions-Link, nichts dahinter "verstecken".

### Monospace-Cleanup (gehört zu Density, separat aufgeführt weil cross-cutting)

12. CSS-Klasse `font-mono` auf alle technischen Werte über alle Templates: CVE-IDs, Paketnamen, Versions-Strings, Server-Hostnames, Kernel-Versionen, File-Paths, Hash-IDs, API-Key-Anzeigen. Body bleibt sans-serif. Schrift-Skala auf drei Größen reduziert (siehe §7a).

## Was NICHT in diesem Block

- **Kein Dark-Mode-Default**. Theme-Toggle aus §7 bleibt, Light bleibt Default. Wer Dark will, klickt einmal — Setting wird gemerkt.
- **Kein Mobile-Pass**. Sidebar ist desktop-first, kein Off-Canvas-Layout für kleine Viewports (siehe ADR-0009).
- **Kein Cmd-K Command-Palette** — Power-User-Feature, wird in einem späteren Block J oder v2 angegangen.
- **Keine Vim-Style-Keyboard-Shortcuts** (j/k Navigation, A für Acknowledge etc.) — selber Grund.
- **Keine Optimistic-Updates** für Acknowledge — bleibt server-roundtrip-confirmed.
- **Keine Loading-Skeletons** — HTMX-Default-Spinner reicht.
- **Keine neuen Endpoints oder Datenmodell-Änderungen** außer der `server_daily_status`-View. Alle Routen aus §6 bleiben funktional unverändert.
- **Kein Design-System-Refactor** auf eine eigene Komponentenbibliothek — DaisyUI-Klassen bleiben die Quelle der Wahrheit.

## Definition of Done

### Datei-Existenz und -Struktur

- [ ] `app/templates/base.html` enthält Sidebar + Detail-Pane Skelett (oder neue `base_app.html` ersetzt sie für authentifizierte Routen)
- [ ] `app/templates/sidebar/` mit Partials: `_quick_stats.html`, `_search.html`, `_filter.html`, `_server_row.html`, `_settings_menu.html`, `_heartbeat_bar.html`
- [ ] `app/templates/_empty/` mit Partials: `no_servers.html`, `no_findings.html`, `no_audit.html`, `no_search_results.html`
- [ ] `app/services/heartbeat_aggregation.py` mit Query/View-Logik für `server_daily_status`
- [ ] `app/static/js/sidebar.js` mit Search-Filter, `/`-Shortcut, History-Wiring
- [ ] `app/static/js/sse_highlight.js` mit Fade-In-Listener
- [ ] `alembic/versions/<rev>_add_server_daily_status.py` mit View oder Materialized View
- [ ] Alle `dashboard/_card.html`-Referenzen aus aktivem Code entfernt (oder Datei in `_archive/` verschoben)

### Statische Checks

- [ ] cmd: `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] grep: kein `|safe` in `sidebar/*.html` oder `_empty/*.html`
- [ ] grep: `font-mono` Klasse auf CVE-IDs in mindestens 5 Templates
- [ ] grep: kein `aria-label` fehlt auf den neuen Icons (manuell stichprobenartig prüfen)

### Tests

- [ ] cmd: `pytest tests/services/test_heartbeat_aggregation.py -v` → grün (50-Tages-Aggregation, KEV-Counter separat, Stale-Tage als grau)
- [ ] cmd: `pytest tests/views/test_sidebar_layout.py -v` → grün (Sidebar gerendert, Detail-Pane Default-Inhalt, HX-Request liefert Fragment, normaler Request liefert volle Seite)
- [ ] cmd: `pytest tests/views/test_search_keyboard_shortcut.py -v` → grün (Shortcut-Handler bindet auf `/`, ignoriert wenn Input fokussiert)
- [ ] cmd: `pytest tests/services/test_quick_stats.py -v` → grün (Zähler reagieren auf Tag-Filter)
- [ ] cmd: `pytest tests/views/test_settings_sidebar_swap.py -v` → grün (Settings-Klick swappt nur Detail-Pane, nicht volle Seite)
- [ ] cmd: `pytest tests/adversarial/test_xss_in_heartbeat_tooltip.py -v` → grün (Skript-Payload in Server-Name oder CVE-Title eskapiert in Tooltip)
- [ ] cmd: `pytest -v --cov=app --cov-fail-under=85` → exit 0

### Migration

- [ ] cmd: `alembic upgrade head` → exit 0, View `server_daily_status` existiert
- [ ] cmd: `alembic downgrade -1 && alembic upgrade head` → exit 0
- [ ] cmd: `psql -c "SELECT * FROM server_daily_status LIMIT 5"` → liefert sinnvolle Zeilen wenn Findings existieren

### Verhaltens-Checks (manuell mit Real-Fixture als Test-Daten)

- [ ] manual: Login → Sidebar mit Quick-Stats, Suche, Filter, Server-Liste mit Heartbeat-Bars sichtbar. Detail-Pane zeigt Welcome-Card.
- [ ] manual: Klick auf Server in Sidebar → Findings-Tabelle erscheint im Detail-Pane ohne Page-Reload, URL ändert sich zu `/servers/<id>`. Browser-Back-Button geht zur Welcome-Card.
- [ ] manual: Direkt-URL `/servers/<id>` in neuem Tab öffnet → volle Seite mit korrekt vorausgewähltem Server in der Sidebar.
- [ ] manual: `/`-Taste fokussiert das Such-Input. Tippen filtert die Server-Liste live. `Esc` leert und entfokussiert. `Enter` öffnet globale Suche im Detail-Pane.
- [ ] manual: Hover über Heartbeat-Pille → Tooltip zeigt Datum, Counts, Last-Scan. Hover über grauen Tag → "kein Scan an diesem Tag".
- [ ] manual: Settings → Tags-Klick swappt Tag-Verwaltung in Detail-Pane. Bookmark der URL und neuer Tab → korrekt vorausgewählt.
- [ ] manual: Server-Liste hat sichtbare Density (mind. 10 Server in Standard-Viewport ohne Scroll bei 1080p)
- [ ] manual: Hover auf Findings-Zeile → Action-Button erscheint mit Fade-In, ist klickbar
- [ ] manual: SSE-Update via Push-eines-Test-Scans → entsprechende Server-Zeile in Sidebar bekommt 1s Akzent-Färbung, dann zurück
- [ ] manual: Empty-State-Test: Server löschen oder neuen leeren User → Empty-Card mit klarem CTA sichtbar
- [ ] Screenshots vorher/nachher pro Hauptansicht (Dashboard, Server-Detail, Settings, Suche, Audit) unter `docs/blocks/I-evidence/`

### Performance-Sanity

- [ ] cmd: mit 50 Test-Servern in DB → Sidebar-Render unter 200ms (Quick-Stats + Server-Liste + Heartbeats)
- [ ] cmd: Heartbeat-View-Refresh-Cron läuft unter 5s für 50 Server × 60 Tage

### Security-Audit (durch `security-auditor`-Agent)

- [ ] XSS-Test mit Skript-Payload in Server-Name → wird im Sidebar-Eintrag UND im Heartbeat-Tooltip korrekt eskapiert
- [ ] Quick-Stats-SQL nutzt parametrisierte Queries, keine String-Konkatenation
- [ ] HTMX-Endpoints validieren weiterhin CSRF auf state-changing Pfaden
- [ ] `pushState`-URL-Updates können nicht zur Open-Redirect-Vulnerability missbraucht werden (nur Same-Origin-Pfade akzeptieren)

### Dokumentation

- [ ] `STATE.md` aktualisiert: Block I → completed, Status "MVP plus UI v2 ready"
- [ ] CHANGELOG.md `v0.2.0` mit Block-I-Highlights
- [ ] Neue Screenshots in `README.md` einbinden falls README-Bilder hatten
- [ ] Falls neue Patterns entstehen die später Implementer brauchen: ADR oder Code-Kommentar im Layout-Template

## Übergabe-Reihenfolge

1. `backend-implementer` baut die Heartbeat-Aggregation und die Migration für `server_daily_status`. Anpassung der bestehenden View-Routes für HX-Request-Erkennung.
2. `frontend-implementer` baut die Sidebar-Templates, das neue base.html, alle Partials. Verdrahtet HTMX-hx-push-url, Search-Shortcut, Settings-Sidebar-Tab.
3. `test-writer` schreibt die Test-Suiten oben.
4. `security-auditor` läuft die XSS- und CSRF-Checks plus Open-Redirect-Test.
5. `reviewer` arbeitet die DoD-Checkliste ab.
6. STOP, du verifizierst manuell mit Screenshots-Vergleich gegen die Block-D/E-Evidence-Bilder.
