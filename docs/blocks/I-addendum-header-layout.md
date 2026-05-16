# Block-I-Addendum — Header-Navigation und Profile-Dropdown

**Geltungsbereich:** Dieses Dokument ist ein Anhang zu `docs/blocks/I-ui-modernization.md`. Der Block-I-Plan wird **nicht editiert**; alle Abweichungen sind hier ausgewiesen. Block-I-Implementer liest in dieser Reihenfolge: `ARCHITECTURE.md §7a` → `docs/blocks/I-ui-modernization.md` → `docs/decisions/0016-header-and-profile-dropdown.md` → dieses Addendum. Bei Konflikten gewinnt das spätere Dokument.

**Begründung:** Siehe ADR-0016. Kurz: visuelles Alignment gegen uptime-kuma hat zwei Layout-Punkte im Block-I-Plan als suboptimal identifiziert (Settings-im-Sidebar-Footer, Multi-Top-Level-Header). Statt den ausgereiften Block-I-Plan halb umzuschreiben — was zu Drift zwischen "Plan vom Reviewer abgesegnet" und "stille Edit-Spur" führen würde — liegen die Deltas hier ausgewiesen.

## Was aus dem Block-I-Plan abgelöst wird

Die folgenden Tasks aus `I-ui-modernization.md` werden **nicht in der ursprünglichen Form** umgesetzt. Der Implementer streicht die entsprechenden DoD-Punkte und ersetzt sie durch die im Addendum genannten.

### Task #5 (Quick-Stats oben in der Sidebar) — ABGELÖST

> "Quick-Stats als Mini-Block oben in der Sidebar: 5 Counter (Total open / KEV / Critical / High / Stale-Server). … Klick auf einen Counter setzt den entsprechenden Filter."

**Ersatz:** Quick-Stats wandern in den Dashboard-Detail-Pane (siehe "Was neu hinzukommt" → "Dashboard-Default-Detail-Pane"). Counter und Filter-Verhalten bleiben funktional gleich; nur die Position ändert sich. Sidebar ist nach dem Refactor reine Navigation.

**Streichen aus DoD:**
- `_quick_stats.html` aus dem `sidebar/`-Partials-Pfad (gehört in `dashboard/`-Pfad).
- `test_quick_stats.py` darf bleiben; Test-Setup muss aber den neuen Render-Kontext nutzen.

### Task #6 (Sticky-Search-Header mit `/`-Shortcut) — TEILWEISE ABGELÖST

> "Search-Input oben in der Sidebar bleibt beim Scrollen sichtbar. … `Enter` öffnet die globale Suche (`search.search`) im Detail-Pane mit dem Suchbegriff."

**Was bleibt:** sticky Such-Input oben in der Sidebar, `/`-Shortcut, clientseitiges Fuzzy-Filter der Server-Liste. Funktioniert unverändert.

**Was sich ändert:** der **globale** Suche-Einstieg (CVE-/Paket-Suche über die ganze Datenbank) wandert in einen eigenen **Header-Button "Suche"** neben dem Dashboard-Button. `Enter` im Sidebar-Suchfeld wirft den eingegebenen Suchbegriff weiterhin an die globale Suche, aber der primäre Einstieg ist der Header-Button.

**Konsequenz:** das Sidebar-Such-Input ist semantisch ein lokaler Listen-Filter, nicht ein globaler Such-Einstieg. Placeholder-Text und `aria-label` entsprechend anpassen ("Server filtern…" statt "Suchen…").

### Task #7 (Settings als Sidebar-Tab) — VOLLSTÄNDIG ABGELÖST

> "Am unteren Rand der Sidebar eine kompakte Liste 'Server' / 'Tags' / 'LLM-Provider' / 'API-Keys & Master-Key' / 'About'. Klick öffnet die jeweilige Settings-View im Detail-Pane via HTMX."

**Ersatz:** Settings wandert ins **Profile-Icon-Dropdown** im Header — aber als **flacher Eintrag, ohne Sub-Menü**. Klick auf "Settings" öffnet die Settings-View im Detail-Pane. Die fünf Sub-Bereiche (Tags, LLM-Provider, Server-Verwaltung, Master-Key, About) werden als **vertikale Sekundär-Navigation links innerhalb des Detail-Pane** dargestellt — analog zum uptime-kuma-Pattern. Default beim ersten Aufruf: `Tags`. Klick in der Settings-Nav swappt nur den Content-Bereich rechts der Nav, die Nav-Liste bleibt stehen.

Die bestehenden Routen (`/settings/tags`, `/settings/llm/`, `/settings/servers/`) bleiben unverändert und liefern weiterhin Detail-Pane-Fragmente bei `HX-Request: true`. Zusätzlich kommen `/settings/master-key` und `/settings/about` neu hinzu (siehe "Was neu hinzukommt"). `/settings` ohne Sub-Pfad ist ein Alias auf `/settings/tags`.

**Streichen aus DoD:**
- `_settings_menu.html` aus dem `sidebar/`-Partials-Pfad.
- `test_settings_sidebar_swap.py` umbenennen zu `test_settings_dropdown_swap.py`. Verhaltens-Assertion: Klick auf "Settings" im Dropdown öffnet die Settings-View mit Default-Sub-Tab `Tags`. Klick auf Settings-Nav-Eintrag swappt nur Content rechts (nicht Nav).

### Filter-Chips in der Sidebar (Teil von §7a §218) — ABGELÖST

§7a §218 hatte "Filter-Chips (Tags, Severity, KEV-only, Stale-only)" in der Sidebar vorgesehen. Diese wandern als kompakte Filter-Bar in den Dashboard-Detail-Pane (über den Quick-Stats oder direkt unter ihnen). Funktional gleich, nur Position geändert. Sidebar bleibt reine Server-Liste.

## Was unverändert aus dem Block-I-Plan bleibt

Die folgenden Tasks aus `I-ui-modernization.md` sind durch dieses Addendum **nicht** betroffen und werden wie im Block-I-Plan beschrieben umgesetzt:

- **Task #1 (Single-Page-Layout):** Sidebar 320–360px + Detail-Pane, sticky, scrollt eigenständig. Konsequenz: die "kleinere Topbar" aus Task #1 wird konkretisiert (siehe "Was neu hinzukommt" → "Header-Aufbau").
- **Task #2 (HTMX-Routing-Refactor):** `HX-Request: true` liefert Fragment, sonst volle Seite. `hx-push-url`, Browser-Back/Forward, Direkt-URLs. Gilt jetzt zusätzlich für alle Profile-Dropdown-Einstiege (Settings-Sub-Views, Audit).
- **Task #3 (Heartbeat-Bars):** 50 vertikale Pillen pro Server-Listeneintrag, `server_daily_status`-View, Tooltip mit 300ms Delay.
- **Task #4 (Density-Refactor der Server-Liste):** Listen-Komponente mit Border-Bottom, Status-Pill + Server-Name + Tag-Pills + Heartbeat-Bar pro Zeile, ~52px Höhe.
- **Task #8 (Inline-Actions auf Hover):** `group-hover:opacity-100` auf Findings/Audit/Server-Zeilen, `@media (hover: none)` Fallback.
- **Task #9 (Status-Pills mit Icons):** Heroicons-Mapping aus §7a §261, `aria-label` für Screenreader.
- **Task #10 (Subtle Fade-In bei SSE-Updates):** `bg-info/20` + `transition-colors duration-1000`, `htmx:afterSettle`-Listener.
- **Task #11 (Konsistente Empty-States):** `_empty/<context>.html`-Partials mit klaren CTAs.
- **Task #12 (Monospace-Cleanup):** `font-mono` auf CVE-IDs, Paket-Namen, Versionen, Hostnames, Kernel, Pfade, Hash-IDs.

## Was neu hinzukommt (war nicht im Block-I-Plan)

### Header-Aufbau (ersetzt §7a §221 und Block-I Task #1 Topbar-Detail)

Von links nach rechts in einem fixen, immer sichtbaren Top-Bar:

1. **Logo + Brand "secscan"** — Klick führt zum Dashboard-Default-Detail-Pane (identisches Verhalten wie Dashboard-Button).
2. **Dashboard-Button** — füllt Detail-Pane mit Quick-Stats-Header + (vorerst leerem) Platzhalter.
3. **Suche-Button** — öffnet globale CVE-/Paket-/Server-Suche im Detail-Pane.
4. *(rest)*
5. **Theme-Toggle-Icon** (sun/moon, Heroicons), sichtbar im Header, Ein-Klick-Toggle. Theme-Cookie wie bisher.
6. **Profile-Icon mit Dropdown** — Avatar-Kreis mit Initial des Admin-Benutzernamens.

Dropdown-Inhalt von oben nach unten (flach, kein Sub-Menü):

- **Settings** — öffnet die Settings-View im Detail-Pane mit Default-Sub-Tab `Tags`. Sub-Bereiche werden in der Settings-View selbst als linke Nav-Liste angezeigt (siehe unten).
- **Audit** — direkter Link auf Audit-Detail-Pane.
- **Logout**.

### Settings-View mit Sekundär-Navigation links

Klick auf "Settings" im Profile-Dropdown öffnet die Settings-View im Detail-Pane. Diese View ist intern zweiteilig — der Detail-Pane wird sozusagen noch einmal aufgeteilt:

```
+--------------------------+--------------------------------------------+
|  Settings-Nav (~200px)   |   Settings-Content                         |
|                          |                                            |
|  Tags     [aktiv]        |   <Tags-Verwaltung>                        |
|  LLM-Provider            |                                            |
|  Server-Verwaltung       |                                            |
|  Master-Key       (neu)  |                                            |
|  About                   |                                            |
+--------------------------+--------------------------------------------+
```

Routen-Mapping:

| Sub-Eintrag | Route | Status im MVP-Code |
|-------------|-------|--------------------|
| Tags | `/settings/tags` | existiert (Default bei `/settings`) |
| LLM-Provider | `/settings/llm/` | existiert |
| Server-Verwaltung | `/settings/servers/` | existiert |
| Master-Key | `/settings/master-key` (neu) | **fehlt — wird mit umgesetzt** |
| About | `/settings/about` (neu) | **fehlt — wird mit umgesetzt** |

`/settings` ohne Sub-Pfad redirected serverseitig auf `/settings/tags`. Direkt-URLs (z.B. `/settings/master-key` als Bookmark) laden die volle Seite mit korrekt vorausgewählter Settings-Nav.

HTMX-Swap-Verhalten:

- **Klick auf "Settings" im Profile-Dropdown** liefert `/settings/tags` als Detail-Pane-Fragment (Settings-Nav-Markup + Content-Markup).
- **Klick auf einen Eintrag in der Settings-Nav** swappt nur den Content-Bereich rechts der Nav (mit `hx-target="#settings-content"` und `hx-swap="innerHTML"`). Die Settings-Nav selbst bleibt stehen und markiert den aktiven Eintrag clientseitig (Alpine `:class`) plus serverseitig fallback.

Settings-Nav-Template: `app/templates/settings/_nav.html` als Partial. Wird sowohl vom äußeren Layout (Full-Page-Direkt-URL) als auch von den Sub-View-Templates eingebunden (bei HX-Request liefern die Sub-View-Routes nur `#settings-content`-Inhalt ohne Nav).

#### Master-Key-Rotations-View (`/settings/master-key`)

Schließt die Spec-Lücke aus `ARCHITECTURE.md §8` ("Rotation ist jederzeit aus der Settings-View möglich"). Layout:

- Hinweis-Box: "Der Master-Key authentifiziert die Registrierung neuer Server und die Rotation von Server-Keys. Er wird nur einmal angezeigt."
- Aktueller Hash-Indikator (z.B. Last-Set-Datum aus Audit-Log, keine Anzeige des Hash-Werts selbst).
- Button "Neuen Master-Key generieren". Klick öffnet Bestätigungs-Modal ("Alte Server-Keys bleiben gültig. Neue Registrierungen brauchen den neuen Master-Key. Fortfahren?").
- Bei Bestätigung: neuer Master-Key generieren, einmalig im Klartext im UI anzeigen mit Copy-Button, Hash speichern, Audit-Event `master_key.rotated` schreiben.

CSRF zwingend. Argon2id-Hash wie beim Setup-Wizard. Keine Pflicht-Kommentare (ADR-0006).

#### About-View (`/settings/about`)

Read-only. Anzeige:

- App-Version (`secscan` Version-String aus `pyproject.toml` oder Konstante).
- Build-Hash (Git-Commit, wenn verfügbar — sonst "unknown").
- DB-Schema-Revision (aus `alembic_version`-Tabelle).
- Trivy-DB-Status zusammengefasst (Anzahl Server mit veralteter DB).
- Python-, Flask-, SQLAlchemy-Versionen.
- Health-Check-Link (`/healthz`) als anklickbarer Status-Indikator.

### Dashboard-Default-Detail-Pane

Bei Klick auf Logo, Dashboard-Button oder beim initialen Login (kein Server in URL):

- **Quick-Stats-Header**: 5 Counter horizontal (Total open / KEV / Critical / High / Stale-Server). Klick auf einen Counter setzt den entsprechenden Filter — selber Verhalten wie in §7a §239, nur Position vom Sidebar-Top in den Detail-Pane gewechselt.
- **Optionale Filter-Bar** darunter (Tag-Filter, Severity-Min, nur-KEV, nur-stale) — kompakt, ein-Klick zum Anwenden. Verhalten unverändert zu Block-D-Dashboard.
- **Platzhalter-Bereich** darunter — **bewusst leer**. Reviewer-Hinweis: das ist kein "DoD-Loch", sondern ausgewiesener leerer Slot. Inhalt kommt mit späterem Block (Trend-Widgets, "letzte Aktivitäten", o.Ä. — separat zu entscheiden, out of scope für diesen Block).

### Audit-Detail-Pane

Klick auf "Audit" im Profile-Dropdown rendert die bestehende `/audit`-View als Detail-Pane-Fragment. Direkt-URL `/audit` liefert volle Seite. Funktional unverändert zu Block F.

## Angepasste DoD-Punkte (gegenüber Block-I-Plan)

Hinzufügen zur Block-I DoD:

- [ ] `app/templates/layout/_header.html` (oder erweiterte `base.html`) mit Logo, Dashboard-Button, Suche-Button, Theme-Toggle, Profile-Icon-Dropdown.
- [ ] `app/templates/layout/_profile_dropdown.html` mit **flachen Einträgen** Settings, Audit, Logout — **kein Settings-Sub-Menü**.
- [ ] `app/templates/settings/_nav.html` als Settings-Sekundär-Nav-Partial (vertikale Liste der fünf Sub-Bereiche, aktiver Eintrag hervorgehoben).
- [ ] `app/templates/settings/_shell.html` (oder Layout-Erweiterung) für die zwei-Spalten-Struktur Settings-Nav + Settings-Content innerhalb des Detail-Pane.
- [ ] `app/views/settings.py` erweitert um `GET /settings/master-key` (View) und `POST /settings/master-key/rotate` (Action) mit CSRF und Audit-Event.
- [ ] `app/views/settings.py` erweitert um `GET /settings/about`.
- [ ] `app/views/settings.py` Redirect von `GET /settings` auf `/settings/tags`.
- [ ] Alle Settings-Sub-Routes (`tags`, `llm`, `servers`, `master-key`, `about`) sind HX-Request-aware: bei `HX-Request: true` und `hx-target="#settings-content"` liefern sie **nur den Content-Bereich** (ohne Settings-Nav, ohne Header). Bei normalem GET (Direkt-URL) liefern sie die volle Seite inkl. Header und Settings-Nav.
- [ ] `app/templates/settings/master_key.html` und `app/templates/settings/about.html` als Detail-Pane-Fragmente (HX-Request-aware).
- [ ] `tests/views/test_master_key_rotation.py`: Rotation funktioniert, alte Server-Keys bleiben gültig, Audit-Event entsteht, CSRF blockiert ohne Token.
- [ ] `tests/views/test_settings_dropdown_swap.py` (vorher `test_settings_sidebar_swap.py`): Klick auf "Settings" im Profile-Dropdown öffnet Settings-View mit Default-Tab `Tags`. Klick in der Settings-Nav swappt nur `#settings-content`, Nav bleibt stehen, Browser-URL ändert sich. Direkt-URL `/settings/master-key` liefert volle Seite mit "Master-Key" als aktivem Nav-Eintrag.
- [ ] `tests/views/test_header_navigation.py`: Dashboard-Button füllt Default-Detail-Pane, Suche-Button öffnet globale Suche, Logo-Klick = Dashboard-Button.
- [ ] manual: Profile-Dropdown öffnet auf Klick, schließt auf Klick-außerhalb, Theme-Toggle wechselt sofort und persistiert über Reload.
- [ ] manual: Settings-View zeigt die Nav-Liste links permanent während man zwischen Sub-Bereichen wechselt. Aktiver Eintrag visuell hervorgehoben.
- [ ] manual: Master-Key-Rotation läuft End-to-End: alter Key invalidiert kein bestehender Server-Key, neuer Master-Key registriert erfolgreich einen neuen Server, alter Master-Key wird abgelehnt.

Streichen aus Block-I DoD:

- ~~`app/templates/sidebar/_quick_stats.html`~~ (wandert nach `dashboard/_quick_stats.html`)
- ~~`app/templates/sidebar/_settings_menu.html`~~ (ersetzt durch `_profile_dropdown.html`)
- ~~`tests/views/test_settings_sidebar_swap.py`~~ (ersetzt durch `test_settings_dropdown_swap.py`)

## Übergabe-Reihenfolge (überlagert die aus Block-I-Plan)

1. `backend-implementer` baut zusätzlich zum Block-I-Plan: `master-key`- und `about`-Routes plus zugehörige Audit-Events.
2. `frontend-implementer` baut zusätzlich zum Block-I-Plan: Header mit Dashboard/Suche/Theme-Toggle/Profile-Icon, Profile-Dropdown-Component mit Settings-Akkordeon, die zwei neuen Settings-Templates. Verdrahtet die Sidebar **ohne** Quick-Stats, Filter-Chips und Settings-Footer.
3. `test-writer` schreibt die neuen Test-Files (Master-Key-Rotation, Header-Navigation, Dropdown-Swap).
4. `security-auditor` prüft zusätzlich: Master-Key-Rotation hat CSRF, alter Key wird sicher invalidiert (`hmac.compare_digest`), neue Klartext-Anzeige hat keine Logging-Spur.
5. `reviewer` arbeitet die vereinigte DoD (Block-I-Plan minus gestrichene Punkte plus neue Punkte aus diesem Addendum) ab.

## Was bewusst NICHT in diesem Addendum

- Inhalt des Dashboard-Platzhalter-Bereichs — kommt in einem späteren Block, separat zu entscheiden.
- Power-User-Features (Cmd-K-Palette, Vim-Shortcuts) — bleiben in Block J reserviert wie ADR-0012 §35 vorsieht.
- Mobile-Layout — bleibt out of scope (ADR-0009).
- API-Keys-Liste als separates Settings-Item — Server-Verwaltung deckt das bereits ab (Server-Keys gibt es nicht "lose", sie hängen immer an einem Server).
