# ADR-0016 — Header-Navigation kompakt, Settings und Audit ins Profile-Dropdown

**Status:** Teilweise abgelöst durch [ADR-0020](0020-dashboard-cross-server-findings.md) (Datum der Supersession: 2026-05-16, Block M) und [ADR-0031](0031-theme-switcher-removed.md) (§"Theme-Toggle als sichtbares Header-Icon" abgelöst, 2026-05-23). Die Sektionen zu Header-Aufbau und Profile-Dropdown bleiben gültig. Die **Settings-Sekundär-Navigation** (vertikale Nav links im Settings-Pane) ist durch [ADR-0047](0047-settings-horizontal-tabs-s-layer.md) abgelöst (2026-06-04, Block AD: horizontale Tab-Nav + `s-*`-Schicht); der Profile-Dropdown-Eintrag „Settings" und die Drei-Modi-Render-Strategie (`render_settings()`) bleiben gültig. Die Dashboard-Pane-Layout-Sektionen (Quick-Stats-Inline-Card, Filter-Bar mit `Anwenden`-Button, Aufmerksamkeits-Sektion, dashed-border-Platzhalter) sind durch das Block-M-Redesign abgelöst — siehe ADR-0020 für die neue cross-server Findings-Surface mit KPI-Sparklines und Hybrid-Auto-Submit-Filter. · **Datum:** 2026-05-15 · **Refined:** Block-I-Plan (`docs/blocks/I-ui-modernization.md`) und `ARCHITECTURE.md §7a`. Block-I-Plan bleibt unverändert; Abweichungen sind im Addendum `docs/blocks/I-addendum-header-layout.md` ausgewiesen. **Render-Pattern (2026-05-16):** Dashboard-Detail-Pane wird nach [ADR-0017](0017-dashboard-pane-single-partial.md) aus einem gemeinsamen Jinja-Partial gerendert; HX-Pfad und Full-Page-Pfad konsumieren dasselbe `dashboard/_detail_pane.html`.

## Kontext

Beim visuellen Alignment der geplanten UI-v2 (Block I, ADR-0012) gegen die Referenz-Screenshots aus uptime-kuma wurde sichtbar, dass die in `ARCHITECTURE.md §7a` und `docs/blocks/I-ui-modernization.md` festgehaltene Layout-Aufteilung in zwei Punkten nicht ideal ist:

1. **Sidebar-Footer als Settings-Tab.** §7a §253 sieht "am unteren Rand der Sidebar eine kompakte Liste 'Server / Tags / LLM-Provider / API-Keys & Master-Key / About'" vor. Drei Probleme: (a) der Sidebar-Footer ist visuell nachgeordnet und versteckt eine wichtige Funktion, (b) er konkurriert mit der Server-Liste um vertikalen Platz, (c) er bricht das uptime-kuma-Pattern bei dem die Sidebar ausschließlich Navigations-Index ist.
2. **Multi-Top-Level-Header.** Die aktuelle MVP-Topbar (Block A/D) führt fünf gleichberechtigte Top-Level-Items: Dashboard, Suche, Audit, Settings, LLM. §7a §221 wollte das auf "App-Name + Theme-Toggle + User + Logout" reduzieren, hat aber nicht festgelegt wohin die globalen Views (Suche, Audit) wandern.

Zusätzliche Beobachtungen aus dem aktuellen MVP-Code (`app/views/`):

- Settings ist im Code bereits in drei Blueprints aufgeteilt: `/settings/tags`, `/settings/llm`, `/settings/servers`. Master-Key-Rotation ist in `ARCHITECTURE.md §8` als "jederzeit aus Settings möglich" spezifiziert, aber **nicht implementiert**. About-Page existiert nicht.
- "LLM" als Top-Level-Header-Item ist semantisch eine Per-Server-Funktion (LLM-Chat auf der Server-Detail-View). Es gehört nicht in den globalen Header.

## Entscheidung

Die UI-v2 aus Block I wird mit folgendem konkreten Layout umgesetzt. Block-I-Plan und §7a bleiben für die nicht widerrufenen Punkte (Heartbeat-Bars, Density, Monospace, Empty-States, Status-Pills, SSE-Fade-In, HTMX-Routing-Refactor) gültig.

### Header (fix, immer sichtbar)

Von links nach rechts:

- **Logo + Brand** "secscan", Klick führt zum Dashboard-Default-Detail-Pane (siehe unten). Identisches Verhalten wie der Dashboard-Button — beide hängen am gleichen Route.
- **Dashboard-Button** — füllt den Detail-Pane mit dem Dashboard-Default (Quick-Stats + Platzhalter, siehe unten). Wirkt von jedem Sub-State aus (Server-Detail, Settings, Audit, Suche).
- **Suche-Button** — öffnet die globale CVE-/Paket-/Server-Suche im Detail-Pane (entspricht der heutigen `search.search`-Route). Mit Such-Eingabe und Ergebnisliste.
- **Theme-Toggle** als sichtbares Icon (sun/moon, Heroicons via CDN gemäß ADR-0001) direkt neben dem Profile-Icon. Ein-Klick-Toggle, Setting in einem eigenen Theme-Cookie.
- **Profile-Icon mit Dropdown.** Initial des Admin-Benutzernamens als Avatar-Kreis. Klick öffnet ein Dropdown mit drei flachen Einträgen (kein Sub-Menü):
  1. **Settings** — öffnet die Settings-View im Detail-Pane mit der Settings-internen Sekundär-Navigation links (siehe "Settings-View" unten). Default-Sub-Tab ist `Tags`.
  2. **Audit** — direkter Link, öffnet die Audit-Liste im Detail-Pane.
  3. **Logout** — wie bisher.

Begründung für flaches Dropdown: ein Akkordeon im Dropdown ist ein zweistufiger Klick-Pfad und versteckt die Settings-Optionen. uptime-kuma-Pattern (Referenz-Screenshot) zeigt die Settings-Sub-Bereiche stattdessen als linke Sekundär-Nav im Settings-Pane selbst — dort sind sie permanent sichtbar, ein Klick weit, und man sieht beim Umschalten zwischen Sub-Bereichen den aktiven Eintrag. Das opfert ein Stück Detail-Pane-Breite an die Settings-Nav, gewinnt aber UX-Klarheit.

Was aus der Top-Level-Navigation **verschwindet**: Settings, Audit, LLM. "LLM" wird auf der Server-Detail-View als Inline-Aktion ("KI-Bewertung") angezeigt (existiert bereits), ist aber kein Top-Level-Item mehr.

### Sidebar links — nur Server-Liste

Die Sidebar enthält **ausschließlich** die Server-Liste (Status-Pill links, Server-Name in `font-mono`, Tag-Pills kompakt, Heartbeat-Bar rechts gemäß §7a §225). Sticky oben: ein lokales Such-/Filter-Input das **nur die sichtbare Server-Liste** filtert (clientseitiges Fuzzy-Matching auf Server-Name und Tag-Namen). `/`-Tastenkürzel fokussiert dieses Input (§7a §249).

Was in der Sidebar **nicht** mehr ist (im Vergleich zu §7a §218 und Block-I-Tasks #5/#7):

- Kein Quick-Stats-Block (5 Counter Total/KEV/Critical/High/Stale) — die wandern in den Detail-Pane (siehe Dashboard).
- Keine Filter-Chips (Tags, Severity, KEV-only, Stale-only) — wandern als kompakte Filter-Bar in den Dashboard-Detail-Pane bzw. die Server-Liste im Detail-Pane.
- Kein Settings-Footer — Settings ist nur noch über das Profile-Dropdown erreichbar.

Begründung für die Reduktion: uptime-kuma-Vergleich (Referenz-Screenshot des Users) zeigt dass eine reine Listen-Sidebar deutlich mehr Server pro Viewport zulässt und die Cognitive Load senkt. Quick-Stats und Filter gehören semantisch zum Dashboard-Inhalt, nicht zum Navigations-Index.

### Detail-Pane rechts — Dashboard-Default

Klick auf "Dashboard" (oder das Logo) zeigt im Detail-Pane:

- **Quick-Stats-Header**: 5 Counter (Total open / KEV / Critical / High / Stale-Server) horizontal nebeneinander. Identisch zu §7a §237, nur Position geändert.
- **Platzhalter-Bereich** darunter, **explizit erstmal leer** (kein Card-Grid wie Block D, keine Server-Tabelle wie ursprünglich in Punkt 3 der Diskussion erwogen). Inhalt kommt in einem späteren Block. Im Block-I-Addendum als bewusst leerer Bereich vermerkt, damit der Reviewer das nicht als "fehlende DoD" anstreicht.

Andere Detail-Pane-Zustände wie in §7a §219:

- **Server-Detail** bei Klick auf Server in Sidebar (Findings-Tabelle, View-Modi Liste/Group/Diff aus Block E, Tags, KI-Bewertung).
- **Settings-View** bei Klick auf "Settings" im Profile-Dropdown (siehe Settings-View unten).
- **Audit** bei Klick auf "Audit" im Profile-Dropdown.
- **Globale Suche** bei Klick auf "Suche" im Header.

HTMX-Swap nur des Detail-Pane (mit `HX-Request: true`), Direkt-URLs liefern volle Seite mit korrekt vorausgewähltem Zustand — wie §7a §221 schon vorsieht.

### Settings-View — Sekundär-Navigation links

Klick auf "Settings" im Profile-Dropdown öffnet die Settings-View im Detail-Pane. Die Settings-View ist intern zweiteilig:

- **Settings-Nav links** (~200–220px breit, sticky an der linken Kante des Detail-Pane). Vertikale Liste der Settings-Sub-Bereiche: `Tags`, `LLM-Provider`, `Server-Verwaltung`, `Master-Key`, `About`. Aktiver Eintrag ist visuell hervorgehoben (Akzent-Hintergrund analog DaisyUI `menu-active`). Klick swappt nur die Content-Seite rechts, nicht die Settings-Nav.
- **Settings-Content rechts** (Rest der Breite). Zeigt die jeweilige Sub-View. Bei direktem Öffnen ohne expliziten Sub-Tab gilt `Tags` als Default.

Direkt-URLs (`/settings/tags`, `/settings/llm/`, `/settings/servers/`, `/settings/master-key`, `/settings/about`) liefern weiterhin die volle Seite mit korrekt vorausgewählter Settings-Nav. HTMX-Swap bei Klick in der Nav: nur der Content-Bereich wechselt, die Nav bleibt stehen (zweite Swap-Ebene innerhalb des Detail-Pane).

Inhalte der fünf Sub-Bereiche:

| Sub-Eintrag | Route (existiert / fehlt) | Inhalt |
|-------------|--------------------------|--------|
| Tags | `/settings/tags` ✓ | Tag-Liste mit Add/Delete (unverändert zu MVP) |
| LLM-Provider | `/settings/llm/` ✓ | Provider-Konfig + Test-Connection (unverändert zu MVP) |
| Server-Verwaltung | `/settings/servers/` ✓ | Server-Liste mit Revoke/Retire (unverändert zu MVP) |
| Master-Key | **fehlt** — Spec-Lücke aus §8 | Rotations-UI: aktueller Hash-Indikator + "Neu generieren"-Button → einmaliges Anzeigen des neuen Klartext-Keys, Hash speichern. Audit-Event `master_key.rotated`. **Kommt mit dem Block der ADR-0016 umsetzt.** |
| About | **fehlt** | Version (`secscan-x.y.z`), Build-Hash, DB-Schema-Revision, letzter erfolgreicher `alembic upgrade`. Read-only. **Kommt mit dem Block der ADR-0016 umsetzt.** |

## Begründung

**Warum Settings ins Profile-Dropdown statt Sidebar-Footer.** Settings ist eine seltene Aktion (Tag anlegen, Provider tauschen, Server retiren) — sie braucht keinen Dauer-Slot im Sichtfeld. Das Profile-Dropdown ist die etablierte Konvention für "Account-und-Konfig-Zeug" in modernen Web-UIs (uptime-kuma, Linear, Vercel, Tailscale Admin). Die Sidebar bleibt dadurch fokussiert auf den Hauptzweck (Server-Index), was die Dichte erhöht und die Suche/Filterung der Liste verbessert.

**Warum Settings flach im Dropdown plus interne Sekundär-Nav.** Ein Settings-Akkordeon-Sub-Menü direkt im Dropdown wäre ein zweistufiger Klick-Pfad mit verstecktem zweitem Schritt — der User muss erst Settings expandieren, dann den Sub-Eintrag wählen. uptime-kuma macht das anders: Dropdown → Settings (ein Klick), die Sub-Bereiche stehen als linke Nav-Liste permanent im Settings-Pane. Sobald man in Settings ist, sieht man alle Sub-Bereiche auf einen Blick, der aktive Eintrag ist hervorgehoben, und das Umschalten ist je ein Klick. Kostet ~200px Detail-Pane-Breite während man in Settings ist, gewinnt aber Orientierung und vermeidet den "wo war Master-Key noch?"-Effekt.

**Warum Audit nicht ins Top-Level.** Audit ist Forensik-Tool, kein täglich genutzter View. Es gehört zur gleichen Klasse wie Settings (selten, technisch). Das Profile-Dropdown ist der richtige Ort. Vorteil: drei Top-Level-Items (Dashboard / Suche / Profile-Icon) sind übersichtlicher als fünf.

**Warum Suche bleibt Top-Level.** Suche ist die primäre Arbeitsbewegung wenn der Admin auf eine CVE-Frage reagieren muss ("Ist CVE-2026-44990 bei uns offen?"). Das muss Ein-Klick weit sein, nicht im Dropdown vergraben. Im Header neben Dashboard ist das richtig.

**Warum kein Card-Grid mehr im Dashboard-Default.** Sidebar zeigt schon die volle Server-Liste mit Heartbeat-Bars. Ein zweites Card-Grid wäre redundant und nimmt Platz für Quick-Stats und zukünftigen Dashboard-Inhalt. Der Platzhalter-Bereich wird bewusst leer gelassen — Inhalt kommt mit Erkenntnissen aus dem realen Einsatz (Trend-Graphen waren §17-out-of-scope, aber andere Widgets sind denkbar).

**Warum Theme-Toggle als sichtbares Header-Icon.** Häufiger Wechsel (Tag-/Nachtarbeit) verträgt keinen Dropdown-Klick. Sichtbares Icon ist die etablierte Konvention.

**Warum keine Änderung am Block-I-Plan-Dokument.** Block-I-Plan ist als detailliertes Implementierungs-Dokument konsolidiert und Reviewer-tauglich vorbereitet. Halb-Edits an einem fertig-strukturierten Plan erzeugen Drift zwischen "was war fertig" und "was wurde stillschweigend geändert". Saubere Lösung: Plan unangetastet lassen, Abweichungen in einem ausgewiesenen Addendum dokumentieren das der Implementer zusätzlich liest. Pattern analog zu ADR-0012 das §7 nicht editiert hat, sondern §7a daneben gestellt hat.

## Konsequenzen

- `docs/blocks/I-addendum-header-layout.md` wird zur Pflichtlektüre für den Block-I-Implementer (zusätzlich zu §7a und dem Block-I-Plan). Reihenfolge: §7a → Block-I-Plan → ADR-0016 → Addendum. Späteres gewinnt bei Konflikten.
- §7a §218 (Sidebar-Settings-Footer), §7a §237 (Quick-Stats-Position) und Block-I-Tasks #5 und #7 sind durch ADR-0016 **abgelöst**. Der Block-I-Implementer wird die entsprechenden Tasks aus der DoD-Checkliste streichen müssen — siehe Addendum für die explizite Liste.
- Zwei neue Settings-Sub-Views (Master-Key-Rotation, About) kommen mit dem Block dazu der ADR-0016 umsetzt. Master-Key schließt eine Spec-Lücke aus §8.
- Die Reduktion der Top-Level-Header-Items macht §7a §221 ("App-Name + Theme-Toggle + User + Logout") obsolet — neue Definition: "Logo + Dashboard + Suche + Theme-Icon + Profile-Icon-Dropdown".
- Tests aus dem Block-I-Plan die markup-spezifisch sind (z.B. `tests/views/test_settings_sidebar_swap.py` aus Block-I §77) werden umbenannt zu `test_settings_dropdown_swap.py` oder ähnlich — Verhalten gleich (Klick auf Settings-Sub-Eintrag swappt nur Detail-Pane), Markup anders (Dropdown-Item statt Sidebar-Tab).

## Re-Open-Trigger

- Wenn nutzerbezogene Akzeptanz-Tests nach Block-I-Implementierung zeigen dass das Profile-Dropdown als Settings-Einstiegspunkt nicht gefunden wird (klassisches "Burger-Menü-Problem" im Großen).
- Wenn der Dashboard-Platzhalter-Bereich nach einer Quartals-Nutzung ungenutzt bleibt und Quick-Stats besser direkt in die Sidebar zurückwandern sollten.

In beiden Fällen: neue ADR (0017+), nicht diese hier editieren.
