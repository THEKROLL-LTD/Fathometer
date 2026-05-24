## ADR-0038 — Server-Detail Triage-First Content-Refactor (Sektions-/Inhalts-Umbau, Styling out-of-scope)

**Status:** Akzeptiert · **Datum:** 2026-05-24 · **Block:** X (`docs/blocks/X-server-detail-content-refactor.md`) · **Bezug:** **Amendet/löst-teilweise-ab** ADR-0018 (Server-Detail-Sektions-Reihenfolge und Lebenszeichen-`<dl>`-Quickinfos), ADR-0022 §UI-Redesign (Host-Snapshot als eigene Sektion), ADR-0023 §UI-Konsequenzen (Workflow-Card-Body). **Wendet auf die Detail-Seite an** ADR-0033 (Color-Reduction „nur escalate trägt cyan") und ADR-0035 (Heartbeat 30 Ticks / 4 Risk-Band-Zustände aus `dominant_risk_band`) — beides war seit Block W in der Sidebar gelebte Realität, auf der Detail-Seite aber noch nicht angewandt. **Unberührt** bleiben ADR-0025 (Findings-View-Modi-Reduktion, Card-Lazy-Load), ADR-0028 (Junction-konsistente Vererbung), ADR-0030 (Performance-Tuning) und ADR-0037 (`/findings` Bucket-View). **Visueller Soll-Stand:** [`docs/design/ServerDetail.jsx`](../design/ServerDetail.jsx) + [`ServerSettings.jsx`](../design/ServerSettings.jsx) + [`server-detail.css`](../design/server-detail.css) + [`server-detail-data.js`](../design/server-detail-data.js) (Output aus Claude-Design, 2026-05-24). Block X übernimmt Content **und** Styling in einem Block; die `sd-*`-BEM-Klassen aus `server-detail.css` werden 1:1 in die Jinja-Partials portiert.

## Kontext

Die Server-Detail-Seite (`app/templates/servers/detail.html` + `_partials/host_snapshot.html` + `_action_needed_section.html` + `_findings_section.html`) wurde in Block K (ADR-0018) visuell aufgebaut und seitdem in Block O (ADR-0022, Host-Snapshot + Action-Required-Pill), Block P (ADR-0023, „Was zu tun ist"-Workflows + Application-Group-Cards) und Block Q (ADR-0025, Findings-View-Modi-Slim-Down + Card-Lazy-Load) inhaltlich erweitert. In Summe ist die Seite heute eine Dashboard-artige Stapelung von ~7 unabhängigen Sektionen, die jede für sich plausibel ist, in Kombination aber das vom User in der Cowork-Konsultation 2026-05-18 explizit formulierte Operator-Bauchgefühl verfehlen: „Hauptsächlich will der User nur wissen: muss ich was patchen oder schlimmer weil kein patch verfügbar ist?"

Eine UX-Iteration in [`docs/ux/mockup-iter-01.html`](../ux/mockup-iter-01.html) hat das Soll-Inhaltsmodell als Splitscreen-Mockup (jetzt auf Detail-Pane reduziert für den Claude-Design-Screenshot) durchgespielt. Drei Befunde aus dem Mockup-vs-Implementation-Vergleich (siehe Cowork-Konversation 2026-05-24):

1. **Quickinfo-Doppelung und Versteckung.** Heute steht „letzter scan vor X h" sowohl in der OS-Zeile (ADR-0018 §Header) als auch in der `<dl>`-Meta-Zeile unter dem Lebenszeichen (ADR-0018 §Lebenszeichen). „Erwarteter Intervall" und „Trivy-DB-Alter" sind im `<dl>` versteckt — Operator muss bis Sektion 4 scrollen um den Stand zu sehen. Das passt nicht zur 10-Sekunden-Triage-Frage.

2. **Host-Snapshot, Tag-Editor, KEV-Tile blockieren den Triage-Fokus.** Host-Snapshot (ADR-0022) ist eine eigene Sektion mit `bg-base-200/40`-Box und Listener-Inline-Liste oberhalb der Findings — Operator scrollt daran vorbei, ohne dass sie für die Triage-Entscheidung gebraucht würde. Tag-Editor-Akkordeon (ADR-0018 §Sektion 2) ist eine Pflege-Funktion, die nichts zur „was-tun-jetzt"-Frage beiträgt. KEV-Ereignisse · 50T (ADR-0018 §Lebenszeichen `<dl>` Spalte 4) ist redundant zur KEV-KPI-Tile in den HeaderStats.

3. **Triage Queue ist nicht risk-band-first.** ADR-0023 etabliert Application-Group-Cards als primäres Listenelement, und ADR-0025 hat sie auf Card-Lazy-Load umgestellt. Die Cards sind aber nicht nach Risk-Band gruppiert sichtbar — der Operator sieht „Cards in einer Reihe" und muss aus den Risk-Band-Badges visuell rekonstruieren, was ESCALATE und was MONITOR ist. Im Mockup ist die Triage Queue ein Risk-Band-Top-Level-Accordion (ESCALATE / ACT / MITIGATE / PENDING / MONITOR / NOISE) mit nur ESCALATE default-expanded — das macht die mentale Sortierung explizit.

Block W (ADR-0033 Color-Reduction, ADR-0035 Heartbeat 30/4) hat das Brand- und Heartbeat-Modell für Sidebar und Dashboard etabliert. Die Detail-Seite zieht beides bewusst nicht mit, weil Block W als Phase 1 explizit nur Login + Dashboard + App-Shell umfasst (STATE.md). Konsequenz: Detail-Seite zeigt heute weiterhin 50 Tage / 7 Zustände im Heartbeat (ADR-0018) und Severity-Rainbow in den KPI-Tiles — visuell drift gegenüber Sidebar und Dashboard.

## Entscheidung

Block X führt einen **Inhalts-/Sektions-Refactor zusammen mit der Style-Adoption** der Server-Detail-Seite durch. Es werden keine neuen Daten-Pipelines, keine neuen Risk-Bands und keine neuen Auth-/Audit-Pfade eingeführt. Das visuelle Styling (Tokens, Farben, Typographie, Animationen) wird aus dem Claude-Design-Output unter `docs/design/server-detail.css` / `ServerDetail.jsx` / `ServerSettings.jsx` / `server-detail-data.js` adoptiert; die `sd-*`-BEM-Klassen wandern 1:1 in `frontend/src/css/components/server-detail.css` und die Jinja-Partials referenzieren sie. Der `legacy-shim.css`-Anteil für Server-Detail schrumpft entsprechend (siehe ADR-0032-Addendum-Pattern). Dieser Block ersetzt die ursprünglich geplante Aufteilung in Content-only + Folge-Block X+1 (Style-Adoption) — Begründung: das Design liegt fertig vor, die Übersetzung React→Jinja+HTMX ist mechanisch, und ein Zwischenzustand mit Legacy-Shim-Look auf der Detail-Seite wäre nicht produktiv (Operator-Realität: jeder Merge-auf-main ist für den User sichtbar).

### (1) Quickinfos wandern aus dem Lebenszeichen-`<dl>` in eine Header-Sysline

Direkt unter der OS-Zeile rendert eine einzeilige Mono-Row im `.sysline`-Pattern (Block-W-Convention, `prompt + Reihe von Key-Value-Paaren mit Mid-Dot-Separator`):

```
> os <pretty> · kernel <ver> · arch <x>   (bleibt — heutige OS-Zeile, OHNE „letzter scan")
> expected interval <N> h · last scan <relative> · trivy-db <relative>   (neu — ersetzt das alte <dl>)
```

Das `<dl>`-Meta-Grid unter dem Lebenszeichen-Heatmap entfällt komplett. „Letzter Scan" verschwindet aus der OS-Zeile (war doppelt). KEV-Ereignisse · 50T wird ersatzlos gestrichen — die KEV-Information ist über die KEV-KPI-Tile in den HeaderStats bereits sichtbar (KEV-Count = aktuell offene KEV-Findings; das ist die Operator-relevantere Größe).

### (2) Tag-Editor + Tag-Hashtag-Zeile → Settings-Sub-View

Beide ziehen in eine neue Settings-Sub-View, erreichbar per Zahnrad-Icon im Header rechts neben dem KI-Bewertung-Button. Route: `GET /servers/<int:server_id>/settings` (mit identischem Auth- und Render-Pattern wie `app/views/_settings_shell.py` aus ADR-0016 / Block-I-Refinement).

Sub-View enthält drei Sektionen:

- **Tags** — heutiger Editor 1:1 (Add/Remove Tags, Tag-Color via vorhandenes Tag-Modell)
- **Group** — Selector für die `server_groups`-Zugehörigkeit aus ADR-0034 (Block W). Heute ist die Zuordnung nur DB-Feld + Sidebar-Render, ohne UI-CRUD. Block X fügt nur den Single-Select hinzu (Pick aus existierenden Groups oder „— keine —"); CRUD für Group-Definition bleibt out-of-Block (Re-Open-Trigger unten).
- **Scan-Interval** — `expected_scan_interval_h`-Editor (heute nur via Agent-Install gesetzt). Number-Input + „Stunden"-Suffix + Save-Button. Validierung 1–168.

Die Header-Hashtag-Zeile (`<a class="#tagname">…`-Loop in `detail.html` Z. 131–146) entfällt im Detail-View — Tags sind weiterhin über Sidebar-Filter + Settings-Sub-View sichtbar und filterbar.

### (3) Host-Snapshot-Sektion → Header-Pills mit Slide-Down im Flow

ADR-0022 §UI-Redesign (Host-Snapshot als eigene Sektion oberhalb der HeaderStats) wird hier präzise überschrieben. Die Persistenz (host_state-Block, `ServerListener`/`ServerProcess`/`ServerService`-Tabellen) und alle Backend-Aggregationen bleiben unverändert — nur die Darstellung kollabiert.

Neu: zwei `<button class="sd-chip">`-Pills inline am Ende der Header-Sysline, mono, hairline-border:

- **„Listeners: <N>"** ← öffnet bei Klick ein Slide-Down-Panel (`sd-flyout`) mit der Listener-Tabelle.
- **„Active services: <N>"** ← öffnet ein Slide-Down-Panel mit der `·`-Liste der systemd-Unit-Namen.

Beide Panels rendern im Flow (max-height-Transition, default `max-height: 0`), nicht als absolutes Overlay. Click auf eine Pille schließt die andere falls offen. Empty-State (snapshot_at IS NULL): Pill rendert als disabled mit Tooltip „Update agent to ≥ 0.3.0 for snapshot".

**Pill-Naming.** Die erste Pill heißt **„Listeners"** (nicht „Listeners & services"). Das Panel-Body zeigt ausschließlich Network-Listener (Datenmodell `ServerListener`); die echten systemd-Services sind die zweite Pill. „& services" im Initial-Mockup-Label war ein Carry-Over und wäre irreführend.

**Keine Pagination.** Beide Panels rendern die komplette Liste. Bei vielen Einträgen (> ~30 Listener oder > ~30 Services in der Praxis selten) bekommt der `sd-flyout`-Body Inner-Scroll via `overflow-y: auto` + `max-height`. Keine Page-Navigation, kein „show more"-Toggle.

**Listener-Exposure-Klassifizierung.** Pro Listener-Eintrag rendert eine zusätzliche Spalte „Exposure" mit einer von zwei Klassifizierungen, abgeleitet aus `addr`:

- **`LOOPBACK`** — wenn `addr` matched `127.0.0.0/8` (IPv4-Loopback) ODER `::1` (IPv6-Loopback). Render-Klasse: neutral gray (keine Hervorhebung).
- **`PUBLIC EXPOSED`** — alles andere (`0.0.0.0`, `::`, externe IPv4/IPv6-Bind-Adressen). Render-Klasse: cyan-outline (`sd-listener-tag--exposed` aus `server-detail.css`).

Implementiert als Render-Helper in `app/services/listener_exposure.py` (neu): pure Function `classify_exposure(addr: str) -> Literal["LOOPBACK", "PUBLIC EXPOSED"]`. Keine Persistenz-Spalte am `ServerListener`-Modell, keine Schema-Änderung — die Klassifizierung ist 100 % aus dem `addr`-Feld ableitbar und kann jederzeit ohne Migration verändert werden. Pydantic-Schema bleibt unverändert (`addr` ist seit Block O ASCII-validiert).

Die Klassifizierung ist bewusst grob (binary) und nicht weiter aufgeschlüsselt. Begründung: Operator braucht hier nur die Antwort auf „kommt das Listener vom Netz erreichbar?" — feinere Aufschlüsselungen (link-local, private-RFC1918, public) gehören in einen separaten Inspection-Tool-Pfad, nicht in den Triage-Header.

### (4) Operator-Workflows-Cards: interner Group-Drilldown beim Expand

Die Cards aus ADR-0023 / Block P (`_action_needed_section.html`) bleiben strukturell unverändert: vertikaler Stack, Phase-Badge + Action-Title + Group-Label-Sublist im Summary. Neu im Body beim Expand:

Eine Tabelle mit drei Spalten — **Group · Worst Finding · Reason** — pro Application-Group die unter dieser Workflow-Card hängt. Reason kommt aus `application_group_evaluations.reason_text` (ADR-0028). Worst-Finding ist die `Finding.id` mit höchstem CVSS / KEV-First aus der jeweiligen Group (existiert seit Block P im `worst_finding`-Loader). Pagination-Footer ab > 25 Groups pro Workflow-Card (vermutlich nie erreicht, aber Stub vorbereiten).

Heute zeigt der Card-Body nur die Sub-Line der Group-Labels — der eigentliche Drilldown auf Worst-Finding + Reason fehlte. ADR-0023 wird hier amendet, ohne dass das Group-Card-Pattern in der Triage Queue selbst angetastet wird.

### (5) Lebenszeichen 30 Tage / 4 Risk-Band-Zustände auf Server-Detail anwenden

ADR-0035 hat das Daily-Risk-State-Mapping als Heartbeat-Konvention etabliert (4 Zustände aus `Finding.risk_band` via `_RISK_BAND_RANK`-Reduce, 30 Ticks). Sidebar nutzt das seit Block W; Server-Detail zeigt heute weiterhin 50 Tage und 7 Zustände (ADR-0018 §Lebenszeichen). Block X zieht Server-Detail nach: `_heartbeat_large.html` schaltet auf das Sidebar-Pattern um (30 Ticks, 4 Zustände, gleiche Klassen-Namen wie `host__beat-tick beat--<band>`).

Severity-Trend-Range-Toggle wird konsequent auf `24h / 7T / 30T` reduziert — der `50T`-Knopf entfällt für Konsistenz mit der Heartbeat-Reduktion (heute: `24h / 7T / 30T / 50T`).

### (6) Triage Queue als Risk-Band-Top-Level-Accordion

Die Application-Group-Cards (ADR-0023) und der Pending-Grouping-Block (ADR-0025) bleiben als Card-Pattern unverändert. Neu darüber: ein Risk-Band-Accordion mit sechs `<details>`-Top-Level-Slots — **ESCALATE / ACT / MITIGATE / PENDING / MONITOR / NOISE** — in der Reihenfolge der `_RISK_BAND_RANK`-Skala (ADR-0035). Jeder Slot hängt die Application-Group-Cards rein die zu diesem Band gehören; der Pending-Grouping-Block hängt unter PENDING.

Default-Expanded: nur ESCALATE wenn nicht leer, sonst der erste nicht-leere Band. Alle anderen Bands collapsed, ihr Body lazy via HTMX (Hook auf `<details>` `toggle`-Event, Endpoint analog zu ADR-0025 §(2)).

Risk-Band-Summary-Row: Chevron + Phase-Badge (outline, gleiche Klassen wie heute) + Count rechts-aligniert.

### (7) Per-Finding-AI-Assessment inline

Jede Finding-Zeile in der Application-Group-Card wird zu einem eigenen `<details>` (heute ist sie ein `<tr>`). Beim Expand rendert direkt darunter ein „KI-Bewertung"-Block mit Eyebrow + einem Paragraph: dem `Finding.risk_band_reason`-Text (existiert seit ADR-0022 / Block O — wird vom LLM-Reviewer in Block P / ADR-0023 gefüllt). Kein eigener Card-Container, kein extra Style — nur eyebrow + Text mit Sekundär-Text-Color.

Wenn `risk_band_reason IS NULL`: der Block rendert nicht (kein „noch keine Bewertung verfügbar"-Stub). Die Chat-Conversation aus ADR-0023 §LLM-Risk-Reviewer bleibt unangetastet — sie ist weiterhin der Pfad für freie LLM-Konversation, der inline-Reason ist nur die fertige Pass-2-Begründung.

### (8) Bulk-Toolbar: „Acknowledge all noise on this server (N)"

Neuer prominenter Button in der Triage-Queue-Toolbar oberhalb des Risk-Band-Accordion. Wenn `noise_count > 0` für diesen Server: Button rendert mit Count, klickt zum Block-F-`BulkActionForm`-Endpoint mit `match.server_id=<id>` + `match.risk_band=noise` (kein Filter-Setup nötig). Confirm-Modal aus Block F (`bulk_ack.js`) wiederverwenden, **kein Pflicht-Kommentar** (ADR-0006).

Wenn `noise_count == 0`: Button rendert nicht.

### (9) Action-Needed-Pill + Status-Pill-Reihe

**(9a) Action-Needed-Pill mit Scan-Flash + verschärfter Render-Condition.** Die Action-Required-Pill aus ADR-0022 (heute `_partials/action_required_pill.html`) bekommt zwei Updates:

1. **Render-Condition wird verschärft** auf `yes_subcounts.escalate + yes_subcounts.act > 0`. Heute rendert die Pill bei jedem `action_required == 'yes'`, also auch wenn nur `pending`/`unknown`-Findings auf dem Server sind („Engine konnte nicht abschließend urteilen, schau selbst drauf"). Operator-Befund: das ist zu unspezifisch — eine pulsierende Pill für „ich weiß es nicht" verbrennt Aufmerksamkeit. Nach dem Update rendert die Pill nur, wenn das LLM (Block P / ADR-0023) tatsächlich `escalate` oder `act` finalisiert hat. Wenn beide Counts 0 sind: Pill rendert nicht, Server wirkt visuell ruhig.
2. **Scan-Flash + Scan-Beam-Animation** wie auf der Dashboard-Action-Needed-Card (Block W Phase D, `_action_needed_card.html` + `dashboard_scan_sync.js`). Pattern: `<span class="scan-chars">` umschließt den Pill-Text und splittet pro Zeichen in `<span class="scan-flash">`-Elemente; ein `useScanFlashSync`-Hook (für Jinja: ein Vanilla-JS-Pendant analog `dashboard_scan_sync.js`) timet jede Span so dass der cyan-Peak in einer L→R-Welle über die Pill läuft. Der Background bekommt zusätzlich den `stat-scan`-Keyframe (`mix-blend-mode: screen`-Beam der durchläuft).

Die Pill rendert mit `border-left: 3px solid var(--accent)` (Brand-Anker aus ADR-0033 §"accent left-bar"). Cyan-Outline-Tile ohne Fill.

**(9b) Übrige Status-Pills stratten.**

- `scan_stale` (warn) und `db_stale` (warn) werden zu **einer** kombinierten Pill „stale" zusammengefasst wenn beide zutreffen (Tooltip listet beide Gründe). Wenn nur einer zutrifft: einzelne Pill mit spezifischem Tooltip.
- Die drei Outdated-Pills aus Block N / ADR-0021 (`agent`/`trivy`/`trivy-db`) bleiben **einzeln**, weil sie verschiedene Operator-Aktionen triggern (Agent-Update via `curl install.sh`, Trivy-Update, Re-Pull der Trivy-DB). **Bewusste Abweichung vom Design:** Der Claude-Design-Output (`ServerDetail.jsx` Z. 79–80) rendert nur eine generische `trivy-db stale`-Pille — das war ein Demo-Fall im Mockup, nicht die finale Soll-Logik. Markup nutzt drei separate `sd-status-flag`-Elemente, eine pro zutreffender Bedingung, jede mit eigenem Tooltip-Text (Agent-Version, Trivy-Version, DB-Alter inkl. Command-Snippet wie heute via `is_agent_outdated`/`is_trivy_outdated`/`is_trivy_db_outdated`-Helpers aus Block N).
- `revoked` und `retired` bleiben.

Die `active`-Pill war schon raus durch ADR-0025 §(4).

### (10) Skeleton-Loading-States für KPI-Tiles, Heartbeat und Severity-Trend

Drei Sektionen mit serverseitig aggregierten Werten bekommen Skeleton-States nach dem Block-W-Pattern (ADR-0035 §"Skeleton scan-probe", `host__beat--skel` aus `frontend/src/css/components/sidebar.css`):

- **KPI-Tiles** (KEV / Critical / High / Medium): Tile-Container bekommt Modifier `sd-tile--skel sd-skel-frame` während Daten in-flight sind. Zahl rendert als `—`, Sparkline ist ausgeblendet, Tile-Border bekommt den dim-pulsing-scan-probe-Sweep (L→R cyan-beam, `mix-blend-mode: screen`).
- **Heartbeat-Strip** (30 Tage / 4 Bands): pro Tick-Element der `sd-heartbeat__tick--skel`-Modifier (dim base + Background-Pulse). Container `sd-skel-frame` mit dem gleichen scan-probe-Beam.
- **Severity-Trend** (30-Tage-Stacked-Bars): pro Bar-Element `sd-trend-col--skel` (dim base, keine Severity-Segmente). Container `sd-skel-frame` mit scan-probe-Beam.

Trigger-Bedingung für den Skel-State: HTMX-Initial-Load wenn die Daten lazy geladen werden (z. B. wenn man von einer anderen Page kommt) UND HTMX-Polling-Re-Render (60-s-Cadence aus ADR-0036). Im aktuellen Polling-Pattern (Single-Pane-Polling, OOB-Swaps) ist der Skel-State zwischen Request-Issue und Response-Render <200 ms sichtbar — also nur ein subtiler Wisch, kein durchgehender Spinner. Begründung: konsistent mit dem Sidebar-Heartbeat-Skel-Pattern; der Operator soll sehen dass Daten frisch sind, ohne durch einen großen Lade-Indikator irritiert zu werden.

Wenn `host_state_snapshot_at IS NULL` (Server hatte noch nie einen Scan, oder Agent < 0.3.0): Skel-State rendert **nicht** als Spinner — stattdessen Empty-State mit Mono-Text „— noch nie gescannt" bzw. „— Snapshot fehlt, Agent updaten" (Pattern aus `_partials/host_snapshot.html` §"Empty-State", wandert mit).

## Begründung

Alle neun Änderungen zielen auf dieselbe Operator-Frage: „muss ich was patchen?". Die heutige Seite beantwortet sie über mehrere weit verteilte Sektionen — Header + HeaderStats + Operator-Workflows + Triage Queue + Host-Snapshot + Tag-Editor + Lebenszeichen + Severity-Trend — die jede für sich plausibel sind, aber den Operator zwingen, die Antwort aus visuell konkurrierenden Stellen zusammenzusetzen.

Konsolidierungen (1)+(2)+(3) ziehen Triage-irrelevante Inhalte (Quickinfo-Reste, Tag-Editor, Host-Snapshot-Liste) in pulslose Zonen — Sysline, Sub-View, Header-Pills mit Slide-Down — und befreien den vertikalen Hauptfluss für die zwei eigentlichen Triage-Werkzeuge: Operator-Workflows („was empfehle ich dir konkret") und Triage Queue („was hängt sonst noch an").

Drilldowns (4)+(7) machen die zwei Workflow- und Finding-Stufen ohne Seitenwechsel ausklappbar — heute musste der Operator die Workflow-Card öffnen UND eine Sub-Group-Card öffnen UND ggf. in den Chat wechseln um die LLM-Begründung zu lesen. Die `Finding.risk_band_reason`-Datenbasis existiert seit Block O / ADR-0022, wurde aber visuell nie inline angeboten.

Risk-Band-Accordion (6) macht die mentale Sortierung explizit, die bisher visuell aus Badges rekonstruiert werden musste. Default-Expanded-ESCALATE-only setzt den Triage-Fokus per Markup-State, ohne Operator-Klick zu erzwingen.

Bulk-Shortcut (8) adressiert den dokumentierten Operator-Workflow „alle bekannten Noise-Findings auf einem Server abhaken", der heute jedes Mal ~6 Klicks (Filter setzen + Select-All + Bulk-Ack + Confirm) bedeutet.

Heartbeat- und Trend-Reduktion (5) ist reines Anwenden bereits getroffener Entscheidungen (ADR-0033/0035) auf eine Surface, die in Block W bewusst ausgespart wurde — kein neuer Konflikt.

Pill-Stratten (9) folgt dem ADR-0025 §(4)-Prinzip: Pills sind Aufmerksamkeits-Signale, nicht Hintergrund-Rauschen. Zwei warn-Pills für „Trivy-DB ist sowohl alt als auch der Scan ist alt" sind operativ ein Signal, nicht zwei.

## Konsequenzen

### Templates

Geändert: `app/templates/servers/detail.html` (Sektionen Header/HeaderStats/Lebenszeichen/Severity-Trend/Triage Queue komplett reorganisiert), `_findings_section.html` (Risk-Band-Accordion + Bulk-Toolbar), `_action_needed_section.html` (Card-Body bekommt Group-Drilldown-Tabelle), `_heartbeat_large.html` (30/4-Modell statt 50/7), `_stacked_bar_chart.html` (Range-Toggle ohne 50T), `_tag_editor.html` (bleibt aber Konsumenten-Pfad wandert), `_kpi_card.html` (color-rule „nur escalate/critical wear cyan" via Klassen-Modifier).

Entfernt: `_partials/host_snapshot.html` als eigenständige Sektion (Markup wandert in zwei Slide-Down-Panels innerhalb `detail.html`-Header).

Neu: `app/templates/servers/settings.html` (Sub-View-Shell), `_partials/server_pill_listeners.html`/`_partials/server_pill_services.html` (Slide-Down-Panel-Bodies), `_partials/risk_band_section.html` (Top-Level-Accordion-Slot mit Lazy-Load-Endpoint).

### Routes

Neu: `GET /servers/<int:server_id>/settings` (Sub-View-Vollseite + HX-Fragment, analog `_settings_shell.py`-Pattern), `POST /servers/<int:server_id>/settings/tags` (bestehende Tag-Add/Remove-Handler wandern dorthin), `POST /servers/<int:server_id>/settings/group` (neu — setzt `server.group_id`), `POST /servers/<int:server_id>/settings/scan-interval` (neu — setzt `server.expected_scan_interval_h`), `GET /servers/<int:server_id>/risk-band/<band>/findings` (Lazy-Load-Body für Risk-Band-Accordion).

Geändert: bestehende Tag-Editor-POSTs werden auf die Settings-Sub-View-Pfade umgezogen; die Detail-View hat keinen Tag-Editor mehr.

### Tests

Pure-Unit (default-pytest): neue Tests für Settings-Sub-View-Render + Tag/Group/Interval-POST-Handler, Risk-Band-Accordion-Aggregator + Default-Expanded-Logik, Host-Snapshot-Pill-Render + Empty-State, Bulk-Ack-Noise-Shortcut-Filter-Validation, Status-Pill-Stratten (kombinierte stale-Pill), Workflow-Card-Drilldown-Tabelle (Worst-Finding + Reason).

Drift-Regression nach `CLAUDE.md`-HTMX-OOB-Single-Source-Pattern für jeden neuen HTMX-Endpoint mit OOB-Antwort.

### Styling-Adoption aus dem Claude-Design-Output

Block X portiert die `sd-*`-BEM-Klassen aus `docs/design/server-detail.css` (~35 KB) in eine neue Komponenten-CSS-Datei `frontend/src/css/components/server-detail.css` (additions-only, kein Touch existierender Klassen). Tokens kommen ausschließlich aus `frontend/src/css/tokens.css` (existieren seit Block W / ADR-0033) — kein Hardcoding von Hex-Werten in der neuen CSS-Datei. Die JSX-Komponenten aus `ServerDetail.jsx` / `ServerSettings.jsx` werden in entsprechende Jinja-Partials übersetzt; React-Hooks (`useState`, `useScanFlashSync`) bekommen Vanilla-JS-Pendants in `frontend/src/js/server_detail.js` analog dem `dashboard_scan_sync.js`-Pattern aus Block W. Alpine.js wird für die zwei `sd-chip`-Slide-Down-Panels eingesetzt (Single-Component-State, gleiches Pattern wie Sidebar-Group-Collapse aus Block W).

`legacy-shim.css` wird für die Detail-Seite nicht mehr gebraucht — alle bisherigen Tailwind-/DaisyUI-Klassen-Aufrufe in `detail.html` und seinen Partials werden durch die `sd-*`-Klassen ersetzt. Der Shim-Anteil schrumpft entsprechend (mess bar an der Zeilen-Differenz in `frontend/src/css/components/legacy-shim.css` post-Block-X).

### Out of scope (explizit)

- **Performance-Re-Tuning** — ADR-0030 / Block V hat die kritischen Query-Pfade adressiert. Block X führt zwei neue Aggregator-Queries ein (Risk-Band-Top-Level-Count, Workflow-Card-Drilldown-Tabelle), beide deutlich kleiner als die bisherigen Group-Card-Loader. Bench-Re-Run nur auf User-Anweisung.
- **Host-Group-CRUD** — Settings-Sub-View bringt nur die Group-Auswahl. CRUD (Anlegen/Löschen/Umbenennen von Groups) bleibt in einem eigenen Folge-Block.
- **Add-Host-UI** — analog, bleibt out-of-Block.
- **Repo-Rename** `secscan` → `fathometer` — separater ADR notwendig wegen Code-Identifier-Sweep, Package-Name, Container-Image-Name.
- **Settings/Findings/Audit-Redesign** — eigene Folge-Blöcke.

### Migrations

Keine Schema-Änderungen. `server.group_id` und `server.expected_scan_interval_h` existieren bereits (ADR-0034 / Block W bzw. Block N). Alle neuen Felder im Settings-Sub-View schreiben auf bestehende Spalten.

### ADR-Status-Anpassungen

- **ADR-0018** — Status auf „Teilweise abgelöst durch 0025 und 0038" (war: „Teilweise abgelöst durch 0025"). 0038 überschreibt Lebenszeichen-`<dl>`-Block und die Sektions-Reihenfolge im Header.
- **ADR-0022** — Status auf „Akzeptiert (§Audit-Events teilweise abgelöst durch 0027; §UI-Redesign Host-Snapshot teilweise abgelöst durch 0038)". 0038 überschreibt nur das UI — die Persistenz und Pre-Triage-Engine bleiben unangetastet.
- **ADR-0023** — Status auf „Akzeptiert (§UI-Konsequenzen amendet durch 0038 — Workflow-Card-Drilldown, Inline-Reason)". Pass-1/Pass-2-Engine und Worker-Queue unangetastet.

## Re-Open-Trigger

- **Inline-Reason wird vom LLM-Reviewer nicht in `Finding.risk_band_reason` gefüllt.** Bisher belegt nur Pass-2 die Spalte über die Junction-Vererbung (ADR-0028 §inherit_group_risk_to_findings). Wenn ein Folge-Block die Spalte deprecated oder umlenkt, wandert der Inline-Block auf das neue Feld.
- **Host-Group-CRUD-Bedarf** — sobald Operator-Workflow für Group-Verwaltung gebraucht wird, eigener Block + ADR.
- **Performance-Drift bei großen Servern (> 1000 Application-Groups)** — Risk-Band-Top-Level-Count + Card-Body-Aggregat kann teuer werden. Re-Tune ggf. mit ADR-0030-Pattern (Single-Aggregate-Query + Lazy-Load).
- **Theming des Risk-Band-Accordion-Headers** — heute outline-Badge, kommt mit Claude-Design ggf. anders. Style-Adoption-Block X+1 entscheidet.
