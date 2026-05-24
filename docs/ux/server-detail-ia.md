# Server-Detail – Information Architecture

> **Status:** Draft 1 · 2026-05-23
> **Bezug:** `ARCHITECTURE.md`, Phase-1-Redesign (`docs/blocks/w-redesign-phase-1.md`, parallel laufend), künftiger Block „Server-Detail" (noch nicht angelegt)
> **Mockup-Referenz:** [`docs/ux/mockup-kandidat-2.html`](./mockup-kandidat-2.html)

Dieses Dokument beschreibt die Information Architecture der **Server-Detail-Pane** (rechter Bereich neben der Server-Liste). Globaler Header und linke Server-Liste werden im Phase-1-Redesign behandelt und sind hier nicht Gegenstand. Die Implementation dieser IA wird in einem separaten Block nach Phase-1 geplant; dieses Dokument ist die Grundlage für die spätere ADR und Block-Spec.

### Layout-Rahmen (Hard-Constraint)

- Die **linke Server-Liste bleibt persistent sichtbar** und nimmt **1/3 der Viewport-Breite** ein. Der Operator kann jederzeit einen anderen Server auswählen, ohne die Detail-Pane zu verlassen.
- Der **Server-Detail-Pane hat folglich 2/3 der Viewport-Breite** zur Verfügung. Alle Layout-Entscheidungen — Sub-Nav, Master/Detail-Innenaufteilung, Stat-Bar, Floating-Chat — müssen in diesem Budget funktionieren.
- Typische Viewports (Desktop): bei 1440px Gesamtbreite verbleiben ~960px für die Detail-Pane; bei 1280px Gesamtbreite ~853px. Die innere Master/Detail-Aufteilung (Findings-Liste / Finding-Detail) muss bei beiden noch sinnvoll lesbar bleiben.
- Mobile-Layout ist explizit out-of-scope (siehe ARCHITECTURE §17).

---

## 1. Zweck und Top-Aufgaben

Die Server-Detail-Pane existiert damit ein Operator **schnell den Sicherheitszustand genau eines Servers einschätzen und Findings triagieren** kann.

**Top-3 Aufgaben (in absteigender Häufigkeit):**

1. **Findings triagieren** — neue/offene Findings sichten, einzeln oder als Application-Group bewerten und Status setzen (Trust / Defer / Fix). Das ist die tägliche Hauptarbeit.
2. **Server-Kontext einschätzen** — „läuft der Server überhaupt", „wann war der letzte Scan", „was läuft da drauf an Diensten", „passt das was läuft zu meinem Bild davon". Eher beim ersten Aufruf oder bei Unstimmigkeiten.
3. **Mit der KI über Findings/Server/Listener diskutieren** — punktuelle Klärung („ist dieses CVE in meinem Setup ausnutzbar", „was macht dieser Listener", „in welcher Reihenfolge patchen").

Aufgaben **nicht** auf dieser Seite:
- Konfiguration des Servers (Tags, Gruppe, Scan-Intervall, Notification-Channel) → separate Settings-Seite (s. §5).
- Vergleich zwischen Servern, Bulk-Operationen → Server-Liste / globales Settings.
- Konfiguration des LLM-Features selbst (Prompts, Provider, Limits) → globale Admin-Settings.

**Leitprinzip (`MEMORY.md`):** Weniger ist mehr. Keine KPI-/Metrik-Dashboards. Primärer Bereich = Arbeitsfläche; Details on-demand.

---

## 2. Inhalts-Inventar

Alle Informationen die auf dieser Seite (oder einen Klick entfernt) verfügbar sein sollen, mit Datenquelle und IA-Klassifikation.

| # | Element | Datenquelle | IA-Klasse |
|---|---|---|---|
| 1 | Server-Name + Status-Indikator (online/offline) | DB: server, heartbeat | **Primary** (Header) |
| 2 | OS-Distribution, Kernel, Architektur | Agent-Snapshot | **Primary** (Header-Subline) |
| 3 | Tags (prod, edge, …) | DB: server_tags | **Primary** (Header-Subline) |
| 4 | Zeit seit letztem Scan | DB: scan_runs | **Primary** (Header-Subline) |
| 5 | Findings gesamt + offen (Counter) | DB: findings | **Secondary** (Stat-Bar) |
| 6 | Lebenszeichen-Sparkline 50 Tage | DB: heartbeat_log | **Secondary** (Stat-Bar) |
| 7 | Severity-Trend-Sparkline | DB: findings über scan_runs | **Secondary** (Stat-Bar) |
| 7a | **„Was zu tun ist"** — Workflow-Items (siehe §3a) | abgeleitet aus DB: findings + listeners + scan_runs + heartbeat | **Primary** (Master, Top-Sektion) |
| 8 | Findings-Liste, default-gefiltert auf offen, gruppiert nach Application-Group | DB: findings + group_assignment | **Primary** (Master, unter „Was zu tun ist") |
| 9 | Findings ohne Group | DB: findings | **Primary** (Master, eigene Sektion am Ende) |
| 10 | Finding-Detail: CVE, CVSS, Beschreibung, Paket, betroffene/gefixte Version, Refs | Trivy-JSON + DB | **Primary** (Detail-Pane) |
| 11 | Finding-Triage-Aktionen: Trust / Defer / Fix / Notiz | DB: finding_status | **Primary** (Detail-Pane) |
| 12 | Listeners & Services Liste (Port, Proto, Bind, Prozess, Paket, Exposure) | Agent-Payload | **Secondary** (Sub-Nav) |
| 13 | Listener-Detail (Prozess, PID, CmdLine, Paket-Mapping) | Agent-Payload | **Secondary** (Detail-Pane) |
| 14 | Host-Snapshot (Distribution, Kernel, Arch, Hostname, Uptime, Boot-ID, Agent-Version, Trivy-Version, Top-Pakete-nach-Findings) | Agent-Snapshot | **Secondary** (Sub-Nav) |
| 15 | Scan-Historie (letzter, vorletzter Scan) | DB: scan_runs | **Tertiary** (in Snapshot) |
| 16 | Erwartetes Scan-Intervall (Anzeige) | DB: server_settings | **Tertiary** (in Snapshot) |
| 17 | KI-Chat (Server-Scope) | LLM-Service | **Primary** (Floating Launcher) |
| 18 | KI-Trigger pro Group / Finding / Listener | LLM-Service | **Primary** (Inline) |
| 19 | Server-Einstellungen-Link | navigation | **Tertiary** (Header-Action) |

**IA-Klassen:**
- **Primary** — direkt sichtbar oder dominant in der Arbeitsfläche.
- **Secondary** — einen Klick / einen Mode-Switch entfernt.
- **Tertiary** — auf separater Seite (Settings) oder eingebettet in eine Secondary-Sektion.

---

## 3. Prio-Hierarchie

Festgehaltene Prio des Operators (User-Input, in absteigender Wichtigkeit):

### Primary — Arbeitsfläche
1. **Header-Kontext** (Name, OS, Kernel, Arch, letzter Scan, Tags) — damit klar ist worüber gesprochen wird.
2. **„Was zu tun ist" — Operator-Workflows** — siehe §3a für Kategorien.
3. **Findings-Liste** — die Detailebene zum Durchsehen und Triagieren. **Default-Filter: offene Findings** (im Beispiel 12 statt 319). Volle 319er-Liste ist über Filter-Toggle einen Klick weit weg, nicht primär.

### 3a. „Was zu tun ist" — über die bestehenden Risk-Bands plus Block P

**Revidiert nach Iteration 2026-05-23 (Korrektur 2):** Die echte main-Implementierung benennt die Kategorien anders als in den frühen Skizzen angenommen. Die tatsächlichen Risk-Bands sind:

| Band | Bedeutung | Default-Status heute |
|---|---|---|
| `escalate` | Sofortige Aufmerksamkeit nötig | expanded |
| `act` | Triage / patchbar | expanded |
| `mitigate` | Workaround empfohlen | expanded |
| `pending` | Noch keine LLM-Einschätzung | expanded |
| `unknown` | Kein Band gesetzt (Edge-Case) | collapsed |
| `monitor` | Niedriges Risiko, beobachten | collapsed |
| `noise` | False-positive / nicht relevant | collapsed |

Zusätzlich existiert eine **„Was zu tun ist"-Sektion (Block P / ADR-0023)** oberhalb der Triage Queue, die aus den Bands `escalate` und `act` bis zu 5 Workflow-Cards aggregiert (gruppiert nach `risk_band + action_type + application_group`, jeweils mit Worst-Finding + LLM-Reason). Diese Sektion bleibt unverändert — sie macht die Workflow-Priorisierung schon heute kompakt sichtbar.

Konsequenzen aus der Iteration:

- **Alle sieben Risk-Bands collapse-by-default.** `escalate`, `act`, `mitigate` und `pending` werden von expanded auf collapsed umgestellt; `unknown`, `monitor`, `noise` bleiben wie heute collapsed. Einheitliches Verhalten.
- **Lazy-Load durchgängig:** Findings werden erst beim Aufklappen einer Band-Sektion über HTMX nachgeladen (heute bereits für `monitor`/`noise`/`unknown`, jetzt einheitlich für alle).
- Workflow-Hinweise (neue Critical-Findings, abgelaufene Defers, KEV-aktiv) kommen über (a) die existierende Block-P-Sektion und (b) Badges/Marker in der Finding-Zeile (`neu`, `KEV`, `aktiver Exploit`) sowie über die LLM-Reason-Spalte rechts (siehe §3b).

Kategorien (Auswahl, nicht abschließend — der Block wird Konkret-Set festlegen):

| Kategorie | Anlass | Aktion |
|---|---|---|
| Neue Findings | Findings die im letzten Scan erstmals auftauchten | Filter auf „Neu" anwenden |
| Severity-Eskalationen | Bestehendes Finding ist im neuesten CVE-Feed höher eingestuft worden | Betroffenes Finding selektieren |
| Unbekannter Listener | Listener ohne Paket-Match oder mit verdächtigem Pfad | Listener-Mode + Selektion |
| Neuer Listener | Listener ist seit letztem Scan dazugekommen | Listener-Mode + Selektion |
| Quick-Win | Application-Group vollständig durch ein einziges Paket-Upgrade behebbar | KI-Chat mit Group-Scope oder direkt Group im Findings-Mode anspringen |
| Defer-Frist erreicht | Auf „Defer until X" gesetzte Findings haben X erreicht | Filter auf „Defer-Frist abgelaufen" |
| Scan überfällig | Erwartetes Scan-Intervall + Toleranz überschritten | Snapshot-Mode öffnen, Operator informieren |
| Lange unangefasst | Offene Findings ohne Status-Änderung seit > 30 Tagen | Filter anwenden |

Anzeige: typisch 3-6 Einträge. Falls keine Action-Items vorliegen, kollabiert die Sektion zu einem ruhigen Status („Alles up to date, letzter Scan vor 10h ok") — bewusst kein Empty-State-Drama.

Sortierung der Items: nach Dringlichkeit absteigend (Eskalationen / unbekannte Listener oben, „lange unangefasst" unten). Eskalations-Algorithmus = im Block zu spezifizieren.

### Secondary — informativ, auflockernd
3. Findings-Counter (offen / gesamt) — als Zahl im Stat-Bar.
4. Lebenszeichen-Sparkline 50 Tage.
5. Severity-Trend pro Tag (Sparkline).

Diese drei landen im **schlanken Stat-Bar unter dem Header**, nicht als Cards.

### Secondary — Kontext, schnell zugreifbar
6. **Host-Snapshot** (vor 10h).
7. **Listeners & Services**.

Beide erreichbar über die Sub-Nav direkt unter dem Stat-Bar — nicht hinter Scroll, nicht hinter Header-Button.

### Tertiary — eigene Seite
8. **Server-Einstellungen** (Tags, Gruppe, Scan-Intervall, Notification-Channel) → siehe §5.

---

## 4. LLM-Integration

Die bisherige „KI Bewertung anfordern"-Button-Lösung ist nicht kontext-bezogen genug und wird ersetzt. Das LLM-Feature wird zweidimensional modelliert: **Scope** × **Trigger**.

### 4.1 Scopes (worüber wird diskutiert)

| Scope | Gegenstand | Typische Fragen |
|---|---|---|
| **Server** | Gesamtbewertung dieses Servers | „Was hat sich seit letztem Scan geändert?", „Patch-Reihenfolge?", „Größte Angriffsfläche?" |
| **Application-Group** | Eine Komponente und ihre Findings als Bundle | „Wie kritisch ist diese Group in meinem Setup?", „Patch-Pfad?", „Wer nutzt das auf meinem Server?" |
| **Finding** | Ein einzelnes CVE | „In meinem Kontext exploitable?", „Workaround ohne Update?", „Wie sicher patchen?" |
| **Listener** | Ein einzelner Port/Dienst | „Was macht dieser Listener?", „Gehört das hierher?", „Ist das gefährlich/üblich?", „Indizien für Malware?" |

### 4.2 Trigger (wo und wie wird gestartet)

| Trigger | Scope | UX-Pattern |
|---|---|---|
| Floating Chat-Launcher (unten rechts) | Server (Default) | Support-Agent-Style Bubble; öffnet Chat-Panel |
| 🤖-Icon an Group-Header | Application-Group | Inline-Action; öffnet Chat-Panel und setzt Scope |
| 🤖-Icon an Finding-Row | Finding | dito |
| 🤖-Button im Finding-Detail-Pane | Finding | dito (zweiter Einstieg im Detail-Pane) |
| 🤖-Icon an Listener-Row | Listener | dito |
| 🤖-Button im Listener-Detail-Pane | Listener | dito |

**Bewusst nicht vorgesehen:** zentraler Header-Button als einziger Einstieg (zu unspezifisch); Modal-Chat (bricht Triage-Flow); Inline-Expansion eines langen Chats unter einer Zeile (unleserlich).

### 4.3 Chat-Surface

- **Floating Panel** unten rechts. Geschlossen = kleine Bubble; geöffnet = ~420×600px Panel mit Header, Scope-Chip-Leiste, History und Eingabe.
- Beim Klick auf ein 🤖-Icon: Panel öffnet (falls geschlossen) und der **Scope wechselt** in der Chip-Leiste sichtbar (z. B. „Listener – nginx :443").
- **Quick-Prompt-Chips** unter der Scope-Leiste; Inhalt je nach Scope unterschiedlich (s. §4.1 Beispielfragen).
- Bei Scope-Wechsel bleibt die History sichtbar (nicht zurückgesetzt). Im finalen Design klären ob neue Messages mit Scope-Badge versehen werden — Detail für später, nicht in dieser IA.

### 4.4 Kontext-Übergabe an das LLM

**Annahme dieser IA (Implementation in eigenem LLM-Block):** das LLM bekommt mit jeder Anfrage den vollständigen Server-Kontext (Snapshot, alle Findings, alle Listeners) als Grundlage, ergänzt um den expliziten Scope-Bezug (welches CVE / welche Group / welcher Listener gerade Fokus ist).

Das ist eine Annahme aus der UX-Perspektive — die tatsächliche Token-Strategie (immer alles vs. selektiv) wird im LLM-Feature-Block entschieden. Aus IA-Sicht relevant ist nur: das LLM hat genügend Kontext für sinnvolle Antworten an jedem Scope.

### 4.5 Out-of-Scope dieser IA

- Prompt-Engineering, System-Prompts, Provider-Konfiguration.
- Token-/Cost-Limits, Rate-Limits.
- Chat-History-Persistenz (pro Server, pro Session, …).
- Streaming-Verhalten, Tool-Use, RAG-Quellen.

Diese gehören in einen separaten LLM-Feature-Block.

---

## 5. Settings-Trennung

Drei Ebenen, klar voneinander getrennt:

### 5.1 Server-Detail-Pane (diese Seite)
Zeigt Server-Zustand und Findings. **Keine Konfiguration des Servers selbst.** Einziger administrativer Touchpoint: ein Link „Server-Einstellungen" im Header, der zur dedizierten Settings-Seite führt.

### 5.2 Server-Einstellungen — pro Server (In-Place-View, **revidiert 2026-05-23**)

Klick auf das ⚙-Icon im Header **ersetzt den Inhalt der gesamten Detail-Pane** durch eine Settings-View. Server-Liste links bleibt erhalten. Settings-View hat oben einen `[← Zurück]`-Button und unten `[Speichern]` / `[Abbrechen]`.

Begründung gegenüber separater Page: kein zweiter Navigations-Schritt, kein verlorener Kontext (Server-Liste bleibt sichtbar, gleicher Server bleibt aktiv markiert). Verhalten wie ein Modus-Wechsel innerhalb des Detail-Pane.

Enthält Konfiguration die nur diesen einen Server betrifft:
- **Tags verwalten** — Add/Remove Tags (zieht aus der Detail-Pane-Header-Sektion hierher um — der Header zeigt nur die gesetzten Tags read-only).
- **Gruppe** — Zuweisung zu einer Server-Gruppe (Server-Gruppen-Feature existiert noch nicht, kommt).
- **Erwartetes Scan-Intervall** — beim Install vom Agent gesetzt, hier veränderbar/überschreibbar; relevant für Heartbeat-Warnungen.
- **Notification-Channel** — pro Server oder via zugewiesene Gruppe (Notification-Feature existiert noch nicht).

URL-State: `/servers/<id>?view=settings` oder `/servers/<id>/settings` (Detail bei Implementierung).

### 5.3 Globale Settings (`/settings/servers/`, existiert teilweise)
Bleibt für Bulk-/Admin-Operationen: alle Server, Defaults für Scan-Intervalle, neuen Server hinzufügen, Server entfernen, globale Tag-Verwaltung, etc.

**Abgrenzung zur Server-Einstellungen-Seite:** Wenn die Aktion „alle Server" oder „neuer Server" betrifft → globale Settings. Wenn sie „dieser eine Server" betrifft → Server-Einstellungen pro Server.

---

## 6. Selektion, URL-State, Empty-States

### 6.1 Selektions-Modell
- **Master-Detail** im Findings- und Listeners-Mode innerhalb der 2/3-Detail-Pane. Linke Innen-Spalte = Liste/Master, rechte Innen-Spalte = Detail.
- **Host-Snapshot-Mode** hat keinen Detail-Pane — der Snapshot wird vollständig in der Innen-Spalte angezeigt; rechts ist leer (mit Hinweis) oder wird ggf. in einem späteren Iterationsschritt anders genutzt. Für jetzt: links voll, rechts dezenter Empty-State.
- Die innere Master-Liste sollte nicht schmaler als ~340px werden, sonst leiden Group-Header und Severity-Badges. Bei knappem Viewport hat der Detail-Pane Vorrang im Wachstum (Master fixed-min, Detail flex).

### 6.2 URL-State (Wunsch, im Detail-Block zu spezifizieren)
- `/servers/<id>` — Default = Findings-Mode, kein Item selektiert.
- `/servers/<id>?mode=listeners` — wechselt zur Listeners-Sub-Nav.
- `/servers/<id>?mode=snapshot` — wechselt zum Snapshot.
- `/servers/<id>?finding=<cve>` — selektiert ein bestimmtes Finding (Deep-Link).
- `/servers/<id>?listener=<id>` — selektiert einen Listener.

Damit ist Bookmark + Sharing möglich. URL-State wird über HTMX `hx-push-url` gepflegt.

### 6.3 Empty-States
- **0 Findings** — gratulierender Hinweis „Keine offenen Findings", aber Application-Group-Liste bleibt sichtbar wenn historische Findings vorhanden (siehe „Alle/Offen"-Filter).
- **Server offline / kein Heartbeat** — Header-Statusindikator wechselt (rot/grau), Stat-Bar bekommt eine sichtbare Warnung; Findings-Liste bleibt vom letzten Scan.
- **Kein Scan-Ergebnis (frisch installierter Server)** — Hinweis-Card im Findings-Pane: „Noch kein Scan-Ergebnis vorhanden", verlinkt auf Snapshot-Tab (zeigt Agent-Version etc.).
- **Listeners leer** — Hinweis „Keine Listener im letzten Scan erfasst" (sollte nicht vorkommen, aber definiert).

---

## 7. Erweiterbarkeit

Die Architektur soll neue Inhalte aufnehmen können ohne Re-Design.

### 7.1 Sub-Nav als primärer Erweiterungs-Anker
Neue Inhalts-Typen pro Server kommen als zusätzliches Sub-Nav-Tab. Beispiele für mögliche Erweiterungen (alle aktuell **out of scope**):
- „Compliance" (CIS-Benchmarks, sobald Misconfigs aktiviert werden — Schema laut ARCHITECTURE bereits vorbereitet)
- „Scan-Historie" (Liste der letzten N Scans mit Findings-Delta)
- „Container/Image-Scans" (laut ARCHITECTURE §17 derzeit out-of-scope, später denkbar)

### 7.2 Detail-Pane als Polymorpher Inspector
Der rechte Pane rendert je nach Selektion verschiedene Detail-Typen (Finding, Listener, ggf. künftig Misconfig, Container, …). Neue Detail-Typen sind durch eine neue Template-Partial-Datei addierbar, ohne Layout-Anpassung.

### 7.3 LLM-Scopes
Aktuell vier Scopes (Server, Group, Finding, Listener). Erweiterbar um z. B. „Misconfig" oder „Container", indem ein 🤖-Trigger an dem entsprechenden Inhalts-Element angebracht und ein Eintrag in `QUICK_PROMPTS[scope]` gepflegt wird.

### 7.4 Settings-Seite
Settings-Sektionen sind additiv. Neue Server-Konfigurationen (z. B. „Air-Gap-Modus-Override pro Server", „Bevorzugte Update-Quelle") landen als neue Sektion in `/servers/<id>/settings`.

---

## 8. Out-of-Scope

Strikt nicht Teil dieses IA-Dokuments und nicht Teil des Server-Detail-Blocks:

- **Phase-1-Redesign** (globaler Header + linke Server-Liste) — läuft parallel, ist separat spezifiziert.
- **LLM-Feature an sich** — Prompts, Provider, Cost, Persistenz (siehe §4.5).
- **Server-Gruppen-Feature** (Verwaltung der Gruppen, Gruppierung in der linken Liste) — eigenständige Erweiterung; in der Server-Einstellungen-Seite hier nur als „Gruppe zuweisen"-Dropdown referenziert.
- **Notification-Channel-Feature** — laut ARCHITECTURE §17 derzeit out-of-scope; in der Server-Einstellungen-Seite hier vorgesehen als Platzhalter-Sektion sobald aktiviert.
- **Mobile-Layout** — laut ARCHITECTURE §17 out-of-scope.
- **Container/Image-Scans, Code-Scans, SBOM, License-Findings, PDF-Export** — siehe ARCHITECTURE §17.
- **Trend-Graphen über lange Zeiträume** — schlanke 50-Tage-Sparklines im Stat-Bar sind okay; alles darüber hinaus out-of-scope.
- **Multi-User-Aspekte** (wer hat triagiert, Audit-Log pro Triage-Aktion) — Single-User-MVP.

---

## 9. Offene Entscheidungen

Wird in der Layout-Detaildiskussion und anschließenden ADR geklärt:

1. **Stat-Bar-Position** — direkt im Header (kompakt, wie im Mockup) oder als eigene schmale Zeile zwischen Header und Sub-Nav? Aktuell: im Header integriert.
2. **Sub-Nav-Style** — Tabs (wie Mockup) oder Segmented-Control oder Pill-Buttons? UX-egal, Daisy-UI-Komponente in der ADR festlegen.
3. **Host-Snapshot-Layout** — voll in der linken Spalte (wie Mockup) oder doch 2-spaltig mit Detail-Pane (z. B. Snapshot-Liste links, Detail eines Snapshot-Items rechts)? Aktuell: voll links, kein Detail-Pane.
4. **Findings-ohne-Group** — eigene Sektion „Ohne Gruppe" am Ende (wie Mockup) oder als virtuelle Group oben? Aktuell: am Ende, mit dezent abgesetztem Background.
5. **Chat-Persistenz** — eine fortlaufende History pro Server oder pro Scope eigene? Aktuell nicht entschieden; UX-relevant nur insofern, als die Chip-Leiste in beiden Modellen funktioniert.
6. **Triage-Aktion Visuell** — Buttons (wie Mockup) oder Status-Pillen mit Click-to-Cycle? Daisy-UI-Komponente in ADR.
7. **„Mehr Findings"-Pattern** — pro Group nur N anzeigen + „… weitere" (wie Mockup) oder volle Liste mit Virtual-Scroll? Hängt an Performance bei großen Servern.
8. **Mode-Switch und Selektion** — beim Wechsel von Findings → Listeners: Selektion vergessen oder pro Mode merken? Aktuell nicht entschieden.
9. **„Was zu tun ist" — Kategorien-Set** — welche Workflow-Kategorien sind in §3a tatsächlich für MVP, welche kommen später? Konkret: Severity-Eskalationen brauchen ein NVD-Feed-Vergleich (Aufwand), Quick-Win-Detektion braucht ein Aggregations-Query — sollte das alles am Anfang dabei sein oder iterativ?
10. **Berechnungs-Zeitpunkt der Action-Items** — beim Page-Load (live aggregiert) oder vorberechnet beim Scan-Import? Bei vielen Servern mit vielen Findings kostet ersteres.
11. **Action-Panel-Collapse** — bei null Items kollabieren oder ganz ausblenden? Aktuell: Plan ist „kollabieren mit ruhiger Status-Zeile", siehe §3a.

---

## 10. Design-Entscheidungen aus Iterations-Runden

Konsolidierte Entscheidungen aus den Layout-Iterationen 2026-05-22/23. Diese Liste ist Quelle der Wahrheit; ältere Abschnitte oben spiegeln zurück.

**Referenz-Implementation:** Aktueller Stand in `app/templates/servers/detail.html`. Mockup der Ziel-Iteration: [`mockup-iter-01.html`](./mockup-iter-01.html).

### Echte Sektions-Reihenfolge auf main (Stand 2026-05)

Aus dem Top-Kommentar von `detail.html` und ADR-0018:

1. Header — Hostname, Status-Pill-Reihe (Action-Required-Pill als erste, dann revoked/retired/stale/db-stale, dann Agent-/Trivy-Outdated), OS-Zeile, Tag-Hashtags, KI-Bewertung-Button rechts.
2. „Was zu tun ist" (Block P / ADR-0023) — bis zu 5 Cards mit `escalate`/`act`-Workflows, gruppiert nach `risk_band + action_type + application_group`.
3. Host-Snapshot (Block O / ADR-0022) — Listeners + Active Services, je default zugeklappt.
4. Tag-Editor — Akkordeon, default zugeklappt.
5. HeaderStats — 64px-Counter „Findings · offen · gesamt" + 4 KPI-Cards (KEV/Critical/High/Medium) mit Sparklines.
6. Lebenszeichen — Heartbeat-Large-Grid (50T, farbig nach max-severity + KEV-Punkt) + 4-Spalten-Meta-Grid (Erwarteter Intervall, Letzter Scan, Trivy-DB, KEV-Ereignisse · 50T).
7. Severity-Trend — Stacked-Bar-Chart (50T) + Range-Toggle 24h/7T/30T/50T + Legende mit Counts und Prozenten.
8. Triage Queue (Block K / ADR-0018) — `_findings_section.html`, Risk-Bands wie §3a, default 4 expanded / 3 collapsed.

### Änderungen für die nächste Iteration

#### Header

- **Sektion 4 (Tag-Editor-Akkordeon) entfällt.** Tags wandern komplett in die Settings-View. Im Detail-Header werden Tag-Hashtags vorerst weiter angezeigt (read-only); ob sie auch dort verschwinden, ist noch offen — Vorschlag: ja, der Header gewinnt damit Luft.
- **Sektion 3 (Host-Snapshot) entfällt aus dem Body.** Wird ersetzt durch zwei **Header-Pills** unter den Status-Pills: `Listeners & services: N` und `Active services: M`. Klick öffnet einen **persistenten Slide-Down-Panel** direkt unter dem Header (kein Tooltip; bleibt offen bis ✕). Nur eines der beiden Panels gleichzeitig sichtbar.
- **Lebenszeichen-Meta-Grid (Sektion 6, untere Hälfte) wird aufgelöst:**
  - `Erwarteter Intervall`, `Letzter Scan`, `Trivy-DB` ziehen in eine **neue Quickinfo-Zeile im Header** direkt unter der OS-Zeile.
  - `KEV-Ereignisse · 50T` entfällt vollständig.
  - Die Heartbeat-Grafik selbst (obere Hälfte von Sektion 6) bleibt.
- **„KI-Bewertung anfordern"-Button bleibt für Phase-1 wo er ist.** TODO im späteren Block: Migration zu einer **Floating-Chat-Bubble** (Support-Agent-Style, unten rechts) mit Kontext-Triggern an Group/Finding/Listener/Listener-Detail. Bis dahin nur der Button.
- **Neuer Settings-Button** rechts neben dem KI-Bewertung-Button. Klick → Body wird komplett durch die Settings-View ersetzt (siehe §5.2 revidiert).

#### Findings-Body (§3a-Revision)

- **Alle sieben Risk-Bands (`escalate` · `act` · `mitigate` · `pending` · `unknown` · `monitor` · `noise`) sind collapse-by-default.** Die heute expanded-by-default vier (escalate/act/mitigate/pending) werden umgestellt.
- **Lazy-Load durchgängig:** Findings werden erst per HTMX nachgeladen wenn die Band-Sektion aufgeklappt wird. Heute schon für `monitor`/`noise`/`unknown`, jetzt einheitlich.
- **Finding-Zeile: zwei-spaltiges Layout** für bessere Scannbarkeit (heute zeigt `_view_list.html` viele Spalten in einer Zeile — Risk-Pill, CVE, Paket, EPSS, CVSS, Status, Severity, Erstmals, Aktion. Das wird umgebaut):
  - Top-Zeile (volle Breite): Risk-Pill · CVE-Link · KEV-Badge · neu/defer-abgelaufen · CVSS · EPSS · erstmals seen.
  - Spalte links (~45%): Paketname mono fett · `Ubuntu package …`-Subline · installed/fix-Version.
  - Spalte rechts (~55%): **LLM-Reason-Text** (`risk_band_reason`) mehrzeilig, fließt natürlich um. Beispielform: `"ssh on 0.0.0.0:22 PUBLIC-EXPOSED; kernel modules reachable via network traffic; CVE-2026-31431 high KEV active exploit, fix available in 5.15.0-178."`
  - Aktions-Zeile darunter (Details/Abhaken-Buttons), nur sichtbar bei Hover oder im Detail-Modal — heute sind die Buttons permanent sichtbar, das macht die Zeile schwer scannbar.
- Heute zeigt `_view_list.html` `risk_band_reason` klein/mono unter dem Identifier (Zeile 117–314). Diese Position bleibt erhalten als zusätzlicher Hinweis, ABER die Reason zieht zusätzlich in die rechte 2-Spalten-Hälfte um — größer und besser lesbar.

#### Settings — In-Place statt eigene Page

- Klick auf ⚙ ersetzt den Body der Detail-Pane durch die Server-Settings-View. Header der Detail-Pane (Name + Status-Pills) bleibt sichtbar (zu klären: ja oder nein? — aktueller Mockup-Vorschlag: nein, kompletter Body inkl. Header wird ersetzt; nur die Server-Liste links bleibt). Save / Abbrechen unten, Zurück oben.
- **Tag-Editor-Akkordeon entfällt** (Sektion 4 der bisherigen Reihenfolge). Tag-Verwaltung läuft komplett über die Settings-View.

### Aus diesen Entscheidungen entfallene Sektionen / Konzepte

- Sektion 3 **Host-Snapshot** im Body → ersetzt durch zwei Header-Pills mit persistentem Slide-Down-Panel.
- Sektion 4 **Tag-Editor-Akkordeon** → entfällt; Tags in Settings-View.
- Sektion 6 **Lebenszeichen-Meta-Grid** (Intervall/Letzter Scan/Trivy-DB/KEV-Ereignisse) → ersten drei in Header-Quickinfo, KEV-Ereignisse komplett entfernt.
- Frühere Skizzen einer „Was zu tun ist"-Sektion oberhalb der Findings → bleibt bei der existierenden Block-P-Sektion, keine zweite parallele Sektion.
- Sub-Navigation `Findings | Listeners | Snapshot` als Tabs → ersetzt durch Header-Pills (persistent panels statt Mode-Switch).
- Server-Einstellungen als separate `/servers/<id>/settings`-Page → ersetzt durch In-Place-View.

### KI-Chat — späterer Schritt

- Der heutige **„KI-Bewertung anfordern"-Button bleibt für Phase-1 wo er ist** (oben rechts im Header). Bei Klick startet er heute eine LLM-Conversation und navigiert zu `/chat/<conversation_id>`.
- Folge-Iteration: Migration zu einer **Floating Chat-Bubble** (Support-Agent-Style, unten rechts) mit Inline-Triggern 🤖 an Group/Finding/Listener/Listener-Detail (Scopes siehe §4.1).
- **TODO im späteren Block:** Migration „KI-Bewertung"-Button → Floating-Bubble explizit als Task aufnehmen; nicht versehentlich in einem anderen Refactor mit erschlagen.

## 11. Offene Punkte aus dieser Iteration

1. **Was passiert mit Host-Snapshot-Daten die nicht Listeners/Active Services sind?** Kernel-Version, Distro, Agent-Version, Top-Pakete, Scan-Historie. Optionen: (a) in den OS-/Quickinfo-Header rein, (b) dritter Header-Pill „Host-Snapshot" mit eigenem Panel, (c) verteilt — OS-Basics im Header-Subline, Rest in Settings-View. Vorschlag: (a) für Kernel/Distro (sind schon da), (b) für Top-Pakete und Scan-Historie.
2. **Wie weit reicht „Active services" vs. „Listeners"?** Listeners = was hört auf einem Port. Active services = was läuft (systemd-units?). Definition für den Block fixieren.
3. **Settings-View Layout** — eine Spalte oder geteilt? Wenn 4+ Sektionen sind (Tags, Gruppe, Intervall, Notification), reicht eine Spalte. Bei Wachstum prüfen.
4. **Beibehaltung URL-State** beim Toggle Findings ↔ Settings (`?view=settings` vs. eigener Path).

## 12. Referenzen

- Mockup: [`docs/ux/mockup-kandidat-2.html`](./mockup-kandidat-2.html)
- ARCHITECTURE: globaler Tech-Stack, Out-of-Scope-Liste
- Phase-1-Redesign: `docs/blocks/w-redesign-phase-1.md`
- Memory-Leitprinzipien:
  - „Server-Detail: less is more — kein KPI-Dashboard"
  - „No forced comments — Triage-Notiz immer optional"
