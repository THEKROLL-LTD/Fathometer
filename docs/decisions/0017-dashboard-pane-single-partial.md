# ADR-0017 — Dashboard-Detail-Pane als ein gemeinsames Partial (kein HX-vs-Full-Page-Drift)

**Status:** Akzeptiert · **Datum:** 2026-05-16 · **Refined:** ADR-0016 (Dashboard-Default-Detail-Pane). ADR-0016 bleibt unverändert; diese ADR legt nur das Template-Pattern fest, mit dem der dort beschriebene Pane konkret gerendert wird.

## Kontext

ADR-0016 hat den Dashboard-Default-Detail-Pane verbindlich definiert: Headline „Dashboard" + Server-Count, fünf KPI-Kacheln (`Total open`, `KEV`, `Critical`, `High`, `Stale-Server`), Filter-Bar, optionale „Aufmerksamkeit nötig"-Sektion, dashed-border-Platzhalter. Diese Spezifikation steht in den UI-Kit-Komponenten (`WelcomePane.jsx`, `QuickStats.jsx`) des Design-Bundles und ist bereits korrekt im Full-Page-Template `app/templates/dashboard/index.html` umgesetzt.

Im Code (`app/views/dashboard.py:177-179`) liegt aber zusätzlich ein zweites Template, das parallel den „Dashboard"-Inhalt rendert: `app/templates/_pane/welcome.html`. Es wird ausschließlich auf dem HX-Request-Pfad benutzt — also immer dann, wenn der User auf den **Dashboard**-Link im Header klickt (HTMX swapt nur `#detail-pane`). Beim Full-Page-Aufruf (Logo-Klick, Direkt-URL, Reload) wird stattdessen das richtige Template gerendert.

Das Partial driftet beobachtbar von ADR-0016 weg:

- Keine `<h1>Dashboard</h1>`-Headline und kein „X Server sichtbar"-Indikator.
- Quick-Stats als kleines Inline-`<dl>` *innerhalb* der Welcome-Card (`text-[10px]`-Labels, `text-base`-Werte), statt der fünf Kacheln mit `bg-base-200`/`bg-error/10`/`bg-warning/10`, `p-4`, `text-2xl font-bold font-mono`.
- CTA-Reihenfolge invertiert: `Server registrieren` als `btn-primary`, im Design ist `Aktuelle KEV-Findings` der Primary.
- Kein Platzhalter-Block.

Der Grund für das parallele Partial steht im Code als Kommentar: während der Block-I-Migration war Block D noch nicht auf ADR-0016 umgezogen, also blieb die Block-D-Vorlage am Full-Page-Pfad stehen, und für den neuen HX-Pfad wurde ein schlankeres „Welcome"-Partial geschrieben. Inzwischen ist auch `dashboard/index.html` auf ADR-0016 umgestellt — die Existenzgrundlage des zweiten Templates ist damit weggefallen.

HTMX selbst macht hier keine Vorgabe. Idiomatisch sind drei Patterns:

1. **Full-Response + selektives Swappen (`hx-select`).** Server liefert immer das vollständige Template; HTMX zieht nur den `#detail-pane`-Knoten heraus. Eine Quelle, aber jede Navigation überträgt den ganzen Body (inkl. Header, Sidebar-Markup).
2. **HX-Branching + gemeinsames Partial.** View prüft `HX-Request`. Bei HX wird nur das Pane-Fragment gerendert, bei Full-Page rendert `dashboard/index.html` und inkludiert dasselbe Pane-Fragment im `{% block detail_pane %}`. Eine Quelle, minimale Response-Größe.
3. **HX-Branching + zwei Templates.** Der aktuelle Zustand. Zwei Quellen, garantierter Drift.

## Entscheidung

Der Dashboard-Detail-Pane wird in **einem** Jinja-Partial gehalten und von beiden Render-Pfaden über `{% include %}` konsumiert (Pattern 2).

- **Neu:** `app/templates/dashboard/_detail_pane.html` ist die einzige Quelle für den Dashboard-Pane-Inhalt (Headline, Quick-Stats, Filter-Bar, Attention-Sektion, Platzhalter).
- **`app/templates/dashboard/index.html`** behält `{% extends "base_app.html" %}` und ruft im `{% block detail_pane %}` ausschließlich `{% include "dashboard/_detail_pane.html" %}` auf.
- **`app/views/dashboard.py`** rendert auf dem HX-Pfad direkt `dashboard/_detail_pane.html` mit denselben Template-Variablen wie der Full-Page-Pfad. Der bisherige `_pane/welcome.html`-Aufruf entfällt.
- **`app/templates/_pane/welcome.html`** wird gelöscht. Wenn andere Views das alte Welcome-Partial benutzen (Audit-Empty-State, 404-Fallback, …), wird der Treffer einzeln auf das passende Ziel umgezogen; das ist nicht Aufgabe dieser ADR.

## Begründung

**Warum Pattern 2 und nicht Pattern 1:** Pattern 1 ist DRY-er auf den ersten Blick (überhaupt kein Branching im View), kostet aber bei jeder Navigation den vollen Body. Die App benutzt `hx-target="#detail-pane"` flächendeckend genau, um diesen Overhead zu vermeiden — das ist eine bewusste Performance-Entscheidung aus Block I. Pattern 1 würde sie unterlaufen.

**Warum überhaupt aufräumen, nicht einfach `_pane/welcome.html` an ADR-0016 angleichen:** Auch wenn das den sichtbaren Bug behebt, bleiben zwei Templates, die in jedem zukünftigen Refactor synchron gehalten werden müssen. Genau dieses Risiko hat den jetzigen Drift erzeugt. Strukturell ausschließen ist billiger als Disziplin.

**Warum das jetzt eine ADR ist, nicht nur ein Bug-Ticket:** Die Wahl zwischen Pattern 1 und 2 ist eine Architektur-Entscheidung, die jedes weitere View-Pane-Paar im Repo betreffen wird (Server-Detail, Settings-Sub-Tabs, Audit, Suche). Es ist sinnvoll, sie einmal festzuschreiben statt jedes Mal neu zu treffen.

## Konsequenzen

- **Template-Inventar:** `_pane/welcome.html` verschwindet. `dashboard/_detail_pane.html` kommt neu hinzu. `dashboard/index.html` wird trivialer.
- **View-Code:** `dashboard.py:_render_pane()`-Helper oder ähnlich, der von beiden Pfaden aufgerufen wird; HX-Branch und Full-Page-Branch teilen sich denselben Context-Dict.
- **Variablen-Vertrag:** Das Pane-Partial dokumentiert oben die erwarteten Variablen verbindlich (analog zu `dashboard/_quick_stats.html`). Jeder Aufrufer muss diesen Vertrag erfüllen — fehlende Variablen werden in Tests detektiert.
- **Tests:** Drei Stellen müssen umgezogen werden (vermutete Treffer aus `Grep`):
  - `tests/views/test_dashboard.py` — Block-D-Asserts auf Header und Quick-Stats sollten weiterhin grün sein, sie zielen bereits auf den vollen Render-Pfad.
  - `tests/views/test_sidebar_layout.py` — der eine Treffer auf `Willkommen bei secscan` muss prüfen ob er den HX-Pfad meint und entsprechend nachgezogen werden.
  - Ein neuer Test, der explizit garantiert dass Full-Page und HX-Response für `/` denselben Pane-Inhalt liefern (gleiches Markup für Header, Quick-Stats, Platzhalter). Das ist der strukturelle Schutz gegen Re-Drift.
- **Pattern für weitere Views:** Server-Detail, Settings-Sub-Tabs und Audit folgen demselben Pattern, sobald jemand sie anfasst. Diese ADR ist normativ für Neu-Implementierungen und für Refactors mit Anlass; ein Big-Bang-Refactor aller bestehenden Views ist nicht gefordert.

## Re-Open-Trigger

- Wenn ein Pane so divergente Vor-Bedingungen zwischen Full-Page und HX-Pfad braucht, dass der gemeinsame Variablen-Vertrag absurd wird (z. B. Pane lebt zwingend in mehreren übergeordneten Layouts mit unterschiedlichen Slots). Dann ist Pattern 1 (`hx-select` auf Full-Response) der ehrlichere Weg für dieses eine Pane.
- Wenn HTMX 3.x oder ein Nachfolger native Server-Side-Includes für `hx-target` einführt, sodass das View-seitige Branching entfällt — dann diese ADR re-evaluieren.
