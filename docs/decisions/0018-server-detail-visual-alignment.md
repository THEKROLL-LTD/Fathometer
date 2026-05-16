# ADR-0018 — Server-Detail-Redesign (Layout, KPI-Sparklines, Trend-Berechnung, sortierbare Findings-Tabelle)

**Status:** Akzeptiert · **Datum:** 2026-05-16 · **Refined:** `ARCHITECTURE.md §7a` (Detail-Pane). §7a beschreibt das Sidebar-Layout und das Server-Listen-Element ausführlich, lässt aber den Server-Detail-Header und die Findings-Triage-Sektion undefiniert — diese ADR füllt die Lücke. Ersetzt die ältere ADR-0018-Fassung („Header + Filter-Bar-Single-Row") vom selben Tag; das war eine Zwischenstand-Spec, bevor das endgültige Design-Bundle vorlag. **Visueller Soll-Stand:** [`docs/blocks/K-mockup-prototype.html`](../blocks/K-mockup-prototype.html) ist die kanonische Pixel-Referenz für die Implementierung — der Implementer baut Jinja-Templates daneben und vergleicht das Resultat 1:1 gegen das Mockup.

## Kontext

Aktuelle Server-Detail-View (`app/templates/servers/detail.html` + `app/templates/servers/_findings_section.html`) versus drittes Design-Bundle (`ui_kits/secscan/ServerDetail.jsx`, `FindingsTable.jsx`, `Charts.jsx` aus `S5lepfeL8MeibyHP1ojRbw`). Die Differenzen sind nicht mehr nur visuell — der Design-Wurf fordert mehrere neue Datenpfade. Insgesamt sieben Drift-Bereiche:

1. **Header-Layout schmal und feature-arm.** `max-w-5xl mx-auto`, Server-Name `text-2xl`, Tag-Pills als Pillen, dreispaltige Meta-Box (Letzter Scan / Trivy-DB / Scan-Interval) als `dl`. Design fordert: voller Pane-Width, Hostname `text-2xl lg:text-3xl font-mono`, Tags als `#hashtag`-Text in Tag-Color, OS-Zeile mit „letzter scan vor 4 h" inline, KI-Bewertung-Button als Primary-Action rechts. Status-Pill bleibt — wird im neuen Layout um `stale` und `db veraltet` erweitert wenn anwendbar.

2. **Fehlende Severity-KPIs als Sparklines.** Heute zeigt der Header gar keine Severity-Übersicht. Design fordert vier KPI-Kacheln (KEV/Critical/High/Medium) je `w-[180px]` mit `text-2xl`-Wert in Severity-Farbe und einer 50-Tage-Mini-Sparkline darunter — die Sparkline zeigt den Verlauf der täglichen OPEN-Snapshots dieser Severity über 50 Tage. KEV-Kachel bekommt zusätzlich einen pulsierenden roten Dot wenn `kev_open > 0`.

3. **Fehlende Tendenz-Anzeige im Header.** Design fordert oben links eine große Findings-Total-Zahl (`text-[64px] font-light tabular-nums`) plus daneben eine textuelle Tendenz: „über 50 tage stabil" / „über 50 tage steigend" / „über 50 tage fallend". Die Tendenz muss im Backend berechnet werden — Feature existiert noch nicht.

4. **Fehlende Heartbeat-Sektion (Detail-Variante).** Block I hat Heartbeat-Bars nur in die Sidebar verlegt. Design fordert eine **deutlich größere** Heartbeat-Bar (`height=56`, breitere Cells, größere Gaps) als eigene Sektion in der Detail-View, mit Legende rechts oben (crit/high/medium/low/clean/kein scan/kev) und einer Vier-Spalten-Meta-Zeile darunter: **Erwarteter Intervall · Letzter Scan · Trivy-DB · KEV-Ereignisse · 50T**. Die Meta-Zeile bringt explizit Scan-Interval und Trivy-DB-Alter zurück (die in der Vor-ADR-Version aus dem Header entfernt waren) und ergänzt eine neue KEV-Ereignis-Zählung über 50 Tage.

5. **Fehlende Verteilungs-Chart-Sektion.** Komplett neu: stacked Bar Chart mit täglichen Severity-Counts über 50 Tage (kumulativ critical/high/medium/low), Range-Toggle (24h/7T/30T/50T), Legende mit Counts und Prozenten, „σ kumulativ"-Hinweis rechts. Der 1J-Toggle aus dem Design wird im MVP nicht implementiert (Re-Open-Trigger unten).

6. **Findings-Filter-Bar entfällt komplett.** Die heutige Filter-Bar mit Status/Klasse/Severity-Min/KEV/Suche/filtern/zuruecksetzen wird ersatzlos entfernt. Replacement-Konzept: sortierbare Spalten-Header in der Tabelle ersetzen Severity/Status/Time-Sort-Filter; die Klasse-Toggle-Filter werden weggelassen (Mode-Toggle ersetzt sie konzeptionell: gruppiert nach Paket gibt OS-vs-Lang-Anteile schon visuell wieder); Suche entfällt (Design-Entscheidung — global gibt es weiterhin die `/search`-View für CVE-/Paket-/Title-Suche über alle Server); die separate „nur KEV"-Checkbox entfällt — KEV-Findings sind via Severity-/CVSS-Sortierung sowieso oben und via KEV-Spalte auf einen Blick erkennbar.

7. **Mode-Toggle und Bulk-Aktion wandern in die Findings-Toolbar.** Die heutigen „Liste / Gruppiert nach Paket / Diff seit letztem Scan"-Tabs als eigene Zeile entfallen. Statt dessen erscheint in der Findings-Header-Zeile rechts: View-Mode-Segment (`flach / gruppiert / diff` als `join btn-xs`), „auswahl ack ·N"-Button (deaktiviert wenn keine Auswahl, sonst öffnet ein Confirm-Modal — Block-F-`BulkActionForm` mit optionalem, **nicht-pflichtigem** Kommentar nach ADR-0006), und „csv exportieren"-Button. Die Tabelle bekommt eine Bulk-Select-Checkbox-Spalte ganz links und eine sortierbare Header-Zeile (CVE/Paket/EPSS/CVSS/Severity/Status/Erstmals).

## Entscheidung

Das Server-Detail wird im Block K nach der Spec unten umgesetzt. Reihenfolge der Sektionen im Detail-Pane (Container `<div class="px-6 py-6 max-w-[1600px] divide-y divide-base-content/10">`):

1. **Header** — Hostname (`font-mono text-2xl lg:text-3xl`) + Status-Pill + OS-Zeile (`os · kernel · arch · letzter scan vor X h`, `font-mono text-xs opacity-60`) + Hashtag-Tags (`<a class="opacity-70 hover:opacity-100" style="color: tag.color">#name</a>`) + KI-Bewertung-Button rechts oben (Block-G-Verhalten unverändert). Status-Pill wird zu einer Pill-Reihe wenn `stale` oder `db veraltet` zutreffen (mehrere `badge-sm`-Pills nebeneinander).

2. **HeaderStats** — Links: `Eyebrow "Findings · offen · gesamt"` + `text-[64px] font-light`-Total + Tendenz-Text rechts daneben in `font-mono text-sm opacity-60 lowercase`. Rechts: vier `KpiCard`-Komponenten je `w-[180px] bg-base-200/40 rounded-box px-4 pt-3 pb-2` mit Label/Indicator/Wert/Sparkline.

3. **Lebenszeichen-Sektion** — Eyebrow + Title + Legende. Großer Heartbeat (`HeartbeatLarge`, height=56) in `rounded-box bg-base-200/40 px-5 py-6`. Darunter `dl grid grid-cols-2 md:grid-cols-4 gap-4`: Erwarteter Intervall / Letzter Scan / Trivy-DB-Alter / KEV-Ereignisse · 50T.

4. **Severity-Trend-Sektion** — Eyebrow + Title + Range-Toggle. `StackedBarChart` (height=220) in `rounded-box bg-base-200/40`. Legende unten mit Counts und Prozenten + „σ kumulativ"-Hinweis.

5. **Triage Queue (FindingsTable)** — Eyebrow „Triage Queue · X Findings" + Title „Findings" + Toolbar rechts (Mode-Segment, auswahl-ack, CSV). Sortierbare Tabelle mit Checkboxes.

### Backend-Pipeline

**Tendenz-Berechnung** (neuer Service `app/services/trend.py` oder Erweiterung von `heartbeat_aggregation.py`):

- Definition: avg(letzte 7 Tage Daily-OPEN-Total) vs. avg(letzte 50 Tage Daily-OPEN-Total).
- Klassifizierung: `(avg_7 - avg_50) / max(avg_50, 1)` — wenn Differenz `>= +5%` → „steigend", `<= -5%` → „fallend", dazwischen → „stabil".
- Rückgabe: Enum `Tendency` mit `STABLE | RISING | FALLING` und ein menschenlesbares Label `"über 50 Tage stabil"` (lowercase im Template, gemäß Design).

**Daily-Severity-Snapshots** (neuer Service `app/services/severity_history.py`):

- Berechnet on-the-fly aus `Finding.first_seen_at` / `Finding.acknowledged_at` / `Finding.resolved_at`. Keine neue persistente Tabelle.
- Definition: ein Finding `f` zählt am Tag `T` als OPEN, wenn
  - `f.first_seen_at <= end_of_day(T)` AND
  - (`f.acknowledged_at IS NULL` OR `f.acknowledged_at > end_of_day(T)`) AND
  - (`f.resolved_at IS NULL` OR `f.resolved_at > end_of_day(T)`).
- Output für Sparklines: `dict[Severity, list[int]]` mit 50 Einträgen pro Severity (kev als Pseudo-Severity, gefiltert auf `is_kev=True`).
- Output für Stacked-Chart: `list[DailySeverityCount]` mit Feldern `day, critical, high, medium, low, kev` (kev = Tageszählung neuer KEV-Events: `Finding.kev_added_at` auf diesen Tag).
- **Bekannte Limitation:** Re-Open-Events (Finding war resolved, wurde wieder geöffnet) sind in den historischen Daten nicht korrekt rekonstruierbar — das Schema führt keinen `reopened_at`-Trail. Für historische Tage vor dem aktuellen Re-Open zeigt die Sparkline das Finding fälschlicherweise als „resolved". Akzeptabel für MVP. Re-Open-Trigger siehe unten.

**KEV-Ereignisse-50T-Counter** — Anzahl distincter Findings, die in den letzten 50 Tagen entweder neu als KEV markiert wurden (`Finding.kev_added_at >= now - 50d`) oder neu erstmalig mit `is_kev=True` ingestet wurden (`first_seen_at >= now - 50d AND is_kev = TRUE`). Eine einzige `SELECT COUNT(DISTINCT id)`-Query.

**Server-Side-Sortierung** in `FindingsViewFilter`:

- Neue Felder `sort: SortKey` (Enum: `cve | pkg | epss | cvss | sev | status | first_seen`) und `dir: SortDir` (Enum: `asc | desc`).
- Default: `sort=sev, dir=desc` (high-severity oben), analog zum Block-E §15-Default.
- URL-Form: `/servers/<id>?sort=cvss&dir=desc`. Klick auf einen Spalten-Header rendert die Tabelle via HTMX neu (`hx-get` auf dieselbe Route mit getauschten Query-Params).
- `app/services/findings_query.py:list_findings()` bekommt entsprechende `order_by`-Klausel.

### Frontend-Komponenten

**Neue Jinja-Macros oder Includes** in `app/templates/_macros.html` oder als eigene Partials:

- `kpi_card(label, value, tone, sparkline_data, kev_indicator=False)` — mit Inline-SVG für die Sparkline (50-Punkt-Linie, area-fill mit 14% Opacity, stroke 2.5px, in `text-error/warning/accent/info`-Farbe).
- `heartbeat_large(cells)` — größere Heartbeat-Variante mit `height=56`, breitere Cells, KEV-Dots oberhalb.
- `stacked_bar_chart(days_data, height=220)` — SVG mit 50 gestapelten Daily-Bars (critical→high→medium→low von unten nach oben).
- `severity_trend_legend(totals)` — Counts + Prozente + σ-Hinweis.
- `sort_header(field, label, current_sort, current_dir)` — Spalten-Header mit Sort-Indikator (↕ / ↑ / ↓) und HTMX-Link auf die View mit getauschten `?sort/?dir`.

**Inline-SVG, keine externen Chart-Libraries.** Sparkline und StackedBar sind genug simpel (50 Datenpunkte, kein Achsen-Rendering, kein Zoom), dass eine ~40-Zeilen-Inline-SVG-Implementation ausreicht. Das hält ADR-0001 (kein Node-Build, kein npm-Dep) ein.

**Klick auf Spalten-Header** triggert HTMX-Swap auf `#findings-section`, nicht eine Volldokument-Navigation. URL bleibt für Bookmarks aktuell via `hx-push-url`.

**Bulk-Ack-Modal** wiederverwendet Block-F-`BulkActionForm` mit `dry_run=true` Default; das Modal zeigt Trefferliste, OPTIONALES Kommentar-Textfeld (ADR-0006 — kein Pflicht), Submit-Button stellt `dry_run=false` und führt die Ack durch. Audit-Trail unverändert.

### CSV-Export

Der CSV-Endpoint (`/findings/export?server_id=X&...`) wird um den `mode`-Parameter erweitert:

- `mode=flach` (Default) → flache CSV aller gefilterten/sortierten Findings (heutiges Verhalten).
- `mode=gruppiert` → identisch zu `flach` plus eine zusätzliche Spalte `Group` mit dem Paket-Namen. Reihenfolge: nach Paket-Gruppe sortiert, dann innerhalb der Gruppe nach aktuellem Sort.
- `mode=diff` → nur Diff-Findings (neue seit letztem Scan + resolved seit letztem Scan), mit Spalte `DiffStatus ∈ {neu, resolved}`.

CSV-Button im UI nutzt `view_filter.to_query_string()` und überschreibt nur `mode` falls nötig — alle anderen Filter/Sort-Werte werden mitgegeben.

### Was explizit nicht im MVP umgesetzt wird

- **1J-Range-Toggle.** Die Demo-Daten haben nur 50 Tage; echte 365-Tage-Aggregation braucht persistente Daily-Snapshot-Tabelle. Re-Open-Trigger unten.
- **Suche-Input in der Findings-Toolbar.** Global existiert weiterhin `/search` für CVE-/Paket-Suche.
- **Klasse-Toggle (OS+Lang / nur OS / nur Lang) in der Findings-Toolbar.** Die Information ist via `gruppiert nach Paket`-Mode visuell zugänglich (Paket-Name verrät Klasse). Falls Operator-Feedback Klasse-Filter explizit fordert → Re-Open.

## Begründung

**Warum komplettes Layout-Redesign statt nur Filter-Bar-Fix.** Der „broken"-Filter-Look war Symptom; das eigentliche Problem ist, dass die Detail-View funktional eine einfache Ack-Liste war, ohne den Operations-Kontext sichtbar zu machen. Das neue Design liefert in einer Ansicht: Bedrohungs-Stand jetzt (KPIs), Trend (Sparklines + Stacked-Chart), Scan-Gesundheit (Heartbeat + Meta), und Triage-Werkzeug (Tabelle) — also alles, was der Operator beim Server-Audit braucht, ohne zwischen Sub-Views zu wechseln.

**Warum on-the-fly statt persistente Daily-Snapshots.** Das Datenmodell trägt mit `first_seen_at` / `acknowledged_at` / `resolved_at` alle Information, um den OPEN-Zustand jedes Tages zu rekonstruieren. Re-Opens sind die einzige Lücke, und im MVP-Single-User-Kontext akzeptabel. Eine Aggregations-Tabelle einzuführen würde Block K erheblich aufblähen (Migration, Backfill-Job, Hook-Logik bei Status-Wechseln, Konsistenz-Checks) — diese Kosten bezahlen wir, wenn echte Performance- oder Korrektheits-Anforderungen auftauchen.

**Warum avg(7T) vs avg(50T) statt Linear-Regression.** Beide Heuristiken sind defensible. avg-Vergleich ist robust gegen einzelne Spitzen, schnell zu erklären (Operator versteht das Konzept ohne Statistik-Kenntnis) und braucht nur zwei SUM-Queries. Linear-Regression wäre mathematisch sauberer, aber die Threshold-Kalibrierung („was ist ein signifikanter Slope?") ist nicht trivial.

**Warum Spalten-Sort statt Filter-Bar.** Die Filter-Bar hatte mehrere semantisch unklare Achsen (Severity-Min vs. Severity-Sort, Status-Filter vs. Status-Sortierung). Spalten-Sort konsolidiert die Sortierachse pro Spalte, ist hypermedia-natürlich (URL-Param), und passt zum „Tabelle ist das Werkzeug"-Konzept der Triage-View.

**Warum kein npm/Build für Charts.** ADR-0001 schließt einen Node-Build aus. Sparkline und Stacked-Bar sind in Inline-SVG mit ~30-60 LOC machbar — vergleichbar zur bestehenden `_heartbeat_bar.html` (50 LOC). Chart.js oder ähnliche Libraries wären Overkill und brächten Bundle-Größe + Build-Komplexität, die wir explizit vermeiden.

## Konsequenzen

**Template-Änderungen.** `app/templates/servers/detail.html` wird komplett umstrukturiert (alle Sektionen ausgenommen Tag-Editor, der bleibt). `app/templates/servers/_findings_section.html` wird komplett umgeschrieben: Filter-Form raus, Sort-Header rein, Mode-Toggle in Toolbar rein, Bulk-Ack-Button rein. Neue Partials: `kpi_card.html`, `heartbeat_large.html`, `stacked_bar_chart.html`, `bulk_ack_modal.html`. Neue Macros in `_macros.html`: `sort_header()`, `tendency_label()`.

**View-Code.** `app/views/server_detail.py:show()` ruft fünf neue Services auf: Tendenz, Daily-Severity-Snapshots, KEV-Events-50T, Heartbeat-Cells (existiert via `heartbeats_for_servers`), Findings-Liste mit Sort. Variablen-Vertrag für `_detail_pane`-Template wird umfangreicher.

**Service-Code.**

- Neu: `app/services/trend.py` mit `compute_tendency(server_id, days_short=7, days_long=50)` → `Tendency`-Enum + Label-String.
- Neu: `app/services/severity_history.py` mit `severity_snapshots_for_server(server_id, days=50)` → `dict[Severity, list[int]]` und `daily_severity_counts_for_server(server_id, days=50)` → `list[DailySeverityCount]`.
- Neu: `count_kev_events(server_id, days=50)` → `int` (kann auch in `severity_history.py` oder eigener Helper).
- Erweitert: `app/services/findings_query.py:list_findings()` bekommt `sort` und `dir`-Parameter.
- Erweitert: `app/schemas/findings_view_filter.py:FindingsViewFilter` bekommt `sort`-/`dir`-Felder + `to_query_string()`-Update.

**Sicherheits-Surface.** Sortier-Parameter (`?sort=cvss&dir=desc`) sind als Whitelist-Enums validiert — keine SQL-Injection-Surface, weil `order_by` immer auf einem fest gemappten Column-Objekt operiert. Daily-Snapshots aggregieren nur Server-eigene Findings — keine Cross-Server-Leak-Surface (Single-User-Auth, ADR-0004).

**Performance.** Pro Server-Detail-View-Render fünf neue Queries: avg-Counts × 2 für Tendenz, OPEN-Snapshot-Aggregation × 50 Tage × 5 Severities (eine einzige Query mit `GROUP BY day, severity`), KEV-Events-Count, Daily-KEV-Aggregation. Plus die bestehenden Heartbeat- und Findings-Queries. Vorab nicht messbar; muss in Block-K-DoD gegen einen Server mit ≥10k Findings geprüft werden. Re-Open-Trigger unten.

**Tests.** Ein Großteil der bestehenden `tests/views/test_server_detail.py`-Suite testet Filter-Bar-Verhalten — diese Tests werden umgeschrieben (Filter-Bar ist weg, Spalten-Sort kommt rein). Neue Test-Areas: Tendenz-Berechnung (Unit-Tests mit fixed Daten-Setups), Daily-Snapshot-Korrektheit, KEV-Event-Counter, Sort-URL-Param-Handling, Mode-Toggle-CSV-Export-Konsistenz.

**Audit-Trail.** Keine Änderung. Bulk-Ack über das neue Modal nutzt denselben `bulk.acknowledged`-Audit-Event wie heute.

**Performance-Bekannte-Limitation.** Daily-Snapshots berechnen pro Server-Detail-View 50 × 5 = 250 Bucket-Counts. Bei einem Server mit ≥100k Findings kann das spürbar werden — Query-Plan-Analyse in Block-K-Reviewer-Phase Pflicht.

**Korrektheits-Bekannte-Limitation.** Re-Open-Events ohne `reopened_at`-Feld → für historische Tage vor einem Re-Open wird das Finding als „resolved" gezählt obwohl es jetzt wieder OPEN ist. Konkrete Auswirkung: leichte Untertreibung der historischen OPEN-Counts in den ersten Tagen nach einem Re-Open. Im Single-User-MVP akzeptabel; Re-Open-Trigger unten.

## Re-Open-Trigger

- **1J-Range gefordert.** Wenn Operator-Feedback längere Trend-Historien fordert: persistente `finding_severity_daily`-Tabelle einführen (server_id, day, severity, count), Cron oder Post-Ingest-Hook schreibt täglich. Backfill-Job für Bestands-Daten.
- **Daily-Snapshot-Performance schmerzt.** Wenn Server-Detail-View bei großen Findings-Beständen messbar langsam wird (>500 ms pro Render): on-the-fly-Aggregation durch persistente Snapshots ersetzen.
- **Re-Open-Korrektheit gefordert.** Wenn historische Genauigkeit über Re-Opens kritisch wird: `finding_status_history`-Tabelle einführen (finding_id, status, changed_at), Tendenz und Daily-Snapshots rechnen darüber.
- **Suche-Input vermisst.** Wenn Operator Server-lokale Suche zurückfordert (statt zur globalen `/search`-View zu wechseln): minimaler Sub-Filter über `?q=`, gegen `cve_id / package_name / title` per `ILIKE`.
- **Klasse-Toggle vermisst.** Falls OS-vs-Lang-Trennung explizit gewünscht: als Tab-Variante neben `flach / gruppiert / diff` oder als Toolbar-Toggle wiederherstellen.
- **Tendenz-Heuristik unscharf.** Wenn avg-7T-vs-avg-50T zu schwankend ist (Wochen-Saisonalität): auf Linear-Regression-Slope umstellen.
- **Severity-Stripe als Card-Sektion fehlt.** Falls die 4-KPI-Kacheln nicht ausreichen und ein zusätzlicher Severity-Strip im Header gefordert wird: KpiCard-Komponente um eine sechste Variante erweitern oder ein eigenes Macro ergänzen.
