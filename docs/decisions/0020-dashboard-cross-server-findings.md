## ADR-0020 — Dashboard-Redesign: Cross-Server-Findings-Tabelle, KPI-Sparklines, Entfernung von /findings/search

**Status:** Akzeptiert · **Datum:** 2026-05-16 · **Refined:** ADR-0016 (Dashboard-Default-Detail-Pane), ADR-0017 (Pane-Single-Partial), ADR-0018 (KPI-Card-Pattern, sortierbare Spaltenheader, Bulk-Ack-Toolbar). ADR-0016 wird in den Punkten Quick-Stats-Layout, Filter-Bar und Platzhalter durch diese ADR ersetzt; das Single-Partial-Pattern aus ADR-0017 bleibt voll wirksam. ADR-0018 stellt die wiederverwendbaren Bausteine (`_kpi_card.html`, `sort_header()`-Macro, `bulk_ack_modal()`, `bulkAckIds()`-Alpine-Komponente) bereit, auf denen Block M aufsetzt.

**Visueller Soll-Stand:** Screenshot des neuen Dashboards aus dem Design-Bundle (Cowork-Anhang vom 2026-05-16). Pixel-Referenz ist analog zu Block K der Mockup-Prototyp, der unter `docs/blocks/M-mockup-prototype.html` als statischer HTML-Stand mit demselben Tailwind/DaisyUI-Setup bei Block-M-Start abzulegen ist (Implementer baut Jinja-Templates daneben und vergleicht 1:1).

## Kontext

Aktueller Dashboard-Stand nach Block J/K/L:

- `app/templates/dashboard/_detail_pane.html` rendert in Reihenfolge eine Headline, fünf flache Quick-Stats-Karten (`_quick_stats.html`), eine kompakte Filter-Bar mit Tag/Severity/KEV/Stale/Anwenden-Button (`_filter_bar.html`), eine optionale „Aufmerksamkeit nötig"-Sektion (`_attention.html`) und einen dashed-border-Platzhalter mit dem Text „Hier kommt später ein Widget-Bereich".
- Cross-Server-Findings-Triage existiert ausschließlich über `/findings/search` (`app/views/search.py`, `app/templates/findings/search.html`). Die View kann CVE-/Paket-/Server-Substring-Suche, hat einen CVE-Aggregations-Header (Server-Count + Status-Counts), bietet Pagination und Bulk-Acknowledge.
- KPI-Sparklines existieren nur auf der Server-Detail-View (Block K, `servers/_kpi_card.html`) und basieren auf per-Server-Aggregaten aus `app/services/severity_history.py`.

Das neue Design-Bundle aus dem Cowork-Anhang (Stand 2026-05-16) löst fünf Drift-Bereiche aus:

1. **Platzhalter-Sektion ist obsolet.** Der dashed-border-Block fällt weg; die Stelle wird vom neuen cross-server Findings-Table gefüllt.

2. **Quick-Stats brauchen Sparklines.** Statt `text-2xl font-bold` flachen Zahlen fordert das Design fünf KPI-Kacheln im Block-K-Stil — Eyebrow + großer Wert + 50-Tage-Sparkline darunter. KEV-Kachel mit pulsierendem roten Dot wenn `kev_open > 0`. Cards bleiben klickbar (Filter-Quick-Links).

3. **Alte Filter-Bar und Attention-Sektion werden ersetzt.** Die heutige Filter-Bar mit Anwenden-Button und die „Aufmerksamkeit nötig"-Sektion entfallen ersatzlos; Filter wandern in eine erweiterte Filter-Bar innerhalb der Findings-Section.

4. **Cross-Server-Findings-Tabelle als Triage-Surface.** Das neue Dashboard zeigt eine sortierbare Tabelle aller offenen Findings über alle Server hinweg, mit Server-Spalte, Tag-Pills, KEV-Badge, EPSS-/CVSS-Werten, Severity-Badge, Status-Pill und „Erstmals"-Datum. Diese Triage-Surface gibt es bislang nur auf `/findings/search`.

5. **Fehlende Aggregationen für Sparklines.** `severity_history.py` aggregiert nur per-Server. Für die Dashboard-Sparklines fehlt Flotten-Aggregation (eine Liste von 50 Tageswerten pro Bucket Total/KEV/Critical/High) sowie eine Daily-Stale-Server-Reihe. Letztere ist aus `Scan.received_at` × `Server.expected_scan_interval_h` rekonstruierbar — keine persistente Snapshot-Tabelle nötig.

## Entscheidung

Block M setzt das Dashboard-Redesign nach dieser Spec um:

### Layout `dashboard/_detail_pane.html`

Container: `<div class="max-w-[1600px] mx-auto px-6 py-6 space-y-8">` (analog Block-K-Server-Detail). Drei Sektionen in dieser Reihenfolge:

1. **Header** — Eyebrow `DASHBOARD` + Title `Alle Findings` links; rechts kleiner Counter `{{ visible_servers }} Server sichtbar` plus `gefiltert`-Badge bei aktivem Filter. Kein H1 mehr im alten Stil.
2. **KPI-Card-Sektion** — Grid `grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3` mit fünf Karten. Jede Karte ist eine Instanz des bestehenden `servers/_kpi_card.html`-Partials mit zusätzlichem `link_url`-Parameter, der die Karte als `<a hx-get="…">` rendert. Karten:
   - **Total Open** · `tone="base"` · `link_url="/"` (Reset-Filter) · Sparkline = `kpi_sparklines.total`.
   - **KEV** · `tone="error"` · `kev_indicator=true` · `link_url="/?kev_only=1"` · Sparkline = `kpi_sparklines.kev`.
   - **Critical** · `tone="error"` · `link_url="/?severity=critical"` · Sparkline = `kpi_sparklines.critical`.
   - **High** · `tone="warning"` · `link_url="/?severity=high"` · Sparkline = `kpi_sparklines.high`.
   - **Stale-Server** · `tone="base"` · `link_url="/?stale_only=1"` · Sparkline = `stale_sparkline`.
3. **Findings-Section** — Eyebrow `TRIAGE QUEUE · ALLE SERVER` + Title `Findings` links; Toolbar rechts mit CSV-Dropdown (kein Mode-Toggle — Mode ist nur auf der Server-Detail-View sinnvoll, weil Diff und Group-by-Package per-Server semantisch sind). Filter-Bar als eigene Zeile unter der Section-Header. Tabelle mit Bulk-Select-Checkbox-Spalte ganz links, Server-Spalte, dann analog Block K (CVE/Titel · Paket · EPSS · CVSS · Severity · Status · Erstmals). Bulk-Ack-Button erscheint in der Section-Toolbar, sobald `selected.length > 0`.

### Sparkline-Semantik

Alle Sparklines zeigen **Flotten-Total über 50 Tage, filter-unabhängig**. Tags/Severity/Status/KEV/Stale-Filter wirken **ausschließlich** auf die Findings-Tabelle, nicht auf die KPI-Counter und nicht auf die Sparklines. Begründung: filter-abhängige Sparklines auf einer Card namens „Critical" mit aktivem `?severity=critical` wären tautologisch; stabile Cards mit OPEN-Counter + flotten-weite Sparkline geben dem User ein konsistentes „big picture", die Tabelle macht das Drilldown. Bewusste Inkonsistenz, dafür semantisch stabile Cards.

KPI-Counter zeigen weiterhin **OPEN-Findings** (auch wenn der Filter `status=acknowledged` aktiv ist). Card-Label bleibt statisch (`KEV`, nicht `KEV (ack)`).

### Filter-Bar-Felder

In der Reihenfolge der visuellen Darstellung:

- `q` (Such-Input mit Placeholder `Server, CVE, Paket, Titel…`) — OR-Filter über `Finding.identifier_key`, `Finding.package_name`, `Finding.title`, `Server.name`, case-insensitive substring, max 128 Chars (`strip()` und Cap).
- `tag` (Single-Select-Dropdown `<select name="tag">`, Default-Option `alle Tags`) — Multi-Value-Filter weiter über mehrere `?tag=…`-Params im URL unterstützt (für Power-User), UI bietet Single-Select.
- `severity` (Single-Select, Default `alle`) — Threshold-basiert wie bisher in `DashboardFilter.severity`.
- `status` (Single-Select, Default `offen`, Werte `offen | acknowledged | resolved | alle`) — neu.
- `kev_only` (Checkbox).
- `stale_only` (Checkbox).
- CSV-Button (Dropdown-Trigger rechts, ohne separates Reset).

Reset-Link `Reset` (oder ein gedämpftes `×`-Icon) erscheint links neben dem CSV-Button, **wenn** `filter.is_active`. Klick führt auf `dashboard.index` ohne Query-String und setzt damit alle Felder zurück.

### Filter-Submit-Verhalten (Hybrid)

- `<select>` und `<input type=checkbox>` triggern `hx-get` auf `#findings-section` mit `hx-trigger="change"`, `hx-target="#findings-section"`, `hx-swap="outerHTML"`, `hx-include="closest form"`, `hx-push-url="true"`.
- Such-Input nutzt `hx-trigger="keyup changed delay:400ms"` (Debounce gegen Tipp-Geschwindigkeit).
- Kein `Anwenden`-Button. Kein Auto-Submit beim ersten Render.
- Polling-Wrapper aus Block L (ADR-0019, `hx-trigger="every 10s [document.visibilityState === 'visible']"`) bleibt auf dem äußeren Pane-Container. Filter-Submit aktualisiert die URL, das nächste Poll holt sich denselben URL — kein Race, der Filter wird nicht überschrieben (siehe Risiken unten).

### Limit-Strategie

Hartes Limit **200 Findings** pro Render. Default-Sort ist `sev,desc` mit den §15-Tiebreaks (KEV-zuerst, EPSS desc nulls last, CVSS desc nulls last, Severity-Rank desc, `first_seen_at asc`). Bei Truncation (`total_count > 200`) erscheint **unterhalb der Tabelle** eine eigene Zeile:

```
Anzeige auf 200 begrenzt — {{ total - 200 }} weitere Treffer.
Filter verfeinern oder CSV exportieren.
```

CSV-Export ist **nicht** limitiert (alle Treffer, gefiltert). Keine Pagination im MVP; siehe Re-Open-Trigger.

### Sort-Keys

Sortierbare Spaltenheader via `_macros.html:sort_header()` aus Block K. Cross-Server-spezifisch kommt ein neuer Sort-Key `server` hinzu (sortiert nach `Server.name`). Vollständige Whitelist im neuen `DashboardFilter`:

```
sort: Literal["server","cve","pkg","epss","cvss","sev","status","first_seen"] = "sev"
dir: Literal["asc","desc"] = "desc"
```

`_macros.html:sort_header()` bekommt einen Parameter `route` (oder `target_url_for`), damit dasselbe Macro sowohl gegen `server_detail.show` (Block K) als auch gegen `dashboard.index` (Block M) verlinkt. Falls die heutige Implementierung den Route-Namen hartkodiert, ist das ein einmaliger Refactor — keine ADR-relevante Änderung.

### Bulk-Acknowledge

Reuse des Block-F-Endpoints `POST /api/findings/bulk-acknowledge` mit `dry_run=false` und der `finding_ids`-Flavor (kein `match`-Flavor, weil die Selection cross-server ist und Server-übergreifendes Match-Pattern nicht sinnvoll). Reuse der `bulkAckIds()`-Alpine-Komponente und des `bulk_ack_modal()`-Macros aus `_macros.html`. Server-Spalte als sticky-left Spalte mit Checkbox-Spalte ganz links. Bulk-Ack-Modal-Trefferliste zeigt zusätzlich den Server-Namen pro Finding.

### CSV-Export

Bestehender Endpoint `findings.export_csv` wird erweitert: bei fehlendem `server_id`-Parameter (cross-server-Modus) liefert er eine CSV mit zusätzlicher `Server`-Spalte als erste Spalte. Aktive Filter aus `DashboardFilter` (`q`, `tag`, `severity`, `status`, `kev_only`, `stale_only`, `sort`, `dir`) werden via Query-String übernommen. OWASP-Formula-Injection-Mitigation aus Block F bleibt unverändert; sie wirkt zusätzlich auf die Server-Spalte.

### `/findings/search` ersatzlos entfernen

`app/views/search.py` (350 LoC), `app/templates/findings/search.html` (und etwaige Sub-Templates), Blueprint-Register, Tests unter `tests/views/test_search.py` — alles entfällt. Die globale Suche aus der Sticky-Sidebar-Suchleiste (`/`-Shortcut in `base_app.html`) zeigt jetzt auf `dashboard.index` mit `name="q"`. Kein 301-Redirect, keine Compat-Bridge; `/findings/search` wird 404. Begründung: kein extern dokumentierter Endpoint, kein API-Compat-Bruch. CVE-Aggregations-Header (Server-Count + Status-Counts pro CVE) fällt mit weg; wer eine CVE-Übersicht braucht, sucht `?q=CVE-2024-6387` im Dashboard und sieht alle betroffenen Server in der Tabelle.

### Backend-Pipeline

**Cross-Server-Findings-Query** — neue Funktion in `app/services/findings_query.py`:

```python
def list_findings_cross_server(
    session: Session,
    filt: DashboardFilter,
    *,
    limit: int = 200,
    sort: FindingsCrossSortKey = "sev",
    dir: FindingsSortDir = "desc",
) -> tuple[list[Finding], int]:
    """Liefert (results, total_count). Eager-load Server.tag_links.tag fuer die
    Server-Spalte. total_count ist ein unabhaengiger COUNT(*), damit der
    Truncation-Hinweis exakt ist."""
```

`FindingsCrossSortKey = Literal["server","cve","pkg","epss","cvss","sev","status","first_seen"]` als Erweiterung von `FindingsSortKey`. `_SORT_COLUMNS_CROSS` mappt `"server"` auf `Server.name` (mit JOIN), die anderen Keys teilen das `_SORT_COLUMNS`-Mapping aus Block K. ORM-only, kein `text()`. Tag-Filter wirkt via `ServerTag`-Join (Reuse von `app/views/search.py:_apply_tag_filter` — bei Removal des Search-Moduls wandert die Helper-Funktion in `findings_query.py`).

**Flotten-Daily-Severity-Snapshots** — neue Funktion in `app/services/severity_history.py`:

```python
def daily_severity_counts_fleet(
    session: Session,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> dict[Literal["total","kev","critical","high"], list[int]]:
    """Pro Bucket eine Liste von `days` ints (aeltester Tag zuerst). 'total'
    sind alle OPEN Severities (kein Threshold), 'kev' sind OPEN + is_kev=True,
    'critical'/'high' sind OPEN + severity = CRITICAL/HIGH.

    Definition OPEN-am-Tag-T identisch zu severity_snapshots_for_server:
    - first_seen_at <= end_of_day(T)
    - (acknowledged_at IS NULL OR acknowledged_at > end_of_day(T))
    - (resolved_at IS NULL OR resolved_at > end_of_day(T))."""
```

Implementierung: einmal alle Findings (inkl. retirede Server — Findings auf retireden Servern sind im aktuellen Schema nicht historisiert weg) laden mit `(first_seen_at, acknowledged_at, resolved_at, severity, is_kev)`, Python-side in 50 Buckets pro Output-Bucket einsortieren. Performance-Mini-Bench: 50k Findings über 50 Tage muss < 200 ms bleiben (Re-Open-Trigger unten).

**Daily-Stale-Server-History** — neue Funktion in `app/services/stale_history.py` (eigene Datei, nicht in `stale_detection.py`, weil die Logik mehrtagig walks-back ist und sonst die enge Helper-API des Detection-Services verwischt):

```python
def daily_stale_server_counts(
    session: Session,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> list[int]:
    """Pro Tag T (aeltester zuerst): Anzahl aktiver Server, die am Ende von T
    stale waren. Stale-Definition siehe stale_detection.is_stale.

    Aktiv = retired_at IS NULL OR retired_at > end_of_day(T); analog
    revoked_at. Server, die nach T erstellt wurden, zaehlen nicht.

    Datenquelle: SELECT id, expected_scan_interval_h, created_at, retired_at,
    revoked_at FROM servers; SELECT server_id, MAX(received_at) FROM scans
    WHERE received_at <= end_of_day(T) GROUP BY server_id — aber on-the-fly
    pro Tag waere N*days Queries; statt dessen einmal alle Scans der letzten
    `days + max_interval`-Tage laden, server-wise sortieren, pro Tag walk-back."""
```

Performance-Mini-Bench: 200 Server × 50 Tage muss < 100 ms bleiben (Re-Open-Trigger unten).

**`DashboardFilter` erweitern** — `app/schemas/dashboard_filter.py`:

Neue Felder `q`, `status`, `sort`, `dir`. Alle mit Whitelist-Validierung + Default-Fallback (`from_request()` log.debug + Default bei Ungültigkeit, analog `FindingsViewFilter`). Neue Methode `to_query_string()` für CSV-Link-Bau und Filter-Bar-`hx-include`. Sort-Defaults werden nicht serialisiert (kompakte URL). `is_active` wird erweitert um die neuen Felder.

## Begründung

**Warum Sparklines filter-unabhängig:** Filter-abhängige Sparklines auf einer Card namens „Critical" mit aktivem `?severity=critical`-Filter wären tautologisch (eine Linie die exakt dem Filter folgt). Mitgefilterte Counter + statische Sparkline wären schizophren (zwei verschiedene Aussagen in einer Card). Stabile Cards mit OPEN-Counter und flotten-weiter Sparkline geben dem User ein konsistentes „big picture"; die Tabelle macht das Drilldown. Mit dieser Trennung sind die Cards auch beim Filter-Switching ruhig und nicht „springig" — der User behält den Vergleichswert.

**Warum kein Status im KPI-Counter:** Wenn `status=resolved` aktiv ist und die `KEV`-Card plötzlich auf `0` springt, weiß der User nicht, ob die Flotte sauber ist oder die Card sich an den Filter angepasst hat. Stabile OPEN-Card + dynamische Tabelle ist klarer und folgt dem Pattern aus Block K (HeaderStats sind „immer offen"; Filter wirkt unten).

**Warum hartes Limit 200, keine Pagination:** Pagination mit `page`/`per_page` ist Bookmark-Routine, aber für ein Browse-und-Triage-UI macht Filter-Verfeinerung mehr Sinn als „Next Page". 200 ist genug, dass typische Flotten (10–50 Server × Default-Sort KEV-zuerst) alles Wichtige zeigen; im seltenen Fall sehr großer Flotten zwingt der Truncation-Hinweis zum Filter — was die Triage-Disziplin fördert. CSV bleibt die Eskalations-Ebene für „ich brauche wirklich alles".

**Warum `/findings/search` ersatzlos:** Mit der Entscheidung, die CVE-Aggregation wegfallen zu lassen (Cowork-Frage 5, User-Antwort), ist `/findings/search` ein Duplikat der Dashboard-Tabelle mit weniger Funktionen (kein Bulk, kein cross-server Sort-by-Server). Ein Redirect wäre Boilerplate für einen Endpoint, der nicht extern dokumentiert ist und dessen einziger interner Caller (Sticky-Sidebar-Suchleiste) im selben PR umgestellt wird. Saubere Removal.

**Warum stale-Sparkline rekonstruieren statt persistente Tabelle:** `Scan.received_at` × `Server.expected_scan_interval_h` enthält alle nötigen Daten. Eine separate `server_stale_daily`-Tabelle wäre Speicher-Duplikation ohne Mehrwert und brächte eine neue Migration plus Hintergrund-Job-Logik. Python-side walk-back ist trivial (Server×Day Bucket-Map) und mit Mini-Bench abgesichert. Re-Open-Trigger falls Performance bei sehr großer Flotte leidet.

**Warum Hybrid-Auto-Submit:** Dropdowns/Checkboxes sind diskret und können sofort submittten ohne UX-Friktion (kein Tipp-in-progress). Suche braucht Debounce, sonst feuert jeder Tastendruck einen Request. Kein Anwenden-Button macht die UX modern und deckungsgleich mit uptime-kuma-Vorbild (siehe ARCHITECTURE §1). Bookmark-Fähigkeit ist über `hx-push-url="true"` gegeben.

**Warum gemeinsamer KPI-Card-Partial:** Block K hat `servers/_kpi_card.html` bereits sauber parametrisierbar gebaut (label/value/tone/sparkline/kev_indicator). Block M ergänzt einen `link_url`-Parameter, damit die Card als `<a hx-get="…">` rendert. Keine Code-Duplikation, kein neuer Partial-Tree. Tone-Variante `base` ist bereits als impliziter Default im Macro angelegt — Block M whitelistet sie explizit.

Alternativen verworfen:

- **CVE-Aggregations-Strip im Dashboard erhalten.** Würde 60 % der Search-Logik wiederbringen. User-Entscheidung: weg. Wer eine CVE-Sicht braucht, sucht im Dashboard nach der CVE-ID und sieht alle Server.
- **Cards mit-gefiltert + Sparkline statisch.** Schizophren wie oben begründet.
- **Pagination.** Verzichtbar bei Limit 200 + CSV. Falls sich Limit häufig als zu klein zeigt → ADR-0022.
- **Dashboard-Findings-Section als separater HX-Endpoint** (z.B. `GET /findings/dashboard`). Würde das ADR-0017-Pattern aufweichen (zweite Quelle für Findings-Markup). Stattdessen: Findings-Section ist Teil von `_detail_pane.html`, HTMX swappt das `#findings-section`-Sub-Tree via `hx-select="#findings-section"` aus dem Pane-Response — analog Block K.

## Konsequenzen

**Code:**

- `app/views/search.py` (≈350 LoC) gelöscht; `search_bp`-Register aus `app/__init__.py` raus.
- `app/templates/findings/search.html` und etwaige Sub-Templates gelöscht.
- `app/templates/dashboard/_quick_stats.html` (≈70 LoC), `_filter_bar.html` (≈70 LoC), `_attention.html` (≈40 LoC) gelöscht. Includes in `_detail_pane.html` entsprechend entfernt.
- `app/templates/dashboard/_detail_pane.html` komplett neu geschrieben (Variablen-Vertrag-Docstring vorne aktualisiert).
- Neue Partials: `dashboard/_kpi_cards.html` (Card-Grid), `dashboard/_findings_section.html` (Section + Toolbar + Filter-Bar-Include + Table), `dashboard/_findings_filter_bar.html`.
- `servers/_kpi_card.html` bekommt optionalen `link_url`-Parameter (default `None`, dann normales `<div>`; sonst `<a hx-get="link_url" hx-target="#detail-pane" hx-swap="outerHTML" hx-push-url="true">`).
- `_macros.html:sort_header()` bekommt `route`-Parameter (oder `target_url_for`); Block-K-Aufrufe entsprechend anpassen (`route="server_detail.show"`).
- `app/schemas/dashboard_filter.py` um `q`, `status`, `sort`, `dir` erweitert; `to_query_string()` neu.
- `app/services/findings_query.py` um `list_findings_cross_server()` + `FindingsCrossSortKey` + `_SORT_COLUMNS_CROSS` erweitert; Tag-Filter-Helper aus `search.py` umgezogen.
- `app/services/severity_history.py` um `daily_severity_counts_fleet()` erweitert.
- `app/services/stale_history.py` neu mit `daily_stale_server_counts()`.
- `app/views/dashboard.py:_build_pane_context()` erweitert um `findings_results`, `findings_total`, `kpi_sparklines`, `stale_sparkline`, `view_filter`, `bulk_form`, `csrf_form`. `attention` raus.
- `app/views/findings.py:export_csv` (oder `app/services/csv_export.py`) erweitert um cross-server-Modus mit Server-Spalte. Server-Name-Spalte unterläuft OWASP-Formula-Injection-Mitigation.
- `app/templates/base_app.html`: Sticky-Sidebar-Such-Form (`/`-Shortcut) zeigt jetzt auf `dashboard.index` mit `name="q"`. Etwaige CVE-Auto-Detect-JS-Logik entfällt.
- `app/static/js/*`: keine neue JS-Datei; Filter-Submit ist reines HTMX, Bulk-Ack-Selection nutzt die bestehende `bulkAckIds()`-Alpine-Komponente.

**Tests:**

- `tests/views/test_search.py` und `tests/services/test_search*` gelöscht (≈25 Tests).
- Tests gegen `_attention.html`/`_filter_bar.html`/`_quick_stats.html`-Markup gelöscht oder auf das neue Markup umgeschrieben.
- Neue Service-Tests: `test_findings_query_cross.py` (≈7 Cases), `test_severity_history_fleet.py` (≈4 Cases), `test_stale_history.py` (≈3 Cases + Mini-Bench), `test_csv_export_cross.py` (≈3 Cases).
- Neue View-Tests in `test_dashboard.py` (≈14 Tests, siehe Block-M-Brief Phase D).
- Neue Adversarial-Tests: `test_dashboard_sort_param_injection.py`, `test_dashboard_q_xss.py`, `test_dashboard_q_sql_injection.py`, `test_dashboard_csv_formula_injection_server_name.py`.
- Erwartete Test-Anzahl nach Block M: vor Block L ≈ 797, nach Block L ≈ 720–740, nach Block M ≈ 750–770.

**Spec:**

- `ARCHITECTURE.md §7` Dashboard-Absatz wird umgeschrieben: KPI-Cards mit Sparklines, Findings-Section ohne Attention/Platzhalter/Anwenden-Button, `/findings/search` als entfernt vermerkt.
- `ARCHITECTURE.md §15` Sortier-Defaults: erwähnt zusätzlich `server` als Sort-Key auf der Dashboard-Tabelle.

**ADR-Beziehungen:**

- ADR-0016 wird in den Punkten Quick-Stats-Layout (jetzt KPI-Cards mit Sparklines), Filter-Bar (jetzt in der Findings-Section), und Platzhalter (entfallen) **abgelöst**. Der Dashboard-Default-Detail-Pane-Begriff bleibt; der Inhalt ist anders. ADR-0016 wird auf Status „Superseded by ADR-0020" gesetzt — partielle Supersession, der Rest (Pane-existiert-und-rendert-im-`#detail-pane`-Target) gilt weiter.
- ADR-0017 (Single-Partial-Pattern) bleibt unverändert. Block M baut explizit darauf auf — das neue `_detail_pane.html` ist nach wie vor die einzige Quelle für den Dashboard-Pane-Inhalt.
- ADR-0018 (Block K) bleibt unverändert. Die Wiederverwendung von `_kpi_card.html` und `sort_header()`-Macro durch Block M ist eine Add-On-Konsequenz, kein Spec-Drift.
- ADR-0019 (Block L Polling) bleibt unverändert. Der Polling-Wrapper-Trigger auf `_detail_pane.html` bleibt; Filter-Submit-URL ist konsistent mit dem Polling-Re-Fetch.

**Versionsstand:**

- Umbau läuft als Block M (Datei `docs/blocks/M-dashboard-findings.md`).
- Reviewer-Freigabe + Security-Auditor (für `q`-XSS/SQL-Injection-Surface) + Test-Grün → Tag `v0.6.0`. CHANGELOG-Eintrag mit Hinweis: `/findings/search` ist weg, aber kein extern dokumentierter API-Endpoint, kein Abwärtskompatibilitäts-Problem.

## Re-Open-Trigger

- **Flotten-Daily-Counts > 300 ms** bei realer Flotte: persistente `finding_severity_daily_fleet`-Tabelle (Mat-View oder Daily-Snapshot-Cron). Eigene ADR.
- **Stale-Reconstruction > 200 ms** bei > 200 aktiven Servern: persistente `server_stale_daily`-Tabelle. Eigene ADR.
- **Operator-Feedback fragt nach CVE-Aggregation:** ADR-0021 für Aggregations-Strip oberhalb der Tabelle, wenn `q` eine CVE-ID matcht (Regex `^CVE-\d{4}-\d{4,7}$`). Strip zeigt `server_count`, `open_count`, `ack_count`, `resolved_count` — Wiederverwendung der aus `app/views/search.py:_aggregate_cve` umgezogenen Logik (wird in dieser ADR ersatzlos entfernt; im Re-Open-Fall wandert sie in `findings_query.py`).
- **200-Limit wird häufig getroffen:** Pagination via `page`/`per_page` als ADR-0022. Standard-Werte 50/200, max 500.
- **Filter-Race mit Polling-Wrapper:** sollte durch URL-Konsistenz aufgelöst sein, aber wenn doch beobachtbar (z.B. Filter wird nach 10 s zurückgesetzt) — eigener Bug-Fix-Block ohne ADR-Status (kleinere Implementation-Entscheidung, kein Spec-Drift).
- **CVE-Aggregation als Modal-Drilldown (Cowork-Frage 5, Option 3):** Falls die User-Entscheidung „weglassen" sich als zu rigoros erweist — eigene ADR mit Modal-Trigger auf der CVE-Zelle.
