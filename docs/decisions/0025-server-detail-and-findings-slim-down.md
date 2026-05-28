## ADR-0025 — Server-Detail- und Dashboard-Entschlackung, dedizierte Findings-Seite

**Status:** Akzeptiert — Flat-Switch (`?flat=1` + flache Tabelle) **Superseded by ADR-0041** (Block AA, 2026-05-28) · **Datum:** 2026-05-21 · **Bezug:** ADR-0018 (Server-Detail-Redesign), ADR-0020 (Dashboard-Cross-Server-Findings), ADR-0023 (LLM-Risk-Reviewer und Application-Grouping) werden in fünf Punkten **amendet/teilweise abgelöst**. Der visuelle Sockel aus ADR-0018 (Header-Layout, KPI-Sparklines, Trend, sortierbare Spaltenheader, KPI-Card-Pattern) und der KPI-Teil aus ADR-0020 bleiben gültig; die unten benannten Stellen werden präzise überschrieben. ADR-0019 (Polling) bleibt unverändert.

## Kontext

Nach v0.9.6 zeigen Server-Detail und Dashboard zwei wiederkehrende Schwächen, die den Operator-Alltag bremsen:

1. **Server-Detail braucht zu lange beim Öffnen.** Eine Code-Analyse am 2026-05-21 hat drei dominante Kostentreiber identifiziert: (a) Drei Aufrufe von `_load_findings()` pro Render (in `compute_tendency`, `severity_snapshots_for_server`, `daily_severity_counts_for_server`) — drei DB-Roundtrips mit identischer Eingrenzung plus drei separate O(F × 50)-Python-Aggregationen über dieselbe Datenbasis. (b) N+1 in `_load_application_groups_for_server`: eine Findings-Query pro Application-Group (bei 10-15 Groups pro Server entsprechend 10-15 zusätzliche Roundtrips). (c) Eager-Render aller Group-Drill-downs in den `<details>`-Cards inklusive `selectinload(Finding.notes)` und Macro-Aufrufen pro Finding-Zeile, selbst wenn `<details>` collapsed sind. Auf der k3s-Card mit 400 Findings ist das spürbar; in der „Pending grouping"-Sektion mit 272 ungroupierten Findings ebenso.

2. **Dashboard tut zu viel auf einmal.** Heute mischt es KPI-Übersicht (Action-Required-Cards, Risk-Band-Pills, Severity-Strip, KPI-Sparklines) mit einer Cross-Server-Triage-Tabelle inklusive Filter-Bar und CSV-Export. Beide Funktionen sind je für sich sinnvoll, gemeinsam aber: (a) lädt das Dashboard auf jedem Aufruf eine Findings-Query mit Tag-Joins, Severity-Filtern, Stale-Server-Subquery und Aggregat-`COUNT(*)`, auch wenn der User nur den Tagesüberblick sehen will; (b) das obere Drittel mit den Cards bekommt der User selten gelesen, weil die Tabelle darunter sofort den Blick einfängt; (c) bei vielen Servern oder Tags wird der Default-Render träge.

3. **Drei Findings-View-Modi auf Server-Detail werden in der Praxis nicht genutzt.** Operator-Befund 2026-05-21: der `gruppiert`-Modus (Block K, `group_findings_by_package`) und der `diff`-Modus (Block K, `compute_diff`/`DiffSection`) werden seit Einführung von Application-Groups (Block P, ADR-0023) überschattet — die Application-Group-Cards bündeln Findings bereits semantisch, der Diff-Vergleich seit-letztem-Scan ist mit der Risk-Band-Klassifikation operativ obsolet. Beide Modi tragen Code, Templates, Tests, CSV-Export-Varianten und Spec-Sektionen, ohne realen Mehrwert.

4. **Die grüne `active`-Status-Pille rauscht im Header.** Sie steht im `else`-Zweig der Pill-Reihe (nicht revoked, nicht retired) und ist damit auf >95% aller Server-Aufrufe präsent. Operator-Soll: Pills nur sehen, wenn sie *etwas bedeuten* (`scan_stale`, `db_stale`, agent-/trivy-outdated, revoked, retired). Der „läuft normal"-Default braucht keine Pille.

## Entscheidung

Block Q amendet ADR-0018/0020/0023 in fünf Punkten. Es werden **keine** neuen Features eingeführt — der Block ist reiner Umbau und Scope-Reduktion.

### (1) Findings-View-Modi `gruppiert` und `diff` entfallen ersatzlos

`FindingsViewFilter.mode` und das zugehörige URL-Parameter-Feld fallen weg; der einzige verbleibende Modus ist der heutige `list`-Modus (Application-Group-Cards plus Pending-Grouping-Sektion bzw. flache Tabelle bei aktivem Filter oder `?flat=1`). Veraltete `?mode=group`- und `?mode=diff`-URLs werden serverseitig **ignoriert** (kein Redirect, keine Weiterleitung); der `list`-Modus rendert.

Konsequenzen:

- Löschen: `app/services/diff_view.py` (komplett, inklusive `compute_diff`, `DiffSection`). In `app/services/findings_query.py` entfallen `group_findings_by_package()` und `PackageGroup`. In `app/views/server_detail.py` der Mode-Branch in `_render_findings_section`; nur der List-Pfad bleibt.
- Templates: `app/templates/servers/_view_group.html` und `_view_diff.html` werden gelöscht. In `app/templates/servers/_findings_section.html` entfallen das Mode-Segment (`flach/gruppiert/diff`-Buttons) und der `{% if/elif/else %}`-Mode-Switch; der Body rendert den heutigen List-Pfad direkt.
- CSV-Export: in `app/services/csv_export.py` und `app/views/findings.py` entfallen die `csv_mode`-Varianten `gruppiert` und `diff`. Der Export-Dropdown im Template wird auf einen einzelnen Link „CSV exportieren" reduziert; der CSV-Inhalt entspricht dem heutigen `flach`-Mode (gefilterte Liste, alle Spalten).
- Tests: `tests/services/test_diff_view.py` entfällt komplett; in `tests/services/test_findings_query.py` entfallen die `group_findings_by_package`-Tests; in `tests/views/test_server_detail.py` entfallen die Mode-Toggle- und Group-/Diff-Render-Tests.
- Spec: ARCHITECTURE.md §7 wird in der Server-Detail-Sektion auf den einen verbleibenden Modus reduziert (siehe §7-Edit unten). ADR-0018 bleibt formal akzeptiert, wird aber durch diese ADR in den Modi-Aufzählungen und im CSV-Export-Verhalten überschrieben.

### (2) Application-Group-Card-Findings: HTMX-Lazy-Load

Application-Group-Cards (`app/templates/_partials/application_group_card.html`) sind **default collapsed** — die heutige `_open_default`-Logik (escalate/act/mitigate/pending/unknown automatisch `<details open>`) entfällt. Stattdessen rendern alle Cards mit collapsed `<details>` und einem leeren Body-Slot, der per HTMX nachgeladen wird, sobald der Operator das `<summary>` öffnet.

Neuer Endpoint: `GET /servers/<int:server_id>/groups/<int:group_id>/findings` → rendert `app/templates/_partials/group_findings_table.html` als Fragment. Auth via `@login_required`. 404 wenn die Group keine OPEN-Findings auf diesem Server hat (Cross-Server-Group-ID-Schutz).

Initial-Render-Inventar (`_load_application_groups_for_server`) wird reduziert auf:

- Eine einzige Aggregat-Query: `SELECT application_group_id, COUNT(*) FROM finding WHERE server_id=? AND status='open' AND application_group_id IS NOT NULL GROUP BY application_group_id` — liefert die Group-IDs plus Counter-Werte für die Card-Header.
- Eine Batch-Query für `ApplicationGroup`-Metadaten (Label, Explanation, Risk-Band, Risk-Band-Reason, Worst-Finding-ID, Action-Type, Group-Kind).
- Eine Batch-Query für die Worst-Finding-Objekte (wie heute).

Die Per-Group-Findings-Query und das Eager-Rendering der `<details>`-Tabellenkörper entfallen am Initial-Render. Sortierung der Findings innerhalb einer Group ist Spec-fix (KEV desc, EPSS desc nulls last, CVSS desc nulls last, Severity-Rank desc, `first_seen_at` asc); der Endpoint braucht keine URL-Parameter.

HTMX-Pattern auf der Card:

```
<details>
  <summary>Show all {{ count }} findings</summary>
  <div hx-get="{{ url_for('server_detail.group_findings_fragment',
                          server_id=server.id, group_id=group.id) }}"
       hx-trigger="toggle once from:closest details"
       hx-swap="innerHTML">
    <span class="loading loading-spinner loading-xs"></span>
  </div>
</details>
```

Bereits geladene Group-Tabellen bleiben im DOM (Zuklappen versteckt, kein Re-Fetch). Anker-Sprünge auf `#finding-<id>` (z.B. der Worst-Finding-Link im Card-Header) bleiben funktional, **nachdem** der User die Card geöffnet hat — initial ist das Ziel-Element nicht im DOM. Der Worst-Finding-Link wird beibehalten, ein automatisches `<details open>`-Triggern bei Anchor-Navigation ist **nicht** im Scope (Operator klickt erst auf „Show all …", dann auf die Worst-Finding-Zeile).

Action-Needed-Sektion (`_action_needed_section.html`, Block-P-v0.9.3) konsumiert weiterhin Group-Label, Worst-Finding-Identifier und Risk-Band-Reason — diese drei Felder liegen alle auf den Group/Worst-Finding-Metadaten und brauchen keine Findings-Liste. Sektion bleibt unverändert.

### (3) Pending-Grouping-Sektion: HTMX-Lazy-Load pro Risk-Band-Bucket

Die „Pending grouping"-Sektion am Ende der Server-Detail-Findings-Section zeigt heute alle Findings ohne `application_group_id` (`_load_ungrouped_findings_for_server`, Limit 500) eager in einer `_view_list.html`-Tabelle, die intern pro Risk-Band ein `<tbody>` als `<details>`-Rollup rendert. Diese Sektion wird analog zu (2) auf Lazy-Load umgestellt.

Initial-Render-Inventar wird auf eine Aggregat-Query reduziert: `SELECT risk_band, COUNT(*) FROM finding WHERE server_id=? AND status='open' AND application_group_id IS NULL GROUP BY risk_band` → liefert pro Risk-Band den Count. Pro Band wird ein collapsed `<details>`-Rollup mit Pill und Count gerendert (kein Findings-Inhalt).

Neuer Endpoint: `GET /servers/<int:server_id>/findings/pending?risk_band=<band>` → rendert das `<tbody>`-Fragment mit den Findings des Buckets, sortiert nach §15-Default. Auth via `@login_required`. 400 wenn `risk_band` nicht in der Whitelist (`escalate`/`act`/`mitigate`/`pending`/`unknown`/`monitor`/`noise`). 404 wenn der Server keine OPEN-Ungrouped-Findings im angefragten Band hat.

`_load_ungrouped_findings_for_server()` entfällt als View-Helper. Eine schmale Variante zieht in den neuen Endpoint um (gleicher SQL-Filter, aber zusätzlich `risk_band == band`).

### (4) `active`-Status-Pille im Server-Detail-Header entfällt

In `app/templates/servers/detail.html` wird die Pill-Reihe von `{% if revoked %}revoked{% elif retired %}retired{% else %}active{% endif %}` auf `{% if revoked %}revoked{% elif retired %}retired{% endif %}` verkürzt. Der `else`-Zweig mit der grünen `active`-Badge fällt ersatzlos. Alle anderen Pills (`scan_stale`, `db_stale`, `agent_outdated`, `trivy_outdated`, `trivy_db_stale`, `action_required`) bleiben unverändert.

Geltungsbereich: **nur der Server-Detail-Header**. Die `active`-Badge in `app/templates/settings/servers.html` (CRUD-Liste der registrierten Server) bleibt erhalten — anderer Kontext, dort hilft der explizite Marker dem Operator zur Unterscheidung von revoked/retired-Einträgen.

Test-Wartung: bestehende Assertions in `tests/views/test_server_detail*.py`, die im Default-Fall die `active`-Badge erwarten, werden umgekehrt — Default-Fall enthält **keine** Status-Pille (außer `scan_stale` etc., falls die Fixture das auslöst).

### (5) Cross-Server-Findings-Tabelle wandert auf dedizierte Seite `/findings`

Die heutige Dashboard-Findings-Section (`app/templates/dashboard/_findings_section.html`) inklusive Filter-Bar, Tabelle, CSV-Export und Bulk-Ack-Toolbar zieht vollständig auf eine neue Route `/findings` um. Das Dashboard verliert diese Sektion ersatzlos; es behält KPI-Cards, Risk-Band-Pills, Severity-Strip und die Sidebar-Polling-Mechanik. Damit fällt die Findings-Query inklusive Tag-Join, Stale-Server-Subquery und `COUNT(*)`-Aggregat aus dem Dashboard-Render heraus — das Dashboard wird zur reinen Übersicht.

#### Header-Navigation

In `base_app.html` (bzw. dem geteilten Header-Partial) erscheint ein zweiter Nav-Eintrag **`Findings`** neben **`Dashboard`**. Active-Highlight via `request.endpoint`-Check (`dashboard.index` vs. `findings.index`). Die Suche-Pseudoroute aus ADR-0020 (`Suche → Dashboard mit ?q=...`) wird auf den neuen `/findings`-Endpoint umgebogen.

#### Default-State: leere Tabelle, expliziter Submit

Die neue `/findings`-Seite rendert **ohne aktivierten Filter** keine einzige Findings-Zeile. Statt der Tabelle erscheint ein Empty-State-Block:

> Filter setzen oder suchen — die Tabelle bleibt sonst leer.
> Insgesamt **{{ total_findings }}** Findings über **{{ visible_servers }}** Server.

`total_findings` ist ein billiger `SELECT COUNT(*) FROM finding WHERE status='open'`; `visible_servers` zählt aktive (nicht revoked/retired) Server.

Der Filter-Submit ist **explizit** — die Filter-Bar wird zu einem `<form method="get">` mit Submit-Button **„Anwenden"**. Die heutige Auto-Submit-Logik aus ADR-0020 (`hx-trigger="change"` auf Dropdowns/Checkboxen, `hx-trigger="keyup changed delay:400ms"` auf Such-Input) wird **vollständig entfernt** — keine HTMX-Triggers auf den Filterfeldern. Enter im Such-Input submittet das Formular (Browser-Default). URL ändert sich erst nach Submit.

Damit ist die Empty-State-Logik wasserdicht: ohne Submit kein Query-String, ohne Query-String kein Findings-Render. Der `total_findings`-Counter im Empty-State-Block bleibt der einzige DB-Touch im Default-Render.

Filter-Aktiv-Definition (für Render-Entscheidung):

- `q` nicht leer, ODER
- `tag` gesetzt (mindestens ein Wert), ODER
- `severity` gesetzt (nicht „alle"), ODER
- `status` gesetzt und nicht der Default `offen` (UI: User hat explizit gewählt), ODER
- `risk_band` gesetzt, ODER
- `action_required` gesetzt, ODER
- `application_group` gesetzt, ODER
- `kev_only=1` ODER `stale_only=1`.

Wenn keine der obigen Bedingungen erfüllt ist und kein `?page=N` mitgegeben wurde, zeigt die Seite den Empty-State. Pagination-Param `page` alleine löst keinen Render aus.

#### Pagination — klassisch nummeriert

Page-Based mit fixer Seitengröße **50 Findings/Seite**. URL-Param `?page=N` (1-basiert, Default 1). Backend: `list_findings_cross_server()` erhält einen `offset`-Parameter (`offset = (page-1) * 50`); der heutige `limit`-Parameter wird auf 50 festgenagelt; `total_count` wird wie heute exakt aus dem gefilterten Subselect berechnet.

UI: am Tabellen-Ende eine schlichte Pager-Zeile:

```
« vorherige   ·   Seite {{ page }} von {{ total_pages }}   ·   nächste »
```

`«`/`»` als deaktivierte Buttons wenn an den Rändern. Total-Pages = `ceil(total_count / 50)`. Bei `total_count == 0`: kein Pager, stattdessen „Kein Treffer für diesen Filter."-Hinweis.

Bewusst **kein** HTMX-Endless-Scroll (`hx-trigger="revealed"`): URL bleibt sauber bookmarkbar, Browser-Back funktioniert, CSV-Export-Scope ist eindeutig.

#### CSV-Export

CSV-Export-Button bleibt auf der Findings-Seite (rechts in der Filter-Section-Toolbar). Export-Scope = **aktive Filter, alle Seiten**. Pagination wird im Export **nicht** angewandt — der Operator bekommt den vollen gefilterten Satz. Limitierung wie heute aus `list_findings_cross_server` (`limit` für die Tabelle wirkt nicht auf den Export-Endpoint).

#### Sortierung

Default-Sort bleibt `risk` / `desc` wie heute. Spaltenheader-Sortierung via `_SORT_COLUMNS_CROSS` und `sort_header()`-Macro unverändert. `?sort=` und `?dir=` werden auch ohne sonstigen Filter aktiv (Power-User-Bookmark: „zeig mir alle nach EPSS sortiert" mit `?sort=epss&dir=desc` rendert die Tabelle — diese Lesart kollidiert mit „Default leer" und wird **bewusst** so entschieden: explizite Sort-Wahl ist ein User-Intent-Signal vergleichbar zum Filter-Submit). Alternativ: auch Sort-Param ignoriert ohne Filter? **Entscheidung:** Sort-Param ohne Filter rendert die Tabelle (Sort allein zählt als „User will Findings sehen"). Re-Open-Trigger wenn das in der Praxis stört.

#### Dashboard-Restbestand

Was nach dem Auszug auf dem Dashboard bleibt:

- KPI-Cards Tier 1 (Action-Required `Action needed` / `Safe`).
- Risk-Band-Pills Tier 2 (Escalate · Act · Mitigate · Pending · Unknown · Monitor · Noise).
- Severity-Strip Tier 3 (Critical · High · Medium · Low).
- Sidebar mit Server-Liste und Heartbeat-Bars (unverändert; globale Navigation).
- Polling-Wrapper aus ADR-0019 auf den Dashboard-Pane-Container (`hx-trigger="every 10s ..."`) bleibt; der gepollte Inhalt ist jetzt aber kleiner.

Was wegfällt: die komplette Findings-Section (Filter-Bar, Tabelle, CSV-Export, Bulk-Ack-Toolbar, Truncation-Hinweis). Die KPI-Klick-Links auf den Cards (`?kev_only=1`, `?severity=critical`, `?action_required=yes` etc.) zeigen jetzt auf `/findings?...` statt auf das eigene Dashboard. Reset-Link entfällt am Dashboard (es gibt nichts mehr zurückzusetzen).

#### Backend-Konsequenzen

- Neue View `app/views/findings.py` bekommt einen `GET /findings`-HTML-Handler (der Modul-Name existiert bereits für den CSV-Export-Endpoint).
- `app/views/dashboard.py` ruft `list_findings_cross_server` und die Filter-Verarbeitung nicht mehr auf. Bleibt: KPI-Aggregation, Risk-Band-Aggregation, Severity-Counter, Flotten-Sparklines.
- `app/schemas/dashboard_filter.py` (`DashboardFilter`) zieht semantisch in den Findings-View um. **Empfehlung:** Datei umbenennen auf `app/schemas/findings_list_filter.py`, Klasse auf `FindingsListFilter`. Re-Export-Stub in der alten Datei wird **nicht** geliefert (kein Drift-Risiko, Block ist eine geschlossene Umbau-Einheit). Implementierungs-Detail: kann auch erst im Folge-Block kommen, dann zuerst nur die Verschiebung der Funktionalität.
- `list_findings_cross_server(limit, offset)` — neuer `offset`-Parameter; bestehende `limit`-Semantik bleibt (Default 50 statt der heutigen 200, weil Pagination jetzt aktiv). Die alte Truncation-Logik (Hinweis-Zeile „Anzeige auf 200 begrenzt") entfällt — sie wird durch Pagination ersetzt.

## Konsequenzen

**Performance-Erwartung Server-Detail** (per Code-Analyse, vor Bench): Initial-Render reduziert sich um die Per-Group-Findings-Queries (heute 1 pro Group, Ziel 0), das Eager-Render der Group-Drill-down-Tabellen, das Eager-Render der `_view_list.html`-Tabelle in der Pending-Grouping-Sektion. Die dreifach-redundante `_load_findings()`-Aufrufkette in `compute_tendency`/`severity_snapshots_for_server`/`daily_severity_counts_for_server` ist **nicht** Teil dieser ADR — gehört in einen separaten Performance-Folge-Block (Re-Open-Trigger unten).

**Performance-Erwartung Dashboard:** der Findings-Query-Block entfällt komplett aus dem Dashboard-Render. Das Dashboard bleibt aber durch die KPI-Aggregationen und die Flotten-Sparkline weiterhin nicht-trivial; der Polling-Pane lädt jetzt eine kleinere HTML-Nutzlast.

**Performance-Erwartung Findings-Seite:** Default-Render = ein `COUNT(*)` plus Filter-Form-Skeleton. Erst nach Submit feuert `list_findings_cross_server` mit `LIMIT 50 OFFSET …` plus `COUNT(*)` für den Pager.

**Breaking Changes für Operator-URLs:**

- Bestehende `/servers/<id>?mode=group`- und `?mode=diff`-Bookmarks zeigen jetzt den `list`-Modus (still ignoriert).
- Bestehende `/?q=…&severity=…`-Dashboard-Filter-URLs rendern auf dem neuen Dashboard nichts Filterbares — die Filter werden ignoriert, der User landet auf der Übersicht ohne Tabelle. Falls häufig genutzt, ein UI-Hinweis im Dashboard („Findings → /findings") kann später nachgereicht werden; nicht in dieser ADR.
- HTMX-Polling-Konsumenten im Frontend, die auf `#findings-section` swappen, müssen auf der Dashboard-Seite ihre Trigger verlieren (es gibt das Element nicht mehr).

**Tests/Migrations:** kein DB-Schema-Touch, keine Alembic-Migration. Alle Änderungen sind Code/Template/Doku.

**Risiken und Mitigation:**

- *Lazy-Load via `<details>`-toggle*: HTMX-`hx-trigger="toggle"` ist solide unterstützt, aber wenn ein Browser-Glitch das Event verschluckt, bleibt die Card leer. Mitigation: `hx-trigger="toggle once from:closest details, click once from:closest summary"` als Fallback. Test mit Selenium oder per Manual-Smoke beim Implementer.
- *Cross-Server-Group-ID*: der neue Endpoint nimmt `server_id` und `group_id` aus der URL. Ein böswilliger oder verirrter Client könnte eine fremde Group-ID anfragen. Mitigation: WHERE-Klausel `Finding.server_id == server_id AND Finding.application_group_id == group_id AND Finding.status == 'open'` — leere Treffer → 404. Group-Metadaten (Label etc.) werden im Endpoint nicht verändert, nur Findings ausgelesen.
- *Pagination-Race*: zwischen zwei `?page=`-Klicks kann sich `total_count` ändern (neuer Scan-Ingest). Operator-Realität: bei Eintreffen frischer Findings springen Page-Inhalte minimal. Akzeptabel, kein Hotfix nötig — Pager zeigt immer `total_pages` auf Basis des aktuellen Requests.
- *CSV-Export-Konsistenz*: Export-Scope = aktiver Filter, alle Seiten, ungewindowed. Bei sehr großen Filtern wird der Export entsprechend groß. Mitigation: keine — Operator hat um den Filter gebeten. Limitierung wird via Re-Open-Trigger nachgeladen falls Operator-Beobachtung das fordert.

## Re-Open-Trigger

- *Triple-Findings-Query auf Server-Detail*: separater Performance-Block. Konsolidierung der drei `_load_findings()`-Aufrufe in `compute_tendency` + `severity_snapshots_for_server` + `daily_severity_counts_for_server` auf einen Aggregations-Helper (analog `daily_severity_counts_fleet` mit Differenz-Array). Sinnvoll als Block R nach Block Q.
- *Endless-Scroll auf Findings*: falls Operator beim Sichten großer Filter-Treffer öfter klicken muss als angenehm. Aufrüstung via `hx-trigger="revealed"` auf der letzten Pager-Zeile mit Append-Pattern; bleibt mit Page-Based-URL kompatibel.
- *Sort-Param ohne Filter rendert*: wenn Operator diese Lesart unintuitiv findet (Empty-State vs. „User wollte sortieren"), Default ändern auf „Sort ohne Filter = Empty-State".
- *Findings-Bulk-Ack über Application-Group-Grenzen*: wenn Lazy-Load die Bulk-Selection einschränkt (Checkboxen nur in expandierten Cards verfügbar), Pattern auf „Header-Bulk-Ack der ganzen Group" erweitern. Aktuell out-of-scope.
- *Spec-Bereinigung*: ADR-0018/0020 enthalten an mehreren Stellen Verweise auf die gestrichenen Modi/Sektionen. Nach Block-Q-Merge ein Doku-PR der die alten ADRs auf `Teilweise abgelöst durch ADR-0025` setzt; nicht Teil dieses Blocks.

## Querverweise

- ADR-0018 — Server-Detail-Visual-Alignment (Modi-Aufzählung und Header-Pill-Reihe werden überschrieben).
- ADR-0020 — Dashboard-Cross-Server-Findings (Findings-Section wandert auf separate Seite).
- ADR-0023 — LLM-Risk-Reviewer und Application-Grouping (Group-Card-Render bleibt strukturell, Default-Expand-Logik entfällt).
- `docs/blocks/Q-slim-down.md` — Implementierungs-Tasks plus maschinell prüfbare Definition of Done.
