## ADR-0037 — `/findings`: Cross-Server Bucket-View nach `(Server, ApplicationGroup)`

**Status:** Akzeptiert · **Datum:** 2026-05-24 · **Bezug:** Loest **ADR-0025 §(5)** (dedizierte flache Cross-Server-Findings-Seite) ab und amendet **ADR-0023 §UI-Konsequenzen** sowie **ADR-0028** (Junction-konsistente Vererbung). ADR-0020 (Cross-Server-CSV-Export-Pfad) bleibt unveraendert.

## Kontext

Die heutige `/findings`-Seite (ADR-0025 §(5)) rendert eine flache, paginierte Cross-Server-Tabelle: 50 Findings pro Seite, ein Eintrag pro Finding. Auf einer Production-DB mit ~18.500 OPEN-Findings ueber wenige Server bedeutet das 371 Seiten und eine Spaltenwand, in der dieselbe `(Server, ApplicationGroup)`-Kombination Dutzende Male hintereinander erscheint — jedes Finding traegt seine Server- und Group-Spalte einzeln, obwohl beide Werte fuer alle Findings derselben Junction identisch sind.

Drei Probleme daraus:

1. **Visuelle Redundanz.** Der Operator-Befund 2026-05-24 (Screenshot mit `linux-modules-5.15.0-177-generic`-Wiederholungen auf `rke2-sv-0`/`rke2-sv-1`) zeigt: dieselbe Risk-Band-Pille, dasselbe Group-Label, derselbe Server, zehn Zeilen in Folge. Die Pille ist nicht "per Finding" gewaehlt — sie ist die Junction-Bewertung aus `application_group_evaluations` (ADR-0028), via `inherit_group_risk_to_findings` auf alle Member-Findings denormalisiert. Visuell wirkt es trotzdem als haette jedes Finding eine eigene Bewertung.

2. **Triage-Workflow passt nicht zur Datenstruktur.** Pass-2 bewertet **pro `(Group, Server)`**, nicht pro CVE (ADR-0023 §"Pass 2 — Risk-Evaluation"). Operator-Aktionen ("Patch einspielen", "Mitigation umsetzen", "als noise verwerfen") sind ebenfalls Group-Aktionen — nicht Finding-Aktionen. Eine flache Finding-Tabelle zwingt den Operator, die Group-Zugehoerigkeit visuell zu rekonstruieren bevor er handeln kann.

3. **Inkonsistenz mit `/servers/<id>`.** Die Server-Detail-Seite zeigt Findings seit Block P / ADR-0023 §UI-Konsequenzen als Application-Group-Cards mit collapsed `<details>` und HTMX-Lazy-Load (ADR-0025 §(2)). Der Operator wechselt zwischen Cross-Server-flach und Per-Server-gruppiert — zwei verschiedene mentale Modelle fuer dieselbe Daten-Aggregation.

Operator-Soll: **dieselbe Group-Card-Optik wie auf `/servers/<id>`, nur cross-server**. Die Bucket-Aggregation muss `(Server, ApplicationGroup)`-paarweise sein, nicht nur Group-weise — sonst zeigt eine Card eine Risk-Band-Pille, die nicht zu allen Findings darin passt (dieselbe Group `nginx` kann auf `rke2-sv-0` `escalate` und auf `rke2-sv-1` `noise` sein; das ist exakt das ADR-0028-Composite-Match-Argument).

## Entscheidung

Die `/findings`-Seite wird auf einen **Bucket-View** umgebaut. Ein Bucket ist ein `(server_id, application_group_id)`-Tupel mit mindestens einem Finding, das zum aktuellen Filter passt. Bucket-Header rendern eager, Bucket-Inhalt rendert lazy per HTMX. Ein zusaetzlicher globaler **Pending-Bucket** sammelt alle Findings ohne Group-Zuordnung cross-server.

Der Default-State (kein Filter, keine Suche) bleibt **leer** wie heute (ADR-0025 §(5)). Erst nach Filter-Submit oder Sucheingabe rendert die Seite Bucket-Header.

### (1) Bucket-Aggregation und -Sortierung

Ein Service-Layer-Aufruf liefert alle gefuellten Buckets als Liste von Header-Records: `(server_id, group_id, server_name, group_label, risk_band, finding_count)`. Risk-Band stammt aus `application_group_evaluations` der `(group_id, server_id)`-Junction (LEFT JOIN; fehlende Row → `risk_band='pending'`, analog ADR-0028 §"UI-bei-Eval-Luecke"). Der Pending-Bucket (alle Findings mit `application_group_id IS NULL`) ist eine separate Aggregat-Query.

Sortierung der Bucket-Liste:

1. `risk_band_rank` DESC (escalate → noise; Pending-Buckets ranken als `pending`/Rank 40 — Operator-Soll: nicht versteckt am Ende).
2. `server.name` ASC.
3. `application_group.label` ASC.

Der Pending-Bucket erscheint als letzter Eintrag in der `pending`-Rang-Gruppe (Cross-Server-Sammler hat keinen einzelnen `server.name`-Sort-Schluessel).

Sort ist **fix** — kein User-Selector, kein `?sort=`-URL-Parameter. Begruendung: Sub-Spalten-Sortierung (EPSS, CVSS, Severity, first_seen) sind auf Bucket-Ebene semantisch leer (ein Bucket hat viele Werte). Findings-Sortierung **innerhalb** eines Buckets bleibt Spec-fix wie bisher: KEV desc, EPSS desc nulls last, CVSS desc nulls last, `first_seen_at` asc.

### (2) Bucket-Header (eager) und Bucket-Body (HTMX-Lazy)

Bucket-Header rendert: Risk-Band-Pille, Server-Name (Link auf `/servers/<id>`), Group-Label, Count-Badge, Bulk-Selektions-Checkbox. Der `<details>`-Body ist initial collapsed mit einem leeren HTMX-Slot:

```
<details>
  <summary>…header…</summary>
  <div hx-get="{{ url_for('findings.bucket_fragment',
                          group_id=g.id, server_id=s.id, page=1) }}?{{ filter_qs }}"
       hx-trigger="toggle once from:closest details"
       hx-swap="innerHTML">
    <span class="loading loading-spinner loading-xs"></span>
  </div>
</details>
```

Der Lazy-Endpoint `GET /findings/bucket` rendert eine Findings-Tabelle mit 20 Eintraegen plus Pager. Spalten ohne Server- und Group-Spalte (redundant mit Header); behalten: CVE/Titel, Paket, EPSS, CVSS, Status, Severity, `first_seen_at`. Pager am Bucket-Ende, klassisch nummeriert (`?page=N`).

Der Pending-Bucket nutzt einen analogen Endpoint `GET /findings/pending`, der Body behaelt aber die **Server-Spalte** in den Zeilen (Cross-Server-Sammler — sonst weiss der Operator nicht, woher das Finding kommt).

### (3) Filter-Konsistenz Bucket-Header ↔ Bucket-Body

Bucket-Count und Bucket-Body **muessen** exakt dieselben WHERE-Bedingungen anwenden. Der Lazy-Endpoint bekommt deshalb den vollstaendigen Filter-Querystring der Outer-Page (search `q`, tag, risk_band, application_group, action_required, severity, status, kev_only, stale_only) als URL-Parameter mitgegeben. Service-Layer-Vertrag: ein einziger `_apply_bucket_filters(stmt, filt)`-Helper wird sowohl im Aggregat als auch im Bucket-Body genutzt — kein Copy-Paste der Filter-Logik.

`q`-Filter matcht weiterhin `Finding.identifier_key`, `Finding.package_name`, `Finding.title`, plus `Server.name` (analog `list_findings_cross_server` heute). Einen separaten Server-Filter im UI gibt es bewusst nicht — Server-Drilldown laeuft ueber `q` (z.B. `q='rke2-sv-0'`).

### (4) Bulk-Acknowledge mit Bucket- und Finding-Mix

Die Outer-Page hat zwei Selektions-Klassen:

- **Bucket-Header-Checkbox** → eine Bucket-Selektion `(server_id, group_id, filter_querystring)`. `group_id=0` markiert den Pending-Bucket.
- **Finding-Checkbox** innerhalb eines aufgeklappten Buckets → eine Finding-ID.

Der Selection-Counter in der Toolbar zaehlt **schlicht die Anzahl geklickter Checkboxen** ("7 ausgewaehlt"). Bucket-Selektion und Finding-Selektion sind nicht gegenseitig exklusiv — wenn der User einen Bucket-Header **und** einzelne Findings darin selektiert, ist Doppel-Selektion zugelassen (Server-Submit dedupliziert; Ack ist idempotent).

Neuer Endpoint: `POST /findings/bulk/acknowledge`. Request-Body enthaelt zwei Listen — `bucket_selections: [{group_id, server_id, filter}]` und `finding_ids: [int]`. Server-Logik:

1. Fuer jede Bucket-Selektion: `SELECT Finding.id WHERE server_id=? AND application_group_id=? AND status='open' AND <filter>`. `group_id=0` mappt auf `application_group_id IS NULL`.
2. Mergen mit den expliziten `finding_ids`, dedupliziert.
3. `UPDATE findings SET status='ACKNOWLEDGED', acknowledged_at=now(), acknowledged_by=? WHERE id IN (…)`.
4. **Ein** Audit-Event `finding.acknowledged.bulk` mit `metadata={"finding_ids": […], "bucket_count": N, "explicit_count": M, "comment": "…"}`.

Comment-Feld optional (ADR-0006). Es wird **kein** erzwungener Kommentar-Input gefordert.

### (5) Was entfaellt

- **Flat-Modus.** `_view_list.html` und der `?flat=1`-Fallback der `/findings`-View entfallen ersatzlos. Der bestehende `_is_flat_mode`-Pfad in `app/views/server_detail.py` bleibt unangetastet — diese ADR ersetzt nur die `/findings`-Cross-Server-Sicht, nicht die Server-Detail-Findings-Sektion.
- **Outer-Pagination.** Die Page-Pagination (50/Seite, `?page=N`) auf der `/findings`-Outer-Seite entfaellt. Bucket-Header werden **alle** gerendert, die zum Filter passen. Sub-Pagination greift nur innerhalb eines aufgeklappten Buckets (20/Seite).
- **Sort-Selector.** `?sort=` / `?dir=` werden serverseitig **ignoriert** (kein Redirect). Templates emittieren keine Sort-Header mehr auf `/findings`.
- **Group-Pille in der Findings-Zeile.** Im Bucket-Body redundant mit dem Header — entfaellt.
- **Counter-Header** wechselt von "X Treffer · Seite N von M" auf "X Gruppen · Y Findings".

CSV-Export (`/findings/export.csv`) bleibt **unveraendert flach** — der Export bedient `stream_findings_csv_cross_server` mit dem aktiven Filter, ohne Bucket-Aggregation. Begruendung: CSV-Konsumenten sind externe Tools (Spreadsheet, Pandas), die ohnehin selbst gruppieren.

### (6) Performance-Annahmen (verifiziert 2026-05-24)

Profiling-Lauf gegen Production-DB (~18.500 OPEN-Findings, 75 Buckets, 2 Server, 536 pending):

- Bucket-Aggregat (ohne Filter): 15.7 ms.
- Bucket-Header-Render mit JOINs auf Server/Group/Eval: 44.9 ms.
- Pending-Count: 3.4 ms (Btree-Index deckt `IS NULL` ab).
- Sub-Pagination 20/Seite aus 2.123-Finding-Bucket: 18.0 ms.
- Selektive Filter-Kombi (KEV + escalate + Substring): 0.6 ms (Partial-Index `ix_findings_kev_open` traegt).
- Worst-Case-Substring-Suche (Servername matcht alle Server, 4-Spalten-ILIKE-OR): 365 ms.

Lineare Hochrechnung auf 10 Server / ~90.000 Findings:

| Pfad | Heute (2 Srv) | 10 Srv | Bewertung |
|---|---|---|---|
| Default-Aggregat | 15.7 ms | ~80 ms | ok |
| Bucket-Render | 44.9 ms | ~220 ms | ok |
| Pending-Count | 3.4 ms | ~17 ms | ok |
| Sub-Pagination | 18.0 ms | ~18 ms (konstant) | ok |
| Selektive Filter | 0.6 ms | <5 ms | ok |
| Worst-Case-Suche | 365 ms | **~1.000 ms** | ueber UX-Schwelle |

Keine neuen Indizes fuer MVP noetig. Sobald die DB nennenswert waechst und Worst-Case-Suche regelmaessig auftritt, ist `pg_trgm` mit GIN-Indizes auf `findings.identifier_key`, `findings.package_name`, `findings.title`, `servers.name` der Phase-2-Pfad — eigene ADR sobald Real-Daten den Bedarf zeigen. Sofort-Mitigation im Code (Server-Name-Match als Subquery statt Join-Filter) ist im Plan vorgesehen, hilft aber nicht im pathologischen Fall "Suchbegriff matcht jeden Servername".

## Konsequenzen

### Positiv

- **Operator-Workflow konsistent.** `/findings` und `/servers/<id>` zeigen Findings beide nach Application-Group gruppiert. Mentaler Modellwechsel entfaellt.
- **Junction-Korrektheit sichtbar.** Risk-Band-Pille im Bucket-Header gehoert eindeutig zur `(Group, Server)`-Junction. Kein Eindruck mehr, dass die Pille "pro Finding" gewaehlt waere.
- **Bulk-Aktionen alignen mit der Datenstruktur.** Pass-2 bewertet `(Group, Server)`; Operator akknolwedged `(Group, Server)` per Header-Checkbox in einem Klick.
- **Initial-Render bleibt schnell.** Bucket-Header sind Aggregat — kein Eager-Load der Findings-Notes, kein Per-Bucket-Roundtrip.

### Negativ

- **Outer-Pagination weg.** Bei extrem vielen Buckets (>500) wuerde die Bucket-Liste lang. Aktuelle DB: 75 Buckets — kein Issue. Falls Real-Betrieb das spaeter ueberschreitet: Outer-Pagination auf Bucket-Ebene nachruesten (eigene ADR).
- **Worst-Case-Suche `q` kann langsam werden** (siehe Performance-Tabelle). Akzeptiert fuer MVP; Phase-2-Pfad ueber `pg_trgm` bekannt.
- **URL-Bookmarks mit `?sort=` werden ignoriert.** User-Befund 2026-05-24: keine bestehenden Bookmarks im Einsatz — kein Migrations-Risiko.

### Migrations-Pfad

Keine Schema-Migration noetig. Code-Cleanup:

- Loeschen: `app/templates/servers/_view_list.html` (sofern `/findings` der einzige Konsument ist — `grep` vor `rm` Pflicht), `?flat=1`-Branch in `findings.index()`, `sort_header`-Aufrufe in `findings/index.html`.
- Behalten: `app/services/findings_query.py::list_findings_cross_server` (CSV-Export nutzt es weiter; Tests bleiben gruen).
- Neu: `app/services/findings_bucket_query.py` mit den Bucket-Services (siehe TICKET-006 fuer den Implementierungs-Schnitt).

## Verworfene Alternativen

**(a) Outer-Pagination auf Bucket-Ebene beibehalten.** Verworfen, weil die Bucket-Anzahl bei MVP-Datenmengen (<200) keine Pagination braucht; die zusaetzliche Klick-Last (zwei Pagination-Ebenen — Buckets und Findings im Bucket) macht den Triage-Flow umstaendlicher.

**(b) Sort-Selector auf Bucket-Ebene** (z.B. "nach Count desc"). Verworfen, weil Risk-Band-Rank-Sortierung der einzig operativ relevante Default ist (eskalierende Probleme zuerst). Sub-Sortierungen innerhalb des Buckets bleiben Spec-fix.

**(c) Bucket nur nach `Group` (cross-server) statt `(Server, Group)`.** Verworfen — verletzt das ADR-0028-Junction-Modell. Eine Group hat **kein** einheitliches Risk-Band cross-server; das Header-Pille-Design waere semantisch falsch.

**(d) Bucket-Selektion und Finding-Selektion gegenseitig exklusiv.** Verworfen — komplexere Frontend-Logik (disablen, visuell verstecken) bei marginalem Gewinn. Doppel-Selektion ist idempotent harmlos; Server-Side-Dedup loest es ohne UI-Friktion.

## Bezug zu anderen ADRs

- **ADR-0025 §(5)** wird durch diese ADR **ersetzt**. Die uebrigen ADR-0025-Punkte (Server-Detail-Slim-Down, Application-Group-Card-Lazy-Load, KPI-Cleanup) bleiben gueltig.
- **ADR-0023 §UI-Konsequenzen** wird amendet: Application-Group-Cards sind jetzt auch auf `/findings` das Primaer-Render-Pattern.
- **ADR-0028** (Junction-Tabelle) bleibt die Daten-Source-of-Truth fuer Bucket-Risk-Bands; diese ADR macht die Junction-Semantik in der UI sichtbar.
- **ADR-0006** (keine Pflicht-Kommentare) gilt unveraendert auch fuer den neuen Bulk-Acknowledge-Endpoint.

## Implementierung

Siehe `docs/tickets/TICKET-006-findings-bucket-view.md` fuer den Vier-Etappen-Schnitt (Service-Layer, View/Routes, Templates/Frontend, Cleanup/Doku) und die Definition-of-Done.
