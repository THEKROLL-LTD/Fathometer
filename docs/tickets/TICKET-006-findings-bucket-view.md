# TICKET-006 — `/findings`: Cross-Server Bucket-View

**Status:** Offen · **Datum:** 2026-05-24 · **Spec:** [ADR-0037](../decisions/0037-findings-cross-server-bucket-view.md) · **Bezug:** ersetzt ADR-0025 §(5); amendet ADR-0023 §UI-Konsequenzen; nutzt ADR-0028-Junction.
**Komponenten:** `app/services/findings_bucket_query.py` (neu), `app/views/findings.py`, `app/templates/findings/index.html`, neue Partials `app/templates/_partials/{bucket_card,bucket_findings_table,pending_bucket_card}.html`, Tests.
**Umfang:** UI-Refactor + neuer Service-Layer + drei neue Routes. Keine Schema-Migration.

## Problem

`/findings` rendert heute eine flache Cross-Server-Findings-Tabelle (50/Seite, 371 Seiten bei 18.5k OPEN). Risk-Band-Pille der Zeilen ist die `(Group, Server)`-Junction-Bewertung — visuell wirkt es aber als waere sie pro Finding gewaehlt. Operator-Workflow (Pass-2 bewertet Groups, Operator handelt auf Group-Ebene) passt nicht zur flachen Sicht. Inkonsistent mit `/servers/<id>` (dort Application-Group-Cards seit Block P / ADR-0023). Volle Begruendung: ADR-0037 §Kontext.

## Loesung — Bucket-View

Cross-Server Bucket-View nach `(server_id, application_group_id)`. Bucket-Header eager, Bucket-Inhalt lazy via HTMX (20 Findings + Pager). Ein zusaetzlicher Pending-Bucket fuer Findings ohne Group, cross-server mit Server-Spalte in den Zeilen. Default-State (kein Filter) bleibt leer. Volle Beschreibung: ADR-0037 §Entscheidung.

## Etappen-Schnitt

Der Block ist in vier Etappen mit je eigener Commit-Grenze geschnitten. Etappen 1-3 sind nacheinander abhaengig (Service-Tests muessen gruen sein bevor View geschrieben wird; View-Tests bevor Templates angefasst werden). Etappe 4 ist Cleanup nach gruener Etappe 3.

### Etappe 1 — Service-Layer

**Ziel:** Alle DB-Zugriffe fuer die Bucket-View kapseln, Pure-Unit-getestet.

**Datei:** `app/services/findings_bucket_query.py` (neu).

**Public-API:**

```python
@dataclass(frozen=True, slots=True)
class BucketHeader:
    server_id: int
    group_id: int  # 0 markiert den Pending-Sammler (application_group_id IS NULL)
    server_name: str
    group_label: str  # "(ohne Group)" fuer Pending
    risk_band: str    # COALESCE(eval.risk_band, 'pending')
    finding_count: int

def list_buckets(
    sess: Session,
    filt: DashboardFilter,
) -> list[BucketHeader]: ...

def pending_bucket_header(
    sess: Session,
    filt: DashboardFilter,
) -> BucketHeader | None: ...

def list_bucket_findings(
    sess: Session,
    *,
    server_id: int,
    group_id: int,           # 0 fuer Pending-Bucket
    filt: DashboardFilter,
    page: int,
    per_page: int = 20,
) -> tuple[list[Finding], int]: ...

def resolve_bucket_to_finding_ids(
    sess: Session,
    *,
    server_id: int,
    group_id: int,           # 0 fuer Pending-Bucket
    filt: DashboardFilter,
) -> list[int]: ...
```

**Wichtig:**

- Genau **ein** `_apply_bucket_filters(stmt, filt)`-Helper im Modul, der von `list_buckets`, `list_bucket_findings`, `resolve_bucket_to_finding_ids` und `pending_bucket_header` gemeinsam genutzt wird. Keine Filter-Duplikation. Verhindert dass Bucket-Header-Count und Bucket-Body-Inhalt auseinanderlaufen.
- Sub-Pagination nutzt LIMIT/OFFSET + COUNT-Subselect (analog `list_findings_cross_server`). Sortierung Findings-intern: Spec-fix KEV desc, EPSS desc nulls last, CVSS desc nulls last, `first_seen_at` asc.
- `group_id=0` mappt im Service auf `Finding.application_group_id IS NULL` — Convention, nicht im DB-Schema. Validierung der Eingabe-Werte (negativ, Sentinel etc.) im View, nicht im Service.
- LEFT JOIN auf `ApplicationGroupEvaluation` fuer `risk_band` der Junction; `COALESCE(..., 'pending')` fuer Buckets ohne Eval-Row.
- Sortierung der Bucket-Liste: `risk_band_rank DESC` (escalate→noise; pending=Rank 40), Tiebreak `server.name ASC, group.label ASC`. Pending-Bucket-Header kommt als letzter Eintrag in der Liste, unabhaengig vom Rang (Cross-Server-Sammler hat keinen einzelnen `server.name`).
- `q`-Filter wendet ILIKE auf `Finding.identifier_key`, `Finding.package_name`, `Finding.title`, plus `Server.name` (via JOIN). Optional **Performance-Mitigation**: Server-Name-Match vorab als Subquery (`Finding.server_id IN (SELECT id FROM servers WHERE name ILIKE :pattern)`) statt Join-Filter — siehe ADR-0037 §(6) Performance.

**Pure-Unit-Tests** in `tests/services/test_findings_bucket_query.py`:

1. `list_buckets` ohne Filter: Aggregat-SQL hat GROUP BY `(server_id, application_group_id)` + LEFT JOIN auf `ApplicationGroupEvaluation`. SQL-Shape-Check via `str(stmt.compile(...))`.
2. `list_buckets` mit `q`: WHERE enthaelt die 4-Spalten-ILIKE-OR (oder die Server-Subquery, je nach Mitigation-Variante).
3. `list_buckets` mit `risk_band='escalate'`: WHERE enthaelt `risk_band = 'escalate'`.
4. `list_buckets` Sort-Reihenfolge: ORDER BY-Clause hat risk-band-rank desc, server.name asc, group.label asc.
5. Pending-Bucket-Sort: Pending erscheint **immer** als letzter Listen-Eintrag, unabhaengig vom Risk-Band-Rank.
6. `list_bucket_findings(group_id=0)` produziert `application_group_id IS NULL`-WHERE.
7. `list_bucket_findings(group_id=22)` produziert `application_group_id = 22 AND server_id = ?`.
8. `list_bucket_findings`: COUNT-Subselect ignoriert ORDER BY und LIMIT.
9. `resolve_bucket_to_finding_ids`: liefert deterministisch sortierte Integer-Liste.
10. `resolve_bucket_to_finding_ids` mit leerem Bucket: liefert `[]`.
11. `_apply_bucket_filters` wird von allen vier Public-Funktionen aufgerufen (Mock-Spy auf den Helper).
12. Idempotenz-Smoke: zwei Calls mit identischem Filter liefern dasselbe SQL.

**Verbotene Tests:** db_integration / acceptance / integration / bench / bats / `RUN_E2E=1` / Docker-Compose / Browser. Siehe CLAUDE.md §"Test-Konvention". Tests nutzen Mock-Sessions (siehe `tests/services/test_finding_group_inheritance.py` als Vorbild).

**Akzeptanz-Kriterien:**

- `ruff check . && ruff format --check .` clean.
- `mypy --strict app/services/findings_bucket_query.py` keine neuen Errors.
- `pytest tests/services/test_findings_bucket_query.py -v` gruen (Bash-Timeout 60000).
- Default-Suite `pytest` gruen (Bash-Timeout 120000) — Service ist additiv, keine Regressionen.

**Commit-Botschaft-Muster:**
```
feat(findings): Service-Layer fuer Cross-Server Bucket-View (ADR-0037)

- list_buckets() Aggregat (server_id, application_group_id) + Eval-JOIN
- pending_bucket_header() Cross-Server-Sammler ohne Group
- list_bucket_findings() Sub-Pagination 20/Seite
- resolve_bucket_to_finding_ids() fuer Bulk-Ack
- 12 Pure-Unit-Tests, mypy --strict clean

Bezug: ADR-0037 §(1)-(3), TICKET-006 Etappe 1
```

### Etappe 2 — View + Routes

**Ziel:** `findings.index()` auf den Bucket-Loader umbiegen, drei neue Routes anlegen, Bulk-Ack-Endpoint mit Bucket+Finding-Mix.

**Datei:** `app/views/findings.py` (Umbau).

**Aenderungen:**

1. `index()` ruft `list_buckets(sess, filt)` + `pending_bucket_header(sess, filt)` statt `list_findings_cross_server`. Context-Vars: `buckets: list[BucketHeader]`, `pending_bucket: BucketHeader | None`, `total_buckets: int`, `total_findings: int`, plus die bekannten Filter-Felder. **Entfernen:** `page`, `per_page`, `total_pages`, `findings`, `sort`, `dir`-Inputs.
2. **Neuer Route:** `GET /findings/bucket?group_id=&server_id=&page=N&<filter-querystring>` → ruft `list_bucket_findings(...)` + rendert `_partials/bucket_findings_table.html` (Tabelle ohne Server/Group-Spalte + Pager). 400 wenn `group_id`/`server_id` fehlen oder negativ; 404 wenn Bucket leer (Cross-Server-/Cross-Group-ID-Probing-Schutz).
3. **Neuer Route:** `GET /findings/pending?page=N&<filter-querystring>` → ruft `list_bucket_findings(group_id=0, ...)` + rendert `_partials/pending_bucket_findings_table.html` (Tabelle **mit** Server-Spalte + Pager).
4. **Neuer Route:** `POST /findings/bulk/acknowledge` mit Form-Payload `{bucket_selections: JSON, finding_ids: JSON, comment: str}`. Resolve-Logik:
   - Fuer jede Bucket-Selektion: `resolve_bucket_to_finding_ids(sess, server_id, group_id, filt)`. `group_id=0` markiert Pending. Filter wird aus dem mitgegebenen `filter_querystring` rekonstruiert via `DashboardFilter.from_querystring(...)` (existierend? — sonst `from_request`-Form-aequivalent bauen).
   - Mit `finding_ids` mergen, dedupliziert via `set()`.
   - `UPDATE findings SET status='ACKNOWLEDGED', acknowledged_at=now(), acknowledged_by=?` auf der finalen ID-Liste.
   - **Ein** Audit-Event `finding.acknowledged.bulk` mit `metadata={"finding_ids": […], "bucket_count": N, "explicit_count": M, "comment": "…" if has_comment}`. Comment optional (ADR-0006).
   - Bei HTMX-Request: 303-Redirect auf `/findings?{filter-querystring}`. Sonst 302.
5. **Entfernen:** `?flat=1`-Branch in `index()`; Sort-Input-Handling; Pager-Variablen.
6. **CSV-Export-Route bleibt unveraendert** — nutzt weiter `stream_findings_csv_cross_server`.

**Hilfsfunktionen:**

- `_filter_querystring_from_request(args) -> str` — kanonischer Filter-QS fuer die Lazy-HTMX-URLs. Sortiert die Keys (deterministisch), schliesst `page` aus.
- `_validate_bucket_id(raw) -> int` — accepts `0..MAX_INT`, sonst 400.

**Pure-Unit-Tests** in `tests/views/test_findings_bucket_view.py` (neu) plus Erweiterung von `tests/views/test_findings_views.py`:

1. `GET /findings` ohne Filter: leerer Empty-State (kein Bucket-Render).
2. `GET /findings?status=open`: rendert Bucket-Liste (Service via Mock).
3. `GET /findings/bucket?group_id=22&server_id=1`: 200 mit Findings-Tabelle-Fragment.
4. `GET /findings/bucket?group_id=22&server_id=1`: 404 wenn Service leeres Result.
5. `GET /findings/bucket` ohne `group_id`/`server_id`: 400.
6. `GET /findings/pending`: 200 mit Server-Spalte im Render.
7. `POST /findings/bulk/acknowledge` mit Bucket-Selektion: ruft Resolver + UPDATE + Audit-Event mit korrekten Metadata.
8. `POST /findings/bulk/acknowledge` mit Finding-IDs only: UPDATE + Audit.
9. `POST /findings/bulk/acknowledge` Mix Bucket+IDs: dedupliziert; Audit-Event hat finale Liste.
10. `POST /findings/bulk/acknowledge` mit leerer Selektion: 400 oder Flash + 302; kein UPDATE.
11. `POST /findings/bulk/acknowledge` ohne Comment: kein erzwungenes Comment-Feld (ADR-0006).
12. `POST /findings/bulk/acknowledge` HTMX-Request: 303-Redirect mit `HX-Redirect`-Header oder 200+Re-Render.

**Akzeptanz-Kriterien:**

- `ruff`, `mypy --strict app/views/findings.py` clean.
- `pytest tests/views/test_findings_bucket_view.py tests/views/test_findings_views.py -v` gruen (Timeout 60000).
- Default-Suite `pytest` gruen — bestehende `/findings`-Tests werden ggf. angepasst (Sort-Selector entfaellt), nicht ersatzlos geloescht.

**Commit-Botschaft-Muster:**
```
feat(findings): Bucket-View + Bulk-Ack-Endpoint (ADR-0037)

- index() rendert Bucket-Header via list_buckets()
- GET /findings/bucket Lazy-Fragment fuer Bucket-Body (20/Seite)
- GET /findings/pending Cross-Server-Sammler ohne Group
- POST /findings/bulk/acknowledge mit Bucket+Finding-ID-Mix
- Flat-Modus, Outer-Pagination, Sort-Selector entfallen
- 12 View-Tests, mypy --strict clean

Bezug: ADR-0037 §(2)-(4), TICKET-006 Etappe 2
```

### Etappe 3 — Templates + Frontend

**Ziel:** UI komplett umbauen, Bulk-Selektion via Alpine mit Bucket/Finding-Mix.

**Dateien:**

- `app/templates/findings/index.html` (Umbau)
- `app/templates/_partials/bucket_card.html` (neu)
- `app/templates/_partials/bucket_findings_table.html` (neu — Tabelle ohne Server/Group-Spalte + Pager)
- `app/templates/_partials/pending_bucket_card.html` (neu, schlanke Variante mit anderer Body-URL)
- `app/templates/_partials/pending_bucket_findings_table.html` (neu — mit Server-Spalte)
- ggf. `app/static/js/bulk_ack.js` Anpassung fuer Bucket-Selektions-Datentyp

**`bucket_card.html` Render-Vertrag:**

```
{# Variablen: bucket (BucketHeader), filter_qs (str) #}
<details class="bucket-card" data-test="bucket-card-{{ bucket.server_id }}-{{ bucket.group_id }}">
  <summary class="bucket-header">
    <input type="checkbox" data-bucket-server="{{ bucket.server_id }}"
                           data-bucket-group="{{ bucket.group_id }}"
                           data-bucket-filter="{{ filter_qs }}">
    {% with band_value=bucket.risk_band, as_link=false, compact=true, show_count=false %}
      {% include "_partials/risk_band_pill.html" %}
    {% endwith %}
    <a href="{{ url_for('server_detail.show', server_id=bucket.server_id) }}">{{ bucket.server_name }}</a>
    <span class="group-label">{{ bucket.group_label }}</span>
    <span class="count-badge">{{ bucket.finding_count }}</span>
  </summary>
  <div hx-get="{{ url_for('findings.bucket_fragment',
                          group_id=bucket.group_id, server_id=bucket.server_id, page=1) }}{% if filter_qs %}&{{ filter_qs }}{% endif %}"
       hx-trigger="toggle once from:closest details"
       hx-swap="innerHTML">
    <span class="loading loading-spinner loading-xs"></span>
  </div>
</details>
```

(Tailwind/DaisyUI-Klassen wie im Server-Detail-Card-Partial uebernehmen — visuell konsistent.)

**Pending-Card** ist eine Variante mit `hx-get="{{ url_for('findings.pending_fragment', page=1) }}{{ '&'+filter_qs if filter_qs }}"`, Server-Name im Header leer (oder "cross-server"), `group_label="— ohne Group"`.

**`bucket_findings_table.html` Render-Vertrag:**

Spalten: Checkbox · CVE/Titel · Paket · EPSS · CVSS · Status · Severity · `first_seen_at`. Kein Server, keine Group. Pager am Ende mit `hx-get`-Links auf den naechsten Seitenwechsel (gleicher Endpoint, `page=N+1`). Pager kann das bestehende Server-Detail-Pager-Muster wiederverwenden (`_partials/pending_findings_table.html` als Vorbild).

**Pending-Variante** identisch, aber **mit** Server-Spalte (Link auf `/servers/<id>`).

**`findings/index.html` Umbau:**

- Header-Counter wechselt von "X Treffer · Seite N von M" auf "X Gruppen · Y Findings".
- Sort-Hidden-Inputs (`sort`/`dir`) entfallen.
- Tabellen-Section ersetzt durch `for bucket in buckets: include 'bucket_card.html'`. Pending-Card am Ende der Liste.
- Bulk-Toolbar-Block bleibt strukturell, Counter zaehlt jetzt geklickte Checkboxen (Bucket + Finding) ohne Unterscheidung. Form-Action `POST /findings/bulk/acknowledge`. Hidden-Inputs sammeln `bucket_selections[]` und `finding_ids[]`.

**Alpine-Selection-State (in `findings/index.html` oder neuem `bulk_ack_bucket.js`):**

```js
{
  bucketSelections: [],   // [{server_id, group_id, filter}]
  findingIds: [],          // [int]
  get total() { return this.bucketSelections.length + this.findingIds.length; },
  toggleBucket(serverId, groupId, filterQs, checked) {
    const key = `${serverId}|${groupId}`;
    if (checked) {
      this.bucketSelections.push({server_id: serverId, group_id: groupId, filter: filterQs});
    } else {
      this.bucketSelections = this.bucketSelections.filter(b =>
        `${b.server_id}|${b.group_id}` !== key);
    }
  },
  toggleFinding(id, checked) { ... },  // analog
}
```

**Frontend-Tests (Pure-Unit / Template-Smoke):**

`tests/templates/test_bucket_card_render.py` (neu): Macro-Render mit verschiedenen `BucketHeader`-Inputs; pruefe Risk-Pille, Count, HTMX-URL.

`tests/templates/test_findings_bucket_index_render.py` (neu): Index-Template mit Bucket-Liste rendert collapsed `<details>`, Counter, Bulk-Toolbar; ohne Filter zeigt Empty-State.

**Akzeptanz-Kriterien:**

- `ruff` clean (nur Python-Touches).
- Pure-Unit-Tests gruen (Timeout 60000).
- Default-Suite gruen (Timeout 120000).
- Visueller Sanity-Check ist Operator-Pflicht (User-Manual-Test nach Merge der Etappe).

**Commit-Botschaft-Muster:**
```
feat(findings): Bucket-Card-Templates + Frontend-Selection (ADR-0037)

- bucket_card.html mit collapsed <details> + HTMX-Lazy-Slot
- bucket_findings_table.html ohne Server/Group-Spalte + Pager
- pending_bucket_*.html mit Server-Spalte (Cross-Server-Sammler)
- Alpine-State fuer Bucket+Finding-Selection-Mix
- Counter "X Gruppen · Y Findings"
- Sort-Selector, Outer-Pagination, Flat-Mode-UI entfallen

Bezug: ADR-0037 §(2),(4),(5), TICKET-006 Etappe 3
```

### Etappe 4 — Cleanup + Doku

**Ziel:** Restliche Spuren des alten Flat-Modus entfernen, Docs aktualisieren, STATE-Update.

**Aenderungen:**

1. **Code-Cleanup:**
   - `grep -r "_view_list" app/` und nur loeschen wenn `/findings` der einzige Konsument war. Falls Server-Detail noch nutzt → behalten, sonst loeschen.
   - `?flat=1`-Branch in `findings.index()` entfernen (sollte schon mit Etappe 2 erledigt sein — Verifikation).
   - Verwaiste Imports in `app/views/findings.py` (z.B. `stream_findings_csv_cross_server` muss bleiben fuer CSV; `list_findings_cross_server` bleibt fuer den CSV-Pfad).
   - Tests die alten Flat-Modus-Behavior gepruft haben: anpassen oder loeschen, nicht skippen.
2. **ARCHITECTURE.md §7** (Endpoints-Sektion) updaten: `/findings`-Beschreibung auf Bucket-View. Neue Routes `/findings/bucket`, `/findings/pending`, `/findings/bulk/acknowledge` auflisten.
3. **CHANGELOG.md:**
   ```
   ### Findings-Seite
   - `/findings` rendert Cross-Server Bucket-View nach `(Server, ApplicationGroup)` mit collapsed HTMX-Lazy-Cards (ADR-0037).
   - Bulk-Acknowledge unterstuetzt Bucket-Header-Selektion (ganzer Bucket auf einen Klick).
   - Flat-Modus, Outer-Pagination, Sort-Selector entfallen ersatzlos.
   ```
4. **docs/blocks/STATE.md** updaten: TICKET-006 als done markieren, neue ADR-0037 referenzieren.
5. **`docs/decisions/README.md`** Index-Eintrag fuer ADR-0037 hinzufuegen.

**Akzeptanz-Kriterien:**

- `grep -r "?flat=1" app/templates/` leer (oder nur Server-Detail-Templates falls dort noch genutzt).
- `ruff`, `mypy --strict app/`, `pytest` Default-Suite alle gruen.
- CHANGELOG/STATE/README-Eintrag vorhanden.

**Commit-Botschaft-Muster:**
```
chore(findings): Cleanup + Doku-Update (ADR-0037)

- Verwaiste Flat-Mode-Reste entfernt
- ARCHITECTURE.md §7, CHANGELOG.md, STATE.md, ADR-Index aktualisiert
- TICKET-006 abgeschlossen

Bezug: ADR-0037, TICKET-006 Etappe 4
```

## Definition-of-Done (Gesamt)

1. ADR-0037 ist akzeptiert und im Index referenziert.
2. `app/services/findings_bucket_query.py` existiert, Pure-Unit-getestet, mypy --strict clean.
3. `findings.index()` rendert Bucket-Liste; drei neue Routes (`/bucket`, `/pending`, `/bulk/acknowledge`) implementiert und Pure-Unit-getestet.
4. Templates `bucket_card.html`, `bucket_findings_table.html`, `pending_bucket_card.html`, `pending_bucket_findings_table.html` existieren und werden vom Smoke-Test geprueft.
5. Bulk-Toolbar zeigt korrekten Selection-Counter (Bucket+Finding-Mix).
6. Flat-Modus, Outer-Pagination, Sort-Selector entfallen ersatzlos im Code **und** in den Tests.
7. CSV-Export-Endpoint unveraendert funktional (alter Test bleibt gruen).
8. CHANGELOG, STATE, ARCHITECTURE.md §7, ADR-Index aktualisiert.
9. Default-`pytest` gruen, `ruff check`/`format --check` gruen, `mypy --strict app/` keine neuen Errors.
10. **User-Manual-Sanity-Check** (nicht Teil der Code-DoD): `/findings` rendert Buckets, Aufklappen laedt Findings, Bulk-Ack auf Bucket-Header funktioniert.

## NICHT in diesem Ticket

- `pg_trgm`/GIN-Index fuer ILIKE-Performance (Phase 2, eigene ADR sobald Real-Daten den Bedarf zeigen — siehe ADR-0037 §(6)).
- Outer-Pagination auf Bucket-Ebene (eigene ADR sobald Bucket-Anzahl >500).
- Sub-Sortierung im Bucket per User-Wahl (Spec-fix bleibt).
- Aenderungen an `/servers/<id>` (Server-Detail-Findings-Sektion bleibt unangetastet).
- Schema-Migration (nicht noetig).
- Cross-Server-Stale-Detection-Refactor.

## Bezug zur Test-Konvention (CLAUDE.md)

Jeder Implementer-/Test-Writer-Subagent-Aufruf zu diesem Ticket enthaelt woertlich:

> Erlaubte Quality-Gates: ruff, mypy, shellcheck (Linter), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien. Jeder pytest-Bash-Aufruf hat ein timeout-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

## Performance-Profil (Stand 2026-05-24, vor Implementation gemessen)

Siehe ADR-0037 §(6). Alle Default-Pfade unter 50ms, Sub-Pagination unter 20ms, Worst-Case-Substring-Suche bei 365ms. Keine neuen Indizes fuer MVP noetig.
