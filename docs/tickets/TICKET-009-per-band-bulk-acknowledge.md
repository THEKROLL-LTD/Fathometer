# TICKET-009 — Server-Detail: Per-Band „Acknowledge all" (server-scoped, ohne 50er-Limit)

**Status:** Offen · **Datum:** 2026-06-04 · **Spec:** [ADR-0044](../decisions/0044-server-scoped-bulk-ack-per-band.md) · **Bezug:** loest ADR-0022 §Bulk-Ack-„noise"-Workflow und ADR-0039 §2 (`fragments/noise`) ab; ADR-0006 (Kommentar optional) gilt; ADR-0037 (`/findings`-Bucket-Bulk-Ack) unberuehrt.
**Komponenten:** `app/schemas/bulk_request.py`, `app/api/bulk.py`, `app/views/server_detail.py`, `app/templates/_partials/risk_band_section.html`, neues `app/templates/_partials/bulk_ack_band_modal.html`, neues `app/static/js/bulk_ack_band.js`, `frontend/src/css/components/server-detail.css`, Loeschungen (Noise-Pfad), Tests.
**Umfang:** API-Flavor + UI-Umbau + Cleanup. Keine Schema-Migration, kein DB-Touch.

## Problem

1. „Acknowledge all noise on this host (N)" ackt maximal 50 Findings: die IDs werden via `noise_fragment` (`.limit(50)`) ins Template eingebettet und als Flavor-A-Liste gepostet. Bei 2.816 noise-Findings zeigt der Button 2816, der dry_run-Preview 50, Apply ackt 50.
2. Nur `noise` ist bulk-abhakbar. Operator-Soll: jedes Band **ausser `pending`** pro Server in einem Schritt abhakbar (Screenshot-Spec 2026-06-04: Hover-Checkbox „ACKNOWLEDGE ALL" am Band-Header).

Volle Begruendung und Sicherheits-Abwaegung: ADR-0044 §Kontext, §(5).

## Loesung

Neuer Request-Flavor C `server_scope: {server_id, risk_band}` auf `POST /api/findings/bulk-acknowledge` — der Server resolved die Findings selbst, keine ID-Liste im Client-Roundtrip. Band-Whitelist `escalate/act/mitigate/monitor/noise` im Pydantic-`Literal` (pending → 422). UI: Hover-Control pro Band-Sektion + ein generisches Modal (max. 5 Beispiele aus der dry_run-Response, optionale Notiz, Pflicht-Confirm). Alter Noise-Pfad entfaellt komplett. Details: ADR-0044 §Entscheidung (1)–(4).

## Etappen-Schnitt

Drei Etappen mit je eigener Commit-Grenze. Etappe 2 setzt gruene Etappe 1 voraus (JS/Modal konsumieren den neuen Flavor). Etappe 3 ist Cleanup nach gruener Etappe 2 — der alte Noise-Pfad bleibt bis dahin funktionsfaehig parallel bestehen (kein Zwischenzustand ohne Bulk-Ack).

### Etappe 1 — Schema + API (Flavor C)

**Ziel:** `POST /api/findings/bulk-acknowledge` kann server-scoped pro Band resolven, dry_run liefert Count + max. 5 Beispiele, Apply cappt Audit-Metadata und bulk-inserted Notes.

**Dateien:** `app/schemas/bulk_request.py`, `app/api/bulk.py`.

**Aenderungen `bulk_request.py`:**

1. Neues Modell `BulkAckServerScope` (`model_config = ConfigDict(extra="ignore")`):
   - `server_id: int` (`> 0`-Validator analog `finding_ids`).
   - `risk_band: Literal["escalate", "act", "mitigate", "monitor", "noise"]` — `pending`/`unknown` scheitern an Pydantic (422). Konstante `BULK_ACK_BANDS` als Single Source fuer Tests und Template.
2. `BulkAckRequest.server_scope: BulkAckServerScope | None = None`; XOR-Validator von zwei auf drei Flavors erweitert (genau einer von `finding_ids`/`match`/`server_scope`).
3. `risk_band_filter: Literal["noise"] | None` **entfernen** (einziger Consumer war `bulk_ack_noise.js`; Entfernung erst wirksam machen, wenn Etappe 1 den Flavor C liefert — `bulk_ack_noise.js` wird in Etappe 3 geloescht, bis dahin schickt es das Feld weiter, das via `extra="ignore"` toleriert wird. **Wichtig:** der server-seitige noise-Drop-Codepfad in `bulk.py` bleibt bis Etappe 3 bestehen, nur das Schema-Feld wandert in ein deprecated-Kommentar — siehe Etappe-3-Checkliste).

   > Hinweis Implementer: einfachste konfliktfreie Reihenfolge ist, `risk_band_filter` in Etappe 1 **zu behalten** und erst in Etappe 3 mit dem JS zusammen zu entfernen. Entscheidet der Implementer anders, muss `bulk_ack_noise.js` in Etappe 1 mit angepasst werden — dann Etappen-Kommentar im Commit.

**Aenderungen `bulk.py`:**

1. Neuer Query-Builder `_build_server_scope_query(scope)`:
   ```python
   select(Finding).where(
       Finding.server_id == scope.server_id,
       Finding.status == FindingStatus.OPEN,
       Finding.risk_band == scope.risk_band,
   )
   ```
   Kein `.limit()`. Server-Guard davor: aktiver Server oder `json_error(404, ...)` (revoked/retired/unbekannt — Wiederverwendung der Guard-Logik analog `_load_active_server_or_404`, aber als JSON-404).
2. dry_run-Response fuer Flavor C: `count`, `examples` (max. 5 × `{identifier_key, package_name}`, `ORDER BY identifier_key ASC LIMIT 5` als **separater** Projektions-Query — nicht alle Findings hydrieren um 5 zu zeigen), `server_scope`-Echo. **Kein** `finding_ids`-Array in der Flavor-C-Response (ADR-0044 §(2)).
3. Apply-Pfad Flavor C: `UPDATE findings SET status='ACKNOWLEDGED', acknowledged_at=now(), acknowledged_by=? WHERE server_id=? AND risk_band=? AND status='open'` — direkt per WHERE-Scope, ohne vorherige ID-Hydration. Betroffene Anzahl aus `result.rowcount`.
4. Notes bei Kommentar: **ein** Bulk-Insert (`sess.execute(insert(FindingNote), rows)`) statt N× `sess.add`. Die IDs fuer die Note-Rows liefert ein schmaler `select(Finding.id)`-Scope-Query (Projektion, keine ORM-Hydration). Gilt fuer alle Flavors (Refactor der bestehenden Schleife).
5. Audit (`finding.bulk_acknowledged`, ein Event): `metadata.finding_ids` auf `[:50]` cappen (Praezedenz `llm_worker.py:1382`), zusaetzlich `metadata.count` (voll), `metadata.server_scope={server_id, risk_band}` bei Flavor C. Gilt fuer alle Flavors.
6. Logging: `bulk_ack.dry_run`/`bulk_ack.applied` um `server_scope`-Felder ergaenzen.
7. Rate-Limit (30/min) und CSRF-Handling (X-CSRFToken) unveraendert.

**Pure-Unit-Tests** — `tests/schemas/test_bulk_request.py` (erweitern) und `tests/api/test_bulk_acknowledge.py` (**neu anlegen** — Achtung Befund 2026-06-04: die Datei existiert im Repo nur noch als `.pyc` unter `tests/api/__pycache__/`, die Quelldatei fehlt; nicht versuchen sie zu „reparieren", sondern frisch schreiben):

1. Schema: `server_scope` mit jedem der fuenf erlaubten Bands validiert.
2. Schema: `risk_band="pending"` → ValidationError. Ebenso `"unknown"`, `""`, `"NOISE"` (case-sensitiv).
3. Schema: `server_id=0` / negativ → ValidationError.
4. Schema: XOR — `server_scope`+`finding_ids` zusammen → ValidationError; `server_scope`+`match` zusammen → ValidationError; keiner von dreien → ValidationError.
5. API dry_run Flavor C: Response hat `count`, `examples` (≤ 5, deterministisch sortiert), kein `finding_ids`-Key; kein UPDATE ausgefuehrt (Mock-Session-Spy).
6. API dry_run Flavor C auf Band ohne Findings: `count=0`, `examples=[]`.
7. API apply Flavor C: UPDATE-WHERE enthaelt `server_id`, `risk_band`, `status='open'`; kein `.limit()` im kompilierten SQL (SQL-Shape-Check via `str(stmt.compile(...))`).
8. API apply Flavor C mit Kommentar: genau **ein** Insert-Execute fuer FindingNotes (Spy), `author='system-bulk-ack'`.
9. API apply: Audit-Metadata `finding_ids` ≤ 50 Eintraege bei > 50 betroffenen Findings, `count` traegt volle Zahl.
10. API Flavor C auf unbekannten/revoked/retired Server: 404, kein UPDATE.
11. Regression Flavor A und B: bestehendes Verhalten unveraendert (mind. je ein Happy-Path).

**Adversarial** — `tests/adversarial/test_bulk_ack_band_scope.py` (neu):

1. `risk_band="pending"` via rohem JSON-POST → 422, kein DB-Write.
2. `server_scope` + zusaetzlich eingeschleustes `finding_ids` im selben Body → 422 (XOR), kein „beides anwenden".
3. SQL-Metazeichen/Array in `risk_band` (`"noise' OR '1'='1"`, `["noise"]`) → 422.
4. `server_id` als String/Float/overflow → 422 oder 404, nie 500.

**Akzeptanz-Kriterien:**

- `ruff check . && ruff format --check .` clean; `mypy app/` keine neuen Errors.
- `pytest tests/schemas/test_bulk_request.py tests/api/test_bulk_acknowledge.py tests/adversarial/test_bulk_ack_band_scope.py -v` gruen (Bash-Timeout 60000).
- Default-Suite `pytest` gruen (Bash-Timeout 120000) — Flavor C ist additiv, alter Noise-Pfad funktioniert weiter.

**Commit-Botschaft-Muster:**
```
feat(api): Server-Scope-Flavor fuer Bulk-Acknowledge (ADR-0044)

- BulkAckServerScope {server_id, risk_band} mit Band-Whitelist (pending → 422)
- Endpoint resolved server-seitig, kein ID-Transport, kein Limit
- dry_run liefert count + max 5 examples
- Audit-finding_ids gecappt [:50], Notes als Bulk-Insert
- Pure-Unit- + Adversarial-Tests, tests/api/test_bulk_acknowledge.py neu angelegt

Bezug: ADR-0044 §(1),(2),(4), TICKET-009 Etappe 1
```

### Etappe 2 — Frontend (Hover-Control + generisches Modal)

**Ziel:** „ACKNOWLEDGE ALL" pro Band-Sektion (ausser pending), generisches Modal, neue Alpine-Komponente auf Flavor C.

**Dateien:**

- `app/templates/_partials/risk_band_section.html` (Umbau)
- `app/templates/_partials/bulk_ack_band_modal.html` (neu)
- `app/static/js/bulk_ack_band.js` (neu)
- `frontend/src/css/components/server-detail.css` (Hover-States)
- `app/templates/base.html` / `base_app.html` (Script-Include `bulk_ack_band.js`)

**`risk_band_section.html` Umbau:**

- Sektion bekommt einen Wrapper mit Alpine-Scope; das Modal liegt als **Sibling des `<details>`** im Wrapper — **nicht** im `<summary>` und nicht im `<details>`-Body (collapsed `<details>` versteckt Inhalt, das Modal waere unsichtbar):
  ```
  {%- set _band_ackable = section.band != "pending" -%}
  <div {% if _band_ackable %}x-data="bulkAckBand({{ server.id }}, '{{ section.band }}', {{ section.total_count }})"{% endif %}>
    <details class="sd-band" data-test="risk-band-{{ section.band }}" ...>
      <summary class="sd-band__summary">
        <span class="sd-band__chev" ...>›</span>
        <span class="sd-badge sd-badge--{{ section.band }}">...</span>
        <span aria-hidden="true"></span>
        {% if _band_ackable %}
          <label class="sd-band__ackall"
                 data-test="band-ack-all-{{ section.band }}"
                 @click.prevent.stop="openModal()">
            <input type="checkbox" tabindex="-1" aria-hidden="true">
            <span>Acknowledge all</span>
          </label>
        {% endif %}
        <span class="sd-band__count">...</span>
      </summary>
      <div class="sd-band__body" ...>...</div>
    </details>
    {% if _band_ackable %}{% include "_partials/bulk_ack_band_modal.html" %}{% endif %}
  </div>
  ```
- `@click.prevent.stop` ist Pflicht — sonst toggelt der Klick das `<details>`.
- Die Checkbox ist rein visuelles Affordance-Element (Screenshot-Spec); der State lebt im Modal (Confirm-Checkbox). `tabindex="-1"` haelt sie aus der Tab-Order, Keyboard-Pfad laeuft ueber das fokussierbare Label.
- Band-Whitelist im Template ist `!= "pending"` ueber `_RISK_BAND_SECTION_ORDER`-Eintraege — identisch zur Schema-Whitelist (`unknown` taucht als Sektion nie auf, ADR-0038).

**`bulk_ack_band_modal.html` (neu, ersetzt funktional `_bulk_ack_noise_modal.html`):**

- Variablen: `server`, `section` (band, total_count). Kein server-gerendertes Findings-Listing — Beispiele kommen aus der dry_run-Response (Alpine `x-for` ueber `examples`, max. 5, plus „… and N more" aus `count - examples.length`).
- Titel: „Acknowledge all {{ section.band | upper }} on this server". Hinweis-Zeile analog heute („Es werden ausschliesslich offene Findings mit risk_band={{ section.band }} auf diesem Server acknowledged.").
- Pflicht-Bestaetigungs-Checkbox (`x-model="confirm"`), Kommentar-Textarea optional (`maxlength="8192"`, ADR-0006: **keine** Pflicht), Abbrechen/Bestaetigen-Buttons mit `busy`-Disable — Struktur 1:1 vom Noise-Modal uebernehmen, `data-test`-Schema: `bulk-ack-band-modal`, `bulk-ack-band-confirm-check`, `bulk-ack-band-confirm`, `bulk-ack-band-examples`, `bulk-ack-band-truncation`.

**`bulk_ack_band.js` (neu, Struktur-Vorlage `bulk_ack_noise.js`):**

- `bulkAckBand(serverId, band, totalCount)` mit identischem State-Vertrag (`open/busy/comment/confirm/previewCount/error` + `examples: []`).
- `_buildPayload(dryRun)` → `{server_scope: {server_id: serverId, risk_band: band}, dry_run: !!dryRun}` (+ `comment` bei Apply). **Keine** `finding_ids`, kein `risk_band_filter`.
- `openModal()` → dry_run; `apply()` → Toast `${n} ${band}-Finding(s) abgehakt` + `window.location.reload()` nach 400 ms (bestehendes Pattern).
- CSRF aus `<meta name="csrf-token">` via `X-CSRFToken`; Response nie als HTML interpretieren; Registrierung via `alpine:init` + window-Fallback — alles wie in der Vorlage.

**CSS (`server-detail.css`):**

- `.sd-band__ackall`: default `visibility: hidden` (nicht `display:none` — kein Layout-Sprung im Grid des Summary), Farbe `var(--text-secondary)`, Mono-Uppercase wie `.sd-band__count`.
- `.sd-band__summary:hover .sd-band__ackall { visibility: visible; }` — Reveal bei Hover ueber der Band-Zeile.
- `.sd-band__ackall:hover span { color: var(--accent); }` — grau → cyan nur bei Hover genau ueber dem Control (Screenshot-Spec).
- `:focus-visible`-State analog `.sd-band__summary:focus-visible` (Outline `--accent`), damit der Keyboard-Pfad das Control sichtbar macht: `.sd-band__summary:focus-within .sd-band__ackall { visibility: visible; }`.

**Pure-Unit-Tests** — `tests/templates/test_risk_band_ack_all.py` (neu):

1. Sektion `escalate/act/mitigate/monitor/noise`: Control `band-ack-all-<band>` im Render vorhanden.
2. Sektion `pending`: **kein** Control, **kein** Modal-Include.
3. Leeres Band (`is_empty`): Sektion rendert gar nicht (Bestand) — kein verwaistes Modal.
4. Modal-Render: Confirm-Checkbox vorhanden, Kommentar-Feld ohne `required`-Attribut (ADR-0006), kein server-gerendertes Findings-Listing (> 0 Items) im Markup.
5. Modal liegt **ausserhalb** des `<details>`-Elements (Struktur-Assert auf Eltern-Reihenfolge im gerenderten HTML).
6. `@click.prevent.stop` (bzw. `x-on:click.prevent.stop`) am Control vorhanden.
7. Script-Include: `bulk_ack_band.js` in `base_app.html`-Render enthalten.

Anpassen: `tests/templates/test_risk_band_accordion.py` (Summary-Markup-Asserts um das neue Element ergaenzen), `tests/test_asset_manifest.py` (neues JS-Asset).

**Akzeptanz-Kriterien:**

- `ruff` clean (Python-Touches), `mypy app/` clean.
- `pytest tests/templates/test_risk_band_ack_all.py tests/templates/test_risk_band_accordion.py -v` gruen (Timeout 60000).
- Default-Suite gruen (Timeout 120000). Alter Noise-Pfad parallel weiter funktionsfaehig (Etappe 3 raeumt auf).
- Visueller Sanity-Check (Hover-Reveal, cyan-Hover, Modal, Apply) ist Operator-Pflicht nach Merge — nicht Teil der Code-DoD.

**Commit-Botschaft-Muster:**
```
feat(server-detail): Per-Band "Acknowledge all" Hover-Control + Modal (ADR-0044)

- risk_band_section.html: Hover-Control fuer alle Bands ausser pending
- bulk_ack_band_modal.html: generisches Modal, Beispiele aus dry_run (max 5)
- bulk_ack_band.js: Alpine-Komponente auf server_scope-Flavor
- CSS Hover-Reveal + grau→cyan, focus-within-Pfad
- 7 Template-Tests neu, Accordion-/Asset-Tests angepasst

Bezug: ADR-0044 §(3), TICKET-009 Etappe 2
```

### Etappe 3 — Cleanup alter Noise-Pfad + Doku

**Ziel:** Alle Noise-Sonderpfad-Artefakte entfernen, Docs aktualisieren.

**Loeschen:**

1. `app/views/server_detail.py::noise_fragment` (Z. ~1007–1056) inkl. Route — danach `grep -rn "fragments/noise\|noise_fragment" app/ tests/` leer.
2. `app/templates/servers/_partials/noise_fragment.html`, `app/templates/servers/_bulk_ack_noise_modal.html`.
3. `app/static/js/bulk_ack_noise.js` + Script-Include in `base.html`/`base_app.html`.
4. `sd-noise-toolbar`-Slot in `_findings_section.html` (Z. 48–54) — der Toolbar-Block behaelt „Auswahl ack" + CSV-Export.
5. `noise_total`/`noise_findings` aus dem `_findings_section.html`-Variablen-Vertrag und aus `server_detail.py` (Context-Aufbau in `show()` bzw. `_load_server_band_aggregates`-Umfeld: nur die Modal-Preview-Anteile — der `noise_count` fuer Band-Counts bleibt, er speist die Sektions-Header).
6. Schema: `risk_band_filter` aus `BulkAckRequest` + zugehoeriger Drop-Codepfad (`skipped_non_noise_ids`) aus `bulk.py` und aus Response/Audit-Metadata.
7. Tests loeschen/ersetzen: `tests/templates/test_bulk_ack_noise_shortcut.py`, `tests/adversarial/test_bulk_ack_noise_strict.py` (Ersatz ist `test_bulk_ack_band_scope.py` aus Etappe 1), Noise-Fragment-Faelle in `tests/views/test_server_detail_fragments.py` (anpassen, nicht skippen).

**Doku:**

1. **ARCHITECTURE.md §6:** `bulk-acknowledge`-Beschreibung um Flavor C ergaenzen, `risk_band_filter` entfernen. **§7a (Server-Detail):** Bulk-Ack-Noise-Button-Beschreibung durch Per-Band-Control ersetzen.
2. **ADR-0022:** Status-Zeile ergaenzen: „… §Bulk-Ack-‚noise'-Workflow abgeloest durch ADR-0044".
3. **ADR-0039:** §2-Tabelle — `fragments/noise`-Zeile mit Hinweis „entfallen per ADR-0044" markieren (Tabelle nicht stillschweigend umschreiben).
4. **`docs/decisions/README.md`:** Index-Eintrag ADR-0044.
5. **CHANGELOG.md:**
   ```
   ### Server-Detail
   - Jedes Risk-Band (ausser pending) hat ein "Acknowledge all"-Hover-Control am Band-Header (ADR-0044).
   - Bulk-Ack wirkt auf ALLE offenen Findings des Bands — das 50er-Limit des Noise-Workflows entfaellt.
   - "Acknowledge all noise on this host"-Link, Noise-Fragment-Endpoint und bulk_ack_noise.js entfernt.
   ```
6. **docs/blocks/STATE.md:** TICKET-009-Eintrag bei Abschluss.

**Akzeptanz-Kriterien:**

- `grep -rn "bulk_ack_noise\|bulkAckNoise\|risk_band_filter\|skipped_non_noise" app/ tests/` leer (Docs duerfen historisch referenzieren).
- `ruff`, `mypy app/`, Default-`pytest` gruen.
- CHANGELOG/STATE/ARCHITECTURE/ADR-Verweise vorhanden.

**Commit-Botschaft-Muster:**
```
chore(server-detail): Noise-Sonderpfad entfernt + Doku (ADR-0044)

- noise_fragment-Endpoint, Noise-Modal, bulk_ack_noise.js geloescht
- risk_band_filter + skipped_non_noise_ids aus Schema/Endpoint entfernt
- ARCHITECTURE §6/§7a, ADR-0022/0039-Verweise, CHANGELOG, ADR-Index

Bezug: ADR-0044, TICKET-009 Etappe 3
```

## Definition-of-Done (Gesamt)

1. ADR-0044 akzeptiert und im Index referenziert; Abloese-Verweise in ADR-0022 und ADR-0039 gesetzt.
2. `BulkAckRequest` hat den `server_scope`-Flavor; `pending`/`unknown` werden mit 422 abgelehnt (Pure-Unit + Adversarial belegt).
3. dry_run liefert echten Count + max. 5 `examples`; Apply ackt **alle** offenen Findings des Scopes (kompiliertes SQL ohne LIMIT, per Test belegt).
4. Audit: ein Event, `finding_ids` ≤ 50, `count` voll, `server_scope` in Metadata; Notes als ein Bulk-Insert.
5. Jede nicht-leere Band-Sektion ausser `pending` rendert das Hover-Control; `pending` nicht (Template-Test).
6. Modal zeigt max. 5 Beispiele + „… and N more", Kommentar optional, Pflicht-Confirm vor Apply.
7. Alter Noise-Pfad restlos entfernt (grep-Kriterien Etappe 3); `tests/api/test_bulk_acknowledge.py` existiert wieder als Quelldatei.
8. `ruff check`/`ruff format --check` gruen, `mypy app/` ohne neue Errors, Default-`pytest` gruen.
9. **User-Manual-Sanity-Check** (nicht Teil der Code-DoD): Hover-Reveal + cyan-Hover je Band, Modal-Preview-Count == Band-Count, Apply auf Band mit > 50 Findings ackt alle, pending hat kein Control.

## NICHT in diesem Ticket

- OOB-Refresh der Band-Counts/Tiles/Sidebar nach Apply (Full-Reload bleibt; Re-Open-Trigger in ADR-0044).
- Bulk-Ack fuer `pending` oder `unknown` (ADR-0044 §Verworfen (e)).
- Aenderungen am Einzel-Acknowledge-Modal oder an „Auswahl ack" (Flavor A bleibt wie er ist).
- Aenderungen am `/findings`-Bucket-Bulk-Ack (ADR-0037, eigener Endpoint).
- Batched UPDATE / Lock-Optimierung fuer 100k-Findings-Server (Re-Open-Trigger).
- Schema-Migration (nicht noetig).

## Bezug zur Test-Konvention (CLAUDE.md)

Jeder Implementer-/Test-Writer-Subagent-Aufruf zu diesem Ticket enthaelt woertlich:

> Erlaubte Quality-Gates: ruff, mypy, shellcheck (Linter), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien. Jeder pytest-Bash-Aufruf hat ein timeout-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).
