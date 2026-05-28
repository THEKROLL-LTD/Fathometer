# ADR-0041 — Finding-Detail Inline: Modal + Flat-Switch entfernen, Body erweitern

**Status:** Akzeptiert · **Datum:** 2026-05-28 · **Block:** AA — Finding-Detail Inline

Bezug: [ADR-0025](0025-server-detail-and-findings-slim-down.md) (Mode-Switch `?flat=1` als Power-User-Bypass), [ADR-0037](0037-findings-cross-server-bucket-view.md) (Cross-Server-Bucket-View, `<details>`-Stack), [ADR-0038](0038-server-detail-triage-refactor.md) (`sd-finding`-Body mit Inline-Reason), [ADR-0039](0039-server-detail-lazy-render-architecture.md) (Triage-Queue-Pagination, Spalten-Projektion), [ADR-0006](0006-no-forced-comments.md) (keine Pflicht-Felder), [ADR-0032/0033](0033-brand-identity-fathometer.md) (sd-* CSS-Klassen).

## Kontext

Der heutige Pfad zu den vollen CVE-Informationen (Description, Reference-Liste, CVSS-Vector, CWE-Liste) führt durch ein Modal in `app/templates/findings/_detail_modal.html`. Dieses Modal ist **nur** in `app/templates/servers/_view_list.html` included. `_view_list.html` selbst wird vom Switch in `_findings_section.html:67-82` aktiviert — sobald (a) `?flat=1` an der URL hängt, (b) irgendein Filter aktiv ist (`status`, `class`, `kev_only`, `search`, `risk_band`, `action_required`, `application_group_id`) oder (c) die Sortierung nicht der Default `risk desc` ist.

In der Default-Ansicht (Sort risk/desc, kein Filter) rendert dagegen `_view_groups.html` → `risk_band_section.html` → `group_findings_table.html`. Hier ist jede Finding-Zeile ein nativer `<details class="sd-finding">`-Stack (Block X Phase G, Commit `f858a08`). Der Body zeigt **ausschließlich** `risk_band_reason` — also nichts, wenn der LLM-Pass-2 noch nicht gelaufen ist. Description, References, Primary-URL und Notes-Thread sind in diesem Modus **nicht erreichbar**.

Drei daraus folgende Probleme:

1. **Versteckte Feature-Gate.** `?flat=1` ist die einzige Möglichkeit, das Detail-Modal im Default-State zu öffnen. Es existiert kein Link, kein Button, kein Menüpunkt in irgendeinem Template, der diesen Querystring setzt (verifiziert via `grep -r "flat=1" app/`). Operator entdeckt das Feature nicht ohne ADR/Code-Lektüre.
2. **Klick-tut-nichts-Wahrnehmung.** Im Default-Modus toggelt der Klick auf eine Finding-Row korrekt `<details>` auf, aber bei fehlendem `risk_band_reason` ist der Body leer — visuell ist nichts unterscheidbar, der Operator denkt, die UI ist kaputt.
3. **PrimaryURL/Description liegen brach.** `PrimaryURL` wird im Trivy-Envelope-Schema (`app/schemas/scan_envelope.py:383`) sogar validiert, aber im Ingest-Mapper (`_build_finding_row`) nicht in die DB-Zeile übernommen. `description` und `references` werden persistiert, aber außerhalb des Modals nirgends angezeigt und auch dem LLM nicht gegeben (siehe ADR-0023 / Pass-2-Prompt-Form).

Zur Performance-Skepsis aus ADR-0039: die Triage-Queue ist seit Block Y paginiert (`_TRIAGE_PAGE_SIZE = 10`), die Bucket-View hat `per_page = 20` (ADR-0037). Description (typisch 0,5–4 KB pro Finding) und References (typisch 5–15 URLs pro Finding) zusätzlich pro Seite zu hydrieren ist im Größenordnungs-Vergleich harmlos.

Drei Design-Optionen wurden im Brainstorm-Round (2026-05-28) geprüft:

1. **Modal an alle drei `<details>`-Pfade anschließen** (Server-Detail-Group-Drilldown, Triage-Queue, Bucket-View). Verworfen weil:
   - Duplikat-Markup pro Pfad widerspricht der HTMX-OOB-Single-Source-Doktrin aus CLAUDE.md.
   - Modal-State-Management pro Row in Alpine ist Mehrkosten (`x-data="{ detailOpen: false }"` × N Rows).
   - User-Wahrnehmung „klick öffnet was anderes als der `<details>`-Toggle" ist inkonsistent — heute toggelt der Klick `<details>`, gleichzeitig ein „Details"-Button zu rendern würde die Mental-Map brechen.

2. **HTMX-Lazy-Fragment** beim ersten `<details open>` (`hx-get="/findings/<id>/detail-fragment"`). Verworfen weil:
   - Zusätzlicher Endpoint, zusätzliche Roundtrip-Latenz pro erstmaligem Aufklappen.
   - Cache-Invalidierung beim Status-Wechsel (Ack/Re-open ändert nur Notes — Description ist immutable, aber der Endpoint muss trotzdem für sauberes Lifecycle alles liefern).
   - Backend-/Frontend-Komplexität für ein Problem, das durch Pagination ohnehin entschärft ist.

3. **Inline-Body erweitern** in den drei `<details>`-Templates. Hydration in der bestehenden Listen-Query bzw. Erweiterung der Projektion. Gewählt. Pagination ist klein genug (10 bzw. 20 pro Seite), Initial-Render ist nicht spürbar teurer, der HTMX-Polling-Pfad ändert sich nicht.

Der Flat-Switch fällt damit komplett weg. Ein einziger Render-Pfad, alle Detail-Daten direkt im Body sichtbar, Ack/Re-open bleibt ein eigenständiges schlankes Modal (Form-Submission mit optionalem Kommentar — kein CVE-Detail mehr drin).

## Entscheidung

### Schema

**Eine Migration:** `findings.primary_url VARCHAR(2048) NULL` per `0016_block_aa_add_primary_url` (die Nummer `0015` war bereits durch `0015_findings_covering_idx` belegt).

- Default `NULL` für alle Bestands-Findings; wird beim nächsten Re-Ingest pro Server befüllt.
- Pydantic-Schema (`TrivyVulnerability.primary_url`) existiert bereits, validiert HttpUrl + `MAX_REF_URL_LENGTH=2048`. Mapper `_build_finding_row` in `app/services/findings_ingest.py` muss um den Eintrag `"primary_url": vuln.primary_url` ergänzt werden, ebenso der `ON CONFLICT DO UPDATE`-Block. Idempotent: kein Backfill nötig, NULL bleibt NULL, beim nächsten Scan wird die Spalte gefüllt.

Keine weitere Schema-Änderung. `description`, `references` sind bereits Bestandsspalten.

### Render-Pfad-Konsolidierung — `?flat=1` und das Detail-Modal entfallen

- **Gelöscht:**
  - `app/templates/servers/_view_list.html` (Flat-Tabelle inkl. Bulk-Toolbar-Wrapper-Logik, Sort-Header, Detail-Modal-Wrapper, Ack-Modal-Wrapper, Re-open-Modal-Wrapper).
  - `app/templates/findings/_detail_modal.html` (Inhalt des bisherigen Detail-Modals — Information wandert komplett in den neuen Inline-Body).
  - `app/templates/_partials/pending_findings_table.html` (siehe unten: wird durch erweiterte `<details>`-Variante ersetzt).
  - `_is_flat_mode`-Helper in `app/views/server_detail.py:607-635` und der `flat_mode`-Branch in `_render_findings_section`.
  - `?flat=1`-Auswertung in `app/templates/servers/_findings_section.html:65-82`. Die Conditional verschwindet; `_view_groups.html` wird unkonditional included.
  - Alle Form-Objekte (`AcknowledgeForm`, `ReopenForm`, `BulkActionForm`, `CSRFOnlyForm`, `NoteForm`) bleiben — werden jetzt immer in den Context gehängt (nicht mehr nur im Flat-Branch).
- **Beibehalten:**
  - `app/templates/findings/_ack_modal.html` und `_status_change_modal.html` — diese Form-Modals bleiben unverändert (nur Ack/Re-open-Form mit optionalem Kommentar gemäß ADR-0006). Sie werden jetzt aus dem Inline-Body heraus per Alpine `x-data`-Wrapper geöffnet, nicht mehr aus der Flat-Tabelle.
  - `app/templates/findings/_notes_thread.html` — wird im neuen Body included, posted weiter auf `findings.add_note` / `findings.delete_note`.

### Inline-Body — neuer Render-Vertrag

Erweitert wird der `<details class="sd-finding">`-Body in:

- `app/templates/_partials/group_findings_table.html` (Server-Detail Group-Drilldown).
- `app/templates/servers/_partials/triage_findings_page.html` (Server-Detail Triage-Queue).
- `app/templates/_partials/bucket_findings_table.html` (Cross-Server `/findings`-View).
- `app/templates/_partials/pending_bucket_findings_table.html` (Cross-Server Pending-Sammler).
- `app/templates/_partials/pending_bucket_findings_table.html` und der Pending-Sektion im Server-Detail werden auf das gleiche `<details>`-Pattern umgestellt (heute reine `<tr>`-Tabelle).

Neue Body-Sektionen in dieser Reihenfolge (Layout-Vorlage: [docs/design/FindingDetailInline.jsx](../design/FindingDetailInline.jsx)):

1. **Body-Header** (zwei-spaltige Flex-Row):
   - links: **KI-Bewertung** — Eyebrow + `risk_band_reason`-Text. Fallback wenn null: dezenter Hint „KI-Bewertung steht aus — Pass 2 läuft asynchron." in `--text-tertiary`.
   - rechts: **Action-Button** — „Abhaken …" für `status='open'`, „Re-open …" für `status='acknowledged'`. Outline-Style, Border in `--accent`. Klick öffnet `_ack_modal.html` bzw. `_status_change_modal.html` (Alpine `x-data="{ ackOpen: false }"` pro Row im neuen Body-Wrapper).
2. **Beschreibung** — Eyebrow „Beschreibung" + `description`-Text. Plain-Text autoescaped (Jinja-Default, **kein** `|safe`). `white-space: pre-line` für eingebettete Newlines aus Trivy.
3. **Quelle** — Eyebrow „Quelle" + `primary_url` als einzelner prominenter Link. Nur wenn nicht-null. Akzentfarbe (`--accent`), Dotted-Border-Bottom.
4. **References (N)** — Eyebrow „References ({{ count }})" + `<ul>` mit allen URLs. Mono-Font, dezent (`--text-secondary`), Dotted-Border-Bottom in `--border-visible`. Jeweils `target="_blank" rel="noopener noreferrer"`. Cap visuell auf 78ch breit, einzelne lange URLs Ellipsis.
5. **Notizen** — Include `_notes_thread.html` mit `finding=f`, `note_form=note_form`, `csrf_form=csrf_form` aus dem View-Context.

Die Doppel-Daten (CVSS, EPSS, KEV, Title, Paket) werden **nicht** im Body wiederholt — sie stehen bereits in der `<summary>`-Zeile sichtbar. Reduktion folgt [feedback_server_detail_less_is_more].

### Backend — Hydration pro Listen-Endpoint

Die paginierten Listen-Pfade hydrieren ab sofort `description`, `references`, `primary_url` und die Notes (max ~5 pro Finding) eager:

- **`server_detail.triage_band_fragment`** (`app/views/server_detail.py:1126`): Projektion auf 13 Spalten wird ersetzt durch `select(Finding).options(selectinload(Finding.notes)).where(...).limit(10).offset(...)`. Die Übergangs-Spalten-Liste fliegt raus; das Template greift wieder auf das `Finding`-ORM zu. Dabei werden `description`, `references`, `primary_url` automatisch verfügbar. Performance: 10 Findings pro Seite × ~5 Notes/Finding + 1 Finding-Query + 1 Notes-Selectinload = 2 Roundtrips, alles im Bereich von Millisekunden — unkritisch.
- **`findings.bucket_fragment`** (`app/views/findings.py:259`): `list_bucket_findings` in `app/services/findings_bucket_query.py:367` liefert bereits ORM-Findings; die `selectinload(Finding.notes)`-Option wird ergänzt.
- **`findings.pending_fragment`** (`app/views/findings.py:320`): Analog. Falls bereits Notes-Eager-Loading existiert, kein Change.
- **Pending-Grouping-Sektion im Server-Detail** (heute `pending_findings_table.html` als reine `<tr>`-Tabelle): wird auf dasselbe `<details>`-Pattern umgestellt; eigener HTMX-Endpoint (existiert bereits) liefert die ORM-Findings + Notes.

Eager-loaded werden ausschließlich die für den Render nötigen Beziehungen:

- `selectinload(Finding.notes)` für den Notes-Thread.
- Bucket-Pfad behält `selectinload(Finding.server)` + `selectinload(Finding.application_group)` (bereits gesetzt).

Audit-Implikation: Die Drift-Tests aus ADR-0039 § Single-Source-Pattern bleiben grün, weil Projektions-vs-ORM-Render strukturell identische DOM-IDs/Klassen erzeugen — der Drift-Test prüft das Markup-Schema, nicht die Datenquelle.

### Ingest — `primary_url` persistieren

`app/services/findings_ingest.py::_build_finding_row` (Zeile 258) bekommt einen Eintrag:

```python
"primary_url": vuln.primary_url,
```

Im `ON CONFLICT DO UPDATE`-Block bei den `update_cols` (ab Zeile 429) ebenfalls eintragen:

```python
"primary_url": stmt.excluded.primary_url,
```

Die Pydantic-Validierung (`TrivyVulnerability._validate_primary_url`) bleibt unverändert — bereits korrekt (HttpUrl-Parse, http(s)-Whitelist, NUL-byte-Schutz, Length-Cap).

### CSV-Export

`csv_export.export_csv` bleibt unverändert — `primary_url` wird nicht in den Export aufgenommen (Export ist für Trend-Tracking, nicht für Verlinkung). Re-Open-Trigger: falls Operator das später möchte, eigener PR.

### Audit / Sicherheit

- `description`, `references`, `primary_url` und Notes werden alle mit Jinja-Autoescape gerendert; explizit **kein** `|safe`. Notes nutzen weiter `markdown_safe`-Filter (nh3-Whitelist).
- References sind bereits per Pydantic auf `http(s)://` whitelisted (`MAX_REF_URL_LENGTH=2048`, max 100 pro Finding). Defensives Template-Re-Check (`url.startswith('https://') or url.startswith('http://')`) wird übernommen.
- `primary_url` ebenfalls per Pydantic vorvalidiert; im Template gleicher defensiver Check.
- Notes-Form: kein `required`, kein „Pflicht"-Hint — [ADR-0006](0006-no-forced-comments.md). Ack-/Reopen-Modal-Kommentar bleibt optional wie bisher.

## Konsequenzen

### Operator (positiv)

- Klick auf eine Finding-Row öffnet **sofort sichtbare** Details: AI-Bewertung, volle Description, Primary-Link (z. B. `https://avd.aquasec.com/nvd/…`), Reference-Liste (NVD, GHSA, USN, RHSA, …), bestehende Notizen, Add-Note-Form.
- Abhaken/Re-open mit einem Klick aus dem Body heraus — kein doppelter Page-State (Modal über Modal).
- Default-Ansicht ist die einzige Ansicht. Filter und Sort funktionieren weiter in der Group-View (siehe „Offene Punkte" unten).

### Operator (neutral / Migrationsaufwand)

- Bestehende URL-Bookmarks mit `?flat=1` rendern jetzt die Group-View. Kein Redirect, keine Warnung — der Querystring wird einfach ignoriert.
- Sort-Header-Links der alten Flat-Tabelle (CVE, Paket, EPSS, CVSS, Severity, Erstmals) fallen weg. Die Default-Sort der Group-View (`is_kev DESC, risk_band-Rank, severity ASC, epss DESC`) bleibt die einzige Sortierung. Operator-Anpassung an Sort-Reihenfolge wandert in den Filter-Bar (siehe Offene Punkte).

### Operator (negativ / Re-Open-Trigger)

- **Cross-Cutting-Sortierung in der Flat-Tabelle** war ein Power-Feature für „zeig mir alle Findings nach EPSS sortiert, egal welche Group". Im neuen Single-Pfad ist EPSS nur innerhalb einer Group-Drilldown sortiert (durch die Default-Sort der `triage_band_fragment`-Query). Re-Open-Trigger: ein optionaler globaler Sort-Toggle in der Filter-Bar.
- **„Erstmals"-Spalte** der Flat-Tabelle (Bestand seit Block-K) entfällt aus der Group-Drilldown-View. Information bleibt aber in der Finding-Detail-Sektion erreichbar (kann als optionales Meta-Feld in den Body aufgenommen werden — out-of-scope Block AA).

### Technisch

- `_view_list.html`, `_detail_modal.html`, `_is_flat_mode`, `pending_findings_table.html` und der `?flat=1`-Switch fallen ersatzlos weg. ca. 800 Zeilen Template/View-Code weniger.
- Pro Listen-Seite ein zusätzlicher Notes-Selectinload-Query (1 SELECT für 10–20 Findings). Memory pro Render-Vorgang ~50 KB zusätzlich für die hydrierten ORM-Objekte. Vernachlässigbar bei 10–20 Findings pro Page.
- Test-Migration: 6 Test-Dateien mit `?flat=1`-Mustern werden umgeschrieben oder gelöscht (siehe Block-AA-Spec §Tests).

### Sicherheit

Keine neuen Exposures. Description und References waren bisher schon per Modal sichtbar; sie wandern nur in einen direkter erreichbaren Container. Autoescape-Doktrin (ADR-0038 §G4) bleibt unverändert verbindlich.

### Performance

- Initial-Page-Load Server-Detail: unverändert (Risk-Band-Sections rendern, Bodies sind alle collapsed `<details>` — Browser lädt das DOM aber rendert nichts Sichtbares).
- Triage-Queue-Fragment-Pageload: 10 Findings × (Description+References+Notes-Hydration) statt 10 Findings × 13-Spalten-Projektion. Erwartete Latenz: +5–15 ms pro Page (PostgreSQL-Selectinload + ORM-Hydration). Akzeptabel.
- Bucket-Fragment-Pageload: 20 Findings analog. Erwartete Latenz: +10–30 ms pro Page. Akzeptabel.
- Tipping-Point: wenn Description-Felder durchschnittlich >10 KB werden (Trivy-Cap ist 64 KB), wird die initial-DOM-Größe spürbar. Operator-Heuristik aus realen Fixtures: median ~1.2 KB, p95 ~6 KB → unkritisch.

## Out-of-Scope (explizit, im Block-Spec verbindlich)

1. **Globaler Sort-Toggle** in der Filter-Bar (Re-Open-Trigger oben).
2. **Erstmals/Last-Seen-Spalte oder Datum** im Inline-Body (kann später ergänzt werden, keine Schema-Änderung nötig).
3. **CVSS-Vector + CWE-Liste** im Inline-Body (bleiben im LLM-Prompt-Pfad, nicht im UI — User-Vorgabe: keine Doppel-Anzeige).
4. **„Quelle/References dem LLM mitgeben"** (Pass-2-Prompt-Erweiterung) — eigener ADR/Block, siehe vorherige Diskussion in der Chat-Historie.
5. **Description-Render mit Markdown** — Trivy liefert Plain-Text, kein Markdown-Render im Body. Operator-Workflow ist „lesen, dann zu Quelle springen".
6. **Modal-Markup-Single-Source-Refactor** für Ack-/Re-open-Modals (das Modal wird heute schon nur in `_view_list.html` included; nach Block AA wird es im Inline-Body inkludiert — als „migrate, not refactor"-Aktion, keine Single-Source-Doktrin-Erweiterung nötig).
7. **References dem LLM mitgeben** — out-of-scope, dafür gibt es eine separate Diskussion (siehe Chat 2026-05-28).
8. **Repository-Rename `secscan` → `fathometer`** — separater ADR notwendig, nicht hier.

## Re-Open-Trigger

- **URL-Filter narrowen die Server-Detail-Ansicht nicht mehr (Block-AA-Implementierungsbefund 2026-05-28).** Vor Block AA wurden die URL-Params `status`/`kev_only`/`q`/`class`/`risk_band`/`action_required`/`application_group` ausschließlich über die flache Tabelle (`_is_flat_mode` → `list_findings(filter)`) ausgewertet — es gibt **keine** Filter-Bar-UI auf der Server-Detail-Seite, die Params waren URL-/Bookmark-only. Mit dem Wegfall des Flat-Pfads rendert nur noch die Lazy-Group-View, deren Queries (`_risk_band_header_counts`, `_load_application_groups_for_server`, `triage_band_fragment`) **filter-unaware** sind. Konsequenz: URL-Param-Filter werden auf der Server-Detail-Seite still ignoriert (kein 4xx, der Counts-Header bleibt filter-aware über `count_findings`). Bewusst als Regression akzeptiert (User-Entscheidung 2026-05-28, analog zu den weggefallenen Sort-Headern). Re-Open: Filter in die Lazy-Group-View-Queries + Section→Fragment-HTMX-URLs durchplumben (eigener ADR/Block).
- **Ursachen-Sub-Zeile (Block N: `target_path`, `vendor_ids`, `package_purl`, Type-Badges) ist als UI-Surface entfallen.** Sie lebte ausschließlich im flachen `_view_list.html`; der neue Inline-Body zeigt sie bewusst nicht (Less-is-more, keine Doppel-Daten). Die Daten bleiben persistiert (Model + Ingest unverändert). Re-Open: optionales Meta-Feld im Inline-Body.
- Globaler EPSS-/CVSS-Sort-Toggle in der Filter-Bar (siehe Operator-Negativ).
- Inline-Display von `cwe_ids` + `cvss_v3_vector` (heute im Modal — User hat ausdrücklich gegen Re-Aufnahme entschieden, kann sich bei realer Triage-Erfahrung ändern).
- HTMX-Lazy-Fragment-Variante (Option 2 aus „Verworfenes"), falls die Description-Hydration in Telemetrie real spürbar wird.
- Bulk-Select-Toolbar im Inline-Body (heute in der gestrichenen Flat-Tabelle, in Group-View weiter aktiv).

## Verworfenes

- **Modal an alle drei `<details>`-Pfade anschließen.** Markup-Duplikation, Modal-State pro Row, inkonsistente Mental-Map (`<details>`-Toggle vs. „Details"-Button).
- **HTMX-Lazy-Fragment pro Body**. Zusätzlicher Endpoint, Roundtrip-Latenz, Cache-Komplexität. Nicht gerechtfertigt bei Paginations-Größe 10/20.
- **Description+References in einem aufklappbaren `<details>` *innerhalb* des Bodies kapseln**, um Initial-DOM zu reduzieren. Pure Visual-Noise — User klickt eh erstmal auf den Body, dann nochmal in den inneren Toggle. Verworfen wegen UX.

## Anhänge

- Layout-Mockup: [docs/design/FindingDetailInline.jsx](../design/FindingDetailInline.jsx) (+ companion `.html`).
- Block-Spec: [docs/blocks/AA-finding-detail-inline.md](../blocks/AA-finding-detail-inline.md).
