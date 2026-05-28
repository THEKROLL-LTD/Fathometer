# Block AA — Finding-Detail Inline (`?flat=1` + Detail-Modal entfernen, Body erweitern)

**Spec-Quelle:** [ADR-0041](../decisions/0041-finding-detail-inline.md)
**Branch:** `feat/block-aa-finding-detail-inline`
**Zielversion:** v0.16.0
**Vorgänger:** Block X (ADR-0038, `sd-finding`-Body mit Inline-Reason), Block Y (ADR-0039, Triage-Queue-Pagination), ADR-0037 (Bucket-View `<details>`-Stack).
**Status:** Geplant

## Ziel

Operator hat in **jeder** Findings-Liste (Server-Detail-Group-Drilldown, Server-Detail-Triage-Queue, `/findings`-Bucket-View, Pending-Sektion) durch einen Klick auf die Row sofort Zugriff auf:

- KI-Bewertung (`risk_band_reason`) + „Abhaken …"/„Re-open …"-Button (rechts)
- volle CVE-Beschreibung
- Primary-URL (Aquasec/NVD/Vendor-Direktlink)
- Reference-Liste (NVD, GHSA, USN, RHSA, Mailinglisten, …)
- Notes-Thread mit Add-Note-Form

Der bisherige Pfad zum Detail-Modal über `?flat=1` oder aktive Filter entfällt komplett. Das Detail-Modal-Template und der Flat-View werden gelöscht. Das Ack-/Re-open-Modal bleibt — wird jetzt aus dem Inline-Body heraus geöffnet.

**Erwartetes Ergebnis:** Single-Render-Pfad pro Findings-Liste, keine versteckte Feature-Gate, alle CVE-Details direkt sichtbar, `primary_url` ist endlich persistiert und in der UI verlinkt.

## Spec-Referenzen (Pflicht-Lektüre)

1. **ADR-0041 komplett** — Architektur-Entscheidung, Body-Sektionen, Verworfenes, Re-Open.
2. **ADR-0038 §G + §G3** — `sd-finding`-Body, `sd-finding__reason-*`-BEM-Sub-Klassen, Autoescape-Doktrin.
3. **ADR-0037 §(1) + §(2)** — Bucket-View `<details>`-Stack, `bucket_findings_table.html`-Render-Vertrag.
4. **ADR-0039 §3** — Triage-Queue-Pagination (`_TRIAGE_PAGE_SIZE = 10`), Spalten-Projektion (wird zurückgedreht in Phase B).
5. **ADR-0025 §Flat-Switch** — Begründung des `?flat=1`-Bypass, wird mit Block AA superseded.
6. **ADR-0006** — keine Pflicht-Felder; Add-Note-Form bleibt optional.
7. **CLAUDE.md §HTMX-OOB-Single-Source-Pattern** — Single-Source-Partial wenn Body in zwei Render-Pfaden vorkommt (Initial + HX-Fragment).
8. **`app/templates/findings/_detail_modal.html`** — Inhalt wandert in den neuen Inline-Body, dann Datei löschen.
9. **`app/templates/findings/_ack_modal.html` + `_status_change_modal.html`** — bleiben, werden aus dem Inline-Body heraus per Alpine geöffnet.
10. **`app/templates/findings/_notes_thread.html`** — wird im neuen Body included; HTMX-Endpoints `findings.add_note` / `findings.delete_note` bleiben.
11. **`app/views/server_detail.py::triage_band_fragment`** (Zeile 1126) — Projektion auf 13 Spalten wird ersetzt.
12. **`app/services/findings_bucket_query.py::list_bucket_findings`** (Zeile 367) — bereits ORM, nur `selectinload(Finding.notes)` ergänzen.
13. **`app/services/findings_ingest.py::_build_finding_row`** (Zeile 258) + `ON CONFLICT DO UPDATE`-Block (Zeile 429) — `primary_url` ergänzen.
14. **`app/schemas/scan_envelope.py::TrivyVulnerability.primary_url`** (Zeile 383) — bereits validiert, kein Change.

## Out of scope (explizit, verbindlich)

Aus ADR-0041 §Out-of-Scope übernommen:

- Globaler Sort-Toggle in der Filter-Bar.
- Erstmals/Last-Seen-Spalte im Inline-Body.
- CVSS-Vector + CWE-Liste im Inline-Body.
- References/Description dem LLM mitgeben (separater Block).
- Description-Markdown-Render.
- Modal-Single-Source-Refactor.
- Repository-Rename `secscan` → `fathometer`.

## Modell-Änderungen

**Eine Migration:** `0016_block_aa_add_primary_url` (die Nummer `0015` war bereits durch `0015_findings_covering_idx` belegt).

- Spalte `findings.primary_url VARCHAR(2048) NULL`.
- Default `NULL` — wird beim nächsten Re-Ingest pro Server befüllt.
- Kein Backfill, kein Default-Server-Side-Wert.
- Reverse: einfacher `op.drop_column('findings', 'primary_url')`.

## Phasen

### Phase A — Migration + Ingest-Persistierung

**Ziel:** `findings.primary_url` ist persistiert, im Pydantic-Schema bereits validiert, im Ingest-Mapper jetzt geschrieben.

**Dateien:**

- `alembic/versions/0016_block_aa_add_primary_url.py` (neu).
- `app/models.py::Finding` — neue Spalte `primary_url: Mapped[str | None] = mapped_column(String(2048))` direkt unter dem `references`-Block (Zeile ~382). Kein Index nötig (keine Query nach `primary_url`).
- `app/services/findings_ingest.py::_build_finding_row` (Zeile 258) — Eintrag `"primary_url": vuln.primary_url`.
- `app/services/findings_ingest.py` `ON CONFLICT DO UPDATE` Block (Zeile 429ff) — `"primary_url": stmt.excluded.primary_url`.

**Tests (Pure-Unit, keine db_integration):**

- `tests/services/test_findings_ingest_primary_url.py` (neu, ~5 Tests):
  - `_build_finding_row` schreibt `primary_url` aus `TrivyVulnerability.primary_url` in den Row-Dict.
  - Bei `vuln.primary_url is None` ist der Row-Dict-Eintrag `None`.
  - Re-Ingest: `primary_url` wandert in den `update_cols`-Set; bei `excluded.primary_url IS NULL` wird die DB-Spalte auf NULL überschrieben (autoritative Quelle = aktueller Scan).
  - Schema-Roundtrip: `TrivyVulnerability(PrimaryURL="https://avd.aquasec.com/…").primary_url == "https://avd.aquasec.com/…"` (bestehender Test, Verifikation).
  - Schema-Reject: `PrimaryURL="javascript:alert(1)"` → `primary_url is None` (bestehender Validator, Verifikation).

**DoD-A:**

1. Migration `0015` exists, `op.add_column` schreibt `String(2048), nullable=True`.
2. `Finding.primary_url` ist Bestandteil des ORM-Modells.
3. Re-Ingest eines Trivy-Reports mit `PrimaryURL` schreibt den Wert in die DB (verifiziert per Pure-Unit-Mapper-Test).
4. `ruff check . && ruff format --check . && mypy app/` PASS.
5. Default-`pytest` PASS, mindestens 5 neue Tests grün.
6. **Alembic-Roundtrip** (User-Anforderung pro Lauf): `pytest -m db_integration -k 0015` — Up/Down/Up. Nur auf User-Anweisung.

### Phase B — Backend-Hydration für die paginierten Listen-Endpoints

**Ziel:** Die paginierten Endpoints liefern wieder vollständige ORM-`Finding`-Objekte mit eager-loaded Notes — Description, References, Primary-URL sind über ORM-Attribut-Zugriff verfügbar.

**Dateien:**

- `app/views/server_detail.py::triage_band_fragment` (Zeile 1126ff):
  - Spalten-Projektion (Zeile 1166–1190) ersetzen durch:
    ```python
    stmt = (
        select(Finding)
        .options(selectinload(Finding.notes))
        .where(*base_where)
        .order_by(...)  # unchanged
        .limit(_TRIAGE_PAGE_SIZE)
        .offset((page - 1) * _TRIAGE_PAGE_SIZE)
    )
    findings = list(sess.execute(stmt).scalars().all())
    ```
  - Render-Call an `triage_findings_page.html` reicht zusätzlich `note_form=NoteForm()` und `csrf_form=CSRFOnlyForm()` durch — für den `_notes_thread.html`-Include.
- `app/services/findings_bucket_query.py::list_bucket_findings` (Zeile 367): bestehende `base_stmt.options(...)`-Liste um `selectinload(Finding.notes)` erweitern.
- `app/views/findings.py::bucket_fragment` (Zeile 259) + `pending_fragment` (Zeile 320): `note_form=NoteForm()`, `csrf_form=CSRFOnlyForm()` an die jeweiligen Render-Calls.
- `app/services/findings_query.py::list_findings` (heute vom Flat-Modus konsumiert): bleibt erhalten, weil andere Surfaces (`audit_view`?) den Pfad nutzen könnten — Phase-D-Cleanup prüft Aufrufer und löscht ggf.

**Tests (Pure-Unit, keine db_integration):**

- `tests/views/test_triage_band_fragment_orm_hydration.py` (neu, ~6 Tests):
  - Mock-Session liefert Finding-ORM-Objekte; Template-Render hat Zugriff auf `f.description`, `f.references`, `f.primary_url`, `f.notes`.
  - Pagination unverändert (Page 1, Page N, Page>N → letzte Page).
  - Sortierung unverändert (`is_kev DESC, severity ASC, epss DESC nulls last`).
  - Render-Kontext enthält `note_form`, `csrf_form`.
- `tests/services/test_findings_bucket_query_notes_loader.py` (neu, ~3 Tests):
  - `list_bucket_findings` liefert Findings mit hydrierten Notes (Mock-Test, kein DB-Roundtrip).
  - Findings ohne Notes haben `f.notes == []`.

**DoD-B:**

1. `triage_band_fragment` liefert ORM-`Finding`-Objekte mit `selectinload(Finding.notes)`.
2. `bucket_fragment` und `pending_fragment` liefern Findings mit hydrierten Notes.
3. Render-Context aller drei Endpoints enthält `note_form` und `csrf_form`.
4. `ruff check . && ruff format --check . && mypy app/` PASS.
5. Default-`pytest` PASS, mindestens 9 neue Tests grün.
6. Keine bestehende Test-Regression in `tests/views/test_server_detail.py`, `tests/services/test_findings_bucket_query.py`.

### Phase C — Template-Refactor: erweiterte `<details>`-Bodies + neuer CSS

**Ziel:** Die drei (vier mit Pending) Listen-Templates rendern den neuen Body mit AI-Reason+Button, Description, Primary-URL, References, Notes. Die alte Body-Variante (nur `risk_band_reason`) ist gelöscht.

**Dateien:**

- `app/templates/_partials/finding_inline_body.html` **(neu)** — Single-Source-Partial mit dem kompletten Body-Markup. Wird von allen vier Listen-Templates included. Render-Vertrag:
  - `finding` (`Finding`-ORM mit `notes` eager-loaded).
  - `note_form` (`NoteForm`).
  - `csrf_form` (`CSRFOnlyForm`).
  - `ack_form` (`AcknowledgeForm`).
  - `reopen_form` (`ReopenForm`).
- `app/templates/_partials/group_findings_table.html` (Zeile 92–98): bisheriger Body durch `{% include "_partials/finding_inline_body.html" %}` ersetzen.
- `app/templates/servers/_partials/triage_findings_page.html` (analog).
- `app/templates/_partials/bucket_findings_table.html` (analog).
- `app/templates/_partials/pending_bucket_findings_table.html` (analog — Server-Spalte ist im Summary-Header, der Body ist gleich).
- `app/templates/_partials/pending_findings_table.html` **gelöscht** — Pending-Sektion im Server-Detail nutzt fortan die `<details>`-Variante (Migration siehe Phase D §_findings_section).
- `frontend/src/css/components/server-detail.css`:
  - `.sd-finding__bodyhead` — Flex-Row für AI-Reason + Action-Button.
  - `.sd-finding__action-btn` — Outline-Button-Style (Border `--accent`, Mono-Font, Uppercase, 11px).
  - `.sd-finding__desc` — Beschreibungs-Text-Block (`max-width: 78ch`, `white-space: pre-line`).
  - `.sd-finding__primary` — Primary-URL-Block (Akzent-Link, Dotted-Border).
  - `.sd-finding__refs` — Reference-Liste (kompakt, Ellipsis bei langen URLs).
  - `.sd-finding__notes` — Notes-Block-Wrapper.
  - Alle Token-only (siehe `tokens.css`); **kein** raw hex, **kein** DaisyUI-/Tailwind-Klassen.

**Single-Source-Pattern-Vertrag (CLAUDE.md):**

`finding_inline_body.html` ist die einzige Quelle für die Body-Sektionen. Initial-Render (Pageload) und HTMX-Fragment-Reload (Pager) müssen strukturell identisches Markup liefern — kein Drift möglich, weil dasselbe Partial included wird.

**Alpine-State pro Row:** der `<details>`-Element-Wrapper bekommt `x-data="{ ackOpen: false }"` (bzw. `reopenOpen` für ack'd Findings). „Abhaken …"-Button setzt `ackOpen = true`. Das beibehaltene Ack-/Reopen-Modal (`_ack_modal.html` / `_status_change_modal.html`) wird im Body inkludiert; sichtbar nur wenn `ackOpen`/`reopenOpen` true.

**Tests:**

- `tests/templates/test_finding_inline_body.py` (neu, ~12 Tests):
  - Body rendert `risk_band_reason` + Action-Button bei `status='open'` mit „Abhaken …".
  - Body rendert „Re-open …" bei `status='acknowledged'`.
  - Body rendert Description, wenn `description` truthy ist; sonst kein Beschreibungs-Block.
  - Body rendert Primary-URL, wenn `primary_url` truthy ist; sonst kein Quelle-Block.
  - Body rendert References-Liste mit `target="_blank" rel="noopener noreferrer"`, jede URL als `<li>`.
  - Body rendert Notes-Thread (Include-Verifikation).
  - Body rendert Fallback-Hint bei `risk_band_reason is None`.
  - Body rendert keinen `|safe`-Filter auf Description/References/Primary-URL/Notes (Markup-Assert).
  - URL-Filter: Reference mit `javascript:` wird im Template gefiltert (defensive Double-Check).
  - DOM-ID `finding-<id>` bleibt auf dem `<details>`-Element für Tiefen-Links.
  - Action-Button hat `data-test="finding-action-btn-<id>"`.
  - Single-Source-Drift-Test: Initial-Render und HX-Fragment-Reload-Markup sind strukturell identisch (gleiche IDs, gleiches Klassen-Set).
- `tests/templates/test_finding_inline_body_xss.py` (neu, ~5 Tests, adversarial):
  - Description mit `<script>` ist autoescaped.
  - References mit `\"><script>` wird per Pydantic-Validator gar nicht erst persistiert; Template-Filter wäre Double-Defense.
  - Primary-URL mit `javascript:` ist per Pydantic null; Template-Filter ebenso.
  - Notes mit `<script>` werden per `markdown_safe` gestrippt (bestehender Test, Verifikation).
  - `risk_band_reason` mit `<script>` bleibt autoescaped (bestehender Test, Verifikation).

**DoD-C:**

1. `finding_inline_body.html` existiert und wird in `group_findings_table.html`, `triage_findings_page.html`, `bucket_findings_table.html`, `pending_bucket_findings_table.html` included.
2. Body rendert AI-Reason + Action-Button (rechts), Description, Primary-URL, References, Notes-Thread.
3. Keine Doppel-Daten zur Summary (kein CVSS/EPSS/KEV/Title/Paket im Body).
4. CSS-Klassen sind token-only; kein raw hex außerhalb von Header-Kommentaren.
5. Single-Source-Drift-Test grün.
6. XSS-Defense-Tests grün.
7. `ruff check . && ruff format --check . && mypy app/` PASS.
8. Default-`pytest` PASS, mindestens 17 neue Tests grün.

### Phase D — `?flat=1` + Flat-View + Detail-Modal entfernen

**Ziel:** Der alte Flat-Pfad ist komplett gelöscht. `_findings_section.html` rendert unkonditional die Group-View. Detail-Modal-Template ist gelöscht.

**Dateien:**

- `app/templates/servers/_view_list.html` **gelöscht**.
- `app/templates/findings/_detail_modal.html` **gelöscht**.
- `app/templates/_partials/pending_findings_table.html` **gelöscht** (durch `<details>`-Variante in Phase C ersetzt).
- `app/templates/servers/_findings_section.html` (Zeile 65–82): `_filters_active`/`_force_flat`/`_sort_default`-Block entfernen, Conditional entfällt, `{% include "servers/_view_groups.html" %}` unkonditional.
- `app/views/server_detail.py::_is_flat_mode` (Zeile 607–635) **gelöscht**.
- `app/views/server_detail.py::_render_findings_section`:
  - `flat_mode = _is_flat_mode(...)`-Branch entfernen.
  - `list_findings`-Call ersatzlos raus (war nur für Flat-Pfad).
  - Form-Objekte (`AcknowledgeForm`, `ReopenForm`, `NoteForm`, `BulkActionForm`, `CSRFOnlyForm`) jetzt unkonditional in den Context (`_load_application_groups_for_server`-Pfad).
- `app/views/server_detail.py::show` — `findings`-Context-Variable bleibt leer (`[]`) für Backward-Compat falls ein anderes Template darauf zugreift; nach Cleanup-Audit ggf. raus.
- `app/services/findings_query.py::list_findings` — Aufrufer prüfen (`grep -r "list_findings" app/`). Wenn nur noch von gelöschten Pfaden konsumiert: löschen. Sonst: behalten mit Hinweis im Docstring „nur noch von …".

**Tests-Migration:**

Die folgenden Test-Dateien rufen heute `?flat=1` auf. Sie werden migriert oder gelöscht:

- `tests/views/test_server_detail.py::test_is_flat_mode_*` (8 Tests) — **alle löschen** (Funktion existiert nicht mehr).
- `tests/integration/test_server_detail_db.py` (3 Stellen mit `?flat=1`) — Tests greifen auf Flat-Tabellen-Markup zu. Migration: Assert auf den neuen `<details>`-Body-Markup im Group-Drilldown statt auf die alte `<table>`-Struktur.
- `tests/integration/test_findings_section_cause_row_db.py` (5 Stellen mit `?flat=1`) — analog migrieren. Cause-Row (Block N) ist im Group-Drilldown sichtbar im erweiterten `<details>`-Body als Teil der Description/References — Test-Migration prüft die Marker-Spans im neuen Markup.
- `tests/integration/test_server_detail_action_required_db.py` (2 Stellen mit `?flat=1`) — analog.
- `tests/adversarial/test_purl_xss.py` (1 Stelle mit `?flat=1`) — XSS-Test prüft, ob `package_purl` mit `<script>` autoescaped wird. Migration: gleicher Assert gegen Group-Drilldown-Markup, oder gegen `finding_inline_body.html` direkt (bevorzugt, weil Pure-Unit-Template-Test schneller ist).
- `tests/adversarial/test_sort_param_injection.py` (1 Stelle mit `?flat=1`) — Sort-Param-Injection-Test war primär für die Sort-Header der Flat-Tabelle. Migration: behalten, aber Sort-Param-Validierung in der Group-View-Query prüfen. Falls Group-View keine User-steuerbare Sort hat (heute: hard-coded `risk desc`), Test als pytest.skip mit Hinweis auf Re-Open-Trigger (globaler Sort-Toggle).

**Doc-Updates:**

- `ARCHITECTURE.md` §17 (oder die einschlägige Sektion): `?flat=1` aus Liste der Operator-URL-Params entfernen.
- `CHANGELOG.md`: Block-AA-Eintrag, Tag-Vorschlag `v0.16.0`.
- `docs/decisions/0025-server-detail-and-findings-slim-down.md`: Status auf `Superseded by ADR-0041` setzen (Flat-Switch-Teil).
- `docs/decisions/README.md`: Status-Zeile für ADR-0025 + neue Zeile für ADR-0041.

**DoD-D:**

1. `app/templates/servers/_view_list.html`, `findings/_detail_modal.html`, `_partials/pending_findings_table.html` sind gelöscht.
2. `_is_flat_mode` und der Flat-Branch in `_render_findings_section` sind gelöscht.
3. `_findings_section.html` rendert unkonditional `_view_groups.html`.
4. `grep -r "flat=1" app/` liefert keine Treffer in `app/templates/`, `app/views/`, `app/services/`.
5. Alle migrierten Tests grün.
6. `ruff check . && ruff format --check . && mypy app/` PASS.
7. Default-`pytest` PASS, keine Regression. Erwartet: ~10–15 Test-Reduktion durch Löschung der `_is_flat_mode`-Tests.

### Phase E — Aufräumen + Operator-Smokes-Vorbereitung

**Ziel:** Stand prüfen, Reste aufräumen, Operator-Smoke-Checkliste schreiben.

**Dateien:**

- `app/services/findings_query.py::list_findings` — Aufrufer-Audit. Wenn keiner mehr konsumiert, löschen (separater Mini-Commit).
- `app/views/server_detail.py` — Imports von `AcknowledgeForm`, `ReopenForm`, `NoteForm`, `BulkActionForm`, `CSRFOnlyForm` jetzt unkonditional gebraucht; Import-Liste aufräumen.
- `app/views/findings.py` — gleicher Audit (`NoteForm` etc. ggf. neu importieren wenn nur in den Listen-Fragments gebraucht).
- `docs/blocks/STATE.md` — Block AA als ABGESCHLOSSEN eintragen mit Phasen-Übersicht (Vorlage: Block Z im STATE.md).

**Operator-Smokes (vor Merge auf `main`, vom User abzuhaken):**

1. `/servers/<id>` Default-View — Group-Drilldown rendert, Risk-Band-Sections aufgeklappt wie bisher.
2. Klick auf eine Finding-Row — Body öffnet sich mit AI-Reason links, „Abhaken …"-Button rechts.
3. Body zeigt Beschreibung, Primary-URL (klickbar, öffnet in neuem Tab), Reference-Liste (klickbar).
4. Body zeigt Notes-Thread; existierende Notes sichtbar; Add-Note-Form funktioniert (HTMX-Swap).
5. „Abhaken …"-Button öffnet Ack-Modal; Submit triggert HTMX-Swap des Notes-Thread (bestehendes Verhalten).
6. Bei `status='acknowledged'`: Button heißt „Re-open …" und öffnet Reopen-Modal.
7. Findings ohne `risk_band_reason` (Pass-2 noch nicht durch): Body zeigt Fallback-Hint, Body ist trotzdem aufklappbar.
8. `?flat=1` an die URL anhängen — wird ignoriert, gleiche Group-View rendert.
9. Filter setzen (Search, KEV-only, Status, Risk-Band) — Group-View bleibt der einzige Pfad, Filter narrowen die Anzeige (Group-Drilldown enthält nur passende Findings).
10. `/findings`-Cross-Server-View mit Filter — Bucket-Cards aufklappen, Klick auf Finding zeigt neuen Body.
11. Pending-Bucket aufklappen — Server-Spalte sichtbar im Summary, Body identisch zum normalen Bucket-Body.
12. Browser-Console: keine Errors, keine Warnings (HTMX-/Alpine-Init).
13. Sidebar-Polling läuft weiter, Heartbeat-Bar updated korrekt (kein Regression durch unkonditionalen Form-Object-Import).

**Bewusst weggelassen (Re-Open-Trigger aus ADR-0041 §Re-Open):**

- Globaler Sort-Toggle.
- CVSS-Vector + CWE-Liste im Body.
- Erstmals/Last-Seen-Spalte im Body.
- References/Description dem LLM mitgeben.
- HTMX-Lazy-Fragment-Variante.

**Tag-Vorschlag:** `v0.16.0` nach Branch-Merge auf `main` (gemäß [Tag-only-on-main-after-Merge]).

## Verifikations-Ziel-Kennzahlen (Block-Abschluss)

- **Default-`pytest`** PASS, erwartete Drift ~+30 neue Tests (5 + 9 + 17 = 31) − ~10–15 gelöschte Flat-Tests = netto **+15 bis +20 Tests**.
- **Linter/Type-Gates** alle grün.
- **Migration 0015** Up/Down/Up grün (db_integration, nur auf User-Anweisung).
- **Frontend-Build** (`cd frontend && npm run build`) PASS, neue CSS-Klassen im Manifest.
- **Operator-Smoke 1–13** vom User abgehakt.

## Phasen-Reihenfolge

A → B → C → D → E. Phase A und B sind unabhängig (A ist Schema, B ist Render-Pfad-Backend). Phase C baut auf B auf (braucht ORM-Findings im Render-Context). Phase D baut auf C auf (`_findings_section.html`-Cleanup setzt voraus, dass alle Templates auf den neuen Body umgestellt sind). Phase E ist Aufräumen.

## Risiken / Mitigation

| Risiko | Mitigation |
|---|---|
| Initial-DOM-Größe wächst durch eager-loaded Description/References. | Pagination ist klein (10–20 pro Page). Bei realen Fixtures median 1.2 KB Description, p95 6 KB — unkritisch. Tipping-Point >10 KB hätte Re-Open-Trigger (HTMX-Lazy-Fragment). |
| Test-Migration der `?flat=1`-Suite ist mechanisch und fehleranfällig. | Pro Test-Datei einzelner Commit, Reviewer prüft Assert-Migration explizit. Vorzug: Pure-Unit-Template-Tests gegen `finding_inline_body.html` direkt statt `?flat=1`-HTTP-Roundtrips (schneller, deterministischer). |
| Notes-Selectinload N+1-Falle bei großen Pages. | `selectinload` macht 1 zusätzlichen Roundtrip pro Listen-Query (nicht N). Verifiziert per SQL-Echo in Phase-B-Test. |
| Bestehende URL-Bookmarks mit `?flat=1` brechen Operator-Workflow. | Querystring wird stillschweigend ignoriert — Group-View rendert immer. Keine 404, kein Redirect, kein Hint. |
| Sort-Headers der Flat-Tabelle (CVE/Paket/EPSS/CVSS/Severity/Erstmals) waren Power-Feature. | Out-of-Scope für Block AA, dokumentiert als Re-Open-Trigger „globaler Sort-Toggle". |
| `pending_findings_table.html` löschen bricht die Pending-Sektion im Server-Detail. | Pending-Sektion wird in Phase C auf `<details>`-Pattern umgestellt; eigener HTMX-Endpoint nutzt das gleiche `finding_inline_body.html`-Partial. |

## Anhänge

- Layout-Mockup: [docs/design/FindingDetailInline.jsx](../design/FindingDetailInline.jsx) (+ companion `.html`).
- ADR: [docs/decisions/0041-finding-detail-inline.md](../decisions/0041-finding-detail-inline.md).
