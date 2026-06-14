# ADR-0065 — Risk-Band-Reason group-/lane-verschachtelt in Findings-Listen sichtbar

**Status:** Akzeptiert · **Datum:** 2026-06-14
**Bezug / amendet:** ADR-0054 (Per-Finding-Reason bleibt verworfen), ADR-0028 (Junction), ADR-0053 (Fix-Lane-Evaluation), TICKET-016 (TD-020 + TD-021).
**Tangiert:** ADR-0043 (Band = Exploitability — Reason-Begründungspflicht).

## Kontext

TD-020: Die LLM-`risk_band_reason` erklärt *warum* eine Lane in ihr Band eingestuft wurde. Bei Downgrades (HIGH/CRITICAL → `monitor`) ist das die wichtigste Information für den Operator. Sie war für `monitor`/`noise`-Lanes in den Findings-Listen praktisch unsichtbar.

TD-021: `ApplicationGroupEvaluation.risk_band_reason` war `String(256)`; der Pass-2-Worker cappte auf 256 Zeichen. Reasons brachen mitten im Satz ab — gerade die „welche Exposure-Schicht fehlt"-Aussage (ADR-0043) stand oft am Satzende und wurde abgeschnitten.

ADR-0054 hat die Reason bewusst **aus den Finding-Zeilen** entfernt, weil sie dort das *worst finding der Group* beschrieb statt des Einzel-Findings (`worst_finding_drift`). Diese Gegenentscheidung gilt weiter.

## Entscheidung

### 1. Reason-Bleibt-Group-/Lane-Level (ADR-0054 gilt weiter)

Die Reason wird **nicht** als Per-Finding-Spalte reaktiviert (`findings.risk_band_reason` wurde in Migration 0021 gedroppt und bleibt weg). Sie wird stattdessen **einmal pro Lane** über den zugehörigen Findings gerendert — korrekt verortet als Group-/Lane-Level-Assessment.

### 2. Sichtbarkeit in beiden Listen-Kontexten

| Kontext | Änderung |
|---|---|
| **Server-Detail Group-Card** (`application_group_card.html`) | Bereits sichtbar für alle Bänder (inkl. monitor/noise). Keine Logik-Änderung — nur Übernahme des neuen Truncation-Partials (§4). |
| **Server-Detail Operator-Workflow** (`_action_needed_section.html`) | Nur act/escalate sichtbar (by design). Truncation-Partial übernehmen. |
| **Findings-Page Bucket-Body** (`bucket_findings_table.html`) | **Neu:** Lane-Reason-Header pro Lane innerhalb des `(server, group)`-Buckets. Die aufklappbaren Finding-Zeilen (`finding_inline_body.html`) bleiben unverändert ohne Reason. |
| **Pending-Buckets** | Keine Group-Eval → keine Reason. Kein Fake-Reason. |

### 3. Findings-Page-Pagination-Strategie

**Gewählt: Strategie (a)** — Reason-Header pro Lane auf **jeder** Seite wiederholen.

- Der Bucket-Body wird nach `fix_lane` gruppiert. Pro nicht-leerer Lane wird ein Header (Band-Badge + Reason-Block) gerendert, gefolgt von den Finding-Zeilen dieser Lane.
- Bei Paginierung über Lane-Grenzen hinweg erscheint der Lane-Header auf der neuen Seite erneut. Das ist minimale Redundanz, aber:
  - Keine Änderung an der Pagination-Arithmetik (COUNT/LIMIT/OFFSET zählen weiterhin Findings, nicht Header).
  - Kein komplexes „Lane-aware OFFSET"-Rechnen.
  - HTMX-Nachladen (`bucket_fragment`) bleibt ein einfacher `page`-Parameter.
  - Kein Drift-Risiko zwischen Initial-Render und OOB-Response.

**Strategie (b)** (Seiten brechen nur an Lane-Grenzen) wurde verworfen: bei ungleich verteilten Lanes würde eine Seite mit 19 patch-Findings und 1 mitigate-Finding leer aussehen, oder wir müssten die `per_page` dynamisch anpassen.

**Strategie (c)** (Lane-Sub-Buckets als eigene aufklappbare HTMX-Slots mit je eigener Pagination) wurde verworfen: zu viele neue Endpunkte/Fragmente, komplexeres HTMX-Swap-Targeting, höheres Drift-Risiko.

### 4. Smart-Truncation-UI (TD-021-Anzeigeteil)

Die Reason kann ab §5 deutlich länger als 256 Zeichen sein. Jeder Render-Ort nutzt ein **einziges** wiederverwendbares Jinja-Element. **Umgesetzt als Macro `reason_block(reason, limit=160)` in `_macros.html`** (statt eines eigenen Partial-Files — funktional gleichwertig, fügt sich in die bestehende Macro-Sammlung der Triage-UI ein):

- Standardmäßig auf **~160 Zeichen** gekürzt (Wortgrenze via Jinja-`truncate`, `killwords=False`, kein hartes Abschneiden).
- „Show all" / "Show less"-Toggle per Alpine.js (`x-data`/`x-show`), client-seitig, kein zusätzlicher Request.
- Echter `<button>` mit `aria-expanded`.
- Voller Text liegt autoescaped im DOM (Jinja-Autoescape) und wird nur per CSS/Alpine ein-/ausgeblendet — **kein** `|safe`, kein DaisyUI, nur eigene Design-Tokens (`.reason-block*`).

Single-Source-Pflicht (CLAUDE.md §HTMX-OOB-Single-Source-Pattern): Das Macro wird in `application_group_card.html`, `_action_needed_section.html` und dem Findings-Page-Lane-Header (`bucket_findings_table.html`) inkludiert. Kein kopiertes Markup.

### 5. Schema — volle Reason speichern (TD-021-Speicherteil)

**`ApplicationGroupEvaluation.risk_band_reason` wird von `String(256)` auf `Text` geändert** (nullable bleibt).

- Migration `0029_*` auf Head `0028_collapse_upstream_lane`: `ALTER COLUMN risk_band_reason TYPE TEXT` (Postgres: in-place bei Vergrößerung, kein Rewrite-Risiko).
- **Downgrade:** `ALTER COLUMN … TYPE VARCHAR(256) USING LEFT(…, 256)`. Hinweis: bestehende Reasons >256 Zeichen werden beim Downgrade still auf 256 abgeschnitten; der Daten-Verlust ist dokumentiert und akzeptiert.
- Single-Head wahren.

### 6. Worker-Cap-Politik

**Pass-2-Reason wird nicht mehr auf 256 Zeichen gecappt.** Der Worker schreibt die volle Reason in die Junction.

- `app/services/risk_engine.py`: Die Konstante `_REASON_MAX_LENGTH = 256` und die Funktion `_truncate()` werden **nicht** für Pass-2-Reasons mehr verwendet. Stattdessen wird `_truncate` nur noch für **Pre-Triage-Reasons** benutzt (kurze, deterministisch generierte Strings — unverändertes Verhalten).
- **Defensiver Schutz-Cap:** Um entartete Mega-Outputs zu verhindern (z.B. Modell-Halluzination mit 50k Zeichen), führt `_upsert_evaluation` einen harten Schutz-Cap von **8 KiB** ein. Dies ist kein fachliches Limit, sondern ein Safety-Net gegen Speicher-/DB-Anomalien. Der Cap wird im Code kommentiert.
- `llm_debug_log` speichert weiterhin `reason_f = str(...)[:16384]` — davon unberührt.

### 7. Kein Per-Finding-Reason

`finding_inline_body.html` bekommt keine Reason zurück. `grep`-Check: `bucket_findings_table.html` und `pending_bucket_findings_table.html` referenzieren weiterhin kein `risk_band_reason` auf Finding-Ebene.

## Konsequenzen

- **Positiv:** Operator sieht für alle Bänder (inkl. monitor/noise) *warum* eine Lane eingestuft wurde. Reasons sind nicht mehr abgeschnitten. Einheitliche Truncation-UI verhindert Drift.
- **Schema:** Migration `0029_*` notwendig. Alembic-Roundtrip muss grün sein (Operator-Verifikation).
- **Tests:** Neue Pure-Unit-Tests für das Truncation-Partial (Render mit Fixture, Toggle-Präsenz, Wortgrenzen-Kürzung). Bestehende Drift-Regressionstests bleiben grün.
- **UI-Sprache:** Neue Strings "Show all" / "Show less" auf Englisch (ADR-0045).

## Querverweise

- `docs/techdebt.md` TD-020, TD-021 — nach Umsetzung als erledigt markieren.
- `docs/tickets/TICKET-016-risk-band-reason-in-findings-list.md` — Implementierungs-Spec.
