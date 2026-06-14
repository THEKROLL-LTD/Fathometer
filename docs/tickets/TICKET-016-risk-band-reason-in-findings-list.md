# TICKET-016 — Risk-Band-Reason group-verschachtelt in den Findings-Listen sichtbar (TD-020 + TD-021)

**Status:** Offen · **Datum:** 2026-06-14
**Bündelt:** `docs/techdebt.md` TD-020 (Reason für `monitor`/`noise` nirgends sichtbar) und TD-021 (`risk_band_reason` bei 256 Zeichen abgeschnitten) — gemeinsames „Observability-Bündel".
**Bezug:** ARCHITECTURE.md §12 (LLM-Risk-Reviewer), ADR-0023 (Two-Pass), ADR-0028 (`application_group_evaluations`-Junction), ADR-0043 (Band = Exploitability), ADR-0052/TICKET-010 (OPEN-only-Eval-Input), ADR-0053/ADR-0061 (Fix-Lane-Evaluation), **ADR-0054 / TICKET-012 (Per-Finding-Reason entfernt — wird hier teilweise revidiert, siehe §1 und §6)**.
**Voraussichtlich neue Migration:** `0029_*` auf Head `0028_collapse_upstream_lane`.
**Voraussichtlich neue ADR:** `0065-*` (siehe §6).

---

## 0. Onboarding für den Implementer (Base noch nicht bekannt)

Diese App ist ein self-hosted Trivy-Scan-Aggregator (Flask + Jinja2 + HTMX + Alpine.js, PostgreSQL, single-user). Pflicht vor dem ersten Commit:

1. **`CLAUDE.md`** komplett lesen — insbesondere die **Test-Konvention** (nur `ruff`/`mypy`/`shellcheck` + Pure-Unit-`pytest` mit Bash-`timeout ≤ 120000`; **keine** db_integration/acceptance/integration/bench/bats/Docker/Browser-Tests proaktiv), das **HTMX-OOB-Single-Source-Pattern** und die **UI-Sprache-Regel** (UI-Strings ausschließlich Englisch, ADR-0045; Doc/Kommentare Deutsch).
2. **ADR-0054** (`docs/decisions/0054-per-finding-risk-band-reason-removed.md`) und **TICKET-012** (`docs/tickets/TICKET-012-ai-assessment-group-level-only.md`) lesen — sie sind die direkte Gegenentscheidung zu diesem Ticket und definieren die Falle, die wir nicht erneut bauen dürfen (§1).
3. **Datenmodell verstehen:** Die Reason ist **kein Per-Finding-Wert**. Sie lebt auf `ApplicationGroupEvaluation.risk_band_reason` — genau **eine** pro `(group_id, server_id, fix_lane)`-Junction-Row (bis zu drei Lanes pro Group: `patch`, `upstream`, `mitigate`). Sie beschreibt das **worst finding der Lane**, nicht das einzelne Finding.

**Erster Arbeitsschritt ist eine Gap-Analyse, kein Code:** Verifiziere pro Render-Kontext (unten §3), wo die Reason heute schon sichtbar ist und wo nicht. Die Server-Detail-Group-Cards zeigen die Lane-Reason bereits (`application_group_card.html`); die Findings-Page-Buckets und die flachen Drilldown-Tabellen zeigen sie seit TICKET-012 **nicht**. Halte die tatsächliche Lücke (insb. für `monitor`/`noise`) schriftlich fest, bevor du baust.

---

## 1. Problem & Historie (wichtig — nicht die alte Falle neu bauen)

**TD-020:** Die LLM-`risk_band_reason` erklärt, *warum* eine Lane in ihr Risk-Band eingestuft wurde — bei Downgrades (HIGH/CRITICAL-CVE → `monitor`) ist das die wichtigste Information für den Operator. Heute ist sie für `monitor`/`noise`-Findings in den **Findings-Listen** praktisch unsichtbar: Der Operator muss „blind" glauben, dass die De-Priorisierung stimmt. Befund 2026-06-13 (k3s-sv-*): `tailscaled CVE-2026-42504` → `monitor` mit korrekter Begründung („MIME-decode flaw unlikely to be triggered by WireGuard…"), für den Operator aber unsichtbar.

**TD-021:** `ApplicationGroupEvaluation.risk_band_reason` ist `String(256)`; der Pass-2-Worker cappt die LLM-Reason auf 256 (`risk_engine._truncate`). Reasons brechen mitten im Satz ab — gerade die entscheidende „welche Exposure-Schicht fehlt"-Aussage steht laut ADR-0043 oft am **Satzende** und wird abgeschnitten („…unlikely to be triggered by WireGuard or", „Multiple CRITICAL gRPC authz", „No attack path" fehlt).

**Historie — die Falle:** TICKET-012 / ADR-0054 (2026-06-11) hat die Reason bewusst **aus den vier Findings-Listen-Templates entfernt** und die (denormalisierte) Spalte `findings.risk_band_reason` gedroppt. Grund: Die Reason wurde **pro Finding-Zeile** als „AI ASSESSMENT" gerendert und beschrieb dort das *worst finding der Group* statt des Findings in der Zeile (`worst_finding_drift`). Auf der Karte eines patchbaren HIGH-Findings stand z. B. „… critical kernel flaw, **no fix**" (= Schwester-CVE). Das wirkte wie ein Widerspruch zur angezeigten Fix-Version.

**Konsequenz für dieses Ticket:** Wir bringen die Reason zurück, aber **nicht** als Per-Finding-Box. Die Reason wird **auf Group-/Lane-Ebene** gerendert (einmal, korrekt verortet), die aufklappbaren Finding-Zeilen darunter bleiben **unverändert** ohne Reason. Damit ist TD-020 erfüllt und die ADR-0054-Falle (Per-Finding-Mislabeling + Drift-Verwechslung) ausgeschlossen.

---

## 2. Ziel (Soll-Zustand)

In **beiden** Listen-Kontexten — **Server-Detail-Findings-Liste** und **Findings-Page** — werden die Findings **nach Group verschachtelt** dargestellt (analog zur Operator-Workflow-Tabelle `_action_needed_section.html`). Die `risk_band_reason` erscheint **einmal auf Group-/Lane-Ebene** über den zugehörigen Findings, **für alle Bänder inklusive `monitor` und `noise`** — nicht nur `act`/`escalate`. Die darunter aufklappenden Finding-Zeilen (`finding_inline_body.html`) bleiben unverändert.

Der **Operator-Workflow ändert sich nicht** in seiner Logik: `_action_needed_section.html` zeigt bereits `act`/`escalate` mit Reason. Hier wird nur die gemeinsame Truncation-UI (§4) übernommen, weil die Reason ab jetzt länger als 256 Zeichen sein kann.

Die volle, nicht abgeschnittene Reason wird gespeichert (§5) und in der UI **smart** dargestellt: gekürzt auf X Zeichen mit einem design-konformen „Show all"-Toggle (§4).

---

## 3. Render-Kontexte & betroffene Komponenten

**Datenquelle (für alle Kontexte gleich):** `ApplicationGroupEvaluation` pro `(group_id, server_id, fix_lane)`. Die Lane eines Findings folgt deterministisch aus `Finding.finding_class` + `Finding.has_fix` + `Finding.host_update_available` über die Single-Source `risk_engine.fix_lane_sql_case` (siehe `app/services/finding_group_inheritance.py`). **Keine** denormalisierte Finding-Spalte wieder einführen — die Reason wird im View geladen und ins Template gereicht.

| Kontext | Template(s) | View / Service | Reason heute? |
|---|---|---|---|
| **Server-Detail — Group-Cards** (einziger Render-Pfad, Block AA) | `servers/_findings_section.html` → `servers/_view_groups.html` → `_partials/application_group_card.html` | `app/views/server_detail.py` (Group-Card-Builder, lädt `evaluations_by_lane`, ~Z. 335–470) | **Ja**, Lane-Reason im `sd-app-group__reason`-Block (`application_group_card.html` ~Z. 88–96). **Verifizieren:** rendert sie auch für `monitor`/`noise`-Lanes? Falls eine Lücke besteht, hier schließen. |
| **Server-Detail — Group-Drilldown** (lazy beim Aufklappen) | `_partials/group_findings_table.html` | `server_detail.py::group_findings_fragment` (~Z. 1056) | Nein (flache Finding-Tabelle, Reason steht im Card-Header darüber → ok, solange Card-Reason vollständig ist) |
| **Server-Detail — Pending-Grouping** (Findings ohne Group) | `_partials/group_findings_table.html` | `server_detail.py::pending_findings_fragment` (~Z. 1118) | Nein. Pending-Findings haben **keine** Group-Eval → es gibt keine LLM-Reason. Im Ticket bestätigen und so belassen (kein Fake-Reason). |
| **Findings-Page — Buckets** `(server, group)` | `findings/index.html` → `_partials/bucket_card.html` → `_partials/bucket_findings_table.html` | `app/views/findings.py::bucket_fragment` (~Z. 263) + `app/services/findings_bucket_query.py::list_bucket_findings` (~Z. 370) | **Nein** — Hauptlücke. Bucket-Body ist eine **flache** paginierte Finding-Liste ohne Group-/Lane-Reason. |
| **Findings-Page — Pending-Bucket** (cross-server, ohne Group) | `_partials/pending_bucket_findings_table.html` | `findings.py::pending_fragment` (~Z. 328) | Nein, und keine Group-Eval vorhanden → keine Reason (wie oben). |
| **Operator-Workflow** | `servers/_action_needed_section.html` | `server_detail.py` (Action-Sections) | **Ja** (`act`/`escalate`). Nur Truncation-UI übernehmen (§4). |

**Single-Source-Body unverändert:** `_partials/finding_inline_body.html` bekommt **keine** Reason zurück (das war der ADR-0054-Fehler). Nicht anfassen außer ggf. Kommentar-Update.

### 3a. Kernkomplexität — Findings-Page (vom Operator explizit benannt)

Auf der Findings-Page ist der Bucket bereits `(server, group)`-verschachtelt, **aber** ein Bucket kann Findings **mehrerer Lanes** enthalten (`patch`/`upstream`/`mitigate`), und jede Lane hat ihre **eigene** Reason und ihr eigenes Band. Die Reason „auf Group-Ebene" heißt deshalb konkret **pro Lane innerhalb des Buckets**, nicht einmal pro Bucket.

Heute ist `bucket_findings_table.html` eine **flache, lane-agnostische** Liste mit `page`-basierter Pagination (`bucket_fragment`, `list_bucket_findings`). Das group/lane-verschachtelte Sollbild erfordert einen Umbau von **Gruppierung _und_ Pagination + HTMX-Nachladen**:

- Findings im Bucket nach Lane gruppieren, pro Lane einen Reason-Header (mit Band) voranstellen, darunter die unveränderten Finding-Zeilen.
- Die Pagination muss lane-stabil bleiben (eine Reason darf nicht ohne ihre Findings auf einer Seite landen und umgekehrt). Mögliche Strategien, die der Implementer im Plan abwägt und in der ADR (§6) festhält:
  - (a) Reason-Header pro Lane auf **jeder** Seite wiederholen (einfachste Pagination-Änderung, leichte Redundanz über Seitengrenzen),
  - (b) Lane-aware Pagination (Seiten brechen nur an Lane-Grenzen), oder
  - (c) Lane-Sub-Buckets als eigene aufklappbare HTMX-Slots mit je eigener Pagination.

  **Empfehlung:** (a) als kleinster, drift-armer Eingriff, sofern die Bucket-Counts im Header (`bucket_card.html`) stimmig bleiben. Endgültige Wahl trifft der Implementer im Plan; Begründung in die ADR.

> Bevor du `bucket_fragment`/`list_bucket_findings` umbaust: prüfe, ob die Reason-Header die `total`-/`per_page`-Semantik des Pagers (`bucket_findings_table.html` Footer) verschieben. Counts müssen weiter die **Findings** zählen, nicht die Header.

---

## 4. UI — Smart-Truncation (TD-021-Anzeigeteil)

Die Reason kann ab §5 deutlich länger als 256 Zeichen sein. Jeder Render-Ort muss sie **smart** darstellen:

- Standardmäßig auf **X Zeichen** gekürzt anzeigen (Vorschlag X ≈ 160; finaler Wert design-getrieben, am bestehenden `sd-ai-text`-Look der Group-Card ausrichten), gefolgt von einem **„Show all"**-Toggle, der den vollen Text design-konform aufklappt (und idealerweise wieder einklappt).
- Implementierung **client-seitig mit Alpine.js** (kein zusätzlicher Request, kein neuer Endpoint), Toggle per `x-data`/`x-show`. **Kein DaisyUI**, nur eigene Design-Tokens/Plain-CSS. Kürzung an Wortgrenze, kein hartes Abschneiden mitten im Wort.
- **Sicherheit:** Reason ist LLM-Output → **niemals `|safe`**, Jinja-Autoescape ist Pflicht (ADR-0038 §G4). Der volle Text liegt im DOM (autoescaped) und wird nur per CSS/Alpine ein-/ausgeblendet — kein zweiter Fetch nötig.
- **A11y:** Toggle ist ein echter `<button>` mit `aria-expanded`; gekürzter Zustand nicht nur via `title`/Tooltip (der bestehende `wf-reason-info`-Hilfe-Tooltip in `_action_needed_section.html` bleibt davon unberührt).

**Single-Source-Pflicht (CLAUDE.md §HTMX-OOB-Single-Source-Pattern):** Die Reason-Anzeige inkl. Truncation/Toggle wird **einmal** als wiederverwendbares Jinja-Partial oder `_macros.html`-Makro implementiert (z. B. `_partials/_reason_block.html` / `macro reason_block(reason, band)`) und an **allen** Render-Orten inkludiert: `application_group_card.html`, `_action_needed_section.html`, und der neue Findings-Page-Lane-Header. Kein kopiertes Markup → kein Drift. Das verhindert genau den Klassen-/ID-Drift, der im Block-W-Heartbeat-Bug zwei Wochen unbemerkt blieb.

---

## 5. Schema & Worker — volle Reason speichern (TD-021-Speicherteil)

Entscheidung Operator (2026-06-14): **`Text` (unbegrenzt)**, nicht `String(1024)`.

1. **Modell:** `ApplicationGroupEvaluation.risk_band_reason` von `String(256)` auf `Text` (nullable bleibt) in `app/models.py` (~Z. 1014).
2. **Migration:** Neue Alembic-Migration `0029_*` auf Head `0028_collapse_upstream_lane`. `ALTER COLUMN … TYPE TEXT` (Postgres: in-place, kein Rewrite-Risiko bei Vergrößerung). **Downgrade** zurück auf `VARCHAR(256)` — Achtung: bestehende Reasons könnten dann > 256 sein; Downgrade muss die Längen-Reduktion sauber handhaben (truncate beim Downgrade oder dokumentierter Daten-Verlust-Hinweis). Single-Head wahren.
3. **Worker-Cap entfernen/anheben:** `app/services/risk_engine.py` — `_REASON_MAX_LENGTH = 256` (~Z. 309) und `_truncate` (~Z. 405). Die Pass-2-Reason soll nicht mehr auf 256 gecappt werden. Optionen: `_truncate` für die Group-Reason ganz entfernen, **oder** Cap stark anheben (z. B. ein defensives Limit gegen entartete Mega-Outputs, z. B. 8 KB) — Operator-Wunsch ist „unbegrenzt", also Default = kein fachliches Cap, höchstens ein defensiver Schutz-Cap. Begründung in den Code-Doc/ADR. **Prüfen:** `_truncate` wird auch für **Pre-Triage**-Reasons benutzt (`risk_engine.py` ~Z. 338/367/375/382) — diese bleiben kurz; die Cap-Änderung darf die Pre-Triage-Strings nicht ungewollt verändern. Falls nötig getrennte Cap-Konstanten.
4. **Worker-Write:** `app/workers/llm_worker.py` schreibt `risk_band_reason=reason` in die Junction (~Z. 1966/1977, Upsert). Sicherstellen, dass nach Cap-Entfernung die volle Reason ankommt; LLM-Debug-Log-Pfad (`reason_f = str(...)[:16384]`, ~Z. 1853) ist davon unabhängig und bleibt.

> **Kein** Wiederbeleben von `findings.risk_band_reason` (in Migration 0021 gedroppt). Die Finding-Vererbung (`finding_group_inheritance.py`) bleibt schlank (`risk_band` + `risk_band_source`).

---

## 6. ADR-Pflicht

Dieses Ticket revidiert ADR-0054 für den Listen-Kontext (Reason war dort entfernt). Entscheidung Operator (2026-06-14): **neue ADR** `0065-*` anlegen, die ADR-0054 **amendiert** (nicht ablöst):

- Festhalten: Per-Finding-Reason bleibt verworfen (ADR-0054 gilt weiter für die Finding-Zeile / `finding_inline_body.html`).
- Neu: Reason wird **group-/lane-verschachtelt** in beiden Listen-Kontexten gezeigt, korrekt als Lane-Level-Assessment gelabelt, inkl. `worst_finding_drift`-Hint-Konsistenz mit der Group-Card/Action-Needed-Tabelle.
- Begründung der gewählten Pagination-Strategie (§3a) dokumentieren.
- `risk_band_reason` → `Text`, Worker-Cap-Politik.

Querverweis in `docs/techdebt.md`: TD-020 und TD-021 nach Umsetzung als erledigt markieren und auf TICKET-016 / ADR-0065 verlinken (Konvention `docs/techdebt.md` §Konventionen — „Wenn ein TD durch einen anderen obsolet wird, kreuzweise verlinken").

---

## 7. Definition of Done (maschinell prüfbar, wo möglich)

- [ ] **Gap-Analyse** (§0/§3) schriftlich im PR: pro Kontext belegt, wo Reason heute fehlt; `monitor`/`noise`-Sichtbarkeit auf der Server-Detail-Group-Card verifiziert/geschlossen.
- [ ] **Findings-Page:** Bucket-Body zeigt die Lane-Reason group-/lane-verschachtelt für **alle** Bänder (inkl. `monitor`/`noise`); aufklappbare Finding-Zeilen unverändert. Pagination + HTMX-Nachladen (`bucket_fragment`/`list_bucket_findings`/`bucket_findings_table.html`) funktioniert mit der neuen Struktur; Pager-Counts zählen weiter Findings.
- [ ] **Server-Detail:** Lane-Reason für `monitor`/`noise` sichtbar (Group-Card oder, falls dort vorhanden, bestätigt unverändert). Operator-Workflow logisch unverändert.
- [ ] **Reason-Anzeige** ist ein **einziges** Partial/Makro, inkludiert in `application_group_card.html`, `_action_needed_section.html` und dem neuen Findings-Page-Lane-Header (kein dupliziertes Markup).
- [ ] **Smart-Truncation:** gekürzte Anzeige + „Show all"-Toggle (Alpine, `aria-expanded`, kein DaisyUI, Wortgrenzen-Kürzung); voller Text autoescaped im DOM, **kein `|safe`**.
- [ ] **Schema:** `ApplicationGroupEvaluation.risk_band_reason` ist `Text`; Migration `0029_*` Single-Head; `alembic upgrade head && downgrade -1 && upgrade head` grün (**Heavy-Suite → Operator-Lauf**, siehe §8).
- [ ] **Worker-Cap:** Pass-2-Reason wird nicht mehr auf 256 gecappt; Pre-Triage-Reasons unverändert. `grep` belegt, dass kein Render-Pfad die Reason auf 256 begrenzt.
- [ ] **Kein** `findings.risk_band_reason` reaktiviert; `finding_inline_body.html` ohne Per-Finding-Reason (`grep`: Per-Finding-Templates referenzieren weiterhin **kein** `risk_band_reason`).
- [ ] **Drift-Regression** (Pure-Unit): Test, der den/die Reason-Render-Pfad(e) mit identischen Fixtures vergleicht (gleiches Partial/Makro, gleiche IDs/Klassen, Truncation-Toggle vorhanden). Vorhandene Drift-Tests (`test_application_group_card_drift`, `test_action_needed_drift_hint`, `test_finding_inline_body_drift`) bleiben grün.
- [ ] **ADR-0065** angelegt; TD-020/TD-021 in `docs/techdebt.md` als erledigt + kreuzverlinkt.
- [ ] `ruff check . && ruff format --check .` grün.
- [ ] `mypy app/` grün.
- [ ] `pytest` (Default-/Pure-Unit-Selektion, Bash-`timeout ≤ 120000`) grün; betroffene Template-Render-Tests (`test_bucket_findings_table_render`, `test_pending_bucket_findings_table_render`, `test_finding_inline_*`, Group-Card-Render) angepasst.

---

## 8. Test- & Prozess-Leitplanken (verbindlich, aus CLAUDE.md)

- **Erlaubte Quality-Gates:** `ruff`, `ruff format --check`, `shellcheck`, `mypy app/`, `pytest` **Default-Selektion** (Pure-Unit). Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).
- **Verboten (keine proaktiven Aufrufe, keine neuen `.bats`/`.sh`-Test-Dateien):** db_integration / acceptance / integration / bench / `RUN_E2E` / Docker-Compose / Browser-Tests. Der **Alembic-Roundtrip** und etwaige Postgres-Reflection-Tests laufen **nur auf ausdrückliche Operator-Anweisung** — sonst das DoD-Item „beim Operator anstehen lassen" markieren.
- **UI-Sprache:** alle neuen Operator-sichtbaren Strings **Englisch** (ADR-0045; `tests/test_ui_language.py`). „Show all"/„Show less" o. ä. englisch.
- **Doc-/Kommentar-Sprache:** Deutsch.
- **Keine Pflicht-Kommentare/Eingaben** in der UI (ADR-006) — der „Show all"-Toggle ist rein optional/lesend.
- **Sicherheit:** kein `|safe` auf LLM-/Client-Daten; SQLAlchemy nur mit gebundenen Parametern.

---

## 9. Empfohlene Umsetzungs-Reihenfolge

1. Gap-Analyse (§0/§3) + ADR-0065-Entwurf (Pagination-Strategie festlegen).
2. Schema/Worker (§5): Modell → Migration `0029` → Cap-Politik in `risk_engine` → Worker-Write prüfen. (Migration-Roundtrip dem Operator zum Lauf übergeben.)
3. Reason-Partial/Makro (§4) mit Smart-Truncation; zuerst in den **bestehenden** Render-Orten (`application_group_card.html`, `_action_needed_section.html`) einsetzen — sofort sichtbar, kleiner Blast-Radius.
4. Findings-Page-Umbau (§3a): Lane-Gruppierung + Reason-Header + Pagination/HTMX in `bucket_fragment` / `list_bucket_findings` / `bucket_findings_table.html`.
5. Drift-/Render-Tests, `ruff`/`mypy`/`pytest`.
6. `docs/techdebt.md` TD-020/TD-021 abschließen + kreuzverlinken.
