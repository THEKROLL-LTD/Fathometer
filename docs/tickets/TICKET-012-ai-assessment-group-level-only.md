# TICKET-012 — AI-Assessment ist Group-Level, raus aus der Per-Finding-Liste

**Status:** Umgesetzt (Migration-Roundtrip beim Operator anstehend) · **Datum:** 2026-06-11 · **Bezug:** ARCHITECTURE.md §12, ADR-0023 (Two-Pass), ADR-0028 (application_group_evaluations-Junction), ADR-0052 / TICKET-010 (OPEN-only-Eval-Input), **ADR-0054** (Entscheidung + Schema-Drop).
**Komponenten:** `app/templates/_partials/finding_inline_body.html`, `app/templates/_partials/bucket_findings_table.html`, `app/templates/_partials/pending_bucket_findings_table.html`, `app/templates/_partials/group_findings_table.html`, `app/templates/servers/_partials/triage_findings_page.html`; `app/models.py` (Finding), `app/services/finding_group_inheritance.py`, `app/services/scan_processing.py`, `app/services/risk_engine.py`, `alembic/versions/0021_drop_findings_risk_band_reason.py`. Tests.
**Umfang (revidiert, User-Entscheidung 2026-06-11):** Nicht mehr UI-Only — das Per-Finding-Feld `Finding.risk_band_reason` wird **komplett entfernt** (Modell + Migration + beide Schreibseiten), kein TD-Eintrag. Das Group-Level-Feld `ApplicationGroupEvaluation.risk_band_reason` bleibt unangetastet. Begründung des Hard-Delete siehe ADR-0054 und gelöste Offene Frage unten.

## Problem (Befund 2026-06-11, Triage-Queue CVE-2026-31431)

Die „AI ASSESSMENT"-Box wird pro Finding-Zeile gerendert (`finding_inline_body.html:33–39`
und Schwester-Tables), zieht ihren Text aber aus `Finding.risk_band_reason`. Dieser Wert
ist **kein Per-Finding-Wert**: Pass 2 bewertet ganze Application-Groups, der `reason`
beschreibt das *worst finding* der Group, und `finding_group_inheritance.inherit_group_risk_to_findings`
vererbt genau diesen einen Group-Reason auf **jedes** OPEN-Finding der Group
(`scan_processing.py:255`, Quelle `ApplicationGroupEvaluation.risk_band_reason`).

Folge: Auf der Karte von CVE-2026-31431 (HIGH, Fix `6.8.0-117.117` verfügbar) steht eine
Bewertung, die wörtlich über einen Schwester-CVE redet:
„… CVE-2026-43304 (id 1056936) critical network-vector kernel flaw, **no fix**."
Das wirkt wie ein Widerspruch („wir zeigen eine Fix-Version, das LLM sagt no fix"), ist
aber korrekt: die Fix-Version gehört zu CVE-2026-31431, die Bewertung zur Group (worst =
CVE-2026-43304). Genau die `worst_finding_drift`-Situation — der Drift-Hint existiert für
die Group-Card (`application_group_card.html:44–49`) und die Action-Needed-Tabelle
(`_action_needed_section.html:64`), **fehlt aber im Per-Finding-Inline-Body**, weshalb die
Verwechslung dort ungebremst durchschlägt.

## Entscheidung (User, 2026-06-11)

Ein AI-Assessment gehört auf die **Application-Group**, nicht in die einzelne Finding-Zeile.
Die Per-Finding-Anzeige der „AI ASSESSMENT"-Box wird entfernt; die Bewertung bleibt
ausschließlich auf der Group-Card sichtbar.

## Lösung

Per-Finding-Render von `risk_band_reason` aus den Findings-Listen entfernen:

- `finding_inline_body.html` — den `risk_band_reason`-Block (`sd-ai-eyebrow` + `sd-ai-text`)
  inkl. „AI assessment pending"-Fallback streichen.
- `bucket_findings_table.html`, `pending_bucket_findings_table.html`,
  `group_findings_table.html`, `triage_findings_page.html` — analoge Inline-„KI-Bewertung"
  entfernen (alle ziehen aus `risk_band_reason`).
- Group-Card (`application_group_card.html`) bleibt **unverändert** — dort ist die Bewertung
  korrekt verortet, inkl. Drift-Hint.

## Definition of Done (maschinell prüfbar)

- [x] Kein Template unter `app/templates/` rendert `risk_band_reason` mehr auf
      Finding-Ebene (grep: nur noch `application_group_card.html` und
      `_action_needed_section.html` referenzieren `risk_band_reason`).
- [x] `Finding.risk_band_reason` ist aus `app/models.py` entfernt;
      `not hasattr(Finding, "risk_band_reason")` (Regressionstest in
      `test_finding_group_inheritance.py`).
- [x] Migration `0021_drop_findings_risk_band_reason` droppt
      `findings.risk_band_reason` (Downgrade re-added nullable). Single-Head.
- [x] `finding_group_inheritance` und `scan_processing` schreiben das Feld
      nicht mehr; Idempotenz-OR-Bedingung ohne `risk_band_reason`-Term.
- [x] `ruff check . && ruff format --check .` grün.
- [x] `mypy app/` grün.
- [x] `pytest` (Default-Selektion) grün; betroffene Template-Render-Tests
      (`test_finding_inline_*`, `test_bucket_findings_table_render`,
      `test_pending_bucket_findings_table_render`) angepasst, sodass sie das
      Fehlen der Per-Finding-AI-Box prüfen statt ihre Anwesenheit.
- [x] Drift-Regression bleibt: Group-Card-Drift-Tests (`test_application_group_card_drift`,
      `test_action_needed_drift_hint`) unverändert grün.
- [ ] **Operator:** `alembic upgrade head && downgrade -1 && upgrade head`
      grün (Heavy-Suite, nicht im Pure-Unit-Lauf); db_integration-Suiten
      (`test_block_o_schema`, `test_llm_worker_db`, …) wurden an das neue
      Schema angepasst, aber nicht ausgeführt.

## Offene Frage — GELÖST (2026-06-11)

`Finding.risk_band_reason` wird nach Entfernen der UI-Box **nirgends** mehr
gelesen: CSV-Export (`FINDINGS_CSV_COLUMNS` / `…_CROSS`) führt es nicht,
`FindingsSortKey` sortiert über `risk_band` (nicht `_reason`), Worst-Finding-
Logik läuft über `worst_finding_id`/`risk_band`. Das Feld war toter Ballast →
Hard-Delete statt TD-Eintrag (siehe ADR-0054).
