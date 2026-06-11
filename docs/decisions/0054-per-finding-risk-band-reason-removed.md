# ADR-0054 — AI-Assessment ist Group-Level: Per-Finding-`risk_band_reason` entfernt

**Status:** Akzeptiert · **Datum:** 2026-06-11
**Bezug / erweitert:** ADR-0023 (LLM-Risk-Reviewer, Two-Pass), ADR-0028 (`application_group_evaluations`-Junction), ADR-0052 / TICKET-010 (OPEN-only-Eval-Input), TICKET-012 (Umsetzung). **Tangiert** ADR-0053 (Fix-Lane-Evaluation — die Reason-Quelle bleibt Group-/Lane-Level).
**Löst ab:** den Per-Finding-Anteil der Block-O-Schema-Erweiterung (Migration 0004) und der Block-T-Vererbung (ADR-0028).

## Kontext

Pass 2 bewertet **ganze Application-Groups**, nicht einzelne Findings: Ein
`ApplicationGroupEvaluation` trägt genau **ein** `(risk_band, reason,
worst_finding_id)` pro `(group, server)`-Junction (ADR-0028). Der `reason`
beschreibt das *worst finding* der Group.

Block T (`finding_group_inheritance.inherit_group_risk_to_findings`) hat diesen
einen Group-Reason auf die Finding-Spalte `Finding.risk_band_reason`
(Migration 0004, Block O) **jedes** OPEN-Findings der Group vererbt, und die
vier Listen-Templates haben ihn pro Finding-Zeile als „AI ASSESSMENT"-Box
gerendert (`finding_inline_body.html`).

Befund 2026-06-11 (Triage-Queue, CVE-2026-31431): Auf der Karte eines
patchbaren HIGH-Findings stand eine Bewertung, die wörtlich über einen
Schwester-CVE der Group redete („… critical network-vector kernel flaw, **no
fix**" — Group-Worst = CVE-2026-43304). Das wirkt wie ein Widerspruch
(angezeigte Fix-Version vs. „no fix"), ist aber die `worst_finding_drift`-
Situation. Der Drift-Hint existiert für die Group-Card und die Action-Needed-
Tabelle, fehlte aber im Per-Finding-Inline-Body — dort schlug die Verwechslung
ungebremst durch.

## Entscheidung

Ein AI-Assessment gehört auf die **Application-Group**, nicht in die einzelne
Finding-Zeile. Das Per-Finding-Feld `Finding.risk_band_reason` wird **komplett
entfernt** — nicht nur die UI-Anzeige, sondern auch Schema, Vererbungs-
Schreibseite und Pre-Triage-Schreibseite.

Audit der Leser ergab, dass das Feld nach Entfernen der UI-Box **nirgends**
mehr gelesen wird: CSV-Export (`FINDINGS_CSV_COLUMNS`) enthält es nicht,
Sortierung (`FindingsSortKey`) nutzt `risk_band` nicht `_reason`, und die
Worst-Finding-Logik läuft über `worst_finding_id`/`risk_band`. Das Feld war
nach der UI-Entfernung toter Ballast — daher Hard-Delete statt TD-Eintrag
(User-Entscheidung 2026-06-11).

Konkret:

1. **Schema:** Migration `0021_drop_findings_risk_band_reason` droppt
   `findings.risk_band_reason` (Downgrade re-added die nullable `String(256)`-
   Spalte). Das Group-Level-Feld `ApplicationGroupEvaluation.risk_band_reason`
   (Migration 0011) bleibt unangetastet.
2. **Modell:** `Finding.risk_band_reason`-Mapped-Column entfernt.
3. **Schreibseiten:** `finding_group_inheritance` schreibt/vergleicht
   `risk_band_reason` nicht mehr (raus aus `UPDATE … VALUES` und der
   Idempotenz-OR-Bedingung); `scan_processing` schreibt `evaluation.reason`
   nicht mehr auf das Finding (`RiskEvaluation.reason` bleibt als Wert-Objekt
   bestehen, nur kein Finding-Write).
4. **UI:** Der `risk_band_reason`-Block (`sd-ai-eyebrow` + `sd-ai-text` inkl.
   „AI assessment pending"-Fallback) in `finding_inline_body.html` ist
   entfernt. Die Group-Card (`application_group_card.html`) und die Action-
   Needed-Tabelle (`_action_needed_section.html`) rendern das Assessment
   weiterhin — dort korrekt verortet, inkl. Drift-Hint.

## Konsequenzen

- **Positiv:** Keine irreführende Per-Finding-Bewertung mehr, die über ein
  anderes Finding redet. Eine einzige Quelle der Wahrheit (Group-Card). Die
  Vererbungs-Logik wird schlanker (nur noch `risk_band` + `risk_band_source`).
- **Migrations-Pflicht:** `alembic upgrade head && downgrade -1 && upgrade
  head` muss grün sein (Roundtrip beim Operator zu verifizieren).
- **Tests:** Per-Finding-Reason-Template-Tests auf Absence umgestellt; die
  Group-Card-/Action-Needed-Drift-Tests bleiben unverändert grün. Schema-
  Regression `not hasattr(Finding, "risk_band_reason")` ergänzt.

## Alternativen (verworfen)

- **Drift-Hint auch in den Per-Finding-Body ziehen:** Hätte den Widerspruch
  entschärft, aber die konzeptionelle Fehlplatzierung (Group-Bewertung auf
  Finding-Zeile) belassen. Verworfen zugunsten klarer Verortung.
- **Nur UI entfernen, DB-Inheritance als TD vormerken:** Ursprünglicher
  Ticket-Vorschlag. Verworfen, weil der Audit das Feld als vollständig
  ungelesen erwies — toter Ballast wird sofort entfernt statt aufgeschoben.
