# TICKET-011 — Pass-2-Input: deterministische Worst-Selektion + Titel statt Description

**Status:** Freigegeben (Entscheidungen 1–2 vom User, 2026-06-10) · **Datum:** 2026-06-10 · **Bezug:** ARCHITECTURE.md §12, ADR-0023 (Two-Pass), ADR-0052 / TICKET-010 (OPEN-only-Eval-Input).
**Komponenten:** `app/services/llm_risk_reviewer.py` (`_render_pass2_prompt`, `_validate_pass2_response`), `app/services/llm_prompts.py` (`PASS2_SYSTEM_PROMPT`), neuer Selektor-Helper, `app/services/llm_fingerprints.py` (`make_cache_key`-Salt), Tests.
**Umfang:** Kein Schema, keine Migration, kein UI-Touch. Zwei Etappen.

## Problem (Befund 2026-06-10, Triage-Queue CVE-2026-31431)

### Bug A — Zufälliges 32er-Cap macht KEV-Findings für das LLM unsichtbar

`_render_pass2_prompt` schneidet pro Group auf `fs[:32]` (`llm_risk_reviewer.py:911`);
die Findings kommen aus dem Worker **ohne ORDER BY** (`llm_worker.py:1527 ff.`) — also in
beliebiger DB-Reihenfolge. Bei großen Groups (Kernel: hunderte CVEs) liegt ein KEV-Finding
beliebig oft außerhalb des Fensters. Beobachtet: Group enthält KEV-Finding CVE-2026-31431
(roter Chip, live), die Eval-Reason behauptet „no KEV/EPSS exploit" — das LLM hat seinen
(zufälligen) Input korrekt beschrieben, aber die falschen 32 gesehen.

### Bug B — System-Prompt verlangt Description-Reasoning, Input enthält keine

`PASS2_SYSTEM_PROMPT` fordert „Attack-chain reasoning based on the **CVE description**
and the host context" (`llm_prompts.py:205`) — die Finding-Zeile enthält aber weder
Description noch Title (`llm_risk_reviewer.py:928–933`: nur ID/CVE/Paket/Metriken/Pfad).
Das Modell kann nur auf Trainingswissen zur CVE-ID zurückfallen (bei frischen CVEs leer)
oder halluzinieren.

### Bug C — `worst_finding_id`-Validierung kennt das Cap nicht

`_validate_pass2_response` akzeptiert jede ID der vollen Group (`input_labels` über alle
`fs`), obwohl das LLM nur 32 gesehen hat — Reason und Worst-Finding können auseinanderfallen.

## Entscheidungen (User, 2026-06-10)

1. **Fix-Verfügbarkeit ist KEIN Selektionskriterium** — ein Fix macht ein Finding nicht
   schlimmer. `fix=` bleibt Attribut in der Prompt-Zeile der selektierten Findings
   (Action-Type-Entscheidung), fließt aber nicht in die Auswahl ein.
2. **Titel statt Description.** Keine CVE-Descriptions im Prompt; stattdessen `title`
   (destillierte Description, enthält bei Kernel-CVEs das Subsystem) plus
   `av=<attack_vector>` (liegt strukturiert in `Finding.attack_vector`, deckt den
   wichtigsten Description-Mehrwert „Angriffskontext" ab). System-Prompt-Satz wird an
   die Realität angepasst.

## Lösung

### Etappe 1 — Deterministischer Selektor (pure Funktion)

**Datei:** `app/services/pass2_input_selection.py` (neu) + Pure-Unit-Tests.

`select_pass2_findings(findings, budget=32) -> SelectionResult` — reine Funktion über
eine Finding-Liste, keine Session:

1. **Pflicht-Slots:** alle KEV; dann alle CRITICAL. Überschreiten allein diese das
   Budget: innerhalb nach EPSS desc kürzen (Verdikt ist dann ohnehin klar, Rest steht
   im Aggregat).
2. **Quote:** Top-k nach EPSS (fängt „wahrscheinlich ausgenutzt, aber nur MEDIUM").
3. **Quote:** je distinct `target_path` bzw. Paket das jeweils schlimmste Finding
   (Exposure-Breite fürs Pfad-Reasoning).
4. **Auffüllen** des Restbudgets nach Triage-Order (`is_kev DESC, epss DESC NULLS LAST,
   cvss DESC NULLS LAST, severity_rank DESC, first_seen ASC`), Tiebreak
   `identifier_key` — deterministisch und reproduzierbar.
5. Dedupe über Finding-ID; Render-Reihenfolge = Triage-Order.
6. `SelectionResult` enthält zusätzlich die **Rest-Aggregate**: Count pro Severity,
   max EPSS, Fix-Verteilung — und die Invariante **„0 KEV im Rest"** (assertbar).

**Tests (Pure-Unit):** Quoten-Matrix, Overflow (mehr KEV/CRITICAL als Budget),
Determinismus (gleicher Input → identische Auswahl/Reihenfolge), Invariante,
Pfad-Diversität, leere/kleine Gruppen (≤ Budget → identisch, keine Aggregat-Zeile).

### Etappe 2 — Prompt-Render, System-Prompt, Validierung

**Dateien:** `llm_risk_reviewer.py`, `llm_prompts.py`, `llm_fingerprints.py`.

- `_render_pass2_prompt` nutzt den Selektor statt `fs[:32]`. Finding-Zeile erweitert um
  `av=<attack_vector|n/a>` und ` title="<gekürzt ~100 Zeichen>"` (newlines gestript,
  escaped — Fremdtext bleibt auf eine Zeile begrenzt). Nach den Zeilen die
  Aggregat-Zeile: `... (N weitere: x critical, y high, …, max_epss=…, 0 kev)`.
- `PASS2_SYSTEM_PROMPT`: „based on the CVE description" → „based on the finding title
  and host context"; Input-Beschreibung (Z. 168–173) um title/av ergänzen.
- `_validate_pass2_response`: `worst_finding_id` muss in den **gezeigten** IDs liegen
  (`SelectionResult`-IDs statt aller `fs`).
- **Cache-Invalidierung:** Prompt-Semantik ändert sich materiell, der Cache-Key
  (Fingerprints) aber nicht → falsche Bestands-Reasons blieben bis zur nächsten
  OPEN-Set-Änderung stehen. Daher Versions-Salt in `make_cache_key`
  (`PASS2_PROMPT_VERSION = 2` in den Payload) → einmaliger Voll-Re-Eval pro
  (group, server) beim nächsten Enqueue, fingerprint-gated, danach normale Cache-Hits.

**Tests (Pure-Unit):** Render-Snapshot (Zeile enthält av/title, Aggregat-Zeile korrekt,
KEV immer enthalten — Regression für Bug A), System-Prompt-Wortlaut-Sweep
(kein „CVE description" mehr), Validierung lehnt nicht-gezeigte worst_finding_id ab,
Cache-Key ändert sich mit Versions-Salt.

## Bewusst NICHT in diesem Ticket

- CVE-Descriptions im Prompt (Entscheidung 2) — Re-Open nur falls Titel-only nachweislich
  zu Fehlurteilen führt (Eval-Stichproben).
- Budget-Tuning (32 bleibt Default) — erst empirisch prüfen, wie oft Groups > 32
  „relevante" Findings haben, bevor am Wert gedreht wird.
- Marker-/Injection-Framework für längere Fremdtexte — bei einzeiligen, gekürzten
  Titeln nicht nötig.

## Performance-Bilanz

- Selektor: O(n log n) in-memory über das bereits geladene OPEN-Set — kein neuer Query.
- Prompt wächst um ~10–15 Tokens pro Finding (title + av) bei gleichem Cap.
- Versions-Salt: einmaliger Re-Eval-Burst (ein LLM-Call pro (group, server) mit
  offenen Findings), danach unverändertes Cache-Verhalten.

## DoD

- [x] `ruff check . && ruff format --check .` grün (2026-06-10)
- [x] `mypy app/` grün (2026-06-10)
- [x] Default-`pytest` grün (2361 passed; Pure-Unit), Regression-Test
      „KEV-Finding ist immer im Prompt" vorhanden
      (`test_pass2_prompt_always_contains_kev_finding`,
      `test_kev_finding_is_always_selected_in_large_group`)
- [x] Keine neuen deutschen UI-/Prompt-Strings (ADR-0045 betrifft Operator-Strings;
      Prompts sind ohnehin englisch — die bis dato deutsche Abschluss-Instruktion
      in `_render_pass2_prompt` und die `... (N weitere)`-Zeile wurden dabei
      auf Englisch umgestellt)
- [ ] Operator-Smoke (User): Re-Eval der Kernel-Group auf dem frisch hinzugefügten
      Server → Reason nennt KEV korrekt (CVE-2026-31431-Fall aus dem Befund)
