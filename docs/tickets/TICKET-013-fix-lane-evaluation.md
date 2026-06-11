# TICKET-013 — Fix-Lane-Evaluation: Pass-2 pro `(group, server, fix_lane)`

**Status:** Offen · **Datum:** 2026-06-11 · **Bezug:** ADR-0053 (diese Umsetzung), ADR-0028 (Junction), ADR-0023 (Two-Pass), TICKET-011 (Selektion), ADR-0052/TICKET-010 (OPEN-only/Live-Worst), TICKET-012 (Reason ist Group-/Lane-Level).
**Komponenten:** `app/models.py`, neue Alembic-Migration, `app/services/llm_fingerprints.py`, `app/services/pass2_input_selection.py` (Caller), `app/services/llm_risk_reviewer.py`, `app/services/llm_prompts.py`, `app/services/pass2_enqueue.py`, `app/workers/llm_worker.py`, `app/services/finding_group_inheritance.py`, `app/views/server_detail.py`, `app/templates/_partials/application_group_card.html`, `app/templates/servers/_action_needed_section.html`, Tests, `ARCHITECTURE.md`.
**Umfang:** Schema + Migration + LLM-Vertrag + View. Sieben Etappen, je grün vor der nächsten.

## Problem & Entscheidung

Siehe ADR-0053. Kurz: `action_type` (patch/mitigate) ist ein deterministischer Fakt aus `fixed_version`, kein LLM-Urteil; das Risiko-Band kann sich zwischen patchbarem und nicht-patchbarem Teil einer Group unterscheiden. Pass 2 wird pro Fix-Lane bewertet, in **zwei getrennten LLM-Requests** pro gemischter Group (Operator-Entscheidung 2026-06-11: getrennt, nicht kombiniert — homogener Prompt, volles Budget pro Lane, einfacher Output-Vertrag).

`fix_lane`-Definition (deterministisch, keine Finding-Spalte):
- `patch` = `fixed_version IS NOT NULL`
- `mitigate` = `fixed_version IS NULL`

## Etappen

### Etappe 1 — Schema & Migration

- `ApplicationGroupEvaluation`: `fix_lane: Mapped[str]` als dritte PK-Spalte (`String(8)`, NOT NULL). CHECK `fix_lane IN ('patch','mitigate')`. Index `ix_app_group_evals_server` → `(server_id, fix_lane, risk_band)`.
- Alembic: Drop & Rebuild der Bestands-Rows (kein Backfill, analog ADR-0028). `fix_lane` hinzufügen, PK auf `(group_id, server_id, fix_lane)`, neuer Index, CHECK.
- `downgrade` baut den alten 2-Spalten-PK zurück (Rows leer).

### Etappe 2 — Fingerprint & Cache pro Lane

- `group_findings_fingerprint`: unverändert in der Signatur, aber Caller übergeben das **Lane-OPEN-Set** (Findings dieser Lane), nicht das Group-OPEN-Set.
- `make_cache_key`: zusätzliche `fix_lane`-Salt-Komponente.
- `PASS2_PROMPT_VERSION` hochzählen (Cache-Invalidation).

### Etappe 3 — Pass-2-Output: `action_type` raus, Lane-Scope

- `PASS2_RESPONSE_SCHEMA` / `Pass2Evaluation` / `Pass2Result`: `action_type` entfernen. `VALID_ACTION_TYPES` + `ALLOWED_BAND_ACTION_COMBOS` entfernen.
- `_validate_pass2_response`: keine `action_type`-Prüfung mehr. **Band-Whitelist pro Lane:** bei `fix_lane == 'mitigate'` ist `risk_band == 'act'` ungültig (act ist patch-only — siehe ADR-0053; ein no-fix Finding ist escalate oder monitor/noise, nie act). `worst_finding_id` weiterhin gegen die im Prompt gezeigten (Lane-)IDs validiert.
- `_render_pass2_prompt`: scoped auf eine Lane. Host-Kontext-Block in eigene Funktion (`_render_host_context(server) -> list[str]`), in beiden Lane-Prompts identisch aufgerufen. System-Prompt-Zeile: alle Findings im Call haben dieselbe Patch-Verfügbarkeit. Im mitigate-Lane-Prompt wird `act` nicht als wählbares Band genannt (nur escalate/monitor/noise).
- `_select_for_groups` → iteriert `(group, lane)`; `select_pass2_findings` pro Lane mit vollem Budget (Selektor selbst unverändert).

### Etappe 4 — Enqueue pro Lane

- `enqueue_pass2_for_server`: pro betroffener Group bis zu zwei Jobs. Payload `{group_id, server_id, fix_lane}`. Doppel-Enqueue-Guard und Fingerprint-Skip auf `(group_id, server_id, fix_lane)`. Leere Lane → kein Job.

### Etappe 5 — Worker-Persist & abgeleiteter `action_type`

- `_do_pass2`: liest `fix_lane` aus Payload, fingerprintet die Lane, selektiert die Lane.
- `_upsert_evaluation`: `fix_lane`-Param; `action_type` deterministisch aus `(fix_lane, risk_band)` ableiten (Tabelle aus ADR-0053). `on_conflict` index_elements `["group_id","server_id","fix_lane"]`.

### Etappe 6 — Inheritance pro Lane

- `inherit_group_risk_to_findings`: Composite-Join + Lane-CASE — Finding erbt aus der Junction-Row seiner eigenen Lane (`eval.fix_lane = CASE WHEN Finding.fixed_version IS NOT NULL THEN 'patch' ELSE 'mitigate' END`).

### Etappe 7 — View, Card-Matrix & Templates

- `_load_application_groups_for_server`: Junction-Batch liefert ≤2 Rows/Group; Render-Dict nach Lane gruppiert. Group-Sortierung nach Max-Band über Lanes.
- `_build_action_sections`: **keine** neue Card-Spec — die fünf Bestands-Karten bleiben unverändert (kein `act + mitigate`, act ist patch-only). Matching auf Lane-Rows statt Group-Rows; Eintrag wird `(group, lane)` mit Lane-Worst (live, ADR-0052).
- `application_group_card.html` / `_action_needed_section.html`: bis zu zwei Lane-Verdikte pro Group, je eigene Reason + Worst.
- `ARCHITECTURE.md` §5/§12 nachziehen.

## Definition of Done (maschinell prüfbar)

- [ ] `ruff check . && ruff format --check .` grün.
- [ ] `mypy app/` grün.
- [ ] `pytest` (Default-/Pure-Unit-Selektion) grün, mit Bash-`timeout` ≤ 120000 ms.
- [ ] Migration-Roundtrip `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` grün — **nur auf ausdrückliche User-Anweisung** (db-nah, fällt unter die On-Demand-Regel in CLAUDE.md); sonst als DoD-Item „beim User anstehen lassen" markieren.
- [ ] Pure-Unit-Tests vorhanden für: Lane-Split der Selektion, Fingerprint pro Lane (Fix-wird-verfügbar ändert beide Lane-Fingerprints), `action_type`-Ableitungstabelle vollständig (kein act+mitigate), Enqueue erzeugt zwei Jobs bei gemischter Group / einen bei reiner Lane, `_validate_pass2_response` ohne `action_type` **und** Ablehnung von `act` bei `fix_lane=='mitigate'`, Card-Matrix inkl. „Group erscheint in zwei Cards" (und keine act+mitigate-Karte), Inheritance-Lane-CASE (patchbares vs. no-fix Finding derselben Group tragen unterschiedliche Bands).
- [ ] Kein `action_type` mehr im LLM-Output-Pfad (grep: `ALLOWED_BAND_ACTION_COMBOS`, `VALID_ACTION_TYPES` entfernt; `Pass2Evaluation` hat kein `action_type`-Feld).
- [ ] HTMX-OOB-Single-Source-Regel eingehalten, falls ein OOB-Endpoint berührt wird (CLAUDE.md).

## Test-Konvention (Subagent-Pflicht, wörtlich)

Erlaubte Quality-Gates: ruff, mypy, shellcheck (Linter), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen `.bats`-/`.sh`-Test-Dateien. Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

## Offene Punkte / Risiken

- **Migration ist db-nah** — Roundtrip-Verifikation braucht User-Genehmigung pro Lauf.
- **Transienter Mixed-State**: zwei Lane-Jobs einer Group können zeitversetzt fertig werden; Group-Card zeigt kurz eine Lane bewertet, andere „re-evaluation pending" (bestehender Hint deckt das ab).
- **Einmaliger Cache-Miss nach Deploy** durch `PASS2_PROMPT_VERSION`-Bump + Lane-Salt — einmalige LLM-Kosten, danach Cache-Hits.
- **Erwogene Vereinfachung** (patch-Lane-Band deterministisch, kein LLM-Call) ist in ADR-0053 als Re-Open-Trigger vermerkt, nicht Teil dieses Tickets.
