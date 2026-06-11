# TICKET-014 — „re-evaluation pending" hängt am falschen Signal (Drift-Hint ≠ Enqueue-Gate)

**Status:** Umgesetzt (2026-06-11) · **Datum:** 2026-06-11 · **Bezug:** ADR-0052 / TICKET-010 (Live-Worst + Drift-Hint, definiert die fehlerhafte Semantik), ADR-0053 / TICKET-013 (Fix-Lane-Evaluation, per-Lane-Kontext), ADR-0028 (Junction + `group_findings_fingerprint`).
**Komponenten:** `app/views/server_detail.py` (`_load_application_groups_for_server`, Drift-Berechnung), `app/templates/_partials/application_group_card.html`, `app/templates/servers/_action_needed_section.html`, `app/services/llm_fingerprints.py` (`group_findings_fingerprint` — Read-Reuse), Tests. **Doku:** ADR-0052 §Entscheidung-2 bekommt eine Korrektur-Note.
**Umfang:** View-Logik + Templates + Tests. Kein Schema, keine Migration, kein LLM-Vertrag.

## Problem (Befund 2026-06-11)

Nach **komplettem Daten-Reset + Voll-Scan**, alle Pass-1/Pass-2-Jobs durchgelaufen, zeigt die „Operator workflows"-Sektion bei mehreren Lanes dauerhaft **„re-evaluation pending"** — obwohl gerade nichts mehr ansteht und auch nichts enqueued wird oder wird.

## Root-Cause

### (a) Drift vergleicht zwei verschiedene Definitionen von „worst"

`_load_application_groups_for_server` berechnet (Stand TICKET-013):

```python
# server_detail.py ~384–388
drift = bool(
    ev is not None
    and ev.worst_finding_id is not None
    and (worst is None or int(ev.worst_finding_id) != int(worst.id))
)
```

- `ev.worst_finding_id` = **LLM-Wahl** aus Pass 2 (exploitability-/exposure-Reasoning).
- `worst` = Live-Worst aus Query 4 (`server_detail.py:337–364`), ein **deterministischer Triage-Sort**: `is_kev DESC, epss DESC NULLS LAST, cvss DESC NULLS LAST, severity_rank DESC, first_seen ASC`.

Das sind zwei unterschiedliche „worst"-Begriffe, die **auch unmittelbar nach einer frisch erfolgreichen Eval** auseinanderfallen. Der Triage-Sort führt mit `is_kev` — ein KEV-gelistetes, aber niedriger eingestuftes Finding schlägt einen non-KEV-Critical. Das LLM wählt aber regelmäßig den Critical-Network-No-Fix als worst.

**Beobachtet:** no-patch-Lane `linux-modules-6.8.0-90-generic` zeigt Live-Worst **CVE-2013-7445** (KEV → Triage-Top), Reason/Eval-Worst ist **CVE-2026-43037** (LLM-Wahl). `worst_finding_id != worst.id` → `drift = True`, permanent.

### (b) Der Hint ist vom Enqueue-Gate entkoppelt

`worst_finding_drift` wird **nur** in Templates + im View gelesen — es triggert **keine** Re-Eval. Was eine Re-Eval auslöst, ist das Fingerprint-Gate in `pass2_enqueue.py:202–207`:

```python
new_fp = group_findings_fingerprint(lane_findings)   # Lane-OPEN-Set
if existing_eval.group_findings_fingerprint == new_fp:
    continue   # kein Pass-2 für diese Lane
```

Nach dem Voll-Scan stimmt dieser Fingerprint exakt (am OPEN-Set hat sich nichts geändert) → **kein Job wird enqueued**. Der Hint behauptet „pending", aber es ist nichts pending und wird es nie. Dauerhaftes False-Positive.

### (c) Endlosschleifen-Falle

Würde man „bei Drift → enqueue" verdrahten (naheliegender Fix-Versuch), liefe es **endlos**: eine Re-Eval bringt das LLM nicht dazu, denselben Finding zu wählen wie der deterministische Triage-Sort. Der Drift bliebe nach jeder Runde bestehen → Dauer-Requeue. Der Hint darf also **nicht** an den LLM-vs-Triage-Vergleich gekoppelt werden.

### Kern

ADR-0052 (Entscheidung 2) wollte zwei Dinge trennen, die hier verschmelzen:

1. **Anzeige-Worst** — bewusst der deterministische Live-Worst (damit ein zwischenzeitlich geschlossenes/verändertes Finding nicht stale angezeigt wird). Darf von der LLM-Wahl abweichen, das ist der Normalfall.
2. **„Eval ist veraltet"-Signal** — sollte genau das sein, was auch das Enqueue-Gate prüft.

Aktuell ist (2) fälschlich als „LLM-Worst ≠ Triage-Live-Worst" definiert und überschießt damit.

## Lösung

`worst_finding_drift` von „LLM-Worst ≠ Triage-Worst" entkoppeln und an dieselbe Bedingung wie das Enqueue-Gate hängen. Eine Lane gilt als „re-evaluation pending" **genau dann**, wenn die gespeicherte Eval gegenüber dem aktuellen Lane-OPEN-Set veraltet ist:

```
drift  ⇔  ev is not None and (
              ev.group_findings_fingerprint != group_findings_fingerprint(lane_open_findings)
              or ev.worst_finding_id not in {f.id for f in lane_open_findings}
          )
```

- **Fingerprint-Mismatch** = OPEN-Set der Lane hat sich seit der Eval geändert (neu/resolved/acked/reopened) → beim nächsten Scan-/Triage-Trigger wird tatsächlich enqueued (`pass2_enqueue`), und nach dem Lauf stimmt der Fingerprint → Hint verschwindet. Kein Loop.
- **`worst_finding_id` nicht mehr offen** = Snapshot-Finding inzwischen geschlossen → ebenfalls ein echtes „stale"-Signal (deckt den ursprünglichen TICKET-010-Fall ab).
- Bei **frischer, aktueller Eval** (Fingerprint stimmt, Worst-Finding offen) ist `drift = False`, **auch wenn** `ev.worst_finding_id != Triage-Live-Worst`. Genau der Voll-Scan-Fall.

Die Spalte „Worst Finding" zeigt weiterhin den deterministischen Live-Worst (TICKET-010 unverändert) — sie treibt nur nicht mehr den Hint.

### Implementierungs-Hinweis

Der View braucht dafür pro Lane die `(identifier_key, package_purl)` der OPEN-Findings, um `group_findings_fingerprint` zu rechnen (Read-Reuse der Funktion aus `llm_fingerprints.py`). Query 4 holt heute nur das Top-Finding. Günstigste Variante: eine schlanke Projektion `(application_group_id, has_fix, identifier_key, package_purl, id)` über die OPEN-Findings der `group_ids` laden und daraus pro Lane sowohl den Fingerprint als auch das `id`-Set bilden — Query 4 (Live-Worst) kann bestehen bleiben oder mit dieser Projektion zusammengelegt werden. Die Eval-Row trägt `group_findings_fingerprint` bereits (Junction-Spalte) und ist im Junction-Batch (Query 3) ergänzbar.

## Definition of Done (maschinell prüfbar)

- [x] `worst_finding_drift` referenziert in `server_detail.py` **nicht mehr** `worst.id` als Drift-Kriterium; Drift folgt aus Lane-Fingerprint-Mismatch ODER `worst_finding_id ∉ Lane-OPEN-Set`. (`_load_application_groups_for_server`, neue Query 5 + Drift-Block)
- [x] Pure-Unit-Test: frische Eval (Fingerprint == aktueller Lane-Fingerprint, `worst_finding_id` offen) → `drift = False`, **auch wenn** `ev.worst_finding_id` ≠ deterministischer Triage-Live-Worst (der Regressions-Fall dieses Tickets). (`test_drift_false_for_fresh_eval_even_if_llm_worst_differs_from_triage`)
- [x] Pure-Unit-Test: geändertes Lane-OPEN-Set (neues/entferntes Finding) → Fingerprint-Mismatch → `drift = True`. (`test_drift_true_on_fingerprint_mismatch`)
- [x] Pure-Unit-Test: `worst_finding_id` zeigt auf ein nicht mehr offenes Finding → `drift = True`. (`test_drift_true_when_worst_finding_id_not_in_open_set`)
- [x] Bestehende Drift-Tests umgestellt; `test_application_group_card_drift`/`test_action_needed_drift_hint` sind flag-getrieben (Render-Vertrag unverändert), die Loader-Tests in `test_server_detail_live_worst`/`_fix_lane`/`_phase_a` auf die neue Query-5- und Drift-Semantik angepasst.
- [x] `ruff check . && ruff format --check .` grün.
- [x] `mypy app/` grün.
- [x] `pytest` (Default-/Pure-Unit-Selektion) grün (2420 passed; die 3 `settings/servers.html`-Smoke-Failures bestehen unverändert schon auf `main`, unbezogen zu TICKET-014).

## Test-Konvention (Subagent-Pflicht, wörtlich)

Erlaubte Quality-Gates: ruff, mypy, shellcheck (Linter), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen `.bats`-/`.sh`-Test-Dateien. Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

## Doku-Folge

ADR-0052 §Entscheidung-2 („Drift-Hint") bekommt eine Korrektur-Note: der Hint signalisiert „Eval veraltet ggü. OPEN-Set" (Fingerprint-/Worst-offen-Kriterium), **nicht** „Anzeige-Worst ≠ Eval-Worst". Die Divergenz LLM-Wahl vs. deterministischer Triage-Sort ist erwartetes Normalverhalten und kein Drift.

## Risiko / Nicht-Ziel

- **Kein** Koppeln von Drift an `enqueue` (würde mit dem alten Kriterium endlos loopen; mit dem neuen Kriterium ist es ohnehin redundant, weil der Scan-/Triage-Trigger den Enqueue schon fingerprint-gated macht).
- Anzeige-Worst-Logik (Query 4, Triage-Order) bleibt unverändert — reiner Anzeige-Zweck.
