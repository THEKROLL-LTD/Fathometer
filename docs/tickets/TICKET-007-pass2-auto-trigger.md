# TICKET-007 — Pass-2-Auto-Trigger nach Pass-1-Completion

**Status:** Offen · **Datum:** 2026-05-28 · **Bezug:** ARCHITECTURE.md §12 "Risk-Reviewer", ADR-0023 (Block P), ADR-0028 (Eval-Junction).
**Komponenten:** `app/services/pass2_enqueue.py` (neu), `app/services/scan_processing.py` (Umbau Block-P-Enqueue), `app/workers/llm_worker.py` (Hooks + Sub-Tick), Tests.
**Umfang:** Trigger-Korrektur in der LLM-Job-Pipeline. Kein UI-Touch, keine Schema-Migration, kein neuer Endpoint.

## Problem

Heute laeuft der Pass-2-Trigger genau einmal pro Scan-Upload — beim Ingest in `scan_processing._process_envelope_inner()` (Zeile ~246–370). Das produziert zwei Bugs:

### Bug A — `depends_on` macht aus einem failed Pass-1 einen toten Pass-2

`scan_processing.py:348-353` legt Pass-2-Jobs mit `depends_on=last_pass1_job.id` an. Die Pickup-SQL in `llm_worker.py:848-892` verlangt:

```
depends_on IS NULL OR depends_on IN (SELECT id FROM llm_jobs WHERE status='done')
```

Wenn ausgerechnet dieser eine Pass-1-Job nach 3 Versuchen `failed` wird, haengt der zugehoerige Pass-2 fuer immer — die Pickup-Logik wartet auf `status='done'`, was nie eintritt. Das eigentlich richtige Sibling-Wait-Pattern direkt darunter im selben SQL macht es korrekt: Pass-2 wartet bis *alle* Pass-1-Siblings fuer denselben `server_id` entweder `done` ODER `failed` sind. `depends_on` ist hier redundant und schaedlich.

### Bug B — Pass-2 wird nicht fuer die *neu* groupierten Findings enqueued

`scan_processing.py:298-310` bestimmt `affected_groups` so:

```python
select(ApplicationGroup).join(Finding, Finding.application_group_id == ApplicationGroup.id)
.where(Finding.server_id == server.id, Finding.status == FindingStatus.OPEN)
```

Diese Query findet nur Gruppen fuer Findings die **schon** ein `application_group_id` haben — Findings die bei frueheren Uploads gegroupt wurden. Die Findings, die der gerade enqueuete Pass-1 erst noch groupen wird, sind in diesem Moment ungroupiert und tauchen hier nicht auf. Resultat: beim ersten Upload mit neuen Findings detektiert Pass-1 frische Gruppen, aber niemand enqueued Pass-2 dafuer. Erst beim *zweiten* Upload (24 h spaeter) sieht die `affected_groups`-Query die jetzt-vorhandenen Gruppen und enqueued endlich Pass-2.

Beobachtetes Operator-Symptom: nach dem ersten Upload bleiben alle frischen Application-Groups dauerhaft im `pending`-Slot, bis der naechste Scan reinkommt.

## Loesung

### Fix 1: `depends_on` aus dem Pass-2-Enqueue raus

Die Sibling-Wait-Logik in der Pickup-SQL ist bereits korrekt und ausreichend (`status IN ('queued', 'in_progress')`-Check schliesst failed Siblings korrekt ein bzw. nicht). Der zusaetzliche `depends_on`-Check ist redundant und blockiert bei failed Pass-1. → ersatzlos streichen.

### Fix 2: Pass-2-Auto-Enqueue nach Pass-1-Completion

Neuer idempotenter Helper `enqueue_pass2_for_server(session, server_id, *, trigger)` als Single-Source-of-Truth fuer Pass-2-Job-Anlage. Drei Aufrufer rufen denselben Helper:

1. **`scan_processing._process_envelope_inner`** — beim Ingest fuer bereits gematchte Gruppen (heute schon, nur Code-Pfad sauber durch den Helper ersetzt).
2. **`llm_worker._do_pass1`** — nach erfolgreichem Pass-1, wenn keine Pass-1-Siblings fuer denselben Server mehr `queued`/`in_progress` sind.
3. **`llm_worker._requeue_or_fail`** — wenn ein Pass-1 final `failed` markiert wird und keine Pass-1-Siblings mehr `queued`/`in_progress` sind.

Plus ein **Backstop-Sub-Tick alle 5 min** im Worker als Crash-Schutz: wenn der Worker zwischen Pass-1-Done und Hook-Aufruf abstuerzt, faengt der naechste Sweep den Trigger nach.

Race-Safety: zwei Pass-1-Siblings die fast gleichzeitig terminieren koennten beide den Sibling-Check „leer" sehen und beide enqueuen wollen. Der `NOT EXISTS`-Guard im Helper (`SELECT 1 FROM llm_jobs WHERE job_type='risk_evaluation' AND server_id=:sid AND payload->>'group_id'=:gid AND status IN ('queued','in_progress')`) verhindert Doppel-Enqueue.

## Etappen-Schnitt

Drei Etappen mit je eigener Commit-Grenze. Etappen 1–2 sind sequenziell abhaengig (Helper-Tests gruen bevor Aufrufer umgestellt werden); Etappe 3 baut auf Etappe 1 auf und kann parallel zu Etappe 2 vorbereitet werden, sollte aber wegen Test-Konsistenz nach Etappe 2 mergen.

### Etappe 1 — Helper `pass2_enqueue.py` + Pure-Unit-Tests

**Ziel:** Single-Source-of-Truth fuer Pass-2-Enqueue, idempotent, race-safe, isoliert testbar.

**Datei:** `app/services/pass2_enqueue.py` (neu).

**Public-API:**

```python
from typing import Literal

Pass2Trigger = Literal[
    "scan_ingest",
    "pass1_completion",
    "pass1_final_failed",
    "backstop_sweep",
]

def enqueue_pass2_for_server(
    session: Session,
    server_id: int,
    *,
    trigger: Pass2Trigger,
) -> int:
    """Enqueued Pass-2-Jobs fuer alle Groups auf diesem Server die bewertet
    werden muessen. Returns Anzahl tatsaechlich enqueueter Jobs.

    Idempotent: kann beliebig oft aufgerufen werden ohne Doppel-Jobs zu
    erzeugen. Eine Group wird NUR enqueued wenn:
    - sie mindestens ein OPEN Finding auf diesem Server hat,
    - es noch keinen queued/in_progress Pass-2-Job fuer (group_id, server_id)
      gibt, und
    - keine application_group_evaluations-Row mit identischem
      group_findings_fingerprint existiert.

    Audit-Event ``llm.pass2_auto_enqueued`` mit metadata={
        server_id, pass2_queued_count, trigger
    } — nur emittiert wenn pass2_queued_count > 0.
    """
```

**Wichtig:**

- Logik 1:1 aus dem heutigen `scan_processing.py:298-355`-Block extrahiert (affected_groups laden, Fingerprint berechnen via `group_findings_fingerprint`, gegen `application_group_evaluations`-Junction vergleichen), aber mit dem zusaetzlichen `NOT EXISTS`-Guard auf bestehende `queued`/`in_progress` Pass-2-Jobs.
- **Kein `depends_on`** in den neu erzeugten `LLMJob`-Rows.
- Defensive Reihenfolge: Sibling-Check + Eval-Vergleich + Existing-Job-Check finden im *selben* `session`-Scope statt; ein einziges `session.flush()` am Ende. Caller ist fuer `session.commit()` zustaendig.
- Kein impliziter Caller-Side-Effect: der Helper triggert nicht selbst den Sibling-Check „sind alle Pass-1 fertig?" — das ist Caller-Verantwortung (Etappe 2/3 wo die Aufrufer den Check vorab machen). Damit bleibt der Helper isoliert testbar.

**Pure-Unit-Tests** in `tests/services/test_pass2_enqueue.py`:

1. `enqueue_pass2_for_server` mit einer neuen Group ohne Eval-Row → 1 Job enqueued, korrekte `payload={"group_id": .., "server_id": ..}`, `depends_on IS NULL`.
2. Zweiter Aufruf direkt danach → 0 Jobs (idempotent via Existing-Job-Guard).
3. Group mit Eval-Row gleicher `group_findings_fingerprint` → 0 Jobs (skippt).
4. Group mit Eval-Row anderer Fingerprint → 1 Job (re-evaluation noetig).
5. Group ohne OPEN-Findings auf dem Server → 0 Jobs (nicht enqueueable).
6. Mehrere Groups gemischt (eine neu, eine cached, eine pending) → korrekte Selektion.
7. Trigger-Parameter `pass1_completion` landet im Audit-Event metadata.
8. Bei 0 enqueueten Jobs wird das Audit-Event NICHT geschrieben (Lärm-Vermeidung).
9. Bestehender `in_progress` Pass-2-Job fuer dieselbe `(group, server)` → kein Doppel-Enqueue.
10. Bestehender `queued` Pass-2-Job → kein Doppel-Enqueue.
11. Bestehender `done` Pass-2-Job (alter Lauf, neuer Fingerprint) → 1 Job (alter Job blockiert nicht).

**Verbotene Tests:** db_integration / acceptance / integration / bench / bats / `RUN_E2E=1` / Docker-Compose / Browser. Siehe CLAUDE.md §"Test-Konvention".

**Akzeptanz-Kriterien:**

- `ruff check . && ruff format --check .` clean.
- `mypy --strict app/services/pass2_enqueue.py` keine neuen Errors.
- `pytest tests/services/test_pass2_enqueue.py -v` gruen (Bash-Timeout 60000).
- Default-Suite `pytest` gruen (Bash-Timeout 120000) — additiv, keine Regressionen.

**Commit-Botschaft-Muster:**
```
feat(llm): Pass-2-Enqueue-Helper (TICKET-007 Etappe 1)

- enqueue_pass2_for_server() idempotent, ohne depends_on
- NOT EXISTS-Guard gegen Doppel-Jobs (queued/in_progress)
- Fingerprint-Skip via application_group_evaluations-Junction
- 11 Pure-Unit-Tests, mypy --strict clean

Bezug: TICKET-007, ARCHITECTURE.md §12, ADR-0023, ADR-0028
```

### Etappe 2 — `scan_processing.py` umstellen + `depends_on` raus

**Ziel:** Heutigen Pass-2-Block durch einen einzigen Helper-Aufruf ersetzen, `depends_on` ersatzlos streichen.

**Datei:** `app/services/scan_processing.py` (Umbau, kein neuer Code).

**Aenderungen:**

1. Block 298–355 (affected_groups laden, evaluations_by_group_id, pass2_queued-Loop) ersetzen durch:
   ```python
   from app.services.pass2_enqueue import enqueue_pass2_for_server
   pass2_queued = enqueue_pass2_for_server(
       session, server.id, trigger="scan_ingest"
   )
   ```
2. `depends_on=pass1_job_id` in Zeile 352 wird damit nie mehr gesetzt — `pass1_job_id` selbst kann als lokale Variable verschwinden (heute nur fuer den `depends_on`-Wert berechnet) bzw. wird nur noch fuer das `llm.jobs_queued`-Audit-Event gebraucht (Anzahl der pass1-Batches).
3. Das bestehende `llm.jobs_queued`-Audit-Event bleibt unveraendert — `pass2_queued` kommt jetzt aus dem Helper-Return statt aus dem lokalen Counter.

**Pure-Unit-Tests** in `tests/services/test_scan_processing.py` (anpassen) und neu in `tests/workers/test_llm_worker_pickup.py`:

1. **Anpassen** — bestehende Scan-Processing-Tests die `depends_on`-Werte pruefen → erwarten jetzt `depends_on IS NULL` auf Pass-2-Jobs.
2. **Anpassen** — bestehende Tests die die `affected_groups`-Schleife direkt mocken → auf `enqueue_pass2_for_server`-Mock umstellen.
3. **Neu** — Pickup-Regressions-Test: Pass-2-Job mit `depends_on=NULL` + failed Pass-1-Sibling fuer denselben `server_id` wird gepickt (war heute durch `depends_on`-Bug nicht moeglich).
4. **Neu** — Pickup-Regressions-Test: Pass-2-Job mit `depends_on=NULL` + queued Pass-1-Sibling wird NICHT gepickt (Sibling-Wait bleibt korrekt).
5. **Neu** — Pickup-Regressions-Test: Pass-2-Job mit `depends_on=NULL` + nur `done` Pass-1-Siblings wird gepickt.

**Akzeptanz-Kriterien:**

- `ruff`, `mypy --strict app/services/scan_processing.py` clean.
- `pytest tests/services/test_scan_processing.py tests/workers/test_llm_worker_pickup.py -v` gruen (Timeout 60000).
- Default-Suite `pytest` gruen (Timeout 120000).
- Grep `depends_on=pass1_job_id` in `app/` leer (keine Restspur).

**Commit-Botschaft-Muster:**
```
refactor(llm): scan_ingest nutzt enqueue_pass2_for_server, depends_on raus
(TICKET-007 Etappe 2)

- Block-P-Enqueue im Scan-Ingest auf zentralen Helper umgestellt
- depends_on auf Pass-2-Jobs ersatzlos gestrichen (war redundant gegenueber
  Sibling-Wait in der Pickup-SQL und blockierte bei failed Pass-1)
- Pickup-Regressions-Tests: failed Pass-1-Sibling blockt Pass-2 nicht mehr

Bezug: TICKET-007, fixt Bug A aus dem Ticket
```

### Etappe 3 — Worker-Hooks + 5-min-Sub-Tick

**Ziel:** Pass-2 wird automatisch enqueued sobald das letzte Pass-1 fuer einen Server terminiert (done oder final-failed); Sub-Tick als Crash-Backstop.

**Datei:** `app/workers/llm_worker.py` (Hooks + Sub-Tick).

**Aenderungen:**

1. **Hook A — `_do_pass1` Pass-2-Trigger** (am Ende von `_do_pass1`, nach dem finalen `session.commit()` ~ Zeile 1148):
   ```python
   _maybe_trigger_pass2_after_pass1(server_id=job_server_id, trigger="pass1_completion")
   ```
   Helper-Funktion neu im Modul:
   ```python
   def _maybe_trigger_pass2_after_pass1(*, server_id: int | None, trigger: Pass2Trigger) -> None:
       if server_id is None:
           return
       with get_session() as session:
           # Sibling-Check: noch Pass-1 fuer diesen Server queued/in_progress?
           pending = session.execute(
               text("""
                   SELECT count(*) FROM llm_jobs
                   WHERE job_type = 'group_detection'
                     AND server_id = :sid
                     AND status IN ('queued', 'in_progress')
               """),
               {"sid": server_id},
           ).scalar()
           if pending and int(pending) > 0:
               return
           enqueue_pass2_for_server(session, server_id, trigger=trigger)
           session.commit()
   ```
   Defensiv: Exception aus dem Helper darf den Pass-1-Done-Pfad nicht killen — try/except mit log-only-Pfad.

2. **Hook B — `_requeue_or_fail` Pass-2-Trigger** (im final-failed-Branch ~ Zeile 2123, nach `session.commit()`):
   ```python
   if job.job_type == "group_detection":
       _maybe_trigger_pass2_after_pass1(
           server_id=job.server_id, trigger="pass1_final_failed"
       )
   ```
   Gleicher defensiver Wrap.

3. **Sub-Tick — Backstop-Sweep alle 5 min** in `_run_subticks` (neue Konstante + State + Aufruf):
   ```python
   PASS2_BACKSTOP_SWEEP_INTERVAL_SEC: float = 300.0
   _last_pass2_backstop_sweep_at: float = 0.0
   ```
   Sub-Tick-Body:
   ```python
   def _run_pass2_backstop_sweep_safe() -> None:
       """Faengt den Pass-2-Trigger ab wenn der Hook im _do_pass1 oder
       _requeue_or_fail-Pfad aus irgendeinem Grund nicht gefeuert hat
       (Worker-Crash zwischen Pass-1-Done und Hook-Aufruf, DB-Hickup).

       Findet Server-IDs mit 0 pending Pass-1-Jobs (queued + in_progress)
       und ruft den idempotenten Helper. Bei normaler Operation no-op weil
       der Hook bereits gefeuert hat und der NOT-EXISTS-Guard im Helper
       greift.
       """
       try:
           with get_session() as session:
               candidate_server_ids = [
                   int(row[0])
                   for row in session.execute(
                       text("""
                           SELECT DISTINCT server_id FROM llm_jobs
                           WHERE job_type = 'group_detection'
                             AND server_id IS NOT NULL
                             AND completed_at > now() - interval '24 hours'
                           EXCEPT
                           SELECT DISTINCT server_id FROM llm_jobs
                           WHERE job_type = 'group_detection'
                             AND server_id IS NOT NULL
                             AND status IN ('queued', 'in_progress')
                       """)
                   ).fetchall()
               ]
               for sid in candidate_server_ids:
                   enqueue_pass2_for_server(session, sid, trigger="backstop_sweep")
               session.commit()
       except Exception:  # pragma: no cover — DB-Hickup darf Worker nicht killen
           log.exception("llm_worker.pass2_backstop_sweep_failed")
   ```
   Aufruf in `_run_subticks`:
   ```python
   if now_mono - _last_pass2_backstop_sweep_at > PASS2_BACKSTOP_SWEEP_INTERVAL_SEC:
       _run_pass2_backstop_sweep_safe()
       _last_pass2_backstop_sweep_at = now_mono
   ```
   Cadence-State auch in `reset_shutdown_for_tests` resetten.

**Pure-Unit-Tests** in `tests/workers/test_llm_worker_pass2_trigger.py` (neu):

1. `_maybe_trigger_pass2_after_pass1` mit anderen Pass-1-Siblings queued → kein Helper-Aufruf.
2. `_maybe_trigger_pass2_after_pass1` mit anderen Pass-1-Siblings in_progress → kein Helper-Aufruf.
3. `_maybe_trigger_pass2_after_pass1` mit allen Pass-1 done/failed → Helper-Aufruf mit korrektem Trigger.
4. `_maybe_trigger_pass2_after_pass1` `server_id=None` → no-op.
5. `_maybe_trigger_pass2_after_pass1` Helper-Exception wird gefangen, kein Re-Raise.
6. `_do_pass1` Hook-Integration: nach erfolgreichem Pass-1 wird `_maybe_trigger_pass2_after_pass1` aufgerufen (Mock-Spy).
7. `_requeue_or_fail` Hook-Integration: final-failed `group_detection`-Job triggert Helper-Aufruf.
8. `_requeue_or_fail` Hook-Integration: final-failed `risk_evaluation`-Job triggert KEINEN Aufruf (nur fuer Pass-1).
9. `_requeue_or_fail` Requeue-Pfad (nicht final-failed) triggert KEINEN Aufruf.
10. `_run_pass2_backstop_sweep_safe` findet Server mit kuerzlichem Pass-1-Done und 0 pending → Helper-Aufruf.
11. `_run_pass2_backstop_sweep_safe` Server mit pending Pass-1 → kein Aufruf.
12. `_run_pass2_backstop_sweep_safe` Server ohne Pass-1-Activity in 24 h → kein Aufruf (Performance-Guard).
13. `_run_pass2_backstop_sweep_safe` DB-Exception → log + return, Worker laeuft weiter.
14. Sub-Tick-Cadence: Aufruf wird alle 300 s ausgeloest, dazwischen no-op.

**Akzeptanz-Kriterien:**

- `ruff`, `mypy --strict app/workers/llm_worker.py` clean.
- `pytest tests/workers/test_llm_worker_pass2_trigger.py -v` gruen (Timeout 60000).
- Default-Suite `pytest` gruen (Timeout 120000).
- `reset_shutdown_for_tests` resettet auch `_last_pass2_backstop_sweep_at` (sonst Test-Leakage).

**Commit-Botschaft-Muster:**
```
feat(llm-worker): Pass-2-Auto-Trigger nach Pass-1-Completion + Backstop-Sweep
(TICKET-007 Etappe 3)

- Hook in _do_pass1: enqueue Pass-2 sobald letztes Pass-1 fuer Server done
- Hook in _requeue_or_fail: dito wenn letztes Pass-1 final-failed
- Sub-Tick alle 5 min als Crash-Backstop (idempotent)
- 14 Pure-Unit-Tests fuer Hooks + Sweep + Cadence

Bezug: TICKET-007, fixt Bug B (Pass-2 ohne 24h-Verzoegerung)
```

## Definition-of-Done (Gesamt)

1. `app/services/pass2_enqueue.py` existiert, idempotent, Pure-Unit-getestet, mypy --strict clean.
2. `scan_processing._process_envelope_inner` nutzt den Helper; `depends_on` auf Pass-2-Jobs nicht mehr gesetzt.
3. `_do_pass1` und `_requeue_or_fail` (fuer `group_detection`-Jobs) triggern den Helper nach Sibling-Check.
4. Sub-Tick `_run_pass2_backstop_sweep_safe` laeuft alle 5 min, idempotent, Exception-gewrappt.
5. Audit-Event `llm.pass2_auto_enqueued` mit `trigger`-Metadata wird bei jedem Enqueue ≥ 1 emittiert.
6. Bestehendes `llm.jobs_queued`-Audit-Event aus `scan_processing` bleibt funktional unveraendert.
7. Bestehendes `llm.pass2_started_with_failed_pass1`-Event (Worker, ~Zeile 1276) bleibt unveraendert — der „Pass-2-mit-failed-Siblings"-Pfad ist jetzt der Normalfall statt der Edge-Case.
8. Default-`pytest` gruen (≤ 120000 ms), `ruff check`/`format --check` gruen, `mypy --strict app/` keine neuen Errors.
9. Grep `depends_on=pass1_job_id` in `app/` leer.
10. **Operator-Manual-Smoke** (nicht Teil der Code-DoD): Nach Merge — Upload mit frischen ungroupierten Findings → Pass-1 laeuft → Pass-2 startet ohne zweiten Upload abwarten zu muessen. Sichtbar im Audit-Log als `llm.pass2_auto_enqueued trigger=pass1_completion`.

## NICHT in diesem Ticket

- Aenderungen an Pass-2-Cache-Logik (`llm_risk_cache`) oder Fingerprint-Berechnung.
- UI-Anzeige des Trigger-Quells im Audit-View (bestehende Audit-Event-Filterung reicht).
- Aenderung der Sibling-Wait-SQL im Pickup (`llm_worker.py:_pick_next_job_id`) — die ist bereits korrekt.
- Multi-Worker-Concurrency-Optimierungen (Block U gilt weiter; Helper ist bereits race-safe via `NOT EXISTS`-Guard).
- Aenderung des `application_group_evaluations`-Schemas (Block T / ADR-0028 bleibt unveraendert).
- Retry-Strategie fuer final-failed Pass-1-Jobs (z. B. „re-queue beim naechsten Ingest") — separates Ticket.
- ARCHITECTURE.md-Update: §12 beschreibt die Trigger-Kette heute nicht im Detail (nur „asynchroner Worker pollt llm_jobs"). Wenn das nach diesem Ticket noch verlangt wird → separater Doc-Commit.

## Warum kein ADR

Die bestehende Pass-1→Pass-2-Architektur (ADR-0023) bleibt unveraendert. Die Sibling-Wait-Semantik im Worker-Pickup ist bereits korrekt implementiert und wird nicht angefasst. Die Junction-Tabelle aus ADR-0028 bleibt das Source-of-Truth fuer Eval-Ergebnisse. Was sich aendert:

1. Ein redundantes `depends_on`-Feld wird nicht mehr gesetzt (Bug-Fix, kein Design-Wechsel).
2. Der Trigger-Punkt fuer Pass-2-Enqueue wird von „einmal pro Scan-Upload" auf „nach jedem Pass-1-Completion + Backstop" erweitert (Operativer Fix, ADR-0023 §"Asynchroner Worker" sieht das ohnehin so vor — die heutige Implementation hat das nur unvollstaendig umgesetzt).

Damit ist die Aenderung **konsistent mit der bestehenden Spec** und kein neuer Architektur-Entscheid. Wer beim Review nach einer ADR fragt: ADR-0023 §"Two-Pass-Architektur" + §"Asynchroner Worker" sind die normativen Referenzen.

## Bezug zur Test-Konvention (CLAUDE.md)

Jeder Implementer-/Test-Writer-Subagent-Aufruf zu diesem Ticket enthaelt woertlich:

> Erlaubte Quality-Gates: ruff, mypy, shellcheck (Linter), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, keine neuen .bats-/.sh-Test-Dateien. Jeder pytest-Bash-Aufruf hat ein timeout-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

Pass-2-Trigger-Logik ist vollstaendig Pure-Unit-testbar (Mock-Sessions, ORM-Stubs). Postgres-Reflection ist nicht noetig — die SQL-Strings im Sibling-Check und Backstop-Sweep werden gegen Snapshot-Strings verifiziert, ihre Semantik wird in Etappe-4-User-Smoke validiert.

## Bezug zur HTMX-OOB-Single-Source-Doktrin

Nicht anwendbar — dieses Ticket hat kein UI-Touch und keinen OOB-Endpoint. Die Audit-View-Anzeige des neuen `llm.pass2_auto_enqueued`-Events nutzt den bestehenden generischen Audit-Renderer.
