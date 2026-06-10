# TICKET-010 — „Jetzt"-Konsistenz: Reopen-on-Redetect + OPEN-only-Eval + Live-Worst-Finding

**Status:** Freigegeben (Entscheidungen 1–3 vom User bestätigt) · **Datum:** 2026-06-10 · **Bezug:** ARCHITECTURE.md §5/§12, ADR-0023 (Two-Pass), ADR-0028 (Eval-Junction), TICKET-007 (pass2_enqueue).
**Komponenten:** `app/services/findings_ingest.py`, `app/workers/llm_worker.py`, `app/services/pass2_enqueue.py`, `app/views/server_detail.py`, `app/views/findings.py`, `app/api/bulk.py`, Templates `servers/_action_needed_section.html` + `_partials/application_group_card.html`, Tests.
**Umfang:** Kein Schema, keine Migration, kein neuer Endpoint. Vier Etappen mit je eigener Commit-Grenze.

## Problem (Befund 2026-06-10, ftp-server / CVE-2026-31431)

### Bug A — Kein Reopen-on-Redetect (Datenkorrektheit)

Die Resolve-Phase (`findings_ingest.py:485–512`) setzt pro Ingest alle OPEN/ACK-Findings auf
RESOLVED, deren `(identifier_key, package_name)` nicht im aktuellen Scan ist. Das Upsert
(`ON CONFLICT`, Zeile 419 ff.) fasst `status` aber **nie wieder an** — taucht das Tupel im
nächsten Scan wieder auf, bleibt das Finding für immer RESOLVED (`last_seen_at` läuft weiter).
Ein einziger partieller Scan / trivy-db-Aussetzer schließt echte Findings dauerhaft und still.
Detektor: `status='resolved' AND last_seen_at > resolved_at` (siehe `diagnose_cve-2026-31431.sql` §7).

### Bug B — Fingerprint-Domain-Mismatch Enqueue ↔ Worker (Eval-Input)

`pass2_enqueue.enqueue_pass2_for_server()` berechnet den Group-Fingerprint über **OPEN-only**
(`pass2_enqueue.py:130–143`). Der Worker `_do_pass2` lädt, bewertet und fingerprintet dagegen
**alle** Findings der Group inkl. resolved/acknowledged (`llm_worker.py:1436–1444`). Folgen:

1. Das LLM bekommt geschlossene Findings als Input und kann sie als `worst_finding_id` wählen
   → Operator-Workflow-Card zeigt geschlossene CVEs als handlungsrelevant.
2. Sobald eine Group non-open Findings enthält, matcht der gespeicherte Eval-Fingerprint
   (ALL-Set) nie den Enqueue-Fingerprint (OPEN-Set) → die Group wird bei **jedem** Ingest
   erneut enqueued (Dauer-Re-Eval-Schleife; meist Cache-Hit, aber Job-Churn + nie konvergent).

### Bug C — Server-Detail rendert Snapshot statt Jetzt-Zustand (UI)

`server_detail._load_application_groups_for_server()` Query (4) löst `worst_finding_id` nur mit
`server_id`-Guard auf — **ohne Status-Filter**. Die Workflow-Card und die Group-Card zeigen damit
ein geschlossenes Finding als „Worst Finding", während `/findings` (live, `status=open`) es
korrekt nicht listet. Operator-Verwirrung: Detail-Seite und Findings-Liste widersprechen sich.

**Leitprinzip der Lösung:** Operator-Sichten (Workflows, Group-Cards, /findings) zeigen den
**Jetzt-Zustand** aus `findings.status`; der Eval-Snapshot liefert nur Bewertung (Band, Reason,
Action-Type) für Groups, die jetzt offene Findings haben. Historische Sichten (Heartbeat,
daily_risk_state) bleiben Snapshot — unverändert.

## Etappen-Schnitt

Reihenfolge nach Nutzen/Risiko: 1 (Datenkorrektheit) → 2 (Eval-Input) → 3 (UI) → 4 (Trigger).
Jede Etappe einzeln shippable; 3 profitiert von 2, funktioniert aber auch ohne.

### Etappe 0 — ADR-0052

ADR „Operator-Sichten zeigen Jetzt-Zustand" mit den drei Entscheidungen unten; Status-Notes auf
ADR-0023/0028 (Eval-Input-Semantik präzisiert). Branch `feat/ticket-010-live-now` von `main`
(nach Merge von `feat/remove-ai-assessment`).

### Etappe 1 — Reopen-on-Redetect im Ingest (Bug A)

**Datei:** `app/services/findings_ingest.py`.

- Vor dem Upsert (analog zur Resolve-Phase, gleicher Python-Filter-Trick): IDs aller
  RESOLVED-Findings des Servers ermitteln, deren `(identifier_key, package_name)` im
  `current_keys`-Set liegt → `ids_to_reopen`.
- `UPDATE findings SET status='open', resolved_at=NULL WHERE id IN (...)` vor dem Upsert
  (ein Statement, idempotent).
- **ACK bleibt ACK** — ein vom Operator abgehaktes Finding wird durch Redetect nicht wieder
  aufgemacht (Operator-Entscheid schlägt Scanner). Nur `resolved → open`.
- `ScanIngestResult` + `scan.ingested`-Audit-Metadata um `findings_reopened` erweitern.
- Einmaliger Bestands-Heal: kein Migrations-Backfill nötig — der nächste Scan jedes Servers
  reopened betroffene Findings automatisch (genau die Wiedergänger aus Diagnose-Query 7).

**Tests (Pure-Unit):** Filter-Logik `ids_to_reopen` als reine Funktion (Set-Vergleich, ACK
ausgeschlossen, leeres Set), Result-/Audit-Felder. Upsert-/UPDATE-Semantik gegen echtes
Postgres = db_integration → **steht beim User an**.

### Etappe 2 — Pass-2 bewertet nur OPEN (Bug B)

**Dateien:** `app/workers/llm_worker.py` (`_do_pass2`, beide Findings-Loads), Doku-Touch
`app/services/llm_fingerprints.py` (Docstring präzisieren: Input ist OPEN-Set).

- Beide `select(Finding)`-Loads in `_do_pass2` (Fingerprint-Phase Z. 1436 ff. und
  Detached-Reload Z. 1513 ff.) um `Finding.status == FindingStatus.OPEN` ergänzen —
  **identische WHERE wie `pass2_enqueue`** (Single-Source-Kommentar mit Querverweis).
- Damit: Worker-Fingerprint == Enqueue-Fingerprint → Dauer-Re-Enqueue endet;
  `worst_finding_id` ist konstruktionsbedingt immer ein offenes Finding (Schema-Validierung
  „muss in finding_ids liegen" existiert bereits in `llm_risk_reviewer`).
- **Rollout-Hinweis Cache:** bestehende `llm_risk_cache`-Keys basieren auf ALL-Set-Fingerprints
  → einmalig Cache-Miss pro (group, server) mit non-open Findings = begrenzter
  LLM-Kosten-Burst beim ersten Ingest danach. Kein Flush nötig, alte Keys veralten passiv.

**Tests (Pure-Unit):** bestehende Worker-Tests (Fakes) erweitern: resolved Finding in Group →
nicht im LLM-Input, nicht als worst wählbar; Fingerprint-Gleichheit Enqueue↔Worker bei
gemischten Status-Sets (genau der Bug-B-Regression-Test).

### Etappe 3 — Server-Detail: Live-Worst-Finding (Bug C)

**Dateien:** `app/views/server_detail.py`, `servers/_action_needed_section.html`,
`_partials/application_group_card.html`.

- Query (4) ersetzen durch **ein** `DISTINCT ON (application_group_id)`-Query über alle
  `group_ids` des Servers: `WHERE server_id=:id AND status='open' AND application_group_id
  IN (...)`, Order pro Group nach §15-Triage (`is_kev DESC, epss DESC NULLS LAST, cvss DESC
  NULLS LAST, severity_rank DESC, first_seen_at ASC`). Gleiche Kostenklasse wie die ersetzte
  Batch-Query (eine indizierte Query pro Render; `group_ids` stammen eh aus dem OPEN-Count).
  `eval.worst_finding_id` wird für die Anzeige **nicht mehr** verwendet.
- Eval-Row liefert weiterhin Band/Reason/Action-Type (Card-Zuordnung unverändert).
- Drift-Kennzeichnung: wenn `evaluation.worst_finding_id` ≠ Live-Worst-ID → kleiner Hint
  „re-evaluation pending" neben der Reason (englisch, ADR-0045) statt stillschweigend
  veralteten Text als aktuell auszugeben. Kein Fingerprint-Recompute im Request-Pfad
  (zu teuer) — der ID-Vergleich ist gratis.
- `worst_finding`-Vertrag der Templates bleibt (`identifier_key`/`package_name`/`title`) —
  reine Datenquellen-Änderung im Loader, beide Templates konsumieren denselben Entry.

**Tests (Pure-Unit):** View-Tests mit Fakes (Live-Worst ersetzt Snapshot-Worst; Group ohne
offene Findings erscheint nicht; Hint-Render bei ID-Drift), Template-Drift-Tests bestehend.
`DISTINCT ON`-Semantik gegen Postgres = db_integration → **steht beim User an**.

### Etappe 4 — Triage-Aktionen triggern Re-Eval sofort

**Dateien:** `app/views/findings.py` (acknowledge, reopen, group_acknowledge,
bulk_acknowledge), `app/api/bulk.py`, `app/services/pass2_enqueue.py` (neuer
Trigger-Literal `"triage_action"`).

- Nach erfolgreichem Status-Write: `enqueue_pass2_for_server(sess, server_id,
  trigger="triage_action")` — idempotent + fingerprint-gated, enqueued also nur wenn sich
  das OPEN-Set wirklich geändert hat (nach Etappe 2 exakt richtig). Bulk-Pfade: distinct
  `server_ids` der betroffenen Findings sammeln, ein Aufruf pro Server.
- Ohne diese Etappe passiert das Re-Eval erst beim nächsten Scan (24-h-Lücke).

**Tests (Pure-Unit):** Endpoint-Tests (Fakes): Ack → Enqueue-Aufruf mit richtigem Trigger;
kein Enqueue wenn nichts geändert.

## Bewusst NICHT in diesem Ticket

- **Partial-Scan-Guard** (Resolve-Phase skippen wenn `findings_total` z. B. < 50 % des
  Vorscans): braucht persistierte Scan-Totals (`scans`-Spalte = Migration) oder
  Audit-Lookup. Durch Etappe 1 verliert der Fall seine Dauerhaftigkeit (nächster Scan
  heilt) — Guard nur nachrüsten, falls Resolve-/Reopen-Flapping im Audit auffällt.
  → Re-Open-Trigger.
- `finding_status_history`-Tabelle (saubere Historie über Reopens, vgl. ADR-0018
  „Bekannte Limitation") — separates Thema, gleiche Triggerbedingung wie dort.
- Anzeige von acknowledged Findings in den Workflow-Cards (bleiben draußen — abgehakt
  ist abgehakt).

## Performance-Bilanz

- Etappe 1: ein zusätzlicher indizierter SELECT + ggf. ein UPDATE pro Ingest — gleiche
  Größenordnung wie die bestehende Resolve-Phase.
- Etappe 2: **reduziert** Last (Dauer-Re-Enqueue-Schleife entfällt); einmaliger
  Cache-Miss-Burst, danach normale Fingerprint-Gates.
- Etappe 3: ersetzt eine Batch-Query durch eine gleich teure; kein N+1, kein neuer Index
  nötig (`server_id`-Indizes existieren; bei Auffälligkeit Partial-Index
  `(server_id, application_group_id) WHERE status='open'` als Option notieren).
- Etappe 4: ein idempotenter Enqueue-Aufruf pro Triage-Aktion (zwei kleine SELECTs).
- LLM-Kosten entstehen nur bei echter OPEN-Set-Änderung; Two-Level-Cache bleibt wirksam.

## DoD (je Etappe)

- [ ] `ruff check . && ruff format --check .` grün
- [ ] `mypy app/` grün
- [ ] Default-`pytest` grün (Pure-Unit; Bash-timeout ≤ 120 s), neue Regression-Tests je Etappe
- [ ] Keine neuen deutschen UI-Strings (Sprach-Sweep-Test, ADR-0045)
- [ ] db_integration-Läufe (Upsert-/Reopen-Semantik, DISTINCT ON) **beim User anstehend**
- [ ] Operator-Browser-Smoke (User): ftp-server-Workflow-Card zeigt offenes Worst-Finding;
      /findings und Server-Detail konsistent; Diagnose-Query 7 nach erstem Scan-Zyklus leer

## Entscheidungen (User, 2026-06-10)

1. **ACK + Redetect:** bleibt ACK — nur `resolved → open`.
2. **Drift-Hint-Wording:** „re-evaluation pending".
3. **Etappe 4 (Sofort-Re-Eval bei Triage):** wird mitgenommen.
