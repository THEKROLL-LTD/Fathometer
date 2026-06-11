# ADR-0052 — Operator-Sichten zeigen Jetzt-Zustand (Reopen-on-Redetect + OPEN-only-Eval + Live-Worst-Finding)

**Status:** Akzeptiert · **Datum:** 2026-06-10 · **Ticket:** [TICKET-010](../tickets/TICKET-010-live-now-consistency.md)

Bezug: [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md) (Two-Pass-Risk-Reviewer — Eval-Input-Semantik wird hier präzisiert), [ADR-0028](0028-application-group-evaluations-junction.md) (Eval-Junction — Snapshot-Felder bleiben, ihre UI-Verwendung wird eingeschränkt), TICKET-007 (`pass2_enqueue` als Single-Source-Trigger), ARCHITECTURE.md §5 (Ingest/Resolve), §12 (Risk-Reviewer), §15 (Triage-Order).

## Kontext

Befund vom 2026-06-10 (ftp-server / CVE-2026-31431, Diagnose in `diagnose_cve-2026-31431.sql`): drei zusammenhängende Inkonsistenzen zwischen dem persistierten Eval-Snapshot und dem tatsächlichen Jetzt-Zustand der Findings.

1. **Bug A — kein Reopen-on-Redetect.** Die Resolve-Phase im Ingest setzt OPEN/ACK-Findings auf RESOLVED, deren `(identifier_key, package_name)` nicht im aktuellen Scan ist. Das Upsert fasst `status` aber nie wieder an — taucht das Tupel später wieder auf, bleibt das Finding für immer RESOLVED (`last_seen_at` läuft weiter). Ein einziger partieller Scan oder trivy-db-Aussetzer schließt echte Findings dauerhaft und still.
2. **Bug B — Fingerprint-Domain-Mismatch Enqueue ↔ Worker.** `pass2_enqueue` fingerprintet über das OPEN-Set, der Worker `_do_pass2` lädt/bewertet/fingerprintet ALLE Findings der Group (inkl. resolved/acknowledged). Folgen: das LLM bekommt geschlossene Findings als Input (und kann sie als `worst_finding_id` wählen); sobald eine Group non-open Findings enthält, matchen die Fingerprints nie → Dauer-Re-Enqueue bei jedem Ingest (nie konvergent).
3. **Bug C — Server-Detail rendert Snapshot statt Jetzt.** Der Group-Loader löst `evaluation.worst_finding_id` ohne Status-Filter auf — die Workflow-Card zeigt geschlossene CVEs als „Worst Finding", während `/findings` (live, `status=open`) sie korrekt nicht listet.

## Entscheidung

**Leitprinzip: Operator-Sichten (Workflow-Cards, Group-Cards, /findings) zeigen den Jetzt-Zustand aus `findings.status`. Der Eval-Snapshot liefert nur die Bewertung (Band, Reason, Action-Type) für Groups, die jetzt offene Findings haben. Historische Sichten (Heartbeat, `daily_risk_state`) bleiben Snapshot — unverändert.**

Konkret in vier Etappen (TICKET-010):

1. **Reopen-on-Redetect im Ingest.** Vor dem Upsert werden RESOLVED-Findings des Servers, deren `(identifier_key, package_name)` im aktuellen Scan wieder auftaucht, per `UPDATE … SET status='open', resolved_at=NULL` reopened (idempotent, ein Statement). `ScanIngestResult` und `scan.ingested`-Audit-Metadata erhalten `findings_reopened`. Kein Migrations-Backfill: der nächste Scan jedes Servers heilt den Bestand automatisch.
2. **Pass-2 bewertet nur OPEN.** Beide Finding-Loads in `_do_pass2` (Fingerprint-Phase + Detached-Reload) filtern auf `status='open'` — identische WHERE-Klausel wie `pass2_enqueue`. Damit konvergiert der Fingerprint-Gate (Dauer-Re-Enqueue endet) und `worst_finding_id` ist konstruktionsbedingt immer offen.
3. **Server-Detail: Live-Worst-Finding.** Der Group-Loader ermittelt das Worst-Finding pro Group live via `DISTINCT ON (application_group_id)` über offene Findings, Order nach §15-Triage (`is_kev DESC, epss DESC NULLS LAST, cvss DESC NULLS LAST, severity_rank DESC, first_seen_at ASC`). `evaluation.worst_finding_id` wird für die Anzeige nicht mehr verwendet; die Eval-Row liefert weiterhin Band/Reason/Action-Type. Bei ID-Drift (`evaluation.worst_finding_id` ≠ Live-Worst-ID) rendert die UI den Hint „re-evaluation pending" (englisch, ADR-0045) — kein Fingerprint-Recompute im Request-Pfad.
4. **Triage-Aktionen triggern Re-Eval sofort.** Acknowledge/Reopen/Group-Ack/Bulk-Ack rufen nach erfolgreichem Status-Write `enqueue_pass2_for_server(trigger="triage_action")` auf (idempotent + fingerprint-gated). Bulk-Pfade sammeln distinct `server_ids` und rufen einmal pro Server.

### User-Entscheidungen (2026-06-10)

1. **ACK + Redetect: bleibt ACK** — ein vom Operator abgehaktes Finding wird durch Redetect nicht wieder aufgemacht (Operator-Entscheid schlägt Scanner). Nur `resolved → open`.
2. **Drift-Hint-Wording:** „re-evaluation pending".

   > **Korrektur (TICKET-014, 2026-06-11):** Der Drift-Hint signalisiert „Eval veraltet ggü. Lane-OPEN-Set" (Fingerprint-Mismatch ODER Worst-Finding nicht mehr offen) — **nicht** „Anzeige-Worst ≠ Eval-Worst". Die Divergenz LLM-Wahl vs. deterministischer Triage-Sort ist erwartetes Normalverhalten und kein Drift. Die in Etappe 3 oben beschriebene ID-Drift-Bedingung (`evaluation.worst_finding_id` ≠ Live-Worst-ID) ist damit überholt; maßgeblich ist jetzt `ev.group_findings_fingerprint != group_findings_fingerprint(lane_open_findings)` ODER `ev.worst_finding_id ∉ Lane-OPEN-Set` — dasselbe Kriterium wie das Enqueue-Gate in `pass2_enqueue`. Die Anzeige-Spalte (Live-Worst, Etappe 3) bleibt unverändert.

3. **Etappe 4 (Sofort-Re-Eval bei Triage)** wird mitgenommen — ohne sie passiert das Re-Eval erst beim nächsten Scan (24-h-Lücke).

## Konsequenzen

- **Einmaliger Cache-Miss-Burst:** bestehende `llm_risk_cache`-Keys basieren auf ALL-Set-Fingerprints. Pro (group, server) mit non-open Findings gibt es nach Etappe 2 genau einen Cache-Miss beim ersten Ingest = begrenzter LLM-Kosten-Burst. Kein Flush nötig, alte Keys veralten passiv.
- **Bestands-Heal ohne Migration:** die fälschlich RESOLVED-gebliebenen Wiedergänger (Diagnose-Query 7) werden vom nächsten Scan jedes Servers automatisch reopened.
- **Last sinkt:** die Dauer-Re-Enqueue-Schleife (Bug B Folge 2) entfällt; Etappe 3 ersetzt eine Batch-Query durch eine gleich teure; Etappe 4 kostet einen idempotenten Enqueue-Aufruf pro Triage-Aktion.
- **Detektor bleibt nutzbar:** `status='resolved' AND last_seen_at > resolved_at` identifiziert Wiedergänger; nach einem vollen Scan-Zyklus muss die Menge leer sein.

### Bewusst nicht enthalten (Re-Open-Trigger in TICKET-010)

- **Partial-Scan-Guard** (Resolve-Phase skippen bei stark geschrumpftem `findings_total`) — braucht persistierte Scan-Totals; durch Etappe 1 verliert der Fall seine Dauerhaftigkeit.
- **`finding_status_history`** (saubere Historie über Reopens, vgl. ADR-0018 „Bekannte Limitation").
- **Acknowledged Findings in Workflow-Cards** — abgehakt ist abgehakt.
