# ADR-0042 — Agent-Fire-and-Forget: Job-Status-Endpoint und Polling-Loop entfernt

**Status:** Akzeptiert
**Datum:** 2026-05-28
**Block:** keiner (Post-Block-R-Vereinfachung)
**Supersedes (teilweise):** ADR-0026 §Status-Endpoint, §Agent-Polling, §Begründung-Trade-off-Polling und die zugehörigen Re-Open-/Konsequenz-Punkte. Der Async-Ingest-Kern aus ADR-0026 (Queue-Tabelle, Edge-Fast-Path, Worker-Sub-Tick, Idempotency, Payload-Transit-Ausnahme) bleibt unverändert in Kraft.

## Kontext

ADR-0026 hat den synchronen `POST /api/scans` durch einen asynchronen Fast-Path
ersetzt: Der Edge antwortet binnen <1s mit `202 + job_id`, die Verarbeitung
läuft im `secscan-llm-worker`. Um das Ergebnis sichtbar zu machen, führte
ADR-0026 zwei Dinge ein:

1. **Status-Endpoint** `GET /api/scans/jobs/<job_id>` (Bearer-Auth, Server-scoped).
2. **Agent-Polling-Loop** in `secscan-agent.sh` (2s-Intervall, max 600s, Exit-Codes
   4 = `failed`, 5 = Polling-Timeout).

ADR-0026 selbst markierte den Polling-Zwang als bewussten Trade-off
(§Begründung: „der Agent muss jetzt zwingend den Status pollen, um eine
Validation-Failure zu sehen").

In der Praxis hat dieser Polling-Pfad keinen Nutzen, der seine Kosten
rechtfertigt:

- Der Agent läuft als Cron-/systemd-Timer-Job ohne Operator am Terminal. Der
  Polling-Exit-Code landet im Cron-Log und wird nicht ausgewertet.
- Der Operator beobachtet Scan-Fortschritt und -Ergebnis ohnehin im Dashboard,
  nicht im Agent-Output. Das Dashboard pollt seinerseits per HTMX (ADR-0019) und
  reflektiert den Worker-Fortschritt live.
- Validation-/Verarbeitungs-Fehler materialisieren sich als Audit-Event
  `scan.ingest_failed` und als `status='failed'`-Zeile — beide im Server
  sichtbar, unabhängig vom Agent.
- Der Polling-Loop hält den Agent-Prozess bis zu 10 Minuten am Leben, hält eine
  Bearer-authentifizierte Verbindung offen und erzeugt Last (bis zu 300 Status-
  Requests pro Scan) ohne Gegenwert.

## Entscheidung

**Der Agent beendet nach der `202`-Annahme sofort mit Exit 0 (Fire-and-Forget).**
Der Server verarbeitet den Scan asynchron; der Agent wartet nicht auf das
Ergebnis.

Konkret:

1. **`secscan-agent.sh`**: Polling-Loop ersatzlos entfernt. Nach `202` wird
   `Scan accepted (job_id=…)` geloggt und mit Exit 0 beendet. Exit-Codes 4
   (`failed`) und 5 (Polling-Timeout) entfallen. `SECSCAN_POLL_MAX_SEC` entfällt.
2. **Status-Endpoint `GET /api/scans/jobs/<job_id>` entfernt** (`app/api/scans.py`):
   Route `scan_job_status`, Serializer `_serialize_job_status` und Konstante
   `_MAX_ERROR_LEN` gelöscht.
3. **202-Response-Body** schrumpft von `{job_id, status, status_url}` auf
   `{job_id, status}`. Das `status_url`-Feld entfällt, weil es auf den entfernten
   Endpoint zeigte.
4. **Worker, Queue-Tabelle, Idempotency und Payload-Lifecycle bleiben
   unverändert** — die Entfernung betrifft ausschließlich die agent-seitige
   Ergebnis-Abfrage, nicht den Verarbeitungs-Pfad.

Das **UI-Polling** (ADR-0019: Dashboard-Pane + Sidebar per HTMX) ist hiervon
unberührt und bleibt der kanonische Weg, Scan-Fortschritt und -Ergebnis zu sehen.

## Begründung

- **Kein Konsument.** Der offizielle Agent hat den Status nie für eine
  Operator-Entscheidung genutzt — der Exit-Code verschwand im Cron-Log. Ein
  Endpoint ohne realen Konsumenten ist Angriffsfläche und Wartungslast ohne
  Nutzen.
- **Single Source of Truth fürs Ergebnis ist das Dashboard.** Fortschritt
  (queued → in_progress → done/failed) und Fehler sind im Server vollständig
  abgebildet (Job-Zeile + Audit-Events) und im UI live sichtbar. Eine zweite,
  agent-seitige Sicht auf denselben Zustand ist Redundanz.
- **Weniger Last und kürzere Agent-Laufzeit.** Statt bis zu 300 Status-Requests
  und 10 Minuten Prozess-Lebenszeit pro Scan endet der Agent in Sekunden.
- **Der ADR-0026-Trade-off entfällt sauber.** ADR-0026 akzeptierte den
  Polling-Zwang nur, „um eine Validation-Failure zu sehen". Da Failures bereits
  serverseitig sichtbar sind, war der Trade-off nie nötig.

## Konsequenzen

- **API-Contract-Change:** `GET /api/scans/jobs/<id>` existiert nicht mehr (vorher
  `200`/`404`, jetzt `404` als generischer Not-Found). 202-Body enthält kein
  `status_url` mehr. Da der offizielle Agent das Body nie geparst und nach dem
  Wegfall nicht mehr pollt, ist die Änderung für ihn non-breaking. Inoffizielle
  Clients, die gegen den Status-Endpoint pollen, brechen — Mitigation ist
  dieselbe wie bei ADR-0026: Min-Agent-Version anheben, alte Agents laufen auf
  `agent_outdated`-400 und triggern Auto-Update.
- **Tests:** `tests/api/test_scan_status_endpoint_unit.py` entfernt (testete nur
  den gelöschten Serializer). Der `status_url`-Assert in
  `tests/api/test_scans_async_edge.py` und der Status-Endpoint-Abschnitt in
  `tests/workers/test_scan_ingest_e2e_flow.py` entfernt.
- **Doku:** `ARCHITECTURE.md` §Block-R, `docs/blocks/R-async-ingest.md`,
  `docs/operations.md`, `CHANGELOG.md` und `docs/blocks/STATE.md` werden
  entsprechend nachgezogen (Endpoint + Polling als entfernt markiert).
- **Keine Schema-Änderung.** Die `scan_ingest_jobs`-Tabelle und ihre Indizes
  bleiben unverändert — sie dienen weiterhin Queue, Idempotency und
  Server-scoped-Lookups im Worker. Der Status-Endpoint war nur ein Reader darauf.

## Re-Open-Trigger

- **Wenn ein nicht-interaktiver Client das Scan-Ergebnis programmatisch braucht**
  (z.B. CI-Gate, das auf `done`/`failed` wartet), kann ein Status-Endpoint
  zurückkehren — dann aber bewusst als API für externe Automatisierung designt,
  nicht als Agent-Polling-Krücke. Eigene ADR.
- **Wenn das Dashboard-Polling als Ergebnis-Sicht nicht ausreicht** (z.B.
  Air-Gap-Betrieb ohne UI-Zugang), Re-Evaluierung der agent-seitigen
  Ergebnis-Rückmeldung. Eigene ADR.
