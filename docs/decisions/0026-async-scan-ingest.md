# ADR-0026 — Asynchroner Scan-Ingest mit `scan_ingest_jobs`-Queue

**Status:** Akzeptiert · **Cutover abgeschlossen 2026-05-22** mit v0.12.0: das ursprünglich vorgesehene Feature-Flag `SECSCAN_SCAN_INGEST_ASYNC` ist ersatzlos entfernt, Async ist der einzige Pfad (kein Sync-Fallback mehr im Edge-Handler). Operator-Setups ohne `secscan-llm-worker`-Container sind nicht mehr unterstützt.
**Datum:** 2026-05-22
**Block:** R (Implementation, siehe `docs/blocks/R-async-ingest.md`)
**Vorgänger:** ADR-0003 (Push, nicht Pull), ADR-0005 (Roh-JSON wird nicht persistiert — wird durch dieses ADR um eine **Transit-Ausnahme** erweitert), ADR-0022 (Pre-Triage-Lauf wandert in den Worker), ADR-0023 (Worker-Modell als Vorbild)

## Kontext

`POST /api/scans` verarbeitet einen Scan heute komplett synchron im HTTP-Request-Handler (`app/api/scans.py`):

1. Auth-Header lesen + SHA-256 + `hmac.compare_digest` (~ms)
2. gzip-Decompress (bis 100 MB) + JSON-Parse (~10-100ms)
3. Pydantic-Envelope-Validation (~ms)
4. `findings_ingest.ingest_scan` — Bulk-UPSERT aller Findings
5. `persist_host_state` — UPSERT von Listenern/Prozessen/Modulen/Services
6. Pre-Triage-Loop **über alle OPEN-Findings des Servers** (nicht nur die neuen) — N × `pretriage(finding, server, snapshot_available)` plus N × Audit-Event
7. `GroupMatcher.reload + apply_matches_for_server` — Library-Reload + Pattern-Match-Lauf pro Finding
8. `inherit_group_risk_to_findings` — Bulk-UPDATE
9. Pass-1-Job-Erzeugung (Affinity-Sort + Batch-Split)
10. Pass-2-Job-Erzeugung pro affected Group (Fingerprint-Check)
11. `notify_conversations_for_scan` — LLM-Update-Hook
12. `sess.commit()` — erst jetzt: 202 + JSON-Body mit Counts.

Produktionsbefund 2026-05-22 (k3s-Server mit ~5000 OPEN-Findings):

- Pre-Triage-Loop (Schritt 6) dauert allein 8–25s (Python-Loop über alle Findings, Audit-Event pro Band-Wechsel → siehe parallel laufendes TICKET-003 für die Audit-Noise-Reduktion).
- `apply_matches_for_server` (Schritt 7) iteriert pro Pattern × Finding — auf großen Servern weitere 5–15s.
- Initial-Scan auf neuem Server (Bulk-UPSERT von 5000+ Findings) kann 15–30s ziehen.
- **Worst-Case ist die agent-seitige `--max-time 60`-Curl-Grenze.** Der Agent meldet `Error: upload failed (HTTP 000)`, der Operator sieht ein vermeintliches Connection-Problem, in Wirklichkeit hat der Server den Scan vollständig verarbeitet und dann ins TCP-Nirvana geantwortet.

Der secscan-llm-worker existiert bereits als Standalone-Prozess mit Postgres-basierter Job-Queue (`llm_jobs`, `SELECT FOR UPDATE SKIP LOCKED`, Stale-Reaper, Heartbeat-Daemon-Thread, Idle-Backoff). Das Pattern ist erprobt — es liegt nahe, den Ingest-Pfad analog asynchron zu machen.

## Entscheidung

`POST /api/scans` wird auf einen **synchronen Fast-Path** und einen **asynchronen Verarbeitungs-Pfad** aufgeteilt.

**Synchroner Fast-Path** (HTTP-Connection-Lifetime < 1s):

1. Auth-Header lesen + SHA-256-Verify (unverändert).
2. Server-Active-Check (unverändert).
3. gzip-Decompress mit 100-MB-Bound (unverändert).
4. **SHA-256 über den dekomprimierten Body** als Idempotency-Key (`payload_sha256`).
5. **Optional** Pydantic-Envelope-Pre-Validation — auf einem _schmalen_ Sub-Schema das nur `agent_version`, `host.hostname` und `scan.metadata` prüft. Vollvalidierung läuft im Worker.
6. Agent-Version-Gate (`agent_outdated` → 400, unverändert).
7. INSERT in `scan_ingest_jobs` mit `(server_id, payload_gzip BYTEA, payload_sha256 UNIQUE, status='queued')`. Bei Unique-Conflict auf `payload_sha256`: vorhandene `job_id` zurückgeben (Retry-Idempotenz).
8. Audit-Event `scan.queued` mit `{job_id, payload_sha256, payload_bytes}`.
9. **HTTP 202** mit Body `{"job_id": ..., "status": "queued", "status_url": "/api/scans/jobs/<id>"}`.

**Asynchroner Verarbeitungs-Pfad** im `secscan-llm-worker` (neuer Sub-Tick `scan_ingest_tick`):

1. `SELECT FOR UPDATE SKIP LOCKED FROM scan_ingest_jobs WHERE status='queued' AND next_attempt_at <= now() ORDER BY created_at LIMIT 1`.
2. Status → `in_progress`, `picked_up_at`, `picked_up_by`.
3. gzip-Decompress des `payload_gzip` (Bytea → bytes → JSON-Parse mit Tiefen-Bound).
4. **Vollständige Pydantic-Envelope-Validation.** Bei `ValidationError` → Status `failed` mit `error` (JSON-Schema-Errors). Audit `scan.ingest_failed`.
5. Original-Verarbeitungssequenz aus Schritt 4–11 des heutigen sync Handlers — UNVERÄNDERT in der Reihenfolge und Logik.
6. Status `done`, `finished_at`, `scan_id` (FK auf den erzeugten `scans`-Row), Counts in `result`-JSONB.
7. **`payload_gzip` wird auf `NULL` gesetzt** (oder in einem nachgelagerten TTL-Sweep entfernt). Damit bleibt ADR-0005 substantiell erhalten — das Roh-JSON ist nur Transit-Speicher.
8. Audit `scan.ingested` mit Counts (semantisch identisch zum heutigen Event — nur emittiert vom Worker statt vom Web-Container).

**Status-Endpoint** `GET /api/scans/jobs/<job_id>` (Bearer-Auth, Server-scoped):

- Liefert `{job_id, status, created_at, finished_at, scan_id, error, counts}`.
- `status ∈ {queued, in_progress, done, failed}`.
- Bei `done`: `counts = {findings_total, findings_inserted, findings_updated, findings_resolved, class_os_pkgs, class_lang_pkgs, class_other}` — semantisch identisch zum heutigen 202-Response-Body.
- Bei `failed`: `error` als String (max 4 KB, höhere Details im Worker-Debug-Log).

**Agent-Polling** in `secscan-agent.sh`:

- Nach `POST /api/scans` mit 202: Polling-Loop `GET /api/scans/jobs/<id>` mit 2s-Intervall, max 600s (10 Min).
- Bei `done`: Exit 0, Server-Response-Counts loggen.
- Bei `failed`: Exit 4 (neuer Exit-Code), `error` ausgeben.
- Bei Polling-Timeout: Exit 5 (Job hängt — Operator-Aktion erforderlich; Job bleibt in der Queue, Stale-Reaper greift später).

## Begründung

**Warum eine eigene Job-Tabelle und nicht `llm_jobs.job_type='scan_ingest'`?** Vier Gründe:

1. `scan_ingest_jobs` hat zwingend einen großen `BYTEA`-Payload (1–10 MB nach gzip, bis 100 MB unkomprimiert). `llm_jobs.payload JSONB` ist für ~kB-Pakete ausgelegt — JSONB-Toast-Slicing wäre verschwenderisch. `BYTEA` mit `STORAGE EXTERNAL` ist die richtige Wahl für blob-Daten.
2. `llm_jobs` hat einen `CheckConstraint("job_type IN ('group_detection','risk_evaluation')")` — eine dritte Job-Art würde den Constraint und alle bestehenden Pickup-/Stale-/Cache-Indizes überdehnen.
3. Lifecycle ist anders: `llm_jobs` haben eine `depends_on`-Kette (Pass-2 wartet auf Pass-1), Pass-2 hat Sibling-Wait-Logik (kein Pass-1 darf parallel laufen). Ingest-Jobs sind einfache First-In-First-Out-Jobs ohne Dependencies.
4. Stale-Reaper-Schwellwert ist anders: `llm_jobs` haben einen LLM-Call der minutenlang stehen kann (`HEARTBEAT_MAX_AGE_SEC=30 × failureThreshold=3 × periodSeconds=30 = 90s`). Ingest-Jobs sind reine DB-Arbeit ohne externe Calls — Stale nach 5 Minuten ist realistisch.

**Warum SHA-256 als Idempotency-Key statt clientseitiger `correlation_id`?**

- Der Agent hat keinen persistenten State zwischen Cron-Aufrufen — eine `correlation_id` müsste pro Scan random sein und somit beim Retry _anders_, was Idempotenz nicht löst.
- `payload_sha256` deduziert sich aus dem gzip-Decompressed-Body. Zwei identische Scans (Re-Upload nach Timeout) haben denselben Hash → Server kann den existierenden Job zurückgeben statt einen neuen anzulegen.
- Trivy-Output ist **nicht** byte-für-byte stabil über Scans hinweg (Timestamps, Result-Ordering) — Race: ein wirklich-neuer Scan kann zufällig denselben Hash wie ein laufender haben, das ist astronomisch unwahrscheinlich (SHA-256-Kollision). Akzeptiert.
- 64-Char-Hex-Spalte plus Unique-Index ist günstig (~100 Bytes pro Row + Index-Entry).

**Warum nur _Pre-Validation_ am Edge, nicht volle Pydantic-Validation?**

- Pydantic-Vollvalidierung auf einem 5 MB Trivy-JSON dauert auf einem schwach dimensionierten Web-Pod 100–300ms — nicht das Problem, aber auch nicht trivial.
- Wichtiger: bei einer im Edge synchron geprüften Envelope-Struktur müssten wir Validation-Errors als 422 zurückgeben, was den 202-Fast-Path zerschießt. Stattdessen: Pre-Validation prüft nur _grundsätzliche Wohlformiertheit_ (Top-Level JSON-Objekt, `agent_version` String) — alles weitere wandert in den Worker und materialisiert sich als `status='failed'` mit `error` im Status-Endpoint.
- **Trade-off:** der Agent muss jetzt zwingend den Status pollen, um eine Validation-Failure zu sehen. Akzeptiert — der Polling-Loop ist die natürliche Stelle dafür.

**Warum Sub-Tick im bestehenden Worker und kein eigener Worker-Container?**

- Postgres-FOR-UPDATE-SKIP-LOCKED erlaubt N parallele Worker auf derselben Tabelle ohne extra Koordination — wir brauchen es heute nicht (Single-Worker-Deploy), aber die Architektur ist multi-worker-bereit.
- Operationelle Komplexität: zwei Worker-Prozesse statt einem würde docker-compose-Healthchecks, k8s-Probes und Logging verdoppeln. Sub-Tick im bestehenden `_tick()` ist günstiger.
- **Trade-off:** Ingest-Job-Verarbeitung läuft auf demselben CPU-Budget wie LLM-Worker. Bei voller LLM-Queue stehen Ingest-Jobs in der Warteschlange. Mitigation: Ingest-Sub-Tick läuft **vor** LLM-Pickup im `_tick()`, Ingest-Jobs werden also priorisiert. Bei nachhaltigen Performance-Problemen kann ein eigener Worker-Prozess als Folge-Block (eigene ADR) eingeführt werden.

**Warum `BYTEA` mit gzip-Payload und nicht `JSONB`?**

- Wir haben den gzipped Body bereits in der Hand (HTTP-Decompression-Stage liest und entpackt). Re-Komprimieren um JSONB zu speichern wäre verschwenderisch.
- JSONB würde den Body parsen und in Postgres' internem Format speichern — wir wollen den Body aber nur _transitiv_ halten, nicht queryen. `BYTEA` ist die richtige Wahl.
- Postgres' `STORAGE EXTERNAL` für die `payload_gzip`-Spalte hebelt Toast-Compression aus (das ist gut — wir komprimieren bereits clientseitig).

**Warum ADR-0005 nicht verwerfen?**

- ADR-0005 hat zwei separate Aussagen: (a) `scans.raw_json`-jsonb-Spalte gibt es nicht, (b) das Trivy-JSON wird nicht _persistent_ gespeichert.
- (a) bleibt unverändert — `scans`-Tabelle hat keine raw_json-Spalte.
- (b) bekommt eine Transit-Ausnahme: `scan_ingest_jobs.payload_gzip` lebt typischerweise <5 Minuten (Job-Pickup + Verarbeitung) und wird beim Status=`done` auf NULL gesetzt. Bei `failed` bleibt das Payload für Debugging maximal 24h erhalten (Retention-Sweep im Worker-Sub-Tick), dann gelöscht.
- Das ist semantisch konsistent: kein langfristiges Roh-JSON-Storage, sondern eine Queue mit selbstreinigendem Payload.

## Konsequenzen

**API-Contract-Change** (Breaking für Agent-Clients):

- POST `/api/scans` 202-Response-Body ändert sich von `{"scan_id", "ingested_at", "findings_total", "findings_inserted", "findings_updated", "findings_resolved"}` auf `{"job_id", "status": "queued", "status_url": "/api/scans/jobs/<id>"}`.
- Alle Agent-Versionen < 0.4.0 brechen, falls sie das 202-Response-Body parsen (heute parsen sie es _nicht_ — siehe `agent/secscan-agent.sh` Zeilen 410–419, der Agent prüft nur `http_status`). Damit ist die Änderung für den offiziellen Agent **non-breaking**.
- Inoffizielle Clients die das 202-Body parsen müssen aktualisiert werden. Migration: Backend setzt für 8 Wochen den alten Body als Co-Response — nein, verworfen, weil der alte Body Counts enthält die wir asynchron nicht haben. Stattdessen: Agent-Min-Version auf 0.4.0 hochziehen (in `app/config.Settings.MIN_AGENT_VERSION`), Agent <0.4.0 läuft auf `agent_outdated`-400 und triggert Auto-Update.

**Schema-Änderungen** (Alembic-Migration `0010_scan_ingest_jobs.py`):

- Neue Tabelle `scan_ingest_jobs` mit Spalten siehe Block-R Phase A.
- Neuer Postgres-Index `ix_scan_ingest_jobs_pickup` (Partial auf `status='queued'`).
- Neuer Unique-Index `ux_scan_ingest_jobs_payload_sha256`.
- Keine Änderung an `scans`, `findings`, `llm_jobs`, `application_groups`.

**Worker-Erweiterung**:

- Neuer Sub-Tick `_run_scan_ingest_tick` in `_tick()` — _vor_ dem LLM-Pickup (Priorisierung).
- Neue Service-Funktion `scan_ingest_worker.process_job(job_id)` die die ehemalige sync-Logik aus `app/api/scans.py:283–540` aufruft.
- Stale-Reaper kennt `scan_ingest_jobs` als zweite Tabelle (Schwellwert 5min, Retries `MAX_ATTEMPTS=3`).
- **Payload-Lifecycle für `status='done'`**: `payload_gzip` wird _atomar im selben UPDATE_ wie der Status-Wechsel auf `NULL` gesetzt. Roh-Body lebt nur so lange wie der Verarbeitungs-Lauf (Sekunden bis Minuten).
- **Payload-Retention-Sweep** im Worker (stündlich) als Safety-Net: `UPDATE scan_ingest_jobs SET payload_gzip=NULL WHERE status='done' AND payload_gzip IS NOT NULL AND finished_at < now() - interval '1 hour'` fängt Crash-Reste ab. Zusätzlich `DELETE FROM scan_ingest_jobs WHERE status='failed' AND finished_at < now() - interval '24 hours'` — bei `failed` bleibt der Payload bewusst 24h für Operator-Debugging erhalten, danach wird die komplette Zeile entfernt.

**Audit-Event-Reihenfolge**:

- Neue Action `scan.queued` — emittiert vom Web-Container beim Job-Insert (Body: `{job_id, payload_sha256, payload_bytes}`).
- Bestehende Action `scan.ingested` — emittiert vom Worker nach erfolgreichem Verarbeitungs-Lauf (Body unverändert).
- Bestehende Action `host_state.snapshot_received` / `host_state.parse_failed` — bleibt, wird vom Worker emittiert.
- Bestehende Action `risk.pretriage_evaluated` — bleibt, vom Worker emittiert.
- Bestehende Action `llm.jobs_queued` — bleibt, vom Worker emittiert.
- Neue Action `scan.ingest_failed` — emittiert vom Worker bei Pydantic-/SQL-Failures (Body: `{job_id, error_class, error_detail_truncated}`).
- _Reihenfolge_ pro Scan: `scan.queued` (Edge) → ggf. mehrere Worker-Events → `scan.ingested` ODER `scan.ingest_failed`. Operator-UI muss damit umgehen (Filter, Gruppierung).

**Test-Aufwand** (vermutlich substantiell):

- Alle bestehenden Tests die gegen das Sync-Response-Body asserten (`tests/api/test_scans_*.py`, `tests/api/test_scans_risk_pretriage.py`, `tests/adversarial/test_pretriage_no_llm_override.py`, mehrere Integration-Tests) müssen umstrukturiert werden: Edge-Test prüft nur 202+`job_id`, Worker-Test prüft die ehemals-sync Logik.
- Neue Tests für `scan_ingest_jobs`-Schema, Pickup, Stale-Reaper, Idempotency-Key, Status-Endpoint.
- Neue Agent-Shell-Tests (bats-Suite) für Polling-Loop.

**Agent-Bootstrap-Installer** (ADR-0021):

- Agent-Version 0.4.0 mit Polling-Loop.
- Auto-Update-Pfad zieht 0.4.0 für alle Agents ≥0.3.1 automatisch (Schema unverändert).

## Re-Open-Trigger

- **Wenn Ingest-Verarbeitung nachhaltig < 5s dauert** (z.B. nach Pre-Triage-Optimierung in Block S oder nach Group-Matching-Refactor), kann der Sync-Pfad als Fast-Path zurückkehren. Hybrid-Modus: Job-Queue-Insert + Inline-Processing im selben Request, Status-Endpoint bleibt als Fallback. Wäre eine eigene ADR.
- **Wenn die Ingest-Queue konsistent staut** (>10 Jobs queued, Wait-Time >2 min), wird ein separater `secscan-ingest-worker`-Container nötig (eigener Pod, eigenes CPU-Budget). Eigene ADR.
- **Wenn der Idempotency-Key zu false-positives führt** (zwei semantisch unterschiedliche Scans mit gleichem Hash — nur möglich bei deterministischem Trivy-Output, sehr unwahrscheinlich), Key-Definition erweitern um `(server_id, payload_sha256, received_at-Tag)`. Eigene ADR oder Punkt-Update dieser ADR.
- **Wenn Multi-Tenant-Deploy verlangt wird** (out of scope MVP), pro-Tenant-Worker-Scoping. Eigene ADR.

## Abgewogene Alternativen

| Alternative | Ablehnung |
|---|---|
| **Status-Quo + Agent-Timeout auf 600s erhöhen** | Verschiebt das Problem, löst es nicht. Web-Container hat dann 10-Minuten-Connections (Gunicorn-Worker-Slots gebunden, gunicorn-Worker-Limits stehen). Eine 5-MB-Upload-Connection blockt einen kompletten gthread-Worker. |
| **HTTP-Chunked-Response mit Keep-Alive-Heartbeat** (Server sendet `\n` alle 10s während er arbeitet) | Verworfen. Reverse-Proxies (nginx, k8s-Ingress) verschlucken oft Chunked-Responses oder buffern komplett. Gunicorn-gthread kann das, aber die operative Komplexität (Buffering-Tuning pro Reverse-Proxy) ist hoch. Außerdem bleibt der Web-Container CPU-gebunden bis die Verarbeitung fertig ist. |
| **Background-Thread im Web-Container** (Request-Handler returnt sofort, Thread arbeitet weiter) | Verworfen. Container-Restart (Deploy, Crash, OOM-Kill) verliert den Job ohne Recovery. Postgres-basierte Queue mit Pickup-Pattern ist die Standard-Lösung. |
| **Server-Sent-Events / WebSocket statt Polling** | Out-of-MVP-Scope. Polling mit 2s-Intervall ist für einen 5-Minuten-Verarbeitungs-Job trivial robust (max 150 Calls/Scan), keine Protokoll-Komplexität. ADR-0019 (Polling, nicht SSE) ist die einschlägige Konvention. |
| **Synchron für `findings_inserted < threshold`, asynchron für `≥ threshold`** | Verworfen. Zweigleisige Logik im Edge bedeutet zweigleisige Logik im Test-Suite und im Agent-Client. Kein nachhaltiger Gewinn — der Cold-Path-Initial-Scan ist immer der lange. |
| **Inline-Verarbeitung _aber_ ohne Pre-Triage-Loop im Request** (Pre-Triage-Loop wird in einen Background-LLM-Job verschoben, alles andere bleibt synchron) | Halbgares Mittelding. Pre-Triage ist nicht der einzige langsame Schritt — Bulk-UPSERT von 5000+ Findings und Group-Matching sind auch teuer. Komplexität von _zwei_ asynchronen Pfaden (Pre-Triage-Job + LLM-Jobs) übersteigt den Async-Ingest-Pfad. |

## Bedrohungsmodell-Implikationen

- **DoS via Job-Queue-Flooding.** Heute begrenzen Rate-Limits (`SECSCAN_RATELIMITS.scans_auth`) und Decompress-Cap (100 MB) den Sync-Endpoint. Diese Limits bleiben aktiv — Job-Insert läuft erst _nach_ Rate-Limit-Check. Ein Angreifer mit gültigem Server-Key kann maximal `scans_auth`-Requests/min absetzen.
- **Storage-DoS via große Payloads.** `payload_gzip BYTEA` ist hart auf 100 MB pro Row begrenzt (gleicher Bound wie heute der Decompress-Limit). Zusätzlich kommt ein soft-Cap `MAX_QUEUED_SCAN_INGEST_JOBS_PER_SERVER=50` — bei Überschreitung 429 Too Many Requests beim Insert. Verhindert dass ein einzelner Server die Queue füllt während der Worker nicht hinterherkommt.
- **Idempotency-Key-Brute-Force.** SHA-256-Kollision für 5-MB-Payload ist nicht praktisch erreichbar. Akzeptabel.
- **Worker-Crash mid-Verarbeitung.** Stale-Reaper requeued den Job; bei `attempts >= MAX_ATTEMPTS` (Default 3) wird er `failed` gesetzt und das Payload bleibt 24h für Operator-Debug. Audit-Event `scan.ingest_failed` informiert den Operator.
- **Race auf `scan_ingest_jobs.status='done'`.** Status-Wechsel und `payload_gzip=NULL` laufen in _einem_ atomaren `UPDATE`-Statement (siehe Block-R Phase C Schritt 5) — wenn das committed, ist beides konsistent; wenn nicht, ist auch der Status nicht auf `done` und Stale-Reaper requeued den Job. Es gibt damit kein Zeitfenster mehr in dem ein `done`-Job noch Payload-Daten trägt (außer im Worker-Crash mid-Statement, was Postgres-seitig nicht passieren kann — die Transaktion ist atomar). Der stündliche Retention-Sweep ist nur Safety-Net für _hypothetische_ Implementations-Fehler (z.B. ein zukünftiger Branch der den UPDATE in zwei Statements aufspaltet) und kostet praktisch nichts (`WHERE … AND payload_gzip IS NOT NULL` matched im Normalbetrieb 0 Rows).
- **ADR-0005-Erosion über Zeit.** Risiko dass jemand `payload_gzip` als "permanenten Forensik-Speicher" reinterpretiert. Mitigation: explizite Retention-Konstanten im Worker (`SCAN_INGEST_PAYLOAD_TTL_DONE_SEC=3600`, `SCAN_INGEST_PAYLOAD_TTL_FAILED_SEC=86400`), Tests die die Retention verifizieren, Code-Kommentar in `app/models.py` der auf diese ADR verweist.

## Quellen / Verweise

- `app/api/scans.py` — heutige Sync-Logik
- `app/workers/llm_worker.py` — Worker-Pattern als Vorlage
- `app/models.py` — `LLMJob`-Modell als Schema-Vorlage
- `app/middleware/gzip.py` — Decompress-Pipeline (wird wiederverwendet)
- `agent/secscan-agent.sh` — Curl-Upload, neu: Polling-Loop
- ADR-0003 (Push, nicht Pull), ADR-0005 (Raw-JSON), ADR-0019 (Polling), ADR-0021 (Agent-Bootstrap), ADR-0023 (Worker-Modell)
- TICKET-003 (Audit-Noise-Reduktion) — komplementär, nicht abhängig. Wenn TICKET-003 nach Block R landet, rutscht das dort skizzierte Folge-ADR auf ADR-0027.
- ARCHITECTURE.md §9 — wird im Zuge von Block R angeglichen (Aufteilung in Fast-Path + Worker-Pfad).
