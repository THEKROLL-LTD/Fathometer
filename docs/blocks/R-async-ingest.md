# Block R — Asynchroner Scan-Ingest

**Spec-Quelle:** [ADR-0026](../decisions/0026-async-scan-ingest.md)
**Branch:** `feat/block-r-async-ingest`
**Vorgänger-Block:** Block Q (v0.10.0)
**Status:** Geplant

> **Hinweis zur Block-Nomenklatur:** Die in ADR-0025, Block-Q-Spec und STATE.md mit *"vermutlich Block R"* tentativ reservierte _Triple-`_load_findings()`-Konsolidierung_ rückt auf **Block S**. Async-Ingest ist Block R, weil Produktions-Stabilität (Agent-Connection-Aborts) priorisiert wird.

## Ziel

`POST /api/scans` antwortet binnen <1s mit 202 + `job_id`. Die ehemals-synchrone Verarbeitung (Findings-UPSERT, Host-State, Pre-Triage, Group-Matching, LLM-Job-Queueing) wandert in den `secscan-llm-worker` als neuer Sub-Tick. Agent pollt `GET /api/scans/jobs/<id>` bis `done`/`failed`.

## Spec-Referenzen (Pflicht-Lektüre vor Implementation)

1. ADR-0026 §Entscheidung — die acht Schritte des Fast-Paths und die acht des Worker-Pfads.
2. ADR-0026 §Konsequenzen — API-Contract-Change, Schema, Audit-Events, Tests.
3. ADR-0026 §Bedrohungsmodell — DoS-Limits, Idempotency-Key, Retention.
4. ARCHITECTURE.md §9 — heutige Ingest-Pipeline (wird im Zuge von Phase B angeglichen).
5. ADR-0023 + `app/workers/llm_worker.py` — Worker-Vorlage (Sub-Tick-Pattern, Stale-Reaper, Heartbeat).
6. ADR-0021 + `agent/secscan-agent.sh` — Agent-Auto-Update-Pfad (für Rollout der 0.4.0).
7. TICKET-003 (Audit-Noise) — komplementär, kann vor/nach/parallel zu Block R laufen.

## Modell

Neue Tabelle `scan_ingest_jobs`:

| Spalte | Typ | Constraints | Zweck |
|---|---|---|---|
| `id` | `BIGSERIAL` | PK | Job-ID, im 202-Response-Body |
| `server_id` | `INT` | FK `servers.id ON DELETE CASCADE`, NOT NULL | Auth-Scoping für Status-Endpoint |
| `payload_gzip` | `BYTEA` | NULL allowed (post-`done` cleared) | gzip-Decompressed-Body als Bytes (gzip-recompressed für Storage) |
| `payload_sha256` | `CHAR(64)` | NOT NULL | SHA-256-Hex über den dekomprimierten Original-Body |
| `payload_bytes` | `INT` | NOT NULL | Original-Body-Größe (decompressed) für Audit/Diagnose |
| `status` | `VARCHAR(16)` | NOT NULL DEFAULT `'queued'`, CHECK in (`queued`, `in_progress`, `done`, `failed`) | Lifecycle |
| `attempts` | `INT` | NOT NULL DEFAULT 0, CHECK `>= 0` | Retry-Count |
| `next_attempt_at` | `TIMESTAMPTZ` | NOT NULL DEFAULT `now()` | Pickup-Gate für Retry-Backoff |
| `picked_up_by` | `VARCHAR(128)` | NULL | Worker-ID (für Stale-Detection) |
| `picked_up_at` | `TIMESTAMPTZ` | NULL | Pickup-Zeitpunkt (Stale-Schwellwert) |
| `result` | `JSONB` | NULL | Counts bei `status='done'`: `{scan_id, findings_total, findings_inserted, findings_updated, findings_resolved, class_os_pkgs, class_lang_pkgs, class_other}` |
| `error` | `TEXT` | NULL | Validation-/SQL-/Worker-Error (max 4 KB, truncated) |
| `created_at` | `TIMESTAMPTZ` | NOT NULL DEFAULT `now()` | FIFO-Ordering |
| `finished_at` | `TIMESTAMPTZ` | NULL | Pickup-Ende (für Retention-Sweep) |
| `scan_id` | `BIGINT` | NULL, FK `scans.id ON DELETE SET NULL` | Resolved-Pointer auf den erzeugten Scan (bei `done`) |

Indizes:

- `ix_scan_ingest_jobs_pickup` — partial auf `status='queued'`, sort `(next_attempt_at, created_at)`.
- `ix_scan_ingest_jobs_stale` — partial auf `status='in_progress'`, sort `picked_up_at`.
- `ix_scan_ingest_jobs_server` — `(server_id, status)` für Status-Endpoint-Lookups und Per-Server-Soft-Cap-Check.
- `ux_scan_ingest_jobs_payload_sha256` — **partial unique** auf `status IN ('queued', 'in_progress')`. Nicht global unique — wir wollen denselben Scan _nochmal_ zulassen wenn der vorherige `done` ist (z.B. nach 24h Re-Upload).

Postgres-Storage-Hint: `ALTER TABLE scan_ingest_jobs ALTER COLUMN payload_gzip SET STORAGE EXTERNAL` (kein Toast-Compression — wir liefern bereits gzipped).

## Phasen

### Phase A — Schema + Migration

**Datei:** `alembic/versions/0010_scan_ingest_jobs.py`

Upgrade:
- `CREATE TABLE scan_ingest_jobs (...)` mit allen Spalten + Constraints aus §Modell.
- Storage-Hint auf `payload_gzip`.
- Vier Indizes.

Downgrade:
- `DROP TABLE scan_ingest_jobs`.

**Tests:**
- `tests/alembic/test_0010_scan_ingest_jobs.py` — Schema-Properties (alle Spalten, Constraint-Werte, Index-Definitionen) via SQLAlchemy-Reflection.
- Roundtrip `upgrade head && downgrade -1 && upgrade head` grün gegen Test-Postgres.

**DoD-A:**
1. Migration-File commit-bar.
2. `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` grün.
3. `mypy --strict app/models.py` ohne neue Errors.
4. `ScanIngestJob`-Model in `app/models.py` definiert (parallel zur Migration).
5. Reflection-Test bestätigt: Storage-Mode auf `payload_gzip` ist EXTERNAL.

### Phase B — Edge-Handler-Refactor (`POST /api/scans` → Fast-Path)

**Datei:** `app/api/scans.py`

Neue Reihenfolge im Handler (analog ADR-0026 §Entscheidung Fast-Path):

1. Bearer-Auth + `hmac.compare_digest` (unverändert).
2. `server_is_active` (unverändert).
3. Rate-Limits (unverändert).
4. gzip-Decompress mit Bound (unverändert).
5. **NEU:** `payload_sha256 = hashlib.sha256(decompressed_body).hexdigest()`.
6. **NEU:** "Schmal-Validierung" — `_pre_validate_envelope(decompressed_body)`. Prüft nur:
   - Top-Level JSON-Objekt.
   - Pflicht-Schlüssel `agent_version` als String mit `version_lt`-kompatiblem Format.
   - Pflicht-Schlüssel `host.hostname` existiert und ist String <128 Chars.
   - Pflicht-Schlüssel `scan` existiert als Objekt.
7. Agent-Version-Gate (`version_lt(envelope_pre.agent_version, Settings.MIN_AGENT_VERSION)` → 400 `agent_outdated`).
8. **NEU:** Soft-Cap: `SELECT COUNT(*) FROM scan_ingest_jobs WHERE server_id=? AND status IN ('queued','in_progress')`. Wenn ≥ `MAX_QUEUED_SCAN_INGEST_JOBS_PER_SERVER` (Default 50, ENV `SECSCAN_MAX_QUEUED_INGEST_JOBS`), 429 mit `error=queue_full`.
9. **NEU:** `INSERT INTO scan_ingest_jobs (server_id, payload_gzip, payload_sha256, payload_bytes, status='queued') VALUES (...) ON CONFLICT (payload_sha256) WHERE status IN ('queued','in_progress') DO UPDATE SET id=id RETURNING id`. Postgres-Pattern: `ON CONFLICT DO NOTHING` plus separater `SELECT id WHERE payload_sha256 = ?` als Fallback.
10. **NEU:** Audit-Event `scan.queued` mit `{job_id, payload_sha256, payload_bytes}`.
11. **NEU:** Response 202 `{"job_id": id, "status": "queued", "status_url": f"/api/scans/jobs/{id}"}`.

**Helper:**
- `app/api/scans._pre_validate_envelope(body: bytes) -> tuple[str | None, str | None]` — returnt `(agent_version, error)`. Implementiert via `json.loads`-Parse + manuelles dict-Walking (kein Pydantic, damit der Validierungs-Pfad <5ms ist).
- `app/services/scan_ingest_queue.enqueue_or_resolve(session, server, payload_bytes, payload_gzip) -> ScanIngestJob` — kapselt die UPSERT-Logik.

**Audit-Helper:** ein neuer Event-Action-Name `scan.queued` wird in `app/audit.py` nicht hardkodiert (das Modul ist event-agnostisch), aber in `ARCHITECTURE.md §9` als Top-Level-Event dokumentiert.

**Tests:**
- `tests/api/test_scans_async_edge.py` — Happy-Path (202 + job_id), Auth-Fail (401), Outdated-Agent (400), Queue-Full (429), Idempotency (zwei identische Bodies → ein Job, identische job_id), Body-Schemafehler (400 vor Insert), Decompress-Limit (413), Wrong-Server-Status (403).

**DoD-B:**
1. Handler-Code in `app/api/scans.py` ersetzt — alte sync-Logik aus Schritt 5–11 ist im Edge-Handler verschwunden (zieht nach Phase C in den Worker).
2. `pytest tests/api/test_scans_async_edge.py -v` grün, mindestens 8 Test-Fälle.
3. `pytest tests/api/test_scans_*.py` _kompiliert_ noch (alte Sync-Asserts werden in Phase G migriert; Phase B macht die Tests `xfail` mit Marker `block_r_sync_to_async`).
4. End-to-End-Smoke: ein `POST /api/scans` retourniert 202 binnen <100ms (lokaler Profile-Run, kein Live-Bench).

### Phase C — Worker-Sub-Tick `scan_ingest_tick`

**Datei:** `app/workers/scan_ingest_worker.py` (neu) + Anpassung in `app/workers/llm_worker.py::_tick`.

Sub-Tick-Logik (analog Phase B des ADR-0026 §Entscheidung Worker-Pfad):

1. `_pick_next_scan_ingest_job_id()` — `SELECT FOR UPDATE SKIP LOCKED FROM scan_ingest_jobs WHERE status='queued' AND next_attempt_at <= now() ORDER BY created_at LIMIT 1`. Returnt `int | None`.
2. `_process_scan_ingest_job(job_id)` lädt den Job in einer frischen Session, setzt Status `in_progress` + `picked_up_at` + `picked_up_by` + `attempts += 1`, committet sofort.
3. **Verarbeitungs-Logik** wird aus `app/api/scans.py:283–540` 1:1 in eine neue Service-Funktion `app/services/scan_processing.process_scan_envelope(session, server, payload_gzip)` extrahiert. Inputs sind das Server-Objekt und der dekomprimierte Body; Output ist eine `ScanProcessingResult`-Pydantic-Klasse mit den Counts.
4. `app/services/scan_processing.process_scan_envelope` ruft intern in dieser Reihenfolge auf (alle aus dem heutigen Sync-Pfad, semantisch unverändert):
   - `json.loads` + `Envelope.model_validate` (Pydantic-Voll-Parse).
   - `findings_ingest.ingest_scan`.
   - `persist_host_state` (Try/Except wie heute).
   - Pre-Triage-Loop (siehe TICKET-003 für Audit-Noise-Anpassung — wenn TICKET-003 vor Block R landet, ist die Audit-Emit-Stelle bereits weg).
   - `GroupMatcher.reload + apply_matches_for_server + inherit_group_risk_to_findings`.
   - Pass-1-/Pass-2-Job-Queueing.
   - `notify_conversations_for_scan` (Best-Effort-Hook, kann nicht den Worker-Job killen).
   - `scan.ingested`-Audit-Event mit Counts.
5. Bei Erfolg: **ein einziges atomares UPDATE** setzt `status='done'`, `finished_at=now()`, `scan_id`, `result`-JSONB mit Counts **und `payload_gzip=NULL`**. Der Roh-Body verschwindet also unmittelbar mit dem Statuswechsel — ADR-0005 wird substantiell respektiert, der Payload lebt nur so lange wie der Verarbeitungs-Lauf (Sekunden bis Minuten). Der Retention-Sweep weiter unten ist ausschließlich Safety-Net für Crash-Szenarien zwischen Schritt 5 und 6.
6. Bei `ValidationError`: Status `failed`, `error` = `format_pydantic_errors(...)`, Audit `scan.ingest_failed`. **`payload_gzip` bleibt erhalten** (Operator-Debugging) — wird erst vom 24h-Retention-Pfad ganzheitlich mit der Zeile entfernt.
7. Bei `SQLAlchemyError`: Rollback, `attempts < MAX_ATTEMPTS` → Status `queued` mit Backoff (`next_attempt_at = now() + 30s * 2^attempts`). `attempts >= MAX_ATTEMPTS` → `failed` (Payload-Verhalten wie Schritt 6).

**Sub-Tick-Reihenfolge** in `_tick()`:

```
# Stale-Reaper (jetzt zwei Tabellen)
# Debug-Log-Eviction
# Feed-Pull-Check
# Mode-Check
# Budget-Check
# >>> NEU: Scan-Ingest-Pickup vor LLM-Pickup
if scan_ingest_job_id := _pick_next_scan_ingest_job_id():
    _process_scan_ingest_job(scan_ingest_job_id)
    _reset_idle_backoff()
    return  # Ein Job pro Tick, gleichberechtigt mit LLM-Pickup.
# LLM-Pickup wie gehabt
```

**Stale-Reaper-Erweiterung** in `_run_stale_reaper`:

- Zweite Pass: `UPDATE scan_ingest_jobs SET status='queued', picked_up_by=NULL, picked_up_at=NULL WHERE status='in_progress' AND picked_up_at < now() - interval '<SCAN_INGEST_STALE_TIMEOUT_MIN> minutes'`.
- `SCAN_INGEST_STALE_TIMEOUT_MIN = 5` als Konstante.
- `attempts >= MAX_ATTEMPTS` → `failed` statt requeue.

**Retention-Sweep** (neuer Sub-Tick, **stündlich**):

- `UPDATE scan_ingest_jobs SET payload_gzip = NULL WHERE status='done' AND payload_gzip IS NOT NULL AND finished_at < now() - interval '1 hour'`. Safety-Net: bei sauberem Worker-Run ist `payload_gzip` schon in Phase-C-Schritt-5 atomar auf NULL gesetzt — dieser UPDATE betrifft nur Crash-Resträume.
- `DELETE FROM scan_ingest_jobs WHERE status='failed' AND finished_at < now() - interval '24 hours'`. Bei `failed` wurde der Payload _nicht_ in Schritt 5 gelöscht (Operator-Debugging-Fenster), die komplette Zeile wird daher nach 24h entfernt.
- `SCAN_INGEST_RETENTION_INTERVAL_SEC = 3600` (Sub-Tick-Cadence — stündlich, damit das 1h-TTL für `done`-Crash-Reste auch effektiv binnen <2h greift).

**Tests:**
- `tests/workers/test_scan_ingest_worker.py` — Happy-Path-Pickup, Concurrency (zwei Worker-Threads, SKIP LOCKED greift), Stale-Reaper-Requeue, Stale-Reaper-Fail-nach-Max-Attempts, Validation-Error-Pfad, SQL-Error-mit-Retry, Retention-Sweep.
- `tests/services/test_scan_processing.py` — die extrahierte `process_scan_envelope`-Funktion läuft pure-unit gegen Test-Postgres mit gemockten Trivy-Fixtures aus `tests/fixtures/trivy/`. Counts-Asserts identisch zur heutigen Sync-Test-Suite.
- `tests/workers/test_scan_ingest_payload_lifecycle.py` (neu) — drei Verifikations-Pfade für die Payload-Lebensdauer:
  1. Happy-Path: nach erfolgreichem Pickup hat die Zeile `payload_gzip IS NULL` _direkt_ nach dem Status-Wechsel auf `done` (kein zweiter Tick, kein Sweep nötig).
  2. Crash-Simulation: ein gemockter Worker stirbt nach `status='done'`-Commit aber vor dem (in dieser Implementation atomaren — daher synthetisch erzeugten) Payload-Clear → Retention-Sweep nach 1h NULL't die Spalte.
  3. Failed-Pfad: bei `status='failed'` bleibt `payload_gzip` 24h erhalten; Retention-Sweep `DELETE`'t die ganze Zeile nach Ablauf, nicht nur die Payload-Spalte.

**DoD-C:**
1. `app/workers/scan_ingest_worker.py` implementiert.
2. `app/services/scan_processing.process_scan_envelope` extrahiert; bestehende `findings_ingest`/`pretriage`/etc. Aufrufe semantisch unverändert (Diff zeigt nur Import + Funktions-Boundary).
3. `_tick()` ruft Scan-Ingest-Sub-Tick vor LLM-Pickup auf.
4. Stale-Reaper kennt beide Tabellen.
5. Retention-Sweep-Sub-Tick läuft stündlich.
6. **Atomares UPDATE in Schritt 5** verifiziert: in `test_scan_ingest_payload_lifecycle.py` Happy-Path liest der Test direkt nach dem Worker-Pickup `SELECT status, payload_gzip IS NULL AS cleared FROM scan_ingest_jobs WHERE id = ?` und erwartet `(done, true)` — _kein_ Sweep-Lauf zwischendurch.
7. `pytest tests/workers/test_scan_ingest_worker.py tests/services/test_scan_processing.py tests/workers/test_scan_ingest_payload_lifecycle.py -v` grün, mindestens 18 Test-Fälle.
8. `mypy --strict app/workers/scan_ingest_worker.py app/services/scan_processing.py` ohne Errors.

### Phase D — Status-Endpoint `GET /api/scans/jobs/<job_id>`

**Datei:** `app/api/scans.py` (oder neuer Sub-Endpoint-Handler im selben Blueprint).

Logik:

1. Bearer-Auth + Server-Active wie POST.
2. `SELECT * FROM scan_ingest_jobs WHERE id = ? AND server_id = ?` (Server-Scoping verhindert Cross-Server-Job-Lookup).
3. Nicht gefunden → 404 `{"error": "job_not_found"}`.
4. Gefunden → 200 mit:
   - `{job_id, status, created_at, picked_up_at, finished_at, attempts}`
   - bei `status='done'`: zusätzlich `{scan_id, counts: {...}}`
   - bei `status='failed'`: zusätzlich `{error}`

Rate-Limit: gleiche Per-Server-Bucket wie `POST /api/scans` (Polling-Verkehr darf den Endpoint nicht killen).

**Tests:**
- `tests/api/test_scan_status_endpoint.py` — alle vier Status-Werte, Cross-Server-403, Unbekannte-Job-404, Auth-Fail-401, Polling-Burst-Test (50 Calls/min ist OK).

**DoD-D:**
1. Endpoint implementiert.
2. `pytest tests/api/test_scan_status_endpoint.py -v` grün, mindestens 7 Test-Fälle.

### Phase E — Agent-Polling-Loop (`secscan-agent.sh` 0.4.0)

**Datei:** `agent/secscan-agent.sh`

Nach dem `curl -X POST /api/scans` Upload (Zeile ~402):

```bash
http_status="$(printf '%s' "$payload" | gzip -c | curl -sS \
  --max-time 30 \
  -o "$response_body" -w '%{http_code}' \
  -X POST "${SECSCAN_URL%/}/api/scans" \
  -H "Authorization: Bearer ${SECSCAN_API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @-)"

case "$http_status" in
  202) ;;
  400|413|422|429) log "Error: upload rejected (HTTP $http_status)"; cat "$response_body"; exit 3 ;;
  *)   log "Error: upload failed (HTTP $http_status)"; cat "$response_body"; exit 3 ;;
esac

job_id="$(jq -r '.job_id' < "$response_body")"
if [[ -z "$job_id" || "$job_id" == "null" ]]; then
  log "Error: response missing job_id"; cat "$response_body"; exit 3
fi
log "Scan queued (job_id=$job_id), waiting for processing..."

# Polling-Loop
poll_start=$(date +%s)
poll_max_sec=600
poll_interval_sec=2
while :; do
  now=$(date +%s); elapsed=$((now - poll_start))
  if [[ "$elapsed" -ge "$poll_max_sec" ]]; then
    log "Error: scan processing timed out after ${poll_max_sec}s (job_id=$job_id)"; exit 5
  fi
  status_json="$(curl -fsS --max-time 10 \
    -H "Authorization: Bearer ${SECSCAN_API_KEY}" \
    "${SECSCAN_URL%/}/api/scans/jobs/${job_id}")" || { sleep "$poll_interval_sec"; continue; }
  status="$(echo "$status_json" | jq -r '.status')"
  case "$status" in
    done)   log "Scan processed (job_id=$job_id)"; echo "$status_json" | jq '.counts'; exit 0 ;;
    failed) log "Error: scan processing failed (job_id=$job_id)"; echo "$status_json" | jq '.error'; exit 4 ;;
    queued|in_progress) sleep "$poll_interval_sec" ;;
    *) log "Unknown status: $status"; sleep "$poll_interval_sec" ;;
  esac
done
```

`AGENT_VERSION` auf `0.4.0` hochziehen. `MIN_AGENT_VERSION` im Backend (`app/config.Settings.MIN_AGENT_VERSION`) bleibt vorerst auf 0.3.1, damit ein gemischtes Deploy-Fenster unterstützt wird. Sobald alle Agents auf 0.4.0 sind: Min-Version auf 0.4.0 (separater Operator-Schritt nach Block R).

**Neue Exit-Codes:**
- 0: success
- 1: missing requirements/config
- 2: trivy scan failed
- 3: upload failed (HTTP-Layer)
- 4: scan processing failed (Worker-Layer)
- 5: polling timeout

**Tests:**
- `tests/agent/test_secscan_agent_polling.sh` (bats) — Mock-Server der 202+job_id liefert, dann nach N Polls `done` returnt; Mock der `failed` returnt; Mock der nie antwortet (Timeout-Exit 5).

**DoD-E:**
1. Agent-Script ergänzt, `shellcheck agent/secscan-agent.sh` PASS.
2. Bats-Suite grün (mindestens 5 Polling-Pfade).
3. Auto-Update-Pfad pullt 0.4.0 automatisch für bestehende ≥0.3.1-Agents.

### Phase F — Audit-Event-Anpassung

**Dateien:** `ARCHITECTURE.md §9`, `docs/decisions/0022-risk-based-prioritization.md` (Cross-Reference auf Worker-Emit-Stelle), `app/audit.py` (keine Code-Änderung — Event-Action-Strings sind heute schon free-form).

Neue Event-Actions die in `ARCHITECTURE.md §9` dokumentiert werden:

- `scan.queued` — Edge-Container, beim Job-Insert. Body: `{job_id, payload_sha256, payload_bytes}`. **Idempotency-Note:** bei Re-Insert (gleicher Hash) wird **kein** zweites `scan.queued` emittiert (Audit-Spam-Schutz).
- `scan.ingest_failed` — Worker-Container, bei Validation-/SQL-Error nach max attempts. Body: `{job_id, error_class, error_truncated}`.

Bestehende Event-Actions die nun vom Worker statt Web-Container emittiert werden (Inhalt unverändert):
- `scan.ingested`
- `host_state.snapshot_received` / `host_state.parse_failed`
- `risk.pretriage_evaluated`
- `llm.jobs_queued`

**Tests:**
- `tests/api/test_scans_audit_events.py` — Reihenfolgen-Assertions: `scan.queued` vor `scan.ingested`, korrekte `actor`-Werte (Edge: server.name, Worker: server.name auch — Server-Identität wird vom Worker via Job-Lookup rekonstruiert).

**DoD-F:**
1. ARCHITECTURE.md §9 angeglichen.
2. ADR-0022 mit Hinweis ergänzt: Pre-Triage-Audit-Events kommen jetzt vom Worker.
3. `pytest tests/api/test_scans_audit_events.py -v` grün.

### Phase G — Test-Suite-Migration

Bestehende Tests die `tests/api/test_scans_*.py` 202-Body asserten oder das `scan.ingested`-Event im selben Request-Cycle erwarten:

- `tests/api/test_scans_smoke.py`
- `tests/api/test_scans_risk_pretriage.py`
- `tests/adversarial/test_pretriage_no_llm_override.py`
- `tests/api/test_scans_block_p_queueing.py`
- (+ ggf. weitere — `grep -rn 'findings_total' tests/` zeigt die Surface)

Anpassungs-Muster:

1. **Edge-Tests** asserten nur `{job_id, status: 'queued'}` und das `scan.queued`-Event.
2. **Verarbeitungs-Tests** rufen direkt `process_scan_envelope(...)` oder den Worker-Tick auf und asserten die heutigen Counts/Audit-Events. Helper: `tests/conftest.py::run_scan_ingest_synchronously(client, server, envelope_bytes)` der den Edge-POST und den Worker-Pickup in einem deterministischen Sweep ausführt — die meisten Bestandstests können nahezu unverändert weiterlaufen, nur der Call-Site wechselt.

**xfail-Marker** aus Phase B werden in Phase G aufgelöst (jeder Test bekommt entweder den neuen Edge-/Worker-Pfad oder bleibt `xfail` mit dokumentiertem Grund).

**DoD-G:**
1. `grep -rn xfail tests/api/test_scans_*.py tests/adversarial/test_pretriage_no_llm_override.py` ist leer.
2. `pytest -v` Gesamt-Suite grün; Test-Anzahl-Delta dokumentiert in der Block-Commit-Message (Erwartung: leicht positiv, da neue Phase-A/B/C/D-Tests dazukommen).

### Phase H — Operator-Migration + Cutover

**`docs/operations.md` (Update):**

- Neuer Abschnitt *"Async-Ingest — Operator-Sicht"*:
  - Wie man die Queue-Tiefe inspiziert (`SELECT status, COUNT(*) FROM scan_ingest_jobs GROUP BY status`).
  - Wie man hängende Jobs erkennt (`status='in_progress' AND picked_up_at < now() - interval '5 min'`).
  - Wie man manuell requeued (`UPDATE ... SET status='queued', picked_up_by=NULL`).
  - Retention-Verhalten dokumentieren.
- Hinweis: Agent-Update auf 0.4.0 vor Backend-Deploy (Auto-Update macht das, aber Operator-Awareness).

**Cutover-Plan:**

1. Deploy Backend 0.11.0 mit Block-R-Code aber **Feature-Flag `SCAN_INGEST_ASYNC=False`** (Default off, alter Sync-Pfad bleibt aktiv).
2. Validate Schema-Migration, Status-Endpoint, Worker-Tick mit künstlichem Job-Insert.
3. Flag auf `True`. POST schaltet auf Fast-Path.
4. Agent-Auto-Update zieht 0.4.0 sukzessive — bis dahin akzeptiert der alte Agent-Polling-loser Pfad die 202+job_id ohne Verifikation (Exit 0 nach Upload, ohne Counts).
5. 7 Tage Beobachtung. `MIN_AGENT_VERSION` auf 0.4.0.
6. Feature-Flag entfernt (Sync-Code aus `app/api/scans.py` ersatzlos, kein Hybrid-Code).

**DoD-H:**
1. Feature-Flag `SCAN_INGEST_ASYNC` in `app/config.Settings` + ENV-Variable.
2. `app/api/scans.py` hat zwei Branches die per Flag schalten.
3. `docs/operations.md` angeglichen.
4. CHANGELOG-Eintrag (v0.11.0).

## Risiken & Mitigation

| Risiko | Mitigation |
|---|---|
| **Worker-Backlog** bei großer Server-Flotte mit kurzem Scan-Cron | Per-Server-Soft-Cap (50 queued/in_progress); Monitoring via `scan_ingest_jobs.status='queued' COUNT` als Healthcheck-Metrik. Bei nachhaltigem Stau: separater `secscan-ingest-worker`-Pod (eigene ADR). |
| **Idempotency-Key-Kollision** zwischen logisch unterschiedlichen Scans | Praktisch unmöglich bei SHA-256 über 5-MB-Payloads. Falls je beobachtet: Key auf `(server_id, payload_sha256, date)` erweitern. |
| **Worker-Crash mid-Verarbeitung** | Stale-Reaper requeued nach 5 min. `attempts >= 3` → `failed`. Operator-Audit über `scan.ingest_failed`. |
| **Agent-Polling-Timeout (10 min)** ohne Job-Done | Job bleibt in Queue, Stale-Reaper greift später, Audit-Event `scan.ingest_failed` informiert Operator. Agent-Exit-Code 5 trennt das von Upload-Fehlern. |
| **`payload_gzip`-Storage-Wachstum** bei langlebigen `failed`-Jobs | 24h-Retention via Sub-Tick. Manuelle Cleanup-Befehle in `docs/operations.md` dokumentiert. |
| **ADR-0005-Erosion** über Zeit | Code-Kommentar in `app/models.ScanIngestJob` der explizit auf ADR-0026 verweist; Retention-Tests die NULL-Setzung nach 1h verifizieren. |
| **Race zwischen Web-Insert und Worker-Pickup** (Job picked up bevor Web-Container commitet hat) | `INSERT ... RETURNING id` plus `sess.commit()` _vor_ der Response. Worker-Pickup nutzt `SELECT FOR UPDATE SKIP LOCKED` und sieht nur commited Rows. Standard-PG-Semantik. |
| **Audit-Event-Reihenfolgen-Brüche** in Operator-UI | Audit-UI rendert Events FIFO nach `ts`. `scan.queued` (Edge) ist immer vor allen Worker-Events. Tests verifizieren. |
| **Bestehende Tests rotieren weg** und decken den neuen Pfad nicht | Phase G ist die explizite Migrations-Phase, `xfail`-Marker aus Phase B sind die Checkliste. |

## NICHT in Block R

- **Multi-Worker-Deploy** (mehrere `secscan-llm-worker`-Pods für Ingest + LLM). SKIP-LOCKED macht es schemenseitig möglich, aber operativ ist es nicht in Block R verlangt. Eigene ADR.
- **HTTP-Streaming/SSE-Statusupdates** statt Polling. ADR-0019-Konvention: Polling ist die Wahl.
- **Pre-Triage-Performance-Optimierung** (Loop-Algorithmus, Audit-Event-Pruning). TICKET-003 macht einen Teil davon. Algorithmische Optimierung ist Block S.
- **Triple-`_load_findings()`-Konsolidierung** auf der Server-Detail-Seite. Ist Block S (vorher tentativ Block R).
- **Retention-UI** (Operator-Seite zum manuellen Löschen von alten `done`/`failed`-Jobs). docs/operations.md mit SQL-Snippet reicht im MVP.
- **Multi-Tenant-Job-Scoping**. Out-of-MVP.
- **Webhook-/Push-Notifications an den Agent** bei `done` (statt Polling). Würde push-from-Server bedeuten, kollidiert mit ADR-0003. Nein.
- **Migration der bestehenden ~49000 `risk.band_changed`-Audit-Events**. Out-of-Block-R (siehe TICKET-003 das diese Frage adressiert).

## Definition-of-Done (Block-Übergreifend)

1. Alle Phasen-DoDs (A–H) grün.
2. `ruff check . && ruff format --check . && mypy app/` PASS.
3. `pytest -v` Gesamt-Suite PASS.
4. `pytest tests/adversarial/ -v` PASS.
5. `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` PASS.
6. `docker compose up -d --build && curl -fsSL http://localhost:8000/healthz` PASS.
7. `shellcheck agent/secscan-agent.sh` PASS, Bats-Suite PASS.
8. ARCHITECTURE.md §9 angeglichen, ADR-0026 commit-bar, ADR-0005 §Konsequenzen ergänzt um Transit-Ausnahme.
9. CHANGELOG-Eintrag v0.11.0.
10. STATE.md Block-Q-Block-R-Block-S-Sequenz dokumentiert (Block R = Async-Ingest, Block S = Perf-Konsolidierung).
11. Operator-Smoketest: Initial-Scan auf einem k3s-Server mit ~5000 Findings retourniert 202 binnen <1s, Worker verarbeitet binnen <60s, Agent-Polling exit 0.
